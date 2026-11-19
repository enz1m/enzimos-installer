// SPDX-License-Identifier: MIT
//! Read-only media preflight, independently rebuilt Arch authority and held archives.
use crate::{answers::Gpu, media_manifest, media_plan, media_source::Media};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use enzimos_policy::{authority, authority_build, package_archive, package_signature};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::fd::AsFd,
    path::{Path, PathBuf},
};
pub struct Package {
    pub filename: String,
    pub identity: Value,
    pub signer: String,
    pub archive: File,
    pub signature: File,
    archive_identity: files::FileIdentity,
    signature_identity: files::FileIdentity,
}
pub struct Admitted {
    pub media: Media,
    pub authority: authority_build::Prepared,
    pub manifest: Value,
    pub packages: Vec<Package>,
    pub native: Vec<NativePackage>,
    pub images: crate::package_preflight::Images,
    pub selected: Vec<String>,
    pub receipt: Value,
    work: PathBuf,
    recent: crate::recheck_cache::Recent,
}
pub struct NativePackage {
    pub declaration: crate::native_media::Declared,
    pub identity: Value,
    pub archive: File,
    identity_pin: files::FileIdentity,
}
fn nvidia(gpu: Gpu) -> Result<bool> {
    if gpu != Gpu::Auto {
        return Ok(gpu == Gpu::Nvidia);
    }
    let bus = files::directory(Path::new("/sys/bus/pci/devices"), Some(0))?;
    let mount = mount_identity::id(bus.as_fd(), true)?;
    let mut count = 0;
    for entry in std::fs::read_dir("/sys/bus/pci/devices")? {
        count += 1;
        require(count <= 4096, "PCI device inventory bound")?;
        let path = std::fs::canonicalize(entry?.path())?;
        require(
            path.starts_with("/sys/devices"),
            "PCI device escaped kernel device tree",
        )?;
        let dir = files::directory(&path, Some(0))?;
        require(
            mount_identity::id(dir.as_fd(), true)? == mount,
            "PCI device filesystem differs",
        )?;
        let vendor = files::read_kernel(&path.join("vendor"), 128)?;
        let class = files::read_kernel(&path.join("class"), 128)?;
        if vendor == b"0x10de\n" && (class.starts_with(b"0x0300") || class.starts_with(b"0x0302")) {
            return Ok(true);
        }
    }
    Ok(false)
}
impl Admitted {
    pub fn open(gpu: Gpu) -> Result<Self> {
        Self::open_checked(gpu, true)
    }
    /// `check: false` skips the full-medium digest and signature passes; pacman still
    /// verifies every package signature when it installs it.
    pub fn open_checked(gpu: Gpu, check: bool) -> Result<Self> {
        Self::admit(check, |base, conditional| {
            media_plan::select(base, conditional, nvidia(gpu)?)
        })
    }
    /// The package job's own admission: the caller already checked the medium (or the
    /// user chose not to), so the full digest and signature passes are not repeated.
    pub(crate) fn from_selection(selected: &[String]) -> Result<Self> {
        Self::admit(false, |base, conditional| {
            require(
                selected == base
                    || media_plan::select(base, conditional, true).is_ok_and(|all| selected == all),
                "worker selection differs from the complete reviewed base or NVIDIA cohort",
            )?;
            Ok(selected.to_vec())
        })
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (getrlimit).")]
    fn admit<F: FnOnce(&[String], &[String]) -> Result<Vec<String>>>(
        check: bool,
        selection: F,
    ) -> Result<Self> {
        crate::setup::live()?;
        let media = Media::open()?;
        let bytes = if check {
            eprintln!("==> checking the installation medium");
            media.verify_manifest()?
        } else {
            0
        };
        let manifest = json::decode(&media.read("manifest.json", 1024 * 1024)?, 1024 * 1024)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error("installer clock before epoch".into()))?
            .as_millis();
        let now = u64::try_from(now).map_err(|_| Error("installer clock overflow".into()))?;
        media_plan::manifest(&manifest, &media.members, now)?;
        // Missing native worker bytes or an undeclared local package must fail
        // before the caller can publish any erase intent.
        let images = crate::package_preflight::Images::open()?;
        let mut native = Vec::new();
        let mut native_names = BTreeSet::new();
        for declaration in crate::native_media::plan(&manifest, &media.members)? {
            let archive = media.member(&declaration.file, declaration.max_bytes)?;
            let identity = package_archive::identity(&archive)?;
            crate::native_media::identity(&declaration, &identity)?;
            require(
                native_names.insert(identity["name"].as_str().unwrap().to_owned()),
                "duplicate native package name",
            )?;
            native.push(NativePackage {
                declaration,
                identity,
                identity_pin: files::identity(&archive.metadata()?),
                archive,
            });
        }
        if !manifest["ai_runtime"].is_null() {
            require(
                json::decode(&media.read("ai-packages.json", 1024 * 1024)?, 1024 * 1024)?
                    == manifest["ai_runtime"],
                "AI runtime sidecar differs from admitted media declaration",
            )?;
        }
        let base = media_manifest::package_list(&media.read("package-files.txt", 1024 * 1024)?)?;
        let conditional =
            media_manifest::package_list(&media.read("nvidia-files.txt", 1024 * 1024)?)?;
        let declared = media_plan::declarations(&media.read("packages.txt", 1024 * 1024)?)?;
        crate::native_media::disjoint(
            &native.iter().map(|p| &p.declaration).collect::<Vec<_>>(),
            &declared,
        )?;
        let filenames = base
            .iter()
            .chain(conditional.iter())
            .cloned()
            .collect::<BTreeSet<_>>();
        require(
            filenames.len() == base.len() + conditional.len()
                && filenames.len() <= 1024
                && filenames.len() == declared.len()
                && !base.is_empty(),
            "offline package list overlap, bound or empty base",
        )?;
        let expected = filenames
            .iter()
            .flat_map(|name| [format!("packages/{name}"), format!("packages/{name}.sig")])
            .collect::<BTreeSet<_>>();
        let mut descriptors: libc::rlimit = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut descriptors) } == 0
                && descriptors.rlim_cur >= (2 * filenames.len() + 256) as libc::rlim_t,
            "offline package descriptor retention exceeds process limit",
        )?;
        require(
            media
                .members
                .keys()
                .filter(|s| s.starts_with("packages/"))
                .cloned()
                .collect::<BTreeSet<_>>()
                == expected,
            "offline archive and signature manifest set differs",
        )?;
        files::ensure_directory(Path::new("/run/enzimos-install-native"), 0o700, 0)?;
        let work = Path::new("/run/enzimos-install-native")
            .join(format!("media-{}", files::random_hex(16)?));
        files::create_directory(&work, 0o700, 0)?;
        let current = work.join("current");
        files::create_directory(&current, 0o700, 0)?;
        for name in authority::FILES {
            let bytes = media.read(&format!("public-keys/{name}"), 8 * 1024 * 1024)?;
            files::atomic_bounded(
                &current.join(name),
                &bytes,
                if name == "gpg.conf" { 0o644 } else { 0o600 },
                Some(0),
                false,
                8 * 1024 * 1024,
            )?;
        }
        media.recheck()?;
        let authority = authority_build::build(
            &current,
            Path::new("/usr/share/pacman/keyrings"),
            &work.join("review"),
            0,
        )?;
        require(
            authority.local.is_empty(),
            "offline Arch admission refuses additional local signing authorities",
        )?;
        let mut packages = Vec::new();
        let mut observed = BTreeMap::new();
        let total = filenames.len();
        if check {
            eprintln!("==> verifying {total} package signatures");
        }
        for (index, filename) in filenames.into_iter().enumerate() {
            if check && index > 0 && index % 50 == 0 {
                eprintln!("    verified {index}/{total} packages");
            }
            authority.recheck()?;
            let archive =
                media.member(&format!("packages/{filename}"), 2 * 1024u64 * 1024 * 1024)?;
            let signature = media.member(&format!("packages/{filename}.sig"), 65536)?;
            let identity = package_archive::identity(&archive)?;
            let signer = if check {
                let signer = package_signature::verify(&archive, &signature, &authority.directory)?;
                require(
                    authority.approved.contains(&signer),
                    "offline package signer lacks current independent Arch quorum",
                )?;
                signer
            } else {
                String::new()
            };
            observed.insert(filename.clone(), identity.clone());
            packages.push(Package {
                archive_identity: files::identity(&archive.metadata()?),
                signature_identity: files::identity(&signature.metadata()?),
                filename,
                identity,
                signer,
                archive,
                signature,
            });
        }
        media_plan::pool(&base, &conditional, &declared, &observed, &manifest)?;
        let selected = selection(&base, &conditional)?;
        crate::desktop_overlay::preflight(&media, &manifest)?;
        crate::flatpak_media::preflight(&media, &manifest)?;
        media.recheck()?;
        authority.recheck()?;
        let receipt = value!({"schema":1,"role":"offline-installation-media-preflight","media_manifest_sha256":media.manifest_sha256,
            "media_bytes":bytes,"package_count":packages.len(),"selected":selected,
            "authority":authority.summary,"authority_sha256":authority.hashes(),
            "packages":packages.iter().map(|p| value!({"file":p.filename,"identity":p.identity,"signer":p.signer})).collect::<Vec<_>>(),
            "native_packages":native.iter().map(|p| value!({"file":p.declaration.file,"identity":p.identity,"sha256":p.declaration.sha256})).collect::<Vec<_>>(),
            "native_images":images.hashes(),
            "development_artifact":true,"release_authorized":false});
        files::atomic(
            &work.join("admission.json"),
            &json::canonical(&receipt)?,
            0o600,
            Some(0),
            false,
        )?;
        let admitted = Self {
            recent: crate::recheck_cache::Recent::new(),
            media,
            authority,
            manifest,
            packages,
            native,
            images,
            selected,
            receipt,
            work,
        };
        admitted.signing_capacity()?;
        Ok(admitted)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs, fstatvfs).")]
    pub(crate) fn signing_capacity(&self) -> Result<()> {
        self.media.recheck()?;
        let mut total = 0u64;
        for package in &self.native {
            total = total
                .checked_add(package.archive.metadata()?.len())
                .ok_or_else(|| Error("native staging byte overflow".into()))?;
        }
        require(
            total <= 4 * 1024u64 * 1024 * 1024,
            "native development cohort staging bound",
        )?;
        let directory = files::directory(Path::new("/run/enzimos-install-native"), Some(0))?;
        use std::os::fd::AsRawFd;
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        let mut available: libc::statvfs = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::fstatfs(directory.as_raw_fd(), &mut fs) } == 0
                && fs.f_type == 0x01021994
                && unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut available) } == 0
                && u128::from(available.f_bavail) * u128::from(available.f_frsize)
                    >= u128::from(total + 128 * 1024 * 1024),
            "live RAM filesystem lacks native signing headroom before destructive intent",
        )?;
        let bytes = files::read_kernel(Path::new("/proc/meminfo"), 65536)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error("live memory inventory encoding".into()))?;
        let rows = text
            .lines()
            .filter_map(|line| line.strip_prefix("MemAvailable:"))
            .collect::<Vec<_>>();
        require(rows.len() == 1, "live memory availability ambiguous")?;
        let fields = rows[0].split_whitespace().collect::<Vec<_>>();
        require(
            fields.len() == 2 && fields[1] == "kB",
            "live memory availability shape",
        )?;
        let memory = fields[0]
            .parse::<u64>()
            .map_err(|_| Error("live memory availability integer".into()))?;
        require(
            u128::from(memory) * 1024 >= u128::from(total + 512 * 1024 * 1024),
            "live memory lacks native signing headroom before destructive intent",
        )
    }
    pub fn recheck(&self) -> Result<()> {
        // A full check of every retained package from the last second stands.
        if self.recent.fresh() {
            return Ok(());
        }
        self.recheck_full()?;
        self.recent.mark();
        Ok(())
    }
    fn recheck_full(&self) -> Result<()> {
        self.media.recheck()?;
        self.authority.recheck()?;
        self.images.recheck()?;
        for package in &self.native {
            let named = self.media.opened(&package.declaration.file)?;
            require(
                files::identity(&package.archive.metadata()?) == package.identity_pin
                    && files::identity(&named.metadata()?) == package.identity_pin
                    && mount_identity::id(package.archive.as_fd(), true)?
                        == mount_identity::id(named.as_fd(), true)?,
                "retained admitted native payload identity changed",
            )?;
        }
        for package in &self.packages {
            for (path, file, identity) in [
                (
                    format!("packages/{}", package.filename),
                    &package.archive,
                    &package.archive_identity,
                ),
                (
                    format!("packages/{}.sig", package.filename),
                    &package.signature,
                    &package.signature_identity,
                ),
            ] {
                let named = self.media.opened(&path)?;
                require(
                    files::identity(&file.metadata()?) == *identity
                        && files::identity(&named.metadata()?) == *identity
                        && mount_identity::id(file.as_fd(), true)?
                            == mount_identity::id(named.as_fd(), true)?,
                    "retained admitted package or signature identity changed",
                )?;
            }
        }
        require(
            json::decode(
                &files::read(
                    &self.work.join("admission.json"),
                    1024 * 1024,
                    Some(0),
                    true,
                )?,
                1024 * 1024,
            )? == self.receipt,
            "offline media admission receipt changed",
        )?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error("installer clock before epoch".into()))?
            .as_millis();
        let now = u64::try_from(now).map_err(|_| Error("installer clock overflow".into()))?;
        media_plan::manifest(&self.manifest, &self.media.members, now)
    }
}
