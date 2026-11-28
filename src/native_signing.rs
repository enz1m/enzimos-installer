// SPDX-License-Identifier: MIT
//! Prepare locally signed native development packages without publishing target trust.
use crate::{media_packages::Admitted, package_handoff::Received};
use enzimos_platform::{
    Result, files, json, memfile, mount_identity, process, require, stream_copy,
};
use enzimos_policy::{
    authority, authority_build,
    development_signer::{Signer, verify_local},
    package_archive,
};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::symlink},
    path::{Path, PathBuf},
    time::Duration,
};

pub struct Signed {
    pub file: String,
    pub archive: File,
    pub signature: File,
    pub identity: Value,
    pub sha256: String,
    max_bytes: u64,
    media_path: Option<PathBuf>,
}
pub struct Prepared {
    pub directory: PathBuf,
    pub packages: Vec<Signed>,
    pub authority: authority_build::Prepared,
    pub fingerprint: String,
    pub receipt: Value,
}
fn import(home: &Path, public: &[u8]) -> Result<()> {
    let ring = memfile::sealed("enzimos-development-public-key", public)?;
    let output = process::run_with_fds(
        "/usr/bin/gpg",
        &[
            "--no-options",
            "--homedir",
            home.to_str().unwrap(),
            "--batch",
            "--no-tty",
            "--no-autostart",
            "--no-auto-key-retrieve",
            "--auto-key-locate",
            "clear",
            "--import",
            "@fd:0",
        ],
        &[],
        Duration::from_secs(60),
        65536,
        &[ring.as_fd()],
    )?;
    require(
        output.status.success(),
        "machine-local public development key import failed",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
pub fn prepare(context: &Received, media: &Admitted) -> Result<Prepared> {
    context.recheck()?;
    media.recheck()?;
    media.signing_capacity()?;
    let work = Path::new("/run/enzimos-install-native").join(format!(
        "native-{}",
        context.request["id"].as_str().unwrap()
    ));
    let directory = files::create_directory(&work, 0o700, 0)?;
    // The only private key is born on live RAM; nothing in this stage enters
    // the target authority or grants production release signing privileges.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    use std::os::fd::AsRawFd;
    require(
        unsafe { libc::fstatfs(directory.as_raw_fd(), &mut stat) } == 0
            && stat.f_type == 0x01021994,
        "ephemeral development signing must remain on live RAM",
    )?;
    let home = work.join("signer");
    let mut signer = Signer::create(&home, 0)?;
    context.recheck()?;
    media.recheck()?;
    let public = signer.public()?;
    let current = work.join("current");
    files::create_directory(&current, 0o700, 0)?;
    for (name, bytes) in media.authority.files() {
        files::atomic_bounded(
            &current.join(&name),
            &bytes,
            if name == "gpg.conf" { 0o644 } else { 0o600 },
            Some(0),
            false,
            8 * 1024 * 1024,
        )?;
    }
    import(&current, &public)?;
    authority_build::gpg(
        &current,
        &["--import-ownertrust"],
        format!("{}:5:\n", signer.fingerprint).as_bytes(),
    )?;
    let authority = authority_build::build(
        &current,
        Path::new("/usr/share/pacman/keyrings"),
        &work.join("review"),
        0,
    )?;
    require(
        authority.approved == media.authority.approved
            && authority.local == vec![signer.fingerprint.clone()],
        "native development authority differs from approved Arch quorum plus this machine's new key",
    )?;
    let packages_directory = work.join("packages");
    let parent = files::create_directory(&packages_directory, 0o700, 0)?;
    let mut packages = Vec::new();
    for package in &media.native {
        context.recheck()?;
        media.recheck()?;
        authority.recheck()?;
        let name = Path::new(&package.declaration.file);
        let media_path = package
            .read_from_media()
            .then(|| crate::media_source::member_path(&package.declaration.file));
        let archive = if let Some(path) = &media_path {
            // Pacman finds the detached signature alongside the private symlink.
            symlink(path, packages_directory.join(name))?;
            package.archive.try_clone()?
        } else {
            let mut source = package.archive.try_clone()?;
            stream_copy::verified(
                &mut source,
                &parent,
                &package.declaration.file,
                package.archive.metadata()?.len(),
                &package.declaration.sha256,
                0,
            )?;
            let archive = files::open_relative(&parent, name)?;
            require(
                package_archive::identity(&archive)? == package.identity,
                "copied native package identity changed",
            )?;
            archive
        };
        let signature_name = format!("{}.sig", package.declaration.file);
        signer.sign(&archive, &packages_directory.join(&signature_name))?;
        let signature = files::open_relative(&parent, Path::new(&signature_name))?;
        verify_local(
            &archive,
            &signature,
            &authority.directory,
            &signer.fingerprint,
        )?;
        packages.push(Signed {
            file: package.declaration.file.clone(),
            archive,
            signature,
            identity: package.identity.clone(),
            sha256: package.declaration.sha256.clone(),
            max_bytes: package.declaration.max_bytes,
            media_path,
        });
    }
    context.recheck()?;
    media.recheck()?;
    authority.recheck()?;
    signer.retire()?;
    let fingerprint = signer.fingerprint.clone();
    require(
        authority_build::gpg(&authority.directory, &["--list-secret-keys"], &[])?.is_empty(),
        "native installation verification authority must be public-only",
    )?;
    let receipt = value!({"schema":1,"operation":"native-development-package-signing",
        "request_sha256":json::fingerprint(&context.request)?,"media_manifest_sha256":media.media.manifest_sha256,
        "development_artifact":true,"release_authorized":false,"private_key_retired":true,
        "local_signer":fingerprint,"authority_sha256":authority.hashes(),
        "packages":packages.iter().map(|p| value!({"file":p.file,"identity":p.identity,"sha256":p.sha256})).collect::<Vec<_>>()});
    files::atomic(
        &work.join("prepared.json"),
        &json::canonical(&receipt)?,
        0o600,
        Some(0),
        false,
    )?;
    context.recheck()?;
    media.recheck()?;
    authority.recheck()?;
    Ok(Prepared {
        directory: packages_directory,
        packages,
        authority,
        fingerprint,
        receipt,
    })
}
impl Prepared {
    pub fn recheck(&self, context: &Received, media: &Admitted) -> Result<()> {
        context.recheck()?;
        media.recheck()?;
        self.authority.recheck()?;
        let parent = files::directory(&self.directory, Some(0))?;
        for package in &self.packages {
            let named = if let Some(path) = &package.media_path {
                let archive = self.directory.join(&package.file);
                require(
                    std::fs::read_link(&archive)? == *path,
                    "native archive symlink differs from the admitted media path",
                )?;
                File::open(archive)?
            } else {
                files::open_relative(&parent, Path::new(&package.file))?
            };
            let signature =
                files::open_relative(&parent, Path::new(&format!("{}.sig", package.file)))?;
            require(
                files::identity(&named.metadata()?)
                    == files::identity(&package.archive.metadata()?)
                    && mount_identity::id(named.as_fd(), true)?
                        == mount_identity::id(package.archive.as_fd(), true)?
                    && files::identity(&signature.metadata()?)
                        == files::identity(&package.signature.metadata()?)
                    && stream_copy::hash_borrowed(&package.archive, package.max_bytes, Some(0))?.1
                        == package.sha256,
                "prepared native archive or signature changed",
            )?;
            verify_local(
                &package.archive,
                &package.signature,
                &self.authority.directory,
                &self.fingerprint,
            )?;
        }
        let receipt = self.directory.parent().unwrap().join("prepared.json");
        require(
            json::decode(
                &files::read(&receipt, 1024 * 1024, Some(0), true)?,
                1024 * 1024,
            )? == self.receipt,
            "native package signing receipt changed",
        )
    }
    pub fn materials(&self) -> std::collections::BTreeMap<String, Vec<u8>> {
        // The final config forbids automatic trust-database mutation during pacman.
        let mut files = self.authority.files();
        files.insert(
            "gpg.conf".into(),
            format!("{}no-auto-check-trustdb\n", authority::CONFIG).into_bytes(),
        );
        files
    }
}
