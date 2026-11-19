// SPDX-License-Identifier: MIT
//! Retain the read-only ISO actually used by this live boot.
use crate::{live_context, media_manifest};
use enzimos_platform::{
    Error, Result, files, json, mount_identity, mountinfo, require, stream_copy,
};
use enzimos_policy::{storage_runtime, topology};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const ROOT: &str = "/run/enzimos-live/media";
/// Media directories whose `repo/` is an OSTree sideload repository (one per remote).
pub(crate) const SIDELOAD_DIRECTORIES: [&str; 2] = ["flatpak", "flatpak-enzimos"];
pub struct Media {
    root: File,
    directory: File,
    identity: files::FileIdentity,
    mount: u64,
    row: mountinfo::Row,
    graph: topology::Graph,
    manifest: File,
    manifest_identity: files::FileIdentity,
    bytes: Vec<u8>,
    pub(crate) members: BTreeMap<String, String>,
    pub manifest_sha256: String,
}
impl Media {
    pub fn open() -> Result<Self> {
        live_context::observe()?;
        let rows = storage_runtime::rows()?;
        let root = files::directory(Path::new(ROOT), Some(0))?;
        let normal = mount_identity::id(root.as_fd(), false)?;
        let row = rows
            .iter()
            .find(|r| r.target == ROOT && r.id == normal)
            .ok_or_else(|| Error("live medium mount disappeared".into()))?
            .clone();
        let graph = topology::observe(&[(row.major, row.minor)])?;
        let directory = files::directory(Path::new(ROOT).join("enzimos").as_path(), Some(0))?;
        let mount = mount_identity::id(root.as_fd(), true)?;
        let manifest = files::open_relative(&directory, Path::new("SHA256SUMS"))?;
        let bytes = files::read_file(&manifest, media_manifest::MAX_MANIFEST, Some(0), true)?;
        let this = Self {
            identity: files::identity(&directory.metadata()?),
            manifest_identity: files::identity(&manifest.metadata()?),
            manifest_sha256: json::sha256(&bytes),
            members: media_manifest::parse(&bytes)?,
            root,
            directory,
            mount,
            row,
            graph,
            manifest,
            bytes,
        };
        this.recheck()?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs, fstatvfs).")]
    pub fn recheck(&self) -> Result<()> {
        live_context::observe()?;
        let named = files::directory(Path::new(ROOT), Some(0))?;
        let directory = files::directory(Path::new(ROOT).join("enzimos").as_path(), Some(0))?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let mut attributes: libc::statvfs = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::fstatfs(self.root.as_raw_fd(), &mut stat) } == 0
                && stat.f_type == 0x9660
                && unsafe { libc::fstatvfs(self.root.as_raw_fd(), &mut attributes) } == 0
                && attributes.f_flag & libc::ST_RDONLY != 0
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.root.as_fd(), true)? == self.mount
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount
                && mount_identity::id(directory.as_fd(), true)? == self.mount
                && files::identity(&directory.metadata()?) == self.identity
                && files::identity(&self.directory.metadata()?) == self.identity,
            "retained read-only installation medium changed",
        )?;
        require(
            storage_runtime::rows()?
                .iter()
                .filter(|r| r.target == ROOT)
                .collect::<Vec<_>>()
                == vec![&self.row]
                && topology::observe(&[(self.row.major, self.row.minor)])? == self.graph,
            "installation medium mount or physical disk sequence changed",
        )?;
        let named_manifest = files::open_relative(&self.directory, Path::new("SHA256SUMS"))?;
        require(
            files::identity(&named_manifest.metadata()?) == self.manifest_identity
                && files::identity(&self.manifest.metadata()?) == self.manifest_identity
                && mount_identity::id(named_manifest.as_fd(), true)? == self.mount
                && files::read_file(&self.manifest, media_manifest::MAX_MANIFEST, Some(0), true)?
                    == self.bytes,
            "installation media integrity record changed",
        )
    }
    pub(crate) fn opened(&self, path: &str) -> Result<File> {
        media_manifest::relative(path)?;
        // OSTree sideload repositories legitimately contain relative symlinks.
        // Kernel RESOLVE_BENEATH confines them to that retained repository only.
        let sideload = SIDELOAD_DIRECTORIES.iter().find_map(|directory| {
            path.strip_prefix(directory)
                .and_then(|rest| rest.strip_prefix("/repo/"))
                .map(|relative| (directory, relative))
        });
        let file = if let Some((directory, relative)) = sideload {
            let repo = files::directory(
                Path::new(ROOT)
                    .join("enzimos")
                    .join(directory)
                    .join("repo")
                    .as_path(),
                Some(0),
            )?;
            require(
                mount_identity::id(repo.as_fd(), true)? == self.mount,
                "sideload repository mount differs",
            )?;
            repository_member(&repo, relative)?
        } else {
            files::open_relative(&self.directory, Path::new(path))?
        };
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && mount_identity::id(file.as_fd(), true)? == self.mount,
            "unsafe or substituted installation media member",
        )?;
        Ok(file)
    }
    pub fn member(&self, path: &str, max: u64) -> Result<File> {
        self.recheck()?;
        let digest = self
            .members
            .get(path)
            .ok_or_else(|| Error("installation media member absent from manifest".into()))?;
        let file = self.opened(path)?;
        require(
            stream_copy::hash_borrowed(&file, max, Some(0))?.1 == *digest,
            "installation media member digest mismatch",
        )?;
        self.recheck()?;
        Ok(file)
    }
    pub fn read(&self, path: &str, max: usize) -> Result<Vec<u8>> {
        let file = self.member(path, max as u64)?;
        files::read_file(&file, max, Some(0), true)
    }
    pub fn verify_manifest(&self) -> Result<u64> {
        self.recheck()?;
        let mut total = 0u64;
        let count = self.members.len();
        for (index, (path, digest)) in self.members.iter().enumerate() {
            if index > 0 && index % 100 == 0 {
                eprintln!("    checked {index}/{count} files on the medium");
            }
            let file = self.opened(path)?;
            let (bytes, actual) =
                stream_copy::hash_borrowed(&file, 16 * 1024u64 * 1024 * 1024, Some(0))?;
            total = total
                .checked_add(bytes)
                .ok_or_else(|| Error("installation media byte overflow".into()))?;
            require(
                total <= 256 * 1024u64 * 1024 * 1024 && actual == *digest,
                "installation media manifest digest or total byte bound",
            )?;
        }
        self.recheck()?;
        Ok(total)
    }
    pub fn physical_leaves(&self) -> &std::collections::BTreeSet<topology::Device> {
        &self.graph.leaves
    }
    pub(crate) fn descriptor(&self) -> &File {
        &self.directory
    }
    /// The sideload repository under one of [`SIDELOAD_DIRECTORIES`].
    pub(crate) fn repository(&self, directory: &str) -> Result<File> {
        self.recheck()?;
        require(
            SIDELOAD_DIRECTORIES.contains(&directory),
            "unregistered sideload repository",
        )?;
        let repo = files::directory_relative(
            &self.directory,
            &Path::new(directory).join("repo"),
            Some(0),
        )?;
        require(
            mount_identity::id(repo.as_fd(), true)? == self.mount,
            "original sideload repository mount differs",
        )?;
        Ok(repo)
    }
}
/// Permit repository-relative symlinks, but forbid escapes, magic links and
/// crossing even a bind mount. Failure has no path-based fallback.
#[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
pub fn repository_member(repo: &File, relative: &str) -> Result<File> {
    media_manifest::relative(relative)?;
    require(
        repo.metadata()?.is_dir(),
        "repository directory descriptor required",
    )?;
    let name =
        std::ffi::CString::new(relative).map_err(|_| Error("repository member encoding".into()))?;
    #[repr(C)]
    struct How {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = How {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: 0x08 | 0x02 | 0x01,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            repo.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<How>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd as i32) };
    require(
        file.metadata()?.is_file(),
        "regular repository member required",
    )?;
    Ok(file)
}
