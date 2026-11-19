// SPDX-License-Identifier: MIT
//! Owned chroot pseudo-filesystems, normally unwound in reverse order.
use crate::setup;
use enzimos_platform::{Error, Result, files, mount_identity, mountinfo, require};
use enzimos_policy::{namespaces, storage_runtime};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
const TARGET: &str = "/mnt/enzimos";
fn magic(kind: &str) -> Result<libc::c_long> {
    match kind {
        "tmpfs" | "devtmpfs" => Ok(0x01021994),
        "devpts" => Ok(0x1cd1),
        "mqueue" => Ok(0x19800202),
        "hugetlbfs" => Ok(0x958458f6),
        "proc" => Ok(0x9fa0),
        "sysfs" => Ok(0x62656572),
        "efivarfs" => Ok(0xde5e81e4),
        _ => Err(Error("unreviewed chroot filesystem type".into())),
    }
}
fn identity(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn opened(path: &Path) -> Result<File> {
    let parent = files::directory(
        path.parent()
            .ok_or_else(|| Error("chroot mount parent missing".into()))?,
        Some(0),
    )?;
    let name = CString::new(
        path.file_name()
            .ok_or_else(|| Error("chroot mount leaf missing".into()))?
            .as_encoded_bytes(),
    )
    .unwrap();
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(raw >= 0, "chroot mount descriptor unavailable")?;
    Ok(unsafe { File::from_raw_fd(raw) })
}
/// Kernel-created sysfs directories are normally 0555. They are mount
/// destinations, not directories which the installer may chmod or recreate.
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn kernel_sysfs_target(file: &File, original_mount: u64) -> Result<()> {
    let metadata = file.metadata()?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o022 == 0
            && unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } == 0
            && stat.f_type == magic("sysfs")?
            && mount_identity::id(file.as_fd(), true)? == original_mount,
        "EFI target must remain in the original owned kernel sysfs mount",
    )
}
struct Mounted {
    path: PathBuf,
    file: Option<File>,
    unique: u64,
    identity: (u64, u64, u32, u32, u32),
    row: mountinfo::Row,
    _underlying: Option<File>,
}
impl Mounted {
    fn capture(path: &Path, underlying: Option<File>) -> Result<Self> {
        let file = opened(path)?;
        let normal = mount_identity::id(file.as_fd(), false)?;
        let unique = mount_identity::id(file.as_fd(), true)?;
        let rows = storage_runtime::rows()?;
        let row = rows
            .iter()
            .find(|r| r.id == normal && r.target == path.to_str().unwrap())
            .ok_or_else(|| Error("new chroot mount record missing".into()))?
            .clone();
        let this = Self {
            path: path.into(),
            identity: identity(&file)?,
            file: Some(file),
            unique,
            row,
            _underlying: underlying,
        };
        this.recheck(&rows)?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
    fn recheck(&self, rows: &[mountinfo::Row]) -> Result<()> {
        let held = self
            .file
            .as_ref()
            .ok_or_else(|| Error("chroot mount descriptor closed".into()))?;
        let current = opened(&self.path)?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        require(
            self.identity.2 == 0
                && identity(held)? == self.identity
                && identity(&current)? == self.identity
                && mount_identity::id(held.as_fd(), true)? == self.unique
                && mount_identity::id(current.as_fd(), true)? == self.unique
                && rows.iter().filter(|r| r.target == self.row.target).count() == 1
                && rows.contains(&self.row)
                && !self.row.optional.iter().any(|s| s.starts_with("shared:"))
                && unsafe { libc::fstatfs(held.as_raw_fd(), &mut stat) } == 0
                && stat.f_type == magic(&self.row.filesystem)?,
            "owned chroot mount replaced or changed",
        )
    }
}
#[derive(Default)]
pub(crate) struct Mounts {
    mounts: Vec<Mounted>,
    uncertain: Option<PathBuf>,
}
pub fn clone_layout(source: &[mountinfo::Row], actual: &[mountinfo::Row]) -> Result<()> {
    require(
        !source.is_empty() && source.len() <= 64 && source.len() == actual.len(),
        "device tree clone count differs",
    )?;
    for row in source {
        require(
            (row.target == "/dev" || row.target.starts_with("/dev/"))
                && matches!(
                    row.filesystem.as_str(),
                    "devtmpfs" | "tmpfs" | "devpts" | "mqueue" | "hugetlbfs"
                ),
            "device tree contains an unreviewed filesystem",
        )?;
        let target = format!("{TARGET}{}", row.target);
        let matches = actual
            .iter()
            .filter(|r| r.target == target)
            .collect::<Vec<_>>();
        require(
            matches.len() == 1
                && matches[0].id != row.id
                && matches[0].root == row.root
                && matches[0].filesystem == row.filesystem
                && matches[0].major == row.major
                && matches[0].minor == row.minor
                && matches[0].options == row.options
                && matches[0].optional.is_empty(),
            "device tree clone differs from its kernel source",
        )?;
    }
    Ok(())
}
impl Mounts {
    pub(crate) fn rows(&self) -> Vec<mountinfo::Row> {
        self.mounts.iter().map(|m| m.row.clone()).collect()
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        setup::live()?;
        namespaces::initial()?;
        require(
            self.uncertain.is_none() && self.mounts.len() <= 96,
            "chroot mount tracking uncertain; retain for inspection",
        )?;
        let rows = storage_runtime::rows()?;
        for mount in &self.mounts {
            mount.recheck(&rows)?;
        }
        Ok(())
    }
    fn target(&self, path: &Path) -> Result<File> {
        require(
            path.starts_with(TARGET) && path != Path::new(TARGET),
            "fixed chroot mount destination required",
        )?;
        let held = if path == Path::new("/mnt/enzimos/sys/firmware/efi/efivars") {
            let sys = self
                .mounts
                .iter()
                .find(|m| m.path == Path::new("/mnt/enzimos/sys") && m.row.filesystem == "sysfs")
                .ok_or_else(|| Error("EFI target has no original owned sysfs mount".into()))?;
            sys.recheck(&storage_runtime::rows()?)?;
            let root = sys
                .file
                .as_ref()
                .ok_or_else(|| Error("original sysfs descriptor retired".into()))?;
            let target =
                files::directory_relative(root, Path::new("firmware/efi/efivars"), Some(0))?;
            kernel_sysfs_target(&target, sys.unique)?;
            target
        } else {
            files::ensure_directory(path, 0o755, 0)?
        };
        require(
            std::fs::read_dir(path)?.next().is_none()
                && !storage_runtime::rows()?.iter().any(|r| {
                    r.target == path.to_str().unwrap()
                        || r.target.starts_with(&format!("{}/", path.display()))
                }),
            "chroot mount target occupied",
        )?;
        Ok(held)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (mount).")]
    fn devices(&mut self) -> Result<()> {
        self.recheck()?;
        let source_rows = storage_runtime::rows()?
            .into_iter()
            .filter(|r| r.target == "/dev" || r.target.starts_with("/dev/"))
            .collect::<Vec<_>>();
        require(
            source_rows.iter().filter(|r| r.target == "/dev").count() == 1
                && source_rows.len() <= 64,
            "kernel device tree mount boundary missing",
        )?;
        for row in &source_rows {
            require(
                matches!(
                    row.filesystem.as_str(),
                    "devtmpfs" | "tmpfs" | "devpts" | "mqueue" | "hugetlbfs"
                ),
                "unreviewed device tree mount refused",
            )?;
        }
        let source = files::directory(Path::new("/dev"), Some(0))?;
        let source_unique = mount_identity::id(source.as_fd(), true)?;
        let path = Path::new("/mnt/enzimos/dev");
        let underlying = self.target(path)?;
        let from = CString::new(format!("/proc/self/fd/{}", source.as_raw_fd())).unwrap();
        let into = CString::new(format!("/proc/self/fd/{}/.", underlying.as_raw_fd())).unwrap();
        require(
            unsafe {
                libc::mount(
                    from.as_ptr(),
                    into.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_REC,
                    std::ptr::null(),
                )
            } == 0,
            "chroot device tree clone failed",
        )?;
        self.uncertain = Some(path.into());
        let root = opened(path)?;
        require(
            mount_identity::id(root.as_fd(), true)? != source_unique,
            "device tree clone reused source mount",
        )?;
        let root_path = CString::new(format!("/proc/self/fd/{}/.", root.as_raw_fd())).unwrap();
        require(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    root_path.as_ptr(),
                    std::ptr::null(),
                    libc::MS_PRIVATE | libc::MS_REC,
                    std::ptr::null(),
                )
            } == 0,
            "chroot device mounts cannot be made private",
        )?;
        drop(root);
        let rows = storage_runtime::rows()?;
        let mut actual = rows
            .iter()
            .filter(|r| r.target == "/mnt/enzimos/dev" || r.target.starts_with("/mnt/enzimos/dev/"))
            .cloned()
            .collect::<Vec<_>>();
        clone_layout(&source_rows, &actual)?;
        let current = rows
            .into_iter()
            .filter(|r| r.target == "/dev" || r.target.starts_with("/dev/"))
            .collect::<Vec<_>>();
        require(
            current == source_rows,
            "source device tree changed during clone",
        )?;
        actual.sort_by_key(|r| (r.target.matches('/').count(), r.target.clone()));
        let mut underlying = Some(underlying);
        for row in actual {
            self.mounts.push(Mounted::capture(
                Path::new(&row.target),
                if row.target == "/mnt/enzimos/dev" {
                    underlying.take()
                } else {
                    None
                },
            )?);
        }
        self.uncertain = None;
        self.recheck()
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (mount).")]
    fn filesystem(&mut self, path: &Path, kind: &str, options: &str) -> Result<()> {
        self.recheck()?;
        require(
            matches!(kind, "proc" | "sysfs" | "tmpfs" | "efivarfs"),
            "fixed chroot pseudo-filesystem required",
        )?;
        let underlying = self
            .target(path)
            .map_err(|error| Error(format!("chroot {kind} target: {error}")))?;
        let destination =
            CString::new(format!("/proc/self/fd/{}/.", underlying.as_raw_fd())).unwrap();
        let kind = CString::new(kind).unwrap();
        let options = CString::new(options).unwrap();
        require(
            unsafe {
                libc::mount(
                    kind.as_ptr(),
                    destination.as_ptr(),
                    kind.as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    options.as_ptr().cast(),
                )
            } == 0,
            "chroot pseudo-filesystem mount failed",
        )?;
        self.uncertain = Some(path.into());
        self.mounts.push(Mounted::capture(path, Some(underlying))?);
        self.uncertain = None;
        self.recheck()
    }
    pub(crate) fn open(&mut self) -> Result<()> {
        require(
            self.mounts.is_empty() && self.uncertain.is_none(),
            "chroot environment cannot be restarted",
        )?;
        self.devices()?;
        self.filesystem(Path::new("/mnt/enzimos/proc"), "proc", "")?;
        self.filesystem(Path::new("/mnt/enzimos/sys"), "sysfs", "")?;
        self.filesystem(
            Path::new("/mnt/enzimos/run"),
            "tmpfs",
            "mode=0755,size=512m",
        )?;
        match std::fs::symlink_metadata("/sys/firmware/efi/efivars") {
            Ok(metadata) => {
                require(
                    metadata.is_dir(),
                    "kernel EFI variable mount boundary changed",
                )?;
                self.filesystem(
                    Path::new("/mnt/enzimos/sys/firmware/efi/efivars"),
                    "efivarfs",
                    "",
                )?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (umount2).")]
    pub(crate) fn close(&mut self) -> Result<()> {
        self.recheck()?;
        while let Some(mount) = self.mounts.last_mut() {
            mount.recheck(&storage_runtime::rows()?)?;
            let target = CString::new(mount.path.as_os_str().as_encoded_bytes()).unwrap();
            mount.file.take();
            if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
                let current = opened(&mount.path)?;
                require(
                    identity(&current)? == mount.identity
                        && mount_identity::id(current.as_fd(), true)? == mount.unique,
                    "failed chroot unmount encountered replacement",
                )?;
                mount.file = Some(current);
                return Err(Error("normal chroot unmount failed; mount retained".into()));
            }
            require(
                !storage_runtime::rows()?
                    .iter()
                    .any(|r| r.id == mount.row.id || r.target == mount.row.target),
                "normal chroot unmount not observed",
            )?;
            self.mounts.pop();
        }
        Ok(())
    }
}

#[cfg(test)]
mod kernel_target_tests {
    use super::*;
    #[test]
    fn read_only_kernel_directory_is_retained_without_chmod_or_adopting_another_mount() {
        let parent = files::directory(Path::new("/sys"), Some(0)).unwrap();
        let target = files::directory_relative(&parent, Path::new("firmware"), Some(0)).unwrap();
        let before = identity(&target).unwrap();
        let unique = mount_identity::id(parent.as_fd(), true).unwrap();
        kernel_sysfs_target(&target, unique).unwrap();
        assert_eq!(identity(&target).unwrap(), before);
        assert!(kernel_sysfs_target(&target, unique + 1).is_err());
        let other = files::directory(Path::new("/dev"), Some(0)).unwrap();
        assert!(
            kernel_sysfs_target(&other, mount_identity::id(other.as_fd(), true).unwrap()).is_err()
        );
    }
}
