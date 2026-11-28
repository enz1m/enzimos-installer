// SPDX-License-Identifier: MIT
//! One original disk and operation-lock lifetime across installation phases.
use crate::{answer_source::Source, disk_guard::Disk};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use std::{
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
pub(crate) const LOCK: &str = "/run/enzimos-install.lock";
pub(crate) struct Session {
    disk: Disk,
    lock: files::Lock,
    identity: files::FileIdentity,
    mount: u64,
}
#[allow(unsafe_code, reason = "Linux syscall ABI (flock).")]
pub(crate) fn recheck_lock(
    lock: &files::Lock,
    identity: &files::FileIdentity,
    mount: u64,
) -> Result<()> {
    let held = lock.as_file();
    let directory = files::directory(Path::new("/run"), Some(0))?;
    let named = files::open_relative(&directory, Path::new("enzimos-install.lock"))?;
    let metadata = held.metadata()?;
    require(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o7777 == 0o600
            && metadata.nlink() == 1
            && metadata.len() == 0
            && files::identity(&metadata) == *identity
            && files::identity(&named.metadata()?) == *identity
            && mount_identity::id(held.as_fd(), true)? == mount
            && mount_identity::id(named.as_fd(), true)? == mount,
        "original installer operation lock changed",
    )?;
    enzimos_platform::flock_identity::exclusive(held)?;
    let acquired = unsafe { libc::flock(named.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    let error = std::io::Error::last_os_error();
    require(
        acquired == -1 && error.raw_os_error() == Some(libc::EWOULDBLOCK),
        "original installer lock no longer excludes another description",
    )?;
    enzimos_platform::flock_identity::exclusive(held)
}
impl Session {
    pub(crate) fn open(source: &Source) -> Result<Self> {
        crate::setup::live()?;
        source.recheck()?;
        let disk = Disk::open(&source.answers.disk)
            .map_err(|error| Error(format!("installer original-disk admission: {error}")))?;
        let lock = files::Lock::acquire(Path::new(LOCK), 0)
            .map_err(|error| Error(format!("installer original-operation lock: {error}")))?;
        Self::from_parts(source, disk, lock)
    }
    pub(crate) fn with_lock(source: &Source, lock: files::Lock) -> Result<Self> {
        crate::setup::live()?;
        source.recheck()?;
        lock.recheck()?;
        let disk = Disk::open(&source.answers.disk)
            .map_err(|error| Error(format!("installer original-disk admission: {error}")))?;
        Self::from_parts(source, disk, lock)
    }
    fn from_parts(source: &Source, disk: Disk, lock: files::Lock) -> Result<Self> {
        review_disk(
            &source.answers.disk,
            source.answers.disk_sequence,
            disk.sequence()?,
        )?;
        let identity = files::identity(&lock.as_file().metadata()?);
        let mount = mount_identity::id(lock.as_file().as_fd(), true)?;
        let session = Self {
            disk,
            lock,
            identity,
            mount,
        };
        session.recheck(source)?;
        Ok(session)
    }
    pub(crate) fn recheck(&self, source: &Source) -> Result<()> {
        source.recheck()?;
        // Answers may name the disk by a stable /dev/disk/by-* link; the held
        // disk records the canonical node it resolved to.
        require(
            std::fs::canonicalize(&source.answers.disk)? == self.disk.path,
            "installation disk selection changed",
        )?;
        recheck_lock(&self.lock, &self.identity, self.mount)?;
        self.disk.recheck()
    }
    pub(crate) fn disk(&self) -> &Disk {
        &self.disk
    }
    pub(crate) fn into_parts(self) -> (Disk, files::Lock, files::FileIdentity, u64) {
        (self.disk, self.lock, self.identity, self.mount)
    }
}

fn review_disk(path: &str, reviewed: Option<u64>, current: u64) -> Result<()> {
    let stable_id = Path::new(path).parent() == Some(Path::new("/dev/disk/by-id"));
    require(
        reviewed.map_or(stable_id, |sequence| sequence == current),
        "disk selection changed or lacks an identity. Select the disk again or use a /dev/disk/by-id path for unattended installation",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reused_kernel_device_name_does_not_inherit_confirmation() {
        assert!(review_disk("/dev/vda", Some(7), 7).is_ok());
        assert!(review_disk("/dev/vda", Some(7), 8).is_err());
        assert!(review_disk("/dev/vda", None, 7).is_err());
        assert!(review_disk("/dev/disk/by-path/pci-fixture", None, 7).is_err());
        assert!(review_disk("/dev/disk/by-id/virtio-target", None, 7).is_ok());
        assert!(review_disk("/dev/disk/by-id/virtio-target", Some(7), 8).is_err());
    }
}
