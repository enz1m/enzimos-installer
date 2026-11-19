// SPDX-License-Identifier: MIT
//! Boot-local ownership of a newly opened LUKS2 mapping. Never adopts a name.
use crate::{answer_source::Source, disk_guard::Disk, format::PartitionFile};
use enzimos_platform::{Error, Result, files, mount_identity, process, require};
use enzimos_policy::{block, topology};
use serde_json::Value;
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::Duration,
};

pub(crate) struct Mapper {
    file: Option<File>,
    canonical: PathBuf,
    name: String,
    uuid: String,
    epoch: Option<std::sync::Arc<crate::device_epoch::Epoch>>,
    mount: u64,
    observation: Value,
    graph: topology::Graph,
    pub number: topology::Device,
}
pub fn kernel_uuid(luks: &str, name: &str) -> Result<String> {
    enzimos_policy::identity::uuid(luks)?;
    require(
        name.len() == 48
            && name.starts_with("enzimos-install-")
            && name[16..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "private installation mapper name required",
    )?;
    Ok(format!("CRYPT-LUKS2-{}-{name}", luks.replace('-', "")))
}
fn text(path: &Path) -> Result<String> {
    let bytes = files::read_kernel(path, 4096)?;
    Ok(std::str::from_utf8(&bytes)
        .map_err(|_| Error("mapper kernel identity encoding".into()))?
        .trim()
        .to_owned())
}
impl Mapper {
    #[allow(unsafe_code, reason = "Linux syscall ABI (major, minor, openat).")]
    pub(crate) fn open(
        source: &Source,
        disk: &Disk,
        partition: &PartitionFile,
        luks: &str,
        name: &str,
    ) -> Result<Self> {
        let uuid = kernel_uuid(luks, name)?;
        let named = Path::new("/dev/mapper").join(name);
        files::directory(Path::new("/dev/mapper"), Some(0))?;
        require(
            matches!(std::fs::symlink_metadata(&named), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "installation mapper name already exists",
        )?;
        source.recheck()?;
        partition.recheck(disk)?;
        let passphrase = source
            .answers
            .passphrase
            .as_ref()
            .ok_or_else(|| Error("encryption passphrase missing".into()))?;
        let partition_write = partition.begin_write("luks-mapper-open")?;
        let output = process::run_with_fds(
            "/usr/bin/cryptsetup",
            &[
                "open",
                "--type",
                "luks2",
                "--disable-keyring",
                "--disable-external-tokens",
                "--key-file",
                "-",
                "@fd:0",
                name,
            ],
            passphrase.as_bytes(),
            Duration::from_secs(120),
            65536,
            &[partition.descriptor()],
        )?;
        // An uncertain open is retained for inspection, never blindly closed by name.
        require(
            output.status.success(),
            "mapper open failed; inspect this non-replayable attempt",
        )?;
        let partition_write = partition_write.settle()?;
        source.recheck()?;
        let canonical = std::fs::canonicalize(&named)?;
        require(
            canonical.parent() == Some(Path::new("/dev"))
                && canonical
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| {
                        s.strip_prefix("dm-")
                            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                    }),
            "mapper escaped canonical kernel device",
        )?;
        let parent = files::directory(Path::new("/dev"), Some(0))?;
        let leaf =
            std::ffi::CString::new(canonical.file_name().unwrap().as_encoded_bytes()).unwrap();
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(raw >= 0, "opened mapper descriptor unavailable")?;
        let file = unsafe { File::from_raw_fd(raw) };
        let metadata = file.metadata()?;
        let number = (libc::major(metadata.rdev()), libc::minor(metadata.rdev()));
        let graph = topology::observe(&[number])?;
        let observation = block::observe(file.as_fd())?;
        require(
            observation["read_only"] == false
                && observation["bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= 19 * 1024u64 * 1024 * 1024),
            "mapped root size or access refused",
        )?;
        require(
            graph.leaves == std::collections::BTreeSet::from([disk.number])
                && graph.nodes[&number].dependencies == [partition.number()?]
                && text(&graph.nodes[&number].path.join("dm/name"))? == name
                && text(&graph.nodes[&number].path.join("dm/uuid"))? == uuid,
            "new mapping does not belong to this original opening operation",
        )?;
        source.recheck()?;
        partition.observed_write(partition_write)?;
        let this = Self {
            mount: mount_identity::id(file.as_fd(), true)?,
            epoch: Some(crate::device_epoch::Epoch::capture(&file)?),
            file: Some(file),
            canonical,
            name: name.into(),
            uuid,
            number,
            graph,
            observation,
        };
        this.recheck(source, disk, partition)?;
        Ok(this)
    }
    pub(crate) fn recheck(
        &self,
        source: &Source,
        disk: &Disk,
        partition: &PartitionFile,
    ) -> Result<()> {
        self.identity(source, disk, partition)?;
        disk.idle_owned(partition.number()?, self.number)?;
        Ok(())
    }
    pub(crate) fn descriptor(&self) -> Result<std::os::fd::BorrowedFd<'_>> {
        Ok(self
            .file
            .as_ref()
            .ok_or_else(|| Error("mapper descriptor already closed".into()))?
            .as_fd())
    }
    pub(crate) fn identity(
        &self,
        source: &Source,
        disk: &Disk,
        partition: &PartitionFile,
    ) -> Result<()> {
        source.recheck()?;
        partition.identity(disk)?;
        self.original_identity_with_write(None)
    }
    pub(crate) fn original_identity_with_write(
        &self,
        write: Option<&crate::device_epoch::Write>,
    ) -> Result<()> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| Error("mapper descriptor already closed".into()))?;
        let epoch = self
            .epoch
            .as_ref()
            .ok_or_else(|| Error("mapper epoch already retired".into()))?;
        let inode = if let Some(write) = write {
            write.for_epoch(epoch)?;
            write.checkpoint()?;
            files::identity(&file.metadata()?)
        } else {
            epoch.recheck()?;
            epoch.snapshot()?
        };
        let node = &self.graph.nodes[&self.number].path;
        require(
            std::fs::canonicalize(Path::new("/dev/mapper").join(&self.name))? == self.canonical
                && files::identity(&std::fs::symlink_metadata(&self.canonical)?) == inode
                && files::identity(&file.metadata()?) == inode
                && mount_identity::id(file.as_fd(), true)? == self.mount
                && block::observe(file.as_fd())? == self.observation
                && topology::observe(&[self.number])? == self.graph
                && text(&node.join("dm/name"))? == self.name
                && text(&node.join("dm/uuid"))? == self.uuid,
            "retained mapper identity changed",
        )?;
        Ok(())
    }
    pub(crate) fn begin_bios_events(&self) -> Result<crate::device_epoch::Write> {
        self.original_identity_with_write(None)?;
        self.epoch
            .as_ref()
            .ok_or_else(|| Error("mapper epoch retired".into()))?
            .begin("bios-device-events")
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    pub(crate) fn observe_bios_events(&self, write: crate::device_epoch::Write) -> Result<()> {
        let epoch = self
            .epoch
            .as_ref()
            .ok_or_else(|| Error("mapper epoch retired".into()))?;
        write.for_epoch(epoch)?;
        self.original_identity_with_write(Some(&write))?;
        let parent = files::directory(Path::new("/dev"), Some(0))?;
        let leaf =
            std::ffi::CString::new(self.canonical.file_name().unwrap().as_encoded_bytes()).unwrap();
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(raw >= 0, "original mapper event name unavailable")?;
        let named = unsafe { File::from_raw_fd(raw) };
        write.observed(&named)?;
        self.original_identity_with_write(None)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    pub(crate) fn run(
        &self,
        source: &Source,
        disk: &Disk,
        partition: &PartitionFile,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        self.recheck(source, disk, partition)?;
        let write = match program {
            "/usr/bin/mkfs.btrfs" => {
                Some(self.epoch.as_ref().unwrap().begin("mapped-root-format")?)
            }
            "/usr/bin/blkid" => None,
            _ => return Err(Error("mapped tool outside closed role registry".into())),
        };
        let result = process::run_with_fds(
            program,
            args,
            &[],
            timeout,
            65536,
            &[self.file.as_ref().unwrap().as_fd()],
        )?;
        require(
            result.status.success(),
            "mapped filesystem preparation failed; no automatic replay",
        )?;
        if let Some(write) = write {
            let write = write.settle()?;
            let parent = files::directory(Path::new("/dev"), Some(0))?;
            let leaf =
                std::ffi::CString::new(self.canonical.file_name().unwrap().as_encoded_bytes())
                    .unwrap();
            let raw = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            require(raw >= 0, "original written mapper name unavailable")?;
            let named = unsafe { File::from_raw_fd(raw) };
            require(
                topology::observe(&[self.number])? == self.graph,
                "written mapping physical ancestry or kernel epoch changed",
            )?;
            source.recheck()?;
            write.observed(&named)?;
        }
        self.recheck(source, disk, partition)?;
        Ok(result.stdout)
    }
    pub(crate) fn close(
        &mut self,
        source: &Source,
        disk: &Disk,
        partition: &PartitionFile,
    ) -> Result<()> {
        self.recheck(source, disk, partition)?;
        // Release our block opener before normal removal. The immutable kernel
        // UUID, including this attempt's random name, is the removal selector.
        self.file.take();
        // Epoch retains a duplicate of the original description. Both references
        // must retire before normal removal; a retained clone must not create EBUSY.
        self.epoch.take();
        let result = process::run(
            "/usr/bin/dmsetup",
            &["remove", "--uuid", &self.uuid],
            &[],
            Duration::from_secs(30),
            65536,
        )?;
        require(
            result.status.success(),
            "owned mapper remains busy; installation is incomplete",
        )?;
        require(
            matches!(std::fs::symlink_metadata(&self.graph.nodes[&self.number].path), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "owned mapper removal not observed",
        )?;
        partition.recheck(disk)?;
        source.recheck()
    }
}
