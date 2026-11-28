// SPDX-License-Identifier: MIT
//! Format only the exact partitions from this boot's successful native erase.
use crate::{answer_source::Source, disk_guard::Disk, erase};
use enzimos_platform::{Error, Result, files, json, mount_identity, process, require};
use enzimos_policy::{block, topology};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::Duration,
};
pub(crate) struct PartitionFile {
    file: File,
    path: PathBuf,
    epoch: std::sync::Arc<crate::device_epoch::Epoch>,
    mount: u64,
    observation: Value,
    graph: topology::Graph,
}
impl PartitionFile {
    #[allow(unsafe_code, reason = "Linux syscall ABI (major, minor, openat).")]
    pub(crate) fn open(disk: &Disk, path: &str, number: u32, bytes: u64) -> Result<Self> {
        crate::answers::disk_path(path)?;
        let path = PathBuf::from(path);
        require(
            path.parent() == Some(Path::new("/dev")),
            "canonical new partition required",
        )?;
        let parent = files::directory(Path::new("/dev"), Some(0))?;
        let name = std::ffi::CString::new(path.file_name().unwrap().as_encoded_bytes()).unwrap();
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(raw >= 0, "new partition unavailable")?;
        let file = unsafe { File::from_raw_fd(raw) };
        let observation = block::observe(file.as_fd())?;
        require(
            observation["bytes"] == bytes && observation["read_only"] == false,
            "new partition size or access changed",
        )?;
        let metadata = file.metadata()?;
        let dev = (libc::major(metadata.rdev()), libc::minor(metadata.rdev()));
        let graph = topology::observe(&[dev])?;
        require(
            graph.leaves == BTreeSet::from([disk.number])
                && graph.nodes[&dev].dependencies == [disk.number],
            "new partition physical ancestry changed",
        )?;
        let partn = files::read_kernel(&graph.nodes[&dev].path.join("partition"), 4096)?;
        require(
            std::str::from_utf8(&partn).is_ok_and(|s| s.trim() == number.to_string()),
            "new partition kernel number changed",
        )?;
        let this = Self {
            mount: mount_identity::id(file.as_fd(), true)?,
            epoch: crate::device_epoch::Epoch::capture(&file)?,
            file,
            path,
            observation,
            graph,
        };
        this.recheck(disk)?;
        Ok(this)
    }
    pub(crate) fn recheck(&self, disk: &Disk) -> Result<()> {
        disk.idle()?;
        self.identity(disk)
    }
    pub(crate) fn identity(&self, disk: &Disk) -> Result<()> {
        disk.recheck()?;
        self.original_identity()
    }
    pub(crate) fn original_identity(&self) -> Result<()> {
        self.identity_with_write(None)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (major, minor, openat).")]
    pub(crate) fn identity_with_write(
        &self,
        write: Option<&crate::device_epoch::Write>,
    ) -> Result<()> {
        let inode = if let Some(write) = write {
            write.for_epoch(&self.epoch)?;
            write.checkpoint()?;
            files::identity(&self.file.metadata()?)
        } else {
            self.epoch.recheck()?;
            self.epoch.snapshot()?
        };
        let named = std::fs::symlink_metadata(&self.path)?;
        let parent = files::directory(Path::new("/dev"), Some(0))?;
        let name =
            std::ffi::CString::new(self.path.file_name().unwrap().as_encoded_bytes()).unwrap();
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(raw >= 0, "new partition path disappeared")?;
        let named_file = unsafe { File::from_raw_fd(raw) };
        require(
            files::identity(&named) == inode
                && files::identity(&named_file.metadata()?) == inode
                && mount_identity::id(named_file.as_fd(), true)? == self.mount
                && files::identity(&self.file.metadata()?) == inode
                && block::observe(self.file.as_fd())? == self.observation
                && mount_identity::id(self.file.as_fd(), true)? == self.mount,
            "new partition inode or media changed",
        )?;
        let dev = (libc::major(named.rdev()), libc::minor(named.rdev()));
        require(
            topology::observe(&[dev])? == self.graph,
            "new partition ancestry changed",
        )
    }
    pub(crate) fn descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }
    pub(crate) fn number(&self) -> Result<(u32, u32)> {
        let m = self.file.metadata()?;
        Ok((libc::major(m.rdev()), libc::minor(m.rdev())))
    }
    pub(crate) fn begin_write(&self, role: &'static str) -> Result<crate::device_epoch::Write> {
        self.epoch.begin(role)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    pub(crate) fn observed_write(&self, write: crate::device_epoch::Write) -> Result<()> {
        write.for_epoch(&self.epoch)?;
        let parent = files::directory(Path::new("/dev"), Some(0))?;
        let leaf =
            std::ffi::CString::new(self.path.file_name().unwrap().as_encoded_bytes()).unwrap();
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(raw >= 0, "original written partition name unavailable")?;
        let named = unsafe { File::from_raw_fd(raw) };
        let dev = self.number()?;
        require(
            topology::observe(&[dev])? == self.graph,
            "written partition kernel sequence or physical ancestry changed",
        )?;
        write.observed(&named)
    }
    pub(crate) fn run(
        &self,
        source: &Source,
        disk: &Disk,
        program: &str,
        args: &[&str],
        input: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        source.recheck()?;
        self.recheck(disk)?;
        let write = match program {
            "/usr/bin/wipefs" | "/usr/bin/mkfs.fat" | "/usr/bin/mkfs.btrfs" => {
                Some(self.epoch.begin("partition-format")?)
            }
            "/usr/bin/cryptsetup" if args.first() == Some(&"luksFormat") => {
                Some(self.epoch.begin("partition-format")?)
            }
            "/usr/bin/blkid" => None,
            _ => return Err(Error("partition tool outside closed role registry".into())),
        };
        let output =
            process::run_with_fds(program, args, input, timeout, 65536, &[self.file.as_fd()])?;
        require(
            output.status.success(),
            "partition tool failed; this attempt cannot be replayed",
        )?;
        if let Some(write) = write {
            let write = write.settle()?;
            source.recheck()?;
            disk.recheck()?;
            self.observed_write(write)?;
        }
        self.recheck(disk)?;
        source.recheck()?;
        Ok(output.stdout)
    }
}
pub fn admitted_receipt<'a>(body: &'a Value, boot: &str, disk: &Value) -> Result<&'a Value> {
    json::fields(body, "schema state boot disk plan result")?;
    require(
        body["schema"] == 1
            && body["state"] == "partitioned"
            && body["boot"] == boot
            && body["disk"] == *disk,
        "formatting requires this boot's unattempted native allocation",
    )?;
    let plan = &body["plan"];
    crate::allocation::validate(plan, disk)?;
    require(
        body["result"]["plan"] == *plan,
        "allocation result was altered",
    )?;
    Ok(plan)
}
pub fn apply(source: &Source) -> Result<Value> {
    let session = crate::install_session::Session::open(source)?;
    apply_session(source, &session)
}
pub(crate) fn apply_session(
    source: &Source,
    session: &crate::install_session::Session,
) -> Result<Value> {
    session.recheck(source)?;
    let disk = session.disk();
    let (path, boot) = erase::receipt_path(disk)?;
    let mut allocation_journal = crate::allocation::Journal::open(&path)?;
    let bytes = files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)?;
    let mut receipt = allocation_journal.body()?;
    require(
        json::canonical(&receipt)? == bytes,
        "allocation journal byte binding differs",
    )?;
    let plan = admitted_receipt(&receipt, &boot, &disk.observation()?)?.clone();
    crate::allocation::mode(&plan, source.answers.partition)?;
    require(
        plan["sector"] == disk.sector_size()?,
        "allocation sector changed",
    )?;
    let output = process::run(
        "/usr/bin/sfdisk",
        &["--json", disk.path.to_str().unwrap()],
        &[],
        Duration::from_secs(30),
        2 * 1024 * 1024,
    )?;
    require(output.status.success(), "allocation GPT readback failed")?;
    let table = json::decode(&output.stdout, 2 * 1024 * 1024)?;
    let result = crate::allocation::verify(&plan, &table["partitiontable"])?;
    require(
        result == receipt["result"],
        "allocation paths or geometry changed",
    )?;
    let sector = plan["sector"].as_u64().unwrap();
    let esp = PartitionFile::open(
        disk,
        result["esp"].as_str().unwrap(),
        crate::allocation::number(&plan, 1)?,
        plan["partitions"][1]["size"].as_u64().unwrap() * sector,
    )?;
    let root = PartitionFile::open(
        disk,
        result["root"].as_str().unwrap(),
        crate::allocation::number(&plan, 2)?,
        plan["partitions"][2]["size"].as_u64().unwrap() * sector,
    )?;
    session.recheck(source)?;
    esp.recheck(disk)?;
    root.recheck(disk)?;
    require(
        files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)? == bytes,
        "allocation receipt changed",
    )?;
    receipt["state"] = value!("formatting");
    receipt["encrypted"] = value!(source.answers.encrypted);
    allocation_journal.replace(&receipt)?;
    let attempt = (|| {
        esp.run(
            source,
            disk,
            "/usr/bin/wipefs",
            &["--all", "--force", "@fd:0"],
            &[],
            Duration::from_secs(60),
        )?;
        esp.run(
            source,
            disk,
            "/usr/bin/mkfs.fat",
            &["-F", "32", "-n", "ENZIMOS_ESP", "@fd:0"],
            &[],
            Duration::from_secs(120),
        )?;
        root.run(
            source,
            disk,
            "/usr/bin/wipefs",
            &["--all", "--force", "@fd:0"],
            &[],
            Duration::from_secs(60),
        )?;
        let root_type = if source.answers.encrypted {
            let password = source
                .answers
                .passphrase
                .as_ref()
                .ok_or_else(|| Error("encryption passphrase missing".into()))?;
            root.run(
                source,
                disk,
                "/usr/bin/cryptsetup",
                &[
                    "luksFormat",
                    "--type",
                    "luks2",
                    "--pbkdf",
                    "argon2id",
                    "--batch-mode",
                    "--key-file",
                    "-",
                    "@fd:0",
                ],
                password.as_bytes(),
                Duration::from_secs(600),
            )?;
            "crypto_LUKS"
        } else {
            root.run(
                source,
                disk,
                "/usr/bin/mkfs.btrfs",
                &["--force", "--label", "ENZIMOS_ROOT", "@fd:0"],
                &[],
                Duration::from_secs(120),
            )?;
            "btrfs"
        };
        let mut formatted = result.clone();
        for (label, partition, kind) in [("esp", &esp, "vfat"), ("root", &root, root_type)] {
            let output = partition.run(
                source,
                disk,
                "/usr/bin/blkid",
                &["--probe", "--output", "export", "@fd:0"],
                &[],
                Duration::from_secs(30),
            )?;
            let info = filesystem(&output, kind)?;
            formatted[format!("{label}_filesystem")] = info;
        }
        Ok(formatted)
    })();
    match &attempt {
        Ok(result) => {
            receipt["state"] = value!("formatted");
            receipt["formatted"] = result.clone();
        }
        Err(_) => receipt["state"] = value!("uncertain"),
    }
    allocation_journal.replace(&receipt)?;
    attempt
}
pub fn filesystem(bytes: &[u8], expected: &str) -> Result<Value> {
    require(bytes.len() <= 65536, "formatted filesystem response bound")?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error("formatted filesystem response encoding".into()))?;
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Error("formatted filesystem response shape".into()))?;
        require(
            fields.len() < 32
                && key.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
                && !value.chars().any(char::is_control)
                && fields.insert(key, value).is_none(),
            "duplicate or invalid formatted filesystem field",
        )?;
    }
    require(
        fields.get("TYPE") == Some(&expected),
        "formatted filesystem type differs",
    )?;
    let uuid = fields
        .get("UUID")
        .ok_or_else(|| Error("formatted filesystem UUID missing".into()))?;
    if expected == "vfat" {
        enzimos_policy::recovery_records::fat_uuid(uuid)?;
    } else {
        enzimos_policy::identity::uuid(uuid)?;
    }
    Ok(value!({"type":expected,"uuid":uuid}))
}
