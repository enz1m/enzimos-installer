// SPDX-License-Identifier: MIT
//! Retained whole-disk identity and active storage admission precede any mutation.
use enzimos_platform::{Error, Result, files, json, mount_identity, mountinfo, process, require};
use enzimos_policy::{namespaces, topology};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};
pub type Device = topology::Device;
pub fn device(value: &str) -> Result<Device> {
    let (a, b) = value
        .split_once(':')
        .ok_or_else(|| Error("block device number missing".into()))?;
    require(
        [a, b]
            .iter()
            .all(|s| !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit())),
        "block device number refused",
    )?;
    let major = a
        .parse::<u32>()
        .map_err(|_| Error("block major overflow".into()))?;
    let minor = b
        .parse::<u32>()
        .map_err(|_| Error("block minor overflow".into()))?;
    require(
        format!("{major}:{minor}") == value,
        "noncanonical block device number",
    )?;
    Ok((major, minor))
}
pub fn inactive_tree(tree: &Value, path: &str) -> Result<BTreeSet<Device>> {
    unmounted_tree(tree, path, None)
}
/// Only this exact retained mapping may extend the selected partition tree.
pub fn unmounted_tree(
    tree: &Value,
    path: &str,
    owned: Option<(Device, Device)>,
) -> Result<BTreeSet<Device>> {
    storage_tree(tree, path, owned, &BTreeMap::new())
}
pub fn storage_tree(
    tree: &Value,
    path: &str,
    owned: Option<(Device, Device)>,
    allowed: &BTreeMap<Device, BTreeSet<String>>,
) -> Result<BTreeSet<Device>> {
    let roots = tree["blockdevices"]
        .as_array()
        .ok_or_else(|| Error("disk inventory missing".into()))?;
    require(
        roots.len() == 1
            && roots[0]["name"] == path
            && roots[0]["type"] == "disk"
            && (roots[0]["ro"] == false || roots[0]["ro"] == 0),
        "one writable selected whole disk required",
    )?;
    fn visit(
        row: &Value,
        depth: usize,
        parent: Option<Device>,
        owned: Option<(Device, Device)>,
        allowed: &BTreeMap<Device, BTreeSet<String>>,
        result: &mut BTreeSet<Device>,
    ) -> Result<()> {
        let number = device(
            row["maj:min"]
                .as_str()
                .ok_or_else(|| Error("block inventory identity missing".into()))?,
        )?;
        let mapping = owned.is_some_and(|(partition, mapper)| {
            parent == Some(partition) && number == mapper && row["type"] == "crypt"
        });
        require(
            depth <= 16
                && result.len() < 256
                && (matches!(row["type"].as_str(), Some("disk" | "part")) || mapping)
                && (row["ro"] == false || row["ro"] == 0),
            "active storage mapping prevents installation",
        )?;
        require(result.insert(number), "ambiguous duplicate block inventory")?;
        let mounts = &row["mountpoints"];
        require(
            mounts.is_null()
                || mounts.as_array().is_some_and(|a| {
                    a.len() <= 64
                        && a.iter().all(|p| {
                            p.is_null()
                                || p == ""
                                || p.as_str().is_some_and(|path| {
                                    allowed
                                        .get(&number)
                                        .is_some_and(|paths| paths.contains(path))
                                })
                        })
                }),
            "selected disk is mounted",
        )?;
        if let Some(children) = row.get("children") {
            let children = children
                .as_array()
                .ok_or_else(|| Error("block children shape refused".into()))?;
            require(children.len() <= 128, "block child count bound")?;
            for child in children {
                require(!mapping, "owned mapper acquired a child")?;
                visit(child, depth + 1, Some(number), owned, allowed, result)?;
            }
        }
        Ok(())
    }
    let mut result = BTreeSet::new();
    visit(&roots[0], 0, None, owned, allowed, &mut result)?;
    if let Some((partition, mapper)) = owned {
        require(
            partition != mapper && result.contains(&partition) && result.contains(&mapper),
            "owned mapping missing from inventory",
        )?;
    }
    Ok(result)
}
pub fn swap_paths(body: &str) -> Result<Vec<PathBuf>> {
    require(
        body.len() <= 1024 * 1024 && !body.contains('\0'),
        "active swap inventory bound",
    )?;
    let mut lines = body.lines();
    require(
        lines.next().is_some_and(|s| {
            s.split_whitespace().collect::<Vec<_>>()
                == ["Filename", "Type", "Size", "Used", "Priority"]
        }),
        "active swap header refused",
    )?;
    let mut paths = Vec::new();
    let mut seen = BTreeSet::new();
    for line in lines {
        require(paths.len() < 256, "active swap count bound")?;
        let fields = line.split_whitespace().collect::<Vec<_>>();
        require(
            fields.len() == 5
                && matches!(fields[1], "partition" | "file")
                && fields[2..4].iter().all(|n| n.parse::<u64>().is_ok())
                && fields[4].parse::<i32>().is_ok(),
            "active swap record refused",
        )?;
        let path = mountinfo::unescape(fields[0])?;
        require(
            path.starts_with('/') && path.len() <= 4096 && seen.insert(path.clone()),
            "active swap path refused",
        )?;
        paths.push(PathBuf::from(path));
    }
    Ok(paths)
}
fn kernel(path: &Path, limit: usize) -> Result<String> {
    String::from_utf8(files::read_kernel(path, limit)?)
        .map_err(|_| Error("active storage observation encoding".into()))
}
pub struct Disk {
    file: File,
    pub path: PathBuf,
    epoch: std::sync::Arc<crate::device_epoch::Epoch>,
    mount: u64,
    pub number: Device,
    graph: topology::Graph,
    pub bytes: u64,
}
impl Disk {
    pub fn descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }
    pub(crate) fn sequence(&self) -> Result<u64> {
        self.recheck()?;
        let observed = enzimos_policy::block::observe(self.descriptor())?;
        let sequence = self.graph.nodes[&self.number].disk_sequence;
        require(
            sequence.is_some() && observed["disk_sequence"].as_u64() == sequence,
            "selected disk descriptor and kernel sequence differ",
        )?;
        sequence.ok_or_else(|| Error("selected disk sequence missing".into()))
    }
    pub fn observation(&self) -> Result<serde_json::Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"path":self.path,"number":[self.number.0,self.number.1],"bytes":self.bytes,"inode":format!("{:?}",self.epoch.snapshot()?),"mount":self.mount,"graph":self.graph.json()}),
        )
    }
    pub(crate) fn begin_write(&self, role: &'static str) -> Result<crate::device_epoch::Write> {
        self.idle()?;
        self.epoch.begin(role)
    }
    /// Only the retained target may call this after checking its owned mounts.
    /// BIOS sector installation intentionally occurs on the mounted target disk.
    pub(crate) fn begin_boot_write(&self) -> Result<crate::device_epoch::Write> {
        self.recheck()?;
        self.epoch.begin("whole-disk-bios")
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    pub(crate) fn observed_write(&self, write: crate::device_epoch::Write) -> Result<()> {
        write.for_epoch(&self.epoch)?;
        let named = files::directory(Path::new("/dev"), Some(0))?;
        let leaf =
            std::ffi::CString::new(self.path.file_name().unwrap().as_encoded_bytes()).unwrap();
        let raw = unsafe {
            libc::openat(
                named.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(raw >= 0, "original written disk name unavailable")?;
        let named = unsafe { File::from_raw_fd(raw) };
        require(
            topology::observe(&[self.number])? == self.graph,
            "written disk kernel sequence or physical ancestry changed",
        )?;
        write.observed(&named)?;
        self.recheck()
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
    pub fn sector_size(&self) -> Result<u64> {
        self.recheck()?;
        let mut sector = 0u32;
        require(
            unsafe { libc::ioctl(self.file.as_raw_fd(), 0x1268 as libc::c_ulong, &mut sector) }
                == 0
                && matches!(sector, 512 | 4096),
            "unsupported logical disk sector size",
        )?;
        Ok(u64::from(sector))
    }
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (ioctl, major, minor, openat)."
    )]
    pub fn open(path: &str) -> Result<Self> {
        crate::setup::live()?;
        crate::answers::disk_path(path)?;
        let canonical = std::fs::canonicalize(path)?;
        require(
            canonical.parent() == Some(Path::new("/dev")),
            "canonical whole-disk device required",
        )?;
        let parent = files::directory(Path::new("/dev"), Some(0))?;
        let name =
            std::ffi::CString::new(canonical.file_name().unwrap().as_encoded_bytes()).unwrap();
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(raw >= 0, "selected disk unavailable")?;
        let file = unsafe { File::from_raw_fd(raw) };
        let metadata = file.metadata()?;
        require(
            metadata.uid() == 0 && metadata.file_type().is_block_device(),
            "Root-owned block disk required",
        )?;
        let number = (libc::major(metadata.rdev()), libc::minor(metadata.rdev()));
        let graph = topology::observe(&[number])?;
        require(
            graph.nodes.len() == 1 && graph.leaves == BTreeSet::from([number]),
            "physical whole disk required",
        )?;
        let mut bytes = 0u64;
        require(
            unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272u64 as libc::c_ulong, &mut bytes) }
                == 0
                && bytes >= 24 * 1024 * 1024 * 1024,
            "installation disk needs at least 24 GiB",
        )?;
        let disk = Self {
            mount: mount_identity::id(file.as_fd(), true)?,
            epoch: crate::device_epoch::Epoch::capture(&file)?,
            file,
            path: canonical,
            number,
            graph,
            bytes,
        };
        disk.idle()?;
        Ok(disk)
    }
    pub fn recheck(&self) -> Result<()> {
        self.recheck_with_write(None)
    }
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (ioctl, major, minor, openat)."
    )]
    fn recheck_with_write(&self, write: Option<&crate::device_epoch::Write>) -> Result<()> {
        crate::setup::live()?;
        let identity = if let Some(write) = write {
            write.for_epoch(&self.epoch)?;
            write.checkpoint()?;
            files::identity(&self.file.metadata()?)
        } else {
            self.epoch.recheck()?;
            self.epoch.snapshot()?
        };
        let metadata = std::fs::symlink_metadata(&self.path)?;
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
        require(raw >= 0, "selected disk path disappeared")?;
        let named = unsafe { File::from_raw_fd(raw) };
        require(
            files::identity(&metadata) == identity
                && files::identity(&named.metadata()?) == identity
                && files::identity(&self.file.metadata()?) == identity
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && metadata.file_type().is_block_device()
                && (libc::major(metadata.rdev()), libc::minor(metadata.rdev())) == self.number
                && topology::observe(&[self.number])? == self.graph,
            "selected disk inode or kernel sequence changed",
        )?;
        let mut bytes = 0u64;
        require(
            unsafe {
                libc::ioctl(
                    self.file.as_raw_fd(),
                    0x80081272u64 as libc::c_ulong,
                    &mut bytes,
                )
            } == 0
                && bytes == self.bytes,
            "selected disk size changed",
        )
    }
    pub fn idle(&self) -> Result<BTreeSet<Device>> {
        self.unmounted(None)
    }
    pub(crate) fn idle_owned(&self, partition: Device, mapper: Device) -> Result<BTreeSet<Device>> {
        let graph = topology::observe(&[mapper])?;
        require(
            graph.leaves == BTreeSet::from([self.number])
                && graph.nodes[&mapper].dependencies == [partition],
            "owned mapping ancestry differs",
        )?;
        let result = self.unmounted(Some((partition, mapper)))?;
        require(
            topology::observe(&[mapper])? == graph,
            "owned mapping changed during admission",
        )?;
        Ok(result)
    }
    fn unmounted(&self, owned: Option<(Device, Device)>) -> Result<BTreeSet<Device>> {
        self.admitted(owned, None, &[], None)
    }
    pub(crate) fn mounted(
        &self,
        owned: Option<(Device, Device)>,
        baseline: &crate::mount_admission::Baseline,
        proofs: &[crate::mount_admission::Proof],
    ) -> Result<()> {
        self.mounted_with_write(owned, baseline, proofs, None)
    }
    pub(crate) fn mounted_with_write(
        &self,
        owned: Option<(Device, Device)>,
        baseline: &crate::mount_admission::Baseline,
        proofs: &[crate::mount_admission::Proof],
        write: Option<&crate::device_epoch::Write>,
    ) -> Result<()> {
        let graph = if let Some((partition, mapper)) = owned {
            let graph = topology::observe(&[mapper])?;
            require(
                graph.leaves == BTreeSet::from([self.number])
                    && graph.nodes[&mapper].dependencies == [partition],
                "mounted mapper ancestry differs",
            )?;
            Some((mapper, graph))
        } else {
            None
        };
        self.admitted(owned, Some(baseline), proofs, write)?;
        if let Some((mapper, graph)) = graph {
            require(
                topology::observe(&[mapper])? == graph,
                "mounted mapper graph changed",
            )?;
        }
        Ok(())
    }
    fn admitted(
        &self,
        owned: Option<(Device, Device)>,
        baseline: Option<&crate::mount_admission::Baseline>,
        proofs: &[crate::mount_admission::Proof],
        write: Option<&crate::device_epoch::Write>,
    ) -> Result<BTreeSet<Device>> {
        self.recheck_with_write(write)?;
        let output = process::run(
            "/usr/bin/lsblk",
            &[
                "--json",
                "--paths",
                "--output",
                "NAME,TYPE,RO,MOUNTPOINTS,MAJ:MIN",
                "--",
                self.path.to_str().unwrap(),
            ],
            &[],
            Duration::from_secs(30),
            2 * 1024 * 1024,
        )?;
        require(
            output.status.success(),
            "selected disk inventory unavailable",
        )?;
        let devices = storage_tree(
            &json::decode(&output.stdout, 2 * 1024 * 1024)?,
            self.path.to_str().unwrap(),
            owned,
            &crate::mount_admission::paths(proofs),
        )?;
        require(
            devices.contains(&self.number),
            "selected disk inventory identity changed",
        )?;
        let mut kernel_devices = BTreeSet::from([self.number]);
        let root = &self.graph.nodes[&self.number].path;
        kernel_devices.extend(crate::disk_partitions::enumerate(root, |path| {
            kernel(path, 4096)
        })?);
        require(
            kernel_devices
                == devices
                    .iter()
                    .copied()
                    .filter(|number| !owned.is_some_and(|(_, mapper)| *number == mapper))
                    .collect(),
            "disk inventory omitted or changed a kernel partition",
        )?;
        for number in &devices {
            let graph = topology::observe(&[*number])?;
            require(
                graph.leaves == BTreeSet::from([self.number]),
                "partition belongs to another disk",
            )?;
            let node = &graph.nodes[number];
            let holders = node.path.join("holders");
            let expected = if owned.is_some_and(|(partition, _)| partition == *number) {
                Some(topology::kernel_node(owned.unwrap().1)?.path)
            } else {
                None
            };
            crate::disk_holders::verify(&holders, expected.as_deref())?;
        }
        let views = if baseline.is_some() {
            // Owned target mounts already have retained kernel proofs. Sample
            // active actors without treating a proven dead group as an actor.
            namespaces::observe_active()
        } else {
            namespaces::observe()
        }
        .map_err(|error| Error(format!("disk complete namespace observation: {error}")))?;
        for view in &views.views {
            for row in &view.mounts {
                if devices.contains(&(row.major, row.minor))
                    && !crate::mount_admission::owns(proofs, view.identity, row)
                {
                    // Kernel numeric identities only: do not disclose target paths,
                    // answers, process command lines or arbitrary mount options.
                    return Err(Error(format!(
                        "disk is mounted in another namespace: representative={} namespace={}:{} mount={} parent={} device={}:{} owned_mounts={}",
                        view.representative,
                        view.identity.0,
                        view.identity.1,
                        row.id,
                        row.parent,
                        row.major,
                        row.minor,
                        proofs.len()
                    )));
                }
            }
        }
        for path in swap_paths(&kernel(Path::new("/proc/swaps"), 1024 * 1024)?)? {
            let metadata = std::fs::metadata(path)?;
            let number = if metadata.file_type().is_block_device() {
                metadata.rdev()
            } else {
                require(metadata.is_file(), "active swap backing file refused")?;
                metadata.dev()
            };
            require(
                !devices.contains(&(libc::major(number), libc::minor(number)))
                    && !proofs.iter().any(|p| {
                        (p.row.major, p.row.minor) == (libc::major(number), libc::minor(number))
                    }),
                "active swap prevents installation",
            )?;
        }
        // Btrfs mountinfo uses anonymous device numbers. Its global kernel
        // member graph also catches mounted multi-device filesystems and swapfiles.
        if let Some(baseline) = baseline {
            baseline.admit(&views, proofs, self.number)?;
            self.recheck_with_write(write)?;
            return Ok(devices);
        }
        let mut count = 0;
        let entries = match std::fs::read_dir("/sys/fs/btrfs") {
            Ok(entries) => Some(entries),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        for entry in entries.into_iter().flatten() {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| Error("mounted Btrfs name encoding".into()))?;
            if name == "features" {
                continue;
            }
            count += 1;
            require(count <= 64, "mounted Btrfs filesystem count bound")?;
            enzimos_policy::identity::uuid(&name)?;
            require(
                !topology::mounted_btrfs(&name)?
                    .leaves
                    .contains(&self.number),
                "mounted Btrfs member prevents installation",
            )?;
        }
        let mut final_devices = BTreeSet::from([self.number]);
        final_devices.extend(crate::disk_partitions::enumerate(root, |path| {
            kernel(path, 4096)
        })?);
        require(
            final_devices == kernel_devices,
            "kernel disk partition set changed during admission",
        )?;
        self.recheck_with_write(write)?;
        Ok(devices)
    }
}
