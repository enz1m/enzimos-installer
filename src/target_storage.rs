// SPDX-License-Identifier: MIT
//! A retained storage lifetime for an installation body. Completion needs teardown.
use crate::{
    answer_source::Source,
    disk_guard::Disk,
    erase,
    format::{self, PartitionFile},
    mapper::Mapper,
    mount_admission::Baseline,
    mount_owner::Top,
    subvolume_prepare,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, process, require};
use enzimos_policy::storage_runtime;
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::fd::AsFd,
    path::{Path, PathBuf},
    time::Duration,
};
/// Original node event reservations accompany exactly one BIOS vendor call.
/// The partition/mapping tokens authorize metadata settlement only.
pub(crate) struct BiosWrite {
    disk: crate::device_epoch::Write,
    root: crate::device_epoch::Write,
    esp: crate::device_epoch::Write,
    mapper: Option<crate::device_epoch::Write>,
}
impl BiosWrite {
    pub(crate) fn settle(self) -> Result<Self> {
        let mapped = self.mapper.is_some();
        let mut cohort = vec![self.disk, self.root, self.esp];
        if let Some(write) = self.mapper {
            cohort.push(write);
        }
        let mut settled = crate::device_epoch::Write::settle_batch(cohort)?.into_iter();
        Ok(Self {
            disk: settled.next().unwrap(),
            root: settled.next().unwrap(),
            esp: settled.next().unwrap(),
            mapper: if mapped { settled.next() } else { None },
        })
    }
}

const TARGET: &str = "/mnt/enzimos";
fn storage_stage<T>(role: &'static str, result: Result<T>) -> Result<T> {
    result.map_err(|error| Error(format!("target {role}: {error}")))
}
pub use crate::chroot_mounts::clone_layout;
pub fn admit<'a>(body: &'a Value, boot: &str, disk: &Value, encrypted: bool) -> Result<&'a Value> {
    json::fields(
        body,
        "schema state boot disk plan result encrypted formatted mapper root_filesystem subvolume_attempt subvolumes",
    )?;
    require(
        body["state"] == "subvolumes-ready",
        "installation storage requires unattempted ready subvolumes",
    )?;
    let mut ready = body.clone();
    let object = ready
        .as_object_mut()
        .ok_or_else(|| Error("ready subvolume receipt shape".into()))?;
    object.remove("subvolume_attempt");
    object.remove("subvolumes");
    object.insert("state".into(), value!("root-ready"));
    subvolume_prepare::admit(&ready, boot, disk, encrypted)?;
    subvolume_prepare::validate_subvolumes(&body["subvolumes"])?;
    let attempt = &body["subvolume_attempt"];
    json::fields(attempt, "id mount mapper")?;
    let id = attempt["id"]
        .as_str()
        .ok_or_else(|| Error("subvolume attempt ID missing".into()))?;
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && attempt["mount"] == format!("/run/enzimos-install-native/mounts/{id}")
            && if encrypted {
                attempt["mapper"] == format!("enzimos-install-{id}")
            } else {
                attempt["mapper"].is_null()
            },
        "subvolume attempt binding changed",
    )?;
    Ok(&body["subvolumes"])
}
// Pure row comparison grants no mount authority. Callers must retain and
// recheck the actual Area and every Top/environment object before using it.
fn target_rows(
    rows: &[enzimos_platform::mountinfo::Row],
    area: &enzimos_platform::mountinfo::Row,
    owned: &[enzimos_platform::mountinfo::Row],
) -> Result<()> {
    require(
        area.target == TARGET && owned.len() <= 104,
        "private target row or owned mount bound",
    )?;
    let expected = std::iter::once(area).chain(owned).collect::<Vec<_>>();
    require(
        expected
            .iter()
            .all(|expected| rows.iter().filter(|row| *row == *expected).count() == 1)
            && expected
                .iter()
                .map(|row| row.id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == expected.len()
            && rows
                .iter()
                .filter(|row| row.target == TARGET || row.target.starts_with("/mnt/enzimos/"))
                .all(|row| expected.contains(&row))
            && owned
                .iter()
                .filter(|row| row.target == TARGET)
                .all(|row| row.parent == area.id),
        "private target area or owned mount replaced, shadowed or extended",
    )
}
pub struct Target<'a> {
    source: &'a Source,
    disk: Disk,
    root: PartitionFile,
    esp: PartitionFile,
    mapper: Option<Mapper>,
    baseline: Baseline,
    target_area: enzimos_policy::installer_mount_area::Area,
    mounts: Vec<Top>,
    receipt: PathBuf,
    allocation_journal: crate::allocation::Journal,
    body: Value,
    expected: Vec<u8>,
    _lock: files::Lock,
    lock_identity: files::FileIdentity,
    lock_mount: u64,
    environment: crate::chroot_mounts::Mounts,
    package_lifetime: bool,
}
impl Target<'_> {
    pub fn directory(&self) -> Result<&File> {
        self.mounts
            .first()
            .ok_or_else(|| Error("installation target is not mounted".into()))?
            .directory()
    }
    pub fn source(&self) -> &Source {
        self.source
    }
    pub(crate) fn operation_lock(&self) -> &File {
        self._lock.as_file()
    }
    pub fn root_filesystem(&self) -> &Value {
        &self.body["root_filesystem"]
    }
    pub fn subvolumes(&self) -> &Value {
        &self.body["subvolumes"]
    }
    pub fn package_request(
        &self,
        media: &crate::media_packages::Admitted,
        id: &str,
    ) -> Result<Value> {
        self.package_request_for(media, id, crate::package_job::ARCH)
    }
    pub fn package_request_for(
        &self,
        media: &crate::media_packages::Admitted,
        id: &str,
        operation: &str,
    ) -> Result<Value> {
        crate::package_job::operation(operation)?;
        use std::os::{fd::AsFd, unix::fs::MetadataExt};
        self.recheck()?;
        media.recheck()?;
        require(
            self.body["state"] == "storage-environment-mounted",
            "package intent requires this attempt's owned chroot environment",
        )?;
        let caller_parent = files::directory(
            Path::new(crate::package_job::CALLER).parent().unwrap(),
            Some(0),
        )?;
        let caller_file = files::open_relative(
            &caller_parent,
            Path::new(Path::new(crate::package_job::CALLER).file_name().unwrap()),
        )?;
        let caller = files::read_file(&caller_file, 32 * 1024 * 1024, Some(0), true)?;
        require(
            caller.starts_with(b"\x7fELF"),
            "installed native installer caller required",
        )?;
        let pid = std::process::id();
        let stat = files::read_kernel(&PathBuf::from(format!("/proc/{pid}/stat")), 8192)?;
        let stat = enzimos_platform::process_identity::parse_stat(
            std::str::from_utf8(&stat)
                .map_err(|_| Error("installer caller stat encoding".into()))?,
            pid,
        )?;
        let process = enzimos_platform::process_identity::Retained::open(
            pid,
            stat.start_ticks,
            0,
            &[PathBuf::from(crate::package_job::CALLER)],
        )?
        .pin_executable(&caller_file)?;
        process.recheck()?;
        let target = self.directory()?;
        let inode = target.metadata()?;
        let mut request = value!({"schema":1,"id":id,"boot_id":self.body["boot"],"operation":operation,"target":TARGET,
            "media_manifest_sha256":media.media.manifest_sha256,"selected":media.selected,
            "target_mount":enzimos_platform::mount_identity::id(target.as_fd(),true)?,
            "target_inode":[inode.dev(),inode.ino(),u64::from(inode.uid()),u64::from(inode.gid()),u64::from(inode.mode())],
            "caller":{"pid":pid,"start_ticks":stat.start_ticks,"executable_sha256":json::sha256(&caller)}});
        require(
            self.source.test_copy.is_none() || operation == crate::package_job::BOOT,
            "test mode requires full bootable installation role",
        )?;
        if crate::package_job::configured(operation) {
            request["schema"] = value!(2);
            request["configuration"] = value!({"filesystem_uuid":self.body["root_filesystem"]["uuid"],
                "esp_uuid":self.body["formatted"]["esp_filesystem"]["uuid"],
                "luks_uuid":if self.source.answers.encrypted {self.body["formatted"]["root_filesystem"]["uuid"].clone()} else {Value::Null},
                "answers":self.source.binding()?});
        }
        if operation == crate::package_job::BOOT {
            request["schema"] = value!(3);
            request["boot"] = value!({"disk":crate::install_boot_disk::observe(self.disk.descriptor(),&self.source.answers.disk,self.body["root_filesystem"]["uuid"].as_str().unwrap())?,
                "security":self.source.boot_security.receipt()?});
            if let Some(copy) = &self.source.test_copy {
                copy.independent(self.disk.number)?;
                request["schema"] = value!(4);
                request["boot"]["test_copy"] = copy.binding()?;
            }
        }
        crate::package_job::request(&request)?;
        self.recheck()?;
        media.recheck()?;
        process.recheck()?;
        Ok(request)
    }
    pub(crate) fn boot_disk(&self) -> Result<std::os::fd::BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.disk.descriptor())
    }
    pub(crate) fn begin_bios_write(&self) -> Result<BiosWrite> {
        self.recheck()?;
        require(
            self.package_lifetime,
            "BIOS write requires this retained package lifetime",
        )?;
        Ok(BiosWrite {
            root: self.root.begin_write("bios-device-events")?,
            esp: self.esp.begin_write("bios-device-events")?,
            mapper: self
                .mapper
                .as_ref()
                .map(super::mapper::Mapper::begin_bios_events)
                .transpose()?,
            disk: self.disk.begin_boot_write()?,
        })
    }
    pub(crate) fn observe_bios_write(&self, write: BiosWrite) -> Result<()> {
        self.bios_checkpoint(&write)?;
        self.disk.observed_write(write.disk)?;
        self.root.observed_write(write.root)?;
        self.esp.observed_write(write.esp)?;
        if let Some(token) = write.mapper {
            self.mapper
                .as_ref()
                .ok_or_else(|| Error("original BIOS mapping disappeared".into()))?
                .observe_bios_events(token)?;
        }
        self.verify_allocation()
    }
    pub(crate) fn begin_package_job(&mut self, request: &Value) -> Result<()> {
        self.recheck()?;
        crate::package_job::request(request)?;
        require(
            self.body["state"] == "storage-environment-mounted",
            "package installation already attempted or chroot environment absent",
        )?;
        self.body["package_attempt"] =
            value!({"id":request["id"],"request_sha256":json::fingerprint(request)?});
        self.package_lifetime = true;
        self.checkpoint("storage-package-starting")
    }
    pub(crate) fn package_stopped(
        &mut self,
        owner: &enzimos_system_backend::native_worker_manager::Owner,
    ) -> Result<()> {
        self.recheck()?;
        require(
            self.package_lifetime
                && owner.state.group
                    == format!(
                        "/system.slice/{}",
                        crate::package_job::unit(
                            self.body["package_attempt"]["id"].as_str().unwrap()
                        )?
                    )
                && owner.exited_and_empty()?,
            "package lifetime cannot end before the original worker and owned cgroup are empty",
        )?;
        self.package_lifetime = false;
        Ok(())
    }
    pub fn mount_environment(&mut self) -> Result<()> {
        self.recheck()?;
        self.environment.open()?;
        self.checkpoint("storage-environment-mounted")
    }
    pub fn recheck(&self) -> Result<()> {
        self.allocation_journal.recheck()?;
        storage_stage(
            "operation lock",
            crate::install_session::recheck_lock(&self._lock, &self.lock_identity, self.lock_mount),
        )?;
        storage_stage("answer source", self.source.recheck())?;
        storage_stage("root device", self.root.identity(&self.disk))?;
        storage_stage("ESP device", self.esp.identity(&self.disk))?;
        if let Some(mapper) = &self.mapper {
            storage_stage(
                "mapper device",
                mapper.identity(self.source, &self.disk, &self.root),
            )?;
        }
        let proofs = self
            .mounts
            .iter()
            .map(|m| m.proof.clone())
            .collect::<Vec<_>>();
        let owned = self
            .mapper
            .as_ref()
            .map(|m| self.root.number().map(|number| (number, m.number)))
            .transpose()?;
        storage_stage(
            "disk mount admission",
            self.disk.mounted(owned, &self.baseline, &proofs),
        )?;
        self.storage_surfaces()
    }
    /// During the one-use BIOS token, only this whole-disk timestamp transition
    /// is permitted. Partition descriptions and every mounted surface stay exact.
    pub(crate) fn bios_checkpoint(&self, write: &BiosWrite) -> Result<()> {
        self.allocation_journal.recheck()?;
        crate::install_session::recheck_lock(&self._lock, &self.lock_identity, self.lock_mount)?;
        self.source.recheck()?;
        storage_stage(
            "BIOS root node",
            self.root.identity_with_write(Some(&write.root)),
        )?;
        storage_stage(
            "BIOS ESP node",
            self.esp.identity_with_write(Some(&write.esp)),
        )?;
        require(
            self.mapper.is_some() == write.mapper.is_some(),
            "BIOS mapping reservation changed",
        )?;
        if let Some(mapper) = &self.mapper {
            storage_stage(
                "BIOS mapped node",
                mapper.original_identity_with_write(write.mapper.as_ref()),
            )?;
        }
        storage_stage("BIOS whole-disk node", write.disk.checkpoint())?;
        let proofs = self
            .mounts
            .iter()
            .map(|m| m.proof.clone())
            .collect::<Vec<_>>();
        let owned = self
            .mapper
            .as_ref()
            .map(|m| self.root.number().map(|number| (number, m.number)))
            .transpose()?;
        self.disk
            .mounted_with_write(owned, &self.baseline, &proofs, Some(&write.disk))?;
        self.storage_surfaces()
    }
    fn storage_surfaces(&self) -> Result<()> {
        for mount in &self.mounts {
            mount.recheck().map_err(|error| {
                Error(format!(
                    "target owned mount {}: {error}",
                    mount.proof.row.target
                ))
            })?;
        }
        storage_stage("chroot environment", self.environment.recheck())?;
        if self.mounts.is_empty() {
            storage_stage("uncovered private area", self.target_area.recheck())?;
        } else {
            storage_stage("covered private area", self.target_area.recheck_covered())?;
        }
        let proofs = self
            .mounts
            .iter()
            .map(|m| m.proof.clone())
            .collect::<Vec<_>>();
        let rows = storage_stage("mount table", storage_runtime::rows())?;
        let environment = self.environment.rows();
        let owned = proofs
            .iter()
            .map(|proof| proof.row.clone())
            .chain(environment)
            .collect::<Vec<_>>();
        target_rows(&rows, self.target_area.binding(), &owned)?;
        require(
            storage_stage(
                "original receipt",
                files::read(&self.receipt, crate::allocation::MAX_RECEIPT, Some(0), true),
            )? == self.expected,
            "changed installation storage receipt",
        )
    }
    fn verify_allocation(&self) -> Result<()> {
        self.recheck()?;
        let output = process::run(
            "/usr/bin/sfdisk",
            &["--json", self.disk.path.to_str().unwrap()],
            &[],
            Duration::from_secs(30),
            2 * 1024 * 1024,
        )?;
        require(
            output.status.success(),
            "completed allocation GPT readback failed",
        )?;
        let table = json::decode(&output.stdout, 2 * 1024 * 1024)?;
        require(
            crate::allocation::verify(&self.body["plan"], &table["partitiontable"])?
                == self.body["result"],
            "completed allocation changed preserved or new partitions",
        )?;
        self.recheck()
    }
    fn checkpoint(&mut self, phase: &str) -> Result<()> {
        self.recheck()?;
        self.body["state"] = value!(phase);
        let bytes = json::canonical(&self.body)?;
        self.allocation_journal.replace(&self.body)?;
        require(
            files::read(&self.receipt, crate::allocation::MAX_RECEIPT, Some(0), true)? == bytes,
            "installation storage checkpoint readback differs",
        )?;
        self.expected = bytes;
        self.recheck()
    }
    fn mount_all(&mut self) -> Result<()> {
        self.recheck()?;
        let filesystem = self.body["root_filesystem"]["uuid"]
            .as_str()
            .unwrap()
            .to_owned();
        let root = Top::subvolume(
            match &self.mapper {
                Some(m) => m.descriptor()?,
                None => self.root.descriptor(),
            },
            Path::new(TARGET),
            &filesystem,
            self.body["subvolumes"]["enzimos-root"].clone(),
        )?;
        self.mounts.push(root);
        self.recheck()?;
        // Only directories in the newly owned root are created here.
        for directory in ["var", "var/lib", "etc", "etc/pacman.d"] {
            files::ensure_directory(&Path::new(TARGET).join(directory), 0o755, 0)?;
        }
        for (name, path) in [
            ("enzimos-home", "home"),
            ("enzimos-control", "var/lib/enzimos-control"),
            ("enzimos-authority", "etc/pacman.d/gnupg"),
            ("enzimos-swap", "swap"),
        ] {
            self.recheck()?;
            let mount = Top::subvolume(
                match &self.mapper {
                    Some(m) => m.descriptor()?,
                    None => self.root.descriptor(),
                },
                &Path::new(TARGET).join(path),
                &filesystem,
                self.body["subvolumes"][name].clone(),
            )?;
            self.mounts.push(mount);
            self.recheck()?;
        }
        let esp = Top::esp(
            self.esp.descriptor(),
            Path::new("/mnt/enzimos/boot"),
            self.body["formatted"]["esp_filesystem"]["uuid"]
                .as_str()
                .unwrap(),
        )?;
        self.mounts.push(esp);
        self.checkpoint("storage-mounted")
    }
    fn close(&mut self) -> Result<()> {
        require(
            !self.package_lifetime,
            "package worker lifetime remains uncertain; retain target mounts and mapper",
        )?;
        self.environment.close()?;
        while !self.mounts.is_empty() {
            self.recheck()?;
            self.mounts.last_mut().unwrap().close()?;
            self.mounts.pop(); // also release the retained mapped block opener
        }
        self.recheck()?;
        if let Some(mapper) = &mut self.mapper {
            mapper.close(self.source, &self.disk, &self.root)?;
        }
        self.mapper.take();
        self.disk.idle()?;
        self.source.recheck()
    }
}
/// The body remains inside a single retained lifetime and may not retain target FDs.
/// Unfinished storage receipts block any automatic rerun of that body.
pub fn with_storage<F>(source: &Source, body: F) -> Result<Value>
where
    F: FnOnce(&mut Target<'_>) -> Result<Value>,
{
    let session = crate::install_session::Session::open(source)?;
    with_session(source, session, body)
}
pub(crate) fn with_session<F>(
    source: &Source,
    session: crate::install_session::Session,
    body: F,
) -> Result<Value>
where
    F: FnOnce(&mut Target<'_>) -> Result<Value>,
{
    with_session_complete(source, session, body, |_, _| Ok(()))
}
pub(crate) fn with_session_complete<F, G>(
    source: &Source,
    session: crate::install_session::Session,
    body: F,
    finished: G,
) -> Result<Value>
where
    F: FnOnce(&mut Target<'_>) -> Result<Value>,
    G: FnOnce(&Value, &Finalized<'_, '_>) -> Result<()>,
{
    session.recheck(source)?;
    source.recheck()?;
    let (disk, lock, lock_identity, lock_mount) = session.into_parts();
    let (path, boot) = erase::receipt_path(&disk)?;
    let mut allocation_journal = crate::allocation::Journal::open(&path)?;
    let bytes = files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)?;
    let mut receipt = allocation_journal.body()?;
    require(
        json::canonical(&receipt)? == bytes,
        "allocation journal byte binding differs",
    )?;
    admit(
        &receipt,
        &boot,
        &disk.observation()?,
        source.answers.encrypted,
    )?;
    let formatted = receipt["formatted"].clone();
    crate::allocation::mode(&formatted["plan"], source.answers.partition)?;
    require(
        formatted["plan"]["sector"] == disk.sector_size()?,
        "ready subvolume allocation sector changed",
    )?;
    let table = process::run(
        "/usr/bin/sfdisk",
        &["--json", disk.path.to_str().unwrap()],
        &[],
        Duration::from_secs(30),
        2 * 1024 * 1024,
    )?;
    require(
        table.status.success()
            && crate::allocation::verify(
                &formatted["plan"],
                &json::decode(&table.stdout, 2 * 1024 * 1024)?["partitiontable"],
            )? == receipt["result"],
        "ready subvolume allocation GPT changed",
    )?;
    let sector = formatted["plan"]["sector"].as_u64().unwrap();
    let root = PartitionFile::open(
        &disk,
        formatted["root"].as_str().unwrap(),
        crate::allocation::number(&formatted["plan"], 2)?,
        formatted["plan"]["partitions"][2]["size"].as_u64().unwrap() * sector,
    )?;
    let esp = PartitionFile::open(
        &disk,
        formatted["esp"].as_str().unwrap(),
        crate::allocation::number(&formatted["plan"], 1)?,
        formatted["plan"]["partitions"][1]["size"].as_u64().unwrap() * sector,
    )?;
    for (partition, key, kind) in [
        (
            &root,
            "root_filesystem",
            if source.answers.encrypted {
                "crypto_LUKS"
            } else {
                "btrfs"
            },
        ),
        (&esp, "esp_filesystem", "vfat"),
    ] {
        let bytes = partition.run(
            source,
            &disk,
            "/usr/bin/blkid",
            &["--probe", "--output", "export", "@fd:0"],
            &[],
            Duration::from_secs(30),
        )?;
        require(
            format::filesystem(&bytes, kind)? == formatted[key],
            "ready subvolume filesystem changed",
        )?;
    }
    let baseline = Baseline::capture(disk.number)?;
    // The private area is an original, durably created bind, not a preexisting
    // target filesystem. Retain it across the exact owned covering mounts.
    let target_area = enzimos_policy::installer_mount_area::Area::observe_target()?;
    target_rows(&storage_runtime::rows()?, target_area.binding(), &[])?;
    let id = files::random_hex(16)?;
    let name = format!("enzimos-install-{id}");
    source.recheck()?;
    disk.idle()?;
    require(
        files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)? == bytes,
        "ready subvolume receipt changed before body admission",
    )?;
    receipt["state"] = value!("storage-starting");
    receipt["installation_attempt"] = value!({"id":id,"target":TARGET,"mapper":if source.answers.encrypted {value!(name)} else {Value::Null}});
    let intent = json::canonical(&receipt)?;
    allocation_journal.replace(&receipt)?;
    require(
        files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)? == intent,
        "installation storage intent readback differs",
    )?;
    let mapper = if source.answers.encrypted {
        Some(Mapper::open(
            source,
            &disk,
            &root,
            formatted["root_filesystem"]["uuid"].as_str().unwrap(),
            &name,
        )?)
    } else {
        None
    };
    let mut target = Target {
        source,
        disk,
        root,
        esp,
        mapper,
        baseline,
        target_area,
        mounts: Vec::new(),
        receipt: path,
        allocation_journal,
        body: receipt,
        expected: intent,
        _lock: lock,
        lock_identity,
        lock_mount,
        environment: crate::chroot_mounts::Mounts::default(),
        package_lifetime: false,
    };
    let attempted = (|| {
        if let Some(mapper) = &target.mapper {
            let probe = mapper.run(
                source,
                &target.disk,
                &target.root,
                "/usr/bin/blkid",
                &["--probe", "--output", "export", "@fd:0"],
                Duration::from_secs(30),
            )?;
            require(
                format::filesystem(&probe, "btrfs")? == target.body["root_filesystem"],
                "ready inner filesystem changed",
            )?;
        }
        target.mount_all()?;
        target.checkpoint("storage-body-started")?;
        let result = body(&mut target)?;
        target.verify_allocation()?;
        target.checkpoint("storage-body-finished")?;
        Ok(result)
    })();
    let closed = target.close();
    let result = match (attempted, closed) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(e), _) | (_, Err(e)) => Err(e),
    };
    target.body["state"] = value!(if result.is_ok() {
        "storage-body-complete"
    } else {
        "uncertain"
    });
    let final_bytes = json::canonical(&target.body)?;
    target.allocation_journal.replace(&target.body)?;
    let terminal = target.allocation_journal.descriptor()?;
    require(
        files::read(
            &target.receipt,
            crate::allocation::MAX_RECEIPT,
            Some(0),
            true,
        )? == final_bytes,
        "installation storage terminal checkpoint readback differs",
    )?;
    crate::install_session::recheck_lock(&target._lock, &target.lock_identity, target.lock_mount)?;
    if let Ok(value) = &result {
        target.expected = final_bytes;
        let finalized = Finalized {
            identity: files::identity(&terminal.metadata()?),
            mount: mount_identity::id(terminal.as_fd(), true)?,
            terminal,
            target: &target,
        };
        finalized.recheck()?;
        finished(value, &finalized)?;
    }
    result
}

/// Only normal teardown can construct this original disk/lock/receipt lifetime.
pub(crate) struct Finalized<'a, 'source> {
    target: &'a Target<'source>,
    terminal: File,
    identity: files::FileIdentity,
    mount: u64,
}
impl Finalized<'_, '_> {
    pub(crate) fn recheck(&self) -> Result<()> {
        self.target.recheck()?;
        self.target.verify_allocation()?;
        self.target.disk.idle()?;
        require(
            self.target.mounts.is_empty()
                && self.target.mapper.is_none()
                && !self.target.package_lifetime
                && self.target.body["state"] == "storage-body-complete",
            "finish requires normal closed storage lifetime",
        )?;
        let parent = files::directory(self.target.receipt.parent().unwrap(), Some(0))?;
        let named =
            files::open_relative(&parent, Path::new(self.target.receipt.file_name().unwrap()))?;
        require(
            files::identity(&self.terminal.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && self.identity.7 & 0o7777 == 0o600
                && self.identity.8 == 0
                && self.identity.9 == 0
                && self.identity.10 == 1
                && mount_identity::id(self.terminal.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && files::read_file(
                    &self.terminal,
                    crate::allocation::MAX_RECEIPT,
                    Some(0),
                    true,
                )? == self.target.expected,
            "original closed storage receipt changed or replaced",
        )
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"receipt_sha256":json::fingerprint(&self.target.body)?,
            "inode":self.identity,"mount":self.mount}),
        )
    }
}

#[cfg(test)]
mod private_target_tests {
    use super::target_rows;
    use enzimos_platform::mountinfo;
    fn row(text: &str) -> mountinfo::Row {
        mountinfo::parse(text).unwrap().remove(0)
    }
    #[test]
    fn original_private_target_survives_only_its_exact_owned_cover_and_children() {
        let area = row(
            "41 1 0:33 /mnt/enzimos /mnt/enzimos rw,nosuid,nodev,noexec - overlay enzimos-live rw\n",
        );
        let root =
            row("42 41 0:51 /enzimos-root /mnt/enzimos rw,nosuid,nodev - btrfs /dev/vda3 rw\n");
        let child = row(
            "43 42 0:51 /enzimos-home /mnt/enzimos/home rw,nosuid,nodev - btrfs /dev/vda3 rw\n",
        );
        assert!(target_rows(std::slice::from_ref(&area), &area, &[]).is_ok());
        let rows = vec![area.clone(), root.clone(), child.clone()];
        assert!(target_rows(&rows, &area, &[root.clone(), child.clone()]).is_ok());
        assert!(target_rows(&rows, &area, &[]).is_err());
        assert!(target_rows(&rows, &area, std::slice::from_ref(&root)).is_err());
        assert!(
            target_rows(
                &[root.clone(), child.clone()],
                &area,
                &[root.clone(), child.clone()]
            )
            .is_err()
        );
        let mut replaced = area.clone();
        replaced.id += 9;
        assert!(
            target_rows(
                &[replaced, root.clone(), child.clone()],
                &area,
                &[root.clone(), child.clone()]
            )
            .is_err()
        );
        let mut wrong_parent = root.clone();
        wrong_parent.parent = 1;
        assert!(
            target_rows(
                &[area.clone(), wrong_parent.clone()],
                &area,
                &[wrong_parent]
            )
            .is_err()
        );
        let mut extra = child.clone();
        extra.id += 10;
        assert!(
            target_rows(
                &[area.clone(), root.clone(), child.clone(), extra],
                &area,
                &[root, child]
            )
            .is_err()
        );
        assert!(target_rows(&[area.clone(), area.clone()], &area, &[]).is_err());
    }
}
