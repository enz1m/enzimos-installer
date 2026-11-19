// SPDX-License-Identifier: MIT
//! PID1 package service accepts only the caller's actual retained descriptions.
use crate::{package_job as job, package_record::Store};
use enzimos_platform::{
    Error, Result,
    fd_packet::{Credentials, Message},
    files, json, memfile, mount_identity, mountinfo, process_identity, require,
};
use enzimos_policy::{filesystem, namespaces, operation, storage_runtime, subvolume, topology};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
pub const FILES: usize = 6;
pub const SYSTEM_FILES: usize = 7;
pub const BOOT_FILES: usize = 8;
pub const OWNER_BOOT_FILES: usize = 9;
pub const TEST_BOOT_FILES: usize = 9;
pub const OWNER_TEST_BOOT_FILES: usize = 10;
pub const MAX_REQUEST: usize = 512 * 1024;
pub fn frame(body: &Value, sender: &Credentials, id: &str) -> Result<Vec<u32>> {
    let boot = body["schema"] == 3 || body["schema"] == 4;
    json::fields(
        body,
        if boot {
            "schema id request_sha256 original_fds owner_credentials"
        } else {
            "schema id request_sha256 original_fds"
        },
    )?;
    job::id(id)?;
    require(
        matches!(body["schema"].as_u64(), Some(1..=4))
            && body["id"] == id
            && sender.uid == 0
            && sender.gid == 0
            && sender.pid > 1,
        "package handoff kernel sender or attempt differs",
    )?;
    enzimos_policy::identity::sha(
        body["request_sha256"]
            .as_str()
            .ok_or_else(|| Error("package request digest missing".into()))?,
    )?;
    let entries = body["original_fds"]
        .as_array()
        .ok_or_else(|| Error("package original descriptions missing".into()))?;
    if boot {
        require(
            body["owner_credentials"].is_boolean(),
            "boot handoff owner description flag type",
        )?;
    }
    let count = if boot {
        if body["owner_credentials"] == true {
            OWNER_BOOT_FILES + usize::from(body["schema"] == 4)
        } else {
            BOOT_FILES + usize::from(body["schema"] == 4)
        }
    } else if body["schema"] == 2 {
        SYSTEM_FILES
    } else {
        FILES
    };
    require(entries.len() == count, "package original description count")?;
    let entries = entries
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|n| (3..1_048_576).contains(n))
                .map(|n| n as u32)
                .ok_or_else(|| Error("package original descriptor number".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    require(
        entries.iter().collect::<BTreeSet<_>>().len() == count,
        "duplicate package original descriptor",
    )?;
    Ok(entries)
}
pub(crate) fn actor(body: &Value, path: &str) -> Result<process_identity::Retained> {
    json::fields(body, "pid start_ticks executable_sha256")?;
    let pid = body["pid"]
        .as_u64()
        .filter(|p| *p > 1 && *p < i32::MAX as u64)
        .ok_or_else(|| Error("native package actor PID".into()))? as u32;
    let clock = body["start_ticks"]
        .as_u64()
        .filter(|c| *c > 0)
        .ok_or_else(|| Error("native package actor clock".into()))?;
    let parent = files::directory(Path::new(path).parent().unwrap(), Some(0))?;
    let image = files::open_relative(&parent, Path::new(Path::new(path).file_name().unwrap()))?;
    let bytes = files::read_file(&image, 32 * 1024 * 1024, Some(0), true)?;
    require(
        bytes.starts_with(b"\x7fELF") && body["executable_sha256"] == json::sha256(&bytes),
        "native package actor image differs",
    )?;
    let process = process_identity::Retained::open(pid, clock, 0, &[PathBuf::from(path)])?
        .pin_executable(&image)?;
    for kind in namespaces::KINDS {
        require(
            namespaces::identity(pid, kind)? == namespaces::identity(2, kind)?,
            "package actor left initial kernel namespaces",
        )?;
    }
    process.recheck()?;
    Ok(process)
}
fn directory(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o7022 == 0,
        "package retained directory protection",
    )?;
    Ok(value!([
        m.dev(),
        m.ino(),
        u64::from(m.uid()),
        u64::from(m.gid()),
        u64::from(m.mode())
    ]))
}
fn scope() -> Result<Vec<mountinfo::Row>> {
    Ok(storage_runtime::rows()?
        .into_iter()
        .filter(|r| r.target == "/mnt/enzimos" || r.target.starts_with("/mnt/enzimos/"))
        .collect())
}
pub struct Received {
    pub request: Value,
    pub store: Store,
    pub target: File,
    pub caller: process_identity::Retained,
    pub caller_pidfd: File,
    pub answers: Option<crate::answer_source::Source>,
    pub boot_disk: Option<File>,
    boot_owner: Option<File>,
    media: File,
    lock: File,
    sealed: File,
    originals: Vec<u32>,
    scope: Vec<mountinfo::Row>,
    filesystem: Value,
    subvolume: Value,
    graph: topology::Graph,
    control: Value,
    control_mount: u64,
    recent: crate::recheck_cache::Recent,
}
impl Received {
    /// The service-manager adapter has already measured this MainPID/invocation.
    pub fn inspect(message: Message, id: &str, invocation: &str) -> Result<Self> {
        crate::setup::live()?;
        let body = json::decode(&message.body, 4096)?;
        let originals = frame(&body, &message.sender, id)?;
        require(
            message.files.len() == originals.len(),
            "package handoff descriptor count",
        )?;
        let mut descriptors = message.files.into_iter().map(File::from);
        let sealed = descriptors.next().unwrap();
        let request = json::decode(&memfile::read_sealed(&sealed, MAX_REQUEST, 0)?, MAX_REQUEST)?;
        job::request(&request)?;
        require(
            request["id"] == id
                && request["schema"] == body["schema"]
                && request["boot_id"] == operation::boot_id()?
                && request["caller"]["pid"].as_u64() == Some(u64::from(message.sender.pid))
                && json::fingerprint(&request)? == body["request_sha256"],
            "package sealed request differs from original caller or boot",
        )?;
        let caller = actor(&request["caller"], job::CALLER)?;
        let target = descriptors.next().unwrap();
        let record = descriptors.next().unwrap();
        let media = descriptors.next().unwrap();
        let lock = descriptors.next().unwrap();
        let caller_pidfd = descriptors.next().unwrap();
        let answer = descriptors.next();
        let boot_disk = descriptors.next();
        let boot_owner = if body["owner_credentials"] == true {
            descriptors.next()
        } else {
            None
        };
        let test_script = if body["schema"] == 4 {
            descriptors.next()
        } else {
            None
        };
        let mut descriptions = vec![&sealed, &target, &record, &media, &lock, &caller_pidfd];
        if let Some(file) = &answer {
            descriptions.push(file);
        }
        if let Some(file) = &boot_disk {
            descriptions.push(file);
        }
        if let Some(file) = &boot_owner {
            descriptions.push(file);
        }
        if let Some(file) = &test_script {
            descriptions.push(file);
        }
        caller.require_descriptions(
            &descriptions
                .iter()
                .zip(&originals)
                .map(|(file, number)| (file.as_fd(), *number))
                .collect::<Vec<_>>(),
        )?;
        require(
            process_identity::pidfd_target(caller_pidfd.as_fd())? == caller.stat.pid,
            "package caller pidfd differs",
        )?;
        let store = Store::receive(record, &request, invocation)?;
        let self_actor = actor(
            &value!({"pid":store.journal["owner"]["pid"],"start_ticks":store.journal["owner"]["start_ticks"],"executable_sha256":store.journal["owner"]["executable_sha256"]}),
            job::EXECUTABLE,
        )?;
        require(
            self_actor.stat.pid == std::process::id() && self_actor.stat.parent == 1,
            "package supervisor must be the original PID1 worker",
        )?;
        // All original descriptions and the measured service owner are checked
        // before any password or disk passphrase is read into protected memory.
        if request["operation"] == job::BOOT {
            require(
                body["owner_credentials"] == !request["boot"]["security"]["owner"].is_null(),
                "optional owner descriptor differs from sealed boot authority before private reads",
            )?;
        }
        let answers = if let Some(file) = answer {
            let source = crate::answer_source::Source::received_with_test(
                file,
                Path::new(
                    request["configuration"]["answers"]["path"]
                        .as_str()
                        .unwrap(),
                ),
                test_script,
            )?;
            require(
                source.binding()? == request["configuration"]["answers"],
                "handed-off answer source differs from original sealed inode and mount",
            )?;
            require(
                !source.answers.test_check || request["operation"] == job::BOOT,
                "test mode cannot use partial package role",
            )?;
            Some(source)
        } else {
            None
        };
        if request["operation"] == job::BOOT {
            let source = answers.as_ref().unwrap();
            require(
                source.answers.test_check == (request["schema"] == 4),
                "test mode differs from sealed descriptor authority",
            )?;
            if let Some(copy) = &source.test_copy {
                require(
                    copy.binding()? == request["boot"]["test_copy"],
                    "original test descriptor differs from sealed binding",
                )?;
                let block = &request["boot"]["disk"]["block"];
                copy.independent((
                    block["major"].as_u64().unwrap() as u32,
                    block["minor"].as_u64().unwrap() as u32,
                ))?;
            }
            require(
                body["owner_credentials"] == !request["boot"]["security"]["owner"].is_null()
                    && answers.as_ref().unwrap().boot_security.receipt()?
                        == request["boot"]["security"],
                "boot security handoff differs from original staged authority",
            )?;
            if let Some(owner) = &boot_owner {
                require(
                    directory(owner)? == request["boot"]["security"]["owner"]["directory"]["inode"]
                        && mount_identity::id(owner.as_fd(), true)?
                            == request["boot"]["security"]["owner"]["directory"]["mount"]
                                .as_u64()
                                .unwrap(),
                    "original staged owner description differs from sealed boot authority",
                )?;
            }
        }
        let filesystem = filesystem::observe(target.as_fd())?;
        if request["operation"].as_str().is_some_and(job::configured) {
            require(
                request["configuration"]["filesystem_uuid"] == filesystem["filesystem_uuid"],
                "configuration root UUID differs from kernel-observed retained filesystem",
            )?;
        }
        let (subvolume, readonly) = subvolume::observe(target.as_fd(), "enzimos-root")?;
        let control_fs = filesystem::observe(store.directory().as_fd())?;
        let (control, control_ro) =
            subvolume::observe(store.directory().as_fd(), "enzimos-control")?;
        require(
            !readonly
                && !control_ro
                && subvolume["parent_uuid"].is_null()
                && control["parent_uuid"].is_null()
                && control_fs == filesystem
                && control["uuid"] != subvolume["uuid"],
            "package target/control filesystem lineage differs",
        )?;
        let graph = topology::mounted_btrfs(filesystem["filesystem_uuid"].as_str().unwrap())?;
        let this = Self {
            recent: crate::recheck_cache::Recent::new(),
            control_mount: mount_identity::id(store.directory().as_fd(), true)?,
            scope: scope()?,
            request,
            store,
            target,
            caller,
            caller_pidfd,
            answers,
            boot_disk,
            boot_owner,
            media,
            lock,
            sealed,
            originals,
            filesystem,
            subvolume,
            graph,
            control,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.recheck_staged(&|_| {})
    }
    /// Fixed component diagnostics only: never source answers or vendor text.
    pub(crate) fn supervised_recheck(&self) -> Result<()> {
        let stage = std::cell::Cell::new("initial namespace");
        self.recheck_staged(&|label| stage.set(label)).map_err(|_| {
            Error(format!(
                "native package worker original {} admission failed",
                stage.get()
            ))
        })
    }
    fn recheck_staged(&self, stage: &dyn Fn(&'static str)) -> Result<()> {
        // Called per extracted file and by the supervision loop; a full check from the
        // last second stands (on a slow laptop thousands of repeats cost minutes).
        if self.recent.fresh() {
            return Ok(());
        }
        self.recheck_full(stage)?;
        self.recent.mark();
        Ok(())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, flock).")]
    fn recheck_full(&self, stage: &dyn Fn(&'static str)) -> Result<()> {
        stage("initial namespace");
        crate::setup::live()?;
        stage("caller process");
        self.caller.recheck()?;
        for kind in namespaces::KINDS {
            require(
                namespaces::identity(self.caller.stat.pid, kind)? == namespaces::identity(2, kind)?,
                "original installer caller left initial kernel namespaces",
            )?;
        }
        stage("durable journal");
        self.store.require_current()?;
        require(
            process_identity::pidfd_target(self.caller_pidfd.as_fd())? == self.caller.stat.pid
                && self.request["boot_id"] == operation::boot_id()?,
            "package caller lease or boot changed",
        )?;
        require(
            json::decode(
                &memfile::read_sealed(&self.sealed, MAX_REQUEST, 0)?,
                MAX_REQUEST,
            )? == self.request,
            "package sealed request changed",
        )?;
        stage("original descriptors");
        let mut descriptions = vec![
            &self.sealed,
            &self.target,
            self.store.directory(),
            &self.media,
            &self.lock,
            &self.caller_pidfd,
        ];
        stage("private answers");
        if let Some(source) = &self.answers {
            source.recheck()?;
            require(
                source.binding()? == self.request["configuration"]["answers"],
                "original private answer binding changed",
            )?;
            descriptions.push(source.descriptor());
        }
        stage("boot disk");
        if let Some(disk) = &self.boot_disk {
            descriptions.push(disk);
            require(
                crate::install_boot_disk::observe(
                    disk.as_fd(),
                    self.request["boot"]["disk"]["path"].as_str().unwrap(),
                    self.request["configuration"]["filesystem_uuid"]
                        .as_str()
                        .unwrap(),
                )? == self.request["boot"]["disk"],
                "original boot disk description or physical lineage changed",
            )?;
            let source = self.answers.as_ref().unwrap();
            require(
                std::fs::canonicalize(&source.answers.disk)?.to_str()
                    == self.request["boot"]["disk"]["path"].as_str()
                    && source.boot_security.receipt()? == self.request["boot"]["security"],
                "boot sources differ from original private answers and staged credentials",
            )?;
        }
        stage("boot owner");
        if let Some(owner) = &self.boot_owner {
            descriptions.push(owner);
            require(
                directory(owner)?
                    == self.request["boot"]["security"]["owner"]["directory"]["inode"]
                    && mount_identity::id(owner.as_fd(), true)?
                        == self.request["boot"]["security"]["owner"]["directory"]["mount"]
                            .as_u64()
                            .unwrap(),
                "original staged owner directory changed",
            )?;
        }
        stage("test copy");
        if let Some(copy) = self
            .answers
            .as_ref()
            .and_then(|source| source.test_copy.as_ref())
        {
            copy.recheck()?;
            descriptions.push(copy.descriptor());
            require(
                copy.binding()? == self.request["boot"]["test_copy"],
                "original test copy epoch changed",
            )?;
        }
        stage("caller descriptor ownership");
        self.caller.require_descriptions(
            &descriptions
                .iter()
                .zip(&self.originals)
                .map(|(file, number)| (file.as_fd(), *number))
                .collect::<Vec<_>>(),
        )?;
        stage("target directory and mount scope");
        let named = files::directory(Path::new("/mnt/enzimos"), Some(0))?;
        require(
            directory(&self.target)? == self.request["target_inode"]
                && directory(&named)? == self.request["target_inode"]
                && mount_identity::id(named.as_fd(), true)?
                    == self.request["target_mount"].as_u64().unwrap()
                && mount_identity::id(self.target.as_fd(), true)?
                    == self.request["target_mount"].as_u64().unwrap()
                && scope()? == self.scope,
            "package target or owned mount scope changed",
        )?;
        stage("filesystem and physical topology");
        require(
            filesystem::observe(self.target.as_fd())? == self.filesystem
                && filesystem::observe(self.store.directory().as_fd())? == self.filesystem
                && subvolume::observe(self.target.as_fd(), "enzimos-root")?
                    == (self.subvolume.clone(), false)
                && subvolume::observe(self.store.directory().as_fd(), "enzimos-control")?
                    == (self.control.clone(), false)
                && mount_identity::id(self.store.directory().as_fd(), true)? == self.control_mount
                && topology::mounted_btrfs(self.filesystem["filesystem_uuid"].as_str().unwrap())?
                    == self.graph,
            "package retained filesystem identities or physical members changed",
        )?;
        stage("original media");
        let media = files::directory(Path::new("/run/enzimos-live/media/enzimos"), Some(0))?;
        require(
            directory(&media)? == directory(&self.media)?
                && mount_identity::id(media.as_fd(), true)?
                    == mount_identity::id(self.media.as_fd(), true)?,
            "package source medium descriptor changed",
        )?;
        stage("operation lock");
        let parent = files::directory(Path::new("/run"), Some(0))?;
        let named = files::open_relative(&parent, Path::new("enzimos-install.lock"))?;
        let m = self.lock.metadata()?;
        require(
            m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o600
                && files::identity(&named.metadata()?) == files::identity(&m)
                && unsafe { libc::fcntl(self.lock.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK
                    != 0,
            "package operation lock identity or flags changed",
        )?;
        enzimos_platform::flock_identity::exclusive(&self.lock)?;
        let result = unsafe { libc::flock(named.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        require(
            result != 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK),
            "package operation lock is no longer held",
        )?;
        enzimos_platform::flock_identity::exclusive(&self.lock)
    }
}
