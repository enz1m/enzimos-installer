// SPDX-License-Identifier: MIT
//! Durable one-shot package journal on the target's independent control subvolume.
use crate::{package_job as job, target_storage::Target};
use enzimos_platform::{Result, files, json, mount_identity, require};
use enzimos_system_backend::{
    native_worker_contract::Definition,
    native_worker_manager::{self, Owner},
    system_manager::Manager,
};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
const MAX: usize = 512 * 1024;
fn identity(directory: &File) -> Result<(u64, u64, u32, u32, u32, u64)> {
    let m = directory.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "private package record directory required",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        mount_identity::id(directory.as_fd(), true)?,
    ))
}
fn measured(owner: &Owner, id: &str) -> Result<Value> {
    require(
        owner.state.group == format!("/system.slice/{}", job::unit(id)?)
            && owner.state.pid == owner.process.stat.pid,
        "package worker role or PID differs",
    )?;
    Ok(
        value!({"pid":owner.state.pid,"start_ticks":owner.process.stat.start_ticks,
        "invocation":owner.state.invocation.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "executable_sha256":owner.executable_sha256,"unit":job::unit(id)?}),
    )
}
pub struct Store {
    directory: File,
    path: PathBuf,
    identity: (u64, u64, u32, u32, u32, u64),
    pub(crate) journal: Value,
}
impl Store {
    pub(crate) fn receive(directory: File, request: &Value, invocation: &str) -> Result<Self> {
        job::request(request)?;
        let path = Path::new("/mnt/enzimos/var/lib/enzimos-control/installations")
            .join(request["id"].as_str().unwrap());
        let mut this = Self {
            identity: identity(&directory)?,
            directory,
            path,
            journal: Value::Null,
        };
        let journal = this.current()?;
        require(
            journal["request"] == *request
                && journal["phase"] == "handoff"
                && journal["owner"]["pid"].as_u64() == Some(u64::from(std::process::id()))
                && journal["owner"]["invocation"] == invocation,
            "package handoff differs from the durable measured invocation",
        )?;
        this.journal = journal;
        this.require_current()?;
        Ok(this)
    }
    pub fn create(
        target: &mut Target<'_>,
        media: &crate::media_packages::Admitted,
        request: Value,
    ) -> Result<Self> {
        target.recheck()?;
        job::request(&request)?;
        require(
            target.package_request_for(
                media,
                request["id"].as_str().unwrap(),
                request["operation"].as_str().unwrap(),
            )? == request,
            "package intent differs from current retained target, media or native caller",
        )?;
        let journal = job::initial(request)?;
        require(
            json::canonical(&journal)?.len() <= MAX,
            "package record byte bound",
        )?;
        target.begin_package_job(&journal["request"])?;
        let parent = Path::new("/mnt/enzimos/var/lib/enzimos-control/installations");
        files::ensure_directory(parent, 0o700, 0)?;
        let path = parent.join(journal["request"]["id"].as_str().unwrap());
        let directory = files::create_directory(&path, 0o700, 0)?;
        let this = Self {
            identity: identity(&directory)?,
            directory,
            path,
            journal,
        };
        files::atomic(
            &this.path.join("package.json"),
            &json::canonical(&this.journal)?,
            0o600,
            Some(0),
            false,
        )?;
        target.recheck()?;
        this.require_current()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        crate::setup::live()?;
        require(
            identity(&self.directory)? == self.identity
                && identity(&files::directory(&self.path, Some(0))?)? == self.identity,
            "package journal directory replaced",
        )
    }
    pub fn current(&self) -> Result<Value> {
        self.recheck()?;
        let file = files::open_relative(&self.directory, Path::new("package.json"))?;
        require(
            mount_identity::id(file.as_fd(), true)? == self.identity.5
                && file.metadata()?.mode() & 0o7777 == 0o600,
            "package record left retained control filesystem or changed mode",
        )?;
        let body = json::decode(&files::read_file(&file, MAX, Some(0), true)?, MAX)?;
        job::validate(&body)?;
        self.recheck()?;
        Ok(body)
    }
    pub fn require_current(&self) -> Result<()> {
        require(
            self.current()? == self.journal,
            "package journal changed outside the owned phase transition",
        )
    }
    fn publish(&mut self, next: Value) -> Result<()> {
        self.require_current()?;
        job::transition(Some(&self.journal), &next)?;
        let bytes = json::canonical(&next)?;
        require(bytes.len() <= MAX, "package checkpoint byte bound")?;
        files::atomic(
            &self.path.join("package.json"),
            &bytes,
            0o600,
            Some(0),
            true,
        )?;
        require(
            self.current()? == next,
            "package checkpoint readback differs",
        )?;
        self.journal = next;
        self.require_current()
    }
    pub fn handoff(&mut self, owner: &Owner) -> Result<()> {
        owner.recheck()?;
        let mut next = self.journal.clone();
        next["phase"] = value!("handoff");
        next["owner"] = measured(owner, next["request"]["id"].as_str().unwrap())?;
        self.publish(next)?;
        owner.recheck()
    }
    /// Only the measured worker may publish running/stopping; completion belongs
    /// to its caller after independently observed PID1 and cgroup teardown.
    pub fn worker_checkpoint(&mut self, phase: &str) -> Result<()> {
        require(
            matches!(phase, "running" | "stopping"),
            "worker checkpoint cannot complete a package attempt",
        )?;
        let owner = &self.journal["owner"];
        let pid = std::process::id();
        require(
            owner["pid"].as_u64() == Some(u64::from(pid)),
            "only the measured package worker may publish execution checkpoints",
        )?;
        let parent = files::directory(Path::new(job::EXECUTABLE).parent().unwrap(), Some(0))?;
        let image = files::open_relative(
            &parent,
            Path::new(Path::new(job::EXECUTABLE).file_name().unwrap()),
        )?;
        let process = enzimos_platform::process_identity::Retained::open(
            pid,
            owner["start_ticks"]
                .as_u64()
                .ok_or_else(|| enzimos_platform::Error("package worker clock missing".into()))?,
            0,
            &[PathBuf::from(job::EXECUTABLE)],
        )?
        .pin_executable(&image)?;
        process.recheck()?;
        let group = files::read_kernel(&PathBuf::from(format!("/proc/{pid}/cgroup")), 8192)?;
        require(
            owner["executable_sha256"]
                == json::sha256(&files::read_file(&image, 32 * 1024 * 1024, Some(0), true)?)
                && group
                    == format!(
                        "0::/system.slice/{}\n",
                        job::unit(self.journal["request"]["id"].as_str().unwrap())?
                    )
                    .as_bytes(),
            "package worker image or owned kernel cgroup changed",
        )?;
        let mut next = self.journal.clone();
        next["phase"] = value!(phase);
        next["exit_code"] = if phase == "stopping" {
            value!(0)
        } else {
            Value::Null
        };
        self.publish(next)
    }
    pub fn accept(&mut self, next: Value) -> Result<()> {
        job::transition(Some(&self.journal), &next)?;
        require(
            matches!(next["phase"].as_str(), Some("running" | "stopping"))
                && self.current()? == next,
            "package notification is not the exact durable worker checkpoint",
        )?;
        self.journal = next;
        self.require_current()
    }
    pub async fn complete(
        &mut self,
        target: &Target<'_>,
        media: &crate::media_packages::Admitted,
        manager: &Manager,
        owner: &Owner,
    ) -> Result<Value> {
        target.recheck()?;
        media.recheck()?;
        self.require_current()?;
        let id = self.journal["request"]["id"].as_str().unwrap().to_owned();
        require(
            self.journal["phase"] == "stopping" && self.journal["owner"] == measured(owner, &id)?,
            "package completion requires the measured stopped worker attempt",
        )?;
        native_worker_manager::stop_for(manager, &Definition::installer(&id)?, owner).await?;
        target.recheck()?;
        media.recheck()?;
        let expected = crate::native_package_body::expected(
            media,
            self.journal["request"]["operation"].as_str().unwrap(),
        )?;
        crate::package_body::database(target.directory()?, &expected)?;
        if self.journal["request"]["operation"] != job::ARCH {
            crate::install_authority::completed(
                target.directory()?,
                media,
                &self.journal,
                self.directory(),
            )?;
        }
        let configuration = if self.journal["request"]["operation"]
            .as_str()
            .is_some_and(job::configured)
        {
            Some(crate::install_configuration::completed(
                target,
                &self.journal,
                self.directory(),
            )?)
        } else {
            None
        };
        if self.journal["request"]["operation"] == job::BOOT {
            crate::test_copy::completed(target, &self.journal, self.directory())?;
            let flatpaks =
                crate::flatpak_verify::completed(target, media, &self.journal, self.directory())?;
            let desktop =
                crate::desktop_verify::completed(target, &self.journal, self.directory())?;
            let boot = crate::install_boot::completed(
                target,
                media,
                &self.journal,
                self.directory(),
                configuration.as_ref().unwrap(),
            )?;
            crate::desktop_overlay_finalize::completed(
                target,
                media,
                &self.journal,
                self.directory(),
                configuration.as_ref().unwrap(),
                &boot,
                desktop.as_ref(),
                flatpaks.as_ref(),
            )?;
        }
        if self.journal["request"]["operation"] == job::BOOT {
            crate::install_bios_caller::install(
                target,
                media,
                &self.journal,
                self.directory(),
                owner,
            )?;
        }
        self.require_current()?;
        let mut next = self.journal.clone();
        next["phase"] = value!("complete");
        next["group_empty"] = value!(true);
        self.publish(next)?;
        Ok(self.journal.clone())
    }
    pub fn directory(&self) -> &File {
        &self.directory
    }
}
