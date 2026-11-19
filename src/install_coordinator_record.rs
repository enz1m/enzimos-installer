// SPDX-License-Identifier: MIT
//! An append-only boot-local preparation record never permits replay.
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
pub const PHASES: [&str; 6] = [
    "partitioned",
    "formatted",
    "root-ready",
    "subvolumes-ready",
    "bootable",
    "storage-closed",
];
fn text<'a>(body: &'a Value, name: &str) -> Result<&'a str> {
    body[name]
        .as_str()
        .ok_or_else(|| Error("coordinator field type differs".into()))
}
fn seal(body: &mut Value) -> Result<()> {
    body.as_object_mut().unwrap().remove("journal_sha256");
    body["journal_sha256"] = value!(json::fingerprint(body)?);
    Ok(())
}
pub fn validate(body: &Value) -> Result<()> {
    json::fields(
        body,
        "schema operation boot_id disk_sha256 answers_sha256 answer_binding_sha256 media_sha256 phase steps installed_qualification journal_sha256",
    )?;
    require(
        body["schema"].as_u64() == Some(1)
            && body["operation"] == "prepare-bootable-installation"
            && body["installed_qualification"] == false,
        "coordinator schema or qualification differs",
    )?;
    enzimos_policy::identity::uuid(text(body, "boot_id")?)?;
    for name in [
        "disk_sha256",
        "answers_sha256",
        "answer_binding_sha256",
        "media_sha256",
        "journal_sha256",
    ] {
        enzimos_policy::identity::sha(text(body, name)?)?;
    }
    let steps = body["steps"]
        .as_array()
        .ok_or_else(|| Error("coordinator steps type".into()))?;
    require(steps.len() <= PHASES.len(), "coordinator steps bound")?;
    for (step, phase) in steps.iter().zip(PHASES) {
        json::fields(step, "phase evidence_sha256")?;
        require(
            step["phase"] == phase,
            "coordinator phase prefix skipped or replayed",
        )?;
        enzimos_policy::identity::sha(text(step, "evidence_sha256")?)?;
    }
    require(
        text(body, "phase")?
            == steps
                .last()
                .map(|s| text(s, "phase"))
                .transpose()?
                .unwrap_or("admitted"),
        "coordinator phase differs from observed history",
    )?;
    let mut unsealed = body.clone();
    unsealed.as_object_mut().unwrap().remove("journal_sha256");
    require(
        body["journal_sha256"] == json::fingerprint(&unsealed)?,
        "coordinator journal digest differs",
    )
}
pub fn initial(
    boot: &str,
    disk: &Value,
    answers: &Value,
    answer_binding: &Value,
    media: &str,
) -> Result<Value> {
    let mut body = value!({"schema":1,"operation":"prepare-bootable-installation","boot_id":boot,
        "disk_sha256":json::fingerprint(disk)?,"answers_sha256":json::fingerprint(answers)?,
        "answer_binding_sha256":json::fingerprint(answer_binding)?,"media_sha256":media,
        "phase":"admitted","steps":[],"installed_qualification":false});
    seal(&mut body)?;
    validate(&body)?;
    Ok(body)
}
pub fn advance(before: &Value, phase: &str, evidence: &Value) -> Result<Value> {
    validate(before)?;
    let index = before["steps"].as_array().unwrap().len();
    require(
        PHASES.get(index).copied() == Some(phase),
        "coordinator cannot replay or skip a phase",
    )?;
    let mut next = before.clone();
    next["phase"] = value!(phase);
    next["steps"]
        .as_array_mut()
        .unwrap()
        .push(value!({"phase":phase,"evidence_sha256":json::fingerprint(evidence)?}));
    seal(&mut next)?;
    validate(&next)?;
    Ok(next)
}
fn directory_identity(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "private Root coordinator directory required",
    )?;
    Ok(
        value!({"shape":[m.dev(),m.ino(),m.mode(),m.uid(),m.gid()],"mount":mount_identity::id(file.as_fd(),true)?}),
    )
}
pub(crate) struct Store {
    path: PathBuf,
    directory: File,
    directory_identity: Value,
    current: File,
    identity: files::FileIdentity,
    body: Value,
}
impl Store {
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(self.body.clone())
    }
    pub(crate) fn create(path: &Path, body: Value) -> Result<Self> {
        validate(&body)?;
        let directory = files::ensure_directory(path.parent().unwrap(), 0o700, 0)?;
        let directory_identity = directory_identity(&directory)?;
        let current = files::atomic_relative_retained(
            &directory,
            Path::new(path.file_name().unwrap()),
            &json::canonical(&body)?,
            0o600,
            Some(0),
            false,
            65536,
        )?;
        let identity = files::identity(&current.metadata()?);
        let store = Self {
            path: path.into(),
            directory,
            directory_identity,
            current,
            identity,
            body,
        };
        store.recheck()?;
        Ok(store)
    }
    fn recheck(&self) -> Result<()> {
        let directory = files::directory(self.path.parent().unwrap(), Some(0))?;
        require(
            directory_identity(&directory)? == self.directory_identity
                && directory_identity(&self.directory)? == self.directory_identity,
            "coordinator directory replaced or remounted",
        )?;
        let named =
            files::open_relative(&self.directory, Path::new(self.path.file_name().unwrap()))?;
        let m = self.current.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && files::identity(&m) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.current.as_fd(), true)?
                    == self.directory_identity["mount"].as_u64().unwrap()
                && mount_identity::id(named.as_fd(), true)?
                    == self.directory_identity["mount"].as_u64().unwrap()
                && json::decode(
                    &files::read_file(&self.current, 65536, Some(0), true)?,
                    65536,
                )? == self.body,
            "original coordinator receipt changed or replaced",
        )
    }
    pub(crate) fn checkpoint(&mut self, phase: &str, evidence: &Value) -> Result<()> {
        self.recheck()?;
        let next = advance(&self.body, phase, evidence)?;
        self.current = files::atomic_replace_original(
            &self.directory,
            Path::new(self.path.file_name().unwrap()),
            &json::canonical(&next)?,
            0o600,
            Some(0),
            65536,
            &self.current,
        )?;
        self.identity = files::identity(&self.current.metadata()?);
        self.body = next;
        self.recheck()
    }
}
