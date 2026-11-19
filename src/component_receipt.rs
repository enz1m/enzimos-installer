// SPDX-License-Identifier: MIT
//! A private component intent retains every receipt epoch through its next write.
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::Value;
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const MAX: usize = 2 * 1024 * 1024;
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "private component receipt directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
pub(crate) struct Receipt {
    directory: File,
    name: &'static str,
    directory_shape: (u64, u64, u32, u32, u32),
    mount: u64,
    file: File,
    identity: files::FileIdentity,
    body: Value,
}
impl Receipt {
    pub(crate) fn create(directory: &File, name: &'static str, body: &Value) -> Result<Self> {
        let directory_shape = shape(directory)?;
        let mount = mount_identity::id(directory.as_fd(), true)?;
        let file = files::atomic_relative_retained(
            directory,
            Path::new(name),
            &json::canonical(body)?,
            0o600,
            Some(0),
            false,
            MAX,
        )?;
        let receipt = Self {
            directory: directory.try_clone()?,
            name,
            directory_shape,
            mount,
            identity: files::identity(&file.metadata()?),
            file,
            body: body.clone(),
        };
        receipt.recheck()?;
        Ok(receipt)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        let named = files::open_relative(&self.directory, Path::new(self.name))?;
        require(
            shape(&self.directory)? == self.directory_shape
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && self.identity.7 & 0o7777 == 0o600
                && self.identity.8 == 0
                && self.identity.9 == 0
                && self.identity.10 == 1
                && json::decode(&files::read_file(&self.file, MAX, Some(0), true)?, MAX)?
                    == self.body,
            "original private component receipt changed or replaced",
        )
    }
    pub(crate) fn publish(&mut self, body: &Value) -> Result<()> {
        self.recheck()?;
        let file = files::atomic_replace_original(
            &self.directory,
            Path::new(self.name),
            &json::canonical(body)?,
            0o600,
            Some(0),
            MAX,
            &self.file,
        )?;
        self.identity = files::identity(&file.metadata()?);
        self.file = file;
        self.body = body.clone();
        self.recheck()
    }
}
