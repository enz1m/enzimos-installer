// SPDX-License-Identifier: MIT
//! Retain the fixed native worker, caller and package tools before destructive intent.
use enzimos_platform::{Result, files, mount_identity, require, stream_copy};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
struct Image {
    path: &'static str,
    file: File,
    identity: files::FileIdentity,
    mount: u64,
    sha256: String,
}
pub struct Images(Vec<Image>);
impl Images {
    pub(crate) fn open() -> Result<Self> {
        crate::setup::live()?;
        let mut images = Vec::new();
        for path in [
            crate::package_job::CALLER,
            crate::package_job::EXECUTABLE,
            "/usr/bin/pacman",
            "/usr/bin/gpg",
            "/usr/bin/gpg-agent",
            "/usr/bin/gpgconf",
            "/usr/bin/chroot",
            "/usr/bin/blkid",
            "/usr/bin/nmcli",
        ] {
            let parent = files::directory(Path::new(path).parent().unwrap(), Some(0))?;
            let file =
                files::open_relative(&parent, Path::new(Path::new(path).file_name().unwrap()))?;
            let m = file.metadata()?;
            require(
                m.mode() & 0o111 != 0
                    && files::read_file(&file, 32 * 1024 * 1024, Some(0), true)?
                        .starts_with(b"\x7fELF"),
                "native package preflight requires fixed protected ELF images",
            )?;
            images.push(Image {
                path,
                identity: files::identity(&m),
                mount: mount_identity::id(file.as_fd(), true)?,
                sha256: stream_copy::hash_borrowed(&file, 32 * 1024 * 1024, Some(0))?.1,
                file,
            });
        }
        let this = Self(images);
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        for image in &self.0 {
            let parent = files::directory(Path::new(image.path).parent().unwrap(), Some(0))?;
            let named = files::open_relative(
                &parent,
                Path::new(Path::new(image.path).file_name().unwrap()),
            )?;
            require(
                files::identity(&named.metadata()?) == image.identity
                    && files::identity(&image.file.metadata()?) == image.identity
                    && mount_identity::id(named.as_fd(), true)? == image.mount
                    && mount_identity::id(image.file.as_fd(), true)? == image.mount,
                "reviewed package tool or native worker image changed",
            )?;
        }
        Ok(())
    }
    pub fn hashes(&self) -> serde_json::Value {
        serde_json::json!(
            self.0
                .iter()
                .map(|image| (image.path, image.sha256.clone()))
                .collect::<std::collections::BTreeMap<_, _>>()
        )
    }
    pub(crate) fn get(&self, path: &str) -> Result<&File> {
        self.recheck()?;
        self.0
            .iter()
            .find(|image| image.path == path)
            .map(|image| &image.file)
            .ok_or_else(|| {
                enzimos_platform::Error("package image outside reviewed registry".into())
            })
    }
}
