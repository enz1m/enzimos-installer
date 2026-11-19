// SPDX-License-Identifier: MIT
//! Read-only sideload inputs are closed and admitted before destructive work.
use crate::media_source::Media;
use enzimos_platform::{Error, Result, files, mount_identity, require};
use enzimos_policy::flatpak_plan::{self, Source};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};

/// Where a remote's offline source sits on the medium and in its manifest.
pub(crate) struct Layout {
    pub source: Source,
    /// Media directory holding `apps.txt`, the `.flatpakrepo` and the create-usb `repo/`.
    pub directory: &'static str,
    pub remote_file: &'static str,
    pub declaration: &'static str,
}
pub(crate) const FLATHUB: Layout = Layout {
    source: Source::Flathub,
    directory: "flatpak",
    remote_file: "flathub.flatpakrepo",
    declaration: "flatpaks",
};
/// Its apps need Flathub's runtime, so it is installed after Flathub's apps.
pub(crate) const ENZIMOS: Layout = Layout {
    source: Source::Enzimos,
    directory: "flatpak-enzimos",
    remote_file: "enzimos.flatpakrepo",
    declaration: "enzimos_flatpaks",
};
impl Layout {
    fn member(&self, leaf: &str) -> String {
        format!("{}/{leaf}", self.directory)
    }
    /// Media without the declaration (older media) carry no apps from this remote.
    pub(crate) fn declared<'a>(&self, manifest: &'a Value) -> Result<&'a [Value]> {
        match manifest.get(self.declaration) {
            None if self.source == Source::Enzimos => Ok(&[]),
            declared => Ok(declared
                .and_then(Value::as_array)
                .ok_or_else(|| Error("offline application declaration type".into()))?),
        }
    }
}
pub(crate) struct Prepared {
    pub layout: &'static Layout,
    pub apps: Vec<String>,
    pub policy: Value,
    pub remote: File,
    pub list: File,
    pub repo: File,
    remote_identity: files::FileIdentity,
    list_identity: files::FileIdentity,
    repo_identity: files::FileIdentity,
    mount: u64,
}
impl Prepared {
    pub(crate) fn observe(
        media: &Media,
        manifest: &Value,
        layout: &'static Layout,
    ) -> Result<Option<Self>> {
        let declared = layout.declared(manifest)?;
        let prefix = layout.member("");
        if declared.is_empty() {
            require(
                !media.members.keys().any(|n| n.starts_with(&prefix)),
                "undeclared offline application media",
            )?;
            return Ok(None);
        }
        require(
            declared.len() <= 128,
            "offline application declaration bound",
        )?;
        let list = media.member(&layout.member("apps.txt"), 64 * 1024)?;
        let remote = media.member(&layout.member(layout.remote_file), 128 * 1024)?;
        let apps = flatpak_plan::applications(
            layout.source,
            &files::read_file(&list, 64 * 1024, Some(0), true)?,
            &Value::from(declared),
        )?;
        let policy = flatpak_plan::remote(
            layout.source,
            &files::read_file(&remote, 128 * 1024, Some(0), true)?,
        )?;
        let repo = media.repository(layout.directory)?;
        flatpak_plan::repository(&media.read(&layout.member("repo/config"), 64 * 1024)?)?;
        let repo_prefix = layout.member("repo/");
        require(
            media
                .members
                .keys()
                .filter(|name| name.starts_with(&prefix))
                .all(|name| {
                    *name == layout.member("apps.txt")
                        || *name == layout.member(layout.remote_file)
                        || name.starts_with(&repo_prefix)
                }),
            "offline application media contains an unregistered source",
        )?;
        let mount = mount_identity::id(repo.as_fd(), true)?;
        closed_repository(media, layout, &repo, mount)?;
        let prepared = Self {
            layout,
            remote_identity: files::identity(&remote.metadata()?),
            list_identity: files::identity(&list.metadata()?),
            repo_identity: files::identity(&repo.metadata()?),
            apps,
            policy,
            remote,
            list,
            repo,
            mount,
        };
        prepared.recheck(media)?;
        Ok(Some(prepared))
    }
    pub(crate) fn recheck(&self, media: &Media) -> Result<()> {
        media.recheck()?;
        let layout = self.layout;
        for (name, held, identity) in [
            (layout.member("apps.txt"), &self.list, self.list_identity),
            (
                layout.member(layout.remote_file),
                &self.remote,
                self.remote_identity,
            ),
        ] {
            let named = media.opened(&name)?;
            require(
                files::identity(&held.metadata()?) == identity
                    && files::identity(&named.metadata()?) == identity
                    && mount_identity::id(held.as_fd(), true)? == self.mount
                    && mount_identity::id(named.as_fd(), true)? == self.mount,
                "original offline application policy replaced",
            )?;
        }
        let named = media.repository(layout.directory)?;
        require(
            files::identity(&self.repo.metadata()?) == self.repo_identity
                && files::identity(&named.metadata()?) == self.repo_identity
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original immutable sideload repository replaced",
        )
    }
    pub(crate) fn receipt(&self) -> Value {
        value!({"schema":1,"apps":self.apps,"policy":self.policy,"list_inode":self.list_identity,"remote_inode":self.remote_identity,"repo_inode":self.repo_identity,"mount":self.mount})
    }
}
fn closed_repository(media: &Media, layout: &Layout, repo: &File, mount: u64) -> Result<()> {
    let mut actual = BTreeSet::new();
    let mut entries = 0;
    let prefix = layout.member("repo/");
    walk_repository(repo, repo, "", &prefix, mount, &mut entries, &mut actual)?;
    let declared = media
        .members
        .keys()
        .filter(|n| n.starts_with(&prefix))
        .cloned()
        .collect::<BTreeSet<_>>();
    require(
        actual == declared && actual.contains(&layout.member("repo/config")) && actual.len() > 2,
        "sideload repository differs from the closed immutable media manifest",
    )?;
    media.recheck()
}
fn walk_repository(
    repo: &File,
    directory: &File,
    relative: &str,
    prefix: &str,
    mount: u64,
    entries: &mut usize,
    actual: &mut BTreeSet<String>,
) -> Result<()> {
    let before = files::identity(&directory.metadata()?);
    require(
        mount_identity::id(directory.as_fd(), true)? == mount,
        "sideload directory crosses a mount",
    )?;
    let remaining = 131072usize
        .checked_sub(*entries)
        .ok_or_else(|| Error("sideload repository entry count bound".into()))?;
    if remaining == 0 {
        require(
            files::directory_is_empty(directory)?,
            "sideload repository entry count bound",
        )?;
        return Ok(());
    }
    for leaf in files::directory_names(directory, remaining)? {
        *entries += 1;
        require(*entries <= 131072, "sideload repository entry count bound")?;
        let leaf = leaf
            .into_string()
            .map_err(|_| Error("sideload path encoding".into()))?;
        let entry = enzimos_platform::directory_entry::Entry::observe(directory, Path::new(&leaf))?;
        let name = if relative.is_empty() {
            leaf.clone()
        } else {
            format!("{relative}/{leaf}")
        };
        crate::media_manifest::relative(&name)?;
        require(
            name.split('/').count() <= 64,
            "sideload directory depth bound",
        )?;
        let m = entry.metadata()?;
        require(
            m.uid() == 0 && m.gid() == 0 && (m.file_type().is_symlink() || m.mode() & 0o022 == 0),
            "sideload member ownership or protection",
        )?;
        if m.is_dir() {
            let child = files::directory_relative(directory, Path::new(&leaf), Some(0))?;
            entry.matches(&child)?;
            require(
                mount_identity::id(child.as_fd(), true)? == mount,
                "sideload child crosses a mount",
            )?;
            walk_repository(repo, &child, &name, prefix, mount, entries, actual)?;
            entry.matches(&child)?;
            continue;
        }
        require(
            m.is_file() || m.file_type().is_symlink(),
            "sideload special file refused",
        )?;
        // A link must resolve to a regular file beneath this exact repo:
        // directory aliases, escapes and proc-style links have no fallback.
        let file = crate::media_source::repository_member(repo, &name)?;
        if m.is_file() {
            entry.matches(&file)?;
        }
        require(
            mount_identity::id(file.as_fd(), true)? == mount && file.metadata()?.nlink() == 1,
            "sideload linked member mount or identity",
        )?;
        entry.recheck()?;
        actual.insert(format!("{prefix}{name}"));
    }
    require(
        files::identity(&directory.metadata()?) == before
            && mount_identity::id(directory.as_fd(), true)? == mount,
        "original sideload directory changed during traversal",
    )
}
pub(crate) fn preflight(media: &Media, manifest: &Value) -> Result<()> {
    let flathub = Prepared::observe(media, manifest, &FLATHUB)?;
    let enzimos = Prepared::observe(media, manifest, &ENZIMOS)?;
    require(
        enzimos.is_none() || flathub.is_some(),
        "enzimOS apps need the Flathub runtime source on the same medium",
    )?;
    for prepared in flathub.iter().chain(enzimos.iter()) {
        let _ = prepared.receipt();
        prepared.recheck(media)?;
    }
    Ok(())
}
