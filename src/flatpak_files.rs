// SPDX-License-Identifier: MIT
//! Root and UID1000 publications remain original inodes, including OSTree links.
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub(crate) struct Held(BTreeMap<String, (File, Value)>);
impl Held {
    pub(crate) fn new() -> Self {
        Self(BTreeMap::new())
    }
    pub(crate) fn add(
        &mut self,
        root: &File,
        name: &str,
        owner: u32,
        single_link: bool,
        body: &mut Value,
    ) -> Result<Vec<u8>> {
        self.recheck(root)?;
        let (file, row, bytes) = observe(root, name, owner, single_link)?;
        require(!self.0.contains_key(name), "Flatpak output repeated")?;
        body["outputs"]
            .as_object_mut()
            .ok_or_else(|| Error("Flatpak output registry missing".into()))?
            .insert(name.into(), row.clone());
        self.0.insert(name.into(), (file, row));
        self.recheck(root)?;
        Ok(bytes)
    }
    pub(crate) fn recheck(&self, root: &File) -> Result<()> {
        for (name, (file, row)) in &self.0 {
            let (_, actual, _) = observe(
                root,
                name,
                row["owner"].as_u64().unwrap() as u32,
                row["single_link"].as_bool().unwrap(),
            )?;
            require(
                actual == *row && value!(files::identity(&file.metadata()?)) == row["inode"],
                "original Flatpak output changed or replaced",
            )?;
        }
        Ok(())
    }
}
pub(crate) fn observe(
    root: &File,
    name: &str,
    owner: u32,
    single_link: bool,
) -> Result<(File, Value, Vec<u8>)> {
    crate::media_manifest::relative(name)?;
    require(
        matches!(owner, 0 | 1000),
        "Flatpak output owner outside installation accounts",
    )?;
    let path = Path::new(name);
    let parent = files::directory_relative(
        root,
        path.parent()
            .ok_or_else(|| Error("Flatpak output parent absent".into()))?,
        None,
    )?;
    let file = files::open_relative(&parent, Path::new(path.file_name().unwrap()))?;
    let m = file.metadata()?;
    let identity = files::identity(&m);
    let mount = mount_identity::id(file.as_fd(), true)?;
    require(
        m.uid() == owner
            && m.gid() == owner
            && m.nlink() > 0
            && matches!(m.mode() & 0o7777, 0o444 | 0o600 | 0o644)
            && mount == mount_identity::id(parent.as_fd(), true)?,
        "Flatpak output ownership, protection or mount differs",
    )?;
    let bytes = files::read_file(&file, 1024 * 1024, Some(owner), single_link)?;
    let named = files::open_relative(&parent, Path::new(path.file_name().unwrap()))?;
    require(
        files::identity(&file.metadata()?) == identity
            && files::identity(&named.metadata()?) == identity
            && mount_identity::id(named.as_fd(), true)? == mount,
        "Flatpak output replaced during observation",
    )?;
    let row = value!({"path":name,"inode":identity,"mount":mount,"parent_inode":[parent.metadata()?.dev(),parent.metadata()?.ino(),parent.metadata()?.uid(),parent.metadata()?.gid(),parent.metadata()?.mode()],"owner":owner,"single_link":single_link,"sha256":json::sha256(&bytes)});
    Ok((file, row, bytes))
}
pub(crate) fn verify(
    root: &File,
    body: &Value,
    expected: &BTreeMap<String, (u32, bool)>,
) -> Result<Held> {
    let rows = body["outputs"]
        .as_object()
        .ok_or_else(|| Error("Flatpak output identities absent".into()))?;
    require(
        rows.keys().eq(expected.keys()),
        "Flatpak output registry differs",
    )?;
    let mut originals = BTreeMap::new();
    for (name, (owner, single)) in expected {
        json::fields(
            &rows[name],
            "path inode mount parent_inode owner single_link sha256",
        )?;
        let (file, actual, _) = observe(root, name, *owner, *single)?;
        require(
            actual == rows[name],
            "completed Flatpak output differs from its worker publication",
        )?;
        originals.insert(name.clone(), (file, actual));
    }
    let originals = Held(originals);
    originals.recheck(root)?;
    Ok(originals)
}
