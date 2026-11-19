// SPDX-License-Identifier: MIT
//! Retain exact configuration publications through the worker's completion.
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, fs::File, os::unix::fs::MetadataExt};

pub(crate) struct Publications(BTreeMap<String, (File, Value)>, u32);
impl Publications {
    pub(crate) fn new(root: &File) -> Result<Self> {
        Ok(Self(BTreeMap::new(), root.metadata()?.uid()))
    }
    pub(crate) fn add(&mut self, root: &File, name: &str, receipt: &mut Value) -> Result<()> {
        self.recheck(root)?;
        let (file, row) = enzimos_policy::file_overlay::capture(root, name, self.1)?;
        require(
            !self.0.contains_key(name),
            "configuration publication repeated",
        )?;
        receipt["members"]
            .as_object_mut()
            .ok_or_else(|| Error("configuration members absent".into()))?
            .insert(name.into(), row.clone());
        self.0.insert(name.into(), (file, row));
        self.recheck(root)
    }
    pub(crate) fn recheck(&self, root: &File) -> Result<()> {
        for (name, (file, row)) in &self.0 {
            let (_, actual) = enzimos_policy::file_overlay::capture(root, name, self.1)?;
            require(
                actual == *row && value!(files::identity(&file.metadata()?)) == row["inode"],
                "original configuration publication changed or replaced",
            )?;
        }
        Ok(())
    }
}
pub(crate) fn validate(body: &Value) -> Result<()> {
    let members = body["members"]
        .as_object()
        .ok_or_else(|| Error("configuration member identities absent".into()))?;
    let files = body["files"]
        .as_object()
        .ok_or_else(|| Error("configuration file registry absent".into()))?;
    let links = body["links"]
        .as_object()
        .ok_or_else(|| Error("configuration link registry absent".into()))?;
    require(
        members.len() <= files.len() + links.len()
            && (body["phase"] != "complete" || members.len() == files.len() + links.len()),
        "configuration identity registry incomplete",
    )?;
    for (name, row) in members {
        let link = links.get(name);
        json::fields(
            row,
            if link.is_some() {
                "path kind target inode mount"
            } else {
                "path kind inode mount"
            },
        )?;
        require(
            row["path"] == *name
                && (files.contains_key(name) || link.is_some())
                && row["kind"] == if link.is_some() { "symlink" } else { "file" }
                && link.is_none_or(|target| row["target"] == *target)
                && row["mount"].as_u64().is_some_and(|n| n > 0),
            "configuration identity belongs to another member",
        )?;
        let inode = row["inode"]
            .as_array()
            .ok_or_else(|| Error("configuration inode identity type".into()))?;
        require(
            inode.len() == 11
                && inode.iter().all(|n| n.as_u64().is_some())
                && inode[7].as_u64().is_some_and(|mode| {
                    mode <= u64::from(u32::MAX)
                        && mode as u32 & libc::S_IFMT
                            == if link.is_some() {
                                libc::S_IFLNK
                            } else {
                                libc::S_IFREG
                            }
                })
                && inode[4].as_u64().is_some_and(|n| n < 1_000_000_000)
                && inode[6].as_u64().is_some_and(|n| n < 1_000_000_000)
                && inode[8] == 0
                && inode[9] == 0
                && inode[10] == 1,
            "configuration inode identity shape or ownership",
        )?;
    }
    Ok(())
}
pub(crate) fn verify(root: &File, body: &Value) -> Result<()> {
    validate(body)?;
    let mut held = Vec::new();
    for (name, row) in body["members"].as_object().unwrap() {
        let (file, actual) = enzimos_policy::file_overlay::capture(root, name, 0)?;
        require(
            actual == *row,
            "completed configuration member changed or replaced",
        )?;
        held.push((name, file, row));
    }
    for (name, file, row) in held {
        let (_, actual) = enzimos_policy::file_overlay::capture(root, name, 0)?;
        require(
            actual == *row && value!(files::identity(&file.metadata()?)) == row["inode"],
            "configuration changed during completion review",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn identical_bytes_and_link_targets_do_not_adopt_replacement_inodes() {
        let work = std::path::PathBuf::from(
            std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        );
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(work)
            .unwrap();
        std::fs::create_dir(temp.path().join("etc")).unwrap();
        std::fs::write(temp.path().join("etc/hostname"), b"enzimos\n").unwrap();
        std::os::unix::fs::symlink("/usr/share/zoneinfo/UTC", temp.path().join("etc/localtime"))
            .unwrap();
        let root = files::directory(temp.path(), Some(unsafe { libc::geteuid() })).unwrap();
        let mut body = value!({"members":{}});
        let mut publications = Publications::new(&root).unwrap();
        publications.add(&root, "etc/hostname", &mut body).unwrap();
        publications.add(&root, "etc/localtime", &mut body).unwrap();
        publications.recheck(&root).unwrap();
        std::fs::rename(
            temp.path().join("etc/hostname"),
            temp.path().join("etc/original-hostname"),
        )
        .unwrap();
        std::fs::write(temp.path().join("etc/hostname"), b"enzimos\n").unwrap();
        assert!(publications.recheck(&root).is_err());
        // A separate link-only publication isolates link identity from file failure.
        let mut links = Publications::new(&root).unwrap();
        links
            .add(&root, "etc/localtime", &mut value!({"members":{}}))
            .unwrap();
        std::fs::rename(
            temp.path().join("etc/localtime"),
            temp.path().join("etc/original-localtime"),
        )
        .unwrap();
        std::os::unix::fs::symlink("/usr/share/zoneinfo/UTC", temp.path().join("etc/localtime"))
            .unwrap();
        assert!(links.recheck(&root).is_err());
    }
}
