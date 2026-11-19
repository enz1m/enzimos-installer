// SPDX-License-Identifier: MIT
//! Retain the two installed kernel inputs and remeasure every named source.
use enzimos_platform::{Error, Result, files, json, mount_identity, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
pub(crate) struct Source {
    pub path: PathBuf,
    pub file: File,
    identity: files::FileIdentity,
    mount: u64,
    pub bytes: u64,
    pub sha: String,
}
impl Source {
    pub(crate) fn open(root: &File, path: &Path, limit: u64) -> Result<Self> {
        let parent = files::directory_relative(
            root,
            path.parent()
                .ok_or_else(|| Error("boot input parent missing".into()))?,
            Some(0),
        )?;
        let file = files::open_relative(&parent, Path::new(path.file_name().unwrap()))?;
        let m = file.metadata()?;
        let (bytes, sha) = stream_copy::hash_borrowed(&file, limit, Some(0))?;
        require(
            bytes > 0 && m.uid() == 0 && m.gid() == 0 && m.nlink() == 1 && m.mode() & 0o022 == 0,
            "protected nonempty boot input required",
        )?;
        Ok(Self {
            path: path.into(),
            mount: mount_identity::id(file.as_fd(), true)?,
            identity: files::identity(&m),
            file,
            bytes,
            sha,
        })
    }
    pub(crate) fn recheck(&self, root: &File) -> Result<()> {
        let parent = files::directory_relative(root, self.path.parent().unwrap(), Some(0))?;
        let named = files::open_relative(&parent, Path::new(self.path.file_name().unwrap()))?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount,
            "original installed boot input changed",
        )
    }
    pub(crate) fn receipt(&self) -> Value {
        value!({"path":self.path,"bytes":self.bytes,"sha256":self.sha,"mount":self.mount,"inode":self.identity})
    }
    pub(crate) fn copy(&self, root: &File, destination: &File, name: &str) -> Result<()> {
        self.recheck(root)?;
        let mut file = self.file.try_clone()?;
        stream_copy::verified(&mut file, destination, name, self.bytes, &self.sha, 0)?;
        self.recheck(root)
    }
}
pub(crate) struct Kernel {
    pub release: String,
    pub pkgbase: Source,
    pub kernel: Source,
}
pub(crate) fn kernels(root: &File) -> Result<BTreeMap<String, Kernel>> {
    let directory = files::directory_relative(root, Path::new("usr/lib/modules"), Some(0))?;
    let mut result = BTreeMap::new();
    for (index, entry) in files::directory_names(&directory, 32)?
        .into_iter()
        .enumerate()
    {
        require(index < 32, "installed kernel release count bound")?;
        let name = entry
            .into_string()
            .map_err(|_| Error("installed kernel release encoding".into()))?;
        enzimos_policy::identity::safe_id(&name)?;
        let module = files::directory_relative(&directory, Path::new(&name), Some(0))?;
        if files::optional_relative(&module, Path::new("pkgbase"))?.is_none() {
            continue;
        }
        let base = Path::new("usr/lib/modules").join(&name);
        let pkgbase = Source::open(root, &base.join("pkgbase"), 256)?;
        let bytes = files::read_file(&pkgbase.file, 256, Some(0), true)?;
        let flavor = std::str::from_utf8(&bytes)
            .map_err(|_| Error("installed kernel flavor encoding".into()))?
            .trim();
        require(
            matches!(flavor, "linux" | "linux-lts"),
            "initial installer kernel outside fixed dual-kernel cohort",
        )?;
        let kernel = Source::open(root, &base.join("vmlinuz"), 128 * 1024 * 1024)?;
        require(
            result
                .insert(
                    flavor.into(),
                    Kernel {
                        release: name,
                        pkgbase,
                        kernel,
                    },
                )
                .is_none(),
            "duplicate installed kernel flavor",
        )?;
    }
    require(
        result.len() == 2 && result.contains_key("linux") && result.contains_key("linux-lts"),
        "both independently installed kernel flavors required",
    )?;
    require(
        result["linux"].release != result["linux-lts"].release,
        "initial kernel releases must be distinct",
    )?;
    for kernel in result.values() {
        kernel.pkgbase.recheck(root)?;
        kernel.kernel.recheck(root)?;
    }
    Ok(result)
}
pub(crate) fn validate(body: &Value) -> Result<()> {
    json::fields(body, "path bytes sha256 mount inode")?;
    let path = body["path"]
        .as_str()
        .ok_or_else(|| Error("boot source path type".into()))?;
    require(
        !path.is_empty()
            && path.len() <= 4096
            && !Path::new(path).is_absolute()
            && Path::new(path)
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            && !path.chars().any(char::is_control)
            && body["mount"].as_u64().is_some_and(|n| n > 0)
            && body["bytes"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 128 * 1024 * 1024),
        "boot source canonical path, mount or size bound",
    )?;
    enzimos_policy::identity::sha(
        body["sha256"]
            .as_str()
            .ok_or_else(|| Error("boot source digest missing".into()))?,
    )?;
    let a = body["inode"]
        .as_array()
        .ok_or_else(|| Error("boot source inode binding type".into()))?;
    require(
        a.len() == 11
            && a.iter().all(|n| n.is_i64() || n.is_u64())
            && a[0].as_u64().is_some_and(|n| n > 0)
            && a[1].as_u64().is_some_and(|n| n > 0)
            && a[2] == body["bytes"]
            && [4, 6]
                .iter()
                .all(|i| a[*i].as_u64().is_some_and(|n| n < 1_000_000_000))
            && a[7].as_u64().is_some_and(|n| {
                n <= u64::from(u32::MAX)
                    && n as u32 & libc::S_IFMT == libc::S_IFREG
                    && n & 0o022 == 0
            })
            && a[8] == 0
            && a[9] == 0
            && a[10] == 1,
        "boot source protected regular inode binding",
    )
}
