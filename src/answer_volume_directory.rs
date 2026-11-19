// SPDX-License-Identifier: MIT
//! A known child publication may change timestamps, but never its parent epoch.
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.gid() == owner && m.mode() & 0o7777 == 0o700,
        "original private answer receipt parent required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
pub(super) struct Directory {
    path: PathBuf,
    file: File,
    shape: Shape,
    mount: u64,
    owner: u32,
}
impl Directory {
    pub(super) fn retain(path: &Path, file: File, owner: u32) -> Result<Self> {
        let this = Self {
            path: path.into(),
            shape: shape(&file, owner)?,
            mount: mount_identity::id(file.as_fd(), true)?,
            file,
            owner,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(super) fn recheck(&self) -> Result<()> {
        let named = files::directory(&self.path, Some(self.owner))?;
        require(
            shape(&named, self.owner)? == self.shape
                && shape(&self.file, self.owner)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount,
            "original answer receipt directory changed or replaced",
        )
    }
    pub(super) fn file(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.file)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn original_parent_accepts_own_new_member_and_refuses_same_contents_replacement() {
        let owner = unsafe { libc::geteuid() };
        let work = std::path::PathBuf::from(
            std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        );
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(work)
            .unwrap();
        let path = temp.path().join("receipt");
        let file = files::create_directory(&path, 0o700, owner).unwrap();
        let original = Directory::retain(&path, file, owner).unwrap();
        files::atomic_relative(
            original.file().unwrap(),
            Path::new("intent"),
            b"fixture intent",
            0o600,
            Some(owner),
            false,
            1024,
        )
        .unwrap();
        original.recheck().unwrap();
        std::fs::rename(&path, temp.path().join("old")).unwrap();
        files::create_directory(&path, 0o700, owner).unwrap();
        std::fs::copy(temp.path().join("old/intent"), path.join("intent")).unwrap();
        assert!(original.recheck().is_err());
    }
}
