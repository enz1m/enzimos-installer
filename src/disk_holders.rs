// SPDX-License-Identifier: MIT
//! Kernel holder aliases identify only the caller's exact original mapping.
use enzimos_platform::{Error, Result, files, mount_identity, require};
use std::{
    fs::File,
    os::fd::{AsFd, AsRawFd},
    path::Path,
};

fn members(directory: &File, path: &Path, expected: Option<&Path>) -> Result<()> {
    let identity = files::identity(&directory.metadata()?);
    let mount = mount_identity::id(directory.as_fd(), true)?;
    let names = files::directory_names(directory, 64)?;
    require(
        names.len() == usize::from(expected.is_some()),
        "foreign or missing kernel holder",
    )?;
    if let Some(expected) = expected {
        let name = names[0]
            .to_str()
            .ok_or_else(|| Error("kernel holder name encoding".into()))?;
        enzimos_policy::identity::safe_id(name)?;
        let alias = path.join(name);
        let before = std::fs::symlink_metadata(&alias)?;
        require(
            before.file_type().is_symlink(),
            "kernel holder must be an alias",
        )?;
        require(
            std::fs::canonicalize(&alias)? == expected,
            "kernel holder differs from original mapping",
        )?;
        require(
            files::identity(&std::fs::symlink_metadata(&alias)?) == files::identity(&before),
            "kernel holder alias changed during admission",
        )?;
    }
    let named = files::directory(path, None)?;
    require(
        files::identity(&named.metadata()?) == identity
            && files::identity(&directory.metadata()?) == identity
            && mount_identity::id(named.as_fd(), true)? == mount
            && files::directory_names(directory, 64)? == names,
        "original kernel holder directory changed",
    )
}

#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
pub(crate) fn verify(path: &Path, expected: Option<&Path>) -> Result<()> {
    require(
        path.starts_with("/sys/devices") && path.file_name().is_some_and(|n| n == "holders"),
        "canonical kernel holder directory required",
    )?;
    let directory = files::directory(path, Some(0))?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } == 0
            && filesystem.f_type as u64 == 0x62656572,
        "actual kernel sysfs holder directory required",
    )?;
    if let Some(expected) = expected {
        require(
            expected.starts_with("/sys/devices"),
            "original mapper kernel path required",
        )?;
        let target = files::directory(expected, Some(0))?;
        require(
            mount_identity::id(target.as_fd(), true)?
                == mount_identity::id(directory.as_fd(), true)?,
            "kernel holder target crosses sysfs mount",
        )?;
    }
    members(&directory, path, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    fn fixture() -> (tempfile::TempDir, File) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("holders")).unwrap();
        std::fs::create_dir(temp.path().join("mapping")).unwrap();
        let parent = files::directory(&temp.path().join("holders"), None).unwrap();
        (temp, parent)
    }
    #[test]
    fn actual_alias_matches_only_original_target_and_empty_has_no_holder() {
        let (temp, parent) = fixture();
        let path = temp.path().join("holders");
        members(&parent, &path, None).unwrap();
        symlink("../mapping", path.join("dm-0")).unwrap();
        members(&parent, &path, Some(&temp.path().join("mapping"))).unwrap();
        assert!(members(&parent, &path, None).is_err());
        std::fs::create_dir(temp.path().join("foreign")).unwrap();
        assert!(members(&parent, &path, Some(&temp.path().join("foreign"))).is_err());
    }
    #[test]
    fn duplicate_alias_regular_member_and_missing_holder_are_refused() {
        let (temp, parent) = fixture();
        let path = temp.path().join("holders");
        let expected = temp.path().join("mapping");
        assert!(members(&parent, &path, Some(&expected)).is_err());
        std::fs::write(path.join("dm-0"), b"not an alias").unwrap();
        assert!(members(&parent, &path, Some(&expected)).is_err());
        std::fs::remove_file(path.join("dm-0")).unwrap();
        symlink("../mapping", path.join("dm-0")).unwrap();
        symlink("../mapping", path.join("dm-1")).unwrap();
        assert!(members(&parent, &path, Some(&expected)).is_err());
    }
    #[test]
    fn replaced_parent_and_non_sysfs_cannot_supply_kernel_holder_authority() {
        let (temp, parent) = fixture();
        let path = temp.path().join("holders");
        let expected = temp.path().join("mapping");
        symlink("../mapping", path.join("dm-0")).unwrap();
        std::fs::rename(&path, temp.path().join("retired")).unwrap();
        std::fs::create_dir(&path).unwrap();
        symlink("../mapping", path.join("dm-0")).unwrap();
        assert!(members(&parent, &path, Some(&expected)).is_err());
        assert!(verify(&path, Some(&expected)).is_err());
    }
}
