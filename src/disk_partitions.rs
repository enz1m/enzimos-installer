// SPDX-License-Identifier: MIT
//! Enumerate actual partition directories, never append a child to a sysfs attribute file.
use crate::disk_guard::{Device, device};
use enzimos_platform::{Result, require};
use std::{collections::BTreeSet, path::Path};

// The caller supplies the original kernel disk path and its bounded kernel reader.
// This metadata helper grants no disk, filesystem or execution authority.
pub(crate) fn enumerate(
    root: &Path,
    read: impl Fn(&Path) -> Result<String>,
) -> Result<BTreeSet<Device>> {
    let mut result = BTreeSet::new();
    for (index, entry) in std::fs::read_dir(root)?.enumerate() {
        require(index < 4096, "kernel disk directory count bound")?;
        let entry = entry?;
        // dev, size, diskseq and uevent are regular attributes. Probing
        // attribute/partition reports ENOTDIR, not absence. Symlink aliases
        // are not partition directories and cannot add an inventory member.
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        match std::fs::symlink_metadata(path.join("partition")) {
            Ok(marker) => {
                require(marker.is_file(), "kernel partition marker is not regular")?;
                let number = device(read(&path.join("dev"))?.trim())?;
                require(result.insert(number), "duplicate kernel partition device")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(std::path::PathBuf::from(
                std::env::var_os("ENZIMOS_TEST_TMPDIR")
                    .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
            ))
            .unwrap()
    }
    #[test]
    fn real_attribute_files_do_not_hide_partitions_or_turn_into_enotdir_errors() {
        let temp = fixture();
        for name in ["dev", "size", "diskseq", "uevent"] {
            std::fs::write(temp.path().join(name), b"attribute\n").unwrap();
        }
        let error = std::fs::symlink_metadata(temp.path().join("dev/partition")).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR));
        std::fs::create_dir(temp.path().join("holders")).unwrap();
        let partition = temp.path().join("vda1");
        std::fs::create_dir(&partition).unwrap();
        std::fs::write(partition.join("partition"), b"1\n").unwrap();
        std::fs::write(partition.join("dev"), b"252:1\n").unwrap();
        std::os::unix::fs::symlink(&partition, temp.path().join("alias")).unwrap();
        let read = |path: &Path| -> Result<String> { Ok(std::fs::read_to_string(path)?) };
        assert_eq!(
            enumerate(temp.path(), read).unwrap(),
            BTreeSet::from([(252, 1)])
        );
        std::fs::remove_file(partition.join("partition")).unwrap();
        assert!(enumerate(temp.path(), read).unwrap().is_empty());
    }
    #[test]
    fn duplicate_devices_and_nonregular_partition_markers_are_refused() {
        let temp = fixture();
        let read = |path: &Path| -> Result<String> { Ok(std::fs::read_to_string(path)?) };
        for name in ["vda1", "vda2"] {
            let path = temp.path().join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("partition"), b"1\n").unwrap();
            std::fs::write(path.join("dev"), b"252:1\n").unwrap();
        }
        assert!(enumerate(temp.path(), read).is_err());
        std::fs::remove_file(temp.path().join("vda2/partition")).unwrap();
        std::os::unix::fs::symlink("../vda1/partition", temp.path().join("vda2/partition"))
            .unwrap();
        assert!(enumerate(temp.path(), read).is_err());
    }
}
