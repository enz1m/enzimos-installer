// SPDX-License-Identifier: MIT
use enzimos_installer::target_storage::clone_layout;
use enzimos_platform::mountinfo;
fn source() -> Vec<mountinfo::Row> {
    mountinfo::parse("20 1 0:3 / /dev rw,nosuid shared:7 - devtmpfs devtmpfs rw\n21 20 0:4 / /dev/pts rw,nosuid,noexec - devpts devpts rw\n22 20 0:5 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw\n").unwrap()
}
fn copied(source: &[mountinfo::Row]) -> Vec<mountinfo::Row> {
    source
        .iter()
        .map(|row| {
            let mut row = row.clone();
            row.id += 100;
            row.parent += 100;
            row.target = format!("/mnt/enzimos{}", row.target);
            row.optional.clear();
            row
        })
        .collect()
}
#[test]
fn device_tree_copy_requires_exact_kernel_source_and_private_mounts() {
    let source = source();
    let actual = copied(&source);
    assert!(clone_layout(&source, &actual).is_ok());
    for field in [
        "device",
        "root",
        "filesystem",
        "options",
        "target",
        "id",
        "shared",
    ] {
        let mut changed = actual.clone();
        match field {
            "device" => changed[1].minor += 1,
            "root" => changed[1].root = "/foreign".into(),
            "filesystem" => changed[1].filesystem = "ext4".into(),
            "options" => changed[1].options = "ro".into(),
            "target" => changed[1].target = "/mnt/foreign/pts".into(),
            "id" => changed[1].id = source[1].id,
            _ => changed[1].optional.push("shared:7".into()),
        }
        assert!(clone_layout(&source, &changed).is_err(), "{field}");
    }
    let mut missing = actual.clone();
    missing.pop();
    assert!(clone_layout(&source, &missing).is_err());
    let mut extra = actual.clone();
    extra.push(actual[1].clone());
    assert!(clone_layout(&source, &extra).is_err());
}
#[test]
fn device_tree_copy_refuses_unreviewed_filesystems_and_foreign_sources() {
    let source = source();
    for kind in ["btrfs", "vfat", "overlay", "fuse"] {
        let mut changed = source.clone();
        changed[1].filesystem = kind.into();
        assert!(clone_layout(&changed, &copied(&changed)).is_err());
    }
    let mut outside = source.clone();
    outside[1].target = "/dev-other/pts".into();
    assert!(clone_layout(&outside, &copied(&outside)).is_err());
    assert!(clone_layout(&[], &[]).is_err());
    assert!(
        clone_layout(
            &vec![source[0].clone(); 65],
            &vec![copied(&source)[0].clone(); 65]
        )
        .is_err()
    );
}
