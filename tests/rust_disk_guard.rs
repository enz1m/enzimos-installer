// SPDX-License-Identifier: MIT
use enzimos_installer::disk_guard;
use serde_json::json;
#[test]
fn disk_admission_requires_complete_unmounted_unmapped_canonical_device_inventory() {
    let tree = json!({"blockdevices":[{"name":"/dev/vda","type":"disk","ro":false,"maj:min":"252:0","mountpoints":[null],
        "children":[{"name":"/dev/vda1","type":"part","ro":false,"maj:min":"252:1","mountpoints":[null]}]}]});
    assert_eq!(
        disk_guard::inactive_tree(&tree, "/dev/vda").unwrap(),
        std::collections::BTreeSet::from([(252, 0), (252, 1)])
    );
    for (key, value) in [
        ("type", json!("crypt")),
        ("mountpoints", json!(["/mounted"])),
        ("mountpoints", json!("")),
        ("maj:min", json!("0252:1")),
    ] {
        let mut changed = tree.clone();
        changed["blockdevices"][0]["children"][0][key] = value;
        assert!(disk_guard::inactive_tree(&changed, "/dev/vda").is_err());
    }
    let mut duplicate = tree.clone();
    duplicate["blockdevices"][0]["children"][0]["maj:min"] = json!("252:0");
    assert!(disk_guard::inactive_tree(&duplicate, "/dev/vda").is_err());
    assert!(disk_guard::inactive_tree(&tree, "/dev/other").is_err());
    for number in ["1:2:3", "-1:1", "01:1", "1:4294967296"] {
        assert!(disk_guard::device(number).is_err());
    }
}
#[test]
fn active_swap_parser_retains_kernel_escaped_paths_and_refuses_incomplete_evidence() {
    let header = "Filename\tType\tSize\tUsed\tPriority\n";
    assert!(disk_guard::swap_paths(header).unwrap().is_empty());
    let rows = disk_guard::swap_paths(&format!(
        "{header}/dev/vda1 partition 1024 0 -2\n/path\\040with\\040spaces file 2048 32 -3\n"
    ))
    .unwrap();
    assert_eq!(
        rows,
        [
            std::path::PathBuf::from("/dev/vda1"),
            std::path::PathBuf::from("/path with spaces")
        ]
    );
    for body in [
        "",
        "wrong header\n",
        "Filename Type Size Used Priority\n/dev/vda1 partition 1024 0\n",
        "Filename Type Size Used Priority\n/path (deleted) file 1024 0 -2\n",
        "Filename Type Size Used Priority\nrelative file 1024 0 -2\n",
        "Filename Type Size Used Priority\n/dev/vda1 partition 1024 0 -2\n/dev/vda1 partition 1024 0 -2\n",
    ] {
        assert!(disk_guard::swap_paths(body).is_err());
    }
}
