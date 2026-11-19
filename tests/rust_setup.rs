// SPDX-License-Identifier: MIT
use enzimos_installer::setup;
use serde_json::json;
#[test]
fn disk_erase_guard_refuses_every_active_descendant_without_opening_devices() {
    let mut v = json!({"blockdevices":[{"type":"disk","mountpoints":[null],"children":[{"type":"part","mountpoints":[null]}]}]});
    setup::unused_inventory(&v).unwrap();
    v["blockdevices"][0]["children"][0]["mountpoints"] = json!(["/"]);
    assert!(setup::unused_inventory(&v).is_err());
    v["blockdevices"][0]["children"][0]["mountpoints"] = json!([null]);
    v["blockdevices"][0]["children"][0]["type"] = json!("crypt");
    assert!(setup::unused_inventory(&v).is_err());
    assert!(setup::unused_inventory(&json!({"blockdevices":[]})).is_err());
}
#[test]
fn multilib_edit_and_partition_fields_preserve_the_fixed_installer_contract() {
    let original = "# unrelated comment\n#[multilib]\n#Include = /etc/pacman.d/mirrorlist\n";
    let enabled = setup::multilib_text(original).unwrap();
    assert_eq!(
        enabled,
        "# unrelated comment\n[multilib]\nInclude = /etc/pacman.d/mirrorlist\n"
    );
    assert_eq!(setup::multilib_text(&enabled).unwrap(), enabled);
    assert!(setup::multilib_text(&format!("{original}{original}")).is_err());
    assert_eq!(
        setup::layout_field(&json!({"esp":"/dev/nvme0n1p3"}), "esp").unwrap(),
        "/dev/nvme0n1p3"
    );
    for bad in [
        "/dev/sda1\ncommand",
        "/etc/shadow",
        "/dev/sda1;command",
        "../sda1",
    ] {
        assert!(setup::layout_field(&json!({"esp":bad}), "esp").is_err());
    }
}
