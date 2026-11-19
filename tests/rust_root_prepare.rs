// SPDX-License-Identifier: MIT
use enzimos_installer::{disk_guard, erase, root_prepare};
use serde_json::{Value, json};
fn receipt(encrypted: bool) -> Value {
    let guids = [
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    ]
    .map(str::to_owned);
    let disk = json!({"path":"/dev/vda","bytes":32*1024u64*1024*1024,"inode":"original","graph":{"disk_sequence":7}});
    let plan = erase::layout(32 * 1024u64 * 1024 * 1024, 4096, "/dev/vda", &guids).unwrap();
    let result = json!({"bios":"/dev/vda1","esp":"/dev/vda2","root":"/dev/vda3","plan":plan});
    let mut formatted = result.clone();
    formatted["esp_filesystem"] = json!({"type":"vfat","uuid":"ABCD-1234"});
    formatted["root_filesystem"] =
        json!({"type":if encrypted {"crypto_LUKS"} else {"btrfs"},"uuid":guids[3]});
    json!({"schema":1,"state":"formatted","boot":"this-boot","disk":disk,"plan":plan,"result":result,"encrypted":encrypted,"formatted":formatted})
}
#[test]
fn preparation_refuses_replay_encryption_changes_and_filesystem_drift() {
    for encrypted in [false, true] {
        let body = receipt(encrypted);
        assert!(root_prepare::admit(&body, "this-boot", &body["disk"], encrypted).is_ok());
        assert!(root_prepare::admit(&body, "this-boot", &body["disk"], !encrypted).is_err());
        assert!(root_prepare::admit(&body, "other-boot", &body["disk"], encrypted).is_err());
        for phase in [
            "partitioned",
            "formatting",
            "root-preparing",
            "root-ready",
            "staging",
            "uncertain",
        ] {
            let mut changed = body.clone();
            changed["state"] = json!(phase);
            assert!(root_prepare::admit(&changed, "this-boot", &body["disk"], encrypted).is_err());
        }
        let mut replacement = body["disk"].clone();
        replacement["inode"] = json!("replaced");
        assert!(root_prepare::admit(&body, "this-boot", &replacement, encrypted).is_err());
        for (pointer, changed) in [
            ("/formatted/root", json!("/dev/vdb3")),
            ("/formatted/root_filesystem/type", json!("ext4")),
            ("/formatted/root_filesystem/uuid", json!("bad")),
            ("/formatted/esp_filesystem/uuid", json!("bad")),
            ("/formatted/plan/sector", json!(512)),
            ("/encrypted", json!("yes")),
        ] {
            let mut altered = body.clone();
            *altered.pointer_mut(pointer).unwrap() = changed;
            assert!(
                root_prepare::admit(&altered, "this-boot", &body["disk"], encrypted).is_err(),
                "{pointer}"
            );
        }
        let mut duplicate = body.clone();
        duplicate["result"]["esp"] = json!("/dev/vda3");
        duplicate["formatted"]["esp"] = json!("/dev/vda3");
        assert!(root_prepare::admit(&duplicate, "this-boot", &body["disk"], encrypted).is_err());
        let mut extra = body.clone();
        extra["resume"] = json!(true);
        assert!(root_prepare::admit(&extra, "this-boot", &body["disk"], encrypted).is_err());
    }
}
#[test]
fn private_mapper_uuid_binds_luks_identity_and_distinct_attempt_name() {
    let name = "enzimos-install-0123456789abcdef0123456789abcdef";
    let luks = "44444444-4444-4444-8444-444444444444";
    assert_eq!(
        root_prepare::kernel_uuid(luks, name).unwrap(),
        format!("CRYPT-LUKS2-44444444444444448444444444444444-{name}")
    );
    assert_ne!(
        root_prepare::kernel_uuid(luks, name).unwrap(),
        root_prepare::kernel_uuid(luks, "enzimos-install-1123456789abcdef0123456789abcdef")
            .unwrap()
    );
    for name in [
        "enzimos-crypt",
        "enzimos-install-0123456789abcdef0123456789abcdeg",
        "enzimos-install-0123456789ABCDEF0123456789abcdef",
        "../mapper",
    ] {
        assert!(root_prepare::kernel_uuid(luks, name).is_err());
    }
    assert!(root_prepare::kernel_uuid("bad", name).is_err());
}
#[test]
fn mapper_admission_requires_exact_parent_and_refuses_all_foreign_activity() {
    let tree = json!({"blockdevices":[{"name":"/dev/vda","type":"disk","ro":false,"maj:min":"252:0","mountpoints":[null],"children":[{"name":"/dev/vda3","type":"part","ro":false,"maj:min":"252:3","mountpoints":[null],"children":[{"name":"/dev/mapper/private","type":"crypt","ro":false,"maj:min":"253:0","mountpoints":[null]}]}]}]});
    let owned = Some(((252, 3), (253, 0)));
    assert!(disk_guard::inactive_tree(&tree, "/dev/vda").is_err());
    assert_eq!(
        disk_guard::unmounted_tree(&tree, "/dev/vda", owned)
            .unwrap()
            .len(),
        3
    );
    for pair in [
        ((252, 2), (253, 0)),
        ((252, 3), (253, 1)),
        ((253, 0), (252, 3)),
    ] {
        assert!(disk_guard::unmounted_tree(&tree, "/dev/vda", Some(pair)).is_err());
    }
    for (key, value) in [
        ("type", json!("lvm")),
        ("ro", json!(true)),
        ("mountpoints", json!(["/foreign"])),
        (
            "children",
            json!([{"type":"part","ro":false,"maj:min":"253:1","mountpoints":null}]),
        ),
    ] {
        let mut changed = tree.clone();
        changed["blockdevices"][0]["children"][0]["children"][0][key] = value;
        assert!(disk_guard::unmounted_tree(&changed, "/dev/vda", owned).is_err());
    }
    let mut extra = tree;
    let row = extra["blockdevices"][0]["children"][0]["children"][0].clone();
    extra["blockdevices"][0]["children"][0]["children"]
        .as_array_mut()
        .unwrap()
        .push(row);
    assert!(disk_guard::unmounted_tree(&extra, "/dev/vda", owned).is_err());
}
