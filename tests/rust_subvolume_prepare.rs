// SPDX-License-Identifier: MIT
use enzimos_installer::{disk_guard, erase, subvolume_prepare};
use enzimos_platform::mountinfo;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
fn ready(encrypted: bool) -> Value {
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
    json!({"schema":1,"state":"root-ready","boot":"boot","disk":disk,"plan":plan,"result":result,"encrypted":encrypted,"formatted":formatted,
        "mapper":if encrypted {json!("enzimos-install-0123456789abcdef0123456789abcdef")} else {Value::Null},
        "root_filesystem":{"type":"btrfs","uuid":if encrypted {guids[2].clone()} else {guids[3].clone()}}})
}
#[test]
fn subvolume_admission_requires_one_unattempted_complete_root_preparation() {
    for encrypted in [false, true] {
        let body = ready(encrypted);
        assert!(subvolume_prepare::admit(&body, "boot", &body["disk"], encrypted).is_ok());
        for state in [
            "formatted",
            "root-preparing",
            "subvolumes-preparing",
            "subvolumes-ready",
            "uncertain",
        ] {
            let mut altered = body.clone();
            altered["state"] = json!(state);
            assert!(subvolume_prepare::admit(&altered, "boot", &body["disk"], encrypted).is_err());
        }
        assert!(subvolume_prepare::admit(&body, "changed-boot", &body["disk"], encrypted).is_err());
        assert!(subvolume_prepare::admit(&body, "boot", &body["disk"], !encrypted).is_err());
        for (field, value) in [("type", json!("ext4")), ("uuid", json!("bad"))] {
            let mut altered = body.clone();
            altered["root_filesystem"][field] = value;
            assert!(subvolume_prepare::admit(&altered, "boot", &body["disk"], encrypted).is_err());
        }
        let mut altered = body.clone();
        altered["mapper"] = json!("enzimos-crypt");
        assert!(subvolume_prepare::admit(&altered, "boot", &body["disk"], encrypted).is_err());
        if !encrypted {
            let mut altered = body.clone();
            altered["root_filesystem"]["uuid"] = json!("33333333-3333-4333-8333-333333333333");
            assert!(subvolume_prepare::admit(&altered, "boot", &body["disk"], encrypted).is_err());
        }
    }
}
#[test]
fn filesystem_inventory_allows_only_exact_owned_source_and_mount_path() {
    let tree = json!({"blockdevices":[{"name":"/dev/vda","type":"disk","ro":false,"maj:min":"252:0","mountpoints":null,"children":[{"name":"/dev/vda3","type":"part","ro":false,"maj:min":"252:3","mountpoints":["/owned"]}]}]});
    let allowed = BTreeMap::from([((252, 3), BTreeSet::from(["/owned".into()]))]);
    assert!(disk_guard::unmounted_tree(&tree, "/dev/vda", None).is_err());
    assert!(disk_guard::storage_tree(&tree, "/dev/vda", None, &allowed).is_ok());
    assert!(
        disk_guard::storage_tree(
            &tree,
            "/dev/vda",
            None,
            &BTreeMap::from([((252, 0), BTreeSet::from(["/owned".into()]))])
        )
        .is_err()
    );
    for value in [
        json!(["/owned", "/foreign"]),
        json!(["/owned/child"]),
        json!("/owned"),
    ] {
        let mut altered = tree.clone();
        altered["blockdevices"][0]["children"][0]["mountpoints"] = value;
        assert!(disk_guard::storage_tree(&altered, "/dev/vda", None, &allowed).is_err());
    }
}
#[test]
fn owned_top_mount_refuses_replacement_shadowing_propagation_and_option_drift() {
    let row = mountinfo::parse(
        "100 20 0:42 / /owned rw,nosuid,nodev,noexec,noatime - btrfs /dev/vda3 rw\n",
    )
    .unwrap()
    .remove(0);
    assert!(subvolume_prepare::row_matches(std::slice::from_ref(&row), &row).is_ok());
    assert!(subvolume_prepare::row_matches(&[], &row).is_err());
    let mut replacement = row.clone();
    replacement.id += 1;
    assert!(subvolume_prepare::row_matches(&[replacement.clone()], &row).is_err());
    assert!(subvolume_prepare::row_matches(&[row.clone(), replacement], &row).is_err());
    let mut child = row.clone();
    child.id += 1;
    child.target = "/owned/foreign".into();
    child.filesystem = "tmpfs".into();
    assert!(subvolume_prepare::row_matches(&[row.clone(), child], &row).is_err());
    for (field, value) in [
        ("root", "/other"),
        ("filesystem", "ext4"),
        ("options", "rw,nosuid,nodev"),
        ("options", "ro,nosuid,nodev,noexec"),
        ("options", "rw,ro,nosuid,nodev,noexec"),
    ] {
        let mut altered = row.clone();
        match field {
            "root" => altered.root = value.into(),
            "filesystem" => altered.filesystem = value.into(),
            _ => altered.options = value.into(),
        }
        assert!(subvolume_prepare::row_matches(&[altered.clone()], &altered).is_err());
    }
    let mut shared = row;
    shared.optional.push("shared:7".into());
    assert!(subvolume_prepare::row_matches(&[shared.clone()], &shared).is_err());
}
#[test]
fn installation_subvolumes_require_complete_distinct_kernel_identities() {
    let names = [
        "enzimos-root",
        "enzimos-home",
        "enzimos-control",
        "enzimos-authority",
        "enzimos-swap",
    ];
    let mut body = json!({});
    for (index, name) in names.iter().enumerate() {
        body[*name] = json!({"path":name,"id":256+index,"uuid":format!("11111111-1111-4111-8111-11111111111{index}"),"parent_uuid":null});
    }
    assert!(subvolume_prepare::validate_subvolumes(&body).is_ok());
    for (key, value) in [
        ("id", json!(256)),
        ("uuid", body["enzimos-root"]["uuid"].clone()),
        ("path", json!("enzimos-root")),
        ("parent_uuid", json!("11111111-1111-4111-8111-111111111110")),
    ] {
        let mut altered = body.clone();
        altered["enzimos-home"][key] = value;
        assert!(subvolume_prepare::validate_subvolumes(&altered).is_err());
    }
    let mut missing = body.clone();
    missing.as_object_mut().unwrap().remove("enzimos-swap");
    assert!(subvolume_prepare::validate_subvolumes(&missing).is_err());
    let mut extra = body.clone();
    extra["foreign"] = body["enzimos-root"].clone();
    assert!(subvolume_prepare::validate_subvolumes(&extra).is_err());
}
