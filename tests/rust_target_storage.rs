// SPDX-License-Identifier: MIT
use enzimos_installer::{erase, target_storage};
use serde_json::{Value, json};
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
    let id = "0123456789abcdef0123456789abcdef";
    let mapper = if encrypted {
        json!(format!("enzimos-install-{id}"))
    } else {
        Value::Null
    };
    let mut subvolumes = json!({});
    for (index, name) in [
        "enzimos-root",
        "enzimos-home",
        "enzimos-control",
        "enzimos-authority",
        "enzimos-swap",
    ]
    .iter()
    .enumerate()
    {
        subvolumes[*name] = json!({"path":name,"id":256+index,"uuid":format!("11111111-1111-4111-8111-11111111111{index}"),"parent_uuid":null});
    }
    json!({"schema":1,"state":"subvolumes-ready","boot":"boot","disk":disk,"plan":plan,"result":result,"encrypted":encrypted,"formatted":formatted,"mapper":mapper,
        "root_filesystem":{"type":"btrfs","uuid":if encrypted {guids[2].clone()} else {guids[3].clone()}},
        "subvolume_attempt":{"id":id,"mount":format!("/run/enzimos-install-native/mounts/{id}"),"mapper":mapper},"subvolumes":subvolumes})
}
#[test]
fn installation_body_cannot_replay_started_completed_or_uncertain_storage_receipts() {
    for encrypted in [false, true] {
        let body = ready(encrypted);
        assert!(target_storage::admit(&body, "boot", &body["disk"], encrypted).is_ok());
        for phase in [
            "subvolumes-preparing",
            "storage-starting",
            "storage-mounted",
            "storage-body-started",
            "storage-body-finished",
            "storage-body-complete",
            "uncertain",
        ] {
            let mut altered = body.clone();
            altered["state"] = json!(phase);
            assert!(
                target_storage::admit(&altered, "boot", &body["disk"], encrypted).is_err(),
                "{phase}"
            );
        }
        assert!(target_storage::admit(&body, "rebooted", &body["disk"], encrypted).is_err());
        assert!(target_storage::admit(&body, "boot", &body["disk"], !encrypted).is_err());
        let mut replaced = body["disk"].clone();
        replaced["inode"] = json!("replacement");
        assert!(target_storage::admit(&body, "boot", &replaced, encrypted).is_err());
    }
}
#[test]
fn installation_body_requires_exact_subvolume_attempt_paths_and_kernel_identities() {
    for encrypted in [false, true] {
        let body = ready(encrypted);
        for (pointer, value) in [
            ("/subvolume_attempt/mount", json!("/mnt/foreign")),
            ("/subvolume_attempt/id", json!("../foreign")),
            ("/subvolume_attempt/mapper", json!("enzimos-crypt")),
            ("/subvolumes/enzimos-root/id", json!(5)),
            (
                "/subvolumes/enzimos-home/uuid",
                body["subvolumes"]["enzimos-root"]["uuid"].clone(),
            ),
            (
                "/subvolumes/enzimos-authority/parent_uuid",
                json!("11111111-1111-4111-8111-111111111110"),
            ),
        ] {
            let mut altered = body.clone();
            *altered.pointer_mut(pointer).unwrap() = value;
            assert!(
                target_storage::admit(&altered, "boot", &body["disk"], encrypted).is_err(),
                "{pointer}"
            );
        }
        let mut changed = body.clone();
        changed["unexpected"] = json!(true);
        assert!(target_storage::admit(&changed, "boot", &body["disk"], encrypted).is_err());
    }
}
