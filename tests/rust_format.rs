// SPDX-License-Identifier: MIT
use enzimos_installer::{erase, format};
use serde_json::json;
#[test]
fn formatting_refuses_replayed_or_changed_native_allocation_receipts() {
    let guids = [
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    ]
    .map(str::to_owned);
    let disk = json!({"bytes":32*1024u64*1024*1024,"path":"/dev/vda","graph":{"disk_sequence":7},"inode":"held-inode"});
    let plan = erase::layout(disk["bytes"].as_u64().unwrap(), 4096, "/dev/vda", &guids).unwrap();
    let receipt = json!({"schema":1,"state":"partitioned","boot":"boot-a","disk":disk,"plan":plan,"result":{"plan":plan}});
    assert!(format::admitted_receipt(&receipt, "boot-a", &disk).is_ok());
    for state in ["started", "formatting", "formatted", "uncertain"] {
        let mut changed = receipt.clone();
        changed["state"] = json!(state);
        assert!(format::admitted_receipt(&changed, "boot-a", &disk).is_err());
    }
    assert!(format::admitted_receipt(&receipt, "boot-b", &disk).is_err());
    let mut changed = disk.clone();
    changed["graph"]["disk_sequence"] = json!(8);
    assert!(format::admitted_receipt(&receipt, "boot-a", &changed).is_err());
    let mut changed = receipt;
    changed["plan"]["partitions"][1]["size"] = json!(1);
    changed["result"]["plan"] = changed["plan"].clone();
    assert!(format::admitted_receipt(&changed, "boot-a", &disk).is_err());
}
#[test]
fn filesystem_readback_requires_exact_type_unique_fields_and_valid_uuid() {
    let uuid = "44444444-4444-4444-8444-444444444444";
    let body = format!("DEVNAME=/proc/self/fd/64\nTYPE=crypto_LUKS\nUUID={uuid}\n");
    assert_eq!(
        format::filesystem(body.as_bytes(), "crypto_LUKS").unwrap()["uuid"],
        uuid
    );
    assert!(format::filesystem(body.as_bytes(), "btrfs").is_err());
    assert!(
        format::filesystem(
            format!("{body}TYPE=crypto_LUKS\n").as_bytes(),
            "crypto_LUKS"
        )
        .is_err()
    );
    assert!(format::filesystem(b"TYPE=vfat\nUUID=ABCD-1234\n", "vfat").is_ok());
    for body in [
        b"TYPE=btrfs\n".as_slice(),
        b"TYPE=btrfs\nUUID=bad\n",
        b"TYPE=btrfs\nUUID=one\nUUID=two\n",
        b"TYPE=vfat\nUUID=ABCD-1234\nBAD=bad\0\n",
    ] {
        assert!(format::filesystem(body, "btrfs").is_err());
    }
}
