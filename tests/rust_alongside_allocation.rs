// SPDX-License-Identifier: MIT
use enzimos_installer::{allocation, answers::Partition, format, root_prepare};
use enzimos_platform::json::fingerprint;
use serde_json::{Value, json};
const GIB: u64 = 1024 * 1024 * 1024;
const UUIDS: [&str; 4] = [
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
    "33333333-3333-3333-3333-333333333333",
    "44444444-4444-4444-4444-444444444444",
];
fn state() -> Value {
    json!({"disk":"/dev/vda","table":{"label":"gpt","id":UUIDS[0],"device":"/dev/vda","unit":"sectors","firstlba":34,"lastlba":64*GIB/512-34,"sectorsize":512,"partitions":[
 {"node":"/dev/vda1","start":2048,"size":8*GIB/512,"type":"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7","uuid":UUIDS[1],"name":"keep","attrs":"GUID:60"},
 {"node":"/dev/vda4","start":40*GIB/512,"size":4*GIB/512,"type":"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7","uuid":"55555555-5555-5555-5555-555555555555","name":"also keep"}],},
 "devices":[{"name":"/dev/vda","children":[{"name":"/dev/vda1","fstype":"ntfs","uuid":"1234567890ABCDEF"},{"name":"/dev/vda4","fstype":"ntfs","uuid":"ABCDEF1234567890"}]}]})
}
fn review(before: &Value, start: u64, size: u64, shrink: Value) -> Value {
    let mut r = json!({"schema":1,"disk":"/dev/vda","before_sha256":fingerprint(before).unwrap(),"start":start,"size":size,"sector":512,"shrink":shrink});
    r["id"] = json!(fingerprint(&r).unwrap());
    r["label"] = json!("reviewed fixture");
    r
}
fn fixture() -> (Value, Value, Value) {
    let before = state();
    let disk = json!({"path":"/dev/vda","bytes":64*GIB});
    let review = review(&before, 8 * GIB / 512 + 2048, 30 * GIB / 512, Value::Null);
    let plan =
        allocation::alongside_plan(&before, &review, &disk, &[UUIDS[2].into(), UUIDS[3].into()])
            .unwrap();
    let mut table = before["table"].clone();
    for index in [1, 2] {
        let mut row = plan["partitions"][index].clone();
        let number = row["number"].as_u64().unwrap();
        row.as_object_mut().unwrap().remove("number");
        row["node"] = json!(format!("/dev/vda{number}"));
        table["partitions"].as_array_mut().unwrap().push(row);
    }
    (plan, table, disk)
}
#[test]
fn alongside_uses_free_gpt_slots_and_preserves_every_original_partition_field() {
    let (plan, table, disk) = fixture();
    allocation::validate(&plan, &disk).unwrap();
    allocation::mode(&plan, Partition::Alongside).unwrap();
    assert!(allocation::mode(&plan, Partition::Erase).is_err());
    assert_eq!(allocation::number(&plan, 1).unwrap(), 2);
    assert_eq!(allocation::number(&plan, 2).unwrap(), 3);
    let result = allocation::verify(&plan, &table).unwrap();
    assert!(result["bios"].is_null());
    assert_eq!(result["esp"], "/dev/vda2");
    assert_eq!(result["root"], "/dev/vda3");
    let script = allocation::append_script(&plan).unwrap();
    assert_eq!(script.lines().count(), 2);
    assert!(script.contains(UUIDS[2]));
    assert!(!script.contains("keep"));
    for (row, key, value) in [
        (0, "attrs", json!("GUID:61")),
        (0, "size", json!(2)),
        (0, "uuid", json!(UUIDS[3])),
        (1, "node", json!("/dev/vda5")),
        (2, "start", json!(1)),
        (3, "type", json!(UUIDS[0])),
    ] {
        let mut wrong = table.clone();
        wrong["partitions"][row][key] = value;
        assert!(allocation::verify(&plan, &wrong).is_err(), "{row} {key}");
    }
    let mut extra = table.clone();
    extra["partitions"][2]["attrs"] = json!("GUID:60");
    assert!(allocation::verify(&plan, &extra).is_err());
    let mut changed = table.clone();
    changed["id"] = json!(UUIDS[3]);
    assert!(allocation::verify(&plan, &changed).is_err());
    let mut changed = table;
    changed["lastlba"] = json!(128);
    assert!(allocation::verify(&plan, &changed).is_err());
}
#[test]
fn alongside_review_cannot_move_the_allocation_reuse_a_guid_or_reset_partition_mode() {
    let (plan, _, disk) = fixture();
    for (field, value) in [
        ("sector", json!(4096)),
        ("bytes", json!(32 * GIB)),
        ("label_id", json!(UUIDS[3])),
        ("mode", json!("erase")),
        ("schema", json!(1)),
    ] {
        let mut changed = plan.clone();
        changed[field] = value;
        assert!(allocation::validate(&changed, &disk).is_err());
    }
    let before = state();
    let overlap = review(&before, 2048, 30 * GIB / 512, Value::Null);
    assert!(
        allocation::alongside_plan(
            &before,
            &overlap,
            &disk,
            &[UUIDS[2].into(), UUIDS[3].into()]
        )
        .is_err()
    );
    assert!(
        allocation::alongside_plan(
            &before,
            &plan["review"],
            &disk,
            &[UUIDS[1].into(), UUIDS[3].into()]
        )
        .is_err()
    );
    let mut wrong = before;
    wrong["table"]["partitions"][0]["name"] = json!("changed");
    assert!(
        allocation::alongside_plan(
            &wrong,
            &plan["review"],
            &disk,
            &[UUIDS[2].into(), UUIDS[3].into()]
        )
        .is_err()
    );
    let mut wrong = plan;
    wrong["partitions"][0] = wrong["partitions"][1].clone();
    assert!(allocation::validate(&wrong, &disk).is_err());
}
#[test]
fn formatted_alongside_handoff_requires_new_paths_and_keeps_the_bios_slot_empty() {
    let (plan, table, disk) = fixture();
    let result = allocation::verify(&plan, &table).unwrap();
    let boot = UUIDS[0];
    let partitioned = json!({"schema":1,"state":"partitioned","boot":boot,"disk":disk,"plan":plan,"result":result});
    format::admitted_receipt(&partitioned, boot, &disk).unwrap();
    let mut body = partitioned;
    body["state"] = json!("formatted");
    body["encrypted"] = json!(false);
    body["formatted"] = result;
    body["formatted"]["esp_filesystem"] = json!({"type":"vfat","uuid":"1234-ABCD"});
    body["formatted"]["root_filesystem"] = json!({"type":"btrfs","uuid":UUIDS[3]});
    root_prepare::admit(&body, boot, &disk, false).unwrap();
    let mut wrong = body.clone();
    wrong["result"]["bios"] = json!("/dev/vda1");
    assert!(root_prepare::admit(&wrong, boot, &disk, false).is_err());
    let mut wrong = body.clone();
    wrong["formatted"]["root"] = json!("/dev/vda1");
    assert!(root_prepare::admit(&wrong, boot, &disk, false).is_err());
    assert!(root_prepare::admit(&body, UUIDS[1], &disk, false).is_err());
    assert!(root_prepare::admit(&body, boot, &disk, true).is_err());
}
#[test]
fn shrink_review_changes_only_the_selected_existing_size_and_frees_its_tail() {
    let mut before = state();
    before["table"]["partitions"].as_array_mut().unwrap().pop();
    before["table"]["partitions"][0]["size"] = json!(60 * GIB / 512);
    before["devices"][0]["children"]
        .as_array_mut()
        .unwrap()
        .pop();
    let start = 30 * GIB / 512 + 2048;
    let r = review(
        &before,
        start,
        30 * GIB / 512,
        json!({"node":"/dev/vda1","filesystem":"ntfs","old_size":60*GIB/512,"new_size":30*GIB/512}),
    );
    let disk = json!({"path":"/dev/vda","bytes":64*GIB});
    let plan = allocation::alongside_plan(&before, &r, &disk, &[UUIDS[2].into(), UUIDS[3].into()])
        .unwrap();
    let effective = allocation::effective_table(&before, &r).unwrap();
    assert_eq!(effective["partitions"][0]["size"], 30 * GIB / 512);
    let mut restored = effective;
    restored["partitions"][0]["size"] = before["table"]["partitions"][0]["size"].clone();
    assert_eq!(restored, before["table"]);
    allocation::validate(&plan, &disk).unwrap();
    let mut changed = r;
    changed["shrink"]["filesystem"] = json!("btrfs");
    assert!(allocation::effective_table(&before, &changed).is_err());
}
