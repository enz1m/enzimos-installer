// SPDX-License-Identifier: MIT
use enzimos_installer::package_job as job;
use serde_json::{Value, json};
const ID: &str = "11111111111111111111111111111111";
fn request() -> Value {
    json!({"schema":1,"id":ID,"boot_id":"12345678-1234-1234-1234-123456789abc","operation":"initial-arch-install","target":"/mnt/enzimos",
        "media_manifest_sha256":"a".repeat(64),"selected":["a-1-x86_64.pkg.tar.zst"],"target_mount":123,"target_inode":[1,2,0,0,16877],
        "caller":{"pid":123,"start_ticks":456,"executable_sha256":"b".repeat(64)}})
}
fn stages() -> Vec<Value> {
    let first = job::initial(request()).unwrap();
    let mut handoff = first.clone();
    handoff["phase"] = json!("handoff");
    handoff["owner"] = json!({"pid":789,"start_ticks":999,"invocation":"c".repeat(32),"executable_sha256":"d".repeat(64),"unit":job::unit(ID).unwrap()});
    let mut running = handoff.clone();
    running["phase"] = json!("running");
    let mut stopping = running.clone();
    stopping["phase"] = json!("stopping");
    stopping["exit_code"] = json!(0);
    let mut complete = stopping.clone();
    complete["phase"] = json!("complete");
    complete["group_empty"] = json!(true);
    vec![first, handoff, running, stopping, complete]
}
#[test]
fn installation_package_receipts_require_all_ordered_phases_and_exact_owner() {
    let sequence = stages();
    job::transition(None, &sequence[0]).unwrap();
    for pair in sequence.windows(2) {
        job::transition(Some(&pair[0]), &pair[1]).unwrap();
    }
    for (index, previous) in sequence.iter().enumerate() {
        assert!(job::transition(Some(previous), previous).is_err());
        for next in sequence.iter().skip(index + 2) {
            assert!(job::transition(Some(previous), next).is_err());
        }
    }
    let mut different = sequence[2].clone();
    different["owner"]["invocation"] = json!("e".repeat(32));
    assert!(job::transition(Some(&sequence[1]), &different).is_err());
    let mut different = sequence[2].clone();
    different["request"]["selected"] = json!(["b-1-x86_64.pkg.tar.zst"]);
    assert!(job::transition(Some(&sequence[1]), &different).is_err());
}
#[test]
fn package_exit_cannot_claim_completion_without_owned_subtree_cleanup() {
    let sequence = stages();
    for missing in [Value::Null, json!(false), json!("true")] {
        let mut final_record = sequence[4].clone();
        final_record["group_empty"] = missing;
        assert!(job::validate(&final_record).is_err());
    }
    let mut stopping = sequence[3].clone();
    stopping["group_empty"] = json!(true);
    assert!(job::validate(&stopping).is_err());
    let mut failed = sequence[3].clone();
    failed["exit_code"] = json!(2);
    assert!(job::validate(&failed).is_err());
}
#[test]
fn offline_package_jobs_cannot_redirect_targets_inject_filenames_or_weaken_root_identity() {
    for (field, value) in [
        ("target", json!("/")),
        ("operation", json!("update")),
        ("target_mount", json!(0)),
        ("target_inode", json!([1, 2, 1000, 0, 16877])),
        ("target_inode", json!([1, 2, 0, 0, 16895])),
        ("target_inode", json!([1, 2, 0, 0, 33188])),
        ("selected", json!(["../a.pkg.tar.zst"])),
        ("selected", json!(["a.pkg.tar.zst", "a.pkg.tar.zst"])),
    ] {
        let mut body = request();
        body[field] = value;
        assert!(job::request(&body).is_err());
    }
    let definition =
        enzimos_system_backend::native_worker_contract::Definition::installer(ID).unwrap();
    assert_eq!(definition.unit(), job::unit(ID).unwrap());
    assert_eq!(definition.arguments(), job::arguments(ID).unwrap());
    assert_eq!(definition.executable(), job::EXECUTABLE);
}
