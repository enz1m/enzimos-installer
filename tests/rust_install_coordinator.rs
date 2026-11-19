// SPDX-License-Identifier: MIT
use enzimos_installer::install_coordinator_record::{self as record, PHASES};
use serde_json::{Value, json as v};
fn initial() -> Value {
    record::initial(
        "11111111-1111-1111-1111-111111111111",
        &v!({"path":"/dev/vda","diskseq":7}),
        &v!({"username":"admin","encrypted":true}),
        &v!({"inode":[1,2],"mount":3}),
        &"a".repeat(64),
    )
    .unwrap()
}
#[test]
fn preparation_receipt_requires_all_ordered_phases_and_never_replays_or_claims_qualification() {
    let mut body = initial();
    for (index, phase) in PHASES.iter().enumerate() {
        for other in PHASES.iter().filter(|other| *other != phase) {
            assert!(record::advance(&body, other, &v!({"actual":"observed"})).is_err());
        }
        body = record::advance(&body, phase, &v!({"observed_phase":phase})).unwrap();
        record::validate(&body).unwrap();
        assert_eq!(body["steps"].as_array().unwrap().len(), index + 1);
        assert_eq!(body["installed_qualification"], false);
    }
    for phase in PHASES {
        assert!(record::advance(&body, phase, &Value::Null).is_err());
    }
}
#[test]
fn binding_digest_refuses_edited_history_and_schema_including_secret_body_fields() {
    let body = record::advance(&initial(), "partitioned", &v!({"actual_guid":"new"})).unwrap();
    for field in [
        "boot_id",
        "disk_sha256",
        "answers_sha256",
        "answer_binding_sha256",
        "media_sha256",
        "phase",
        "operation",
        "journal_sha256",
    ] {
        let mut changed = body.clone();
        changed[field] = v!("b".repeat(64));
        assert!(record::validate(&changed).is_err());
    }
    let mut changed = body.clone();
    changed["steps"][0]["evidence_sha256"] = v!("c".repeat(64));
    assert!(record::validate(&changed).is_err());
    let mut changed = body.clone();
    changed["installed_qualification"] = v!(true);
    assert!(record::validate(&changed).is_err());
    let mut changed = body.clone();
    changed["password"] = v!("secret");
    assert!(record::validate(&changed).is_err());
    assert!(!serde_json::to_string(&body).unwrap().contains("admin"));
}
