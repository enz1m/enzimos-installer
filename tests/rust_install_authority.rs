// SPDX-License-Identifier: MIT
use enzimos_installer::{install_authority, native_package_body, package_job as job};
use enzimos_platform::json as encoding;
use enzimos_policy::authority;
use serde_json::{Value, json};
use std::path::Path;
const ID: &str = "11111111111111111111111111111111";
fn request() -> Value {
    json!({"schema":1,"id":ID,"boot_id":"12345678-1234-1234-1234-123456789abc","operation":job::OFFLINE,"target":"/mnt/enzimos",
        "media_manifest_sha256":"a".repeat(64),"selected":["a-1-x86_64.pkg.tar.zst"],"target_mount":123,"target_inode":[1,2,0,0,16877],
        "caller":{"pid":123,"start_ticks":456,"executable_sha256":"b".repeat(64)}})
}
fn owner() -> Value {
    json!({"pid":789,"start_ticks":999,"invocation":"c".repeat(32),"executable_sha256":"d".repeat(64),"unit":job::unit(ID).unwrap()})
}
fn receipt() -> Value {
    json!({"schema":1,"id":ID,"role":"fresh-installation-public-authority","phase":"publishing",
        "request_sha256":encoding::fingerprint(&request()).unwrap(),"owner":owner(),
        "authority":{"filesystem_uuid":"11111111-1111-4111-8111-111111111111",
            "subvolume":{"path":"enzimos-authority","id":257,"uuid":"22222222-2222-4222-8222-222222222222","parent_uuid":null},
            "mount":123,"inode":[1,2,0,0,16832]},
        "files":{"pubring.gpg":"a".repeat(64),"trustdb.gpg":"b".repeat(64),"gpg.conf":"c".repeat(64),"approved.trust":"d".repeat(64)},
        "local_signer":"E".repeat(40),"development_artifact":true,"release_authorized":false,"private_key_retired":true})
}
#[test]
fn public_authority_receipts_bind_the_original_offline_job_worker_and_private_subvolume() {
    let body = receipt();
    install_authority::validate(&body, &request(), &owner()).unwrap();
    for (field, value) in [
        ("phase", json!("adopted")),
        ("private_key_retired", json!(false)),
        ("release_authorized", json!(true)),
        ("request_sha256", json!("f".repeat(64))),
        ("local_signer", json!("e".repeat(40))),
    ] {
        let mut wrong = body.clone();
        wrong[field] = value;
        assert!(install_authority::validate(&wrong, &request(), &owner()).is_err());
    }
    let mut previous = owner();
    previous["invocation"] = json!("f".repeat(32));
    assert!(install_authority::validate(&body, &request(), &previous).is_err());
    let mut wrong = body.clone();
    wrong["authority"]["subvolume"]["path"] = json!("enzimos-root");
    assert!(install_authority::validate(&wrong, &request(), &owner()).is_err());
    let mut wrong = body;
    wrong["files"]["private-keys-v1.d"] = json!("a".repeat(64));
    assert!(install_authority::validate(&wrong, &request(), &owner()).is_err());
}
#[test]
fn authority_publication_has_only_exact_ordered_public_prefixes() {
    let body = receipt();
    assert_eq!(
        install_authority::prefix(&body["files"], 0).unwrap(),
        json!({})
    );
    assert_eq!(
        install_authority::prefix(&body["files"], 1).unwrap(),
        json!({"pubring.gpg":"a".repeat(64)})
    );
    assert_eq!(
        install_authority::prefix(&body["files"], authority::FILES.len()).unwrap(),
        body["files"]
    );
    assert!(install_authority::prefix(&body["files"], 5).is_err());
    let mut missing = body["files"].clone();
    missing.as_object_mut().unwrap().remove("trustdb.gpg");
    assert!(install_authority::prefix(&missing, 2).is_err());
}
#[test]
fn arch_only_wire_stays_valid_and_cannot_be_upgraded_mid_attempt() {
    let mut arch = request();
    arch["operation"] = json!(job::ARCH);
    job::request(&arch).unwrap();
    job::request(&request()).unwrap();
    let first = job::initial(arch).unwrap();
    let mut next = first.clone();
    next["phase"] = json!("handoff");
    next["owner"] = owner();
    next["request"] = request();
    assert!(job::transition(Some(&first), &next).is_err());
    assert!(install_authority::validate(&receipt(), &first["request"], &owner()).is_err());
    assert!(job::operation("initial-native-retry").is_err());
}
#[test]
fn native_offline_arguments_cannot_select_network_sync_or_redirect_payload_paths() {
    let directory = format!("/run/enzimos-install-native/native-{ID}/packages");
    let args = native_package_body::arguments(
        Path::new(&directory),
        &["native-policy.pkg.tar.zst".into()],
    )
    .unwrap();
    assert_eq!(
        &args[..10],
        [
            "--root",
            "@fd-dir:0",
            "--config",
            "@fd:1",
            "--gpgdir",
            "@fd-dir:2",
            "--noconfirm",
            "--needed",
            "-U",
            "--"
        ]
    );
    assert_eq!(args[10], format!("{directory}/native-policy.pkg.tar.zst"));
    assert!(
        native_package_body::arguments(
            Path::new("/tmp/packages"),
            &["native-policy.pkg.tar.zst".into()]
        )
        .is_err()
    );
    for files in [
        vec!["../../foreign.pkg.tar.zst".into()],
        vec!["--sync".into()],
        vec!["a.pkg.tar.zst".into(), "a.pkg.tar.zst".into()],
    ] {
        assert!(native_package_body::arguments(Path::new(&directory), &files).is_err());
    }
}
