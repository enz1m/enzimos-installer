// SPDX-License-Identifier: MIT
use enzimos_installer::native_media;
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn manifest() -> Value {
    json!({"development_artifact":true,"release_authorized":false,
        "native_policy":{"release":24,"sha256":"a".repeat(64)},"backend":null,"update_client":null,
        "mcp_center":null,"activity_service":null,"native_apps":{},"ai_runtime":null})
}
fn members() -> BTreeMap<String, String> {
    BTreeMap::from([("native-policy.pkg.tar.zst".into(), "a".repeat(64))])
}
#[test]
fn rust_candidate_cohort_is_complete_closed_exact_and_never_activates_from_media() {
    let mut body = manifest();
    let mut files = members();
    body["native_rust"] = json!({});
    for component in native_media::RUST {
        body["native_rust"][component] = json!({"package_name":format!("enzimos-rust-{component}"),
            "version":"0.2.0","release":1,"sha256":"c".repeat(64),"profile":"rust-candidate","automatic_activation":false});
        files.insert(format!("rust-{component}.pkg.tar.zst"), "c".repeat(64));
    }
    let plan = native_media::plan(&body, &files).unwrap();
    assert_eq!(plan.len(), 6);
    for row in plan.iter().filter(|r| r.name.starts_with("enzimos-rust-")) {
        native_media::identity(row, &json!({"name":row.name,"version":"0.2.0-1"})).unwrap();
        assert!(
            native_media::identity(row, &json!({"name":row.name,"version":"0.2.0-2"})).is_err()
        );
    }
    for (key, wrong) in [
        ("automatic_activation", json!(true)),
        ("version", json!("0.3.0")),
        ("profile", json!("release")),
        ("package_name", json!("systemd")),
        ("release", json!(0)),
        ("sha256", json!("d".repeat(64))),
    ] {
        let mut changed = body.clone();
        changed["native_rust"]["installer"][key] = wrong;
        assert!(native_media::plan(&changed, &files).is_err());
    }
    let mut updated = body.clone();
    updated["native_rust"]["installer"]["version"] = json!("0.2.1");
    let plan = native_media::plan(&updated, &files).unwrap();
    let installer = plan
        .iter()
        .find(|r| r.name == "enzimos-rust-installer")
        .unwrap();
    native_media::identity(
        installer,
        &json!({"name":installer.name,"version":"0.2.1-1"}),
    )
    .unwrap();
    updated["native_rust"]["updates"]["version"] = json!("0.2.1");
    assert!(native_media::plan(&updated, &files).is_err());
    let mut partial = body.clone();
    partial["native_rust"]
        .as_object_mut()
        .unwrap()
        .remove("updates");
    assert!(native_media::plan(&partial, &files).is_err());
    let mut extra = body.clone();
    extra["native_rust"]["unknown"] = json!({});
    assert!(native_media::plan(&extra, &files).is_err());
    body["native_rust"] = Value::Null;
    assert!(native_media::plan(&body, &files).is_err());
}
#[test]
fn local_packages_require_exact_declared_hash_name_and_version_before_signing() {
    let body = manifest();
    let files = members();
    let plan = native_media::plan(&body, &files).unwrap();
    assert_eq!(plan.len(), 1);
    assert!(
        native_media::identity(
            &plan[0],
            &json!({"name":"enzimos-native-policy","version":"0.1.0-24"})
        )
        .is_ok()
    );
    for identity in [
        json!({"name":"systemd","version":"0.1.0-24"}),
        json!({"name":"enzimos-native-policy","version":"0.1.0-23"}),
    ] {
        assert!(native_media::identity(&plan[0], &identity).is_err());
    }
    let mut extra = files.clone();
    extra.insert("remote-access.pkg.tar.zst".into(), "b".repeat(64));
    assert!(native_media::plan(&body, &extra).is_err());
    for (key, value) in [
        ("release_authorized", json!(true)),
        ("development_artifact", json!(false)),
    ] {
        let mut wrong = body.clone();
        wrong[key] = value;
        assert!(native_media::plan(&wrong, &files).is_err());
    }
    let mut stale = body;
    stale["native_policy"]["sha256"] = json!("b".repeat(64));
    assert!(native_media::plan(&stale, &files).is_err());
}
#[test]
fn schema_one_legacy_application_default_keeps_exact_archive_version() {
    let mut body = manifest();
    let mut files = members();
    body["native_apps"]["remote-access"] = json!({"package_name":"enzimos-remote-access",
        "release":24,"sha256":"b".repeat(64),"revision":"owned","profile":"native-python"});
    files.insert("remote-access.pkg.tar.zst".into(), "b".repeat(64));
    let plan = native_media::plan(&body, &files).unwrap();
    let app = plan
        .iter()
        .find(|p| p.name == "enzimos-remote-access")
        .unwrap();
    native_media::identity(
        app,
        &json!({"name":"enzimos-remote-access","version":"0.1.0-24"}),
    )
    .unwrap();
    assert!(
        native_media::identity(
            app,
            &json!({"name":"enzimos-remote-access","version":"0.2.0-24"})
        )
        .is_err()
    );
    for version in [json!(null), json!(24), json!(""), json!("../0.1.0")] {
        let mut wrong = body.clone();
        wrong["native_apps"]["remote-access"]["version"] = version;
        assert!(native_media::plan(&wrong, &files).is_err());
    }
    body["native_apps"]["remote-access"]["unknown"] = json!(true);
    assert!(native_media::plan(&body, &files).is_err());
}
#[test]
fn native_application_registry_rejects_unknown_components_and_undeclared_payloads() {
    let mut body = manifest();
    let mut files = members();
    body["native_apps"]["remote-access"] = json!({"package_name":"enzimos-remote-access","version":"0.1.0",
        "release":28,"sha256":"b".repeat(64),"revision":"owned","profile":null});
    files.insert("remote-access.pkg.tar.zst".into(), "b".repeat(64));
    assert_eq!(native_media::plan(&body, &files).unwrap().len(), 2);
    let mut wrong = body.clone();
    wrong["native_apps"]["remote-access"]["package_name"] = json!("enzimos-store");
    assert!(native_media::plan(&wrong, &files).is_err());
    let mut unknown = body.clone();
    unknown["native_apps"]["unknown"] = unknown["native_apps"]["remote-access"].clone();
    assert!(native_media::plan(&unknown, &files).is_err());
    body["native_apps"]["remote-access"]["developer_descriptor"] =
        json!({"package_payloads_shipped":false});
    assert!(native_media::plan(&body, &files).is_err());
}
#[test]
fn ai_runtime_requires_its_complete_cohort_and_declares_its_models() {
    let mut body = manifest();
    let mut files = members();
    let rows=native_media::AI[..3].iter().map(|component| {
        let file=format!("ai-{component}.pkg.tar.zst"); files.insert(file.clone(),"b".repeat(64));
        json!({"package_name":format!("enzimos-{component}"),"media_file":file,"sha256":"b".repeat(64)})
    }).collect::<Vec<_>>();
    body["ai_runtime"] =
        json!({"schema":1,"packages":rows,"models_included":false,"release_authorized":false});
    assert_eq!(native_media::plan(&body, &files).unwrap().len(), 4);
    let mut missing = body.clone();
    missing["ai_runtime"]["packages"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(native_media::plan(&missing, &files).is_err());
    let mut duplicate = body.clone();
    duplicate["ai_runtime"]["packages"][1] = duplicate["ai_runtime"]["packages"][0].clone();
    assert!(native_media::plan(&duplicate, &files).is_err());
    let mut swapped = body.clone();
    swapped["ai_runtime"]["packages"][0]["media_file"] = json!("../../foreign.pkg.tar.zst");
    assert!(native_media::plan(&swapped, &files).is_err());
    body["ai_runtime"]["models_included"] = json!(true);
    assert!(
        native_media::plan(&body, &files).is_err(),
        "models declared without the models package"
    );
    files.insert("ai-ai-models.pkg.tar.zst".into(), "d".repeat(64));
    body["ai_runtime"]["packages"].as_array_mut().unwrap().push(
        json!({"package_name":"enzimos-ai-models","media_file":"ai-ai-models.pkg.tar.zst","sha256":"d".repeat(64)}));
    let plan = native_media::plan(&body, &files).unwrap();
    assert_eq!(plan.len(), 5);
    let models = plan
        .iter()
        .find(|row| row.name == "enzimos-ai-models")
        .unwrap();
    assert_eq!(models.max_bytes, 2 * 1024 * 1024 * 1024);
    body["ai_runtime"]["models_included"] = json!(false);
    assert!(
        native_media::plan(&body, &files).is_err(),
        "the models package without the declaration"
    );
    body["ai_runtime"]["models_included"] = json!(true);
    files.insert("ai-streaming-speech.pkg.tar.zst".into(), "9".repeat(64));
    body["ai_runtime"]["packages"].as_array_mut().unwrap().push(
        json!({"package_name":"enzimos-streaming-speech","media_file":"ai-streaming-speech.pkg.tar.zst","sha256":"9".repeat(64)}));
    assert!(native_media::plan(&body, &files).is_err());
    files.insert("ai-dictation.pkg.tar.zst".into(), "e".repeat(64));
    body["ai_runtime"]["packages"].as_array_mut().unwrap().push(
        json!({"package_name":"enzimos-dictation","media_file":"ai-dictation.pkg.tar.zst","sha256":"e".repeat(64)}));
    let plan = native_media::plan(&body, &files).unwrap();
    assert!(
        plan.iter().any(|r| r.name == "enzimos-dictation"),
        "dictation installs with the AI runtime"
    );
    files.insert("ai-sherpa-onnx-cpu.pkg.tar.zst".into(), "f".repeat(64));
    body["ai_runtime"]["packages"].as_array_mut().unwrap().push(
        json!({"package_name":"enzimos-sherpa-onnx-cpu","media_file":"ai-sherpa-onnx-cpu.pkg.tar.zst","sha256":"f".repeat(64)}));
    let plan = native_media::plan(&body, &files).unwrap();
    assert!(
        plan.iter().any(|r| r.name == "enzimos-sherpa-onnx-cpu"),
        "the speech-model runtime installs with the AI runtime"
    );
}
#[test]
fn the_recovery_environment_is_one_declared_package() {
    let mut body = manifest();
    let mut files = members();
    body["recovery_env"] = json!({"release":1,"sha256":"f".repeat(64)});
    assert!(
        native_media::plan(&body, &files).is_err(),
        "declared but absent"
    );
    files.insert("recovery-env.pkg.tar.zst".into(), "f".repeat(64));
    let plan = native_media::plan(&body, &files).unwrap();
    let row = plan
        .iter()
        .find(|r| r.name == "enzimos-recovery-env")
        .unwrap();
    native_media::identity(
        row,
        &json!({"name":"enzimos-recovery-env","version":"0.1.0-1"}),
    )
    .unwrap();
}
#[test]
fn native_replacements_are_exact_and_never_beside_their_arch_providers() {
    let mut body = manifest();
    let mut files = members();
    body["native_apps"]["xdg-desktop-portal-hyprland"] = json!({
        "package_name":"enzimos-xdg-desktop-portal-hyprland","version":"1.3.12.r1","release":1,
        "sha256":"e".repeat(64),"revision":"0e832b50ecc49d4bae01a29845c1b3fafc5c5c99",
        "profile":"release","replaces":"xdg-desktop-portal-hyprland"});
    files.insert(
        "xdg-desktop-portal-hyprland.pkg.tar.zst".into(),
        "e".repeat(64),
    );
    body["native_apps"]["greetd"] = json!({"package_name":"enzimos-greetd","version":"0.10.3.enzimos1",
        "release":1,"sha256":"f".repeat(64),"revision":"08efe60feceea8c81f9571c666880ff1e1c2e3ff",
        "profile":"release","replaces":"greetd"});
    files.insert("greetd.pkg.tar.zst".into(), "f".repeat(64));
    body["native_apps"]["keyring"] = json!({"package_name":"enzimos-keyring", "version":"0.6.0", "release":1,
        "sha256":"a".repeat(64), "revision":null, "profile":null, "replaces":"gnome-keyring"});
    files.insert("keyring.pkg.tar.zst".into(), "a".repeat(64));
    let plan = native_media::plan(&body, &files).unwrap();
    let portal = plan
        .iter()
        .find(|p| p.name == "enzimos-xdg-desktop-portal-hyprland")
        .unwrap();
    assert_eq!(
        portal.replaces.as_deref(),
        Some("xdg-desktop-portal-hyprland")
    );
    native_media::identity(
        portal,
        &json!({"name":"enzimos-xdg-desktop-portal-hyprland","version":"1.3.12.r1-1"}),
    )
    .unwrap();
    let rows = plan.iter().collect::<Vec<_>>();
    let without = BTreeMap::from([("hyprutils".to_owned(), "0.14.2-1".to_owned())]);
    native_media::disjoint(&rows, &without).unwrap();
    let mut beside = without.clone();
    beside.insert("xdg-desktop-portal-hyprland".into(), "1.4.1-2".into());
    assert!(native_media::disjoint(&rows, &beside).is_err());
    for name in ["greetd", "greetd-agreety", "gnome-keyring"] {
        let mut conflict = without.clone();
        conflict.insert(name.into(), "0.10.3-2".into());
        assert!(native_media::disjoint(&rows, &conflict).is_err(), "{name}");
    }
    let mut same_name = without;
    same_name.insert(
        "enzimos-xdg-desktop-portal-hyprland".into(),
        "1.3.12.r1-1".into(),
    );
    assert!(native_media::disjoint(&rows, &same_name).is_err());
    // The replacement is fixed by the reviewed registry: omitted, retargeted or
    // claimed by another component, the media are refused.
    for wrong in [
        json!(null),
        json!("systemd"),
        json!(["xdg-desktop-portal-hyprland"]),
    ] {
        let mut changed = body.clone();
        changed["native_apps"]["xdg-desktop-portal-hyprland"]["replaces"] = wrong;
        assert!(native_media::plan(&changed, &files).is_err());
    }
    let mut omitted = body.clone();
    omitted["native_apps"]["xdg-desktop-portal-hyprland"]
        .as_object_mut()
        .unwrap()
        .remove("replaces");
    assert!(native_media::plan(&omitted, &files).is_err());
    let mut other = body.clone();
    other["native_apps"]["remote-access"] = json!({"package_name":"enzimos-remote-access","version":"0.1.0",
        "release":28,"sha256":"b".repeat(64),"revision":"owned","profile":null,
        "replaces":"xdg-desktop-portal-hyprland"});
    files.insert("remote-access.pkg.tar.zst".into(), "b".repeat(64));
    assert!(native_media::plan(&other, &files).is_err());
    other["native_apps"]["remote-access"]
        .as_object_mut()
        .unwrap()
        .remove("replaces");
    let plan = native_media::plan(&other, &files).unwrap();
    assert!(
        plan.iter()
            .find(|p| p.name == "enzimos-remote-access")
            .unwrap()
            .replaces
            .is_none()
    );
}
// Application, device-service and icon packages must pass media admission.
#[test]
fn native_enzui_app_packages_are_admitted() {
    let mut body = manifest();
    let mut files = members();
    for (index, component) in [
        "files",
        "text",
        "task-manager",
        "phone-link",
        "mount",
        "aft-mtp",
        "icon-theme",
    ]
    .into_iter()
    .enumerate()
    {
        let digest = ["c", "d", "e", "f", "1", "2", "3"][index].repeat(64);
        body["native_apps"][component] = json!({"package_name":format!("enzimos-{component}"),
            "version":"0.1.0","release":1,"sha256":digest,"revision":"a".repeat(40),"profile":"release"});
        files.insert(format!("{component}.pkg.tar.zst"), digest);
    }
    let plan = native_media::plan(&body, &files).unwrap();
    for name in [
        "enzimos-files",
        "enzimos-text",
        "enzimos-task-manager",
        "enzimos-phone-link",
        "enzimos-mount",
        "enzimos-aft-mtp",
        "enzimos-icon-theme",
    ] {
        assert!(
            plan.iter().any(|row| row.name == name),
            "{name} not planned"
        );
    }
}
