// SPDX-License-Identifier: MIT
use enzimos_installer::{media_manifest, media_plan};
use serde_json::json;
use std::collections::BTreeMap;
#[test]
fn sideload_repository_symlinks_stay_inside_the_retained_directory() {
    use enzimos_installer::media_source::repository_member;
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir().unwrap();
    let repo = temporary.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    std::fs::write(repo.join("object"), b"owned").unwrap();
    std::fs::write(temporary.path().join("outside"), b"not repository").unwrap();
    symlink("object", repo.join("summary")).unwrap();
    symlink("../outside", repo.join("escape")).unwrap();
    symlink(temporary.path().join("outside"), repo.join("absolute")).unwrap();
    symlink("/proc/self/fd/0", repo.join("magic")).unwrap();
    let directory = std::fs::File::open(repo).unwrap();
    let file = repository_member(&directory, "summary").unwrap();
    assert_eq!(
        enzimos_platform::files::read_file(&file, 32, None, true).unwrap(),
        b"owned"
    );
    for path in ["escape", "absolute", "magic", "../outside", "."] {
        assert!(repository_member(&directory, path).is_err());
    }
}
#[test]
fn offline_manifest_rejects_escaping_duplicate_and_noncanonical_records() {
    let hash = "a".repeat(64);
    let good = format!("{hash}  packages/a-1-x86_64.pkg.tar.zst\n");
    assert_eq!(media_manifest::parse(good.as_bytes()).unwrap().len(), 1);
    for path in [
        "../escape",
        "/absolute",
        "a/../b",
        "a//b",
        "a/./b",
        "a/",
        "SHA256SUMS",
    ] {
        assert!(media_manifest::parse(format!("{hash}  {path}\n").as_bytes()).is_err());
    }
    assert!(media_manifest::parse(format!("{good}{good}").as_bytes()).is_err());
    assert!(media_manifest::parse(format!("{}  a\n", hash.to_uppercase()).as_bytes()).is_err());
    for list in [
        "../a.pkg.tar.zst\n",
        "a.pkg.tar.zst\na.pkg.tar.zst\n",
        "-a.pkg.tar.zst\n",
        "a.pkg.tar.zst.sig\n",
    ] {
        assert!(media_manifest::package_list(list.as_bytes()).is_err());
    }
}
#[test]
fn reviewed_epoch_filenames_preserve_exact_versions_and_reject_renamed_archives() {
    let filename = "zlib-1:1.3.2-3-x86_64.pkg.tar.zst";
    let base = media_manifest::package_list(format!("{filename}\n").as_bytes()).unwrap();
    let declared = BTreeMap::from([("zlib".into(), "1:1.3.2-3".into())]);
    let observed = BTreeMap::from([(
        filename.into(),
        json!({"name":"zlib","version":"1:1.3.2-3"}),
    )]);
    let manifest = json!({"package_count":1,"nvidia_conditional":[]});
    assert_eq!(
        media_plan::pool(&base, &[], &declared, &observed, &manifest).unwrap(),
        base
    );
    let wrong = "other-1:1.3.2-3-x86_64.pkg.tar.zst";
    let observed_wrong = BTreeMap::from([(wrong.into(), observed[filename].clone())]);
    assert!(media_plan::pool(&[wrong.into()], &[], &declared, &observed_wrong, &manifest).is_err());
    let omitted = "zlib-1.3.2-3-x86_64.pkg.tar.zst";
    let omitted_map = BTreeMap::from([(omitted.into(), observed[filename].clone())]);
    assert!(media_plan::pool(&[omitted.into()], &[], &declared, &omitted_map, &manifest).is_ok());
    for bad in [
        "../zlib-1:1.3.2-3-x86_64.pkg.tar.zst",
        "-zlib-1:1.3.2-3-x86_64.pkg.tar.zst",
        "zlib-1:1.3.2-3-x86_64.pkg.tar.zst.sig",
        "zlib-1:1.3.2-3-x86_64.pkg.tar.zst\nzlib-1:1.3.2-3-x86_64.pkg.tar.zst",
    ] {
        assert!(media_manifest::package_list(format!("{bad}\n").as_bytes()).is_err());
    }
}
#[test]
fn archive_identities_and_conditional_driver_pool_must_match_the_complete_cohort() {
    let base: Vec<String> = vec!["a-1-x86_64.pkg.tar.zst".into()];
    let conditional = media_plan::NVIDIA
        .iter()
        .map(|name| format!("{name}-1-x86_64.pkg.tar.zst"))
        .collect::<Vec<_>>();
    let declared = media_plan::declarations(
        format!(
            "a 1\n{}",
            media_plan::NVIDIA
                .iter()
                .map(|name| format!("{name} 1\n"))
                .collect::<String>()
        )
        .as_bytes(),
    )
    .unwrap();
    let mut observed = BTreeMap::from([(base[0].clone(), json!({"name":"a","version":"1"}))]);
    for (name, file) in media_plan::NVIDIA.iter().zip(&conditional) {
        observed.insert(file.clone(), json!({"name":name,"version":"1"}));
    }
    let manifest = json!({"package_count":5,"nvidia_conditional":media_plan::NVIDIA});
    assert_eq!(
        media_plan::pool(&base, &conditional, &declared, &observed, &manifest)
            .unwrap()
            .len(),
        5
    );
    assert_eq!(
        media_plan::select(&base, &conditional, true).unwrap().len(),
        5
    );
    assert_eq!(
        media_plan::select(&base, &conditional, false).unwrap(),
        base
    );
    assert!(media_plan::select(&base, &conditional[..3], true).is_err());
    let mut wrong = observed.clone();
    wrong.get_mut(&base[0]).unwrap()["version"] = json!("2");
    assert!(media_plan::pool(&base, &conditional, &declared, &wrong, &manifest).is_err());
    let mut overlap = base.clone();
    overlap.push(conditional[0].clone());
    assert!(media_plan::pool(&overlap, &conditional, &declared, &observed, &manifest).is_err());
    assert!(media_plan::declarations(b"a 1\na 2\n").is_err());
}
fn manifest() -> serde_json::Value {
    json!({"native_apps":{},"activity_service":null,"ai_runtime":null,"secure_media":null,"schema":1,"label":"dev","development_artifact":true,"release_authorized":false,
        "native_policy":{"sha256":"a".repeat(64)},"cohort_plan_sha256":"b".repeat(64),"package_count":1,"nvidia_conditional":[],"trust_lock_sha256":"c".repeat(64),"review_before":"2026-10-10T00:00:00+00:00","kernel":"linux",
        "live":{"graphical_installer":true},"installer_sha256":"d".repeat(64),"desktop_preview_files":0,"flatpaks":[],"update_client":null,"mcp_center":null,"backend":null})
}
#[test]
fn development_media_requires_a_review_record_and_declared_native_package_digests() {
    let original = manifest();
    let members = BTreeMap::from([("native-policy.pkg.tar.zst".into(), "a".repeat(64))]);
    let now = chrono::DateTime::parse_from_rfc3339("2026-10-09T10:00:00Z")
        .unwrap()
        .timestamp_millis() as u64;
    assert!(media_plan::manifest(&original, &members, now).is_ok());
    // Producer live-root provenance belongs inside the existing live object;
    // adding a top-level key would break this closed installation contract.
    let mut native_live = original.clone();
    native_live["live"]["native_installer"] =
        json!({"sha256":"e".repeat(64),"production_cutover":false});
    assert!(media_plan::manifest(&native_live, &members, now).is_ok());
    let mut foreign_top_level = original.clone();
    foreign_top_level["native_installer"] = native_live["live"]["native_installer"].clone();
    assert!(media_plan::manifest(&foreign_top_level, &members, now).is_err());
    // enzimOS apps run on Flathub's runtime: their source needs Flathub's beside it.
    let mut fleet = original.clone();
    fleet["enzimos_flatpaks"] = json!(["org.enzimos.Calculator"]);
    assert!(media_plan::manifest(&fleet, &members, now).is_err());
    let mut runtime_members = members.clone();
    for path in [
        "flatpak/apps.txt",
        "flatpak/flathub.flatpakrepo",
        "flatpak/repo/config",
    ] {
        runtime_members.insert(path.into(), "b".repeat(64));
    }
    assert!(media_plan::manifest(&fleet, &runtime_members, now).is_ok());
    fleet["flatpaks"] = json!(["app.zen_browser.zen"]);
    assert!(media_plan::manifest(&fleet, &members, now).is_ok());
    fleet["enzimos_flatpaks"] = json!("org.enzimos.Calculator");
    assert!(media_plan::manifest(&fleet, &members, now).is_err());
    // The trust review is a one-time record: media stays installable after its date.
    assert!(media_plan::manifest(&original, &members, now + 365 * 86_400_000).is_ok());
    for (key, value) in [
        ("review_before", json!(1)),
        ("release_authorized", json!(true)),
        ("development_artifact", json!(false)),
        ("trust_lock_sha256", json!("bad")),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        assert!(media_plan::manifest(&changed, &members, now).is_err());
    }
    let mut extra = members.clone();
    extra.insert("backend.pkg.tar.zst".into(), "a".repeat(64));
    assert!(media_plan::manifest(&original, &extra, now).is_err());
    let mut swapped = original;
    swapped["native_policy"]["sha256"] = json!("b".repeat(64));
    assert!(media_plan::manifest(&swapped, &members, now).is_err());
}

#[test]
fn desktop_xwayland_receipt_has_a_closed_shape_and_requires_an_overlay() {
    let members = BTreeMap::from([("native-policy.pkg.tar.zst".into(), "a".repeat(64))]);
    let mut body = manifest();
    body["desktop_preview_files"] = json!(2);
    body["desktop_xwayland"] = json!({
        "version":"24.1.15",
        "url":"https://www.x.org/releases/individual/xserver/xwayland-24.1.15.tar.xz",
        "sha256":"a".repeat(64),
        "build_revision":format!("xwayland {} {}", "b".repeat(64), "c".repeat(64)),
        "binary_sha256":"d".repeat(64),
        "notice_sha256":"e".repeat(64),
    });
    assert!(media_plan::manifest(&body, &members, 0).is_ok());
    for (key, invalid) in [
        ("version", json!("../24.1.15")),
        ("url", json!("https://example.org/xwayland-24.1.15.tar.xz")),
        ("build_revision", json!("xwayland unbounded")),
        ("notice_sha256", json!("A".repeat(64))),
        ("unknown", json!(true)),
    ] {
        let mut wrong = body.clone();
        wrong["desktop_xwayland"][key] = invalid;
        assert!(media_plan::manifest(&wrong, &members, 0).is_err(), "{key}");
    }
    body["desktop_preview_files"] = json!(0);
    assert!(media_plan::manifest(&body, &members, 0).is_err());
    body["desktop_xwayland"] = json!(null);
    assert!(media_plan::manifest(&body, &members, 0).is_err());
}
