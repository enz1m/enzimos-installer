// SPDX-License-Identifier: MIT
use enzimos_installer::{install_configuration, package_handoff, package_job as job};
use enzimos_platform::{fd_packet::Credentials, json as encoding};
use serde_json::{Value, json};
fn request() -> Value {
    json!({"schema":2,"id":"1".repeat(32),"boot_id":"12345678-1234-1234-1234-123456789abc","operation":job::SYSTEM,"target":"/mnt/enzimos",
        "media_manifest_sha256":"a".repeat(64),"selected":["a-1-x86_64.pkg.tar.zst"],"target_mount":123,"target_inode":[1,2,0,0,16877],
        "caller":{"pid":123,"start_ticks":456,"executable_sha256":"b".repeat(64)},
        "configuration":{"filesystem_uuid":"11111111-1111-4111-8111-111111111111","esp_uuid":"1234-ABCD","luks_uuid":null,
            "answers":{"path":"/run/installer/answers","mount":456,"inode":[1,2,128,1,2,3,4,33152,0,0,1]}}})
}
fn receipt(request: &Value, owner: &Value) -> Value {
    let names = [
        "etc/hostname",
        "etc/hosts",
        "etc/locale.conf",
        "etc/vconsole.conf",
        "etc/X11/xorg.conf.d/00-keyboard.conf",
        "etc/tmpfiles.d/portables.conf",
        "etc/tmpfiles.d/systemd-nspawn.conf",
        "etc/fstab",
        "etc/enzimos/storage.json",
        "etc/locale.gen",
        "etc/mkinitcpio.conf",
    ];
    json!({"schema":1,"id":request["id"],"role":"fresh-system-configuration","phase":"writing","request_sha256":encoding::fingerprint(request).unwrap(),
        "owner":owner,"configuration":request["configuration"],"files":names.into_iter().map(|n|(n,"a".repeat(64))).collect::<std::collections::BTreeMap<_,_>>(),
        "links":{"etc/localtime":"/usr/share/zoneinfo/UTC","etc/resolv.conf":"/run/systemd/resolve/stub-resolv.conf"},
        "root_options":"root=UUID=11111111-1111-4111-8111-111111111111","hooks":"base systemd filesystems","steps":[],"boot_complete":false,"installed_qualified":false})
}
#[test]
fn system_wire_requires_exact_version_and_private_answer_inode_without_secrets() {
    let good = request();
    job::request(&good).unwrap();
    for (key, value) in [("schema", json!(1)), ("operation", json!(job::OFFLINE))] {
        let mut wrong = good.clone();
        wrong[key] = value;
        assert!(job::request(&wrong).is_err());
    }
    for (index, value) in [
        (7, json!(33188)),
        (8, json!(1000)),
        (9, json!(1000)),
        (10, json!(2)),
    ] {
        let mut wrong = good.clone();
        wrong["configuration"]["answers"]["inode"][index] = value;
        assert!(job::request(&wrong).is_err());
    }
    let mut wrong = good.clone();
    wrong["configuration"]["password"] = json!("never accepted");
    assert!(job::request(&wrong).is_err());
    let sender = Credentials {
        pid: 123,
        uid: 0,
        gid: 0,
    };
    let frame = json!({"schema":2,"id":good["id"],"request_sha256":encoding::fingerprint(&good).unwrap(),"original_fds":[3,4,5,6,7,8,9]});
    package_handoff::frame(&frame, &sender, good["id"].as_str().unwrap()).unwrap();
    let mut wrong = frame.clone();
    wrong["schema"] = json!(1);
    assert!(package_handoff::frame(&wrong, &sender, good["id"].as_str().unwrap()).is_err());
    let mut wrong = frame;
    wrong["original_fds"][6] = json!(3);
    assert!(package_handoff::frame(&wrong, &sender, good["id"].as_str().unwrap()).is_err());
}
#[test]
fn configuration_receipts_require_ordered_steps_exact_files_and_original_attempt() {
    let request = request();
    let owner = json!({"pid":789,"invocation":"a".repeat(32)});
    let good = receipt(&request, &owner);
    install_configuration::validate(&good, &request, &owner).unwrap();
    for (key, value) in [
        ("phase", json!("complete")),
        ("steps", json!(["account"])),
        ("boot_complete", json!(true)),
        ("installed_qualified", json!(true)),
        ("request_sha256", json!("b".repeat(64))),
    ] {
        let mut wrong = good.clone();
        wrong[key] = value;
        assert!(install_configuration::validate(&wrong, &request, &owner).is_err());
    }
    let mut wrong = good.clone();
    wrong["files"]["etc/shadow"] = json!("a".repeat(64));
    assert!(install_configuration::validate(&wrong, &request, &owner).is_err());
    let mut wrong = good.clone();
    wrong["configuration"]["answers"]["mount"] = json!(789);
    assert!(install_configuration::validate(&wrong, &request, &owner).is_err());
    let mut complete = good;
    complete["phase"] = json!("complete");
    complete["steps"] = json!(["material", "account", "locale", "services"]);
    install_configuration::validate(&complete, &request, &owner).unwrap();
    assert!(
        install_configuration::validate(
            &complete,
            &request,
            &json!({"pid":789,"invocation":"b".repeat(32)})
        )
        .is_err()
    );
}
#[test]
fn expanded_configuration_receipts_bind_storage_sessions_and_private_network_identities() {
    let request = request();
    let owner = json!({"pid":789,"invocation":"a".repeat(32)});
    let mut body = receipt(&request, &owner);
    body["schema"] = json!(2);
    body["files"]["etc/pacman.conf"] = json!("a".repeat(64));
    body["files"]["etc/snap-pac.ini"] = json!("b".repeat(64));
    for key in ["storage", "sessions", "network"] {
        body[key] = Value::Null;
    }
    install_configuration::validate(&body, &request, &owner).unwrap();
    let volume = |path: &str, id: u64, uuid: &str| json!({"path":path,"id":id,"uuid":uuid,"parent_uuid":null});
    body["storage"] = json!({"swap":{"mib":256,"container":volume("enzimos-swap",256,"11111111-1111-4111-8111-111111111111"),"mount":1,
        "inode":[1,2,256*1024*1024,1,2,3,4,33152,0,0,1],"flags":8388608},
        "root_snapshots":{"subvolume":volume(".snapshots",257,"22222222-2222-4222-8222-222222222222"),"mount":2,"inode":[1,3,0,0,16872]},
        "home_snapshots":{"subvolume":volume("home/.snapshots",258,"33333333-3333-4333-8333-333333333333"),"mount":3,"inode":[1,4,0,0,16872]},
        "root_config_sha256":"a".repeat(64),"home_config_sha256":"b".repeat(64)});
    body["sessions"] = json!({"username":"admin","uid":1000,"gid":1000,"wants":{"mount":4,"inode":[1,5,1000,1000,16832]},"units":{"enzimos-activity.service":"a".repeat(64)}});
    body["network"] = json!({"unavailable":false,"files":{"enzimos-11111111-1111-4111-8111-111111111111.nmconnection":{"mount":5,"inode":[1,6,128,1,2,3,4,33152,0,0,1]}}});
    assert!(install_configuration::validate(&body, &request, &owner).is_err());
    body["steps"] = json!([
        "material", "account", "locale", "services", "storage", "sessions", "network"
    ]);
    body["phase"] = json!("complete");
    install_configuration::validate(&body, &request, &owner).unwrap();
    for (field, value) in [
        (
            "network",
            json!({"unavailable":true,"files":body["network"]["files"]}),
        ),
        (
            "sessions",
            json!({"username":"admin","uid":0,"gid":1000,"wants":body["sessions"]["wants"],"units":{}}),
        ),
    ] {
        let mut wrong = body.clone();
        wrong[field] = value;
        assert!(install_configuration::validate(&wrong, &request, &owner).is_err());
    }
    let mut wrong = body.clone();
    wrong["network"]["password"] = json!("refused");
    assert!(install_configuration::validate(&wrong, &request, &owner).is_err());
    let mut wrong = body.clone();
    wrong["storage"]["swap"]["flags"] = json!(0);
    assert!(install_configuration::validate(&wrong, &request, &owner).is_err());
    let mut wrong = body;
    wrong["storage"]["swap"]["container"]["parent_uuid"] =
        json!("44444444-4444-4444-8444-444444444444");
    assert!(install_configuration::validate(&wrong, &request, &owner).is_err());
}
#[test]
fn multilib_configuration_is_idempotent_and_refuses_duplicate_or_redirected_blocks() {
    let original = "[options]\nSigLevel = Required TrustedOnly\n\n#[multilib]\n#Include = /etc/pacman.d/mirrorlist\n\n#[multilib-testing]\n#Include = /etc/pacman.d/mirrorlist\n";
    let enabled = enzimos_installer::system_config::multilib(original).unwrap();
    assert!(enabled.contains("[multilib]\nInclude = /etc/pacman.d/mirrorlist\n"));
    assert_eq!(
        enzimos_installer::system_config::multilib(&enabled).unwrap(),
        enabled
    );
    for invalid in [
        "[multilib]\nInclude = /tmp/redirect\n",
        "[multilib]\nInclude = /etc/pacman.d/mirrorlist\nInclude = /etc/pacman.d/mirrorlist\n",
        "[multilib]\nInclude = /etc/pacman.d/mirrorlist\nServer = https://unreviewed.invalid\n",
        "[multilib]\nInclude = /etc/pacman.d/mirrorlist\n#[multilib]\n#Include = /etc/pacman.d/mirrorlist\n",
    ] {
        assert!(enzimos_installer::system_config::multilib(invalid).is_err());
    }
}

#[test]
fn attachment_placeholder_requires_new_closed_configuration_version() {
    let request = request();
    let owner = json!({"pid":789,"invocation":"a".repeat(32)});
    let mut body = receipt(&request, &owner);
    body["schema"] = json!(3);
    body["members"] = json!({});
    body["files"]["etc/pacman.conf"] = json!("a".repeat(64));
    body["files"]["etc/snap-pac.ini"] = json!("b".repeat(64));
    for key in ["storage", "sessions", "network"] {
        body[key] = Value::Null;
    }
    install_configuration::validate(&body, &request, &owner).unwrap();
    body["schema"] = json!(4);
    assert!(install_configuration::validate(&body, &request, &owner).is_err());
    body["files"]["etc/tmpfiles.d/enzimos-backup-source.conf"] = json!("c".repeat(64));
    install_configuration::validate(&body, &request, &owner).unwrap();
    body["schema"] = json!(3);
    assert!(install_configuration::validate(&body, &request, &owner).is_err());
    body["schema"] = json!(4);
    body["files"]["etc/tmpfiles.d/other.conf"] = json!("c".repeat(64));
    assert!(install_configuration::validate(&body, &request, &owner).is_err());
}
