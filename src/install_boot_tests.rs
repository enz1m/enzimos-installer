// SPDX-License-Identifier: MIT
//! Pure negative controls for boot intent, source identity and authorization bindings.
use crate::{install_boot_receipt as receipt, package_job as job};
use enzimos_platform::json as encoding;
use serde_json::{Value, json};
fn artifact(path: &str) -> Value {
    json!({"path":path,"bytes":128,"sha256":"a".repeat(64),"mount":123,"inode":[1,2,128,1,0,2,0,33188,0,0,1]})
}
pub(crate) fn request() -> Value {
    json!({"schema":3,"id":"1".repeat(32),"boot_id":"12345678-1234-1234-1234-123456789abc","operation":job::BOOT,"target":"/mnt/enzimos",
        "media_manifest_sha256":"a".repeat(64),"selected":["a-1-x86_64.pkg.tar.zst"],"target_mount":123,"target_inode":[1,2,0,0,16877],
        "caller":{"pid":123,"start_ticks":456,"executable_sha256":"b".repeat(64)},
        "configuration":{"filesystem_uuid":"11111111-1111-4111-8111-111111111111","esp_uuid":"1234-ABCD","luks_uuid":null,"answers":{"path":"/run/installer/answers","mount":456,"inode":[1,2,128,1,2,3,4,33152,0,0,1]}},
        "boot":{"security":{"firmware":{"uefi":false,"capable":false,"enabled":false,"setup_mode":false},"owner":null},
            "disk":{"path":"/dev/vda","mount":123,"inode":[1,2,0,1,0,2,0,25008,0,6,1],
                "block":{"major":252,"minor":0,"device_inode":2,"device_filesystem":1,"disk_sequence":123,"bytes":10737418240u64,"read_only":false},
                "graph":{"nodes":[{"device":[252,0],"path":"/sys/devices/pci0000:00/virtio0/block/vda","dependencies":[],"disk_sequence":123}],"leaves":[[252,0]]}}}})
}
fn body(request: &Value, owner: &Value) -> Value {
    let kernel = |release: &str| json!({"release":release,"pkgbase":artifact(&format!("usr/lib/modules/{release}/pkgbase")),"kernel":artifact(&format!("usr/lib/modules/{release}/vmlinuz"))});
    json!({"schema":1,"id":request["id"],"role":"fresh-boot-installation","phase":"writing","request_sha256":encoding::fingerprint(request).unwrap(),"owner":owner,"security":request["boot"]["security"],"disk":request["boot"]["disk"],
        "options":"root=UUID=11111111-1111-4111-8111-111111111111 rootflags=subvol=enzimos-root rw quiet","kernels":{"linux":kernel("6.18.1-arch1-1"),"linux-lts":kernel("6.12.1-1-lts")},"files":{},"steps":[],"firmware":null,"recovery_pending":null,"boot_complete":false,"installed_qualified":false})
}
#[test]
fn boot_request_preserves_wire_roles_and_refuses_disk_or_security_identity_substitution() {
    let good = request();
    job::request(&good).unwrap();
    for (pointer, value) in [
        ("/schema", json!(2)),
        ("/operation", json!(job::SYSTEM)),
        ("/boot/disk/inode/7", json!(33152)),
        ("/boot/disk/block/disk_sequence", json!(124)),
        ("/boot/disk/graph/leaves", json!([[252, 1]])),
        ("/boot/disk/mount", json!(0)),
        ("/boot/security/firmware/enabled", json!(true)),
        ("/boot/security/firmware/uefi", json!("true")),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(job::request(&bad).is_err(), "{pointer}");
    }
    let mut bad = good;
    bad["boot"]["security"]["private_key"] = json!("refused");
    assert!(job::request(&bad).is_err());
}
#[test]
fn boot_intent_cannot_skip_publication_claim_installed_qualification_or_move_sources() {
    let request = request();
    let owner = json!({"pid":789,"invocation":"a".repeat(32)});
    let good = body(&request, &owner);
    receipt::validate(&good, &request, &owner).unwrap();
    for (pointer, value) in [
        ("/phase", json!("complete")),
        ("/steps", json!(["sources", "loaders"])),
        ("/boot_complete", json!(true)),
        ("/installed_qualified", json!(true)),
        ("/request_sha256", json!("b".repeat(64))),
        (
            "/kernels/linux/kernel/path",
            json!("usr/lib/modules/foreign/vmlinuz"),
        ),
        ("/kernels/linux/kernel/inode/10", json!(2)),
        ("/kernels/linux/kernel/inode/4", json!(-1)),
        ("/kernels/linux/kernel/inode/7", json!(33206)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            receipt::validate(&bad, &request, &owner).is_err(),
            "{pointer}"
        );
    }
    let mut bad = good.clone();
    bad["files"]["etc/shadow"] = artifact("etc/shadow");
    assert!(receipt::validate(&bad, &request, &owner).is_err());
    let mut bad = good.clone();
    bad["files"]["boot/owner.key"] = artifact("boot/owner.key");
    assert!(receipt::validate(&bad, &request, &owner).is_err());
    let mut bad = good;
    bad["kernels"]["linux-lts"] = bad["kernels"]["linux"].clone();
    assert!(receipt::validate(&bad, &request, &owner).is_err());
}
#[test]
fn staged_enrolled_owner_authority_requires_private_single_link_material_and_exact_public_bindings()
{
    let mut security = json!({"firmware":{"uefi":true,"capable":true,"enabled":true,"setup_mode":false},"owner":{"directory":{"mount":123,"inode":[1,2,0,0,16832]},"files":{"owner.key":[1,2,128,1,0,2,0,33152,0,0,1],"owner.crt":[1,3,128,1,0,2,0,33188,0,0,1],"owner.cer":[1,4,128,1,0,2,0,33188,0,0,1]},"certificate_sha256":"a".repeat(64),"enrolled_db_sha256":"b".repeat(64)}});
    crate::boot_security_source::validate(&security).unwrap();
    for (pointer, value) in [
        ("/owner/files/owner.key/7", json!(33188)),
        ("/owner/files/owner.key/10", json!(2)),
        ("/owner/files/owner.crt/8", json!(1000)),
        ("/owner/directory/mount", json!(0)),
        ("/owner/enrolled_db_sha256", json!("wrong")),
        ("/firmware/enabled", json!(false)),
    ] {
        let mut bad = security.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            crate::boot_security_source::validate(&bad).is_err(),
            "{pointer}"
        );
    }
    security["owner"]["key_bytes"] = json!("refused");
    assert!(crate::boot_security_source::validate(&security).is_err());
}
#[test]
fn complete_bios_receipt_requires_every_boot_artifact_and_an_empty_private_recovery_marker() {
    let request = request();
    let owner = json!({"pid":789,"invocation":"a".repeat(32)});
    let mut complete = body(&request, &owner);
    complete["phase"] = json!("complete");
    complete["boot_complete"] = json!(true);
    complete["steps"] = json!(receipt::STEPS);
    complete["recovery_pending"] = json!({"mount":123,"inode":[1,2,0,1,0,2,0,33152,0,0,1]});
    let plan =
        crate::install_boot_plan::prepare(complete["options"].as_str().unwrap(), false).unwrap();
    for name in plan.files.keys().map(|n| format!("boot/{n}")).chain(
        [
            "etc/plymouth/plymouthd.conf",
            "boot/vmlinuz-linux",
            "boot/vmlinuz-linux-lts",
            "boot/initramfs-linux.img",
            "boot/initramfs-linux-lts.img",
            "boot/limine/limine-bios.sys",
            "boot/EFI/systemd/systemd-bootx64.efi",
            "boot/EFI/BOOT/BOOTX64.EFI",
            "etc/systemd/system/enzimos-recovery-image.service",
        ]
        .map(str::to_owned),
    ) {
        complete["files"][&name] = artifact(&name);
    }
    receipt::validate(&complete, &request, &owner).unwrap();
    let mut missing = complete.clone();
    missing["files"]
        .as_object_mut()
        .unwrap()
        .remove("boot/vmlinuz-linux-lts");
    assert!(receipt::validate(&missing, &request, &owner).is_err());
    for (pointer, value) in [
        ("/recovery_pending/inode/2", json!(1)),
        ("/recovery_pending/inode/7", json!(33188)),
        ("/recovery_pending/inode/10", json!(2)),
        (
            "/steps",
            json!([
                "sources",
                "initramfs",
                "loaders",
                "entries",
                "signatures",
                "menus",
                "recovery"
            ]),
        ),
    ] {
        let mut bad = complete.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            receipt::validate(&bad, &request, &owner).is_err(),
            "{pointer}"
        );
    }
}
