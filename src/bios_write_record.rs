// SPDX-License-Identifier: MIT
//! Closed BIOS write evidence codec. Records never construct execution authority.
//! The caller retains its pidfd, the stopped worker cgroup, pinned vendor image,
//! original device description and one-use durable intent through the actual write.
use crate::{install_boot_disk, install_boot_sources, package_job};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::Value;

pub const ROLE: &str = "whole-disk-bios";
pub const MAX: usize = 32768;

fn inode(disk: &Value) -> Result<files::FileIdentity> {
    install_boot_disk::validate(disk)?;
    let identity: files::FileIdentity = serde_json::from_value(disk["inode"].clone())
        .map_err(|_| Error("BIOS original inode field bounds".into()))?;
    require(
        (0..1_000_000_000).contains(&identity.4) && (0..1_000_000_000).contains(&identity.6),
        "BIOS original inode timestamp precision bounds",
    )?;
    Ok(identity)
}

fn owner_record(owner: &Value, id: &str) -> Result<()> {
    json::fields(owner, "pid start_ticks invocation executable_sha256 unit")?;
    require(
        owner["pid"]
            .as_u64()
            .is_some_and(|p| p > 1 && p < i32::MAX as u64)
            && owner["start_ticks"].as_u64().is_some_and(|t| t > 0)
            && owner["unit"] == package_job::unit(id)?,
        "BIOS measured worker record shape",
    )?;
    package_job::id(
        owner["invocation"]
            .as_str()
            .ok_or_else(|| Error("BIOS invocation missing".into()))?,
    )?;
    enzimos_policy::identity::sha(
        owner["executable_sha256"]
            .as_str()
            .ok_or_else(|| Error("BIOS worker image missing".into()))?,
    )
    .map(|_| ())
}

/// Validate evidence against the already selected request, measured owner and
/// retained vendor's public receipt. Equality here is necessary but insufficient
/// for a write grant or completion: no record supplies a live kernel object.
pub fn validate(body: &Value, request: &Value, owner: &Value, vendor: &Value) -> Result<()> {
    package_job::request(request)?;
    json::fields(
        body,
        "schema id role phase request_sha256 owner vendor arguments before_disk after_disk vendor_exit device_events_settled worker_closed installed_qualified",
    )?;
    require(
        json::canonical(body)?.len() <= MAX
            && request["operation"] == package_job::BOOT
            && body["schema"] == 1
            && body["id"] == request["id"]
            && body["role"] == ROLE
            && body["request_sha256"] == json::fingerprint(request)?
            && body["owner"] == *owner
            && body["vendor"] == *vendor
            && body["before_disk"] == request["boot"]["disk"]
            && body["arguments"] == serde_json::json!(["bios-install", "@fd:1", "1"])
            && body["worker_closed"] == false
            && body["installed_qualified"] == false,
        "BIOS evidence original binding or premature authority claim",
    )?;
    owner_record(owner, request["id"].as_str().unwrap())?;
    install_boot_sources::validate(vendor)?;
    require(
        vendor["path"] == "usr/bin/limine"
            && vendor["bytes"]
                .as_u64()
                .is_some_and(|n| n <= 32 * 1024 * 1024)
            && vendor["inode"][7]
                .as_u64()
                .is_some_and(|mode| mode & 0o111 != 0),
        "BIOS requires the exact protected executable vendor record",
    )?;
    let before = inode(&body["before_disk"])?;
    match body["phase"].as_str() {
        Some("writing") => require(
            body["after_disk"].is_null()
                && body["vendor_exit"].is_null()
                && body["device_events_settled"] == false,
            "BIOS intent cannot claim vendor success or final device evidence",
        ),
        Some("data-write-observed") => {
            require(
                body["vendor_exit"] == 0 && body["device_events_settled"] == true,
                "BIOS observed write requires successful vendor and settlement",
            )?;
            let after = inode(&body["after_disk"])?;
            for field in ["path", "block", "mount", "graph"] {
                require(
                    body["before_disk"][field] == body["after_disk"][field],
                    "BIOS write changed device description, media epoch or ancestry",
                )?;
            }
            crate::device_epoch::transition(&before, &after)
        }
        _ => Err(Error(
            "BIOS evidence phase cannot authorize completion or replay".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Value, Value, Value, Value) {
        let request = crate::install_boot_tests::request();
        let owner = json!({"pid":789,"start_ticks":456,"invocation":"a".repeat(32),"executable_sha256":"b".repeat(64),"unit":package_job::unit(request["id"].as_str().unwrap()).unwrap()});
        let vendor = json!({"path":"usr/bin/limine","bytes":128,"sha256":"c".repeat(64),"mount":123,"inode":[1,3,128,1,0,2,0,33261,0,0,1]});
        let body = json!({"schema":1,"id":request["id"],"role":ROLE,"phase":"writing","request_sha256":json::fingerprint(&request).unwrap(),"owner":owner,"vendor":vendor,"arguments":["bios-install","@fd:1","1"],"before_disk":request["boot"]["disk"],"after_disk":null,"vendor_exit":null,"device_events_settled":false,"worker_closed":false,"installed_qualified":false});
        (body, request, owner, vendor)
    }
    fn observed(mut body: Value) -> Value {
        body["phase"] = json!("data-write-observed");
        body["vendor_exit"] = json!(0);
        body["device_events_settled"] = json!(true);
        body["after_disk"] = body["before_disk"].clone();
        body["after_disk"]["inode"][3] = json!(3);
        body["after_disk"]["inode"][5] = json!(4);
        body
    }
    #[test]
    fn bios_evidence_distinguishes_intent_and_observed_write_without_worker_closure() {
        let (body, request, owner, vendor) = fixture();
        validate(&body, &request, &owner, &vendor).unwrap();
        let done = observed(body.clone());
        validate(&done, &request, &owner, &vendor).unwrap();
        for (pointer, value) in [
            ("/worker_closed", json!(true)),
            ("/installed_qualified", json!(true)),
            ("/phase", json!("complete")),
            ("/vendor_exit", json!(2)),
            ("/device_events_settled", json!(false)),
            ("/arguments", json!(["bios-install", "/dev/vda", "1"])),
        ] {
            let mut bad = done.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate(&bad, &request, &owner, &vendor).is_err(),
                "{pointer}"
            );
        }
        let mut bad = body;
        bad["vendor_exit"] = json!(0);
        assert!(validate(&bad, &request, &owner, &vendor).is_err());
    }
    #[test]
    fn bios_observation_refuses_equal_content_substitution_static_epoch_change_and_regression() {
        let (body, request, owner, vendor) = fixture();
        let good = observed(body);
        for (pointer, value) in [
            ("/after_disk/inode/1", json!(9)),
            ("/after_disk/inode/7", json!(25024)),
            ("/after_disk/inode/9", json!(7)),
            ("/after_disk/inode/10", json!(2)),
            ("/after_disk/inode/6", json!(1_000_000_000)),
            ("/after_disk/mount", json!(124)),
            ("/after_disk/block/disk_sequence", json!(124)),
            ("/after_disk/path", json!("/dev/vdb")),
            ("/request_sha256", json!("d".repeat(64))),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate(&bad, &request, &owner, &vendor).is_err(),
                "{pointer}"
            );
        }
        let mut other_owner = owner.clone();
        other_owner["pid"] = json!(790);
        assert!(validate(&good, &request, &other_owner, &vendor).is_err());
        let mut other_vendor = vendor;
        other_vendor["inode"][1] = json!(4);
        assert!(validate(&good, &request, &owner, &other_vendor).is_err());
    }
}
