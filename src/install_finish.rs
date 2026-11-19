// SPDX-License-Identifier: MIT
//! A one-shot finish intent is durable before an irreversible PID 1 request.
use crate::{
    answer_source::Source, answers::Finish, component_receipt::Receipt,
    install_coordinator_record as coordinator, media_packages::Admitted,
};
use enzimos_platform::{Error, Result, files, json, require};
use enzimos_system_backend::system_manager::Manager;
use serde_json::{Value, json as value};
use std::path::Path;

fn target(action: &str) -> Result<&'static str> {
    match action {
        "reboot" => Ok("reboot.target"),
        "poweroff" => Ok("poweroff.target"),
        _ => Err(Error(
            "installer finish action outside closed registry".into(),
        )),
    }
}
fn validate(body: &Value) -> Result<()> {
    json::fields(
        body,
        "schema operation boot_id action phase coordinator_sha256 answers_sha256 answer_binding_sha256 media_sha256 package_sha256 storage_sha256 job installed_qualification",
    )?;
    require(
        body["schema"] == 1
            && body["operation"] == "finish-installation"
            && body["installed_qualification"] == false,
        "installer finish receipt role",
    )?;
    target(
        body["action"]
            .as_str()
            .ok_or_else(|| Error("finish action type".into()))?,
    )?;
    enzimos_policy::identity::uuid(
        body["boot_id"]
            .as_str()
            .ok_or_else(|| Error("finish boot type".into()))?,
    )?;
    for name in [
        "coordinator_sha256",
        "answers_sha256",
        "answer_binding_sha256",
        "media_sha256",
        "package_sha256",
        "storage_sha256",
    ] {
        enzimos_policy::identity::sha(
            body[name]
                .as_str()
                .ok_or_else(|| Error("finish digest type".into()))?,
        )?;
    }
    require(
        match body["phase"].as_str() {
            Some("requesting") => body["job"].is_null(),
            Some("accepted") => body["job"]
                .as_str()
                .and_then(|s| s.strip_prefix("/org/freedesktop/systemd1/job/"))
                .is_some_and(|id| {
                    !id.is_empty()
                        && id.len() <= 20
                        && id.bytes().all(|b| b.is_ascii_digit())
                        && id.parse::<u64>().is_ok_and(|n| n > 0)
                }),
            _ => false,
        },
        "installer finish phase or actual job path differs",
    )
}
fn accept(before: &Value, job: &str) -> Result<Value> {
    validate(before)?;
    require(
        before["phase"] == "requesting",
        "installer finish cannot be replayed",
    )?;
    let mut next = before.clone();
    next["phase"] = value!("accepted");
    next["job"] = value!(job);
    validate(&next)?;
    Ok(next)
}

// Only the coordinator invokes this after normal teardown, while the original
// Target still holds the original disk and exclusion lock. No standalone retry.
pub(crate) fn request(
    source: &Source,
    media: &Admitted,
    store: &coordinator::Store,
    package: &Value,
    storage: &crate::target_storage::Finalized<'_, '_>,
) -> Result<Value> {
    source.recheck()?;
    media.recheck()?;
    let preparation = store.evidence()?;
    let storage_evidence = storage.evidence()?;
    coordinator::validate(&preparation)?;
    crate::package_job::validate(package)?;
    require(
        preparation["phase"] == "storage-closed"
            && preparation["steps"].as_array().unwrap().len() == coordinator::PHASES.len()
            && package["phase"] == "complete"
            && package["exit_code"] == 0
            && package["group_empty"] == true
            && package["request"]["operation"] == crate::package_job::BOOT
            && package["request"]["boot_id"] == preparation["boot_id"]
            && package["request"]["media_manifest_sha256"] == media.media.manifest_sha256
            && preparation["answers_sha256"] == json::fingerprint(&source.answers.review())?
            && preparation["answer_binding_sha256"] == json::fingerprint(&source.binding()?)?
            && preparation["media_sha256"] == media.media.manifest_sha256
            && preparation["steps"][4]["evidence_sha256"] == json::fingerprint(package)?
            && preparation["steps"][5]["evidence_sha256"] == json::fingerprint(package)?,
        "finish requires this original fully completed storage and package lifetime",
    )?;
    let action = if source.answers.finish == Finish::Reboot {
        "reboot"
    } else {
        "poweroff"
    };
    let body = value!({"schema":1,"operation":"finish-installation","boot_id":preparation["boot_id"],
        "action":action,"phase":"requesting","coordinator_sha256":json::fingerprint(&preparation)?,
        "answers_sha256":preparation["answers_sha256"],"answer_binding_sha256":preparation["answer_binding_sha256"],
        "media_sha256":media.media.manifest_sha256,"package_sha256":json::fingerprint(package)?,
        "storage_sha256":json::fingerprint(&storage_evidence)?,
        "job":null,"installed_qualification":false});
    validate(&body)?;
    let path = Path::new("/run/enzimos-install-native/finish")
        .join(format!("attempt-{}", files::random_hex(16)?));
    files::ensure_directory(path.parent().unwrap(), 0o700, 0)?;
    let directory = files::create_directory(&path, 0o700, 0)?;
    let mut receipt = Receipt::create(&directory, "finish.json", &body)?;
    let accepted = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let manager = Manager::new().await?;
            source.recheck()?;
            media.recheck()?;
            receipt.recheck()?;
            require(
                store.evidence()? == preparation && storage.evidence()? == storage_evidence,
                "original finish prerequisites changed before PID 1 request",
            )?;
            let job = manager.request_power_target(target(action)?).await?;
            accept(&body, &job)
        })?;
    // A shutdown can win this race. The requesting receipt still forbids replay;
    // a missing accepted epoch never means the provider did not receive it.
    receipt.publish(&accepted)?;
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn intent() -> Value {
        value!({"schema":1,"operation":"finish-installation",
        "boot_id":"11111111-1111-4111-8111-111111111111","action":"reboot","phase":"requesting",
        "coordinator_sha256":"a".repeat(64),"answers_sha256":"b".repeat(64),
        "answer_binding_sha256":"c".repeat(64),"media_sha256":"d".repeat(64),
        "package_sha256":"e".repeat(64),"storage_sha256":"f".repeat(64),"job":null,"installed_qualification":false})
    }
    #[test]
    fn finish_is_one_shot_and_only_accepts_actual_manager_job_paths() {
        let before = intent();
        validate(&before).unwrap();
        let after = accept(&before, "/org/freedesktop/systemd1/job/123").unwrap();
        assert!(accept(&after, "/org/freedesktop/systemd1/job/124").is_err());
        for job in [
            "/org/freedesktop/systemd1/job/0",
            "/org/freedesktop/systemd1/job/-1",
            "/other/123",
            "/org/freedesktop/systemd1/job/1/2",
        ] {
            assert!(accept(&before, job).is_err());
        }
        for action in ["halt", "reboot.target", "--force", ""] {
            let mut body = before.clone();
            body["action"] = value!(action);
            assert!(validate(&body).is_err());
        }
        let mut body = before;
        body["password"] = value!("must-not-be-recorded");
        assert!(validate(&body).is_err());
    }
}
