// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::process::{Command, Stdio};

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn graphical_refusals_keep_stdout_json_and_the_original_exit_status() {
    // Ordinary UID refusal proves the error transport without touching host
    // network configuration, discovering disks or invoking Root helper bodies.
    assert_ne!(unsafe { libc::geteuid() }, 0);
    for args in [
        vec!["network"],
        vec!["partition", "inspect", "/dev/enzimos-no-such-fixture"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_enzimos-installer"))
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let body: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(body.as_object().unwrap().len(), 1);
        assert!(body["error"].as_str().is_some_and(|s| !s.is_empty()));
    }
}

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn coordinator_refusal_keeps_its_distinct_stderr_contract() {
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let output = Command::new(env!("CARGO_BIN_EXE_enzimos-installer"))
        .arg("prepare-from-stdin")
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let body: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(body["contract_valid"], false);
    assert_eq!(body["execution_available"], false);
}

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn graphical_install_refusal_never_emits_success_or_requests_restart() {
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let output = Command::new(env!("CARGO_BIN_EXE_enzimos-installer"))
        .arg("install-ui-from-stdin")
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = std::str::from_utf8(&output.stderr).unwrap();
    assert!(error.starts_with("Installation failed: "));
    assert!(!error.contains("ENZIMOS_INSTALL_PASS"));
}

#[test]
fn graphical_completion_refuses_incomplete_or_automatic_finish_outcomes() {
    use enzimos_installer::install_ui::{Stage, stage_line, validate_completion};
    let completed = serde_json::json!({
        "schema":1,"status":"bootable-base-prepared",
        "package_journal":{"phase":"complete","exit_code":0},
        "finish_requested":false,"finish_receipt":null
    });
    validate_completion(&completed).unwrap();
    let clean = enzimos_installer::install_ui::completion_state(&completed, true).unwrap();
    assert_eq!(clean["status"], "installed");
    let incomplete = enzimos_installer::install_ui::completion_state(&completed, false).unwrap();
    assert_eq!(incomplete["status"], "installed-cleanup-incomplete");
    assert_eq!(incomplete["installation_completed"], true);
    assert_eq!(incomplete["reinstall_required"], false);
    assert_eq!(incomplete["answers_retired"], false);
    let mut attempts = 0;
    let notice = enzimos_installer::install_ui::finalize_notice(
        &completed,
        "ENZIMOS_INSTALL_PASS fixture",
        || {
            attempts += 1;
            Err(enzimos_platform::Error("fixture cleanup I/O error".into()))
        },
    )
    .unwrap();
    assert_eq!(attempts, 2);
    assert!(
        notice.starts_with("ENZIMOS_INSTALL_CLEANUP_INCOMPLETE ")
            && !notice.contains("ENZIMOS_INSTALL_PASS")
    );
    assert_eq!(
        enzimos_installer::install_ui::finalize_notice(
            &completed,
            "ENZIMOS_INSTALL_PASS fixture",
            || Ok(())
        )
        .unwrap(),
        "ENZIMOS_INSTALL_PASS fixture"
    );

    for (path, value) in [
        (vec!["schema"], serde_json::json!(2)),
        (vec!["status"], serde_json::json!("pending")),
        (
            vec!["package_journal", "phase"],
            serde_json::json!("uncertain"),
        ),
        (vec!["package_journal", "exit_code"], serde_json::json!(1)),
        (vec!["finish_requested"], serde_json::json!(true)),
        (
            vec!["finish_receipt"],
            serde_json::json!({"phase":"accepted"}),
        ),
    ] {
        let mut altered = completed.clone();
        let mut member = &mut altered;
        for key in path {
            member = &mut member[key];
        }
        *member = value;
        assert!(validate_completion(&altered).is_err());
    }
    assert!(validate_completion(&serde_json::json!({})).is_err());
    // The UI recognizes these stage markers.
    assert!(stage_line(Stage::Disk).starts_with("==> "));
    assert!(stage_line(Stage::Disk).contains("creating the enzimOS layout"));
    assert!(stage_line(Stage::Packages).contains("installing the offline package set"));
}
