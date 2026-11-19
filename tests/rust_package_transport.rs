// SPDX-License-Identifier: MIT
use enzimos_installer::{package_body, package_client, package_handoff, package_watch};
use enzimos_platform::fd_packet::{Credentials, Packet};
use serde_json::json;
use std::os::unix::fs::MetadataExt;
use std::{
    os::fd::{AsFd, AsRawFd, FromRawFd},
    time::Duration,
};
const ID: &str = "11111111111111111111111111111111";
#[test]
fn boot_frame_binds_optional_owner_directory_to_exact_version_and_count() {
    let root = Credentials {
        pid: 123,
        uid: 0,
        gid: 0,
    };
    for (schema, owner, count) in [(3, false, 8), (3, true, 9), (4, false, 9), (4, true, 10)] {
        let good = json!({"schema":schema,"id":ID,"request_sha256":"a".repeat(64),"owner_credentials":owner,"original_fds":(3..3+count).collect::<Vec<_>>()});
        assert_eq!(
            package_handoff::frame(&good, &root, ID).unwrap().len(),
            count as usize
        );
        for flag in [json!(!owner), json!(null), json!("true"), json!(1)] {
            let mut bad = good.clone();
            bad["owner_credentials"] = flag;
            assert!(package_handoff::frame(&bad, &root, ID).is_err());
        }
        let mut old = good.clone();
        old["schema"] = json!(2);
        assert!(package_handoff::frame(&old, &root, ID).is_err());
        let mut duplicate = good;
        duplicate["original_fds"][count as usize - 1] = json!(3);
        assert!(package_handoff::frame(&duplicate, &root, ID).is_err());
    }
}
#[test]
fn package_frames_bind_kernel_sender_and_distinct_original_descriptors() {
    let root = Credentials {
        pid: 123,
        uid: 0,
        gid: 0,
    };
    let frame =
        json!({"schema":1,"id":ID,"request_sha256":"a".repeat(64),"original_fds":[3,4,5,6,7,8]});
    assert_eq!(
        package_handoff::frame(&frame, &root, ID).unwrap(),
        vec![3, 4, 5, 6, 7, 8]
    );
    for sender in [
        Credentials {
            pid: 123,
            uid: 1000,
            gid: 0,
        },
        Credentials {
            pid: 123,
            uid: 0,
            gid: 1000,
        },
    ] {
        assert!(package_handoff::frame(&frame, &sender, ID).is_err());
    }
    let mut duplicate = frame;
    duplicate["original_fds"] = json!([3, 4, 5, 6, 7, 7]);
    assert!(package_handoff::frame(&duplicate, &root, ID).is_err());
    let checkpoint =
        json!({"schema":2,"id":ID,"kind":"checkpoint","journal_sha256":"b".repeat(64)});
    assert!(package_client::notification(&checkpoint, &root, ID, 123).is_ok());
    assert!(package_client::notification(&checkpoint, &root, ID, 124).is_err());
    let mut obsolete = checkpoint.clone();
    obsolete["schema"] = json!(1);
    assert!(package_client::notification(&obsolete, &root, ID, 123).is_err());
    let mut heartbeat = checkpoint;
    heartbeat["kind"] = json!("heartbeat");
    assert!(package_client::notification(&heartbeat, &root, ID, 123).is_err());
    heartbeat["journal_sha256"] = json!(null);
    assert!(package_client::notification(&heartbeat, &root, ID, 123).is_ok());
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (fstat).")]
fn real_unprivileged_handoff_refusal_closes_every_supplied_descriptor() {
    let (sender, receiver) = Packet::pair().unwrap();
    let file = tempfile::tempfile().unwrap();
    sender
        .send(b"{}", &[file.as_fd()], Duration::from_secs(1))
        .unwrap();
    let message = receiver.receive(32, 1, Duration::from_secs(1)).unwrap();
    let descriptor = message.files[0].as_raw_fd();
    let original = file.metadata().unwrap();
    assert!(package_handoff::Received::inspect(message, ID, &"a".repeat(32)).is_err());
    let mut current: libc::stat = unsafe { std::mem::zeroed() };
    let observed = unsafe { libc::fstat(descriptor, &mut current) };
    assert!(observed == -1 || (current.st_dev, current.st_ino) != (original.dev(), original.ino()));
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
fn caller_watch_ignores_legitimate_phase_acknowledgements_but_detects_peer_and_task_loss() {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Child(
        std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap(),
    );
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.0.id(), 0) };
    assert!(raw >= 0);
    let task = unsafe { std::fs::File::from_raw_fd(raw as i32) };
    let (caller, worker) = Packet::pair().unwrap();
    caller
        .send(b"phase-ack", &[], Duration::from_secs(1))
        .unwrap();
    assert!(!package_watch::ended(&[task.as_fd(), worker.as_fd()]).unwrap());
    drop(caller);
    assert!(package_watch::ended(&[task.as_fd(), worker.as_fd()]).unwrap());
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(package_watch::ended(&[task.as_fd()]).unwrap());
    assert!(package_watch::ended(&[]).is_err());
}
#[test]
fn offline_command_and_database_identity_refuse_fetches_flag_injection_and_ambiguous_records() {
    let args = package_body::arguments(&["a-1-x86_64.pkg.tar.zst".into()]).unwrap();
    assert!(args.contains(&"-U".into()));
    assert!(args.contains(&"--".into()));
    assert!(
        !args
            .iter()
            .any(|arg| arg == "-Syu" || arg.starts_with("https:"))
    );
    assert!(package_body::arguments(&["--config=evil.pkg.tar.zst".into()]).is_err());
    assert_eq!(
        package_body::installed_identity(b"%NAME%\na\n\n%VERSION%\n1\n\n").unwrap(),
        ("a".into(), "1".into())
    );
    for record in [
        b"%\nx\n".as_slice(),
        b"%NAME%\na\nb\n\n%VERSION%\n1\n\n",
        b"%NAME%\na\n\n%NAME%\nb\n\n%VERSION%\n1\n\n",
    ] {
        assert!(package_body::installed_identity(record).is_err());
    }
    assert!(package_body::output_clean(
        b"transaction completed without errors"
    ));
    assert!(!package_body::output_clean(
        b"error: command failed to execute correctly"
    ));
    assert!(!package_body::output_clean(b"mkinitcpio: ERROR: failed"));
}

#[test]
fn initial_transaction_bootstraps_verified_pacman_without_changing_selection() {
    let selected = vec![
        "fontconfig-2.18.3-2-x86_64.pkg.tar.zst".into(),
        "pacman-mirrorlist-20261001-1-any.pkg.tar.zst".into(),
        "pacman-7.1.0-2-x86_64.pkg.tar.zst".into(),
        "zlib-1.3.1-1-x86_64.pkg.tar.zst".into(),
    ];
    let ordinary = package_body::arguments(&selected).unwrap();
    let ordered = package_body::bootstrap_arguments(&selected, &selected[2]).unwrap();
    let offset = ordinary.len() - selected.len();
    assert_eq!(ordered[..offset], ordinary[..offset]);
    assert_eq!(ordered[offset], ordinary[offset + 2]);
    assert_eq!(ordered[offset + 1], ordinary[offset]);
    assert_eq!(ordered[offset + 2], ordinary[offset + 1]);
    assert_eq!(ordered[offset + 3], ordinary[offset + 3]);
    assert_eq!(selected[0], "fontconfig-2.18.3-2-x86_64.pkg.tar.zst");
    assert!(package_body::bootstrap_arguments(&selected, "absent.pkg.tar.zst").is_err());
    assert!(package_body::bootstrap_arguments(&[], "absent.pkg.tar.zst").is_err());
    assert!(
        package_body::bootstrap_arguments(
            &[selected[2].clone(), selected[2].clone()],
            &selected[2]
        )
        .is_err()
    );
    assert!(!package_body::output_clean(
        b".INSTALL: line 2: ((: < 0 : arithmetic syntax error: operand expected"
    ));
    assert!(package_body::output_clean(
        b"warning: directory permissions differ"
    ));
}

#[test]
fn installed_identity_accepts_makepkg_empty_url_but_never_empty_or_duplicate_identity() {
    assert_eq!(
        package_body::installed_identity(
            b"%NAME%\nenzimos-rust-installer\n\n%URL%\n\n\n%VERSION%\n0.2.0-1\n\n"
        )
        .unwrap(),
        ("enzimos-rust-installer".into(), "0.2.0-1".into())
    );
    for bytes in [
        b"%NAME%\n\n\n%VERSION%\n1\n".as_slice(),
        b"%NAME%\na\n\n%URL%\n\n\n%NAME%\nb\n\n%VERSION%\n1\n",
        b"%NAME%\na\n%VERSION%\n1\n",
    ] {
        assert!(package_body::installed_identity(bytes).is_err());
    }
}
