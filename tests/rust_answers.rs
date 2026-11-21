// SPDX-License-Identifier: MIT
use enzimos_installer::{
    answers::{self, Answers},
    system_config as config,
};
use std::{
    io::Write,
    process::{Command, Stdio},
};
const BASE: &str = "ENZIMOS_DISK=/dev/vda\nENZIMOS_ERASE_CONFIRM=yes\nENZIMOS_USER=admin\nENZIMOS_PASSWORD=fixture-user-secret\nENZIMOS_PASSPHRASE=fixture-disk-secret\n";
fn answer(body: &str) -> enzimos_platform::Result<Answers> {
    Answers::from_values(answers::parse(body.as_bytes())?)
}
#[test]
fn typed_answers_refuse_overwrites_injection_and_conflicting_installation_choices() {
    let a = answer(BASE).unwrap();
    let review = a.review().to_string();
    assert!(
        !review.contains("fixture-user-secret")
            && !review.contains("fixture-disk-secret")
            && !review.contains("PASSWORD")
    );
    assert_eq!(a.password.as_str(), "fixture-user-secret");
    for extra in [
        "ENZIMOS_USER=other\n",
        "FOREIGN_KEY=yes\n",
        "ENZIMOS_FULLNAME=Admin:root\n",
        "ENZIMOS_HOSTNAME=host;reboot\n",
        "ENZIMOS_TIMEZONE=../etc\n",
        "ENZIMOS_SWAP_MIB=000256\n",
        "ENZIMOS_PARTITION_MODE=alongside\n",
        "ENZIMOS_ENCRYPT=no\n",
    ] {
        assert!(
            answer(&format!("{BASE}{extra}")).is_err(),
            "accepted {extra:?}"
        );
    }
    assert!(answer(&BASE.replace("/dev/vda", "/dev/../host")).is_err());
    assert!(answer(&BASE.replace("admin", "root")).is_err());
    assert!(answers::parse(&[b'x'; answers::MAX_FILE + 1]).is_err());
}
#[test]
fn generated_storage_and_boot_configuration_preserve_independent_roles_and_encryption() {
    let a = answer(&format!("{BASE}ENZIMOS_TEST_CHECK=1\n")).unwrap();
    let fs = "00000000-0000-0000-0000-000000000001";
    let luks = "00000000-0000-0000-0000-000000000002";
    let result = config::render(
        &a,
        fs,
        "A123-B456",
        Some(luks),
        "console=ttyS0,115200n8 quiet",
    )
    .unwrap();
    assert_eq!(
        result.files["etc/tmpfiles.d/enzimos-backup-source.conf"],
        b"d /backup-source 0700 root root -\n"
    );
    let storage: serde_json::Value =
        serde_json::from_slice(&result.files["etc/enzimos/storage.json"]).unwrap();
    enzimos_policy::storage::validate(&storage).unwrap();
    let fstab = String::from_utf8(result.files["etc/fstab"].clone()).unwrap();
    for role in ["root", "home", "control", "authority", "swap"] {
        assert!(fstab.contains(&format!("subvol=enzimos-{role},")));
    }
    assert!(
        result
            .root_options
            .contains(&format!("rd.luks.name={luks}=enzimos-crypt"))
    );
    assert!(result.root_options.contains("console=ttyS0,115200n8"));
    assert!(result.hooks.contains("sd-encrypt"));
    assert!(config::render(&a, fs, "A123-B456", None, "").is_err());
    let unencrypted = answer(&BASE.replace(
        "ENZIMOS_PASSPHRASE=fixture-disk-secret\n",
        "ENZIMOS_ENCRYPT=no\n",
    ))
    .unwrap();
    let result =
        config::render(&unencrypted, fs, "A123-B456", None, "console=foreign$value").unwrap();
    assert!(!result.files.contains_key("etc/crypttab") && !result.hooks.contains("sd-encrypt"));
    assert!(!result.root_options.contains("console="));
}
#[test]
fn config_edits_refuse_duplicate_authority_and_native_firstboot_options_are_literal() {
    assert_eq!(
        config::locale_gen("#en_US.UTF-8 UTF-8\n#other\n", "en_US.UTF-8").unwrap(),
        "en_US.UTF-8 UTF-8\n#other\n"
    );
    assert!(config::locale_gen("en_US.UTF-8 UTF-8\n#en_US.UTF-8 UTF-8\n", "en_US.UTF-8").is_err());
    assert!(config::locale_gen("", "en_US.UTF-8\nroot").is_err());
    assert!(config::mkinitcpio("HOOKS=(base)\nHOOKS=(systemd)\n", "base systemd").is_err());
    assert!(config::mkinitcpio("HOOKS=(base)\n", "base $(foreign)").is_err());
    let input = "MODULES=(btrfs)\nHOOKS=(base)\n";
    let hooks = "base systemd autodetect keyboard block sd-encrypt filesystems";
    let encrypted = config::mkinitcpio(input, hooks).unwrap();
    assert!(encrypted.contains("MODULES=(btrfs)"));
    let surface = encrypted
        .lines()
        .find(|line| line.starts_with("MODULES+=("))
        .unwrap();
    assert!(
        surface.contains("8250_dw")
            && surface.contains("surface_aggregator")
            && surface.contains("surface_kbd")
    );
    assert_eq!(config::mkinitcpio(&encrypted, hooks).unwrap(), encrypted);
    assert_eq!(
        config::mkinitcpio(input, "base systemd").unwrap(),
        "MODULES=(btrfs)\nHOOKS=(base systemd)\n"
    );
    assert!(config::consoles("console=ttyS0,115200 console=ttyS0,115200", true).is_err());
    assert!(config::recovery_service("6.18.%n", "", false).is_err());
    assert!(config::recovery_service("6.18.1", "console=ttyS0\"", true).is_err());
    let service = config::recovery_service("6.18.1", "console=ttyS0,115200n8", true).unwrap();
    assert!(service.contains("ExecStart=/usr/lib/enzimos-native/enzimos-policy recovery-image first-boot --kernel 6.18.1 --options \"console=ttyS0,115200n8 systemd.log_color=no"));
    assert!(!service.contains("python"));
    assert_eq!(config::swap_size(None, 512 * 1024).unwrap(), 1024);
    assert_eq!(config::swap_size(None, 32 * 1024 * 1024).unwrap(), 8192);
    assert!(config::swap_size(Some(128), 1024).is_err());
}
#[test]
fn native_answer_review_cli_never_returns_passwords() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_enzimos-installer"))
        .arg("validate-answers")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(BASE.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let review: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(review["username"], "admin");
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("fixture")
    );
}
