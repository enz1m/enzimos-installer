// SPDX-License-Identifier: MIT
//! The initial installer uses the same content-addressed owner UKI contract as updates.
use crate::{install_boot_files as artifacts, media_packages::Admitted, package_handoff::Received};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{path::Path, time::Duration};
pub(crate) const LOADERS: [&str; 4] = [
    "boot/EFI/systemd/systemd-bootx64.efi",
    "boot/EFI/BOOT/BOOTX64.EFI",
    "boot/EFI/enzimos/refind_x64.efi",
    "boot/EFI/enzimos/select-entry.efi",
];
pub(crate) fn prepare(context: &Received, media: &Admitted, options: &str) -> Result<Vec<String>> {
    let source = context
        .answers
        .as_ref()
        .ok_or_else(|| Error("boot original answers absent".into()))?;
    source.boot_security.install(&context.target)?;
    let owner = files::directory_relative(
        &context.target,
        Path::new("var/lib/enzimos-control/secure-boot"),
        Some(0),
    )?;
    let certificate = files::read_file(
        &files::open_relative(&owner, Path::new("owner.crt"))?,
        16384,
        Some(0),
        true,
    )?;
    let mut names = Vec::new();
    let mut loader_receipts = serde_json::Map::new();
    for name in LOADERS {
        context.recheck()?;
        let before = artifacts::measure(&context.target, name)?;
        let absolute = format!("/{name}");
        crate::install_config_tools::run_timeout(
            context,
            media,
            "/usr/lib/enzimos-native/enzimos-policy",
            &["secure-boot", "sign", "--source", &absolute],
            &[],
            Duration::from_secs(600),
        )?;
        let after = artifacts::measure(&context.target, name)?;
        loader_receipts.insert(
            name.strip_prefix("boot/").unwrap().into(),
            value!({"source":before["sha256"],"signed":after["sha256"]}),
        );
        names.push(name.into());
    }
    artifacts::text(
        &context.target,
        "var/lib/enzimos-control/secure-boot/loaders.json",
        &json::canonical(&Value::Object(loader_receipts))?,
        false,
    )?;
    names.push("var/lib/enzimos-control/secure-boot/loaders.json".into());
    let directory = files::ensure_directory_relative(
        &context.target,
        Path::new("boot/enzimos/secure-boot"),
        0o755,
        0,
    )?;
    let boot = files::directory_relative(&context.target, Path::new("boot"), Some(0))?;
    use std::os::fd::AsFd;
    require(
        enzimos_platform::mount_identity::id(directory.as_fd(), true)?
            == enzimos_platform::mount_identity::id(boot.as_fd(), true)?,
        "initial owner UKI destination cannot cross another mount",
    )?;
    for flavor in ["linux", "linux-lts"] {
        let kernel = artifacts::measure(&context.target, &format!("boot/vmlinuz-{flavor}"))?;
        let initrd = artifacts::measure(&context.target, &format!("boot/initramfs-{flavor}.img"))?;
        let digest = enzimos_policy::signed_entry::digest(
            kernel["sha256"].as_str().unwrap(),
            initrd["sha256"].as_str().unwrap(),
            options,
            &json::sha256(&certificate),
        )?;
        let relative = format!("/enzimos/secure-boot/{digest}.efi");
        let destination = format!("/boot{relative}");
        let linux = format!("/boot/vmlinuz-{flavor}");
        let ramdisk = format!("/boot/initramfs-{flavor}.img");
        crate::install_config_tools::run_timeout(
            context,
            media,
            "/usr/lib/enzimos-native/enzimos-policy",
            &[
                "secure-boot",
                "build-uki",
                "--kernel",
                &linux,
                "--initrd",
                &ramdisk,
                "--options",
                options,
                "--destination",
                &destination,
            ],
            &[],
            Duration::from_secs(900),
        )?;
        let output_name = format!("boot{relative}");
        let uki = files::read_file(
            &files::open_relative(
                &files::directory_relative(
                    &context.target,
                    Path::new("boot/enzimos/secure-boot"),
                    Some(0),
                )?,
                Path::new(&format!("{digest}.efi")),
            )?,
            128 * 1024 * 1024,
            Some(0),
            true,
        )?;
        enzimos_policy::secure_artifacts::verify_payload(
            &uki,
            kernel["sha256"].as_str().unwrap(),
            initrd["sha256"].as_str().unwrap(),
            options,
        )?;
        let name = format!("boot/loader/entries/{flavor}.conf");
        let entries =
            files::directory_relative(&context.target, Path::new("boot/loader/entries"), Some(0))?;
        let text = String::from_utf8(files::read_file(
            &files::open_relative(&entries, Path::new(&format!("{flavor}.conf")))?,
            65536,
            Some(0),
            true,
        )?)
        .map_err(|_| Error("initial signed entry encoding".into()))?;
        let rendered = enzimos_policy::signed_entry::rewrite(&text, &relative)?;
        artifacts::text(&context.target, &name, rendered.as_bytes(), true)?;
        names.push(output_name);
    }
    // The selected entries and every authenticated image precede policy activation.
    artifacts::text(
        &context.target,
        "var/lib/enzimos-control/secure-boot/config.json",
        &json::canonical(&value!({"schema":1,"mode":"owner-uki"}))?,
        false,
    )?;
    names.push("var/lib/enzimos-control/secure-boot/config.json".into());
    crate::install_config_tools::run(
        context,
        media,
        "/usr/bin/systemctl",
        &["--root", "/", "mask", "systemd-boot-update.service"],
        &[],
    )?;
    context.recheck()?;
    require(
        source.boot_security.receipt()? == context.request["boot"]["security"],
        "original signing authority changed before initial publication",
    )?;
    Ok(names)
}
