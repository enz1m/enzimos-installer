// SPDX-License-Identifier: MIT
//! Durable boot intent and strict ordered publication, independent of package success.
use crate::{install_boot_files, package_handoff::Received, package_job as job};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{fs::File, path::Path};
pub(crate) const NAME: &str = "boot.json";
pub(crate) const MAX: usize = 2 * 1024 * 1024;
pub(crate) const STEPS: [&str; 8] = [
    "sources",
    "initramfs",
    "loaders",
    "entries",
    "signatures",
    "menus",
    "recovery",
    "firmware",
];
fn public_destination(name: &str) -> bool {
    if matches!(
        name,
        "etc/plymouth/plymouthd.conf"
            | "boot/vmlinuz-linux"
            | "boot/vmlinuz-linux-lts"
            | "boot/initramfs-linux.img"
            | "boot/initramfs-linux-lts.img"
            | "boot/loader/loader.conf"
            | "boot/loader/entries/linux.conf"
            | "boot/loader/entries/linux-lts.conf"
            | "boot/limine/limine.conf"
            | "boot/limine/limine-bios.sys"
            | "boot/EFI/systemd/systemd-bootx64.efi"
            | "boot/EFI/BOOT/BOOTX64.EFI"
            | "boot/EFI/enzimos/refind_x64.efi"
            | "boot/EFI/enzimos/select-entry.efi"
            | "boot/EFI/enzimos/background.png"
            | "boot/EFI/enzimos/refind.conf"
            | "boot/EFI/enzimos/recovery.conf"
            | "boot/EFI/enzimos/power.conf"
            | "etc/systemd/system/enzimos-recovery-image.service"
            | "var/lib/enzimos-control/secure-boot/config.json"
            | "var/lib/enzimos-control/secure-boot/loaders.json"
    ) {
        return true;
    }
    if let Some(icon) = name.strip_prefix("boot/EFI/enzimos/icons/") {
        return !icon.is_empty()
            && icon.len() <= 128
            && !matches!(icon, "." | "..")
            && icon
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    }
    name.strip_prefix("boot/enzimos/secure-boot/")
        .and_then(|s| s.strip_suffix(".efi"))
        .is_some_and(|s| enzimos_policy::identity::sha(s).is_ok())
}
pub(crate) fn validate(body: &Value, request: &Value, owner: &Value) -> Result<()> {
    job::request(request)?;
    json::fields(
        body,
        "schema id role phase request_sha256 owner security disk options kernels files steps firmware recovery_pending boot_complete installed_qualified",
    )?;
    require(
        request["operation"] == job::BOOT
            && body["schema"] == 1
            && body["id"] == request["id"]
            && body["role"] == "fresh-boot-installation"
            && matches!(body["phase"].as_str(), Some("writing" | "complete"))
            && body["request_sha256"] == json::fingerprint(request)?
            && body["owner"] == *owner
            && body["security"] == request["boot"]["security"]
            && body["disk"] == request["boot"]["disk"]
            && body["installed_qualified"] == false
            && body["boot_complete"] == (body["phase"] == "complete"),
        "boot receipt original ownership or qualification differs",
    )?;
    let options = body["options"]
        .as_str()
        .ok_or_else(|| Error("boot receipt options type".into()))?;
    crate::install_boot_plan::prepare(options, true)?;
    let steps = body["steps"]
        .as_array()
        .ok_or_else(|| Error("boot receipt ordered steps type".into()))?;
    require(
        steps.len() <= STEPS.len()
            && steps.iter().zip(STEPS).all(|(a, b)| a == b)
            && (body["phase"] != "complete" || steps.len() == STEPS.len()),
        "boot receipt step order or premature completion",
    )?;
    json::fields(&body["kernels"], "linux linux-lts")?;
    let mut releases = Vec::new();
    for flavor in ["linux", "linux-lts"] {
        let kernel = &body["kernels"][flavor];
        json::fields(kernel, "release pkgbase kernel")?;
        let release = kernel["release"]
            .as_str()
            .ok_or_else(|| Error("boot kernel release type".into()))?;
        enzimos_policy::identity::safe_id(release)?;
        require(release.len() <= 128, "boot kernel release bound")?;
        releases.push(release);
        for (field, leaf) in [("pkgbase", "pkgbase"), ("kernel", "vmlinuz")] {
            crate::install_boot_sources::validate(&kernel[field])?;
            require(
                kernel[field]["path"] == format!("usr/lib/modules/{release}/{leaf}"),
                "boot kernel source path differs from selected release",
            )?;
        }
    }
    require(
        releases[0] != releases[1],
        "dual kernel releases must be distinct",
    )?;
    let files = body["files"]
        .as_object()
        .ok_or_else(|| Error("boot receipt artifacts type".into()))?;
    require(files.len() <= 768, "boot receipt artifact count bound")?;
    for (name, artifact) in files {
        require(
            public_destination(name),
            "boot receipt artifact outside fixed public destinations",
        )?;
        crate::install_boot_sources::validate(artifact)?;
        require(
            artifact["path"] == *name,
            "boot receipt artifact key differs from bound path",
        )?;
    }
    if !body["firmware"].is_null() {
        require(
            body["security"]["firmware"]["uefi"] == true,
            "BIOS cannot publish EFI entry receipt",
        )?;
        crate::install_boot_firmware::validate(&body["firmware"])?;
    }
    if !body["recovery_pending"].is_null() {
        json::fields(&body["recovery_pending"], "mount inode")?;
        crate::private_file::validate_inode(&body["recovery_pending"]["inode"], 0o600, 1)?;
        require(
            body["recovery_pending"]["inode"][2] == 0
                && body["recovery_pending"]["mount"]
                    .as_u64()
                    .is_some_and(|n| n > 0),
            "first-boot recovery marker empty private binding",
        )?;
    }
    require(
        steps.len() < 7 || !body["recovery_pending"].is_null(),
        "completed recovery stage lacks its marker",
    )?;
    if body["phase"] == "complete" {
        for name in [
            "etc/plymouth/plymouthd.conf",
            "boot/vmlinuz-linux",
            "boot/vmlinuz-linux-lts",
            "boot/initramfs-linux.img",
            "boot/initramfs-linux-lts.img",
            "boot/loader/loader.conf",
            "boot/loader/entries/linux.conf",
            "boot/loader/entries/linux-lts.conf",
            "boot/limine/limine.conf",
            "boot/limine/limine-bios.sys",
            "boot/EFI/systemd/systemd-bootx64.efi",
            "boot/EFI/BOOT/BOOTX64.EFI",
            "etc/systemd/system/enzimos-recovery-image.service",
        ] {
            require(
                files.contains_key(name),
                "completed boot receipt is missing a mandatory artifact",
            )?;
        }
        if body["security"]["firmware"]["uefi"] == true {
            require(
                !body["firmware"]["entry"].is_null(),
                "UEFI boot completion requires exact firmware publication",
            )?;
            for name in [
                "boot/EFI/enzimos/refind_x64.efi",
                "boot/EFI/enzimos/select-entry.efi",
                "boot/EFI/enzimos/refind.conf",
                "boot/EFI/enzimos/recovery.conf",
                "boot/EFI/enzimos/power.conf",
            ] {
                require(
                    files.contains_key(name),
                    "completed UEFI boot receipt is incomplete",
                )?;
            }
        }
    }
    Ok(())
}
pub(crate) fn read(directory: &File) -> Result<Value> {
    json::decode(
        &files::read_file(
            &files::open_relative(directory, Path::new(NAME))?,
            MAX,
            Some(0),
            true,
        )?,
        MAX,
    )
}
pub(crate) fn record(context: &Received, body: &Value, replace: bool) -> Result<()> {
    context.recheck()?;
    validate(body, &context.request, &context.store.journal["owner"])?;
    files::atomic_relative(
        context.store.directory(),
        Path::new(NAME),
        &json::canonical(body)?,
        0o600,
        Some(0),
        replace,
        MAX,
    )?;
    require(
        read(context.store.directory())? == *body,
        "boot receipt readback differs",
    )?;
    context.recheck()
}
pub(crate) fn advance(
    context: &Received,
    body: &mut Value,
    step: &str,
    names: &[String],
) -> Result<()> {
    let index = body["steps"].as_array().unwrap().len();
    require(
        STEPS.get(index) == Some(&step),
        "boot body cannot skip or repeat a publication step",
    )?;
    for name in names {
        body["files"].as_object_mut().unwrap().insert(
            name.clone(),
            install_boot_files::measure(&context.target, name)?,
        );
    }
    body["steps"].as_array_mut().unwrap().push(value!(step));
    record(context, body, true)
}
