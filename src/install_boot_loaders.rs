// SPDX-License-Identifier: MIT
//! Loader writes remain descendants of the original supervised storage owner.
use crate::{
    install_boot_files as artifacts, install_boot_sources::Source, media_packages::Admitted,
    package_handoff::Received,
};
use enzimos_platform::{Result, files, require};
use std::path::Path;

pub(crate) fn prepare(context: &Received, media: &Admitted) -> Result<Vec<String>> {
    context.recheck()?;
    let uefi = context.request["boot"]["security"]["firmware"]["uefi"] == true;
    // Variables are published in a separate, durably recorded step after signatures.
    crate::install_config_tools::run(
        context,
        media,
        "/usr/bin/bootctl",
        &["--esp-path=/boot", "--no-variables", "install"],
        &[],
    )?;
    let mut names: Vec<String> = vec![
        "boot/EFI/systemd/systemd-bootx64.efi".into(),
        "boot/EFI/BOOT/BOOTX64.EFI".into(),
    ];
    for destination in &names {
        let expected = Source::open(
            &context.target,
            Path::new("usr/lib/systemd/boot/efi/systemd-bootx64.efi"),
            16 * 1024 * 1024,
        )?;
        let installed = artifacts::measure(&context.target, destination)?;
        require(
            installed["sha256"] == expected.sha && installed["bytes"] == expected.bytes,
            "bootctl installed unexpected loader bytes",
        )?;
        expected.recheck(&context.target)?;
    }
    let source = Source::open(
        &context.target,
        Path::new("usr/share/limine/limine-bios.sys"),
        16 * 1024 * 1024,
    )?;
    artifacts::copy(
        &context.target,
        &source,
        "boot/limine/limine-bios.sys",
        false,
    )?;
    names.push("boot/limine/limine-bios.sys".into());
    // The caller installs BIOS sectors after this worker's cgroup has closed.
    // A worker may not independently advance the caller's retained disk epoch.
    if uefi {
        for (source, destination) in [
            (
                "usr/share/refind/refind_x64.efi",
                "boot/EFI/enzimos/refind_x64.efi",
            ),
            (
                "usr/share/enzimos-boot/select-entry.efi",
                "boot/EFI/enzimos/select-entry.efi",
            ),
            (
                "usr/share/enzimos-boot/background.png",
                "boot/EFI/enzimos/background.png",
            ),
        ] {
            let source = Source::open(&context.target, Path::new(source), 16 * 1024 * 1024)?;
            artifacts::copy(&context.target, &source, destination, false)?;
            names.push(destination.into());
        }
        names.extend(artifacts::icons(&context.target)?);
    }
    context.recheck()?;
    Ok(names)
}
pub(crate) fn empty_destinations(context: &Received) -> Result<()> {
    // A format receipt does not authorize replacing a loader planted afterward.
    let boot = files::directory_relative(&context.target, Path::new("boot"), Some(0))?;
    for name in ["loader", "limine", "EFI", "enzimos"] {
        require(
            files::optional_relative(&boot, Path::new(name))?.is_none(),
            "preexisting boot state requires review; boot installation cannot be replayed",
        )?;
    }
    Ok(())
}
