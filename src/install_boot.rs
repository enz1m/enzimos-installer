// SPDX-License-Identifier: MIT
//! Supervised dual-kernel boot installation; a partial intent is never resumed.
use crate::{
    install_boot_files as artifacts, install_boot_receipt as receipt,
    install_boot_sources as sources, media_packages::Admitted, package_handoff::Received,
    package_job as job,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::fd::{AsFd, AsRawFd},
    path::Path,
    time::Duration,
};

pub fn install(context: &Received, media: &Admitted, configured: Value) -> Result<Value> {
    context.recheck()?;
    media.recheck()?;
    require(
        context.request["operation"] == job::BOOT
            && configured["operation"] == job::BOOT
            && configured["exit_code"] == 0
            && configured["configuration"]["phase"] == "complete",
        "initial boot requires this original attempt's complete system configuration",
    )?;
    let source = context
        .answers
        .as_ref()
        .ok_or_else(|| Error("original boot answers absent".into()))?;
    crate::install_configuration::validate(
        &configured["configuration"],
        &context.request,
        &context.store.journal["owner"],
    )?;
    let plan = crate::install_boot_plan::prepare(
        configured["configuration"]["root_options"]
            .as_str()
            .unwrap(),
        source.answers.test_check,
    )?;
    crate::install_boot_loaders::empty_destinations(context)?;
    let policy = sources::Source::open(
        &context.target,
        Path::new("usr/lib/enzimos-native/enzimos-policy"),
        32 * 1024 * 1024,
    )?;
    require(
        files::read_file(&policy.file, 32 * 1024 * 1024, Some(0), true)?.starts_with(b"\x7fELF"),
        "boot and first-boot recovery require the installed native policy image",
    )?;
    let kernels = sources::kernels(&context.target)?;
    let mut body = value!({"schema":1,"id":context.request["id"],"role":"fresh-boot-installation","phase":"writing",
        "request_sha256":json::fingerprint(&context.request)?,"owner":context.store.journal["owner"],"security":context.request["boot"]["security"],"disk":context.request["boot"]["disk"],
        "options":plan.options,"kernels":kernels.iter().map(|(flavor,k)| (flavor,value!({"release":k.release,"pkgbase":k.pkgbase.receipt(),"kernel":k.kernel.receipt()}))).collect::<BTreeMap<_,_>>(),
        "files":{},"steps":[],"firmware":null,"recovery_pending":null,"boot_complete":false,"installed_qualified":false});
    receipt::record(context, &body, false)?;
    receipt::advance(context, &mut body, "sources", &[])?;
    let theme = crate::install_boot_theme::prepare(context)?;
    crate::install_config_tools::run_timeout(
        context,
        media,
        "/usr/bin/mkinitcpio",
        &["-P"],
        &[],
        Duration::from_secs(900),
    )?;
    let mut kernel_names = vec![theme];
    for (flavor, kernel) in &kernels {
        kernel.pkgbase.recheck(&context.target)?;
        artifacts::copy(
            &context.target,
            &kernel.kernel,
            &format!("boot/vmlinuz-{flavor}"),
            true,
        )?;
        let name = format!("boot/initramfs-{flavor}.img");
        artifacts::measure(&context.target, &name)?;
        kernel_names.extend([format!("boot/vmlinuz-{flavor}"), name]);
    }
    receipt::advance(context, &mut body, "initramfs", &kernel_names)?;
    let mut entries = Vec::new();
    for (name, bytes) in &plan.files {
        let destination = format!("boot/{name}");
        artifacts::text(&context.target, &destination, bytes, false)?;
        entries.push(destination);
    }
    let loaders = crate::install_boot_loaders::prepare(context, media)?;
    for (name, bytes) in &plan.files {
        require(
            artifacts::measure(&context.target, &format!("boot/{name}"))?["sha256"]
                == json::sha256(bytes),
            "loader tool changed the prepared initial entry",
        )?;
    }
    receipt::advance(context, &mut body, "loaders", &loaders)?;
    receipt::advance(context, &mut body, "entries", &entries)?;
    let signed = if body["security"]["firmware"]["enabled"] == true {
        crate::install_boot_secure::prepare(context, media, &plan.options)?
    } else {
        Vec::new()
    };
    let mut signed_names = signed;
    signed_names.extend(
        entries
            .iter()
            .filter(|n| n.starts_with("boot/loader/entries/"))
            .cloned(),
    );
    receipt::advance(context, &mut body, "signatures", &signed_names)?;
    let uefi = body["security"]["firmware"]["uefi"] == true;
    let mut menus = Vec::new();
    if uefi {
        for name in ["refind.conf", "recovery.conf", "power.conf"] {
            let dir =
                files::directory_relative(&context.target, Path::new("boot/EFI/enzimos"), Some(0))?;
            require(
                files::optional_relative(&dir, Path::new(name))?.is_none(),
                "preexisting graphical boot menu cannot be adopted",
            )?;
        }
        enzimos_policy::boot_menu::render(Path::new("/mnt/enzimos/boot"), false)?;
        menus.extend(
            ["refind.conf", "recovery.conf", "power.conf"].map(|s| format!("boot/EFI/enzimos/{s}")),
        );
        crate::install_config_tools::run(
            context,
            media,
            "/usr/bin/systemctl",
            &[
                "--root",
                "/",
                "enable",
                "enzimos-recovery-session-state.service",
                "enzimos-boot-menu.path",
            ],
            &[],
        )?;
    }
    receipt::advance(context, &mut body, "menus", &menus)?;
    let cmdline = String::from_utf8(files::read_kernel(Path::new("/proc/cmdline"), 65536)?)
        .map_err(|_| Error("live recovery options encoding".into()))?;
    let service = crate::system_config::recovery_service(
        &kernels["linux"].release,
        &cmdline,
        source.answers.test_check,
    )?;
    artifacts::text(
        &context.target,
        "etc/systemd/system/enzimos-recovery-image.service",
        service.as_bytes(),
        false,
    )?;
    let control = files::directory_relative(
        &context.target,
        Path::new("var/lib/enzimos-control"),
        Some(0),
    )?;
    files::atomic_relative(
        &control,
        Path::new("recovery-image-pending"),
        &[],
        0o600,
        Some(0),
        false,
        1,
    )?;
    body["recovery_pending"] = pending(&context.target)?;
    crate::install_config_tools::run(
        context,
        media,
        "/usr/bin/systemctl",
        &["--root", "/", "enable", "enzimos-recovery-image.service"],
        &[],
    )?;
    receipt::advance(
        context,
        &mut body,
        "recovery",
        &["etc/systemd/system/enzimos-recovery-image.service".into()],
    )?;
    if uefi {
        let partition = crate::install_boot_esp::observe(context, media)?;
        body["firmware"] = value!({"before":crate::install_boot_firmware::capture()?,"entry":null,"entry_sha256":null,"partition":partition});
        receipt::record(context, &body, true)?;
        let entry = crate::install_boot_firmware::registration(&body["firmware"]["before"])?;
        require(
            crate::install_boot_firmware::capture()? == body["firmware"]["before"],
            "firmware boot variables changed before entry publication",
        )?;
        let disk = context.boot_disk.as_ref().unwrap();
        let number = partition["partition"].as_u64().unwrap().to_string();
        crate::install_config_tools::run_descriptors(
            context,
            media,
            "/usr/bin/efibootmgr",
            &[
                "--create",
                "--bootnum",
                &entry,
                "--disk",
                "@fd:1",
                "--part",
                &number,
                "--label",
                "enzimOS",
                "--loader",
                "\\EFI\\enzimos\\refind_x64.efi",
            ],
            &[],
            Duration::from_secs(120),
            &[disk.as_fd()],
        )?;
        body["firmware"] =
            crate::install_boot_firmware::published(body["firmware"].clone(), &entry)?;
    }
    receipt::advance(context, &mut body, "firmware", &[])?;
    for kernel in kernels.values() {
        kernel.pkgbase.recheck(&context.target)?;
        kernel.kernel.recheck(&context.target)?;
    }
    policy.recheck(&context.target)?;
    verify(&context.target, &body)?;
    body["phase"] = value!("complete");
    body["boot_complete"] = value!(true);
    receipt::record(context, &body, true)?;
    Ok(
        value!({"schema":1,"operation":job::BOOT,"system":configured,"boot":body,"exit_code":0,"boot_complete":true,"installed_qualified":false}),
    )
}
fn pending(root: &File) -> Result<Value> {
    let dir = files::directory_relative(root, Path::new("var/lib/enzimos-control"), Some(0))?;
    let file = files::open_relative(&dir, Path::new("recovery-image-pending"))?;
    let inode = value!(files::identity(&file.metadata()?));
    crate::private_file::validate_inode(&inode, 0o600, 1)?;
    require(
        inode[2] == 0,
        "first-boot recovery marker must remain empty",
    )?;
    Ok(value!({"mount":enzimos_platform::mount_identity::id(file.as_fd(),true)?,"inode":inode}))
}
fn verify(root: &File, body: &Value) -> Result<()> {
    artifacts::verify(root, &body["files"])?;
    crate::install_boot_theme::verify(root)?;
    require(
        pending(root)? == body["recovery_pending"],
        "first-boot recovery marker replaced",
    )?;
    if !body["firmware"].is_null() {
        crate::install_boot_firmware::verify(&body["firmware"])?;
    }
    let wants = files::directory_relative(
        root,
        Path::new("etc/systemd/system/multi-user.target.wants"),
        Some(0),
    )?;
    require(
        std::fs::read_link(format!(
            "/proc/self/fd/{}/enzimos-recovery-image.service",
            wants.as_raw_fd()
        ))? == Path::new("/etc/systemd/system/enzimos-recovery-image.service"),
        "first-boot recovery unit not enabled from this target's exact service",
    )
}
pub(crate) fn completed(
    target: &crate::target_storage::Target<'_>,
    media: &Admitted,
    journal: &Value,
    directory: &File,
    configuration: &Value,
) -> Result<Value> {
    target.recheck()?;
    media.recheck()?;
    require(
        journal["phase"] == "stopping",
        "boot completion requires original stopped worker",
    )?;
    let body = receipt::read(directory)?;
    receipt::validate(&body, &journal["request"], &journal["owner"])?;
    require(
        body["phase"] == "complete" && body["options"] == configuration["root_options"],
        "unfinished boot intent is not replayed and options cannot change",
    )?;
    require(
        crate::install_boot_disk::observe(
            target.boot_disk()?,
            &target.source().answers.disk,
            journal["request"]["configuration"]["filesystem_uuid"]
                .as_str()
                .unwrap(),
        )? == body["disk"],
        "caller independently observed a different original boot disk",
    )?;
    let root = target.directory()?;
    let kernels = sources::kernels(root)?;
    for (flavor, kernel) in &kernels {
        require(
            body["kernels"][flavor]
                == value!({"release":kernel.release,"pkgbase":kernel.pkgbase.receipt(),"kernel":kernel.kernel.receipt()}),
            "caller kernel inventory differs from original worker sources",
        )?;
    }
    let plan = crate::install_boot_plan::prepare(
        body["options"].as_str().unwrap(),
        target.source().answers.test_check,
    )?;
    let certificate = target.source().boot_security.verify_installed()?;
    for (name, bytes) in &plan.files {
        let expected = if let Some(cert) = &certificate {
            if name.starts_with("loader/entries/") {
                let flavor = Path::new(name).file_stem().unwrap().to_str().unwrap();
                let kernel = body["files"][format!("boot/vmlinuz-{flavor}")]["sha256"]
                    .as_str()
                    .unwrap();
                let initrd = body["files"][format!("boot/initramfs-{flavor}.img")]["sha256"]
                    .as_str()
                    .unwrap();
                let digest =
                    enzimos_policy::signed_entry::digest(kernel, initrd, &plan.options, cert)?;
                enzimos_policy::signed_entry::rewrite(
                    std::str::from_utf8(bytes).unwrap(),
                    &format!("/enzimos/secure-boot/{digest}.efi"),
                )?
                .into_bytes()
            } else {
                bytes.clone()
            }
        } else {
            bytes.clone()
        };
        crate::install_boot_verify::text(root, &format!("boot/{name}"), &expected)?;
    }
    let cmdline = String::from_utf8(files::read_kernel(Path::new("/proc/cmdline"), 65536)?)
        .map_err(|_| Error("caller live command line encoding".into()))?;
    let service = crate::system_config::recovery_service(
        &kernels["linux"].release,
        &cmdline,
        target.source().answers.test_check,
    )?;
    crate::install_boot_verify::text(
        root,
        "etc/systemd/system/enzimos-recovery-image.service",
        service.as_bytes(),
    )?;
    if body["security"]["firmware"]["uefi"] == true {
        for (name, bytes) in
            enzimos_policy::boot_menu::material(Path::new("/mnt/enzimos/boot"), false)?
        {
            crate::install_boot_verify::text(root, &format!("boot/EFI/enzimos/{name}"), &bytes)?;
        }
    }
    if let Some(certificate) = certificate {
        crate::install_boot_verify::signatures(root, media, &body, &certificate)?;
    }
    verify(root, &body)?;
    target.recheck()?;
    media.recheck()?;
    Ok(body)
}
