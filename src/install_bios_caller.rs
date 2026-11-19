// SPDX-License-Identifier: MIT
//! BIOS sectors are written by the original caller after worker cgroup closure.
//! Durable records bind this one attempt; only retained kernel objects grant a write.
use crate::{
    bios_write_record as evidence, install_boot_sources::Source, media_packages::Admitted,
    package_job, target_storage::Target,
};
use enzimos_platform::{Result, files, json, process, require, stream_copy};
use enzimos_system_backend::native_worker_manager::Owner;
use serde_json::{Value, json as value};
use std::{fs::File, os::fd::AsFd, path::Path, time::Duration};
const NAME: &str = "bios-write.json";

pub(crate) fn install(
    target: &Target<'_>,
    media: &Admitted,
    journal: &Value,
    directory: &File,
    owner: &Owner,
) -> Result<()> {
    target.recheck()?;
    media.recheck()?;
    require(
        journal["phase"] == "stopping"
            && journal["request"]["operation"] == package_job::BOOT
            && owner.exited_and_empty()?,
        "BIOS caller requires the original stopped and empty worker",
    )?;
    if target.source().answers.partition != crate::answers::Partition::Erase {
        return Ok(());
    }
    let request = &journal["request"];
    let caller = crate::package_handoff::actor(&request["caller"], package_job::CALLER)?;
    require(
        caller.stat.pid == std::process::id(),
        "BIOS execution requires original caller",
    )?;
    let root = target.directory()?;
    let disk = target.boot_disk()?;
    let vendor = Source::open(root, Path::new("usr/bin/limine"), 32 * 1024 * 1024)?;
    require(
        files::read_file(&vendor.file, 32 * 1024 * 1024, Some(0), true)?.starts_with(b"\x7fELF"),
        "BIOS requires protected installed vendor ELF",
    )?;
    let before = crate::install_boot_disk::observe(
        disk,
        &target.source().answers.disk,
        request["configuration"]["filesystem_uuid"]
            .as_str()
            .unwrap(),
    )?;
    require(
        before == request["boot"]["disk"],
        "BIOS caller original disk changed before intent",
    )?;
    let mut body = value!({"schema":1,"id":request["id"],"role":evidence::ROLE,"phase":"writing",
        "request_sha256":json::fingerprint(request)?,"owner":journal["owner"],"vendor":vendor.receipt(),
        "arguments":["bios-install","@fd:1","1"],"before_disk":before,"after_disk":null,
        "vendor_exit":null,"device_events_settled":false,"worker_closed":false,"installed_qualified":false});
    evidence::validate(&body, request, &journal["owner"], &vendor.receipt())?;
    let intent = files::atomic_relative_retained(
        directory,
        Path::new(NAME),
        &json::canonical(&body)?,
        0o600,
        Some(0),
        false,
        evidence::MAX,
    )?;
    // No reset, drop retry or journal-derived authority exists after reservation.
    let write = target.begin_bios_write()?;
    let mut checkpoint = || {
        caller.recheck()?;
        require(
            owner.exited_and_empty()?,
            "original worker cgroup repopulated during BIOS write",
        )?;
        media.recheck()?;
        vendor.recheck(root)?;
        require(
            stream_copy::hash_borrowed(&vendor.file, 32 * 1024 * 1024, Some(0))?.1 == vendor.sha,
            "original BIOS executable bytes changed",
        )?;
        target.bios_checkpoint(&write)
    };
    let result = process::run_pinned_with_checkpoint(
        "/usr/bin/chroot",
        media.images.get("/usr/bin/chroot")?,
        &["@fd-dir:0", "@fd:2", "bios-install", "@fd:1", "1"],
        &[],
        Duration::from_secs(120),
        1024 * 1024,
        &[root.as_fd(), disk, vendor.file.as_fd()],
        &mut checkpoint,
    )?;
    require(
        result.status.success(),
        "BIOS vendor failed; original write intent retained without replay",
    )?;
    target.observe_bios_write(write.settle()?)?;
    caller.recheck()?;
    require(
        owner.exited_and_empty()?,
        "original worker cgroup not empty after BIOS write",
    )?;
    media.recheck()?;
    vendor.recheck(root)?;
    body["phase"] = value!("data-write-observed");
    body["vendor_exit"] = value!(0);
    body["device_events_settled"] = value!(true);
    body["after_disk"] = crate::install_boot_disk::observe(
        target.boot_disk()?,
        &target.source().answers.disk,
        request["configuration"]["filesystem_uuid"]
            .as_str()
            .unwrap(),
    )?;
    evidence::validate(&body, request, &journal["owner"], &vendor.receipt())?;
    let receipt = files::atomic_replace_original(
        directory,
        Path::new(NAME),
        &json::canonical(&body)?,
        0o600,
        Some(0),
        evidence::MAX,
        &intent,
    )?;
    require(
        files::read_file(&receipt, evidence::MAX, Some(0), true)? == json::canonical(&body)?,
        "BIOS observation durable readback changed",
    )?;
    target.recheck()
}
