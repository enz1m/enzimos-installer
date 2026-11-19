// SPDX-License-Identifier: MIT
//! Bind the firmware hard-drive node to the mounted ESP and original physical disk.
use crate::{media_packages::Admitted, package_handoff::Received};
use enzimos_platform::{Error, Result, files, process, require};
use enzimos_policy::{block, storage_runtime, topology};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::fd::{AsFd, AsRawFd, FromRawFd},
    path::Path,
    time::Duration,
};
fn decimal(path: &Path) -> Result<u64> {
    let bytes = files::read_kernel(path, 128)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error("kernel ESP scalar encoding".into()))?;
    require(
        text.trim().bytes().all(|b| b.is_ascii_digit()),
        "kernel ESP scalar type",
    )?;
    text.trim()
        .parse()
        .map_err(|_| Error("kernel ESP scalar overflow".into()))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
pub(crate) fn observe(context: &Received, media: &Admitted) -> Result<Value> {
    context.recheck()?;
    media.recheck()?;
    crate::install_config_identity::verify(context, media)?;
    let rows = storage_runtime::rows()?;
    let matches = rows
        .iter()
        .filter(|r| r.target == "/mnt/enzimos/boot" && r.filesystem == "vfat")
        .collect::<Vec<_>>();
    require(matches.len() == 1, "original ESP mount required")?;
    let row = matches[0];
    let node = topology::kernel_node((row.major, row.minor))?;
    let event = String::from_utf8(files::read_kernel(&node.path.join("uevent"), 65536)?)
        .map_err(|_| Error("kernel ESP event encoding".into()))?;
    let names = event
        .lines()
        .filter_map(|l| l.strip_prefix("DEVNAME="))
        .collect::<Vec<_>>();
    require(
        names.len() == 1
            && !names[0].is_empty()
            && names[0]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "canonical ESP device name required",
    )?;
    let devices = files::directory(Path::new("/dev"), Some(0))?;
    let name = std::ffi::CString::new(names[0]).unwrap();
    let raw = unsafe {
        libc::openat(
            devices.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(raw >= 0, "original ESP device unavailable")?;
    let device = unsafe { File::from_raw_fd(raw) };
    let identity = files::identity(&device.metadata()?);
    let info = block::observe(device.as_fd())?;
    let graph = topology::observe(&[(row.major, row.minor)])?;
    let disk = &context.request["boot"]["disk"]["block"];
    require(
        info["major"] == row.major
            && info["minor"] == row.minor
            && graph.leaves
                == std::collections::BTreeSet::from([(
                    disk["major"].as_u64().unwrap() as u32,
                    disk["minor"].as_u64().unwrap() as u32,
                )]),
        "EFI ESP differs from original installation disk",
    )?;
    let leaf = graph
        .nodes
        .get(graph.leaves.iter().next().unwrap())
        .unwrap();
    let sector = decimal(&leaf.path.join("queue/logical_block_size"))?;
    require(
        matches!(sector, 512 | 4096),
        "EFI original disk logical sector bound",
    )?;
    let offset = decimal(&node.path.join("start"))?
        .checked_mul(512)
        .ok_or_else(|| Error("EFI partition offset overflow".into()))?;
    let size = decimal(&node.path.join("size"))?
        .checked_mul(512)
        .ok_or_else(|| Error("EFI partition size overflow".into()))?;
    require(
        offset % sector == 0 && size % sector == 0,
        "EFI partition sector alignment",
    )?;
    let number = decimal(&node.path.join("partition"))?;
    let probe = process::run_pinned(
        "/usr/bin/blkid",
        media.images.get("/usr/bin/blkid")?,
        &["--probe", "--output", "export", "@fd:0"],
        &[],
        Duration::from_secs(30),
        65536,
        &[device.as_fd()],
    )?;
    require(probe.status.success(), "EFI GPT identity probe failed")?;
    let text = std::str::from_utf8(&probe.stdout)
        .map_err(|_| Error("EFI GPT identity encoding".into()))?;
    let values = text
        .lines()
        .filter_map(|s| s.strip_prefix("PART_ENTRY_UUID="))
        .collect::<Vec<_>>();
    require(
        values.len() == 1
            && text
                .lines()
                .filter(|s| *s == "PART_ENTRY_SCHEME=gpt")
                .count()
                == 1,
        "EFI GPT UUID absent or ambiguous",
    )?;
    enzimos_policy::identity::uuid(values[0])?;
    require(
        block::observe(device.as_fd())? == info
            && files::identity(&device.metadata()?) == identity
            && storage_runtime::rows()? == rows,
        "EFI source changed during GPT probe",
    )?;
    context.recheck()?;
    media.recheck()?;
    Ok(
        value!({"partition":number,"offset":offset/sector,"size":size/sector,"uuid":values[0],"loader":"\\EFI\\enzimos\\refind_x64.efi","label":"enzimOS"}),
    )
}
