// SPDX-License-Identifier: MIT
//! Independently bind fstab/crypttab UUIDs to the mounted kernel device graph.
use crate::{media_packages::Admitted, package_handoff::Received};
use enzimos_platform::{Error, Result, files, process, require};
use enzimos_policy::{block, filesystem, storage_runtime, topology};
use std::{
    fs::File,
    os::fd::{AsFd, AsRawFd, FromRawFd},
    path::Path,
    time::Duration,
};
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
pub(crate) fn verify(context: &Received, media: &Admitted) -> Result<()> {
    context.recheck()?;
    media.recheck()?;
    let config = &context.request["configuration"];
    let source = context
        .answers
        .as_ref()
        .ok_or_else(|| Error("configuration original answer description missing".into()))?;
    require(
        source.answers.encrypted == !config["luks_uuid"].is_null(),
        "kernel encryption configuration differs from original answers",
    )?;
    let root = filesystem::observe(context.target.as_fd())?;
    require(
        root["filesystem_uuid"] == config["filesystem_uuid"],
        "configuration root UUID differs from retained kernel filesystem",
    )?;
    let graph = topology::mounted_btrfs(root["filesystem_uuid"].as_str().unwrap())?;
    let mut dm = Vec::new();
    for node in graph.nodes.values() {
        match std::fs::symlink_metadata(node.path.join("dm")) {
            Ok(m) => {
                require(m.is_dir(), "kernel device-mapper directory shape")?;
                let bytes = files::read_kernel(&node.path.join("dm/uuid"), 4096)?;
                let uuid = std::str::from_utf8(&bytes)
                    .map_err(|_| Error("kernel device-mapper UUID encoding".into()))?
                    .trim()
                    .to_owned();
                dm.push(uuid);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    encryption(&dm, config["luks_uuid"].as_str())?;
    let rows = storage_runtime::rows()?;
    let esp = rows
        .iter()
        .filter(|r| r.target == "/mnt/enzimos/boot")
        .collect::<Vec<_>>();
    require(
        esp.len() == 1 && esp[0].filesystem == "vfat",
        "configuration ESP kernel mount is missing or ambiguous",
    )?;
    let row = esp[0];
    let node = topology::kernel_node((row.major, row.minor))?;
    let uevent = files::read_kernel(&node.path.join("uevent"), 65536)?;
    let event =
        std::str::from_utf8(&uevent).map_err(|_| Error("kernel ESP device encoding".into()))?;
    let names = event
        .lines()
        .filter_map(|l| l.strip_prefix("DEVNAME="))
        .collect::<Vec<_>>();
    require(
        names.len() == 1
            && !names[0].is_empty()
            && names[0].len() <= 255
            && names[0]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "canonical kernel ESP device name",
    )?;
    let device_path = Path::new("/dev").join(names[0]);
    let path = device_path.as_path();
    require(
        path.parent() == Some(Path::new("/dev")),
        "canonical configuration ESP device required",
    )?;
    crate::answers::disk_path(path.to_str().unwrap())?;
    let devices = files::directory(Path::new("/dev"), Some(0))?;
    let name = std::ffi::CString::new(path.file_name().unwrap().as_encoded_bytes()).unwrap();
    let raw = unsafe {
        libc::openat(
            devices.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(raw >= 0, "configuration ESP device unavailable")?;
    let device = unsafe { File::from_raw_fd(raw) };
    let before = block::observe(device.as_fd())?;
    let identity = files::identity(&device.metadata()?);
    require(
        before["major"] == row.major
            && before["minor"] == row.minor
            && topology::observe(&[(row.major, row.minor)])?.leaves == graph.leaves,
        "configuration ESP source or physical disk differs",
    )?;
    let probe = process::run_pinned(
        "/usr/bin/blkid",
        media.images.get("/usr/bin/blkid")?,
        &["--probe", "--output", "export", "@fd:0"],
        &[],
        Duration::from_secs(30),
        65536,
        &[device.as_fd()],
    )?;
    require(
        probe.status.success()
            && crate::format::filesystem(&probe.stdout, "vfat")?["uuid"] == config["esp_uuid"]
            && block::observe(device.as_fd())? == before
            && files::identity(&device.metadata()?) == identity
            && storage_runtime::rows()? == rows,
        "configuration ESP UUID or retained kernel source changed",
    )?;
    context.recheck()?;
    media.recheck()
}
fn encryption(dm: &[String], luks: Option<&str>) -> Result<()> {
    if let Some(uuid) = luks {
        enzimos_policy::identity::uuid(uuid)?;
        let prefix = format!("CRYPT-LUKS2-{}-", uuid.replace('-', ""));
        require(
            dm.len() == 1 && dm[0].starts_with(&prefix) && dm[0].len() > prefix.len(),
            "installed root kernel LUKS identity differs",
        )
    } else {
        require(
            dm.is_empty(),
            "cleartext configuration cannot adopt a device-mapper root",
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encryption_configuration_requires_one_exact_kernel_luks2_identity() {
        let id = "11111111-1111-4111-8111-111111111111";
        let actual = format!(
            "CRYPT-LUKS2-{}-enzimos-install-crypt-fixture",
            id.replace('-', "")
        );
        encryption(std::slice::from_ref(&actual), Some(id)).unwrap();
        encryption(&[], None).unwrap();
        assert!(encryption(&[], Some(id)).is_err());
        assert!(encryption(std::slice::from_ref(&actual), None).is_err());
        assert!(encryption(&[actual.clone(), actual], Some(id)).is_err());
        assert!(
            encryption(
                &["CRYPT-LUKS1-11111111111141118111111111111111-name".into()],
                Some(id)
            )
            .is_err()
        );
    }
}
