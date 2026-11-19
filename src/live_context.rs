// SPDX-License-Identifier: MIT
//! Installer role comes from the real live boot layout, never a marker alone.
use enzimos_platform::{Error, Result, files, mount_identity, mountinfo, require};
use enzimos_policy::{namespaces, storage_runtime};
use std::{
    os::fd::{AsFd, AsRawFd},
    path::Path,
};
const LAYOUT: &[(&str, &str, libc::c_long, &str)] = &[
    ("/", "overlay", 0x794c7630, "rw"),
    ("/run/enzimos-live/lower", "squashfs", 0x73717368, "ro"),
    ("/run/enzimos-live/rw", "tmpfs", 0x01021994, "rw"),
    ("/run/enzimos-live/media", "iso9660", 0x9660, "ro"),
];
pub fn validate(rows: &[mountinfo::Row], cmdline: &str) -> Result<()> {
    require(
        cmdline.len() <= 65536
            && !cmdline.contains('\0')
            && cmdline
                .split_whitespace()
                .filter(|s| *s == "rd.systemd.wants=enzimos-live-root.service")
                .count()
                == 1
            && !cmdline
                .split_whitespace()
                .any(|s| s.starts_with("enzimos.installer-rescue=")),
        "actual live installer kernel role required",
    )?;
    for (path, kind, _, access) in LAYOUT {
        let found = rows
            .iter()
            .filter(|r| r.target == *path)
            .collect::<Vec<_>>();
        require(
            found.len() == 1
                && found[0].filesystem == *kind
                && found[0].root == "/"
                && found[0].options.split(',').any(|s| s == *access)
                && !found[0]
                    .options
                    .split(',')
                    .any(|s| s == if *access == "ro" { "rw" } else { "ro" }),
            "live installer mount layout changed",
        )?;
        if *kind == "iso9660" {
            require(
                ["nodev", "nosuid"]
                    .iter()
                    .all(|option| found[0].options.split(',').any(|s| s == *option)),
                "live install medium mount protections changed",
            )?;
        }
    }
    Ok(())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
pub(crate) fn observe() -> Result<()> {
    namespaces::initial()?;
    let cmdline = files::read_kernel(Path::new("/proc/cmdline"), 65536)?;
    let cmdline = std::str::from_utf8(&cmdline)
        .map_err(|_| Error("live installer command line encoding".into()))?;
    let before = storage_runtime::rows()?;
    validate(&before, cmdline)?;
    for (path, _, magic, _) in LAYOUT {
        let file = files::directory(Path::new(path), Some(0))?;
        let normal = mount_identity::id(file.as_fd(), false)?;
        let unique = mount_identity::id(file.as_fd(), true)?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } == 0
                && stat.f_type == *magic
                && before.iter().any(|r| r.target == *path && r.id == normal),
            "live installer kernel filesystem differs",
        )?;
        let current = files::directory(Path::new(path), Some(0))?;
        require(
            mount_identity::id(current.as_fd(), true)? == unique,
            "live installer filesystem replaced during observation",
        )?;
    }
    let after = storage_runtime::rows()?;
    validate(&after, cmdline)?;
    require(
        LAYOUT.iter().all(|(path, _, _, _)| {
            before.iter().find(|r| r.target == *path) == after.iter().find(|r| r.target == *path)
        }),
        "live installer mounts changed during observation",
    )
}
