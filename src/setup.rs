// SPDX-License-Identifier: MIT
//! Small native replacements for installer shell's embedded Python fragments.
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::Value;
use std::path::Path;
pub fn unused_inventory(v: &Value) -> Result<()> {
    json::fields(v, "blockdevices")?;
    let rows = v["blockdevices"]
        .as_array()
        .ok_or_else(|| Error("selected disk inventory shape".into()))?;
    require(rows.len() == 1, "one selected disk required")?;
    let mut count = 0;
    fn check(v: &Value, depth: usize, count: &mut usize) -> Result<()> {
        require(
            depth < 32
                && *count < 256
                && v.is_object()
                && matches!(v["type"].as_str(), Some("disk" | "part")),
            "selected disk has active or unsupported children",
        )?;
        *count += 1;
        if let Some(mounts) = v.get("mountpoints")
            && !mounts.is_null()
        {
            let mounts = mounts
                .as_array()
                .ok_or_else(|| Error("disk mount inventory type".into()))?;
            require(
                mounts.len() <= 64 && mounts.iter().all(|m| m.is_null() || m.as_str() == Some("")),
                "selected disk is mounted",
            )?;
        }
        if let Some(children) = v.get("children") {
            for child in children
                .as_array()
                .ok_or_else(|| Error("disk children inventory type".into()))?
            {
                check(child, depth + 1, count)?;
            }
        }
        Ok(())
    }
    require(rows[0]["type"] == "disk", "whole disk required")?;
    check(&rows[0], 0, &mut count)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
pub fn live() -> Result<()> {
    crate::live_context::observe()?;
    require(
        unsafe { libc::geteuid() } == 0,
        "live installer root context required",
    )?;
    let marker = files::directory(Path::new("/run/enzimos-live"), Some(0))?;
    use std::os::unix::fs::MetadataExt;
    require(
        marker.metadata()?.uid() == 0,
        "live installer marker authority",
    )?;
    require(
        std::fs::read_link("/proc/self/ns/mnt")? == std::fs::read_link("/proc/1/ns/mnt")?,
        "initial live mount namespace required",
    )
}
pub fn disk_idle(disk: &str) -> Result<()> {
    let disk = crate::disk_guard::Disk::open(disk)?;
    disk.recheck()
}
pub fn multilib_text(input: &str) -> Result<String> {
    require(
        input.len() <= 1024 * 1024 && !input.contains('\0'),
        "pacman configuration bound",
    )?;
    let old = "#[multilib]\n#Include = /etc/pacman.d/mirrorlist";
    let enabled = "[multilib]\nInclude = /etc/pacman.d/mirrorlist";
    let headers = input
        .lines()
        .filter(|s| matches!(s.trim(), "[multilib]" | "#[multilib]"))
        .count();
    require(headers == 1, "ambiguous multilib repository")?;
    if input.contains(enabled) {
        return Ok(input.into());
    }
    require(
        input.matches(old).count() == 1,
        "unsupported multilib repository configuration",
    )?;
    Ok(input.replacen(old, enabled, 1))
}
pub fn enable_multilib() -> Result<()> {
    live()?;
    let path = Path::new("/mnt/enzimos/etc/pacman.conf");
    let bytes = files::read(path, 1024 * 1024, Some(0), true)?;
    let input =
        std::str::from_utf8(&bytes).map_err(|_| Error("pacman configuration encoding".into()))?;
    let output = multilib_text(input)?;
    files::atomic(path, output.as_bytes(), 0o644, Some(0), true)
}
pub fn layout_field(v: &Value, key: &str) -> Result<String> {
    require(matches!(key, "esp" | "root"), "partition output field")?;
    let s = v[key]
        .as_str()
        .ok_or_else(|| Error("partition output shape".into()))?;
    require(
        s.len() <= 255
            && s.starts_with("/dev/")
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-".contains(&b)),
        "partition output path",
    )?;
    Ok(s.into())
}
