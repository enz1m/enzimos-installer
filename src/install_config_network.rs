// SPDX-License-Identifier: MIT
//! Export current private connection profiles without embedding credentials in receipts.
use crate::{media_packages::Admitted, package_handoff::Received};
use enzimos_platform::{Error, Result, files, json, mount_identity, process, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::Duration,
};
fn shape(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 1
            && m.len() <= 65536,
        "exported connection profile protection differs",
    )?;
    Ok(value!({"mount":mount_identity::id(file.as_fd(),true)?,"inode":files::identity(&m)}))
}
fn names(directory: &File) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for (index, entry) in files::directory_names(directory, 512)?
        .into_iter()
        .enumerate()
    {
        require(index < 512, "connection profile count bound")?;
        require(
            result.insert(
                entry
                    .into_string()
                    .map_err(|_| Error("connection profile filename encoding".into()))?,
            ),
            "duplicate connection profile filename",
        )?;
    }
    Ok(result)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod).")]
pub(crate) fn create(context: &Received, media: &Admitted) -> Result<Value> {
    context.recheck()?;
    media.recheck()?;
    let destination = files::ensure_directory_relative(
        &context.target,
        Path::new("etc/NetworkManager/system-connections"),
        0o700,
        0,
    )?;
    require(
        destination.metadata()?.uid() == 0
            && destination.metadata()?.gid() == 0
            && names(&destination)?.is_empty(),
        "fresh network export refuses existing profile state",
    )?;
    require(
        unsafe { libc::fchmod(destination.as_raw_fd(), 0o700) } == 0,
        "private network export directory mode publication failed",
    )?;
    destination.sync_all()?;
    let active = process::run_pinned(
        "/usr/bin/nmcli",
        media.images.get("/usr/bin/nmcli")?,
        &[
            "--wait",
            "25",
            "--terse",
            "--escape",
            "yes",
            "-g",
            "UUID",
            "connection",
            "show",
            "--active",
        ],
        &[],
        Duration::from_secs(35),
        65536,
        &[],
    )?;
    context.recheck()?;
    media.recheck()?;
    let mut files = serde_json::Map::new();
    if !active.status.success() {
        return Ok(value!({"unavailable":true,"files":files}));
    }
    let active = std::str::from_utf8(&active.stdout)
        .map_err(|_| Error("active connection identity encoding".into()))?
        .lines()
        .collect::<BTreeSet<_>>();
    let mut copied = BTreeSet::new();
    for base in [
        "/run/NetworkManager/system-connections",
        "/etc/NetworkManager/system-connections",
    ] {
        match std::fs::symlink_metadata(base) {
            Ok(m) => require(m.is_dir(), "private connection source cannot be a symlink")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        }
        let directory = files::directory(Path::new(base), Some(0))?;
        for name in names(&directory)? {
            context.recheck()?;
            media.recheck()?;
            if !name.ends_with(".nmconnection") {
                continue;
            }
            let source = files::open_relative(&directory, Path::new(&name))?;
            require(
                source.metadata()?.mode() & 0o7777 == 0o600,
                "active connection input must remain private",
            )?;
            let bytes = crate::private_file::read(&source, 65536, 0)?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| Error("private connection profile encoding".into()))?;
            let Some(uuid) = connection(text)? else {
                continue;
            };
            if !active.contains(uuid) || !copied.insert(uuid.to_owned()) {
                continue;
            }
            let filename = format!("enzimos-{uuid}.nmconnection");
            files::atomic_relative(
                &destination,
                Path::new(&filename),
                &bytes,
                0o600,
                Some(0),
                false,
                65536,
            )?;
            let written = files::open_relative(&destination, Path::new(&filename))?;
            require(
                *crate::private_file::read(&written, 65536, 0)? == *bytes,
                "private connection export readback differs",
            )?;
            files.insert(filename, shape(&written)?);
        }
    }
    let result = value!({"unavailable":false,"files":files});
    verify(&context.target, &result)?;
    context.recheck()?;
    media.recheck()?;
    Ok(result)
}
fn connection(text: &str) -> Result<Option<&str>> {
    require(
        text.len() <= 65536 && !text.contains('\0'),
        "connection profile text bound",
    )?;
    let (mut section, mut uuid, mut kind) = ("", None, None);
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
        } else if section == "connection"
            && let Some((name, value)) = line.split_once('=')
        {
            match name.trim() {
                "uuid" => {
                    require(uuid.is_none(), "duplicate connection UUID")?;
                    uuid = Some(value.trim());
                }
                "type" => {
                    require(kind.is_none(), "duplicate connection type")?;
                    kind = Some(value.trim());
                }
                _ => {}
            }
        }
    }
    if matches!(
        kind,
        Some("wifi" | "ethernet" | "802-11-wireless" | "802-3-ethernet")
    ) {
        let uuid = uuid.ok_or_else(|| Error("active connection UUID missing".into()))?;
        enzimos_policy::identity::uuid(uuid)?;
        Ok(Some(uuid))
    } else {
        Ok(None)
    }
}
pub(crate) fn validate(body: &Value) -> Result<()> {
    json::fields(body, "unavailable files")?;
    let files = body["files"]
        .as_object()
        .ok_or_else(|| Error("connection export members missing".into()))?;
    require(
        body["unavailable"].is_boolean()
            && files.len() <= 512
            && (body["unavailable"] == false || files.is_empty()),
        "connection export status or member bound",
    )?;
    for (name, metadata) in files {
        let uuid = name
            .strip_prefix("enzimos-")
            .and_then(|s| s.strip_suffix(".nmconnection"))
            .ok_or_else(|| Error("connection export filename role".into()))?;
        enzimos_policy::identity::uuid(uuid)?;
        json::fields(metadata, "mount inode")?;
        require(
            metadata["mount"].as_u64().is_some_and(|n| n > 0),
            "connection profile unique mount missing",
        )?;
        crate::private_file::validate_inode(&metadata["inode"], 0o600, 65536)?;
    }
    Ok(())
}
pub(crate) fn verify(root: &File, body: &Value) -> Result<()> {
    validate(body)?;
    let directory = files::directory_relative(
        root,
        Path::new("etc/NetworkManager/system-connections"),
        Some(0),
    )?;
    require(
        directory.metadata()?.mode() & 0o7777 == 0o700
            && names(&directory)? == body["files"].as_object().unwrap().keys().cloned().collect(),
        "connection export private directory members changed",
    )?;
    for (name, metadata) in body["files"].as_object().unwrap() {
        require(
            shape(&files::open_relative(&directory, Path::new(name))?)? == *metadata,
            "connection export original private inode changed",
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_profile_selection_rejects_duplicate_identity_without_returning_credentials() {
        let id = "11111111-1111-4111-8111-111111111111";
        let profile =
            format!("[connection]\nuuid={id}\ntype=wifi\n[wifi-security]\npsk=never-in-receipt\n");
        assert_eq!(connection(&profile).unwrap(), Some(id));
        assert!(connection(&format!("[connection]\nuuid={id}\nuuid={id}\ntype=wifi\n")).is_err());
        assert_eq!(connection("[connection]\ntype=vpn\n").unwrap(), None);
        assert!(connection("[connection]\nuuid=bad\ntype=wifi\n").is_err());
    }
}
