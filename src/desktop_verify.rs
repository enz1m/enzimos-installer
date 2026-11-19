// SPDX-License-Identifier: MIT
//! Independent desktop checks after the original worker subtree has ended.
use crate::{desktop_policy as policy, target_storage::Target};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};
pub(crate) const CONFIGURATIONS: [&str; 8] = [
    "etc/pam.d/greetd",
    "etc/pam.d/enzui-lock",
    "etc/pam.d/passwd",
    "etc/environment",
    "etc/cups/cupsd.conf",
    "etc/ipp-usb/ipp-usb.conf",
    "etc/avahi/avahi-daemon.conf",
    "etc/NetworkManager/conf.d/30-enzimos-connectivity.conf",
];
pub(crate) fn receipt(root: &File, body: &Value, request: &Value, owner: &Value) -> Result<()> {
    json::fields(
        body,
        "schema role phase request_sha256 owner inputs files services_started password_handled installed_qualification keyring_activation provider",
    )?;
    require(
        body["schema"].as_u64() == Some(1)
            && body["role"] == "fresh-desktop-configuration"
            && body["phase"] == "complete"
            && body["request_sha256"] == json::fingerprint(request)?
            && body["owner"] == *owner
            && body["services_started"] == false
            && body["password_handled"] == false
            && body["installed_qualification"] == false,
        "desktop completion binding differs",
    )?;
    let rows = body["files"]
        .as_array()
        .ok_or_else(|| Error("desktop files missing".into()))?;
    require(
        rows.len() == CONFIGURATIONS.len(),
        "desktop file set differs",
    )?;
    for (row, name) in rows.iter().zip(CONFIGURATIONS) {
        json::fields(row, "path inode parent mode")?;
        require(row["path"] == name, "desktop file identity differs")?;
        let parent = files::directory_relative(root, Path::new(name).parent().unwrap(), Some(0))?;
        let m = parent.metadata()?;
        require(
            row["parent"]
                == serde_json::json!({"inode":[m.dev(),m.ino(),m.mode(),m.uid(),m.gid()],"mount":mount_identity::id(std::os::fd::AsFd::as_fd(&parent),true)?}),
            "desktop parent identity differs",
        )?;
        let file = files::open_relative(&parent, Path::new(Path::new(name).file_name().unwrap()))?;
        require(
            serde_json::json!(files::identity(&file.metadata()?)) == row["inode"]
                && file.metadata()?.mode() & 0o7777
                    == row["mode"].as_u64().unwrap_or(u64::MAX) as u32,
            "completed original desktop file changed",
        )?;
        let bytes = files::read_file(&file, 128 * 1024, Some(0), true)?;
        let body = std::str::from_utf8(&bytes)
            .map_err(|_| Error("desktop verification encoding".into()))?;
        let expected = match name {
            "etc/pam.d/greetd" => policy::pam(body, "greetd")?,
            "etc/pam.d/enzui-lock" => policy::pam(body, "enzui-lock")?,
            "etc/pam.d/passwd" => policy::pam(body, "passwd")?,
            "etc/environment" => policy::environment(body)?,
            "etc/cups/cupsd.conf" => policy::cups(body)?,
            "etc/ipp-usb/ipp-usb.conf" => policy::ipp_usb(body)?,
            "etc/avahi/avahi-daemon.conf" => policy::avahi(body)?,
            _ => policy::CONNECTIVITY.into(),
        };
        require(
            expected == body,
            "actual desktop policy differs from completed transformation",
        )?;
    }
    let provider = crate::install_boot_sources::Source::open(
        root,
        Path::new("usr/lib/security/pam_oo7.so"),
        16 * 1024 * 1024,
    )?;
    require(
        provider.receipt() == body["provider"],
        "desktop keyring provider changed",
    )?;
    json::fields(&body["keyring_activation"], "retired present")?;
    require(
        body["keyring_activation"]["retired"].is_boolean()
            && body["keyring_activation"]["present"] == false,
        "desktop keyring activation completion differs",
    )?;
    if let Some(parent) = files::optional_directory_relative(
        root,
        Path::new("etc/systemd/user/sockets.target.wants"),
        Some(0),
    )? {
        let path = format!(
            "/proc/self/fd/{}/gnome-keyring-daemon.socket",
            parent.as_raw_fd()
        );
        require(
            matches!(std::fs::symlink_metadata(path),Err(error)if error.kind()==std::io::ErrorKind::NotFound),
            "early keyring socket activation remains enabled",
        )?;
    }
    for (name, target) in enabled_links(root)? {
        link(root, &name, &target)?;
    }
    Ok(())
}
fn link(root: &File, name: &str, expected: &str) -> Result<()> {
    let (_, row) = enzimos_policy::file_overlay::capture(root, name, 0)?;
    require(
        row["kind"] == "symlink" && row["target"] == expected,
        "enabled desktop unit points elsewhere",
    )
}
pub(crate) fn enabled_links(root: &File) -> Result<BTreeMap<String, String>> {
    let mut links = BTreeMap::new();
    for unit in [
        "cups.socket",
        "avahi-daemon.service",
        "ipp-usb.service",
        "greetd.service",
    ] {
        for (path, target) in unit_links(root, unit)? {
            require(
                links.insert(path, target).is_none(),
                "desktop units duplicate an enablement link",
            )?;
        }
    }
    links.insert(
        "etc/systemd/system/default.target".into(),
        "/usr/lib/systemd/system/graphical.target".into(),
    );
    Ok(links)
}
fn unit_links(root: &File, unit: &str) -> Result<BTreeMap<String, String>> {
    let file = files::open_relative(root, Path::new(&format!("usr/lib/systemd/system/{unit}")))?;
    let bytes = files::read_file(&file, 65536, Some(0), true)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error("desktop unit encoding".into()))?;
    let mut install = false;
    let mut wants = BTreeSet::new();
    let mut aliases = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') {
            install = line == "[Install]";
            continue;
        }
        if !install {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            let output = match name.trim() {
                "WantedBy" => &mut wants,
                "Alias" => &mut aliases,
                _ => continue,
            };
            if value.trim().is_empty() {
                output.clear();
                continue;
            }
            for name in value.split_whitespace() {
                enzimos_policy::identity::safe_id(name)?;
                require(output.len() < 16, "desktop unit install link bound")?;
                output.insert(name.to_owned());
            }
        }
    }
    require(
        !wants.is_empty() || !aliases.is_empty(),
        "desktop unit lacks reviewed enablement metadata",
    )?;
    let mut links = BTreeMap::new();
    for target in wants {
        require(
            target.ends_with(".target"),
            "desktop unit install target differs",
        )?;
        links.insert(
            format!("etc/systemd/system/{target}.wants/{unit}"),
            format!("/usr/lib/systemd/system/{unit}"),
        );
    }
    for alias in aliases {
        links.insert(
            format!("etc/systemd/system/{alias}"),
            format!("/usr/lib/systemd/system/{unit}"),
        );
    }
    Ok(links)
}

pub(crate) fn completed(
    target: &Target<'_>,
    journal: &Value,
    directory: &File,
) -> Result<Option<Value>> {
    target.recheck()?;
    if !target.source().answers.desktop {
        return Ok(None);
    }
    let body = json::decode(
        &files::read_file(
            &files::open_relative(directory, Path::new("desktop-config.json"))?,
            128 * 1024,
            Some(0),
            true,
        )?,
        128 * 1024,
    )?;
    receipt(
        target.directory()?,
        &body,
        &journal["request"],
        &journal["owner"],
    )?;
    target.recheck()?;
    Ok(Some(body))
}
