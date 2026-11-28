// SPDX-License-Identifier: MIT
//! Bind the offline package pool to its declared identities and conditional GPU set.
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
pub const NVIDIA: [&str; 4] = [
    "lib32-nvidia-utils",
    "nvidia-open",
    "nvidia-open-lts",
    "nvidia-utils",
];
const XWAYLAND_RUNTIME: [&str; 5] = [
    "xorg-xwayland",
    "xorg-xkbcomp",
    "xkeyboard-config",
    "libbsd",
    "libmd",
];
pub(crate) const XWAYLAND_FILES: [(&str, &str, u32); 2] = [
    (
        "usr/lib/enzui/compositor/hyprland-current-build/Xwayland",
        "binary_sha256",
        0o755,
    ),
    (
        "usr/share/licenses/enzui-desktop/Xwayland-COPYING",
        "notice_sha256",
        0o644,
    ),
];

fn sha256(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn xwayland(body: &Value, receipt: &Value) -> Result<()> {
    json::fields(
        receipt,
        "sha256 url version build_revision binary_sha256 notice_sha256",
    )?;
    let version = receipt["version"]
        .as_str()
        .filter(|v| {
            v.len() <= 32
                && v.split('.').count() == 3
                && v.split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        })
        .ok_or_else(|| Error("Xwayland version encoding".into()))?;
    require(
        receipt["url"]
            == format!("https://www.x.org/releases/individual/xserver/xwayland-{version}.tar.xz")
            && ["sha256", "binary_sha256", "notice_sha256"]
                .iter()
                .all(|key| receipt[key].as_str().is_some_and(sha256)),
        "Xwayland source URL or digest differs",
    )?;
    let revision = receipt["build_revision"].as_str().unwrap_or_default();
    let mut fields = revision.split(' ');
    require(
        fields.next() == Some("xwayland")
            && fields.next().is_some_and(sha256)
            && fields.next().is_some_and(sha256)
            && fields.next().is_none()
            && body["desktop_preview_files"]
                .as_u64()
                .is_some_and(|count| count > 0),
        "Xwayland build revision or desktop overlay missing",
    )
}

pub fn manifest(body: &Value, members: &BTreeMap<String, String>, now_millis: u64) -> Result<()> {
    let mut fields = "native_apps activity_service ai_runtime secure_media schema label development_artifact release_authorized native_policy cohort_plan_sha256 package_count nvidia_conditional trust_lock_sha256 review_before kernel live installer_sha256 desktop_preview_files flatpaks update_client mcp_center backend".to_owned();
    if body.get("native_rust").is_some() {
        fields.push_str(" native_rust");
    }
    if body.get("recovery_env").is_some() {
        fields.push_str(" recovery_env");
    }
    if body.get("enzimos_flatpaks").is_some() {
        use crate::flatpak_media::{ENZIMOS, FLATHUB};
        fields.push_str(" enzimos_flatpaks");
        if !ENZIMOS.declared(body)?.is_empty() && FLATHUB.declared(body)?.is_empty() {
            require(
                ["apps.txt", FLATHUB.remote_file, "repo/config"]
                    .iter()
                    .all(|path| members.contains_key(&FLATHUB.member(path))),
                "enzimOS Flatpak source without the Flathub runtime source",
            )?;
        }
    }
    if let Some(receipt) = body.get("desktop_xwayland") {
        fields.push_str(" desktop_xwayland");
        xwayland(body, receipt)?;
    }
    json::fields(body, &fields)?;
    require(
        body["schema"] == 1
            && body["development_artifact"] == true
            && body["release_authorized"] == false
            && body["live"]["graphical_installer"] == true,
        "installation media role or schema refused",
    )?;
    // The package trust review is a one-time record; the media does not expire with it.
    require(
        body["review_before"]
            .as_str()
            .is_some_and(|v| v.len() <= 64),
        "media review record bound",
    )?;
    let _ = now_millis;
    for key in [
        "cohort_plan_sha256",
        "trust_lock_sha256",
        "installer_sha256",
    ] {
        let hash = body[key]
            .as_str()
            .ok_or_else(|| Error("media digest missing".into()))?;
        require(sha256(hash), "media digest encoding")?;
    }
    require(
        members
            .get("native-policy.pkg.tar.zst")
            .is_some_and(|digest| body["native_policy"]["sha256"] == *digest),
        "native policy package differs from media declaration",
    )?;
    for (key, path) in [
        ("backend", "backend.pkg.tar.zst"),
        ("update_client", "update-client.pkg.tar.zst"),
        ("mcp_center", "mcp-center.pkg.tar.zst"),
    ] {
        if body[key].is_null() {
            require(
                !members.contains_key(path),
                "undeclared native media component",
            )?;
        } else {
            require(
                members
                    .get(path)
                    .is_some_and(|digest| body[key]["sha256"] == *digest),
                "native media component digest differs",
            )?;
        }
    }
    Ok(())
}
pub fn declarations(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    require(
        bytes.len() <= 1024 * 1024,
        "offline package identities byte bound",
    )?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error("offline package identities encoding".into()))?;
    let mut identities = BTreeMap::new();
    for line in text.lines() {
        let (name, version) = line
            .split_once(' ')
            .ok_or_else(|| Error("offline package identity row".into()))?;
        enzimos_policy::package_archive::metadata(&format!(
            "pkgname = {name}\npkgver = {version}\narch = any\n"
        ))?;
        require(
            identities.len() < 1024 && identities.insert(name.into(), version.into()).is_none(),
            "duplicate or excessive offline package identities",
        )?;
    }
    require(
        !identities.is_empty(),
        "offline package identity list empty",
    )?;
    Ok(identities)
}
pub fn pool(
    base: &[String],
    nvidia: &[String],
    declared: &BTreeMap<String, String>,
    observed: &BTreeMap<String, Value>,
    manifest: &Value,
) -> Result<Vec<String>> {
    let files = base
        .iter()
        .chain(nvidia.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    require(
        !base.is_empty()
            && files.len() == base.len() + nvidia.len()
            && files == observed.keys().cloned().collect()
            && files.len() == declared.len()
            && manifest["package_count"].as_u64() == Some(files.len() as u64),
        "offline package pool differs from declaration",
    )?;
    let mut seen = BTreeSet::new();
    let mut conditional = BTreeSet::new();
    for (file, identity) in observed {
        json::fields(identity, "name version")?;
        let name = identity["name"]
            .as_str()
            .ok_or_else(|| Error("package name missing".into()))?;
        require(
            seen.insert(name)
                && declared
                    .get(name)
                    .is_some_and(|version| identity["version"] == *version),
            "offline archive identity differs from declared package",
        )?;
        let version = identity["version"]
            .as_str()
            .ok_or_else(|| Error("package version missing".into()))?;
        require(
            enzimos_policy::package_archive::filename_matches(file, name, version),
            "offline filename differs from admitted archive identity",
        )?;
        require(
            nvidia.contains(file) == NVIDIA.contains(&name),
            "NVIDIA conditional package classification differs",
        )?;
        if nvidia.contains(file) {
            conditional.insert(name.to_owned());
        }
    }
    require(
        manifest["nvidia_conditional"] == serde_json::json!(conditional.iter().collect::<Vec<_>>()),
        "NVIDIA package declaration differs",
    )?;
    if manifest.get("desktop_xwayland").is_some() {
        require(
            XWAYLAND_RUNTIME.iter().all(|name| seen.contains(name)),
            "Xwayland runtime package cohort incomplete",
        )?;
    }
    Ok(files.into_iter().collect())
}
pub fn select(base: &[String], nvidia: &[String], requested: bool) -> Result<Vec<String>> {
    require(
        !requested || nvidia.len() == NVIDIA.len(),
        "requested NVIDIA driver requires the complete offline cohort",
    )?;
    let mut selected = base.to_vec();
    if requested {
        selected.extend_from_slice(nvidia);
    }
    Ok(selected)
}
