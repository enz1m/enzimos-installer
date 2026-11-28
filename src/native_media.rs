// SPDX-License-Identifier: MIT
//! Closed development payload registry; hashes identify bytes, never release trust.
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const APPS: [&str; 19] = [
    "terminal",
    "phone-link",
    "mount",
    "aft-mtp",
    "keyring",
    "archive-keyring",
    "greetd",
    "store",
    "files",
    "text",
    "task-manager",
    "app-permissions",
    "agent-harness",
    "developer-tools",
    "remote-access",
    "background-apps",
    "dev-monitor",
    "xdg-desktop-portal-hyprland",
    // The default 'enzim' icon theme (data only).
    "icon-theme",
];
/// Native components that take an Arch package's place: the media leave that
/// package out of the offline Arch cohort, so the native transaction never
/// meets (or answers) a conflict and no Arch package is removed.
pub const REPLACES: [(&str, &str); 3] = [
    ("xdg-desktop-portal-hyprland", "xdg-desktop-portal-hyprland"),
    ("greetd", "greetd"),
    ("keyring", "gnome-keyring"),
];
pub(crate) const AI_MODELS_FILE: &str = "ai-ai-models.pkg.tar.zst";

pub const AI: [&str; 9] = [
    "inference-service",
    "ai-gateway",
    "llama-cpu",
    "llama-vulkan",
    "whisper-cpu",
    "ai-models",
    "dictation",
    "sherpa-onnx-cpu",
    "streaming-speech",
];
pub const RUST: [&str; 5] = [
    "packages",
    "installer",
    "remote-access",
    "recovery-ui",
    "updates",
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declared {
    pub file: String,
    pub name: String,
    pub version: Option<String>,
    pub sha256: String,
    pub max_bytes: u64,
    pub replaces: Option<String>,
}
fn add(
    rows: &mut Vec<Declared>,
    declaration: &Value,
    members: &BTreeMap<String, String>,
    file: String,
    name: String,
    version: Option<String>,
    max_bytes: u64,
) -> Result<()> {
    let digest = declaration["sha256"]
        .as_str()
        .ok_or_else(|| Error("native payload digest missing".into()))?;
    require(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && members.get(&file).is_some_and(|hash| hash == digest),
        "native payload digest differs from media declaration",
    )?;
    if let Some(version) = &version {
        enzimos_policy::package_archive::metadata(&format!(
            "pkgname = {name}\npkgver = {version}\narch = any\n"
        ))?;
    }
    require(
        rows.iter().all(|row| row.file != file && row.name != name),
        "duplicate native payload identity",
    )?;
    rows.push(Declared {
        file,
        name,
        version,
        sha256: digest.into(),
        max_bytes,
        replaces: None,
    });
    Ok(())
}
fn release(row: &Value, base: &str) -> Result<String> {
    let number = row["release"]
        .as_u64()
        .filter(|n| (1..=9999).contains(n))
        .ok_or_else(|| Error("native payload release bound".into()))?;
    Ok(format!("{base}-{number}"))
}
pub fn plan(manifest: &Value, members: &BTreeMap<String, String>) -> Result<Vec<Declared>> {
    require(
        manifest["development_artifact"] == true && manifest["release_authorized"] == false,
        "local native signing only admits explicit development media",
    )?;
    let mut rows = Vec::new();
    let policy = &manifest["native_policy"];
    json::fields(policy, "release sha256")?;
    add(
        &mut rows,
        policy,
        members,
        "native-policy.pkg.tar.zst".into(),
        "enzimos-native-policy".into(),
        Some(release(policy, "0.1.0")?),
        128 * 1024 * 1024,
    )?;
    for (key, name, max) in [
        ("backend", "enzimos-system-backend", 128),
        ("update_client", "enzimos-update-client", 128),
        ("mcp_center", "enzui-mcp-center", 128),
        ("activity_service", "enzimos-activity-service", 32),
        // The on-disk recovery environment: about 1.2 GB of compressed images.
        ("recovery_env", "enzimos-recovery-env", 2048),
    ] {
        let row = &manifest[key];
        if row.is_null() {
            continue;
        }
        json::fields(
            row,
            if key == "activity_service" {
                "release sha256 package_name"
            } else {
                "release sha256"
            },
        )?;
        require(
            key != "activity_service" || row["package_name"] == name,
            "activity payload identity declaration",
        )?;
        let filename = match key {
            "update_client" => "update-client",
            "mcp_center" => "mcp-center",
            "activity_service" => "activity-service",
            "recovery_env" => "recovery-env",
            _ => key,
        };
        add(
            &mut rows,
            row,
            members,
            format!("{filename}.pkg.tar.zst"),
            name.into(),
            Some(release(row, "0.1.0")?),
            max * 1024 * 1024,
        )?;
    }
    if let Some(row) = manifest.get("surface_touch") {
        json::fields(row, "version sha256 arch_packages")?;
        let version = row["version"]
            .as_str()
            .ok_or_else(|| Error("IPTS DKMS package version missing".into()))?;
        add(
            &mut rows,
            row,
            members,
            "ipts-dkms.pkg.tar.zst".into(),
            crate::surface_touch::MODULE_PACKAGE.into(),
            Some(version.into()),
            2 * 1024 * 1024,
        )?;
    }
    let apps = manifest["native_apps"]
        .as_object()
        .ok_or_else(|| Error("native application declarations shape".into()))?;
    require(apps.len() <= APPS.len(), "native application count bound")?;
    for (component, row) in apps {
        require(
            APPS.contains(&component.as_str()),
            "unreviewed native application component",
        )?;
        // The thin developer descriptor is build inventory, not installed code authority.
        // The original schema-one builder omitted its fixed 0.1.0 default.
        // Absence is the one legacy form; explicit null/type errors cannot
        // select it. Both forms retain a closed field set and exact pkgver.
        let mut fields = "package_name release sha256 revision profile".to_owned();
        if row.get("version").is_some() {
            fields.push_str(" version");
        }
        if row.get("developer_descriptor").is_some() {
            fields.push_str(" developer_descriptor");
        }
        if row.get("replaces").is_some() {
            fields.push_str(" replaces");
        }
        json::fields(row, &fields)?;
        let name = format!("enzimos-{component}");
        require(
            row["package_name"] == name,
            "native application name declaration",
        )?;
        let legacy = Value::String("0.1.0".into());
        let version = row
            .get("version")
            .unwrap_or(&legacy)
            .as_str()
            .filter(|v| {
                !v.is_empty()
                    && v.len() <= 64
                    && v.as_bytes()[0].is_ascii_alphanumeric()
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._+".contains(&b))
            })
            .ok_or_else(|| Error("native application version declaration".into()))?;
        if let Some(descriptor) = row.get("developer_descriptor") {
            require(
                component == "developer-tools" && descriptor["package_payloads_shipped"] == false,
                "thin developer descriptor role",
            )?;
        }
        let replaces = REPLACES
            .iter()
            .find(|(c, _)| c == component)
            .map(|(_, arch)| *arch);
        require(
            row.get("replaces").and_then(Value::as_str) == replaces
                && row.get("replaces").is_some() == replaces.is_some(),
            "native replacement declaration differs from the reviewed registry",
        )?;
        add(
            &mut rows,
            row,
            members,
            format!("{component}.pkg.tar.zst"),
            name,
            Some(release(row, version)?),
            128 * 1024 * 1024,
        )?;
        rows.last_mut().unwrap().replaces = replaces.map(str::to_owned);
    }
    let ai = &manifest["ai_runtime"];
    if !ai.is_null() {
        json::fields(ai, "schema packages models_included release_authorized")?;
        require(
            ai["schema"] == 1
                && ai["models_included"].is_boolean()
                && ai["release_authorized"] == false,
            "AI media must declare their models and stay development media",
        )?;
        let packages = ai["packages"]
            .as_array()
            .filter(|p| (3..=AI.len()).contains(&p.len()))
            .ok_or_else(|| Error("AI package declaration count".into()))?;
        let mut seen = BTreeSet::new();
        for row in packages {
            json::fields(row, "package_name media_file sha256")?;
            let name = row["package_name"]
                .as_str()
                .ok_or_else(|| Error("AI package name type".into()))?;
            let component = name
                .strip_prefix("enzimos-")
                .filter(|s| AI.contains(s))
                .ok_or_else(|| Error("unreviewed AI runtime package".into()))?;
            let file = format!("ai-{component}.pkg.tar.zst");
            require(
                row["media_file"] == file && seen.insert(component),
                "AI filename or duplicate declaration",
            )?;
            let max_bytes = if file == AI_MODELS_FILE {
                enzimos_platform::stream_copy::STREAM_BOUND
            } else {
                256 * 1024 * 1024
            };
            add(&mut rows, row, members, file, name.into(), None, max_bytes)?;
        }
        require(
            (ai["models_included"] == true) == seen.contains("ai-models"),
            "AI models are declared exactly when the models package is present",
        )?;
        require(
            !seen.contains("streaming-speech") || seen.contains("dictation"),
            "streaming speech requires the dictation client",
        )?;
        require(
            ["inference-service", "ai-gateway", "llama-cpu"]
                .iter()
                .all(|s| seen.contains(s)),
            "AI runtime dependency cohort incomplete",
        )?;
    }
    if let Some(cohort) = manifest.get("native_rust") {
        json::fields(
            cohort,
            "packages installer remote-access recovery-ui updates",
        )?;
        for component in RUST {
            let row = &cohort[component];
            json::fields(
                row,
                "package_name release version sha256 profile automatic_activation",
            )?;
            let name = format!("enzimos-rust-{component}");
            let version = match (component, row["version"].as_str()) {
                (_, Some("0.2.0")) => "0.2.0",
                ("installer", Some("0.2.1")) => "0.2.1",
                ("installer", Some("0.2.2")) => "0.2.2",
                _ => return Err(Error("native Rust candidate version differs".into())),
            };
            require(
                row["package_name"] == name
                    && row["profile"] == "rust-candidate"
                    && row["automatic_activation"] == false,
                "native Rust candidate identity or activation differs",
            )?;
            add(
                &mut rows,
                row,
                members,
                format!("rust-{component}.pkg.tar.zst"),
                name,
                Some(release(row, version)?),
                128 * 1024 * 1024,
            )?;
        }
    }
    let declared = rows.iter().map(|r| r.file.clone()).collect::<BTreeSet<_>>();
    require(
        members
            .keys()
            .filter(|p| !p.contains('/') && p.ends_with(".pkg.tar.zst"))
            .cloned()
            .collect::<BTreeSet<_>>()
            == declared,
        "undeclared or missing native media package",
    )?;
    rows.sort_by(|a, b| a.file.cmp(&b.file));
    Ok(rows)
}
/// Native payloads neither share a name with the offline Arch cohort nor arrive
/// beside the Arch package they replace.
pub fn disjoint(rows: &[&Declared], arch: &BTreeMap<String, String>) -> Result<()> {
    require(
        rows.iter().all(|row| !arch.contains_key(&row.name)),
        "native payload must not replace an Arch base package",
    )?;
    require(
        rows.iter()
            .filter_map(|row| row.replaces.as_ref())
            .all(|name| !arch.contains_key(name)),
        "replaced Arch package must be absent from the offline Arch cohort",
    )?;
    // The matching console greeter is bundled in this replacement; Arch's
    // separate agreety depends on greetd and cannot precede the native body.
    require(
        !rows.iter().any(|row| row.name == "enzimos-greetd")
            || !arch.contains_key("greetd-agreety"),
        "replaced Arch console greeter must be absent from the offline Arch cohort",
    )
}
pub fn identity(declared: &Declared, observed: &Value) -> Result<()> {
    json::fields(observed, "name version")?;
    require(
        observed["name"] == declared.name
            && declared
                .version
                .as_ref()
                .is_none_or(|version| observed["version"] == *version),
        "native archive identity differs from media declaration",
    )
}
