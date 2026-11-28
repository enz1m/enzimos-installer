// SPDX-License-Identifier: MIT
//! Space required by the selected target payload before partitioning.
use crate::{answers::Answers, media_packages::Admitted};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::Value;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const BOOT_AND_ALIGNMENT: u64 = 4 * GIB + 64 * MIB;
const MIN_GEOMETRY: u64 = 24 * GIB;

// Installed payload allowance for media built before it recorded these sizes.
const LEGACY_PAYLOAD: u64 = 17 * GIB;
const FIELDS: &str = "base_bytes nvidia_bytes models_bytes desktop_bytes flatpak_bytes";

pub(crate) fn validate(payload: &Value) -> Result<()> {
    json::fields(payload, FIELDS)?;
    require(
        FIELDS.split_whitespace().all(|field| {
            payload[field]
                .as_u64()
                .is_some_and(|size| size <= 1024 * GIB)
        }) && payload["base_bytes"].as_u64().is_some_and(|size| size > 0),
        "installation media payload size is missing or out of range",
    )
}

fn minimum(
    payload: Option<&Value>,
    nvidia: bool,
    desktop: bool,
    flatpaks: bool,
    swap_mib: u32,
) -> Result<u64> {
    let installed = if let Some(payload) = payload {
        validate(payload)?;
        let bytes = |field: &str| payload[field].as_u64().unwrap_or_default();
        bytes("base_bytes")
            + bytes("models_bytes")
            + if nvidia { bytes("nvidia_bytes") } else { 0 }
            + if desktop { bytes("desktop_bytes") } else { 0 }
            + if flatpaks { bytes("flatpak_bytes") } else { 0 }
    } else {
        LEGACY_PAYLOAD
    };
    // Preserve space for Btrfs metadata, the first snapshots and an update
    // transaction. Recovery boot files fit inside the separately budgeted ESP.
    let reserve = (installed / 5).max(4 * GIB);
    let total = installed + reserve + u64::from(swap_mib) * MIB + BOOT_AND_ALIGNMENT;
    Ok((total.div_ceil(GIB) * GIB).max(MIN_GEOMETRY))
}

pub(crate) fn check(bytes: u64, media: &Admitted, answers: &Answers) -> Result<()> {
    let swap = crate::system_config::swap_size(
        answers.swap_mib,
        crate::install_config_storage::memory_kib()?,
    )?;
    let nvidia = media.packages.iter().any(|package| {
        package.identity["name"].as_str().is_some_and(|name| {
            crate::media_plan::NVIDIA.contains(&name) && media.selected.contains(&package.filename)
        })
    });
    let minimum = minimum(
        media.manifest.get("storage_payload"),
        nvidia,
        answers.desktop,
        answers.flatpaks,
        swap,
    )?;
    require(
        bytes >= minimum,
        &format!(
            "Installation target is too small. enzimOS needs at least {} GiB for this installation (available {:.1} GiB, swap {:.1} GiB).",
            minimum / GIB,
            bytes as f64 / GIB as f64,
            f64::from(swap) / 1024.0,
        ),
    )
}

/// Read the minimum for the graphical installer's default answer set.
///
/// # Errors
/// Returns an error if the live media manifest or system memory cannot be read.
pub fn graphical_minimum() -> Result<u64> {
    const MANIFEST_LIMIT: usize = 1024 * 1024;
    let manifest = json::decode(
        &files::read(
            &crate::media_source::member_path("manifest.json"),
            MANIFEST_LIMIT,
            Some(0),
            false,
        )?,
        MANIFEST_LIMIT,
    )?;
    if !manifest.is_object() {
        return Err(Error("installation media manifest is missing".into()));
    }
    minimum(
        manifest.get("storage_payload"),
        crate::media_packages::nvidia(crate::answers::Gpu::Auto)?,
        true,
        true,
        crate::system_config::swap_size(None, crate::install_config_storage::memory_kib()?)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn uses_selected_payload_and_requested_swap() -> Result<()> {
        let payload = json!({
            "base_bytes": 8 * GIB,
            "nvidia_bytes": 4 * GIB,
            "models_bytes": 2 * GIB,
            "desktop_bytes": GIB,
            "flatpak_bytes": 8 * GIB,
        });
        assert_eq!(minimum(Some(&payload), false, true, true, 8192)?, 36 * GIB);
        assert_eq!(minimum(Some(&payload), true, true, true, 8192)?, 40 * GIB);
        assert_eq!(minimum(Some(&payload), false, true, true, 1024)?, 29 * GIB);
        assert_eq!(
            minimum(Some(&payload), false, false, false, 1024)?,
            MIN_GEOMETRY
        );
        assert!(minimum(Some(&Value::Null), false, true, true, 8192).is_err());
        assert!(minimum(None, false, true, true, 8192)? > 24 * GIB);
        Ok(())
    }
}
