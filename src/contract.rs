// SPDX-License-Identifier: MIT
use enzimos_platform::{
    Error, Result,
    json::{fields, fingerprint},
    require,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn fixed(actual: &Value, expected: Value, label: &str) -> Result<()> {
    require(*actual == expected, label)
}
fn identifier(value: &Value) -> Result<&str> {
    let s = value
        .as_str()
        .ok_or_else(|| Error("invalid synthetic identity".into()))?;
    require(
        !s.is_empty()
            && s.len() <= 64
            && s.as_bytes()[0].is_ascii_lowercase()
            && s.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
        "invalid synthetic identity",
    )?;
    Ok(s)
}
pub fn span(item: &Value, disk_size: u64) -> Result<(u64, u64)> {
    let start = item["start_bytes"]
        .as_u64()
        .ok_or_else(|| Error("invalid byte interval".into()))?;
    let size = item["size_bytes"]
        .as_u64()
        .ok_or_else(|| Error("invalid byte interval".into()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error("interval overflow".into()))?;
    require(
        size > 0 && end <= disk_size && start % 4096 == 0 && size % 4096 == 0,
        "interval outside device or unaligned",
    )?;
    Ok((start, end))
}
fn disjoint(mut intervals: Vec<(u64, u64)>) -> Result<()> {
    intervals.sort_unstable();
    require(
        intervals.windows(2).all(|w| w[0].1 <= w[1].0),
        "overlapping intervals",
    )
}
pub fn validate(inventory: &Value, plan: &Value) -> Result<Value> {
    fields(
        inventory,
        "schema_version synthetic device_id disk_size_bytes firmware secure_boot windows_firmware regions",
    )?;
    fixed(
        &inventory["schema_version"],
        json!(1),
        "inventory version unsupported",
    )?;
    fixed(
        &inventory["synthetic"],
        json!(true),
        "only explicitly synthetic inventories are supported",
    )?;
    identifier(&inventory["device_id"])?;
    let size = inventory["disk_size_bytes"]
        .as_u64()
        .ok_or_else(|| Error("invalid device size".into()))?;
    require(size > 0 && size <= i64::MAX as u64, "invalid device size")?;
    let firmware = inventory["firmware"]
        .as_str()
        .ok_or_else(|| Error("unsupported firmware".into()))?;
    let security = inventory["secure_boot"]
        .as_str()
        .ok_or_else(|| Error("unsupported security state".into()))?;
    require(
        matches!(
            (firmware, security),
            ("uefi", "enabled" | "disabled") | ("bios", "not-applicable")
        ),
        "firmware/security mismatch",
    )?;
    require(
        inventory["windows_firmware"].is_null() || inventory["windows_firmware"] == firmware,
        "Windows firmware mode mismatch",
    )?;
    let regions = inventory["regions"]
        .as_array()
        .ok_or_else(|| Error("invalid region list".into()))?;
    require(
        !regions.is_empty() && regions.len() <= 256,
        "invalid region list",
    )?;
    let (mut by_id, mut spans, mut windows) = (BTreeMap::new(), Vec::new(), false);
    for region in regions {
        fields(region, "id kind owner start_bytes size_bytes")?;
        let id = identifier(&region["id"])?;
        require(
            by_id.insert(id, region).is_none(),
            "repeated region identity",
        )?;
        match region["kind"].as_str() {
            Some("free") => require(
                region["owner"].is_null(),
                "free region cannot have an owner",
            )?,
            Some("protected") => {
                require(
                    matches!(
                        region["owner"].as_str(),
                        Some("windows" | "shared-esp" | "other")
                    ),
                    "invalid protected owner",
                )?;
                windows |= region["owner"] == "windows";
            }
            _ => return Err(Error("invalid region kind".into())),
        }
        spans.push(span(region, size)?);
    }
    disjoint(spans)?;
    require(
        windows == !inventory["windows_firmware"].is_null(),
        "Windows ownership/mode declaration mismatch",
    )?;
    fields(
        plan,
        "schema_version inventory_sha256 device_id loader secure_boot encryption root swap recovery allocations",
    )?;
    fixed(
        &plan["schema_version"],
        json!(1),
        "plan version unsupported",
    )?;
    fixed(
        &plan["inventory_sha256"],
        json!(fingerprint(inventory)?),
        "stale or mismatched inventory digest",
    )?;
    fixed(
        &plan["device_id"],
        inventory["device_id"].clone(),
        "wrong target identity",
    )?;
    fixed(
        &plan["loader"],
        json!(if firmware == "uefi" {
            "systemd-boot"
        } else {
            "limine"
        }),
        "loader/firmware mismatch",
    )?;
    fixed(
        &plan["secure_boot"],
        json!(security),
        "plan must preserve firmware security state",
    )?;
    fields(&plan["encryption"], "kind explicit_opt_out")?;
    require(
        matches!(plan["encryption"]["kind"].as_str(), Some("luks2" | "none")),
        "unsupported encryption",
    )?;
    fixed(
        &plan["encryption"]["explicit_opt_out"],
        json!(plan["encryption"]["kind"] == "none"),
        "encryption opt-out must be explicit and consistent",
    )?;
    fixed(
        &plan["root"],
        json!({"filesystem":"btrfs","compression":true,"separate_home_history":true,"os_rollback_reverts_home":false}),
        "root/home contract mismatch",
    )?;
    fixed(
        &plan["swap"],
        json!({"kind":"btrfs-swapfile","separate_subvolume":true,"nocow":true,"compression":false,"snapshots":false,"backups":false,"zram":true,"zswap":false,"inside_luks_when_enabled":true}),
        "swap contract mismatch",
    )?;
    fixed(
        &plan["recovery"],
        json!("independent-on-disk"),
        "independent recovery required",
    )?;
    let allocations = plan["allocations"]
        .as_array()
        .ok_or_else(|| Error("invalid allocations".into()))?;
    require(
        allocations.len() == 3,
        "requires boot/root/recovery allocation intents",
    )?;
    let (mut roles, mut spans) = (BTreeSet::new(), Vec::new());
    for allocation in allocations {
        fields(allocation, "free_region role start_bytes size_bytes")?;
        let role = allocation["role"]
            .as_str()
            .ok_or_else(|| Error("invalid allocation role".into()))?;
        require(
            matches!(role, "boot" | "root" | "recovery") && roles.insert(role),
            "invalid or repeated allocation role",
        )?;
        let region_id = allocation["free_region"]
            .as_str()
            .ok_or_else(|| Error("unknown free-space identity".into()))?;
        let region = by_id
            .get(region_id)
            .ok_or_else(|| Error("unknown free-space identity".into()))?;
        require(
            region["kind"] == "free",
            "protected space cannot be allocated or resized",
        )?;
        let (start, end) = span(allocation, size)?;
        let (low, high) = span(region, size)?;
        require(
            low <= start && end <= high,
            "allocation escapes supplied free space",
        )?;
        spans.push((start, end));
    }
    disjoint(spans)?;
    Ok(
        json!({"contract_valid":true,"synthetic_only":true,"plan_sha256":fingerprint(plan)?,"execution_available":false,"release_qualified":false,
        "limitations":["caller-supplied-inventory-is-not-device-discovery","no-backend-or-privilege-authorization","no-boot-or-resume-qualification","advanced-layout-and-shared-esp-adapters-not-implemented","fixture-sizes-and-alignment-are-not-selected-layout-defaults"]}),
    )
}
