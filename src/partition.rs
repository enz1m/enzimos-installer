// SPDX-License-Identifier: MIT
use enzimos_platform::{
    Error, Result,
    json::{self, fingerprint},
    process, require,
};
use serde_json::{Value, json as value};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::time::Duration;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const MIN_ROOT: u64 = 20 * GIB;
const BOOT_SIZE: u64 = 4 * GIB;

fn number(v: &Value) -> Result<u64> {
    v.as_u64()
        .ok_or_else(|| Error("invalid partition number".into()))
}
fn text(v: &Value) -> Result<&str> {
    v.as_str()
        .ok_or_else(|| Error("invalid partition field".into()))
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| Error("partition arithmetic overflow".into()))
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| Error("partition arithmetic overflow".into()))
}
fn align(n: u64, unit: u64) -> Result<u64> {
    Ok(add(n, unit - 1)? / unit * unit)
}
fn command(program: &str, args: &[&str], input: &str, codes: &[i32]) -> Result<String> {
    process::output(
        &format!("/usr/bin/{program}"),
        args,
        input.as_bytes(),
        Duration::from_secs(1800),
        codes,
    )
}
fn cmd(program: &str, args: &[&str]) -> Result<String> {
    command(program, args, "", &[0])
}
fn sector(table: &Value) -> Result<u64> {
    let sector = if table["sectorsize"].is_null() {
        512
    } else {
        number(&table["sectorsize"])?
    };
    require(matches!(sector, 512 | 4096), "Unsupported sector size.")?;
    Ok(sector)
}
fn partitions(table: &Value) -> Result<&Vec<Value>> {
    table["partitions"]
        .as_array()
        .ok_or_else(|| Error("missing partition table".into()))
}
fn visit(node: &Value, depth: usize) -> Result<()> {
    require(
        depth <= 16 && matches!(node["type"].as_str(), Some("disk" | "part")),
        "The disk has active storage mappings.",
    )?;
    require(
        node["mountpoints"]
            .as_array()
            .is_none_or(|a| a.iter().all(|p| p.is_null() || p == "")),
        "The disk is in use. Unmount its volumes first.",
    )?;
    let dev = text(&node["maj:min"])?;
    require(
        dev.split_once(':').is_some_and(|(a, b)| {
            !a.is_empty() && !b.is_empty() && a.bytes().chain(b.bytes()).all(|c| c.is_ascii_digit())
        }),
        "Invalid block identity.",
    )?;
    let holders = Path::new("/sys/dev/block").join(dev).join("holders");
    if holders.exists() {
        require(
            std::fs::read_dir(holders)?.next().is_none(),
            "Disk has active storage mappings.",
        )?;
    }
    if let Some(children) = node["children"].as_array() {
        for child in children {
            visit(child, depth + 1)?;
        }
    }
    Ok(())
}
pub fn observe(disk: &str) -> Result<Value> {
    let retained = crate::disk_guard::Disk::open(disk)?;
    require(
        disk.strip_prefix("/dev/")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric())),
        "Select a whole disk.",
    )?;
    let metadata = std::fs::symlink_metadata(disk)?;
    require(
        metadata.file_type().is_block_device(),
        "Select an actual block disk.",
    )?;
    let tree = json::decode(
        cmd(
            "lsblk",
            &[
                "--json",
                "--bytes",
                "--paths",
                "--output",
                "NAME,TYPE,SIZE,RO,MOUNTPOINTS,FSTYPE,UUID,SERIAL,MAJ:MIN",
                disk,
            ],
        )?
        .as_bytes(),
        2 * 1024 * 1024,
    )?;
    let devices = tree["blockdevices"]
        .as_array()
        .ok_or_else(|| Error("invalid disk observation".into()))?;
    require(
        devices.len() == 1
            && devices[0]["name"] == disk
            && devices[0]["type"] == "disk"
            && (devices[0]["ro"] == false || devices[0]["ro"] == 0),
        "Disk is not writable.",
    )?;
    visit(&devices[0], 0)?;
    let table = json::decode(
        cmd("sfdisk", &["--json", disk])?.as_bytes(),
        2 * 1024 * 1024,
    )?["partitiontable"]
        .clone();
    require(
        table["label"] == "gpt" && table["device"] == disk,
        "Alongside installation requires GPT. Existing MBR disks are not changed.",
    )?;
    sector(&table)?;
    require(
        partitions(&table)?.len() <= 120,
        "No room for additional GPT entries.",
    )?;
    free_regions(&table)?;
    retained.recheck()?;
    Ok(value!({"disk":disk,"table":table,"devices":devices}))
}
pub fn free_regions(table: &Value) -> Result<Vec<(u64, u64)>> {
    let unit = MIB / sector(table)?;
    let first = number(&table["firstlba"])?;
    let last = add(number(&table["lastlba"])?, 1)?;
    require(first < last, "invalid usable GPT bounds")?;
    let mut cursor = align(first, unit)?;
    let mut raw_end = first;
    let mut entries = partitions(table)?.iter().collect::<Vec<_>>();
    entries.sort_by_key(|p| p["start"].as_u64().unwrap_or(0));
    let mut out = Vec::new();
    for p in entries {
        let start = number(&p["start"])?;
        let size = number(&p["size"])?;
        let end = add(start, size)?;
        require(
            size > 0 && start >= raw_end && end <= last,
            "overlapping or invalid existing partitions",
        )?;
        let free_end = start / unit * unit;
        if free_end > cursor {
            out.push((cursor, free_end - cursor));
        }
        raw_end = end;
        cursor = align(end, unit)?;
    }
    let end = last / unit * unit;
    if end > cursor {
        out.push((cursor, end - cursor));
    }
    Ok(out)
}
fn make_plan(state: &Value, start: u64, size: u64, shrink: Value) -> Result<Value> {
    let sector = sector(&state["table"])?;
    require(
        mul(size, sector)? >= MIN_ROOT + BOOT_SIZE,
        "At least 24 GiB is needed for enzimOS and its boot files.",
    )?;
    let mut p = value!({"schema":1,"disk":state["disk"],"before_sha256":fingerprint(state)?,"start":start,"size":size,"sector":sector,"shrink":shrink});
    p["id"] = value!(fingerprint(&p)?);
    Ok(p)
}
fn filesystem_number(info: &str, key: &str) -> Result<u64> {
    let s = info
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .ok_or_else(|| Error("missing filesystem geometry".into()))?;
    s.trim()
        .parse()
        .map_err(|_| Error("invalid filesystem geometry".into()))
}
pub fn inspect(disk: &str) -> Result<Value> {
    let state = observe(disk)?;
    let table = &state["table"];
    let sector = sector(table)?;
    let mut plans = Vec::new();
    for (start, size) in free_regions(table)? {
        if mul(size, sector)? >= MIN_ROOT + BOOT_SIZE {
            let mut p = make_plan(&state, start, size, Value::Null)?;
            p["label"] = value!("Use unallocated space");
            plans.push(p);
        }
    }
    let devices = state["devices"][0]["children"].as_array();
    for p in partitions(table)? {
        let node = text(&p["node"])?;
        let fs = devices
            .and_then(|a| a.iter().find(|d| d["name"] == node))
            .and_then(|d| d["fstype"].as_str())
            .unwrap_or("");
        let size = mul(number(&p["size"])?, sector)?;
        let new = size / 2 / MIB * MIB;
        if !matches!(fs, "ext4" | "ntfs") || size - new < MIN_ROOT + BOOT_SIZE {
            continue;
        }
        let checked: Result<()> = (|| {
            if fs == "ext4" {
                cmd("e2fsck", &["-fn", node])?;
                let info = cmd("dumpe2fs", &["-h", node])?;
                let block = filesystem_number(&info, "Block size:")?;
                let count = filesystem_number(&info, "Block count:")?;
                let free = filesystem_number(&info, "Free blocks:")?;
                require(
                    free <= count && new >= add(mul(count - free, block)?, 2 * GIB)?,
                    "insufficient filesystem free space",
                )?;
            } else {
                command(
                    "ntfsresize",
                    &["--no-action", "--size", &(new - MIB).to_string(), node],
                    "y\n",
                    &[0],
                )?;
            }
            Ok(())
        })();
        if checked.is_err() {
            continue;
        }
        let start = align(add(number(&p["start"])?, new / sector)?, MIB / sector)?;
        let end = add(number(&p["start"])?, number(&p["size"])?)? / (MIB / sector) * (MIB / sector);
        // MiB alignment of an unaligned partition can cost almost 2 MiB; a region
        // that falls below the minimum is not offered rather than failing the
        // whole disk inspection (and every other plan with it).
        if end <= start || mul(end - start, sector)? < MIN_ROOT + BOOT_SIZE {
            continue;
        }
        let shrink = value!({"node":node,"filesystem":fs,"old_size":p["size"],"new_size":start - number(&p["start"])?});
        let mut plan = make_plan(&state, start, end - start, shrink)?;
        plan["label"] = value!(format!("Make space on {node} ({fs})"));
        plans.push(plan);
    }
    Ok(
        value!({"schema":1,"disk":disk,"partitions":table["partitions"],"plans":plans,"uefi":Path::new("/sys/firmware/efi").exists()}),
    )
}
