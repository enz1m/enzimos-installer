// SPDX-License-Identifier: MIT
use enzimos_platform::{
    Error, Result,
    json::{self, fingerprint},
    process, require,
};
use serde_json::{Value, json as value};
use std::os::unix::fs::FileExt;
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
fn protective_mbr(sector: &[u8; 512], disk_sectors: u64) -> Result<()> {
    let mut protective_entries = 0;
    for row in sector[446..510].chunks_exact(16) {
        if row == [0; 16] {
            continue;
        }
        require(
            row[0] == 0
                && row[4] == 0xee
                && row[8..12] == 1u32.to_le_bytes()
                && row[12..16]
                    == ((disk_sectors - 1).min(u64::from(u32::MAX)) as u32).to_le_bytes(),
            "Alongside installation requires a standard protective MBR. Hybrid or nonstandard disks are left unchanged.",
        )?;
        protective_entries += 1;
    }
    require(
        sector[510..] == [0x55, 0xaa] && protective_entries == 1,
        "Alongside installation requires a valid protective MBR.",
    )
}

pub fn observe(disk: &str) -> Result<Value> {
    let retained = crate::disk_guard::Disk::open(disk)?;
    let disk = retained.path.to_str().unwrap();
    let mut mbr = [0; 512];
    let file = std::fs::File::from(retained.descriptor().try_clone_to_owned()?);
    file.read_exact_at(&mut mbr, 0)?;
    protective_mbr(&mbr, retained.bytes / retained.sector_size()?)?;
    let verified = process::run_with_fds(
        "/usr/bin/sfdisk",
        &["--verify", "@fd:0"],
        &[],
        Duration::from_secs(30),
        65536,
        &[retained.descriptor()],
    )?;
    require(
        verified.status.success() && verified.stderr.is_empty(),
        "Alongside installation requires an intact GPT.",
    )?;
    let tree = json::decode(
        cmd(
            "lsblk",
            &[
                "--json",
                "--bytes",
                "--paths",
                "--output",
                "NAME,TYPE,SIZE,RO,MOUNTPOINTS,FSTYPE,UUID,SERIAL,MAJ:MIN,DISK-SEQ",
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
            && devices[0]["disk-seq"] == retained.sequence()?
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
fn make_plan(state: &Value, start: u64, size: u64) -> Result<Value> {
    let sector = sector(&state["table"])?;
    require(
        mul(size, sector)? >= MIN_ROOT + BOOT_SIZE,
        "At least 24 GiB is needed for enzimOS and its boot files.",
    )?;
    let mut p = value!({"schema":1,"disk":state["disk"],"before_sha256":fingerprint(state)?,"start":start,"size":size,"sector":sector,"shrink":null});
    p["id"] = value!(fingerprint(&p)?);
    Ok(p)
}
pub fn inspect(disk: &str) -> Result<Value> {
    inspect_with_minimum(disk, MIN_ROOT + BOOT_SIZE)
}

pub fn inspect_with_minimum(disk: &str, minimum: u64) -> Result<Value> {
    let minimum = minimum.max(MIN_ROOT + BOOT_SIZE);
    let state = observe(disk)?;
    let table = &state["table"];
    let sector = sector(table)?;
    let mut plans = Vec::new();
    for (start, size) in free_regions(table)? {
        if mul(size, sector)? >= minimum {
            let mut p = make_plan(&state, start, size)?;
            p["label"] = value!("Use unallocated space");
            plans.push(p);
        }
    }
    Ok(
        value!({"schema":1,"disk":state["disk"],"partitions":table["partitions"],"plans":plans,"uefi":Path::new("/sys/firmware/efi").exists()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_mbr_and_stale_protective_geometry_refuse_alongside() {
        let mut mbr = [0; 512];
        mbr[450] = 0xee;
        mbr[454..458].copy_from_slice(&1u32.to_le_bytes());
        mbr[458..462].copy_from_slice(&65535u32.to_le_bytes());
        mbr[510..].copy_from_slice(&[0x55, 0xaa]);
        assert!(protective_mbr(&mbr, 65536).is_ok());
        assert!(protective_mbr(&mbr, 65537).is_err());
        mbr[466] = 0x07;
        assert!(protective_mbr(&mbr, 65536).is_err());
    }
}
