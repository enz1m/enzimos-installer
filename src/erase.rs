// SPDX-License-Identifier: MIT
//! One boot-local erase attempt. A refused or uncertain attempt is never replayed.
use crate::{answer_source::Source, answers::Partition, disk_guard::Disk};
use enzimos_platform::{Error, Result, files, json, process, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const BIOS: &str = "21686148-6449-6e6f-744e-656564454649";
const ESP: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
const ROOT: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
pub fn layout(bytes: u64, sector: u64, disk: &str, guids: &[String; 4]) -> Result<Value> {
    require(
        matches!(sector, 512 | 4096) && bytes >= 24 * GIB && bytes.is_multiple_of(sector),
        "erase disk geometry refused",
    )?;
    crate::answers::disk_path(disk)?;
    for guid in guids {
        enzimos_policy::identity::uuid(guid)?;
    }
    require(
        guids.iter().collect::<BTreeSet<_>>().len() == 4,
        "distinct new GPT identities required",
    )?;
    // Reserve a full MiB for the backup GPT, then align root's end down to a MiB.
    let end = (bytes - MIB) / MIB * (MIB / sector);
    let unit = MIB / sector;
    let root_start = 2 * unit + 4 * GIB / sector;
    require(
        end > root_start && (end - root_start) * sector >= 19 * GIB,
        "erase root geometry too small",
    )?;
    Ok(
        value!({"schema":1,"disk":disk,"bytes":bytes,"sector":sector,"label_id":guids[0],"partitions":[
            {"number":1,"start":unit,"size":unit,"type":BIOS,"name":"enzimos-bios","uuid":guids[1]},
            {"number":2,"start":2*unit,"size":4*GIB/sector,"type":ESP,"name":"enzimos-esp","uuid":guids[2]},
            {"number":3,"start":root_start,"size":end-root_start,"type":ROOT,"name":"enzimos-root","uuid":guids[3]}
        ]}),
    )
}
fn guid() -> Result<String> {
    let s = files::random_hex(16)?;
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &s[..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..]
    ))
}
/// systemd-repart definitions for the reviewed layout. Every partition has its
/// reviewed UUID, label, type and exact byte size, so repart's allocation (first
/// partition at 1 MiB, then contiguous) reproduces the reviewed sectors; the
/// readback still verifies that instead of assuming it.
pub fn definitions(plan: &Value) -> Result<Vec<(String, String)>> {
    let rows = plan["partitions"]
        .as_array()
        .ok_or_else(|| Error("erase plan shape".into()))?;
    require(rows.len() == 3, "erase partition count")?;
    let sector = plan["sector"]
        .as_u64()
        .ok_or_else(|| Error("erase sector missing".into()))?;
    enzimos_policy::identity::uuid(
        plan["label_id"]
            .as_str()
            .ok_or_else(|| Error("erase disk GUID missing".into()))?,
    )?;
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            let size = row["size"]
                .as_u64()
                .and_then(|size| size.checked_mul(sector))
                .ok_or_else(|| Error("erase size missing".into()))?;
            let kind = row["type"]
                .as_str()
                .ok_or_else(|| Error("erase type missing".into()))?;
            let uuid = row["uuid"]
                .as_str()
                .ok_or_else(|| Error("erase UUID missing".into()))?;
            let name = row["name"]
                .as_str()
                .ok_or_else(|| Error("erase name missing".into()))?;
            enzimos_policy::identity::uuid(kind)?;
            enzimos_policy::identity::uuid(uuid)?;
            require(
                matches!(name, "enzimos-bios" | "enzimos-esp" | "enzimos-root"),
                "erase partition name refused",
            )?;
            Ok((
                format!("{}-{name}.conf", 10 * (index + 1)),
                format!(
                    "[Partition]\nType={kind}\nLabel={name}\nUUID={uuid}\nSizeMinBytes={size}\nSizeMaxBytes={size}\n"
                ),
            ))
        })
        .collect()
}
/// repart derives the disk GUID from its seed; adopt the GUID it wrote once it
/// is a valid identity distinct from every reviewed partition UUID.
pub fn realize(plan: &Value, table: &Value) -> Result<Value> {
    let text = table["id"]
        .as_str()
        .ok_or_else(|| Error("new GPT disk identity missing".into()))?;
    require(
        text.len() == 36 && text.is_ascii(),
        "vendor GPT GUID encoding",
    )?;
    let id = text.to_ascii_lowercase();
    enzimos_policy::identity::uuid(&id)?;
    let rows = plan["partitions"]
        .as_array()
        .ok_or_else(|| Error("erase plan partitions missing".into()))?;
    require(
        rows.iter().all(|row| row["uuid"] != value!(id)),
        "new GPT disk identity collides with a partition",
    )?;
    let mut realized = plan.clone();
    realized["label_id"] = value!(id);
    Ok(realized)
}
pub fn verify(plan: &Value, table: &Value) -> Result<Value> {
    // libfdisk renders binary GUIDs in uppercase. Normalize only these typed
    // vendor fields; names, device paths, geometry and plan bytes remain exact.
    let guid = |v: &Value| -> Result<String> {
        let text = v
            .as_str()
            .ok_or_else(|| Error("vendor GPT GUID text required".into()))?;
        require(
            text.len() == 36 && text.is_ascii(),
            "vendor GPT GUID encoding",
        )?;
        let canonical = text.to_ascii_lowercase();
        enzimos_policy::identity::uuid(&canonical)?;
        Ok(canonical)
    };
    require(
        table["label"] == "gpt"
            && table["device"] == plan["disk"]
            && guid(&table["id"])? == plan["label_id"]
            && table["sectorsize"] == plan["sector"],
        "new GPT disk identity changed",
    )?;
    let actual = table["partitions"]
        .as_array()
        .ok_or_else(|| Error("new GPT partitions missing".into()))?;
    let expected = plan["partitions"]
        .as_array()
        .ok_or_else(|| Error("erase plan partitions missing".into()))?;
    require(
        actual.len() == 3 && expected.len() == 3,
        "unexpected new GPT partition count",
    )?;
    let actual = actual
        .iter()
        .map(|row| {
            let mut row = row.clone();
            let uuid = guid(&row["uuid"])?;
            let kind = guid(&row["type"])?;
            require(row.is_object(), "vendor GPT partition object required")?;
            row["uuid"] = value!(uuid);
            row["type"] = value!(kind);
            Ok(row)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut names = BTreeSet::new();
    let mut paths = Vec::new();
    for row in expected {
        let matches = actual
            .iter()
            .filter(|p| p["uuid"] == row["uuid"])
            .collect::<Vec<_>>();
        require(matches.len() == 1, "new partition GUID ambiguous")?;
        let p = matches[0];
        require(
            ["start", "size", "type", "name"]
                .iter()
                .all(|key| p[*key] == row[*key]),
            "new partition geometry differs from reviewed plan",
        )?;
        let node = p["node"]
            .as_str()
            .ok_or_else(|| Error("new partition node missing".into()))?;
        crate::answers::disk_path(node)?;
        require(
            node != plan["disk"].as_str().unwrap_or("") && names.insert(node),
            "new partition path ambiguous",
        )?;
        paths.push(node);
    }
    Ok(value!({"bios":paths[0],"esp":paths[1],"root":paths[2],"plan":plan}))
}
fn tool(source: &Source, disk: &Disk, program: &str, args: &[&str], input: &[u8]) -> Result<()> {
    source.recheck()?;
    disk.idle()?;
    let write = disk.begin_write(match program {
        "/usr/bin/wipefs" => "whole-disk-wipe",
        "/usr/bin/systemd-repart" => "whole-disk-gpt",
        "/usr/bin/sfdisk" => "whole-disk-gpt",
        _ => return Err(Error("erase writer outside closed role registry".into())),
    })?;
    let output = process::run_with_fds(
        program,
        args,
        input,
        Duration::from_secs(120),
        65536,
        &[disk.descriptor()],
    )?;
    require(
        output.status.success(),
        "disk erase tool failed; inspect this attempt before any further operation",
    )?;
    let write = write.settle()?;
    source.recheck()?;
    disk.observed_write(write)
}
pub(crate) fn receipt_path(disk: &Disk) -> Result<(PathBuf, String)> {
    let boot = files::read_kernel(Path::new("/proc/sys/kernel/random/boot_id"), 4096)?;
    let boot = std::str::from_utf8(&boot)
        .map_err(|_| Error("boot ID encoding".into()))?
        .trim()
        .to_owned();
    enzimos_policy::identity::uuid(&boot)?;
    // A replacement at the selected device name must not reset admission.
    // The receipt body separately binds its exact inode and kernel sequence.
    let key = json::fingerprint(&value!({"boot":boot,"selected_disk":disk.path}))?;
    Ok((
        Path::new("/run/enzimos-install-native").join(format!("erase-{key}.json")),
        boot,
    ))
}
pub fn apply(source: &Source) -> Result<Value> {
    source.recheck()?;
    require(
        source.answers.partition == Partition::Erase,
        "erase mode and explicit confirmation required",
    )?;
    let media = crate::media_packages::Admitted::open_checked(
        source.answers.gpu,
        source.answers.verify_media,
    )?;
    apply_admitted(source, &media)
}
/// The complete coordinator retains this admission across every storage phase.
pub fn apply_admitted(source: &Source, media: &crate::media_packages::Admitted) -> Result<Value> {
    let session = crate::install_session::Session::open(source)?;
    apply_session(source, media, &session)
}
pub(crate) fn apply_session(
    source: &Source,
    media: &crate::media_packages::Admitted,
    session: &crate::install_session::Session,
) -> Result<Value> {
    session.recheck(source)?;
    media.recheck()?;
    require(
        source.answers.partition == Partition::Erase,
        "erase mode and explicit confirmation required",
    )?;
    require(
        !source.answers.desktop
            || media.manifest["desktop_preview_files"]
                .as_u64()
                .is_some_and(|count| count > 0),
        "requested desktop overlay absent before erase",
    )?;
    let disk = session.disk();
    require(
        !media.media.physical_leaves().contains(&disk.number),
        "installation medium cannot be the erase target",
    )?;
    let sector = disk.sector_size()?;
    let guids = [guid()?, guid()?, guid()?, guid()?];
    let plan = layout(disk.bytes, sector, disk.path.to_str().unwrap(), &guids)?;
    let directory = Path::new("/run/enzimos-install-native");
    files::ensure_directory(directory, 0o700, 0)?;
    // Geometry changes do not produce another receipt key within this boot.
    let (receipt, boot) = receipt_path(disk)?;
    session.recheck(source)?;
    disk.idle()?;
    media.recheck()?;
    let body =
        value!({"schema":1,"state":"started","boot":boot,"disk":disk.observation()?,"plan":plan});
    files::atomic(&receipt, &json::canonical(&body)?, 0o600, Some(0), false)?;
    // Private, root-only definitions for this attempt; never reused.
    let definitions_directory = directory.join(format!(
        "repart-{}",
        receipt
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| Error("erase receipt name".into()))?
    ));
    let attempted = (|| {
        files::ensure_directory(&definitions_directory, 0o700, 0)?;
        for (name, body) in definitions(&plan)? {
            files::atomic(
                &definitions_directory.join(name),
                body.as_bytes(),
                0o600,
                Some(0),
                true,
            )?;
        }
        let definitions_argument = format!("--definitions={}", definitions_directory.display());
        let seed = format!("--seed={}", plan["label_id"].as_str().unwrap_or_default());
        session.recheck(source)?;
        media.recheck()?;
        tool(
            source,
            disk,
            "/usr/bin/wipefs",
            &["--all", "--force", "@fd:0"],
            &[],
        )?;
        session.recheck(source)?;
        media.recheck()?;
        tool(
            source,
            disk,
            "/usr/bin/systemd-repart",
            &[
                "--empty=force",
                "--dry-run=no",
                "--discard=no",
                "--no-pager",
                &definitions_argument,
                &seed,
                "@fd:0",
            ],
            &[],
        )?;
        // repart marks the root for systemd-growfs whatever GrowFileSystem=
        // says; growing the LUKS root at every boot can only fail.
        session.recheck(source)?;
        media.recheck()?;
        tool(
            source,
            disk,
            "/usr/bin/sfdisk",
            &["--part-attrs", "@fd:0", "3", ""],
            &[],
        )?;
        let settled = process::run(
            "/usr/bin/udevadm",
            &["settle", "--timeout=30"],
            &[],
            Duration::from_secs(35),
            65536,
        )?;
        require(
            settled.status.success(),
            "new disk partition discovery failed",
        )?;
        session.recheck(source)?;
        disk.idle()?;
        let output = process::run(
            "/usr/bin/sfdisk",
            &["--json", disk.path.to_str().unwrap()],
            &[],
            Duration::from_secs(30),
            2 * 1024 * 1024,
        )?;
        require(output.status.success(), "new GPT readback failed")?;
        let table = json::decode(&output.stdout, 2 * 1024 * 1024)?;
        let realized = realize(&plan, &table["partitiontable"])?;
        let result = verify(&realized, &table["partitiontable"])?;
        disk.idle()?;
        session.recheck(source)?;
        Ok(result)
    })();
    let mut final_body = body;
    match &attempted {
        Ok(result) => {
            final_body["disk"] = disk.observation()?;
            final_body["plan"] = result["plan"].clone();
            final_body["state"] = value!("partitioned");
            final_body["result"] = result.clone();
        }
        Err(_) => final_body["state"] = value!("uncertain"),
    }
    files::atomic(
        &receipt,
        &json::canonical(&final_body)?,
        0o600,
        Some(0),
        true,
    )?;
    attempted
}
