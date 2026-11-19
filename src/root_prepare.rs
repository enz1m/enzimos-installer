// SPDX-License-Identifier: MIT
//! Durable format-to-root preparation handoff. Uncertain preparation never replays.
pub use crate::mapper::kernel_uuid;
use crate::{
    answer_source::Source,
    erase,
    format::{self, PartitionFile},
    mapper::Mapper,
};
use enzimos_platform::{Error, Result, files, json, process, require};
use serde_json::{Value, json as value};
use std::{collections::BTreeSet, path::Path, time::Duration};

pub fn admit<'a>(body: &'a Value, boot: &str, disk: &Value, encrypted: bool) -> Result<&'a Value> {
    json::fields(
        body,
        "schema state boot disk plan result encrypted formatted",
    )?;
    require(
        body["schema"] == 1
            && body["state"] == "formatted"
            && body["boot"] == boot
            && body["disk"] == *disk
            && body["encrypted"] == encrypted,
        "root preparation requires this boot's unattempted formatted allocation",
    )?;
    let partitioned = value!({"schema":1,"state":"partitioned","boot":boot,"disk":disk,"plan":body["plan"],"result":body["result"]});
    format::admitted_receipt(&partitioned, boot, disk)?;
    json::fields(&body["result"], "bios esp root plan")?;
    let mut names = BTreeSet::new();
    let alongside = crate::allocation::alongside(&body["plan"]);
    if alongside {
        require(
            body["result"]["bios"].is_null(),
            "alongside cannot own a BIOS partition",
        )?;
    }
    for key in ["bios", "esp", "root"] {
        if alongside && key == "bios" {
            continue;
        }
        let name = body["result"][key]
            .as_str()
            .ok_or_else(|| Error("formatted partition path missing".into()))?;
        crate::answers::disk_path(name)?;
        require(
            Path::new(name).parent() == Some(Path::new("/dev"))
                && name != disk["path"].as_str().unwrap_or("")
                && names.insert(name),
            "formatted partition paths ambiguous",
        )?;
    }
    json::fields(
        &body["formatted"],
        "bios esp root plan esp_filesystem root_filesystem",
    )?;
    require(
        ["bios", "esp", "root", "plan"]
            .iter()
            .all(|key| body["formatted"][*key] == body["result"][*key]),
        "formatted allocation changed",
    )?;
    for (key, kind) in [
        ("esp_filesystem", "vfat"),
        (
            "root_filesystem",
            if encrypted { "crypto_LUKS" } else { "btrfs" },
        ),
    ] {
        let fs = &body["formatted"][key];
        json::fields(fs, "type uuid")?;
        require(
            fs["type"] == kind,
            "formatted root encryption or ESP type differs",
        )?;
        let uuid = fs["uuid"]
            .as_str()
            .ok_or_else(|| Error("formatted filesystem UUID missing".into()))?;
        if kind == "vfat" {
            enzimos_policy::recovery_records::fat_uuid(uuid)?;
        } else {
            enzimos_policy::identity::uuid(uuid)?;
        }
    }
    Ok(&body["formatted"])
}
pub fn prepare(source: &Source) -> Result<Value> {
    let session = crate::install_session::Session::open(source)?;
    prepare_session(source, &session)
}
pub(crate) fn prepare_session(
    source: &Source,
    session: &crate::install_session::Session,
) -> Result<Value> {
    session.recheck(source)?;
    let disk = session.disk();
    let (path, boot) = erase::receipt_path(disk)?;
    let mut allocation_journal = crate::allocation::Journal::open(&path)?;
    let bytes = files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)?;
    let mut receipt = allocation_journal.body()?;
    require(
        json::canonical(&receipt)? == bytes,
        "allocation journal byte binding differs",
    )?;
    let formatted = admit(
        &receipt,
        &boot,
        &disk.observation()?,
        source.answers.encrypted,
    )?
    .clone();
    crate::allocation::mode(&formatted["plan"], source.answers.partition)?;
    require(
        formatted["plan"]["sector"] == disk.sector_size()?,
        "formatted allocation sector changed",
    )?;
    let table = process::run(
        "/usr/bin/sfdisk",
        &["--json", disk.path.to_str().unwrap()],
        &[],
        Duration::from_secs(30),
        2 * 1024 * 1024,
    )?;
    require(
        table.status.success()
            && crate::allocation::verify(
                &formatted["plan"],
                &json::decode(&table.stdout, 2 * 1024 * 1024)?["partitiontable"],
            )? == receipt["result"],
        "formatted allocation GPT changed",
    )?;
    let root = PartitionFile::open(
        disk,
        formatted["root"].as_str().unwrap(),
        crate::allocation::number(&formatted["plan"], 2)?,
        formatted["plan"]["partitions"][2]["size"].as_u64().unwrap()
            * formatted["plan"]["sector"].as_u64().unwrap(),
    )?;
    let esp = PartitionFile::open(
        disk,
        formatted["esp"].as_str().unwrap(),
        crate::allocation::number(&formatted["plan"], 1)?,
        formatted["plan"]["partitions"][1]["size"].as_u64().unwrap()
            * formatted["plan"]["sector"].as_u64().unwrap(),
    )?;
    for (partition, key, kind) in [
        (
            &root,
            "root_filesystem",
            if source.answers.encrypted {
                "crypto_LUKS"
            } else {
                "btrfs"
            },
        ),
        (&esp, "esp_filesystem", "vfat"),
    ] {
        let readback = partition.run(
            source,
            disk,
            "/usr/bin/blkid",
            &["--probe", "--output", "export", "@fd:0"],
            &[],
            Duration::from_secs(30),
        )?;
        require(
            format::filesystem(&readback, kind)? == formatted[key],
            "formatted filesystem identity changed before preparation",
        )?;
    }
    let name = format!("enzimos-install-{}", files::random_hex(16)?);
    session.recheck(source)?;
    disk.idle()?;
    require(
        files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)? == bytes,
        "formatted receipt changed before preparation",
    )?;
    receipt["state"] = value!("root-preparing");
    receipt["mapper"] = if source.answers.encrypted {
        value!(name)
    } else {
        Value::Null
    };
    let prepared_bytes = json::canonical(&receipt)?;
    allocation_journal.replace(&receipt)?;
    require(
        files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)? == prepared_bytes,
        "root preparation intent readback differs",
    )?;
    let attempt: Result<Value> = (|| {
        if !source.answers.encrypted {
            // Already formatted by the previous phase: never repeat mkfs.
            root.recheck(disk)?;
            session.recheck(source)?;
            return Ok(formatted["root_filesystem"].clone());
        }
        let mut mapper = Mapper::open(
            source,
            disk,
            &root,
            formatted["root_filesystem"]["uuid"].as_str().unwrap(),
            &name,
        )?;
        let prepared = (|| {
            mapper.run(
                source,
                disk,
                &root,
                "/usr/bin/mkfs.btrfs",
                &["--force", "--label", "ENZIMOS_ROOT", "@fd:0"],
                Duration::from_secs(120),
            )?;
            let probe = mapper.run(
                source,
                disk,
                &root,
                "/usr/bin/blkid",
                &["--probe", "--output", "export", "@fd:0"],
                Duration::from_secs(30),
            )?;
            format::filesystem(&probe, "btrfs")
        })();
        // Even failed mkfs gets one normal, identity-bound cleanup attempt.
        let closed = mapper.close(source, disk, &root);
        match (prepared, closed) {
            (Ok(fs), Ok(())) => Ok(fs),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    })();
    require(
        files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)? == prepared_bytes,
        "root preparation receipt changed during attempt",
    )?;
    match &attempt {
        Ok(fs) => {
            session.recheck(source)?;
            disk.idle()?;
            receipt["state"] = value!("root-ready");
            receipt["root_filesystem"] = fs.clone();
        }
        Err(_) => receipt["state"] = value!("uncertain"),
    }
    let final_bytes = json::canonical(&receipt)?;
    allocation_journal.replace(&receipt)?;
    require(
        files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)? == final_bytes,
        "root preparation completion readback differs",
    )?;
    attempt
}
