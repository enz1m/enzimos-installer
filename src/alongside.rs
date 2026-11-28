// SPDX-License-Identifier: MIT
//! Reviewed UEFI allocation, retaining the original disk, lock and signed media.
use crate::{
    allocation, answer_source::Source, answers::Partition, install_session::Session,
    media_packages::Admitted,
};
use enzimos_platform::{Error, Result, files, json, process, require};
use serde_json::{Value, json as value};
use std::{path::Path, time::Duration};
const MIB: u64 = 1024 * 1024;
fn number(v: &Value) -> Result<u64> {
    v.as_u64()
        .ok_or_else(|| Error("alongside geometry missing".into()))
}
fn text(v: &Value) -> Result<&str> {
    v.as_str()
        .ok_or_else(|| Error("alongside text missing".into()))
}
fn random_guid() -> Result<String> {
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
fn table(source: &Source, session: &Session) -> Result<Value> {
    session.recheck(source)?;
    let output = process::run(
        "/usr/bin/sfdisk",
        &["--json", session.disk().path.to_str().unwrap()],
        &[],
        Duration::from_secs(30),
        2 * 1024 * 1024,
    )?;
    require(output.status.success(), "alongside GPT readback failed")?;
    session.recheck(source)?;
    Ok(json::decode(&output.stdout, 2 * 1024 * 1024)?["partitiontable"].clone())
}
#[derive(Clone, Copy)]
enum GptOperation {
    Preview,
    Write,
}
impl GptOperation {
    fn role(self, args: &[&str]) -> Result<&'static str> {
        let previews = args.iter().filter(|arg| **arg == "--no-act").count();
        require(
            previews == usize::from(matches!(self, Self::Preview)),
            "GPT operation and preview argument differ",
        )?;
        Ok(match self {
            Self::Preview => "gpt-preview-device-events",
            Self::Write => "whole-disk-gpt",
        })
    }
}
// sfdisk reports the inherited /proc descriptor spelling as its device label.
// Reservation receipts can occupy additional descriptors between the two reads;
// normalize only that spelling and its validated canonical partition suffixes.
fn descriptor_labels(mut table: Value) -> Result<Value> {
    let alias = text(&table["device"])?.to_owned();
    let fd = alias
        .strip_prefix("/proc/self/fd/")
        .ok_or_else(|| Error("GPT original descriptor label missing".into()))?;
    let number = fd
        .parse::<u32>()
        .map_err(|_| Error("GPT descriptor number invalid".into()))?;
    require(
        number >= 64 && fd == number.to_string(),
        "GPT descriptor number not canonical",
    )?;
    let rows = table["partitions"]
        .as_array_mut()
        .ok_or_else(|| Error("GPT partitions missing".into()))?;
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let number = allocation::partition_number(&alias, text(&row["node"])?)?;
        require(seen.insert(number), "GPT duplicate partition number")?;
        row["node"] = value!(format!("original-partition:{number}"));
    }
    table["device"] = value!("original-device");
    Ok(table)
}
fn pinned_table(session: &Session) -> Result<Value> {
    let output = process::run_with_fds(
        "/usr/bin/sfdisk",
        &["--json", "@fd:0"],
        &[],
        Duration::from_secs(30),
        2 * 1024 * 1024,
        &[session.disk().descriptor()],
    )?;
    require(output.status.success(), "original GPT readback failed")?;
    descriptor_labels(json::decode(&output.stdout, 2 * 1024 * 1024)?["partitiontable"].clone())
}
fn gpt(
    source: &Source,
    media: &Admitted,
    session: &Session,
    args: &[&str],
    input: &[u8],
    operation: GptOperation,
) -> Result<()> {
    let role = operation.role(args)?;
    session.recheck(source)?;
    media.recheck()?;
    session.disk().idle()?;
    let before = if matches!(operation, GptOperation::Preview) {
        Some(pinned_table(session)?)
    } else {
        None
    };
    // Even a successful --no-act call queues udev timestamp refreshes. Retain
    // the original one-use reservation through settlement; independently prove
    // that a preview left the actual GPT unchanged before observing its epoch.
    let epoch = session.disk().begin_write(role)?;
    let output = process::run_with_fds(
        "/usr/bin/sfdisk",
        args,
        input,
        Duration::from_secs(120),
        65536,
        &[session.disk().descriptor()],
    )?;
    require(
        output.status.success(),
        "alongside GPT tool failed; no replay allowed",
    )?;
    let epoch = epoch.settle()?;
    if let Some(before) = before {
        require(
            pinned_table(session)? == before,
            "GPT preview changed original table",
        )?;
        epoch.checkpoint()?;
    }
    source.recheck()?;
    media.recheck()?;
    session.disk().observed_write(epoch)?;
    session.recheck(source)?;
    media.recheck()
}
fn settle(source: &Source, session: &Session) -> Result<()> {
    let output = process::run(
        "/usr/bin/udevadm",
        &["settle", "--timeout=30"],
        &[],
        Duration::from_secs(35),
        65536,
    )?;
    require(
        output.status.success(),
        "alongside partition discovery failed",
    )?;
    session.recheck(source)?;
    session.disk().idle().map(|_| ())
}
fn filesystem(bytes: &[u8], kind: &str) -> Result<Value> {
    if kind == "ext4" {
        return crate::format::filesystem(bytes, kind);
    }
    require(kind == "ntfs", "unsupported existing filesystem")?;
    let body = std::str::from_utf8(bytes).map_err(|_| Error("NTFS probe encoding".into()))?;
    let mut fields = std::collections::BTreeMap::new();
    for line in body.lines() {
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| Error("NTFS probe shape".into()))?;
        require(
            fields.len() < 32 && !v.chars().any(char::is_control) && fields.insert(k, v).is_none(),
            "NTFS probe ambiguous",
        )?;
    }
    let uuid = fields
        .get("UUID")
        .ok_or_else(|| Error("NTFS UUID missing".into()))?;
    require(
        fields.get("TYPE") == Some(&"ntfs")
            && uuid.len() == 16
            && uuid.bytes().all(|b| b.is_ascii_hexdigit()),
        "NTFS filesystem identity invalid",
    )?;
    Ok(value!({"type":kind,"uuid":uuid}))
}
fn shrink(source: &Source, media: &Admitted, session: &Session, plan: &Value) -> Result<()> {
    let shrink = &plan["review"]["shrink"];
    if shrink.is_null() {
        return Ok(());
    }
    let row = plan["before"]["table"]["partitions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["node"] == shrink["node"])
        .ok_or_else(|| Error("original shrink partition missing".into()))?;
    let node = text(&row["node"])?;
    let sector = number(&plan["sector"])?;
    let part = crate::format::PartitionFile::open(
        session.disk(),
        node,
        allocation::partition_number(text(&plan["disk"])?, node)?,
        number(&row["size"])?
            .checked_mul(sector)
            .ok_or_else(|| Error("existing partition byte overflow".into()))?,
    )?;
    let kind = text(&shrink["filesystem"])?;
    let probe = |part: &crate::format::PartitionFile| -> Result<Value> {
        filesystem(
            &part.run(
                source,
                session.disk(),
                "/usr/bin/blkid",
                &["--probe", "--output", "export", "@fd:0"],
                &[],
                Duration::from_secs(30),
            )?,
            kind,
        )
    };
    let before = probe(&part)?;
    let device = plan["before"]["devices"][0]["children"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == node)
        .unwrap();
    require(
        before["uuid"] == device["uuid"],
        "original shrink filesystem UUID changed",
    )?;
    let bytes = number(&shrink["new_size"])?
        .checked_mul(sector)
        .and_then(|n| n.checked_sub(MIB))
        .ok_or_else(|| Error("filesystem shrink byte overflow".into()))?;
    session.recheck(source)?;
    media.recheck()?;
    if kind == "ext4" {
        part.run(
            source,
            session.disk(),
            "/usr/bin/e2fsck",
            &["-fn", "@fd:0"],
            &[],
            Duration::from_secs(600),
        )?;
        part.run(
            source,
            session.disk(),
            "/usr/bin/e2fsck",
            &["-f", "-p", "@fd:0"],
            &[],
            Duration::from_secs(600),
        )?;
        part.run(
            source,
            session.disk(),
            "/usr/bin/resize2fs",
            &["@fd:0", &format!("{}K", bytes / 1024)],
            &[],
            Duration::from_secs(600),
        )?;
        part.run(
            source,
            session.disk(),
            "/usr/bin/e2fsck",
            &["-fn", "@fd:0"],
            &[],
            Duration::from_secs(600),
        )?;
    } else {
        part.run(
            source,
            session.disk(),
            "/usr/bin/ntfsresize",
            &["--no-action", "--size", &bytes.to_string(), "@fd:0"],
            b"y\n",
            Duration::from_secs(600),
        )?;
        part.run(
            source,
            session.disk(),
            "/usr/bin/ntfsresize",
            &["--size", &bytes.to_string(), "@fd:0"],
            b"y\n",
            Duration::from_secs(600),
        )?;
    }
    require(
        probe(&part)? == before,
        "shrinking changed original filesystem identity",
    )?;
    drop(part);
    // Resize only this reviewed GPT row after successful filesystem shrink.
    // The allocation intent is already durable; failure never permits retry.
    let partn = allocation::partition_number(text(&plan["disk"])?, node)?.to_string();
    let input = format!(", {}\n", number(&shrink["new_size"])?);
    gpt(
        source,
        media,
        session,
        &[
            "--no-act",
            "--wipe",
            "never",
            "--wipe-partitions",
            "never",
            "-N",
            &partn,
            "@fd:0",
        ],
        input.as_bytes(),
        GptOperation::Preview,
    )?;
    gpt(
        source,
        media,
        session,
        &[
            "--wipe",
            "never",
            "--wipe-partitions",
            "never",
            "-N",
            &partn,
            "@fd:0",
        ],
        input.as_bytes(),
        GptOperation::Write,
    )?;
    settle(source, session)?;
    let actual = table(source, session)?;
    let expected = allocation::effective_table(&plan["before"], &plan["review"])?;
    require(
        actual == expected,
        "shrinking changed unrelated GPT metadata",
    )?;
    let resized = crate::format::PartitionFile::open(
        session.disk(),
        node,
        allocation::partition_number(text(&plan["disk"])?, node)?,
        number(&shrink["new_size"])?
            .checked_mul(sector)
            .ok_or_else(|| Error("resized partition byte overflow".into()))?,
    )?;
    require(
        probe(&resized)? == before,
        "resized partition filesystem identity differs",
    )?;
    media.recheck()
}
pub(crate) fn apply(source: &Source, media: &Admitted, session: &Session) -> Result<Value> {
    session.recheck(source)?;
    media.recheck()?;
    session.disk().idle()?;
    require(
        source.answers.partition == Partition::Alongside
            && source.boot_security.receipt()?["firmware"]["uefi"] == true,
        "alongside allocation requires reviewed UEFI answers",
    )?;
    require(
        !media
            .media
            .physical_leaves()
            .contains(&session.disk().number),
        "installation medium cannot be the alongside target",
    )?;
    let inspected = crate::partition::inspect(session.disk().path.to_str().unwrap())?;
    let id = source
        .answers
        .partition_plan
        .as_deref()
        .ok_or_else(|| Error("alongside reviewed plan missing".into()))?;
    let review = inspected["plans"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == id)
        .ok_or_else(|| Error("alongside disk layout changed after review".into()))?;
    let region_bytes = number(&review["sector"])?
        .checked_mul(number(&review["size"])?)
        .ok_or_else(|| Error("alongside geometry overflow".into()))?;
    crate::install_capacity::check(region_bytes, media, &source.answers)?;
    let before = crate::partition::observe(session.disk().path.to_str().unwrap())?;
    let plan = allocation::alongside_plan(
        &before,
        review,
        &session.disk().observation()?,
        &[random_guid()?, random_guid()?],
    )?;
    require(
        plan["sector"] == session.disk().sector_size()?,
        "reviewed alongside kernel sector changed",
    )?;
    let dump = process::run_with_fds(
        "/usr/bin/sfdisk",
        &["--dump", "@fd:0"],
        &[],
        Duration::from_secs(30),
        65536,
        &[session.disk().descriptor()],
    )?;
    require(dump.status.success(), "alongside original GPT dump failed")?;
    session.recheck(source)?;
    media.recheck()?;
    require(
        crate::partition::observe(session.disk().path.to_str().unwrap())? == before,
        "alongside observation changed before intent",
    )?;
    let (path, boot) = crate::erase::receipt_path(session.disk())?;
    let directory = Path::new("/run/enzimos-install-native");
    files::ensure_directory(directory, 0o700, 0)?;
    // The stable boot/disk key excludes every previous mode and uncertain
    // attempt. The exact original dump is retained before any repair or resize.
    files::atomic_bounded(
        &path.with_extension("sfdisk"),
        &dump.stdout,
        0o600,
        Some(0),
        false,
        65536,
    )?;
    let mut body = value!({"schema":1,"state":"started","boot":boot,"disk":session.disk().observation()?,"plan":plan});
    let mut journal = allocation::Journal::create(&path, &body)?;
    let attempt = (|| {
        journal.recheck()?;
        session.recheck(source)?;
        media.recheck()?;
        shrink(source, media, session, &plan)?;
        let script = allocation::append_script(&plan)?;
        gpt(
            source,
            media,
            session,
            &[
                "--no-act",
                "--append",
                "--wipe",
                "never",
                "--wipe-partitions",
                "never",
                "@fd:0",
            ],
            script.as_bytes(),
            GptOperation::Preview,
        )?;
        journal.recheck()?;
        gpt(
            source,
            media,
            session,
            &[
                "--append",
                "--wipe",
                "never",
                "--wipe-partitions",
                "never",
                "@fd:0",
            ],
            script.as_bytes(),
            GptOperation::Write,
        )?;
        settle(source, session)?;
        let result = allocation::verify(&plan, &table(source, session)?)?;
        session.recheck(source)?;
        media.recheck()?;
        Ok(result)
    })();
    match &attempt {
        Ok(result) => {
            body["disk"] = session.disk().observation()?;
            body["state"] = value!("partitioned");
            body["result"] = result.clone();
        }
        Err(_) => body["state"] = value!("uncertain"),
    };
    journal.replace(&body)?;
    attempt
}

#[cfg(test)]
mod operation_tests {
    use super::*;
    #[test]
    fn preview_reservation_requires_exactly_one_no_act_argument() {
        assert_eq!(
            GptOperation::Preview
                .role(&["--no-act", "--append", "@fd:0"])
                .unwrap(),
            "gpt-preview-device-events"
        );
        assert!(GptOperation::Preview.role(&["--append", "@fd:0"]).is_err());
        assert!(
            GptOperation::Preview
                .role(&["--no-act", "--no-act", "@fd:0"])
                .is_err()
        );
        assert!(GptOperation::Write.role(&["--no-act", "@fd:0"]).is_err());
        assert_eq!(
            GptOperation::Write.role(&["--append", "@fd:0"]).unwrap(),
            "whole-disk-gpt"
        );
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;
    fn table(fd: u32) -> Value {
        value!({"device":format!("/proc/self/fd/{fd}"),"label":"gpt","id":"same","partitions":[{"node":format!("/proc/self/fd/{fd}p1"),"start":2048,"size":100,"uuid":"same"}]})
    }
    #[test]
    fn inherited_descriptor_spelling_changes_do_not_change_gpt_geometry() {
        assert_eq!(
            descriptor_labels(table(64)).unwrap(),
            descriptor_labels(table(70)).unwrap()
        );
        let mut changed = table(70);
        changed["partitions"][0]["size"] = value!(101);
        assert_ne!(
            descriptor_labels(table(64)).unwrap(),
            descriptor_labels(changed).unwrap()
        );
        for label in ["/dev/vda1", "/proc/self/fd/65p1", "/proc/self/fd/64p01"] {
            let mut invalid = table(64);
            invalid["partitions"][0]["node"] = value!(label);
            assert!(descriptor_labels(invalid).is_err());
        }
        let mut duplicate = table(64);
        let row = duplicate["partitions"][0].clone();
        duplicate["partitions"].as_array_mut().unwrap().push(row);
        assert!(descriptor_labels(duplicate).is_err());
        assert!(descriptor_labels(table(3)).is_err());
    }
}
