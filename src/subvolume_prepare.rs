// SPDX-License-Identifier: MIT
//! One-shot allocation of installation subvolumes; no package execution yet.
pub use crate::mount_owner::row_matches;
use crate::{
    answer_source::Source,
    disk_guard::Disk,
    erase,
    format::{self, PartitionFile},
    mapper::Mapper,
    mount_admission::Baseline,
    mount_owner::Top,
    root_prepare,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, process, require};
use enzimos_policy::{filesystem, subvolume};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::Duration,
};
const NAMES: &[&str] = &[
    "enzimos-root",
    "enzimos-home",
    "enzimos-control",
    "enzimos-authority",
    "enzimos-swap",
];
fn initial_permissions(name: &str) -> Result<u32> {
    match name {
        // systemd's root.conf protects / with 0555. Establish it on the new
        // actual subvolume before a mount owner or sealed worker epoch exists;
        // subsequent tmpfiles normalization must not change that epoch.
        "enzimos-root" => Ok(0o555),
        "enzimos-control" | "enzimos-authority" => Ok(0o700),
        "enzimos-home" | "enzimos-swap" => Ok(0o755),
        _ => Err(Error(
            "closed new installation subvolume role required".into(),
        )),
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, getegid, geteuid).")]
fn protect_new_directory(file: &File, name: &str) -> Result<()> {
    let mode = initial_permissions(name)?;
    let before = file.metadata()?;
    let mount = mount_identity::id(file.as_fd(), true)?;
    require(
        before.is_dir()
            && before.uid() == unsafe { libc::geteuid() }
            && before.gid() == unsafe { libc::getegid() }
            && before.mode() & 0o7022 == 0,
        "new owned installation directory protection required",
    )?;
    require(
        unsafe { libc::fchmod(file.as_raw_fd(), mode) } == 0,
        "new installation directory permission initialization failed",
    )?;
    let after = file.metadata()?;
    require(
        after.dev() == before.dev()
            && after.ino() == before.ino()
            && after.uid() == before.uid()
            && after.gid() == before.gid()
            && after.nlink() == before.nlink()
            && after.len() == before.len()
            && (after.mtime(), after.mtime_nsec()) == (before.mtime(), before.mtime_nsec())
            && (after.ctime(), after.ctime_nsec()) >= (before.ctime(), before.ctime_nsec())
            && after.mode() == libc::S_IFDIR | mode
            && mount_identity::id(file.as_fd(), true)? == mount,
        "original new installation directory changed during initialization",
    )?;
    file.sync_all()?;
    Ok(())
}
pub fn validate_subvolumes(body: &Value) -> Result<()> {
    json::fields(body, &NAMES.join(" "))?;
    let mut ids = std::collections::BTreeSet::new();
    let mut uuids = std::collections::BTreeSet::new();
    for name in NAMES {
        let entry = &body[*name];
        json::fields(entry, "path id uuid parent_uuid")?;
        let id = entry["id"]
            .as_u64()
            .ok_or_else(|| Error("installation subvolume ID missing".into()))?;
        let uuid = entry["uuid"]
            .as_str()
            .ok_or_else(|| Error("installation subvolume UUID missing".into()))?;
        enzimos_policy::identity::uuid(uuid)?;
        require(
            entry["path"] == *name
                && id >= 256
                && entry["parent_uuid"].is_null()
                && ids.insert(id)
                && uuids.insert(uuid),
            "installation subvolumes have duplicate or changed identities",
        )?;
    }
    Ok(())
}
pub fn admit<'a>(body: &'a Value, boot: &str, disk: &Value, encrypted: bool) -> Result<&'a Value> {
    json::fields(
        body,
        "schema state boot disk plan result encrypted formatted mapper root_filesystem",
    )?;
    require(
        body["state"] == "root-ready",
        "subvolume preparation requires an unattempted ready root",
    )?;
    let mut formatted = body.clone();
    let object = formatted
        .as_object_mut()
        .ok_or_else(|| Error("ready root receipt shape".into()))?;
    object.remove("mapper");
    object.remove("root_filesystem");
    object.insert("state".into(), value!("formatted"));
    root_prepare::admit(&formatted, boot, disk, encrypted)?;
    json::fields(&body["root_filesystem"], "type uuid")?;
    require(
        body["root_filesystem"]["type"] == "btrfs",
        "prepared root filesystem type differs",
    )?;
    enzimos_policy::identity::uuid(
        body["root_filesystem"]["uuid"]
            .as_str()
            .ok_or_else(|| Error("prepared root filesystem UUID missing".into()))?,
    )?;
    if encrypted {
        root_prepare::kernel_uuid(
            body["formatted"]["root_filesystem"]["uuid"]
                .as_str()
                .unwrap(),
            body["mapper"]
                .as_str()
                .ok_or_else(|| Error("prepared mapper identity missing".into()))?,
        )?;
    } else {
        require(
            body["mapper"].is_null()
                && body["root_filesystem"] == body["formatted"]["root_filesystem"],
            "plaintext root changed between preparation phases",
        )?;
    }
    Ok(&body["root_filesystem"])
}
fn check(
    source: &Source,
    disk: &Disk,
    root: &PartitionFile,
    esp: &PartitionFile,
    mapper: Option<&Mapper>,
    baseline: &Baseline,
    top: Option<&Top>,
) -> Result<()> {
    source.recheck()?;
    root.identity(disk)?;
    esp.identity(disk)?;
    if let Some(mapper) = mapper {
        mapper.identity(source, disk, root)?;
    }
    if let Some(top) = top {
        top.recheck()?;
    }
    let owned = mapper
        .map(|m| root.number().map(|number| (number, m.number)))
        .transpose()?;
    let proofs = top.map(|t| vec![t.proof.clone()]).unwrap_or_default();
    disk.mounted(owned, baseline, &proofs)
}
fn entries(top: &File) -> Result<Vec<String>> {
    let mut entries = Vec::new();
    for entry in files::directory_names(top, 8)? {
        require(
            entries.len() < 8,
            "fresh installation subvolume count bound",
        )?;
        entries.push(
            entry
                .into_string()
                .map_err(|_| Error("fresh subvolume name encoding".into()))?,
        );
    }
    entries.sort();
    Ok(entries)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn opened(top: &File, name: &str) -> Result<File> {
    let leaf = std::ffi::CString::new(name).unwrap();
    let raw = unsafe {
        libc::openat(
            top.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(
        raw >= 0,
        "new installation subvolume descriptor unavailable",
    )?;
    Ok(unsafe { File::from_raw_fd(raw) })
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
    let rootfs = admit(
        &receipt,
        &boot,
        &disk.observation()?,
        source.answers.encrypted,
    )?
    .clone();
    let formatted = receipt["formatted"].clone();
    crate::allocation::mode(&formatted["plan"], source.answers.partition)?;
    require(
        formatted["plan"]["sector"] == disk.sector_size()?,
        "prepared allocation sector changed",
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
        "prepared allocation GPT changed",
    )?;
    let sector = formatted["plan"]["sector"].as_u64().unwrap();
    let root = PartitionFile::open(
        disk,
        formatted["root"].as_str().unwrap(),
        crate::allocation::number(&formatted["plan"], 2)?,
        formatted["plan"]["partitions"][2]["size"].as_u64().unwrap() * sector,
    )?;
    let esp = PartitionFile::open(
        disk,
        formatted["esp"].as_str().unwrap(),
        crate::allocation::number(&formatted["plan"], 1)?,
        formatted["plan"]["partitions"][1]["size"].as_u64().unwrap() * sector,
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
        let bytes = partition.run(
            source,
            disk,
            "/usr/bin/blkid",
            &["--probe", "--output", "export", "@fd:0"],
            &[],
            Duration::from_secs(30),
        )?;
        require(
            format::filesystem(&bytes, kind)? == formatted[key],
            "prepared allocation filesystem changed",
        )?;
    }
    let baseline = Baseline::capture(disk.number)?;
    let attempt_id = files::random_hex(16)?;
    let name = format!("enzimos-install-{attempt_id}");
    let target = Path::new("/run/enzimos-install-native/mounts").join(&attempt_id);
    session.recheck(source)?;
    disk.idle()?;
    require(
        files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)? == bytes,
        "ready root receipt changed",
    )?;
    receipt["state"] = value!("subvolumes-preparing");
    receipt["subvolume_attempt"] = value!({"id":attempt_id,"mount":target,"mapper":if source.answers.encrypted {value!(name)} else {Value::Null}});
    let intent = json::canonical(&receipt)?;
    allocation_journal.replace(&receipt)?;
    require(
        files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)? == intent,
        "subvolume intent readback differs",
    )?;
    let attempt: Result<Value> = (|| {
        let mut mapper = if source.answers.encrypted {
            Some(Mapper::open(
                source,
                disk,
                &root,
                formatted["root_filesystem"]["uuid"].as_str().unwrap(),
                &name,
            )?)
        } else {
            None
        };
        let work: Result<Value> = (|| {
            if let Some(mapper) = &mapper {
                let probe = mapper.run(
                    source,
                    disk,
                    &root,
                    "/usr/bin/blkid",
                    &["--probe", "--output", "export", "@fd:0"],
                    Duration::from_secs(30),
                )?;
                require(
                    format::filesystem(&probe, "btrfs")? == rootfs,
                    "prepared inner filesystem changed",
                )?;
            }
            check(source, disk, &root, &esp, mapper.as_ref(), &baseline, None)?;
            let descriptor = match &mapper {
                Some(mapper) => mapper.descriptor()?,
                None => root.descriptor(),
            };
            let mut top = Top::open(descriptor, &target, rootfs["uuid"].as_str().unwrap())?;
            let created: Result<Value> = (|| {
                check(
                    source,
                    disk,
                    &root,
                    &esp,
                    mapper.as_ref(),
                    &baseline,
                    Some(&top),
                )?;
                require(
                    entries(top.directory()?)?.is_empty(),
                    "prepared filesystem is not empty; creation cannot replay",
                )?;
                let mut identities = serde_json::Map::new();
                for name in NAMES {
                    check(
                        source,
                        disk,
                        &root,
                        &esp,
                        mapper.as_ref(),
                        &baseline,
                        Some(&top),
                    )?;
                    subvolume::new(top.directory()?.as_fd(), name)?;
                    let subvol = opened(top.directory()?, name)?;
                    require(
                        subvol.metadata()?.ino() == 256
                            && subvol.metadata()?.uid() == 0
                            && subvol.metadata()?.gid() == 0
                            && filesystem::observe(subvol.as_fd())?["filesystem_uuid"]
                                == rootfs["uuid"],
                        "new original subvolume root or filesystem differs",
                    )?;
                    protect_new_directory(&subvol, name)?;
                    require(
                        subvol.metadata()?.mode() == libc::S_IFDIR | initial_permissions(name)?
                            && subvol.metadata()?.uid() == 0
                            && mount_identity::id(subvol.as_fd(), true)?
                                == mount_identity::id(top.directory()?.as_fd(), true)?
                            && filesystem::observe(subvol.as_fd())?["filesystem_uuid"]
                                == rootfs["uuid"],
                        "new subvolume owner, mount or filesystem differs",
                    )?;
                    let (identity, readonly) = subvolume::observe(subvol.as_fd(), name)?;
                    require(
                        !readonly && identity["parent_uuid"].is_null(),
                        "new subvolume has unexpected snapshot ancestry",
                    )?;
                    identities.insert((*name).into(), identity);
                }
                let mut expected = NAMES.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
                expected.sort();
                require(
                    entries(top.directory()?)? == expected,
                    "new subvolume inventory changed",
                )?;
                let result = Value::Object(identities);
                validate_subvolumes(&result)?;
                for name in NAMES {
                    let file = opened(top.directory()?, name)?;
                    let (identity, readonly) = subvolume::observe(file.as_fd(), name)?;
                    require(
                        !readonly
                            && file.metadata()?.mode()
                                == libc::S_IFDIR | initial_permissions(name)?
                            && file.metadata()?.uid() == 0
                            && file.metadata()?.gid() == 0
                            && identity == result[*name]
                            && mount_identity::id(file.as_fd(), true)?
                                == mount_identity::id(top.directory()?.as_fd(), true)?
                            && filesystem::observe(file.as_fd())?["filesystem_uuid"]
                                == rootfs["uuid"],
                        "created subvolume changed before durable handoff",
                    )?;
                }
                subvolume::sync(top.directory()?.as_fd())?;
                check(
                    source,
                    disk,
                    &root,
                    &esp,
                    mapper.as_ref(),
                    &baseline,
                    Some(&top),
                )?;
                Ok(result)
            })();
            // Drop every child FD before one normal, exact-owned unmount.
            let closed = top.close();
            drop(top); // also release the retained mapped block opener
            match (created, closed) {
                (Ok(result), Ok(())) => Ok(result),
                (Err(e), _) | (_, Err(e)) => Err(e),
            }
        })();
        let closed = if let Some(mapper) = &mut mapper {
            mapper.close(source, disk, &root)
        } else {
            disk.idle().map(|_| ())
        };
        match (work, closed) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    })();
    require(
        files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)? == intent,
        "subvolume attempt receipt changed",
    )?;
    match &attempt {
        Ok(result) => {
            session.recheck(source)?;
            disk.idle()?;
            receipt["state"] = value!("subvolumes-ready");
            receipt["subvolumes"] = result.clone();
        }
        Err(_) => receipt["state"] = value!("uncertain"),
    }
    let final_bytes = json::canonical(&receipt)?;
    allocation_journal.replace(&receipt)?;
    require(
        files::read(&path, crate::allocation::MAX_RECEIPT, Some(0), true)? == final_bytes,
        "subvolume completion readback differs",
    )?;
    attempt
}

#[cfg(test)]
mod permission_tests {
    use super::*;
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn actual_new_root_is_protected_before_worker_epoch_and_unknown_roles_do_not_mutate() {
        let work = std::path::PathBuf::from(
            std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        );
        let temp = tempfile::tempdir_in(work).unwrap();
        let file = files::directory(temp.path(), Some(unsafe { libc::geteuid() })).unwrap();
        let original = file.metadata().unwrap();
        protect_new_directory(&file, "enzimos-root").unwrap();
        let actual = file.metadata().unwrap();
        assert_eq!(
            (actual.dev(), actual.ino(), actual.uid(), actual.gid()),
            (
                original.dev(),
                original.ino(),
                original.uid(),
                original.gid()
            )
        );
        assert_eq!(actual.mode() & 0o7777, 0o555);
        let epoch = files::identity(&actual);
        assert!(protect_new_directory(&file, "arbitrary-role").is_err());
        assert_eq!(files::identity(&file.metadata().unwrap()), epoch);
        assert_eq!(initial_permissions("enzimos-control").unwrap(), 0o700);
        assert_eq!(initial_permissions("enzimos-authority").unwrap(), 0o700);
        assert_eq!(initial_permissions("enzimos-home").unwrap(), 0o755);
    }
}
