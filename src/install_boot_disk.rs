// SPDX-License-Identifier: MIT
//! The boot phase retains the original whole-disk description, never a pathname claim.
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use enzimos_policy::{block, topology};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
#[allow(unsafe_code, reason = "Linux syscall ABI (major, minor, openat).")]
pub(crate) fn observe(file: BorrowedFd<'_>, path: &str, filesystem: &str) -> Result<Value> {
    crate::setup::live()?;
    crate::answers::disk_path(path)?;
    // Answers may name the disk by a stable /dev/disk/by-* link; record the node.
    let path = &std::fs::canonicalize(path)?;
    require(
        path.parent() == Some(Path::new("/dev")),
        "canonical installation boot disk required",
    )?;
    let root = files::directory(Path::new("/dev"), Some(0))?;
    let name = std::ffi::CString::new(path.file_name().unwrap().as_encoded_bytes()).unwrap();
    let raw = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    require(raw >= 0, "original boot disk name unavailable")?;
    let named = unsafe { File::from_raw_fd(raw) };
    let held = File::from(file.try_clone_to_owned()?);
    let m = held.metadata()?;
    let number = (libc::major(m.rdev()), libc::minor(m.rdev()));
    let block = block::observe(held.as_fd())?;
    let graph = topology::observe(&[number])?;
    require(
        files::identity(&named.metadata()?) == files::identity(&m)
            && block["read_only"] == false
            && graph.leaves == std::collections::BTreeSet::from([number])
            && graph.nodes.len() == 1
            && graph.nodes[&number].disk_sequence.is_some()
            && topology::mounted_btrfs(filesystem)?.leaves == graph.leaves,
        "boot disk inode, whole-disk identity or original installation ancestry differs",
    )?;
    let mount = mount_identity::id(held.as_fd(), true)?;
    require(
        mount_identity::id(named.as_fd(), true)? == mount,
        "original boot disk device mount changed",
    )?;
    Ok(
        value!({"path":path,"block":block,"mount":mount,"inode":files::identity(&m),"graph":graph.json()}),
    )
}
pub(crate) fn validate(body: &Value) -> Result<()> {
    json::fields(body, "path block mount inode graph")?;
    let path = body["path"]
        .as_str()
        .ok_or_else(|| Error("installation boot disk path missing".into()))?;
    crate::answers::disk_path(path)?;
    require(
        Path::new(path).parent() == Some(Path::new("/dev"))
            && body["mount"].as_u64().is_some_and(|n| n > 0),
        "canonical boot disk mount binding",
    )?;
    json::fields(
        &body["block"],
        "major minor device_inode device_filesystem disk_sequence bytes read_only",
    )?;
    let block = &body["block"];
    require(
        block["read_only"] == false
            && block["bytes"]
                .as_u64()
                .is_some_and(|n| n > 0 && n < i64::MAX as u64)
            && block["major"]
                .as_u64()
                .is_some_and(|n| n <= u64::from(u32::MAX))
            && block["minor"]
                .as_u64()
                .is_some_and(|n| n <= u64::from(u32::MAX))
            && block["disk_sequence"].as_u64().is_some_and(|n| n > 0),
        "boot disk kernel state binding",
    )?;
    let a = body["inode"]
        .as_array()
        .ok_or_else(|| Error("boot disk inode binding type".into()))?;
    require(
        a.len() == 11
            && a.iter().all(|n| n.is_i64() || n.is_u64())
            && a[0] == block["device_filesystem"]
            && a[1] == block["device_inode"]
            && a[7].as_u64().is_some_and(|n| {
                n <= u64::from(u32::MAX)
                    && n as u32 & libc::S_IFMT == libc::S_IFBLK
                    && n & 0o002 == 0
            })
            && a[8] == 0
            && a[10] == 1,
        "boot disk protected block inode binding",
    )?;
    json::fields(&body["graph"], "nodes leaves")?;
    let nodes = body["graph"]["nodes"]
        .as_array()
        .ok_or_else(|| Error("boot disk kernel graph type".into()))?;
    let number = value!([block["major"], block["minor"]]);
    require(
        nodes.len() == 1 && body["graph"]["leaves"] == value!([number]),
        "boot disk must be one physical leaf",
    )?;
    json::fields(&nodes[0], "device path dependencies disk_sequence")?;
    require(
        nodes[0]["device"] == number
            && nodes[0]["dependencies"] == value!([])
            && nodes[0]["disk_sequence"] == block["disk_sequence"]
            && nodes[0]["path"].as_str().is_some_and(|s| {
                s.starts_with("/sys/devices/") && !s.split('/').any(|p| matches!(p, "." | ".."))
            }),
        "boot disk graph identity differs",
    )
}
