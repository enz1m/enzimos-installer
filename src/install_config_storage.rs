// SPDX-License-Identifier: MIT
//! Fresh swap and Snapper allocation in the already measured installation scope.
use crate::{install_config_tools as tools, media_packages::Admitted, package_handoff::Received};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use enzimos_policy::{filesystem, subvolume};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
};
fn absent(directory: &File, name: &str) -> Result<()> {
    for (index, entry) in files::directory_names(directory, 4096)?
        .into_iter()
        .enumerate()
    {
        require(index < 4096, "fresh configuration directory member bound")?;
        require(
            entry != name,
            "fresh allocation refuses an existing file, link or subvolume",
        )?;
    }
    Ok(())
}
pub(crate) fn memory_kib() -> Result<u64> {
    let bytes = files::read_kernel(Path::new("/proc/meminfo"), 65536)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error("kernel memory encoding".into()))?;
    let rows = text
        .lines()
        .filter(|s| s.starts_with("MemTotal:"))
        .collect::<Vec<_>>();
    require(rows.len() == 1, "kernel memory total missing or ambiguous")?;
    let fields = rows[0].split_whitespace().collect::<Vec<_>>();
    require(
        fields.len() == 3 && fields[2] == "kB",
        "kernel memory units differ",
    )?;
    fields[1]
        .parse()
        .map_err(|_| Error("kernel memory total type".into()))
}
fn snapshot(root: &File, path: &str, uuid: &Value) -> Result<Value> {
    let dir = files::directory_relative(root, Path::new(path), Some(0))?;
    let m = dir.metadata()?;
    let (subvolume, readonly) = subvolume::observe(dir.as_fd(), path)?;
    require(
        !readonly
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o022 == 0
            && subvolume["parent_uuid"].is_null()
            && filesystem::observe(dir.as_fd())?["filesystem_uuid"] == *uuid,
        "fresh Snapper container kernel lineage differs",
    )?;
    Ok(
        value!({"subvolume":subvolume,"mount":mount_identity::id(dir.as_fd(),true)?,"inode":[m.dev(),m.ino(),m.uid(),m.gid(),m.mode()]}),
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl, sysconf).")]
fn swap(root: &File, mib: u32, uuid: &Value) -> Result<Value> {
    let directory = files::directory_relative(root, Path::new("swap"), Some(0))?;
    let (container, readonly) = subvolume::observe(directory.as_fd(), "enzimos-swap")?;
    require(
        !readonly
            && container["parent_uuid"].is_null()
            && filesystem::observe(directory.as_fd())?["filesystem_uuid"] == *uuid,
        "swap must remain in its original writable non-snapshot subvolume",
    )?;
    let file = files::open_relative(&directory, Path::new("swapfile"))?;
    let m = file.metadata()?;
    require(
        m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 1
            && m.len() == u64::from(mib) * 1024 * 1024,
        "new swap file authority, links or exact size differs",
    )?;
    let mut flags: libc::c_long = 0;
    require(
        unsafe { libc::ioctl(file.as_raw_fd(), 0x80086601u64 as libc::c_ulong, &mut flags) } == 0
            && flags & 0x800000 != 0,
        "new swap file is not kernel-confirmed NOCOW",
    )?;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    require((4096..=65536).contains(&page), "kernel swap page bound")?;
    let mut magic = [0u8; 10];
    require(
        file.read_at(&mut magic, page as u64 - 10)? == 10 && magic == *b"SWAPSPACE2",
        "new swap file header differs",
    )?;
    file.sync_all()?;
    Ok(
        value!({"mib":mib,"container":container,"mount":mount_identity::id(file.as_fd(),true)?,"inode":files::identity(&m),"flags":flags}),
    )
}
fn config_hash(root: &File, name: &str) -> Result<String> {
    let file = files::open_relative(root, Path::new(name))?;
    Ok(json::sha256(&files::read_file(
        &file,
        65536,
        Some(0),
        true,
    )?))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
pub(crate) fn create(context: &Received, media: &Admitted) -> Result<Value> {
    context.recheck()?;
    media.recheck()?;
    let source = context
        .answers
        .as_ref()
        .ok_or_else(|| Error("storage configuration requires original answers".into()))?;
    let uuid = &context.request["configuration"]["filesystem_uuid"];
    let swapdir = files::directory_relative(&context.target, Path::new("swap"), Some(0))?;
    absent(&swapdir, "swapfile")?;
    absent(&context.target, ".snapshots")?;
    let home = files::directory_relative(&context.target, Path::new("home"), Some(0))?;
    absent(&home, ".snapshots")?;
    let configs = files::ensure_directory_relative(
        &context.target,
        Path::new("etc/snapper/configs"),
        0o755,
        0,
    )?;
    absent(&configs, "root")?;
    absent(&configs, "home")?;
    let mib = crate::system_config::swap_size(source.answers.swap_mib, memory_kib()?)?;
    let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatvfs(swapdir.as_raw_fd(), &mut space) } == 0
            && u128::from(space.f_bavail) * u128::from(space.f_frsize)
                >= u128::from(mib + 256) * 1024 * 1024,
        "new installation lacks space for requested swap plus configuration reserve",
    )?;
    tools::run(
        context,
        media,
        "/usr/bin/btrfs",
        &[
            "filesystem",
            "mkswapfile",
            "--size",
            &format!("{mib}m"),
            "/swap/swapfile",
        ],
        &[],
    )?;
    let swap = swap(&context.target, mib, uuid)?;
    for (name, path) in [("root", "/"), ("home", "/home")] {
        tools::run(
            context,
            media,
            "/usr/bin/snapper",
            &["--no-dbus", "-c", name, "create-config", path],
            &[],
        )?;
    }
    tools::run(
        context,
        media,
        "/usr/bin/snapper",
        &[
            "--no-dbus",
            "-c",
            "root",
            "set-config",
            "TIMELINE_CREATE=no",
            "NUMBER_LIMIT=10",
            "NUMBER_LIMIT_IMPORTANT=5",
        ],
        &[],
    )?;
    tools::run(
        context,
        media,
        "/usr/bin/snapper",
        &[
            "--no-dbus",
            "-c",
            "home",
            "set-config",
            "TIMELINE_CREATE=no",
            // Home history (hourly, enzimos-home-history.timer): like Time
            // Machine, a day of hourlies, two weeks of dailies, two months of
            // weeklies, half a year of monthlies and one yearly. The history
            // service also keeps 15% of the disk free by removing the oldest.
            "TIMELINE_LIMIT_HOURLY=24",
            "TIMELINE_LIMIT_DAILY=14",
            "TIMELINE_LIMIT_WEEKLY=8",
            "TIMELINE_LIMIT_MONTHLY=6",
            "TIMELINE_LIMIT_YEARLY=1",
            "NUMBER_LIMIT=10",
            "NUMBER_LIMIT_IMPORTANT=10",
        ],
        &[],
    )?;
    let root_snapshot = snapshot(&context.target, ".snapshots", uuid)?;
    let home_snapshot = snapshot(&context.target, "home/.snapshots", uuid)?;
    require(
        root_snapshot["subvolume"]["uuid"] != home_snapshot["subvolume"]["uuid"],
        "Snapper containers must have distinct kernel UUIDs",
    )?;
    let result = value!({"swap":swap,"root_snapshots":root_snapshot,"home_snapshots":home_snapshot,
        "root_config_sha256":config_hash(&context.target,"etc/snapper/configs/root")?,"home_config_sha256":config_hash(&context.target,"etc/snapper/configs/home")?});
    verify(&context.target, &result, uuid)?;
    context.recheck()?;
    media.recheck()?;
    Ok(result)
}
pub(crate) fn validate(body: &Value) -> Result<()> {
    json::fields(
        body,
        "swap root_snapshots home_snapshots root_config_sha256 home_config_sha256",
    )?;
    for key in ["root_config_sha256", "home_config_sha256"] {
        enzimos_policy::identity::sha(
            body[key]
                .as_str()
                .ok_or_else(|| Error("Snapper configuration digest missing".into()))?,
        )?;
    }
    json::fields(&body["swap"], "mib container mount inode flags")?;
    require(
        body["swap"]["mib"]
            .as_u64()
            .is_some_and(|n| (256..=65536).contains(&n)),
        "swap receipt size bound",
    )?;
    let mib = body["swap"]["mib"].as_u64().unwrap();
    crate::private_file::validate_inode(&body["swap"]["inode"], 0o600, mib * 1024 * 1024)?;
    require(
        body["swap"]["inode"][2].as_u64() == Some(mib * 1024 * 1024)
            && body["swap"]["mount"].as_u64().is_some_and(|n| n > 0)
            && body["swap"]["flags"]
                .as_i64()
                .is_some_and(|n| n > 0 && n & 0x800000 != 0),
        "swap receipt kernel flags, mount or exact size",
    )?;
    volume(&body["swap"]["container"], "enzimos-swap")?;
    for key in ["root_snapshots", "home_snapshots"] {
        json::fields(&body[key], "subvolume mount inode")?;
        volume(
            &body[key]["subvolume"],
            if key == "root_snapshots" {
                ".snapshots"
            } else {
                "home/.snapshots"
            },
        )?;
        let a = body[key]["inode"]
            .as_array()
            .ok_or_else(|| Error("Snapper container inode binding type".into()))?;
        require(
            a.len() == 5
                && a.iter().all(Value::is_u64)
                && a[0].as_u64().unwrap() > 0
                && a[1].as_u64().unwrap() > 0
                && a[2] == 0
                && a[3] == 0
                && a[4].as_u64().is_some_and(|n| {
                    n <= u64::from(u32::MAX)
                        && n as u32 & libc::S_IFMT == libc::S_IFDIR
                        && n & 0o022 == 0
                })
                && body[key]["mount"].as_u64().is_some_and(|n| n > 0),
            "Snapper container unique mount or private inode binding",
        )?;
    }
    Ok(())
}
fn volume(body: &Value, path: &str) -> Result<()> {
    json::fields(body, "path id uuid parent_uuid")?;
    require(
        body["path"] == path
            && body["id"].as_u64().is_some_and(|n| n >= 256)
            && body["parent_uuid"].is_null(),
        "fresh storage container lineage differs",
    )?;
    enzimos_policy::identity::uuid(
        body["uuid"]
            .as_str()
            .ok_or_else(|| Error("fresh storage container UUID type".into()))?,
    )
    .map(|_| ())
}
pub(crate) fn verify(root: &File, body: &Value, uuid: &Value) -> Result<()> {
    validate(body)?;
    let mib = body["swap"]["mib"].as_u64().unwrap() as u32;
    require(
        swap(root, mib, uuid)? == body["swap"]
            && snapshot(root, ".snapshots", uuid)? == body["root_snapshots"]
            && snapshot(root, "home/.snapshots", uuid)? == body["home_snapshots"]
            && config_hash(root, "etc/snapper/configs/root")? == body["root_config_sha256"]
            && config_hash(root, "etc/snapper/configs/home")? == body["home_config_sha256"],
        "configuration storage changed before completion",
    )
}
