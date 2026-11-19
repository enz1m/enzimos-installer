// SPDX-License-Identifier: MIT
//! Link only reviewed per-user services into the freshly created UID/GID 1000 home.
use crate::package_handoff::Received;
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const SERVICES: [&str; 2] = ["enzui-center.service", "enzimos-activity.service"];
fn shape(directory: &File) -> Result<Value> {
    let m = directory.metadata()?;
    require(
        m.is_dir() && m.uid() == 1000 && m.gid() == 1000 && m.mode() & 0o7777 == 0o700,
        "fresh per-user configuration directory protection",
    )?;
    Ok(
        value!({"mount":mount_identity::id(directory.as_fd(),true)?,"inode":[m.dev(),m.ino(),m.uid(),m.gid(),m.mode()]}),
    )
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fchmod, fchown, mkdirat, openat)."
)]
fn child(parent: &File, name: &str) -> Result<File> {
    let c = std::ffi::CString::new(name).unwrap();
    let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) };
    if rc < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
        return Err(std::io::Error::last_os_error().into());
    }
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(raw >= 0, "fresh user configuration directory unavailable")?;
    let file = unsafe { File::from_raw_fd(raw) };
    let m = file.metadata()?;
    require(
        m.is_dir()
            && if rc == 0 {
                m.uid() == 0 && m.gid() == 0
            } else {
                m.uid() == 1000 && m.gid() == 1000 && m.mode() & 0o022 == 0
            },
        "new user configuration directory ownership differs",
    )?;
    if rc == 0 {
        require(
            unsafe { libc::fchown(file.as_raw_fd(), 1000, 1000) } == 0,
            "new user configuration ownership publication failed",
        )?;
    }
    require(
        unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } == 0,
        "new user configuration mode publication failed",
    )?;
    file.sync_all()?;
    parent.sync_all()?;
    shape(&file)?;
    Ok(file)
}
fn units(root: &File) -> Result<Value> {
    let source = files::directory_relative(root, Path::new("usr/lib/systemd/user"), Some(0))?;
    let mut units = serde_json::Map::new();
    for name in SERVICES {
        if let Some(file) = files::optional_relative(&source, Path::new(name))? {
            units.insert(
                name.into(),
                value!(json::sha256(&files::read_file(
                    &file,
                    65536,
                    Some(0),
                    true
                )?)),
            );
        }
    }
    Ok(Value::Object(units))
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fchownat, renameat2, symlinkat, unlinkat)."
)]
pub(crate) fn create(context: &Received) -> Result<Value> {
    context.recheck()?;
    let username = &context
        .answers
        .as_ref()
        .ok_or_else(|| Error("original session answers missing".into()))?
        .answers
        .username;
    let services = units(&context.target)?;
    let home_path = format!("home/{username}");
    let home = files::directory_relative(&context.target, Path::new(&home_path), Some(1000))?;
    let metadata = home.metadata()?;
    require(
        metadata.uid() == 1000 && metadata.gid() == 1000 && metadata.mode() & 0o022 == 0,
        "new administrator home protection differs",
    )?;
    let mut directory = home;
    for name in [".config", "systemd", "user", "default.target.wants"] {
        directory = child(&directory, name)?;
        context.recheck()?;
    }
    for name in services.as_object().unwrap().keys() {
        context.recheck()?;
        let name = std::ffi::CString::new(name.as_str()).unwrap();
        let target =
            std::ffi::CString::new(format!("/usr/lib/systemd/user/{}", name.to_str().unwrap()))
                .unwrap();
        let temporary =
            std::ffi::CString::new(format!(".enzimos-user-link-{}", files::random_hex(16)?))
                .unwrap();
        require(
            unsafe { libc::symlinkat(target.as_ptr(), directory.as_raw_fd(), temporary.as_ptr()) }
                == 0,
            "new user service link creation failed",
        )?;
        let result = (|| -> Result<()> {
            require(
                unsafe {
                    libc::fchownat(
                        directory.as_raw_fd(),
                        temporary.as_ptr(),
                        1000,
                        1000,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } == 0,
                "new user service link ownership failed",
            )?;
            require(
                unsafe {
                    libc::renameat2(
                        directory.as_raw_fd(),
                        temporary.as_ptr(),
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::RENAME_NOREPLACE,
                    )
                } == 0,
                "new user service link refuses preexisting skeleton state",
            )?;
            directory.sync_all()?;
            Ok(())
        })();
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) };
        result?;
    }
    let result = value!({"username":username,"uid":1000,"gid":1000,"wants":shape(&directory)?,"units":services});
    verify(&context.target, &result, username)?;
    context.recheck()?;
    Ok(result)
}
pub(crate) fn validate(body: &Value) -> Result<()> {
    json::fields(body, "username uid gid wants units")?;
    let username = body["username"]
        .as_str()
        .ok_or_else(|| Error("new user session identity missing".into()))?;
    require(
        crate::answers::ordinary_name(username) && body["uid"] == 1000 && body["gid"] == 1000,
        "new user session identity differs",
    )?;
    json::fields(&body["wants"], "mount inode")?;
    let a = body["wants"]["inode"]
        .as_array()
        .ok_or_else(|| Error("new user directory inode binding type".into()))?;
    require(
        a.len() == 5
            && a.iter().all(Value::is_u64)
            && a[0].as_u64().unwrap() > 0
            && a[1].as_u64().unwrap() > 0
            && a[2] == 1000
            && a[3] == 1000
            && a[4].as_u64() == Some(u64::from(libc::S_IFDIR | 0o700))
            && body["wants"]["mount"].as_u64().is_some_and(|n| n > 0),
        "new user service directory unique mount or inode binding",
    )?;
    let units = body["units"]
        .as_object()
        .ok_or_else(|| Error("new user service units missing".into()))?;
    require(
        units.len() <= SERVICES.len() && units.keys().all(|n| SERVICES.contains(&n.as_str())),
        "new user service outside closed registry",
    )?;
    for hash in units.values() {
        enzimos_policy::identity::sha(
            hash.as_str()
                .ok_or_else(|| Error("new user service digest type".into()))?,
        )?;
    }
    Ok(())
}
pub(crate) fn verify(root: &File, body: &Value, username: &str) -> Result<()> {
    validate(body)?;
    require(
        body["username"] == username && body["units"] == units(root)?,
        "new user session differs from original administrator or reviewed units",
    )?;
    let path = format!("home/{username}/.config/systemd/user/default.target.wants");
    let directory = files::directory_relative(root, Path::new(&path), Some(1000))?;
    require(
        shape(&directory)? == body["wants"],
        "new user service directory changed",
    )?;
    let mut found = std::collections::BTreeSet::new();
    for name in files::directory_names(&directory, SERVICES.len())? {
        let name = name
            .into_string()
            .map_err(|_| Error("new user service link encoding".into()))?;
        require(
            body["units"].get(&name).is_some() && found.insert(name.clone()),
            "new user service link outside admitted set",
        )?;
        let entry =
            enzimos_platform::directory_entry::Entry::observe(&directory, Path::new(&name))?;
        let metadata = entry.metadata()?;
        require(
            metadata.file_type().is_symlink()
                && metadata.uid() == 1000
                && metadata.gid() == 1000
                && metadata.nlink() == 1
                && entry.read_link(4096)? == Path::new("/usr/lib/systemd/user").join(&name),
            "new user service link changed",
        )?;
        entry.recheck()?;
    }
    require(
        found.len() == body["units"].as_object().unwrap().len(),
        "new user service link is missing",
    )
}
