// SPDX-License-Identifier: MIT
//! Only separately validated installation writes may supersede overlay outputs.
use crate::{media_packages::Admitted, package_handoff::Received, target_storage::Target};
use enzimos_platform::{Error, Result, files, json, mount_identity, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const NAME: &str = "desktop-overlay.json";
const MAX: usize = 2 * 1024 * 1024;
struct Held {
    file: File,
    identity: files::FileIdentity,
    mount: u64,
    body: Value,
}
impl Held {
    fn observe(directory: &File) -> Result<Self> {
        let file = files::open_relative(directory, Path::new(NAME))?;
        let m = file.metadata()?;
        let mount = mount_identity::id(file.as_fd(), true)?;
        require(
            m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && mount == mount_identity::id(directory.as_fd(), true)?,
            "private original overlay receipt required",
        )?;
        let body = json::decode(&files::read_file(&file, MAX, Some(0), true)?, MAX)?;
        let held = Self {
            file,
            identity: files::identity(&m),
            mount,
            body,
        };
        held.recheck(directory)?;
        Ok(held)
    }
    fn recheck(&self, directory: &File) -> Result<()> {
        let named = files::open_relative(directory, Path::new(NAME))?;
        require(
            files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(directory.as_fd(), true)? == self.mount
                && json::decode(&files::read_file(&self.file, MAX, Some(0), true)?, MAX)?
                    == self.body,
            "original overlay receipt changed or replaced",
        )
    }
}
fn read(directory: &File, name: &str) -> Result<Value> {
    json::decode(
        &files::read_file(
            &files::open_relative(directory, Path::new(name))?,
            MAX,
            Some(0),
            true,
        )?,
        MAX,
    )
}
fn validate(body: &Value, request: &Value, owner: &Value, media: &Admitted) -> Result<()> {
    json::fields(
        body,
        "schema role phase request_sha256 owner archive_inode manifest_inode archive_sha256 manifest_sha256 review_sha256 publication release_authorized final_members authorized_changes",
    )?;
    require(
        body["schema"].as_u64() == Some(1)
            && body["role"] == "fresh-desktop-overlay"
            && matches!(body["phase"].as_str(), Some("complete" | "settled"))
            && body["request_sha256"] == json::fingerprint(request)?
            && body["owner"] == *owner
            && body["release_authorized"] == false
            && media
                .media
                .members
                .get("desktop-preview.tar.zst")
                .is_some_and(|sha| body["archive_sha256"] == *sha)
            && media
                .media
                .members
                .get("desktop-preview.json")
                .is_some_and(|sha| body["manifest_sha256"] == *sha),
        "overlay finalization binding differs",
    )?;
    json::fields(&body["publication"], "schema files links review_sha256")?;
    require(
        body["publication"]["schema"].as_u64() == Some(2)
            && body["publication"]["review_sha256"] == body["review_sha256"],
        "original overlay publication schema differs",
    )?;
    let archive = media
        .media
        .member("desktop-preview.tar.zst", 4 * 1024 * 1024 * 1024)?;
    let manifest = media
        .media
        .member("desktop-preview.json", 4 * 1024 * 1024)?;
    require(
        value!(files::identity(&archive.metadata()?)) == body["archive_inode"]
            && value!(files::identity(&manifest.metadata()?)) == body["manifest_inode"],
        "original finalized overlay source inode differs",
    )?;
    Ok(())
}
fn changes(
    root: &File,
    configuration: &Value,
    boot: &Value,
    desktop: Option<&Value>,
    flatpaks: Option<&Value>,
    request: &Value,
    owner: &Value,
) -> Result<BTreeMap<String, Value>> {
    crate::install_configuration::validate(configuration, request, owner)?;
    crate::install_boot_receipt::validate(boot, request, owner)?;
    require(
        configuration["phase"] == "complete"
            && configuration["schema"] == 4
            && boot["phase"] == "complete",
        "completed installation components required",
    )?;
    crate::configuration_members::verify(root, configuration)?;
    let mut allowed = BTreeMap::new();
    for (name, sha) in configuration["files"].as_object().unwrap() {
        allowed.insert(
            name.clone(),
            value!({"component":"system","kind":"file","sha256":sha,"inode":configuration["members"][name]["inode"]}),
        );
    }
    for (name, target) in configuration["links"].as_object().unwrap() {
        allowed.insert(
            name.clone(),
            value!({"component":"system","kind":"symlink","target":target,"inode":configuration["members"][name]["inode"]}),
        );
    }
    for (name, row) in boot["files"].as_object().unwrap() {
        allowed.insert(
            name.clone(),
            value!({"component":"boot","kind":"file","sha256":row["sha256"],"inode":row["inode"]}),
        );
    }
    if boot["security"]["firmware"]["enabled"] == true {
        allowed.insert(
            "etc/systemd/system/systemd-boot-update.service".into(),
            value!({"component":"boot","kind":"symlink","target":"/dev/null"}),
        );
    }
    if let Some(desktop) = desktop {
        crate::desktop_verify::receipt(root, desktop, request, owner)?;
        for row in desktop["files"].as_array().unwrap() {
            allowed.insert(
                row["path"].as_str().unwrap().into(),
                value!({"component":"desktop","kind":"file","inode":row["inode"]}),
            );
        }
        for (name, target) in crate::desktop_verify::enabled_links(root)? {
            allowed.insert(
                name,
                value!({"component":"desktop-unit","kind":"symlink","target":target}),
            );
        }
        if desktop["keyring_activation"]["retired"] == true {
            allowed.insert(
                "etc/systemd/user/sockets.target.wants/gnome-keyring-daemon.socket".into(),
                value!({"component":"desktop","kind":"absent"}),
            );
        }
    }
    if let Some(flatpaks) = flatpaks {
        crate::flatpak_verify::validate(flatpaks, request, owner)?;
        require(
            flatpaks["phase"] == "complete",
            "completed original Flatpak component required",
        )?;
        crate::flatpak_verify::state(root, flatpaks)?;
        for (name, row) in flatpaks["outputs"].as_object().unwrap() {
            if row["owner"] == 0 {
                allowed.insert(name.clone(),value!({"component":"flatpak","kind":"file","inode":row["inode"],"sha256":row["sha256"]}));
            }
        }
    }
    Ok(allowed)
}
fn matches_change(root: &File, name: &str, actual: &Value, expected: &Value) -> Result<()> {
    require(
        actual["kind"] == expected["kind"],
        "overlay change has a different component-owned type",
    )?;
    if let Some(inode) = expected.get("inode") {
        require(actual["inode"] == *inode, "overlay component inode differs")?;
    }
    if let Some(target) = expected.get("target") {
        require(
            actual["target"] == *target,
            "overlay component link differs",
        )?;
    }
    if let Some(sha) = expected.get("sha256") {
        let file = files::open_relative(root, Path::new(name))?;
        require(
            stream_copy::hash_borrowed(&file, 512 * 1024 * 1024, Some(0))?.1 == *sha,
            "overlay component file bytes differ",
        )?;
    }
    Ok(())
}
fn original_members(body: &Value) -> Result<BTreeMap<String, Value>> {
    let mut rows = BTreeMap::new();
    let files = body["publication"]["files"]
        .as_object()
        .ok_or_else(|| Error("overlay files absent".into()))?;
    require(files.len() <= 2048, "overlay final file bound")?;
    for (name, inode) in files {
        rows.insert(
            name.clone(),
            value!({"path":name,"kind":"file","inode":inode}),
        );
    }
    let links = body["publication"]["links"]
        .as_array()
        .ok_or_else(|| Error("overlay links absent".into()))?;
    require(links.len() <= 2048, "overlay final link bound")?;
    for row in links {
        json::fields(row, "path kind target inode mount")?;
        let name = row["path"]
            .as_str()
            .ok_or_else(|| Error("overlay link path type".into()))?;
        require(
            row["kind"] == "symlink" && rows.insert(name.into(), row.clone()).is_none(),
            "overlay final member duplicated",
        )?;
    }
    Ok(rows)
}
fn absent(root: &File, name: &str) -> Result<Value> {
    let path = Path::new(name);
    let parent = files::directory_relative(root, path.parent().unwrap(), Some(0))?;
    let path = format!(
        "/proc/self/fd/{}/{}",
        std::os::fd::AsRawFd::as_raw_fd(&parent),
        path.file_name().unwrap().to_str().unwrap()
    );
    require(
        matches!(std::fs::symlink_metadata(path),Err(error)if error.kind()==std::io::ErrorKind::NotFound),
        "retired overlay member reappeared",
    )?;
    Ok(value!({"path":name,"kind":"absent"}))
}
pub(crate) fn settle(context: &Received, media: &Admitted, result: &Value) -> Result<()> {
    if media.manifest["desktop_preview_files"] == 0 {
        return Ok(());
    }
    context.recheck()?;
    media.recheck()?;
    let original_receipt = Held::observe(context.store.directory())?;
    let mut body = original_receipt.body.clone();
    validate(
        &body,
        &context.request,
        &context.store.journal["owner"],
        media,
    )?;
    require(
        body["phase"] == "complete"
            && body["final_members"].is_null()
            && body["authorized_changes"].is_null(),
        "overlay cannot adopt an earlier finalization",
    )?;
    let allowed = changes(
        &context.target,
        &result["system"]["configuration"],
        &result["boot"],
        result["system"].get("desktop"),
        result["system"]
            .get("flatpaks")
            .filter(|row| row["role"] == "fresh-offline-flatpaks"),
        &context.request,
        &context.store.journal["owner"],
    )?;
    let mut final_members = BTreeMap::new();
    let mut authorized = BTreeMap::new();
    let mut held = Vec::new();
    for (name, original) in original_members(&body)? {
        context.recheck()?;
        media.recheck()?;
        let actual = if allowed
            .get(&name)
            .is_some_and(|row| row["kind"] == "absent")
        {
            absent(&context.target, &name)?
        } else {
            let (file, row) = enzimos_policy::file_overlay::capture(&context.target, &name, 0)?;
            held.push((name.clone(), file, row.clone()));
            row
        };
        let same = actual["kind"] == original["kind"]
            && actual["inode"] == original["inode"]
            && (actual["kind"] != "symlink" || actual["target"] == original["target"]);
        if !same {
            let expected = allowed.get(&name).ok_or_else(|| {
                Error(format!(
                    "unowned overlay member changed during installation: {name}"
                ))
            })?;
            matches_change(&context.target, &name, &actual, expected)?;
            authorized.insert(name.clone(), expected.clone());
        }
        final_members.insert(name, actual);
    }
    for (name, file, row) in held {
        let (_, actual) = enzimos_policy::file_overlay::capture(&context.target, &name, 0)?;
        require(
            actual == row && value!(files::identity(&file.metadata()?)) == row["inode"],
            "original settled overlay member changed",
        )?;
    }
    for (name, row) in &final_members {
        if row["kind"] == "absent" {
            require(
                absent(&context.target, name)? == *row,
                "retired overlay member changed before publication",
            )?;
        }
    }
    context.recheck()?;
    media.recheck()?;
    original_receipt.recheck(context.store.directory())?;
    body["final_members"] = value!(final_members);
    body["authorized_changes"] = value!(authorized);
    body["phase"] = value!("settled");
    files::atomic_relative(
        context.store.directory(),
        Path::new(NAME),
        &json::canonical(&body)?,
        0o600,
        Some(0),
        true,
        MAX,
    )?;
    require(
        read(context.store.directory(), NAME)? == body,
        "overlay finalization readback differs",
    )
}
pub(crate) fn completed(
    target: &Target<'_>,
    media: &Admitted,
    journal: &Value,
    directory: &File,
    configuration: &Value,
    boot: &Value,
    desktop: Option<&Value>,
    flatpaks: Option<&Value>,
) -> Result<()> {
    if media.manifest["desktop_preview_files"] == 0 {
        return Ok(());
    }
    target.recheck()?;
    media.recheck()?;
    let held = Held::observe(directory)?;
    let body = held.body.clone();
    validate(&body, &journal["request"], &journal["owner"], media)?;
    require(
        body["phase"] == "settled",
        "original overlay was not finalized by its worker",
    )?;
    let original = original_members(&body)?;
    let finals = body["final_members"]
        .as_object()
        .ok_or_else(|| Error("settled overlay member set absent".into()))?;
    require(
        finals.keys().eq(original.keys()),
        "settled overlay member set differs",
    )?;
    let allowed = changes(
        target.directory()?,
        configuration,
        boot,
        desktop,
        flatpaks,
        &journal["request"],
        &journal["owner"],
    )?;
    let changes = body["authorized_changes"]
        .as_object()
        .ok_or_else(|| Error("overlay change set absent".into()))?;
    let mut members = Vec::new();
    for (name, old) in original {
        let final_row = &finals[&name];
        let actual = if final_row["kind"] == "absent" {
            absent(target.directory()?, &name)?
        } else {
            let (file, row) = enzimos_policy::file_overlay::capture(target.directory()?, &name, 0)?;
            members.push((name.clone(), file, row.clone()));
            row
        };
        require(
            actual == *final_row,
            "settled original overlay file or link changed after worker exit",
        )?;
        if let Some(change) = changes.get(&name) {
            require(
                allowed.get(&name) == Some(change),
                "overlay final change belongs to another component",
            )?;
            matches_change(target.directory()?, &name, &actual, change)?;
        } else {
            require(
                actual["kind"] == old["kind"]
                    && actual["inode"] == old["inode"]
                    && (actual["kind"] != "symlink" || actual["target"] == old["target"]),
                "overlay finalization silently adopted a changed member",
            )?;
        }
    }
    require(
        changes.keys().all(|name| finals.contains_key(name)),
        "overlay change set has an unregistered member",
    )?;
    for (name, file, row) in members {
        let (_, actual) = enzimos_policy::file_overlay::capture(target.directory()?, &name, 0)?;
        require(
            actual == row && value!(files::identity(&file.metadata()?)) == row["inode"],
            "settled overlay member changed during final verification",
        )?;
    }
    for (name, row) in finals {
        if row["kind"] == "absent" {
            require(
                absent(target.directory()?, name)? == *row,
                "retired overlay member reappeared during final verification",
            )?;
        }
    }
    held.recheck(directory)?;
    target.recheck()?;
    media.recheck()
}
