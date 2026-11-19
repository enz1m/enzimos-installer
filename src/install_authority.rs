// SPDX-License-Identifier: MIT
//! Publish a fresh public-only installation authority; unexpected prior material is refused.
use crate::{media_packages::Admitted, native_signing::Prepared, package_handoff::Received};
use enzimos_platform::{Error, Result, files, json, mount_identity, require, stream_copy};
use enzimos_policy::{authority, authority_build, filesystem, subvolume};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const PATH: &str = "/mnt/enzimos/etc/pacman.d/gnupg";
const MAX: usize = 8 * 1024 * 1024;
fn inode(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "installation authority must be a private Root directory",
    )?;
    Ok(value!([m.dev(), m.ino(), m.uid(), m.gid(), m.mode()]))
}
pub struct Fresh {
    directory: File,
    shape: Value,
}
impl Fresh {
    pub fn observe(target: &File) -> Result<Self> {
        crate::setup::live()?;
        let directory =
            files::directory_relative(target, Path::new("etc/pacman.d/gnupg"), Some(0))?;
        let fs = filesystem::observe(directory.as_fd())?;
        let root = filesystem::observe(target.as_fd())?;
        let (identity, readonly) = subvolume::observe(directory.as_fd(), "enzimos-authority")?;
        let (target_identity, _) = subvolume::observe(target.as_fd(), "enzimos-root")?;
        require(
            fs == root
                && !readonly
                && identity["parent_uuid"].is_null()
                && identity["uuid"] != target_identity["uuid"],
            "installation authority filesystem or fresh subvolume lineage",
        )?;
        let shape = value!({"filesystem_uuid":fs["filesystem_uuid"],"subvolume":identity,
            "mount":mount_identity::id(directory.as_fd(),true)?,"inode":inode(&directory)?});
        let result = Self { directory, shape };
        result.recheck()?;
        Ok(result)
    }
    fn recheck(&self) -> Result<()> {
        crate::setup::live()?;
        let named = files::directory(Path::new(PATH), Some(0))?;
        let (identity, readonly) = subvolume::observe(self.directory.as_fd(), "enzimos-authority")?;
        require(
            !readonly
                && identity == self.shape["subvolume"]
                && filesystem::observe(self.directory.as_fd())?["filesystem_uuid"]
                    == self.shape["filesystem_uuid"]
                && inode(&self.directory)? == self.shape["inode"]
                && inode(&named)? == self.shape["inode"]
                && mount_identity::id(self.directory.as_fd(), true)?
                    == self.shape["mount"].as_u64().unwrap()
                && mount_identity::id(named.as_fd(), true)?
                    == self.shape["mount"].as_u64().unwrap(),
            "installation authority retained directory identity changed",
        )
    }
    fn names(&self) -> Result<BTreeSet<String>> {
        self.recheck()?;
        let alias = format!("/proc/self/fd/{}", self.directory.as_raw_fd());
        let mut names = BTreeSet::new();
        for (index, entry) in std::fs::read_dir(alias)?.enumerate() {
            require(index < 16, "unexpected installation authority member count")?;
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| Error("authority member encoding".into()))?;
            require(
                names.insert(name),
                "duplicate installation authority member",
            )?;
        }
        self.recheck()?;
        Ok(names)
    }
    pub fn empty(&self) -> Result<()> {
        require(
            self.names()?.is_empty(),
            "fresh authority contains unexpected prior material; no adoption or deletion",
        )
    }
    fn hashes(&self) -> Result<Value> {
        let names = self.names()?;
        require(
            names
                .iter()
                .all(|name| authority::FILES.contains(&name.as_str())),
            "installation authority contains extra or private material",
        )?;
        let mut hashes = BTreeMap::new();
        for name in names {
            let file = files::open_relative(&self.directory, Path::new(&name))?;
            require(
                file.metadata()?.mode() & 0o7777 == if name == "gpg.conf" { 0o644 } else { 0o600 }
                    && mount_identity::id(file.as_fd(), true)?
                        == self.shape["mount"].as_u64().unwrap(),
                "installation authority file mode or mount changed",
            )?;
            hashes.insert(
                name,
                stream_copy::hash_borrowed(&file, MAX as u64, Some(0))?.1,
            );
        }
        self.recheck()?;
        Ok(value!(hashes))
    }
}
pub fn prefix(after: &Value, count: usize) -> Result<Value> {
    require(
        count <= authority::FILES.len(),
        "installation authority publication prefix bound",
    )?;
    let mut prefix = BTreeMap::new();
    for name in authority::FILES.iter().take(count) {
        let hash = after[*name]
            .as_str()
            .ok_or_else(|| Error("authority publication digest missing".into()))?;
        enzimos_policy::identity::sha(hash)?;
        prefix.insert(*name, hash);
    }
    Ok(value!(prefix))
}
pub fn validate(body: &Value, request: &Value, owner: &Value) -> Result<()> {
    json::fields(
        body,
        "schema id role phase request_sha256 owner authority files local_signer development_artifact release_authorized private_key_retired",
    )?;
    crate::package_job::request(request)?;
    require(
        body["schema"] == 1
            && body["id"] == request["id"]
            && matches!(
                request["operation"].as_str(),
                Some(
                    crate::package_job::OFFLINE
                        | crate::package_job::SYSTEM
                        | crate::package_job::BOOT
                )
            )
            && body["role"] == "fresh-installation-public-authority"
            && matches!(body["phase"].as_str(), Some("publishing" | "complete"))
            && body["request_sha256"] == json::fingerprint(request)?
            && body["owner"] == *owner
            && body["development_artifact"] == true
            && body["release_authorized"] == false
            && body["private_key_retired"] == true,
        "installation authority receipt role or original worker differs",
    )?;
    enzimos_policy::authority::fingerprint(
        body["local_signer"]
            .as_str()
            .ok_or_else(|| Error("installation local signer missing".into()))?,
    )?;
    json::fields(&body["authority"], "filesystem_uuid subvolume mount inode")?;
    enzimos_policy::identity::uuid(
        body["authority"]["filesystem_uuid"]
            .as_str()
            .ok_or_else(|| Error("installation authority filesystem missing".into()))?,
    )?;
    crate::mount_spec::Spec::Subvolume(body["authority"]["subvolume"].clone())
        .validate(Path::new(PATH))?;
    require(
        body["authority"]["mount"].as_u64().is_some_and(|n| n > 0)
            && body["authority"]["inode"].as_array().is_some_and(|a| {
                a.len() == 5
                    && a.iter().all(Value::is_u64)
                    && a[0].as_u64().unwrap() > 0
                    && a[1].as_u64().unwrap() > 0
                    && a[2] == 0
                    && a[3] == 0
                    && a[4].as_u64().unwrap() == u64::from(libc::S_IFDIR | 0o700)
            }),
        "authority receipt mount or protected inode shape",
    )?;
    json::fields(
        &body["files"],
        "gpg.conf pubring.gpg trustdb.gpg approved.trust",
    )?;
    prefix(&body["files"], authority::FILES.len()).map(|_| ())
}
fn record(context: &Received, body: &Value, replace: bool) -> Result<()> {
    context.recheck()?;
    validate(body, &context.request, &context.store.journal["owner"])?;
    let path = Path::new("/mnt/enzimos/var/lib/enzimos-control/installations")
        .join(context.request["id"].as_str().unwrap())
        .join("authority.json");
    files::atomic(&path, &json::canonical(body)?, 0o600, Some(0), replace)?;
    require(
        json::decode(
            &files::read_file(
                &files::open_relative(context.store.directory(), Path::new("authority.json"))?,
                65536,
                Some(0),
                true,
            )?,
            65536,
        )? == *body,
        "installation authority receipt readback differs",
    )?;
    context.recheck()
}
pub fn publish(context: &Received, media: &Admitted, prepared: &Prepared) -> Result<Value> {
    prepared.recheck(context, media)?;
    let authority = Fresh::observe(&context.target)?;
    authority.empty()?;
    let materials = prepared.materials();
    let after = value!(
        materials
            .iter()
            .map(|(name, body)| (name.clone(), json::sha256(body)))
            .collect::<BTreeMap<_, _>>()
    );
    let mut receipt = value!({"schema":1,"id":context.request["id"],"role":"fresh-installation-public-authority","phase":"publishing",
        "request_sha256":json::fingerprint(&context.request)?,"owner":context.store.journal["owner"],"authority":authority.shape,
        "files":after,"local_signer":prepared.fingerprint,"development_artifact":true,"release_authorized":false,"private_key_retired":true});
    record(context, &receipt, false)?;
    for (index, name) in authority::FILES.iter().enumerate() {
        prepared.recheck(context, media)?;
        authority.recheck()?;
        require(
            authority.hashes()? == prefix(&after, index)?,
            "authority publication prefix differs; unfinished attempt retained",
        )?;
        files::atomic_bounded(
            &Path::new(PATH).join(name),
            &materials[*name],
            if *name == "gpg.conf" { 0o644 } else { 0o600 },
            Some(0),
            false,
            MAX,
        )?;
        require(
            authority.hashes()? == prefix(&after, index + 1)?,
            "authority publication file readback differs",
        )?;
    }
    authority.directory.sync_all()?;
    prepared.recheck(context, media)?;
    authority.recheck()?;
    receipt["phase"] = value!("complete");
    record(context, &receipt, true)?;
    Ok(receipt)
}
/// Caller-only: run after the original worker and retained cgroup are empty.
pub fn completed(
    target: &File,
    media: &Admitted,
    journal: &Value,
    directory: &File,
) -> Result<Value> {
    require(
        journal["phase"] == "stopping",
        "public authority confirmation follows worker stopping checkpoint",
    )?;
    let body = json::decode(
        &files::read_file(
            &files::open_relative(directory, Path::new("authority.json"))?,
            65536,
            Some(0),
            true,
        )?,
        65536,
    )?;
    validate(&body, &journal["request"], &journal["owner"])?;
    let authority = Fresh::observe(target)?;
    require(
        body["phase"] == "complete"
            && body["authority"] == authority.shape
            && body["files"] == authority.hashes()?,
        "completed public authority differs from exact stopped attempt",
    )?;
    media.recheck()?;
    let work = Path::new("/run/enzimos-install-native")
        .join(format!("authority-confirm-{}", files::random_hex(16)?));
    let rebuilt = authority_build::build(
        Path::new(PATH),
        Path::new("/usr/share/pacman/keyrings"),
        &work,
        0,
    )?;
    require(
        rebuilt.approved == media.authority.approved
            && rebuilt.local == vec![body["local_signer"].as_str().unwrap().to_owned()],
        "installed public authority differs from independent quorum plus the one new local signer",
    )?;
    rebuilt.recheck()?;
    media.recheck()?;
    authority.recheck()?;
    require(
        body["files"] == authority.hashes()?,
        "installed public authority changed during independent confirmation",
    )?;
    Ok(body)
}
