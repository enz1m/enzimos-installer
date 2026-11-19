// SPDX-License-Identifier: MIT
//! Retain explicitly staged owner credentials; never enroll or replace firmware keys.
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use enzimos_policy::secure_boot;
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const PATH: &str = "/run/enzimos-owner-key";
pub(crate) struct Source {
    firmware: Value,
    directory: Option<File>,
    binding: Value,
    files: Vec<(&'static str, File, files::FileIdentity, u64)>,
    material: Option<secure_boot::Material>,
}
fn directory(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "staged owner directory must be private Root-owned data",
    )?;
    Ok(
        value!({"mount":mount_identity::id(file.as_fd(),true)?,"inode":[m.dev(),m.ino(),m.uid(),m.gid(),m.mode()]}),
    )
}
impl Source {
    #[allow(unsafe_code, reason = "Linux syscall ABI (getrlimit, prctl).")]
    pub(crate) fn observe(encrypted: bool) -> Result<Self> {
        crate::setup::live()?;
        let firmware = secure_boot::firmware()?;
        let mut this = Self {
            firmware,
            directory: None,
            binding: Value::Null,
            files: Vec::new(),
            material: None,
        };
        if this.firmware["enabled"] == true {
            require(
                encrypted,
                "Secure Boot owner credentials require encrypted installation before erase",
            )?;
            let mut core: libc::rlimit = unsafe { std::mem::zeroed() };
            require(
                unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0
                    && unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) } == 0
                    && core.rlim_cur == 0
                    && core.rlim_max == 0,
                "staged owner credentials require protected installer process before reading",
            )?;
            let dir = files::directory(Path::new(PATH), Some(0))?;
            let shape = directory(&dir)?;
            let mut members = BTreeMap::new();
            for name in ["owner.key", "owner.crt", "owner.cer"] {
                let file = files::open_relative(&dir, Path::new(name))?;
                let m = file.metadata()?;
                require(
                    m.uid() == 0
                        && m.gid() == 0
                        && m.nlink() == 1
                        && m.len() > 0
                        && m.len() <= 16384
                        && m.mode() & 0o7777 == if name == "owner.key" { 0o600 } else { 0o644 },
                    "staged owner credential protection or size",
                )?;
                let mount = mount_identity::id(file.as_fd(), true)?;
                require(
                    mount == shape["mount"].as_u64().unwrap(),
                    "staged owner credentials cannot cross another mount",
                )?;
                members.insert(name, files::identity(&m));
                this.files.push((name, file, files::identity(&m), mount));
            }
            let material = secure_boot::credentials_at(Path::new(PATH))?;
            let db = files::read(
                &Path::new(secure_boot::EFI).join(secure_boot::DB),
                1024 * 1024,
                Some(0),
                false,
            )?;
            require(
                secure_boot::db_contains(&db, &material.der)?,
                "original owner enrollment changed during credential admission",
            )?;
            this.binding = value!({"directory":shape,"files":members,"certificate_sha256":json::sha256(&material.der),"enrolled_db_sha256":json::sha256(&db)});
            this.directory = Some(dir);
            this.material = Some(material);
        }
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        crate::setup::live()?;
        require(
            secure_boot::firmware()? == self.firmware,
            "firmware security flags changed during native installation",
        )?;
        if let Some(held) = &self.directory {
            require(
                directory(held)? == self.binding["directory"]
                    && directory(&files::directory(Path::new(PATH), Some(0))?)?
                        == self.binding["directory"],
                "original staged owner credential directory changed",
            )?;
            for (name, file, identity, mount) in &self.files {
                let named = files::open_relative(held, Path::new(name))?;
                require(
                    files::identity(&file.metadata()?) == *identity
                        && files::identity(&named.metadata()?) == *identity
                        && mount_identity::id(file.as_fd(), true)? == *mount
                        && mount_identity::id(named.as_fd(), true)? == *mount,
                    "original staged owner credential inode or mount changed",
                )?;
            }
            // Enrollment is observed, never changed. A removed certificate stops
            // the job even when SecureBoot's enabled/setup flags stay unchanged.
            let db = files::read(
                &Path::new(secure_boot::EFI).join(secure_boot::DB),
                1024 * 1024,
                Some(0),
                false,
            )?;
            require(
                secure_boot::db_contains(&db, &self.material.as_ref().unwrap().der)?
                    && json::sha256(&db) == self.binding["enrolled_db_sha256"],
                "original staged owner certificate is no longer enrolled",
            )?;
        }
        Ok(())
    }
    pub(crate) fn receipt(&self) -> Result<Value> {
        self.recheck()?;
        let body = value!({"firmware":self.firmware,"owner":self.binding});
        validate(&body)?;
        Ok(body)
    }
    pub(crate) fn descriptor(&self) -> Result<Option<&File>> {
        self.recheck()?;
        Ok(self.directory.as_ref())
    }
    pub(crate) fn install(&self, target: &File) -> Result<()> {
        self.recheck()?;
        let Some(material) = &self.material else {
            return Err(Error(
                "owner installation requires explicitly staged enrolled credentials".into(),
            ));
        };
        let control =
            files::directory_relative(target, Path::new("var/lib/enzimos-control"), Some(0))?;
        require(
            filesystem_equal(&control, target)?,
            "owner destination must remain on the installation filesystem",
        )?;
        material.write_new(
            Path::new("/mnt/enzimos/var/lib/enzimos-control/secure-boot"),
            0,
        )?;
        let copied = secure_boot::Material::load(
            Path::new("/mnt/enzimos/var/lib/enzimos-control/secure-boot"),
            0,
        )?;
        require(
            copied.der == material.der && copied.pem == material.pem,
            "installed owner public material differs from original staged credentials",
        )?;
        self.recheck()
    }
    pub(crate) fn verify_installed(&self) -> Result<Option<String>> {
        self.recheck()?;
        let Some(original) = &self.material else {
            return Ok(None);
        };
        let copied = secure_boot::Material::load(
            Path::new("/mnt/enzimos/var/lib/enzimos-control/secure-boot"),
            0,
        )?;
        require(
            copied.der == original.der && copied.pem == original.pem,
            "installed owner authority differs from explicitly staged enrolled credentials",
        )?;
        self.recheck()?;
        Ok(Some(json::sha256(&copied.pem)))
    }
}
fn filesystem_equal(a: &File, b: &File) -> Result<bool> {
    Ok(enzimos_policy::filesystem::observe(a.as_fd())?
        == enzimos_policy::filesystem::observe(b.as_fd())?)
}
pub(crate) fn validate(body: &Value) -> Result<()> {
    json::fields(body, "firmware owner")?;
    let fw = &body["firmware"];
    json::fields(fw, "uefi capable enabled setup_mode")?;
    require(
        ["uefi", "capable", "enabled", "setup_mode"]
            .iter()
            .all(|k| fw[*k].is_boolean())
            && (fw["uefi"] == true
                || (fw["capable"] == false && fw["enabled"] == false && fw["setup_mode"] == false))
            && (fw["capable"] == true || (fw["enabled"] == false && fw["setup_mode"] == false))
            && (fw["enabled"] == true) == !body["owner"].is_null(),
        "staged owner authority differs from firmware security state",
    )?;
    if !body["owner"].is_null() {
        let owner = &body["owner"];
        json::fields(
            owner,
            "directory files certificate_sha256 enrolled_db_sha256",
        )?;
        json::fields(&owner["directory"], "mount inode")?;
        let a = owner["directory"]["inode"]
            .as_array()
            .ok_or_else(|| Error("staged owner directory inode type".into()))?;
        require(
            a.len() == 5
                && a.iter().all(Value::is_u64)
                && a[0].as_u64().unwrap() > 0
                && a[1].as_u64().unwrap() > 0
                && a[2] == 0
                && a[3] == 0
                && a[4].as_u64() == Some(u64::from(libc::S_IFDIR | 0o700))
                && owner["directory"]["mount"].as_u64().is_some_and(|n| n > 0),
            "staged owner directory private unique identity",
        )?;
        json::fields(&owner["files"], "owner.key owner.crt owner.cer")?;
        for name in ["owner.key", "owner.crt", "owner.cer"] {
            crate::private_file::validate_inode(
                &owner["files"][name],
                if name == "owner.key" { 0o600 } else { 0o644 },
                16384,
            )?;
            require(
                owner["files"][name][2].as_u64().is_some_and(|n| n > 0),
                "staged owner credential is empty",
            )?;
        }
        enzimos_policy::identity::sha(
            owner["certificate_sha256"]
                .as_str()
                .ok_or_else(|| Error("staged owner public certificate digest missing".into()))?,
        )?;
        enzimos_policy::identity::sha(
            owner["enrolled_db_sha256"]
                .as_str()
                .ok_or_else(|| Error("original enrollment digest missing".into()))?,
        )?;
    }
    Ok(())
}
