// SPDX-License-Identifier: MIT
//! Observe every desktop input before writes; retain each replacement afterwards.
use crate::{desktop_policy as policy, media_packages::Admitted, package_handoff::Received};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
struct Edit {
    path: PathBuf,
    parent: File,
    parent_identity: Value,
    file: Option<File>,
    identity: Option<files::FileIdentity>,
    before: Vec<u8>,
    after: Vec<u8>,
    mode: u32,
    gid: u32,
}
fn shape(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    require(
        // Distribution directories may keep a service group (/etc/cups is root:cups);
        // only root may write them.
        m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "protected desktop parent required",
    )?;
    Ok(
        value!({"inode":[m.dev(),m.ino(),m.mode(),m.uid(),m.gid()],"mount":mount_identity::id(file.as_fd(),true)?}),
    )
}
impl Edit {
    fn observe(
        root: &File,
        name: &str,
        optional: bool,
        transform: impl FnOnce(&str) -> Result<String>,
    ) -> Result<Self> {
        let path = PathBuf::from(name);
        let parent = files::directory_relative(root, path.parent().unwrap(), Some(0))?;
        let parent_identity = shape(&parent)?;
        let file = files::optional_relative(&parent, Path::new(path.file_name().unwrap()))?;
        require(
            optional || file.is_some(),
            "required signed desktop configuration absent",
        )?;
        let (identity, before, mode, gid) = match &file {
            Some(file) => {
                let m = file.metadata()?;
                require(
                    m.uid() == 0
                        && m.nlink() == 1
                        && m.mode() & 0o022 == 0
                        && mount_identity::id(file.as_fd(), true)?
                            == parent_identity["mount"].as_u64().unwrap(),
                    "desktop input crosses a mount or has unsafe ownership",
                )?;
                (
                    Some(files::identity(&m)),
                    files::read_file(file, 128 * 1024, Some(0), true)?,
                    m.mode() & 0o7777,
                    m.gid(),
                )
            }
            None => (None, Vec::new(), 0o644, 0),
        };
        let after = transform(
            std::str::from_utf8(&before)
                .map_err(|_| Error("desktop configuration encoding".into()))?,
        )?
        .into_bytes();
        require(after.len() <= 128 * 1024, "desktop output bound")?;
        let edit = Self {
            path,
            parent,
            parent_identity,
            file,
            identity,
            before,
            after,
            mode,
            gid,
        };
        edit.recheck(root)?;
        Ok(edit)
    }
    fn recheck(&self, root: &File) -> Result<()> {
        let named = files::directory_relative(root, self.path.parent().unwrap(), Some(0))?;
        require(
            shape(&named)? == self.parent_identity && shape(&self.parent)? == self.parent_identity,
            "original desktop parent replaced or remounted",
        )?;
        let actual =
            files::optional_relative(&self.parent, Path::new(self.path.file_name().unwrap()))?;
        match (&self.file, actual, self.identity) {
            (None, None, None) => Ok(()),
            (Some(held), Some(named), Some(identity)) => require(
                files::identity(&held.metadata()?) == identity
                    && files::identity(&named.metadata()?) == identity
                    && mount_identity::id(held.as_fd(), true)?
                        == self.parent_identity["mount"].as_u64().unwrap()
                    && mount_identity::id(named.as_fd(), true)?
                        == self.parent_identity["mount"].as_u64().unwrap()
                    && files::read_file(held, 128 * 1024, Some(0), true)? == self.before,
                "original desktop input changed or replaced",
            ),
            _ => Err(Error("desktop input appeared or disappeared".into())),
        }
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fchown).")]
    fn write(&mut self, root: &File) -> Result<()> {
        self.recheck(root)?;
        if self.before == self.after {
            return Ok(());
        }
        files::atomic_relative(
            &self.parent,
            Path::new(self.path.file_name().unwrap()),
            &self.after,
            self.mode,
            Some(0),
            self.file.is_some(),
            128 * 1024,
        )?;
        let new = files::open_relative(&self.parent, Path::new(self.path.file_name().unwrap()))?;
        // Keep a distribution file's service group (cupsd.conf is root:cups 0640).
        require(
            self.gid == 0 || unsafe { libc::fchown(new.as_raw_fd(), 0, self.gid) } == 0,
            "desktop output group restore failed",
        )?;
        require(
            files::read_file(&new, 128 * 1024, Some(0), true)? == self.after,
            "desktop output readback differs",
        )?;
        self.identity = Some(files::identity(&new.metadata()?));
        self.file = Some(new);
        self.before = self.after.clone();
        self.recheck(root)
    }
    fn receipt(&self) -> Value {
        value!({"path":self.path,"inode":self.identity,"parent":self.parent_identity,"mode":self.mode})
    }
}
/// Every desktop configuration file this step owns, observed before any write.
fn observe_edits(root: &File) -> Result<Vec<Edit>> {
    let mut edits = Vec::new();
    for service in ["greetd", "enzui-lock", "passwd"] {
        edits.push(Edit::observe(
            root,
            &format!("etc/pam.d/{service}"),
            false,
            |body| policy::pam(body, service),
        )?);
    }
    edits.push(Edit::observe(
        root,
        "etc/environment",
        true,
        policy::environment,
    )?);
    edits.push(Edit::observe(
        root,
        "etc/cups/cupsd.conf",
        false,
        policy::cups,
    )?);
    edits.push(Edit::observe(
        root,
        "etc/ipp-usb/ipp-usb.conf",
        false,
        policy::ipp_usb,
    )?);
    edits.push(Edit::observe(
        root,
        "etc/avahi/avahi-daemon.conf",
        false,
        policy::avahi,
    )?);
    edits.push(Edit::observe(
        root,
        "etc/NetworkManager/conf.d/30-enzimos-connectivity.conf",
        true,
        |_| Ok(policy::CONNECTIVITY.into()),
    )?);
    Ok(edits)
}
/// Called only by the original supervised package worker after the desktop overlay.
pub(crate) fn install(context: &Received, media: &Admitted) -> Result<Value> {
    context.recheck()?;
    media.recheck()?;
    let provider = crate::install_boot_sources::Source::open(
        &context.target,
        Path::new("usr/lib/security/pam_oo7.so"),
        16 * 1024 * 1024,
    )?;
    let mut edits = observe_edits(&context.target)?;
    let activation = Activation::observe(&context.target)?;
    let mut receipt = value!({"schema":1,"role":"fresh-desktop-configuration","phase":"writing",
        "request_sha256":json::fingerprint(&context.request)?,"owner":context.store.journal["owner"],
        "inputs":edits.iter().map(Edit::receipt).collect::<Vec<_>>(),"files":[],"services_started":false,
        "password_handled":false,"installed_qualification":false,"keyring_activation":null,"provider":provider.receipt()});
    files::atomic_relative(
        context.store.directory(),
        Path::new("desktop-config.json"),
        &json::canonical(&receipt)?,
        0o600,
        Some(0),
        false,
        128 * 1024,
    )?;
    for index in 0..edits.len() {
        context.recheck()?;
        media.recheck()?;
        provider.recheck(&context.target)?;
        for edit in &edits {
            edit.recheck(&context.target)?;
        }
        edits[index].write(&context.target)?;
    }
    for edit in &edits {
        edit.recheck(&context.target)?;
    }
    provider.recheck(&context.target)?;
    context.recheck()?;
    media.recheck()?;
    receipt["files"] = value!(edits.iter().map(Edit::receipt).collect::<Vec<_>>());
    activation.retire(&context.target)?;
    receipt["keyring_activation"] = value!({"retired":activation.file.is_some(),"present":false});
    for (program, args) in [
        (
            "/usr/bin/systemd-tmpfiles",
            vec!["--create", "/usr/lib/tmpfiles.d/enzui-greeter.conf"],
        ),
        ("/usr/bin/cupsd", vec!["-t"]),
        ("/usr/bin/firewall-offline-cmd", vec!["--check-config"]),
        (
            "/usr/bin/systemctl",
            vec![
                "--root",
                "/",
                "enable",
                "cups.socket",
                "avahi-daemon.service",
                "ipp-usb.service",
                "greetd.service",
            ],
        ),
        (
            "/usr/bin/systemctl",
            vec!["--root", "/", "set-default", "graphical.target"],
        ),
        // Every account, not only the first: the activity broker and the MCP
        // center have no socket or bus activation, so an account created after
        // installation would otherwise never run them.
        (
            "/usr/bin/systemctl",
            vec![
                "--root",
                "/",
                "--global",
                "enable",
                "enzimos-activity.service",
                "enzui-center.service",
            ],
        ),
    ] {
        crate::install_config_tools::run(context, media, program, &args, &[])?;
    }
    for edit in &edits {
        edit.recheck(&context.target)?;
    }
    provider.recheck(&context.target)?;
    context.recheck()?;
    media.recheck()?;
    require(
        Activation::observe(&context.target)?.file.is_none(),
        "keyring socket reappeared during setup",
    )?;
    receipt["phase"] = value!("complete");
    files::atomic_relative(
        context.store.directory(),
        Path::new("desktop-config.json"),
        &json::canonical(&receipt)?,
        0o600,
        Some(0),
        true,
        128 * 1024,
    )?;
    Ok(receipt)
}
struct Activation {
    parent: Option<File>,
    parent_shape: Option<Value>,
    file: Option<File>,
    identity: Option<files::FileIdentity>,
    target: Option<PathBuf>,
}
impl Activation {
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    fn observe(root: &File) -> Result<Self> {
        let parent = files::optional_directory_relative(
            root,
            Path::new("etc/systemd/user/sockets.target.wants"),
            Some(0),
        )?;
        let mut this = Self {
            parent,
            parent_shape: None,
            file: None,
            identity: None,
            target: None,
        };
        if let Some(parent) = &this.parent {
            this.parent_shape = Some(shape(parent)?);
            let raw = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    c"gnome-keyring-daemon.socket".as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                let error = std::io::Error::last_os_error();
                require(
                    error.kind() == std::io::ErrorKind::NotFound,
                    "keyring activation observation failed",
                )?;
            } else {
                let file = unsafe { File::from_raw_fd(raw) };
                let m = file.metadata()?;
                require(
                    m.file_type().is_symlink() && m.uid() == 0 && m.gid() == 0 && m.nlink() == 1,
                    "administrator keyring activation requires review",
                )?;
                require(
                    mount_identity::id(file.as_fd(), true)?
                        == this.parent_shape.as_ref().unwrap()["mount"]
                            .as_u64()
                            .unwrap(),
                    "keyring activation crosses another mount",
                )?;
                let target = std::fs::read_link(format!(
                    "/proc/self/fd/{}/gnome-keyring-daemon.socket",
                    parent.as_raw_fd()
                ))?;
                require(
                    matches!(
                        target.to_str(),
                        Some(
                            "/usr/lib/systemd/user/gnome-keyring-daemon.socket"
                                | "../../../../usr/lib/systemd/user/gnome-keyring-daemon.socket"
                        )
                    ),
                    "administrator keyring activation target requires review",
                )?;
                this.identity = Some(files::identity(&m));
                this.target = Some(target);
                this.file = Some(file);
            }
        }
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    fn retire(&self, root: &File) -> Result<()> {
        let fresh = Self::observe(root)?;
        require(
            fresh.identity == self.identity
                && fresh.parent_shape == self.parent_shape
                && fresh.target == self.target,
            "original keyring activation replaced or remounted",
        )?;
        if let Some(file) = &self.file {
            require(
                Some(files::identity(&file.metadata()?)) == self.identity,
                "original keyring activation inode changed",
            )?;
            let parent = self.parent.as_ref().unwrap();
            require(
                unsafe {
                    libc::unlinkat(
                        parent.as_raw_fd(),
                        c"gnome-keyring-daemon.socket".as_ptr(),
                        0,
                    )
                } == 0,
                "owned keyring activation retirement failed",
            )?;
            parent.sync_all()?;
        }
        require(
            Self::observe(root)?.file.is_none(),
            "retired keyring activation still present",
        )
    }
}

#[cfg(test)]
mod repro_tests {
    use super::*;
    /// Run against an installed scratch root as namespace root:
    /// ENZIMOS_REPRO_ROOT=work/repro-root unshare --map-auto --map-root-user \
    ///   cargo test -- --ignored desktop_edits_apply_to_installed_root
    #[test]
    #[ignore]
    fn desktop_edits_apply_to_installed_root() {
        let root = File::open(std::env::var("ENZIMOS_REPRO_ROOT").unwrap()).unwrap();
        let mut edits = observe_edits(&root).unwrap();
        let activation = Activation::observe(&root).unwrap();
        for index in 0..edits.len() {
            edits[index].write(&root).unwrap();
        }
        for edit in &edits {
            edit.recheck(&root).unwrap();
        }
        activation.retire(&root).unwrap();
        assert!(Activation::observe(&root).unwrap().file.is_none());
    }
}
