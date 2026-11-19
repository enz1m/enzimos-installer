// SPDX-License-Identifier: MIT
//! One owned read-only answer mount; failure retains its intent and never replays.
use enzimos_platform::{Error, Result, files, json, mount_identity, mountinfo, require};
use enzimos_policy::{
    installer_mount_area::Area,
    installer_volume_device::{Device, Label},
    storage_runtime, topology,
};
use serde_json::{Value, json as value};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
use zeroize::Zeroizing;
const ROOT: &str = crate::test_copy::ROOT;
#[path = "answer_volume_directory.rs"]
mod directory;
use directory::Directory;
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "private Root answer mountpoint required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
fn admit(rows: &[mountinfo::Row], parent: u64) -> Result<()> {
    enzimos_policy::installer_mount_area::validate_mount(rows, parent)?;
    Ok(())
}
fn mounted(
    rows: &[mountinfo::Row],
    id: u64,
    device: topology::Device,
    kind: &str,
    area: &mountinfo::Row,
) -> Result<mountinfo::Row> {
    let candidates = rows.iter().filter(|r| r.target == ROOT).collect::<Vec<_>>();
    require(
        candidates.len() == 2
            && candidates.iter().filter(|r| ***r == *area).count() == 1
            && !rows
                .iter()
                .any(|r| r.target.starts_with(&format!("{ROOT}/"))),
        "answer mount shadowed or replaced",
    )?;
    enzimos_policy::installer_mount_area::validate_mount(std::slice::from_ref(area), area.id)?;
    let row = candidates
        .iter()
        .find(|r| r.id == id)
        .copied()
        .ok_or_else(|| Error("owned answer mount missing".into()))?;
    let flags = row
        .options
        .split(',')
        .collect::<std::collections::BTreeSet<_>>();
    let super_flags = row
        .filesystem_options
        .split(',')
        .collect::<std::collections::BTreeSet<_>>();
    require(
        row.id == id
            && row.id != area.id
            && row.parent == area.id
            && (row.major, row.minor) == device
            && row.filesystem == kind
            && row.root == "/"
            && row.optional.is_empty()
            && matches!(kind, "ext4" | "vfat" | "iso9660")
            && ["ro", "nodev", "nosuid", "noexec"]
                .iter()
                .all(|n| flags.contains(n))
            && !flags.contains("rw")
            && super_flags.contains("ro")
            && (kind != "iso9660"
                || [
                    "uid=0",
                    "gid=0",
                    "fmode=600",
                    "dmode=700",
                    "overriderockperm",
                ]
                .iter()
                .all(|n| super_flags.contains(n)))
            && (kind != "ext4"
                || row
                    .filesystem_options
                    .split(',')
                    .any(|n| matches!(n, "noload" | "norecovery"))),
        "owned answer mount protections differ",
    )?;
    Ok(row.clone())
}
pub struct Volume {
    area: Area,
    lock: files::Lock,
    device: Device,
    underlying: File,
    underlying_shape: Shape,
    underlying_mount: u64,
    root: Option<File>,
    mount: u64,
    row: mountinfo::Row,
    receipt_dir: Directory,
    receipt: File,
    receipt_identity: files::FileIdentity,
    body: Value,
    bytes: Vec<u8>,
}
impl Volume {
    pub fn open(label: Label) -> Result<Self> {
        crate::answer_source::Source::protect()?;
        let lock = files::Lock::acquire(Path::new(crate::install_session::LOCK), 0)?;
        Self::with_lock(label, lock)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (mount).")]
    fn with_lock(label: Label, lock: files::Lock) -> Result<Self> {
        lock.recheck()?;
        let device = Device::observe(label)?;
        let media = files::directory(Path::new("/run/enzimos-live/media"), Some(0))?;
        let normal = mount_identity::id(media.as_fd(), false)?;
        let rows = storage_runtime::rows()?;
        let media_row = rows
            .iter()
            .find(|r| r.id == normal && r.target == "/run/enzimos-live/media")
            .ok_or_else(|| Error("original live media mount missing".into()))?;
        device.independent(&topology::observe(&[(media_row.major, media_row.minor)])?)?;
        let root = Path::new(ROOT);
        let area = Area::observe()?;
        admit(&rows, area.binding().id)?;
        let underlying = area.descriptor()?.try_clone()?;
        require(
            std::fs::read_dir(root)?.next().is_none(),
            "answer mountpoint must be empty",
        )?;
        let underlying_shape = shape(&underlying)?;
        let underlying_mount = mount_identity::id(underlying.as_fd(), true)?;
        admit(
            &storage_runtime::rows()?,
            mount_identity::id(underlying.as_fd(), false)?,
        )?;
        let receipt_dir =
            files::ensure_directory(Path::new("/run/enzimos-install-native"), 0o700, 0)?;
        let receipt_dir =
            Directory::retain(Path::new("/run/enzimos-install-native"), receipt_dir, 0)?;
        require(
            mount_identity::id(receipt_dir.file()?.as_fd(), true)? == area.parent_mount(),
            "answer intent must remain on original live tmpfs mount",
        )?;
        let body = value!({"schema":1,"phase":"mounting","boot":enzimos_policy::operation::boot_id()?,"source":device.evidence(false)?,"underlying":underlying_shape,"underlying_mount":underlying_mount});
        let bytes = json::canonical(&body)?;
        let receipt = files::atomic_relative_retained(
            receipt_dir.file()?,
            Path::new("answer-volume.json"),
            &bytes,
            0o600,
            Some(0),
            false,
            65536,
        )?;
        let receipt_identity = files::identity(&receipt.metadata()?);
        device.recheck(false)?;
        area.recheck()?;
        require(
            shape(&files::directory(root, Some(0))?)? == underlying_shape
                && mount_identity::id(underlying.as_fd(), true)? == underlying_mount,
            "original answer mount stub changed",
        )?;
        let source = CString::new(format!(
            "/proc/self/fd/{}",
            device.descriptor(false)?.as_raw_fd()
        ))
        .unwrap();
        let target = CString::new(format!("/proc/self/fd/{}/.", underlying.as_raw_fd())).unwrap();
        let kind = CString::new(device.filesystem()).unwrap();
        let options = CString::new(match device.filesystem() {
            "ext4" => "ro,noload",
            "vfat" => "ro,uid=0,gid=0,fmask=0177,dmask=0077",
            // Preserve Rock Ridge names, but do not inherit lab ISO uid/mode
            // metadata. This protects this mount; the attached ISO is plaintext.
            "iso9660" => "ro,uid=0,gid=0,mode=0600,dmode=0700,overriderockperm",
            _ => return Err(Error("unsupported answer mount filesystem".into())),
        })
        .unwrap();
        require(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    kind.as_ptr(),
                    libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
                    options.as_ptr().cast(),
                )
            } == 0,
            "owned read-only answer mount failed; original intent retained",
        )?;
        let root = files::directory(Path::new(ROOT), Some(0))?;
        let mount = mount_identity::id(root.as_fd(), true)?;
        require(
            mount != underlying_mount,
            "answer mount did not establish a fresh kernel identity",
        )?;
        let row = mounted(
            &storage_runtime::rows()?,
            mount_identity::id(root.as_fd(), false)?,
            device.number(),
            device.filesystem(),
            area.binding(),
        )?;
        let this = Self {
            area,
            lock,
            device,
            underlying,
            underlying_shape,
            underlying_mount,
            root: Some(root),
            mount,
            row,
            receipt_dir,
            receipt,
            receipt_identity,
            body,
            bytes,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        crate::setup::live()?;
        self.lock.recheck()?;
        self.device.recheck(true)?;
        self.area.recheck_covered()?;
        self.original_receipt()?;
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| Error("owned answer mount retired".into()))?;
        let named = files::directory(Path::new(ROOT), Some(0))?;
        let held = root.metadata()?;
        let current = named.metadata()?;
        require(
            (held.dev(), held.ino(), held.uid(), held.gid(), held.mode())
                == (
                    current.dev(),
                    current.ino(),
                    current.uid(),
                    current.gid(),
                    current.mode(),
                )
                && held.uid() == 0
                && held.mode() & 0o022 == 0
                && mount_identity::id(root.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mounted(
                    &storage_runtime::rows()?,
                    mount_identity::id(root.as_fd(), false)?,
                    self.device.number(),
                    self.device.filesystem(),
                    self.area.binding(),
                )? == self.row,
            "original owned answer mount changed",
        )
    }
    fn original_receipt(&self) -> Result<()> {
        let named =
            files::open_relative(self.receipt_dir.file()?, Path::new("answer-volume.json"))?;
        require(
            files::identity(&self.receipt.metadata()?) == self.receipt_identity
                && files::identity(&named.metadata()?) == self.receipt_identity
                && files::read_file(&self.receipt, 65536, Some(0), true)? == self.bytes,
            "original answer mount intent changed",
        )
    }
    pub fn answers(&self) -> Result<crate::answer_source::Source> {
        self.recheck()?;
        let file = files::open_relative(self.root.as_ref().unwrap(), Path::new("answers.env"))?;
        let before = files::identity(&file.metadata()?);
        let m = file.metadata()?;
        require(
            m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o600,
            "private Root answer-volume file required before secret read",
        )?;
        require(
            mount_identity::id(file.as_fd(), true)? == self.mount,
            "answers file left original volume",
        )?;
        let bytes: Zeroizing<Vec<u8>> =
            crate::private_file::read(&file, crate::answers::MAX_FILE, 0)?;
        self.recheck()?;
        let named = files::open_relative(self.root.as_ref().unwrap(), Path::new("answers.env"))?;
        require(
            files::identity(&file.metadata()?) == before
                && files::identity(&named.metadata()?) == before,
            "original volume answer file changed",
        )?;
        let source = crate::answer_transport::bytes(&bytes)?;
        self.recheck()?;
        source.recheck()?;
        Ok(source)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (umount2).")]
    pub fn close(mut self) -> Result<Value> {
        self.recheck()?;
        drop(self.root.take());
        // Every borrowed script and source-volume descriptor must be dropped
        // first. Ordinary umount refuses a busy mount; no lazy/forced fallback.
        let path = CString::new(ROOT).unwrap();
        require(
            unsafe { libc::umount2(path.as_ptr(), 0) } == 0,
            "answer mount remains busy; original intent retained",
        )?;
        let named = files::directory(Path::new(ROOT), Some(0))?;
        require(
            shape(&named)? == self.underlying_shape
                && shape(&self.underlying)? == self.underlying_shape
                && mount_identity::id(named.as_fd(), true)? == self.underlying_mount
                && mount_identity::id(self.underlying.as_fd(), true)? == self.underlying_mount
                && admit(&storage_runtime::rows()?, self.area.binding().id).is_ok(),
            "original answer mount did not close normally",
        )?;
        self.area.recheck()?;
        self.device.recheck(false)?;
        self.original_receipt()?;
        self.body["phase"] = value!("closed");
        self.body["mount_closed"] = value!(true);
        let complete = files::atomic_replace_original(
            self.receipt_dir.file()?,
            Path::new("answer-volume.json"),
            &json::canonical(&self.body)?,
            0o600,
            Some(0),
            65536,
            &self.receipt,
        )?;
        let named =
            files::open_relative(self.receipt_dir.file()?, Path::new("answer-volume.json"))?;
        require(
            files::identity(&named.metadata()?) == files::identity(&complete.metadata()?)
                && files::read_file(&complete, 65536, Some(0), true)?
                    == json::canonical(&self.body)?,
            "closed answer receipt changed before return",
        )?;
        self.device.recheck(false)?;
        self.receipt_dir.recheck()?;
        self.lock.recheck()?;
        Ok(
            value!({"schema":1,"label":self.body["source"]["label"],"mount_closed":true,"installed_qualification":false}),
        )
    }
}
pub fn prepare_area() -> Result<Value> {
    crate::answer_source::Source::protect()?;
    let lock = files::Lock::acquire(Path::new(crate::install_session::LOCK), 0)?;
    enzimos_policy::installer_mount_area::create(&lock)
}
pub fn prepare_storage_area() -> Result<Value> {
    crate::answer_source::Source::protect()?;
    let lock = files::Lock::acquire(Path::new(crate::install_session::LOCK), 0)?;
    enzimos_policy::installer_mount_area::create_storage(&lock)
}
pub fn prepare_target_area() -> Result<Value> {
    crate::answer_source::Source::protect()?;
    let lock = files::Lock::acquire(Path::new(crate::install_session::LOCK), 0)?;
    enzimos_policy::installer_mount_area::create_target(&lock)
}
pub fn inspect(label: Label) -> Result<Value> {
    let volume = Volume::open(label)?;
    let source = volume.answers()?;
    source.recheck()?;
    volume.recheck()?;
    drop(source);
    let closed = volume.close()?;
    Ok(
        value!({"schema":1,"answer_volume":closed,"installation_started":false,"installed_qualification":false}),
    )
}
pub fn prepare() -> Result<Value> {
    let volume = Volume::open(Label::Answers)?;
    let source = volume.answers()?;
    let result = crate::install_coordinator::prepare_with_lock(&source, volume.lock.duplicate()?)?;
    source.recheck()?;
    volume.recheck()?;
    drop(source);
    let closed = volume.close()?;
    Ok(value!({"installation":result,"answer_volume":closed,"finish_requested":false}))
}
/// Fresh unattended console operation; the original exclusion lock also owns
/// all three one-shot private areas. The read-only input volume remains owned
/// while any explicit test script is being copied and the finish is requested.
pub fn install_fresh() -> Result<Value> {
    crate::answer_source::Source::protect()?;
    let lock = files::Lock::acquire(Path::new(crate::install_session::LOCK), 0)?;
    enzimos_policy::installer_mount_area::create(&lock)?;
    enzimos_policy::installer_mount_area::create_storage(&lock)?;
    enzimos_policy::installer_mount_area::create_target(&lock)?;
    let volume = Volume::with_lock(Label::Answers, lock)?;
    let source = volume.answers()?;
    let result = crate::install_coordinator::finish_with_lock(&source, volume.lock.duplicate()?)?;
    source.recheck()?;
    volume.recheck()?;
    drop(source);
    let closed = volume.close()?;
    Ok(value!({"installation":result,"answer_volume":closed,"finish_requested":true}))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn area_line() -> &'static str {
        "1 53 0:27 /enzimos-answers /run/enzimos-answers rw,nodev,nosuid,noexec - tmpfs tmpfs rw\n"
    }
    fn area() -> mountinfo::Row {
        mountinfo::parse(area_line()).unwrap().remove(0)
    }
    #[test]
    fn fresh_answer_mount_refuses_existing_targets_and_shared_or_nonvolatile_parent() {
        let good = area_line();
        assert!(admit(&mountinfo::parse(good).unwrap(), 1).is_ok());
        for bad in [
            good.replace("noexec -", "noexec shared:1 -"),
            good.replace("tmpfs tmpfs", "ext4 /dev/root"),
            format!(
                "{good}2 1 8:17 / {ROOT} ro,nodev,nosuid,noexec - ext4 /dev/fixture ro,norecovery\n"
            ),
        ] {
            assert!(admit(&mountinfo::parse(&bad).unwrap(), 1).is_err());
        }
        assert!(admit(&mountinfo::parse(good).unwrap(), 2).is_err());
    }
    #[test]
    fn optical_mount_requires_readback_of_private_ownership_and_rock_ridge_override() {
        let good = format!(
            "{}42 1 11:1 / {ROOT} ro,nodev,nosuid,noexec - iso9660 /dev/sr1 ro,uid=0,gid=0,fmode=600,dmode=700,overriderockperm\n",
            area_line()
        );
        assert!(
            mounted(
                &mountinfo::parse(&good).unwrap(),
                42,
                (11, 1),
                "iso9660",
                &area()
            )
            .is_ok()
        );
        for bad in [
            good.replace(",overriderockperm", ""),
            good.replace("fmode=600", "fmode=644"),
            good.replace("dmode=700", "dmode=755"),
            good.replace("uid=0", "uid=1000"),
            good.replace("gid=0", "gid=1000"),
            good.replace("ro,nodev", "rw,nodev"),
            good.replace("11:1", "11:2"),
        ] {
            assert!(
                mounted(
                    &mountinfo::parse(&bad).unwrap(),
                    42,
                    (11, 1),
                    "iso9660",
                    &area()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn owned_ext4_mount_requires_no_journal_replay_and_original_device_mount() {
        let good = format!(
            "{}42 1 8:17 / {ROOT} ro,nodev,nosuid,noexec - ext4 /dev/fixture ro,norecovery\n",
            area_line()
        );
        assert!(
            mounted(
                &mountinfo::parse(&good).unwrap(),
                42,
                (8, 17),
                "ext4",
                &area()
            )
            .is_ok()
        );
        assert!(
            mounted(
                &mountinfo::parse(&good.replace("norecovery", "noload")).unwrap(),
                42,
                (8, 17),
                "ext4",
                &area()
            )
            .is_ok()
        );
        for bad in [
            good.replace(",norecovery", ""),
            good.replace("ro,nodev", "rw,nodev"),
            good.replace(",noexec", ""),
            good.replace("8:17", "8:18"),
            good.replace("/ /run", "/subdir /run"),
            good.replace("noexec -", "noexec shared:3 -"),
        ] {
            assert!(
                mounted(
                    &mountinfo::parse(&bad).unwrap(),
                    42,
                    (8, 17),
                    "ext4",
                    &area()
                )
                .is_err()
            );
        }
        assert!(
            mounted(
                &mountinfo::parse(&good).unwrap(),
                43,
                (8, 17),
                "ext4",
                &area()
            )
            .is_err()
        );
    }
}
