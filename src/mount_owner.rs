// SPDX-License-Identifier: MIT
//! Fresh, retained top-level Btrfs mount. Failed normal unmount keeps ownership.
use crate::{mount_admission::Proof, mount_spec::Spec, setup};
use enzimos_platform::{Error, Result, files, mount_identity, mountinfo, require};
use enzimos_policy::{block, installer_mount_area::Area, namespaces, storage_runtime, topology};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
type Identity = (u64, u64, u32, u32, u32);
fn identity(file: &File) -> Result<Identity> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
pub(crate) struct Top {
    path: PathBuf,
    source: File,
    source_identity: serde_json::Value,
    underlying: File,
    underlying_identity: Identity,
    underlying_unique: u64,
    mounted: Option<File>,
    mounted_identity: Identity,
    unique: u64,
    pub proof: Proof,
    spec: Spec,
    private_area: Option<Area>,
}
pub fn row_matches(rows: &[mountinfo::Row], expected: &mountinfo::Row) -> Result<()> {
    require(
        rows.iter()
            .filter(|row| row.target == expected.target)
            .count()
            == 1
            && rows.iter().any(|row| row == expected)
            && !rows
                .iter()
                .any(|row| row.target.starts_with(&format!("{}/", expected.target)))
            && expected.filesystem == "btrfs"
            && expected.root == "/"
            && ["rw", "nodev", "nosuid", "noexec"]
                .iter()
                .all(|option| expected.options.split(',').any(|s| s == *option))
            && !expected.options.split(',').any(|s| s == "ro")
            && !expected.optional.iter().any(|s| s.starts_with("shared:")),
        "owned top mount replaced, shadowed or writable policy changed",
    )
}
// Only the actual retained Area can supply this exception. Remove its exact
// original bind row before the existing strict one-owned-filesystem codec runs.
fn owned_rows(
    rows: &[mountinfo::Row],
    mounted: &mountinfo::Row,
    area: Option<&Area>,
) -> Result<Vec<mountinfo::Row>> {
    let Some(area) = area.filter(|a| a.binding().target == mounted.target) else {
        return Ok(rows.to_vec());
    };
    area.recheck_covered()?;
    parent_rows(rows, mounted, area.binding())
}
fn parent_rows(
    rows: &[mountinfo::Row],
    mounted: &mountinfo::Row,
    parent: &mountinfo::Row,
) -> Result<Vec<mountinfo::Row>> {
    require(
        parent.target == mounted.target
            && parent.id != mounted.id
            && mounted.parent == parent.id
            && parent.optional.is_empty()
            && rows.iter().filter(|r| r.target == mounted.target).count() == 2
            && rows.iter().filter(|r| *r == parent).count() == 1
            && rows.iter().filter(|r| *r == mounted).count() == 1,
        "original private root bind or its owned covering mount changed",
    )?;
    Ok(rows.iter().filter(|r| *r != parent).cloned().collect())
}
impl Top {
    pub(crate) fn open(source: BorrowedFd<'_>, path: &Path, uuid: &str) -> Result<Self> {
        Self::attach(source, path, uuid, Spec::Top)
    }
    pub(crate) fn subvolume(
        source: BorrowedFd<'_>,
        path: &Path,
        uuid: &str,
        identity: serde_json::Value,
    ) -> Result<Self> {
        Self::attach(source, path, uuid, Spec::Subvolume(identity))
    }
    pub(crate) fn esp(source: BorrowedFd<'_>, path: &Path, uuid: &str) -> Result<Self> {
        Self::attach(source, path, uuid, Spec::Esp)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (mount).")]
    fn attach(source: BorrowedFd<'_>, path: &Path, uuid: &str, spec: Spec) -> Result<Self> {
        setup::live()?;
        namespaces::initial()?;
        if spec.filesystem() == "btrfs" {
            enzimos_policy::identity::uuid(uuid)?;
        } else {
            enzimos_policy::recovery_records::fat_uuid(uuid)?;
        }
        spec.validate(path)?;
        let private_area = if matches!(spec, Spec::Top) {
            Some(Area::observe_storage()?)
        } else if matches!(&spec, Spec::Subvolume(identity) if identity["path"] == "enzimos-root") {
            Some(Area::observe_target()?)
        } else {
            None
        };
        let source = File::from(source.try_clone_to_owned()?);
        let source_identity = block::observe(source.as_fd())?;
        let number = (
            source_identity["major"].as_u64().unwrap() as u32,
            source_identity["minor"].as_u64().unwrap() as u32,
        );
        let graph = topology::observe(&[number])?;
        if matches!(spec, Spec::Top) {
            files::ensure_directory(path.parent().unwrap(), 0o700, 0)?;
        } else {
            files::directory(path.parent().unwrap(), Some(0))?;
        }
        // A new directory name is never adopted after an interrupted attempt.
        if matches!(spec, Spec::Top) {
            std::fs::create_dir(path)?;
            std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        } else {
            match std::fs::symlink_metadata(path) {
                Ok(_) => {
                    files::directory(path, Some(0))?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    files::create_directory(path, 0o700, 0)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        let underlying = files::directory(path, Some(0))?;
        let underlying_identity = identity(&underlying)?;
        let underlying_unique = mount_identity::id(underlying.as_fd(), true)?;
        if let Some(area) = &private_area {
            area.recheck()?;
            require(
                underlying_unique == mount_identity::id(area.descriptor()?.as_fd(), true)?,
                "fresh top stub left original private storage area",
            )?;
        }
        let rows = storage_runtime::rows()?;
        let parent_id = mount_identity::id(underlying.as_fd(), false)?;
        let parent = rows
            .iter()
            .find(|r| r.id == parent_id)
            .ok_or_else(|| Error("mount parent observation missing".into()))?;
        require(
            !parent.optional.iter().any(|s| s.starts_with("shared:"))
                && !rows.iter().any(|r| {
                    (r.target == path.to_str().unwrap()
                        && private_area.as_ref().is_none_or(|a| r != a.binding()))
                        || r.target.starts_with(&format!("{}/", path.display()))
                })
                && std::fs::read_dir(path)?.next().is_none(),
            "installer mount parent is shared or target occupied",
        )?;
        require(
            identity(&files::directory(path, Some(0))?)? == underlying_identity,
            "installer mount target changed",
        )?;
        if let Some(area) = &private_area {
            area.recheck()?;
            require(
                parent_id == area.binding().id,
                "installer parent differs from original private bind",
            )?;
        }
        let device = CString::new(format!("/proc/self/fd/{}", source.as_raw_fd())).unwrap();
        let target = CString::new(format!("/proc/self/fd/{}/.", underlying.as_raw_fd())).unwrap();
        let filesystem = CString::new(spec.filesystem()).unwrap();
        let options = CString::new(spec.options()).unwrap();
        let flags = libc::MS_NOSUID
            | libc::MS_NODEV
            | libc::MS_NOATIME
            | if spec.noexec() { libc::MS_NOEXEC } else { 0 };
        require(
            unsafe {
                libc::mount(
                    device.as_ptr(),
                    target.as_ptr(),
                    filesystem.as_ptr(),
                    flags,
                    options.as_ptr().cast(),
                )
            } == 0,
            "fresh installer Btrfs mount failed",
        )?;
        // Once mounted, observation failure leaves the target for inspection.
        let mounted = files::directory(path, Some(0))?;
        let unique = mount_identity::id(mounted.as_fd(), true)?;
        let normal = mount_identity::id(mounted.as_fd(), false)?;
        let mounted_identity = identity(&mounted)?;
        let rows = storage_runtime::rows()?;
        let row = rows
            .iter()
            .find(|r| r.id == normal && r.target == path.to_str().unwrap())
            .ok_or_else(|| Error("new installer mount observation missing".into()))?
            .clone();
        require(
            row.parent == parent_id,
            "new installer mount left original parent",
        )?;
        spec.row(&owned_rows(&rows, &row, private_area.as_ref())?, &row)?;
        require(
            unique != underlying_unique && block::observe(source.as_fd())? == source_identity,
            "new installer filesystem differs from retained device",
        )?;
        spec.observe(&mounted, &source, uuid, &graph, &row)?;
        let this = Self {
            path: path.into(),
            source,
            source_identity,
            underlying,
            underlying_identity,
            underlying_unique,
            mounted: Some(mounted),
            mounted_identity,
            unique,
            spec,
            private_area,
            proof: Proof {
                namespace: namespaces::identity(std::process::id(), "mnt")?,
                row,
                source: number,
                uuid: uuid.into(),
                graph,
            },
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn directory(&self) -> Result<&File> {
        self.mounted
            .as_ref()
            .ok_or_else(|| Error("installer top mount already closed".into()))
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        setup::live()?;
        namespaces::initial()?;
        if let Some(area) = &self.private_area {
            if area.binding().target == self.path.to_str().unwrap() {
                area.recheck_covered()?;
            } else {
                area.recheck()?;
            }
        }
        let held = self.directory()?;
        let current = files::directory(&self.path, Some(0))?;
        require(
            namespaces::identity(std::process::id(), "mnt")? == self.proof.namespace,
            "retained installer mount namespace changed",
        )?;
        let held_identity = identity(held)?;
        let named_identity = identity(&current)?;
        require(
            held_identity == self.mounted_identity && named_identity == self.mounted_identity,
            &format!(
                "retained installer root directory identity changed: expected {:?}; held {:?}; named {:?}",
                self.mounted_identity, held_identity, named_identity
            ),
        )?;
        require(
            mount_identity::id(held.as_fd(), true)? == self.unique
                && mount_identity::id(current.as_fd(), true)? == self.unique,
            "retained installer original filesystem mount identity changed",
        )?;
        require(
            identity(&self.underlying)? == self.underlying_identity
                && mount_identity::id(self.underlying.as_fd(), true)? == self.underlying_unique,
            "retained installer underlying original area changed",
        )?;
        require(
            block::observe(self.source.as_fd())? == self.source_identity,
            "retained installer original backing block identity changed",
        )?;
        require(
            topology::observe(&[self.proof.source])? == self.proof.graph,
            "retained installer original backing device ancestry changed",
        )?;
        self.spec.observe(
            held,
            &self.source,
            &self.proof.uuid,
            &self.proof.graph,
            &self.proof.row,
        )?;
        self.spec.row(
            &owned_rows(
                &storage_runtime::rows()?,
                &self.proof.row,
                self.private_area.as_ref(),
            )?,
            &self.proof.row,
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (umount2).")]
    pub(crate) fn close(&mut self) -> Result<()> {
        self.recheck()?;
        let target = CString::new(self.path.as_os_str().as_encoded_bytes()).unwrap();
        self.mounted.take();
        if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
            let current = files::directory(&self.path, Some(0))?;
            require(
                identity(&current)? == self.mounted_identity
                    && mount_identity::id(current.as_fd(), true)? == self.unique,
                "failed unmount encountered a replacement; retained mount cannot be reacquired",
            )?;
            self.mounted = Some(current);
            return Err(Error(
                "normal installer unmount failed; owned mount retained".into(),
            ));
        }
        require(
            !storage_runtime::rows()?.iter().any(|r| {
                (r.target == self.path.to_str().unwrap()
                    && self.private_area.as_ref().is_none_or(|a| r != a.binding()))
                    || r.id == self.proof.row.id
            }),
            "normal installer unmount not observed",
        )?;
        let current = files::directory(&self.path, Some(0))?;
        require(
            identity(&current)? == self.underlying_identity
                && mount_identity::id(current.as_fd(), true)? == self.underlying_unique,
            "installer underlying target changed during unmount",
        )?;
        if let Some(area) = &self.private_area {
            area.recheck()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod private_parent_tests {
    use super::*;
    #[test]
    fn covering_root_requires_the_exact_original_private_bind_and_parent() {
        let text = "42 1 0:33 /mnt/enzimos /mnt/enzimos rw,nodev,nosuid,noexec - overlay enzimos-live rw\n43 42 0:44 /enzimos-root /mnt/enzimos rw,nodev,nosuid - btrfs /dev/vda3 rw\n";
        let rows = mountinfo::parse(text).unwrap();
        let original = rows[0].clone();
        let mounted = rows[1].clone();
        assert_eq!(
            parent_rows(&rows, &mounted, &original).unwrap(),
            vec![mounted.clone()]
        );
        for bad in [
            text.replace("43 42", "43 1"),
            text.replace(" - overlay", " shared:1 - overlay"),
            text.replace("/mnt/enzimos /mnt/enzimos", "/other /mnt/enzimos"),
            format!("{text}44 42 0:45 / /mnt/enzimos rw - tmpfs tmpfs rw\n"),
        ] {
            let changed = mountinfo::parse(&bad).unwrap();
            assert!(parent_rows(&changed, &mounted, &original).is_err());
        }
    }
}
