// SPDX-License-Identifier: MIT
//! Fixed target layout and kernel identity checks for temporary install mounts.
use enzimos_platform::{Error, Result, mountinfo, process, require};
use enzimos_policy::{filesystem, subvolume, topology};
use serde_json::Value;
use std::{
    fs::File,
    os::fd::{AsFd, AsRawFd},
    path::Path,
    time::Duration,
};
pub(crate) enum Spec {
    Top,
    Subvolume(Value),
    Esp,
}
impl Spec {
    pub(crate) fn validate(&self, path: &Path) -> Result<()> {
        match self {
            Self::Top => require(
                path.parent() == Some(Path::new("/run/enzimos-install-native/mounts"))
                    && path.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
                        s.len() == 32
                            && s.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    }),
                "private installer mount location required",
            ),
            Self::Esp => require(
                path == Path::new("/mnt/enzimos/boot"),
                "fixed installer ESP mount required",
            ),
            Self::Subvolume(identity) => {
                enzimos_platform::json::fields(identity, "path id uuid parent_uuid")?;
                let name = identity["path"]
                    .as_str()
                    .ok_or_else(|| Error("target subvolume name missing".into()))?;
                let expected = match name {
                    "enzimos-root" => "/mnt/enzimos",
                    "enzimos-home" => "/mnt/enzimos/home",
                    "enzimos-control" => "/mnt/enzimos/var/lib/enzimos-control",
                    "enzimos-authority" => "/mnt/enzimos/etc/pacman.d/gnupg",
                    "enzimos-swap" => "/mnt/enzimos/swap",
                    _ => return Err(Error("fixed installer subvolume required".into())),
                };
                enzimos_policy::identity::uuid(
                    identity["uuid"]
                        .as_str()
                        .ok_or_else(|| Error("target subvolume UUID missing".into()))?,
                )?;
                require(
                    path == Path::new(expected)
                        && identity["id"].as_u64().is_some_and(|id| id >= 256)
                        && identity["parent_uuid"].is_null(),
                    "target subvolume identity or path refused",
                )
            }
        }
    }
    pub(crate) fn filesystem(&self) -> &str {
        if matches!(self, Self::Esp) {
            "vfat"
        } else {
            "btrfs"
        }
    }
    pub(crate) fn noexec(&self) -> bool {
        !matches!(self, Self::Subvolume(identity) if identity["path"] == "enzimos-root" || identity["path"] == "enzimos-home")
    }
    pub(crate) fn options(&self) -> String {
        match self {
            Self::Top => "subvolid=5,nodiscard".into(),
            Self::Esp => "fmask=0177,dmask=0077,uid=0,gid=0".into(),
            Self::Subvolume(identity) => format!(
                "subvolid={},nodiscard{}",
                identity["id"].as_u64().unwrap(),
                if identity["path"] == "enzimos-root" || identity["path"] == "enzimos-home" {
                    ",compress=zstd:1"
                } else {
                    ""
                }
            ),
        }
    }
    pub(crate) fn row(&self, rows: &[mountinfo::Row], expected: &mountinfo::Row) -> Result<()> {
        if matches!(self, Self::Top) {
            return crate::mount_owner::row_matches(rows, expected);
        }
        let root = match self {
            Self::Subvolume(identity) => format!("/{}", identity["path"].as_str().unwrap()),
            _ => "/".into(),
        };
        require(
            rows.iter().filter(|r| r.target == expected.target).count() == 1
                && rows.iter().any(|r| r == expected)
                && expected.filesystem == self.filesystem()
                && expected.root == root
                && ["rw", "nosuid", "nodev"]
                    .iter()
                    .all(|option| expected.options.split(',').any(|s| s == *option))
                && !expected.options.split(',').any(|s| s == "ro")
                && expected.options.split(',').any(|s| s == "noexec") == self.noexec()
                && !expected.optional.iter().any(|s| s.starts_with("shared:")),
            "target filesystem mount identity or options changed",
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
    pub(crate) fn observe(
        &self,
        mounted: &File,
        source: &File,
        uuid: &str,
        graph: &topology::Graph,
        row: &mountinfo::Row,
    ) -> Result<()> {
        match self {
            Self::Top | Self::Subvolume(_) => {
                require(
                    filesystem::observe(mounted.as_fd())?["filesystem_uuid"] == uuid
                        && topology::mounted_btrfs(uuid)? == *graph,
                    "target Btrfs filesystem or members changed",
                )?;
                if let Self::Subvolume(identity) = self {
                    let (current, readonly) =
                        subvolume::observe(mounted.as_fd(), identity["path"].as_str().unwrap())?;
                    require(
                        !readonly && current == *identity,
                        "mounted target subvolume differs from prepared kernel identity",
                    )?;
                }
            }
            Self::Esp => {
                enzimos_policy::recovery_records::fat_uuid(uuid)?;
                let info = enzimos_policy::block::observe(source.as_fd())?;
                let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
                require(
                    unsafe { libc::fstatfs(mounted.as_raw_fd(), &mut stat) } == 0
                        && stat.f_type == 0x4d44
                        && (u64::from(row.major), u64::from(row.minor))
                            == (
                                info["major"].as_u64().unwrap(),
                                info["minor"].as_u64().unwrap(),
                            ),
                    "target ESP kernel filesystem or source differs",
                )?;
                let probe = process::run_with_fds(
                    "/usr/bin/blkid",
                    &["--probe", "--output", "export", "@fd:0"],
                    &[],
                    Duration::from_secs(30),
                    65536,
                    &[source.as_fd()],
                )?;
                require(
                    probe.status.success()
                        && crate::format::filesystem(&probe.stdout, "vfat")?["uuid"] == uuid,
                    "target ESP filesystem UUID changed",
                )?;
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn prepared_subvolume_mount_requires_fixed_destination_and_kernel_identity() {
        let identity = json!({"path":"enzimos-root","id":256,"uuid":"11111111-1111-4111-8111-111111111111","parent_uuid":null});
        let spec = Spec::Subvolume(identity.clone());
        assert!(spec.validate(Path::new("/mnt/enzimos")).is_ok());
        assert!(spec.validate(Path::new("/mnt/foreign")).is_err());
        assert!(!spec.noexec());
        for (key, value) in [
            ("id", json!("256")),
            ("id", json!(5)),
            ("path", json!("../root")),
            ("uuid", json!("bad")),
            ("parent_uuid", json!("11111111-1111-4111-8111-111111111111")),
        ] {
            let mut changed = identity.clone();
            changed[key] = value;
            assert!(
                Spec::Subvolume(changed)
                    .validate(Path::new("/mnt/enzimos"))
                    .is_err()
            );
        }
        assert!(Spec::Esp.validate(Path::new("/mnt/enzimos/boot")).is_ok());
        assert!(Spec::Esp.validate(Path::new("/boot")).is_err());
    }
    #[test]
    fn target_root_and_private_authority_have_distinct_execution_policies() {
        let mut identity = json!({"path":"enzimos-root","id":256,"uuid":"11111111-1111-4111-8111-111111111111","parent_uuid":null});
        let row = mountinfo::parse(
            "100 20 0:42 /enzimos-root /mnt/enzimos rw,nosuid,nodev,noatime - btrfs /dev/vda3 rw\n",
        )
        .unwrap()
        .remove(0);
        assert!(
            Spec::Subvolume(identity.clone())
                .row(std::slice::from_ref(&row), &row)
                .is_ok()
        );
        let mut changed = row.clone();
        changed.options.push_str(",noexec");
        assert!(
            Spec::Subvolume(identity.clone())
                .row(&[changed.clone()], &changed)
                .is_err()
        );
        identity["path"] = json!("enzimos-authority");
        identity["id"] = json!(257);
        let authority = Spec::Subvolume(identity);
        assert!(authority.noexec());
        assert!(
            authority
                .validate(Path::new("/mnt/enzimos/etc/pacman.d/gnupg"))
                .is_ok()
        );
        assert!(authority.row(std::slice::from_ref(&row), &row).is_err());
        let mut changed = row;
        changed.root = "/enzimos-authority".into();
        changed.target = "/mnt/enzimos/etc/pacman.d/gnupg".into();
        changed.options.push_str(",noexec");
        assert!(authority.row(&[changed.clone()], &changed).is_ok());
        changed.optional.push("shared:1".into());
        assert!(authority.row(&[changed.clone()], &changed).is_err());
    }
}
