// SPDX-License-Identifier: MIT
//! A known write may change only timestamps on the original block description.
//! These receipts observe a successful vendor call; they do not prove worker closure.
use enzimos_platform::{Error, Result, files, json, mount_identity, process, require};
use enzimos_policy::block;
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
const STORE: &str = "/run/enzimos-install-native";
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "private original device-write store required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
pub(crate) fn transition(before: &files::FileIdentity, after: &files::FileIdentity) -> Result<()> {
    require(
        (
            before.0, before.1, before.2, before.7, before.8, before.9, before.10,
        ) == (
            after.0, after.1, after.2, after.7, after.8, after.9, after.10,
        ) && before.7 & libc::S_IFMT == libc::S_IFBLK
            && before.8 == 0
            && before.10 == 1
            && before.7 & 0o002 == 0,
        "known write replaced or changed original block inode authority",
    )
    // Timestamps are not compared: they follow the wall clock, which steps back when the
    // live system first syncs time on a machine whose hardware clock runs ahead.
}
pub(crate) struct Epoch {
    original: File,
    current: Mutex<State>,
    block: Value,
    mount: u64,
    flags: i32,
}
struct State {
    identity: files::FileIdentity,
    writer: Option<String>,
}
impl Epoch {
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    pub(crate) fn capture(file: &File) -> Result<Arc<Self>> {
        enzimos_policy::namespaces::initial()?;
        let original = file.try_clone()?;
        let block = block::observe(original.as_fd())?;
        require(
            block["read_only"] == false,
            "known-write epoch requires writable kernel device",
        )?;
        let flags = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) };
        require(
            flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
            "original read-only device description required",
        )?;
        let this = Self {
            current: Mutex::new(State {
                identity: files::identity(&original.metadata()?),
                writer: None,
            }),
            mount: mount_identity::id(original.as_fd(), true)?,
            original,
            block,
            flags,
        };
        this.recheck()?;
        Ok(Arc::new(this))
    }
    pub(crate) fn snapshot(&self) -> Result<files::FileIdentity> {
        Ok(self
            .current
            .lock()
            .map_err(|_| Error("device epoch state unavailable".into()))?
            .identity)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    fn fixed(&self) -> Result<()> {
        enzimos_policy::namespaces::initial()?;
        require(
            block::observe(self.original.as_fd())? == self.block
                && mount_identity::id(self.original.as_fd(), true)? == self.mount
                && unsafe { libc::fcntl(self.original.as_raw_fd(), libc::F_GETFL) } == self.flags,
            "original device description, media epoch or flags changed",
        )
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.fixed()?;
        require(
            files::identity(&self.original.metadata()?) == self.snapshot()?,
            "original device inode epoch changed outside known write",
        )
    }
    pub(crate) fn begin(self: &Arc<Self>, role: &'static str) -> Result<Write> {
        require(
            matches!(
                role,
                "whole-disk-wipe"
                    | "whole-disk-gpt"
                    | "whole-disk-bios"
                    | "bios-device-events"
                    | "gpt-preview-device-events"
                    | "partition-format"
                    | "mapped-root-format"
                    | "luks-mapper-open"
            ),
            "device write role outside closed registry",
        )?;
        self.recheck()?;
        let parent = files::directory(Path::new(STORE), Some(0))?;
        let parent_shape = shape(&parent)?;
        let parent_mount = mount_identity::id(parent.as_fd(), true)?;
        let run = files::directory(Path::new("/run"), Some(0))?;
        require(
            parent_mount == mount_identity::id(run.as_fd(), true)?,
            "device-write store left original live run mount",
        )?;
        let name = format!("device-write-{}.json", files::random_hex(16)?);
        let before = self.snapshot()?;
        {
            let mut state = self
                .current
                .lock()
                .map_err(|_| Error("device epoch state unavailable".into()))?;
            require(
                state.identity == before && state.writer.is_none(),
                "original device already has an incomplete write; no replay",
            )?;
            // A failed intent publication or dropped token leaves this reservation
            // incomplete. There is no destructor retry, reset or implicit cleanup.
            state.writer = Some(name.clone());
        }
        let body = value!({"schema":1,"role":role,"phase":"writing","caller_pid":std::process::id(),
            "block":self.block,"device_mount":self.mount,"before":before,"after":null,
            "device_events_settled":false,"worker_closed":false,"installed_qualification":false});
        let receipt = files::atomic_relative_retained(
            &parent,
            Path::new(&name),
            &json::canonical(&body)?,
            0o600,
            Some(0),
            false,
            32768,
        )?;
        let receipt_identity = files::identity(&receipt.metadata()?);
        self.recheck()?;
        Ok(Write {
            epoch: Arc::clone(self),
            parent,
            parent_shape,
            parent_mount,
            name,
            receipt,
            receipt_identity,
            body,
            before,
            settled: false,
        })
    }
}
pub(crate) struct Write {
    // Own the original OFD and fenced epoch through a supervised write lifetime.
    // This token is neither cloneable nor constructible from a receipt.
    epoch: Arc<Epoch>,
    parent: File,
    parent_shape: Shape,
    parent_mount: u64,
    name: String,
    receipt: File,
    receipt_identity: files::FileIdentity,
    body: Value,
    before: files::FileIdentity,
    settled: bool,
}
impl Write {
    pub(crate) fn checkpoint(&self) -> Result<()> {
        self.epoch.fixed()?;
        transition(
            &self.before,
            &files::identity(&self.epoch.original.metadata()?),
        )?;
        let state = self
            .epoch
            .current
            .lock()
            .map_err(|_| Error("device epoch state unavailable".into()))?;
        require(
            state.identity == self.before && state.writer.as_deref() == Some(self.name.as_str()),
            "original device write reservation changed",
        )
    }
    pub(crate) fn for_epoch(&self, epoch: &Arc<Epoch>) -> Result<()> {
        require(
            Arc::ptr_eq(&self.epoch, epoch),
            "write token belongs to another original device epoch",
        )
    }
    /// Vendor completion may precede udev's timestamp refresh on the same node.
    /// Keep the one-use write reservation until that bounded queue is drained.
    pub(crate) fn settle(self) -> Result<Self> {
        Ok(Self::settle_batch(vec![self])?.remove(0))
    }
    /// Drain the event queue once while all original node reservations remain
    /// live. No receipt reconstructs a token, and failure consumes the batch.
    pub(crate) fn settle_batch(mut writes: Vec<Self>) -> Result<Vec<Self>> {
        require(
            !writes.is_empty() && writes.len() <= 4,
            "device settlement cohort bound",
        )?;
        for (index, write) in writes.iter().enumerate() {
            require(
                !write.settled
                    && writes[..index]
                        .iter()
                        .all(|v| !Arc::ptr_eq(&v.epoch, &write.epoch)),
                "device settlement repeated original epoch",
            )?;
            write.checkpoint()?;
        }
        let output = process::run(
            "/usr/bin/udevadm",
            &["settle", "--timeout=30"],
            &[],
            Duration::from_secs(35),
            65536,
        )?;
        require(
            output.status.success(),
            "owned device-write events did not settle; no replay",
        )?;
        for write in &mut writes {
            write.checkpoint()?;
            write.settled = true;
        }
        Ok(writes)
    }
    /// The caller has checked the actual vendor result and original named inode,
    /// physical graph and source lifetime. No report supplies the new epoch.
    pub(crate) fn observed(mut self, named: &File) -> Result<()> {
        require(
            self.settled,
            "device-write observation requires successful event settlement",
        )?;
        self.epoch.fixed()?;
        let after = files::identity(&self.epoch.original.metadata()?);
        transition(&self.before, &after)?;
        require(
            files::identity(&named.metadata()?) == after
                && mount_identity::id(named.as_fd(), true)? == self.epoch.mount,
            "known write lost original named block description",
        )?;
        let named_parent = files::directory(Path::new(STORE), Some(0))?;
        let named_receipt = files::open_relative(&self.parent, Path::new(&self.name))?;
        require(
            shape(&named_parent)? == self.parent_shape
                && shape(&self.parent)? == self.parent_shape
                && mount_identity::id(named_parent.as_fd(), true)? == self.parent_mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount
                && files::identity(&self.receipt.metadata()?) == self.receipt_identity
                && files::identity(&named_receipt.metadata()?) == self.receipt_identity
                && mount_identity::id(self.receipt.as_fd(), true)? == self.parent_mount
                && mount_identity::id(named_receipt.as_fd(), true)? == self.parent_mount
                && files::read_file(&self.receipt, 32768, Some(0), true)?
                    == json::canonical(&self.body)?,
            "original device-write intent or parent changed",
        )?;
        let mut current = self
            .epoch
            .current
            .lock()
            .map_err(|_| Error("device epoch state unavailable".into()))?;
        require(
            current.identity == self.before
                && current.writer.as_deref() == Some(self.name.as_str()),
            "concurrent original device write epoch change",
        )?;
        self.epoch.fixed()?;
        require(
            files::identity(&self.epoch.original.metadata()?) == after
                && files::identity(&named.metadata()?) == after,
            "original device epoch changed during write observation",
        )?;
        self.body["after"] = value!(after);
        self.body["phase"] = value!(if self.body["role"] == "gpt-preview-device-events" {
            "preview-device-events-observed"
        } else {
            "data-write-observed"
        });
        self.body["device_events_settled"] = value!(true);
        let receipt = files::atomic_replace_original(
            &self.parent,
            Path::new(&self.name),
            &json::canonical(&self.body)?,
            0o600,
            Some(0),
            32768,
            &self.receipt,
        )?;
        require(
            files::read_file(&receipt, 32768, Some(0), true)? == json::canonical(&self.body)?
                && files::identity(&self.epoch.original.metadata()?) == after,
            "device write observation readback changed",
        )?;
        current.identity = after;
        current.writer = None;
        drop(current);
        self.epoch.recheck()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn initial() -> files::FileIdentity {
        (7, 127, 0, 100, 1, 100, 1, libc::S_IFBLK | 0o660, 0, 993, 1)
    }
    #[test]
    fn only_timestamp_changes_in_either_direction_on_same_protected_block_node_are_known_writes() {
        let before = initial();
        let mut after = before;
        after.3 = 101;
        after.4 = 2;
        after.5 = 101;
        after.6 = 3;
        assert!(transition(&before, &after).is_ok());
        assert!(transition(&before, &before).is_ok());
        let cases = [
            (
                after.0 + 1,
                after.1,
                after.2,
                after.7,
                after.8,
                after.9,
                after.10,
            ),
            (
                after.0,
                after.1 + 1,
                after.2,
                after.7,
                after.8,
                after.9,
                after.10,
            ),
            (
                after.0,
                after.1,
                after.2,
                after.7 | 0o002,
                after.8,
                after.9,
                after.10,
            ),
            (after.0, after.1, after.2, after.7, 1000, after.9, after.10),
            (after.0, after.1, after.2, after.7, after.8, after.9, 2),
            (after.0, after.1, 4096, after.7, after.8, after.9, after.10),
            (after.0, after.1, after.2, after.7, after.8, 0, after.10),
            (
                after.0,
                after.1,
                after.2,
                libc::S_IFBLK | 0o600,
                after.8,
                after.9,
                after.10,
            ),
        ];
        for (dev, ino, len, mode, uid, gid, links) in cases {
            let mut changed = after;
            (
                changed.0, changed.1, changed.2, changed.7, changed.8, changed.9, changed.10,
            ) = (dev, ino, len, mode, uid, gid, links);
            assert!(transition(&before, &changed).is_err());
        }
        // A clock stepped back by time sync is still the same known write.
        after = before;
        (after.3, after.4, after.5, after.6) = (50, 0, 50, 0);
        assert!(transition(&before, &after).is_ok());
        after.7 = libc::S_IFREG | 0o660;
        assert!(transition(&before, &after).is_err());
    }
}
