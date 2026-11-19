// SPDX-License-Identifier: MIT
//! Typed allocation geometry; serialized plans confer no disk execution authority.
use crate::answers::Partition;
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::collections::BTreeSet;
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const ESP: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
const ROOT: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
pub const MAX_RECEIPT: usize = 2 * 1024 * 1024;
fn n(v: &Value) -> Result<u64> {
    v.as_u64()
        .ok_or_else(|| Error("allocation integer required".into()))
}
fn s(v: &Value) -> Result<&str> {
    v.as_str()
        .ok_or_else(|| Error("allocation text required".into()))
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| Error("allocation geometry overflow".into()))
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| Error("allocation geometry overflow".into()))
}
fn guid(v: &Value) -> Result<String> {
    let text = s(v)?.to_ascii_lowercase();
    enzimos_policy::identity::uuid(&text)?;
    Ok(text)
}
pub fn alongside(plan: &Value) -> bool {
    plan["schema"] == 2 && plan["mode"] == "alongside"
}
pub fn mode(plan: &Value, mode: Partition) -> Result<()> {
    require(
        match mode {
            Partition::Erase => plan["schema"] == 1,
            Partition::Alongside => alongside(plan),
        },
        "allocation mode differs from original answers",
    )
}
pub fn number(plan: &Value, index: usize) -> Result<u32> {
    let n = n(&plan["partitions"][index]["number"])?;
    require((1..=128).contains(&n), "allocation partition number bound")?;
    Ok(n as u32)
}
pub(crate) fn partition_number(disk: &str, node: &str) -> Result<u32> {
    old_number(disk, &value!(node))
}
fn old_number(disk: &str, node: &Value) -> Result<u32> {
    let suffix = s(node)?
        .strip_prefix(disk)
        .ok_or_else(|| Error("existing partition belongs to another disk".into()))?;
    let suffix = if disk.as_bytes().last().is_some_and(u8::is_ascii_digit) {
        suffix
            .strip_prefix('p')
            .ok_or_else(|| Error("existing partition separator missing".into()))?
    } else {
        suffix
    };
    let number = suffix
        .parse::<u32>()
        .map_err(|_| Error("existing partition number invalid".into()))?;
    require(
        (1..=128).contains(&number) && suffix == number.to_string(),
        "existing partition number not canonical",
    )?;
    Ok(number)
}
fn normalized(row: &Value) -> Result<Value> {
    require(row.is_object(), "partition row must be an object")?;
    let mut row = row.clone();
    row["uuid"] = value!(guid(&row["uuid"])?);
    row["type"] = value!(guid(&row["type"])?);
    Ok(row)
}
pub fn effective_table(before: &Value, review: &Value) -> Result<Value> {
    let mut table = before["table"].clone();
    let rows = table["partitions"]
        .as_array_mut()
        .ok_or_else(|| Error("existing GPT partitions missing".into()))?;
    let shrink = &review["shrink"];
    if !shrink.is_null() {
        json::fields(shrink, "node filesystem old_size new_size")?;
        require(
            matches!(shrink["filesystem"].as_str(), Some("ext4" | "ntfs")),
            "unsupported reviewed shrink filesystem",
        )?;
        let matches = rows
            .iter_mut()
            .filter(|r| r["node"] == shrink["node"])
            .collect::<Vec<_>>();
        require(
            matches.len() == 1,
            "reviewed shrink partition missing or ambiguous",
        )?;
        let row = matches.into_iter().next().unwrap();
        require(
            row["size"] == shrink["old_size"]
                && n(&shrink["new_size"])? > 0
                && n(&shrink["new_size"])? < n(&row["size"])?,
            "reviewed shrink geometry differs",
        )?;
        let device = before["devices"][0]["children"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["name"] == shrink["node"]))
            .ok_or_else(|| Error("reviewed shrink filesystem observation missing".into()))?;
        require(
            device["fstype"] == shrink["filesystem"]
                && device["uuid"].as_str().is_some_and(|s| !s.is_empty()),
            "reviewed shrink filesystem identity differs",
        )?;
        row["size"] = shrink["new_size"].clone();
    }
    Ok(table)
}
pub fn alongside_plan(
    before: &Value,
    review: &Value,
    disk: &Value,
    guids: &[String; 2],
) -> Result<Value> {
    json::fields(before, "disk table devices")?;
    json::fields(
        review,
        "schema disk before_sha256 start size sector shrink id label",
    )?;
    let mut unsigned = review.clone();
    unsigned.as_object_mut().unwrap().remove("id");
    unsigned.as_object_mut().unwrap().remove("label");
    require(
        review["schema"] == 1
            && review["id"] == json::fingerprint(&unsigned)?
            && review["before_sha256"] == json::fingerprint(before)?
            && review["disk"] == disk["path"]
            && before["disk"] == disk["path"],
        "alongside review digest or disk changed",
    )?;
    let path = s(&disk["path"])?;
    crate::answers::disk_path(path)?;
    let table = &before["table"];
    let sector = n(&review["sector"])?;
    let bytes = n(&disk["bytes"])?;
    require(
        matches!(sector, 512 | 4096)
            && bytes % sector == 0
            && table["label"] == "gpt"
            && table["device"] == path
            && table["unit"] == "sectors"
            && table["sectorsize"] == sector
            && n(&table["lastlba"])? < bytes / sector,
        "alongside original GPT geometry differs",
    )?;
    let label = guid(&table["id"])?;
    let old = table["partitions"]
        .as_array()
        .ok_or_else(|| Error("original GPT partitions missing".into()))?;
    require(
        !old.is_empty() && old.len() <= 120,
        "alongside existing partition count bound",
    )?;
    let mut used = BTreeSet::new();
    let mut identities = BTreeSet::from([label.clone()]);
    for row in old {
        require(
            used.insert(old_number(path, &row["node"])?) && identities.insert(guid(&row["uuid"])?),
            "ambiguous original partition identity",
        )?;
        normalized(row)?;
    }
    for uuid in guids {
        enzimos_policy::identity::uuid(uuid)?;
        require(
            identities.insert(uuid.clone()),
            "new allocation GUID collides",
        )?;
    }
    let mut available = (1..=128).filter(|n| !used.contains(n));
    let esp = available.next().unwrap();
    let root = available.next().unwrap();
    let start = n(&review["start"])?;
    let size = n(&review["size"])?;
    let end = add(start, size)?;
    require(
        start % (MIB / sector) == 0 && end % (MIB / sector) == 0 && mul(size, sector)? >= 24 * GIB,
        "alongside allocation alignment or minimum size",
    )?;
    let effective = effective_table(before, review)?;
    require(
        crate::partition::free_regions(&effective)?
            .iter()
            .any(|(first, count)| {
                start >= *first && first.checked_add(*count).is_some_and(|last| end <= last)
            }),
        "reviewed alongside allocation overlaps preserved partitions",
    )?;
    let esp_size = 4 * GIB / sector;
    let plan = value!({"schema":2,"mode":"alongside","disk":path,"bytes":bytes,"sector":sector,"label_id":label,"before":before,"review":review,"partitions":[null,
        {"number":esp,"start":start,"size":esp_size,"type":ESP,"name":"enzimos-esp","uuid":guids[0]},
        {"number":root,"start":add(start,esp_size)?,"size":size-esp_size,"type":ROOT,"name":"enzimos-root","uuid":guids[1]}]});
    require(
        json::canonical(&plan)?.len() <= MAX_RECEIPT / 8,
        "alongside retained plan byte bound",
    )?;
    Ok(plan)
}
pub fn validate(plan: &Value, disk: &Value) -> Result<()> {
    if alongside(plan) {
        json::fields(
            plan,
            "schema mode disk bytes sector label_id before review partitions",
        )?;
        let uuids = [
            s(&plan["partitions"][1]["uuid"])?.into(),
            s(&plan["partitions"][2]["uuid"])?.into(),
        ];
        require(
            *plan == alongside_plan(&plan["before"], &plan["review"], disk, &uuids)?,
            "alongside allocation plan was altered",
        )
    } else {
        let rows = plan["partitions"]
            .as_array()
            .ok_or_else(|| Error("erase allocation partitions missing".into()))?;
        require(rows.len() == 3, "erase allocation partition count")?;
        let guids = [
            s(&plan["label_id"])?.into(),
            s(&rows[0]["uuid"])?.into(),
            s(&rows[1]["uuid"])?.into(),
            s(&rows[2]["uuid"])?.into(),
        ];
        require(
            *plan
                == crate::erase::layout(
                    n(&disk["bytes"])?,
                    n(&plan["sector"])?,
                    s(&disk["path"])?,
                    &guids,
                )?,
            "erase allocation plan was altered",
        )
    }
}
pub fn verify(plan: &Value, table: &Value) -> Result<Value> {
    if !alongside(plan) {
        return crate::erase::verify(plan, table);
    }
    validate(plan, &value!({"path":plan["disk"],"bytes":plan["bytes"]}))?;
    let effective = effective_table(&plan["before"], &plan["review"])?;
    let mut wanted = effective.clone();
    let mut actual = table.clone();
    wanted
        .as_object_mut()
        .ok_or_else(|| Error("original GPT header shape".into()))?
        .remove("partitions");
    actual
        .as_object_mut()
        .ok_or_else(|| Error("current GPT header shape".into()))?
        .remove("partitions");
    wanted["id"] = value!(guid(&wanted["id"])?);
    actual["id"] = value!(guid(&actual["id"])?);
    require(wanted == actual, "preserved GPT header changed")?;
    let old = effective["partitions"].as_array().unwrap();
    let rows = table["partitions"]
        .as_array()
        .ok_or_else(|| Error("current GPT partitions missing".into()))?;
    require(
        rows.len() == old.len() + 2,
        "unexpected alongside partition count",
    )?;
    let rows = rows.iter().map(normalized).collect::<Result<Vec<_>>>()?;
    let mut identities = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for row in &rows {
        require(
            identities.insert(s(&row["uuid"])?) && paths.insert(s(&row["node"])?),
            "current partition identity or path ambiguous",
        )?;
    }
    for row in old {
        let wanted = normalized(row)?;
        require(
            rows.iter().any(|row| row == &wanted),
            "preserved partition metadata changed",
        )?;
    }
    let mut new_paths = Vec::new();
    for index in [1, 2] {
        let planned = &plan["partitions"][index];
        let matches = rows
            .iter()
            .filter(|row| row["uuid"] == planned["uuid"])
            .collect::<Vec<_>>();
        require(matches.len() == 1, "new alongside GUID missing")?;
        let row = matches[0];
        require(
            ["start", "size", "type", "name"]
                .iter()
                .all(|key| row[*key] == planned[*key])
                && old_number(s(&plan["disk"])?, &row["node"])? == number(plan, index)?,
            "new alongside geometry or partition number differs",
        )?;
        // New entries may carry no inherited GPT attributes or unknown fields.
        json::fields(row, "node start size type uuid name")?;
        new_paths.push(s(&row["node"])?.to_owned());
    }
    Ok(value!({"bios":null,"esp":new_paths[0],"root":new_paths[1],"plan":plan}))
}
pub fn append_script(plan: &Value) -> Result<String> {
    require(alongside(plan), "alongside append role required")?;
    validate(plan, &value!({"path":plan["disk"],"bytes":plan["bytes"]}))?;
    let mut script = String::new();
    for index in [1, 2] {
        let row = &plan["partitions"][index];
        script.push_str(&format!(
            "start={}, size={}, type={}, uuid={}, name=\"{}\"\n",
            n(&row["start"])?,
            n(&row["size"])?,
            s(&row["type"])?,
            s(&row["uuid"])?,
            s(&row["name"])?
        ));
    }
    Ok(script)
}

pub(crate) struct Journal {
    parent: std::fs::File,
    parent_path: std::path::PathBuf,
    name: std::path::PathBuf,
    original: std::fs::File,
    identity: enzimos_platform::files::FileIdentity,
    bytes: Vec<u8>,
    mount: u64,
    flags: i32,
    parent_flags: i32,
}
impl Journal {
    pub(crate) fn create(path: &std::path::Path, body: &Value) -> Result<Self> {
        let parent = enzimos_platform::files::directory(
            path.parent()
                .ok_or_else(|| Error("allocation receipt parent missing".into()))?,
            Some(0),
        )?;
        let name = std::path::PathBuf::from(
            path.file_name()
                .ok_or_else(|| Error("allocation receipt name missing".into()))?,
        );
        let bytes = json::canonical(body)?;
        let original = enzimos_platform::files::atomic_relative_retained(
            &parent,
            &name,
            &bytes,
            0o600,
            Some(0),
            false,
            MAX_RECEIPT,
        )?;
        Self::retained(
            parent,
            path.parent().unwrap().to_owned(),
            name,
            original,
            bytes,
        )
    }
    pub(crate) fn open(path: &std::path::Path) -> Result<Self> {
        let parent = enzimos_platform::files::directory(
            path.parent()
                .ok_or_else(|| Error("allocation receipt parent missing".into()))?,
            Some(0),
        )?;
        let name = std::path::PathBuf::from(
            path.file_name()
                .ok_or_else(|| Error("allocation receipt name missing".into()))?,
        );
        let original = enzimos_platform::files::open_relative(&parent, &name)?;
        let bytes = enzimos_platform::files::read_file(&original, MAX_RECEIPT, Some(0), true)?;
        Self::retained(
            parent,
            path.parent().unwrap().to_owned(),
            name,
            original,
            bytes,
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    fn retained(
        parent: std::fs::File,
        parent_path: std::path::PathBuf,
        name: std::path::PathBuf,
        original: std::fs::File,
        bytes: Vec<u8>,
    ) -> Result<Self> {
        use std::os::fd::{AsFd, AsRawFd};
        let flags = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) };
        let parent_flags = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_GETFL) };
        require(
            flags >= 0
                && parent_flags >= 0
                && flags & libc::O_ACCMODE == libc::O_RDONLY
                && flags & (libc::O_PATH | libc::O_APPEND) == 0,
            "allocation receipt descriptions must be readable originals",
        )?;
        require(
            parent_path == std::path::Path::new("/run/enzimos-install-native")
                && name
                    .to_str()
                    .and_then(|s| s.strip_prefix("erase-"))
                    .and_then(|s| s.strip_suffix(".json"))
                    .is_some_and(|s| {
                        s.len() == 64
                            && s.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    }),
            "allocation journal outside closed namespace",
        )?;
        let this = Self {
            flags,
            parent_flags,
            parent_path,
            identity: enzimos_platform::files::identity(&original.metadata()?),
            mount: enzimos_platform::mount_identity::id(parent.as_fd(), true)?,
            parent,
            name,
            original,
            bytes,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn descriptor(&self) -> Result<std::fs::File> {
        self.recheck()?;
        Ok(self.original.try_clone()?)
    }
    pub(crate) fn body(&self) -> Result<Value> {
        self.recheck()?;
        json::decode(&self.bytes, MAX_RECEIPT)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    pub(crate) fn recheck(&self) -> Result<()> {
        use std::os::{
            fd::{AsFd, AsRawFd},
            unix::fs::MetadataExt,
        };
        let named = enzimos_platform::files::open_relative(&self.parent, &self.name)?;
        let m = self.original.metadata()?;
        let parent = self.parent.metadata()?;
        let named_parent = enzimos_platform::files::directory(&self.parent_path, Some(0))?;
        let named_meta = named_parent.metadata()?;
        require(
            parent.dev() == named_meta.dev()
                && parent.ino() == named_meta.ino()
                && parent.uid() == named_meta.uid()
                && parent.gid() == named_meta.gid()
                && parent.mode() == named_meta.mode()
                && enzimos_platform::mount_identity::id(named_parent.as_fd(), true)? == self.mount,
            "original allocation directory name or mount changed",
        )?;
        require(
            parent.is_dir()
                && parent.uid() == 0
                && parent.gid() == 0
                && parent.mode() & 0o7777 == 0o700
                && unsafe { libc::fcntl(self.parent.as_raw_fd(), libc::F_GETFL) }
                    == self.parent_flags
                && unsafe { libc::fcntl(self.original.as_raw_fd(), libc::F_GETFL) } == self.flags,
            "original allocation directory or descriptor status changed",
        )?;
        require(
            m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && enzimos_platform::files::identity(&m) == self.identity
                && enzimos_platform::files::identity(&named.metadata()?) == self.identity
                && enzimos_platform::mount_identity::id(self.original.as_fd(), true)? == self.mount
                && enzimos_platform::mount_identity::id(named.as_fd(), true)? == self.mount
                && enzimos_platform::files::read_file(&self.original, MAX_RECEIPT, Some(0), true)?
                    == self.bytes,
            "original allocation journal changed",
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    pub(crate) fn replace(&mut self, body: &Value) -> Result<()> {
        self.recheck()?;
        let bytes = json::canonical(body)?;
        let new = enzimos_platform::files::atomic_replace_original(
            &self.parent,
            &self.name,
            &bytes,
            0o600,
            Some(0),
            MAX_RECEIPT,
            &self.original,
        )?;
        use std::os::fd::AsRawFd;
        let flags = unsafe { libc::fcntl(new.as_raw_fd(), libc::F_GETFL) };
        require(
            flags == self.flags,
            "published allocation description status changed",
        )?;
        self.original = new;
        self.identity = enzimos_platform::files::identity(&self.original.metadata()?);
        self.bytes = bytes;
        self.recheck()
    }
}
