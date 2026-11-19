// SPDX-License-Identifier: MIT
//! Explicit test-mode input on an already mounted, read-only independent volume.
//! This module never mounts media or executes its check on the live system.
use enzimos_platform::{Result, files, json, mount_identity, mountinfo, require};
use enzimos_policy::{storage_runtime, topology};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub const ROOT: &str = "/run/enzimos-answers";
pub const NAME: &str = "firstboot-check.sh";
pub const LIMIT: usize = 1024 * 1024;
const SCRIPT: &str = "usr/lib/enzimos-test/firstboot-check.sh";
const UNIT: &str = "etc/systemd/system/enzimos-firstboot-check.service";
const SERVICE:&[u8]=b"[Unit]\nDescription=enzimOS installer test: first-boot check\nAfter=multi-user.target enzimos-recovery-image.service\n[Service]\nType=simple\nExecStart=/usr/lib/enzimos-test/firstboot-check.sh\nStandardOutput=tty\nTTYPath=/dev/ttyS0\n[Install]\nWantedBy=multi-user.target\n";
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.mode() & 0o022 == 0,
        "protected test volume directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
struct Script {
    parent: File,
    file: File,
    shape: Shape,
    identity: files::FileIdentity,
    mount: u64,
    bytes: Vec<u8>,
    owner: u32,
}
impl Script {
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    fn retain(parent: File, file: File, owner: u32) -> Result<Self> {
        use std::os::fd::AsRawFd;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        require(
            flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
            "test script requires original read-only description",
        )?;
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == owner
                && m.gid() == parent.metadata()?.gid()
                && m.mode() & 0o022 == 0
                && m.nlink() == 1
                && (1..=LIMIT as u64).contains(&m.len()),
            "original test script protection or size",
        )?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            mount_identity::id(file.as_fd(), true)? == mount,
            "test script crosses volume mount",
        )?;
        let bytes = files::read_file(&file, LIMIT, Some(owner), true)?;
        require(
            bytes.starts_with(b"#!/") && !bytes.contains(&0),
            "test script requires bounded executable text",
        )?;
        let this = Self {
            shape: shape(&parent, owner)?,
            parent,
            file,
            identity: files::identity(&m),
            mount,
            bytes,
            owner,
        };
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        let named = files::open_relative(&self.parent, Path::new(NAME))?;
        require(
            shape(&self.parent, self.owner)? == self.shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity
                && files::read_file(&self.file, LIMIT, Some(self.owner), true)? == self.bytes,
            "original test script changed or replaced",
        )
    }
}
fn row(rows: &[mountinfo::Row], normal: u64) -> Result<mountinfo::Row> {
    require(
        !rows
            .iter()
            .any(|r| r.target.starts_with(&format!("{ROOT}/"))),
        "nested test volume mount refused",
    )?;
    let rows = rows.iter().filter(|r| r.target == ROOT).collect::<Vec<_>>();
    require(
        matches!(rows.len(), 1 | 2),
        "one original test volume and optional private area required",
    )?;
    let row = rows
        .iter()
        .find(|r| r.id == normal)
        .copied()
        .ok_or_else(|| enzimos_platform::Error("original test volume mount missing".into()))?;
    if rows.len() == 2 {
        let area = rows.iter().find(|r| r.id != normal).copied().unwrap();
        enzimos_policy::installer_mount_area::validate_mount(std::slice::from_ref(area), area.id)?;
        require(
            row.parent == area.id && row.optional.is_empty(),
            "test volume left private original area",
        )?;
    }
    let flags = row
        .options
        .split(',')
        .collect::<std::collections::BTreeSet<_>>();
    require(
        row.id == normal
            && row.root == "/"
            && row.major > 0
            && matches!(row.filesystem.as_str(), "ext4" | "vfat" | "iso9660")
            && ["ro", "nodev", "nosuid", "noexec"]
                .iter()
                .all(|n| flags.contains(n))
            && !flags.contains("rw")
            && row.filesystem_options.split(',').any(|n| n == "ro"),
        "read-only protected whole test volume required",
    )?;
    Ok(row.clone())
}
pub struct Copy {
    script: Script,
    row: mountinfo::Row,
    graph: topology::Graph,
}
impl Copy {
    pub fn open() -> Result<Self> {
        Self::received(None)
    }
    pub(crate) fn received(original: Option<File>) -> Result<Self> {
        crate::setup::live()?;
        let parent = files::directory(Path::new(ROOT), Some(0))?;
        let normal = mount_identity::id(parent.as_fd(), false)?;
        let row = row(&storage_runtime::rows()?, normal)?;
        let graph = topology::observe(&[(row.major, row.minor)])?;
        let file = match original {
            Some(file) => file,
            None => files::open_relative(&parent, Path::new(NAME))?,
        };
        let this = Self {
            script: Script::retain(parent, file, 0)?,
            row,
            graph,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn descriptor(&self) -> &File {
        &self.script.file
    }
    pub fn recheck(&self) -> Result<()> {
        crate::setup::live()?;
        self.script.recheck()?;
        let parent = files::directory(Path::new(ROOT), Some(0))?;
        require(
            shape(&parent, 0)? == self.script.shape
                && mount_identity::id(parent.as_fd(), true)? == self.script.mount
                && row(
                    &storage_runtime::rows()?,
                    mount_identity::id(parent.as_fd(), false)?,
                )? == self.row
                && topology::observe(&[(self.row.major, self.row.minor)])? == self.graph,
            "original test volume epoch changed",
        )
    }
    pub fn independent(&self, device: topology::Device) -> Result<()> {
        self.recheck()?;
        let target = topology::observe(&[device])?;
        require(
            self.graph.leaves.is_disjoint(&target.leaves),
            "test volume cannot be erased as installation target",
        )
    }
    pub(crate) fn binding(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"schema":1,"mount":self.script.mount,"inode":self.script.identity,"sha256":json::sha256(&self.script.bytes),"volume":self.graph.json()}),
        )
    }
}
pub(crate) fn validate(v: &Value) -> Result<()> {
    json::fields(v, "schema mount inode sha256 volume")?;
    require(
        v["schema"].as_u64() == Some(1) && v["mount"].as_u64().is_some_and(|n| n > 0),
        "test copy binding version/mount",
    )?;
    enzimos_policy::identity::sha(v["sha256"].as_str().unwrap_or(""))?;
    let i = v["inode"]
        .as_array()
        .ok_or_else(|| enzimos_platform::Error("test script inode missing".into()))?;
    require(
        i.len() == 11
            && i.iter().all(|n| n.is_u64() || n.is_i64())
            && i[0].as_u64().is_some_and(|n| n > 0)
            && i[1].as_u64().is_some_and(|n| n > 0)
            && i[2]
                .as_u64()
                .is_some_and(|n| (1..=LIMIT as u64).contains(&n))
            && i[7].as_u64().is_some_and(|n| {
                n <= u64::from(u32::MAX)
                    && n as u32 & libc::S_IFMT == libc::S_IFREG
                    && n & 0o022 == 0
            })
            && i[8] == 0
            && i[9] == 0
            && i[10] == 1,
        "test script original protected inode binding",
    )?;
    json::fields(&v["volume"], "nodes leaves")?;
    require(
        v["volume"]["nodes"]
            .as_array()
            .is_some_and(|n| !n.is_empty() && n.len() <= 64)
            && v["volume"]["leaves"]
                .as_array()
                .is_some_and(|n| !n.is_empty() && n.len() <= 64),
        "test volume topology bound",
    )
}
fn publication(context: &crate::package_handoff::Received) -> Result<Value> {
    context.recheck()?;
    let copy = context
        .answers
        .as_ref()
        .unwrap()
        .test_copy
        .as_ref()
        .ok_or_else(|| enzimos_platform::Error("original test copy missing".into()))?;
    Ok(
        value!({"schema":1,"id":context.request["id"],"request_sha256":json::fingerprint(&context.request)?,"owner":context.store.journal["owner"],"source":copy.binding()?,"files":{SCRIPT:json::sha256(&copy.script.bytes),UNIT:json::sha256(SERVICE)},"links":links(),"members":{}}),
    )
}
fn links() -> Value {
    value!({"etc/systemd/system/multi-user.target.wants/enzimos-firstboot-check.service":"../enzimos-firstboot-check.service","etc/systemd/system/serial-getty@ttyS0.service":"/dev/null"})
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod).")]
pub(crate) fn install(context: &crate::package_handoff::Received) -> Result<()> {
    let Some(copy) = context.answers.as_ref().unwrap().test_copy.as_ref() else {
        return Ok(());
    };
    context.recheck()?;
    let mut receipt = publication(context)?;
    receipt["phase"] = value!("writing");
    validate_publication(
        &receipt,
        &context.request,
        &context.store.journal["owner"],
        &copy.binding()?,
        &json::sha256(&copy.script.bytes),
        "writing",
    )?;
    let original_bytes = json::canonical(&receipt)?;
    let original = files::atomic_relative_retained(
        context.store.directory(),
        Path::new("test-copy.json"),
        &original_bytes,
        0o600,
        Some(0),
        false,
        65536,
    )?;
    let original_identity = files::identity(&original.metadata()?);
    let mut publications = crate::configuration_members::Publications::new(&context.target)?;
    for (name, bytes, mode) in [
        (SCRIPT, copy.script.bytes.as_slice(), 0o755),
        (UNIT, SERVICE, 0o644),
    ] {
        context.recheck()?;
        let path = Path::new(name);
        let parent =
            files::ensure_directory_relative(&context.target, path.parent().unwrap(), 0o755, 0)?;
        let file = files::atomic_relative_retained(
            &parent,
            Path::new(path.file_name().unwrap()),
            bytes,
            0o644,
            Some(0),
            false,
            LIMIT,
        )?;
        use std::os::fd::AsRawFd;
        require(
            unsafe { libc::fchmod(file.as_raw_fd(), mode) } == 0,
            "test copy final mode publication failed",
        )?;
        file.sync_all()?;
        parent.sync_all()?;
        publications.add(&context.target, name, &mut receipt)?;
        require(
            value!(files::identity(&file.metadata()?)) == receipt["members"][name]["inode"],
            "test publication does not retain original output inode",
        )?;
    }
    context.recheck()?;
    let system =
        files::directory_relative(&context.target, Path::new("etc/systemd/system"), Some(0))?;
    let wants =
        files::ensure_directory_relative(&system, Path::new("multi-user.target.wants"), 0o755, 0)?;
    files::symlink_member(
        &wants,
        Path::new("enzimos-firstboot-check.service"),
        "../enzimos-firstboot-check.service",
        0,
    )?;
    publications.add(
        &context.target,
        "etc/systemd/system/multi-user.target.wants/enzimos-firstboot-check.service",
        &mut receipt,
    )?;
    files::symlink_relative(
        &system,
        Path::new("serial-getty@ttyS0.service"),
        "/dev/null",
        0,
    )?;
    publications.add(
        &context.target,
        "etc/systemd/system/serial-getty@ttyS0.service",
        &mut receipt,
    )?;
    verify(&context.target, &receipt)?;
    context.recheck()?;
    receipt["phase"] = value!("complete");
    validate_publication(
        &receipt,
        &context.request,
        &context.store.journal["owner"],
        &copy.binding()?,
        &json::sha256(&copy.script.bytes),
        "complete",
    )?;
    publications.recheck(&context.target)?;
    // Replace only the original writing receipt, never a pathname replacement.
    require(
        files::identity(&original.metadata()?) == original_identity
            && files::read_file(&original, 65536, Some(0), true)? == original_bytes,
        "original test copy receipt changed",
    )?;
    files::atomic_replace_original(
        context.store.directory(),
        Path::new("test-copy.json"),
        &json::canonical(&receipt)?,
        0o600,
        Some(0),
        65536,
        &original,
    )?;
    publications.recheck(&context.target)?;
    context.recheck()
}
fn verify(target: &File, receipt: &Value) -> Result<()> {
    for (name, mode) in [(SCRIPT, 0o755), (UNIT, 0o644)] {
        let file = files::open_relative(target, Path::new(name))?;
        require(
            file.metadata()?.mode() & 0o7777 == mode
                && file.metadata()?.gid() == 0
                && json::sha256(&files::read_file(&file, LIMIT, Some(0), true)?)
                    == receipt["files"][name],
            "installed original test copy changed",
        )?;
    }
    for (name, dest) in [
        (
            "etc/systemd/system/multi-user.target.wants/enzimos-firstboot-check.service",
            "../enzimos-firstboot-check.service",
        ),
        ("etc/systemd/system/serial-getty@ttyS0.service", "/dev/null"),
    ] {
        use std::os::fd::AsRawFd;
        let p = Path::new(name);
        let parent = files::directory_relative(target, p.parent().unwrap(), Some(0))?;
        require(
            std::fs::read_link(format!(
                "/proc/self/fd/{}/{}",
                parent.as_raw_fd(),
                p.file_name().unwrap().to_str().unwrap()
            ))? == Path::new(dest),
            "installed test service link changed",
        )?;
    }
    Ok(())
}
fn validate_publication(
    receipt: &Value,
    request: &Value,
    owner: &Value,
    source: &Value,
    script_sha: &str,
    phase: &str,
) -> Result<()> {
    crate::package_job::request(request)?;
    validate(source)?;
    enzimos_policy::identity::sha(script_sha)?;
    json::fields(
        receipt,
        "schema id request_sha256 owner source files links members phase",
    )?;
    require(
        matches!(phase, "writing" | "complete")
            && request["operation"] == crate::package_job::BOOT
            && request["boot"]["test_copy"] == *source
            && receipt["schema"] == 1
            && receipt["phase"] == phase
            && receipt["id"] == request["id"]
            && receipt["request_sha256"] == json::fingerprint(request)?
            && receipt["owner"] == *owner
            && receipt["source"] == *source
            && receipt["files"] == value!({SCRIPT:script_sha,UNIT:json::sha256(SERVICE)})
            && receipt["links"] == links(),
        "test copy completion differs from original source and worker",
    )?;
    crate::configuration_members::validate(receipt)
}
pub(crate) fn completed(
    target: &crate::target_storage::Target<'_>,
    journal: &Value,
    directory: &File,
) -> Result<()> {
    let Some(copy) = &target.source().test_copy else {
        return Ok(());
    };
    target.recheck()?;
    copy.recheck()?;
    require(
        journal["phase"] == "stopping",
        "test copy completion requires stopped original worker",
    )?;
    let bytes = files::read_file(
        &files::open_relative(directory, Path::new("test-copy.json"))?,
        65536,
        Some(0),
        true,
    )?;
    let receipt = json::decode(&bytes, 65536)?;
    validate_publication(
        &receipt,
        &journal["request"],
        &journal["owner"],
        &copy.binding()?,
        &json::sha256(&copy.script.bytes),
        "complete",
    )?;
    crate::configuration_members::verify(target.directory()?, &receipt)?;
    verify(target.directory()?, &receipt)?;
    target.recheck()
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> tempfile::TempDir {
        let work = std::path::PathBuf::from(
            std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        );
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(work)
            .unwrap()
    }
    #[test]
    fn test_receipt_binds_the_nested_original_request_and_all_four_publications() {
        let mut request = crate::install_boot_tests::request();
        let source = value!({"schema":1,"mount":456,"inode":[1,2,20,1,0,2,0,33152,0,0,1],
            "sha256":"a".repeat(64),"volume":{"nodes":[{}],"leaves":[[11,1]]}});
        request["schema"] = value!(4);
        request["boot"]["test_copy"] = source.clone();
        let owner = value!({"pid":789,"start_ticks":456,"unit":crate::package_job::unit(request["id"].as_str().unwrap()).unwrap(),
            "invocation":"b".repeat(32),"executable_sha256":"c".repeat(64)});
        let script_sha = "a".repeat(64);
        let mut receipt = value!({"schema":1,"id":request["id"],"request_sha256":json::fingerprint(&request).unwrap(),
            "owner":owner,"source":source,"files":{SCRIPT:script_sha,UNIT:json::sha256(SERVICE)},
            "links":links(),"members":{},"phase":"complete"});
        for (index, name) in [
            SCRIPT,
            UNIT,
            "etc/systemd/system/multi-user.target.wants/enzimos-firstboot-check.service",
            "etc/systemd/system/serial-getty@ttyS0.service",
        ]
        .iter()
        .enumerate()
        {
            let link = receipt["links"].get(*name);
            let mut row = value!({"path":name,"kind":if link.is_some(){"symlink"}else{"file"},
                "inode":[1,index+1,20,1,0,2,0,33188,0,0,1],"mount":123});
            if let Some(target) = link {
                row["target"] = target.clone();
                row["inode"][7] = value!(libc::S_IFLNK | 0o777);
            }
            receipt["members"][*name] = row;
        }
        validate_publication(&receipt, &request, &owner, &source, &script_sha, "complete").unwrap();
        for (pointer, value) in [
            ("/id", value!("d".repeat(32))),
            ("/owner/pid", value!(790)),
            ("/source/inode/1", value!(3)),
            ("/request_sha256", value!("e".repeat(64))),
            ("/phase", value!("writing")),
            (
                "/links/etc~1systemd~1system~1serial-getty@ttyS0.service",
                value!("/tmp/other"),
            ),
        ] {
            let mut changed = receipt.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_publication(&changed, &request, &owner, &source, &script_sha, "complete")
                    .is_err(),
                "{pointer}"
            );
        }
        let mut missing = receipt.clone();
        missing["members"].as_object_mut().unwrap().remove(SCRIPT);
        assert!(
            validate_publication(&missing, &request, &owner, &source, &script_sha, "complete")
                .is_err()
        );
        let mut contradictory = receipt.clone();
        contradictory["members"]["etc/systemd/system/serial-getty@ttyS0.service"]["inode"][7] =
            value!(libc::S_IFREG | 0o644);
        assert!(
            validate_publication(
                &contradictory,
                &request,
                &owner,
                &source,
                &script_sha,
                "complete"
            )
            .is_err()
        );
        let mut wrong_source = request.clone();
        wrong_source["boot"]["test_copy"]["sha256"] = value!("f".repeat(64));
        assert!(
            validate_publication(
                &receipt,
                &wrong_source,
                &owner,
                &source,
                &script_sha,
                "complete"
            )
            .is_err()
        );
    }
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn original_test_script_refuses_identical_replacement_and_extra_links() {
        let temp = fixture();
        let owner = unsafe { libc::geteuid() };
        let parent = files::directory(temp.path(), Some(owner)).unwrap();
        let bytes = b"#!/usr/bin/bash\nexit 0\n";
        files::atomic_relative(
            &parent,
            Path::new(NAME),
            bytes,
            0o644,
            Some(owner),
            false,
            LIMIT,
        )
        .unwrap();
        let original = Script::retain(
            parent.try_clone().unwrap(),
            files::open_relative(&parent, Path::new(NAME)).unwrap(),
            owner,
        )
        .unwrap();
        original.recheck().unwrap();
        std::fs::hard_link(temp.path().join(NAME), temp.path().join("alias")).unwrap();
        assert!(original.recheck().is_err());
        std::fs::remove_file(temp.path().join("alias")).unwrap();
        // Removing an added link does not restore the original ctime epoch.
        assert!(original.recheck().is_err());
        let fresh = Script::retain(
            parent.try_clone().unwrap(),
            files::open_relative(&parent, Path::new(NAME)).unwrap(),
            owner,
        )
        .unwrap();
        files::atomic_relative(
            &parent,
            Path::new("replacement"),
            bytes,
            0o644,
            Some(owner),
            false,
            LIMIT,
        )
        .unwrap();
        std::fs::rename(temp.path().join("replacement"), temp.path().join(NAME)).unwrap();
        assert!(fresh.recheck().is_err());
    }
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn non_script_mutable_and_oversized_test_inputs_are_refused() {
        let temp = fixture();
        let owner = unsafe { libc::geteuid() };
        let parent = files::directory(temp.path(), Some(owner)).unwrap();
        for bytes in [
            Vec::new(),
            b"exit 0\n".to_vec(),
            b"#!/usr/bin/bash\n\0".to_vec(),
            vec![b'x'; LIMIT + 1],
        ] {
            std::fs::write(temp.path().join(NAME), bytes).unwrap();
            std::fs::set_permissions(
                temp.path().join(NAME),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(
                Script::retain(
                    parent.try_clone().unwrap(),
                    files::open_relative(&parent, Path::new(NAME)).unwrap(),
                    owner
                )
                .is_err()
            );
        }
        std::fs::write(temp.path().join(NAME), b"#!/usr/bin/bash\nexit 0\n").unwrap();
        let writable = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(temp.path().join(NAME))
            .unwrap();
        assert!(Script::retain(parent.try_clone().unwrap(), writable, owner).is_err());
        std::fs::set_permissions(
            temp.path().join(NAME),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(
            Script::retain(
                parent.try_clone().unwrap(),
                files::open_relative(&parent, Path::new(NAME)).unwrap(),
                owner
            )
            .is_err()
        );
    }
    #[test]
    fn volume_mount_must_be_whole_readonly_protected_and_unshadowed() {
        let good =
            "42 1 8:17 / /run/enzimos-answers ro,nodev,nosuid,noexec - ext4 /dev/fixture ro\n";
        assert!(row(&mountinfo::parse(good).unwrap(), 42).is_ok());
        let optical = good
            .replace("8:17", "11:1")
            .replace("ext4", "iso9660")
            .replace("/dev/fixture", "/dev/sr1");
        assert!(row(&mountinfo::parse(&optical).unwrap(), 42).is_ok());
        let private_area = "1 53 0:27 /enzimos-answers /run/enzimos-answers rw,nodev,nosuid,noexec - tmpfs tmpfs rw\n";
        let stacked = format!("{private_area}{optical}");
        assert!(row(&mountinfo::parse(&stacked).unwrap(), 42).is_ok());
        for bad in [
            stacked.replace("42 1 11:1", "42 53 11:1"),
            stacked.replace("noexec - tmpfs", "noexec shared:11 - tmpfs"),
            stacked.replace("/enzimos-answers /run", "/other /run"),
        ] {
            assert!(row(&mountinfo::parse(&bad).unwrap(), 42).is_err());
        }
        for bad in [
            good.replace("ro,nodev", "rw,nodev"),
            good.replace(",noexec", ""),
            good.replace("/ /run", "/subdir /run"),
            good.replace("ext4", "tmpfs"),
            good.replace("8:17", "0:17"),
            good.replace("fixture ro", "fixture rw"),
        ] {
            assert!(row(&mountinfo::parse(&bad).unwrap(), 42).is_err());
        }
        assert!(row(&mountinfo::parse(good).unwrap(), 43).is_err());
        let nested = format!(
            "{good}43 42 8:18 / /run/enzimos-answers/other ro,nodev,nosuid,noexec - ext4 /dev/other ro\n"
        );
        assert!(row(&mountinfo::parse(&nested).unwrap(), 42).is_err());
    }
}
