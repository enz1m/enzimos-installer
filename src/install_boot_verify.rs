// SPDX-License-Identifier: MIT
//! Verification is separate from publication and runs after exact worker/cgroup teardown.
use crate::{
    install_boot_files as artifacts, install_boot_sources as sources, media_packages::Admitted,
};
use enzimos_platform::{Error, Result, files, memfile, process, require};
use serde_json::Value;
use std::{fs::File, os::fd::AsFd, path::Path, time::Duration};
pub(crate) fn signatures(
    root: &File,
    media: &Admitted,
    body: &Value,
    certificate: &str,
) -> Result<()> {
    let directory = files::directory_relative(
        root,
        Path::new("var/lib/enzimos-control/secure-boot"),
        Some(0),
    )?;
    let public = files::read_file(
        &files::open_relative(&directory, Path::new("owner.crt"))?,
        16384,
        Some(0),
        true,
    )?;
    require(
        enzimos_platform::json::sha256(&public) == certificate,
        "original owner public certificate changed before verification",
    )?;
    let cert = memfile::sealed("enzimos-installer-public-certificate", &public)?;
    let mut names = crate::install_boot_secure::LOADERS
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>();
    for flavor in ["linux", "linux-lts"] {
        let kernel = &body["files"][format!("boot/vmlinuz-{flavor}")]["sha256"];
        let initrd = &body["files"][format!("boot/initramfs-{flavor}.img")]["sha256"];
        let digest = enzimos_policy::signed_entry::digest(
            kernel.as_str().unwrap(),
            initrd.as_str().unwrap(),
            body["options"].as_str().unwrap(),
            certificate,
        )?;
        let name = format!("boot/enzimos/secure-boot/{digest}.efi");
        require(
            !body["files"][&name].is_null(),
            "signed boot receipt omits original content-addressed UKI",
        )?;
        let source = sources::Source::open(root, Path::new(&name), 128 * 1024 * 1024)?;
        enzimos_policy::secure_artifacts::verify_payload(
            &files::read_file(&source.file, 128 * 1024 * 1024, Some(0), true)?,
            kernel.as_str().unwrap(),
            initrd.as_str().unwrap(),
            body["options"].as_str().unwrap(),
        )?;
        source.recheck(root)?;
        names.push(name);
    }
    for name in names {
        media.recheck()?;
        let source = sources::Source::open(root, Path::new(&name), 128 * 1024 * 1024)?;
        let result = process::run_pinned(
            "/usr/bin/chroot",
            media.images.get("/usr/bin/chroot")?,
            &["@fd-dir:0", "/usr/bin/sbverify", "--cert", "@fd:1", "@fd:2"],
            &[],
            Duration::from_secs(120),
            65536,
            &[root.as_fd(), cert.as_fd(), source.file.as_fd()],
        )?;
        require(
            result.status.success(),
            "caller independent owner signature verification refused",
        )?;
        source.recheck(root)?;
        media.recheck()?;
    }
    let config = files::read_file(
        &files::open_relative(&directory, Path::new("config.json"))?,
        4096,
        Some(0),
        true,
    )?;
    require(
        enzimos_platform::json::decode(&config, 4096)?
            == serde_json::json!({"schema":1,"mode":"owner-uki"}),
        "installed owner boot policy differs",
    )?;
    artifacts::verify(root, &body["files"])
}
pub(crate) fn text(root: &File, name: &str, expected: &[u8]) -> Result<()> {
    let path = Path::new(name);
    let directory = files::directory_relative(
        root,
        path.parent()
            .ok_or_else(|| Error("boot verification parent absent".into()))?,
        Some(0),
    )?;
    require(
        files::read_file(
            &files::open_relative(&directory, Path::new(path.file_name().unwrap()))?,
            65536,
            Some(0),
            true,
        )? == expected,
        "initial boot text differs from independently rendered original plan",
    )
}
