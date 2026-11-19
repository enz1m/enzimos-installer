// SPDX-License-Identifier: MIT
//! Initial Arch installation from the admitted read-only pool, with no sync/fetch.
use crate::{media_packages::Admitted, package_handoff::Received, package_job};
use enzimos_platform::{Error, Result, files, json, memfile, process, require};
use enzimos_policy::authority;
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, fs::File, os::fd::AsFd, path::Path, time::Duration};
pub fn config() -> String {
    "[options]\nArchitecture = x86_64\nCacheDir = /run/enzimos-live/media/enzimos/packages\nLogFile = /var/log/pacman-install.log\nSigLevel = Required TrustedOnly DatabaseOptional\nLocalFileSigLevel = Required TrustedOnly\nCheckSpace\n".into()
}
pub fn arguments(selected: &[String]) -> Result<Vec<String>> {
    let bytes = format!("{}\n", selected.join("\n"));
    require(
        !selected.is_empty()
            && crate::media_manifest::package_list(bytes.as_bytes())?.len() == selected.len(),
        "offline pacman selection shape",
    )?;
    let mut args = [
        "--root",
        "@fd-dir:0",
        "--config",
        "@fd:1",
        "--gpgdir",
        "@fd-dir:2",
        "--noconfirm",
        "--needed",
        "-U",
        "--",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    args.extend(
        selected
            .iter()
            .map(|name| format!("/run/enzimos-live/media/enzimos/packages/{name}")),
    );
    Ok(args)
}
pub fn output_clean(bytes: &[u8]) -> bool {
    [
        b"error: command failed to execute correctly".as_slice(),
        b"ERROR:".as_slice(),
        b"error:".as_slice(),
    ]
    .iter()
    .all(|marker| !bytes.windows(marker.len()).any(|part| part == *marker))
}
pub fn bootstrap_arguments(selected: &[String], pacman: &str) -> Result<Vec<String>> {
    let mut args = arguments(selected)?;
    let position = selected
        .iter()
        .position(|name| name == pacman)
        .ok_or_else(|| Error("verified pacman package missing from selected cohort".into()))?;
    // libalpm visits targets in order and installs their dependencies first.
    // An empty target needs pacman's vercmp before unrelated install scripts;
    // moving this admitted archive changes neither selection nor authorization.
    let first_package = args.len() - selected.len();
    let archive = args.remove(first_package + position);
    args.insert(first_package, archive);
    Ok(args)
}
fn fields(bytes: &[u8]) -> Result<BTreeMap<String, Vec<String>>> {
    Ok(enzimos_platform::alpm_sections::parse(bytes)?
        .into_iter()
        .map(|(key, values)| {
            (
                key.to_owned(),
                values.into_iter().map(str::to_owned).collect(),
            )
        })
        .collect())
}
pub fn installed_identity(bytes: &[u8]) -> Result<(String, String)> {
    let row = fields(bytes)?;
    let one = |key| -> Result<&str> {
        Ok(row
            .get(key)
            .filter(|values| values.len() == 1)
            .ok_or_else(|| Error("installed package identity section count".into()))?[0]
            .as_str())
    };
    let (name, version) = (one("%NAME%")?, one("%VERSION%")?);
    enzimos_policy::package_archive::metadata(&format!(
        "pkgname = {name}\npkgver = {version}\narch = any\n"
    ))?;
    Ok((name.into(), version.into()))
}
pub fn database(target: &File, expected: &BTreeMap<String, String>) -> Result<()> {
    let mut seen = BTreeMap::new();
    let directory = files::directory_relative(target, Path::new("var/lib/pacman/local"), Some(0))?;
    let root = format!(
        "/proc/self/fd/{}",
        std::os::fd::AsRawFd::as_raw_fd(&directory)
    );
    // The retained target is checked by the supervisor around this read. Each
    // entry is reopened by descriptor without following database symlinks.
    for (index, entry) in std::fs::read_dir(&root)?.enumerate() {
        require(index < 2048, "installed package database count bound")?;
        let name = entry?.file_name();
        if name == "ALPM_DB_VERSION" {
            continue;
        }
        let desc = files::open_relative(&directory, Path::new(&name).join("desc").as_path())?;
        let (package, version) =
            installed_identity(&files::read_file(&desc, 512 * 1024, Some(0), true)?)?;
        require(
            name.to_str()
                .and_then(|name| name.strip_prefix(&format!("{package}-")))
                .is_some_and(|container| {
                    enzimos_policy::package_archive::version_matches(container, &version)
                })
                && expected
                    .get(&package)
                    .is_some_and(|wanted| wanted == &version)
                && seen.insert(package, version).is_none(),
            "installed package database differs from exact selected cohort or directory identity",
        )?;
    }
    require(
        &seen == expected,
        "installed package database lacks selected packages",
    )
}
pub fn install(context: &Received, media: &Admitted) -> Result<Value> {
    context.recheck()?;
    media.recheck()?;
    require(
        media.selected
            == context.request["selected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
            && media.media.manifest_sha256 == context.request["media_manifest_sha256"],
        "pacman body media binding differs",
    )?;
    let root = Path::new("/mnt/enzimos");
    let authority = crate::install_authority::Fresh::observe(&context.target)?;
    authority.empty()?;
    for path in ["var/lib/pacman", "etc/tmpfiles.d"] {
        files::ensure_directory(&root.join(path), 0o755, 0)?;
    }
    require(
        std::fs::read_dir(root.join("var/lib/pacman"))?
            .next()
            .is_none(),
        "initial package database must be empty; no adoption or replay",
    )?;
    for (name, body) in [
        ("portables.conf", "d /var/lib/portables 0700 root root -\n"),
        (
            "systemd-nspawn.conf",
            "d /var/lib/machines 0700 root root -\nR! /var/lib/machines/.#*\nR! /.#machine.*\n",
        ),
    ] {
        files::atomic(
            &root.join("etc/tmpfiles.d").join(name),
            body.as_bytes(),
            0o644,
            Some(0),
            false,
        )?;
    }
    let work = Path::new("/run/enzimos-install-native").join(format!(
        "pacman-{}",
        context.request["id"].as_str().unwrap()
    ));
    files::create_directory(&work, 0o700, 0)?;
    let keys = work.join("keys");
    let key_directory = files::create_directory(&keys, 0o700, 0)?;
    let mut materials = media.authority.files();
    materials.insert(
        "gpg.conf".into(),
        format!("{}no-auto-check-trustdb\n", authority::CONFIG).into_bytes(),
    );
    for (name, bytes) in &materials {
        files::atomic_bounded(
            &keys.join(name),
            bytes,
            if name == "gpg.conf" { 0o644 } else { 0o600 },
            Some(0),
            false,
            8 * 1024 * 1024,
        )?;
    }
    let config = memfile::sealed("enzimos-offline-pacman", config().as_bytes())?;
    let image = media.images.get("/usr/bin/pacman")?;
    let pacman = media
        .packages
        .iter()
        .filter(|package| {
            package.identity["name"] == "pacman" && media.selected.contains(&package.filename)
        })
        .collect::<Vec<_>>();
    require(pacman.len() == 1, "selected verified pacman identity count")?;
    let args = bootstrap_arguments(&media.selected, &pacman[0].filename)?;
    context.recheck()?;
    media.recheck()?;
    let output = process::run_pinned(
        "/usr/bin/pacman",
        image,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        &[],
        Duration::from_secs(package_job::RUNTIME_SECONDS - 60),
        32 * 1024 * 1024,
        &[
            context.target.as_fd(),
            config.as_fd(),
            key_directory.as_fd(),
        ],
    )?;
    files::atomic_bounded(
        &work.join("stdout.log"),
        &output.stdout,
        0o600,
        Some(0),
        false,
        32 * 1024 * 1024,
    )?;
    files::atomic_bounded(
        &work.join("stderr.log"),
        &output.stderr,
        0o600,
        Some(0),
        false,
        32 * 1024 * 1024,
    )?;
    context.recheck()?;
    media.recheck()?;
    require(
        output.status.success() && output_clean(&output.stdout) && output_clean(&output.stderr),
        "offline pacman or package hook failed; unfinished attempt retained",
    )?;
    for (name, bytes) in &materials {
        require(
            files::read(&keys.join(name), 8 * 1024 * 1024, Some(0), true)? == *bytes,
            "offline pacman changed the approved verification authority",
        )?;
    }
    let expected = media
        .packages
        .iter()
        .filter(|p| media.selected.contains(&p.filename))
        .map(|p| {
            (
                p.identity["name"].as_str().unwrap().to_owned(),
                p.identity["version"].as_str().unwrap().to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    database(&context.target, &expected)?;
    authority.empty()?;
    context.target.sync_all()?;
    let result = value!({"schema":1,"operation":"initial-arch-install","request_sha256":json::fingerprint(&context.request)?,"installed":expected,"exit_code":0});
    files::atomic(
        &work.join("result.json"),
        &json::canonical(&result)?,
        0o600,
        Some(0),
        false,
    )?;
    context.recheck()?;
    media.recheck()?;
    Ok(result)
}
