// SPDX-License-Identifier: MIT
//! The native development cohort follows Arch within the same one-shot PID1 job.
use crate::{
    media_packages::Admitted, native_signing, package_body, package_handoff::Received,
    package_job as job,
};
use enzimos_platform::{Result, files, json, memfile, process, require};
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, os::fd::AsFd, path::Path, time::Duration};
pub fn expected(media: &Admitted, operation: &str) -> Result<BTreeMap<String, String>> {
    job::operation(operation)?;
    let mut expected = BTreeMap::new();
    for package in media
        .packages
        .iter()
        .filter(|p| media.selected.contains(&p.filename))
    {
        require(
            expected
                .insert(
                    package.identity["name"].as_str().unwrap().into(),
                    package.identity["version"].as_str().unwrap().into(),
                )
                .is_none(),
            "duplicate installed Arch package identity",
        )?;
    }
    if operation != job::ARCH {
        for package in &media.native {
            require(
                expected
                    .insert(
                        package.identity["name"].as_str().unwrap().into(),
                        package.identity["version"].as_str().unwrap().into(),
                    )
                    .is_none(),
                "native package replaces selected Arch identity",
            )?;
        }
    }
    Ok(expected)
}
/// Native packages one offline transaction may install. The full media carry
/// about 35: policy, runtimes, services, applications and the local AI stack.
pub const MAX_NATIVE_PACKAGES: usize = 64;
pub fn arguments(directory: &Path, files: &[String]) -> Result<Vec<String>> {
    // A fixed private job directory, never a caller-supplied pacman option/path.
    let parent = directory
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let id = parent.strip_prefix("native-").unwrap_or("");
    job::id(id)?;
    require(
        directory
            == Path::new("/run/enzimos-install-native")
                .join(parent)
                .join("packages")
            && !files.is_empty()
            && files.len() <= MAX_NATIVE_PACKAGES,
        "native package directory or selection bound",
    )?;
    require(
        crate::media_manifest::package_list(format!("{}\n", files.join("\n")).as_bytes())?.len()
            == files.len(),
        "native pacman filename ambiguity",
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
        files
            .iter()
            .map(|name| directory.join(name).to_str().unwrap().to_owned()),
    );
    Ok(args)
}
pub fn install(context: &Received, media: &Admitted, arch: Value) -> Result<Value> {
    context.recheck()?;
    media.recheck()?;
    require(
        context.request["operation"] != job::ARCH && arch["exit_code"] == 0,
        "native package stage follows this attempt's successful Arch body",
    )?;
    package_body::database(&context.target, &expected(media, job::ARCH)?)?;
    let authority = crate::install_authority::Fresh::observe(&context.target)?;
    authority.empty()?;
    let prepared = native_signing::prepare(context, media)
        .map_err(|error| enzimos_platform::Error(format!("native development signing: {error}")))?;
    prepared.recheck(context, media)?;
    authority.empty()?;
    let config = memfile::sealed(
        "enzimos-native-offline-pacman",
        package_body::config().as_bytes(),
    )?;
    // Freeze GPG's verification material for this transaction. The prepared
    // review directory retains its own original files for independent rechecks.
    let keys = prepared.directory.parent().unwrap().join("verification");
    let verification = files::create_directory(&keys, 0o700, 0)?;
    let materials = prepared.materials();
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
    let names = prepared
        .packages
        .iter()
        .map(|p| p.file.clone())
        .collect::<Vec<_>>();
    let args = arguments(&prepared.directory, &names)?;
    let output = process::run_pinned(
        "/usr/bin/pacman",
        media.images.get("/usr/bin/pacman")?,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        &[],
        Duration::from_secs(job::RUNTIME_SECONDS - 60),
        32 * 1024 * 1024,
        &[context.target.as_fd(), config.as_fd(), verification.as_fd()],
    )?;
    for (name, bytes) in [
        ("native-stdout.log", &output.stdout),
        ("native-stderr.log", &output.stderr),
    ] {
        files::atomic_bounded(
            &prepared.directory.parent().unwrap().join(name),
            bytes,
            0o600,
            Some(0),
            false,
            32 * 1024 * 1024,
        )?;
    }
    context.recheck()?;
    media.recheck()?;
    prepared.recheck(context, media)?;
    require(
        output.status.success()
            && package_body::output_clean(&output.stdout)
            && package_body::output_clean(&output.stderr),
        "native offline pacman or package hook failed; unfinished attempt retained",
    )?;
    for (name, bytes) in &materials {
        require(
            files::read(&keys.join(name), 8 * 1024 * 1024, Some(0), true)? == *bytes,
            "native package transaction changed verification authority",
        )?;
    }
    authority.empty()?;
    let installed = expected(media, job::OFFLINE)?;
    package_body::database(&context.target, &installed)?;
    let publication = crate::install_authority::publish(context, media, &prepared)?;
    context.target.sync_all()?;
    let result = value!({"schema":1,"operation":context.request["operation"],"request_sha256":json::fingerprint(&context.request)?,
        "arch":arch,"installed":installed,"authority":publication,"exit_code":0,"development_artifact":true,"release_authorized":false});
    files::atomic(
        &prepared.directory.parent().unwrap().join("result.json"),
        &json::canonical(&result)?,
        0o600,
        Some(0),
        false,
    )?;
    context.recheck()?;
    media.recheck()?;
    prepared.recheck(context, media)?;
    Ok(result)
}
