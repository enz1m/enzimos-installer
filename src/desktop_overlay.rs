// SPDX-License-Identifier: MIT
//! Admit and publish the ISO's complete desktop/boot overlay under worker ownership.
use crate::{media_packages::Admitted, package_handoff::Received};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::path::Path;
pub(crate) fn install(context: &Received, media: &Admitted) -> Result<Value> {
    context.recheck()?;
    media.recheck()?;
    let Some(prepared) = prepare(&media.media, &media.manifest)? else {
        return Ok(value!({"schema":1,"status":"absent","files":0}));
    };
    let Prepared {
        manifest,
        manifest_identity,
        document,
        archive,
        archive_identity,
        reviewed,
    } = prepared;
    let mut receipt = value!({"schema":1,"role":"fresh-desktop-overlay","phase":"writing",
        "request_sha256":json::fingerprint(&context.request)?,"owner":context.store.journal["owner"],
        "archive_inode":archive_identity,"manifest_inode":manifest_identity,
        "archive_sha256":media.media.members["desktop-preview.tar.zst"],
        "manifest_sha256":media.media.members["desktop-preview.json"],"review_sha256":json::fingerprint(&reviewed)?,
        "publication":null,"release_authorized":false,"final_members":null,"authorized_changes":null});
    context.recheck()?;
    media.recheck()?;
    files::atomic_relative(
        context.store.directory(),
        Path::new("desktop-overlay.json"),
        &json::canonical(&receipt)?,
        0o600,
        Some(0),
        false,
        2 * 1024 * 1024,
    )?;
    let mut guard = || -> Result<()> {
        context.recheck()?;
        media.recheck()?;
        require(
            files::identity(&archive.metadata()?) == archive_identity
                && files::identity(&manifest.metadata()?) == manifest_identity,
            "original desktop overlay inputs changed",
        )
    };
    let publication = enzimos_policy::file_overlay::extract(
        &archive,
        &document["files"],
        &reviewed,
        &context.target,
        0,
        &mut guard,
    )?;
    // Preserve the public per-file review used by the existing desktop status UI.
    let parent =
        files::ensure_directory_relative(&context.target, Path::new("usr/share/enzui"), 0o755, 0)?;
    guard()?;
    files::atomic_relative(
        &parent,
        Path::new("desktop-preview.json"),
        &json::canonical(&document)?,
        0o644,
        Some(0),
        false,
        4 * 1024 * 1024,
    )?;
    guard()?;
    receipt["publication"] = publication;
    receipt["phase"] = value!("complete");
    files::atomic_relative(
        context.store.directory(),
        Path::new("desktop-overlay.json"),
        &json::canonical(&receipt)?,
        0o600,
        Some(0),
        true,
        2 * 1024 * 1024,
    )?;
    Ok(receipt)
}

struct Prepared {
    manifest: std::fs::File,
    manifest_identity: files::FileIdentity,
    document: Value,
    archive: std::fs::File,
    archive_identity: files::FileIdentity,
    reviewed: Value,
}
fn prepare(media: &crate::media_source::Media, manifest: &Value) -> Result<Option<Prepared>> {
    let count = manifest["desktop_preview_files"]
        .as_u64()
        .ok_or_else(|| Error("desktop preview manifest count absent".into()))?;
    require(count <= 2048, "desktop preview file count bound")?;
    if count == 0 {
        require(
            !media.members.contains_key("desktop-preview.json")
                && !media.members.contains_key("desktop-preview.tar.zst"),
            "undeclared desktop overlay",
        )?;
        return Ok(None);
    }
    let manifest = media.member("desktop-preview.json", 4 * 1024 * 1024)?;
    let manifest_identity = files::identity(&manifest.metadata()?);
    let document = json::decode(
        &files::read_file(&manifest, 4 * 1024 * 1024, Some(0), true)?,
        4 * 1024 * 1024,
    )?;
    json::fields(
        &document,
        "schema preview_snapshot release_authorized source_revision files",
    )?;
    require(
        document["schema"].as_u64() == Some(1)
            && document["preview_snapshot"] == true
            && document["release_authorized"] == false
            && document["files"]
                .as_object()
                .is_some_and(|files| files.len() as u64 == count)
            && document["source_revision"].as_str().is_some_and(|text| {
                !text.is_empty() && text.len() <= 256 && text.bytes().all(|b| b.is_ascii_graphic())
            }),
        "desktop preview declaration differs",
    )?;
    let archive = media.member("desktop-preview.tar.zst", 4 * 1024 * 1024 * 1024)?;
    let archive_identity = files::identity(&archive.metadata()?);
    let reviewed = enzimos_policy::file_overlay::review(&archive, &document["files"])?;
    enzimos_policy::file_overlay::resources(&reviewed)?;
    Ok(Some(Prepared {
        manifest,
        manifest_identity,
        document,
        archive,
        archive_identity,
        reviewed,
    }))
}
pub(crate) fn preflight(media: &crate::media_source::Media, manifest: &Value) -> Result<()> {
    prepare(media, manifest).map(|_| ())
}
