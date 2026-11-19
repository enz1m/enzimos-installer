// SPDX-License-Identifier: MIT
//! Bounded boot artifacts below the original target; unknown destinations are never adopted.
use crate::install_boot_sources::Source;
use enzimos_platform::{Error, Result, files, require};
use serde_json::Value;
use std::{collections::BTreeMap, fs::File, path::Path};

pub(crate) fn text(root: &File, name: &str, bytes: &[u8], replace: bool) -> Result<()> {
    require(bytes.len() <= 65536, "initial boot text bound")?;
    let path = Path::new(name);
    let parent = files::ensure_directory_relative(root, path.parent().unwrap(), 0o755, 0)?;
    if let Some(old) = files::optional_relative(&parent, Path::new(path.file_name().unwrap()))? {
        require(
            replace,
            "preexisting boot destination cannot be replayed or adopted",
        )?;
        files::read_file(&old, 65536, Some(0), true)?;
    }
    let mode = files::public_file_mode(&parent)?;
    files::atomic_relative(
        &parent,
        Path::new(path.file_name().unwrap()),
        bytes,
        mode,
        Some(0),
        replace,
        65536,
    )?;
    require(
        files::read_file(
            &files::open_relative(&parent, Path::new(path.file_name().unwrap()))?,
            65536,
            Some(0),
            true,
        )? == bytes,
        "initial boot text readback differs",
    )
}
pub(crate) fn copy(
    root: &File,
    source: &Source,
    destination: &str,
    matching_existing: bool,
) -> Result<()> {
    source.recheck(root)?;
    let path = Path::new(destination);
    let parent = files::ensure_directory_relative(root, path.parent().unwrap(), 0o755, 0)?;
    if files::optional_relative(&parent, Path::new(path.file_name().unwrap()))?.is_some() {
        require(
            matching_existing,
            "unknown preexisting boot artifact refused",
        )?;
        let old = Source::open(root, path, 128 * 1024 * 1024)?;
        require(
            old.bytes == source.bytes && old.sha == source.sha,
            "existing kernel differs from original installed module",
        )?;
        old.recheck(root)?;
    } else {
        source.copy(root, &parent, path.file_name().unwrap().to_str().unwrap())?;
    }
    source.recheck(root)
}
pub(crate) fn measure(root: &File, name: &str) -> Result<Value> {
    let source = Source::open(root, Path::new(name), 128 * 1024 * 1024)?;
    source.recheck(root)?;
    Ok(source.receipt())
}
pub(crate) fn verify(root: &File, artifacts: &Value) -> Result<()> {
    let map = artifacts
        .as_object()
        .ok_or_else(|| Error("boot artifacts missing".into()))?;
    require(
        !map.is_empty() && map.len() <= 768,
        "boot artifact count bound",
    )?;
    for (name, body) in map {
        crate::install_boot_sources::validate(body)?;
        require(
            body["path"] == *name && measure(root, name)? == *body,
            "installed boot artifact identity or bytes changed",
        )?;
    }
    Ok(())
}
fn icon_name(name: &str) -> Result<bool> {
    if !name.ends_with(".png") {
        return Ok(false);
    }
    require(
        name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            && !matches!(name, "." | ".."),
        "boot icon canonical name",
    )?;
    Ok(true)
}
pub(crate) fn icons(root: &File) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let mut total = 0u64;
    let mut originals = Vec::<Source>::new();
    let mut copied = BTreeMap::<String, usize>::new();
    for source_path in ["usr/share/refind/icons", "usr/share/enzimos-boot"] {
        let directory = files::directory_relative(root, Path::new(source_path), Some(0))?;
        for (index, entry) in files::directory_names(&directory, 512)?
            .into_iter()
            .enumerate()
        {
            require(index < 512, "boot icon directory count bound")?;
            let name = entry
                .into_string()
                .map_err(|_| Error("boot icon name encoding".into()))?;
            // rEFInd also ships auxiliary SVG sources in a directory. Only
            // renderable PNG files enter the installed icon namespace.
            if !icon_name(&name)? {
                continue;
            }
            let source = Source::open(root, &Path::new(source_path).join(&name), 4 * 1024 * 1024)?;
            total = total
                .checked_add(source.bytes)
                .ok_or_else(|| Error("boot icon byte overflow".into()))?;
            require(total <= 64 * 1024 * 1024, "boot icon total byte bound")?;
            copied.insert(name, originals.len());
            // Keep the stock binding even when a reviewed custom PNG wins.
            originals.push(source);
        }
    }
    require(!copied.is_empty(), "graphical boot icon material absent")?;
    for (name, index) in &copied {
        let source = &originals[*index];
        let destination = format!("boot/EFI/enzimos/icons/{name}");
        copy(root, source, &destination, false)?;
        names.push(destination);
    }
    // Even replaced stock sources are rechecked after collection and publication.
    for source in &originals {
        source.recheck(root)?;
    }
    Ok(names)
}
