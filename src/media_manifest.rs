// SPDX-License-Identifier: MIT
//! Legacy installation media hashes are integrity records, never signer authority.
use enzimos_platform::{Error, Result, require};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};
pub const MAX_MANIFEST: usize = 16 * 1024 * 1024;
pub fn relative(path: &str) -> Result<()> {
    require(
        !path.is_empty()
            && path.len() <= 4096
            && !path.starts_with('/')
            && !path.chars().any(char::is_control)
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 255)
            && Path::new(path)
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "noncanonical installation media path",
    )
}
pub fn parse(body: &[u8]) -> Result<BTreeMap<String, String>> {
    require(
        body.len() <= MAX_MANIFEST && !body.is_empty(),
        "installation media manifest byte bound",
    )?;
    let text = std::str::from_utf8(body)
        .map_err(|_| Error("installation media manifest encoding".into()))?;
    let mut files = BTreeMap::new();
    for line in text.lines() {
        let (digest, path) = line
            .split_once("  ")
            .ok_or_else(|| Error("installation media digest row shape".into()))?;
        require(
            files.len() < 131072
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "installation media digest bound or encoding",
        )?;
        relative(path)?;
        require(
            path != "SHA256SUMS" && files.insert(path.into(), digest.into()).is_none(),
            "duplicate or self-referential installation media digest",
        )?;
    }
    require(!files.is_empty(), "installation media manifest is empty")?;
    Ok(files)
}
pub fn package_list(body: &[u8]) -> Result<Vec<String>> {
    require(body.len() <= 1024 * 1024, "offline package list bound")?;
    let text =
        std::str::from_utf8(body).map_err(|_| Error("offline package list encoding".into()))?;
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();
    for line in text.lines() {
        require(
            files.len() < 1024
                && line.len() <= 255
                && line.ends_with(".pkg.tar.zst")
                && line
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && line
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"@+_.:-".contains(&b))
                && seen.insert(line),
            "ambiguous or invalid offline package filename",
        )?;
        files.push(line.into());
    }
    Ok(files)
}
