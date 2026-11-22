// SPDX-License-Identifier: MIT
//! Exact Mesa GL refs for offline installs, where Flatpak can skip related refs.
use crate::{flatpak_media::Prepared, media_source::Media};
use enzimos_platform::{Error, Result, files, json, require};
use enzimos_policy::{
    file_overlay,
    flatpak_plan::{Source, app_id},
};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
};

const PLATFORM: &str = "org.freedesktop.Platform";
const GL: &str = "org.freedesktop.Platform.GL.default";
/// create-usb mirrors Flathub refs under Flathub's collection in either repository.
const MIRROR: &str = "repo/refs/mirrors/org.flathub.Stable/runtime/";
pub(crate) const LISTING: [&str; 4] = [
    "list",
    "--system",
    "--runtime",
    "--columns=application:full,arch:full,branch:full,origin:full,active:full",
];

pub(crate) fn branch(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
pub(crate) fn reference(name: &str) -> Option<&str> {
    name.strip_prefix(GL)?
        .strip_prefix("/x86_64/")
        .filter(|b| branch(b))
}
pub(crate) fn link(gl_ref: &str) -> String {
    format!("var/lib/flatpak/runtime/{gl_ref}/active")
}
/// One installed runtime: its origin and the commit prefix `flatpak list` prints.
#[derive(Debug, PartialEq)]
pub(crate) struct Installed {
    pub origin: String,
    pub commit: String,
}
/// `id/x86_64/branch` of each installed system runtime.
pub(crate) fn installed(bytes: &[u8]) -> Result<BTreeMap<String, Installed>> {
    require(
        bytes.len() <= 256 * 1024 && !bytes.contains(&0),
        "installed Flatpak runtime listing bound",
    )?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error("installed Flatpak runtime listing encoding".into()))?;
    let mut rows = BTreeMap::new();
    for line in text.lines() {
        let fields = line.split('\t').map(str::trim).collect::<Vec<_>>();
        require(
            fields.len() == 5
                && rows.len() < 512
                && app_id(fields[0])
                && fields[1] == "x86_64"
                && branch(fields[2])
                && matches!(fields[3], "flathub" | "enzimos")
                && (12..=64).contains(&fields[4].len())
                && fields[4]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "installed Flatpak runtime identity",
        )?;
        let row = Installed {
            origin: fields[3].into(),
            commit: fields[4].into(),
        };
        require(
            rows.insert(format!("{}/x86_64/{}", fields[0], fields[2]), row)
                .is_none(),
            "installed Flatpak runtime duplicated",
        )?;
    }
    Ok(rows)
}
/// GL extension branches with their commits in one medium's sideload repository.
/// The medium's closed manifest names exactly the repository's files.
pub(crate) fn offered(media: &Media, prepared: &Prepared) -> Result<BTreeMap<String, String>> {
    let prefix = format!("{}/{MIRROR}{GL}/x86_64/", prepared.layout.directory);
    let mut offered = BTreeMap::new();
    for name in media.members.keys().filter(|n| n.starts_with(&prefix)) {
        let leaf = name.strip_prefix(&prefix).unwrap_or_default();
        require(branch(leaf), "sideload graphics ref name")?;
        let bytes = media.read(name, 4096)?;
        let commit = std::str::from_utf8(&bytes)
            .map_err(|_| Error("sideload graphics ref encoding".into()))?
            .trim_end_matches('\n');
        enzimos_policy::identity::sha(commit)?;
        offered.insert(leaf.to_owned(), commit.to_owned());
    }
    Ok(offered)
}
/// The GL extensions, `name -> commit`, this sideload adds for the Flathub
/// Platform runtimes now installed. Extensions already installed or already
/// chosen from an earlier sideload are left alone.
pub(crate) fn select(
    installed: &BTreeMap<String, Installed>,
    offered: &BTreeMap<String, String>,
    chosen: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut selected = BTreeMap::new();
    for (name, row) in installed {
        let Some(platform) = name
            .strip_prefix(PLATFORM)
            .and_then(|rest| rest.strip_prefix("/x86_64/"))
        else {
            continue;
        };
        if row.origin != Source::Flathub.name() {
            continue;
        }
        for wanted in [platform.to_owned(), format!("{platform}-extra")] {
            let gl = format!("{GL}/x86_64/{wanted}");
            if let Some(commit) = offered.get(&wanted)
                && !installed.contains_key(&gl)
                && !chosen.contains(&gl)
            {
                selected.insert(gl, commit.clone());
            }
        }
    }
    selected
}
/// The listing shows each installed extension from Flathub at its sideload commit.
pub(crate) fn confirm(
    installed: &BTreeMap<String, Installed>,
    chosen: &BTreeMap<String, String>,
) -> Result<()> {
    for (name, commit) in chosen {
        require(
            installed.get(name).is_some_and(|row| {
                row.origin == Source::Flathub.name() && commit.starts_with(&row.commit)
            }),
            "offline Mesa GL extension did not install from its sideload commit",
        )?;
    }
    Ok(())
}
/// Each recorded extension's active link, still at its recorded state.
pub(crate) fn capture(root: &File, body: &Value) -> Result<Vec<(File, Value)>> {
    let mut links = Vec::new();
    for row in body["graphics"]
        .as_object()
        .ok_or_else(|| Error("offline Mesa GL registry type".into()))?
        .values()
    {
        let (file, actual) = file_overlay::capture(
            root,
            row["active"]["path"]
                .as_str()
                .ok_or_else(|| Error("offline Mesa GL active path".into()))?,
            0,
        )?;
        require(
            actual == row["active"],
            "actual Mesa GL extension deployment changed",
        )?;
        links.push((file, actual));
    }
    Ok(links)
}
pub(crate) fn recheck(root: &File, links: &[(File, Value)]) -> Result<()> {
    for (file, row) in links {
        let (_, actual) = file_overlay::capture(root, row["path"].as_str().unwrap(), 0)?;
        require(
            actual == *row && value!(files::identity(&file.metadata()?)) == row["inode"],
            "original Mesa GL extension deployment changed",
        )?;
    }
    Ok(())
}
/// Receipt rows: each extension, from a sideload the receipt names, bound to
/// the active link of its sideload commit.
pub(crate) fn validate(body: &Value) -> Result<()> {
    let rows = body["graphics"]
        .as_object()
        .ok_or_else(|| Error("offline Mesa GL registry type".into()))?;
    require(rows.len() <= 16, "offline Mesa GL registry bound")?;
    for (name, row) in rows {
        json::fields(row, "commit source active")?;
        json::fields(&row["active"], "path kind target inode mount")?;
        enzimos_policy::identity::sha(
            row["commit"]
                .as_str()
                .ok_or_else(|| Error("offline Mesa GL commit type".into()))?,
        )?;
        require(
            reference(name).is_some()
                && (row["source"] == Source::Flathub.name()
                    || (row["source"] == Source::Enzimos.name() && !body["enzimos"].is_null()))
                && row["active"]["kind"] == "symlink"
                && row["active"]["target"] == row["commit"]
                && row["active"]["path"] == link(name),
            "offline Mesa GL extension binding differs",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn listing(rows: &[(&str, &str, &str)]) -> Vec<u8> {
        rows.iter()
            .map(|(id, branch, origin)| format!("{id}\tx86_64\t{branch}\t{origin}\t0123456789ab\n"))
            .collect::<String>()
            .into_bytes()
    }
    fn offer(branches: &[&str]) -> BTreeMap<String, String> {
        branches
            .iter()
            .map(|b| ((*b).to_owned(), "0123456789ab".repeat(5) + "cdef"))
            .collect()
    }
    #[test]
    fn selects_only_the_graphics_refs_of_installed_flathub_platforms() {
        let installed = installed(&listing(&[
            (PLATFORM, "25.08", "flathub"),
            (PLATFORM, "26.08", "flathub"),
            ("org.freedesktop.Platform.Locale", "26.08", "flathub"),
            ("org.gnome.Platform", "51", "flathub"),
        ]))
        .unwrap();
        let flathub = select(&installed, &offer(&["24.08", "25.08"]), &BTreeSet::new());
        assert_eq!(
            flathub.keys().collect::<Vec<_>>(),
            [&format!("{GL}/x86_64/25.08")]
        );
        let ours = select(
            &installed,
            &offer(&["25.08", "26.08", "26.08-extra"]),
            &flathub.keys().cloned().collect(),
        );
        assert_eq!(
            ours.keys().cloned().collect::<Vec<_>>(),
            [
                format!("{GL}/x86_64/26.08"),
                format!("{GL}/x86_64/26.08-extra")
            ]
        );
        assert!(select(&installed, &BTreeMap::new(), &BTreeSet::new()).is_empty());
    }
    #[test]
    fn leaves_installed_and_foreign_runtimes_alone() {
        let installed = installed(&listing(&[
            (PLATFORM, "26.08", "flathub"),
            (GL, "26.08", "flathub"),
            (PLATFORM, "27.08", "enzimos"),
        ]))
        .unwrap();
        let selected = select(
            &installed,
            &offer(&["26.08", "26.08-extra", "27.08"]),
            &BTreeSet::new(),
        );
        assert_eq!(
            selected.keys().cloned().collect::<Vec<_>>(),
            [format!("{GL}/x86_64/26.08-extra")]
        );
    }
    #[test]
    fn confirms_origin_and_commit() {
        let chosen = BTreeMap::from([(
            format!("{GL}/x86_64/26.08"),
            "0123456789ab".repeat(5) + "cdef",
        )]);
        let good = installed(&listing(&[(GL, "26.08", "flathub")])).unwrap();
        confirm(&good, &chosen).unwrap();
        for rows in [
            listing(&[]),
            listing(&[(GL, "26.08", "enzimos")]),
            b"org.freedesktop.Platform.GL.default\tx86_64\t26.08\tflathub\tffffffffffff\n".to_vec(),
        ] {
            assert!(confirm(&installed(&rows).unwrap(), &chosen).is_err());
        }
    }
    #[test]
    fn refuses_malformed_listings_and_names() {
        for rows in [
            b"org.freedesktop.Platform\tx86_64\t26.08\tflathub\n".to_vec(),
            b"org.freedesktop.Platform\taarch64\t26.08\tflathub\t0123456789ab\n".to_vec(),
            b"org.freedesktop.Platform\tx86_64\t../x\tflathub\t0123456789ab\n".to_vec(),
            b"org.freedesktop.Platform\tx86_64\t26.08\tother\t0123456789ab\n".to_vec(),
            listing(&[
                (PLATFORM, "26.08", "flathub"),
                (PLATFORM, "26.08", "flathub"),
            ]),
        ] {
            assert!(installed(&rows).is_err());
        }
        assert_eq!(
            reference(&format!("{GL}/x86_64/26.08-extra")),
            Some("26.08-extra")
        );
        for name in [
            format!("{GL}/x86_64/"),
            format!("{GL}/aarch64/26.08"),
            format!("{GL}/x86_64/.."),
            format!("{PLATFORM}/x86_64/26.08"),
        ] {
            assert_eq!(reference(&name), None, "{name}");
        }
    }
    #[test]
    fn receipt_rows_bind_their_sideload_commit() {
        let name = format!("{GL}/x86_64/26.08");
        let commit = "a".repeat(64);
        let body = serde_json::json!({"enzimos":{},"graphics":{&name:{"commit":commit,"source":"enzimos",
            "active":{"path":link(&name),"kind":"symlink","target":commit,"inode":0,"mount":0}}}});
        validate(&body).unwrap();
        let mut changes = Vec::new();
        for (pointer, value) in [
            ("/enzimos".to_owned(), Value::Null),
            (
                "/graphics/".to_owned() + &name.replace('/', "~1") + "/source",
                value!("other"),
            ),
            (
                "/graphics/".to_owned() + &name.replace('/', "~1") + "/active/target",
                value!("b".repeat(64)),
            ),
            (
                "/graphics/".to_owned() + &name.replace('/', "~1") + "/active/path",
                value!(link(&format!("{GL}/x86_64/25.08"))),
            ),
        ] {
            let mut changed = body.clone();
            *changed.pointer_mut(&pointer).unwrap() = value;
            changes.push(changed);
        }
        let mut renamed = body.clone();
        let row = renamed["graphics"]
            .as_object_mut()
            .unwrap()
            .remove(&name)
            .unwrap();
        renamed["graphics"][format!("{PLATFORM}/x86_64/26.08")] = row;
        changes.push(renamed);
        for changed in changes {
            assert!(validate(&changed).is_err(), "{changed}");
        }
    }
}
