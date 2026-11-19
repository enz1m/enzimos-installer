// SPDX-License-Identifier: MIT
//! Independent completion checks after the exact worker/cgroup has stopped.
use crate::{
    flatpak_install as install,
    flatpak_media::{ENZIMOS, FLATHUB, Prepared},
    media_packages::Admitted,
    target_storage::Target,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use enzimos_policy::{flatpak_plan::Source, flatpak_state};
use serde_json::Value;
use std::{collections::BTreeMap, fs::File, os::fd::AsFd, path::Path};
pub(crate) const STEPS: [&str; 5] = ["policy", "system-remote", "apps", "user-remote", "browser"];
pub(crate) fn validate(body: &Value, request: &Value, owner: &Value) -> Result<()> {
    json::fields(
        body,
        "schema role phase request_sha256 owner inputs enzimos providers store username user_remote steps outputs deployments network_fallback installed_qualification",
    )?;
    require(
        body["schema"] == 1
            && body["role"] == "fresh-offline-flatpaks"
            && matches!(body["phase"].as_str(), Some("writing" | "complete"))
            && body["request_sha256"] == json::fingerprint(request)?
            && body["owner"] == *owner
            && body["network_fallback"] == false
            && body["installed_qualification"] == false
            && body["username"]
                .as_str()
                .is_some_and(crate::answers::ordinary_name)
            && body["user_remote"].as_bool().is_some(),
        "offline Flatpak receipt binding or role differs",
    )?;
    let steps = body["steps"]
        .as_array()
        .ok_or_else(|| Error("offline Flatpak receipt steps missing".into()))?;
    require(
        steps.len() <= STEPS.len()
            && steps.iter().zip(STEPS).all(|(a, b)| a == b)
            && (body["phase"] != "complete" || steps.len() == STEPS.len()),
        "offline Flatpak ordered steps differ",
    )?;
    let origins = origins(body)?;
    json::fields(&body["providers"], "flatpak runuser env")?;
    let user = body["user_remote"].as_bool().unwrap();
    require(
        user == !body["store"].is_null()
            && user == !body["providers"]["runuser"].is_null()
            && user == !body["providers"]["env"].is_null(),
        "offline Flatpak user/provider role differs",
    )?;
    let deployments = body["deployments"]
        .as_object()
        .ok_or_else(|| Error("offline Flatpak deployment registry type".into()))?;
    require(
        deployments.is_empty() || deployments.keys().eq(origins.keys()),
        "offline Flatpak deployment registry differs",
    )?;
    require(
        body["phase"] != "complete" || !deployments.is_empty(),
        "offline Flatpak complete receipt lacks deployments",
    )?;
    for (app, row) in deployments {
        json::fields(row, "ref commit origin active")?;
        require(
            row["ref"] == format!("app/{app}/x86_64/stable")
                && origins.get(app).is_some_and(|s| row["origin"] == s.name()),
            "offline Flatpak deployment ref or origin differs",
        )?;
        enzimos_policy::identity::sha(
            row["commit"]
                .as_str()
                .ok_or_else(|| Error("offline Flatpak commit type".into()))?,
        )?;
        json::fields(&row["active"], "path kind target inode mount")?;
        require(
            row["active"]["kind"] == "symlink"
                && row["active"]["target"] == row["commit"]
                && row["active"]["path"]
                    == format!("var/lib/flatpak/app/{app}/x86_64/stable/active"),
            "offline Flatpak active link binding differs",
        )?;
    }
    let outputs = body["outputs"]
        .as_object()
        .ok_or_else(|| Error("offline Flatpak output registry type".into()))?;
    let expected = expected(body)?;
    require(
        outputs.keys().all(|s| expected.contains_key(s))
            && (body["phase"] != "complete" || outputs.keys().eq(expected.keys())),
        "offline Flatpak output registry differs",
    )?;
    Ok(())
}
/// Each selected app with the remote it is installed from; an app selected
/// from both remotes is ambiguous.
fn origins(body: &Value) -> Result<BTreeMap<String, Source>> {
    let mut origins = BTreeMap::new();
    for (key, source) in [("inputs", Source::Flathub), ("enzimos", Source::Enzimos)] {
        if source == Source::Enzimos && body[key].is_null() {
            continue;
        }
        let inputs = &body[key];
        json::fields(
            inputs,
            "schema apps policy list_inode remote_inode repo_inode mount",
        )?;
        require(
            inputs["schema"] == 1 && inputs["policy"]["remote"] == source.name(),
            "offline Flatpak input schema",
        )?;
        let apps = inputs["apps"]
            .as_array()
            .ok_or_else(|| Error("offline Flatpak apps missing".into()))?;
        require(
            !apps.is_empty() && apps.len() <= 128,
            "offline Flatpak app selection ambiguous",
        )?;
        for app in apps {
            let app = app
                .as_str()
                .ok_or_else(|| Error("offline Flatpak app type".into()))?;
            require(
                enzimos_policy::flatpak_plan::app_id(app)
                    && origins.insert(app.to_owned(), source).is_none(),
                "offline Flatpak app selection ambiguous",
            )?;
        }
    }
    Ok(origins)
}
fn expected(body: &Value) -> Result<BTreeMap<String, (u32, bool)>> {
    let mut names = BTreeMap::from([
        (install::REMOTE.into(), (0, true)),
        (install::APPS.into(), (0, true)),
        ("var/lib/flatpak/repo/config".into(), (0, true)),
        (
            "var/lib/flatpak/repo/flathub.trustedkeys.gpg".into(),
            (0, true),
        ),
    ]);
    for (app, row) in body["deployments"]
        .as_object()
        .ok_or_else(|| Error("Flatpak deployment type".into()))?
    {
        let commit = row["commit"]
            .as_str()
            .ok_or_else(|| Error("Flatpak deployment commit missing".into()))?;
        names.insert(
            format!("var/lib/flatpak/app/{app}/x86_64/stable/{commit}/metadata"),
            (0, false),
        );
    }
    if !body["enzimos"].is_null() {
        names.insert(install::ENZIMOS_REMOTE.into(), (0, true));
        names.insert(install::ENZIMOS_APPS.into(), (0, true));
        names.insert(
            "var/lib/flatpak/repo/enzimos.trustedkeys.gpg".into(),
            (0, true),
        );
    }
    if body["user_remote"] == true {
        let username = body["username"]
            .as_str()
            .ok_or_else(|| Error("Flatpak user name missing".into()))?;
        for leaf in ["config", "flathub.trustedkeys.gpg"] {
            names.insert(
                format!("home/{username}/.local/share/flatpak/repo/{leaf}"),
                (1000, true),
            );
        }
    }
    if body["inputs"]["apps"]
        .as_array()
        .ok_or_else(|| Error("Flatpak apps missing".into()))?
        .iter()
        .any(|app| app == "app.zen_browser.zen")
    {
        names.insert(install::BROWSER.into(), (0, true));
    }
    Ok(names)
}
pub(crate) fn state(root: &File, body: &Value) -> Result<()> {
    let originals = crate::flatpak_files::verify(root, body, &expected(body)?)?;
    let mut active_links = Vec::new();
    let system = if body["enzimos"].is_null() {
        &[Source::Flathub][..]
    } else {
        &[Source::Flathub, Source::Enzimos][..]
    };
    flatpak_state::remote(
        &crate::flatpak_files::observe(root, "var/lib/flatpak/repo/config", 0, true)?.2,
        system,
    )?;
    if body["user_remote"] == true {
        let name = format!(
            "home/{}/.local/share/flatpak/repo/config",
            body["username"].as_str().unwrap()
        );
        flatpak_state::remote(
            &crate::flatpak_files::observe(root, &name, 1000, true)?.2,
            &[Source::Flathub],
        )?;
    }
    for (app, row) in body["deployments"].as_object().unwrap() {
        let (file, actual) = enzimos_policy::file_overlay::capture(
            root,
            row["active"]["path"].as_str().unwrap(),
            0,
        )?;
        require(
            actual == row["active"],
            "actual Flatpak active deployment changed",
        )?;
        active_links.push((file, actual));
        let path = format!(
            "var/lib/flatpak/app/{app}/x86_64/stable/{}/metadata",
            row["commit"].as_str().unwrap()
        );
        flatpak_state::metadata(
            &crate::flatpak_files::observe(root, &path, 0, false)?.2,
            app,
        )?;
    }
    for (source, key, list, remote) in [
        (Source::Flathub, "inputs", install::APPS, install::REMOTE),
        (
            Source::Enzimos,
            "enzimos",
            install::ENZIMOS_APPS,
            install::ENZIMOS_REMOTE,
        ),
    ] {
        if body[key].is_null() {
            continue;
        }
        let list = crate::flatpak_files::observe(root, list, 0, true)?.2;
        enzimos_policy::flatpak_plan::applications(source, &list, &body[key]["apps"])?;
        let remote = crate::flatpak_files::observe(root, remote, 0, true)?.2;
        require(
            enzimos_policy::flatpak_plan::remote(source, &remote)? == body[key]["policy"],
            "published Flatpak remote differs from original ISO signing policy",
        )?;
    }
    if expected(body)?.contains_key(install::BROWSER) {
        require(
            crate::flatpak_files::observe(root, install::BROWSER, 0, true)?.2 == install::MIME,
            "Flatpak default browser associations differ",
        )?;
    }
    for (file, row) in active_links {
        let (_, actual) =
            enzimos_policy::file_overlay::capture(root, row["path"].as_str().unwrap(), 0)?;
        require(
            actual == row && serde_json::json!(files::identity(&file.metadata()?)) == row["inode"],
            "original Flatpak deployment changed during verification",
        )?;
    }
    originals.recheck(root)
}
pub(crate) fn completed(
    target: &Target<'_>,
    media: &Admitted,
    journal: &Value,
    directory: &File,
) -> Result<Option<Value>> {
    target.recheck()?;
    media.recheck()?;
    let needed = target.source().answers.flatpaks
        && !media.manifest["flatpaks"]
            .as_array()
            .ok_or_else(|| Error("Flatpak declaration type".into()))?
            .is_empty();
    let record = files::optional_relative(directory, Path::new(install::RECORD))?;
    if !needed {
        require(record.is_none(), "unexpected Flatpak worker receipt")?;
        return Ok(None);
    }
    let file = record.ok_or_else(|| Error("original Flatpak worker receipt absent".into()))?;
    let identity = files::identity(&file.metadata()?);
    let mount = mount_identity::id(file.as_fd(), true)?;
    require(
        identity.7 & 0o7777 == 0o600 && identity.8 == 0 && identity.9 == 0 && identity.10 == 1,
        "private original Flatpak receipt required",
    )?;
    require(
        mount == mount_identity::id(directory.as_fd(), true)?,
        "Flatpak receipt crosses its original control mount",
    )?;
    let body = json::decode(
        &files::read_file(&file, 2 * 1024 * 1024, Some(0), true)?,
        2 * 1024 * 1024,
    )?;
    validate(&body, &journal["request"], &journal["owner"])?;
    require(
        body["phase"] == "complete" && body["username"] == target.source().answers.username,
        "original Flatpak attempt incomplete or another account",
    )?;
    let prepared = Prepared::observe(&media.media, &media.manifest, &FLATHUB)?
        .ok_or_else(|| Error("original offline Flatpak media absent".into()))?;
    let enzimos = Prepared::observe(&media.media, &media.manifest, &ENZIMOS)?;
    require(
        body["inputs"] == prepared.receipt()
            && body["enzimos"] == serde_json::json!(enzimos.as_ref().map(Prepared::receipt)),
        "original offline Flatpak input identities differ",
    )?;
    let mut providers = Vec::new();
    for (name, path) in [
        ("flatpak", "usr/bin/flatpak"),
        ("runuser", "usr/bin/runuser"),
        ("env", "usr/bin/env"),
    ] {
        let row = &body["providers"][name];
        if !row.is_null() {
            let provider = crate::install_boot_sources::Source::open(
                target.directory()?,
                Path::new(path),
                32 * 1024 * 1024,
            )?;
            require(
                provider.receipt() == *row,
                "original Flatpak provider changed",
            )?;
            provider.recheck(target.directory()?)?;
            providers.push(provider);
        }
    }
    let bin = files::directory_relative(target.directory()?, Path::new("usr/bin"), Some(0))?;
    require(
        files::optional_relative(&bin, Path::new("store-app"))?.is_some()
            == (body["user_remote"] == true),
        "Flatpak Store presence differs",
    )?;
    if body["user_remote"] == true {
        let store = crate::install_boot_sources::Source::open(
            target.directory()?,
            Path::new("usr/bin/store-app"),
            crate::flatpak_install::STORE_LIMIT,
        )?;
        require(
            store.receipt() == body["store"],
            "original Flatpak Store provider differs",
        )?;
        providers.push(store);
    }
    state(target.directory()?, &body)?;
    for provider in providers {
        provider.recheck(target.directory()?)?;
    }
    let named = files::open_relative(directory, Path::new(install::RECORD))?;
    require(
        files::identity(&named.metadata()?) == identity
            && mount_identity::id(named.as_fd(), true)? == mount
            && mount_identity::id(file.as_fd(), true)? == mount
            && files::identity(&file.metadata()?) == identity
            && json::decode(
                &files::read_file(&file, 2 * 1024 * 1024, Some(0), true)?,
                2 * 1024 * 1024,
            )? == body,
        "original Flatpak receipt replaced during final verification",
    )?;
    target.recheck()?;
    media.recheck()?;
    Ok(Some(body))
}
#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    fn row(app: &str, origin: &str) -> Value {
        let commit = "a".repeat(64);
        json!({"ref":format!("app/{app}/x86_64/stable"),"commit":commit,"origin":origin,
            "active":{"path":format!("var/lib/flatpak/app/{app}/x86_64/stable/active"),"kind":"symlink","target":commit,"inode":0,"mount":0}})
    }
    fn inputs(remote: &str, apps: &[&str]) -> Value {
        json!({"schema":1,"apps":apps,"policy":{"remote":remote},"list_inode":0,"remote_inode":0,"repo_inode":0,"mount":0})
    }
    #[test]
    fn receipt_binds_each_app_to_the_remote_it_was_selected_from() {
        let (request, owner) = (json!({"operation":"boot"}), json!("owner"));
        let (zen, calculator) = ("app.zen_browser.zen", "org.enzimos.Calculator");
        let body = json!({"schema":1,"role":"fresh-offline-flatpaks","phase":"writing",
            "request_sha256":enzimos_platform::json::fingerprint(&request).unwrap(),"owner":owner,
            "inputs":inputs("flathub", &[zen]),"enzimos":inputs("enzimos", &[calculator]),
            "providers":{"flatpak":{},"runuser":null,"env":null},"store":null,"username":"admin","user_remote":false,
            "steps":[],"outputs":{},"deployments":{zen:row(zen, "flathub"),calculator:row(calculator, "enzimos")},
            "network_fallback":false,"installed_qualification":false});
        super::validate(&body, &request, &owner).unwrap();
        let mut changes = Vec::new();
        let mut wrong_origin = body.clone();
        wrong_origin["deployments"][calculator] = row(calculator, "flathub");
        changes.push(wrong_origin);
        // Before any deployment: one app selected from both remotes.
        let mut both = body.clone();
        both["enzimos"] = inputs("enzimos", &[calculator, zen]);
        both["deployments"] = json!({});
        changes.push(both);
        // A selected enzimOS app that did not deploy.
        let mut missing = body.clone();
        missing["deployments"] = json!({zen:row(zen, "flathub")});
        changes.push(missing);
        let mut unselected = body.clone();
        unselected["enzimos"] = Value::Null;
        changes.push(unselected);
        let mut swapped = body;
        swapped["enzimos"]["policy"]["remote"] = json!("flathub");
        changes.push(swapped);
        for changed in changes {
            assert!(
                super::validate(&changed, &request, &owner).is_err(),
                "{changed}"
            );
        }
    }
}
