// SPDX-License-Identifier: MIT
//! One original supervised offline attempt; a partial intent is never resumed.
use crate::{
    flatpak_files::Held,
    flatpak_media::{ENZIMOS, FLATHUB, Prepared},
    flatpak_tools::Tools,
    media_packages::Admitted,
    package_handoff::Received,
};
use enzimos_platform::{Error, Result, files, json, require};
use enzimos_policy::{flatpak_plan::Source, flatpak_state};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::fd::AsFd,
    path::{Component, Path},
};
pub(crate) const RECORD: &str = "flatpaks.json";
/// The native Store binary is a full GUI application (about 49 MiB today).
pub(crate) const STORE_LIMIT: u64 = 128 * 1024 * 1024;
pub(crate) const REMOTE: &str = "usr/share/enzimos/flathub.flatpakrepo";
pub(crate) const APPS: &str = "usr/share/enzimos/default-flatpaks.txt";
pub(crate) const ENZIMOS_REMOTE: &str = "usr/share/enzimos/enzimos.flatpakrepo";
pub(crate) const ENZIMOS_APPS: &str = "usr/share/enzimos/enzimos-flatpaks.txt";
pub(crate) const BROWSER: &str = "etc/xdg/mimeapps.list";
pub(crate) const MIME:&[u8] = b"[Default Applications]\nx-scheme-handler/http=app.zen_browser.zen.desktop\nx-scheme-handler/https=app.zen_browser.zen.desktop\ntext/html=app.zen_browser.zen.desktop\napplication/xhtml+xml=app.zen_browser.zen.desktop\n";
pub(crate) fn fresh(root: &File, path: &str) -> Result<()> {
    crate::media_manifest::relative(path)?;
    let mut current = root.try_clone()?;
    for part in Path::new(path).components() {
        let Component::Normal(name) = part else {
            return Err(Error("Flatpak destination path refused".into()));
        };
        let Some(next) = files::optional_directory_relative(&current, Path::new(name), None)?
        else {
            return Ok(());
        };
        current = next;
    }
    Err(Error(
        "fresh offline Flatpak installation cannot adopt an existing repository".into(),
    ))
}
/// Installs and records the Mesa GL refs for the installed Flathub runtimes.
fn graphics(
    context: &Received,
    media: &Admitted,
    prepared: &Prepared,
    enzimos: Option<&Prepared>,
    tools: &Tools,
    body: &mut Value,
) -> Result<()> {
    use crate::flatpak_graphics as gl;
    let mut chosen = BTreeMap::new();
    for sideload in std::iter::once(prepared).chain(enzimos) {
        let offered = gl::offered(&media.media, sideload)?;
        if offered.is_empty() {
            continue;
        }
        let listing = tools.system(context, media, sideload, &gl::LISTING, &[])?;
        let selected = gl::select(
            &gl::installed(&listing)?,
            &offered,
            &chosen.keys().cloned().collect(),
        );
        if selected.is_empty() {
            continue;
        }
        let refs = selected
            .keys()
            .map(|name| format!("runtime/{name}"))
            .collect::<Vec<_>>();
        let mut arguments = vec![
            "install",
            "--system",
            "--noninteractive",
            "--no-related",
            "--no-deps",
            "--sideload-repo",
            "@fd-dir:2",
            "flathub",
        ];
        arguments.extend(refs.iter().map(String::as_str));
        tools.system(
            context,
            media,
            sideload,
            &arguments,
            &[sideload.repo.as_fd()],
        )?;
        for (name, commit) in selected {
            chosen.insert(name, (commit, sideload.layout.source));
        }
    }
    if chosen.is_empty() {
        return Ok(());
    }
    let listing = tools.system(context, media, prepared, &gl::LISTING, &[])?;
    gl::confirm(
        &gl::installed(&listing)?,
        &chosen
            .iter()
            .map(|(name, (commit, _))| (name.clone(), commit.clone()))
            .collect(),
    )?;
    for (name, (commit, source)) in chosen {
        let (_, active) =
            enzimos_policy::file_overlay::capture(&context.target, &gl::link(&name), 0)?;
        require(
            active["target"] == commit.as_str(),
            "offline Mesa GL extension active deployment differs from its sideload commit",
        )?;
        body["graphics"][&name] = value!({"commit":commit,"source":source.name(),"active":active});
    }
    Ok(())
}
fn record(
    context: &Received,
    receipt: &mut crate::component_receipt::Receipt,
    body: &Value,
) -> Result<()> {
    context.recheck()?;
    crate::flatpak_verify::validate(body, &context.request, &context.store.journal["owner"])?;
    receipt.publish(body)?;
    context.recheck()
}
#[allow(
    clippy::too_many_arguments,
    reason = "one step's retained inputs, all rechecked together"
)]
fn advance(
    context: &Received,
    media: &Admitted,
    prepared: &Prepared,
    enzimos: Option<&Prepared>,
    tools: &Tools,
    held: &Held,
    receipt: &mut crate::component_receipt::Receipt,
    body: &mut Value,
    step: &str,
) -> Result<()> {
    tools.recheck(context)?;
    prepared.recheck(&media.media)?;
    if let Some(enzimos) = enzimos {
        enzimos.recheck(&media.media)?;
    }
    held.recheck(&context.target)?;
    body["steps"].as_array_mut().unwrap().push(value!(step));
    record(context, receipt, body)
}
fn publish(
    context: &Received,
    held: &mut Held,
    body: &mut Value,
    name: &str,
    bytes: &[u8],
    replace: bool,
) -> Result<()> {
    context.recheck()?;
    held.recheck(&context.target)?;
    let path = Path::new(name);
    let parent =
        files::ensure_directory_relative(&context.target, path.parent().unwrap(), 0o755, 0)?;
    files::atomic_relative(
        &parent,
        Path::new(path.file_name().unwrap()),
        bytes,
        0o644,
        Some(0),
        replace,
        128 * 1024,
    )?;
    require(
        held.add(&context.target, name, 0, true, body)? == bytes,
        "offline Flatpak public file readback differs",
    )
}
pub(crate) fn install(context: &Received, media: &Admitted) -> Result<Value> {
    context.recheck()?;
    media.recheck()?;
    let source = context
        .answers
        .as_ref()
        .ok_or_else(|| Error("offline Flatpak original answers absent".into()))?;
    if !source.answers.flatpaks {
        return Ok(value!({"schema":1,"status":"not-requested","installed_qualification":false}));
    }
    let enzimos = Prepared::observe(&media.media, &media.manifest, &ENZIMOS)?;
    let Some(prepared) = Prepared::observe(&media.media, &media.manifest, &FLATHUB)? else {
        require(
            enzimos.is_none(),
            "enzimOS apps need the Flathub runtime source on the same medium",
        )?;
        return Ok(
            value!({"schema":1,"status":"no-offline-media","installed_qualification":false}),
        );
    };
    let enzimos = enzimos.as_ref();
    let bin = files::directory_relative(&context.target, Path::new("usr/bin"), Some(0))?;
    let user_remote = files::optional_relative(&bin, Path::new("store-app"))?.is_some();
    let store = if user_remote {
        Some(crate::install_boot_sources::Source::open(
            &context.target,
            Path::new("usr/bin/store-app"),
            STORE_LIMIT,
        )?)
    } else {
        None
    };
    let tools = Tools::observe(context, user_remote)?;
    fresh(&context.target, "var/lib/flatpak/repo")?;
    let user_repo = format!("home/{}/.local/share/flatpak/repo", source.answers.username);
    if user_remote {
        fresh(&context.target, &user_repo)?;
    }
    let mut body = value!({"schema":1,"role":"fresh-offline-flatpaks","phase":"writing","request_sha256":json::fingerprint(&context.request)?,"owner":context.store.journal["owner"],
        "inputs":prepared.receipt(),"enzimos":enzimos.map(Prepared::receipt),"providers":tools.receipt(),"store":store.as_ref().map(crate::install_boot_sources::Source::receipt),"username":source.answers.username,"user_remote":user_remote,"steps":[],"outputs":{},"deployments":{},"graphics":{},"network_fallback":false,"installed_qualification":false});
    crate::flatpak_verify::validate(&body, &context.request, &context.store.journal["owner"])?;
    let mut receipt =
        crate::component_receipt::Receipt::create(context.store.directory(), RECORD, &body)?;
    let mut held = Held::new();
    publish(
        context,
        &mut held,
        &mut body,
        REMOTE,
        &files::read_file(&prepared.remote, 128 * 1024, Some(0), true)?,
        false,
    )?;
    publish(
        context,
        &mut held,
        &mut body,
        APPS,
        &files::read_file(&prepared.list, 64 * 1024, Some(0), true)?,
        false,
    )?;
    if let Some(enzimos) = enzimos {
        publish(
            context,
            &mut held,
            &mut body,
            ENZIMOS_REMOTE,
            &files::read_file(&enzimos.remote, 128 * 1024, Some(0), true)?,
            false,
        )?;
        publish(
            context,
            &mut held,
            &mut body,
            ENZIMOS_APPS,
            &files::read_file(&enzimos.list, 64 * 1024, Some(0), true)?,
            false,
        )?;
    }
    advance(
        context,
        media,
        &prepared,
        enzimos,
        &tools,
        &held,
        &mut receipt,
        &mut body,
        "policy",
    )?;
    let remote_path = format!("/{REMOTE}");
    tools.system(
        context,
        media,
        &prepared,
        &[
            "remote-add",
            "--system",
            "--if-not-exists",
            "--from",
            // flatpak 1.18 remote-add spells it with an underscore.
            "--no-follow_redirect",
            "--no-authenticator-install",
            "flathub",
            &remote_path,
        ],
        &[],
    )?;
    tools.system(
        context,
        media,
        &prepared,
        &[
            "remote-modify",
            "--system",
            "--collection-id=org.flathub.Stable",
            "--no-follow-redirect",
            "--no-authenticator-install",
            "flathub",
        ],
        &[],
    )?;
    let mut sources = vec![Source::Flathub];
    if let Some(enzimos) = enzimos {
        let remote_path = format!("/{ENZIMOS_REMOTE}");
        let collection = format!("--collection-id={}", Source::Enzimos.collection());
        tools.system(
            context,
            media,
            enzimos,
            &[
                "remote-add",
                "--system",
                "--if-not-exists",
                "--from",
                "--no-follow_redirect",
                "--no-authenticator-install",
                "enzimos",
                &remote_path,
            ],
            &[],
        )?;
        tools.system(
            context,
            media,
            enzimos,
            &[
                "remote-modify",
                "--system",
                &collection,
                "--no-follow-redirect",
                "--no-authenticator-install",
                "enzimos",
            ],
            &[],
        )?;
        sources.push(Source::Enzimos);
    }
    let config = files::open_relative(&context.target, Path::new("var/lib/flatpak/repo/config"))?;
    flatpak_state::remote(
        &files::read_file(&config, 512 * 1024, Some(0), true)?,
        &sources,
    )?;
    for source in &sources {
        held.add(
            &context.target,
            &format!("var/lib/flatpak/repo/{}.trustedkeys.gpg", source.name()),
            0,
            true,
            &mut body,
        )?;
    }
    advance(
        context,
        media,
        &prepared,
        enzimos,
        &tools,
        &held,
        &mut receipt,
        &mut body,
        "system-remote",
    )?;
    let refs = prepared
        .apps
        .iter()
        .map(|id| format!("app/{id}/x86_64/stable"))
        .collect::<Vec<_>>();
    let mut arguments = vec![
        "install",
        "--system",
        "--noninteractive",
        "--sideload-repo",
        "@fd-dir:2",
        "flathub",
    ];
    arguments.extend(refs.iter().map(String::as_str));
    tools.system(
        context,
        media,
        &prepared,
        &arguments,
        &[prepared.repo.as_fd()],
    )?;
    let mut expected = prepared
        .apps
        .iter()
        .map(|app| (app.clone(), Source::Flathub))
        .collect::<BTreeMap<_, _>>();
    if let Some(enzimos) = enzimos {
        // Flathub's apps brought the runtime these apps need, so the enzimOS
        // sideload repository alone completes this offline install.
        let refs = enzimos
            .apps
            .iter()
            .map(|id| format!("app/{id}/x86_64/stable"))
            .collect::<Vec<_>>();
        let mut arguments = vec![
            "install",
            "--system",
            "--noninteractive",
            "--sideload-repo",
            "@fd-dir:2",
            "enzimos",
        ];
        arguments.extend(refs.iter().map(String::as_str));
        tools.system(context, media, enzimos, &arguments, &[enzimos.repo.as_fd()])?;
        for app in &enzimos.apps {
            require(
                expected.insert(app.clone(), Source::Enzimos).is_none(),
                "offline application selected from two remotes",
            )?;
        }
    }
    let listing = tools.system(
        context,
        media,
        &prepared,
        &[
            "list",
            "--system",
            "--app",
            "--columns=application:full,arch:full,branch:full,origin:full,active:full",
        ],
        &[],
    )?;
    body["deployments"] = value!(flatpak_state::deployments(&listing, &expected)?);
    let mut active_links = Vec::new();
    for (app, row) in body["deployments"].as_object().unwrap().clone() {
        let directory = format!("var/lib/flatpak/app/{app}/x86_64/stable");
        let (link, active) = enzimos_policy::file_overlay::capture(
            &context.target,
            &format!("{directory}/active"),
            0,
        )?;
        // The listing shows a commit prefix; the active link names the full commit.
        let full = active["target"].as_str().unwrap_or_default().to_owned();
        enzimos_policy::identity::sha(&full)?;
        require(
            full.starts_with(row["commit"].as_str().unwrap_or("-")),
            "offline Flatpak active deployment differs from actual installed commit",
        )?;
        body["deployments"][&app]["commit"] = value!(full);
        let row = &body["deployments"][&app].clone();
        body["deployments"][&app]["active"] = active.clone();
        active_links.push((link, active));
        let name = format!("{directory}/{}/metadata", row["commit"].as_str().unwrap());
        let metadata = held.add(&context.target, &name, 0, false, &mut body)?;
        flatpak_state::metadata(&metadata, &app)?;
    }
    held.add(
        &context.target,
        "var/lib/flatpak/repo/config",
        0,
        true,
        &mut body,
    )?;
    advance(
        context,
        media,
        &prepared,
        enzimos,
        &tools,
        &held,
        &mut receipt,
        &mut body,
        "apps",
    )?;
    graphics(context, media, &prepared, enzimos, &tools, &mut body)?;
    advance(
        context,
        media,
        &prepared,
        enzimos,
        &tools,
        &held,
        &mut receipt,
        &mut body,
        "graphics",
    )?;
    if user_remote {
        store.as_ref().unwrap().recheck(&context.target)?;
        tools.user(
            context,
            media,
            &prepared,
            &[
                "remote-add",
                "--user",
                "--if-not-exists",
                "--from",
                "--no-follow_redirect",
                "--no-authenticator-install",
                "flathub",
                &remote_path,
            ],
        )?;
        tools.user(
            context,
            media,
            &prepared,
            &[
                "remote-modify",
                "--user",
                "--collection-id=org.flathub.Stable",
                "--no-follow-redirect",
                "--no-authenticator-install",
                "flathub",
            ],
        )?;
        let bytes = held.add(
            &context.target,
            &format!("{user_repo}/config"),
            1000,
            true,
            &mut body,
        )?;
        flatpak_state::remote(&bytes, &[Source::Flathub])?;
        held.add(
            &context.target,
            &format!("{user_repo}/flathub.trustedkeys.gpg"),
            1000,
            true,
            &mut body,
        )?;
    }
    advance(
        context,
        media,
        &prepared,
        enzimos,
        &tools,
        &held,
        &mut receipt,
        &mut body,
        "user-remote",
    )?;
    if prepared.apps.iter().any(|app| app == "app.zen_browser.zen") {
        publish(context, &mut held, &mut body, BROWSER, MIME, true)?;
    }
    advance(
        context,
        media,
        &prepared,
        enzimos,
        &tools,
        &held,
        &mut receipt,
        &mut body,
        "browser",
    )?;
    crate::flatpak_verify::state(&context.target, &body)?;
    let graphics_links = crate::flatpak_graphics::capture(&context.target, &body)?;
    if let Some(store) = store {
        store.recheck(&context.target)?;
    }
    tools.recheck(context)?;
    prepared.recheck(&media.media)?;
    if let Some(enzimos) = enzimos {
        enzimos.recheck(&media.media)?;
    }
    held.recheck(&context.target)?;
    crate::flatpak_graphics::recheck(&context.target, &graphics_links)?;
    for (link, row) in active_links {
        let (_, actual) = enzimos_policy::file_overlay::capture(
            &context.target,
            row["path"].as_str().unwrap(),
            0,
        )?;
        require(
            actual == row && value!(files::identity(&link.metadata()?)) == row["inode"],
            "original offline Flatpak active link changed",
        )?;
    }
    body["phase"] = value!("complete");
    record(context, &mut receipt, &body)?;
    Ok(body)
}
