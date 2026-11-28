// SPDX-License-Identifier: MIT
//! A one-shot configuration body; intent is durable before files or accounts change.
use crate::{
    media_packages::Admitted, package_handoff::Received, package_job as job, system_config,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, fs::File, os::fd::AsRawFd, path::Path};
const RECEIPT: &str = "configuration.json";
const MAX: usize = 1024 * 1024;
fn read(root: &File, name: &str) -> Result<String> {
    String::from_utf8(files::read_file(
        &files::open_relative(root, Path::new(name))?,
        MAX,
        Some(0),
        true,
    )?)
    .map_err(|_| Error("installed configuration encoding".into()))
}
fn material(context: &Received) -> Result<system_config::Material> {
    context.recheck()?;
    require(
        context.request["operation"]
            .as_str()
            .is_some_and(job::configured),
        "configuration requires versioned system role",
    )?;
    let source = context
        .answers
        .as_ref()
        .ok_or_else(|| Error("configuration original answers absent".into()))?;
    material_for(&context.target, source, &context.request["configuration"])
}
fn material_for(
    root: &File,
    source: &crate::answer_source::Source,
    c: &Value,
) -> Result<system_config::Material> {
    source.recheck()?;
    let cmdline = String::from_utf8(files::read_kernel(Path::new("/proc/cmdline"), 65536)?)
        .map_err(|_| Error("kernel command-line encoding".into()))?;
    let mut result = system_config::render(
        &source.answers,
        c["filesystem_uuid"].as_str().unwrap(),
        c["esp_uuid"].as_str().unwrap(),
        c["luks_uuid"].as_str(),
        &cmdline,
    )?;
    crate::install_power_profile::add(&mut result.files);
    if source.answers.flatpaks {
        result.files.insert(
            crate::install_flatpak_triggers::UNIT_PATH.into(),
            crate::install_flatpak_triggers::UNIT_TEXT.into(),
        );
    }
    result.files.insert(
        "etc/locale.gen".into(),
        system_config::locale_gen(&read(root, "etc/locale.gen")?, &source.answers.locale)?
            .into_bytes(),
    );
    result.files.insert(
        "etc/mkinitcpio.conf".into(),
        system_config::mkinitcpio(&read(root, "etc/mkinitcpio.conf")?, &result.hooks)?.into_bytes(),
    );
    if result
        .hooks
        .split_whitespace()
        .any(|hook| hook == "sd-encrypt")
    {
        result.files.insert(
            format!(
                "etc/initcpio/install/{}",
                system_config::SURFACE_KEYBOARD_HOOK
            ),
            system_config::SURFACE_KEYBOARD_INSTALL.as_bytes().to_vec(),
        );
    }
    let mut pacman = system_config::multilib(&read(root, "etc/pacman.conf")?)?;
    let share = files::directory_relative(root, Path::new("usr/share/enzimos"), Some(0))?;
    if let Some(repositories) =
        files::optional_relative(&share, Path::new("pacman-repositories.conf"))?
    {
        files::read_file(&repositories, 65536, Some(0), true)?;
        pacman = system_config::archive_repos(&pacman)?;
    }
    result
        .files
        .insert("etc/pacman.conf".into(), pacman.into_bytes());
    result.files.insert(
        "etc/snap-pac.ini".into(),
        files::read_file(
            &files::open_relative(root, Path::new("usr/share/enzimos/snap-pac.ini"))?,
            65536,
            Some(0),
            true,
        )?,
    );
    // Resolve the selected zone below the retained target before publishing its link.
    let zones = files::directory_relative(root, Path::new("usr/share/zoneinfo"), Some(0))?;
    files::read_file(
        &files::open_beneath(&zones, Path::new(&source.answers.timezone))?,
        MAX,
        Some(0),
        false,
    )?;
    // Arch's locale-gen ignores unknown locales and sd-vconsole silently skips a
    // missing keymap (the LUKS prompt then uses the wrong layout): refuse both
    // before anything is published instead.
    let supported = files::read_file(
        &files::open_relative(root, Path::new("usr/share/i18n/SUPPORTED"))?,
        1 << 20,
        Some(0),
        true,
    )?;
    require(
        supported_locale(&String::from_utf8_lossy(&supported), &source.answers.locale),
        "selected locale is not available on the target",
    )?;
    let keymaps = files::directory_relative(root, Path::new("usr/share/kbd/keymaps"), Some(0))?;
    require(
        keymap_present(&keymaps, &source.answers.keymap)?,
        "selected console keymap is not available on the target",
    )?;
    Ok(result)
}
fn supported_locale(supported: &str, locale: &str) -> bool {
    let wanted = format!("{locale} UTF-8");
    supported.lines().any(|line| line.trim() == wanted)
}
/// A `<keymap>.map[.gz]` anywhere below the keymap tree (bounded walk).
fn keymap_present(keymaps: &std::fs::File, keymap: &str) -> Result<bool> {
    use std::os::fd::AsRawFd;
    let names = [format!("{keymap}.map.gz"), format!("{keymap}.map")];
    let mut pending = vec![std::path::PathBuf::from(format!(
        "/proc/self/fd/{}",
        keymaps.as_raw_fd()
    ))];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            visited += 1;
            require(visited <= 20000, "keymap tree bound")?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && names.iter().any(|n| entry.file_name() == n.as_str()) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
fn hashes(material: &system_config::Material) -> Value {
    value!(
        material
            .files
            .iter()
            .map(|(name, bytes)| (name, json::sha256(bytes)))
            .collect::<BTreeMap<_, _>>()
    )
}
pub fn validate(body: &Value, request: &Value, owner: &Value) -> Result<()> {
    job::request(request)?;
    let attachment = body["schema"] == 4;
    let identities = body["schema"] == 3 || attachment;
    let expanded = body["schema"] == 2 || identities;
    json::fields(
        body,
        if identities {
            "schema id role phase request_sha256 owner configuration files links members root_options hooks steps storage sessions network boot_complete installed_qualified"
        } else if expanded {
            "schema id role phase request_sha256 owner configuration files links root_options hooks steps storage sessions network boot_complete installed_qualified"
        } else {
            "schema id role phase request_sha256 owner configuration files links root_options hooks steps boot_complete installed_qualified"
        },
    )?;
    require(
        matches!(body["schema"].as_u64(), Some(1..=4))
            && request["operation"].as_str().is_some_and(job::configured)
            && body["id"] == request["id"]
            && body["role"] == "fresh-system-configuration"
            && matches!(body["phase"].as_str(), Some("writing" | "complete"))
            && body["request_sha256"] == json::fingerprint(request)?
            && body["owner"] == *owner
            && body["configuration"] == request["configuration"]
            && body["boot_complete"] == false
            && body["installed_qualified"] == false,
        "configuration receipt differs from original system worker or claims boot qualification",
    )?;
    let entries = body["files"]
        .as_object()
        .ok_or_else(|| Error("configuration file hashes missing".into()))?;
    let mut names = vec![
        "etc/hostname",
        "etc/hosts",
        "etc/locale.conf",
        "etc/vconsole.conf",
        "etc/X11/xorg.conf.d/00-keyboard.conf",
        "etc/tmpfiles.d/portables.conf",
        "etc/tmpfiles.d/systemd-nspawn.conf",
        "etc/fstab",
        "etc/enzimos/storage.json",
        "etc/locale.gen",
        "etc/mkinitcpio.conf",
    ];
    if attachment {
        names.push("etc/tmpfiles.d/enzimos-backup-source.conf");
        for unit in [
            crate::install_power_profile::UNIT_PATH,
            crate::install_flatpak_triggers::UNIT_PATH,
        ] {
            if entries.contains_key(unit) {
                names.push(unit);
            }
        }
    }
    if expanded {
        names.extend(["etc/pacman.conf", "etc/snap-pac.ini"]);
    }
    if !request["configuration"]["luks_uuid"].is_null() {
        names.push("etc/crypttab");
        names.push("etc/initcpio/install/enzimos-surface-keyboard");
    }
    require(
        entries.len() == names.len() && names.iter().all(|n| entries.contains_key(*n)),
        "configuration material closed file registry",
    )?;
    for (name, hash) in entries {
        require(
            name.starts_with("etc/")
                && Path::new(name)
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
            "configuration receipt file path",
        )?;
        enzimos_policy::identity::sha(
            hash.as_str()
                .ok_or_else(|| Error("configuration file digest type".into()))?,
        )?;
    }
    json::fields(&body["links"], "etc/localtime etc/resolv.conf")?;
    if identities {
        crate::configuration_members::validate(body)?;
    }
    require(
        body["links"]["etc/resolv.conf"] == "/run/systemd/resolve/stub-resolv.conf"
            && body["links"]["etc/localtime"]
                .as_str()
                .is_some_and(|s| s.starts_with("/usr/share/zoneinfo/") && !s.contains("..")),
        "configuration link destination",
    )?;
    let steps = body["steps"]
        .as_array()
        .ok_or_else(|| Error("configuration steps missing".into()))?;
    let expected: &[&str] = if expanded {
        &[
            "material", "account", "locale", "services", "storage", "sessions", "network",
        ]
    } else {
        &["material", "account", "locale", "services"]
    };
    require(
        steps.len() <= expected.len()
            && steps.iter().zip(expected).all(|(a, b)| a == *b)
            && (body["phase"] != "complete" || steps.len() == expected.len()),
        "configuration receipt step order",
    )?;
    if expanded {
        for field in ["storage", "sessions", "network"] {
            let done = steps.iter().any(|v| v == field);
            require(
                done == !body[field].is_null(),
                "configuration receipt material must follow its completed step",
            )?;
            if done {
                match field {
                    "storage" => crate::install_config_storage::validate(&body[field])?,
                    "sessions" => crate::install_config_sessions::validate(&body[field])?,
                    "network" => crate::install_config_network::validate(&body[field])?,
                    _ => unreachable!(),
                }
            }
        }
    }
    require(
        body["root_options"]
            .as_str()
            .is_some_and(|s| s.len() <= 4096 && !s.chars().any(char::is_control))
            && body["hooks"]
                .as_str()
                .is_some_and(|s| s.len() <= 512 && !s.chars().any(char::is_control)),
        "configuration boot material bound",
    )
}
fn record(context: &Received, body: &Value, replace: bool) -> Result<()> {
    context.recheck()?;
    validate(body, &context.request, &context.store.journal["owner"])?;
    files::atomic_relative(
        context.store.directory(),
        Path::new(RECEIPT),
        &json::canonical(body)?,
        0o600,
        Some(0),
        replace,
        MAX,
    )?;
    require(
        json::decode(
            &files::read_file(
                &files::open_relative(context.store.directory(), Path::new(RECEIPT))?,
                MAX,
                Some(0),
                true,
            )?,
            MAX,
        )? == *body,
        "configuration receipt readback differs",
    )?;
    context.recheck()
}
pub fn install(context: &Received, media: &Admitted, packages: Value) -> Result<Value> {
    context.recheck()?;
    media.recheck()?;
    crate::install_config_identity::verify(context, media)?;
    require(
        packages["exit_code"] == 0 && packages["operation"] == context.request["operation"],
        "configuration follows this system attempt's package success",
    )?;
    let material = material(context)?;
    let mut receipt = value!({"schema":4,"id":context.request["id"],"role":"fresh-system-configuration","phase":"writing",
        "request_sha256":json::fingerprint(&context.request)?,"owner":context.store.journal["owner"],"configuration":context.request["configuration"],
        "files":hashes(&material),"links":material.links,"members":{},"root_options":material.root_options,"hooks":material.hooks,"steps":[],"storage":null,"sessions":null,"network":null,"boot_complete":false,"installed_qualified":false});
    // Exclusivity is the replay barrier: even a failed earlier intent is not resumed.
    record(context, &receipt, false)?;
    let mut publications = crate::configuration_members::Publications::new(&context.target)?;
    for (name, bytes) in &material.files {
        context.recheck()?;
        publications.recheck(&context.target)?;
        let path = Path::new(name);
        let parent =
            files::ensure_directory_relative(&context.target, path.parent().unwrap(), 0o755, 0)?;
        // Existing package files must be protected regular single-link inputs.
        if let Some(file) = files::optional_relative(&parent, Path::new(path.file_name().unwrap()))?
        {
            files::read_file(&file, MAX, Some(0), true)?;
        }
        files::atomic_relative(
            &parent,
            Path::new(path.file_name().unwrap()),
            bytes,
            0o644,
            Some(0),
            true,
            MAX,
        )?;
        require(
            files::read_file(
                &files::open_relative(&parent, Path::new(path.file_name().unwrap()))?,
                MAX,
                Some(0),
                true,
            )? == *bytes,
            "configuration material readback differs",
        )?;
        publications.add(&context.target, name, &mut receipt)?;
        context.recheck()?;
    }
    let etc = files::directory_relative(&context.target, Path::new("etc"), Some(0))?;
    for (name, destination) in &material.links {
        context.recheck()?;
        publications.recheck(&context.target)?;
        files::symlink_relative(
            &etc,
            Path::new(Path::new(name).file_name().unwrap()),
            destination,
            0,
        )?;
        publications.add(&context.target, name, &mut receipt)?;
    }
    for step in [
        "material", "account", "locale", "services", "storage", "sessions", "network",
    ] {
        publications.recheck(&context.target)?;
        match step {
            "account" => crate::install_config_tools::account(context, media)?,
            "locale" => {
                crate::install_config_tools::run(context, media, "/usr/bin/locale-gen", &[], &[])?;
            }
            "services" => {
                let mut enable = vec![
                    "--root",
                    "/",
                    "enable",
                    "bluetooth.service",
                    "power-profiles-daemon.service",
                    "fwupd-refresh.timer",
                ];
                if crate::install_power_profile::selected(&material.files) {
                    enable.push(crate::install_power_profile::UNIT);
                }
                if material
                    .files
                    .contains_key(crate::install_flatpak_triggers::UNIT_PATH)
                {
                    enable.push(crate::install_flatpak_triggers::UNIT);
                }
                crate::install_config_tools::run(
                    context,
                    media,
                    "/usr/bin/systemctl",
                    &enable,
                    &[],
                )?;
                crate::install_config_tools::run(
                    context,
                    media,
                    "/usr/bin/systemctl",
                    &[
                        "--root",
                        "/",
                        "mask",
                        "archlinux-keyring-wkd-sync.service",
                        "archlinux-keyring-wkd-sync.timer",
                    ],
                    &[],
                )?;
            }
            "storage" => {
                receipt["storage"] = crate::install_config_storage::create(context, media)?;
            }
            "sessions" => receipt["sessions"] = crate::install_config_sessions::create(context)?,
            "network" => {
                receipt["network"] = crate::install_config_network::create(context, media)?;
            }
            _ => {}
        }
        publications.recheck(&context.target)?;
        receipt["steps"].as_array_mut().unwrap().push(value!(step));
        record(context, &receipt, true)?;
    }
    verify(&context.target, &receipt)?;
    crate::install_config_storage::verify(
        &context.target,
        &receipt["storage"],
        &context.request["configuration"]["filesystem_uuid"],
    )?;
    crate::install_config_sessions::verify(
        &context.target,
        &receipt["sessions"],
        &context.answers.as_ref().unwrap().answers.username,
    )?;
    crate::install_config_network::verify(&context.target, &receipt["network"])?;
    receipt["phase"] = value!("complete");
    publications.recheck(&context.target)?;
    record(context, &receipt, true)?;
    Ok(
        value!({"schema":1,"operation":context.request["operation"],"packages":packages,"configuration":receipt,"exit_code":0,"boot_complete":false,"installed_qualified":false}),
    )
}
fn verify(target: &File, receipt: &Value) -> Result<()> {
    for (name, hash) in receipt["files"].as_object().unwrap() {
        let file = files::open_relative(target, Path::new(name))?;
        use std::os::unix::fs::MetadataExt;
        require(
            file.metadata()?.mode() & 0o7777 == 0o644
                && json::sha256(&files::read_file(&file, MAX, Some(0), true)?) == *hash,
            "installed configuration changed before completion",
        )?;
    }
    let etc = files::directory_relative(target, Path::new("etc"), Some(0))?;
    for (name, destination) in receipt["links"].as_object().unwrap() {
        let path = format!(
            "/proc/self/fd/{}/{}",
            etc.as_raw_fd(),
            Path::new(name).file_name().unwrap().to_str().unwrap()
        );
        require(
            std::fs::read_link(path)?.to_str() == destination.as_str(),
            "installed configuration symlink changed",
        )?;
    }
    Ok(())
}
pub fn completed(
    target: &crate::target_storage::Target<'_>,
    journal: &Value,
    directory: &File,
) -> Result<Value> {
    target.recheck()?;
    require(
        journal["phase"] == "stopping",
        "configuration completion requires stopped original worker",
    )?;
    let body = json::decode(
        &files::read_file(
            &files::open_relative(directory, Path::new(RECEIPT))?,
            MAX,
            Some(0),
            true,
        )?,
        MAX,
    )?;
    validate(&body, &journal["request"], &journal["owner"])?;
    require(
        body["phase"] == "complete" && body["schema"] == 4,
        "unfinished system configuration is not replayed",
    )?;
    let material = material_for(
        target.directory()?,
        target.source(),
        &journal["request"]["configuration"],
    )?;
    require(
        body["files"] == hashes(&material)
            && body["links"] == value!(material.links)
            && body["root_options"] == material.root_options
            && body["hooks"] == material.hooks,
        "configuration completion differs from independently rendered original answers",
    )?;
    verify(target.directory()?, &body)?;
    crate::configuration_members::verify(target.directory()?, &body)?;
    crate::install_config_tools::verify_account(
        target.directory()?,
        &target.source().answers.username,
    )?;
    crate::install_config_storage::verify(
        target.directory()?,
        &body["storage"],
        &journal["request"]["configuration"]["filesystem_uuid"],
    )?;
    crate::install_config_sessions::verify(
        target.directory()?,
        &body["sessions"],
        &target.source().answers.username,
    )?;
    crate::install_config_network::verify(target.directory()?, &body["network"])?;
    target.recheck()?;
    Ok(body)
}

#[cfg(test)]
mod availability_tests {
    #[test]
    fn locales_and_keymaps_must_exist_on_the_target() {
        assert!(super::supported_locale(
            "de_DE.UTF-8 UTF-8\nde_DE ISO-8859-1\n",
            "de_DE.UTF-8"
        ));
        assert!(!super::supported_locale(
            "de_DE ISO-8859-1\n",
            "de_DE.UTF-8"
        ));
        assert!(!super::supported_locale(
            "xx_YY.UTF-8 UTF-8x\n",
            "xx_YY.UTF-8"
        ));
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("i386/qwerty")).unwrap();
        std::fs::write(root.path().join("i386/qwerty/de.map.gz"), b"x").unwrap();
        let dir = std::fs::File::open(root.path()).unwrap();
        assert!(super::keymap_present(&dir, "de").unwrap());
        assert!(!super::keymap_present(&dir, "xx").unwrap());
    }
}
