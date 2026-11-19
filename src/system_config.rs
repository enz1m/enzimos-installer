// SPDX-License-Identifier: MIT
//! Pure configuration material for a fresh, identity-bound installation target.
use crate::answers::Answers;
use enzimos_platform::{Result, require};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
pub const ROOT: &str = "enzimos-root";
const LSM: &str = "landlock,lockdown,yama,integrity,apparmor,bpf";
pub struct Material {
    pub files: BTreeMap<String, Vec<u8>>,
    pub links: BTreeMap<String, String>,
    pub root_options: String,
    pub hooks: String,
}
pub fn consoles(cmdline: &str, test: bool) -> Result<Vec<String>> {
    require(
        cmdline.len() <= 65536 && !cmdline.contains('\0'),
        "installer command-line bound",
    )?;
    if !test {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for word in cmdline
        .split_whitespace()
        .filter(|w| w.starts_with("console="))
    {
        let suffix = word.strip_prefix("console=").unwrap();
        require(
            !suffix.is_empty()
                && suffix.len() <= 96
                && result.len() < 8
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_,.-".contains(&b))
                && seen.insert(word),
            "installer test console refused",
        )?;
        result.push(word.into());
    }
    Ok(result)
}
pub fn locale_gen(input: &str, locale: &str) -> Result<String> {
    require(
        locale.strip_suffix(".UTF-8").is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 32
                && s.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_')
        }),
        "invalid locale generation choice",
    )?;
    require(
        input.len() <= 1024 * 1024 && !input.contains('\0'),
        "locale generation file bound",
    )?;
    let expected = format!("{locale} UTF-8");
    let mut output = String::new();
    let mut found = false;
    for line in input.lines() {
        let actual = line.strip_prefix('#').unwrap_or(line).trim();
        if actual == expected {
            require(!found, "duplicate selected locale")?;
            found = true;
            output.push_str(&expected);
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    if !found {
        output.push_str(&expected);
        output.push('\n');
    }
    Ok(output)
}
pub fn mkinitcpio(input: &str, hooks: &str) -> Result<String> {
    let allowed = "base systemd autodetect microcode modconf kms plymouth enzimos-recovery-mode keyboard sd-vconsole block sd-encrypt filesystems fsck";
    let mut names = BTreeSet::new();
    require(
        !hooks.is_empty()
            && hooks.len() <= 512
            && !hooks.chars().any(char::is_control)
            && hooks
                .split_whitespace()
                .all(|h| allowed.split_whitespace().any(|a| a == h) && names.insert(h)),
        "invalid native installer hooks",
    )?;
    require(
        input.len() <= 1024 * 1024 && !input.contains('\0'),
        "mkinitcpio configuration bound",
    )?;
    let mut output = String::new();
    let mut found = false;
    for line in input.lines() {
        if line.starts_with("HOOKS=") {
            require(!found, "duplicate mkinitcpio hook assignment")?;
            found = true;
            output.push_str(&format!("HOOKS=({hooks})"));
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    require(found, "mkinitcpio hooks assignment missing")?;
    Ok(output)
}
/// Enable only the official multilib section, refusing ambiguous duplicate blocks.
pub fn multilib(input: &str) -> Result<String> {
    require(
        input.len() <= 1024 * 1024 && !input.contains('\0'),
        "pacman configuration bound",
    )?;
    let mut output = String::new();
    let mut found = false;
    let mut include = false;
    let mut inside = false;
    for line in input.lines() {
        let trimmed = line.trim();
        let section = trimmed.starts_with('[') || trimmed.starts_with("#[");
        if section && inside {
            require(include, "multilib mirror include missing")?;
            inside = false;
        }
        if matches!(trimmed, "#[multilib]" | "[multilib]") {
            require(!found, "duplicate multilib section")?;
            found = true;
            inside = true;
            output.push_str("[multilib]\n");
            continue;
        }
        if inside
            && matches!(
                trimmed,
                "#Include = /etc/pacman.d/mirrorlist" | "Include = /etc/pacman.d/mirrorlist"
            )
        {
            require(!include, "duplicate multilib mirror include")?;
            include = true;
            output.push_str("Include = /etc/pacman.d/mirrorlist\n");
            continue;
        }
        if inside && !trimmed.is_empty() && !trimmed.starts_with('#') {
            return Err(enzimos_platform::Error(
                "unexpected multilib configuration assignment".into(),
            ));
        }
        output.push_str(line);
        output.push('\n');
    }
    require(
        found && include,
        "official multilib repository configuration missing",
    )?;
    Ok(output)
}
pub fn render(
    answers: &Answers,
    filesystem: &str,
    esp: &str,
    luks: Option<&str>,
    cmdline: &str,
) -> Result<Material> {
    enzimos_policy::identity::uuid(filesystem)?;
    enzimos_policy::recovery_records::fat_uuid(esp)?;
    require(
        answers.encrypted == luks.is_some(),
        "installed encryption identity differs from answers",
    )?;
    if let Some(id) = luks {
        enzimos_policy::identity::uuid(id)?;
    }
    let mut files = BTreeMap::new();
    let mut links = BTreeMap::new();
    let mut add = |name: &str, body: String| {
        files.insert(name.into(), body.into_bytes());
    };
    add("etc/hostname", format!("{}\n", answers.hostname));
    add(
        "etc/hosts",
        format!(
            "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 {}\n",
            answers.hostname
        ),
    );
    add("etc/locale.conf", format!("LANG={}\n", answers.locale));
    add("etc/vconsole.conf", format!("KEYMAP={}\n", answers.keymap));
    add(
        "etc/X11/xorg.conf.d/00-keyboard.conf",
        format!(
            "Section \"InputClass\"\n    Identifier \"system-keyboard\"\n    MatchIsKeyboard \"on\"\n    Option \"XkbLayout\" \"{}\"\nEndSection\n",
            answers.xkb_layout
        ),
    );
    add(
        "etc/tmpfiles.d/portables.conf",
        "d /var/lib/portables 0700 root root -\n".into(),
    );
    add(
        "etc/tmpfiles.d/enzimos-backup-source.conf",
        "d /backup-source 0700 root root -\n".into(),
    );
    add(
        "etc/tmpfiles.d/systemd-nspawn.conf",
        "d /var/lib/machines 0700 root root -\nR! /var/lib/machines/.#*\nR! /.#machine.*\n".into(),
    );
    let mut fstab = String::new();
    for (target, subvolume, options) in [
        ("/", ROOT, "compress=zstd:1,noatime"),
        ("/home", "enzimos-home", "compress=zstd:1,noatime"),
        ("/var/lib/enzimos-control", "enzimos-control", "noatime"),
        ("/etc/pacman.d/gnupg", "enzimos-authority", "noatime"),
        ("/swap", "enzimos-swap", "noatime"),
    ] {
        fstab.push_str(&format!(
            "UUID={filesystem} {target} btrfs subvol={subvolume},{options} 0 0\n"
        ));
    }
    fstab.push_str(&format!(
        "UUID={esp} /boot vfat fmask=0177,dmask=0077 0 2\n/swap/swapfile none swap defaults 0 0\n"
    ));
    add("etc/fstab", fstab);
    add(
        "etc/enzimos/storage.json",
        format!(
            "{}\n",
            serde_json::to_string(&json!({"filesystem_uuid":filesystem,"root_subvol":ROOT,
        "home_subvol":"enzimos-home","authority_subvol":"enzimos-authority","control_subvol":"enzimos-control",
        "legacy_boot_entries":{"uefi":["linux.conf","linux-lts.conf"],"bios":["enzimOS linux","enzimOS linux-lts"]}}))?
        ),
    );
    let root_args = if let Some(id) = luks {
        add(
            "etc/crypttab",
            format!("enzimos-crypt UUID={id} none luks,discard,x-initrd.attach\n"),
        );
        format!(
            "rd.luks.name={id}=enzimos-crypt rd.luks.options={id}=discard root=/dev/mapper/enzimos-crypt"
        )
    } else {
        format!("root=UUID={filesystem}")
    };
    links.insert(
        "etc/localtime".into(),
        format!("/usr/share/zoneinfo/{}", answers.timezone),
    );
    links.insert(
        "etc/resolv.conf".into(),
        "/run/systemd/resolve/stub-resolv.conf".into(),
    );
    let console = consoles(cmdline, answers.test_check)?.join(" ");
    let quiet = "zswap.enabled=0 quiet splash plymouth.ignore-serial-consoles loglevel=0 rd.systemd.show_status=false systemd.show_status=false rd.udev.log_level=0 udev.log_level=0 vt.global_cursor_default=0";
    let mut root_options = format!("{root_args} rootflags=subvol={ROOT} rw lsm={LSM}");
    if !console.is_empty() {
        root_options.push(' ');
        root_options.push_str(&console);
    }
    root_options.push(' ');
    root_options.push_str(quiet);
    let hooks = format!(
        "base systemd autodetect microcode modconf kms plymouth enzimos-recovery-mode keyboard sd-vconsole block {}filesystems fsck",
        if answers.encrypted { "sd-encrypt " } else { "" }
    );
    Ok(Material {
        files,
        links,
        root_options,
        hooks,
    })
}
pub fn recovery_service(release: &str, cmdline: &str, test: bool) -> Result<String> {
    enzimos_policy::identity::safe_id(release)?;
    require(release.len() <= 128, "recovery kernel release bound")?;
    let mut options = consoles(cmdline, test)?.join(" ");
    if !options.is_empty() {
        options.push(' ');
    }
    options.push_str(&format!("systemd.log_color=no panic=10 lsm={LSM}"));
    Ok(format!(
        "[Unit]\nDescription=enzimOS: build the independent recovery image (first boot)\nConditionPathExists=/var/lib/enzimos-control/recovery-image-pending\nConditionPathExists=!/var/lib/enzimos-control/recovery-image-attempted\nAfter=local-fs.target\n[Service]\nType=oneshot\nExecStart=/usr/lib/enzimos-native/enzimos-policy recovery-image first-boot --kernel {release} --options \"{options}\"\nTimeoutStartSec=30min\n[Install]\nWantedBy=multi-user.target\n"
    ))
}
pub fn swap_size(requested: Option<u32>, memory_kib: u64) -> Result<u32> {
    require(
        requested.is_none_or(|n| (256..=65536).contains(&n)),
        "invalid requested swap size",
    )?;
    require(
        memory_kib > 0 && memory_kib <= 1024 * 1024 * 1024 * 1024,
        "installed memory size bound",
    )?;
    Ok(requested.unwrap_or((memory_kib / 1024).clamp(1024, 8192) as u32))
}
