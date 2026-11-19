// SPDX-License-Identifier: MIT
//! Fresh-target desktop policy preserves vendor authorization and admin values.
use enzimos_platform::{Error, Result, require};
use std::collections::{BTreeMap, BTreeSet};
/// Use the same PAM policy as package upgrades, including expired-password changes.
pub fn pam(body: &str, service: &str) -> Result<String> {
    enzimos_policy::desktop_setup::pam(body, service)
}
fn bounded(body: &str) -> Result<()> {
    require(
        body.len() <= 128 * 1024 && !body.contains('\0'),
        "desktop configuration byte bound",
    )
}
pub fn environment(body: &str) -> Result<String> {
    bounded(body)?;
    let present = body
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let line = line
                .strip_prefix("export")
                .filter(|tail| tail.starts_with(char::is_whitespace))
                .unwrap_or(line)
                .trim_start();
            let (key, _) = line.split_once('=')?;
            let key = key.trim_end();
            (key.as_bytes()
                .first()
                .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
            .then_some(key)
        })
        .collect::<BTreeSet<_>>();
    let missing = [
        ("XMODIFIERS", "@im=fcitx"),
        ("QT_IM_MODULE", "fcitx"),
        ("SDL_IM_MODULE", "fcitx"),
    ]
    .into_iter()
    .filter(|(key, _)| !present.contains(key))
    .map(|(key, value)| format!("{key}={value}"))
    .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(body.into());
    }
    Ok(format!(
        "{}\n\n# enzimOS input method defaults (GTK uses native Wayland text input)\n{}\n",
        body.trim_end(),
        missing.join("\n")
    ))
}
pub const CONNECTIVITY: &str = "# SPDX-License-Identifier: MIT\n# Existing Arch connectivity endpoint; no identifiers or credentials are sent.\n# HTTP is intentional: a captive network must be detectable without TLS bypass.\n# The desktop offers explicit browser sign-in and the NM privacy toggle.\n[connectivity]\nenabled=true\nuri=http://ping.archlinux.org/nm-check.txt\nresponse=NetworkManager is online\ninterval=300\ntimeout=5\n";
pub fn cups(body: &str) -> Result<String> {
    bounded(body)?;
    let policy = [
        (
            "Listen",
            vec!["127.0.0.1:631", "[::1]:631", "/run/cups/cups.sock"],
        ),
        ("Browsing", vec!["No"]),
        ("WebInterface", vec!["No"]),
        ("DefaultShared", vec!["No"]),
        ("PreserveJobFiles", vec!["No"]),
        ("PreserveJobHistory", vec!["86400"]),
        ("MaxLogSize", vec!["1048576"]),
        ("MaxJobs", vec!["100"]),
        ("MaxJobsPerUser", vec!["20"]),
    ];
    let mut sections = Vec::<String>::new();
    let mut lines = Vec::new();
    let mut authorized = false;
    let mut default = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(tail) = trimmed.strip_prefix("</") {
            require(tail.ends_with('>'), "malformed CUPS closing section")?;
            let kind = &tail[..tail.len() - 1];
            require(
                sections
                    .pop()
                    .as_deref()
                    .and_then(|tag| tag.split_whitespace().next())
                    == Some(kind),
                "mismatched CUPS section",
            )?;
        }
        let words = trimmed.split_whitespace().collect::<Vec<_>>();
        if sections.is_empty() && !trimmed.is_empty() && !trimmed.starts_with(['#', '<']) {
            let key = words[0];
            require(
                !key.eq_ignore_ascii_case("include") && !key.eq_ignore_ascii_case("port"),
                "unexpected CUPS include or listener",
            )?;
            if policy
                .iter()
                .any(|(name, _)| key.eq_ignore_ascii_case(name))
            {
                continue;
            }
        }
        if words == ["Require", "user", "@SYSTEM"]
            && sections.iter().any(|tag| tag == "Policy default")
        {
            authorized = true;
        }
        if trimmed == "<Policy default>" {
            default = true;
        }
        lines.push(line);
        if trimmed.starts_with('<') && !trimmed.starts_with("</") {
            require(
                trimmed.ends_with('>') && sections.len() < 32,
                "CUPS section bound",
            )?;
            require(
                !trimmed[1..trimmed.len() - 1].trim().is_empty(),
                "empty CUPS section",
            )?;
            sections.push(trimmed[1..trimmed.len() - 1].into());
        }
    }
    require(
        sections.is_empty() && authorized && default,
        "vendor CUPS authorization policy missing or unbalanced",
    )?;
    let suffix = policy
        .into_iter()
        .flat_map(|(key, values)| {
            values
                .into_iter()
                .map(move |value| format!("{key} {value}\n"))
        })
        .collect::<String>();
    Ok(format!("{}\n{suffix}", lines.join("\n").trim_end()))
}
/// Strict vendor INI observation; overrides never duplicate a competing key.
pub fn ini(body: &str, overrides: &[(&str, &[(&str, &str)])]) -> Result<String> {
    bounded(body)?;
    let mut sections = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut section = None::<String>;
    for line in body.lines() {
        let mut trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            continue;
        }
        // Match ConfigParser's inline comments only after whitespace.
        if let Some(index) = trimmed.char_indices().find_map(|(i, c)| {
            (matches!(c, '#' | ';')
                && i > 0
                && trimmed[..i].chars().last().is_some_and(char::is_whitespace))
            .then_some(i)
        }) {
            trimmed = trimmed[..index].trim_end();
        }
        if trimmed.starts_with('[') {
            require(
                trimmed.ends_with(']') && trimmed.len() > 2,
                "invalid desktop INI section",
            )?;
            let name = &trimmed[1..trimmed.len() - 1];
            require(
                sections.len() < 128 && !sections.contains_key(name),
                "duplicate desktop INI section",
            )?;
            sections.insert(name.into(), BTreeMap::new());
            section = Some(name.into());
        } else {
            let (key, value) = trimmed
                .split_once('=')
                .or_else(|| trimmed.split_once(':'))
                .ok_or_else(|| Error("unsupported desktop INI row".into()))?;
            let key = key.trim().to_ascii_lowercase();
            require(!key.is_empty() && key.len() <= 128, "desktop INI key bound")?;
            let rows = sections
                .get_mut(
                    section
                        .as_deref()
                        .ok_or_else(|| Error("INI key outside section".into()))?,
                )
                .unwrap();
            require(
                rows.len() < 1024 && rows.insert(key, value.trim().into()).is_none(),
                "duplicate desktop INI key",
            )?;
        }
    }
    for (section, rows) in overrides {
        let output = sections.entry((*section).into()).or_default();
        for (key, value) in *rows {
            output.insert(key.to_ascii_lowercase(), (*value).into());
        }
    }
    Ok(sections
        .into_iter()
        .map(|(section, rows)| {
            format!(
                "[{section}]\n{}\n",
                rows.into_iter()
                    .map(|(key, value)| format!("{key}={value}\n"))
                    .collect::<String>()
            )
        })
        .collect())
}
pub fn ipp_usb(body: &str) -> Result<String> {
    ini(
        body,
        &[
            (
                "network",
                &[
                    ("interface", "loopback"),
                    ("dns-sd", "enable"),
                    ("ipv6", "enable"),
                ],
            ),
            (
                "auth uid",
                &[
                    ("print", "cups, @lp, root"),
                    ("config", "@wheel"),
                    ("scan", "root"),
                    ("fax", "root"),
                    ("all", "root"),
                ],
            ),
            (
                "logging",
                &[
                    ("device-log", "error"),
                    ("main-log", "error"),
                    ("console-log", "error"),
                    ("max-file-size", "256K"),
                    ("max-backup-files", "2"),
                    ("console-color", "disable"),
                ],
            ),
        ],
    )
}
pub fn avahi(body: &str) -> Result<String> {
    ini(
        body,
        &[
            ("wide-area", &[("enable-wide-area", "no")]),
            (
                "publish",
                &[
                    ("publish-workstation", "no"),
                    ("publish-hinfo", "no"),
                    ("publish-domain", "no"),
                ],
            ),
            ("reflector", &[("enable-reflector", "no")]),
        ],
    )
}
