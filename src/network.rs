// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, files, json, process, require};
use serde_json::{Value, json as value};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

fn nm(args: &[&str]) -> Result<String> {
    let mut all = vec!["--wait", "25", "--terse", "--escape", "yes"];
    all.extend_from_slice(args);
    process::output("/usr/bin/nmcli", &all, &[], Duration::from_secs(35), &[0])
        .map(|s| s.trim().to_owned())
        .map_err(|_| Error("Connection could not be completed. Check the password, signal or cable and try again.".into()))
}
pub fn rows(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .map(|line| {
            let (mut fields, mut field, mut escaped) = (Vec::new(), String::new(), false);
            for c in line.chars() {
                if escaped {
                    field.push(c);
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == ':' {
                    fields.push(std::mem::take(&mut field));
                } else {
                    field.push(c);
                }
            }
            fields.push(field);
            fields
        })
        .collect()
}
pub fn state() -> Result<Value> {
    let mut devices = Vec::new();
    for row in rows(&nm(&[
        "-f",
        "DEVICE,TYPE,STATE,CONNECTION",
        "device",
        "status",
    ])?) {
        if row.len() == 4 && matches!(row[1].as_str(), "ethernet" | "wifi") {
            devices
                .push(value!({"device":row[0],"kind":row[1],"state":row[2],"connection":row[3]}));
        }
    }
    let mut aps = Vec::new();
    if devices.iter().any(|d| d["kind"] == "wifi") {
        for row in rows(&nm(&[
            "-f",
            "IN-USE,SSID,BSSID,SIGNAL,SECURITY,DEVICE",
            "device",
            "wifi",
            "list",
            "--rescan",
            "auto",
        ])?) {
            if row.len() != 6 || row[1].is_empty() {
                continue;
            }
            if let Ok(signal) = row[3].parse::<u32>() {
                if signal > 100 {
                    continue;
                }
                aps.push(value!({"active":row[0]=="*","ssid":row[1],"bssid":row[2],"signal":signal,"security":row[4],"device":row[5],"supported":!row[4].contains("802.1X") && !row[4].contains("WEP")}));
            }
        }
    }
    aps.sort_by(|a, b| {
        b["active"]
            .as_bool()
            .cmp(&a["active"].as_bool())
            .then(b["signal"].as_u64().cmp(&a["signal"].as_u64()))
            .then(a["ssid"].as_str().cmp(&b["ssid"].as_str()))
    });
    let mut seen = BTreeSet::new();
    aps.retain(|a| {
        seen.insert((
            a["ssid"].as_str().unwrap().to_owned(),
            a["security"].as_str().unwrap().to_owned(),
            a["device"].as_str().unwrap().to_owned(),
        ))
    });
    aps.truncate(64);
    Ok(value!({"devices":devices,"wifi":aps,"radio":nm(&["radio","wifi"])? == "enabled"}))
}
fn key_string(value: &str) -> Result<String> {
    require(
        !value.chars().any(|c| (c as u32) < 32 || c == '\u{7f}'),
        "Invalid network text.",
    )?;
    Ok(value.replace('\\', "\\\\").replace(' ', "\\s"))
}
pub fn wifi_profile(ap: &Value, password: &str, identity: &str) -> Result<String> {
    require(
        ap["supported"] == true,
        "This network needs enterprise or legacy settings. Use a personal Wi-Fi network or Ethernet during setup.",
    )?;
    let security = ap["security"]
        .as_str()
        .ok_or_else(|| Error("Invalid network security.".into()))?;
    let secured = !matches!(security, "" | "--");
    require(
        secured || password.is_empty(),
        "This Wi-Fi network no longer requests a password. Refresh and choose it again.",
    )?;
    require(
        !secured
            || (8..=63).contains(&password.len())
            || (password.len() == 64 && password.bytes().all(|c| c.is_ascii_hexdigit())),
        "Enter a Wi-Fi password of 8–63 bytes, or a 64-digit hexadecimal key.",
    )?;
    let ssid = ap["ssid"]
        .as_str()
        .ok_or_else(|| Error("Invalid network name.".into()))?;
    require(
        !ssid.is_empty() && ssid.len() <= 32,
        "Invalid network name.",
    )?;
    // Escape semicolons so a numeric SSID is read as literal text.
    let ssid = key_string(&ssid.replace(';', r"\;"))?;
    let mut text = format!(
        "[connection]\nid=enzimOS Wi-Fi\nuuid={identity}\ntype=wifi\nautoconnect=true\n\n[wifi]\nmode=infrastructure\nssid={ssid}\n"
    );
    if secured {
        let key = if security.contains("WPA3") && !security.contains("WPA2") {
            "sae"
        } else {
            "wpa-psk"
        };
        text.push_str(&format!(
            "\n[wifi-security]\nkey-mgmt={key}\npsk={}\n",
            key_string(password)?
        ));
    }
    text.push_str("\n[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n");
    Ok(text)
}
fn uuid() -> Result<String> {
    let mut s = files::random_hex(16)?.into_bytes();
    s[12] = b'4';
    s[16] = b"89ab"[(s[16] % 4) as usize];
    let s = String::from_utf8(s).unwrap();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &s[..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..]
    ))
}
pub fn perform(request: &Value) -> Result<Value> {
    require(request.is_object(), "Invalid network request.")?;
    match request["action"].as_str() {
        Some("status") => {
            json::fields(request, "action")?;
            return state();
        }
        Some("radio") => {
            json::fields(request, "action on")?;
            let on = request["on"]
                .as_bool()
                .ok_or_else(|| Error("Invalid radio setting.".into()))?;
            nm(&["radio", "wifi", if on { "on" } else { "off" }])?;
            return state();
        }
        _ => {}
    }
    let current = state()?;
    let device = request["device"]
        .as_str()
        .ok_or_else(|| Error("Invalid network adapter.".into()))?;
    match request["action"].as_str() {
        Some("wired") => {
            json::fields(request, "action device")?;
            require(
                current["devices"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|d| d["device"] == device && d["kind"] == "ethernet"),
                "Wired adapter is no longer available.",
            )?;
            nm(&["device", "connect", device])?;
        }
        Some("wifi") => {
            // The UI may omit the name (older builds); with it, a network whose strongest
            // access point changed since the list was shown (dual-band, mesh) still matches.
            json::fields(
                request,
                if request.get("ssid").is_some() {
                    "action device bssid ssid password"
                } else {
                    "action device bssid password"
                },
            )?;
            let password = request["password"]
                .as_str()
                .ok_or_else(|| Error("Invalid Wi-Fi password.".into()))?;
            let ssid = request["ssid"].as_str().filter(|name| !name.is_empty());
            let aps = current["wifi"].as_array().unwrap();
            let matches_selection =
                |ap: &&Value| ap["device"] == device && ssid.is_none_or(|name| ap["ssid"] == name);
            let ap = aps
                .iter()
                .filter(matches_selection)
                .find(|a| a["bssid"] == request["bssid"])
                .or_else(|| {
                    ssid?;
                    let mut candidates = aps.iter().filter(matches_selection).filter(|ap| {
                        ap["supported"] == true
                            && (matches!(ap["security"].as_str(), Some("" | "--"))
                                == password.is_empty())
                    });
                    let first = candidates.next()?;
                    candidates.next().is_none().then_some(first)
                })
                .ok_or_else(|| {
                    Error(
                        "This network is no longer available. Refresh and choose it again.".into(),
                    )
                })?;
            let identity = uuid()?;
            let profile = wifi_profile(ap, password, &identity)?;
            let base = Path::new("/etc/NetworkManager/system-connections");
            files::ensure_directory(base, 0o700, 0)?;
            let path = base.join(format!("enzimos-{identity}.nmconnection"));
            files::atomic(&path, profile.as_bytes(), 0o600, Some(0), false)?;
            let bssid = ap["bssid"].as_str().unwrap();
            let result = nm(&["connection", "load", path.to_str().unwrap()]).and_then(|_| {
                nm(&[
                    "connection",
                    "up",
                    "uuid",
                    &identity,
                    "ifname",
                    device,
                    "ap",
                    bssid,
                ])
            });
            if result.is_err() {
                let _ = nm(&["connection", "delete", "uuid", &identity]);
                // The unique profile was created by this request; no other profile is removed.
                let _ = std::fs::remove_file(&path);
            }
            result?;
        }
        _ => return Err(Error("Unsupported network action.".into())),
    }
    state()
}

#[allow(unsafe_code, reason = "Linux syscall ABI (prctl, setrlimit).")]
pub fn export_connected(target: &Path) -> Result<()> {
    crate::setup::live()?;
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    require(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } == 0
            && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "private network export process protection unavailable",
    )?;
    require(
        target == Path::new("/mnt/enzimos"),
        "fixed installer target required",
    )?;
    let active = match nm(&["-g", "UUID", "connection", "show", "--active"]) {
        Ok(s) => s.lines().map(str::to_owned).collect::<BTreeSet<_>>(),
        Err(_) => {
            println!(
                "Network service unavailable; connection settings can be added after installation."
            );
            return Ok(());
        }
    };
    let dest = target.join("etc/NetworkManager/system-connections");
    files::ensure_directory(&dest, 0o700, 0)?;
    let mut copied = BTreeSet::new();
    for base in [
        "/run/NetworkManager/system-connections",
        "/etc/NetworkManager/system-connections",
    ] {
        let Ok(entries) = std::fs::read_dir(base) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|s| s != "nmconnection") {
                continue;
            }
            let Ok(parent) = files::directory(path.parent().unwrap(), Some(0)) else {
                continue;
            };
            let Ok(file) = files::open_relative(&parent, Path::new(path.file_name().unwrap()))
            else {
                continue;
            };
            let Ok(body) = crate::private_file::read(&file, 65536, 0) else {
                continue;
            };
            let Ok(text) = std::str::from_utf8(&body) else {
                continue;
            };
            let (mut section, mut identity, mut kind) = ("", "", "");
            for line in text.lines() {
                let line = line.trim();
                if line.starts_with('[') && line.ends_with(']') {
                    section = &line[1..line.len() - 1];
                } else if section == "connection"
                    && let Some((k, v)) = line.split_once('=')
                {
                    match k.trim() {
                        "uuid" => identity = v.trim(),
                        "type" => kind = v.trim(),
                        _ => {}
                    }
                }
            }
            if !active.contains(identity)
                || copied.contains(identity)
                || !valid_uuid(identity)
                || !matches!(
                    kind,
                    "wifi" | "ethernet" | "802-11-wireless" | "802-3-ethernet"
                )
            {
                continue;
            }
            files::atomic(
                &dest.join(format!("enzimos-{identity}.nmconnection")),
                &body,
                0o600,
                Some(0),
                false,
            )?;
            copied.insert(identity.to_owned());
        }
    }
    Ok(())
}
fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}
