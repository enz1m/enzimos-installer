// SPDX-License-Identifier: MIT
//! Answer files are bounded data, never shell input. Secrets stay in zeroed memory.
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
pub const MAX_FILE: usize = 64 * 1024;
const KEYS: &str = "ENZIMOS_PARTITION_MODE ENZIMOS_PARTITION_PLAN ENZIMOS_FLATPAKS ENZIMOS_DESKTOP ENZIMOS_GPU_DRIVER ENZIMOS_DISK ENZIMOS_ERASE_CONFIRM ENZIMOS_HOSTNAME ENZIMOS_USER ENZIMOS_FULLNAME ENZIMOS_PASSWORD ENZIMOS_ENCRYPT ENZIMOS_PASSPHRASE ENZIMOS_TIMEZONE ENZIMOS_LOCALE ENZIMOS_KEYMAP ENZIMOS_FINISH ENZIMOS_TEST_CHECK ENZIMOS_SWAP_MIB ENZIMOS_XKB_LAYOUT ENZIMOS_VERIFY_MEDIA";
pub type Values = BTreeMap<String, Zeroizing<String>>;
pub fn parse(bytes: &[u8]) -> Result<Values> {
    require(
        bytes.len() <= MAX_FILE && !bytes.contains(&0),
        "installer answers byte bound",
    )?;
    let body =
        std::str::from_utf8(bytes).map_err(|_| Error("installer answers encoding".into()))?;
    let mut result = Values::new();
    for (index, line) in body.lines().enumerate() {
        require(index < 128, "installer answers line bound")?;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Error("installer answer must be KEY=VALUE".into()))?;
        require(
            KEYS.split_whitespace().any(|k| k == key) && !result.contains_key(key),
            "unknown or duplicate installer answer",
        )?;
        require(
            value.len() <= 8192 && !value.chars().any(char::is_control),
            "installer answer value bound",
        )?;
        result.insert(key.into(), Zeroizing::new(value.into()));
    }
    Ok(result)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Partition {
    Erase,
    Alongside,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    Reboot,
    Poweroff,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gpu {
    Auto,
    Nvidia,
    None,
}
pub struct Answers {
    pub disk: String,
    pub partition: Partition,
    pub partition_plan: Option<String>,
    pub hostname: String,
    pub username: String,
    pub fullname: String,
    pub password: Zeroizing<String>,
    pub encrypted: bool,
    pub passphrase: Option<Zeroizing<String>>,
    pub timezone: String,
    pub locale: String,
    pub keymap: String,
    pub xkb_layout: String,
    pub finish: Finish,
    pub test_check: bool,
    pub swap_mib: Option<u32>,
    pub desktop: bool,
    pub flatpaks: bool,
    pub gpu: Gpu,
    /// Check every file and signature on the medium before writing the disk (pacman
    /// still verifies each package's signature when it installs it).
    pub verify_media: bool,
}
fn take(values: &mut Values, key: &str, default: Option<&str>) -> Result<Zeroizing<String>> {
    values
        .remove(key)
        .or_else(|| default.map(|s| Zeroizing::new(s.into())))
        .ok_or_else(|| Error(format!("missing installer answer {key}")))
}
fn plain(values: &mut Values, key: &str, default: Option<&str>) -> Result<String> {
    Ok(take(values, key, default)?.to_string())
}
fn boolean(s: &str) -> Result<bool> {
    match s {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(Error("installer choice must be yes or no".into())),
    }
}
pub fn ordinary_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s != "root"
        && matches!(s.as_bytes()[0], b'a'..=b'z' | b'_')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}
pub fn disk_path(s: &str) -> Result<()> {
    require(
        s.len() <= 255
            && s.starts_with("/dev/")
            && s.len() > 5
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
            && s[1..]
                .split('/')
                .all(|part| !matches!(part, "" | "." | "..")),
        "invalid installation disk path",
    )
}
impl Answers {
    pub fn from_values(mut values: Values) -> Result<Self> {
        let disk = plain(&mut values, "ENZIMOS_DISK", None)?;
        disk_path(&disk)?;
        require(
            take(&mut values, "ENZIMOS_ERASE_CONFIRM", None)?.as_str() == "yes",
            "installation disk confirmation required",
        )?;
        let partition = match take(&mut values, "ENZIMOS_PARTITION_MODE", Some("erase"))?.as_str() {
            "erase" => Partition::Erase,
            "alongside" => Partition::Alongside,
            _ => return Err(Error("invalid installation partition mode".into())),
        };
        let plan = plain(&mut values, "ENZIMOS_PARTITION_PLAN", Some(""))?;
        if partition == Partition::Alongside {
            enzimos_policy::identity::sha(&plan)?;
        } else {
            require(
                plan.is_empty(),
                "erase installation cannot carry an alongside plan",
            )?;
        }
        let hostname = plain(&mut values, "ENZIMOS_HOSTNAME", Some("enzimos"))?;
        require(
            !hostname.is_empty()
                && hostname.len() <= 63
                && hostname.as_bytes()[0].is_ascii_alphanumeric()
                && hostname.as_bytes()[hostname.len() - 1].is_ascii_alphanumeric()
                && hostname
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid computer name",
        )?;
        let username = plain(&mut values, "ENZIMOS_USER", None)?;
        require(ordinary_name(&username), "invalid administrator user name")?;
        let fullname = plain(&mut values, "ENZIMOS_FULLNAME", Some(""))?;
        require(
            fullname.len() <= 256
                && !fullname.contains(':')
                && !fullname.chars().any(char::is_control),
            "invalid administrator full name",
        )?;
        let password = take(&mut values, "ENZIMOS_PASSWORD", None)?;
        require(
            !password.is_empty() && password.len() < 512,
            "administrator password size bound",
        )?;
        let encrypted = boolean(&take(&mut values, "ENZIMOS_ENCRYPT", Some("yes"))?)?;
        let secret = take(&mut values, "ENZIMOS_PASSPHRASE", Some(""))?;
        require(
            (encrypted && !secret.is_empty() && secret.len() <= 1000)
                || (!encrypted && secret.is_empty()),
            "disk encryption passphrase choice differs",
        )?;
        let timezone = plain(&mut values, "ENZIMOS_TIMEZONE", Some("UTC"))?;
        require(
            !timezone.is_empty()
                && timezone.len() <= 128
                && !timezone.contains("..")
                && !timezone.starts_with('/')
                && !timezone.ends_with('/')
                && !timezone.contains("//")
                && timezone
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_+/-".contains(&b)),
            "invalid time zone",
        )?;
        let locale = plain(&mut values, "ENZIMOS_LOCALE", Some("en_US.UTF-8"))?;
        require(
            locale.strip_suffix(".UTF-8").is_some_and(|s| {
                !s.is_empty()
                    && s.len() <= 32
                    && s.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_')
            }),
            "invalid locale",
        )?;
        let keymap = plain(&mut values, "ENZIMOS_KEYMAP", Some("us"))?;
        require(
            !keymap.is_empty()
                && keymap.len() <= 64
                && keymap
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid console keymap",
        )?;
        let xkb_layout = plain(&mut values, "ENZIMOS_XKB_LAYOUT", Some("us"))?;
        require(
            (2..=3).contains(&xkb_layout.len())
                && xkb_layout.bytes().all(|b| b.is_ascii_lowercase()),
            "invalid graphical keyboard layout",
        )?;
        let finish = match take(&mut values, "ENZIMOS_FINISH", Some("reboot"))?.as_str() {
            "reboot" => Finish::Reboot,
            "poweroff" => Finish::Poweroff,
            _ => return Err(Error("invalid installation finish action".into())),
        };
        let test = take(&mut values, "ENZIMOS_TEST_CHECK", Some("0"))?;
        require(
            matches!(test.as_str(), "0" | "1"),
            "invalid installation test choice",
        )?;
        let test_check = test.as_str() == "1";
        let swap = plain(&mut values, "ENZIMOS_SWAP_MIB", Some(""))?;
        let swap_mib = if swap.is_empty() {
            None
        } else {
            let size = swap
                .parse::<u32>()
                .map_err(|_| Error("invalid swap size".into()))?;
            require(
                (256..=65536).contains(&size) && size.to_string() == swap,
                "invalid swap size",
            )?;
            Some(size)
        };
        let desktop = match take(&mut values, "ENZIMOS_DESKTOP", Some("preview"))?.as_str() {
            "preview" => true,
            "none" => false,
            _ => return Err(Error("invalid desktop choice".into())),
        };
        let flatpaks = boolean(&take(&mut values, "ENZIMOS_FLATPAKS", Some("yes"))?)?;
        let gpu = match take(&mut values, "ENZIMOS_GPU_DRIVER", Some("auto"))?.as_str() {
            "auto" => Gpu::Auto,
            "nvidia" => Gpu::Nvidia,
            "none" => Gpu::None,
            _ => return Err(Error("invalid GPU choice".into())),
        };
        let verify_media = boolean(&take(&mut values, "ENZIMOS_VERIFY_MEDIA", Some("yes"))?)?;
        require(values.is_empty(), "unconsumed installer answers")?;
        Ok(Self {
            disk,
            partition,
            partition_plan: if plan.is_empty() { None } else { Some(plan) },
            hostname,
            username,
            fullname,
            password,
            encrypted,
            passphrase: if encrypted { Some(secret) } else { None },
            timezone,
            locale,
            keymap,
            xkb_layout,
            finish,
            test_check,
            swap_mib,
            desktop,
            flatpaks,
            gpu,
            verify_media,
        })
    }
    pub fn review(&self) -> Value {
        json!({"disk":self.disk,"partition_mode":if self.partition == Partition::Erase {"erase"}else{"alongside"},"partition_plan":self.partition_plan,
            "hostname":self.hostname,"username":self.username,"fullname":self.fullname,"encrypted":self.encrypted,
            "timezone":self.timezone,"locale":self.locale,"keymap":self.keymap,"xkb_layout":self.xkb_layout,
            "finish":if self.finish == Finish::Reboot {"reboot"}else{"poweroff"},"test_check":self.test_check,"swap_mib":self.swap_mib,
            "desktop":self.desktop,"flatpaks":self.flatpaks,"gpu":match self.gpu {Gpu::Auto=>"auto",Gpu::Nvidia=>"nvidia",Gpu::None=>"none"}})
    }
}
