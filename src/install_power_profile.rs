// SPDX-License-Identifier: MIT
//! The first-boot power mode of a computer without a battery.
//!
//! power-profiles-daemon keys its saved profile to the drivers it probes at run
//! time, so a fresh system asks the running daemon once instead of writing its
//! state file. A user's later choice is saved by the daemon and never replaced.
use std::collections::BTreeMap;
use std::path::Path;

/// The unit a battery-less fresh install enables.
pub(crate) const UNIT: &str = "enzimos-initial-power-profile.service";
const UNIT_PATH: &str = "etc/systemd/system/enzimos-initial-power-profile.service";
const POWER_SUPPLY: &str = "/sys/class/power_supply";
const UNIT_TEXT: &str = "\
[Unit]
Description=Use the performance power mode on a computer without a battery
After=power-profiles-daemon.service
Wants=power-profiles-daemon.service
ConditionPathExists=!/var/lib/enzimos-initial-power-profile/done

[Service]
Type=oneshot
StateDirectory=enzimos-initial-power-profile
# Hardware without a performance mode keeps the default; the choice is made once either way.
ExecStart=-/usr/bin/busctl --timeout=30 call org.freedesktop.UPower.PowerProfiles /org/freedesktop/UPower/PowerProfiles org.freedesktop.DBus.Properties Set ssv org.freedesktop.UPower.PowerProfiles ActiveProfile s performance
ExecStartPost=/usr/bin/touch /var/lib/enzimos-initial-power-profile/done

[Install]
WantedBy=multi-user.target
";

/// Adds the first-boot unit to `files` when the installing computer has no system battery.
pub(crate) fn add(files: &mut BTreeMap<String, Vec<u8>>) {
    if !system_battery(Path::new(POWER_SUPPLY)) {
        files.insert(UNIT_PATH.into(), UNIT_TEXT.into());
    }
}

/// Whether `files` carries the unit, which then needs enabling.
pub(crate) fn selected(files: &BTreeMap<String, Vec<u8>>) -> bool {
    files.contains_key(UNIT_PATH)
}

// Peripheral batteries (mice, keyboards, pens) report scope `Device`. An
// unreadable directory counts as a battery, so it keeps the default mode.
fn system_battery(power_supply: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(power_supply) else {
        return true;
    };
    entries.filter_map(Result::ok).take(256).any(|entry| {
        let attribute = |name: &str| {
            std::fs::read_to_string(entry.path().join(name))
                .map(|value| value.trim().to_owned())
                .ok()
        };
        attribute("type").as_deref() == Some("Battery")
            && attribute("scope").as_deref() != Some("Device")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supply(root: &Path, name: &str, kind: &str, scope: Option<&str>) {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("type"), format!("{kind}\n")).unwrap();
        if let Some(scope) = scope {
            std::fs::write(dir.join("scope"), format!("{scope}\n")).unwrap();
        }
    }

    #[test]
    fn only_a_system_battery_counts_as_a_battery() {
        let root = tempfile::tempdir().unwrap();
        assert!(system_battery(&root.path().join("absent")));
        assert!(!system_battery(root.path()));
        supply(root.path(), "AC", "Mains", None);
        supply(root.path(), "hidpp_battery_0", "Battery", Some("Device"));
        supply(root.path(), "ucsi-source-psy-USBC000:001", "USB", None);
        assert!(!system_battery(root.path()));
        supply(root.path(), "BAT0", "Battery", None);
        assert!(system_battery(root.path()));
        let scoped = tempfile::tempdir().unwrap();
        supply(scoped.path(), "BAT1", "Battery", Some("System"));
        assert!(system_battery(scoped.path()));
    }

    #[test]
    fn the_unit_is_selected_only_with_its_file() {
        let mut files = BTreeMap::new();
        assert!(!selected(&files));
        files.insert(UNIT_PATH.to_owned(), UNIT_TEXT.as_bytes().to_vec());
        assert!(selected(&files));
        assert!(UNIT_PATH.ends_with(UNIT));
    }
}
