// SPDX-License-Identifier: MIT
//! First-boot Flatpak export cache generation.

pub(crate) const UNIT: &str = "enzimos-initial-flatpak-triggers.service";
pub(crate) const UNIT_PATH: &str = "etc/systemd/system/enzimos-initial-flatpak-triggers.service";

// The offline installer drops CAP_SYS_ADMIN before Flatpak runs. The installed
// system helper can run Flatpak's regular bubblewrap trigger sandbox.
pub(crate) const UNIT_TEXT: &str = "\
[Unit]
Description=Generate caches for preinstalled Flatpak apps
After=dbus.service
Before=display-manager.service
ConditionPathIsDirectory=/var/lib/flatpak/exports/share
ConditionPathExists=!/var/lib/enzimos-initial-flatpak-triggers/done

[Service]
Type=oneshot
StateDirectory=enzimos-initial-flatpak-triggers
ExecStart=/usr/bin/busctl --system --timeout=60 call org.freedesktop.Flatpak.SystemHelper /org/freedesktop/Flatpak/SystemHelper org.freedesktop.Flatpak.SystemHelper RunTriggers us 0 \"\"
# The Flatpak helper can return success after a trigger exits unsuccessfully.
ExecStartPost=/usr/bin/sh -ec 'cd /var/lib/flatpak/exports/share; (test ! -d applications || test -s applications/mimeinfo.cache) && (test ! -d icons/hicolor || test -s icons/hicolor/icon-theme.cache) && (test ! -d mime/packages || test -s mime/mime.cache)'
ExecStartPost=/usr/bin/touch /var/lib/enzimos-initial-flatpak-triggers/done

[Install]
WantedBy=multi-user.target
";
