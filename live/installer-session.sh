#!/bin/sh
# SPDX-License-Identifier: MIT
# The installer kiosk: a Hyprland compositor that shows only the enzimOS Installer over the
# enzUI wallpaper and exits with it. ENZIMOS_INSTALLER_ARGS=--demo for the preview.
export XDG_SESSION_TYPE=wayland WINIT_UNIX_BACKEND=wayland
export ENZIMOS_INSTALLER_ARGS="${ENZIMOS_INSTALLER_ARGS:-}"
# Under systemd (the live medium) the compositor logs to the journal; otherwise to a file.
if [ -n "${INVOCATION_ID:-}" ]; then exec /usr/bin/Hyprland --config /usr/share/enzimos-installer-ui/hyprland.lua; fi
state="${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/enzimos-installer"
mkdir -p "$state"
exec /usr/bin/Hyprland --config /usr/share/enzimos-installer-ui/hyprland.lua > "$state/compositor.log" 2>&1
