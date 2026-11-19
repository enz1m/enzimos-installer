#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Live system: choose the installer front end. An answer volume (unattended) or
# enzimos.text on the kernel command line runs the text installer on tty1; otherwise the
# graphical installer runs on tty1 and the text dialogue stays available on a serial port.
set -uo pipefail
export PATH=/usr/bin
udevadm settle --timeout=30 || true
if [[ -n $(blkid -L ENZIMOS_ANSWERS 2>/dev/null) ]] || grep -qw enzimos.text /proc/cmdline; then
    exec systemctl --no-block start enzimos-installer.service
fi
systemctl --no-block start enzimos-installer-ui.service
stty -F /dev/ttyS0 >/dev/null 2>&1 && systemctl --no-block start enzimos-installer-serial.service
exit 0
