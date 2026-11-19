#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -uo pipefail
export PATH=/usr/bin LC_ALL=C
mode=install-console
[[ -n ${ENZIMOS_SERIAL_ONLY:-} ]] && mode=install-serial-console
# Capture errors and print them after the installer exits, on the screen and the
# serial console, so headless runs show why an installation stopped.
errors=$(mktemp)
/usr/lib/enzimos-installer/enzimos-installer-native "$mode" 2>"$errors"
status=$?
if [[ -s $errors ]]; then
    cat "$errors" >&2
    [[ -w /dev/ttyS0 ]] && cat "$errors" > /dev/ttyS0
fi
rm -f "$errors"
exit "$status"
