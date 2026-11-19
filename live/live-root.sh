#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Initramfs: assemble the enzimOS live root at /sysroot. The install medium (label
# ENZIMOS_INSTALL) carries enzimos/live.sfs, a read-only squashfs; a RAM overlay makes it
# writable. The medium stays mounted at /run/enzimos-live/media (moved with /run).
set -euo pipefail
export PATH=/usr/bin
base=/run/enzimos-live
mkdir -p "$base/media" "$base/lower" "$base/rw"
for _ in $(seq 90); do media=$(blkid -L ENZIMOS_INSTALL 2>/dev/null || true); [[ -n $media ]] && break; sleep 1; udevadm settle --timeout=5 || true; done
[[ -n ${media:-} ]] || { echo 'enzimOS: install medium (label ENZIMOS_INSTALL) not found' >&2; exit 1; }
# Rock Ridge records retain the ISO creator's host UID. The medium is public,
# immutable input; normalize its view without trusting creator ownership/modes.
mount -t iso9660 -o ro,nodev,nosuid,noexec,uid=0,gid=0,mode=0444,dmode=0555,overriderockperm "$media" "$base/media"
mount -t squashfs -o ro,loop "$base/media/enzimos/live.sfs" "$base/lower"
mount -t tmpfs -o mode=0755,size=75% enzimos-live-rw "$base/rw"
mkdir -p "$base/rw/upper" "$base/rw/work"
mount -t overlay -o "lowerdir=$base/lower,upperdir=$base/rw/upper,workdir=$base/rw/work" enzimos-live /sysroot

# Maintenance inherited from the installed package set has no role in a RAM
# live root. In particular Snapper's ten-minute cleanup timer creates a private
# mount namespace containing an in-progress target. Keep those units masked
# only in this ephemeral overlay; installed target units are configured separately.
mkdir -p /sysroot/etc/systemd/system
for unit in \
    snapper-cleanup.service snapper-cleanup.timer \
    snapper-timeline.service snapper-timeline.timer \
    systemd-tmpfiles-clean.service systemd-tmpfiles-clean.timer \
    man-db.service man-db.timer \
    updatedb.service updatedb.timer \
    fstrim.service fstrim.timer \
    e2scrub_all.service e2scrub_all.timer \
    btrfs-scrub@.service btrfs-scrub@.timer \
    archlinux-keyring-wkd-sync.service archlinux-keyring-wkd-sync.timer \
    fwupd-refresh.service fwupd-refresh.timer; do
    ln -sfn /dev/null "/sysroot/etc/systemd/system/$unit"
done
