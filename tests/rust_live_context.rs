// SPDX-License-Identifier: MIT
use enzimos_installer::live_context;
use enzimos_platform::mountinfo;
const CMD: &str = "quiet rd.systemd.wants=enzimos-live-root.service systemd.firstboot=no";
fn rows() -> Vec<mountinfo::Row> {
    mountinfo::parse("1 0 0:1 / / rw - overlay enzimos-live rw\n2 1 7:0 / /run/enzimos-live/lower ro - squashfs /dev/loop0 ro\n3 1 0:3 / /run/enzimos-live/rw rw - tmpfs enzimos-live-rw rw\n4 1 11:0 / /run/enzimos-live/media ro,nodev,nosuid - iso9660 /dev/sr0 ro\n").unwrap()
}
#[test]
fn installer_live_role_requires_overlay_ram_squashfs_and_readonly_medium() {
    let rows = rows();
    assert!(live_context::validate(&rows, CMD).is_ok());
    for index in 0..rows.len() {
        let mut missing = rows.clone();
        missing.remove(index);
        assert!(live_context::validate(&missing, CMD).is_err());
        let mut replaced = rows.clone();
        replaced[index].filesystem = "btrfs".into();
        assert!(live_context::validate(&replaced, CMD).is_err());
        let mut shadowed = rows.clone();
        let mut extra = shadowed[index].clone();
        extra.id += 100;
        shadowed.push(extra);
        assert!(live_context::validate(&shadowed, CMD).is_err());
    }
    for options in [
        "rw,nodev,nosuid",
        "ro,nodev",
        "ro,nosuid",
        "ro,rw,nodev,nosuid",
    ] {
        let mut changed = rows.clone();
        changed[3].options = options.into();
        assert!(live_context::validate(&changed, CMD).is_err());
    }
}
#[test]
fn marker_or_rescue_role_cannot_admit_installer_operations() {
    let rows = rows();
    for cmd in [
        "",
        "quiet",
        "rd.systemd.wants=other.service",
        "rd.systemd.wants=enzimos-live-root.service enzimos.installer-rescue=1",
        "rd.systemd.wants=enzimos-live-root.service rd.systemd.wants=enzimos-live-root.service",
    ] {
        assert!(live_context::validate(&rows, cmd).is_err());
    }
    assert!(live_context::validate(&[], CMD).is_err());
}
