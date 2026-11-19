// SPDX-License-Identifier: MIT
//! Exact dual-kernel initial loader material; no commands are interpolated into a shell.
use enzimos_platform::{Result, require};
use std::collections::BTreeMap;
pub struct Plan {
    pub files: BTreeMap<String, Vec<u8>>,
    pub options: String,
}
pub fn prepare(options: &str, serial: bool) -> Result<Plan> {
    require(
        !options.is_empty()
            && options.len() <= 4096
            && options.bytes().all(|b| (32..127).contains(&b)),
        "initial boot options byte bound",
    )?;
    require(
        enzimos_policy::boot_options::subvolume_from_options(options)?
            == crate::system_config::ROOT,
        "initial boot options must bind the prepared root subvolume",
    )?;
    require(
        options
            .split_whitespace()
            .filter(|s| s.starts_with("root="))
            .count()
            == 1
            && !options.split_whitespace().any(|s| {
                [
                    "init=",
                    "rdinit=",
                    "enzimos.staged=",
                    "enzimos.recovery=",
                    "enzimos.generation=",
                ]
                .iter()
                .any(|p| s.starts_with(p))
            }),
        "initial boot options cannot select another execution or generation",
    )?;
    require(
        serial
            || !options
                .split_whitespace()
                .any(|s| s.starts_with("console=")),
        "serial diagnostics require explicit installer test choice",
    )?;
    let mut files = BTreeMap::new();
    files.insert(
        "loader/loader.conf".into(),
        b"default linux.conf\ntimeout menu-hidden\neditor no\n".to_vec(),
    );
    let mut bios="timeout: 1\nquiet: yes\ndefault_entry: 1\ninterface_branding: enzimOS\nterm_background: f0f3fa\nterm_foreground: 26334b\nterm_background_bright: 2a5df2\nterm_foreground_bright: ffffff\n".to_owned();
    if serial
        && options
            .split_whitespace()
            .any(|s| s.starts_with("console=ttyS"))
    {
        bios.push_str("serial: yes\n");
    }
    for flavor in ["linux", "linux-lts"] {
        files.insert(format!("loader/entries/{flavor}.conf"),format!("title enzimOS ({flavor})\nlinux /vmlinuz-{flavor}\ninitrd /initramfs-{flavor}.img\noptions {options}\n").into_bytes());
        bios.push_str(&format!("/enzimOS {flavor}\n    protocol: linux\n    path: boot():/vmlinuz-{flavor}\n    module_path: boot():/initramfs-{flavor}.img\n    cmdline: {options}\n"));
    }
    enzimos_policy::boot_entries::menu(&bios)?;
    files.insert("limine/limine.conf".into(), bios.into_bytes());
    Ok(Plan {
        files,
        options: options.into(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    const OPTIONS: &str =
        "root=UUID=11111111-1111-4111-8111-111111111111 rootflags=subvol=enzimos-root rw quiet";
    #[test]
    fn dual_kernel_plan_preserves_both_loaders_and_refuses_execution_overrides() {
        let plan = prepare(OPTIONS, false).unwrap();
        assert_eq!(plan.files.len(), 4);
        assert!(
            std::str::from_utf8(&plan.files["loader/loader.conf"])
                .unwrap()
                .contains("timeout menu-hidden\n")
        );
        let bios = std::str::from_utf8(&plan.files["limine/limine.conf"]).unwrap();
        assert_eq!(
            enzimos_policy::boot_entries::menu(bios)
                .unwrap()
                .entries
                .len(),
            2
        );
        assert!(bios.starts_with("timeout: 1\nquiet: yes\n"));
        for suffix in [
            " init=/bin/sh",
            " root=/other",
            " enzimos.generation=foreign",
            " enzimos.staged=foreign",
            " console=ttyS0",
        ] {
            assert!(prepare(&format!("{OPTIONS}{suffix}"), false).is_err());
        }
        let serial = prepare(&format!("{OPTIONS} console=ttyS0,115200"), true).unwrap();
        assert!(
            std::str::from_utf8(&serial.files["limine/limine.conf"])
                .unwrap()
                .contains("serial: yes\n")
        );
        assert!(prepare(&OPTIONS.replace("enzimos-root", "foreign"), false).is_err());
    }
}
