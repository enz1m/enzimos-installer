// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, process, require};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};
const TARGET: &str = "/mnt/enzimos";

pub fn holders(proc: &Path) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut result = Vec::new();
    let Ok(mountinfo) = std::fs::read_to_string(proc.join("self/mountinfo")) else {
        return result;
    };
    let mounts = mountinfo
        .lines()
        .filter_map(|l| {
            let fields = l.split_whitespace().collect::<Vec<_>>();
            if fields.len() >= 5 && (fields[4] == TARGET || fields[4].starts_with("/mnt/enzimos/"))
            {
                Some(fields[0].to_owned())
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();
    let Ok(entries) = std::fs::read_dir(proc) else {
        return result;
    };
    let mut processes = entries
        .flatten()
        .filter_map(|p| {
            p.file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
                .map(|pid| (pid, p.path()))
        })
        .collect::<Vec<_>>();
    processes.sort_unstable_by_key(|p| p.0);
    for (pid, path) in processes {
        if Instant::now() >= deadline || result.len() >= 32 {
            break;
        }
        let Ok(fds) = std::fs::read_dir(path.join("fdinfo")) else {
            continue;
        };
        let mut found = false;
        for fd in fds.flatten() {
            if Instant::now() >= deadline {
                break;
            }
            if let Ok(text) = std::fs::read_to_string(fd.path())
                && text.lines().any(|l| {
                    l.strip_prefix("mnt_id:")
                        .is_some_and(|id| mounts.contains(id.trim()))
                })
            {
                found = true;
                break;
            }
        }
        if found && let Ok(name) = std::fs::read_to_string(path.join("comm")) {
            let name = name
                .trim()
                .chars()
                .take(64)
                .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
                .collect::<String>();
            result.push(json!({"pid":pid,"name":name}));
        }
    }
    result
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
pub fn finish() -> Result<()> {
    require(
        unsafe { libc::geteuid() } == 0
            && !std::fs::symlink_metadata(TARGET)?.file_type().is_symlink(),
        "fixed installer target and Root context required",
    )?;
    require(
        Path::new("/run/enzimos-live").exists(),
        "live installer context required",
    )?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut retries = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        require(
            !remaining.is_zero(),
            "target filesystems still busy; installation is not complete",
        )?;
        let result = process::run(
            "/usr/bin/umount",
            &["--recursive", "--", TARGET],
            &[],
            remaining.min(Duration::from_secs(5)),
            65536,
        )
        .map_err(|_| Error("target unmount outcome unknown".into()))?;
        if result.status.success() {
            println!("ENZIMOS_TARGET_UNMOUNT_PASS retries={retries}");
            return Ok(());
        }
        if retries == 0 {
            println!(
                "ENZIMOS_TARGET_UNMOUNT_WAIT holders={}",
                serde_json::to_string(&holders(Path::new("/proc")))?
            );
        }
        retries += 1;
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(1)),
        );
    }
}
