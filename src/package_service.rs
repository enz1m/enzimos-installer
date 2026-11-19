// SPDX-License-Identifier: MIT
//! A measured initial-namespace PID1 worker owns the offline package process tree.
use crate::{
    media_packages::Admitted, package_body, package_handoff::Received, package_job as job,
    package_watch::Watch,
};
use enzimos_platform::{Error, Result, fd_packet::Packet, files, json, packet_socket, require};
use enzimos_system_backend::{
    native_worker_contract::Definition, native_worker_manager, system_manager::Manager,
};
use serde_json::{Value, json as value};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
// Version 2 permits one outstanding control message. Acknowledging heartbeats
// prevents slow physical-storage checks from building a queue ahead of the
// final checkpoint. Waiting retains the original caller and its ownership.
pub const CONTROL_SCHEMA: u32 = 2;
pub const CONTROL_WAIT: Duration = Duration::from_secs(120);
pub fn socket(id: &str) -> Result<PathBuf> {
    job::id(id)?;
    Ok(Path::new("/run/enzimos-install-native/package-jobs")
        .join(id)
        .join("worker.sock"))
}
fn notify(channel: &Packet, id: &str, kind: &str, journal: Option<&Value>) -> Result<()> {
    let message = value!({"schema":CONTROL_SCHEMA,"id":id,"kind":kind,"journal_sha256":journal.map(json::fingerprint).transpose()?});
    channel.send(&json::canonical(&message)?, &[], Duration::from_secs(1))
}
fn acknowledged(channel: &Packet, context: &Received, id: &str, started: Instant) -> Result<()> {
    let remaining =
        Duration::from_secs(job::RUNTIME_SECONDS - 60).saturating_sub(started.elapsed());
    channel
        .wait_ready(&context.caller, remaining.min(CONTROL_WAIT), &mut || {
            context.supervised_recheck()
        })
        .map_err(|error| {
            Error(format!(
                "native package {} acknowledgement: {error}",
                context.store.journal["phase"]
            ))
        })?;
    let message = channel.receive(4096, 0, Duration::from_secs(1))?;
    context.recheck()?;
    require(
        message.sender.pid == context.caller.stat.pid
            && message.sender.uid == 0
            && message.sender.gid == 0
            && json::decode(&message.body, 4096)?
                == value!({"schema":CONTROL_SCHEMA,"id":id,"kind":"phase-ack","journal_sha256":json::fingerprint(&context.store.journal)?}),
        "package phase acknowledgement differs from the original native caller",
    )
}
fn supervision(
    context: &Received,
    media: Option<&Admitted>,
    channel: &Packet,
    id: &str,
    started: Instant,
) -> Result<()> {
    require(
        started.elapsed() < Duration::from_secs(job::RUNTIME_SECONDS - 60),
        "native package worker supervision deadline",
    )?;
    context.supervised_recheck()?;
    if let Some(media) = media {
        media
            .recheck()
            .map_err(|_| Error("native package worker original admitted media changed".into()))?;
    }
    notify(channel, id, "heartbeat", None)
        .map_err(|_| Error("native package worker original heartbeat channel failed".into()))?;
    acknowledged(channel, context, id, started)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (_exit).")]
fn abort_supervision(phase: &'static str, error: Error) -> ! {
    // Fixed component labels contain no source answers, credential bytes or
    // vendor output. Do not join a privileged child after its lease fails.
    eprintln!("native package {phase} boundary: {error}");
    unsafe { libc::_exit(2) }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (prctl).")]
pub async fn serve(id: &str) -> Result<()> {
    crate::setup::live()?;
    job::id(id)?;
    let manager = Manager::new().await?;
    let definition = Definition::installer(id)?;
    let state = native_worker_manager::snapshot_for(&manager, &definition)
        .await?
        .ok_or_else(|| Error("installer worker unit absent".into()))?;
    require(
        state.pid == std::process::id() && matches!(state.active.as_str(), "active" | "activating"),
        "installer worker is not this PID1 service's MainPID",
    )?;
    require(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "installer worker process protection unavailable",
    )?;
    let invocation = state
        .invocation
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let channel = packet_socket::connect(&socket(id)?, 0, Duration::from_secs(10))?;
    channel.send(
        &json::canonical(
            &value!({"schema":CONTROL_SCHEMA,"id":id,"kind":"ready","invocation":invocation}),
        )?,
        &[],
        Duration::from_secs(1),
    )?;
    let mut context = Received::inspect(
        channel.receive_counts(
            4096,
            &[
                crate::package_handoff::FILES,
                crate::package_handoff::SYSTEM_FILES,
                crate::package_handoff::BOOT_FILES,
                crate::package_handoff::OWNER_BOOT_FILES,
                crate::package_handoff::OWNER_TEST_BOOT_FILES,
            ],
            Duration::from_secs(30),
        )?,
        id,
        &invocation,
    )?;
    let _watch = Watch::start(&context, &channel)?;
    let started = Instant::now();
    let selected = context.request["selected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let verified = std::thread::scope(|scope| -> Result<Admitted> {
        let verification = scope.spawn(|| Admitted::from_selection(&selected));
        while !verification.is_finished() {
            if let Err(error) = supervision(&context, None, &channel, id, started) {
                // Scope joining cannot postpone a failed ownership boundary while
                // a privileged child continues. PID1 owns whole-group cleanup.
                abort_supervision("verification", error);
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        verification
            .join()
            .map_err(|_| Error("installer package verification thread failed".into()))?
    })?;
    require(
        verified.media.manifest_sha256 == context.request["media_manifest_sha256"],
        "worker independently admitted a different medium",
    )?;
    context.store.worker_checkpoint("running")?;
    notify(&channel, id, "checkpoint", Some(&context.store.journal))?;
    acknowledged(&channel, &context, id, started)?;
    let result = std::thread::scope(|scope| -> Result<Value> {
        let execution = scope.spawn(|| {
            // Phase markers: the graphical installer follows this journal and moves its stages.
            eprintln!("==> installing the system packages");
            let arch = package_body::install(&context, &verified)
                .map_err(|e| Error(format!("Arch package installation: {e}")))?;
            if context.request["operation"] != job::ARCH {
                let mut native = crate::native_package_body::install(&context, &verified, arch)
                    .map_err(|e| Error(format!("native package installation: {e}")))?;
                if context.request["operation"] == job::BOOT {
                    eprintln!("==> setting up the desktop");
                    native["desktop_overlay"] =
                        crate::desktop_overlay::install(&context, &verified)
                            .map_err(|e| Error(format!("desktop overlay publication: {e}")))?;
                }
                if context.request["operation"]
                    .as_str()
                    .is_some_and(job::configured)
                {
                    eprintln!("==> configuring the system and your account");
                    let configured =
                        crate::install_configuration::install(&context, &verified, native)
                            .map_err(|e| Error(format!("system configuration: {e}")))?;
                    if context.request["operation"] == job::BOOT {
                        let mut configured = configured;
                        if context.answers.as_ref().unwrap().answers.desktop {
                            configured["desktop"] =
                                crate::desktop_configuration::install(&context, &verified)?;
                        }
                        eprintln!("==> installing apps");
                        configured["flatpaks"] =
                            crate::flatpak_install::install(&context, &verified)?;
                        eprintln!("==> installing the boot loader and finishing up");
                        let result = crate::install_boot::install(&context, &verified, configured)
                            .map_err(|e| Error(format!("boot installation: {e}")))?;
                        crate::test_copy::install(&context)
                            .map_err(|e| Error(format!("first-boot test publication: {e}")))?;
                        crate::desktop_overlay_finalize::settle(&context, &verified, &result)
                            .map_err(|e| Error(format!("desktop overlay settlement: {e}")))?;
                        Ok(result)
                    } else {
                        Ok(configured)
                    }
                } else {
                    Ok(native)
                }
            } else {
                Ok(arch)
            }
        });
        // pacman buffers its own output when it is not on a terminal, but logs and flushes
        // every package and hook to its install log: follow that for live progress.
        let mut pacman_log = PacmanLog::new(&context.target);
        while !execution.is_finished() {
            if let Err(error) = supervision(&context, Some(&verified), &channel, id, started) {
                abort_supervision("execution", error);
            }
            pacman_log.poll();
            std::thread::sleep(Duration::from_secs(1));
        }
        pacman_log.poll();
        execution
            .join()
            .map_err(|_| Error("installer package execution thread failed".into()))?
    })?;
    require(result["exit_code"] == 0, "installer package body failed")?;
    context.store.worker_checkpoint("stopping")?;
    notify(&channel, id, "checkpoint", Some(&context.store.journal))?;
    acknowledged(&channel, &context, id, started)?;
    files::directory(Path::new("/mnt/enzimos"), Some(0))?.sync_all()?;
    Ok(())
}

/// Follows pacman's install log (`LogFile` in the job's pacman.conf) from where it was when
/// the job started. pacman may resolve it on the live system or under the target root.
struct PacmanLog {
    logs: Vec<(std::path::PathBuf, u64, Vec<u8>)>,
}
impl PacmanLog {
    fn new(target: &std::fs::File) -> Self {
        use std::os::fd::AsRawFd;
        let logs = [
            std::path::PathBuf::from("/var/log/pacman-install.log"),
            std::path::PathBuf::from(format!(
                "/proc/self/fd/{}/var/log/pacman-install.log",
                target.as_raw_fd()
            )),
        ]
        .into_iter()
        .map(|path| {
            let offset = std::fs::metadata(&path).map_or(0, |m| m.len());
            (path, offset, Vec::new())
        })
        .collect();
        Self { logs }
    }
    fn poll(&mut self) {
        use std::io::{Read, Seek, SeekFrom};
        for (path, offset, partial) in &mut self.logs {
            let Ok(mut file) = std::fs::File::open(&*path) else {
                continue;
            };
            let Ok(len) = file.metadata().map(|m| m.len()) else {
                continue;
            };
            if len < *offset {
                *offset = 0;
            }
            if len == *offset || file.seek(SeekFrom::Start(*offset)).is_err() {
                continue;
            }
            let mut chunk = Vec::new();
            if file
                .take((len - *offset).min(1 << 20))
                .read_to_end(&mut chunk)
                .is_err()
            {
                continue;
            }
            *offset += chunk.len() as u64;
            partial.extend_from_slice(&chunk);
            while let Some(end) = partial.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = partial.drain(..=end).collect();
                let line = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
                // "[time] [ALPM] installed foo (1.0-1)" -> "installed foo (1.0-1)"
                let text = line.splitn(3, "] ").nth(2).unwrap_or(&line);
                if !text.trim().is_empty() {
                    eprintln!("{text}");
                }
            }
        }
    }
}
