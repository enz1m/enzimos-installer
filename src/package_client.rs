// SPDX-License-Identifier: MIT
//! The native caller retains all storage until the original worker subtree ends.
use crate::{
    media_packages::Admitted, package_handoff, package_job as job, package_record::Store,
    package_service, target_storage::Target,
};
use enzimos_platform::{
    Error, Result,
    fd_packet::{Credentials, Packet},
    files, json, memfile,
    packet_socket::Listener,
    require,
};
use enzimos_system_backend::{
    native_worker_contract::Definition, native_worker_manager, system_manager::Manager,
};
use serde_json::{Value, json as value};
use std::{
    os::fd::AsFd,
    time::{Duration, Instant},
};
pub fn notification(body: &Value, sender: &Credentials, id: &str, pid: u32) -> Result<()> {
    json::fields(body, "schema id kind journal_sha256")?;
    require(
        body["schema"] == package_service::CONTROL_SCHEMA
            && body["id"] == id
            && sender.pid == pid
            && sender.uid == 0
            && sender.gid == 0,
        "package notification sender or attempt differs",
    )?;
    match body["kind"].as_str() {
        Some("heartbeat") => require(
            body["journal_sha256"].is_null(),
            "package heartbeat cannot advance a receipt",
        ),
        Some("checkpoint") => enzimos_policy::identity::sha(
            body["journal_sha256"]
                .as_str()
                .ok_or_else(|| Error("package checkpoint digest missing".into()))?,
        )
        .map(|_| ()),
        _ => Err(Error("package notification kind refused".into())),
    }
}
pub async fn launch(target: &mut Target<'_>, media: &Admitted) -> Result<Value> {
    launch_for(target, media, job::ARCH).await
}
pub async fn launch_offline(target: &mut Target<'_>, media: &Admitted) -> Result<Value> {
    launch_for(target, media, job::OFFLINE).await
}
pub async fn launch_system(target: &mut Target<'_>, media: &Admitted) -> Result<Value> {
    launch_for(target, media, job::SYSTEM).await
}
pub async fn launch_bootable(target: &mut Target<'_>, media: &Admitted) -> Result<Value> {
    launch_for(target, media, job::BOOT).await
}
fn stage<T>(role: &'static str, result: Result<T>) -> Result<T> {
    result.map_err(|error| Error(format!("native package {role}: {error}")))
}
fn closure_observation(
    original: &Result<Value>,
    owner: &native_worker_manager::Owner,
) -> Result<bool> {
    owner.exited_and_empty().map_err(|error| {
        Error(format!(
            "{}; native package original worker cgroup closure: {error}",
            original.as_ref().err().unwrap()
        ))
    })
}
async fn launch_for(target: &mut Target<'_>, media: &Admitted, operation: &str) -> Result<Value> {
    target.recheck()?;
    media.recheck()?;
    let manager = Manager::new().await?;
    let id = files::random_hex(16)?;
    let definition = Definition::installer(&id)?;
    let request = target.package_request_for(media, &id, operation)?;
    let caller = package_handoff::actor(&request["caller"], job::CALLER)?;
    let sealed = memfile::sealed("enzimos-install-package", &json::canonical(&request)?)?;
    let mut store = Store::create(target, media, request.clone())?;
    let socket = package_service::socket(&id)?;
    files::ensure_directory(socket.parent().unwrap().parent().unwrap(), 0o700, 0)?;
    files::create_directory(socket.parent().unwrap(), 0o700, 0)?;
    let listener = Listener::bind(&socket, 0)?;
    // An unconfirmed start keeps the target lifetime fenced. No request files
    // have been sent, and the journal remains available for inspection.
    let owner = native_worker_manager::start_for(&manager, &definition).await?;
    // Forward the worker's live output (tools and phase markers) to this caller's
    // output, which the graphical installer shows. Best effort: the job never depends on it.
    let follower = std::process::Command::new("/usr/bin/journalctl")
        .args([
            "--follow",
            "--output=cat",
            "--lines=all",
            "--unit",
            definition.unit(),
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok();
    let _follower = Follower(follower);
    let mut channel: Option<Packet> = None;
    let outcome=async {
        channel=Some(listener.accept(Duration::from_secs(10))?);
        let channel=channel.as_ref().unwrap();
        let ready=channel.receive(4096,0,Duration::from_secs(5))?;
        let invocation=owner.state.invocation.iter().map(|b| format!("{b:02x}")).collect::<String>();
        require(ready.sender.pid==owner.state.pid && ready.sender.uid==0 && ready.sender.gid==0
            && json::decode(&ready.body,4096)?==value!({"schema":package_service::CONTROL_SCHEMA,"id":id,"kind":"ready","invocation":invocation}),"package ready packet is not the measured native PID1 worker")?;
        stage("ready target",target.recheck())?;stage("ready media",media.recheck())?;
        stage("ready caller",caller.recheck())?;stage("ready owner",owner.recheck())?;
        stage("durable handoff",store.handoff(&owner))?;
        let mut descriptors=vec![sealed.as_fd(),target.directory()?.as_fd(),store.directory().as_fd(),media.media.descriptor().as_fd(),target.operation_lock().as_fd(),caller.pidfd()];
        if job::configured(operation) {descriptors.push(target.source().descriptor().as_fd());}
        if operation==job::BOOT {
            descriptors.push(target.boot_disk()?);
            if let Some(directory)=target.source().boot_security.descriptor()? {descriptors.push(directory.as_fd());}
            if let Some(copy)=&target.source().test_copy {descriptors.push(copy.descriptor().as_fd());}
        }
        let mut frame=value!({"schema":request["schema"],"id":id,"request_sha256":json::fingerprint(&request)?,"original_fds":descriptors.iter().map(std::os::fd::AsRawFd::as_raw_fd).collect::<Vec<_>>()});
        if operation==job::BOOT {frame["owner_credentials"]=value!(!request["boot"]["security"]["owner"].is_null());}
        channel.send(&json::canonical(&frame)?,&descriptors,Duration::from_secs(1))?;
        let started=Instant::now();
        loop {
            require(started.elapsed()<Duration::from_secs(job::RUNTIME_SECONDS+20),"package caller deadline; unfinished receipt retained")?;
            stage("running manager",manager.recheck().await)?;
            let remaining=Duration::from_secs(job::RUNTIME_SECONDS+20).saturating_sub(started.elapsed());
            stage("running channel readiness",channel.wait_ready(&owner.process,remaining.min(package_service::CONTROL_WAIT),&mut || {
                stage("running target",target.recheck())?;stage("running media",media.recheck())?;
                stage("running caller",caller.recheck())
            }))?;
            let message=stage("running channel",channel.receive(4096,0,Duration::from_secs(5)))?;
            let body=json::decode(&message.body,4096)?;notification(&body,&message.sender,&id,owner.state.pid)?;
            if body["kind"]=="checkpoint" {
                let journal=stage("durable checkpoint read",store.current())?;
                require(json::fingerprint(&journal)?==body["journal_sha256"],"package notification differs from its durable checkpoint")?;
                store.accept(journal)?;
            }
            stage("control acknowledgement",channel.send(&json::canonical(&value!({"schema":package_service::CONTROL_SCHEMA,"id":id,"kind":"phase-ack","journal_sha256":json::fingerprint(&store.journal)?}))?,&[],Duration::from_secs(1)))?;
            if body["kind"]=="checkpoint" && store.journal["phase"]=="stopping" {break;}
        }
        store.complete(target,media,&manager,&owner).await
    }.await;
    if outcome.is_ok() {
        stage("successful worker closure", target.package_stopped(&owner))?;
        return outcome;
    }
    // The caller's error only says the job stopped answering; the cause is in the job's
    // own log. Show its end on this output so the installer screen and log carry it.
    if let Ok(tail) = std::process::Command::new("/usr/bin/journalctl")
        .args([
            "--output=cat",
            "--no-pager",
            "--lines=40",
            "--unit",
            definition.unit(),
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
    {
        eprintln!(
            "---- last lines of the package job ({}) ----",
            definition.unit()
        );
        for line in String::from_utf8_lossy(&tail.stdout).lines() {
            if !line.chars().any(|c| c.is_control() && c != '\t') {
                eprintln!("{line}");
            }
        }
        eprintln!("---- end of package job lines ----");
    }
    // Closing the exact channel also causes the independently measured native
    // supervisor to exit if the manager's unique provider has disappeared.
    drop(channel.take());
    let stopped = native_worker_manager::stop_for(&manager, &definition, &owner).await;
    if stopped.is_err() {
        let deadline = Instant::now() + Duration::from_secs(job::STOP_SECONDS + 10);
        while Instant::now() < deadline && !closure_observation(&outcome, &owner)? {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    if closure_observation(&outcome, &owner)?
        && let Err(closing) = target.package_stopped(&owner)
    {
        let original = outcome.err().unwrap();
        return Err(Error(format!(
            "{original}; native package failed-worker storage closure: {closing}"
        )));
    }
    outcome
}

/// Stops the journal follower when the package job ends, however it ends.
struct Follower(Option<std::process::Child>);
impl Drop for Follower {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            // Let the last lines through before stopping.
            std::thread::sleep(Duration::from_millis(500));
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
