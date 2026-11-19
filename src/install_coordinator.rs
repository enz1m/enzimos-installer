// SPDX-License-Identifier: MIT
//! Native storage-to-boot preparation with one original operation lifetime.
use crate::{
    answer_source::Source, answers::Partition, install_session::Session, media_packages::Admitted,
};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json as value};
use std::path::Path;

pub fn prepare_bootable(source: &Source) -> Result<Value> {
    run(source, false)
}
pub fn install_and_finish(source: &Source) -> Result<Value> {
    run(source, true)
}
fn run(source: &Source, finish: bool) -> Result<Value> {
    run_with_lock(source, finish, None, false)
}
pub(crate) fn prepare_with_lock(
    source: &Source,
    lock: enzimos_platform::files::Lock,
) -> Result<Value> {
    run_with_lock(source, false, Some(lock), false)
}
pub(crate) fn prepare_graphical(source: &Source) -> Result<Value> {
    prepare_fresh(source, false, true)
}
pub(crate) fn prepare_fresh(source: &Source, finish: bool, graphical: bool) -> Result<Value> {
    source.recheck()?;
    let lock = enzimos_platform::files::Lock::acquire(Path::new(crate::install_session::LOCK), 0)?;
    // Only fresh preparations are allowed. An existing or partial area intent
    // remains a refusal, rather than an exception followed by adoption/retry.
    enzimos_policy::installer_mount_area::create(&lock)?;
    source.recheck()?;
    enzimos_policy::installer_mount_area::create_storage(&lock)?;
    source.recheck()?;
    enzimos_policy::installer_mount_area::create_target(&lock)?;
    source.recheck()?;
    run_with_lock(source, finish, Some(lock), graphical)
}
pub(crate) fn finish_with_lock(
    source: &Source,
    lock: enzimos_platform::files::Lock,
) -> Result<Value> {
    run_with_lock(source, true, Some(lock), false)
}
fn run_with_lock(
    source: &Source,
    finish: bool,
    lock: Option<enzimos_platform::files::Lock>,
    graphical: bool,
) -> Result<Value> {
    source.recheck()?;
    // Boot preparation is explicit. Refuse missing/replaced private staging
    // before media admission, journals or any disk write; never adopt an intent.
    let storage_area = enzimos_policy::installer_mount_area::Area::observe_storage()?;
    let target_area = enzimos_policy::installer_mount_area::Area::observe_target()?;
    require(
        source.answers.partition != Partition::Alongside
            || source.boot_security.receipt()?["firmware"]["uefi"] == true,
        "alongside installation requires the original UEFI boot context",
    )?;
    // All signed offline inputs and staged owner credentials are admitted before
    // the first disk mutation, then retained through the last worker and teardown.
    let media = Admitted::open_checked(source.answers.gpu, source.answers.verify_media)?;
    let session = match lock {
        Some(lock) => Session::with_lock(source, lock)?,
        None => Session::open(source)?,
    };
    if let Some(copy) = &source.test_copy {
        copy.independent(session.disk().number)?;
    }
    require(
        !media
            .media
            .physical_leaves()
            .contains(&session.disk().number),
        "installation medium cannot be the target",
    )?;
    let (erase_path, boot) = crate::erase::receipt_path(session.disk())?;
    let name = format!(
        "coordinator-{}",
        erase_path.file_name().unwrap().to_str().unwrap()
    );
    let path = Path::new("/run/enzimos-install-native").join(name);
    let initial = crate::install_coordinator_record::initial(
        &boot,
        &session.disk().observation()?,
        &source.answers.review(),
        &source.binding()?,
        &media.media.manifest_sha256,
    )?;
    media.recheck()?;
    session.recheck(source)?;
    storage_area.recheck()?;
    target_area.recheck()?;
    let mut store = crate::install_coordinator_record::Store::create(&path, initial)?;
    if graphical {
        crate::install_ui::progress(crate::install_ui::Stage::Disk)?;
    }
    let partitioned = match source.answers.partition {
        Partition::Erase => crate::erase::apply_session(source, &media, &session),
        Partition::Alongside => crate::alongside::apply(source, &media, &session),
    }
    .map_err(|error| Error(format!("installer reviewed partition allocation: {error}")))?;
    media.recheck()?;
    session.recheck(source)?;
    storage_area.recheck()?;
    target_area.recheck()?;
    store.checkpoint("partitioned", &partitioned)?;
    let formatted = crate::format::apply_session(source, &session)
        .map_err(|error| Error(format!("installer fresh filesystem formatting: {error}")))?;
    media.recheck()?;
    session.recheck(source)?;
    storage_area.recheck()?;
    target_area.recheck()?;
    store.checkpoint("formatted", &formatted)?;
    let root = crate::root_prepare::prepare_session(source, &session)
        .map_err(|error| Error(format!("installer root filesystem preparation: {error}")))?;
    media.recheck()?;
    session.recheck(source)?;
    storage_area.recheck()?;
    target_area.recheck()?;
    store.checkpoint("root-ready", &root)?;
    let subvolumes =
        crate::subvolume_prepare::prepare_session(source, &session).map_err(|error| {
            Error(format!(
                "installer protected subvolume preparation: {error}"
            ))
        })?;
    media.recheck()?;
    session.recheck(source)?;
    storage_area.recheck()?;
    target_area.recheck()?;
    store.checkpoint("subvolumes-ready", &subvolumes)?;
    let mut finish_receipt = Value::Null;
    let package = crate::target_storage::with_session_complete(
        source,
        session,
        |target| {
            target.mount_environment()?;
            if graphical {
                crate::install_ui::progress(crate::install_ui::Stage::Packages)?;
            }
            let package = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(crate::package_client::launch_bootable(target, &media))?;
            target.recheck()?;
            storage_area.recheck()?;
            target_area.recheck_covered()?;
            media.recheck()?;
            Ok(package)
        },
        |package, storage| {
            // Completion runs while Target still retains the original lock, after
            // normal unmount, mapper retirement and final storage receipt readback.
            source.recheck()?;
            storage_area.recheck()?;
            target_area.recheck()?;
            media.recheck()?;
            store.checkpoint("bootable", package)?;
            store.checkpoint("storage-closed", package)?;
            if finish {
                // Unattended runs end in power-off; report success first, on
                // the console and the serial port, as the graphical path does.
                let line = crate::install_ui::pass_line(source)?;
                println!("{line}");
                if let Ok(mut serial) = std::fs::OpenOptions::new().write(true).open("/dev/ttyS0") {
                    let _ = std::io::Write::write_all(&mut serial, format!("{line}\n").as_bytes());
                }
                finish_receipt =
                    crate::install_finish::request(source, &media, &store, package, storage)?;
            }
            Ok(())
        },
    )?;
    storage_area.recheck()?;
    target_area.recheck()?;
    Ok(
        value!({"schema":1,"status":"bootable-base-prepared","package_journal":package,
        "desktop_pending":false,"flatpaks_pending":false,
        "desktop_configured":source.answers.desktop,
        "flatpak_status":if !source.answers.flatpaks {"not-requested"} else if media.manifest["flatpaks"].as_array().unwrap().is_empty() {"no-offline-media"} else {"provisioned"},
        "finish_requested":finish,"finish_receipt":finish_receipt,
        "installed_qualification":false,"installer_runtime":"rust"}),
    )
}
