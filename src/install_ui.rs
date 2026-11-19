// SPDX-License-Identifier: MIT
//! The graphical caller owns restart; completion follows normal storage close.
use crate::{answer_source::Source, answer_transport, install_coordinator};
use enzimos_platform::{Result, require};
use serde_json::Value;
use std::io::{self, Write};

#[derive(Clone, Copy)]
pub enum Stage {
    Disk,
    Packages,
}
pub fn stage_line(stage: Stage) -> &'static str {
    match stage {
        Stage::Disk => "==> creating the enzimOS layout from the reviewed disk plan",
        Stage::Packages => "==> installing the offline package set",
    }
}
pub(crate) fn progress(stage: Stage) -> Result<()> {
    let mut output = io::stdout().lock();
    writeln!(output, "{}", stage_line(stage))?;
    output.flush()?;
    Ok(())
}
pub fn validate_completion(result: &Value) -> Result<()> {
    require(
        result["schema"] == 1
            && result["status"] == "bootable-base-prepared"
            && result["package_journal"]["phase"] == "complete"
            && result["package_journal"]["exit_code"] == 0
            && result["finish_requested"] == false
            && result["finish_receipt"].is_null(),
        "graphical installation has no completed, normally closed preparation",
    )
}
/// The line headless harnesses and the graphical frontend treat as success.
pub(crate) fn pass_line(source: &Source) -> Result<String> {
    let firmware = source.boot_security.receipt()?;
    Ok(format!(
        "ENZIMOS_INSTALL_PASS disk={} encrypted={} firmware={}",
        source.answers.disk,
        if source.answers.encrypted {
            "yes"
        } else {
            "no"
        },
        if firmware["firmware"]["uefi"] == true {
            "uefi"
        } else {
            "bios"
        },
    ))
}
pub fn completion_state(result: &Value, answers_retired: bool) -> Result<Value> {
    validate_completion(result)?;
    Ok(serde_json::json!({"schema":1,"installation_completed":true,
        "status":if answers_retired {"installed"} else {"installed-cleanup-incomplete"},
        "answers_retired":answers_retired,"reinstall_required":false}))
}

pub fn finalize_notice(
    result: &Value,
    pass: &str,
    mut retire: impl FnMut() -> Result<()>,
) -> Result<String> {
    validate_completion(result)?;
    let retired = retire().or_else(|_| retire()).is_ok();
    let state = completion_state(result, retired)?;
    Ok(if retired {
        pass.to_owned()
    } else {
        format!("ENZIMOS_INSTALL_CLEANUP_INCOMPLETE {state}")
    })
}

pub fn stdin() -> Result<()> {
    let source = answer_transport::stdin()?;
    let outcome = install_coordinator::prepare_graphical(&source).and_then(|result| {
        source.recheck()?;
        validate_completion(&result)?;
        let success = pass_line(&source)?;
        // Retrying retirement cannot replay installation. Both attempts retain
        // the exact answer inode/identity checks, including partial-wipe failure.
        let notice = finalize_notice(&result, &success, || source.retire())?;
        let mut output = io::stdout().lock();
        writeln!(output, "{notice}")?;
        output.flush()?;
        Ok(())
    });
    if outcome.is_err() && source.retire().or_else(|_| source.retire()).is_err() {
        eprintln!(
            "enzimos-installer: sensitive answer cleanup incomplete; shut down the live environment"
        );
    }
    outcome
}
