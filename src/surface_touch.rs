// SPDX-License-Identifier: MIT
//! Select the offline IPTS cohort by the MEI client's firmware UUID.
use enzimos_platform::{Error, Result, files, require};
use std::path::Path;

pub(crate) const MODULE_PACKAGE: &str = "enzimos-ipts-dkms";
pub(crate) const REQUIRED_ARCH: [&str; 3] = ["dkms", "linux-headers", "linux-lts-headers"];
const IPTS_UUID: &str = "3e8d0870-271a-4208-8eb5-9acb9402ae04";

pub(crate) fn present() -> Result<bool> {
    let devices = match std::fs::read_dir("/sys/bus/mei/devices") {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    for (index, entry) in devices.enumerate() {
        require(index < 4096, "MEI device inventory bound")?;
        let path = std::fs::canonicalize(entry?.path())?;
        require(
            path.starts_with(Path::new("/sys/devices")),
            "MEI device escaped kernel device tree",
        )?;
        let bytes = files::read_kernel(&path.join("uuid"), 256)?;
        let uuid =
            std::str::from_utf8(&bytes).map_err(|_| Error("MEI device UUID encoding".into()))?;
        if is_ipts(uuid) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_ipts(uuid: &str) -> bool {
    uuid.trim_end().eq_ignore_ascii_case(IPTS_UUID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_matches_the_ipts_mei_client() {
        assert!(is_ipts("3E8D0870-271A-4208-8EB5-9ACB9402AE04\n"));
        assert!(!is_ipts("3e8d0870-271a-4208-8eb5-9acb9402ae05"));
        assert!(!is_ipts("wrong:3e8d0870-271a-4208-8eb5-9acb9402ae04"));
    }
}
