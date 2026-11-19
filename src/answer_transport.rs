// SPDX-License-Identifier: MIT
//! UI secrets enter through stdin and remain in a private boot-volatile inode.
use crate::{answer_source::Source, answers};
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    io::Read,
    os::fd::{AsFd, AsRawFd},
    path::Path,
};
use zeroize::Zeroizing;

pub fn stdin() -> Result<Source> {
    Source::protect()?;
    let mut input = Zeroizing::new(Vec::with_capacity(answers::MAX_FILE + 1));
    std::io::stdin()
        .take((answers::MAX_FILE + 1) as u64)
        .read_to_end(&mut input)?;
    bytes(&input)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
pub(crate) fn bytes(bytes: &[u8]) -> Result<Source> {
    Source::protect()?;
    let path = Path::new("/run/enzimos-install-native/answers");
    let directory = files::ensure_directory(path, 0o700, 0)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatfs(directory.as_raw_fd(), &mut stat) } == 0
            && stat.f_type == 0x01021994,
        "private answer transport requires live tmpfs",
    )?;
    let mount = mount_identity::id(directory.as_fd(), true)?;
    // Validate before publication; diagnostics contain key names, never values.
    let _ = answers::Answers::from_values(answers::parse(bytes)?)?;
    let name = format!("answers-{}", files::random_hex(16)?);
    let file = files::atomic_relative_retained(
        &directory,
        Path::new(&name),
        bytes,
        0o600,
        Some(0),
        false,
        answers::MAX_FILE,
    )?;
    require(
        mount_identity::id(file.as_fd(), true)? == mount,
        "answer transport left its retained tmpfs",
    )?;
    // No automatic retirement after an uncertain storage outcome. This private
    // inode is volatile at reboot and cannot be adopted by a fresh operation.
    Source::received(file, &path.join(name))
}
