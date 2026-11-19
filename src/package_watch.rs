// SPDX-License-Identifier: MIT
//! Caller or private channel loss ends the owned supervisor; PID1 reaps its unit.
use crate::package_handoff::Received;
use enzimos_platform::{Error, Result, fd_packet::Packet, require};
use std::{
    fs::File,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
#[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
pub fn ended(files: &[BorrowedFd<'_>]) -> Result<bool> {
    require(
        !files.is_empty() && files.len() <= 2,
        "package lease descriptor count",
    )?;
    let mut polls = files
        .iter()
        .enumerate()
        .map(|(index, file)| libc::pollfd {
            fd: file.as_raw_fd(),
            events: if index == 0 {
                libc::POLLIN
            } else {
                libc::POLLRDHUP
            },
            revents: 0,
        })
        .collect::<Vec<_>>();
    let result = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as _, 100) };
    if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
        return Ok(false);
    }
    require(
        result >= 0
            && polls
                .iter()
                .all(|p| p.revents & (libc::POLLERR | libc::POLLNVAL) == 0),
        "package lease observation unavailable",
    )?;
    Ok(polls.iter().enumerate().any(|(index, p)| {
        p.revents & (libc::POLLHUP | libc::POLLRDHUP | if index == 0 { libc::POLLIN } else { 0 })
            != 0
    }))
}
pub struct Watch {
    done: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Watch {
    #[allow(unsafe_code, reason = "Linux syscall ABI (_exit, fcntl).")]
    pub fn start(context: &Received, channel: &Packet) -> Result<Self> {
        context.recheck()?;
        let caller = context.caller_pidfd.try_clone()?;
        let raw = unsafe { libc::fcntl(channel.as_fd().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
        require(raw >= 0, "package caller channel retention failed")?;
        let channel = unsafe { File::from_raw_fd(raw) };
        let done = Arc::new(AtomicBool::new(false));
        let stopping = done.clone();
        let thread = std::thread::Builder::new()
            .name("installer-caller-watch".into())
            .spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    let observed = ended(&[caller.as_fd(), channel.as_fd()]);
                    if stopping.load(Ordering::Acquire) {
                        return;
                    }
                    if !matches!(observed, Ok(false)) {
                        unsafe { libc::_exit(2) };
                    }
                }
            })
            .map_err(|_| Error("package caller watcher unavailable".into()))?;
        Ok(Self {
            done,
            thread: Some(thread),
        })
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
