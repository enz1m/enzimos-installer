// SPDX-License-Identifier: MIT
//! Console prompts collect bounded data; the native coordinator owns execution.
use crate::{answer_source::Source, answer_transport, answers, install_coordinator};
use enzimos_platform::{Error, Result, require};
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::fd::AsRawFd,
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

struct Echo {
    fd: i32,
    original: libc::termios,
}
impl Echo {
    #[allow(unsafe_code, reason = "Linux syscall ABI (tcgetattr, tcsetattr).")]
    fn disable(file: &File) -> Result<Self> {
        let fd = file.as_raw_fd();
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::tcgetattr(fd, &mut original) } == 0,
            "console terminal required for secrets",
        )?;
        let mut hidden = original;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
        require(
            unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &hidden) } == 0,
            "console echo protection failed",
        )?;
        Ok(Self { fd, original })
    }
}
impl Drop for Echo {
    #[allow(unsafe_code, reason = "Linux syscall ABI (tcsetattr).")]
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original);
        }
    }
}
fn line(file: &mut File) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        let mut byte = [0];
        require(file.read(&mut byte)? == 1, "console input ended")?;
        if byte[0] == b'\n' {
            break;
        }
        require(bytes.len() < 8192 && byte[0] != 0, "console answer bound")?;
        bytes.push(byte[0]);
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| Error("console answer encoding".into()))?;
    require(
        !value.chars().any(char::is_control),
        "console answer control character",
    )?;
    Ok(Zeroizing::new(value.into()))
}
fn ask(file: &mut File, prompt: &str, default: &str, secret: bool) -> Result<Zeroizing<String>> {
    write!(
        file,
        "{prompt}{}: ",
        if default.is_empty() {
            String::new()
        } else {
            format!(" [{default}]")
        }
    )?;
    file.flush()?;
    let echo = if secret {
        Some(Echo::disable(file)?)
    } else {
        None
    };
    let value = line(file)?;
    drop(echo);
    if secret {
        writeln!(file)?;
    }
    Ok(if value.is_empty() {
        Zeroizing::new(default.into())
    } else {
        value
    })
}
fn secret(file: &mut File, prompt: &str) -> Result<Zeroizing<String>> {
    loop {
        let first = ask(file, prompt, "", true)?;
        let second = ask(file, "Repeat", "", true)?;
        if !first.is_empty() && first == second {
            return Ok(first);
        }
        writeln!(file, "Empty or not matching, try again.")?;
    }
}
fn encode(values: &answers::Values) -> Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(Vec::new());
    for (key, value) in values {
        body.extend_from_slice(key.as_bytes());
        body.push(b'=');
        body.extend_from_slice(value.as_bytes());
        body.push(b'\n');
    }
    let _ = answers::Answers::from_values(answers::parse(&body)?)?;
    Ok(body)
}
pub fn finish_fresh(source: &Source) -> Result<Value> {
    install_coordinator::prepare_fresh(source, true, false)
}
pub fn install(serial: bool) -> Result<Value> {
    Source::protect()?;
    // The serial frontend remains idle until explicitly selected, without taking
    // the operation lock away from the graphical caller.
    let mut tty = OpenOptions::new().read(true).write(true).open(if serial {
        "/dev/ttyS0"
    } else {
        "/dev/tty1"
    })?;
    if serial {
        writeln!(tty, "Press Enter to begin the enzimOS installation.")?;
        let _ = line(&mut tty)?;
    }
    let volume = Command::new("/usr/bin/blkid")
        .args(["-L", "ENZIMOS_ANSWERS"])
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    match volume.code() {
        Some(0) => return crate::answer_volume::install_fresh(),
        Some(2) => {}
        _ => return Err(Error("answer-volume discovery failed".into())),
    }
    writeln!(
        tty,
        "enzimOS installer — the confirmed disk will be erased."
    )?;
    let _ = Command::new("/usr/bin/lsblk")
        .args(["-dpo", "NAME,SIZE,MODEL,SERIAL"])
        .env_clear()
        .env("PATH", "/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(tty.try_clone()?))
        .stderr(Stdio::from(tty.try_clone()?))
        .status()?;
    let mut values = answers::Values::new();
    let disk = ask(&mut tty, "Disk to ERASE and install enzimOS on", "", false)?;
    let reviewed = crate::disk_guard::Disk::open(&disk)?;
    let disk_sequence = reviewed.sequence()?;
    let confirm = ask(
        &mut tty,
        "Type the disk path again to confirm erasing it",
        "",
        false,
    )?;
    require(disk == confirm, "installation disk not confirmed")?;
    values.insert("ENZIMOS_DISK".into(), disk);
    values.insert(
        "ENZIMOS_DISK_SEQUENCE".into(),
        Zeroizing::new(disk_sequence.to_string()),
    );
    values.insert("ENZIMOS_ERASE_CONFIRM".into(), Zeroizing::new("yes".into()));
    for (key, prompt, default) in [
        ("ENZIMOS_HOSTNAME", "Computer name", "enzimos"),
        ("ENZIMOS_USER", "Administrator user name", ""),
        ("ENZIMOS_FULLNAME", "Full name", ""),
    ] {
        values.insert(key.into(), ask(&mut tty, prompt, default, false)?);
    }
    values.insert(
        "ENZIMOS_PASSWORD".into(),
        secret(&mut tty, "Administrator password")?,
    );
    let encrypt = ask(&mut tty, "Encrypt the disk (yes/no)", "yes", false)?;
    require(
        matches!(encrypt.as_str(), "yes" | "no"),
        "encryption choice must be yes or no",
    )?;
    if encrypt.as_str() == "yes" {
        values.insert(
            "ENZIMOS_PASSPHRASE".into(),
            secret(&mut tty, "Disk encryption passphrase")?,
        );
    }
    values.insert("ENZIMOS_ENCRYPT".into(), encrypt);
    values.insert(
        "ENZIMOS_TIMEZONE".into(),
        ask(&mut tty, "Time zone", "UTC", false)?,
    );
    values.insert(
        "ENZIMOS_FINISH".into(),
        ask(&mut tty, "When finished (reboot/poweroff)", "reboot", false)?,
    );
    let body = encode(&values)?;
    let source = answer_transport::bytes(&body)?;
    finish_fresh(&source)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn console_serialization_refuses_injected_answer_lines_and_duplicates() {
        let mut values = answers::Values::new();
        values.insert(
            "ENZIMOS_DISK".into(),
            Zeroizing::new("/dev/vda\nENZIMOS_USER=intruder".into()),
        );
        values.insert("ENZIMOS_USER".into(), Zeroizing::new("admin".into()));
        assert!(encode(&values).is_err());
    }
}
