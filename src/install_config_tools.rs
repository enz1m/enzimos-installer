// SPDX-License-Identifier: MIT
//! Fixed target-native tools, always descendants of the measured installation worker.
use crate::{media_packages::Admitted, package_handoff::Received};
use enzimos_platform::{Error, Result, files, process, require};
use std::{os::fd::AsFd, path::Path, time::Duration};
use zeroize::Zeroizing;

pub(crate) fn run(
    context: &Received,
    media: &Admitted,
    program: &str,
    args: &[&str],
    input: &[u8],
) -> Result<()> {
    run_timeout(
        context,
        media,
        program,
        args,
        input,
        Duration::from_secs(120),
    )
}
pub(crate) fn run_timeout(
    context: &Received,
    media: &Admitted,
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
) -> Result<()> {
    run_descriptors(context, media, program, args, input, timeout, &[])
}
pub(crate) fn run_descriptors(
    context: &Received,
    media: &Admitted,
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    extra: &[std::os::fd::BorrowedFd<'_>],
) -> Result<()> {
    require(
        !timeout.is_zero() && timeout <= Duration::from_secs(900) && extra.len() <= 1,
        "installed configuration tool timeout or descriptor bound",
    )?;
    require(
        matches!(
            program,
            "/usr/bin/useradd"
                | "/usr/bin/chpasswd"
                | "/usr/bin/passwd"
                | "/usr/bin/locale-gen"
                | "/usr/bin/systemctl"
                | "/usr/bin/snapper"
                | "/usr/bin/btrfs"
                | "/usr/bin/groupadd"
                | "/usr/bin/mkinitcpio"
                | "/usr/bin/bootctl"
                | "/usr/bin/limine"
                | "/usr/bin/efibootmgr"
                | "/usr/lib/enzimos-native/enzimos-policy"
                | "/usr/bin/systemd-tmpfiles"
                | "/usr/bin/cupsd"
                | "/usr/bin/firewall-offline-cmd"
        ),
        "configuration tool outside fixed registry",
    )?;
    context.recheck()?;
    media.recheck()?;
    let mut arguments = vec!["@fd-dir:0", program];
    arguments.extend_from_slice(args);
    let mut descriptors = vec![context.target.as_fd()];
    descriptors.extend_from_slice(extra);
    let result = process::run_pinned(
        "/usr/bin/chroot",
        media.images.get("/usr/bin/chroot")?,
        &arguments,
        input,
        timeout,
        1024 * 1024,
        &descriptors,
    )?;
    context.recheck()?;
    media.recheck()?;
    // chpasswd output is deliberately not logged or returned to the caller.
    require(
        result.status.success(),
        "fixed installed-system configuration tool failed; attempt cannot be replayed",
    )
}
fn text(context: &Received, name: &str) -> Result<String> {
    let file = files::open_relative(&context.target, Path::new(name))?;
    String::from_utf8(files::read_file(&file, 1024 * 1024, Some(0), true)?)
        .map_err(|_| Error("installed account database encoding".into()))
}
pub(crate) fn account_absent(passwd: &str, group: &str, username: &str) -> Result<()> {
    require(
        crate::answers::ordinary_name(username),
        "invalid installation account",
    )?;
    for (database, columns) in [(passwd, 7), (group, 4)] {
        require(
            database.len() <= 1024 * 1024 && !database.contains('\0'),
            "installed account database bound",
        )?;
        let mut names = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        for line in database.lines() {
            let row = line.split(':').collect::<Vec<_>>();
            require(row.len() == columns, "installed account database row shape")?;
            let id = row[2]
                .parse::<u32>()
                .map_err(|_| Error("installed account ID type".into()))?;
            require(
                names.insert(row[0]) && ids.insert(id) && row[0] != username && id != 1000,
                "fresh account name, UID or GID already exists or database is ambiguous",
            )?;
        }
    }
    Ok(())
}
pub(crate) fn account(context: &Received, media: &Admitted) -> Result<()> {
    let answers = &context
        .answers
        .as_ref()
        .ok_or_else(|| Error("original answers required".into()))?
        .answers;
    account_absent(
        &text(context, "etc/passwd")?,
        &text(context, "etc/group")?,
        &answers.username,
    )?;
    run(
        context,
        media,
        "/usr/bin/groupadd",
        &["--gid", "1000", "--", &answers.username],
        &[],
    )?;
    run(
        context,
        media,
        "/usr/bin/useradd",
        &[
            "--create-home",
            "--gid",
            "1000",
            "--uid",
            "1000",
            "--groups",
            "wheel,gamemode",
            "--shell",
            "/bin/bash",
            "--comment",
            &answers.fullname,
            "--",
            &answers.username,
        ],
        &[],
    )?;
    // No secret enters argv, environment, receipts or ordinary String buffers.
    let input = Zeroizing::new(format!(
        "{}:{}\n",
        answers.username,
        answers.password.as_str()
    ));
    run(context, media, "/usr/bin/chpasswd", &[], input.as_bytes())?;
    run(context, media, "/usr/bin/passwd", &["--lock", "root"], &[])?;
    home_folders(context, &answers.username)?;
    account_present(
        &text(context, "etc/passwd")?,
        &text(context, "etc/group")?,
        &answers.username,
    )?;
    shadow_present(&context.target, &answers.username)
}
/// The everyday folders a new home starts with, and the XDG map apps use to find them.
pub(crate) const HOME_FOLDERS: [&str; 6] = [
    "Documents",
    "Downloads",
    "Music",
    "Pictures",
    "Projects",
    "Videos",
];
const USER_DIRS: &str = "# Written by the enzimOS installer.\n\
XDG_DESKTOP_DIR=\"$HOME\"\n\
XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n\
XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"\n\
XDG_MUSIC_DIR=\"$HOME/Music\"\n\
XDG_PICTURES_DIR=\"$HOME/Pictures\"\n\
XDG_PUBLICSHARE_DIR=\"$HOME\"\n\
XDG_TEMPLATES_DIR=\"$HOME\"\n\
XDG_VIDEOS_DIR=\"$HOME/Videos\"\n";
fn home_folders(context: &Received, username: &str) -> Result<()> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    };
    let home = std::path::PathBuf::from(format!(
        "/proc/self/fd/{}/home/{username}",
        context.target.as_raw_fd()
    ));
    let meta = std::fs::symlink_metadata(&home)?;
    require(
        meta.is_dir() && meta.uid() == 1000,
        "new home directory missing or not the new account's",
    )?;
    let own = |path: &Path| -> Result<()> {
        std::os::unix::fs::lchown(path, Some(1000), Some(1000))?;
        Ok(())
    };
    for name in HOME_FOLDERS.iter().copied().chain([".config"]) {
        let path = home.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(existing) => require(
                existing.is_dir() && !existing.file_type().is_symlink(),
                "home folder name is taken",
            )?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new().mode(0o755).create(&path)?;
                own(&path)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let map = home.join(".config/user-dirs.dirs");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&map)?;
    std::io::Write::write_all(&mut file, USER_DIRS.as_bytes())?;
    own(&map)?;
    Ok(())
}
fn shadow_present(target: &std::fs::File, username: &str) -> Result<()> {
    let shadow = files::open_relative(target, Path::new("etc/shadow"))?;
    let bytes = crate::private_file::read(&shadow, 1024 * 1024, 0)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error("installed shadow encoding".into()))?;
    let mut root = 0;
    let mut user = 0;
    for line in text.lines() {
        let row = line.split(':').collect::<Vec<_>>();
        require(row.len() == 9, "installed shadow row shape")?;
        if row[0] == "root" {
            root += 1;
            require(
                row[1].starts_with('!'),
                "installed Root account is not locked",
            )?;
        }
        if row[0] == username {
            user += 1;
            require(
                row[1].starts_with('$') && row[1].len() > 32,
                "new account password hash unavailable",
            )?;
        }
    }
    require(
        root == 1 && user == 1,
        "installed account shadow identity differs",
    )
}
pub(crate) fn verify_account(target: &std::fs::File, username: &str) -> Result<()> {
    let read = |name: &str| -> Result<String> {
        String::from_utf8(files::read_file(
            &files::open_relative(target, Path::new(name))?,
            1024 * 1024,
            Some(0),
            true,
        )?)
        .map_err(|_| Error("installed account database encoding".into()))
    };
    account_present(&read("etc/passwd")?, &read("etc/group")?, username)?;
    shadow_present(target, username)
}
pub(crate) fn account_present(passwd: &str, group: &str, username: &str) -> Result<()> {
    require(
        crate::answers::ordinary_name(username)
            && passwd.len() <= 1024 * 1024
            && group.len() <= 1024 * 1024,
        "installed account readback bound",
    )?;
    let users = passwd
        .lines()
        .filter(|l| l.split(':').next() == Some(username))
        .collect::<Vec<_>>();
    require(
        users.len() == 1,
        "installed administrator account missing or duplicated",
    )?;
    let row = users[0].split(':').collect::<Vec<_>>();
    require(
        row.len() == 7
            && row[1] == "x"
            && row[2] == "1000"
            && row[3] == "1000"
            && row[5] == format!("/home/{username}")
            && row[6] == "/bin/bash",
        "installed account identity differs",
    )?;
    for required in [username, "wheel", "gamemode"] {
        let groups = group
            .lines()
            .filter(|l| l.split(':').next() == Some(required))
            .collect::<Vec<_>>();
        require(
            groups.len() == 1,
            "installed administrator group missing or duplicated",
        )?;
        let row = groups[0].split(':').collect::<Vec<_>>();
        require(
            row.len() == 4
                && if required == username {
                    row[2] == "1000"
                } else {
                    row[3].split(',').any(|u| u == username)
                },
            "installed administrator group membership differs",
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_creation_refuses_preexisting_numeric_aliases_and_ambiguous_databases() {
        account_absent(
            "root:x:0:0:root:/root:/bin/bash\n",
            "root:x:0:\nwheel:x:998:\ngamemode:x:997:\n",
            "admin",
        )
        .unwrap();
        for passwd in [
            "other:x:01000:1000::/home/other:/bin/bash\n",
            "root:x:0:0::/root:/bin/bash\nroot:x:1:1::/:/bin/false\n",
            "bad\n",
        ] {
            assert!(account_absent(passwd, "root:x:0:\n", "admin").is_err());
        }
        assert!(
            account_absent("root:x:0:0::/root:/bin/bash\n", "other:x:01000:\n", "admin").is_err()
        );
    }
    #[test]
    fn administrator_readback_requires_exact_uid_home_shell_and_both_groups() {
        let passwd = "root:x:0:0::/root:/bin/bash\nadmin:x:1000:1000:Name:/home/admin:/bin/bash\n";
        let group = "root:x:0:\nadmin:x:1000:\nwheel:x:998:admin\ngamemode:x:997:admin\n";
        account_present(passwd, group, "admin").unwrap();
        assert!(
            account_present(&passwd.replace("1000:1000", "1001:1000"), group, "admin").is_err()
        );
        assert!(
            account_present(
                passwd,
                &group.replace("gamemode:x:997:admin", "gamemode:x:997:"),
                "admin"
            )
            .is_err()
        );
        assert!(
            account_present(
                &format!("{passwd}admin:x:1000:1000:Name:/home/admin:/bin/bash\n"),
                group,
                "admin"
            )
            .is_err()
        );
    }
}
