// SPDX-License-Identifier: MIT
//! Fixed, retained target providers; network isolation exists only in children.
use crate::{
    flatpak_media::Prepared, install_boot_sources::Source, media_packages::Admitted,
    package_handoff::Received,
};
use enzimos_platform::{Error, Result, files, process, require};
use std::{
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::Duration,
};
pub(crate) struct Tools {
    flatpak: Source,
    runuser: Option<Source>,
    environment: Option<Source>,
}
impl Tools {
    pub(crate) fn observe(context: &Received, user_remote: bool) -> Result<Self> {
        let flatpak = Self::image(context, "usr/bin/flatpak")?;
        let (runuser, environment) = if user_remote {
            (
                Some(Self::image(context, "usr/bin/runuser")?),
                Some(Self::image(context, "usr/bin/env")?),
            )
        } else {
            (None, None)
        };
        Ok(Self {
            flatpak,
            runuser,
            environment,
        })
    }
    fn image(context: &Received, path: &str) -> Result<Source> {
        let source = Source::open(&context.target, Path::new(path), 32 * 1024 * 1024)?;
        require(
            source.file.metadata()?.mode() & 0o111 != 0
                && files::read_file(&source.file, 32 * 1024 * 1024, Some(0), true)?
                    .starts_with(b"\x7fELF"),
            "native protected Flatpak provider required",
        )?;
        Ok(source)
    }
    pub(crate) fn recheck(&self, context: &Received) -> Result<()> {
        context.recheck()?;
        self.flatpak.recheck(&context.target)?;
        for source in self.runuser.iter().chain(self.environment.iter()) {
            source.recheck(&context.target)?;
        }
        Ok(())
    }
    pub(crate) fn receipt(&self) -> serde_json::Value {
        serde_json::json!({"flatpak":self.flatpak.receipt(),"runuser":self.runuser.as_ref().map(Source::receipt),"env":self.environment.as_ref().map(Source::receipt)})
    }
    pub(crate) fn system(
        &self,
        context: &Received,
        media: &Admitted,
        prepared: &Prepared,
        arguments: &[&str],
        extra: &[BorrowedFd<'_>],
    ) -> Result<Vec<u8>> {
        self.execute(
            context,
            media,
            prepared,
            "/usr/bin/flatpak",
            arguments,
            extra,
        )
    }
    pub(crate) fn user(
        &self,
        context: &Received,
        media: &Admitted,
        prepared: &Prepared,
        arguments: &[&str],
    ) -> Result<Vec<u8>> {
        require(
            self.runuser.is_some() && self.environment.is_some(),
            "original user remote providers absent",
        )?;
        let answers = &context
            .answers
            .as_ref()
            .ok_or_else(|| Error("original Flatpak account answers absent".into()))?
            .answers;
        crate::install_config_tools::verify_account(&context.target, &answers.username)?;
        let home = format!("HOME=/home/{}", answers.username);
        let mut args = vec![
            "-u",
            answers.username.as_str(),
            "--",
            "@fd:2",
            home.as_str(),
            "@fd:3",
        ];
        args.extend_from_slice(arguments);
        self.execute(context, media, prepared, "/usr/bin/runuser", &args, &[])
    }
    fn execute(
        &self,
        context: &Received,
        media: &Admitted,
        prepared: &Prepared,
        program: &str,
        arguments: &[&str],
        extra: &[BorrowedFd<'_>],
    ) -> Result<Vec<u8>> {
        require(
            extra.len() <= 1 && arguments.len() <= 150,
            "offline Flatpak command bounds",
        )?;
        self.recheck(context)?;
        prepared.recheck(&media.media)?;
        media.recheck()?;
        let image = match program {
            "/usr/bin/flatpak" => &self.flatpak.file,
            "/usr/bin/runuser" => {
                &self
                    .runuser
                    .as_ref()
                    .ok_or_else(|| Error("original runuser image absent".into()))?
                    .file
            }
            _ => {
                return Err(Error(
                    "offline Flatpak program outside fixed provider set".into(),
                ));
            }
        };
        let mut args = vec!["@fd-dir:0", "@fd:1"];
        args.extend_from_slice(arguments);
        let mut descriptors = vec![context.target.as_fd(), image.as_fd()];
        if program == "/usr/bin/runuser" {
            descriptors.push(
                self.environment
                    .as_ref()
                    .ok_or_else(|| Error("original environment image absent".into()))?
                    .file
                    .as_fd(),
            );
            descriptors.push(self.flatpak.file.as_fd());
        }
        descriptors.extend_from_slice(extra);
        let output = process::run_pinned_offline(
            media.images.get("/usr/bin/chroot")?,
            &args,
            &[],
            Duration::from_secs(900),
            2 * 1024 * 1024,
            &descriptors,
        )?;
        self.recheck(context)?;
        prepared.recheck(&media.media)?;
        media.recheck()?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            let detail: String = detail
                .trim()
                .chars()
                .rev()
                .take(400)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            return Err(Error(format!(
                "offline Flatpak target command failed; original attempt requires review and cannot be replayed: {detail}"
            )));
        }
        Ok(output.stdout)
    }
}
