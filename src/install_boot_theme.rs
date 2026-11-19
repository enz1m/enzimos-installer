// SPDX-License-Identifier: MIT
//! Publish the boot theme through the original configuration description.
use crate::package_handoff::Received;
use enzimos_platform::{Result, files, require};
use std::path::Path;
pub(crate) const NAME: &str = "etc/plymouth/plymouthd.conf";
const MAX: usize = 65536;

pub(crate) fn render(input: &str) -> Result<String> {
    require(
        input.len() <= MAX
            && !input.contains(['\0', '\r'])
            && input.lines().all(|l| l.len() <= 4096),
        "Plymouth daemon configuration bounds",
    )?;
    let mut lines = input.lines().map(str::to_owned).collect::<Vec<_>>();
    let mut daemon = None;
    let mut theme = None;
    let mut in_daemon = false;
    let mut end = lines.len();
    for (i, line) in lines.iter().enumerate() {
        let text = line.trim();
        if text.is_empty() || text.starts_with(['#', ';']) {
            continue;
        }
        if text.starts_with('[') {
            require(
                text.ends_with(']')
                    && text.len() > 2
                    && !text[1..text.len() - 1].contains(['[', ']']),
                "ambiguous Plymouth section",
            )?;
            if in_daemon {
                end = i;
            }
            in_daemon = text == "[Daemon]";
            if in_daemon {
                require(
                    daemon.replace(i).is_none(),
                    "duplicate Plymouth daemon section",
                )?;
            }
        } else {
            let (key, _) = text
                .split_once('=')
                .ok_or_else(|| enzimos_platform::Error("Plymouth assignment shape".into()))?;
            require(!key.trim().is_empty(), "Plymouth empty configuration key")?;
            if in_daemon && key.trim() == "Theme" {
                require(
                    theme.replace(i).is_none(),
                    "duplicate Plymouth daemon theme",
                )?;
            }
        }
    }
    if let Some(index) = theme {
        // Preserve an already exact publication rather than replacing its inode.
        if lines[index] != "Theme=enzimos" {
            lines[index] = "Theme=enzimos".into();
        }
    } else if daemon.is_some() {
        lines.insert(end, "Theme=enzimos".into());
    } else {
        if lines.last().is_some_and(|line| !line.is_empty()) {
            lines.push(String::new());
        }
        lines.extend(["[Daemon]".into(), "Theme=enzimos".into()]);
    }
    let output = lines.join("\n") + "\n";
    require(
        output.len() <= MAX,
        "Plymouth generated configuration bound",
    )?;
    Ok(output)
}
pub(crate) fn prepare(context: &Received) -> Result<String> {
    context.recheck()?;
    let parent =
        files::ensure_directory_relative(&context.target, Path::new("etc/plymouth"), 0o755, 0)?;
    let name = Path::new("plymouthd.conf");
    let old = files::optional_relative(&parent, name)?;
    let original_identity = old
        .as_ref()
        .map(|file| file.metadata().map(|m| files::identity(&m)))
        .transpose()?;
    let before = old
        .as_ref()
        .map(|file| files::read_file(file, MAX, Some(0), true))
        .transpose()?
        .unwrap_or_default();
    let input = std::str::from_utf8(&before)
        .map_err(|_| enzimos_platform::Error("Plymouth daemon encoding".into()))?;
    let output = render(input)?;
    context.recheck()?;
    if let (Some(original), Some(identity)) = (&old, original_identity) {
        let named = files::open_relative(&parent, name)?;
        require(
            files::identity(&original.metadata()?) == identity
                && files::identity(&named.metadata()?) == identity,
            "original Plymouth configuration changed before publication",
        )?;
    }
    if before != output.as_bytes() {
        if let Some(original) = &old {
            files::atomic_replace_original(
                &parent,
                name,
                output.as_bytes(),
                0o644,
                Some(0),
                MAX,
                original,
            )?;
        } else {
            files::atomic_relative(&parent, name, output.as_bytes(), 0o644, Some(0), false, MAX)?;
        }
    }
    verify(&context.target)?;
    require(
        files::read_file(&files::open_relative(&parent, name)?, MAX, Some(0), true)?
            == output.as_bytes(),
        "Plymouth exact publication readback changed",
    )?;
    context.recheck()?;
    Ok(NAME.into())
}
pub(crate) fn verify(root: &std::fs::File) -> Result<()> {
    let bytes = files::read_file(
        &files::open_relative(root, Path::new(NAME))?,
        MAX,
        Some(0),
        true,
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| enzimos_platform::Error("Plymouth daemon encoding".into()))?;
    require(
        render(text)?.as_bytes() == bytes,
        "installed Plymouth daemon does not select exact native boot theme",
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn theme_selection_preserves_other_settings_and_refuses_ambiguous_daemon_configuration() {
        let current = "[Daemon]\nTheme=enzimos\nShowDelay=0\n";
        assert_eq!(render(current).unwrap(), current);
        assert_eq!(
            render("# vendor\n[Daemon]\nTheme=old\nShowDelay=5\n[Other]\nTheme=keep\n").unwrap(),
            "# vendor\n[Daemon]\nTheme=enzimos\nShowDelay=5\n[Other]\nTheme=keep\n"
        );
        assert_eq!(
            render("[Daemon]\nShowDelay=3\n[Other]\nX=y\n").unwrap(),
            "[Daemon]\nShowDelay=3\nTheme=enzimos\n[Other]\nX=y\n"
        );
        assert_eq!(render("").unwrap(), "[Daemon]\nTheme=enzimos\n");
        for bad in [
            "[Daemon]\nTheme=a\nTheme=b\n",
            "[Daemon]\n[Daemon]\n",
            "[Daemon\n",
            "[Daemon]\ninvalid\n",
            "[Daemon]\nTheme=a\r\n",
            "[Daemon]\nTheme=a\0\n",
        ] {
            assert!(render(bad).is_err(), "{bad:?}");
        }
    }
}
