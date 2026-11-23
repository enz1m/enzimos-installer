// SPDX-License-Identifier: MIT
//! System associations for applications installed from offline media.

pub(crate) const PATH: &str = "etc/xdg/mimeapps.list";

const GROUPS: &[(&[&str], &[&str])] = &[
    (
        &[
            "x-scheme-handler/http",
            "x-scheme-handler/https",
            "text/html",
            "application/xhtml+xml",
        ],
        &["org.enzim.Browser", "app.zen_browser.zen"],
    ),
    (&["x-scheme-handler/mailto"], &["io.github.enzui.Mail"]),
    (
        &["text/calendar", "application/ics"],
        &["io.github.enzui.Calendar"],
    ),
    (
        &[
            "application/pdf",
            "application/epub+zip",
            "application/vnd.comicbook+zip",
            "application/x-cbz",
        ],
        &["io.github.enzui.Reader"],
    ),
    (
        &[
            "audio/aac",
            "audio/flac",
            "audio/mp4",
            "audio/mpeg",
            "audio/ogg",
            "audio/opus",
            "audio/wav",
            "audio/x-flac",
            "audio/x-ms-wma",
            "audio/x-opus+ogg",
            "audio/x-wav",
        ],
        &["io.github.enzui.Music"],
    ),
    (
        &[
            "image/apng",
            "image/avif",
            "image/bmp",
            "image/gif",
            "image/heic",
            "image/heic-sequence",
            "image/heif",
            "image/heif-sequence",
            "image/jpeg",
            "image/jxl",
            "image/png",
            "image/qoi",
            "image/tiff",
            "image/vnd.microsoft.icon",
            "image/webp",
            "image/x-icon",
        ],
        &["org.enzimos.Photos"],
    ),
    (
        &[
            "video/3gpp",
            "video/3gpp2",
            "video/matroska",
            "video/mp2t",
            "video/mp4",
            "video/mpeg",
            "video/ogg",
            "video/quicktime",
            "video/vnd.avi",
            "video/webm",
            "video/x-flv",
            "video/x-m4v",
            "video/x-matroska",
            "video/x-ms-wmv",
            "video/x-msvideo",
        ],
        &["io.github.enzui.Video", "org.enzimos.Photos"],
    ),
    (
        &[
            "application/x-rdp",
            "application/x-remmina",
            "application/x-enzui-remote-profiles+json",
        ],
        &["io.github.enzui.Remote"],
    ),
];

pub(crate) fn mimeapps(has_app: impl Fn(&str) -> bool) -> Option<String> {
    const HEADER: &str = "[Default Applications]\n";
    let mut defaults = HEADER.to_owned();
    for (types, candidates) in GROUPS {
        let Some(app) = candidates.iter().find(|app| has_app(app)) else {
            continue;
        };
        for mime in *types {
            defaults.push_str(mime);
            defaults.push('=');
            defaults.push_str(app);
            defaults.push_str(".desktop\n");
        }
    }
    (defaults.len() > HEADER.len()).then_some(defaults)
}

#[cfg(test)]
mod tests {
    use super::mimeapps;

    #[test]
    fn system_defaults_follow_the_offline_fleet() {
        assert!(mimeapps(|app| app == "org.enzimos.Calculator").is_none());
        let installed = [
            "app.zen_browser.zen",
            "io.github.enzui.Calendar",
            "io.github.enzui.Reader",
            "io.github.enzui.Music",
            "org.enzimos.Photos",
        ];
        let defaults = mimeapps(|app| installed.contains(&app)).unwrap();
        for (mime, app) in [
            ("text/html", "app.zen_browser.zen"),
            ("text/calendar", "io.github.enzui.Calendar"),
            ("application/pdf", "io.github.enzui.Reader"),
            ("audio/flac", "io.github.enzui.Music"),
            ("image/avif", "org.enzimos.Photos"),
            ("image/png", "org.enzimos.Photos"),
            ("video/webm", "org.enzimos.Photos"),
        ] {
            assert!(
                defaults
                    .lines()
                    .any(|line| line == format!("{mime}={app}.desktop")),
                "{mime} must open in the installed {app}"
            );
        }
        assert!(
            !defaults.contains("mailto"),
            "Mail is absent from this fleet"
        );

        let with_video =
            mimeapps(|app| installed.contains(&app) || app == "io.github.enzui.Video").unwrap();
        assert!(
            with_video.contains("video/webm=io.github.enzui.Video.desktop\n"),
            "prefer Video when the dedicated player is installed"
        );
    }
}
