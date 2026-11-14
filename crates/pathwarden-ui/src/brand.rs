//! The Crown W in the app's chrome: favicons, the web app manifest and its
//! icons, and the old logo swapped out of reports saved before the rebrand.
//!
//! The icons are public (served without a session, like the bare pages that
//! show the mark anyway): a browser fetches a manifest without cookies, and
//! the "link expired" and "session ended" pages have no session to send.
//! They live under `/static/brand/`, so a browser profile that cached the
//! old lighthouse under `/static/favicon.svg` fetches them anew.

use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::server::Shared;

const DIR: &str = "/static/brand/";

/// The adaptive SVG favicon: the small cut, no tile, light colors on light
/// browser UIs (its own `<style>`).
pub const FAVICON_SVG: &str = include_str!("../../../assets/brand/favicon/favicon.svg");
const FAVICON_ICO: &[u8] = include_bytes!("../../../assets/brand/favicon/favicon.ico");
/// The brand's manifest, written for a site root; its icon paths are moved
/// under [`DIR`] when served.
const MANIFEST: &str = include_str!("../../../assets/brand/favicon/site.webmanifest");

/// PNG icons on the navy tile: favicons (16 to 64 px), the Apple touch
/// icon, and the manifest's icons (which an Edge or Chrome app window uses
/// for its title bar and taskbar).
const PNGS: &[(&str, &[u8])] = &[
    (
        "favicon-16.png",
        include_bytes!("../../../assets/brand/favicon/favicon-16.png"),
    ),
    (
        "favicon-32.png",
        include_bytes!("../../../assets/brand/favicon/favicon-32.png"),
    ),
    (
        "favicon-48.png",
        include_bytes!("../../../assets/brand/favicon/favicon-48.png"),
    ),
    (
        "favicon-64.png",
        include_bytes!("../../../assets/brand/favicon/favicon-64.png"),
    ),
    (
        "apple-touch-icon.png",
        include_bytes!("../../../assets/brand/favicon/apple-touch-icon.png"),
    ),
    (
        "icon-192.png",
        include_bytes!("../../../assets/brand/favicon/icon-192.png"),
    ),
    (
        "icon-512.png",
        include_bytes!("../../../assets/brand/favicon/icon-512.png"),
    ),
    (
        "icon-maskable-512.png",
        include_bytes!("../../../assets/brand/favicon/icon-maskable-512.png"),
    ),
];

/// The `<head>` lines every page of the app carries.
pub const HEAD_LINKS: &str = r##"<link rel="icon" href="/static/brand/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/static/brand/favicon-16.png" sizes="16x16" type="image/png">
<link rel="icon" href="/static/brand/favicon-32.png" sizes="32x32" type="image/png">
<link rel="icon" href="/static/brand/favicon-48.png" sizes="48x48" type="image/png">
<link rel="icon" href="/static/brand/favicon-64.png" sizes="64x64" type="image/png">
<link rel="apple-touch-icon" href="/static/brand/apple-touch-icon.png">
<link rel="manifest" href="/static/brand/site.webmanifest">
<meta name="theme-color" content="#0B0E14">"##;

/// Whether a path is one of the public brand files.
pub fn is_public(path: &str) -> bool {
    matches!(
        path,
        "/favicon.ico" | "/static/favicon.svg" | "/static/favicon-32.png"
    ) || path.strip_prefix(DIR).is_some_and(|name| {
        name == "favicon.svg" || name == "site.webmanifest" || PNGS.iter().any(|(n, _)| *n == name)
    })
}

/// The routes for the brand files (and the two favicon paths earlier pages
/// linked, which now serve the Crown W too).
pub fn routes() -> Router<Shared> {
    let mut r = Router::new()
        .route("/static/brand/favicon.svg", get(favicon_svg))
        .route("/static/favicon.svg", get(favicon_svg))
        .route(
            "/favicon.ico",
            get(|| async {
                ([(header::CONTENT_TYPE, "image/x-icon")], FAVICON_ICO).into_response()
            }),
        )
        .route("/static/brand/site.webmanifest", get(manifest))
        .route("/static/favicon-32.png", get(|| async { png(PNGS[1].1) }));
    for (name, bytes) in PNGS {
        let bytes: &'static [u8] = bytes;
        r = r.route(
            &format!("{DIR}{name}"),
            get(move || async move { png(bytes) }),
        );
    }
    r
}

fn png(bytes: &'static [u8]) -> Response {
    ([(header::CONTENT_TYPE, "image/png")], bytes).into_response()
}

/// The SVG favicon switches colors with an inline `<style>`, which the
/// app's policy (styles from files only) would block; it gets a policy of
/// its own that allows that and nothing else.
async fn favicon_svg() -> Response {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'",
            ),
        ],
        FAVICON_SVG,
    )
        .into_response()
}

async fn manifest() -> Response {
    (
        [(header::CONTENT_TYPE, "application/manifest+json")],
        MANIFEST.replace(r#""/icon-"#, r#""/static/brand/icon-"#),
    )
        .into_response()
}

// ------------------------------------------------- reports saved earlier

/// The old logo blocks of reports written before the Crown W: the light
/// and the dark variant side by side, each an inline SVG in a span. Every
/// earlier report has exactly one:
///
/// - `logo`: the stacked logo in the rail (with or without the tagline
///   under it), or before the rail the horizontal logo in the header; both
///   carry the wordmark, so the Crown W lockup replaces them.
/// - `mark`: the first report's small mark, next to a text wordmark; the
///   Crown W mark alone replaces it.
const OLD_BLOCKS: &[(&str, &str, bool)] = &[
    (
        r#"<span class="logo logo-light">"#,
        r#"<span class="logo logo-dark">"#,
        true,
    ),
    (
        r#"<span class="mark mark-light">"#,
        r#"<span class="mark mark-dark">"#,
        false,
    ),
];

/// Styles for the swapped-in Crown W, scoped to its own class: the old
/// report's stylesheet knows nothing of it. Static colors per theme (the
/// report's `data-theme`, or the system's for the first reports, which had
/// no theme button), light in print. No motion: the mark is drawn at rest.
const OLD_REPORT_STYLE: &str = "<style>\
.pw-cw{--cw-a:#9d5cff;--cw-b:#7ce46b;--cw-i:#f7f7f7;--lh:36px;display:flex;align-items:center;\
gap:calc(var(--lh)*13/50.75);height:var(--lh);width:max-content;max-width:100%;color:var(--cw-i)}\
.pw-cw.pw-cw-mark{--lh:40px;margin:0 14px 0 0}\
.pw-cw svg{display:block;height:100%;width:auto;overflow:visible}\
.pw-cw .cw-a{stop-color:var(--cw-a)}.pw-cw .cw-b{stop-color:var(--cw-b)}\
.pw-cw .cw-nl,.pw-cw .cw-nr{fill:var(--cw-a)}.pw-cw .cw-jw{fill:var(--cw-b)}.pw-cw .cw-bar{fill:var(--cw-i)}\
:root:not([data-theme]) .pw-cw,[data-theme=\"light\"] .pw-cw{--cw-a:#6b00d6;--cw-b:#1f8a3a;--cw-i:#0b0e14}\
:root:not([data-theme]) .pw-cw .cw-halo,[data-theme=\"light\"] .pw-cw .cw-halo{display:none}\
@media (prefers-color-scheme:dark){:root:not([data-theme]) .pw-cw{--cw-a:#9d5cff;--cw-b:#7ce46b;--cw-i:#f7f7f7}\
:root:not([data-theme]) .pw-cw .cw-halo{display:inline}}\
@media (max-width:860px){.pw-cw{--lh:28px}}\
@media print{.pw-cw{--cw-a:#6b00d6!important;--cw-b:#1f8a3a!important;--cw-i:#0b0e14!important}.pw-cw .cw-halo{display:none!important}}\
</style>";

/// A report saved before the Crown W, with its old logo block replaced by
/// the Crown W (and the styles for it added to the head); `None` when the
/// report has no old logo (it is current, or not one Pathwarden wrote).
///
/// Only that block changes: the report's scripts are untouched, so their
/// hashes (which the embedded view's policy pins) still match.
pub fn rebrand_old_report(html: &str) -> Option<String> {
    let head_end = html.find("</head>")?;
    // The logo sits in the body, before any script.
    let body = head_end
        ..html[head_end..]
            .find("<script")
            .map_or(html.len(), |i| head_end + i);
    for &(light, dark, lockup) in OLD_BLOCKS {
        let Some(start) = html[body.clone()].find(light).map(|i| body.start + i) else {
            continue;
        };
        let dark_at = start + html[start..body.end].find(dark)?;
        let end = dark_at + html[dark_at..body.end].find("</span>")? + "</span>".len();
        let block = &html[start..end];
        if block.matches("<svg").count() != 2 || block.matches("</svg>").count() != 2 {
            return None;
        }
        let new = if lockup {
            format!(
                r#"<span class="pw-cw" role="img" aria-label="Pathwarden">{}</span>"#,
                pathwarden_core::report::brand_lockup()
            )
        } else {
            format!(
                r#"<span class="pw-cw pw-cw-mark">{}</span>"#,
                pathwarden_core::report::brand_mark()
            )
        };
        let mut out = String::with_capacity(html.len() + new.len() + OLD_REPORT_STYLE.len());
        out.push_str(&html[..head_end]);
        out.push_str(OLD_REPORT_STYLE);
        out.push_str(&html[head_end..start]);
        out.push_str(&new);
        out.push_str(&html[end..]);
        return Some(out);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_paths_are_only_the_brand_files() {
        for p in [
            "/favicon.ico",
            "/static/brand/favicon.svg",
            "/static/brand/favicon-48.png",
            "/static/brand/icon-512.png",
            "/static/brand/site.webmanifest",
            "/static/favicon.svg",
        ] {
            assert!(is_public(p), "{p}");
        }
        for p in [
            "/",
            "/static/app.css",
            "/static/brand/",
            "/static/brand/../app.css",
            "/static/brand/icon-512.png/x",
            "/static/app.js",
        ] {
            assert!(!is_public(p), "{p}");
        }
    }

    #[test]
    fn current_reports_are_left_alone() {
        let html = format!(
            r#"<html><head><style></style></head><body><div class="brand"><div class="lockup cw-intro">{}</div></div><script>x</script></body></html>"#,
            pathwarden_core::report::brand_lockup()
        );
        assert_eq!(rebrand_old_report(&html), None);
        // A logo-looking block inside a script is not the logo.
        let html = r#"<html><head></head><body><script>"<span class="logo logo-light"><svg></svg></span><span class="logo logo-dark"><svg></svg></span>"</script></body></html>"#;
        assert_eq!(rebrand_old_report(html), None);
    }

    #[test]
    fn the_first_reports_small_mark() {
        let html = r#"<html><head><style>.mark svg{width:40px}</style></head><body><header class="top">
  <div class="brand">
    <span class="mark mark-light"><svg viewBox="0 0 64 64"><path d="M32 3 L34 17"/></svg></span><span class="mark mark-dark"><svg viewBox="0 0 64 64"><path d="M32 3 L34 17"/></svg></span>
    <div><div class="wordmark"><span class="w1">Path</span><span class="w2">warden</span></div>"#;
        let out = rebrand_old_report(html).unwrap();
        assert!(!out.contains("M32 3 L34 17") && !out.contains("mark-light"));
        assert!(out.contains(r#"<span class="pw-cw pw-cw-mark"><svg"#));
        assert!(out.contains(r#"<span class="w1">Path</span>"#));
        assert_eq!(out.matches(r#"class="cw""#).count(), 1);
        assert!(!out.contains("cw-word"));
    }
}
