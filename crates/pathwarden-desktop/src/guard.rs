//! What the window decides about each navigation, new window, download
//! and `/__desktop/*` request, kept apart from `wry` and `tao` so it can
//! be tested without a window. [`crate::window`] only carries the
//! answers out.

use axum::http::Method;

use crate::bridge::{self, ORIGIN};

/// Developer tools: on in debug builds only.
pub const DEVTOOLS: bool = cfg!(debug_assertions);

/// What a `/__desktop/*` request from a page asks of the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    /// Not a POST, or from another origin.
    Refused,
    PickFile,
    PickFolder,
    /// Save the answer at this app URL; `None` for a target that isn't one
    /// of the app's paths (answered like a save, but nothing is saved).
    Save(Option<String>),
    NotFound,
}

/// A `/__desktop/*` request: only a POST, with no `Origin` or the window's
/// own (no other site can reach the custom protocol).
pub fn desktop_request(method: &Method, origin: Option<&[u8]>, path: &str, body: &[u8]) -> Ask {
    if method != Method::POST || origin.is_some_and(|o| o != ORIGIN.as_bytes()) {
        return Ask::Refused;
    }
    match path {
        "/__desktop/pick-file" => Ask::PickFile,
        "/__desktop/pick-folder" => Ask::PickFolder,
        "/__desktop/save" => Ask::Save(save_target(&String::from_utf8_lossy(body))),
        _ => Ask::NotFound,
    }
}

/// The app URL a page asks to save: an absolute path of the app (never
/// `//host`, never a backslash), else none.
pub fn save_target(target: &str) -> Option<String> {
    (target.starts_with('/') && !target.starts_with("//") && !target.contains('\\'))
        .then(|| format!("{ORIGIN}{target}"))
}

/// Whether the window may go to `url`: only the app's own pages. Anything
/// else is handed to [`web_link`]'s check and the default browser.
pub fn navigation_allowed(url: &str) -> bool {
    bridge::is_internal(url)
}

/// What a new window (`target="_blank"`, `window.open`) becomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewWindow {
    /// An app page: a window of its own.
    App(String),
    /// Another site: the default browser, if [`web_link`] allows it.
    Elsewhere(String),
    /// An app page with a query string: not opened.
    Refused,
}

/// A new window is never a webview's own popup: an app page opens in an
/// app window, anything else elsewhere. The app opens its own pages in a
/// new window by their path alone ("Open full page"); a page with a query
/// string would be one a report loaded from the history picked, to have
/// the app do or show something of its choosing, so it isn't opened.
pub fn new_window(url: &str) -> NewWindow {
    if bridge::is_internal(url) {
        let rest = &url[ORIGIN.len()..];
        if rest.contains('?') {
            NewWindow::Refused
        } else {
            NewWindow::App(url.to_string())
        }
    } else {
        NewWindow::Elsewhere(url.to_string())
    }
}

/// A download WebView2 started: an app URL is saved through the native
/// Save dialog (`Some`), anything else is dropped. WebView2's own download
/// is always cancelled.
pub fn download(url: &str) -> Option<String> {
    bridge::is_internal(url).then(|| url.to_string())
}

/// Whether a link to another site may be opened in the default browser:
/// web and mail links only, never a file, a program or another protocol
/// handler.
pub fn web_link(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://") || lower.starts_with("mailto:")
}

/// The app path a save fetches, from its app URL.
pub fn save_path(url: &str) -> &str {
    url.strip_prefix(ORIGIN)
        .filter(|p| p.starts_with('/'))
        .unwrap_or("/")
}

/// The name the Save dialog suggests: the answer's
/// `Content-Disposition` file name, else the path's last part, else
/// "download". Only a plain file name: anything with a folder in it is
/// cut to its last part.
pub fn save_name(disposition: Option<&str>, path: &str) -> String {
    let named = disposition
        .and_then(|v| v.split("filename=\"").nth(1))
        .and_then(|v| v.split('"').next())
        .map(str::to_string);
    let name = named.unwrap_or_else(|| {
        path.split(['?', '#'])
            .next()
            .and_then(|p| p.rsplit('/').next())
            .unwrap_or_default()
            .to_string()
    });
    let name = name.rsplit(['/', '\\']).next().unwrap_or_default();
    if name.is_empty() || name == "." || name == ".." {
        "download".into()
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "https://pathwarden.localhost";

    #[test]
    fn desktop_requests_need_a_post_from_the_window() {
        let own = Some(APP.as_bytes());
        let ask = |m: &Method, o: Option<&[u8]>, p: &str| desktop_request(m, o, p, b"");
        assert_eq!(
            ask(&Method::POST, own, "/__desktop/pick-file"),
            Ask::PickFile
        );
        assert_eq!(
            ask(&Method::POST, None, "/__desktop/pick-folder"),
            Ask::PickFolder
        );
        for (m, o) in [
            (Method::GET, own),
            (Method::GET, None),
            (Method::PUT, own),
            (Method::POST, Some(&b"null"[..])),
            (Method::POST, Some(&b"https://contoso.com"[..])),
            (
                Method::POST,
                Some(&b"https://pathwarden.localhost.contoso.com"[..]),
            ),
            (Method::POST, Some(&b"http://pathwarden.localhost"[..])),
        ] {
            assert_eq!(
                ask(&m, o, "/__desktop/pick-file"),
                Ask::Refused,
                "{m} {o:?}"
            );
        }
        assert_eq!(ask(&Method::POST, own, "/__desktop/run"), Ask::NotFound);
        assert_eq!(ask(&Method::POST, own, "/__desktop/"), Ask::NotFound);
    }

    #[test]
    fn a_save_is_only_of_an_app_path() {
        let save = |body: &str| {
            desktop_request(
                &Method::POST,
                Some(APP.as_bytes()),
                "/__desktop/save",
                body.as_bytes(),
            )
        };
        assert_eq!(
            save("/runs/x/report?download=1"),
            Ask::Save(Some(format!("{APP}/runs/x/report?download=1")))
        );
        for bad in [
            "",
            "runs/x",
            "//contoso.com/x",
            "/\\contoso.com\\x",
            "https://contoso.com/x",
            "\\\\fabrikam\\share\\x",
        ] {
            assert_eq!(save(bad), Ask::Save(None), "{bad:?}");
        }
    }

    #[test]
    fn the_window_never_leaves_the_app() {
        assert!(navigation_allowed(APP));
        assert!(navigation_allowed(&format!("{APP}/runs/x")));
        for url in [
            "https://contoso.com/",
            "https://pathwarden.localhost.contoso.com/",
            "https://pathwarden.localhost@contoso.com/",
            "http://pathwarden.localhost/",
            "file:///C:/Windows/System32/calc.exe",
            "pathwarden://localhost/",
            "javascript:alert(1)",
        ] {
            assert!(!navigation_allowed(url), "{url}");
        }
    }

    #[test]
    fn new_windows_and_downloads() {
        let page = format!("{APP}/runs/x/report");
        assert_eq!(new_window(&page), NewWindow::App(page.clone()));
        // A query string is a page someone else chose what to ask of.
        for asked in [
            format!("{APP}/runs/x/report?download=1"),
            format!("{APP}/collect?domain=contoso.com"),
            format!("{APP}/?x"),
        ] {
            assert_eq!(new_window(&asked), NewWindow::Refused, "{asked}");
        }
        assert_eq!(
            new_window("https://learn.microsoft.com/"),
            NewWindow::Elsewhere("https://learn.microsoft.com/".into())
        );
        assert_eq!(
            new_window("https://pathwarden.localhost.contoso.com/"),
            NewWindow::Elsewhere("https://pathwarden.localhost.contoso.com/".into())
        );
        assert_eq!(download(&page), Some(page.clone()));
        assert_eq!(download("https://contoso.com/evil.exe"), None);
        assert_eq!(download("file:///C:/x.exe"), None);
    }

    #[test]
    fn only_web_and_mail_links_go_to_the_browser() {
        for ok in [
            "https://learn.microsoft.com/",
            "HTTP://contoso.com/",
            "mailto:secops@contoso.com",
        ] {
            assert!(web_link(ok), "{ok}");
        }
        for bad in [
            "file:///C:/Windows/System32/calc.exe",
            "\\\\fabrikam\\share\\x.exe",
            "C:\\Windows\\System32\\calc.exe",
            "ms-settings:privacy",
            "search-ms:query=x",
            "javascript:alert(1)",
            "vbscript:x",
            " file:///C:/x.exe",
            "",
        ] {
            assert!(!web_link(bad), "{bad}");
        }
    }

    #[test]
    fn saves_fetch_an_app_path_under_a_plain_name() {
        assert_eq!(save_path(&format!("{APP}/runs/x/report")), "/runs/x/report");
        assert_eq!(save_path(APP), "/");
        assert_eq!(save_path("https://contoso.com/x"), "/");
        assert_eq!(save_path(&format!("{APP}.contoso.com/x")), "/");
        assert_eq!(
            save_name(
                Some("attachment; filename=\"pathwarden-report.html\""),
                "/x"
            ),
            "pathwarden-report.html"
        );
        assert_eq!(save_name(None, "/runs/x/export.csv?y=1#z"), "export.csv");
        assert_eq!(save_name(None, "/"), "download");
        assert_eq!(
            save_name(
                Some("attachment; filename=\"..\\..\\Startup\\x.cmd\""),
                "/x"
            ),
            "x.cmd"
        );
        assert_eq!(
            save_name(Some("attachment; filename=\"..\""), "/x"),
            "download"
        );
    }

    #[test]
    fn developer_tools_follow_the_build() {
        assert_eq!(DEVTOOLS, cfg!(debug_assertions));
        // Release builds (`cargo test --release`) check the real setting.
        #[cfg(not(debug_assertions))]
        assert!(!DEVTOOLS);
    }
}
