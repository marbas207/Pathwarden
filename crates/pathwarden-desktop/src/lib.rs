//! `pathwarden ui --window`: Pathwarden's UI in a native window with **no
//! listening port**. In builds with the `desktop` feature it is
//! what `pathwarden ui` opens by default on Windows desktops.
//!
//! The window is a system webview (WebView2 on Windows, through `wry` and
//! `tao`). Its pages load from a custom protocol, `pathwarden://`, which
//! WebView2 shows as `https://pathwarden.localhost`. Every request the
//! webview makes there is handed to the UI's axum `Router` inside this
//! process ([`bridge`]); nothing listens on a socket, so no other program,
//! user or browser can reach the UI at all. The UI's guard runs in its
//! embedded mode ([`pathwarden_ui::security::Transport::Embedded`]): no
//! link or cookie, the same headers and CSP.
//!
//! What the window adds to the pages (`window`):
//! - collector files are chosen with a native file or folder picker (or
//!   dropped on the window), one or more at a time, and analyzed where they
//!   are, by path, instead of being uploaded through the webview (which
//!   would hold them in memory);
//! - downloads go through a native Save dialog;
//! - links to other sites open in the default browser; the window never
//!   navigates away from the app, and new windows are refused (an app page
//!   opened in a new tab gets its own app window);
//! - developer tools are off in release builds, WebView2 browser
//!   extensions are off (its default), autofill is off, and the WebView2
//!   profile lives in the workspace (`webview2`).
//!
//! Started from Explorer (the console is Pathwarden's own), the console is
//! closed once the window opens (`session`). Without the WebView2 Runtime,
//! `run` says how to install it and falls back to the browser
//! (`pathwarden ui`). Windows only for now: elsewhere `run` says to use
//! `pathwarden ui`, and the window is never the default.

#[cfg(windows)]
pub mod bridge;
#[cfg(windows)]
mod guard;
#[cfg(windows)]
mod session;
#[cfg(windows)]
mod window;

/// Debug builds only: the variables the end-to-end smoke test sets.
#[cfg(all(windows, debug_assertions))]
pub use window::{TEST_DEBUG_PORT, TEST_HIDDEN};

/// Opens Pathwarden in its own window and blocks until the window is
/// closed (or Stop Pathwarden is clicked, or Ctrl+C).
pub fn run(args: pathwarden_ui::UiArgs) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        window::run(args)
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        anyhow::bail!(
            "the Pathwarden window (--window) is only available on Windows for now; run `pathwarden ui` to use the browser"
        )
    }
}

/// Whether `pathwarden ui` opens the window rather than the browser when
/// neither is asked for: on a Windows client edition (not Server), on a
/// desktop the user can see, not over SSH. False elsewhere.
pub fn window_by_default() -> bool {
    #[cfg(windows)]
    {
        session::window_by_default()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Whether Pathwarden was started from Explorer (a double-click, a
/// shortcut): Windows opened a console just for it, rather than it running
/// in a terminal. False elsewhere.
pub fn started_from_explorer() -> bool {
    #[cfg(windows)]
    {
        session::own_console()
    }
    #[cfg(not(windows))]
    {
        false
    }
}
