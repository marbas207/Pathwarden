//! Opening the browser without putting the link's token on a command line.
//!
//! Handing a browser `http://127.0.0.1:PORT/?token=...` as an argument puts
//! the token in that process's command line, which other local users can
//! read on Linux (`/proc/<pid>/cmdline`) and which Windows command-line
//! auditing records. Instead Pathwarden writes a tiny HTML file that
//! redirects to the link, in a new folder only this account can read, and
//! asks the system to open that *file*. The file is deleted as soon as the
//! link has been used, when it expires, when a new link replaces it, and when
//! Pathwarden stops.
//!
//! - Windows: `ShellExecuteW` on the file (no `cmd /C start`). Its path is
//!   the only argument the browser gets.
//! - macOS: `open <file>`; elsewhere `xdg-open <file>`. The folder is in
//!   `$XDG_RUNTIME_DIR` when set (private to the user), else the temp folder.
//!
//! The printed link remains the fallback (stdout is the user's own console).
//!
//! # An app window
//!
//! By default (`--browser app`) the launcher file is opened in an app window
//! of Edge or Chrome (or Chromium): `--app=<file URL of the launcher>` with
//! its own profile, `--user-data-dir=<workspace>/browser-profile`. The window
//! has no tabs or address bar, and the separate profile keeps the user's
//! everyday extensions, history and cookies out of it. The browser's command
//! line holds the launcher's *path* and the profile folder, never the link.
//! When no such browser is found, or it doesn't start, the default browser
//! opens the file as above. A Chromium installed as a snap is skipped: its
//! sandbox can't read the private launcher folder.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::perms;
use crate::security::Token;
use crate::server::AppState;

/// A launcher file and the private folder holding it.
#[derive(Debug)]
pub struct LaunchFile {
    dir: PathBuf,
    file: PathBuf,
}

impl LaunchFile {
    pub fn path(&self) -> &Path {
        &self.file
    }

    fn remove(&self) {
        let _ = std::fs::remove_file(&self.file);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

impl Drop for LaunchFile {
    fn drop(&mut self) {
        self.remove();
    }
}

/// The current launcher file, if any.
#[derive(Debug, Default)]
pub struct Slot(Mutex<Option<LaunchFile>>);

impl Slot {
    fn set(&self, f: Option<LaunchFile>) {
        // The old file (if any) is dropped, which deletes it.
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = f;
    }

    pub fn is_empty(&self) -> bool {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).is_none()
    }
}

/// Deletes the launcher file (the link was used, expired or replaced).
pub fn discard(state: &AppState) {
    state.launch_file.set(None);
}

fn base_dir() -> PathBuf {
    #[cfg(unix)]
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_absolute() && d.is_dir())
    {
        return d;
    }
    std::env::temp_dir()
}

fn page(url: &str) -> String {
    // The URL is ours (`http://127.0.0.1:PORT/?token=<hex>`), so it needs
    // no escaping; checked anyway.
    debug_assert!(url
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b":/.?=".contains(&b)));
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<meta http-equiv="refresh" content="0;url={url}">
<title>Opening Pathwarden</title></head>
<body><p>Opening Pathwarden&hellip; If nothing happens, <a href="{url}">continue</a>.</p></body></html>
"#
    )
}

/// Writes a launcher for `url` in a new private folder.
pub fn write(url: &str) -> std::io::Result<LaunchFile> {
    let dir = base_dir().join(format!(
        "pathwarden-open-{}",
        &Token::generate().map_err(std::io::Error::other)?.expose()[..16]
    ));
    perms::create_private_dir(&dir)?;
    let file = dir.join("open.html");
    let launch = LaunchFile { dir, file };
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(&launch.file)?.write_all(page(url).as_bytes())?;
    Ok(launch)
}

/// Which browser `pathwarden ui` opens (`--browser`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum BrowserMode {
    /// An app window of Edge or Chrome with its own profile, else the
    /// default browser
    #[default]
    App,
    /// The default browser, in a normal tab
    Default,
}

/// An Edge, Chrome or Chromium to open app windows with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppBrowser {
    pub name: &'static str,
    pub program: PathBuf,
}

/// How to open launcher files: in an app window when one is available,
/// else in the default browser.
#[derive(Debug, Clone, Default)]
pub struct Opener {
    app: Option<(AppBrowser, PathBuf)>,
}

impl Opener {
    /// For `--browser`: an app-window browser, with its profile folder under
    /// `workspace`; none in `default` mode or when none is installed (then
    /// the default browser opens the launcher).
    pub fn new(mode: BrowserMode, workspace: &Path) -> Self {
        let app = match mode {
            BrowserMode::Default => None,
            // Absolute: the browser would read a relative profile folder
            // against its own idea of the current folder.
            BrowserMode::App => std::path::absolute(workspace.join("browser-profile"))
                .ok()
                .and_then(|profile| find_app_browser().map(|b| (b, profile))),
        };
        Opener { app }
    }

    /// The app-window browser, when there is one.
    pub fn app_browser(&self) -> Option<&AppBrowser> {
        self.app.as_ref().map(|(b, _)| b)
    }

    /// Opens `file`: in an app window if possible, else the default browser.
    /// `None` when nothing started.
    fn open(&self, file: &Path) -> Option<Opened> {
        if let Some((browser, profile)) = &self.app {
            if open_app(browser, profile, file) {
                return Some(Opened::App);
            }
        }
        open_file(file).then_some(Opened::Default)
    }
}

/// How a launcher file was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    App,
    Default,
}

/// Writes a launcher for `url`, keeps it in `state` (replacing any older
/// one) and opens it: in an app window when `opener` has a browser for one,
/// else in the default browser. `None` when no browser could be started.
pub fn open_browser(state: &AppState, url: &str, opener: &Opener) -> Option<Opened> {
    let launch = write(url).ok()?;
    let opened = opener.open(launch.path());
    state.launch_file.set(opened.is_some().then_some(launch));
    opened
}

/// `file:///C:/...` (or `file:///tmp/...`) for a local absolute path, with
/// everything but unreserved characters, `/` and `:` percent-encoded.
pub fn file_url(path: &Path) -> String {
    let text = path.to_string_lossy();
    let text = if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.into_owned()
    };
    let mut url = String::from("file://");
    if !text.starts_with('/') {
        url.push('/');
    }
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/:".contains(&b) {
            url.push(b as char);
        } else {
            url.push_str(&format!("%{b:02X}"));
        }
    }
    url
}

/// The app window's command line: the launcher's file URL and the profile
/// folder, never the link itself.
pub fn app_args(profile: &Path, file: &Path) -> Vec<OsString> {
    let mut dir = OsString::from("--user-data-dir=");
    dir.push(profile.as_os_str());
    vec![
        format!("--app={}", file_url(file)).into(),
        dir,
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        // Edge signs a new profile in to the Windows account on its own and
        // would then sync the user's extensions into it: no sync, and no
        // extensions (except ones forced by policy).
        "--disable-sync".into(),
        "--disable-extensions".into(),
    ]
}

/// Starts `browser` in app mode on `file`, with its profile in `profile`
/// (created private to this account if missing). False if it didn't start.
fn open_app(browser: &AppBrowser, profile: &Path, file: &Path) -> bool {
    if !profile.is_dir() {
        if let Some(parent) = profile.parent().filter(|p| !p.as_os_str().is_empty()) {
            if std::fs::create_dir_all(parent).is_err() {
                return false;
            }
        }
        match perms::create_private_dir(profile) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return false,
        }
    }
    use std::process::Stdio;
    let mut cmd = pathwarden_core::spawn::detached(&browser.program);
    pathwarden_core::keystore::scrub_env(&mut cmd);
    cmd.args(app_args(profile, file))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match cmd.spawn() {
        Ok(mut child) => {
            // Reaped when it exits (it exits at once when a browser with the
            // same profile is already running and takes the window over).
            std::thread::spawn(move || child.wait());
            true
        }
        Err(_) => false,
    }
}

/// The first Edge, Chrome or Chromium installed in a standard place.
pub fn find_app_browser() -> Option<AppBrowser> {
    candidates(&|k| std::env::var_os(k))
        .into_iter()
        .find(|b| b.program.is_file() && !is_snap(&b.program))
}

/// Where to look, best first. Windows: Edge, then Chrome, each from the
/// `App Paths` registry entries, then Program Files (and Chrome's per-user
/// install). macOS: `/Applications` and `~/Applications`. Elsewhere: `PATH`.
fn candidates(env: &dyn Fn(&str) -> Option<OsString>) -> Vec<AppBrowser> {
    let mut out: Vec<AppBrowser> = Vec::new();
    let mut add = |name: &'static str, program: PathBuf| {
        if !out.iter().any(|b| b.program == program) {
            out.push(AppBrowser { name, program });
        }
    };
    let dir = |k: &str| env(k).map(PathBuf::from).filter(|p| p.is_absolute());
    if cfg!(windows) {
        let browsers = [
            ("Microsoft Edge", "msedge.exe", ["Microsoft", "Edge"]),
            ("Google Chrome", "chrome.exe", ["Google", "Chrome"]),
        ];
        for (name, exe, rel) in browsers {
            for p in app_paths(exe) {
                add(name, p);
            }
            for base in ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"] {
                if let Some(d) = dir(base) {
                    add(
                        name,
                        d.join(rel[0]).join(rel[1]).join("Application").join(exe),
                    );
                }
            }
        }
    } else if cfg!(target_os = "macos") {
        let apps = [
            (
                "Google Chrome",
                "Google Chrome.app/Contents/MacOS/Google Chrome",
            ),
            (
                "Microsoft Edge",
                "Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            ),
            ("Chromium", "Chromium.app/Contents/MacOS/Chromium"),
        ];
        let home = dir("HOME");
        for (name, rel) in apps {
            add(name, Path::new("/Applications").join(rel));
            if let Some(h) = &home {
                add(name, h.join("Applications").join(rel));
            }
        }
    } else {
        let names = [
            ("Google Chrome", "google-chrome-stable"),
            ("Google Chrome", "google-chrome"),
            ("Chromium", "chromium"),
            ("Chromium", "chromium-browser"),
            ("Microsoft Edge", "microsoft-edge-stable"),
            ("Microsoft Edge", "microsoft-edge"),
        ];
        let path = env("PATH").unwrap_or_default();
        for (name, exe) in names {
            for d in std::env::split_paths(&path).filter(|d| d.is_absolute()) {
                add(name, d.join(exe));
            }
        }
    }
    out
}

/// A browser installed as a snap (or a script that runs one, like Ubuntu's
/// `chromium-browser`): its sandbox can't read the private launcher folder,
/// so it isn't used for app windows.
fn is_snap(program: &Path) -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    let real = std::fs::canonicalize(program).unwrap_or_else(|_| program.to_path_buf());
    if real.starts_with("/snap") {
        return true;
    }
    use std::io::Read;
    let mut head = Vec::new();
    std::fs::File::open(&real)
        .and_then(|f| f.take(4096).read_to_end(&mut head))
        .is_ok()
        && head.starts_with(b"#!")
        && String::from_utf8_lossy(&head).contains("snap")
}

/// The programs `App Paths` registers for `exe`, per user first.
#[cfg(windows)]
fn app_paths(exe: &str) -> Vec<PathBuf> {
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ,
    };
    let key: Vec<u16> = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut out = Vec::new();
    for root in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let mut buf = [0u16; 1024];
        let mut bytes = (buf.len() * 2) as u32;
        // SAFETY: `key` is NUL-terminated; `buf` holds `bytes` bytes, and on
        // success `bytes` is the size written, NUL included. REG_EXPAND_SZ
        // values come back expanded.
        let rc = unsafe {
            RegGetValueW(
                root,
                key.as_ptr(),
                std::ptr::null(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if rc != 0 {
            continue;
        }
        let n = (bytes as usize / 2).min(buf.len());
        let text = String::from_utf16_lossy(&buf[..n]);
        let p = PathBuf::from(text.trim_end_matches('\0').trim().trim_matches('"'));
        if p.is_absolute() {
            out.push(p);
        }
    }
    out
}

#[cfg(not(windows))]
fn app_paths(_exe: &str) -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(windows)]
fn open_file(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    };
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let file: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // On its own thread: ShellExecute wants COM initialized as a
    // single-threaded apartment, which the server thread is not.
    std::thread::spawn(move || {
        let verb: Vec<u16> = "open\0".encode_utf16().collect();
        // SAFETY: both strings are NUL-terminated and outlive the call.
        unsafe {
            CoInitializeEx(
                std::ptr::null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            );
            // Above 32 means it started; SW_SHOWNORMAL is 1.
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            ) as isize
                > 32
        }
    })
    .join()
    .unwrap_or(false)
}

#[cfg(not(windows))]
fn open_file(path: &Path) -> bool {
    use std::process::Stdio;
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    match pathwarden_core::keystore::scrub_env(&mut pathwarden_core::spawn::quiet(program))
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            // Reap the launcher when it exits.
            std::thread::spawn(move || child.wait());
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_window_command_line_has_no_token() {
        let f = write("http://127.0.0.1:4242/?token=feedface0123").unwrap();
        let profile = std::env::temp_dir().join("pw profile");
        let args: Vec<String> = app_args(&profile, f.path())
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for a in &args {
            assert!(!a.contains("feedface") && !a.contains("token"), "{a}");
        }
        assert_eq!(args[0], format!("--app={}", file_url(f.path())));
        assert!(args[0].starts_with("--app=file:///") && args[0].ends_with("/open.html"));
        assert_eq!(args[1], format!("--user-data-dir={}", profile.display()));
    }

    #[test]
    fn file_urls() {
        if cfg!(windows) {
            assert_eq!(
                file_url(Path::new(r"C:\Users\A B\Temp\open.html")),
                "file:///C:/Users/A%20B/Temp/open.html"
            );
            assert_eq!(
                file_url(Path::new(r"C:\x\50%#?é.html")),
                "file:///C:/x/50%25%23%3F%C3%A9.html"
            );
        } else {
            assert_eq!(
                file_url(Path::new("/run/user/1000/a b/50%#?é.html")),
                "file:///run/user/1000/a%20b/50%25%23%3F%C3%A9.html"
            );
        }
    }

    #[test]
    fn browsers_are_looked_for_in_the_standard_places() {
        let env = |k: &str| -> Option<OsString> {
            match k {
                "ProgramFiles(x86)" => Some(r"C:\Program Files (x86)".into()),
                "ProgramFiles" => Some(r"C:\Program Files".into()),
                "LOCALAPPDATA" => Some(r"relative\is\ignored".into()),
                "HOME" => Some("/Users/me".into()),
                "PATH" => std::env::join_paths(["/usr/bin", "relative"]).ok(),
                _ => None,
            }
        };
        let programs: Vec<String> = candidates(&env)
            .iter()
            .map(|b| b.program.to_string_lossy().replace('\\', "/"))
            .collect();
        if cfg!(windows) {
            let edge = "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
            let chrome = "C:/Program Files/Google/Chrome/Application/chrome.exe";
            assert!(programs.iter().any(|p| p == edge), "{programs:?}");
            assert!(programs.iter().any(|p| p == chrome), "{programs:?}");
            // Every Edge comes before any Chrome.
            let last_edge = programs.iter().rposition(|p| p.ends_with("msedge.exe"));
            let first_chrome = programs.iter().position(|p| p.ends_with("chrome.exe"));
            assert!(last_edge < first_chrome);
            assert!(programs.iter().all(|p| !p.starts_with("relative")));
        } else if cfg!(target_os = "macos") {
            assert_eq!(
                programs[0],
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
            );
            assert!(programs
                .iter()
                .any(|p| p.starts_with("/Users/me/Applications/")));
        } else {
            assert_eq!(programs[0], "/usr/bin/google-chrome-stable");
            assert!(programs.iter().all(|p| p.starts_with("/usr/bin/")));
        }
        let mut unique = programs.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), programs.len());
    }

    #[test]
    fn default_mode_never_uses_an_app_window() {
        let o = Opener::new(BrowserMode::Default, Path::new("ws"));
        assert!(o.app_browser().is_none());
        assert!(Opener::default().app_browser().is_none());
    }

    #[test]
    fn launcher_is_private_and_cleaned_up() {
        let url = "http://127.0.0.1:4242/?token=00ff";
        let f = write(url).unwrap();
        let text = std::fs::read_to_string(f.path()).unwrap();
        assert!(text.contains(r#"content="0;url=http://127.0.0.1:4242/?token=00ff""#));
        let dir = f.path().parent().unwrap().to_path_buf();
        assert!(perms::readable_by_others(&dir).is_empty());
        assert!(perms::readable_by_others(f.path()).is_empty());
        drop(f);
        assert!(!dir.exists());
    }
}
