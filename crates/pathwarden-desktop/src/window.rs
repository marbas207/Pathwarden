//! The window: a `tao` event loop with one `wry` webview per window, the
//! custom protocol wired to the [`bridge`], and the native pieces (file
//! pickers, the Save dialog, opening other sites in the default browser).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use axum::Router;
use pathwarden_ui::UiArgs;
use tao::dpi::{LogicalPosition, LogicalSize, PhysicalSize};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy, EventLoopWindowTarget};
use tao::platform::run_return::EventLoopExtRunReturn;
use tao::platform::windows::{IconExtWindows, WindowBuilderExtWindows};
use tao::window::{Icon, Window, WindowBuilder, WindowId};
use wry::{
    DragDropEvent, NewWindowResponse, RequestAsyncResponder, WebContext, WebView, WebViewBuilder,
    WebViewBuilderExtWindows, WebViewId,
};

use crate::bridge::{self, SCHEME};
use crate::guard::{self, Ask, NewWindow};
use crate::session;

/// Added to every page the window shows (see the file for what it does).
const DESKTOP_JS: &str = include_str!("desktop.js");

/// Where the WebView2 Runtime can be downloaded, for the message when it
/// is missing: Microsoft's page (Evergreen Bootstrapper and Standalone
/// Installer), and the Evergreen Bootstrapper itself.
const WEBVIEW2_PAGE: &str = "https://developer.microsoft.com/microsoft-edge/webview2/#download";
const WEBVIEW2_BOOTSTRAPPER: &str = "https://go.microsoft.com/fwlink/p/?LinkId=2124703";

/// WebView2's command-line arguments as `wry` sets them by default (no
/// "mini menu", no SmartScreen lookups), kept when a debug build adds
/// remote debugging.
#[cfg(debug_assertions)]
const WRY_DEFAULT_ARGS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection";

/// Debug builds only, for the end-to-end smoke test
/// (`crates/pathwarden-cli/tests/desktop_smoke.rs`): a port for WebView2's
/// remote debugging, and whether to keep the window hidden. Release builds
/// ignore both.
#[cfg(debug_assertions)]
pub const TEST_DEBUG_PORT: &str = "PATHWARDEN_DESKTOP_TEST_DEBUG_PORT";
#[cfg(debug_assertions)]
pub const TEST_HIDDEN: &str = "PATHWARDEN_DESKTOP_TEST_HIDDEN";

/// What the webviews and the Stop watcher ask of the event loop.
enum UserEvent {
    /// Stop Pathwarden was clicked, or Ctrl+C: close everything.
    Stop,
    /// An app page asked for a new window (`target="_blank"`).
    OpenWindow(String),
    /// Save the answer at this app URL with a native Save dialog.
    Save(String),
    /// A native file (or folder) picker for the Analyze page.
    Pick {
        folder: bool,
        responder: RequestAsyncResponder,
    },
    /// Files dropped on a window: their paths.
    Dropped(WindowId, Vec<PathBuf>),
}

/// What every webview's callbacks share.
struct Shared {
    runtime: tokio::runtime::Handle,
    router: Router,
    proxy: Mutex<EventLoopProxy<UserEvent>>,
}

impl Shared {
    fn send(&self, event: UserEvent) {
        let proxy = self.proxy.lock().unwrap_or_else(|e| e.into_inner());
        let _ = proxy.send_event(event);
    }

    /// The custom protocol: the window's own requests (`/__desktop/...`),
    /// and everything else through the router.
    fn handle(&self, req: Request<Vec<u8>>, responder: RequestAsyncResponder) {
        if req.uri().path().starts_with("/__desktop/") {
            self.window_request(req, responder);
            return;
        }
        let router = self.router.clone();
        self.runtime.spawn(async move {
            responder.respond(bridge::serve(router, req).await);
        });
    }

    fn window_request(&self, req: Request<Vec<u8>>, responder: RequestAsyncResponder) {
        let ask = guard::desktop_request(
            req.method(),
            req.headers().get(header::ORIGIN).map(HeaderValue::as_bytes),
            req.uri().path(),
            req.body(),
        );
        match ask {
            Ask::Refused => {
                responder.respond(bridge::json_error(StatusCode::FORBIDDEN, "Refused."))
            }
            Ask::PickFile => self.send(UserEvent::Pick {
                folder: false,
                responder,
            }),
            Ask::PickFolder => self.send(UserEvent::Pick {
                folder: true,
                responder,
            }),
            Ask::Save(target) => {
                if let Some(url) = target {
                    self.send(UserEvent::Save(url));
                }
                let mut r = Response::new(Vec::new());
                *r.status_mut() = StatusCode::NO_CONTENT;
                responder.respond(r);
            }
            Ask::NotFound => {
                responder.respond(bridge::json_error(StatusCode::NOT_FOUND, "Not found."))
            }
        }
    }
}

pub fn run(args: UiArgs) -> anyhow::Result<()> {
    // WebView2 is part of Windows 11 and current Windows 10, but not of
    // Windows Server: without it, say how to get it and use the browser.
    let version = match wry::webview_version() {
        Ok(v) => v,
        Err(e) => {
            no_runtime(&e.to_string());
            return pathwarden_ui::run(args);
        }
    };
    // A release build never lets the environment hand WebView2 extra
    // arguments (such as remote debugging); see docs/ui.md.
    #[cfg(not(debug_assertions))]
    std::env::remove_var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
    let (state, dir, notes) = pathwarden_ui::embedded(&args, bridge::ORIGIN)?;
    // A git history is pulled from the first page load on, as in the browser.
    state.auto_pull.enable();

    // Started from Explorer, the console is Pathwarden's own and would only
    // show the lines below: close it, and say what goes wrong in a message
    // box instead. Started from a terminal, the console stays as it is.
    let own_console = session::own_console();
    if own_console {
        session::release_console();
    }
    let result = open(state, &dir, &notes, &version);
    if let (Err(e), true) = (&result, own_console) {
        rfd::MessageDialog::new()
            .set_title("Pathwarden")
            .set_description(format!("Pathwarden stopped: {e:#}"))
            .set_level(rfd::MessageLevel::Error)
            .show();
    }
    result
}

/// Says the WebView2 Runtime is missing and how to install it: in the
/// console, and in a message box when the console is Pathwarden's own
/// (started from Explorer), where it would close before it could be read.
fn no_runtime(error: &str) {
    let text = format!(
        "The Pathwarden window needs the Microsoft Edge WebView2 Runtime, which this computer \
         doesn't have ({error}). Windows 11 and current Windows 10 include it; Windows Server \
         doesn't.\n\n\
         To use the window, install the Evergreen WebView2 Runtime (x64), then start Pathwarden \
         again:\n\
         - Microsoft's download page: {WEBVIEW2_PAGE}\n\
         - the Evergreen Bootstrapper itself: {WEBVIEW2_BOOTSTRAPPER}\n\
         - or, from a terminal: winget install Microsoft.EdgeWebView2Runtime\n\
         Without internet access, use the Evergreen Standalone Installer from the download page.\n\n\
         Opening Pathwarden in the browser instead."
    );
    eprintln!("{text}\n");
    if session::own_console() {
        rfd::MessageDialog::new()
            .set_title("Pathwarden: WebView2 Runtime needed")
            .set_description(&text)
            .set_level(rfd::MessageLevel::Warning)
            .show();
    }
}

/// Opens the window and runs it until it is closed.
fn open(
    state: Arc<pathwarden_ui::server::AppState>,
    dir: &std::path::Path,
    notes: &[String],
    version: &str,
) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("starting the UI")?;

    let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let shared = Arc::new(Shared {
        runtime: runtime.handle().clone(),
        router: pathwarden_ui::server::router(state.clone()),
        proxy: Mutex::new(event_loop.create_proxy()),
    });

    {
        let state = state.clone();
        runtime.spawn_blocking(move || pathwarden_ui::warm(&state));
    }

    // Stop Pathwarden (in the page) and Ctrl+C close the window.
    {
        let on_ctrl_c = state.clone();
        runtime.spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            on_ctrl_c.stop.notify_one();
        });
        let state = state.clone();
        let shared = shared.clone();
        runtime.spawn(async move {
            state.stop.notified().await;
            // Long enough to show the "stopped" page.
            tokio::time::sleep(Duration::from_millis(600)).await;
            shared.send(UserEvent::Stop);
        });
    }

    println!("Pathwarden is open in its own window. It has no network port: only that window");
    println!("can reach it. Close the window, or use Stop Pathwarden, to stop.");
    println!("Workspace: {}", dir.display());
    println!("WebView2 Runtime: {version}");
    for n in notes {
        println!("{n}");
    }

    // The WebView2 profile (cache, local storage) stays in the workspace,
    // which is private to this account.
    let mut context = WebContext::new(Some(dir.join("webview2")));
    let main = open_window(
        &event_loop,
        &mut context,
        &shared,
        "pathwarden://localhost/",
    )?;
    let main_id = main.0.id();
    let mut windows: HashMap<WindowId, (Window, WebView)> = HashMap::from([(main_id, main)]);

    event_loop.run_return(|event, target, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::WindowEvent {
                window_id,
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if window_id == main_id {
                    windows.clear();
                    *control_flow = ControlFlow::Exit;
                } else {
                    windows.remove(&window_id);
                }
            }
            Event::UserEvent(UserEvent::Stop) => {
                windows.clear();
                *control_flow = ControlFlow::Exit;
            }
            Event::UserEvent(UserEvent::OpenWindow(url)) => {
                match open_window(target, &mut context, &shared, &url) {
                    Ok(w) => {
                        windows.insert(w.0.id(), w);
                    }
                    Err(e) => eprintln!("Could not open a window: {e:#}"),
                }
            }
            Event::UserEvent(UserEvent::Pick { folder, responder }) => {
                let picked = windows
                    .get(&main_id)
                    .map(|(w, _)| pick(w, folder))
                    .unwrap_or_default();
                let paths: Vec<String> = picked.iter().map(|p| p.display().to_string()).collect();
                let body = serde_json::json!({ "paths": paths });
                let mut r = Response::new(body.to_string().into_bytes());
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                responder.respond(r);
            }
            Event::UserEvent(UserEvent::Save(url)) => {
                if let Some((w, _)) = windows.get(&main_id) {
                    save(&shared, w, &url);
                }
            }
            Event::UserEvent(UserEvent::Dropped(id, paths)) => {
                if let Some((_, webview)) = windows.get(&id) {
                    let paths: Vec<String> =
                        paths.iter().map(|p| p.display().to_string()).collect();
                    let json = serde_json::to_string(&paths).unwrap_or_else(|_| "[]".into());
                    let _ = webview.evaluate_script(&format!(
                        "window.__pathwardenDropped && window.__pathwardenDropped({json})"
                    ));
                }
            }
            _ => {}
        }
    });
    drop(windows);
    drop(context);
    runtime.shutdown_timeout(Duration::from_secs(2));
    println!("Stopped.");
    Ok(())
}

/// The smallest a window can be made, in logical pixels.
const MIN_WIDTH: f64 = 480.0;
const MIN_HEIGHT: f64 = 360.0;
/// The share of the monitor's work area a new window takes, and the most
/// it takes on a large monitor, in logical pixels.
const SHARE: f64 = 0.9;
const MAX_WIDTH: f64 = 1680.0;
const MAX_HEIGHT: f64 = 1050.0;
/// Below this work area width (logical pixels), a new window opens
/// maximized: 90% of it would make the pages scroll sideways.
const MAXIMIZE_BELOW: f64 = 1400.0;
/// Without a monitor to measure (none reported).
const FALLBACK: (f64, f64) = (1320.0, 880.0);

/// Where a new window goes, in logical pixels.
#[derive(Debug, PartialEq)]
struct Placement {
    size: LogicalSize<f64>,
    /// Its top left corner, centered in the work area; `None` leaves it to
    /// Windows.
    position: Option<LogicalPosition<f64>>,
    maximized: bool,
}

/// The work area of the primary monitor (the screen without the taskbar)
/// as `(x, y, width, height)` in logical pixels; the whole monitor when the
/// work area can't be read, `None` with no monitor.
fn work_area(target: &EventLoopWindowTarget<UserEvent>) -> Option<(f64, f64, f64, f64)> {
    use tao::platform::windows::MonitorHandleExtWindows;
    use windows_sys::Win32::Graphics::Gdi::{GetMonitorInfoW, HMONITOR, MONITORINFO};
    let monitor = target
        .primary_monitor()
        .or_else(|| target.available_monitors().next())?;
    let scale = monitor.scale_factor().max(0.1);
    let mut info = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        rcMonitor: windows_sys::Win32::Foundation::RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        rcWork: windows_sys::Win32::Foundation::RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        dwFlags: 0,
    };
    // SAFETY: `info` is a MONITORINFO with its size set, as the call needs;
    // the handle is the monitor tao just listed.
    let ok = unsafe { GetMonitorInfoW(monitor.hmonitor() as HMONITOR, &mut info) } != 0;
    let (x, y, w, h) =
        if ok && info.rcWork.right > info.rcWork.left && info.rcWork.bottom > info.rcWork.top {
            let r = info.rcWork;
            (r.left, r.top, r.right - r.left, r.bottom - r.top)
        } else {
            let (p, s) = (monitor.position(), monitor.size());
            (p.x, p.y, s.width as i32, s.height as i32)
        };
    Some((
        f64::from(x) / scale,
        f64::from(y) / scale,
        f64::from(w) / scale,
        f64::from(h) / scale,
    ))
}

/// A new window's place in `work` (logical `(x, y, width, height)`):
/// 90% of it, centered, at most [`MAX_WIDTH`] × [`MAX_HEIGHT`]; maximized
/// on a work area narrower than [`MAXIMIZE_BELOW`]; the old fixed size
/// when there is no monitor to measure.
fn placement(work: Option<(f64, f64, f64, f64)>) -> Placement {
    let Some((x, y, w, h)) = work.filter(|&(_, _, w, h)| w > 0.0 && h > 0.0) else {
        return Placement {
            size: LogicalSize::new(FALLBACK.0, FALLBACK.1),
            position: None,
            maximized: false,
        };
    };
    let width = (w * SHARE).min(MAX_WIDTH).max(MIN_WIDTH.min(w));
    let height = (h * SHARE).min(MAX_HEIGHT).max(MIN_HEIGHT.min(h));
    Placement {
        size: LogicalSize::new(width.round(), height.round()),
        position: Some(LogicalPosition::new(
            (x + (w - width) / 2.0).round(),
            (y + (h - height) / 2.0).round(),
        )),
        maximized: w < MAXIMIZE_BELOW,
    }
}

/// A window showing `url` (an app page), with every guard on its webview.
fn open_window(
    target: &EventLoopWindowTarget<UserEvent>,
    context: &mut WebContext,
    shared: &Arc<Shared>,
    url: &str,
) -> anyhow::Result<(Window, WebView)> {
    #[cfg(debug_assertions)]
    let visible = std::env::var_os(TEST_HIDDEN).is_none();
    #[cfg(not(debug_assertions))]
    let visible = true;
    let place = placement(work_area(target));
    let mut builder = WindowBuilder::new()
        .with_title("Pathwarden")
        .with_inner_size(place.size)
        .with_min_inner_size(LogicalSize::new(MIN_WIDTH, MIN_HEIGHT))
        .with_maximized(place.maximized)
        .with_window_icon(icon(true))
        .with_taskbar_icon(icon(false))
        .with_visible(visible);
    if let Some(at) = place.position {
        builder = builder.with_position(at);
    }
    let window = builder.build(target).context("opening a window")?;
    let id = window.id();

    let protocol = {
        let shared = shared.clone();
        move |_: WebViewId, req: Request<Vec<u8>>, responder: RequestAsyncResponder| {
            shared.handle(req, responder)
        }
    };
    let new_window = {
        let shared = shared.clone();
        move |url: String, _| {
            match guard::new_window(&url) {
                NewWindow::App(url) => shared.send(UserEvent::OpenWindow(url)),
                NewWindow::Elsewhere(url) => open_elsewhere(&url),
                NewWindow::Refused => {}
            }
            NewWindowResponse::Deny
        }
    };
    let download = {
        let shared = shared.clone();
        move |url: String, _: &mut PathBuf| {
            if let Some(url) = guard::download(&url) {
                shared.send(UserEvent::Save(url));
            }
            false
        }
    };
    let dropped = {
        let shared = shared.clone();
        move |e: DragDropEvent| {
            if let DragDropEvent::Drop { paths, .. } = e {
                shared.send(UserEvent::Dropped(id, paths));
            }
            true
        }
    };

    let builder = WebViewBuilder::new_with_web_context(context);
    #[cfg(debug_assertions)]
    let builder = match std::env::var(TEST_DEBUG_PORT) {
        Ok(port) if port.parse::<u16>().is_ok() => builder.with_additional_browser_args(format!(
            "{WRY_DEFAULT_ARGS} --remote-debugging-port={port}"
        )),
        _ => builder,
    };
    let webview = builder
        .with_https_scheme(true)
        .with_asynchronous_custom_protocol(SCHEME.into(), protocol)
        .with_url(url)
        .with_initialization_script(DESKTOP_JS)
        // Never leave the app: other sites open in the default browser.
        .with_navigation_handler(|url| {
            if guard::navigation_allowed(&url) {
                return true;
            }
            open_elsewhere(&url);
            false
        })
        .with_new_window_req_handler(new_window)
        .with_download_started_handler(download)
        .with_drag_drop_handler(dropped)
        .with_devtools(guard::DEVTOOLS)
        .with_general_autofill_enabled(false)
        .with_browser_extensions_enabled(false)
        .with_background_color((21, 23, 28, 255))
        .with_visible(visible)
        .build(&window)
        .context("starting WebView2")?;
    Ok((window, webview))
}

/// The icon embedded in pathwarden.exe (crates/pathwarden-cli/build.rs), at
/// the title bar's size or (`small` false) Windows' default icon size, for
/// the taskbar and Alt+Tab. None when the program has no icon resource.
fn icon(small: bool) -> Option<Icon> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSMICON};
    let size = if small {
        // SAFETY: a plain query.
        let px = unsafe { GetSystemMetrics(SM_CXSMICON) };
        u32::try_from(px)
            .ok()
            .filter(|&px| px > 0)
            .map(|px| PhysicalSize::new(px, px))
    } else {
        None
    };
    Icon::from_resource(1, size).ok()
}

/// A native picker for collector files (or folders of them); one or more.
fn pick(parent: &Window, folder: bool) -> Vec<PathBuf> {
    let dialog = rfd::FileDialog::new().set_parent(parent);
    let picked = if folder {
        dialog
            .set_title("Choose the folders with the collector files")
            .pick_folders()
    } else {
        dialog
            .set_title("Choose collector output")
            .add_filter("SharpHound or RustHound-CE output", &["zip", "json"])
            .pick_files()
    };
    picked.unwrap_or_default()
}

/// Fetches an app URL through the router and saves it where the user says.
fn save(shared: &Shared, parent: &Window, url: &str) {
    let path = guard::save_path(url);
    let Ok(req) = Request::get(path).body(Vec::new()) else {
        return;
    };
    let res = shared
        .runtime
        .block_on(bridge::serve(shared.router.clone(), req));
    if !res.status().is_success() {
        message(parent, "Pathwarden could not prepare that download.");
        return;
    }
    let name = guard::save_name(
        res.headers()
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok()),
        path,
    );
    let Some(dest) = rfd::FileDialog::new()
        .set_parent(parent)
        .set_title("Save")
        .set_file_name(name)
        .save_file()
    else {
        return;
    };
    if let Err(e) = std::fs::write(&dest, res.body()) {
        message(parent, &format!("Could not save {}: {e}", dest.display()));
    }
}

fn message(parent: &Window, text: &str) {
    rfd::MessageDialog::new()
        .set_parent(parent)
        .set_title("Pathwarden")
        .set_description(text)
        .set_level(rfd::MessageLevel::Warning)
        .show();
}

/// Opens a link to another site in the default browser: web and mail links
/// only, never a file, a program or another protocol handler.
fn open_elsewhere(url: &str) {
    if !guard::web_link(url) {
        return;
    }
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (verb, file) = (wide("open"), wide(url));
    // SAFETY: NUL-terminated UTF-16 strings that outlive the call.
    unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 90% of the work area, centered and capped; maximized on a narrow
    /// one; the old size without a monitor.
    #[test]
    fn a_new_window_fits_the_monitor() {
        // 1920 x 1080 at 100% with a 48 px taskbar.
        let p = placement(Some((0.0, 0.0, 1920.0, 1032.0)));
        assert_eq!(p.size, LogicalSize::new(1680.0, 929.0));
        assert_eq!(p.position, Some(LogicalPosition::new(120.0, 52.0)));
        assert!(!p.maximized);
        // 2560 x 1440 at 125%: 2048 x 1113.6 logical, capped.
        let p = placement(Some((0.0, 0.0, 2048.0, 1113.6)));
        assert_eq!(p.size, LogicalSize::new(1680.0, 1002.0));
        assert!(!p.maximized);
        // A second monitor to the left: centered on it.
        let p = placement(Some((-1600.0, 0.0, 1600.0, 860.0)));
        assert_eq!(p.size, LogicalSize::new(1440.0, 774.0));
        assert_eq!(p.position, Some(LogicalPosition::new(-1520.0, 43.0)));
        // 1366 x 768, or 1920 x 1080 at 150% (1280 logical): maximized.
        for w in [1366.0, 1280.0] {
            let p = placement(Some((0.0, 0.0, w, 720.0)));
            assert!(p.maximized, "{w}");
            assert!(p.size.width >= MIN_WIDTH && p.size.width <= w, "{w}");
        }
        let p = placement(None);
        assert_eq!(p.size, LogicalSize::new(1320.0, 880.0));
        assert_eq!(p.position, None);
        assert!(!p.maximized);
    }
}
