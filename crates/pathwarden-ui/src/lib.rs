//! `pathwarden ui`: a local web app for people who don't use the command
//! line. It runs on this computer only (bound to 127.0.0.1, opened with a
//! one-time link), and drives the same analysis and report as the CLI.
//!
//! - [`workspace`]: where runs, uploads and the config live
//! - [`security`]: the one-time link, sessions, Host and Origin checks
//! - [`launch`]: opening the browser without the link on a command line
//! - [`perms`]: keeping the workspace private to this account (shared with
//!   the collector, in `pathwarden-core`)
//! - [`jobs`]: analyses running in the background, with progress
//! - [`server`]: routes and handlers
//! - [`pages`]: the HTML pages
//! - [`brand`]: favicons, the web app manifest, and the old logo swapped
//!   out of reports saved before the Crown W
//! - [`collect`]: the Collect wizard (collect from Active Directory, then
//!   analyze)
//! - [`explore_ui`]: the graph explorer (a run's objects, paths and zone
//!   suggestions)

pub mod actions_app;
pub mod actions_ui;
pub mod add_data;
pub mod auto_pull;
pub mod brand;
pub mod collect;
pub mod connect;
pub mod connect_ui;
pub mod demo_runs;
pub mod diagnose;
pub mod encryption_ui;
pub mod env_remove;
pub mod env_where;
pub mod environments;
pub mod evidence_ui;
pub mod explore_ui;
pub mod history_ui;
pub mod home_overview;
pub mod jobs;
pub mod last_pull;
pub mod launch;
pub mod logs_ui;
pub mod pages;
pub use pathwarden_core::perms;
pub mod run_details;
pub mod run_list;
pub mod secret_json;
pub mod security;
pub mod server;
pub mod shared_runs;
pub mod sign_in;
pub mod workspace;

// Configuration screens: Settings, Privilege Zones and Plugins, the data
// they use from each run, and `pathwarden.toml` write-back.
pub mod plugins_ui;
pub mod run_data;
pub mod settings;
pub mod sync_ui;
pub mod zones_ui;

// OpenGraph sources: the Detected sources panel, coverage declarations and
// the Mappings page.
pub mod opengraph_ui;

// Retesting findings and progress over time.
pub mod progress;
pub mod retest_ui;

// Automate: the schedule, ticketing and where the run history is kept.
pub mod automate;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Args;

const AFTER_HELP: &str = "\
Security:
  The printed link works once, within 2 minutes; it is exchanged for a
  separate session cookie. Press Enter in this window for a new link.
  Sessions end after --idle-timeout without use, after --session-limit in
  any case, and when you click Stop Pathwarden or press Ctrl+C.
  The browser is opened through a private, short-lived file, so the link is
  never on a command line. By default that is an app window of Edge or
  Chrome with its own profile (in the workspace), so your usual browser
  extensions can't see the page; --browser default uses a normal tab.
  Closing the window doesn't stop Pathwarden: use Stop Pathwarden (the
  power button at the bottom of the left rail), or Ctrl+C here.
  The app can't choose where findings and runs go (a plugin's program or
  instance, where the run history is kept, connecting to a shared history)
  unless you start with --allow-destinations, or use pathwarden.toml and the
  command line.";

#[derive(Debug, Args)]
#[command(after_help = AFTER_HELP)]
pub struct UiArgs {
    /// The port to listen on (default: any free port).
    #[arg(long)]
    pub port: Option<u16>,
    /// Don't open a browser window; use the printed link.
    #[arg(long)]
    pub no_browser: bool,
    /// How to open the app (default: app).
    #[arg(long, value_enum, value_name = "HOW", num_args = 0..=1, default_missing_value = "app")]
    pub browser: Option<launch::BrowserMode>,
    /// The app's workspace: the folder for runs and uploads (default: a
    /// per-user data folder).
    #[arg(long, value_name = "DIR")]
    pub workspace: Option<PathBuf>,
    /// The run history folder, as `pathwarden run --state` (default: [state]
    /// in the workspace's pathwarden.toml, else pathwarden-state in the
    /// workspace).
    #[arg(long, value_name = "DIR")]
    pub state: Option<PathBuf>,
    /// Start in this environment (its name or ID; see Environments in the
    /// app) (default: the one used last).
    #[arg(long, value_name = "NAME")]
    pub env: Option<String>,
    /// Keep uploaded collector files after analysis (they are deleted by
    /// default).
    #[arg(long)]
    pub keep_uploads: bool,
    /// Let the pages choose where findings and runs go: plugins that run a
    /// program, a plugin's instance or project, where the run history is
    /// kept, and connecting to a shared history (off: only pathwarden.toml
    /// and the command line can).
    // `--allow-plugin-commands` was its name before 1.0.0-rc.1.
    #[arg(long, alias = "allow-plugin-commands")]
    pub allow_destinations: bool,
    /// Sign out after this long without use, like 30m, 8h or 1d.
    #[arg(long, value_name = "TIME", default_value = "8h", value_parser = parse_duration)]
    pub idle_timeout: Duration,
    /// Sign out this long after signing in, however busy.
    #[arg(long, value_name = "TIME", default_value = "24h", value_parser = parse_duration)]
    pub session_limit: Duration,
    /// The most one analysis may upload in total, in GB.
    #[arg(long, value_name = "GB", default_value_t = 16, value_parser = clap::value_parser!(u64).range(1..=1024))]
    pub max_upload: u64,
}

/// `90s`, `30m`, `8h`, `1d`, or a number of minutes.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => s.split_at(i),
        None => (s, "m"),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("{s:?}: use a number and a unit, like 30m, 8h or 1d"))?;
    let secs = match unit.trim() {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return Err(format!("{s:?}: the unit must be s, m, h or d")),
    };
    if secs == 0 || secs > 30 * 86_400 {
        return Err(format!("{s:?}: choose between 1 second and 30 days"));
    }
    Ok(Duration::from_secs(secs))
}

/// Starts the UI and blocks until it is stopped (Ctrl+C, or Stop Pathwarden).
pub fn run(args: UiArgs) -> anyhow::Result<()> {
    let (dir, notes, ws) = open_workspace(&args)?;
    let link = security::Token::generate()?;
    // One thread serves requests (they are light); analyses run on their own
    // thread and file writes on tokio's blocking pool.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the web server")?;
    let served = runtime.block_on(async move {
        let addr = bind_addr(args.port);
        let listener = listen(addr).with_context(|| format!("listening on {addr}"))?;
        let port = listener.local_addr()?.port();
        // Held until the server stops.
        let v6 = reserve_v6(port);
        let mut state = server::AppState::new(ws, link.clone(), port);
        state.localhost_host = !matches!(v6, V6::Taken);
        apply_args(&mut state, &args)?;
        logs_ui::start_session(&mut state, "the browser");
        // A git history is pulled from the first page load on.
        state.auto_pull.enable();
        let state = Arc::new(state);

        // The only places the link is shown: this console and the private
        // launcher file.
        let url = link_url(port, &link);
        println!("Pathwarden is running on this computer only.");
        println!();
        println!("  Open: {url}");
        println!();
        println!(
            "The link works once, within {}. Press Enter here for a new one.",
            security::human(state.sessions.policy.link_ttl)
        );
        println!("Workspace: {}", dir.display());
        for n in &notes {
            println!("{n}");
        }
        if state.allow_destinations {
            println!("The pages may choose where findings and runs go: plugin programs and instances, the run history (--allow-destinations).");
        }
        println!("Keep this window open while you use Pathwarden. To stop, press Ctrl+C here or use Stop Pathwarden (the power button at the bottom of the left rail).");
        let opener = (!args.no_browser).then(|| launch::Opener::new(args.browser.unwrap_or_default(), &dir));
        if let Some(opener) = &opener {
            open_and_say(&state, &url, opener);
        }
        new_links_on_enter(state.clone(), opener);
        tokio::spawn(expire_launcher(state.clone()));
        {
            let state = state.clone();
            tokio::task::spawn_blocking(move || warm(&state));
        }
        {
            let state = state.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                state.stop.notify_one();
            });
        }

        let shutdown = state.clone();
        axum::serve(listener, server::router(state.clone()))
            .with_graceful_shutdown(async move { shutdown.stop.notified().await })
            .await
            .context("web server")?;
        launch::discard(&state);
        logs_ui::end_session(&state);
        drop(v6);
        println!("Stopped.");
        Ok(())
    });
    // Not waiting for blocking tasks still running ([`warm`]).
    runtime.shutdown_background();
    served
}

/// Loads what the first pages need while the user opens the link
/// (blocking: start it on a blocking thread): the newest run's graph for
/// Explore, Zones and object search, and the history's key when the
/// history is encrypted and its passphrase is at hand without asking.
/// Anything that fails is left for the page that needs it, which says why.
/// What it loads, like anything a page loads, is let go after a while
/// without a request ([`run_data::release_when_idle`], started here).
pub fn warm(state: &server::AppState) {
    use pathwarden_core::{crypt, keystore};
    run_data::release_when_idle();
    let env = state.env_id();
    let ws = state.ws();
    // Stops when the user switches to another environment meanwhile.
    let current = || state.env_id() == env;
    std::thread::scope(|s| {
        // The key (a second of scrypt) beside the graph. Never anything
        // that could ask for the passphrase: Windows' credential store and
        // protected file don't, but elsewhere a locked keyring may, so
        // there only the environment variable is used.
        s.spawn(|| {
            if !(cfg!(windows) || matches!(keystore::from_env(), Ok(Some(_)))) {
                return;
            }
            let Ok(loc) = history_ui::locate(&ws, state.state_dir_for(&ws).as_deref()) else {
                return;
            };
            if crypt::is_encrypted(&loc.dir) && current() {
                let _ = crypt::key_for(&loc.dir);
            }
        });
        // The newest run, found once.
        let Some((_, dir)) = run_data::latest_with(&ws, run_data::OBJECTS_FILE) else {
            return;
        };
        if current() {
            explore_ui::warm(&dir);
        }
        // Loaded with Explore's, unless the run can't be explored.
        if current() {
            run_data::graph(&dir);
        }
        if current() && dir.join(run_data::EVENT_FILE).is_file() {
            run_data::findings(&dir);
        }
    });
}

/// Finds (or creates) the workspace, keeps it private, and opens it.
/// Returns its folder and anything worth telling the user about it.
fn open_workspace(args: &UiArgs) -> anyhow::Result<(PathBuf, Vec<String>, workspace::Workspace)> {
    let (dir, default) = match &args.workspace {
        Some(d) => (d.clone(), false),
        None => (workspace::default_dir()?, true),
    };
    let notes = secure_workspace(&dir, default)?;
    let ws = workspace::Workspace::open(&dir)?;
    Ok((dir, notes, ws))
}

/// The options that apply whichever way the UI is reached.
fn apply_args(state: &mut server::AppState, args: &UiArgs) -> anyhow::Result<()> {
    // Before anything else: an environment with the reserved ID `removed`
    // gets another, and runs saved for an environment while it was being
    // removed join it (with `--state`, so that folder is never taken).
    // A first environment's history only in --state makes it used.
    crate::environments::set_default_state(state.workspace.root(), args.state.as_deref());
    // What stops it is said here and on the Environments page, as
    // `pathwarden env list` says it: names shown safe for a terminal, the
    // CLI's warning style.
    if let Some(problem) = env_remove::sweep_on_start(state.workspace.root(), args.state.as_deref())
    {
        let warn = anstyle::Style::new().fg_color(Some(anstyle::AnsiColor::Yellow.into()));
        anstream::eprintln!(
            "{warn}warning:{warn:#} {}",
            pathwarden_core::text::terminal_safe(&problem.to_string())
        );
    }
    if let Some(name) = &args.env {
        let reg = state.workspace.registry();
        let Some(env) = reg.find(name) else {
            let names: Vec<&str> = reg.environments.iter().map(|e| e.name.as_str()).collect();
            anyhow::bail!(
                "no environment named {name:?} (there is: {}); create one on the Environments page",
                names.join(", ")
            );
        };
        state.set_env(&env.id);
    }
    // Reads on disk that can't be resumed any more, in the
    // background: only Pathwarden's files, never a read in progress.
    {
        let ws = state.workspace.clone();
        std::thread::spawn(move || crate::collect::sweep_stopped_reads(&ws));
    }
    state.keep_uploads = args.keep_uploads;
    state.jobs.set_state_dir(args.state.clone());
    state.allow_destinations = args.allow_destinations;
    state.sessions.policy.idle = args.idle_timeout;
    state.sessions.policy.absolute = args.session_limit.max(args.idle_timeout);
    state.limits.total = args.max_upload << 30;
    state.limits.per_file = state.limits.per_file.min(state.limits.total);
    Ok(())
}

/// The UI's state for an embedded window (experimental `pathwarden ui
/// --window`, in the `pathwarden-desktop` crate): the same workspace and
/// options as [`run`], with [`security::Transport::Embedded`] for `origin`
/// and no listener. Serve it with [`server::router`]. Also returns the
/// workspace folder and notes about it, as [`run`] prints them.
pub fn embedded(
    args: &UiArgs,
    origin: &str,
) -> anyhow::Result<(Arc<server::AppState>, PathBuf, Vec<String>)> {
    let (dir, notes, ws) = open_workspace(args)?;
    let mut state = server::AppState::embedded(ws, origin)?;
    apply_args(&mut state, args)?;
    logs_ui::start_session(&mut state, "the desktop window");
    Ok((Arc::new(state), dir, notes))
}

/// Opens the link (through the launcher file) and says how.
fn open_and_say(state: &server::AppState, url: &str, opener: &launch::Opener) {
    match launch::open_browser(state, url, opener) {
        Some(launch::Opened::App) => println!(
            "Opened in its own {} window (a separate profile in the workspace). Closing it \
             doesn't stop Pathwarden: use Stop Pathwarden (the power button at the bottom of \
             the left rail), or Ctrl+C here.",
            opener.app_browser().map_or("browser", |b| b.name)
        ),
        Some(launch::Opened::Default) => {}
        None => println!("Couldn't open a browser; copy the link above into one."),
    }
}

fn link_url(port: u16, link: &security::Token) -> String {
    format!("http://127.0.0.1:{port}/?token={}", link.expose())
}

/// Makes the workspace private to this account where that is safe, and says
/// what it found. A folder Pathwarden creates (or its own default folder) is
/// made private outright. An existing `--workspace` keeps its permissions on
/// Windows, since another account (a scheduled task's) may need it; a
/// warning names who else can read it.
fn secure_workspace(dir: &Path, default: bool) -> anyhow::Result<Vec<String>> {
    let mut notes = Vec::new();
    if !dir.exists() {
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        match perms::create_private_dir(dir) {
            Ok(()) => {}
            // Created meanwhile: treat it as existing.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
        }
        return Ok(notes);
    }
    let others = perms::readable_by_others(dir);
    // On Windows, setting the permissions rewrites those of every file in
    // the workspace (thousands, with the app window's browser profile): a
    // second or more at each start. A folder already private is left as
    // it is ([`perms::is_private_dir`] fails closed).
    if cfg!(windows) && default && perms::is_private_dir(dir) {
        return Ok(notes);
    }
    if cfg!(unix) || default {
        if let Err(e) = perms::make_private(dir) {
            notes.push(format!(
                "Warning: couldn't make the workspace private to your account: {e}"
            ));
        } else if !others.is_empty() {
            notes.push(format!(
                "Note: the workspace could be read by {}. It is now private to your account; \
                 anything already in it may have been read.",
                others.join(", ")
            ));
        }
    } else if !others.is_empty() {
        notes.push(format!(
            "Warning: other accounts can read this workspace ({}). Reports in it describe how to \
             attack your directory. To make it private to you, run:\n  {}",
            others.join(", "),
            perms::private_hint(dir)
        ));
    }
    Ok(notes)
}

/// Where the server listens: loopback only, so nothing else on the
/// network can connect; `port`, or any free one.
fn bind_addr(port: Option<u16>) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port.unwrap_or(0)))
}

/// Binds the listener. On Windows the socket is exclusive
/// (`SO_EXCLUSIVEADDRUSE`), so no other program can bind the same port to
/// intercept connections.
fn listen(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    exclusive(&socket)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

/// What [`reserve_v6`] found at `[::1]` on the server's port.
enum V6 {
    /// Held here: bound, never listening, so nothing else can listen there.
    Held(#[allow(dead_code)] tokio::net::TcpSocket),
    /// This computer has no IPv6 loopback: nothing can listen there.
    Unavailable,
    /// Another program holds it: `localhost` may reach that program.
    Taken,
}

/// Browsers try `[::1]` first for `localhost`, and the server listens on
/// 127.0.0.1 only: `[::1]` on the same port is held (bound, exclusively on
/// Windows, and never listening, so a connection there is refused at once
/// and the browser goes on to 127.0.0.1). When another program already
/// holds it, the server refuses `localhost` in the Host header.
fn reserve_v6(port: u16) -> V6 {
    let Ok(socket) = tokio::net::TcpSocket::new_v6() else {
        return V6::Unavailable;
    };
    if exclusive(&socket).is_err() {
        return V6::Taken;
    }
    match socket.bind(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))) {
        Ok(()) => V6::Held(socket),
        // No `::1` here.
        Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => V6::Unavailable,
        // In use (on Windows an exclusive holder makes it access denied):
        // `localhost` isn't trusted then.
        Err(_) => V6::Taken,
    }
}

/// On Windows `SO_EXCLUSIVEADDRUSE`, so no other program can bind the same
/// address and port.
fn exclusive(socket: &tokio::net::TcpSocket) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, SOCKET, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        };
        let on: i32 = 1;
        // SAFETY: a valid socket, and a 4-byte BOOL option value.
        let rc = unsafe {
            setsockopt(
                socket.as_raw_socket() as SOCKET,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&on as *const i32).cast(),
                std::mem::size_of::<i32>() as i32,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(not(windows))]
    let _ = socket;
    Ok(())
}

/// Each Enter in the console prints a fresh one-time link (and opens it),
/// replacing any unused one. Stops when stdin closes.
fn new_links_on_enter(state: Arc<server::AppState>, opener: Option<launch::Opener>) {
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match std::io::stdin().read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let Ok(link) = state.sessions.new_link() else {
                continue;
            };
            launch::discard(&state);
            let url = link_url(state.port, &link);
            println!(
                "  New link (works once, within {}): {url}",
                security::human(state.sessions.policy.link_ttl)
            );
            if let Some(opener) = &opener {
                open_and_say(&state, &url, opener);
            }
        }
    });
}

/// Deletes the launcher file once its link has expired.
async fn expire_launcher(state: Arc<server::AppState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        if !state.launch_file.is_empty() && state.sessions.link_spent() {
            launch::discard(&state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("8h"), Ok(Duration::from_secs(8 * 3600)));
        assert_eq!(parse_duration("30m"), Ok(Duration::from_secs(1800)));
        assert_eq!(parse_duration("45"), Ok(Duration::from_secs(45 * 60)));
        assert_eq!(parse_duration("1d"), Ok(Duration::from_secs(86_400)));
        assert!(parse_duration("0m").is_err());
        assert!(parse_duration("8x").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("31d").is_err());
    }

    /// `[::1]` on the server's port is held (where browsers try
    /// `localhost` first), so nothing else can listen there; held by
    /// another program already, it is reported, and the server then
    /// refuses `localhost` in the Host header.
    #[test]
    fn the_ipv6_loopback_port_is_held() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = listen(bind_addr(None)).unwrap();
            let port = listener.local_addr().unwrap().port();
            match reserve_v6(port) {
                V6::Unavailable => {} // no IPv6 loopback here: nothing to hold
                V6::Taken => panic!("a fresh port was taken"),
                V6::Held(_held) => {
                    let other = tokio::net::TcpSocket::new_v6().unwrap();
                    let at = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));
                    assert!(other.bind(at).is_err(), "bound beside it");
                    assert!(matches!(reserve_v6(port), V6::Taken));
                }
            }
        });
    }

    /// The server listens on 127.0.0.1 only, on the port asked for or any
    /// free one (gap 14), and on Windows no other program can bind
    /// that port beside it, not even with `SO_REUSEADDR`.
    #[test]
    fn the_listener_is_loopback_only_and_exclusive() {
        assert_eq!(bind_addr(None), "127.0.0.1:0".parse().unwrap());
        assert_eq!(bind_addr(Some(4242)), "127.0.0.1:4242".parse().unwrap());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = listen(bind_addr(None)).unwrap();
            let addr = listener.local_addr().unwrap();
            assert!(addr.ip().is_loopback(), "{addr}");
            assert_ne!(addr.port(), 0);
            // Nobody else gets the port while it listens.
            let again = tokio::net::TcpSocket::new_v4().unwrap();
            if cfg!(windows) {
                again.set_reuseaddr(true).unwrap();
            }
            assert!(again.bind(addr).is_err(), "bound beside it");
            assert!(listen(addr).is_err());
            #[cfg(windows)]
            {
                use std::os::windows::io::AsRawSocket;
                use windows_sys::Win32::Networking::WinSock::{
                    getsockopt, SOCKET, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                };
                let mut on: i32 = 0;
                let mut len = std::mem::size_of::<i32>() as i32;
                // SAFETY: a valid socket, and a 4-byte BOOL option value.
                let rc = unsafe {
                    getsockopt(
                        listener.as_raw_socket() as SOCKET,
                        SOL_SOCKET,
                        SO_EXCLUSIVEADDRUSE,
                        (&mut on as *mut i32).cast(),
                        &mut len,
                    )
                };
                assert_eq!(rc, 0);
                assert_eq!(on, 1, "SO_EXCLUSIVEADDRUSE is set");
                // A socket on every address may share the port, but
                // connections to 127.0.0.1 still come to this one.
                let any = tokio::net::TcpSocket::new_v4().unwrap();
                any.set_reuseaddr(true).unwrap();
                let wild = SocketAddr::from((Ipv4Addr::UNSPECIFIED, addr.port()));
                if any.bind(wild).is_ok() {
                    let other = any.listen(8).unwrap();
                    let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
                    let ours =
                        tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;
                    assert!(ours.is_ok(), "the connection went elsewhere");
                    let theirs =
                        tokio::time::timeout(Duration::from_millis(200), other.accept()).await;
                    assert!(theirs.is_err(), "the other socket got a connection");
                }
            }
        });
    }

    /// A default workspace that isn't private is made private; one that is
    /// already private is left as it is, with nothing to say.
    #[test]
    fn a_default_workspace_is_made_private_once() {
        let tmp = std::env::temp_dir().join(format!(
            "pw-secure-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let ws = tmp.join("Pathwarden");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("a.txt"), "x").unwrap();
        if cfg!(windows) {
            // Readable by Users: not private to this account. (The temp
            // folder's own permissions may be private already, as for an
            // elevated process, whose folders Administrators own.)
            let granted = pathwarden_core::spawn::quiet("icacls")
                .arg(&ws)
                .args(["/grant", "*S-1-5-32-545:(OI)(CI)R"])
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap()
                .success();
            assert!(granted);
            assert!(!perms::is_private_dir(&ws));
        }
        secure_workspace(&ws, true).unwrap();
        assert!(perms::is_private_dir(&ws));
        assert!(secure_workspace(&ws, true).unwrap().is_empty());
        assert!(perms::is_private_dir(&ws));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
