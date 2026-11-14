//! Pulling a git history while the app is open.
//!
//! - **When**: on the first page load of a session (never when the server
//!   starts with no browser), then every `[state] refresh` minutes (5 by
//!   default), read again at each tick. Pull now, the Where to keep it
//!   Save and a switch to another environment start the wait again; a
//!   switch, and a passphrase entered on Runs, pull at once.
//! - **Pauses** when no page has checked in for twice the interval; a page
//!   that comes back pulls at once if a pull is overdue.
//! - **Skips** a tick when the history is a folder, an analysis is running,
//!   the environment is the demo, or the history's lock is held (taken
//!   without waiting). A pull that fails is tried again at the same
//!   interval, with no backoff ([`crate::last_pull`] says so).
//! - **Tells** open pages: each environment has a pull counter and what
//!   each pull brought (runs, settings sections, runs removed here). The
//!   shell stamps the counter on the page; `app.js` asks
//!   `GET /api/history/pulled?since=N` every 30 seconds while the tab is
//!   shown, refreshes the footer in place and shows the page's note when
//!   the change is one it shows. A page never reloads itself.
//!
//! The pull is [`crate::history_ui::refresh_detail`], the same code as
//! Sync now and `pathwarden history storage sync`.

use std::collections::HashMap;
use std::fmt::Write;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Query, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::history_ui::{self, PullError, Pulled};
use crate::last_pull;
use crate::pages::{esc, icon};
use crate::server::AppState;
use crate::workspace::Workspace;

type Shared = Arc<AppState>;

/// When the next pull is due, and whether anyone is looking.
#[derive(Default)]
pub struct Timer {
    inner: Mutex<TimerState>,
    wake: Notify,
}

#[derive(Default)]
struct TimerState {
    /// The last page check-in.
    seen: Option<Instant>,
    /// The last pull (or skipped tick, or reset).
    last: Option<Instant>,
    /// Pull at once.
    kick: bool,
}

/// What the loop does next.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// Nobody checked in for twice the interval: wait for a page.
    Pause,
    Wait(Instant),
    Pull,
}

impl Timer {
    fn state(&self) -> std::sync::MutexGuard<'_, TimerState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A page was loaded or asked for news.
    pub fn check_in(&self) {
        self.state().seen = Some(Instant::now());
        self.wake.notify_one();
    }

    /// The next pull is a whole interval from now (one just happened, or
    /// the interval changed).
    pub fn reset(&self) {
        let mut s = self.state();
        s.last = Some(Instant::now());
        s.kick = false;
        drop(s);
        self.wake.notify_one();
    }

    /// Pull at once (another environment, a passphrase entered).
    pub fn kick(&self) {
        self.state().kick = true;
        self.wake.notify_one();
    }

    fn plan(&self, now: Instant, every: Duration) -> Plan {
        let s = self.state();
        let active = s.seen.is_some_and(|t| now.duration_since(t) <= every * 2);
        if !active {
            return Plan::Pause;
        }
        if s.kick {
            return Plan::Pull;
        }
        match s.last {
            Some(t) if t + every > now => Plan::Wait(t + every),
            _ => Plan::Pull,
        }
    }

    /// A pull starts: a kick asked for before it is done with.
    fn starting(&self) {
        self.state().kick = false;
    }

    /// A pull (or a skipped tick) ended at `now`: the next is a whole
    /// interval on from here, failed or not, so a slow or stalled pull never
    /// makes the next one start at once.
    fn ended(&self, now: Instant) {
        self.state().last = Some(now);
    }
}

/// The loop: pulls through `tick` when due, `minutes` read again before
/// each wait. Runs until the program ends.
pub async fn run<M, T, F>(timer: Arc<Timer>, mut minutes: M, mut tick: T)
where
    M: FnMut() -> u32,
    T: FnMut() -> F,
    F: Future<Output = ()>,
{
    loop {
        let every = Duration::from_secs(
            u64::from(minutes().clamp(1, pathwarden_core::config::MAX_REFRESH_MINUTES)) * 60,
        );
        let now = Instant::now();
        match timer.plan(now, every) {
            Plan::Pause => timer.wake.notified().await,
            // Until due, or until something changes (a check-in, a reset).
            Plan::Wait(at) => {
                let _ = tokio::time::timeout_at(at, timer.wake.notified()).await;
            }
            Plan::Pull => {
                timer.starting();
                tick().await;
                timer.ended(Instant::now());
            }
        }
    }
}

/// What a pull brought, for the pages open on it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Change {
    /// Runs it brought.
    pub runs: usize,
    /// Shared sections applied here, by key.
    pub sections: Vec<String>,
    /// Runs removed here, by folder ID.
    pub removed: Vec<String>,
}

impl Change {
    fn is_empty(&self) -> bool {
        self.runs == 0 && self.sections.is_empty() && self.removed.is_empty()
    }

    fn add(&mut self, o: &Change) {
        self.runs += o.runs;
        for s in &o.sections {
            if !self.sections.contains(s) {
                self.sections.push(s.clone());
            }
        }
        for r in &o.removed {
            if !self.removed.contains(r) {
                self.removed.push(r.clone());
            }
        }
    }
}

impl From<&Pulled> for Change {
    fn from(p: &Pulled) -> Self {
        Change {
            runs: p.runs,
            sections: p.sections.iter().map(|s| s.to_string()).collect(),
            removed: p.removed.clone(),
        }
    }
}

#[derive(Default)]
struct EnvLog {
    n: u64,
    /// The pulls that brought something: (counter, what).
    changes: Vec<(u64, Change)>,
}

/// The most changes kept per environment.
const KEPT_CHANGES: usize = 200;

/// The app's pulling: on [`AppState`].
#[derive(Default)]
pub struct AutoPull {
    /// Set by the programs that serve a browser or a window (`pathwarden
    /// ui`, the desktop app): tests driving the router never pull.
    enabled: AtomicBool,
    started: AtomicBool,
    pub timer: Arc<Timer>,
    log: Mutex<HashMap<String, EnvLog>>,
}

impl AutoPull {
    /// Pull while pages are open, from the first page load on.
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    fn logs(&self) -> std::sync::MutexGuard<'_, HashMap<String, EnvLog>> {
        self.log.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Environment `env`'s pull counter.
    pub fn counter(&self, env: &str) -> u64 {
        self.logs().get(env).map_or(0, |l| l.n)
    }

    /// Counts a pull of `env` and all it brought, at once.
    pub fn record(&self, env: &str, p: &Pulled) -> u64 {
        self.record_change(env, Change::from(p))
    }

    /// Counts the shared sections a pull of `env` applied, as soon as they
    /// are applied (before the full runs are loaded): a page loaded from
    /// then on shows them, and carries this counter, so its saves aren't
    /// refused for them.
    pub fn record_sections(&self, env: &str, sections: &[&'static str]) -> u64 {
        self.record_change(
            env,
            Change {
                sections: sections.iter().map(|s| s.to_string()).collect(),
                ..Change::default()
            },
        )
    }

    /// Counts the end of a pull whose sections [`AutoPull::record_sections`]
    /// counted: the runs it brought and removed.
    pub fn record_runs(&self, env: &str, p: &Pulled) -> u64 {
        self.record_change(
            env,
            Change {
                runs: p.runs,
                removed: p.removed.clone(),
                ..Change::default()
            },
        )
    }

    fn record_change(&self, env: &str, c: Change) -> u64 {
        let mut logs = self.logs();
        let l = logs.entry(env.to_string()).or_default();
        l.n += 1;
        if !c.is_empty() {
            l.changes.push((l.n, c));
            if l.changes.len() > KEPT_CHANGES {
                l.changes.remove(0);
            }
        }
        l.n
    }

    /// What `env`'s pulls after counter `since` brought, together.
    pub fn since(&self, env: &str, since: u64) -> Change {
        let mut out = Change::default();
        if let Some(l) = self.logs().get(env) {
            for (n, c) in &l.changes {
                if *n > since {
                    out.add(c);
                }
            }
        }
        out
    }
}

/// A page checked in: the loop starts on the first, when enabled.
pub fn check_in(st: &Shared) {
    let ap = &st.auto_pull;
    ap.timer.check_in();
    if ap.enabled.load(Ordering::SeqCst) && !ap.started.swap(true, Ordering::SeqCst) {
        let timer = ap.timer.clone();
        let (a, b) = (st.clone(), st.clone());
        tokio::spawn(run(
            timer,
            move || minutes(&a),
            move || {
                let b = b.clone();
                async move {
                    let _ = tick(b).await;
                }
            },
        ));
    }
}

/// The current environment's `[state] refresh`.
fn minutes(st: &AppState) -> u32 {
    st.ws()
        .config()
        .map(|c| c.state.refresh_minutes())
        .unwrap_or(pathwarden_core::config::DEFAULT_REFRESH_MINUTES)
}

/// Why a tick was skipped, if it was.
#[derive(Debug, PartialEq, Eq)]
pub enum Skip {
    Analysis,
    Demo,
    Folder,
    Busy,
    /// The pull failed (recorded as the last pull; tried again next tick).
    Failed,
}

/// Pulls `ws`'s history as the app does every few minutes: skipped for a
/// folder history (or one that can't be located) and while its lock is
/// held (taken without waiting); git never prompts.
pub fn pull_env(ws: &Workspace, flag: Option<&std::path::Path>) -> Result<Pulled, Skip> {
    pull_env_with(ws, flag, &mut |_| {})
}

/// [`pull_env`], telling `settings_applied` the shared sections applied
/// here as soon as they are ([`history_ui::refresh_detail`]).
pub fn pull_env_with(
    ws: &Workspace,
    flag: Option<&std::path::Path>,
    settings_applied: &mut dyn FnMut(&[&'static str]),
) -> Result<Pulled, Skip> {
    pull_env_busy(ws, flag, settings_applied, &|| false)
}

/// [`pull_env_with`]; nothing waiting here is pushed while `busy` says an
/// analysis is running ([`crate::shared_runs::PullBy::Background`]).
pub fn pull_env_busy(
    ws: &Workspace,
    flag: Option<&std::path::Path>,
    settings_applied: &mut dyn FnMut(&[&'static str]),
    busy: &dyn Fn() -> bool,
) -> Result<Pulled, Skip> {
    let loc = history_ui::locate(ws, flag).map_err(|_| Skip::Folder)?;
    if loc.git.is_none() {
        return Err(Skip::Folder);
    }
    // Git stopped after 45 seconds of silence: a stalled network never
    // keeps a recording out for long.
    pathwarden_core::store::background(|| {
        history_ui::refresh_detail_busy(
            Some(ws),
            &loc,
            true,
            Duration::ZERO,
            "app",
            settings_applied,
            busy,
        )
    })
    .map_err(|e| match e {
        PullError::Busy(_) => Skip::Busy,
        PullError::Failed(_) => Skip::Failed,
    })
}

/// One tick: the current environment's pull, unless skipped.
pub async fn tick(st: Shared) -> Result<(), Skip> {
    if st.jobs.running().is_some() {
        return Err(Skip::Analysis);
    }
    let env = st.env_id();
    if st.workspace.registry().get(&env).is_some_and(|e| e.demo) {
        return Err(Skip::Demo);
    }
    let ws = st.ws();
    let flag = st.state_dir_for(&ws);
    let (st2, env2, st3) = (st.clone(), env.clone(), st.clone());
    let done = tokio::task::spawn_blocking(move || {
        pull_env_busy(
            &ws,
            flag.as_deref(),
            &mut |s| {
                st2.auto_pull.record_sections(&env2, s);
            },
            // An analysis that started meanwhile records soon: nothing is
            // pushed that would keep it waiting.
            &|| st3.jobs.running().is_some(),
        )
    })
    .await
    .map_err(|_| Skip::Busy)?;
    let p = done?;
    st.auto_pull.record_runs(&env, &p);
    Ok(())
}

/// Middleware: every page load and every news check is a check-in.
pub async fn touch(State(st): State<Shared>, req: Request, next: Next) -> Response {
    if is_check_in(req.method(), req.uri().path()) {
        check_in(&st);
    }
    next.run(req).await
}

fn is_check_in(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::GET
        && (path == "/api/history/pulled"
            || !(path.starts_with("/api/")
                || path.starts_with("/static/")
                || path.ends_with("/report")
                || crate::brand::is_public(path)))
}

// ----------------------------------------------------------- the pages

/// The sidebar footer's status for `ws`: empty unless its history is a
/// git repository.
pub fn foot_html(ws: &Workspace, flag: Option<&std::path::Path>) -> String {
    pull_status(ws, flag)
        .map(|s| s.foot_html())
        .unwrap_or_default()
}

/// The last pull of `ws`'s history in words, when it is a git repository.
pub fn pull_status(ws: &Workspace, flag: Option<&std::path::Path>) -> Option<last_pull::Status> {
    let config = ws.config().ok()?;
    let loc = history_ui::locate_with(ws, flag, &config).ok()?;
    loc.git.as_ref()?;
    // The runs waiting come with the record: noted on recordings and
    // syncs, never worked out (nor git run) for a page.
    Some(last_pull::status(
        last_pull::read(&loc.store),
        config.state.refresh_minutes(),
        pathwarden_core::analyze::now(),
    ))
}

#[derive(Deserialize)]
pub struct PulledQuery {
    #[serde(default)]
    since: u64,
    /// The page asking: `home`, `runs`, `progress`, `settings`, `zones`,
    /// `mappings` or `run`.
    #[serde(default)]
    page: String,
    /// With `page=run`: its run.
    #[serde(default)]
    run: Option<String>,
    /// The page has unsaved edits.
    #[serde(default)]
    editing: bool,
    /// The environment the page was loaded in: no note for a page of
    /// another one (switched in another tab).
    #[serde(default)]
    env: Option<String>,
}

/// The sections each configuration page shows.
fn page_sections(page: &str) -> &'static [&'static str] {
    match page {
        "settings" => &["tier_zero", "settings_folders", "rules", "suppress"],
        "zones" => &["zone", "management_planes"],
        "mappings" => &["mapping"],
        _ => &[],
    }
}

/// `GET /api/history/pulled?since=N&page=P`: the counter now, the footer,
/// and the note page `P` shows for what the pulls after `N` brought, if
/// any.
pub async fn pulled_api(State(st): State<Shared>, Query(q): Query<PulledQuery>) -> Response {
    let env = st.env_id();
    let n = st.auto_pull.counter(&env);
    // A page of another environment: its counter means nothing here.
    let change = if q.env.as_deref().is_some_and(|e| !e.is_empty() && e != env) {
        Change::default()
    } else {
        st.auto_pull.since(&env, q.since)
    };
    let ws = st.ws();
    let flag = st.state_dir_for(&ws);
    let (foot, note) = tokio::task::spawn_blocking(move || {
        let foot = foot_html(&ws, flag.as_deref());
        (foot, note_html(&ws, flag.as_deref(), &q, &change))
    })
    .await
    .unwrap_or_default();
    Json(serde_json::json!({ "n": n, "foot": foot, "note": note })).into_response()
}

/// The note fixed at the bottom of page `q.page` for `change`, if it shows
/// one.
fn note_html(
    ws: &Workspace,
    flag: Option<&std::path::Path>,
    q: &PulledQuery,
    change: &Change,
) -> Option<String> {
    let reload = r#"<button type="button" class="btn primary" data-repo-reload>Reload</button>"#;
    match q.page.as_str() {
        "home" | "runs" | "progress" if change.runs > 0 => Some(note(
            &format!(
                "The repository has <strong>{}</strong>.",
                esc(&pathwarden_core::text::count(
                    change.runs,
                    "new run",
                    "new runs"
                ))
            ),
            None,
            reload,
        )),
        "run" => {
            let id = q.run.as_deref()?;
            change.removed.iter().any(|r| r == id).then(|| {
                note(
                    "This run was removed from the repository.",
                    None,
                    r#"<a class="btn primary" href="/runs">Open Runs</a>"#,
                )
            })
        }
        page => {
            let mine = page_sections(page);
            let names: Vec<&str> = change
                .sections
                .iter()
                .filter(|s| mine.contains(&s.as_str()))
                .map(|s| last_pull::short_name(s))
                .collect();
            if names.is_empty() {
                return None;
            }
            let what = format!("<strong>{}</strong>", esc(&last_pull::names_words(&names)));
            if q.editing {
                return Some(note(
                    &format!("{what} changed in the repository while you were editing."),
                    Some("Reload to see the new version. Your unsaved changes here will be lost."),
                    reload,
                ));
            }
            Some(note(
                &format!(
                    "{what} changed in the repository. {}",
                    changed_tip(ws, flag)
                ),
                None,
                reload,
            ))
        }
    }
}

/// Who changed the settings, when and what, as the last pull applied them.
fn changed_tip(ws: &Workspace, flag: Option<&std::path::Path>) -> String {
    let applied = history_ui::locate(ws, flag)
        .ok()
        .and_then(|loc| pathwarden_core::settings_sync::unseen_applied(&loc.store, false));
    let mut rows = Vec::new();
    if let Some(a) = &applied {
        if let Some(w) = crate::sync_ui::who(&a.by, &a.on) {
            rows.push(("By".to_string(), esc(&w)));
        }
        if let Some(at) = &a.changed_at {
            rows.push(("When".to_string(), crate::sync_ui::when(at)));
        }
        if let Some(s) = &a.summary {
            rows.push((
                "What".to_string(),
                esc(s.strip_prefix("pathwarden settings: ").unwrap_or(s)),
            ));
        }
    }
    rows.push(("Applies".to_string(), "From the next analysis".to_string()));
    crate::sync_ui::tip("rn", "What came from the repository", &rows, false)
}

fn note(main: &str, sub: Option<&str>, action: &str) -> String {
    let mut b = format!(
        r#"<div class="repo-note card" id="repo-note" role="status">{}<div>{main}"#,
        icon("i-history")
    );
    if let Some(s) = sub {
        let _ = write!(b, r#"<span class="rn-sub">{}</span>"#, esc(s));
    }
    let _ = write!(
        b,
        r#"</div>{action}<button type="button" class="fl-remove" data-repo-close aria-label="Close">{}</button></div>"#,
        icon("i-x")
    );
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const MIN: Duration = Duration::from_secs(60);

    /// The loop with a counting tick, `n` minutes apart.
    fn start(timer: &Arc<Timer>, n: u32) -> Arc<AtomicUsize> {
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        tokio::spawn(run(
            timer.clone(),
            move || n,
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            },
        ));
        count
    }

    /// Lets the loop run, `d` of paused time later.
    async fn after(d: Duration) {
        tokio::time::sleep(d).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pulls_on_the_first_page_load_then_every_interval() {
        let timer = Arc::new(Timer::default());
        let count = start(&timer, 5);
        after(MIN * 30).await;
        assert_eq!(count.load(Ordering::SeqCst), 0, "no page yet: no pull");
        timer.check_in();
        after(Duration::from_millis(1)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1, "the first page load pulls");
        timer.check_in();
        after(MIN * 4).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        timer.check_in();
        after(MIN + Duration::from_secs(1)).await;
        assert_eq!(count.load(Ordering::SeqCst), 2, "five minutes on");
    }

    #[tokio::test(start_paused = true)]
    async fn a_reset_waits_a_whole_interval_and_a_kick_pulls_now() {
        let timer = Arc::new(Timer::default());
        let count = start(&timer, 5);
        timer.check_in();
        after(MIN * 4).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        // Pull now, or a Save: five minutes from here.
        timer.reset();
        timer.check_in();
        after(MIN * 2).await;
        assert_eq!(count.load(Ordering::SeqCst), 1, "reset pushed it back");
        timer.check_in();
        after(MIN * 3 + Duration::from_secs(1)).await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
        // Another environment: at once.
        timer.kick();
        after(Duration::from_millis(1)).await;
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn pauses_when_no_page_checks_in_and_catches_up_when_one_does() {
        let timer = Arc::new(Timer::default());
        let count = start(&timer, 5);
        timer.check_in();
        after(Duration::from_millis(1)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        // Nobody checks in: pulls at 5 and 10 minutes (seen within twice
        // the interval), none at 15 or later.
        after(MIN * 60).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            3,
            "paused after twice the interval"
        );
        // A page comes back: overdue, so at once.
        timer.check_in();
        after(Duration::from_millis(1)).await;
        assert_eq!(count.load(Ordering::SeqCst), 4);
    }

    /// A pull that takes 3 minutes (a slow network, or one stopped after
    /// git's silence limit): the next one is 5 minutes after it ended.
    #[tokio::test(start_paused = true)]
    async fn the_next_pull_counts_from_when_the_last_one_ended() {
        let timer = Arc::new(Timer::default());
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        tokio::spawn(run(
            timer.clone(),
            || 5,
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(MIN * 3).await;
                }
            },
        ));
        timer.check_in();
        after(Duration::from_millis(1)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        // Ends at 3 minutes; not due at 7 (5 from its start), due at 8.
        timer.check_in();
        after(MIN * 6 + Duration::from_secs(30)).await;
        timer.check_in();
        after(Duration::from_millis(1)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1, "counted from the end");
        after(MIN * 2).await;
        assert_eq!(count.load(Ordering::SeqCst), 2, "8 minutes in");
        // A kick while a pull runs isn't lost.
        after(MIN).await;
        timer.kick();
        after(MIN * 2 + Duration::from_secs(1)).await;
        assert_eq!(count.load(Ordering::SeqCst), 3, "pulled again at once");
    }

    #[tokio::test(start_paused = true)]
    async fn the_interval_is_read_again_each_tick() {
        let timer = Arc::new(Timer::default());
        let n = Arc::new(std::sync::atomic::AtomicU32::new(5));
        let count = Arc::new(AtomicUsize::new(0));
        let (c, m) = (count.clone(), n.clone());
        tokio::spawn(run(
            timer.clone(),
            move || m.load(Ordering::SeqCst),
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            },
        ));
        timer.check_in();
        after(Duration::from_millis(1)).await;
        n.store(1, Ordering::SeqCst);
        // A Save resets the wait and the loop reads 1 minute.
        timer.reset();
        timer.check_in();
        after(MIN + Duration::from_secs(1)).await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn check_ins_are_pages_and_the_news_check() {
        use axum::http::Method;
        assert!(is_check_in(&Method::GET, "/"));
        assert!(is_check_in(&Method::GET, "/runs/20261025-0422"));
        assert!(is_check_in(&Method::GET, "/api/history/pulled"));
        assert!(!is_check_in(&Method::GET, "/api/jobs/1"));
        assert!(!is_check_in(&Method::GET, "/static/app.js"));
        assert!(!is_check_in(&Method::GET, "/runs/x/report"));
        assert!(!is_check_in(&Method::POST, "/settings"));
    }

    #[test]
    fn changes_add_up_since_a_counter() {
        let ap = AutoPull::default();
        assert_eq!(ap.counter("e"), 0);
        let p = |runs, sections: Vec<&'static str>| Pulled {
            runs,
            sections,
            ..Pulled::default()
        };
        assert_eq!(ap.record("e", &p(2, vec![])), 1);
        assert_eq!(ap.record("e", &p(0, vec![])), 2);
        assert_eq!(ap.record("e", &p(1, vec!["rules"])), 3);
        assert_eq!(ap.since("e", 0).runs, 3);
        assert_eq!(ap.since("e", 1).runs, 1);
        assert_eq!(ap.since("e", 1).sections, vec!["rules"]);
        assert_eq!(ap.since("e", 3), Change::default());
        assert_eq!(ap.since("other", 0), Change::default());
    }
}
