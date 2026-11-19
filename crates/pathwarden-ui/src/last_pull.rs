//! The last sync of a git history, for History storage's
//! In use, the sidebar's footer and `pathwarden history storage show`.
//!
//! Every sync ([`crate::history_ui::refresh_all`]: the app's own, Sync
//! now, Sign in, `pathwarden history storage sync`) records how its pull
//! went in the state folder's `.pathwarden-last-pull.json`, beside the lock
//! ([`pathwarden_core::store::LAST_PULL_FILE`]): there before the first
//! clone, so a clone that fails is recorded too, and listed in the working
//! copy's `.git/info/exclude`, so it is never committed or pushed, plain or
//! encrypted. One function turns it into words ([`status`]), with the runs
//! recorded here still waiting to be pushed ([`Status::with_waiting`]), so
//! the page, the footer and the command line say the same.

use std::fmt::Write;

use pathwarden_core::connect::{NOT_SIGNED_IN, NO_HELPER};
use pathwarden_core::store::Store;
use serde::{Deserialize, Serialize};

use crate::pages::{esc, icon};

/// The record's file name, in the state folder.
pub const FILE: &str = pathwarden_core::store::LAST_PULL_FILE;

/// How the last pull went.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastPull {
    /// When it was tried (Unix seconds).
    pub at: i64,
    /// It reached the repository.
    pub ok: bool,
    /// What git said when it didn't.
    #[serde(default)]
    pub error: Option<String>,
    /// What loading full runs said ("2 full runs loaded from the
    /// repository.").
    #[serde(default)]
    pub loaded: Option<String>,
    /// Shared sections it applied here, by key (`rules`, `tier_zero`, ...).
    #[serde(default)]
    pub sections: Vec<String>,
    /// Who pulled: `app`, `pull now`, `sign in` or `command line`.
    #[serde(default)]
    pub by: String,
    /// Failed pulls in a row (0 after one that worked).
    #[serde(default)]
    pub tries: u32,
    /// Runs it brought (new points in the history).
    #[serde(default)]
    pub runs: usize,
    /// When a pull last worked.
    #[serde(default)]
    pub last_ok: Option<i64>,
    /// When the failures in a row began.
    #[serde(default)]
    pub failing_since: Option<i64>,
    /// Some shared section changed here and in the repository waits for a
    /// choice.
    #[serde(default)]
    pub conflict: bool,
    /// The history is encrypted and this computer has no passphrase for
    /// it: the pull brought the files, but nothing was loaded.
    #[serde(default)]
    pub locked: bool,
    /// It failed for a sign-in git couldn't make
    /// ([`pathwarden_core::connect::is_sign_in`]).
    #[serde(default)]
    pub sign_in: bool,
    /// And git here has no credential helper to ask for an account
    /// ([`pathwarden_core::connect::no_helper`]).
    #[serde(default)]
    pub no_helper: bool,
    /// Or the repository refused the account git gave
    /// ([`pathwarden_core::connect::refused`]).
    #[serde(default)]
    pub refused: bool,
    /// The runs recorded here still waiting to be pushed, as of the last
    /// recording, sync or push from here ([`set_waiting`]): pages read
    /// them from here and never work them out themselves.
    #[serde(default)]
    pub waiting: Vec<WaitingRun>,
}

/// The record of `store`'s last pull, if it is a git working copy that
/// was pulled (or had runs waiting noted, with `at` 0).
pub fn read(store: &Store) -> Option<LastPull> {
    serde_json::from_slice(&store.read_last_pull()?).ok()
}

/// Notes the runs recorded here still waiting to be pushed
/// ([`crate::shared_runs::waiting_runs`]), with the last sync's record
/// (one with `at` 0 when there has been no sync yet).
pub fn set_waiting(store: &Store, waiting: Vec<WaitingRun>) {
    let _one = one_at_a_time();
    let mut r = read(store).unwrap_or_default();
    if r.waiting != waiting {
        r.waiting = waiting;
        write(store, &r);
    }
}

/// Held while a change to the record reads it and writes it back, so two
/// at once (a sync's end and a recording noting runs waiting) don't lose
/// one another's change. Within this process; the history's lock keeps
/// another Pathwarden's sync apart.
fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    ONE.lock().unwrap_or_else(|e| e.into_inner())
}

fn write(store: &Store, r: &LastPull) {
    if let Ok(b) = serde_json::to_vec_pretty(r) {
        let _ = store.write_last_pull(&b);
    }
}

/// What a pull that worked brought.
#[derive(Debug, Clone, Default)]
pub struct Brought {
    pub loaded: Option<String>,
    pub sections: Vec<String>,
    pub runs: usize,
    pub conflict: bool,
    pub locked: bool,
}

/// Records a pull that worked, at `at`.
pub fn succeeded(store: &Store, by: &str, at: i64, b: &Brought) {
    let _one = one_at_a_time();
    let waiting = read(store).map(|r| r.waiting).unwrap_or_default();
    write(
        store,
        &LastPull {
            at,
            ok: true,
            error: None,
            loaded: b.loaded.clone(),
            sections: b.sections.clone(),
            by: by.to_string(),
            tries: 0,
            runs: b.runs,
            last_ok: Some(at),
            failing_since: None,
            conflict: b.conflict,
            locked: b.locked,
            sign_in: false,
            no_helper: false,
            refused: false,
            waiting,
        },
    );
}

/// Records a pull that failed, at `at`, with git's message: runs and
/// settings here stay as they were, and so does what the record says of
/// them. A sign-in git couldn't make is told apart, and whether git here
/// has a credential helper at all.
pub fn failed(store: &Store, by: &str, at: i64, error: &str) {
    let _one = one_at_a_time();
    let prev = read(store).unwrap_or_default();
    let (tries, since) = if prev.ok || prev.at == 0 {
        (1, at)
    } else {
        (
            prev.tries.saturating_add(1),
            prev.failing_since.unwrap_or(at),
        )
    };
    let sign_in = pathwarden_core::connect::is_sign_in(error);
    let no_helper = sign_in && pathwarden_core::connect::no_helper(error, Some(&store.dir));
    write(
        store,
        &LastPull {
            at,
            ok: false,
            error: Some(error.to_string()),
            by: by.to_string(),
            tries,
            failing_since: Some(since),
            last_ok: prev.last_ok,
            conflict: prev.conflict,
            locked: prev.locked,
            loaded: None,
            sections: Vec::new(),
            runs: 0,
            sign_in,
            no_helper,
            refused: sign_in && pathwarden_core::connect::refused(error),
            waiting: prev.waiting,
        },
    );
}

/// After a choice on Settings settled the shared settings (or didn't):
/// whether some section still differs from them. Kept in the record; the
/// sidebar and History storage say only how the sync went, and Settings
/// itself shows a difference.
pub fn set_conflict(store: &Store, conflict: bool) {
    let _one = one_at_a_time();
    if let Some(mut r) = read(store) {
        if r.conflict != conflict {
            r.conflict = conflict;
            write(store, &r);
        }
    }
}

/// What the last sync comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Not synced yet on this computer.
    NotYet,
    UpToDate,
    /// Synced, and runs recorded here still wait to be pushed
    /// ([`Status::with_waiting`]).
    Waiting,
    /// The repository couldn't be reached.
    Failed,
    /// The repository wanted a sign-in git couldn't make.
    NotSignedIn,
    /// The same, and git here has no credential helper to ask with.
    NoHelper,
    /// Pulled, but nothing loaded: no passphrase here.
    Locked,
}

/// A run recorded here and not pushed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitingRun {
    /// When it was analyzed (Unix seconds).
    pub at: i64,
    /// Its numbers are in the history already; its full run waits.
    pub full: bool,
}

/// The last sync in words, for the page, the footer and the command line.
#[derive(Debug, Clone)]
pub struct Status {
    pub kind: Kind,
    /// The record, when there is one.
    pub last: Option<LastPull>,
    /// How often the app syncs, in minutes.
    pub minutes: u32,
    /// Now (Unix seconds).
    pub now: i64,
    /// Runs recorded here still waiting to be pushed.
    pub waiting: Vec<WaitingRun>,
}

/// [`Status`] of `last` with the app syncing every `minutes`, at `now`.
pub fn status(last: Option<LastPull>, minutes: u32, now: i64) -> Status {
    // The runs waiting, as noted; a record kept only for them is no sync.
    let waiting = last.as_ref().map(|r| r.waiting.clone()).unwrap_or_default();
    let last = last.filter(|r| r.at != 0);
    let kind = match &last {
        None => Kind::NotYet,
        Some(r) if !r.ok && r.sign_in && r.no_helper => Kind::NoHelper,
        Some(r) if !r.ok && r.sign_in => Kind::NotSignedIn,
        Some(r) if !r.ok => Kind::Failed,
        Some(r) if r.locked => Kind::Locked,
        Some(_) => Kind::UpToDate,
    };
    Status {
        kind,
        last,
        minutes,
        now,
        waiting: Vec::new(),
    }
    .with_waiting(waiting)
}

/// "just now", "2 min ago", "3 h ago", "2 days ago".
pub fn ago(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86_399 => format!("{} h ago", s / 3600),
        _ => {
            let d = s / 86_400;
            if d == 1 {
                "1 day ago".into()
            } else {
                format!("{d} days ago")
            }
        }
    }
}

/// A section's short name ("Rules", "Tier Zero").
pub fn short_name(key: &str) -> &'static str {
    match key {
        "tier_zero" => "Tier Zero",
        "settings_folders" => "Tier Zero settings folders",
        "rules" => "Rules",
        "suppress" => "Accepted risks",
        "zone" => "Zones",
        "management_planes" => "Management planes",
        "mapping" => "Mapping packs",
        _ => "Settings",
    }
}

/// "Rules", "Rules and Zones", "Tier Zero, Rules and Zones".
pub fn names_words(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The Sign in button, as Sync now looks: History storage's and the
/// Connect page's.
pub fn sign_in_button(attr: &str) -> String {
    format!(
        r#"<button type="button" class="btn" {attr}>{} Sign in</button>"#,
        icon("i-external")
    )
}

/// What the Sign in button says on the History storage page.
pub const SIGN_IN_TIP: &str =
    "Opens the Git Credential Manager window. Pathwarden never sees the password.";

impl Status {
    /// With `waiting`, the runs recorded here still waiting to be pushed:
    /// a sync that worked says so instead of "Up to date".
    pub fn with_waiting(mut self, waiting: Vec<WaitingRun>) -> Self {
        if self.kind == Kind::Waiting && waiting.is_empty() {
            self.kind = if self.last.is_some() {
                Kind::UpToDate
            } else {
                Kind::NotYet
            };
        }
        if !waiting.is_empty() && matches!(self.kind, Kind::UpToDate | Kind::NotYet) {
            self.kind = Kind::Waiting;
        }
        self.waiting = waiting;
        self
    }

    fn since_last(&self) -> Option<String> {
        self.last
            .as_ref()
            .and_then(|r| r.last_ok)
            .map(|t| ago(self.now - t))
    }

    /// "Last synced 23 min ago." or "Not synced yet."
    fn last_synced(&self) -> String {
        match self.since_last() {
            Some(a) => format!("Last synced {a}."),
            None => "Not synced yet.".into(),
        }
    }

    fn pulled_ago(&self) -> String {
        self.last
            .as_ref()
            .map(|r| ago(self.now - r.at))
            .unwrap_or_default()
    }

    /// Minutes to the next try: at least 1.
    fn retry_in(&self) -> i64 {
        let at = self.last.as_ref().map_or(self.now, |r| r.at);
        let left = at + i64::from(self.minutes) * 60 - self.now;
        ((left + 59) / 60).max(1)
    }

    /// Whether something is wrong: the footer turns amber.
    pub fn warn(&self) -> bool {
        matches!(
            self.kind,
            Kind::Failed | Kind::NotSignedIn | Kind::NoHelper | Kind::Locked
        )
    }

    /// Whether the repository wanted a sign-in git couldn't make.
    pub fn signed_out(&self) -> bool {
        matches!(self.kind, Kind::NotSignedIn | Kind::NoHelper)
    }

    /// The repository refused the account git gave (a credential kept on
    /// this computer): Sign in can pick another.
    pub fn refused(&self) -> bool {
        self.kind == Kind::NotSignedIn && self.last.as_ref().is_some_and(|r| r.refused)
    }

    /// "1 run is waiting to be pushed.", "2 runs are waiting to be pushed."
    pub fn waiting_head(&self) -> String {
        let n = self.waiting.len();
        format!(
            "{} waiting to be pushed.",
            pathwarden_core::text::count(n, "run is", "runs are")
        )
    }

    /// The sidebar footer's words: "Synced 2 min ago", "2 runs loaded ·
    /// just now", "Rules updated · just now", or the problem.
    pub fn foot(&self) -> String {
        match self.kind {
            Kind::NotYet => "Not synced yet".into(),
            Kind::Failed => "Couldn't sync with the repository".into(),
            Kind::NotSignedIn if self.refused() => "Sign-in refused by the repository".into(),
            Kind::NotSignedIn | Kind::NoHelper => "Not signed in to the repository".into(),
            Kind::Locked => "Passphrase needed".into(),
            Kind::Waiting => format!(
                "{} waiting to be pushed",
                pathwarden_core::text::count(self.waiting.len(), "run", "runs")
            ),
            Kind::UpToDate => {
                let r = self.last.as_ref().expect("up to date has a record");
                let when = self.pulled_ago();
                if r.runs > 0 {
                    format!(
                        "{} loaded · {when}",
                        pathwarden_core::text::count(r.runs, "run", "runs")
                    )
                } else if !r.sections.is_empty() {
                    let names: Vec<&str> = r.sections.iter().map(|k| short_name(k)).collect();
                    format!("{} updated · {when}", names_words(&names))
                } else {
                    format!("Synced {when}")
                }
            }
        }
    }

    /// The footer's icon.
    fn foot_icon(&self) -> &'static str {
        match self.kind {
            Kind::Locked => "i-lock",
            Kind::Failed | Kind::NotSignedIn | Kind::NoHelper => "i-alert",
            Kind::Waiting => "i-upload",
            _ => "i-sync",
        }
    }

    /// The sidebar footer's link to History storage (wide screens) and the
    /// icon button standing for it on a phone.
    pub fn foot_html(&self) -> String {
        let text = esc(&self.foot());
        let warn = if self.warn() { " warn" } else { "" };
        format!(
            r##"<a class="pull-foot{warn}" href="/automate/history#in-use" title="History storage: {text}">{ic}<span>{text}</span></a><a class="theme-toggle icon-btn pull-btn{warn}" href="/automate/history#in-use" title="{text}" aria-label="History storage: {text}">{dl}{dot}</a>"##,
            ic = icon(self.foot_icon()),
            dl = icon("i-sync"),
            dot = if self.warn() {
                r#"<span class="dot" aria-hidden="true"></span>"#
            } else {
                ""
            },
        )
    }

    /// The line after Sync now on History storage: "✓ Up to date · synced
    /// 2 min ago · every 5 min ⓘ", or what is wrong, or waiting; with the
    /// Sign in button after it when signing in can help.
    pub fn line_html(&self) -> String {
        let every = format!("every {} min", self.minutes);
        // The rest after the bold head: " · a · b" chips, or sentences.
        let (class, ic, head, rest, tip): (&str, &str, String, String, Option<String>) =
            match self.kind {
                Kind::NotYet => (
                    "",
                    "i-sync",
                    "Not synced yet".to_string(),
                    format!(" · {every}"),
                    Some(self.ok_tip()),
                ),
                Kind::UpToDate => (
                    "",
                    "i-check",
                    "Up to date".to_string(),
                    format!(" · synced {} · {every}", self.pulled_ago()),
                    Some(self.ok_tip()),
                ),
                Kind::Waiting => (
                    "",
                    "i-upload",
                    self.waiting_head(),
                    self.last_synced(),
                    Some(self.waiting_tip()),
                ),
                Kind::Failed => (
                    " warn",
                    "i-alert",
                    "Couldn't sync with the repository.".to_string(),
                    format!(
                        "Retrying in {} min. {}",
                        self.retry_in(),
                        self.last_synced()
                    ),
                    Some(self.failed_tip(None)),
                ),
                Kind::NotSignedIn => (
                    " warn",
                    "i-alert",
                    if self.refused() {
                        pathwarden_core::connect::REFUSED
                    } else {
                        NOT_SIGNED_IN
                    }
                    .to_string(),
                    self.last_synced(),
                    Some(self.failed_tip(Some(("Sign in", SIGN_IN_TIP)))),
                ),
                Kind::NoHelper => (
                    " warn",
                    "i-alert",
                    NOT_SIGNED_IN.to_string(),
                    format!("{NO_HELPER} then sync again."),
                    Some(self.failed_tip(Some((
                        "Sign-in helper",
                        "None is set up for git on this computer, so git can't ask for an account.",
                    )))),
                ),
                Kind::Locked => (
                    " warn",
                    "i-lock",
                    format!("Synced {}", self.pulled_ago()),
                    " · nothing loaded until the passphrase is entered ·".to_string(),
                    Some(self.locked_tip()),
                ),
            };
        let mut b = format!(
            r#"<span class="pl-state{class}">{}<strong>{}</strong><span>{}</span>"#,
            icon(ic),
            esc(&head),
            esc(&rest)
        );
        if self.kind == Kind::Locked {
            b.push_str(r#"<a href="/runs">Enter it on Runs</a>"#);
        }
        b.push_str(&tip.unwrap_or_default());
        b.push_str("</span>");
        if self.kind == Kind::NotSignedIn {
            b.push_str(&sign_in_button(r#"data-history-action="sign-in""#));
        }
        b
    }

    fn ok_tip(&self) -> String {
        crate::sync_ui::tip(
            "pull",
            "Syncing with the repository",
            &[
                (
                    "When".into(),
                    format!(
                        "When the app opens, then every {} while it is open.",
                        minutes_words(self.minutes)
                    ),
                ),
                (
                    "Brings".into(),
                    "New runs, numbers, settings and accepted risks.".into(),
                ),
                (
                    "Pushes".into(),
                    "Runs recorded here that are waiting, unless an analysis is running.".into(),
                ),
                ("Never".into(), "Reloads the page you are on.".into()),
                (
                    "Change".into(),
                    "Set Sync every under Where to keep it.".into(),
                ),
            ],
            false,
        )
    }

    /// The runs waiting, by date: "The full run of Oct 27, 2026, 9:59 PM."
    fn waiting_tip(&self) -> String {
        let n = self.waiting.len();
        let full = self.waiting.iter().all(|w| w.full);
        let mut times: Vec<i64> = self.waiting.iter().map(|w| w.at).collect();
        times.sort_unstable();
        let shown: Vec<String> = times
            .iter()
            .take(3)
            .map(|t| crate::pages::time(*t))
            .collect();
        let mut dates = names_html(&shown);
        if n > 3 {
            let _ = write!(dates, " and {} more", n - 3);
        }
        let one = n == 1;
        let what = match (full, one) {
            (true, true) => {
                format!("The full run of {dates}. Its numbers are in the history already.")
            }
            (true, false) => {
                format!("The full runs of {dates}. Their numbers are in the history already.")
            }
            (false, true) => format!("The run of {dates}."),
            (false, false) => format!("The runs of {dates}."),
        };
        crate::sync_ui::tip(
            "pullwait",
            "Runs waiting to be pushed",
            &[
                ("Waiting".into(), what),
                (
                    "Sync now".into(),
                    if one {
                        "Pushes it, then gets the latest."
                    } else {
                        "Pushes them, then gets the latest."
                    }
                    .into(),
                ),
                (
                    "Otherwise".into(),
                    if one {
                        "It goes with the next run recorded here."
                    } else {
                        "They go with the next run recorded here."
                    }
                    .into(),
                ),
            ],
            false,
        )
    }

    /// What git said, `extra` (the Sign in row, or the helper's), and how
    /// often it was tried.
    fn failed_tip(&self, extra: Option<(&str, &str)>) -> String {
        let r = self.last.as_ref();
        let tries = r.map_or(1, |r| r.tries.max(1));
        let since = r
            .and_then(|r| r.failing_since)
            .map(crate::pages::time)
            .unwrap_or_default();
        let mut rows = vec![(
            "Git said".to_string(),
            format!(
                "<code>{}</code>",
                esc(r.and_then(|r| r.error.as_deref()).unwrap_or("nothing"))
            ),
        )];
        if let Some((k, v)) = extra {
            rows.push((k.to_string(), esc(v)));
        }
        rows.push(("Here".into(), "Runs and settings stay as they were.".into()));
        rows.push((
            "Tried".into(),
            if tries == 1 {
                format!("Once, at {since}.")
            } else {
                format!("{tries} times since {since}.")
            },
        ));
        let about = if self.signed_out() {
            "Why the sync needs a sign-in"
        } else {
            "Why the sync failed"
        };
        crate::sync_ui::tip("pullerr", about, &rows, false)
    }

    fn locked_tip(&self) -> String {
        crate::sync_ui::tip(
            "pulllock",
            "Encrypted history",
            &[
                (
                    "Syncs".into(),
                    "Still happen. The files stay encrypted here.".into(),
                ),
                (
                    "Loads".into(),
                    "No runs, numbers or settings until the passphrase is entered.".into(),
                ),
                (
                    "Passphrase".into(),
                    "Entered on Runs. Pathwarden never asks on its own.".into(),
                ),
            ],
            false,
        )
    }

    /// "tried once at Oct 27, 2026, 9:51 PM", "tried 3 times since ...".
    fn tried_since(&self) -> String {
        let r = self.last.as_ref();
        let since = r
            .and_then(|r| r.failing_since)
            .map(pathwarden_core::time::format_local)
            .unwrap_or_default();
        match r.map_or(1, |r| r.tries.max(1)) {
            1 => format!("tried once at {since}"),
            n => format!("tried {n} times since {since}"),
        }
    }

    /// `history storage show`'s "Last sync" row.
    pub fn text(&self) -> String {
        let pulled = self.pulled_ago();
        let last = match self.since_last() {
            Some(a) => format!("last synced {a}"),
            None => "not synced yet".into(),
        };
        let said = || {
            self.last
                .as_ref()
                .and_then(|r| r.error.as_deref())
                .unwrap_or("nothing")
                .to_string()
        };
        let tries = || match self.last.as_ref().map_or(1, |r| r.tries.max(1)) {
            1 => "once".to_string(),
            n => format!("{n} times in a row"),
        };
        match self.kind {
            Kind::NotYet => "Not synced yet on this computer".into(),
            Kind::UpToDate | Kind::Waiting => {
                let mut t = if self.last.is_some() {
                    format!("Up to date · synced {pulled}")
                } else {
                    "Not synced yet on this computer".to_string()
                };
                if let Some(r) = &self.last {
                    if r.runs > 0 {
                        let _ = write!(
                            t,
                            " · {} loaded",
                            pathwarden_core::text::count(r.runs, "run", "runs")
                        );
                    }
                    if !r.sections.is_empty() {
                        let names: Vec<&str> = r.sections.iter().map(|k| short_name(k)).collect();
                        let _ = write!(t, " · {} updated", names_words(&names));
                    }
                }
                if self.kind == Kind::Waiting {
                    t = format!(
                        "{} `pathwarden history storage sync` pushes {}. {t}",
                        self.waiting_head(),
                        if self.waiting.len() == 1 { "it" } else { "them" }
                    );
                }
                t
            }
            Kind::Locked => format!(
                "Synced {pulled} · nothing loaded until the passphrase is entered (`pathwarden history storage passphrase set`)"
            ),
            Kind::Failed => format!(
                "Couldn't sync with the repository ({}) · tried {pulled} · {last}; runs and settings here stay as they were. Git said: {}",
                tries(),
                said(),
            ),
            Kind::NotSignedIn if self.refused() => format!(
                "Sign-in refused by the repository · {} · {last}. Sign in with another account with `pathwarden history storage sign-in`. Git said: {}",
                self.tried_since(),
                said(),
            ),
            Kind::NotSignedIn => format!(
                "Not signed in to the repository · {} · {last}. Sign in with `pathwarden history storage sign-in`. Git said: {}",
                self.tried_since(),
                said(),
            ),
            Kind::NoHelper => format!(
                "Not signed in to the repository · {} · {last}. Git on this computer has no credential helper (`git config --get credential.helper` is empty). Install Git for Windows with Git Credential Manager, or run `git config --global credential.helper manager`, then `pathwarden history storage sign-in`. Git said: {}",
                self.tried_since(),
                said(),
            ),
        }
    }
}

/// "a", "a and b", "a, b and c" (already HTML).
fn names_html(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// "5 minutes", "1 minute".
pub fn minutes_words(n: u32) -> String {
    if n == 1 {
        "minute".into()
    } else {
        format!("{n} minutes")
    }
}

/// `history storage show`'s "Syncs" row.
pub fn every_words(n: u32) -> String {
    format!(
        "Every {} while the app is open, and when it opens",
        minutes_words(n)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> LastPull {
        LastPull {
            at: 1000,
            ok: true,
            by: "app".into(),
            last_ok: Some(1000),
            ..LastPull::default()
        }
    }

    #[test]
    fn the_words_for_each_state() {
        let s = status(None, 5, 1000);
        assert_eq!(s.kind, Kind::NotYet);
        assert_eq!(s.foot(), "Not synced yet");
        assert!(!s.warn());

        let s = status(Some(rec()), 5, 1000 + 125);
        assert_eq!(s.kind, Kind::UpToDate);
        assert_eq!(s.foot(), "Synced 2 min ago");
        let line = s.line_html();
        assert!(
            line.contains(
                "<strong>Up to date</strong><span> · synced 2 min ago · every 5 min</span>"
            ),
            "{line}"
        );
        // The (i) no longer says it never pushes: it does.
        assert!(!line.contains("Pushes changes"), "{line}");
        assert!(
            line.contains("Runs recorded here that are waiting"),
            "{line}"
        );
        assert!(line.contains("Set Sync every"), "{line}");
        assert!(!line.contains("Sign in"), "{line}");
        assert!(s.text().starts_with("Up to date · synced 2 min ago"));

        let s = status(Some(LastPull { runs: 2, ..rec() }), 5, 1010);
        assert_eq!(s.foot(), "2 runs loaded · just now");
        let s = status(
            Some(LastPull {
                sections: vec!["rules".into()],
                ..rec()
            }),
            5,
            1010,
        );
        assert_eq!(s.foot(), "Rules updated · just now");
        assert!(s.text().contains("Rules updated"));

        let s = status(
            Some(LastPull {
                conflict: true,
                ..rec()
            }),
            5,
            1010,
        );
        // Settings that differ from the shared ones are Settings' to say:
        // the footer and the line say only how the sync went.
        assert_eq!(s.kind, Kind::UpToDate);
        assert_eq!(s.foot(), "Synced just now");
        assert!(!s.warn());
        let foot = s.foot_html();
        assert!(
            !foot.contains("warn") && !foot.contains("differ") && !foot.contains("i-alert"),
            "{foot}"
        );
        let line = s.line_html();
        assert!(
            !line.contains("warn") && line.contains("Up to date"),
            "{line}"
        );
        assert!(!s.text().contains("differ"), "{}", s.text());

        let locked = LastPull {
            locked: true,
            ..rec()
        };
        let s = status(Some(locked), 5, 1000 + 120);
        assert_eq!(s.foot(), "Passphrase needed");
        let line = s.line_html();
        assert!(line.contains("<strong>Synced 2 min ago</strong><span> · nothing loaded until the passphrase is entered ·</span><a href=\"/runs\">Enter it on Runs</a>"), "{line}");

        let failed = LastPull {
            at: 1000 + 25 * 60,
            ok: false,
            error: Some("fatal: could not resolve <host>".into()),
            tries: 4,
            failing_since: Some(1000 + 10 * 60),
            last_ok: Some(1000),
            ..rec()
        };
        let s = status(Some(failed.clone()), 5, 1000 + 25 * 60);
        assert_eq!(s.kind, Kind::Failed);
        assert_eq!(s.foot(), "Couldn't sync with the repository");
        let line = s.line_html();
        assert!(line.contains("<strong>Couldn&#39;t sync with the repository.</strong><span>Retrying in 5 min. Last synced 25 min ago.</span>") || line.contains("<strong>Couldn't sync with the repository.</strong><span>Retrying in 5 min. Last synced 25 min ago.</span>"), "{line}");
        assert!(
            line.contains("fatal: could not resolve &lt;host&gt;"),
            "{line}"
        );
        assert!(line.contains("4 times since"), "{line}");
        assert!(
            line.contains("Runs and settings stay as they were."),
            "{line}"
        );
        assert!(!line.contains("Sign in"), "{line}");
        assert!(s.text().contains("4 times in a row"), "{}", s.text());
        // Failure goes before a passphrase or a choice.
        let foot = s.foot_html();
        assert!(
            foot.contains("pull-foot warn") && foot.contains("class=\"dot\""),
            "{foot}"
        );
        // Runs waiting don't hide a failure.
        let s = status(Some(failed.clone()), 5, 1000 + 25 * 60).with_waiting(vec![WaitingRun {
            at: 1000,
            full: true,
        }]);
        assert_eq!(s.kind, Kind::Failed);

        // Not signed in: no retrying (background syncs can't sign in), and
        // the Sign in button after the line.
        let out = LastPull {
            error: Some("git fetch failed: fatal: could not read Password for 'https://github.com': terminal prompts disabled".into()),
            sign_in: true,
            ..failed.clone()
        };
        let s = status(Some(out.clone()), 5, 1000 + 25 * 60);
        assert_eq!(s.kind, Kind::NotSignedIn);
        assert_eq!(s.foot(), "Not signed in to the repository");
        assert!(s.warn());
        let line = s.line_html();
        assert!(
            line.contains(
                "signed in to the repository.</strong><span>Last synced 25 min ago.</span>"
            ),
            "{line}"
        );
        assert!(!line.contains("Retrying"), "{line}");
        assert!(
            line.contains(
                "Opens the Git Credential Manager window. Pathwarden never sees the password."
            ),
            "{line}"
        );
        assert!(line.ends_with(r##"<button type="button" class="btn" data-history-action="sign-in"><svg class="ic" aria-hidden="true"><use href="#i-external"/></svg> Sign in</button>"##), "{line}");
        assert!(
            s.text().contains("pathwarden history storage sign-in"),
            "{}",
            s.text()
        );

        // No helper: what to install, and no button.
        let s = status(
            Some(LastPull {
                no_helper: true,
                ..out
            }),
            5,
            1000 + 25 * 60,
        );
        assert_eq!(s.kind, Kind::NoHelper);
        let line = s.line_html();
        assert!(line.contains("Git here has no sign-in helper. Install Git for Windows with Git Credential Manager, then sync again."), "{line}");
        assert!(!line.contains("data-history-action=\"sign-in\""), "{line}");
        assert!(
            line.contains("so git can&#39;t ask for an account")
                || line.contains("so git can't ask for an account"),
            "{line}"
        );
        assert_eq!(s.foot(), "Not signed in to the repository");

        // Waiting: calm, with the upload icon.
        let s = status(Some(rec()), 5, 1000 + 120).with_waiting(vec![WaitingRun {
            at: 1_793_138_340,
            full: true,
        }]);
        assert_eq!(s.kind, Kind::Waiting);
        assert!(!s.warn());
        assert_eq!(s.foot(), "1 run waiting to be pushed");
        assert!(s.foot_html().contains("#i-upload"));
        let line = s.line_html();
        assert!(line.contains(r##"<span class="pl-state"><svg class="ic" aria-hidden="true"><use href="#i-upload"/></svg><strong>1 run is waiting to be pushed.</strong><span>Last synced 2 min ago.</span>"##), "{line}");
        assert!(
            line.contains("Its numbers are in the history already."),
            "{line}"
        );
        assert!(line.contains("Pushes it, then gets the latest."), "{line}");
        assert!(
            line.contains("It goes with the next run recorded here."),
            "{line}"
        );
        assert!(
            s.text().starts_with("1 run is waiting to be pushed."),
            "{}",
            s.text()
        );
    }

    /// The runs waiting come with the record; one kept only for them is no
    /// sync; a refusal reads as one.
    #[test]
    fn waiting_from_the_record_and_refusals() {
        let w = WaitingRun {
            at: 1_793_138_340,
            full: false,
        };
        // Noted before any sync: waiting, never "synced " with no time.
        let only = LastPull {
            waiting: vec![w],
            ..LastPull::default()
        };
        let s = status(Some(only), 5, 1000);
        assert_eq!(s.kind, Kind::Waiting);
        assert!(s.last.is_none());
        assert!(
            s.text().contains("Not synced yet on this computer"),
            "{}",
            s.text()
        );
        assert!(!s.text().contains("synced ·") && !s.text().ends_with("synced "));
        assert!(s.line_html().contains("<span>Not synced yet.</span>"));
        // Worked out again (the CLI): none waiting any more.
        let s = status(
            Some(LastPull {
                waiting: vec![w],
                ..rec()
            }),
            5,
            1010,
        );
        assert_eq!(s.kind, Kind::Waiting);
        assert_eq!(s.with_waiting(Vec::new()).kind, Kind::UpToDate);
        let s = status(
            Some(LastPull {
                waiting: vec![w],
                ..LastPull::default()
            }),
            5,
            1010,
        )
        .with_waiting(Vec::new());
        assert_eq!(s.kind, Kind::NotYet);

        // Refused: the repository's words, with Sign in.
        let r = LastPull {
            at: 2000,
            ok: false,
            error: Some("remote: HTTP Basic: Access denied".into()),
            tries: 1,
            failing_since: Some(2000),
            sign_in: true,
            refused: true,
            ..rec()
        };
        let s = status(Some(r), 5, 2000);
        assert_eq!(s.kind, Kind::NotSignedIn);
        assert_eq!(s.foot(), "Sign-in refused by the repository");
        let line = s.line_html();
        assert!(
            line.contains("<strong>The repository refused this computer&#39;s sign-in.</strong>"),
            "{line}"
        );
        assert!(line.contains("data-history-action=\"sign-in\""), "{line}");
        assert!(
            s.text().starts_with("Sign-in refused by the repository"),
            "{}",
            s.text()
        );
    }

    #[test]
    fn times_ago() {
        assert_eq!(ago(-5), "just now");
        assert_eq!(ago(59), "just now");
        assert_eq!(ago(60), "1 min ago");
        assert_eq!(ago(3600 * 3), "3 h ago");
        assert_eq!(ago(86_400), "1 day ago");
        assert_eq!(ago(86_400 * 3), "3 days ago");
    }
}
