//! Logs and crash reports (docs/running.md, "Logs and crash reports").
//!
//! One log per app session (`session-<time>.log`) and one per job
//! (`job-<time>-<kind>.log`): a collection with the collector's output and
//! exit code, an analysis, `run`, a retest, a history sync, each finding
//! action. The first line names the job and what started it; every line
//! after it is `HH:MM:SS.mmm [<kind>, <started by>] <text>`, passed through
//! [`crate::redact::log_line`] and flushed as it is written, so the last
//! lines survive a hard crash. A job's last line is its result
//! (`result: ok`, `result: failed: ...`, `result: stopped`).
//!
//! A panic writes `crash-<time>.txt` ([`install_crash_hook`]): the message,
//! where it happened, the backtrace, the version, the job that was running
//! and its log's last [`CRASH_TAIL`] lines. The latest one not dismissed
//! ([`pending_crash`], [`dismiss`]) is what the app's Settings shows.
//!
//! The folder ([`dir`]) is `%LOCALAPPDATA%\Pathwarden\logs` on Windows,
//! `$XDG_STATE_HOME/pathwarden/logs` (or `~/.local/state/pathwarden/logs`)
//! elsewhere, private to this account like the workspace. Logs are kept
//! [`KEEP_DAYS`] days and [`KEEP_BYTES`] in all ([`prune`]). Debug builds
//! write none unless [`TEST_DIR_ENV`] names a folder, so tests never touch
//! this account's logs.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// Days a log or crash report is kept.
pub const KEEP_DAYS: i64 = 30;
/// The most the folder keeps in all; the oldest files go first.
pub const KEEP_BYTES: u64 = 200 << 20;
/// The most one log grows to: later lines are left out, its result isn't.
pub const MAX_LOG_BYTES: u64 = 50 << 20;
/// The job log's last lines a crash report holds.
pub const CRASH_TAIL: usize = 200;
/// Days of logs the diagnostics bundle takes ([`for_bundle`]).
pub const BUNDLE_DAYS: i64 = 7;
/// The most log text the diagnostics bundle takes.
pub const BUNDLE_BYTES: u64 = 20 << 20;
/// Debug builds only: the logs folder (none without it).
pub const TEST_DIR_ENV: &str = "PATHWARDEN_TEST_LOGS";
/// What the folder keeps, in words (the Settings card, `pathwarden logs`).
pub const KEPT_WORDS: &str = "kept 30 days, at most 200 MB";

/// The file that names the latest crash report dismissed.
const DISMISSED_FILE: &str = "dismissed-crash.txt";
/// Which log each finding action's activity entry has ([`note_action`]).
const ACTIONS_FILE: &str = "action-logs.txt";

/// What a log is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Session,
    Collect,
    Analyze,
    Run,
    Retest,
    Sync,
    Action,
}

impl Kind {
    pub const ALL: [Kind; 7] = [
        Kind::Session,
        Kind::Collect,
        Kind::Analyze,
        Kind::Run,
        Kind::Retest,
        Kind::Sync,
        Kind::Action,
    ];

    /// Its word in file names and lines: `collect`.
    pub fn slug(self) -> &'static str {
        match self {
            Kind::Session => "session",
            Kind::Collect => "collect",
            Kind::Analyze => "analyze",
            Kind::Run => "run",
            Kind::Retest => "retest",
            Kind::Sync => "sync",
            Kind::Action => "action",
        }
    }

    pub fn from_slug(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.slug() == s)
    }

    /// "Collection", as a list names it.
    pub fn title(self) -> &'static str {
        match self {
            Kind::Session => "App session",
            Kind::Collect => "Collection",
            Kind::Analyze => "Analysis",
            Kind::Run => "Run",
            Kind::Retest => "Retest",
            Kind::Sync => "History sync",
            Kind::Action => "Action",
        }
    }

    /// "a collection": what Pathwarden was doing when it stopped.
    pub fn during(self) -> &'static str {
        match self {
            Kind::Session => "",
            Kind::Collect => "a collection",
            Kind::Analyze => "an analysis",
            Kind::Run => "a run",
            Kind::Retest => "a retest",
            Kind::Sync => "a history sync",
            Kind::Action => "a finding action",
        }
    }
}

/// What started a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum By {
    App,
    CommandLine,
    Schedule,
}

impl By {
    /// "command line": its word in a line and a list.
    pub fn word(self) -> &'static str {
        match self {
            By::App => "app",
            By::CommandLine => "command line",
            By::Schedule => "schedule",
        }
    }

    pub fn from_word(s: &str) -> Option<By> {
        [By::App, By::CommandLine, By::Schedule]
            .into_iter()
            .find(|b| b.word() == s)
    }

    /// "started in the app".
    pub fn started(self) -> &'static str {
        match self {
            By::App => "started in the app",
            By::CommandLine => "started on the command line",
            By::Schedule => "started by a schedule",
        }
    }

    /// A command-line job: by a schedule when `PATHWARDEN_SCHEDULED` is
    /// set (the scheduled task's script sets it).
    pub fn command_line() -> By {
        if std::env::var_os("PATHWARDEN_SCHEDULED").is_some_and(|v| !v.is_empty() && v != "0") {
            By::Schedule
        } else {
            By::CommandLine
        }
    }
}

// ------------------------------------------------------------------ folder

/// The logs folder (not created): `None` when this account's environment
/// doesn't say where its data is, and in debug builds without
/// [`TEST_DIR_ENV`].
pub fn dir() -> Option<PathBuf> {
    if cfg!(debug_assertions) {
        return std::env::var_os(TEST_DIR_ENV)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
    }
    dir_from(|n| std::env::var_os(n), cfg!(windows))
}

/// [`dir`] from the environment `var` gives, for Windows or not.
/// `XDG_STATE_HOME` counts only when absolute (the XDG rule).
pub fn dir_from(
    var: impl Fn(&str) -> Option<std::ffi::OsString>,
    windows: bool,
) -> Option<PathBuf> {
    let var = |n: &str| {
        var(n)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if windows {
        var("LOCALAPPDATA").map(|d| d.join("Pathwarden").join("logs"))
    } else {
        var("XDG_STATE_HOME")
            .or_else(|| var("HOME").map(|h| h.join(".local").join("state")))
            .map(|d| d.join("pathwarden").join("logs"))
    }
}

/// Creates `dir` private to this account when missing; makes an existing
/// one private when it isn't.
pub fn ensure(dir: &Path) -> io::Result<()> {
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    match crate::perms::create_private_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if fs::symlink_metadata(dir)?.is_dir() && !crate::perms::is_private_dir(dir) {
                crate::perms::make_private(dir)?;
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

// --------------------------------------------------------------- the time

fn now() -> i64 {
    crate::analyze::now()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

/// `20261119-094211`, this computer's time: file names.
fn stamp(t: i64) -> String {
    let (y, m, d, s) = crate::time::local_civil(t);
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

/// `09:42:11.204`, this computer's time: a line's.
fn clock_ms(ms: i64) -> String {
    let (_, _, _, s) = crate::time::local_civil(ms.div_euclid(1000));
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        s / 3600,
        s % 3600 / 60,
        s % 60,
        ms.rem_euclid(1000)
    )
}

/// The `20261119-094211` of a file name: (year, month, day, hour, minute).
fn stamp_of(name: &str) -> Option<(i64, i64, i64, i64, i64)> {
    let rest = name
        .strip_prefix("job-")
        .or_else(|| name.strip_prefix("session-"))
        .or_else(|| name.strip_prefix("crash-"))?;
    let s = rest.get(..15)?;
    let n = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    (s.as_bytes()[8] == b'-').then_some(())?;
    Some((n(0, 4)?, n(4, 6)?, n(6, 8)?, n(9, 11)?, n(11, 13)?))
}

/// "Nov 19 09:42": when a file was made, as its name says (this
/// computer's time).
pub fn when_words(name: &str) -> String {
    match stamp_of(name) {
        Some((_, m, d, hh, mm)) => format!(
            "{} {d} {hh:02}:{mm:02}",
            crate::time::MONTHS[(m.clamp(1, 12) - 1) as usize]
        ),
        None => "-".into(),
    }
}

/// "Nov 19, 9:47 AM": the same, as the app writes a time.
pub fn when_page(name: &str) -> String {
    match stamp_of(name) {
        Some((_, m, d, hh, mm)) => {
            let (h12, half) = match hh {
                0 => (12, "AM"),
                1..=11 => (hh, "AM"),
                12 => (12, "PM"),
                _ => (hh - 12, "PM"),
            };
            format!(
                "{} {d}, {h12}:{mm:02} {half}",
                crate::time::MONTHS[(m.clamp(1, 12) - 1) as usize]
            )
        }
        None => String::new(),
    }
}

/// Whether `name` is a file this module writes.
pub fn is_log_name(name: &str) -> bool {
    let ok_chars = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    ok_chars
        && !name.starts_with('.')
        && !name.contains("..")
        && name.len() <= 80
        && stamp_of(name).is_some()
        && ((name.starts_with("crash-") && name.ends_with(".txt"))
            || ((name.starts_with("job-") || name.starts_with("session-"))
                && name.ends_with(".log")))
}

// -------------------------------------------------------------- a log

struct Writer {
    file: File,
    written: u64,
    cut: bool,
    ended: bool,
}

/// A log being written: a session's or a job's.
pub struct JobLog {
    path: PathBuf,
    name: String,
    kind: Kind,
    by: By,
    /// "Collection SCALE.LOCAL".
    title: String,
    out: Mutex<Writer>,
}

/// The logs open in this process, for the crash hook.
static LIVE: Mutex<Vec<Weak<JobLog>>> = Mutex::new(Vec::new());

thread_local! {
    /// The job this thread works for ([`JobLog::enter`]).
    static CURRENT: std::cell::RefCell<Option<Weak<JobLog>>> = const { std::cell::RefCell::new(None) };
    /// A panic is being reported on this thread.
    static IN_HOOK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// One line's text, safe for one line of a log.
fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() && c != '\t' { ' ' } else { c })
        .collect::<String>()
        .trim_end()
        .to_string()
}

impl JobLog {
    /// A new log in [`dir`]; `None` when there is no folder or it can't be
    /// written (a log never stops what it logs).
    pub fn open(kind: Kind, by: By, subject: &str) -> Option<Arc<JobLog>> {
        Self::open_in(&dir()?, kind, by, subject).ok()
    }

    /// A new log in `dir`: its first line names the job (`Collection`
    /// and `subject`) and what started it. Prunes the folder first, once
    /// per process.
    pub fn open_in(dir: &Path, kind: Kind, by: By, subject: &str) -> io::Result<Arc<JobLog>> {
        ensure(dir)?;
        prune_once(dir);
        let base = match kind {
            Kind::Session => format!("session-{}", stamp(now())),
            k => format!("job-{}-{}", stamp(now()), k.slug()),
        };
        let mut n = 1;
        let (file, name) = loop {
            let name = if n == 1 {
                format!("{base}.log")
            } else {
                format!("{base}-{n}.log")
            };
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(&name))
            {
                Ok(f) => break (f, name),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && n < 100 => n += 1,
                Err(e) => return Err(e),
            }
        };
        let subject = crate::redact::log_line(&one_line(subject)).replace('|', "/");
        let title = if subject.is_empty() {
            kind.title().to_string()
        } else {
            format!("{} {subject}", kind.title())
        };
        let log = Arc::new(JobLog {
            path: dir.join(&name),
            name,
            kind,
            by,
            title,
            out: Mutex::new(Writer {
                file,
                written: 0,
                cut: false,
                ended: false,
            }),
        });
        log.raw(&format!(
            "# {} | {} | {} | Pathwarden {}",
            log.title,
            by.word(),
            kind.slug(),
            env!("CARGO_PKG_VERSION")
        ));
        let mut live = LIVE.lock().unwrap_or_else(|e| e.into_inner());
        live.retain(|w| w.strong_count() > 0);
        live.push(Arc::downgrade(&log));
        drop(live);
        log.line(&format!("{} {}", log.title, by.started()));
        Ok(log)
    }

    /// The file's name: `job-20261119-094211-collect.log`.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn by(&self) -> By {
        self.by
    }

    /// "Collection SCALE.LOCAL".
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Whether its result was written.
    pub fn ended(&self) -> bool {
        // Never waits: the crash hook asks, maybe on a thread that holds it.
        self.out.try_lock().map(|w| w.ended).unwrap_or(false)
    }

    fn raw(&self, text: &str) {
        let mut w = self.out.lock().unwrap_or_else(|e| e.into_inner());
        let _ = w.file.write_all(text.as_bytes());
        let _ = w.file.write_all(b"\n");
        let _ = w.file.flush();
        w.written += text.len() as u64 + 1;
    }

    /// Writes `text`, each of its lines time-stamped with the job and what
    /// started it, redacted, and flushed.
    pub fn line(&self, text: &str) {
        self.write(text, false, false);
    }

    /// [`JobLog::line`] unless the log is busy: for the crash hook, which
    /// may run on a thread that is writing it.
    fn try_line(&self, text: &str) {
        self.write(text, false, true);
    }

    fn write(&self, text: &str, last: bool, try_only: bool) {
        let prefix = format!("[{}, {}]", self.kind.slug(), self.by.word());
        let at = clock_ms(now_ms());
        let got = if try_only {
            match self.out.try_lock() {
                Ok(w) => Some(w),
                Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            }
        } else {
            Some(self.out.lock().unwrap_or_else(|e| e.into_inner()))
        };
        let Some(mut w) = got else {
            return;
        };
        if w.ended && !last {
            return;
        }
        for l in text.lines().map(one_line).filter(|l| !l.is_empty()) {
            if w.cut && !last {
                return;
            }
            let l: String = crate::redact::log_line(&l).chars().take(8000).collect();
            let s = format!("{at} {prefix} {l}\n");
            let _ = w.file.write_all(s.as_bytes());
            w.written += s.len() as u64;
            if w.written > MAX_LOG_BYTES && !w.cut && !last {
                w.cut = true;
                let s = format!(
                    "{at} {prefix} (later lines are left out: a log keeps at most {})\n",
                    crate::diagnostics::bytes(MAX_LOG_BYTES)
                );
                let _ = w.file.write_all(s.as_bytes());
            }
        }
        let _ = w.file.flush();
    }

    /// Writes the result, once: `ok`, `failed` with why, or `stopped`.
    pub fn end(&self, result: Outcome, detail: &str) {
        {
            let w = self.out.lock().unwrap_or_else(|e| e.into_inner());
            if w.ended {
                return;
            }
        }
        let detail = one_line(detail);
        let text = match (result, detail.is_empty()) {
            (r, true) => format!("result: {}", r.word()),
            (r, false) => format!("result: {}: {detail}", r.word()),
        };
        self.write(&text, true, false);
        self.out.lock().unwrap_or_else(|e| e.into_inner()).ended = true;
    }

    /// Makes this the job of the current thread until the guard drops:
    /// what a crash report on this thread names.
    pub fn enter(self: &Arc<Self>) -> Entered {
        let before = CURRENT.with(|c| c.replace(Some(Arc::downgrade(self))));
        Entered { before }
    }
}

/// [`JobLog::enter`]'s guard.
pub struct Entered {
    before: Option<Weak<JobLog>>,
}

impl Drop for Entered {
    fn drop(&mut self) {
        let before = self.before.take();
        CURRENT.with(|c| *c.borrow_mut() = before);
    }
}

/// How a job ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Failed,
    Stopped,
}

impl Outcome {
    pub fn word(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Failed => "failed",
            Outcome::Stopped => "stopped",
        }
    }
}

/// The log of the job this process or thread runs: the thread's
/// ([`JobLog::enter`]), else the newest job still open, else the session.
fn running() -> Option<Arc<JobLog>> {
    if let Some(l) = CURRENT
        .try_with(|c| {
            c.try_borrow()
                .ok()
                .and_then(|c| c.as_ref().and_then(Weak::upgrade))
        })
        .ok()
        .flatten()
    {
        return Some(l);
    }
    let live = LIVE.try_lock().ok()?;
    let open: Vec<Arc<JobLog>> = live.iter().filter_map(Weak::upgrade).collect();
    drop(live);
    open.iter()
        .rev()
        .find(|l| l.kind != Kind::Session && !l.ended())
        .or_else(|| open.iter().rev().find(|l| l.kind == Kind::Session))
        .cloned()
}

/// The log of the job this thread works for ([`JobLog::enter`]).
pub fn current() -> Option<Arc<JobLog>> {
    CURRENT
        .try_with(|c| {
            c.try_borrow()
                .ok()
                .and_then(|c| c.as_ref().and_then(Weak::upgrade))
        })
        .ok()
        .flatten()
}

/// Writes `text` to the log of the job this thread works for, if any.
pub fn note(text: &str) {
    if let Some(l) = current() {
        l.line(text);
    }
}

/// The session log open in this process, if any.
fn session() -> Option<Arc<JobLog>> {
    let live = LIVE.try_lock().ok()?;
    live.iter()
        .filter_map(Weak::upgrade)
        .rev()
        .find(|l| l.kind == Kind::Session)
}

/// Writes `text` to the session log, when this process has one.
pub fn session_line(text: &str) {
    if let Some(s) = session() {
        s.line(text);
    }
}

// ------------------------------------------------------------ retention

/// Deletes logs and crash reports older than [`KEEP_DAYS`], then the
/// oldest until the folder holds at most [`KEEP_BYTES`]; never a log this
/// process has open, nor any other file. Returns how many it deleted.
pub fn prune(dir: &Path, now: i64) -> usize {
    prune_to(dir, now, KEEP_DAYS, KEEP_BYTES)
}

fn prune_to(dir: &Path, now: i64, days: i64, max: u64) -> usize {
    let open: Vec<PathBuf> = LIVE
        .lock()
        .map(|l| {
            l.iter()
                .filter_map(Weak::upgrade)
                .map(|l| l.path.clone())
                .collect()
        })
        .unwrap_or_default();
    let mut files = files_in(dir);
    // Oldest first.
    files.sort_by_key(|f| f.modified);
    let mut removed = 0;
    let mut total: u64 = files.iter().map(|f| f.bytes).sum();
    let old = now - days * 86_400;
    for f in &files {
        if open.contains(&f.path) {
            continue;
        }
        if (f.modified < old || total > max) && fs::remove_file(&f.path).is_ok() {
            removed += 1;
            total = total.saturating_sub(f.bytes);
        }
    }
    if removed > 0 {
        prune_actions(dir);
    }
    removed
}

fn prune_once(dir: &Path) {
    static DONE: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
    let mut done = DONE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !done.iter().any(|d| d == dir) {
        done.push(dir.to_path_buf());
        prune(dir, now());
    }
}

struct FileInfo {
    path: PathBuf,
    name: String,
    bytes: u64,
    modified: i64,
    modified_ns: u128,
}

/// This module's files in `dir` (no links, no other files).
fn files_in(dir: &Path) -> Vec<FileInfo> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if !is_log_name(&name) {
                return None;
            }
            let meta = fs::symlink_metadata(e.path()).ok()?;
            if !meta.is_file() {
                return None;
            }
            let since = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .unwrap_or_default();
            Some(FileInfo {
                path: e.path(),
                name,
                bytes: meta.len(),
                modified: since.as_secs() as i64,
                modified_ns: since.as_nanos(),
            })
        })
        .collect()
}

// -------------------------------------------------------------- reading

/// A log or crash report, as `pathwarden logs` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub kind: Option<Kind>,
    /// "Collection SCALE.LOCAL", or "Pathwarden crashed".
    pub title: String,
    /// "app", "command line" or "schedule".
    pub by: String,
    /// `ok`, `failed`, `stopped`, `crashed`, or `-` (none written: still
    /// running, or stopped without one).
    pub result: String,
    pub crash: bool,
}

/// Every log and crash report in `dir`, newest first.
pub fn list(dir: &Path) -> Vec<Entry> {
    let mut files = files_in(dir);
    newest_first(&mut files);
    let crashes: Vec<CrashReport> = files
        .iter()
        .filter(|f| f.name.starts_with("crash-"))
        .filter_map(|f| CrashReport::read(&f.path))
        .collect();
    files
        .into_iter()
        .map(|f| {
            if f.name.starts_with("crash-") {
                let c = crashes.iter().find(|c| c.name == f.name);
                return Entry {
                    title: "Pathwarden crashed".into(),
                    by: c.and_then(|c| c.by.clone()).unwrap_or_else(|| "-".into()),
                    result: "-".into(),
                    crash: true,
                    kind: None,
                    name: f.name,
                    path: f.path,
                    bytes: f.bytes,
                };
            }
            let head = first_line(&f.path).unwrap_or_default();
            let parts: Vec<&str> = head.trim_start_matches("# ").split(" | ").collect();
            let kind = parts.get(2).and_then(|k| Kind::from_slug(k));
            let mut result = last_result(&f.path).unwrap_or_else(|| "-".into());
            if result == "-"
                && crashes
                    .iter()
                    .any(|c| c.job_log.as_deref() == Some(&f.name))
            {
                result = "crashed".into();
            }
            Entry {
                title: parts
                    .first()
                    .filter(|t| !t.is_empty())
                    .map_or_else(|| f.name.clone(), |t| t.to_string()),
                by: parts.get(1).map_or("-", |b| b).to_string(),
                result,
                crash: false,
                kind,
                name: f.name,
                path: f.path,
                bytes: f.bytes,
            }
        })
        .collect()
}

/// How files sort, oldest first: by the time in the name, then by the
/// `-2` a second file of the same second gets.
fn order(name: &str) -> (String, u32) {
    let stamp = name
        .find('-')
        .and_then(|i| name.get(i + 1..i + 16))
        .unwrap_or_default()
        .to_string();
    let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
    let n = stem
        .rsplit_once('-')
        .and_then(|(_, n)| (n.len() <= 2).then(|| n.parse::<u32>().ok()).flatten())
        .unwrap_or(1);
    (stamp, n)
}

/// Newest first: the time in the name, then the last written.
fn newest_first(files: &mut [FileInfo]) {
    files.sort_by(|a, b| {
        let (ka, kb) = (order(&a.name), order(&b.name));
        kb.0.cmp(&ka.0)
            .then(b.modified_ns.cmp(&a.modified_ns))
            .then(kb.1.cmp(&ka.1))
    });
}

fn first_line(path: &Path) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0u8; 1024];
    let n = f.read(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);
    text.lines().next().map(str::to_string)
}

/// The last `bytes` of a file, from a line start.
fn tail_text(path: &Path, bytes: u64) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let from = len.saturating_sub(bytes);
    f.seek(SeekFrom::Start(from)).ok()?;
    let mut buf = Vec::new();
    f.take(bytes).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    Some(if from > 0 {
        text.split_once('\n')
            .map_or(text.clone(), |(_, r)| r.to_string())
    } else {
        text
    })
}

/// A log's last `n` lines (its first, the header, left out).
pub fn tail(path: &Path, n: usize) -> Vec<String> {
    let text = tail_text(path, 256 * 1024).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|l| !l.starts_with("# ")).collect();
    lines[lines.len().saturating_sub(n)..]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// The result word of a log's last line, if it has one.
fn last_result(path: &Path) -> Option<String> {
    let text = tail_text(path, 8192)?;
    let last = text.lines().last()?;
    let (_, rest) = last.split_once("] result: ")?;
    Some(rest.split(':').next().unwrap_or(rest).trim().to_string())
}

/// The newest job log (not a session's) in `dir`.
pub fn last_job(dir: &Path) -> Option<Entry> {
    list(dir)
        .into_iter()
        .find(|e| !e.crash && e.kind != Some(Kind::Session))
}

/// The file `name` in the logs folder `dir`, for opening it: only a name
/// this module writes, a plain file (not a link) right in that folder.
pub fn file_in(dir: &Path, name: &str) -> Option<PathBuf> {
    if !is_log_name(name) {
        return None;
    }
    let path = dir.join(name);
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let real = fs::canonicalize(&path).ok()?;
    let folder = fs::canonicalize(dir).ok()?;
    (real.parent() == Some(folder.as_path())).then_some(path)
}

// -------------------------------------------------------- crash reports

/// What a crash report says, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashReport {
    pub name: String,
    pub path: PathBuf,
    pub version: String,
    pub system: String,
    pub message: String,
    pub location: String,
    /// What was running, if a job was.
    pub during: Option<Kind>,
    /// That job's subject ("SCALE.LOCAL").
    pub subject: String,
    /// That job's log.
    pub job_log: Option<String>,
    pub by: Option<String>,
}

impl CrashReport {
    pub fn read(path: &Path) -> Option<CrashReport> {
        let name = path.file_name()?.to_string_lossy().into_owned();
        let text = tail_text_head(path)?;
        let field = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(k))
                .map(|v| v.trim().to_string())
        };
        Some(CrashReport {
            path: path.to_path_buf(),
            version: field("Pathwarden:").unwrap_or_default(),
            system: field("System:").unwrap_or_default(),
            message: field("Message:").unwrap_or_default(),
            location: field("Where:").unwrap_or_default(),
            during: field("Kind:").and_then(|k| Kind::from_slug(&k)),
            subject: field("Subject:").unwrap_or_default(),
            job_log: field("Job log:").filter(|l| is_log_name(l)),
            by: field("Started by:").filter(|b| By::from_word(b).is_some()),
            name,
        })
    }

    /// "Stopped unexpectedly during a collection, Nov 19, 9:47 AM.": the
    /// app's line.
    pub fn line(&self) -> String {
        match self.during.filter(|k| *k != Kind::Session) {
            Some(k) => format!(
                "Stopped unexpectedly during {}, {}.",
                k.during(),
                when_page(&self.name)
            ),
            None => format!("Stopped unexpectedly, {}.", when_page(&self.name)),
        }
    }

    /// "Stopped unexpectedly Nov 19 09:47, during a collection of
    /// SCALE.LOCAL.": the command line's.
    pub fn sentence(&self) -> String {
        let during = match self.during.filter(|k| *k != Kind::Session) {
            Some(k) if !self.subject.is_empty() => {
                let of = if k == Kind::Action { ": " } else { " of " };
                format!(", during {}{of}{}", k.during(), self.subject)
            }
            Some(k) => format!(", during {}", k.during()),
            None => String::new(),
        };
        format!("Stopped unexpectedly {}{during}.", when_words(&self.name))
    }
}

/// The head of a crash report (its fields come first).
fn tail_text_head(path: &Path) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0u8; 16 * 1024];
    let n = f.read(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// The newest crash report in `dir`.
pub fn last_crash(dir: &Path) -> Option<CrashReport> {
    let mut names: Vec<FileInfo> = files_in(dir)
        .into_iter()
        .filter(|f| f.name.starts_with("crash-"))
        .collect();
    names.sort_by_key(|f| std::cmp::Reverse(order(&f.name)));
    names.iter().find_map(|f| CrashReport::read(&f.path))
}

/// The newest crash report not dismissed ([`dismiss`]): what the app's
/// Settings shows, with the amber dot by Settings.
pub fn pending_crash(dir: &Path) -> Option<CrashReport> {
    let c = last_crash(dir)?;
    let dismissed = fs::read_to_string(dir.join(DISMISSED_FILE)).unwrap_or_default();
    let dismissed = dismissed.trim();
    (!is_log_name(dismissed) || order(&c.name) > order(dismissed)).then_some(c)
}

/// Dismisses the crash reports there are now, on this computer.
pub fn dismiss(dir: &Path) -> io::Result<()> {
    let Some(c) = last_crash(dir) else {
        return Ok(());
    };
    ensure(dir)?;
    let tmp = dir.join(format!(".{DISMISSED_FILE}.{}", std::process::id()));
    fs::write(&tmp, &c.name)?;
    fs::rename(&tmp, dir.join(DISMISSED_FILE))
}

/// How many crash reports one process writes at most.
const MAX_CRASHES: usize = 5;

/// Installs the panic hook that writes a crash report to [`dir`] (then
/// runs the hook there was). `system` is this computer's OS, as the
/// diagnostics bundle says it.
pub fn install_crash_hook(system: String) {
    let before = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let first = IN_HOOK.try_with(|h| !h.replace(true)).unwrap_or(false);
        if first {
            if let Some(dir) = dir() {
                let _ = write_crash(&dir, info, &system);
            }
            let _ = IN_HOOK.try_with(|h| h.set(false));
        }
        before(info);
    }));
}

/// Writes the crash report of the panic `info` in `dir`, and a line about
/// it in the running job's log and the session's. Returns its name.
pub fn write_crash(
    dir: &Path,
    info: &std::panic::PanicHookInfo<'_>,
    system: &str,
) -> io::Result<String> {
    static WRITTEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if WRITTEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= MAX_CRASHES {
        return Err(io::Error::other("enough crash reports"));
    }
    let message = info
        .payload()
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| info.payload().downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "(no message)".into());
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_default();
    let thread = std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .to_string();
    let backtrace = std::backtrace::Backtrace::force_capture().to_string();
    let job = running();
    let crash = Crash {
        message,
        location,
        thread,
        backtrace,
        system: system.to_string(),
        job: job.as_ref().map(|j| JobRef {
            kind: j.kind,
            by: j.by,
            subject: j
                .title
                .strip_prefix(j.kind.title())
                .unwrap_or_default()
                .trim()
                .to_string(),
            name: j.name.clone(),
            path: j.path.clone(),
        }),
    };
    let name = crash.write_in(dir)?;
    if let Some(j) = &job {
        j.try_line(&format!("internal error: see {name}"));
    }
    if let Some(s) = session().filter(|s| job.as_ref().is_none_or(|j| !Arc::ptr_eq(j, s))) {
        s.try_line(&format!("internal error: see {name}"));
    }
    Ok(name)
}

/// The job a crash report names.
pub struct JobRef {
    pub kind: Kind,
    pub by: By,
    pub subject: String,
    pub name: String,
    pub path: PathBuf,
}

/// What a crash report holds.
pub struct Crash {
    pub message: String,
    pub location: String,
    pub thread: String,
    pub backtrace: String,
    pub system: String,
    pub job: Option<JobRef>,
}

impl Crash {
    /// Writes `crash-<time>.txt` in `dir`; returns its name.
    pub fn write_in(&self, dir: &Path) -> io::Result<String> {
        ensure(dir)?;
        let t = now();
        let red = |s: &str| crate::redact::log_line(&one_line(s));
        let mut text = String::new();
        let (y, m, d, s) = crate::time::local_civil(t);
        text.push_str("Pathwarden crash report\n\n");
        text.push_str(&format!("Pathwarden: {}\n", env!("CARGO_PKG_VERSION")));
        text.push_str(&format!(
            "System: {}, {}\n",
            red(&self.system),
            std::env::consts::ARCH
        ));
        text.push_str(&format!(
            "When: {y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} (this computer's time)\n",
            s / 3600,
            s % 3600 / 60,
            s % 60
        ));
        match &self.job {
            Some(j) => {
                text.push_str(&format!(
                    "During: {}, {}\n",
                    if j.kind == Kind::Session {
                        "the app session".to_string()
                    } else {
                        j.kind.during().to_string()
                    },
                    j.by.started()
                ));
                text.push_str(&format!("Kind: {}\n", j.kind.slug()));
                if !j.subject.is_empty() {
                    text.push_str(&format!("Subject: {}\n", red(&j.subject)));
                }
                text.push_str(&format!("Started by: {}\n", j.by.word()));
                text.push_str(&format!("Job log: {}\n", j.name));
            }
            None => text.push_str("During: no job\n"),
        }
        text.push_str(&format!("Message: {}\n", red(&self.message)));
        text.push_str(&format!("Where: {}\n", red(&self.location)));
        text.push_str(&format!("Thread: {}\n", red(&self.thread)));
        text.push_str("\nBacktrace:\n");
        for l in self.backtrace.lines() {
            text.push_str(&crate::redact::log_line(l));
            text.push('\n');
        }
        if let Some(j) = &self.job {
            text.push_str(&format!("\nThe last {CRASH_TAIL} lines of {}:\n", j.name));
            for l in tail(&j.path, CRASH_TAIL) {
                text.push_str(&l);
                text.push('\n');
            }
        }
        let mut n = 1;
        loop {
            let name = if n == 1 {
                format!("crash-{}.txt", stamp(t))
            } else {
                format!("crash-{}-{n}.txt", stamp(t))
            };
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(&name))
            {
                Ok(mut f) => {
                    f.write_all(text.as_bytes())?;
                    f.flush()?;
                    return Ok(name);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && n < 100 => n += 1,
                Err(e) => return Err(e),
            }
        }
    }
}

// ------------------------------------------------------- finding actions

/// Records that the activity entry `at` on finding `fingerprint` has the
/// log `file`, so its Activity entry can offer Open log on this computer.
pub fn note_action(dir: &Path, fingerprint: &str, at: &str, file: &str) {
    let clean = |s: &str| !s.is_empty() && s.len() <= 128 && !s.contains(['\t', '\n', '\r']);
    if !(clean(fingerprint) && clean(at) && is_log_name(file)) {
        return;
    }
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(ACTIONS_FILE))
    {
        let _ = writeln!(f, "{fingerprint}\t{at}\t{file}");
    }
}

/// Every activity entry's log on this computer, by (fingerprint, at),
/// whose log is still there.
pub fn action_logs(dir: &Path) -> HashMap<(String, String), String> {
    let text = fs::read_to_string(dir.join(ACTIONS_FILE)).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let mut p = l.split('\t');
            let (fp, at, file) = (p.next()?, p.next()?, p.next()?);
            (is_log_name(file) && dir.join(file).is_file())
                .then(|| ((fp.to_string(), at.to_string()), file.to_string()))
        })
        .collect()
}

/// Drops the entries whose log is gone.
fn prune_actions(dir: &Path) {
    let path = dir.join(ACTIONS_FILE);
    let Ok(text) = fs::read_to_string(&path) else {
        return;
    };
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| {
            l.rsplit('\t')
                .next()
                .is_some_and(|f| is_log_name(f) && dir.join(f).is_file())
        })
        .collect();
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    let _ = fs::write(&path, out);
}

// ---------------------------------------------------------- diagnostics

/// What the diagnostics bundle takes from `dir`: every crash report, then
/// the logs of the last [`BUNDLE_DAYS`] days, newest first, up to
/// [`BUNDLE_BYTES`] in all (a log that doesn't fit whole gives its last
/// part). Names as they are: the bundle replaces them.
pub fn for_bundle(dir: &Path, now: i64) -> Vec<(String, String)> {
    let mut files = files_in(dir);
    newest_first(&mut files);
    let since = now - BUNDLE_DAYS * 86_400;
    let mut left = BUNDLE_BYTES;
    let mut out = Vec::new();
    let crashes = files.iter().filter(|f| f.name.starts_with("crash-"));
    let logs = files
        .iter()
        .filter(|f| !f.name.starts_with("crash-") && f.modified >= since);
    for f in crashes.chain(logs) {
        if left == 0 {
            break;
        }
        let text = if f.bytes <= left {
            fs::read(&f.path)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .ok()
        } else {
            tail_text(&f.path, left).map(|t| format!("(earlier lines left out)\n{t}"))
        };
        if let Some(t) = text {
            left = left.saturating_sub(t.len() as u64);
            out.push((f.name.clone(), t));
        }
    }
    out
}

#[cfg(test)]
#[path = "logs_tests.rs"]
mod tests;
