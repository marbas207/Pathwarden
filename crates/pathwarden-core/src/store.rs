//! Where run state lives: a local folder, or a git repository that is pulled
//! before each run and committed and pushed after.
//!
//! Git goes through the `git` command line, so it uses whatever credentials
//! the machine or pipeline already has (credential manager, SSH key, CI
//! token). The git working copy is owned by Pathwarden: each run resets it to
//! the remote, so the remote is always the source of truth. To make sure that
//! never happens to someone else's repository, Pathwarden only works in a
//! working copy it created (marked with `.pathwarden-state`) whose `origin` is
//! the configured remote, and only on a branch that holds Pathwarden state
//! (or nothing yet).
//!
//! Runs on different machines that share one remote meet at the push: when
//! another run pushed first, [`Store::publish_with`] starts again from what
//! that run left and applies its change on top (the caller says how), so
//! neither run is lost. A push that fails for any other reason (the remote
//! out of reach, a refused push) keeps the run's commit in the working copy,
//! and the next run pushes it along with its own.

use std::collections::hash_map::RandomState;
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::binding::{self, Binding, BindingError, Parsed};
use crate::config::{StateBackend, StateConfig};
use crate::crypt::{self, SecretString};
use crate::keystore;
use crate::state::{FindingsState, HistoryPoint, LastRun, STATE_VERSION};
use anyhow::{bail, Context, Result};
use serde::Serialize;

/// How many times [`Store::publish_with`] applies its change again after
/// other runs pushed first, before it gives up.
const PUSH_RETRIES: usize = 3;

/// A lock older than this is assumed to be left over from a crashed run.
const STALE_LOCK: Duration = Duration::from_secs(6 * 3600);

/// How long a git command may go without a sign of life (output, or the
/// progress clone, fetch and push report) before it is stopped.
const GIT_IDLE: Duration = Duration::from_secs(10 * 60);

/// The author and committer of Pathwarden's commits to an encrypted
/// history, whoever runs it.
pub const NEUTRAL_AUTHOR: [(&str, &str); 4] = [
    ("GIT_AUTHOR_NAME", "Pathwarden"),
    ("GIT_AUTHOR_EMAIL", "pathwarden@invalid"),
    ("GIT_COMMITTER_NAME", "Pathwarden"),
    ("GIT_COMMITTER_EMAIL", "pathwarden@invalid"),
];

/// Whether a path git listed matches a pattern [`Store::commit`] stages.
type Matches = Box<dyn Fn(&str) -> bool>;

/// Pathwarden's own temporary files ([`write_atomic`]): `.<name>.<pid>.tmp`.
fn is_temp(name: &str) -> bool {
    name.starts_with('.') && name.ends_with(".tmp")
}

/// How often a held lock's time is renewed, so a long run's lock never
/// looks stale.
const LOCK_REFRESH: Duration = Duration::from_secs(10 * 60);

/// Set (in the working copy's own `.git/config`, never committed) in every
/// working copy Pathwarden clones: the proof it made it, which a clone of
/// the state repository by hand lacks.
const OWNED_CONFIG: &str = "pathwarden.workingcopy=true";

/// In `.git`: the tip of the commits a failed push left, which
/// [`Store::pull`] keeps.
const KEPT_FILE: &str = "pathwarden-unpushed";

/// The run's lock file, inside the state folder (local or git): a
/// scheduled task's account may write only there. Never committed: git
/// stages only the state's own files, and the working copy's
/// `.git/info/exclude` lists it ([`OWN_FILES`]).
const LOCK_FILE: &str = ".pathwarden.lock";

/// Beside the lock while a run takes over a lock nothing holds
/// ([`take_over`]). Never committed either ([`OWN_FILES`]).
const TAKING_FILE: &str = ".pathwarden.lock.taking";

/// The folder inside the state folder the first clone is made in, before
/// its `.git` is moved into place.
const CLONING_DIR: &str = ".pathwarden-cloning";

/// How the last pull went ([`Store::read_last_pull`]), in the state folder
/// beside the lock: there before the first clone, so a clone that fails is
/// recorded too. Never committed ([`OWN_FILES`]).
pub const LAST_PULL_FILE: &str = ".pathwarden-last-pull.json";

/// Pathwarden's own files in a git state folder that no commit may hold:
/// listed in `.git/info/exclude`, and a remote branch holding one is refused.
const OWN_FILES: &[&str] = &[LOCK_FILE, TAKING_FILE, CLONING_DIR, LAST_PULL_FILE];

/// Marks a git working copy as created and owned by Pathwarden.
pub(crate) const MARKER: &str = ".pathwarden-state";
const MARKER_TEXT: &str =
    "This repository holds Pathwarden run state (findings.json, last-run.json, history/), and \
with \"Full runs and settings\" each run in full (runs/) and the environment's shared settings \
(settings/).\n\
Pathwarden resets this working copy to the remote at the start of every run.\n\
Do not keep anything else here.\n";

/// The environment's shared settings, with `[state] keep = "full"`
/// ([`crate::settings_sync`]): the sections of `pathwarden.toml` in
/// [`crate::config_edit::SHARED_SECTIONS`].
pub const SETTINGS_FILE: &str = "settings/pathwarden.toml";

/// What the environment is: its name, domains and scope keys, and the
/// Pathwarden that wrote the settings.
pub const ENVIRONMENT_FILE: &str = "settings/environment.json";

/// The last change to the shared settings: what, which sections, who on
/// which computer, when ([`crate::settings_sync::ChangeRecord`]).
pub const LAST_CHANGE_FILE: &str = "settings/last-change.json";

thread_local! {
    /// Set while a save shares its change ([`non_interactive`]): git and
    /// its credential helper must not open a sign-in prompt nobody sees.
    static NON_INTERACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Set while the app pulls in the background ([`background`]): how long
    /// git may say nothing before it is stopped, under [`GIT_IDLE`].
    static IDLE_LIMIT: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

/// How long git may say nothing in a pull the app makes in the background
/// ([`background`]): well under how long a run or a save waits for the
/// history's lock (60 seconds by default,
/// [`crate::settings_sync::lock_wait`]), so a network that stalls never
/// keeps a recording out.
pub const BACKGROUND_GIT_IDLE: Duration = Duration::from_secs(45);

/// [`non_interactive`], with git stopped after [`BACKGROUND_GIT_IDLE`]
/// without a sign of progress: for the app's own pulls while it is open.
///
/// The fetch can't move out of the lock: the lock guards the working copy's
/// `.git` too. A recording fetches, rebases and pushes there under it, and a
/// second git updating the same refs at once makes one of them fail ("cannot
/// lock ref"); the first pull clones into the folder the lock lives in; and
/// a git stopped for silence has its stale `.git` locks removed, which is
/// only safe while nothing else runs git there.
pub fn background<T>(f: impl FnOnce() -> T) -> T {
    let _restore = Restore::idle(IDLE_LIMIT.with(|c| c.replace(Some(BACKGROUND_GIT_IDLE))));
    non_interactive(f)
}

/// How long git may say nothing on this thread: [`GIT_IDLE`], or less in
/// [`background`].
fn git_idle() -> Duration {
    IDLE_LIMIT
        .with(std::cell::Cell::get)
        .map_or(GIT_IDLE, |d| d.min(GIT_IDLE))
}

/// Runs `f` with this thread's git commands unable to prompt for a sign-in
/// (`GCM_INTERACTIVE=never`, `GIT_TERMINAL_PROMPT=0`): for work nobody
/// watches, such as sharing a saved settings change. A sign-in that is
/// needed fails, and the failure is reported.
pub fn non_interactive<T>(f: impl FnOnce() -> T) -> T {
    let _restore = Restore::non_interactive(NON_INTERACTIVE.with(|c| c.replace(true)));
    f()
}

/// Puts this thread's git settings back when dropped, a panic included: a
/// pooled thread never keeps the background pull's silence limit, or
/// prompts turned off, for the next work it does.
struct Restore {
    non_interactive: Option<bool>,
    idle: Option<Option<Duration>>,
}

impl Restore {
    fn non_interactive(before: bool) -> Self {
        Restore {
            non_interactive: Some(before),
            idle: None,
        }
    }

    fn idle(before: Option<Duration>) -> Self {
        Restore {
            non_interactive: None,
            idle: Some(before),
        }
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        if let Some(b) = self.non_interactive {
            NON_INTERACTIVE.with(|c| c.set(b));
        }
        if let Some(b) = self.idle {
            IDLE_LIMIT.with(|c| c.set(b));
        }
    }
}

/// One kind of file Pathwarden keeps in the history.
#[derive(Debug, Clone, Copy)]
enum StatePattern {
    /// One file, by its path in the history (`findings.json`; with A3,
    /// `settings/pathwarden.toml`).
    File(&'static str),
    /// One file per run: `<folder>/<run ID>.json`.
    Runs(&'static str),
    /// One folder per run, holding the files of [`BUNDLE_FILES`] only:
    /// `<folder>/<run ID>/<name>` (a full run, with "Full runs and
    /// settings").
    Bundle(&'static str),
}

/// The full runs' folder: `runs/<run ID>/<name>`, one folder per shared run,
/// next to its point `history/<run ID>.json`.
pub const BUNDLE_DIR: &str = "runs";

/// The files a full run in the history may hold, and nothing else (no
/// deeper folders). `run.json` describes the others.
///
/// A Pathwarden that doesn't know a file here refuses the full run, so a
/// file added after 0.2 needs the manifest's format raised again
/// (`pathwarden_ui::shared_runs::FORMAT`), which makes older versions say
/// to update instead. 0.2 raised it to 2 for `exposed.json.gz`.
pub const BUNDLE_FILES: &[&str] = &[
    "run.json",
    "summary.json",
    "report.html.gz",
    "graph.bin.gz",
    "objects.json.gz",
    "event.json.gz",
    "retest.json.gz",
    crate::exposed::FILE,
    "opengraph.json",
    "settings.toml",
];

/// The most bytes a history file of `plain` bytes takes on disk: itself,
/// or encrypted (age adds 16 bytes per 64 KiB chunk and a header), with
/// room to spare.
pub fn max_on_disk(plain: u64) -> u64 {
    plain.saturating_add(plain / 4096).saturating_add(64 * 1024)
}

/// The seam's name of full run `run_id`'s file `name`
/// (`runs/<run ID>/<name>`).
pub fn bundle_rel(run_id: &str, name: &str) -> String {
    format!("{BUNDLE_DIR}/{run_id}/{name}")
}

/// Every file Pathwarden keeps in the history, by the name the seam uses
/// ([`Store::read_state_file`]). Everything else follows this one list:
/// the names the seam accepts ([`is_state_rel`]), what a commit stages,
/// what a state working copy and branch may hold, the link check, and
/// which files turning encryption on or off rewrites. A new kind of state
/// file (A3: `settings/pathwarden.toml`, `settings/environment.json`) is
/// added here, and only here, and is then encrypted with the rest.
///
/// Anything that compares a state file's content across syncs (a base
/// hash of the shared settings) must compare the decrypted bytes
/// ([`Store::read_state_file`]), never the bytes on disk: an encrypted
/// file's bytes change each time it is written, even with the same
/// content.
const STATE_FILES: &[StatePattern] = &[
    StatePattern::File("findings.json"),
    StatePattern::File("last-run.json"),
    StatePattern::Runs(HISTORY_DIR),
    StatePattern::Runs(TIMINGS_DIR),
    StatePattern::Runs(crate::exposed::DIR),
    StatePattern::File(SETTINGS_FILE),
    StatePattern::File(ENVIRONMENT_FILE),
    StatePattern::File(LAST_CHANGE_FILE),
    StatePattern::File(crate::action_log::FILE),
    StatePattern::Bundle(BUNDLE_DIR),
];

/// The run points' folder: `history/<run>.json`.
const HISTORY_DIR: &str = "history";

/// Every folder [`STATE_FILES`] puts files in: the run folders, and the
/// folder of a single file (A3's `settings/`). What git cleans and diffs.
fn state_folders() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = run_folders().chain(bundle_folders()).collect();
    for f in single_files() {
        if let Some((folder, _)) = f.split_once('/') {
            if !out.contains(&folder) {
                out.push(folder);
            }
        }
    }
    out
}

/// The single files of [`STATE_FILES`].
fn single_files() -> impl Iterator<Item = &'static str> {
    STATE_FILES.iter().filter_map(|p| match p {
        StatePattern::File(f) => Some(*f),
        _ => None,
    })
}

/// The run folders of [`STATE_FILES`].
fn run_folders() -> impl Iterator<Item = &'static str> {
    STATE_FILES.iter().filter_map(|p| match p {
        StatePattern::Runs(f) => Some(*f),
        _ => None,
    })
}

/// The full-run folders of [`STATE_FILES`] (`runs`).
fn bundle_folders() -> impl Iterator<Item = &'static str> {
    STATE_FILES.iter().filter_map(|p| match p {
        StatePattern::Bundle(f) => Some(*f),
        _ => None,
    })
}

/// The full runs (by run ID) whose folder in `folder` of the history in
/// `dir` holds at least one file of [`BUNDLE_FILES`], in the form
/// `encrypted` says. Sorted.
fn bundle_ids(dir: &Path, folder: &str, encrypted: bool) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir.join(folder)) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|id| is_run_id(id))
        .filter(|id| !bundle_names(dir, folder, id, encrypted).is_empty())
        .collect();
    out.sort();
    out
}

/// The names of [`BUNDLE_FILES`] in full run `id`'s folder, in the form
/// `encrypted` says.
fn bundle_names(dir: &Path, folder: &str, id: &str, encrypted: bool) -> Vec<&'static str> {
    BUNDLE_FILES
        .iter()
        .copied()
        .filter(|name| {
            let path = on_disk(dir, &format!("{folder}/{id}/{name}"), encrypted);
            fs::symlink_metadata(&path).is_ok_and(|m| m.is_file())
        })
        .collect()
}

/// What a state working copy holds at its top besides [`STATE_FILES`].
const OTHER_ENTRIES: &[&str] = &[
    ".git",
    LOCK_FILE,
    TAKING_FILE,
    CLONING_DIR,
    LAST_PULL_FILE,
    ".gitignore",
    MARKER,
    crypt::MARKER,
    crypt::KEY_FILE,
];

/// Whether `name`, at the top of a state working copy, is Pathwarden's.
fn state_entry(name: &str) -> bool {
    OTHER_ENTRIES.contains(&name)
        || STATE_FILES.iter().any(|p| match p {
            StatePattern::File(f) => match f.split_once('/') {
                Some((folder, _)) => name == folder,
                None => name == *f || name.strip_suffix(crypt::SUFFIX) == Some(f),
            },
            StatePattern::Runs(folder) | StatePattern::Bundle(folder) => name == *folder,
        })
}

/// Whether `path` (in a branch without the marker) is a file a state branch
/// may hold: the state's own files (plain or encrypted), or what a new
/// repository's host creates in it (README, LICENSE or LICENCE, each with
/// or without an extension, `.gitattributes`, `.gitignore`). Names are
/// compared ignoring case.
fn state_file(path: &str) -> bool {
    let plain = path.strip_suffix(crypt::SUFFIX).unwrap_or(path);
    if is_state_rel(plain) || matches!(path, crypt::MARKER | crypt::KEY_FILE) {
        return true;
    }
    if path.contains('/') {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    let host = |stem: &str| {
        lower == stem
            || lower
                .strip_prefix(stem)
                .and_then(|rest| rest.strip_prefix('.'))
                .is_some_and(|ext| !ext.is_empty() && !ext.contains('.'))
    };
    matches!(lower.as_str(), ".gitattributes" | ".gitignore")
        || host("readme")
        || host("license")
        || host("licence")
}

/// The first attribute in `.gitattributes` text that a history may not
/// set, or a macro definition (`[attr]...`): anything but line endings and
/// "binary". A `filter`, a named `diff` or `merge` driver, `ident` or an
/// encoding would have git run a program the computer's own git settings
/// name, or rewrite the state files as they are checked out.
fn unsafe_attribute(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The pattern: quoted (with escapes) or up to the first space.
        let rest = if let Some(q) = line.strip_prefix('"') {
            let mut escaped = false;
            let end = q.char_indices().find(|&(_, c)| {
                let close = c == '"' && !escaped;
                escaped = c == '\\' && !escaped;
                close
            });
            match end {
                Some((i, _)) => &q[i + 1..],
                None => return Some(line.to_string()),
            }
        } else {
            if line.starts_with("[attr]") {
                return Some(line.to_string());
            }
            line.split_once(char::is_whitespace).map_or("", |(_, r)| r)
        };
        for attr in rest.split_whitespace() {
            // A bare `diff` or `merge` is git's own; an attribute unset
            // (`-filter`) or unspecified (`!filter`) asks for nothing.
            let unset = attr.starts_with(['-', '!']);
            let name = attr.trim_start_matches(['-', '!']);
            let ok = match name.split_once('=') {
                None => unset || matches!(name, "text" | "binary" | "diff" | "merge" | "crlf"),
                Some(_) if attr.starts_with(['-', '!']) => false,
                Some(("text", v)) => v == "auto",
                Some(("eol", v)) => matches!(v, "lf" | "crlf"),
                Some(("merge", v)) => matches!(v, "text" | "binary" | "union"),
                Some(_) => false,
            };
            if !ok {
                return Some(attr.to_string());
            }
        }
    }
    None
}

/// Whether `rel` names a file the seam reads and writes
/// ([`Store::read_state_file`]): one of [`STATE_FILES`].
fn is_state_rel(rel: &str) -> bool {
    STATE_FILES.iter().any(|p| match p {
        StatePattern::File(f) => rel == *f,
        StatePattern::Runs(folder) => rel
            .strip_prefix(folder)
            .and_then(|r| r.strip_prefix('/'))
            .and_then(|name| name.strip_suffix(".json"))
            .is_some_and(is_run_id),
        StatePattern::Bundle(folder) => rel
            .strip_prefix(folder)
            .and_then(|r| r.strip_prefix('/'))
            .and_then(|r| r.split_once('/'))
            .is_some_and(|(id, name)| is_run_id(id) && BUNDLE_FILES.contains(&name)),
    })
}

fn check_rel(rel: &str) -> Result<()> {
    if !is_state_rel(rel) {
        bail!("'{rel}' is not a file of the history");
    }
    Ok(())
}

/// The file on disk for `rel`: `<rel>.age` when the history is encrypted.
pub(crate) fn on_disk(dir: &Path, rel: &str, encrypted: bool) -> PathBuf {
    if encrypted {
        dir.join(format!("{rel}{}", crypt::SUFFIX))
    } else {
        dir.join(rel)
    }
}

/// In a git working copy's `.git` (never committed): the SHA-256 of the key
/// file this computer last opened the history with. Its presence pins the
/// history as encrypted here: a pull that removes the encryption is
/// refused until `history storage set --no-encrypt` on this computer.
const PIN_FILE: &str = "pathwarden-encrypted";

fn pin_path(dir: &Path) -> Option<PathBuf> {
    let git = dir.join(".git");
    git.is_dir().then(|| git.join(PIN_FILE))
}

/// The key file's digest this computer pinned, if any.
pub(crate) fn pinned_key(dir: &Path) -> Option<String> {
    let text = fs::read_to_string(pin_path(dir)?).ok()?;
    Some(text.trim().to_string())
}

fn pin_key(dir: &Path, digest: &str) -> Result<()> {
    if let Some(path) = pin_path(dir) {
        if pinned_key(dir).as_deref() != Some(digest) {
            fs::write(&path, format!("{digest}\n"))
                .with_context(|| format!("writing {}", path.display()))?;
        }
    }
    Ok(())
}

/// Beside [`PIN_FILE`]: what the next pull says after this computer
/// followed a key it hadn't pinned. Every change of the key is told
/// once, whoever made it, so a key someone else could open never replaces
/// the pinned one unseen.
const KEY_CHANGED_FILE: &str = "pathwarden-key-changed";

/// Whether this process is a scheduled run: the generated nightly
/// scripts set `PATHWARDEN_SCHEDULED`. Nobody would see a note it leaves,
/// so it doesn't follow a replaced key ([`follow_key`]).
pub fn unattended() -> bool {
    std::env::var_os("PATHWARDEN_SCHEDULED").is_some_and(|v| !v.is_empty() && v != "0")
}

/// Pins `digest`, a key the passphrase here opens. A different key pinned
/// before is a change made elsewhere: the next pull says so
/// ([`take_key_note`]), naming the commit. A scheduled run refuses it
/// instead ([`unattended`]): a passphrase source someone planted for
/// the task's account (a protected file beside the history) could open a
/// key of theirs, and nobody would read the note.
fn follow_key(dir: &Path, digest: &str) -> Result<()> {
    follow_key_as(dir, digest, unattended())
}

fn follow_key_as(dir: &Path, digest: &str, unattended: bool) -> Result<()> {
    let before = pinned_key(dir);
    if unattended && before.as_deref().is_some_and(|b| b != digest) {
        let change = last_change(dir, crypt::KEY_FILE);
        bail!(
            "the history's key was replaced{}, and a scheduled run doesn't follow a new key. \
             If the passphrase was changed, open the history once by hand on this computer to \
             accept the new key; if nobody changed it, revert {} in the repository",
            change
                .as_ref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default(),
            change.as_deref().unwrap_or("the change")
        );
    }
    pin_key(dir, digest)?;
    let (Some(before), Some(pin)) = (before, pin_path(dir)) else {
        return Ok(());
    };
    if before == digest {
        return Ok(());
    }
    let note = key_changed_note(last_change(dir, crypt::KEY_FILE).as_deref());
    let path = pin.with_file_name(KEY_CHANGED_FILE);
    fs::write(&path, note).with_context(|| format!("writing {}", path.display()))
}

/// What a pull says about a key followed since the last one.
fn key_changed_note(change: Option<&str>) -> String {
    match change {
        Some(c) => format!(
            "The history's key was replaced ({c}), and the passphrase this computer has opens \
             the new one. If nobody changed the passphrase, revert {c} and check where this \
             computer keeps the passphrase."
        ),
        None => "The history's key was replaced, and the passphrase this computer has opens the \
                 new one. If nobody changed the passphrase, revert the change and check where \
                 this computer keeps the passphrase."
            .into(),
    }
}

/// The note [`follow_key`] left, once.
fn take_key_note(dir: &Path) -> Option<String> {
    let path = pin_path(dir)?.with_file_name(KEY_CHANGED_FILE);
    let note = fs::read_to_string(&path).ok()?;
    let _ = fs::remove_file(&path);
    let note = note.trim();
    (!note.is_empty()).then(|| note.chars().take(1000).collect())
}

fn unpin(dir: &Path) -> Result<()> {
    match pin_path(dir) {
        Some(path) => remove_if_there(&path).map(|_| ()),
        None => Ok(()),
    }
}

/// "commit 1a2b3c4 by Jane Doe": the last commit that touched `file` in the
/// history's git working copy, for an error that blames a change.
fn last_change(dir: &Path, file: &str) -> Option<String> {
    dir.join(".git").is_dir().then_some(())?;
    // --full-history: a merge whose other parent never had the file must
    // not hide the commit that dropped it ([`marker_removed_by`]).
    let out = run_git(
        Some(dir),
        &[
            "log",
            "-1",
            "--full-history",
            "--format=%h by %an",
            "--",
            file,
        ],
    )
    .ok()?;
    let out = out.trim();
    (!out.is_empty()).then(|| format!("commit {out}"))
}

/// Encrypted files of the history in `dir` (the key, the single files):
/// for a history whose marker is missing. Not `actions.json.age`: an
/// older release that turned encryption off leaves it, and only what
/// actions did is then unavailable ([`crate::action_log::load`]).
fn sealed_leftovers(dir: &Path, all: bool) -> Vec<String> {
    let mut found: Vec<String> = std::iter::once(crypt::KEY_FILE.to_string())
        .chain(
            single_files()
                .filter(|f| *f != crate::action_log::FILE)
                .map(|f| format!("{f}{}", crypt::SUFFIX)),
        )
        .filter(|f| fs::symlink_metadata(dir.join(f)).is_ok())
        .collect();
    if all {
        for folder in run_folders() {
            if let Ok(entries) = fs::read_dir(dir.join(folder)) {
                found.extend(
                    entries
                        .flatten()
                        .filter_map(|e| e.file_name().into_string().ok())
                        .filter(|n| n.ends_with(".json.age"))
                        .map(|n| format!("{folder}/{n}")),
                );
            }
        }
        for folder in bundle_folders() {
            for id in bundle_ids(dir, folder, true) {
                found.extend(
                    bundle_names(dir, folder, &id, true)
                        .into_iter()
                        .map(|n| format!("{folder}/{id}/{n}{}", crypt::SUFFIX)),
                );
            }
        }
    }
    found
}

/// The history `dir` holds, as this computer knows it whatever the
/// repository does: for a git working copy its remote and branch
/// ("git:<remote>#<branch>", the remote normalised); for a folder both its
/// full path with links and junctions resolved and the path as given
/// ("folder:..."), so a junction swapped in its place still matches.
fn location_keys(dir: &Path) -> Vec<String> {
    if let Some(key) = git_location_key(dir) {
        return vec![key];
    }
    let canonical = format!("folder:{}", keystore::history_key(dir));
    let given = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let given = given.to_string_lossy();
    let given = format!(
        "folder:{}",
        if cfg!(windows) {
            given.replace('/', "\\").to_lowercase()
        } else {
            given.into_owned()
        }
    );
    if given == canonical {
        vec![canonical]
    } else {
        vec![canonical, given]
    }
}

/// [`location_keys`] for a git working copy, kept for the process while
/// its `.git/config` and `.git/HEAD` are unchanged (a long-running app may
/// see the remote or branch changed at the same folder).
fn git_location_key(dir: &Path) -> Option<String> {
    type Seen = (Option<std::time::SystemTime>, Option<std::time::SystemTime>);
    static KEYS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, (Seen, String)>>,
    > = std::sync::OnceLock::new();
    let git = dir.join(".git");
    if !git.is_dir() {
        return None;
    }
    let modified = |p: PathBuf| fs::metadata(p).and_then(|m| m.modified()).ok();
    let seen: Seen = (modified(git.join("config")), modified(git.join("HEAD")));
    let keys = KEYS.get_or_init(Default::default);
    if let Some((was, key)) = keys.lock().unwrap_or_else(|e| e.into_inner()).get(dir) {
        if *was == seen {
            return Some(key.clone());
        }
    }
    let remote = run_git(Some(dir), &["config", "--get", "remote.origin.url"]).ok()?;
    let branch = run_git(Some(dir), &["symbolic-ref", "--quiet", "--short", "HEAD"]).ok()?;
    let (remote, branch) = (remote.trim(), branch.trim());
    if remote.is_empty() || branch.is_empty() {
        return None;
    }
    let key = format!("git:{}#{branch}", normalize_remote(remote));
    keys.lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(dir.to_path_buf(), (seen, key.clone()));
    Some(key)
}

/// This account's sticky records that the history at `dir`'s location was
/// encrypted ([`keystore::pins_dir`]), where no repository reaches: one per
/// [`location_keys`]. None in a debug build without the test store; an
/// error when the account's environment doesn't say where its data is.
fn location_pins(dir: &Path) -> Result<Vec<PathBuf>> {
    let Some(pins) = keystore::pins_dir()? else {
        return Ok(Vec::new());
    };
    Ok(location_keys(dir)
        .iter()
        .map(|k| pins.join(format!("{}.json", crypt::digest_hex(k.as_bytes()))))
        .collect())
}

/// Records, the first time this computer sees it (any pull, open or read,
/// with or without the passphrase), that the history at `dir`'s location
/// is encrypted: only for a marker this version reads and a key file next
/// to it (an empty marker someone committed and removed again must not
/// lock every account out). Refuses when the record can't be kept.
fn record_location_pin(dir: &Path) -> Result<()> {
    if !matches!(crypt::marker(dir), Ok(Some(_)))
        || !fs::symlink_metadata(dir.join(crypt::KEY_FILE)).is_ok_and(|m| m.is_file())
    {
        return Ok(());
    }
    for (path, key) in location_pins(dir)?.into_iter().zip(location_keys(dir)) {
        if path.is_file() {
            continue;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let record = serde_json::json!({
            "location": key,
            "encrypted": true,
            "note": "Pathwarden saw this history encrypted; a plain history here is refused until \
                     `pathwarden history storage set --no-encrypt --yes` on this computer (or an \
                     administrator deletes this file).",
        });
        write_atomic(&path, format!("{record:#}\n").as_bytes())?;
    }
    Ok(())
}

/// A sticky record this computer has for `dir`'s location, if any. (Where
/// the records can't be kept, none was ever written: there is nothing to
/// find.)
fn location_pinned(dir: &Path) -> Option<PathBuf> {
    location_pins(dir).ok()?.into_iter().find(|p| p.is_file())
}

/// Whether the history in `dir` is encrypted, refusing one whose
/// encryption looks stripped: encrypted files without the marker, a
/// location this computer saw encrypted ([`location_pinned`], and the
/// working copy's own [`PIN_FILE`]), and, with `full` (before anything is
/// written, and once before a whole history is read), a git history whose
/// commits show the marker removed, or a plain history this computer keeps
/// a passphrase for. Someone who can push to the repository could
/// otherwise remove the encryption and have the next run write and push
/// the history in plain text. Seeing it encrypted records the location.
fn mode(dir: &Path, full: bool) -> Result<bool> {
    if crypt::is_encrypted(dir) {
        record_location_pin(dir)?;
        return Ok(true);
    }
    let blame = || {
        last_change(dir, crypt::MARKER)
            .map(|c| format!(" ({c})"))
            .unwrap_or_default()
    };
    let leftovers = sealed_leftovers(dir, full);
    if !leftovers.is_empty() {
        bail!(
            "the history in {} holds encrypted files ({}) but its encryption marker {} is \
             missing{}; Pathwarden refuses to read or write it in plain text. Restore the \
             marker, or find out who removed it.",
            dir.display(),
            leftovers.join(", "),
            crypt::MARKER,
            blame()
        );
    }
    let stripped = |when: &str, record: Option<&Path>| -> anyhow::Error {
        let change = last_change(dir, crypt::MARKER);
        anyhow::anyhow!(
            "the history in {} was encrypted {when}, and now it isn't{}{}; Pathwarden refuses \
             to read or write it in plain text. If encryption was turned off on purpose, run \
             `pathwarden history storage set --no-encrypt --yes` on this computer. If nobody \
             here turned it off, restore the repository ({}), or run `pathwarden history \
             storage set --encrypt --yes` (it encrypts the history again).",
            dir.display(),
            change
                .as_ref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default(),
            record
                .map(|r| format!(" (this computer's record: {})", r.display()))
                .unwrap_or_default(),
            change
                .map(|c| format!("revert {c}"))
                .unwrap_or_else(|| "put the encrypted commits back on its branch".into()),
        )
    };
    if pinned_key(dir).is_some() {
        return Err(stripped(
            "when this computer last opened it",
            pin_path(dir).as_deref(),
        ));
    }
    if let Some(record) = location_pinned(dir) {
        return Err(stripped("when this computer last saw it", Some(&record)));
    }
    if full {
        // A working copy that never saw it encrypted (a fresh clone): the
        // repository's own commits say it was, until `--no-encrypt` here
        // accepts the change.
        if marker_removed_by(dir)?.is_some_and(|c| !plain_accepted(dir, &c)) {
            return Err(stripped("before", None));
        }
        // Only a passphrase kept for this history counts: the environment
        // variable or a service credential may serve other, plain
        // histories of the same account.
        if let Some(source) = crypt::local_passphrase(dir)? {
            bail!(
                "this computer has a passphrase for the history in {} ({}), but the history \
                 isn't encrypted{}; Pathwarden refuses to read or write it in plain text. \
                 Encrypt it \
                 (`pathwarden history storage set --encrypt --yes`), or, if encryption was \
                 turned off on purpose, remove the passphrase (`pathwarden history storage \
                 passphrase forget`).",
                dir.display(),
                source.words(),
                blame(),
            );
        }
    }
    Ok(false)
}

/// In `.git` (never committed): the commit that removed the encryption
/// marker, once this computer accepted the plain history
/// (`set --no-encrypt` here).
const ACCEPTED_FILE: &str = "pathwarden-plain-accepted";

/// The full hash of the last commit that touched the encryption marker,
/// when the history is a git working copy whose tip lacks the marker but
/// whose history had it: the commit that removed it. `--full-history`, so
/// a merge with a branch that never had the marker is found too. Fails
/// closed: only a branch with no commit yet (HEAD names a branch, and git
/// says it doesn't exist) has nothing to look at; git missing, or a
/// damaged `.git`, refuses.
fn marker_removed_by(dir: &Path) -> Result<Option<String>> {
    if !dir.join(".git").is_dir() || crypt::is_encrypted(dir) {
        return Ok(None);
    }
    // The answer depends only on the commits up to HEAD: kept by HEAD's
    // commit, read from `.git` without running git, so a page showing the
    // history runs none while HEAD stays where it was. Only when HEAD is
    // a branch whose commit plain files say for sure ([`head_commit`]);
    // anything else asks git, which fails closed.
    let head = head_commit(dir);
    if let Some(h) = &head {
        if let Some(found) = removed_by_cache()
            .get(dir)
            .filter(|(at, _)| at == h)
            .map(|(_, found)| found.clone())
        {
            return Ok(found);
        }
    }
    let found = marker_removed_by_git(dir)?;
    // Kept only if HEAD didn't move while git looked.
    if let Some(h) = head.filter(|h| head_commit(dir).as_ref() == Some(h)) {
        removed_by_cache().insert(dir.to_path_buf(), (h, found.clone()));
    }
    Ok(found)
}

/// [`marker_removed_by`]'s answers, by working copy: HEAD's commit then,
/// and the answer.
type RemovedBy = std::collections::HashMap<PathBuf, (String, Option<String>)>;

fn removed_by_cache() -> std::sync::MutexGuard<'static, RemovedBy> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<RemovedBy>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// [`Store::kept_unpushed`]'s answers: (working copy, kept tip, branch
/// commit) to whether the branch holds the tip.
type KeptHeld = std::collections::HashMap<(PathBuf, String, String), bool>;

fn kept_cache() -> std::sync::MutexGuard<'static, KeptHeld> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<KeptHeld>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// A commit ID as git writes it in a ref file.
fn hex_id(s: &str) -> Option<String> {
    let s = s.trim();
    (s.len() >= 40 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_string())
}

/// HEAD's commit in the working copy `dir`, read from `.git` as files,
/// when HEAD names a branch ([`ref_commit`]). `None` for a detached HEAD,
/// or whenever the files can't say for sure: then git is asked.
fn head_commit(dir: &Path) -> Option<String> {
    let git = dir.join(".git");
    let head = fs::read_to_string(git.join("HEAD")).ok()?;
    let name = head.trim().strip_prefix("ref: ")?;
    ref_commit(&git, name)
}

/// The commit the remote-tracking branch of HEAD's branch
/// (`refs/remotes/origin/<branch>`) points at, read from `.git` as files;
/// `None` when they can't say.
fn remote_tip(dir: &Path) -> Option<String> {
    let git = dir.join(".git");
    let head = fs::read_to_string(git.join("HEAD")).ok()?;
    let branch = head.trim().strip_prefix("ref: refs/heads/")?;
    ref_commit(&git, &format!("refs/remotes/origin/{branch}")).and_then(|c| hex_id(&c))
}

/// Whether the refs in the `.git` folder `git` are plain files (loose refs
/// and `packed-refs`): not when `.git` is a file (a linked work tree), and
/// not with the reftable format (`.git/reftable`, or
/// `extensions.refStorage` in its config), whose files say nothing here.
fn plain_refs(git: &Path) -> bool {
    if !fs::symlink_metadata(git).is_ok_and(|m| m.is_dir()) {
        return false;
    }
    if fs::symlink_metadata(git.join("reftable")).is_ok() {
        return false;
    }
    match fs::read_to_string(git.join("config")) {
        Ok(c) => !c.to_ascii_lowercase().contains("refstorage"),
        Err(_) => false,
    }
}

/// The commit branch ref `name` (`refs/heads/...`, or a remote-tracking
/// `refs/remotes/...`) points at in the `.git`
/// folder `git`, read as files: a loose ref, or `packed-refs`; "unborn"
/// and its name for a branch with no commit yet, only when neither file
/// is there at all. `None` whenever the files can't say for sure (the
/// reftable format, a name like `.invalid`, a read that failed for any
/// other reason than the file not being there, a line that is no commit):
/// then git is asked, every time.
fn ref_commit(git: &Path, name: &str) -> Option<String> {
    if !plain_refs(git)
        || !(name.starts_with("refs/heads/") || name.starts_with("refs/remotes/"))
        || name.contains("..")
        || name.ends_with(".invalid")
    {
        return None;
    }
    match fs::read_to_string(git.join(name)) {
        Ok(t) => return hex_id(&t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return None,
    }
    match fs::read_to_string(git.join("packed-refs")) {
        Ok(packed) => packed.lines().find_map(|l| {
            let (id, r) = l.split_once(' ')?;
            (r.trim() == name).then(|| hex_id(id)).flatten()
        }),
        // A branch with no commit yet: git answers once for it.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(format!("unborn {name}")),
        Err(_) => None,
    }
}

/// [`marker_removed_by`], asking git.
fn marker_removed_by_git(dir: &Path) -> Result<Option<String>> {
    let checking = "checking the history's git commits for its encryption marker";
    run_git(Some(dir), &["symbolic-ref", "--quiet", "HEAD"]).context(checking)?;
    match run_git(Some(dir), &["rev-parse", "--verify", "--quiet", "HEAD"]) {
        Ok(_) => {}
        Err(e)
            if e.downcast_ref::<GitFailed>()
                .is_some_and(|f| f.code == Some(1)) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e.context(checking)),
    }
    let out = run_git(
        Some(dir),
        &[
            "log",
            "-1",
            "--full-history",
            "--format=%H",
            "--",
            crypt::MARKER,
        ],
    )
    .context(checking)?;
    let out = out.trim();
    Ok((!out.is_empty()).then(|| out.to_string()))
}

fn plain_accepted(dir: &Path, commit: &str) -> bool {
    fs::read_to_string(dir.join(".git").join(ACCEPTED_FILE)).is_ok_and(|t| t.trim() == commit)
}

/// Whether this computer expects the history in `dir` encrypted: it opened
/// it ([`PIN_FILE`]), or saw it ([`location_pinned`]).
fn expects_encrypted_here(dir: &Path) -> bool {
    pinned_key(dir).is_some() || location_pinned(dir).is_some()
}

/// This computer accepts the history in `dir` being plain: no pin, no
/// sticky record, and the commit that removed the marker recorded as
/// accepted.
fn accept_plain(dir: &Path) -> Result<()> {
    unpin(dir)?;
    // The key is gone with the encryption: only the folder's mark can be
    // found.
    forget_bindings(dir, None);
    for record in location_pins(dir).unwrap_or_default() {
        remove_if_there(&record)?;
    }
    if let Some(commit) = marker_removed_by(dir)? {
        let path = dir.join(".git").join(ACCEPTED_FILE);
        fs::write(&path, format!("{commit}\n"))
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

/// What removed the history's encryption, for the user: "commit 1a2b3c4 by
/// Jane Doe", when its commits say.
fn removal_words(dir: &Path) -> Option<String> {
    last_change(dir, crypt::MARKER)
}

/// The key of the encrypted history in `dir` ([`crypt::key_for`]), checked
/// against the one this computer pinned: a key the passphrase here
/// doesn't open, that isn't the pinned one, was replaced; one it opens is
/// pinned (a passphrase changed on another computer), and the next pull
/// says so ([`follow_key`]).
fn key(dir: &Path) -> Result<std::sync::Arc<age::x25519::Identity>> {
    let digest = crypt::key_digest(dir)?;
    match crypt::key_for(dir) {
        Ok(k) => {
            follow_key(dir, &digest)?;
            Ok(k)
        }
        Err(e) => match pinned_key(dir) {
            Some(pin)
                if pin != digest
                    && matches!(
                        e.downcast_ref::<crypt::CryptError>(),
                        Some(crypt::CryptError::WrongPassphrase(_))
                    ) =>
            {
                let change = last_change(dir, crypt::KEY_FILE);
                Err(e.context(format!(
                    "the history's key was replaced since this computer last opened it{}; if \
                     its passphrase was changed, store the new one here. If nobody changed \
                     it, revert {} in the repository",
                    change
                        .as_ref()
                        .map(|c| format!(" ({c})"))
                        .unwrap_or_default(),
                    change.as_deref().unwrap_or("the change that replaced it")
                )))
            }
            _ => Err(e),
        },
    }
}

/// Reads `rel` ("findings.json", "history/<run>.json", ...) from the
/// history in `dir`, decrypted when it is encrypted ([`crate::crypt`]);
/// `None` when it isn't there. [`Store::read_state_file`] for a folder
/// known only by its path.
pub fn read_state_file(dir: &Path, rel: &str) -> Result<Option<Vec<u8>>> {
    check_rel(rel)?;
    let encrypted = mode(dir, false)?;
    read_as(dir, rel, encrypted)
}

/// [`read_state_file`] in the form given, without the checks of [`mode`]:
/// for turning encryption on and off.
fn read_as(dir: &Path, rel: &str, encrypted: bool) -> Result<Option<Vec<u8>>> {
    let path = on_disk(dir, rel, encrypted);
    if is_link(&path) {
        bail!(
            "{} is a symbolic link; Pathwarden does not read state through links",
            path.display()
        );
    }
    let bytes = match max_state_bytes(rel) {
        None => fs::read(&path),
        Some(max) => read_capped(&path, max_on_disk(max)),
    };
    let bytes = match bytes {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::FileTooLarge => {
            return Err(TooLarge {
                path: path.display().to_string(),
                max: max_state_bytes(rel).unwrap_or_default(),
            }
            .into())
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    decode_state(dir, rel, bytes, encrypted)
}

/// The most bytes (plain) Pathwarden reads of the history's findings
/// state, latest run, run points and timings: any writer can push
/// them, and each is read whole. `None`: the file has a cap of its own
/// where it is read (settings, full runs, exposed accounts).
fn max_state_bytes(rel: &str) -> Option<u64> {
    const MIB: u64 = 1 << 20;
    match rel {
        "findings.json" => Some(1024 * MIB),
        "last-run.json" => Some(64 * MIB),
        crate::action_log::FILE => Some(crate::action_log::MAX_BYTES),
        _ if rel.starts_with("history/") || rel.starts_with("timings/") => Some(16 * MIB),
        _ => None,
    }
}

/// A plain `rel` in an encrypted history in `dir`, which an older release
/// may have left when it turned encryption on, or anyone who can push may
/// have put there: never read into the history, only shown to someone
/// deciding whether to import it ([`crate::action_log::read_plain`]). At
/// most `max` bytes, never through a link. `None` when there is none, or
/// the history is plain.
pub(crate) fn read_leftover(dir: &Path, rel: &str, max: u64) -> Result<Option<Vec<u8>>> {
    if !crypt::is_encrypted(dir) {
        return Ok(None);
    }
    let path = dir.join(rel);
    if is_link(&path) {
        bail!(
            "{} is a symbolic link; Pathwarden does not read state through links",
            path.display()
        );
    }
    match read_capped(&path, max) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::FileTooLarge => Err(TooLarge {
            path: path.display().to_string(),
            max,
        }
        .into()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Removes a plain `rel` from an encrypted history in `dir`, once its
/// contents were taken in on purpose
/// ([`crate::action_log::import_plain`]).
pub(crate) fn remove_plain_leftover(dir: &Path, rel: &str) -> Result<bool> {
    if !crypt::is_encrypted(dir) {
        bail!("the history isn't encrypted");
    }
    remove_if_there(&dir.join(rel))
}

/// `path`'s bytes, or a `FileTooLarge` error when it holds more than
/// `max`: checked before it is read, and again as it is read (it may
/// grow).
fn read_capped(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let f = fs::File::open(path)?;
    if f.metadata()?.len() > max {
        return Err(std::io::ErrorKind::FileTooLarge.into());
    }
    let mut bytes = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::ErrorKind::FileTooLarge.into());
    }
    Ok(bytes)
}

/// A history file larger than Pathwarden reads ([`max_state_bytes`]).
#[derive(Debug)]
pub struct TooLarge {
    path: String,
    max: u64,
}

impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} is larger than {} MiB; it is not read",
            self.path,
            self.max >> 20
        )
    }
}

impl std::error::Error for TooLarge {}

/// The history's `findings.json` can't be read as a findings state: cut
/// short, not JSON, or too large ([`Store::load_for_run`]).
#[derive(Debug)]
pub struct DamagedFindings(String);

impl std::fmt::Display for DamagedFindings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DamagedFindings {}

/// This computer's record of the sequences seen in the encrypted history
/// in `dir` under `key` ([`binding::record_for`]).
fn seq_record(dir: &Path, key: &age::x25519::Identity) -> Option<PathBuf> {
    binding::record_for(&keystore::history_key(dir), &key.to_public().to_string())
}

/// `plain` bound to `rel` at sequence `seq` and encrypted to `key`: an
/// encrypted file's bytes on disk.
fn seal_bound(key: &age::x25519::Identity, rel: &str, seq: u64, plain: &[u8]) -> Result<Vec<u8>> {
    crypt::seal(key, &binding::wrap(&Binding::new(rel, seq), plain))
}

/// The sequence the next write of `rel` gets: one more than the file has
/// now, or than this computer has seen there, whichever is higher.
fn next_seq(dir: &Path, key: &age::x25519::Identity, rel: &str) -> u64 {
    let now = fs::read(on_disk(dir, rel, true))
        .ok()
        .and_then(|b| crypt::open(key, &b, rel).ok())
        .and_then(|p| match binding::parse(p) {
            Ok(Parsed::Bound(b, _)) if b.path == rel => Some(b.seq),
            _ => None,
        })
        .unwrap_or(0);
    let seen = seq_record(dir, key)
        .and_then(|r| binding::last_seen(&r, rel))
        .unwrap_or(0);
    now.max(seen).saturating_add(1)
}

/// What was read from disk for `rel`, decrypted when the history is
/// encrypted, and checked against its binding ([`crate::binding`]): the
/// path and run it names must be `rel`'s, and its sequence no lower than
/// this computer has seen at `rel`. A file without a binding is read only
/// while the marker says the history was encrypted before the binding
/// ([`crypt::UNBOUND_FORMAT`]), and only where this computer never saw the
/// marker say otherwise. A higher sequence is remembered once the remote
/// holds the file as it is here ([`on_remote`]).
///
/// `None` for a file bound to `rel` in another case: on a file system
/// that ignores case, a run ID typed in another case finds the run's file,
/// which is not the run asked for.
fn decode_state(dir: &Path, rel: &str, bytes: Vec<u8>, encrypted: bool) -> Result<Option<Vec<u8>>> {
    if !encrypted {
        return Ok(Some(bytes));
    }
    let key = key(dir)?;
    let plain = crypt::open(&key, &bytes, &on_disk(dir, rel, true).display().to_string())?;
    let git = dir.join(".git").exists();
    let record = seq_record(dir, &key);
    let history = keystore::history_key(dir);
    let refuse = |problem: binding::Problem, records: Vec<PathBuf>| -> anyhow::Error {
        let e = BindingError {
            problem,
            rel: rel.to_string(),
            records,
            git,
        };
        binding::note_refused(&history, &e);
        e.into()
    };
    let format = crypt::marker(dir)?.map_or(crypt::FORMAT, |m| m.format);
    check_marker_format(dir, format, git, record.as_deref())?;
    match binding::parse(plain).map_err(|p| refuse(p, Vec::new()))? {
        Parsed::Unbound(plain) if format < crypt::FORMAT => Ok(Some(plain)),
        Parsed::Unbound(_) => Err(refuse(binding::Problem::Unbound, Vec::new())),
        Parsed::Bound(b, plain) => {
            if b.path != rel && b.path.eq_ignore_ascii_case(rel) {
                return Ok(None);
            }
            if b.path != rel || b.run != binding::run_of(rel) {
                return Err(refuse(binding::Problem::Moved, Vec::new()));
            }
            if let Some(r) = &record {
                let seen = binding::last_seen(r, rel);
                if seen.is_some_and(|s| b.seq < s) {
                    return Err(refuse(binding::Problem::Older, vec![r.clone()]));
                }
                if seen.is_none_or(|s| b.seq > s)
                    && on_remote(dir, &format!("{rel}{}", crypt::SUFFIX), &bytes)
                {
                    binding::advance(r, rel, b.seq);
                }
            }
            binding::clear_refused(&history, Some(rel));
            Ok(Some(plain))
        }
    }
}

/// Refuses a marker at `format` 1 where this computer saw format 2 for
/// the history in `dir` (under this key, or under any: a key file put
/// back with the marker), naming the records that say so. At format 2,
/// remembers it once the remote's marker says format 2 too (parsed, not
/// compared byte for byte: a line-ending rule on the marker must not keep
/// this from ever arming).
fn check_marker_format(dir: &Path, format: u32, git: bool, record: Option<&Path>) -> Result<()> {
    let mark = binding::format2_mark_for(&keystore::history_key(dir));
    if format < crypt::FORMAT {
        let mut records: Vec<PathBuf> = Vec::new();
        if let Some(r) = record.filter(|r| binding::seen_bound(r)) {
            records.push(r.to_path_buf());
        }
        if let Some(m) = mark.filter(|m| m.is_file()) {
            records.push(m);
        }
        if !records.is_empty() {
            let e = BindingError {
                problem: binding::Problem::MarkerOlder,
                rel: crypt::MARKER.to_string(),
                records,
                git,
            };
            binding::note_refused(&keystore::history_key(dir), &e);
            return Err(e.into());
        }
        binding::clear_refused(&keystore::history_key(dir), Some(crypt::MARKER));
        return Ok(());
    }
    binding::clear_refused(&keystore::history_key(dir), Some(crypt::MARKER));
    let unarmed = record.is_some_and(|r| !binding::seen_bound(r))
        || mark.as_ref().is_some_and(|m| !m.is_file());
    if unarmed && (!git || remote_marker_format(dir).is_some_and(|f| f >= crypt::FORMAT)) {
        if let Some(r) = record {
            binding::mark_bound(r);
        }
        if let Some(m) = &mark {
            binding::mark_format2(m);
        }
    }
    Ok(())
}

/// Forgets this computer's marks of the bindings of the history in `dir`
/// when encryption is turned off here: its format-2 mark and, when
/// given, the record of sequences under the key going away. Turning
/// encryption on or changing the passphrase keeps them (a new key starts
/// its own record anyway).
fn forget_bindings(dir: &Path, record: Option<&Path>) {
    if let Some(m) = binding::format2_mark_for(&keystore::history_key(dir)) {
        let _ = fs::remove_file(m);
    }
    if let Some(r) = record {
        binding::forget(r);
    }
    binding::clear_refused(&keystore::history_key(dir), None);
}

/// This computer's records that make it refuse older copies in the
/// encrypted history in `dir` ([`crate::binding`]): the sequences seen
/// under its key and the format-2 mark, those that are there. What
/// [`accept_history`] resets. Needs the history's passphrase (the record
/// belongs to its key).
pub fn acceptable_records(dir: &Path) -> Result<Vec<PathBuf>> {
    if !crypt::is_encrypted(dir) {
        bail!("The history isn't encrypted, so there is nothing to accept.");
    }
    let key = key(dir)?;
    Ok(seq_record(dir, &key)
        .into_iter()
        .chain(binding::format2_mark_for(&keystore::history_key(dir)))
        .filter(|f| f.is_file())
        .collect())
}

/// What the app and `pathwarden history storage accept` say before
/// accepting the history as it is.
pub const ACCEPT_WORDS: &str = "This computer will trust the history's files as they are now. Do \
                                this only if you restored an older copy on purpose. You can't undo it.";

/// Why [`accept_history`] refuses: reading the history here met no
/// refusal that accepting it gets past.
pub const NOTHING_REFUSED: &str = "Nothing needs accepting: the history is fine. Reload the page.";

/// The refusal that accepting the history in `dir` would get past, as
/// reading it in this process last met it ([`binding::refused`]).
pub fn refusal(dir: &Path) -> Option<BindingError> {
    binding::refused(&keystore::history_key(dir))
}

/// Reads every file of the encrypted history in `dir`, as a command
/// that is about to accept it does, and returns the first refusal that
/// accepting it gets past ([`BindingError::acceptable`]), if any. Reads
/// advance this computer's records as any read does.
pub fn find_refusal(dir: &Path) -> Result<Option<BindingError>> {
    if !crypt::is_encrypted(dir) {
        return Ok(None);
    }
    check_readable(dir)?;
    for rel in state_files_in(dir, true)? {
        if let Err(e) = read_state_file(dir, &rel) {
            if let Some(b) = e
                .chain()
                .find_map(|c| c.downcast_ref::<BindingError>())
                .filter(|b| b.acceptable())
            {
                return Ok(Some(b.clone()));
            }
        }
    }
    Ok(refusal(dir))
}

/// Accepts the encrypted history in `dir` as it is now, on this computer,
/// after a restore made on purpose (a backup, a force push): forgets this
/// computer's records for that history only ([`acceptable_records`]), so
/// the files there now are read as they are and their sequences become
/// the ones remembered. Refused ([`NOTHING_REFUSED`]) unless reading the
/// history in this process met a refusal accepting gets past
/// ([`refusal`], [`find_refusal`]): a stale page never resets the
/// records of a history nothing is wrong with. Returns the records reset.
pub fn accept_history(dir: &Path) -> Result<Vec<PathBuf>> {
    if refusal(dir).is_none() {
        bail!("{NOTHING_REFUSED}");
    }
    let records = acceptable_records(dir)?;
    for r in &records {
        if r.is_file() {
            fs::remove_file(r).with_context(|| format!("removing {}", r.display()))?;
        }
        binding::forget(r);
    }
    binding::clear_refused(&keystore::history_key(dir), None);
    Ok(records)
}

/// The tree of the remote-tracking branch of an encrypted git history, as
/// last listed ([`remember_remote_tree`]).
struct RemoteTree {
    /// The commit listed.
    tip: String,
    /// Each blob's ID, by path.
    ids: std::collections::HashMap<String, String>,
    /// The format its encryption marker says, parsed.
    marker_format: Option<u32>,
    /// When it was last used, for evicting the oldest.
    used: u64,
}

/// [`RemoteTree`]s by [`keystore::history_key`].
type RemoteTrees = std::collections::HashMap<String, RemoteTree>;

/// How many histories' trees are kept; past it, the least recently used
/// one goes.
const REMOTE_TREES: usize = 256;

fn remote_trees() -> std::sync::MutexGuard<'static, RemoteTrees> {
    static TREES: std::sync::OnceLock<std::sync::Mutex<RemoteTrees>> = std::sync::OnceLock::new();
    TREES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// A clock for [`RemoteTree::used`].
fn tick() -> u64 {
    static CLOCK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    CLOCK.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Lists the tree the remote-tracking branch of the encrypted git history
/// in `dir` points at, once per commit, for [`on_remote`] and
/// [`remote_marker_format`]: after each pull and each push, where git runs
/// anyway, never while a page is shown.
fn remember_remote_tree(dir: &Path) {
    if !crypt::is_encrypted(dir) {
        return;
    }
    let Some(tip) = remote_tip(dir) else {
        return;
    };
    let key = keystore::history_key(dir);
    if let Some(t) = remote_trees().get_mut(&key).filter(|t| t.tip == tip) {
        t.used = tick();
        return;
    }
    let Ok(out) = run_git(Some(dir), &["ls-tree", "-r", "-z", &tip]) else {
        return;
    };
    let ids: std::collections::HashMap<String, String> = out
        .split('\0')
        .filter_map(|entry| {
            let (meta, path) = entry.split_once('\t')?;
            let mut parts = meta.split(' ');
            let (_mode, kind, id) = (parts.next()?, parts.next()?, parts.next()?);
            (kind == "blob").then(|| (path.to_string(), id.to_string()))
        })
        .collect();
    // The remote's marker, parsed: the copy here when it is the same blob,
    // else the blob itself.
    let marker_format = ids.get(crypt::MARKER).and_then(|id| {
        let here = fs::read(dir.join(crypt::MARKER)).ok();
        let bytes = match here {
            Some(b) if blob_id(&b, id.len()).as_deref() == Some(id.as_str()) => b,
            _ => small_blob(dir, id, MAX_SMALL_FILE).ok()?,
        };
        serde_json::from_slice::<crypt::Marker>(&bytes)
            .ok()
            .map(|m| m.format)
    });
    // The remote says format 2: this computer refuses format 1 here from
    // now on, whether or not it reads a file before that.
    if marker_format.is_some_and(|f| f >= crypt::FORMAT) {
        if let Some(m) = binding::format2_mark_for(&key) {
            binding::mark_format2(&m);
        }
    }
    let mut trees = remote_trees();
    if trees.len() >= REMOTE_TREES {
        if let Some(oldest) = trees
            .iter()
            .min_by_key(|(_, t)| t.used)
            .map(|(k, _)| k.clone())
        {
            trees.remove(&oldest);
        }
    }
    trees.insert(
        key,
        RemoteTree {
            tip,
            ids,
            marker_format,
            used: tick(),
        },
    );
}

/// Git's ID of a blob holding `bytes`: SHA-1, or SHA-256 for a repository
/// in that format (an ID `hex_len` long).
fn blob_id(bytes: &[u8], hex_len: usize) -> Option<String> {
    let head = format!("blob {}\0", bytes.len());
    let hex = |d: &[u8]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    match hex_len {
        40 => {
            use sha1::Digest as _;
            let mut h = sha1::Sha1::new();
            h.update(head.as_bytes());
            h.update(bytes);
            Some(hex(&h.finalize()))
        }
        64 => {
            use sha2::Digest as _;
            let mut h = sha2::Sha256::new();
            h.update(head.as_bytes());
            h.update(bytes);
            Some(hex(&h.finalize()))
        }
        _ => None,
    }
}

/// The listed tree of the git history in `dir` ([`remember_remote_tree`]),
/// when it is of the commit the remote-tracking branch points at now.
fn with_remote_tree<T>(dir: &Path, f: impl FnOnce(&RemoteTree) -> T) -> Option<T> {
    let tip = remote_tip(dir)?;
    let mut trees = remote_trees();
    let t = trees
        .get_mut(&keystore::history_key(dir))
        .filter(|t| t.tip == tip)?;
    t.used = tick();
    Some(f(t))
}

/// The format the remote's encryption marker says, as last listed.
fn remote_marker_format(dir: &Path) -> Option<u32> {
    with_remote_tree(dir, |t| t.marker_format).flatten()
}

/// Whether `bytes`, read from `name` in the history in `dir`, are what
/// everyone reads there: always in a folder history (the folder is the
/// history); in a git working copy, only when the remote-tracking branch's
/// tree as last listed ([`remember_remote_tree`]) holds that blob at that
/// path. A write of this computer's own that isn't pushed, or was pushed
/// and then lost a race, never counts. Never asks git.
fn on_remote(dir: &Path, name: &str, bytes: &[u8]) -> bool {
    if !dir.join(".git").exists() {
        return true;
    }
    with_remote_tree(dir, |t| {
        t.ids
            .get(name)
            .is_some_and(|id| blob_id(bytes, id.len()).as_deref() == Some(id.as_str()))
    })
    .unwrap_or(false)
}

/// Binds every file of an encrypted history from before the binding
/// (marker format [`crypt::UNBOUND_FORMAT`]) to its path, run and a
/// sequence, then sets the marker's format, so a reader refuses an
/// unbound file from then on. Done on the first write, which a git
/// history commits and pushes with the rest; a write that loses a race to
/// another computer's push does it again on what that computer left, or
/// finds it done. Files that don't decrypt, or are bound already, stay as
/// they are. A file that can't be written leaves the marker at format 1,
/// so the next write tries again, and the write that asked goes on, with
/// a note for the user ([`upgrade_note`]) as what this returns.
///
/// Refused where this computer saw format 2 for this history: binding
/// what is there would accept older copies put back with the marker.
fn upgrade_binding(dir: &Path) -> Result<Option<String>> {
    let Some(mut marker) = crypt::marker(dir)? else {
        return Ok(None);
    };
    if marker.format >= crypt::FORMAT {
        return Ok(None);
    }
    let key = key(dir)?;
    let record = seq_record(dir, &key);
    check_marker_format(
        dir,
        marker.format,
        dir.join(".git").exists(),
        record.as_deref(),
    )?;
    let mut failed = 0usize;
    for rel in state_files_in(dir, true)? {
        let path = on_disk(dir, &rel, true);
        // A file that can't be read now may be readable later: the
        // upgrade is left to the next write rather than leave it unbound.
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                failed += 1;
                continue;
            }
        };
        // One that doesn't decrypt never will (another key, damage): it
        // is refused when read, bound or not.
        let Ok(plain) = crypt::open(&key, &bytes, &rel) else {
            continue;
        };
        if let Ok(Parsed::Unbound(plain)) = binding::parse(plain) {
            // Unbound: its sequence is this computer's record's, plus one.
            let seq = record
                .as_deref()
                .and_then(|r| binding::last_seen(r, &rel))
                .unwrap_or(0)
                .saturating_add(1);
            let written = seal_bound(&key, &rel, seq, &plain).and_then(|b| write_atomic(&path, &b));
            if written.is_err() {
                failed += 1;
            }
        }
    }
    if failed > 0 {
        return Ok(Some(upgrade_note(failed)));
    }
    marker.format = crypt::FORMAT;
    marker.note = crypt::Marker::new().note;
    write_atomic(&dir.join(crypt::MARKER), &marker.to_bytes())?;
    Ok(None)
}

/// What a run or a sync says when [`upgrade_binding`] couldn't rewrite
/// `n` files.
pub fn upgrade_note(n: usize) -> String {
    format!(
        "{} {UPGRADE_NOTE_END}",
        if n == 1 {
            "1 file".to_string()
        } else {
            format!("{n} files")
        }
    )
}

/// How [`upgrade_note`] ends.
const UPGRADE_NOTE_END: &str =
    "in the history couldn't be upgraded. Pathwarden tries again on the next run.";

/// Whether a run's warning is an [`upgrade_note`]: Run details shows it
/// on a row of its own, not as a difference from the previous run.
pub fn is_upgrade_note(warning: &str) -> bool {
    warning.ends_with(UPGRADE_NOTE_END)
}

/// `notes` without repeats, in their order, and of the upgrade notes
/// ([`upgrade_note`]) only the last: each write tries the upgrade again,
/// and the last one says how it stands.
pub fn once_each(notes: Vec<String>) -> Vec<String> {
    let last_upgrade = notes.iter().rposition(|n| is_upgrade_note(n));
    let mut out: Vec<String> = Vec::with_capacity(notes.len());
    for (i, n) in notes.into_iter().enumerate() {
        if is_upgrade_note(&n) && Some(i) != last_upgrade {
            continue;
        }
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

/// Every file of the history in `dir`, by its seam name, in the form
/// `encrypted` says.
fn state_files_in(dir: &Path, encrypted: bool) -> Result<Vec<String>> {
    let mut out: Vec<String> = single_files()
        .filter(|f| {
            let path = on_disk(dir, f, encrypted);
            !is_link(&path) && path.is_file()
        })
        .map(str::to_string)
        .collect();
    for folder in run_folders() {
        out.extend(list_as(dir, folder, encrypted)?);
    }
    out.extend(bundle_files_as(dir, encrypted));
    Ok(out)
}

/// Writes `rel` into the history in `dir`, atomically, encrypted when the
/// history is encrypted (which needs its passphrase), and bound to its
/// path, run and the next sequence ([`crate::binding`]); the other form of
/// the file, if any, is removed. [`Store::write_state_file`] for a folder
/// known only by its path.
///
/// The next sequence is read and then written, which is safe because
/// every writer holds the history's [`Lock`] (a run: `record.rs`; shared
/// settings: `settings_sync.rs`; full runs: the UI's `shared_runs.rs`).
/// A writer outside it racing another could give two writes one sequence
/// (never a lower one than the file had), and, in a folder history whose
/// writer then wrote again, make its own computer refuse the other's
/// copy as older.
///
/// Returns notes for the user: one short sentence each (an upgrade of
/// the binding that couldn't rewrite every file, [`upgrade_binding`]).
pub fn write_state_file(dir: &Path, rel: &str, bytes: &[u8]) -> Result<Vec<String>> {
    check_rel(rel)?;
    let encrypted = mode(dir, true)?;
    let mut notes = Vec::new();
    if encrypted {
        notes.extend(upgrade_binding(dir)?);
        let key = key(dir)?;
        let seq = next_seq(dir, &key, rel);
        write_atomic(
            &on_disk(dir, rel, true),
            &seal_bound(&key, rel, seq, bytes)?,
        )?;
        // A folder is the history itself: what is written is what
        // everyone reads. (In git, only once the remote has it.)
        if !dir.join(".git").exists() {
            if let Some(r) = seq_record(dir, &key) {
                binding::advance(&r, rel, seq);
            }
        }
        // A plain copy from before encryption; findings.json stays as the
        // stub older versions refuse.
        if rel == "findings.json" {
            let path = dir.join(rel);
            if !fs::read(&path).is_ok_and(|b| crypt::is_stub(&b)) {
                write_atomic(&path, &crypt::stub())?;
            }
        } else if rel != crate::action_log::FILE {
            // A plain actions.json is never read, and never removed but on
            // purpose ([`remove_plain_leftover`]).
            remove_if_there(&dir.join(rel))?;
        }
    } else {
        write_atomic(&dir.join(rel), bytes)?;
        remove_if_there(&on_disk(dir, rel, true))?;
    }
    Ok(notes)
}

/// Removes `rel` from the history in `dir`, in either form; whether it
/// was there.
pub fn remove_state_file(dir: &Path, rel: &str) -> Result<bool> {
    check_rel(rel)?;
    // A file removed (a run deleted, a full run trimmed) is refused no
    // more.
    binding::clear_refused(&keystore::history_key(dir), Some(rel));
    let encrypted = mode(dir, false)?;
    let sealed = remove_if_there(&on_disk(dir, rel, true))?;
    // The stub of an encrypted history stays.
    let plain = if rel == "findings.json" && encrypted {
        false
    } else {
        remove_if_there(&dir.join(rel))?
    };
    Ok(sealed || plain)
}

/// Whether the history in `dir` holds `rel`, without reading it.
pub fn has_state_file(dir: &Path, rel: &str) -> bool {
    if !is_state_rel(rel) {
        return false;
    }
    let path = on_disk(dir, rel, crypt::is_encrypted(dir));
    !is_link(&path) && path.is_file()
}

/// The files in `folder` ("history" or "timings") of the history in `dir`,
/// by their seam names ("history/<run>.json"), sorted. Files of the other
/// form (plain ones in an encrypted history: [`planted_files`]) are left
/// out.
pub fn list_state_files(dir: &Path, folder: &str) -> Result<Vec<String>> {
    list_as(dir, folder, crypt::is_encrypted(dir))
}

fn list_as(dir: &Path, folder: &str, encrypted: bool) -> Result<Vec<String>> {
    if !run_folders().any(|f| f == folder) {
        bail!("'{folder}' is not a folder of the history");
    }
    let path = dir.join(folder);
    let entries = match fs::read_dir(&path) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|name| {
            let name = if encrypted {
                name.strip_suffix(crypt::SUFFIX)?.to_string()
            } else {
                name
            };
            let rel = format!("{folder}/{name}");
            is_state_rel(&rel).then_some(rel)
        })
        .collect();
    out.sort();
    Ok(out)
}

/// Plain state files in an encrypted history (the `findings.json` stub
/// aside), by their seam names: nothing Pathwarden writes, so someone put
/// them there. They are never read, and a git pull removes them so no
/// commit stages them again ([`Store::pull`]).
pub fn planted_files(dir: &Path) -> Vec<String> {
    if !crypt::is_encrypted(dir) {
        return Vec::new();
    }
    // A plain actions.json is never read, and never removed but when
    // someone imports it ([`crate::action_log::import_plain`]).
    let mut out: Vec<String> = single_files()
        .filter(|f| *f != crate::action_log::FILE)
        .filter(|f| {
            let path = dir.join(f);
            path.is_file()
                && !(*f == "findings.json" && fs::read(&path).is_ok_and(|b| crypt::is_stub(&b)))
        })
        .map(str::to_string)
        .collect();
    for folder in run_folders() {
        out.extend(list_as(dir, folder, false).unwrap_or_default());
    }
    out.extend(bundle_files_as(dir, false));
    out
}

/// Every file of every full run in the history in `dir`, by its seam name
/// (`runs/<run>/<name>`), in the form `encrypted` says. Sorted.
fn bundle_files_as(dir: &Path, encrypted: bool) -> Vec<String> {
    let mut out = Vec::new();
    for folder in bundle_folders() {
        for id in bundle_ids(dir, folder, encrypted) {
            out.extend(
                bundle_names(dir, folder, &id, encrypted)
                    .into_iter()
                    .map(|n| format!("{folder}/{id}/{n}")),
            );
        }
    }
    out
}

/// The full runs the history in `dir` holds (`runs/<run>/`), by run ID,
/// oldest first. Folders holding none of [`BUNDLE_FILES`] (in the form
/// the history is in) are left out.
pub fn list_bundles(dir: &Path) -> Vec<String> {
    let encrypted = crypt::is_encrypted(dir);
    bundle_folders()
        .flat_map(|f| bundle_ids(dir, f, encrypted))
        .collect()
}

/// The files of full run `run_id` in the history in `dir`, by name
/// ([`BUNDLE_FILES`]).
pub fn bundle_files(dir: &Path, run_id: &str) -> Vec<&'static str> {
    if !is_run_id(run_id) {
        return Vec::new();
    }
    bundle_names(dir, BUNDLE_DIR, run_id, crypt::is_encrypted(dir))
}

/// Whether the history in `dir` can be read here: not encrypted, or its
/// passphrase is at hand and opens it; and its encryption wasn't stripped
/// ([`mode`]). The error says why not, for the user
/// ([`crypt::CryptError`]).
pub fn check_readable(dir: &Path) -> Result<()> {
    if mode(dir, true)? {
        key(dir)?;
    }
    Ok(())
}

fn remove_if_there(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// What [`Store::publish_with`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Published {
    /// Committed and pushed; false with nothing to commit, or when the
    /// state is a folder.
    pub pushed: bool,
    /// How many times another run had pushed first, so the change was
    /// applied again on top of it.
    pub retries: usize,
    /// For the user: what happened to commits earlier runs could not push
    /// ([`Store::pull`]'s notes).
    pub notes: Vec<String>,
}

/// What [`Store::encrypt`], [`Store::decrypt`] or
/// [`Store::change_passphrase`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Converted {
    /// How many files of the history were written again.
    pub files: usize,
    /// Committed and pushed (git).
    pub pushed: bool,
    /// For the user: what happened to earlier unpushed changes, or that
    /// this push failed and the change is committed here.
    pub notes: Vec<String>,
    /// [`Store::decrypt`] on a history already plain (decrypted elsewhere,
    /// or stripped): nothing was written; what removed the encryption
    /// ("commit 1a2b3c4 by Jane Doe", or a rewrite of the branch).
    pub accepted: Option<String>,
}

/// The error of a push that failed for another reason than another run
/// pushing first (the remote out of reach, a refused push): the run is
/// committed in the working copy, and the next run that can push pushes it.
#[derive(Debug, Clone)]
pub struct KeptUnpushed {
    /// Why, in a few words: "the remote can't be reached, or refused the
    /// sign-in".
    pub reason: String,
    /// What git said, for `--verbose` and the History storage page.
    pub detail: String,
    /// What became of commits earlier runs could not push
    /// ([`Store::pull`]'s notes), when this publish got that far.
    pub notes: Vec<String>,
}

impl KeptUnpushed {
    /// One sentence for the user. `done`: what was done here ("This run is
    /// recorded", "The run was removed").
    pub fn sentence(&self, done: &str) -> String {
        format!(
            "{done} here, but the change couldn't be pushed ({}); it goes with the next run that \
             pushes.",
            self.reason
        )
    }
}

impl std::fmt::Display for KeptUnpushed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({})",
            self.sentence("The change is committed"),
            self.detail
        )
    }
}

impl std::error::Error for KeptUnpushed {}

/// What commits a failed push left changed, for [`Store::pull`] to add
/// back when another machine pushed first.
#[derive(Default)]
struct Salvage {
    /// History points and timings they added: (path, contents).
    files: Vec<(String, Vec<u8>)>,
    /// History points they removed (runs forgotten here): not redone.
    removed: usize,
}

/// Why a push failed, found out after the fact.
enum Rejected {
    /// The remote has commits this working copy lacks: another run pushed
    /// first.
    Behind,
    /// The remote can't be reached (offline, moved, credentials).
    Unreachable(anyhow::Error),
    /// The remote was reached and had nothing new, yet refused the push
    /// (permissions, a protected branch, a hook).
    Refused,
    /// The remote has this commit already (it got there another way).
    Pushed,
}

/// Each run's collection timings, as `timings/<run>.json`
/// ([`crate::diagnostics::CollectionTimings`]): kept apart from the
/// history's points, which stay small.
pub const TIMINGS_DIR: &str = "timings";

/// The timings recorded with history run `run_id`, if any.
pub fn run_timings(
    state_dir: &Path,
    run_id: &str,
) -> Option<crate::diagnostics::CollectionTimings> {
    if !is_run_id(run_id) {
        return None;
    }
    let bytes = read_state_file(state_dir, &format!("{TIMINGS_DIR}/{run_id}.json")).ok()??;
    crate::diagnostics::CollectionTimings::parse(std::str::from_utf8(&bytes).ok()?)
}

/// Whether history run `run_id` has timings ([`run_timings`]), without
/// reading them: for a list of runs.
pub fn has_run_timings(state_dir: &Path, run_id: &str) -> bool {
    is_run_id(run_id) && has_state_file(state_dir, &format!("{TIMINGS_DIR}/{run_id}.json"))
}

/// A history run ID: "20261018T170000.000Z" and the like, never a path.
pub(crate) fn is_run_id(run_id: &str) -> bool {
    !run_id.is_empty()
        && run_id.len() <= 64
        && run_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !run_id.starts_with('.')
}

pub struct Store {
    pub dir: PathBuf,
    git: Option<Git>,
    /// Problems with the settings worth telling the user about.
    pub warnings: Vec<String>,
    /// `[state] encrypted`, at the config's own location: any plain history
    /// here is refused ([`Store::check_expected`]).
    expect_encrypted: bool,
    /// The history is the one the config names (not a `--state` folder).
    at_config_location: bool,
    /// The pathwarden.toml the settings came from, when known.
    config_file: Option<PathBuf>,
}

struct Git {
    remote: String,
    branch: String,
}

/// Held for the duration of a run; removed on drop, but only if it is still
/// ours (a run that outlived the stale-lock window must not delete the lock of
/// the run that replaced it).
pub struct Lock {
    path: PathBuf,
    token: String,
    /// Dropped with the lock, which stops the thread that renews the lock's
    /// time ([`LOCK_REFRESH`]): a run longer than [`STALE_LOCK`] keeps it.
    _renew: std::sync::mpsc::Sender<()>,
    /// A git state folder taking the lock made, and the missing parents it
    /// made on the way (that folder first): removed with the lock while
    /// they are empty again (the first clone failed).
    made_dirs: Vec<PathBuf>,
}

/// The tokens of the locks this process holds now ([`Lock`]): a lock file
/// naming this process with one of them is held here, by another task (a
/// pull, a save, a recording); with any other token, it was left by an
/// earlier process that had the same ID, or by a lock this process failed
/// to remove, and nothing holds it.
fn held_here() -> std::sync::MutexGuard<'static, std::collections::HashSet<String>> {
    static HELD: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    HELD.get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// This computer's name, as lock files say it.
fn this_host() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}

/// A lock file's "host H pid P token T started S": S is when process P
/// started (Unix seconds), so a process that got its ID later is told
/// apart. Older versions write no S.
#[derive(Debug, Default, PartialEq, Eq)]
struct LockHolder {
    host: Option<String>,
    pid: Option<u32>,
    token: Option<String>,
    started: Option<u64>,
}

impl LockHolder {
    fn parse(text: &str) -> LockHolder {
        let mut h = LockHolder::default();
        let words: Vec<&str> = text.split_whitespace().collect();
        for pair in words.windows(2) {
            match pair[0] {
                "host" if h.host.is_none() => h.host = Some(pair[1].to_string()),
                "pid" if h.pid.is_none() => h.pid = pair[1].parse().ok(),
                "token" if h.token.is_none() => h.token = Some(pair[1].to_string()),
                "started" if h.started.is_none() => h.started = pair[1].parse().ok(),
                _ => {}
            }
        }
        h
    }
}

/// Unix seconds of a process's start.
fn unix_secs(t: std::time::SystemTime) -> Option<u64> {
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// When this process started (Unix seconds), as its lock files say.
fn own_start() -> Option<u64> {
    static START: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *START.get_or_init(|| match crate::proc_tree::holder(std::process::id()) {
        crate::proc_tree::Holder::Running {
            started: Some(t), ..
        } => unix_secs(t),
        _ => None,
    })
}

/// What to do about a lock file another task left.
#[derive(Debug, PartialEq, Eq)]
enum LockVerdict {
    /// Nothing holds it any more: taken over at once.
    Left,
    /// Held by another task of this very process.
    HeldHere,
    /// Held by another Pathwarden (here or on another computer), or it
    /// can't be told.
    HeldElsewhere,
}

/// Whether a program by this file name is Pathwarden: `pathwarden.exe`,
/// the desktop app, or this program itself (a test build).
fn is_pathwarden(program: &str) -> bool {
    let p = program.to_ascii_lowercase();
    p.contains("pathwarden")
        || std::env::current_exe()
            .ok()
            .and_then(|e| {
                e.file_name()
                    .map(|n| n.to_string_lossy().to_ascii_lowercase())
            })
            .is_some_and(|me| me == p)
}

/// Whether the lock `holder` wrote (last renewed `age` ago) is still
/// held. A lock of another computer is held until it is [`STALE_LOCK`]
/// old. One of this computer is not held once its process stopped, or its
/// ID is now another program's, or another process's than the one that
/// wrote it (started at another time); nor is one naming this process with
/// a token it doesn't hold. `look` says what a process is now
/// ([`crate::proc_tree::holder`]).
fn lock_verdict(
    holder: &LockHolder,
    age: Duration,
    look: impl Fn(u32) -> crate::proc_tree::Holder,
) -> LockVerdict {
    use crate::proc_tree::Holder;
    if age > STALE_LOCK {
        return LockVerdict::Left;
    }
    let here = holder
        .host
        .as_deref()
        .is_some_and(|h| h.eq_ignore_ascii_case(&this_host()));
    let Some(pid) = holder.pid.filter(|_| here) else {
        return LockVerdict::HeldElsewhere;
    };
    if pid == std::process::id() {
        let held = holder
            .token
            .as_ref()
            .is_some_and(|t| held_here().contains(t));
        return if held {
            LockVerdict::HeldHere
        } else {
            LockVerdict::Left
        };
    }
    match look(pid) {
        Holder::Gone => LockVerdict::Left,
        Holder::Running { program, .. } if !is_pathwarden(&program) => LockVerdict::Left,
        // Not the process that wrote it: its ID was used again.
        Holder::Running {
            started: Some(started),
            ..
        } if holder
            .started
            .zip(unix_secs(started))
            .is_some_and(|(wrote, now)| wrote.abs_diff(now) > 2) =>
        {
            LockVerdict::Left
        }
        Holder::Running { .. } | Holder::Unknown => LockVerdict::HeldElsewhere,
    }
}

/// What [`Store::lock`] says when another task of this Pathwarden holds
/// the lock; [`Store::lock_waiting`] waits for it.
const HELD_HERE: &str = "this Pathwarden is already using";

/// A token in [`held_here`] while a lock is being taken: removed again
/// unless the lock is taken ([`Registered::keep`]).
struct Registered(String);

impl Registered {
    fn new(token: &str) -> Self {
        held_here().insert(token.to_string());
        Registered(token.to_string())
    }

    /// The lock was taken: [`Lock`] removes the token when dropped.
    fn keep(self) {
        std::mem::forget(self);
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        held_here().remove(&self.0);
    }
}

/// How long a take-over's own guard file ([`take_over`]) may be there
/// before it is taken for one a crash left.
const TAKE_OVER_GUARD: Duration = Duration::from_secs(30);

/// Whether the take-over guard at `guard` was left by a run that stopped:
/// older than [`TAKE_OVER_GUARD`], or dated in the future (a clock put
/// back), which no run taking over now made.
fn guard_left(guard: &Path) -> bool {
    match fs::metadata(guard).and_then(|m| m.modified()) {
        Err(_) => false,
        Ok(t) => t.elapsed().map_or(true, |age| age > TAKE_OVER_GUARD),
    }
}

/// Removes the lock file at `path` that nothing holds, when it still says
/// `holder`. One run at a time does it, under a guard file of its own made
/// with an atomic create ([`TAKING_FILE`]): of runs taking the same left
/// lock over at once, one removes it and the others try again, so none
/// removes the fresh lock a faster one took meanwhile (only a take-over
/// removes a lock it didn't take, and the guard keeps take-overs apart).
fn take_over(path: &Path, holder: &str) {
    let guard = path.with_file_name(TAKING_FILE);
    if guard_left(&guard) {
        let _ = fs::remove_file(&guard);
    }
    if fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&guard)
        .is_err()
    {
        // Another run is taking it over.
        return;
    }
    if fs::read_to_string(path).is_ok_and(|now| now == holder) {
        let _ = fs::remove_file(path);
    }
    let _ = fs::remove_file(&guard);
}

/// Renews the time of the lock file at `path` every `every` while it still
/// names `token`, until `stop` says so (its [`Lock`] is dropped): a lock
/// another run took over is never touched.
fn renew_lock(path: &Path, token: &str, stop: &std::sync::mpsc::Receiver<()>, every: Duration) {
    while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = stop.recv_timeout(every) {
        if fs::read_to_string(path).is_ok_and(|s| s.contains(token)) {
            let _ = fs::File::options()
                .write(true)
                .open(path)
                .and_then(|f| f.set_modified(std::time::SystemTime::now()));
        }
    }
}

impl Lock {
    fn new(path: PathBuf, token: String, made_dirs: Vec<PathBuf>) -> Self {
        held_here().insert(token.clone());
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (p, t) = (path.clone(), token.clone());
        std::thread::spawn(move || renew_lock(&p, &t, &rx, LOCK_REFRESH));
        Lock {
            path,
            token,
            _renew: tx,
            made_dirs,
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        if fs::read_to_string(&self.path).is_ok_and(|s| s.contains(&self.token)) {
            let _ = fs::remove_file(&self.path);
        }
        held_here().remove(&self.token);
        // Only when empty: never a folder holding anything.
        remove_made_dirs(&self.made_dirs);
    }
}

impl Store {
    pub fn new(cfg: &StateConfig, dir_override: Option<&Path>) -> Result<Self> {
        let dir = dir_override
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(cfg.path.as_deref().unwrap_or("pathwarden-state")));
        let warnings = Vec::new();
        let git = match cfg.backend {
            StateBackend::Local => None,
            StateBackend::Git => {
                let remote = cfg
                    .remote
                    .clone()
                    .context("[state] backend = \"git\" needs `remote`")?;
                let branch = cfg.branch.clone().unwrap_or_else(|| "main".into());
                validate_remote(&remote)?;
                validate_branch(&branch)?;
                // Refused, as the app and `pathwarden connect` refuse it:
                // git would keep the secret in `.git/config`.
                if crate::config::remote_has_password(&remote)
                    || crate::config::remote_has_token(&remote)
                {
                    bail!(crate::config::REMOTE_PASSWORD_REFUSED);
                }
                Some(Git { remote, branch })
            }
        };
        // The config's own history: its repository and branch (a working
        // copy anywhere), or its folder when no other is given.
        let at_config_location = git.is_some() || dir_override.is_none();
        Ok(Store {
            dir,
            git,
            warnings,
            expect_encrypted: cfg.encrypted && at_config_location,
            at_config_location,
            config_file: None,
        })
    }

    /// [`Store::new`] for `dir`, the folder the config itself names
    /// (resolved by the caller, as the app does from the environment's
    /// folder): `[state] encrypted` applies to it.
    pub fn new_configured(cfg: &StateConfig, dir: &Path) -> Result<Self> {
        let mut store = Store::new(cfg, Some(dir))?;
        store.at_config_location = true;
        store.expect_encrypted = cfg.encrypted;
        Ok(store)
    }

    /// The pathwarden.toml the settings came from, named when its
    /// `[state] encrypted` refuses a history.
    pub fn with_config_file(mut self, path: PathBuf) -> Self {
        self.config_file = Some(path);
        self
    }

    /// The pathwarden.toml whose `[state] encrypted` speaks for this
    /// history: none for a folder the config doesn't name (`--state`).
    pub fn flag_config(&self) -> Option<&Path> {
        self.config_file
            .as_deref()
            .filter(|_| self.at_config_location)
    }

    /// Whether `file` lives inside the git working copy, where anyone who can
    /// push to the state repository controls it.
    pub fn in_git_working_copy(&self, file: &Path) -> bool {
        if self.git.is_none() {
            return false;
        }
        let full = |p: &Path| {
            fs::canonicalize(p)
                .or_else(|_| std::path::absolute(p))
                .unwrap_or_else(|_| p.to_path_buf())
        };
        full(file).starts_with(full(&self.dir))
    }

    /// Backed by a git repository (pulled before a run, pushed after).
    pub fn is_git(&self) -> bool {
        self.git.is_some()
    }

    /// The remote (credentials hidden) and branch, for git.
    /// Asks the remote for its branch (`git ls-remote`), without the lock
    /// and without touching the working copy: for Sign in, so git's sign-in
    /// window can stay open as long as it takes while runs and syncs carry
    /// on. Not for a folder history.
    pub fn check_access(&self) -> Result<()> {
        let Some(g) = &self.git else {
            bail!("the history is a folder, not a git repository");
        };
        let args = [
            "ls-remote",
            "--heads",
            "--",
            &g.remote,
            &format!("refs/heads/{}", g.branch),
        ];
        // In the working copy, so its own settings (a credential helper,
        // http settings) apply; before the first clone, from a neutral
        // folder, never the repository Pathwarden happens to be run from.
        // Only a working copy Pathwarden made ([`Store::verify_owned`]'s
        // checks, read only: this runs without the lock): another one's
        // `.git/config` (a credential helper, `core.sshCommand`) must not
        // apply.
        if self.dir.join(".git").is_dir() && self.owned_already(g) {
            return run_git(Some(&self.dir), &args).map(|_| ());
        }
        let neutral = std::env::temp_dir();
        let ceiling = neutral.to_string_lossy().into_owned();
        run_git_env(
            Some(&neutral),
            &args,
            git_idle(),
            &[("GIT_CEILING_DIRECTORIES", &ceiling)],
        )
        .map(|_| ())
    }

    pub fn remote(&self) -> Option<(String, String)> {
        self.git
            .as_ref()
            .map(|g| (redact_url(&g.remote), g.branch.clone()))
    }

    pub fn describe(&self) -> String {
        match &self.git {
            Some(g) => format!(
                "{} (git {} @ {})",
                self.dir.display(),
                redact_url(&g.remote),
                g.branch
            ),
            None => format!("{} (local)", self.dir.display()),
        }
    }

    /// Prevents two runs from using the same state folder at once. It guards
    /// one machine's folder; runs on different machines sharing one git remote
    /// meet at the push instead ([`Store::publish_with`]).
    pub fn lock(&self) -> Result<Lock> {
        let path = self.lock_path();
        let made_dirs = if self.git.is_some() {
            missing_dirs(&self.dir)
        } else {
            Vec::new()
        };
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let token = format!("{:016x}", RandomState::new().build_hasher().finish());
        let host = this_host();
        // Known before the file is made: another task of this process that
        // reads it meanwhile sees its token held here, never a lock left.
        let started = own_start()
            .map(|s| format!(" started {s}"))
            .unwrap_or_default();
        let registered = Registered::new(&token);
        for attempt in 0..2 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    use std::io::Write;
                    let _ = writeln!(
                        f,
                        "host {host} pid {} token {token}{started}",
                        std::process::id()
                    );
                    drop(f);
                    #[cfg(test)]
                    tests::after_create(&path);
                    registered.keep();
                    let lock = Lock::new(path, token, made_dirs);
                    // Taken first, so an older run starting meanwhile is seen.
                    self.check_old_lock()?;
                    return Ok(lock);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                    let age = fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .unwrap_or_default();
                    let holder = fs::read_to_string(&path).unwrap_or_default();
                    match lock_verdict(
                        &LockHolder::parse(&holder),
                        age,
                        crate::proc_tree::holder,
                    ) {
                        LockVerdict::Left => {
                            take_over(&path, &holder);
                            // Then an atomic create: if another run took it
                            // first, that create fails.
                            continue;
                        }
                        LockVerdict::HeldHere => bail!(
                            "{HELD_HERE} {} for something else (getting the latest, sharing a \
                             change or recording a run); try again when it has finished",
                            self.dir.display()
                        ),
                        LockVerdict::HeldElsewhere => bail!(
                            "another pathwarden run is using {} (lock file {}: {}); try again when it has finished. A running Pathwarden keeps its lock fresh; one left by a Pathwarden that stopped is taken over at once on its own computer, and after 6 hours from any other",
                            self.dir.display(),
                            path.display(),
                            holder.trim()
                        ),
                    }
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("creating lock {}", path.display()))
                }
            }
        }
        bail!(
            "another pathwarden run took the lock {} at the same time",
            path.display()
        )
    }

    /// [`Store::lock`], waiting up to `wait` for another run (or a save
    /// sharing its change) that holds it, instead of failing at once.
    pub fn lock_waiting(&self, wait: Duration) -> Result<Lock> {
        let started = std::time::Instant::now();
        loop {
            match self.lock() {
                Ok(l) => return Ok(l),
                Err(e)
                    if started.elapsed() < wait
                        && (e.to_string().contains("pathwarden run is using")
                            || e.to_string().contains(HELD_HERE)
                            || e.to_string().contains("at the same time")) =>
                {
                    std::thread::sleep(Duration::from_millis(250));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The lock file, inside the state folder, for local and git storage
    /// alike: a scheduled task's account may write only there (its parent
    /// holds the programs it runs). In a git working copy it is never
    /// committed ([`OWN_FILES`]).
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join(LOCK_FILE)
    }

    /// Refuses the run while a Pathwarden older than this one may still be
    /// using the git state folder: those kept its lock beside the folder
    /// (`<folder>.lock`). Those versions never renew it, so one older than
    /// [`STALE_LOCK`] is taken for a crash and ignored, as they did
    /// themselves; a longer run of theirs can then overlap. Neither is ever
    /// removed: it isn't this run's, and the folder beside it may be
    /// read-only to this account.
    fn check_old_lock(&self) -> Result<()> {
        if self.git.is_none() {
            return Ok(());
        }
        let Some(name) = self.dir.file_name().and_then(|n| n.to_str()) else {
            return Ok(());
        };
        let old = self
            .dir
            .parent()
            .unwrap_or(Path::new("."))
            .join(format!("{name}.lock"));
        let fresh = fs::metadata(&old)
            .and_then(|m| m.modified())
            .is_ok_and(|t| t.elapsed().unwrap_or_default() <= STALE_LOCK);
        if fresh {
            let holder = fs::read_to_string(&old).unwrap_or_default();
            bail!(
                "an older pathwarden run is using {} (lock file {}: {}); if no older run is \
                 running, delete that lock file",
                self.dir.display(),
                old.display(),
                holder.trim()
            );
        }
        Ok(())
    }

    /// Brings the state up to date with the remote (git) or makes sure the
    /// folder exists (local).
    ///
    /// Commits earlier runs could not push ([`KeptUnpushed`]) are kept while
    /// the remote has not moved on, and pushed by the next
    /// [`Store::publish_with`]. When it has, the runs they recorded are added
    /// to the history again as points before the newer runs
    /// ([`HistoryPoint::inserted`]), in a commit of their own the next
    /// publish pushes; the findings state is the remote's. The returned note
    /// says so, and names points of runs never committed (`--no-push`) that
    /// were removed: for the user.
    pub fn pull(&self) -> Result<Option<String>> {
        self.sync(false)
    }

    /// [`Store::pull`]. `publishing`: called by [`Store::publish_with`]
    /// after another run pushed first, with this run's own commit on top,
    /// which the caller makes again: only the commits before it are kept.
    fn sync(&self, publishing: bool) -> Result<Option<String>> {
        let Some(g) = &self.git else {
            fs::create_dir_all(&self.dir)
                .with_context(|| format!("creating {}", self.dir.display()))?;
            if crypt::is_encrypted(&self.dir) {
                record_location_pin(&self.dir)?;
            }
            return Ok(None);
        };
        let dir = Some(self.dir.as_path());
        if !self.dir.join(".git").exists() {
            let cloning = self.dir.join(CLONING_DIR);
            let others = self.dir.exists()
                && fs::read_dir(&self.dir)
                    .with_context(|| format!("reading {}", self.dir.display()))?
                    .filter_map(|e| e.ok())
                    // The run's own lock is taken before the clone, and a
                    // clone that failed before left its record of the pull.
                    .any(|e| !OWN_FILES.iter().any(|o| e.file_name() == *o));
            if !others && fs::symlink_metadata(&cloning).is_ok() {
                // A clone a stopped run (the idle limit, Ctrl+C, a crash, a
                // power cut) left unfinished: only this code makes it.
                remove_tree(&cloning).with_context(|| {
                    format!("removing an unfinished clone {}", cloning.display())
                })?;
            }
            if others {
                bail!(
                    "{} exists and is not a git working copy; point [state] path at an empty or new folder",
                    self.dir.display()
                );
            }
            self.clone_into_place(g)?;
        } else {
            self.verify_owned(g)?;
            // Locks an earlier idle stop had to keep, now long stale.
            remove_left_locks(&self.dir);
            // A crash or a conflicting push may have left a git operation
            // half-done; abort it so the reset below can proceed. Both fail
            // when there is nothing to abort, which is the usual case.
            let _ = run_git(dir, &["rebase", "--abort"]);
            let _ = run_git(dir, &["merge", "--abort"]);
            // Seen encrypted before this fetch (a pull a crash cut short
            // after its fetch included): this computer keeps that.
            if crypt::is_encrypted(&self.dir) {
                record_location_pin(&self.dir)?;
            }
            self.fetch()?;
        }
        self.exclude_own_files()?;
        let remote_branch = format!("origin/{}", g.branch);
        let local_branch = format!("refs/heads/{}", g.branch);
        let has_remote =
            run_git(dir, &["rev-parse", "--verify", "--quiet", &remote_branch]).is_ok();
        if has_remote {
            self.check_state_branch(g, &remote_branch)?;
        }
        let mut notes = Vec::new();
        // Commits a failed push left, and nothing else: a remote moved back
        // on purpose is followed, never undone.
        // Kept commits the remote has now (pushed another way) are not kept
        // any more: a later rollback of the remote must not undo them.
        if has_remote {
            if let Some(tip) = self.kept_unpushed(&local_branch, false) {
                if run_git(dir, &["merge-base", "--is-ancestor", &tip, &remote_branch]).is_ok() {
                    self.clear_kept();
                }
            }
        }
        let kept = self.kept_unpushed(&local_branch, false);
        let fast_forward = kept.is_some()
            && !publishing
            && (!has_remote
                || run_git(
                    dir,
                    &["merge-base", "--is-ancestor", &remote_branch, &local_branch],
                )
                .is_ok());
        let mut salvage = Salvage::default();
        if fast_forward {
            // Nobody pushed since: keep them, for the next run to push.
            if has_remote {
                run_git(dir, &["checkout", "--quiet", "--force", &g.branch])?;
            } else {
                run_git(dir, &["symbolic-ref", "HEAD", &local_branch])?;
            }
            run_git(dir, &["reset", "--quiet", "--hard", &local_branch])?;
        } else {
            if let Some(kept) = &kept {
                salvage = self.kept_points(has_remote.then_some(remote_branch.as_str()), kept)?;
            }
            if has_remote {
                run_git(
                    dir,
                    &[
                        "checkout",
                        "--quiet",
                        "--force",
                        "-B",
                        &g.branch,
                        &remote_branch,
                    ],
                )?;
                run_git(dir, &["reset", "--quiet", "--hard", &remote_branch])?;
            } else {
                // A new, empty state repository: the branch starts with the
                // next commit, from nothing.
                run_git(dir, &["symbolic-ref", "HEAD", &local_branch])?;
                if run_git(dir, &["rev-parse", "--verify", "--quiet", &local_branch]).is_ok() {
                    run_git(dir, &["update-ref", "-d", &local_branch])?;
                    run_git(dir, &["read-tree", "--empty"])?;
                    for f in single_files()
                        .flat_map(|f| [f.to_string(), format!("{f}{}", crypt::SUFFIX)])
                        .chain([crypt::MARKER.to_string(), crypt::KEY_FILE.to_string()])
                    {
                        let _ = fs::remove_file(self.dir.join(f));
                    }
                }
            }
            self.clear_kept();
        }
        // Files no commit holds (a --no-push run's point, a crashed write)
        // never carry over into the next run's commit.
        let folders = state_folders();
        let mut clean_n = vec!["clean", "-n", "-d", "-x", "--"];
        clean_n.extend(&folders);
        let untracked = run_git(dir, &clean_n)?;
        let removed = untracked
            .lines()
            .filter(|l| {
                l.contains(&format!("{HISTORY_DIR}/"))
                    && (l.ends_with(".json") || l.ends_with(".json.age"))
            })
            .count();
        if removed > 0 {
            notes.push(format!(
                "{} that no commit holds (from a --no-push run, or recorded while pushing was \
                 off) {} removed from {}: the history is the remote's.",
                crate::text::count(removed, "run point", "run points"),
                if removed == 1 { "was" } else { "were" },
                self.dir.display()
            ));
        }
        let mut clean = vec!["clean", "--quiet", "--force", "-d", "-x", "--"];
        clean.extend(&folders);
        run_git(dir, &clean)?;
        // Git checks symlinks out as plain files (core.symlinks=false), but
        // refuse a remote that commits them at all, and anything on disk.
        let links: Vec<String> = run_git(dir, &["ls-files", "--stage"])?
            .lines()
            .filter(|l| l.starts_with("120000 "))
            .filter_map(|l| l.split_once('\t').map(|(_, p)| p.to_string()))
            .collect();
        if !links.is_empty() {
            bail!(
                "the state repository {} contains symbolic links ({}); Pathwarden refuses to use it. \
                 Remove them from the repository.",
                redact_url(&g.remote),
                links.join(", ")
            );
        }
        self.check_no_links()?;
        if !self.dir.join(MARKER).exists() {
            fs::write(self.dir.join(MARKER), MARKER_TEXT)
                .with_context(|| format!("writing {}", self.dir.join(MARKER).display()))?;
        }
        // Seen encrypted: this computer keeps that, passphrase or not.
        if crypt::is_encrypted(&self.dir) {
            record_location_pin(&self.dir)?;
        }
        // What the remote holds now: sequences read from it are remembered.
        remember_remote_tree(&self.dir);
        // Plain files in an encrypted history: never read, and taken out of
        // the working copy so no commit stages them again.
        let planted = planted_files(&self.dir);
        if !planted.is_empty() {
            let who = last_change(&self.dir, &planted[0])
                .map(|c| format!(" (the latest: {c})"))
                .unwrap_or_default();
            for rel in &planted {
                if rel == "findings.json" {
                    write_atomic(&self.dir.join(rel), &crypt::stub())?;
                } else {
                    remove_if_there(&self.dir.join(rel))?;
                }
            }
            notes.push(format!(
                "The encrypted history held {} in plain text, which Pathwarden never writes \
                 into an encrypted history{who}: {}. {} left out, and the next commit removes {}.",
                crate::text::count(planted.len(), "file", "files"),
                planted.join(", "),
                if planted.len() == 1 {
                    "It is"
                } else {
                    "They are"
                },
                if planted.len() == 1 { "it" } else { "them" },
            ));
        }
        if kept.is_some() && !fast_forward {
            notes.extend(self.restore_points(&salvage)?);
        }
        // A key that isn't the pinned one: followed now when the passphrase
        // here opens it, and said once. One it doesn't open is the
        // error of the first read.
        if crypt::is_encrypted(&self.dir) {
            let pinned = pinned_key(&self.dir);
            if crypt::key_digest(&self.dir).is_ok_and(|d| pinned.is_some_and(|p| p != d)) {
                let _ = key(&self.dir);
            }
        }
        notes.extend(take_key_note(&self.dir));
        // What finding actions did here that no push carried yet: made
        // again on what the remote holds, for the next commit to carry.
        notes.extend(crate::action_log::replay_pending(self));
        Ok((!notes.is_empty()).then(|| notes.join(" ")))
    }

    /// Whether the working copy holds commits a failed push left, which the
    /// next recording pushes ([`KeptUnpushed`]).
    pub fn has_unpushed(&self) -> bool {
        self.git.as_ref().is_some_and(|g| {
            self.kept_unpushed(&format!("refs/heads/{}", g.branch), true)
                .is_some()
        })
    }

    /// Where the tip of the commits a failed push left is recorded (inside
    /// `.git`, never committed).
    fn kept_path(&self) -> PathBuf {
        self.dir.join(".git").join(KEPT_FILE)
    }

    /// The commit a failed push left ([`KeptUnpushed`]), when the branch
    /// still holds it.
    /// `cached`: for what pages show ([`Store::has_unpushed`]), answered by
    /// the branch's commit read from `.git` while neither moves; a pull or
    /// a publish, which act on it, always ask git.
    fn kept_unpushed(&self, local_branch: &str, cached: bool) -> Option<String> {
        let tip = fs::read_to_string(self.kept_path()).ok()?;
        let tip = tip.trim();
        let git = self.dir.join(".git");
        (tip.len() >= 40 && tip.bytes().all(|b| b.is_ascii_hexdigit()))
            .then_some(tip)
            .filter(|tip| {
                let key = cached
                    .then(|| ref_commit(&git, local_branch))
                    .flatten()
                    .map(|head| (self.dir.clone(), tip.to_string(), head));
                if let Some(k) = &key {
                    if let Some(held) = kept_cache().get(k) {
                        return *held;
                    }
                }
                let held = run_git(
                    Some(&self.dir),
                    &["merge-base", "--is-ancestor", tip, local_branch],
                )
                .is_ok();
                // Kept only if the branch didn't move while git looked.
                if let Some(k) =
                    key.filter(|k| ref_commit(&git, local_branch).as_ref() == Some(&k.2))
                {
                    let mut c = kept_cache();
                    if c.len() > 64 {
                        c.clear();
                    }
                    c.insert(k, held);
                }
                held
            })
            .map(str::to_string)
    }

    /// Records HEAD as commits a failed push left, for [`Store::pull`] to
    /// keep.
    fn mark_kept(&self) -> Result<()> {
        let head = run_git(Some(&self.dir), &["rev-parse", "HEAD"])?;
        fs::write(self.kept_path(), head.trim())
            .with_context(|| format!("writing {}", self.kept_path().display()))
    }

    fn clear_kept(&self) {
        let _ = fs::remove_file(self.kept_path());
    }

    /// What the kept commits up to `kept` changed that the remote lacks,
    /// read before the working copy is reset.
    fn kept_points(&self, remote: Option<&str>, kept: &str) -> Result<Salvage> {
        let dir = Some(self.dir.as_path());
        let changed = |filter: &str| -> Result<String> {
            match remote {
                Some(r) => run_git(
                    dir,
                    &[
                        "diff",
                        "--name-only",
                        "-z",
                        // A removed point and an added one that look alike
                        // are not a rename here.
                        "--no-renames",
                        filter,
                        &format!("{r}...{kept}"),
                        "--",
                    ]
                    .into_iter()
                    .chain(state_folders())
                    .collect::<Vec<_>>(),
                ),
                None if filter == "--diff-filter=A" => run_git(
                    dir,
                    &["ls-tree", "-r", "-z", "--name-only", kept, "--"]
                        .into_iter()
                        .chain(state_folders())
                        .collect::<Vec<_>>(),
                ),
                None => Ok(String::new()),
            }
        };
        let mut out = Salvage::default();
        for path in changed("--diff-filter=A")?
            .split('\0')
            .filter(|p| state_file(p))
        {
            let bytes = run_git_bytes(dir, &["show", &format!("{kept}:{path}")])?;
            out.files.push((path.to_string(), bytes));
        }
        // Only removals the remote undoes: not a run the other machine
        // removed too.
        out.removed = changed("--diff-filter=D")?
            .split('\0')
            .filter(|p| p.starts_with(&format!("{HISTORY_DIR}/")) && state_file(p))
            .filter(|p| {
                remote
                    .is_some_and(|r| run_git(dir, &["cat-file", "-e", &format!("{r}:{p}")]).is_ok())
            })
            .count();
        Ok(out)
    }

    /// Writes the points and timings of `salvage` ([`Store::kept_points`])
    /// back that the remote does not have, history points marked
    /// [`HistoryPoint::inserted`], and commits them for the next publish to
    /// push. Returns the notes for the user: one short sentence each.
    fn restore_points(&self, salvage: &Salvage) -> Result<Vec<String>> {
        let mut restored = 0;
        let mut written = 0;
        let mut bundles: Vec<String> = Vec::new();
        let mut unreadable = 0;
        for (path, bytes) in &salvage.files {
            // Written as the history is now (encrypted or not), whatever
            // form the kept commit had.
            let (rel, sealed) = match path.strip_suffix(crypt::SUFFIX) {
                Some(rel) => (rel, true),
                None => (path.as_str(), false),
            };
            if !is_state_rel(rel) || self.has_state_file(rel) {
                continue;
            }
            let plain = if sealed {
                // Encrypted with the key of a passphrase changed since:
                // can't be added back.
                // A file bound to another path is not this one; one from
                // before the binding is taken (this computer's own commit).
                match key(&self.dir)
                    .and_then(|k| crypt::open(&k, bytes, path))
                    .and_then(|p| match binding::parse(p) {
                        Ok(Parsed::Unbound(p)) => Ok(p),
                        Ok(Parsed::Bound(b, p))
                            if b.path == rel && b.run == binding::run_of(rel) =>
                        {
                            Ok(p)
                        }
                        _ => bail!("{path} is bound to another file"),
                    }) {
                    Ok(p) => p,
                    Err(_) => {
                        unreadable += 1;
                        continue;
                    }
                }
            } else {
                bytes.clone()
            };
            let plain = if rel.starts_with(&format!("{HISTORY_DIR}/")) {
                let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&plain) else {
                    continue;
                };
                v["inserted"] = serde_json::Value::Bool(true);
                restored += 1;
                let mut text = serde_json::to_string_pretty(&v)?;
                text.push('\n');
                text.into_bytes()
            } else {
                plain
            };
            self.check_no_links()?;
            // An upgrade's note comes again with the run that pushes.
            self.write_state_file(rel, &plain)?;
            written += 1;
            if let Some(id) = rel
                .strip_prefix(&format!("{BUNDLE_DIR}/"))
                .and_then(|r| r.split_once('/'))
                .map(|(id, _)| id.to_string())
            {
                if !bundles.contains(&id) {
                    bundles.push(id);
                }
            }
        }
        let mut notes = Vec::new();
        // Whatever was added back is committed and kept for the next push:
        // points, their timings and full runs alike. Left uncommitted, the
        // next pull's clean would remove it.
        if written > 0 {
            let message = if restored > 0 {
                format!("pathwarden: add {restored} earlier run(s) another run's push came before")
            } else {
                format!(
                    "pathwarden: add {} kept from an earlier push",
                    crate::text::count(bundles.len().max(1), "full run", "full runs")
                )
            };
            if self.commit(&message)? {
                self.mark_kept()?;
            }
        }
        if !bundles.is_empty() {
            notes.push(format!(
                "{} committed here {} kept and {} with the next push.",
                crate::text::count(bundles.len(), "full run", "full runs"),
                if bundles.len() == 1 { "was" } else { "were" },
                if bundles.len() == 1 { "goes" } else { "go" }
            ));
        }
        if restored > 0 {
            notes.push(format!(
                "{} recorded here but not pushed before another machine pushed {} added to the \
                 history as earlier points; the latest run and the findings state are the \
                 remote's.",
                crate::text::count(restored, "run", "runs"),
                if restored == 1 { "was" } else { "were" }
            ));
        }
        if unreadable > 0 {
            notes.push(format!(
                "{} recorded here but not pushed couldn't be added back: {} encrypted with the \
                 key of an earlier passphrase.",
                crate::text::count(unreadable, "file", "files"),
                if unreadable == 1 {
                    "it was"
                } else {
                    "they were"
                }
            ));
        }
        if salvage.removed > 0 {
            notes.push(format!(
                "{} made here {} not pushed before another machine pushed, and {} undone: \
                 remove the run again (`pathwarden history --forget`, or Delete).",
                crate::text::count(salvage.removed, "removal of a run", "removals of runs"),
                if salvage.removed == 1 { "was" } else { "were" },
                if salvage.removed == 1 { "is" } else { "are" }
            ));
        }
        if notes.is_empty() {
            notes.push(
                "Changes made here were not pushed before another machine pushed, and were \
                 dropped; the history is the remote's."
                    .to_string(),
            );
        }
        Ok(notes)
    }

    /// Refuses a remote branch that holds something other than Pathwarden
    /// state (a mistyped remote, someone's project): a run would otherwise
    /// commit its state on top of it and push.
    fn check_state_branch(&self, g: &Git, remote_branch: &str) -> Result<()> {
        let dir = Some(self.dir.as_path());
        let top = run_git(dir, &["ls-tree", "--name-only", remote_branch])?;
        // Checked out, it would replace (and a later reset remove) the run's
        // lock. Case is ignored: Windows' file names ignore it.
        if let Some(own) = top
            .lines()
            .find(|n| OWN_FILES.iter().any(|o| n.eq_ignore_ascii_case(o)))
        {
            bail!(
                "branch {} of {} holds {own}, the name of a file Pathwarden keeps for itself in \
                 the state folder; remove it from the repository.",
                g.branch,
                redact_url(&g.remote)
            );
        }
        // Every file, as "<mode> <type> <object>\t<path>".
        let listing = run_git(dir, &["ls-tree", "-r", "-z", remote_branch])?;
        // Before anything is checked out: attributes that would make git
        // run a filter or a diff or merge program.
        for (meta, path) in listing
            .split('\0')
            .filter_map(|l| l.split_once('\t'))
            .filter(|(meta, p)| {
                meta.split(' ').nth(1) == Some("blob")
                    && p.rsplit('/')
                        .next()
                        .is_some_and(|n| n.eq_ignore_ascii_case(".gitattributes"))
            })
        {
            let object = meta.split(' ').nth(2).unwrap_or_default();
            let text = String::from_utf8_lossy(&small_blob(
                dir.context("no history folder")?,
                object,
                MAX_SMALL_FILE,
            )?)
            .into_owned();
            if let Some(bad) = unsafe_attribute(&text) {
                bail!(
                    "branch {} of {} has a {path} that sets \"{bad}\"; a history's \
                     .gitattributes may only set text, eol and binary, so nothing was checked \
                     out. Remove it from the repository.",
                    g.branch,
                    redact_url(&g.remote)
                );
            }
        }
        if top.lines().any(|n| n == MARKER) {
            return Ok(());
        }
        let foreign: Vec<&str> = listing
            .split('\0')
            .filter(|l| !l.is_empty())
            .filter_map(|l| l.split_once('\t'))
            // Symbolic links are refused below, with their own message.
            .filter(|(meta, _)| !meta.starts_with("120000 "))
            .filter(|(meta, path)| !(meta.split(' ').nth(1) == Some("blob") && state_file(path)))
            .map(|(_, path)| path)
            .collect();
        if foreign.is_empty() {
            return Ok(());
        }
        let mut shown = foreign[..foreign.len().min(5)].join(", ");
        if foreign.len() > 5 {
            shown.push_str(", ...");
        }
        bail!(
            "branch {} of {} is not Pathwarden state (it holds {shown}); Pathwarden will not \
             commit its state on top of it. Use a repository (or a branch) of its own for the state.",
            g.branch,
            redact_url(&g.remote)
        )
    }

    /// Refuses a state folder in which any state path is a symbolic link or
    /// junction: someone who can push to the state repository could otherwise
    /// point `history` (or a state file) elsewhere and redirect the run's
    /// writes. The state folder itself may be a link the operator set up.
    fn check_no_links(&self) -> Result<()> {
        let mut paths: Vec<PathBuf> = [MARKER, crypt::MARKER, crypt::KEY_FILE]
            .iter()
            .map(|n| self.dir.join(n))
            .collect();
        for f in single_files() {
            paths.push(self.dir.join(f));
            paths.push(self.dir.join(format!("{f}{}", crypt::SUFFIX)));
            // The folder a file is in (A3's settings/).
            if let Some((folder, _)) = f.split_once('/') {
                paths.push(self.dir.join(folder));
            }
        }
        for folder in run_folders().chain(bundle_folders()) {
            paths.push(self.dir.join(folder));
        }
        // Each full run's folder, and what is in it.
        for folder in bundle_folders() {
            let folder = self.dir.join(folder);
            if folder.is_dir() && !is_link(&folder) {
                for run in fs::read_dir(&folder)
                    .with_context(|| format!("reading {}", folder.display()))?
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                {
                    if run.is_dir() && !is_link(&run) {
                        paths.extend(
                            fs::read_dir(&run)
                                .with_context(|| format!("reading {}", run.display()))?
                                .filter_map(|e| e.ok())
                                .map(|e| e.path()),
                        );
                    }
                    paths.push(run);
                }
            }
        }
        for folder in run_folders() {
            let folder = self.dir.join(folder);
            if folder.is_dir() && !is_link(&folder) {
                paths.extend(
                    fs::read_dir(&folder)
                        .with_context(|| format!("reading {}", folder.display()))?
                        .filter_map(|e| e.ok())
                        .map(|e| e.path()),
                );
            }
        }
        if let Some(link) = paths.iter().find(|p| is_link(p)) {
            bail!(
                "{} is a symbolic link or junction; Pathwarden does not write state through links. \
                 Remove it (and from the state repository, if it came from there).",
                link.display()
            );
        }
        Ok(())
    }

    /// The first clone. It is made in a folder inside the state folder
    /// ([`CLONING_DIR`]) and its `.git` moved into place only when complete:
    /// a clone stopped halfway (the idle limit, Ctrl+C, a crash, a power cut)
    /// never leaves a working copy that looks like Pathwarden's but can't
    /// fetch the state's branch. The state folder itself is never removed or
    /// replaced: it may be a link, or carry permissions, the operator set up
    /// (a scheduled task's account may write only there, not beside it).
    fn clone_into_place(&self, g: &Git) -> Result<()> {
        let made = missing_dirs(&self.dir);
        fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        // Folders this run made (the state folder, and parents it lacked)
        // are removed again when the clone fails, while empty.
        let discard = |temp: &Path| {
            let _ = remove_tree(temp);
            remove_made_dirs(&made);
        };
        let temp = self.dir.join(CLONING_DIR);
        let target = temp.to_string_lossy().into_owned();
        let cloned = run_git(
            None,
            &[
                "clone",
                "--progress",
                // Nothing on disk until the branch is known to hold state:
                // the clone is its `.git` alone.
                "--no-checkout",
                "--config",
                "core.symlinks=false",
                "--config",
                // Git for Windows converts line endings by default; the
                // state files (and the encrypted ones) are kept byte for byte.
                "core.autocrlf=false",
                "--config",
                OWNED_CONFIG,
                "--",
                &g.remote,
                &target,
            ],
        );
        if let Err(e) = cloned {
            discard(&temp);
            return Err(e);
        }
        // A virus scanner may still hold a file of the new clone briefly.
        let mut tries = 0;
        loop {
            match fs::rename(temp.join(".git"), self.dir.join(".git")) {
                Ok(()) => break,
                Err(_) if tries < 10 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => {
                    discard(&temp);
                    return Err(e).with_context(|| {
                        format!(
                            "moving the new clone into {}; the clone was discarded, and the next run clones again",
                            self.dir.display()
                        )
                    });
                }
            }
        }
        // Empty now; one left behind holds nothing and git doesn't list it.
        let _ = fs::remove_dir(&temp);
        Ok(())
    }

    /// Lists [`OWN_FILES`] in the working copy's `.git/info/exclude`, so
    /// `git status` never reports the run's lock. (Git never removes it
    /// either way: the resets touch tracked files only, and the clean is
    /// limited to the history's folders.)
    fn exclude_own_files(&self) -> Result<()> {
        let info = self.dir.join(".git").join("info");
        let file = info.join("exclude");
        let text = fs::read_to_string(&file).unwrap_or_default();
        let missing: String = OWN_FILES
            .iter()
            .map(|f| format!("/{f}"))
            // Git skips a UTF-8 byte order mark at the start, too.
            .filter(|l| {
                !text
                    .strip_prefix('\u{feff}')
                    .unwrap_or(&text)
                    .lines()
                    .any(|t| git_pattern(t) == l)
            })
            .map(|l| l + "\n")
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        fs::create_dir_all(&info).with_context(|| format!("creating {}", info.display()))?;
        let sep = if text.is_empty() || text.ends_with('\n') {
            ""
        } else {
            "\n"
        };
        fs::write(&file, format!("{text}{sep}{missing}"))
            .with_context(|| format!("writing {}", file.display()))
    }

    /// Fetches origin's branches. The refspec is given, not taken from the
    /// working copy's config: one a stopped clone of an older version left
    /// without it would fetch only origin's HEAD, never `origin/<branch>`.
    /// The config is mended too.
    fn fetch(&self) -> Result<()> {
        const REFSPEC: &str = "+refs/heads/*:refs/remotes/origin/*";
        let dir = Some(self.dir.as_path());
        // `git config --get` exits with 1 when the key is missing; any other
        // failure (a config git can't read) is left to the fetch to report.
        let missing = match run_git(
            dir,
            &["config", "--local", "--get-all", "remote.origin.fetch"],
        ) {
            Ok(v) => v.trim().is_empty(),
            Err(e) => e
                .downcast_ref::<GitFailed>()
                .is_some_and(|f| f.code == Some(1)),
        };
        if missing {
            run_git(dir, &["config", "--local", "remote.origin.fetch", REFSPEC])?;
        }
        run_git(dir, &["fetch", "--progress", "--prune", "origin", REFSPEC])?;
        Ok(())
    }

    /// Refuses to touch a git working copy that Pathwarden did not create for
    /// this remote: it would otherwise reset someone's project repository.
    /// Whether the working copy is one Pathwarden cloned and marked, for
    /// the configured remote: [`Store::verify_owned`]'s checks without
    /// taking an older copy over (nothing is written).
    fn owned_already(&self, g: &Git) -> bool {
        let dir = Some(self.dir.as_path());
        let origin = run_git(dir, &["remote", "get-url", "origin"]).unwrap_or_default();
        let (key, _) = OWNED_CONFIG.split_once('=').unwrap_or_default();
        same_remote(origin.trim(), &g.remote)
            && run_git(dir, &["config", "--local", "--get", key]).is_ok_and(|v| v.trim() == "true")
    }

    fn verify_owned(&self, g: &Git) -> Result<()> {
        let dir = Some(self.dir.as_path());
        let origin = run_git(dir, &["remote", "get-url", "origin"]).unwrap_or_default();
        if !same_remote(origin.trim(), &g.remote) {
            bail!(
                "{} is a git working copy whose origin ({}) is not the configured state remote ({}); \
                 Pathwarden only works in a working copy it cloned itself. Point [state] path at an empty \
                 or new folder.",
                self.dir.display(),
                redact_url(origin.trim()),
                redact_url(&g.remote)
            );
        }
        let (key, _) = OWNED_CONFIG.split_once('=').unwrap_or_default();
        let owned =
            run_git(dir, &["config", "--local", "--get", key]).is_ok_and(|v| v.trim() == "true");
        if owned {
            return Ok(());
        }
        // Working copies cloned before Pathwarden marked them (0.1.6 and
        // earlier): taken over once, if they are on the state's branch and
        // hold nothing but state files. A clone made by hand on another
        // branch, or with other files in it, is left alone.
        let branch =
            run_git(dir, &["symbolic-ref", "--quiet", "--short", "HEAD"]).unwrap_or_default();
        let foreign: Vec<String> = fs::read_dir(&self.dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !state_entry(n) && !state_file(n) && !is_temp(n))
            .collect();
        if branch.trim() != g.branch || !foreign.is_empty() {
            bail!(
                "{} is a git working copy Pathwarden did not clone (it is on branch {}{}); \
                 Pathwarden will not reset it. Point [state] path at an empty or new folder, or, \
                 if Pathwarden did make it, run `git -C \"{}\" config {key} true`.",
                self.dir.display(),
                branch.trim(),
                if foreign.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", and holds files that are not Pathwarden state: {}",
                        foreign.join(", ")
                    )
                },
                self.dir.display()
            );
        }
        run_git(dir, &["config", "--local", key, "true"])?;
        Ok(())
    }

    /// Reads `rel` ("findings.json", "last-run.json", "history/<run>.json",
    /// "timings/<run>.json") from the history: decrypted when the history
    /// is encrypted, which needs its passphrase ([`crypt::key_for`]).
    /// `None` when it isn't there. Every read of a file inside the history
    /// goes through here (or [`read_state_file`], for a folder known only
    /// by its path).
    pub fn read_state_file(&self, rel: &str) -> Result<Option<Vec<u8>>> {
        read_state_file(&self.dir, rel)
    }

    /// Writes `rel` into the history atomically (a temporary file renamed
    /// over it): encrypted when the history is encrypted. Every write of a
    /// file inside the history goes through here. Returns notes for the
    /// user ([`write_state_file`]).
    pub fn write_state_file(&self, rel: &str, bytes: &[u8]) -> Result<Vec<String>> {
        self.check_expected()?;
        write_state_file(&self.dir, rel, bytes)
    }

    /// Refuses a plain history where pathwarden.toml says it is encrypted
    /// (`[state] encrypted`): whatever the repository holds now (a rewrite
    /// of its branch, a fresh clone of one), this computer was told.
    pub fn check_expected(&self) -> Result<()> {
        if self.expect_encrypted && !crypt::is_encrypted(&self.dir) {
            bail!(
                "{} says the history in {} is encrypted ([state] encrypted = true), but it \
                 isn't{}; Pathwarden refuses to use it in plain text. If encryption was turned \
                 off on purpose, run `pathwarden history storage set --no-encrypt --yes` here. If \
                 nobody turned it off, restore the repository's branch (revert the change, or \
                 push the encrypted commits back), or run `pathwarden history storage set \
                 --encrypt --yes` (it encrypts the history again).",
                self.config_file
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "pathwarden.toml".into()),
                self.dir.display(),
                last_change(&self.dir, crypt::MARKER)
                    .map(|c| format!(" ({c} touched its marker last)"))
                    .unwrap_or_default()
            );
        }
        Ok(())
    }

    /// Whether pathwarden.toml says the history here is encrypted.
    pub fn expects_encrypted(&self) -> bool {
        self.expect_encrypted
    }

    /// Whether the history here is encrypted now.
    pub fn is_encrypted(&self) -> bool {
        crypt::is_encrypted(&self.dir)
    }

    /// A file of this machine's own in the working copy's `.git` (never
    /// committed): what [`crate::settings_sync`] keeps between syncs. It
    /// stays outside encryption: the settings base file holds the shared
    /// sections' values in plain text, on this computer only. `None` when
    /// there is none, and for a folder.
    pub fn read_local_file(&self, name: &str) -> Option<Vec<u8>> {
        self.git.as_ref()?;
        if name.contains(['/', '\\']) || name.starts_with('.') {
            return None;
        }
        fs::read(self.dir.join(".git").join(name)).ok()
    }

    /// Where decrypting moves a plain actions.json it leaves out: in the
    /// working copy's `.git` (never committed), or beside a folder history.
    fn leftover_target(&self) -> PathBuf {
        let stamp = crate::action_log::name_stamp();
        if self.is_git() {
            crate::action_log::unique_path(
                &self.dir.join(".git"),
                &format!("pathwarden-{}{stamp}", crate::action_log::LEFTOVER_PREFIX),
            )
        } else {
            crate::action_log::unique_path(
                &self.dir,
                &format!("{}{stamp}", crate::action_log::LEFTOVER_PREFIX),
            )
        }
    }

    /// The plain actions.json files decrypting moved aside
    /// ([`Store::leftover_target`]).
    pub fn leftovers(&self) -> Vec<PathBuf> {
        let (dir, start) = if self.is_git() {
            (
                self.dir.join(".git"),
                format!("pathwarden-{}", crate::action_log::LEFTOVER_PREFIX),
            )
        } else {
            (
                self.dir.clone(),
                crate::action_log::LEFTOVER_PREFIX.to_string(),
            )
        };
        let mut out: Vec<PathBuf> = fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(&start))
            .map(|e| e.path())
            .collect();
        out.sort();
        out
    }

    /// Removes [`Store::read_local_file`]'s file; whether it was there.
    /// Nothing for a folder.
    pub fn remove_local_file(&self, name: &str) -> Result<bool> {
        if self.git.is_none() || name.contains(['/', '\\']) || name.starts_with('.') {
            return Ok(false);
        }
        remove_if_there(&self.dir.join(".git").join(name))
    }

    /// Writes [`Store::read_local_file`]'s file (atomically). Nothing for a
    /// folder.
    pub fn write_local_file(&self, name: &str, bytes: &[u8]) -> Result<()> {
        if self.git.is_none() {
            return Ok(());
        }
        if name.contains(['/', '\\']) || name.starts_with('.') {
            bail!("{name:?} is not a file name");
        }
        let git = self.dir.join(".git");
        let tmp = git.join(format!("{name}.{}.tmp", std::process::id()));
        fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, git.join(name)).with_context(|| {
            let _ = fs::remove_file(&tmp);
            format!("writing {}", git.join(name).display())
        })
    }

    /// The record of the last pull of a git history ([`LAST_PULL_FILE`]):
    /// `None` for a folder, or before any pull.
    pub fn read_last_pull(&self) -> Option<Vec<u8>> {
        self.git.as_ref()?;
        fs::read(self.dir.join(LAST_PULL_FILE)).ok()
    }

    /// Writes the record of the last pull of a git history, making the
    /// state folder when a first clone failed before it was there. Nothing
    /// for a folder history.
    pub fn write_last_pull(&self, bytes: &[u8]) -> Result<()> {
        if self.git.is_none() {
            return Ok(());
        }
        fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        write_atomic(&self.dir.join(LAST_PULL_FILE), bytes)
    }

    /// The last commit that changed the shared settings ([`SETTINGS_FILE`],
    /// plain or encrypted) in the working copy's branch: its git author and
    /// time, and its message (whose trailers name who made the change in
    /// Pathwarden, unless the history is encrypted).
    pub fn last_settings_commit(&self) -> Option<SettingsCommit> {
        self.git.as_ref()?;
        let sealed = format!("{SETTINGS_FILE}{}", crypt::SUFFIX);
        let out = run_git(
            Some(&self.dir),
            &[
                "log",
                "-1",
                "--full-history",
                "--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%B",
                "HEAD",
                "--",
                SETTINGS_FILE,
                &sealed,
            ],
        )
        .ok()?;
        let mut parts = out.splitn(5, '\u{1f}');
        let commit = parts.next()?.trim().to_string();
        if commit.is_empty() {
            return None;
        }
        Some(SettingsCommit {
            commit,
            author: parts.next()?.to_string(),
            email: parts.next()?.to_string(),
            at: parts.next()?.to_string(),
            message: parts.next()?.trim().to_string(),
        })
    }

    /// This account's sticky record that the history here was seen
    /// encrypted, when there is one: where it is.
    pub fn location_record(&self) -> Option<PathBuf> {
        location_pinned(&self.dir)
    }

    /// Removes `rel` from the history; whether it was there.
    pub fn remove_state_file(&self, rel: &str) -> Result<bool> {
        remove_state_file(&self.dir, rel)
    }

    /// Whether the history holds `rel`, without reading it.
    pub fn has_state_file(&self, rel: &str) -> bool {
        has_state_file(&self.dir, rel)
    }

    /// The history's files in `folder` ("history", "timings"), by name.
    pub fn list_state_files(&self, folder: &str) -> Result<Vec<String>> {
        list_state_files(&self.dir, folder)
    }

    /// [`Store::write_state_file`] of `value` as JSON.
    fn write_state_json<T: Serialize>(&self, rel: &str, value: &T) -> Result<Vec<String>> {
        // A run's point carries the status keys' 1.0 names beside the old
        // ones (crate::status_keys).
        let mut text = if rel.starts_with(&format!("{HISTORY_DIR}/")) {
            serde_json::to_string_pretty(&crate::status_keys::to_value(value)?)?
        } else {
            serde_json::to_string_pretty(value)?
        };
        text.push('\n');
        self.write_state_file(rel, text.as_bytes())
    }

    pub fn load(&self) -> Result<FindingsState> {
        self.check_expected()?;
        let path = self.dir.join("findings.json");
        let bytes = match self.read_state_file("findings.json") {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(FindingsState::default()),
            Err(e) => {
                let t = e.downcast::<TooLarge>()?;
                return Err(DamagedFindings(t.to_string()).into());
            }
        };
        let state: FindingsState = serde_json::from_slice(&bytes)
            .map_err(|e| DamagedFindings(format!("{} can't be read: {e}", path.display())))?;
        if state.version == crypt::STUB_VERSION && !crypt::is_encrypted(&self.dir) {
            bail!(
                "{} says the history is encrypted, but its marker {} is missing; restore it from \
                 the repository or a backup",
                path.display(),
                crypt::MARKER
            );
        }
        if !crate::formats::of_u32(state.version, STATE_VERSION).is_known() {
            bail!(
                "{} was saved by a newer Pathwarden (state version {}). Update Pathwarden to use \
                 this history.",
                path.display(),
                state.version
            );
        }
        Ok(state)
    }

    /// [`Store::load`] for a run about to be recorded: a `findings.json`
    /// that can't be read as one (cut short, not JSON, too large; any
    /// writer can push one) doesn't stop every run until someone repairs
    /// it. The run is compared with no earlier findings instead, and the
    /// second value says so. Every other failure (a newer version, a
    /// refused binding, a missing passphrase) is still an error.
    pub fn load_for_run(&self) -> Result<(FindingsState, Option<String>)> {
        match self.load() {
            Ok(s) => Ok((s, None)),
            Err(e) => match e.downcast::<DamagedFindings>() {
                Ok(d) => Ok((
                    FindingsState::default(),
                    Some(format!(
                        "{}. This run was compared with no earlier findings, so all of its \
                         findings count as new.{}",
                        d.0,
                        if self.is_git() {
                            " The damaged file stays in the repository's earlier commits."
                        } else {
                            ""
                        }
                    )),
                )),
                Err(e) => Err(e),
            },
        }
    }

    /// Writes a run: the findings state, `last-run.json` and its history
    /// point. Returns notes for the user, each once
    /// ([`write_state_file`]).
    pub fn save(
        &self,
        state: &FindingsState,
        last: &LastRun,
        point: &HistoryPoint,
    ) -> Result<Vec<String>> {
        self.check_no_links()?;
        for folder in run_folders() {
            let folder = self.dir.join(folder);
            fs::create_dir_all(&folder)
                .with_context(|| format!("creating {}", folder.display()))?;
            let (root, inside) = (fs::canonicalize(&self.dir)?, fs::canonicalize(&folder)?);
            if !inside.starts_with(&root) {
                bail!(
                    "{} resolves outside the state folder ({}); refusing to write there",
                    folder.display(),
                    inside.display()
                );
            }
        }
        if !is_run_id(&last.run_id) {
            bail!("'{}' is not a run ID from the history", last.run_id);
        }
        // Checked before anything is written: an encrypted history needs
        // its passphrase for every file.
        check_readable(&self.dir)?;
        let mut notes = self.write_state_json("findings.json", state)?;
        // A newer Pathwarden's last run is never written over
        // (docs/dev/formats.md): this run's point says what it found.
        if self.last_run_is_newer() {
            notes.push(
                "last-run.json was saved by a newer Pathwarden, so it is left as it is. Update \
                 Pathwarden to record the last run there."
                    .into(),
            );
        } else {
            notes.extend(self.write_state_json("last-run.json", last)?);
        }
        notes.extend(self.write_state_json(&format!("{HISTORY_DIR}/{}.json", last.run_id), point)?);
        Ok(once_each(notes))
    }

    /// Whether the exposed accounts file `rel` is of a version this one
    /// doesn't know (one that can't be read at all is not: it goes).
    fn exposed_is_newer(&self, rel: &str) -> bool {
        #[derive(serde::Deserialize)]
        struct Head {
            #[serde(default)]
            version: serde_json::Value,
        }
        matches!(self.read_state_file(rel), Ok(Some(b))
        if serde_json::from_slice::<Head>(&b).is_ok_and(|h| {
            let v = serde_json::json!({ "version": h.version });
            !crate::formats::of_json(&v, "version", crate::exposed::VERSION).is_known()
        }))
    }

    /// Whether `last-run.json` is of a version this one doesn't know.
    fn last_run_is_newer(&self) -> bool {
        matches!(self.read_state_file("last-run.json"), Ok(Some(b))
        if serde_json::from_slice::<serde_json::Value>(&b).is_ok_and(|v| {
            !crate::formats::of_json(&v, "version", STATE_VERSION).is_known()
        }))
    }

    /// Writes only a run's history point (`history/<run>.json`), leaving
    /// the findings state and `last-run.json` as they are: for a run older
    /// than the newest one recorded. Returns notes for the user
    /// ([`write_state_file`]).
    pub fn save_point(&self, point: &HistoryPoint) -> Result<Vec<String>> {
        self.check_no_links()?;
        if !is_run_id(&point.run_id) {
            bail!("'{}' is not a run ID from the history", point.run_id);
        }
        self.write_state_json(&format!("{HISTORY_DIR}/{}.json", point.run_id), point)
    }

    /// Keeps run `run_id`'s collection timings ([`TIMINGS_DIR`]), after
    /// [`Store::save`] and before [`Store::publish_with`]. Returns notes for
    /// the user ([`write_state_file`]).
    pub fn save_timings(
        &self,
        run_id: &str,
        timings: &crate::diagnostics::CollectionTimings,
    ) -> Result<Vec<String>> {
        self.check_no_links()?;
        if !is_run_id(run_id) {
            bail!("'{run_id}' is not a run ID from the history");
        }
        self.write_state_json(&format!("{TIMINGS_DIR}/{run_id}.json"), timings)
    }

    /// Keeps a run's exposed accounts as name-free keys
    /// (`exposed/<run>.json`, [`crate::exposed`]), after its point.
    /// Returns what the write has to say, as [`Store::save`] does.
    pub fn save_exposed(&self, record: &crate::exposed::ExposedRecord) -> Result<Vec<String>> {
        self.check_no_links()?;
        if !is_run_id(&record.run_id) {
            bail!("'{}' is not a run ID from the history", record.run_id);
        }
        let folder = self.dir.join(crate::exposed::DIR);
        fs::create_dir_all(&folder).with_context(|| format!("creating {}", folder.display()))?;
        let (root, inside) = (fs::canonicalize(&self.dir)?, fs::canonicalize(&folder)?);
        if !inside.starts_with(&root) {
            bail!(
                "{} resolves outside the state folder ({}); refusing to write there",
                folder.display(),
                inside.display()
            );
        }
        self.write_state_file(
            &format!("{}/{}.json", crate::exposed::DIR, record.run_id),
            &record.to_bytes(),
        )
    }

    /// Removes the exposed accounts the history no longer needs: it keeps
    /// those of each environment's latest [`crate::exposed::KEPT`] runs and
    /// of its latest run of each kind (what it targeted, on which exposure
    /// basis) with the run each compares with, so the next run of any kind
    /// finds its previous run's. Files of runs the history has no point
    /// for go too; those of points it has but can't read stay. Returns how
    /// many files were removed.
    pub fn prune_exposed(&self) -> Result<usize> {
        let files = self.list_state_files(crate::exposed::DIR)?;
        if files.is_empty() {
            return Ok(0);
        }
        let (mut points, _) = crate::history::load(&self.dir).map_err(anyhow::Error::msg)?;
        crate::state::migrate_points(&mut points);
        let keep = crate::exposed::kept_runs(&points);
        let read: std::collections::HashSet<&str> =
            points.iter().map(|p| p.run_id.as_str()).collect();
        let mut removed = 0;
        for rel in files {
            let id = rel
                .strip_prefix(&format!("{}/", crate::exposed::DIR))
                .and_then(|r| r.strip_suffix(".json"))
                .unwrap_or_default();
            // Its point is gone: an orphan. A point the history has but
            // that wasn't read (refused by its binding, damaged, of a
            // newer shape) keeps its keys: what it is can't be told.
            let orphan = !self.has_state_file(&format!("{HISTORY_DIR}/{id}.json"));
            let dropped = read.contains(id) && !keep.contains(id);
            // A newer Pathwarden's file is left to it (docs/dev/formats.md).
            if (orphan || dropped)
                && !self.exposed_is_newer(&rel)
                && self.remove_state_file(&rel)?
            {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Removes run `run_id`'s point from the history (`history/<run>.json`),
    /// so trends, Progress and `pathwarden history` stop showing it. The
    /// findings state (first seen, resolved) keeps what that run taught it,
    /// and `last-run.json` is left alone. Returns whether there was a point.
    /// Hold the [`Lock`] (and [`Store::pull`] first when the history is in
    /// git); [`Store::publish_with`] afterwards, or use [`Store::forget_and_publish`].
    pub fn forget(&self, run_id: &str) -> Result<bool> {
        self.check_no_links()?;
        // A history run ID only: "20261018T170000.000Z" and the like, never
        // a path.
        if !is_run_id(run_id) {
            bail!("'{run_id}' is not a run ID from the history");
        }
        // Its timings, its exposed accounts and its full run go with it.
        self.remove_state_file(&format!("{TIMINGS_DIR}/{run_id}.json"))?;
        self.remove_state_file(&format!("{}/{run_id}.json", crate::exposed::DIR))?;
        self.remove_bundle(run_id)?;
        self.remove_state_file(&format!("{HISTORY_DIR}/{run_id}.json"))
    }

    /// Writes file `name` ([`BUNDLE_FILES`]) of full run `run_id` into the
    /// history (`runs/<run>/<name>`), through the seam: encrypted when the
    /// history is. Refuses a state folder with links in it, and a `runs`
    /// folder that resolves outside it.
    pub fn write_bundle_file(&self, run_id: &str, name: &str, bytes: &[u8]) -> Result<()> {
        if !is_run_id(run_id) {
            bail!("'{run_id}' is not a run ID from the history");
        }
        let rel = bundle_rel(run_id, name);
        check_rel(&rel)?;
        self.check_no_links()?;
        let folder = self.dir.join(BUNDLE_DIR).join(run_id);
        fs::create_dir_all(&folder).with_context(|| format!("creating {}", folder.display()))?;
        let (root, inside) = (fs::canonicalize(&self.dir)?, fs::canonicalize(&folder)?);
        if !inside.starts_with(&root) {
            bail!(
                "{} resolves outside the state folder ({}); refusing to write there",
                folder.display(),
                inside.display()
            );
        }
        // An upgrade's note comes with the run (it tries again there).
        self.write_state_file(&rel, bytes).map(drop)
    }

    /// Reads file `name` of full run `run_id` from the history, decrypted
    /// when it is encrypted; `None` when it isn't there.
    pub fn read_bundle_file(&self, run_id: &str, name: &str) -> Result<Option<Vec<u8>>> {
        if !is_run_id(run_id) {
            bail!("'{run_id}' is not a run ID from the history");
        }
        self.read_state_file(&bundle_rel(run_id, name))
    }

    /// The size on disk of file `name` of full run `run_id` (encrypted, as
    /// stored, when the history is), without reading it; `None` when it
    /// isn't there. Compare it with [`max_on_disk`] of the size expected
    /// before reading the file.
    pub fn bundle_file_len(&self, run_id: &str, name: &str) -> Result<Option<u64>> {
        if !is_run_id(run_id) {
            bail!("'{run_id}' is not a run ID from the history");
        }
        let rel = bundle_rel(run_id, name);
        check_rel(&rel)?;
        let path = on_disk(&self.dir, &rel, mode(&self.dir, false)?);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => bail!(
                "{} is a symbolic link; Pathwarden does not read state through links",
                path.display()
            ),
            Ok(m) => Ok(Some(m.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Removes full run `run_id` from the history (`runs/<run>/`): the
    /// files of [`BUNDLE_FILES`], in either form, and its folder when that
    /// leaves it empty. Anything else in it is left alone. Returns how many
    /// files were removed.
    pub fn remove_bundle(&self, run_id: &str) -> Result<usize> {
        if !is_run_id(run_id) {
            bail!("'{run_id}' is not a run ID from the history");
        }
        let folder = self.dir.join(BUNDLE_DIR).join(run_id);
        if is_link(&folder) || is_link(&self.dir.join(BUNDLE_DIR)) {
            bail!(
                "{} is a symbolic link or junction; Pathwarden does not write state through links.",
                folder.display()
            );
        }
        let mut n = 0;
        for name in BUNDLE_FILES {
            if self.remove_state_file(&bundle_rel(run_id, name))? {
                n += 1;
            }
        }
        let _ = fs::remove_dir(&folder);
        Ok(n)
    }

    /// The full runs the history holds, by run ID, oldest first
    /// ([`list_bundles`]).
    pub fn bundles(&self) -> Vec<String> {
        list_bundles(&self.dir)
    }

    /// Removes run `run_id`'s point ([`Store::forget`]) and, when `push`
    /// and the history is in git, commits and pushes; if another run pushed
    /// first, removes it again from what that run left. Hold the [`Lock`]
    /// and [`Store::pull`] first. Returns whether there was a point, and
    /// notes for the user; a push that failed but left the removal
    /// committed ([`KeptUnpushed`]) is one of them, not an error.
    pub fn forget_and_publish(&self, run_id: &str, push: bool) -> Result<(bool, Vec<String>)> {
        let removed = self.forget(run_id)?;
        let mut notes = Vec::new();
        if removed && push && self.is_git() {
            let message = format!("pathwarden: remove run {run_id} from the history");
            match self.publish_with(&message, || {
                Ok(self.forget(run_id)?.then(|| message.clone()))
            }) {
                Ok(p) => notes = p.notes,
                Err(e) => {
                    let kept = e.downcast::<KeptUnpushed>()?;
                    notes = kept.notes.clone();
                    notes.push(kept.sentence("The run was removed from the history"));
                }
            }
        }
        Ok((removed, notes))
    }

    /// Whether the history is encrypted: its marker, `None` when not.
    pub fn encryption(&self) -> Result<Option<crypt::Marker>> {
        crypt::marker(&self.dir)
    }

    /// Every file of the history, by its seam name.
    fn state_files(&self) -> Result<Vec<String>> {
        state_files_in(&self.dir, crypt::is_encrypted(&self.dir))
    }

    /// Writes every file of the history again: encrypted to a new key
    /// opened by `to`, or plain (`None`). Files are first written beside
    /// their place, then moved into it, and the marker is written (or
    /// removed) last, so a reader in between finds every file in the form
    /// the marker says. Only the folder: the caller
    /// commits. Returns how many files.
    fn rewrite(&self, to: Option<&SecretString>) -> Result<usize> {
        self.check_no_links()?;
        let was = crypt::is_encrypted(&self.dir);
        // This computer's record of sequences under the key going away.
        let old_record = if was && to.is_none() {
            key(&self.dir).ok().and_then(|k| seq_record(&self.dir, &k))
        } else {
            None
        };
        // Decrypting: a plain actions.json beside the encrypted history was
        // never read (anyone who can push could have put it there), so it
        // must not become the plain history's log: moved aside.
        if was && to.is_none() {
            let plain = self.dir.join(crate::action_log::FILE);
            if fs::symlink_metadata(&plain).is_ok_and(|m| m.is_file()) {
                let aside = self.leftover_target();
                fs::rename(&plain, &aside)
                    .with_context(|| format!("moving {} aside", plain.display()))?;
            }
        }
        // The key the saves waiting for a push are sealed with now, kept
        // in memory to write them again in the new form at the end.
        let old_key = if was && self.is_git() {
            crypt::key_for(&self.dir).ok()
        } else {
            None
        };
        let files = self.state_files()?;
        let key = to.map(crypt::new_key).transpose()?;
        let mut staged: Vec<(PathBuf, PathBuf)> = Vec::new();
        let stage = |staged: &mut Vec<(PathBuf, PathBuf)>, target: PathBuf, bytes: &[u8]| {
            let tmp = target.with_file_name(format!(
                ".{}.{}.rekey.tmp",
                target
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                std::process::id()
            ));
            staged.push((tmp.clone(), target));
            write_atomic(&tmp, bytes)
        };
        // What finding actions did, when it can't be read (an older release
        // changed the storage and left it): kept as it is, not rewritten.
        let mut kept: Vec<String> = Vec::new();
        let result = (|| -> Result<()> {
            for rel in &files {
                let plain = match read_as(&self.dir, rel, was) {
                    Err(_) if rel == crate::action_log::FILE => {
                        kept.push(rel.clone());
                        continue;
                    }
                    read => read?,
                }
                .with_context(|| format!("{rel} disappeared while it was being rewritten"))?;
                match &key {
                    // A new key: this computer's record of sequences
                    // starts again with it ([`binding::record_for`]).
                    Some((id, _)) => stage(
                        &mut staged,
                        on_disk(&self.dir, rel, true),
                        &seal_bound(id, rel, 1, &plain)?,
                    )?,
                    None => stage(&mut staged, self.dir.join(rel), &plain)?,
                }
            }
            if let Some((_, key_file)) = &key {
                stage(&mut staged, self.dir.join(crypt::KEY_FILE), key_file)?;
            }
            Ok(())
        })();
        #[cfg(test)]
        tests::during_rewrite();
        // The saves waiting for a push: their lock is taken only now, for
        // the short end of the rewrite (one held through a long rewrite
        // would look left from a crash and be taken over), and they are
        // written again in the new form at the end, as they are then.
        let pending_lock = match result {
            Ok(()) if self.is_git() => crate::action_log::lock_pending(self).map(Some),
            Ok(()) => Ok(None),
            Err(e) => Err(e),
        };
        let _pending_lock = match pending_lock {
            Ok(l) => l,
            Err(e) => {
                for (tmp, _) in &staged {
                    let _ = fs::remove_file(tmp);
                }
                return Err(e);
            }
        };
        for (tmp, target) in &staged {
            fs::rename(tmp, target).with_context(|| format!("replacing {}", target.display()))?;
        }
        // The new key is in place: the saves waiting for a push follow it
        // at once, so nothing that fails after this leaves them sealed with
        // a key that is gone.
        if self.is_git() {
            crate::action_log::reseal_pending(
                self,
                old_key.as_deref(),
                key.as_ref().map(|(id, _)| &**id),
            )?;
        }
        if key.is_none() {
            // Plain from here on: readers stop looking for `.age` files.
            remove_if_there(&self.dir.join(crypt::MARKER))?;
        }
        // This computer expects the history in the form it has now.
        match &key {
            Some((_, key_file)) => pin_key(&self.dir, &crypt::digest_hex(key_file))?,
            None => {
                unpin(&self.dir)?;
                // Off on purpose: a later encryption here, by any
                // version, starts without this computer's marks.
                forget_bindings(&self.dir, old_record.as_deref());
            }
        }
        if key.is_some() {
            // Encrypted from here on.
            write_atomic(
                &self.dir.join(crypt::MARKER),
                &crypt::Marker::new().to_bytes(),
            )?;
            write_atomic(&self.dir.join("findings.json"), &crypt::stub())?;
            record_location_pin(&self.dir)?;
            if !was {
                for rel in files
                    .iter()
                    .filter(|r| r.as_str() != "findings.json" && !kept.contains(r))
                {
                    remove_if_there(&self.dir.join(rel))?;
                }
            }
        } else {
            remove_if_there(&self.dir.join(crypt::KEY_FILE))?;
            for rel in files.iter().filter(|r| !kept.contains(r)) {
                remove_if_there(&on_disk(&self.dir, rel, true))?;
            }
            if !files.iter().any(|r| r == "findings.json") {
                // Only the stub was there.
                remove_if_there(&self.dir.join("findings.json"))?;
            }
        }
        Ok(files.len() - kept.len())
    }

    /// Turns encryption on: every file of the history encrypted with a new
    /// key that `passphrase` opens, in one commit (git). Takes the lock and
    /// pulls first; with git, `push` must be on (a computer that only reads
    /// can't change the shared history). Older git history keeps the files
    /// as they were.
    pub fn encrypt(&self, passphrase: &SecretString, push: bool) -> Result<Converted> {
        crypt::check_passphrase(passphrase).map_err(anyhow::Error::msg)?;
        self.convert("pathwarden: encrypt the history", push, &|store: &Store| {
            if crypt::is_encrypted(&store.dir) {
                bail!(ENCRYPTED_ALREADY);
            }
            // Encrypted files without their marker: someone removed it.
            // (A history pinned here but decrypted elsewhere may be
            // encrypted again: that is what the pin asks for.)
            if !sealed_leftovers(&store.dir, true).is_empty() {
                mode(&store.dir, false)?;
            }
            store.rewrite(Some(passphrase))
        })
    }

    /// Turns encryption off: every file of the history written plain again,
    /// in one commit (git). Needs the passphrase at hand
    /// ([`crypt::key_for`]). Older git history stays encrypted. The
    /// passphrase is then removed from this computer, which would otherwise
    /// refuse the plain history ([`mode`]). On a history another computer
    /// decrypted, this only stops this computer expecting it encrypted.
    pub fn decrypt(&self, push: bool) -> Result<Converted> {
        // Turned off on another computer: there is nothing to commit, so
        // this needs no push (a computer that only reads accepts it too).
        let accepted = {
            let _lock = self.lock_waiting(crate::settings_sync::lock_wait())?;
            let notes: Vec<String> = self.pull()?.into_iter().collect();
            if crypt::is_encrypted(&self.dir) {
                None
            } else if self.expect_encrypted
                || expects_encrypted_here(&self.dir)
                || marker_removed_by(&self.dir)?.is_some()
            {
                // Said before it is accepted: a real decrypt can be told
                // from a strip by who did it.
                let by = removal_words(&self.dir)
                    .unwrap_or_else(|| "the change that removed it isn't known here".into());
                accept_plain(&self.dir)?;
                Some(Converted {
                    files: 0,
                    pushed: false,
                    notes,
                    accepted: Some(by),
                })
            } else {
                bail!("the history isn't encrypted");
            }
        };
        let mut done = match accepted {
            Some(done) => done,
            None => {
                let done =
                    self.convert("pathwarden: decrypt the history", push, &|store: &Store| {
                        if !crypt::is_encrypted(&store.dir) {
                            bail!("the history was decrypted elsewhere meanwhile; run this again");
                        }
                        check_readable(&store.dir)?;
                        store.rewrite(None)
                    })?;
                // This computer's own decrypt commit: accepted here.
                accept_plain(&self.dir)?;
                done
            }
        };
        let removed = keystore::forget(&self.dir)?;
        if !removed.is_empty() {
            done.notes.push(format!(
                "The passphrase was removed from this computer ({}).",
                removed.join(" and ")
            ));
        }
        Ok(done)
    }

    /// Changes the passphrase: a new key, and every file encrypted with it
    /// again, in one commit (git). Needs the current passphrase at hand
    /// ([`crypt::key_for`]). The old passphrase still opens what older git
    /// history kept, and nothing newer.
    pub fn change_passphrase(&self, new: &SecretString, push: bool) -> Result<Converted> {
        crypt::check_passphrase(new).map_err(anyhow::Error::msg)?;
        self.convert(
            "pathwarden: re-encrypt the history with a new passphrase",
            push,
            &|store: &Store| {
                if !crypt::is_encrypted(&store.dir) {
                    bail!(
                        "the history isn't encrypted; `pathwarden history storage set --encrypt` \
                         turns encryption on"
                    );
                }
                check_readable(&store.dir)?;
                store.rewrite(Some(new))
            },
        )
    }

    /// [`Store::encrypt`], [`Store::decrypt`] and
    /// [`Store::change_passphrase`]: under the lock, from the latest
    /// (pull), then committed and pushed with `message`; `change` again on
    /// what another computer pushed first.
    fn convert(
        &self,
        message: &str,
        push: bool,
        change: &dyn Fn(&Store) -> Result<usize>,
    ) -> Result<Converted> {
        if self.is_git() && !push {
            bail!(
                "this computer only reads the shared history (pushing is off), so it can't \
                 change it; do this on a computer that records runs"
            );
        }
        let _lock = self.lock_waiting(crate::settings_sync::lock_wait())?;
        let mut notes: Vec<String> = self.pull()?.into_iter().collect();
        let aside_before = self.leftovers();
        let files = change(self)?;
        for moved in self
            .leftovers()
            .iter()
            .filter(|p| !aside_before.contains(p))
        {
            notes.push(format!(
                "A plain actions.json beside the encrypted history was never read, so it was \
                 left out of the decrypted history and moved aside to {}.",
                moved.display()
            ));
        }
        // What finding actions did, left as it was when it couldn't be read.
        if let Err(e) = crate::action_log::load(self) {
            notes.push(format!(
                "What finding actions did (actions.json) was left as it is: {e:#}"
            ));
        }
        let mut out = Converted {
            files,
            pushed: false,
            notes: Vec::new(),
            accepted: None,
        };
        if self.is_git() {
            match self.publish_with(message, || {
                out.files = change(self)?;
                Ok(Some(message.to_string()))
            }) {
                Ok(p) => {
                    out.pushed = p.pushed;
                    notes.extend(p.notes);
                }
                Err(e) => {
                    let kept = e.downcast::<KeptUnpushed>()?;
                    notes.extend(kept.notes.clone());
                    notes.push(kept.sentence("The history was changed"));
                }
            }
        }
        out.notes = notes;
        Ok(out)
    }

    /// Commits and pushes the state (git), with `message`.
    ///
    /// When another run pushed first, the working copy is reset to what it
    /// left and `reapply` is called to make this change again on top: it
    /// returns the commit message, or `None` when there is nothing left to
    /// do. If it fails, or other runs push first [`PUSH_RETRIES`] times
    /// over, the working copy is left at the remote's state and this change
    /// is not recorded; the error says so.
    ///
    /// When the push fails for any other reason (the remote out of reach, a
    /// refused push), the commit stays in the working copy: the next pull
    /// keeps it while the remote has not moved on, and the next publish
    /// pushes it. The error says that too.
    pub fn publish_with(
        &self,
        message: &str,
        mut reapply: impl FnMut() -> Result<Option<String>>,
    ) -> Result<Published> {
        let Some(g) = &self.git else {
            return Ok(Published::default());
        };
        let remote = redact_url(&g.remote);
        let mut message = message.to_string();
        let mut notes = Vec::new();
        let local_branch = format!("refs/heads/{}", g.branch);
        for retries in 0..=PUSH_RETRIES {
            // Commits an earlier failed push left go along, even with
            // nothing new.
            if !self.commit(&message)? && self.kept_unpushed(&local_branch, false).is_none() {
                return Ok(Published {
                    notes,
                    ..Published::default()
                });
            }
            let target = format!("HEAD:refs/heads/{}", g.branch);
            let Err(e) = run_git(Some(&self.dir), &["push", "--progress", "origin", &target])
            else {
                self.clear_kept();
                remember_remote_tree(&self.dir);
                crate::action_log::prune_pending(self);
                return Ok(Published {
                    pushed: true,
                    retries,
                    notes,
                });
            };
            let kept = |reason: String, detail: String| -> anyhow::Error {
                let _ = self.mark_kept();
                KeptUnpushed {
                    reason,
                    detail,
                    notes: notes.clone(),
                }
                .into()
            };
            match self.why_rejected(g) {
                Rejected::Behind => {}
                Rejected::Pushed => {
                    // The remote has it already (pushed another way).
                    self.clear_kept();
                    remember_remote_tree(&self.dir);
                    crate::action_log::prune_pending(self);
                    return Ok(Published {
                        pushed: true,
                        retries,
                        notes,
                    });
                }
                Rejected::Unreachable(fetch) => {
                    return Err(kept(
                        format!("{remote} can't be reached, or refused the sign-in"),
                        format!("{fetch:#}"),
                    ))
                }
                Rejected::Refused => {
                    return Err(kept(
                        format!(
                            "{remote} refused it: can this account write there, or is branch {} \
                             protected?",
                            g.branch
                        ),
                        format!("{e:#}"),
                    ))
                }
            }
            // Another run pushed first: start again from what it left. Never
            // a rebase or merge: the state files change every run and would
            // conflict; the caller makes its change again instead.
            if let Some(note) = self
                .sync(true)
                .context("getting the state another run pushed meanwhile")?
            {
                notes.push(note);
            }
            if retries == PUSH_RETRIES {
                break;
            }
            match reapply() {
                Ok(Some(m)) => message = m,
                Ok(None) => {
                    // Nothing left to do but what an earlier failed push
                    // left, if anything.
                    message = "pathwarden: earlier runs".to_string();
                }
                Err(e) => {
                    let _ = self.pull();
                    return Err(e.context(format!(
                        "another run pushed to {remote} first, and this run's state could not be \
                         applied on top of it, so it was not recorded"
                    )));
                }
            }
        }
        bail!(
            "other runs pushed to {remote} first {} times in a row, so this run's state was not \
             recorded (the working copy is at the remote's state, with any runs kept from \
             earlier failed pushes).{}",
            PUSH_RETRIES + 1,
            notes.iter().map(|n| format!(" {n}")).collect::<String>()
        )
    }

    /// Why the push just made failed: fetches, then compares.
    fn why_rejected(&self, g: &Git) -> Rejected {
        let dir = Some(self.dir.as_path());
        if let Err(e) = self.fetch() {
            return Rejected::Unreachable(e);
        }
        let remote_branch = format!("origin/{}", g.branch);
        let exists = run_git(dir, &["rev-parse", "--verify", "--quiet", &remote_branch]).is_ok();
        let ancestor =
            |a: &str, b: &str| run_git(dir, &["merge-base", "--is-ancestor", a, b]).is_ok();
        if exists && ancestor("HEAD", &remote_branch) {
            Rejected::Pushed
        } else if exists && !ancestor(&remote_branch, "HEAD") {
            Rejected::Behind
        } else {
            Rejected::Refused
        }
    }

    /// Stages the state and commits it with `message`; false when there was
    /// nothing to commit.
    fn commit(&self, message: &str) -> Result<bool> {
        let dir = Some(self.dir.as_path());
        // --force: a `.gitignore` in the state repository, or the machine's
        // own excludes, must never keep a run's point out of the commit. Only
        // the state's own files: nothing else that turns up in the folders
        // (Thumbs.db, desktop.ini) is committed.
        // Each apart: git refuses a pattern that matches nothing, and a
        // history may have no points left, no timings, or (plain or
        // encrypted) only one form of each file. Git is asked first what
        // the pattern matches (files on disk, ignored ones too, and tracked
        // ones deleted from it), so any other failure to stage (a file an
        // antivirus holds open) stops the commit: a run's point is never
        // left out while the rest of its state goes in.
        let top: Vec<String> = [MARKER, crypt::MARKER, crypt::KEY_FILE]
            .iter()
            .map(|f| f.to_string())
            .chain(single_files().flat_map(|f| [f.to_string(), format!("{f}{}", crypt::SUFFIX)]))
            .collect();
        // (pattern, whether a listed path matches it)
        let mut patterns: Vec<(String, Matches)> = top
            .into_iter()
            .map(|f| {
                (
                    format!(":(literal){f}"),
                    Box::new(move |p: &str| p == f) as Matches,
                )
            })
            .collect();
        for folder in run_folders() {
            for ext in [".json".to_string(), format!(".json{}", crypt::SUFFIX)] {
                let prefix = format!("{folder}/");
                let pattern = format!(":(glob){folder}/*{ext}");
                patterns.push((
                    pattern,
                    Box::new(move |p: &str| {
                        p.strip_prefix(&prefix)
                            .is_some_and(|n| !n.contains('/') && n.ends_with(&ext))
                    }),
                ));
            }
        }
        // Full runs: `runs/<run>/<name>`, the names of BUNDLE_FILES only.
        for folder in bundle_folders() {
            for name in BUNDLE_FILES {
                for file in [name.to_string(), format!("{name}{}", crypt::SUFFIX)] {
                    let pattern = format!(":(glob){folder}/*/{file}");
                    let prefix = format!("{folder}/");
                    patterns.push((
                        pattern,
                        Box::new(move |p: &str| {
                            p.strip_prefix(&prefix)
                                .and_then(|r| r.split_once('/'))
                                .is_some_and(|(id, n)| is_run_id(id) && n == file)
                        }),
                    ));
                }
            }
        }
        let mut ls = vec!["ls-files", "-z", "--cached", "--others", "--"];
        ls.extend(patterns.iter().map(|(p, _)| p.as_str()));
        let listed = run_git(dir, &ls)?;
        let listed: Vec<&str> = listed.split('\0').filter(|p| !p.is_empty()).collect();
        let mut add = vec!["add", "--all", "--force", "--"];
        add.extend(
            patterns
                .iter()
                .filter(|(_, matches)| listed.iter().any(|p| matches(p)))
                .map(|(p, _)| p.as_str()),
        );
        if add.len() > 4 {
            let names: Vec<&str> = add[4..]
                .iter()
                .map(|p| p.split_once(')').map_or(*p, |(_, name)| name))
                .collect();
            run_git(dir, &add).with_context(|| {
                format!("staging {} in {}", names.join(", "), self.dir.display())
            })?;
        }
        if run_git(dir, &["diff", "--cached", "--quiet"]).is_ok() {
            return Ok(false);
        }
        // An encrypted history's commit messages say nothing the file
        // names don't: no counts, sizes or names ([`neutral_message`]).
        let neutral;
        let message = if crypt::is_encrypted(&self.dir) {
            neutral = neutral_message(message);
            neutral.as_str()
        } else {
            message
        };
        // An encrypted history's commits name nobody: git's own author and
        // committer would say who works on it to anyone who can read the
        // repository. Who changed the shared settings is kept inside, in the
        // encrypted settings/last-change.json.
        if crypt::is_encrypted(&self.dir) {
            run_git_env(
                dir,
                &["commit", "--quiet", "-m", message],
                GIT_IDLE,
                &NEUTRAL_AUTHOR,
            )?;
            return Ok(true);
        }
        let has_identity =
            run_git(dir, &["config", "user.email"]).is_ok_and(|e| !e.trim().is_empty());
        let mut commit = Vec::new();
        if !has_identity {
            commit.extend([
                "-c",
                "user.name=Pathwarden",
                "-c",
                "user.email=pathwarden@localhost",
            ]);
        }
        commit.extend(["commit", "--quiet", "-m", message]);
        run_git(dir, &commit)?;
        Ok(true)
    }
}

/// Why turning encryption on is refused for a history encrypted already:
/// the same words in the app and on the command line, without a command
/// (the command line adds its own hint).
pub const ENCRYPTED_ALREADY: &str = "This history is encrypted already.";

/// The message a commit to an encrypted history gets for `message`: what
/// the file names show anyway, and nothing more. A run's commit keeps
/// "pathwarden run <id>" (its point or its full run), a removal "pathwarden:
/// remove run <id> from the history", and a few fixed messages that carry
/// no count, size or name stay as they are. Anything else (counts of
/// imported or kept runs, full runs' sizes, settings changes) becomes
/// "pathwarden: update the history". Every commit goes through here, so no
/// caller can put more in an encrypted history's log.
pub fn neutral_message(message: &str) -> String {
    const FIXED: &[&str] = &[
        "pathwarden settings",
        "pathwarden: encrypt the history",
        "pathwarden: decrypt the history",
        "pathwarden: re-encrypt the history with a new passphrase",
        "pathwarden: earlier runs",
        "pathwarden: changes kept from an earlier push",
        crate::action_log::MESSAGE,
    ];
    let first = message.lines().next().unwrap_or("").trim();
    if FIXED.contains(&first) && !message.trim().contains('\n') {
        return first.to_string();
    }
    if let Some(rest) = first.strip_prefix("pathwarden run ") {
        let id = rest.split(':').next().unwrap_or("").trim();
        if is_run_id(id) {
            return format!("pathwarden run {id}");
        }
    }
    if let Some(id) = first
        .strip_prefix("pathwarden: remove run ")
        .and_then(|r| r.strip_suffix(" from the history"))
    {
        if is_run_id(id) && !message.trim().contains('\n') {
            return first.to_string();
        }
    }
    "pathwarden: update the history".to_string()
}

/// A commit that changed the shared settings ([`Store::last_settings_commit`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SettingsCommit {
    pub commit: String,
    /// Git's author (`user.name`, or Pathwarden's own when git has none).
    pub author: String,
    pub email: String,
    /// ISO 8601, as git gives it.
    pub at: String,
    /// The whole message, trailers included.
    pub message: String,
}

/// The last run recorded in the state, if any (and readable). One a
/// newer Pathwarden saved (its version above [`STATE_VERSION`]) is not
/// taken: what it says may not mean the same here (docs/dev/formats.md).
pub fn last_run(store: &Store) -> Option<LastRun> {
    store
        .read_state_file("last-run.json")
        .ok()
        .flatten()
        .and_then(|t| serde_json::from_slice::<LastRun>(&t).ok())
        .filter(|l| crate::formats::of_u32(l.version, STATE_VERSION).is_known())
}

/// Writes a file atomically: to a temporary file in the same folder, then
/// renamed over the target, so a crash never leaves a truncated state file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".into());
    let tmp = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    if let Some(link) = [path, &tmp].into_iter().find(|p| is_link(p)) {
        bail!(
            "{} is a symbolic link; Pathwarden does not write state through links",
            link.display()
        );
    }
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("replacing {}", path.display()));
    }
    Ok(())
}

/// How many git commands this process has started ([`git_runs`]).
static GIT_RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many git commands this process has started: tests check that
/// showing a page starts none.
pub fn git_runs() -> u64 {
    GIT_RUNS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Forgets the answers the encryption-marker and kept-commit checks keep
/// by commit, as a new process starts with none: for tests of a cold
/// start.
#[doc(hidden)]
pub fn forget_kept_answers() {
    removed_by_cache().clear();
    kept_cache().clear();
    remote_trees().clear();
}

/// Whether git on this computer has a credential helper set up (Git
/// Credential Manager, or any other), in `dir`'s working copy when given
/// or in the user's and the system's settings: without one, git can't ask
/// for an account at all, and signing in can't work.
pub fn has_credential_helper(dir: Option<&Path>) -> bool {
    let dir = dir.filter(|d| d.join(".git").is_dir());
    match run_git(dir, &["config", "--get-regexp", r"^credential\..*helper$"]) {
        // `helper =` (empty) only clears the helpers named before it.
        Ok(out) => out
            .lines()
            .any(|l| l.split_once(' ').is_some_and(|(_, v)| !v.trim().is_empty())),
        Err(_) => false,
    }
}

/// `https://user:token@host/x` -> `https://***@host/x`, for every URL in
/// the text (git's messages can hold more than one); other forms unchanged.
pub fn redact_url(url: &str) -> String {
    crate::config::redact_urls(url)
}

/// Compares remotes loosely: credentials, trailing `/` or `.git`, scheme and
/// host case, and Windows path separators and case do not matter.
pub fn same_remote(a: &str, b: &str) -> bool {
    normalize_remote(a) == normalize_remote(b)
}

fn normalize_remote(url: &str) -> String {
    let mut s = url.trim().replace('\\', "/");
    if let Some(scheme_end) = s.find("://") {
        let rest = s[scheme_end + 3..].to_string();
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let host = authority.rsplit('@').next().unwrap_or(authority);
        s = format!(
            "{}://{}{}",
            s[..scheme_end].to_ascii_lowercase(),
            host.to_ascii_lowercase(),
            &rest[authority_end..]
        );
    } else if cfg!(windows) {
        s = s.to_ascii_lowercase();
    }
    loop {
        let before = s.len();
        s = s.trim_end_matches('/').to_string();
        if let Some(stripped) = s.strip_suffix(".git") {
            s = stripped.to_string();
        }
        if s.len() == before {
            return s;
        }
    }
}

/// The same checks the UI applies before saving `[state]` (shared in core).
fn validate_remote(remote: &str) -> Result<()> {
    crate::config::validate_remote(remote).map_err(anyhow::Error::msg)
}

/// A conservative branch-name check (no option injection, no odd refs).
fn validate_branch(branch: &str) -> Result<()> {
    crate::config::validate_branch(branch).map_err(anyhow::Error::msg)
}

/// A symbolic link or (on Windows) a junction; false if `path` is missing.
fn is_link(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// Git's variables that point it at a repository, a work tree, an index or
/// other settings (`git rev-parse --local-env-vars`, and the namespace).
/// Set when Pathwarden runs from a git hook, `git rebase -x` or some CI and
/// IDE runners, they would send the reset, clean and commit to another
/// repository; every git command here runs without them.
pub const GIT_LOCAL_ENV: &[&str] = &[
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_GRAFT_FILE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PREFIX",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
];

/// "10 minutes", "45 seconds".
fn idle_words(idle: Duration) -> String {
    if idle.as_secs() >= 60 {
        crate::text::count((idle.as_secs() / 60) as usize, "minute", "minutes")
    } else {
        crate::text::count(idle.as_secs() as usize, "second", "seconds")
    }
}

pub(crate) fn run_git(dir: Option<&Path>, args: &[&str]) -> Result<String> {
    run_git_bytes(dir, args).map(|out| String::from_utf8_lossy(&out).into_owned())
}

/// The most of git's output kept: far more than a history's
/// largest file (a run's graph, at most 75 MB) or listing. More is an
/// error, never a cut answer read as whole.
const MAX_GIT_OUTPUT: usize = 256 << 20;

/// The most of git's error output kept, for its message.
const MAX_GIT_ERRORS: usize = 1 << 20;

/// The most a small file the history's repository holds (the marker, a
/// `.gitattributes`) may be to be read from git.
const MAX_SMALL_FILE: u64 = 1 << 20;

/// A blob of the history's repository, when it is at most `max` bytes:
/// its size is asked first (`cat-file -s`), so a large one is never read.
fn small_blob(dir: &Path, id: &str, max: u64) -> Result<Vec<u8>> {
    let size: u64 = run_git(Some(dir), &["cat-file", "-s", id])?
        .trim()
        .parse()
        .with_context(|| format!("git cat-file -s {id}: not a size"))?;
    if size > max {
        bail!(
            "the repository's object {id} is {size} bytes, more than the {max} such a file may \
             be; it wasn't read"
        );
    }
    run_git_bytes(Some(dir), &["cat-file", "blob", id])
}

/// [`run_git`], with git's output as it is (a file's contents).
fn run_git_bytes(dir: Option<&Path>, args: &[&str]) -> Result<Vec<u8>> {
    run_git_idle(dir, args, git_idle())
}

/// A piece of git's output, from the thread reading one of its pipes.
enum Piece {
    Out(Vec<u8>),
    Err(Vec<u8>),
    /// That pipe is closed.
    Closed,
}

/// [`run_git_bytes`], stopping git (and every process it started: the
/// launcher, ssh, a credential helper) when it says nothing for `idle`. A
/// network that never answers must not hold the state's lock, which a run
/// keeps fresh, forever; a big clone over a slow link that keeps reporting
/// progress (`--progress`) is never stopped.
fn run_git_idle(dir: Option<&Path>, args: &[&str], idle: Duration) -> Result<Vec<u8>> {
    run_git_env(dir, args, idle, &[])
}

/// [`run_git_idle`] with these environment variables set for git.
fn run_git_env(
    dir: Option<&Path>,
    args: &[&str],
    idle: Duration,
    env: &[(&str, &str)],
) -> Result<Vec<u8>> {
    GIT_RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut cmd = git_command(dir, args, env);
    crate::proc_tree::prepare(&mut cmd);
    let child = cmd
        .spawn()
        .context("running git; is it installed and on PATH?")?;
    run_git_child(dir, args, idle, child)
}

/// The git command [`run_git_env`] runs: without the variables that
/// point git elsewhere, never able to prompt in the terminal or over SSH
/// (nor through Git Credential Manager's window, in [`non_interactive`]
/// work), with links checked out as files and line endings as they are.
fn git_command(dir: Option<&Path>, args: &[&str], env: &[(&str, &str)]) -> std::process::Command {
    let mut cmd = crate::spawn::quiet("git");
    for var in GIT_LOCAL_ENV {
        cmd.env_remove(var);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    // Nor a hook or credential helper sees the history's passphrase.
    keystore::scrub_env(&mut cmd);
    // Symlinks in the state repository are checked out as plain files (L7).
    cmd.args(["-c", "core.symlinks=false", "-c", "core.autocrlf=false"]);
    if let Some(d) = dir {
        cmd.arg("-C").arg(d);
    }
    // Never wait for a password prompt; an SSH command the machine sets
    // already is kept.
    if std::env::var_os("GIT_SSH_COMMAND").is_none() && std::env::var_os("GIT_SSH").is_none() {
        cmd.env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes");
    }
    // Git Credential Manager may still open a sign-in window: not for work
    // nobody watches ([`non_interactive`]).
    if NON_INTERACTIVE.with(std::cell::Cell::get) {
        cmd.env("GCM_INTERACTIVE", "never");
    }
    cmd.args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd
}

/// Waits for git, started by [`run_git_env`], stopping it when it says
/// nothing for `idle`.
fn run_git_child(
    dir: Option<&Path>,
    args: &[&str],
    idle: Duration,
    mut child: std::process::Child,
) -> Result<Vec<u8>> {
    let tree = crate::proc_tree::Tree::attach(&child);
    // Counted until both pipes close (each reader holds it), not only until
    // this returns: a process an idle stop missed may still write a lock.
    let running = dir.map(|d| std::sync::Arc::new(RunningGit::new(d)));
    // Both pipes are read apart, so a chatty git never blocks on a full one,
    // and each piece read counts as a sign of life.
    let (tx, rx) = std::sync::mpsc::channel::<Piece>();
    let read = |pipe: Option<Box<dyn std::io::Read + Send>>, out: bool| {
        let tx = tx.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            if let Some(mut p) = pipe {
                let mut buf = [0u8; 8192];
                while let Ok(n) = p.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let piece = buf[..n].to_vec();
                    let piece = if out {
                        Piece::Out(piece)
                    } else {
                        Piece::Err(piece)
                    };
                    // Read on to the end when nobody listens (git was
                    // stopped): the count lasts while the pipe is held.
                    let _ = tx.send(piece);
                }
            }
            drop(running);
            let _ = tx.send(Piece::Closed);
        });
    };
    read(child.stdout.take().map(|p| Box::new(p) as _), true);
    read(child.stderr.take().map(|p| Box::new(p) as _), false);
    drop(tx);
    drop(running);
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let mut too_much = false;
    let mut open = 2;
    let mut last = std::time::Instant::now();
    // Kept up to the limits; the rest is read and dropped, so git never
    // blocks on a full pipe.
    let mut take = |piece: Piece, open: &mut i32| match piece {
        Piece::Out(b) if stdout.len() + b.len() <= MAX_GIT_OUTPUT => stdout.extend(b),
        Piece::Out(_) => too_much = true,
        Piece::Err(b) => {
            let room = MAX_GIT_ERRORS.saturating_sub(stderr.len());
            stderr.extend_from_slice(&b[..b.len().min(room)]);
        }
        Piece::Closed => *open -= 1,
    };
    let status = loop {
        if open > 0 {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(piece) => {
                    last = std::time::Instant::now();
                    take(piece, &mut open);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => open = 0,
            }
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
        if let Some(status) = child.try_wait()? {
            // What is left, briefly: a process git started (an ssh
            // connection kept open) may hold a pipe long after git exits.
            let until = std::time::Instant::now() + Duration::from_secs(5);
            while open > 0 {
                let left = until.saturating_duration_since(std::time::Instant::now());
                match rx.recv_timeout(left) {
                    Ok(piece) => take(piece, &mut open),
                    Err(_) => break,
                }
            }
            break status;
        }
        if last.elapsed() > idle {
            let found = stop_tree(&mut child, &tree);
            // Every process git started holds its pipes (the real git the
            // Windows launcher starts, ssh, a hook's shell): both closed
            // means none is left that could still be writing a lock. Only
            // then are the locks it left removed; one a git still running
            // holds (an index.lock it is writing) is never taken from it.
            let until = std::time::Instant::now() + Duration::from_secs(5);
            while open > 0 {
                let left = until.saturating_duration_since(std::time::Instant::now());
                match rx.recv_timeout(left) {
                    Ok(piece) => take(piece, &mut open),
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => open = 0,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                }
            }
            let stopped = std::time::SystemTime::now();
            let kept = match dir {
                Some(d) if open == 0 => {
                    remove_stale_locks(&d.join(".git"), stopped);
                    Vec::new()
                }
                Some(d) => {
                    let kept = stale_locks(&d.join(".git"), stopped);
                    if !kept.is_empty() {
                        record_survivors(&d.join(".git"), &found);
                    }
                    kept
                }
                None => Vec::new(),
            };
            bail!(
                "git {} gave no sign of progress for {} and was stopped (a network or remote \
                 that doesn't answer?){}",
                args.first().unwrap_or(&""),
                idle_words(idle),
                kept_locks_words(&kept)
            );
        }
    };
    if !status.success() {
        return Err(GitFailed {
            code: status.code(),
            message: format!(
                "git {} failed: {}",
                args.first().unwrap_or(&""),
                redact_url(&git_message(&stderr))
            ),
        }
        .into());
    }
    if too_much {
        bail!(
            "git {} printed more than {} MiB, more than a history ever needs; it wasn't read",
            args.first().unwrap_or(&""),
            MAX_GIT_OUTPUT >> 20
        );
    }
    Ok(stdout)
}

/// A git command that ran and failed, with its exit code.
#[derive(Debug)]
pub(crate) struct GitFailed {
    pub(crate) code: Option<i32>,
    pub(crate) message: String,
}

impl std::fmt::Display for GitFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for GitFailed {}

/// Stops git and every process it started. Returns the processes it found
/// that git started (Windows; none elsewhere): their IDs and when each was
/// created.
fn stop_tree(
    child: &mut std::process::Child,
    tree: &crate::proc_tree::Tree,
) -> Vec<(u32, std::time::SystemTime)> {
    // On Windows `git` is a launcher for the real git, which it may start
    // in the moment before it joins the job: the tree is ended by parent
    // too, while the launcher still lives to be found by. Only processes
    // created after their parent are ended, never an orphan an earlier
    // process with the launcher's ID left.
    #[cfg(windows)]
    let found = crate::proc_tree::end_descendants(child);
    #[cfg(not(windows))]
    let found = Vec::new();
    tree.kill();
    let _ = child.kill();
    let _ = child.wait();
    found
}

/// The file in a working copy's `.git` naming the processes an idle stop
/// found still running (one line each: `pid P created N`, N in
/// nanoseconds since 1970): the git locks it kept are not removed while
/// any of them runs, even by a later Pathwarden.
const SURVIVORS_FILE: &str = "pathwarden-survivors";

/// The processes [`SURVIVORS_FILE`] in `git_dir` names.
fn read_survivors(git_dir: &Path) -> Vec<(u32, u128)> {
    fs::read_to_string(git_dir.join(SURVIVORS_FILE))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| match l.split_whitespace().collect::<Vec<_>>()[..] {
            ["pid", pid, "created", t] => Some((pid.parse().ok()?, t.parse().ok()?)),
            _ => None,
        })
        .collect()
}

/// Whether process `pid`, created at `created` (ns since 1970), still runs.
/// One that can't be told (another account's) is taken for running.
fn survivor_runs(pid: u32, created: u128) -> bool {
    match crate::proc_tree::holder(pid) {
        crate::proc_tree::Holder::Gone => false,
        crate::proc_tree::Holder::Unknown => true,
        crate::proc_tree::Holder::Running { started, .. } => {
            started.is_none_or(|s| unix_nanos(s) == Some(created))
        }
    }
}

fn unix_nanos(t: std::time::SystemTime) -> Option<u128> {
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos())
}

/// Records in `git_dir` the processes among `found` still running after an
/// idle stop, with those an earlier stop recorded that still run.
fn record_survivors(git_dir: &Path, found: &[(u32, std::time::SystemTime)]) {
    let mut alive: Vec<(u32, u128)> = read_survivors(git_dir)
        .into_iter()
        .chain(
            found
                .iter()
                .filter_map(|&(pid, t)| Some((pid, unix_nanos(t)?))),
        )
        .filter(|&(pid, t)| survivor_runs(pid, t))
        .collect();
    alive.sort_unstable();
    alive.dedup();
    if alive.is_empty() {
        return;
    }
    let text: String = alive
        .iter()
        .map(|(pid, t)| format!("pid {pid} created {t}\n"))
        .collect();
    let _ = fs::write(git_dir.join(SURVIVORS_FILE), text);
}

/// Removes the lock files a git stopped mid-update left in `git_dir`
/// (`refs/remotes/origin/main.lock`, `index.lock`, ...), made before
/// `stopped`: each would fail every later git command ("cannot lock ref").
/// The run's own lock keeps any other Pathwarden git out meanwhile.
fn remove_stale_locks(git_dir: &Path, stopped: std::time::SystemTime) -> usize {
    stale_locks(git_dir, stopped)
        .iter()
        .filter(|p| fs::remove_file(p).is_ok())
        .count()
}

/// The lock files a git leaves in `git_dir` while it updates refs, the
/// index or the config, made before `before`.
fn stale_locks(git_dir: &Path, before: std::time::SystemTime) -> Vec<PathBuf> {
    fn stale(path: &Path, before: std::time::SystemTime) -> bool {
        fs::symlink_metadata(path)
            .is_ok_and(|m| m.is_file() && m.modified().is_ok_and(|t| t <= before))
    }
    fn walk(dir: &Path, before: std::time::SystemTime, found: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let path = e.path();
            let Ok(kind) = e.file_type() else { continue };
            if kind.is_dir() {
                walk(&path, before, found);
            } else if path.extension().is_some_and(|x| x == "lock") && stale(&path, before) {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(&git_dir.join("refs"), before, &mut found);
    for name in [
        "index.lock",
        "packed-refs.lock",
        "HEAD.lock",
        "config.lock",
        "shallow.lock",
    ] {
        let path = git_dir.join(name);
        if stale(&path, before) {
            found.push(path);
        }
    }
    found
}

/// The git commands of this process whose output may still be written,
/// by working copy: each counts from its start until both its pipes close,
/// which is after every process it started (one an idle stop missed
/// included) has stopped.
fn running_git() -> std::sync::MutexGuard<'static, std::collections::HashMap<PathBuf, usize>> {
    static RUNNING: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, usize>>,
    > = std::sync::OnceLock::new();
    RUNNING
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The key [`running_git`] counts `dir` by: the same folder named two ways
/// counts once.
fn running_key(dir: &Path) -> PathBuf {
    fs::canonicalize(dir)
        .or_else(|_| std::path::absolute(dir))
        .unwrap_or_else(|_| dir.to_path_buf())
}

/// One git command counted in [`running_git`] while it lives.
struct RunningGit(PathBuf);

impl RunningGit {
    fn new(dir: &Path) -> Self {
        let key = running_key(dir);
        *running_git().entry(key.clone()).or_default() += 1;
        RunningGit(key)
    }
}

impl Drop for RunningGit {
    fn drop(&mut self) {
        let mut running = running_git();
        if let Some(n) = running.get_mut(&self.0) {
            *n -= 1;
            if *n == 0 {
                running.remove(&self.0);
            }
        }
    }
}

/// Removes the git lock files an earlier stopped git kept in `dir`'s
/// working copy (one of the processes it started still ran then), once
/// they are older than [`GIT_IDLE`], no git this process started there
/// still runs, and none of the processes a stop recorded as still running
/// ([`SURVIVORS_FILE`], by any Pathwarden process) runs. Only while this
/// process holds the history's lock, so no other Pathwarden runs git there
/// either; otherwise every later fetch fails ("cannot lock ref").
fn remove_left_locks(dir: &Path) -> usize {
    let holder = fs::read_to_string(dir.join(LOCK_FILE)).unwrap_or_default();
    let held = LockHolder::parse(&holder)
        .token
        .is_some_and(|t| held_here().contains(&t));
    if !held || running_git().contains_key(&running_key(dir)) {
        return 0;
    }
    // Processes an earlier stop (of this Pathwarden or one before it) saw
    // still running: their locks stay while any of them runs.
    let git_dir = dir.join(".git");
    if read_survivors(&git_dir)
        .into_iter()
        .any(|(pid, t)| survivor_runs(pid, t))
    {
        return 0;
    }
    let _ = fs::remove_file(git_dir.join(SURVIVORS_FILE));
    let Some(before) = std::time::SystemTime::now().checked_sub(GIT_IDLE) else {
        return 0;
    };
    remove_stale_locks(&git_dir, before)
}

/// The folders creating `dir` would make: it and each missing parent,
/// `dir` first.
fn missing_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut missing = Vec::new();
    let mut at = Some(dir);
    while let Some(d) = at.filter(|d| !d.as_os_str().is_empty()) {
        if fs::symlink_metadata(d).is_ok() {
            break;
        }
        missing.push(d.to_path_buf());
        at = d.parent();
    }
    missing
}

/// Removes the folders [`missing_dirs`] named, `dir` first, while they are
/// empty: never one holding anything, nor a parent of one.
fn remove_made_dirs(made: &[PathBuf]) {
    for d in made {
        if fs::remove_dir(d).is_err() {
            break;
        }
    }
}

/// The pattern a line of `.git/info/exclude` is to git: leading spaces
/// kept, trailing spaces dropped unless the last is escaped (`\ `). (The
/// line ending, `\r` included, is gone already.)
fn git_pattern(line: &str) -> &str {
    let trimmed = line.trim_end_matches(' ');
    if trimmed.len() < line.len() && trimmed.ends_with('\\') {
        &line[..=trimmed.len()]
    } else {
        trimmed
    }
}

/// The sentence an idle stop adds for the git lock files it kept.
fn kept_locks_words(kept: &[PathBuf]) -> String {
    if kept.is_empty() {
        return String::new();
    }
    let list = kept
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let (these, they) = if kept.len() == 1 {
        ("this git lock file was", "It is")
    } else {
        ("these git lock files were", "They are")
    };
    format!(
        ". A process it started was still running, so {these} kept: {list}. {they} safe to \
         remove once no git is running there."
    )
}

/// Removes a folder this code made, git's read-only object files included
/// (Windows won't delete a read-only file); a link is removed, never
/// followed.
fn remove_tree(path: &Path) -> std::io::Result<()> {
    fn writable(dir: &Path) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let Ok(kind) = e.file_type() else { continue };
            if kind.is_dir() {
                writable(&e.path());
            } else if kind.is_file() {
                if let Ok(m) = e.metadata() {
                    let mut perms = m.permissions();
                    if perms.readonly() {
                        #[allow(clippy::permissions_set_readonly_false)]
                        perms.set_readonly(false);
                        let _ = fs::set_permissions(e.path(), perms);
                    }
                }
            }
        }
    }
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return fs::remove_file(path).or_else(|_| fs::remove_dir(path));
    }
    if !meta.is_dir() {
        return fs::remove_file(path);
    }
    writable(path);
    fs::remove_dir_all(path)
}

/// What git said on stderr, without its progress lines (`--progress`).
fn git_message(stderr: &[u8]) -> String {
    const PROGRESS: &[&str] = &[
        "Counting objects",
        "Compressing objects",
        "Receiving objects",
        "Resolving deltas",
        "Writing objects",
        "Enumerating objects",
        "Total ",
        "Delta compression",
        "Unpacking objects",
    ];
    String::from_utf8_lossy(stderr)
        .lines()
        .filter_map(|l| l.rsplit('\r').find(|s| !s.trim().is_empty()))
        .map(str::trim)
        .filter(|l| {
            !PROGRESS
                .iter()
                .any(|p| l.trim_start_matches("remote: ").starts_with(p))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scheduled run doesn't follow a key it hasn't pinned: the
    /// pin stays, and nothing says it was followed. By hand it is followed,
    /// and told once; the key already pinned is fine either way.
    #[test]
    fn a_scheduled_run_refuses_a_replaced_key() {
        let dir = std::env::temp_dir().join(format!("pw-follow-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".git")).unwrap();
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        pin_key(&dir, &old).unwrap();
        follow_key_as(&dir, &old, true).unwrap();
        let e = follow_key_as(&dir, &new, true).unwrap_err().to_string();
        assert!(
            e.contains("a scheduled run doesn't follow a new key"),
            "{e}"
        );
        assert_eq!(pinned_key(&dir).as_deref(), Some(old.as_str()));
        assert!(take_key_note(&dir).is_none());
        follow_key_as(&dir, &new, false).unwrap();
        assert_eq!(pinned_key(&dir).as_deref(), Some(new.as_str()));
        assert!(take_key_note(&dir).is_some_and(|n| n.contains("was replaced")));
        // Nothing pinned yet: the first key is pinned, scheduled or not.
        fs::remove_file(pin_path(&dir).unwrap()).unwrap();
        follow_key_as(&dir, &old, true).unwrap();
        assert_eq!(pinned_key(&dir).as_deref(), Some(old.as_str()));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A small file of the repository (the marker, a `.gitattributes`) is
    /// read only when git says it is small.
    #[test]
    fn large_blobs_are_not_read() {
        let dir = std::env::temp_dir().join(format!("pw-small-blob-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        if run_git(Some(&dir), &["init", "-q"]).is_err() {
            assert!(std::env::var_os("CI").is_none(), "git is required in CI");
            return;
        }
        fs::write(dir.join("small"), "text=auto\n").unwrap();
        fs::write(dir.join("big"), vec![b'x'; 4096]).unwrap();
        let id = |f: &str| {
            run_git(Some(&dir), &["hash-object", "-w", f])
                .unwrap()
                .trim()
                .to_string()
        };
        let (small, big) = (id("small"), id("big"));
        assert_eq!(small_blob(&dir, &small, 1024).unwrap(), b"text=auto\n");
        let e = small_blob(&dir, &big, 1024).unwrap_err().to_string();
        assert!(
            e.contains("is 4096 bytes") && e.contains("wasn't read"),
            "{e}"
        );
        remove_tree(&dir).unwrap();
    }

    #[test]
    fn forget_removes_one_point_and_refuses_paths() {
        let dir = std::env::temp_dir().join(format!("pw-forget-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("history")).unwrap();
        for id in ["20261018T120000.000Z", "20261018T130000.000Z"] {
            fs::write(dir.join("history").join(format!("{id}.json")), "{}").unwrap();
        }
        fs::write(dir.join("findings.json"), "{}").unwrap();
        let store = Store::new(&StateConfig::default(), Some(&dir)).unwrap();
        assert!(store.forget("20261018T120000.000Z").unwrap());
        assert!(!dir.join("history/20261018T120000.000Z.json").exists());
        assert!(dir.join("history/20261018T130000.000Z.json").exists());
        // The findings state is untouched; a second forget finds nothing.
        assert!(dir.join("findings.json").exists());
        assert!(!store.forget("20261018T120000.000Z").unwrap());
        for bad in ["", "../findings", "..", "a/b", r"a\b", ".hidden"] {
            assert!(store.forget(bad).is_err(), "{bad}");
        }
        assert!(dir.join("findings.json").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A run's exposed accounts are a file of the history: written
    /// through the seam, removed with the run, and kept for the latest
    /// runs only.
    #[test]
    fn exposed_accounts_are_kept_with_their_runs() {
        use crate::exposed::{ExposedRecord, DIR};
        assert!(is_state_rel("exposed/20261018T120000.000Z.json"));
        assert!(!is_state_rel("exposed/x/y.json"));
        assert!(!is_state_rel("exposed/../findings.json"));
        assert!(!is_state_rel("exposed/a.txt"));
        assert!(state_entry("exposed"));
        let dir = std::env::temp_dir().join(format!("pw-exposed-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("history")).unwrap();
        let store = Store::new(&StateConfig::default(), Some(&dir)).unwrap();
        // Twelve runs of one environment, all Full; and keys of a run the
        // history has no point for.
        let ids: Vec<String> = (0..12)
            .map(|i| format!("20261018T12{i:02}00.000Z"))
            .collect();
        for (i, id) in ids.iter().enumerate() {
            let point = serde_json::json!({
                "version": 1, "run_id": id, "at": 1000 + i, "collected_at": null,
                "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": 1,
                "tier_zero_population": 1, "tier_zero_objects": 1, "protection_score": null,
                "findings": {"attack_path": 0, "hygiene": 0, "suppressed": 0, "critical": 0,
                    "high": 0, "medium": 0, "low": 0, "info": 0},
                "changes": {"new": 0, "open": 0, "regressed": 0, "suppressed": 0,
                    "resolved": 0},
            });
            fs::write(
                dir.join("history").join(format!("{id}.json")),
                point.to_string(),
            )
            .unwrap();
            store
                .save_exposed(&ExposedRecord::new(id, 0, [i as u64]))
                .unwrap();
        }
        store
            .save_exposed(&ExposedRecord::new("20261018T000000.000Z", 0, [7]))
            .unwrap();
        assert!(store
            .save_exposed(&ExposedRecord::new("../x", 0, [7]))
            .is_err());
        // A point the history has but can't read (damaged, or of a newer
        // shape): its keys stay, whatever it is.
        let unread = "20261018T000100.000Z";
        fs::write(dir.join("history").join(format!("{unread}.json")), "{").unwrap();
        store
            .save_exposed(&ExposedRecord::new(unread, 0, [8]))
            .unwrap();
        assert_eq!(store.list_state_files(DIR).unwrap().len(), 14);
        // The orphan and the two oldest go.
        assert_eq!(store.prune_exposed().unwrap(), 3);
        let left = store.list_state_files(DIR).unwrap();
        assert_eq!(left.first().unwrap(), &format!("{DIR}/{unread}.json"));
        assert_eq!(left[1], format!("{DIR}/{}.json", ids[2]));
        assert_eq!(left.len(), 11);
        assert_eq!(store.prune_exposed().unwrap(), 0);
        // Forgetting a run removes its keys.
        assert!(store.forget(&ids[5]).unwrap());
        assert!(!dir.join(format!("{DIR}/{}.json", ids[5])).exists());
        assert_eq!(store.list_state_files(DIR).unwrap().len(), 10);
        // A newer Pathwarden's keys, even an orphan's, stay
        // (docs/dev/formats.md); one of ours goes.
        let newer = dir.join(DIR).join("20261017T000000.000Z.json");
        fs::write(&newer, r#"{"version":2,"run_id":"20261017T000000.000Z"}"#).unwrap();
        fs::write(
            dir.join(DIR).join("20261016T000000.000Z.json"),
            r#"{"version":1,"run_id":"20261016T000000.000Z"}"#,
        )
        .unwrap();
        assert_eq!(store.prune_exposed().unwrap(), 1);
        assert!(newer.is_file());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn encrypted_histories_get_neutral_commit_messages() {
        let id = "20261023T015208.222Z";
        for (given, want) in [
            (
                format!("pathwarden run {id}: 3 new, 0 regressed, 1 resolved, 9 open"),
                format!("pathwarden run {id}"),
            ),
            (
                format!("pathwarden run {id}: full run (2.1 MB)"),
                format!("pathwarden run {id}"),
            ),
            (
                format!("pathwarden run {id}: full run (2.1 MB); 1 older full run removed"),
                format!("pathwarden run {id}"),
            ),
            (
                format!("pathwarden: remove run {id} from the history"),
                format!("pathwarden: remove run {id} from the history"),
            ),
            ("pathwarden settings".into(), "pathwarden settings".into()),
            (
                "pathwarden: encrypt the history".into(),
                "pathwarden: encrypt the history".into(),
            ),
            (
                "pathwarden: 2 full runs (2.0 KB); 1 older full run removed".into(),
                "pathwarden: update the history".into(),
            ),
            (
                "pathwarden: import 3 run(s) analyzed in the UI".into(),
                "pathwarden: update the history".into(),
            ),
            (
                "pathwarden: add 1 earlier run(s) another run's push came before".into(),
                "pathwarden: update the history".into(),
            ),
            (
                "pathwarden settings: 1 Tier Zero addition\n\nChanged-by: NORTH\\x".into(),
                "pathwarden: update the history".into(),
            ),
            (
                "pathwarden settings\n\nChanged-by: NORTH\\x".into(),
                "pathwarden: update the history".into(),
            ),
            (
                "pathwarden run ../x: y".into(),
                "pathwarden: update the history".into(),
            ),
        ] {
            assert_eq!(neutral_message(&given), want, "{given}");
        }
    }

    #[test]
    fn redacts_credentials() {
        assert_eq!(
            redact_url("https://user:ghp_secret@github.com/org/state.git"),
            "https://***@github.com/org/state.git"
        );
        assert_eq!(
            redact_url("https://token@dev.azure.com/org/p/_git/state"),
            "https://***@dev.azure.com/org/p/_git/state"
        );
        assert_eq!(
            redact_url("https://github.com/org/state.git"),
            "https://github.com/org/state.git"
        );
        assert_eq!(redact_url("C:/state/remote.git"), "C:/state/remote.git");
        // The @ in a path is not userinfo.
        assert_eq!(
            redact_url("https://host/a@b/state.git"),
            "https://host/a@b/state.git"
        );
    }

    #[test]
    fn remote_comparison_is_loose_about_form_only() {
        assert!(same_remote(
            "https://GitHub.com/org/state.git/",
            "https://github.com/org/state"
        ));
        assert!(same_remote(
            "https://user:tok@github.com/org/state.git",
            "https://github.com/org/state.git"
        ));
        assert!(!same_remote(
            "https://github.com/org/project.git",
            "https://github.com/org/state.git"
        ));
        assert!(!same_remote("", "https://github.com/org/state.git"));
    }

    #[test]
    fn validates_git_inputs() {
        assert!(validate_branch("main").is_ok());
        assert!(validate_branch("pathwarden/state-1.0").is_ok());
        for bad in [
            "",
            "--upload-pack=/x.sh",
            "-x",
            "a..b",
            "x.lock",
            "x/",
            "a b",
            "a;b",
        ] {
            assert!(validate_branch(bad).is_err(), "{bad:?} accepted");
        }
        assert!(validate_remote("--upload-pack=evil").is_err());
        assert!(validate_remote("https://github.com/org/state.git").is_ok());
    }

    /// A directory link: a junction on Windows (no privilege needed), a
    /// symlink elsewhere.
    fn link_dir(target: &Path, link: &Path) -> bool {
        #[cfg(windows)]
        {
            crate::spawn::quiet("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .is_ok_and(|o| o.status.success())
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
    }

    #[test]
    fn state_is_not_written_through_links() {
        let dir = std::env::temp_dir().join(format!("pw-links-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (state, outside) = (dir.join("state"), dir.join("outside"));
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&outside).unwrap();
        if !link_dir(&outside, &state.join("history")) {
            eprintln!("cannot create a directory link here; skipping");
            return;
        }
        let cfg = StateConfig::default();
        let store = Store::new(&cfg, Some(&state)).unwrap();
        // save() runs this check before writing anything.
        let err = store.check_no_links().unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err:#}");
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        // Without the link, the state folder passes.
        // A Unix symlink is removed as a file, a Windows junction as a folder.
        let link = state.join("history");
        fs::remove_file(&link)
            .or_else(|_| fs::remove_dir(&link))
            .unwrap();
        fs::create_dir(&link).unwrap();
        store.check_no_links().unwrap();
        fs::remove_dir_all(&dir).ok();
    }

    /// The app's background pull stops a silent git after 45 seconds, well
    /// before a run or a save waiting for the lock gives up; elsewhere the
    /// limit stays 10 minutes, and it ends with the pull.
    #[test]
    fn a_background_pull_gives_up_on_a_silent_git_early() {
        assert_eq!(git_idle(), GIT_IDLE);
        let inside = background(|| (git_idle(), NON_INTERACTIVE.with(std::cell::Cell::get)));
        assert_eq!(inside, (BACKGROUND_GIT_IDLE, true));
        assert!(BACKGROUND_GIT_IDLE < crate::settings_sync::lock_wait());
        assert_eq!(git_idle(), GIT_IDLE);
        assert!(!NON_INTERACTIVE.with(std::cell::Cell::get));
        assert_eq!(idle_words(BACKGROUND_GIT_IDLE), "45 seconds");
        assert_eq!(idle_words(GIT_IDLE), "10 minutes");
        // A panic inside puts them back too.
        let caught = std::panic::catch_unwind(|| background(|| panic!("in a pull")));
        assert!(caught.is_err());
        assert_eq!(git_idle(), GIT_IDLE);
        assert!(!NON_INTERACTIVE.with(std::cell::Cell::get));
        // The record of the last pull is Pathwarden's own: a working copy
        // from before the mark that holds it is still taken over.
        assert!(state_entry(LAST_PULL_FILE));
    }

    /// A git that says nothing for too long is stopped, with every process
    /// it started (on Windows `git` is a launcher; here an alias's shell
    /// and its `sleep`): the alias never gets to write its file.
    #[test]
    fn a_silent_git_is_stopped_with_everything_it_started() {
        if crate::spawn::quiet("git")
            .arg("--version")
            .output()
            .is_err()
        {
            assert!(std::env::var_os("CI").is_none(), "git is required in CI");
            eprintln!("git is not installed: skipping this test");
            return;
        }
        let dir = std::env::temp_dir().join(format!("pw-git-idle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let late = dir.join("late.txt");
        let alias = format!(
            "alias.zz=!sleep 4; echo late > '{}'",
            late.to_string_lossy().replace('\\', "/")
        );
        // A ref lock an earlier stopped fetch left goes with the stop.
        run_git(Some(&dir), &["init", "-q"]).unwrap();
        let lock = dir.join(".git/refs/heads/main.lock");
        fs::write(&lock, "x").unwrap();
        let started = std::time::Instant::now();
        let e =
            run_git_idle(Some(&dir), &["-c", &alias, "zz"], Duration::from_secs(1)).unwrap_err();
        assert!(
            format!("{e:#}").contains("gave no sign of progress"),
            "{e:#}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "stopped, not waited for"
        );
        std::thread::sleep(Duration::from_secs(6));
        assert!(
            !late.exists(),
            "the alias's shell and sleep were stopped too"
        );
        assert!(!lock.exists(), "a stale ref lock is removed");
        // Output is a sign of life; a git that finishes is not stopped.
        let out = run_git_idle(None, &["--version"], Duration::from_secs(1)).unwrap();
        assert!(String::from_utf8_lossy(&out).starts_with("git version"));
        remove_tree(&dir).ok();
    }

    /// A process git started that outlives the stop (here one that left
    /// the process group; on Windows a real git that started before the
    /// launcher joined its job) may still be writing: the locks are kept.
    #[cfg(target_os = "linux")]
    #[test]
    fn locks_are_kept_while_a_process_git_started_lives() {
        if crate::spawn::quiet("git")
            .arg("--version")
            .output()
            .is_err()
            || crate::spawn::quiet("setsid")
                .arg("--version")
                .output()
                .is_err()
        {
            eprintln!("git or setsid is not installed: skipping this test");
            return;
        }
        let dir = std::env::temp_dir().join(format!("pw-git-escaped-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        run_git(Some(&dir), &["init", "-q"]).unwrap();
        let lock = dir.join(".git/index.lock");
        fs::write(&lock, "x").unwrap();
        let e = run_git_idle(
            Some(&dir),
            &["-c", "alias.zz=!setsid sleep 9", "zz"],
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(
            format!("{e:#}").contains("gave no sign of progress"),
            "{e:#}"
        );
        assert!(lock.exists(), "a lock a live git may hold is kept");
        let words = format!("{e:#}");
        assert!(
            words.contains(&lock.display().to_string()) && words.contains("safe to remove"),
            "the kept lock is named: {words}"
        );
        // While the escaped process holds the pipes, git counts as running
        // there: the next pull leaves the lock alone.
        assert!(running_git().contains_key(&running_key(&dir)));
        fs::remove_dir_all(&dir).ok();
    }

    /// Lock files a stopped fetch left are removed; ones made after the
    /// stop, and anything else, are not.
    #[test]
    fn locks_a_stopped_git_left_are_removed() {
        let dir = std::env::temp_dir().join(format!("pw-stale-locks-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let git = dir.join(".git");
        let origin = git.join("refs/remotes/origin");
        fs::create_dir_all(&origin).unwrap();
        for f in [
            origin.join("main.lock"),
            git.join("index.lock"),
            origin.join("main"),
        ] {
            fs::write(&f, "x").unwrap();
        }
        let stopped = std::time::SystemTime::now();
        let later = origin.join("other.lock");
        let f = fs::File::create(&later).unwrap();
        f.set_modified(stopped + Duration::from_secs(60)).unwrap();
        drop(f);
        assert_eq!(remove_stale_locks(&git, stopped), 2);
        assert!(!origin.join("main.lock").exists());
        assert!(!git.join("index.lock").exists());
        assert!(origin.join("main").exists());
        assert!(later.exists(), "made after the stop");
        fs::remove_dir_all(&dir).ok();
    }

    fn git_store(dir: &Path) -> Store {
        let cfg = StateConfig {
            backend: StateBackend::Git,
            remote: Some("https://example.invalid/state.git".into()),
            ..StateConfig::default()
        };
        Store::new(&cfg, Some(dir)).unwrap()
    }

    /// Git locks an earlier idle stop kept go before the next fetch, once
    /// older than the idle limit, only while this process holds the
    /// history's lock and runs no git there.
    #[test]
    fn locks_kept_by_an_earlier_stop_go_once_stale() {
        let dir = std::env::temp_dir().join(format!("pw-left-locks-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let git = dir.join(".git");
        let origin = git.join("refs/remotes/origin");
        fs::create_dir_all(&origin).unwrap();
        let old = std::time::SystemTime::now() - GIT_IDLE - Duration::from_secs(60);
        let (index, reflock, fresh) = (
            git.join("index.lock"),
            origin.join("main.lock"),
            origin.join("other.lock"),
        );
        for f in [&index, &reflock, &fresh] {
            let file = fs::File::create(f).unwrap();
            if *f != fresh {
                file.set_modified(old).unwrap();
            }
        }
        let store = git_store(&dir);
        // No history lock held here: nothing is touched.
        assert_eq!(remove_left_locks(&dir), 0);
        assert!(index.exists());
        let lock = store.lock().unwrap();
        // A git of this process still running there: kept.
        {
            let _running = RunningGit::new(&dir);
            assert_eq!(remove_left_locks(&dir), 0);
            assert!(index.exists() && reflock.exists());
        }
        // A process an earlier stop recorded as still running (here this
        // one): kept, whichever Pathwarden asks.
        let me = std::process::id();
        let my_start = match crate::proc_tree::holder(me) {
            crate::proc_tree::Holder::Running {
                started: Some(s), ..
            } => s,
            _ => std::time::SystemTime::now(),
        };
        record_survivors(&git, &[(me, my_start)]);
        assert_eq!(read_survivors(&git).len(), 1, "recorded while it runs");
        assert_eq!(remove_left_locks(&dir), 0);
        assert!(index.exists() && reflock.exists());
        // Once every recorded process has stopped, the record goes too.
        let mut cmd = crate::spawn::quiet(if cfg!(windows) { "cmd" } else { "true" });
        if cfg!(windows) {
            cmd.args(["/c", "exit"]);
        }
        let mut gone = cmd.spawn().unwrap();
        let gone_pid = gone.id();
        gone.wait().unwrap();
        drop(gone);
        fs::write(
            git.join(SURVIVORS_FILE),
            format!("pid {gone_pid} created 1\n"),
        )
        .unwrap();
        assert_eq!(remove_left_locks(&dir), 2);
        assert!(!git.join(SURVIVORS_FILE).exists());
        assert!(!index.exists() && !reflock.exists());
        assert!(fresh.exists(), "younger than the idle limit");
        drop(lock);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn kept_locks_are_named_with_what_to_do() {
        assert_eq!(kept_locks_words(&[]), "");
        let one = kept_locks_words(&[PathBuf::from("w/.git/index.lock")]);
        assert!(one.contains("this git lock file was kept:"), "{one}");
        assert!(one.contains("index.lock. It is safe to remove"), "{one}");
        assert!(one.ends_with("once no git is running there."), "{one}");
        let two = kept_locks_words(&[
            PathBuf::from("w/.git/index.lock"),
            PathBuf::from("w/.git/HEAD.lock"),
        ]);
        assert!(two.contains("index.lock, w"), "{two}");
        assert!(two.contains("They are safe to remove"), "{two}");
    }

    /// Lines of `.git/info/exclude` compare as git reads them: a leading
    /// space is part of the pattern, trailing ones are not.
    #[test]
    fn exclude_lines_compare_as_git_reads_them() {
        assert_eq!(git_pattern("/.pathwarden.lock"), "/.pathwarden.lock");
        assert_eq!(git_pattern("/.pathwarden.lock   "), "/.pathwarden.lock");
        assert_eq!(git_pattern("  /.pathwarden.lock"), "  /.pathwarden.lock");
        assert_eq!(git_pattern("/a\\  "), "/a\\ ");

        let dir = std::env::temp_dir().join(format!("pw-exclude-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let info = dir.join(".git/info");
        fs::create_dir_all(&info).unwrap();
        // A byte order mark before the first line, as Notepad may write.
        let mine = format!("\u{feff}/{TAKING_FILE}\r\n  /{LOCK_FILE}\r\n/{CLONING_DIR}  \r\n");
        fs::write(info.join("exclude"), &mine).unwrap();
        git_store(&dir).exclude_own_files().unwrap();
        let text = fs::read_to_string(info.join("exclude")).unwrap();
        assert!(text.starts_with(&mine), "the user's lines stay: {text:?}");
        let added: Vec<&str> = text[mine.len()..].lines().collect();
        assert!(
            added.contains(&format!("/{LOCK_FILE}").as_str()),
            "{text:?}"
        );
        for present in [CLONING_DIR, TAKING_FILE] {
            assert!(
                !added.contains(&format!("/{present}").as_str()),
                "present already: {text:?}"
            );
        }
        // Once listed, nothing more is added.
        git_store(&dir).exclude_own_files().unwrap();
        assert_eq!(fs::read_to_string(info.join("exclude")).unwrap(), text);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_messages_leave_progress_out() {
        let err = b"Enumerating objects: 5, done.\nCounting objects:  20% (1/5)\rCounting objects: 100% (5/5), done.\nremote: Resolving deltas: 100% (1/1)\nTo C:/x.git\n ! [remote rejected] main -> main (pre-receive hook declined)\nerror: failed to push some refs\n";
        assert_eq!(
            git_message(err),
            "To C:/x.git\n! [remote rejected] main -> main (pre-receive hook declined)\nerror: failed to push some refs"
        );
    }

    /// A scheduled task may write only inside its state folder, not next to
    /// it (the folder above holds the programs it runs).
    #[test]
    fn a_local_lock_stays_inside_the_state_folder() {
        let dir = std::env::temp_dir().join(format!("pw-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let state = dir.join("pathwarden-state");
        let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
        assert_eq!(store.lock_path(), state.join(LOCK_FILE));
        let lock = store.lock().unwrap();
        assert!(state.join(LOCK_FILE).exists());
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            1,
            "nothing beside the state folder"
        );
        assert!(store.lock().is_err(), "a second run is refused");
        drop(lock);
        assert!(!state.join(LOCK_FILE).exists(), "released");
        fs::remove_dir_all(&dir).ok();
    }

    /// Run by [`Store::lock`] just after it made the lock file of `path`,
    /// before it returns the lock: what a test set for that path.
    type AfterCreate = Option<(PathBuf, Box<dyn FnOnce() + Send>)>;
    static AFTER_CREATE: std::sync::Mutex<AfterCreate> = std::sync::Mutex::new(None);

    pub(super) fn after_create(path: &Path) {
        let f = {
            let mut g = AFTER_CREATE.lock().unwrap_or_else(|e| e.into_inner());
            match g.take() {
                Some((p, f)) if p == path => Some(f),
                other => {
                    *g = other;
                    None
                }
            }
        };
        if let Some(f) = f {
            f();
        }
    }

    /// Another task of this process that finds the lock file in the moment
    /// between its making and the lock being returned sees it held here:
    /// it never takes it over as left.
    #[test]
    fn a_lock_being_taken_is_held_here_already() {
        let dir = std::env::temp_dir().join(format!("pw-taking-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let state = dir.join("pathwarden-state");
        fs::create_dir_all(&state).unwrap();
        let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (state2, ran2) = (state.clone(), ran.clone());
        *AFTER_CREATE.lock().unwrap() = Some((
            store.lock_path(),
            Box::new(move || {
                let other = Store::new(&StateConfig::default(), Some(&state2)).unwrap();
                let e = std::thread::spawn(move || other.lock().map(drop))
                    .join()
                    .unwrap()
                    .expect_err("the lock is being taken");
                let e = format!("{e:#}");
                assert!(e.contains(HELD_HERE), "{e}");
                ran2.store(true, std::sync::atomic::Ordering::SeqCst);
            }),
        ));
        let lock = store.lock().unwrap();
        assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
        assert!(fs::read_to_string(store.lock_path())
            .unwrap()
            .contains(&lock.token));
        drop(lock);
        fs::remove_dir_all(&dir).ok();
    }

    /// A take-over guard a stopped run left is old, or dated in the
    /// future; a fresh one isn't, nor one that isn't there.
    #[test]
    fn a_left_take_over_guard_is_old_or_from_the_future() {
        let dir = std::env::temp_dir().join(format!("pw-guard-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let guard = dir.join(TAKING_FILE);
        assert!(!guard_left(&guard));
        let f = fs::File::create(&guard).unwrap();
        assert!(!guard_left(&guard), "fresh");
        let now = std::time::SystemTime::now();
        f.set_modified(now - Duration::from_secs(120)).unwrap();
        assert!(guard_left(&guard), "old");
        f.set_modified(now + Duration::from_secs(3600)).unwrap();
        assert!(guard_left(&guard), "from the future");
        drop(f);
        // A left one doesn't keep a take-over out.
        let state = dir.join("state");
        fs::create_dir_all(&state).unwrap();
        let g = fs::File::create(state.join(TAKING_FILE)).unwrap();
        g.set_modified(now + Duration::from_secs(3600)).unwrap();
        drop(g);
        fs::write(
            state.join(LOCK_FILE),
            format!("host {} pid {} token gone\n", this_host(), stopped_pid()),
        )
        .unwrap();
        let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
        drop(store.lock().unwrap());
        assert!(!state.join(TAKING_FILE).exists());
        fs::remove_dir_all(&dir).ok();
    }

    /// Runs taking over the same left lock at once: one gets it.
    #[test]
    fn one_run_takes_over_a_left_lock() {
        let dir = std::env::temp_dir().join(format!("pw-race-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let state = dir.join("pathwarden-state");
        fs::create_dir_all(&state).unwrap();
        let left = format!("host {} pid {} token gone\n", this_host(), stopped_pid());
        for _ in 0..5 {
            fs::write(state.join(LOCK_FILE), &left).unwrap();
            let n = 8;
            let gate = std::sync::Barrier::new(n);
            let done = std::sync::Barrier::new(n);
            let got = std::thread::scope(|s| {
                let handles: Vec<_> = (0..n)
                    .map(|_| {
                        s.spawn(|| {
                            let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
                            gate.wait();
                            let l = store.lock();
                            done.wait();
                            l.is_ok()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .filter(|ok| *ok)
                    .count()
            });
            assert_eq!(got, 1);
            assert!(!state.join(LOCK_FILE).exists(), "released");
            let others: Vec<_> = fs::read_dir(&state).unwrap().flatten().collect();
            assert!(others.is_empty(), "nothing moved aside is left: {others:?}");
        }
        fs::remove_dir_all(&dir).ok();
    }

    fn holder_of(host: &str, pid: u32, token: &str) -> LockHolder {
        LockHolder::parse(&format!("host {host} pid {pid} token {token}\n"))
    }

    #[test]
    fn lock_files_are_read() {
        assert_eq!(
            LockHolder::parse("host HQ01 pid 43108 token 00ab\n"),
            LockHolder {
                host: Some("HQ01".into()),
                pid: Some(43108),
                token: Some("00ab".into()),
                started: None,
            }
        );
        assert_eq!(
            LockHolder::parse("host HQ01 pid 1 token t started 1800000000").started,
            Some(1_800_000_000)
        );
        assert_eq!(LockHolder::parse("x"), LockHolder::default());
        assert_eq!(LockHolder::parse("host a pid nope").pid, None);
    }

    /// A lock this computer's stopped Pathwarden left is taken over at
    /// once; one of another computer, or of a Pathwarden still running
    /// here, is not; one naming this process is never another run's.
    #[test]
    fn whose_lock_it_is() {
        use crate::proc_tree::Holder;
        let here = this_host();
        let fresh = Duration::from_secs(60);
        let then = std::time::SystemTime::now() - Duration::from_secs(3600);
        let running = |program: &str, started: std::time::SystemTime| {
            let program = program.to_string();
            move |_| Holder::Running {
                program: program.clone(),
                started: Some(started),
            }
        };
        let never = |_| -> Holder { panic!("another computer's process isn't looked up") };
        // Another computer's: held until stale.
        let other = holder_of("SOMEWHERE-ELSE", 4, "t");
        assert_eq!(
            lock_verdict(&other, fresh, never),
            LockVerdict::HeldElsewhere
        );
        assert_eq!(
            lock_verdict(&other, STALE_LOCK + fresh, never),
            LockVerdict::Left
        );
        // This computer's, its process stopped: at once.
        let mine = holder_of(&here.to_ascii_lowercase(), 43108, "t");
        assert_eq!(
            lock_verdict(&mine, fresh, |_| Holder::Gone),
            LockVerdict::Left
        );
        // Its ID now another program's.
        assert_eq!(
            lock_verdict(&mine, fresh, running("notepad.exe", then)),
            LockVerdict::Left
        );
        // A Pathwarden running: held, unless the lock says it was written
        // by a process that started at another time (the ID used again).
        assert_eq!(
            lock_verdict(&mine, fresh, running("Pathwarden.exe", then)),
            LockVerdict::HeldElsewhere
        );
        let wrote = LockHolder {
            started: unix_secs(then),
            ..holder_of(&here, 43108, "t")
        };
        assert_eq!(
            lock_verdict(&wrote, fresh, running("pathwarden.exe", then)),
            LockVerdict::HeldElsewhere
        );
        assert_eq!(
            lock_verdict(
                &wrote,
                fresh,
                running("pathwarden.exe", then + Duration::from_secs(600))
            ),
            LockVerdict::Left
        );
        // Can't be told: held.
        assert_eq!(
            lock_verdict(&mine, fresh, |_| Holder::Unknown),
            LockVerdict::HeldElsewhere
        );
        // This process: held here while one of its locks has the token,
        // else nothing holds it.
        let me = std::process::id();
        assert_eq!(
            lock_verdict(&holder_of(&here, me, "not-held"), fresh, never),
            LockVerdict::Left
        );
        held_here().insert("held-token".into());
        assert_eq!(
            lock_verdict(&holder_of(&here, me, "held-token"), fresh, never),
            LockVerdict::HeldHere
        );
        held_here().remove("held-token");
        assert!(is_pathwarden("pathwarden.exe"));
        assert!(is_pathwarden("Pathwarden Desktop.exe"));
        assert!(!is_pathwarden("git.exe"));
    }

    /// A stopped process's ID, which nothing may hold now.
    fn stopped_pid() -> u32 {
        let mut cmd = crate::spawn::quiet(if cfg!(windows) { "cmd" } else { "true" });
        if cfg!(windows) {
            cmd.args(["/c", "exit"]);
        }
        let mut child = cmd.spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// The lock files a stopped Pathwarden of this computer leaves, and the
    /// one a lock this process failed to remove leaves, are taken over at
    /// once; a lock another task of this process holds is waited for, and
    /// never called another run's.
    #[test]
    fn this_computer_s_left_locks_are_taken_over_at_once() {
        let dir = std::env::temp_dir().join(format!("pw-left-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let state = dir.join("pathwarden-state");
        let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
        fs::create_dir_all(&state).unwrap();
        let here = this_host();
        for left in [
            format!("host {here} pid {} token gone\n", stopped_pid()),
            format!("host {here} pid {} token nobody\n", std::process::id()),
        ] {
            fs::write(store.lock_path(), &left).unwrap();
            let lock = store.lock().unwrap_or_else(|e| panic!("{left}: {e:#}"));
            let now = fs::read_to_string(store.lock_path()).unwrap();
            assert!(!now.contains(&left), "{now}");
            // When it started, so a later process with its ID is told apart.
            if cfg!(windows) {
                assert!(now.contains(" started "), "{now}");
            }
            drop(lock);
            assert!(!store.lock_path().exists());
        }
        // A program that isn't Pathwarden, running under the ID.
        let mut cmd = crate::spawn::quiet(if cfg!(windows) { "ping" } else { "sleep" });
        if cfg!(windows) {
            cmd.args(["-n", "30", "127.0.0.1"]);
        } else {
            cmd.arg("30");
        }
        cmd.stdout(std::process::Stdio::null());
        let mut other = cmd.spawn().unwrap();
        fs::write(
            store.lock_path(),
            format!("host {here} pid {} token ping\n", other.id()),
        )
        .unwrap();
        let taken = store.lock();
        let _ = other.kill();
        let _ = other.wait();
        drop(taken.unwrap());

        // Held by another task here (the app's pull, say): waited for, and
        // said so.
        let lock = store.lock().unwrap();
        let other = Store::new(&StateConfig::default(), Some(&state)).unwrap();
        let e =
            std::thread::scope(|s| s.spawn(|| other.lock().err()).join().unwrap()).expect("held");
        let e = format!("{e:#}");
        assert!(e.contains(HELD_HERE), "{e}");
        assert!(!e.contains("another pathwarden run"), "{e}");
        let waited = std::thread::scope(|s| {
            let t = s.spawn(|| other.lock_waiting(Duration::from_secs(20)).map(|_| ()));
            std::thread::sleep(Duration::from_millis(600));
            drop(lock);
            t.join().unwrap()
        });
        waited.unwrap();
        // Another computer's fresh lock still holds.
        fs::write(store.lock_path(), "host SOMEWHERE-ELSE pid 1 token x\n").unwrap();
        let e = format!("{:#}", store.lock().err().unwrap());
        assert!(e.contains("another pathwarden run is using"), "{e}");
        fs::remove_dir_all(&dir).ok();
    }

    /// Run by [`a_running_pathwarden_s_lock_holds`] as the other Pathwarden.
    #[test]
    #[ignore = "a helper process"]
    fn a_pathwarden_that_keeps_running() {
        if std::env::var_os("PW_LOCK_HOLDER").is_some() {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    /// A lock of another Pathwarden running on this computer holds.
    #[test]
    fn a_running_pathwarden_s_lock_holds() {
        let dir = std::env::temp_dir().join(format!("pw-live-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let state = dir.join("pathwarden-state");
        fs::create_dir_all(&state).unwrap();
        let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
        let mut cmd = crate::spawn::quiet(std::env::current_exe().unwrap());
        cmd.args([
            "--ignored",
            "--exact",
            "store::tests::a_pathwarden_that_keeps_running",
        ])
        .env("PW_LOCK_HOLDER", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
        let mut other = cmd.spawn().unwrap();
        // Made after it started.
        std::thread::sleep(Duration::from_millis(1500));
        fs::write(
            store.lock_path(),
            format!("host {} pid {} token other\n", this_host(), other.id()),
        )
        .unwrap();
        let held = store.lock().err();
        // The same ID, written by a process that started long before: not
        // this one's, so taken over.
        fs::write(
            store.lock_path(),
            format!(
                "host {} pid {} token older started 1000000000\n",
                this_host(),
                other.id()
            ),
        )
        .unwrap();
        let reused = store.lock().map(drop);
        let _ = other.kill();
        let _ = other.wait();
        let e = format!("{:#}", held.expect("held by the other Pathwarden"));
        assert!(e.contains("another pathwarden run is using"), "{e}");
        if cfg!(windows) {
            reused.unwrap();
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp_files() {
        let dir = std::env::temp_dir().join(format!("pw-atomic-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("findings.json");
        write_atomic(&path, b"{\"a\": 1}").unwrap();
        write_atomic(&path, b"{\"a\": 2}").unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains('2'));
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    /// The marker and kept-commit checks answer from what `.git`'s files
    /// say only when they say it for sure: a branch's loose ref or packed
    /// line, or "unborn" when neither file is there. A detached HEAD, the
    /// reftable format, a ref that can't be read or a packed-refs without
    /// the branch: no answer, so git is asked (and nothing is kept).
    #[test]
    fn refs_are_read_from_files_only_when_they_say_for_sure() {
        let dir = std::env::temp_dir().join(format!("pw-refs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let git = dir.join(".git");
        let id = "0123456789abcdef0123456789abcdef01234567";
        let fresh = || {
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(git.join("refs").join("heads")).unwrap();
            fs::write(git.join("config"), "[core]\n\tbare = false\n").unwrap();
            fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        };
        // A branch with no commit yet, then with one, loose or packed.
        fresh();
        assert_eq!(head_commit(&dir).as_deref(), Some("unborn refs/heads/main"));
        fs::write(git.join("refs/heads/main"), format!("{id}\n")).unwrap();
        assert_eq!(head_commit(&dir).as_deref(), Some(id));
        fs::remove_file(git.join("refs/heads/main")).unwrap();
        fs::write(
            git.join("packed-refs"),
            format!("# pack-refs\n{id} refs/heads/main\n"),
        )
        .unwrap();
        assert_eq!(head_commit(&dir).as_deref(), Some(id));
        // packed-refs without the branch: not "unborn".
        fs::write(git.join("packed-refs"), format!("{id} refs/heads/other\n")).unwrap();
        assert_eq!(head_commit(&dir), None);
        // Detached.
        fresh();
        fs::write(git.join("HEAD"), format!("{id}\n")).unwrap();
        assert_eq!(head_commit(&dir), None);
        // Reftable: its stub HEAD, its folder, or the config's extension.
        fresh();
        fs::write(git.join("HEAD"), "ref: refs/heads/.invalid\n").unwrap();
        assert_eq!(head_commit(&dir), None);
        fresh();
        fs::create_dir_all(git.join("reftable")).unwrap();
        assert_eq!(head_commit(&dir), None);
        fresh();
        fs::write(
            git.join("config"),
            "[core]\n\trepositoryformatversion = 1\n[extensions]\n\trefStorage = reftable\n",
        )
        .unwrap();
        assert_eq!(head_commit(&dir), None);
        // A ref that can't be read (here a folder where the file goes).
        fresh();
        fs::create_dir_all(git.join("refs/heads/main")).unwrap();
        assert_eq!(head_commit(&dir), None);
        // `.git` a file (a linked work tree).
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(&git, "gitdir: elsewhere\n").unwrap();
        assert_eq!(head_commit(&dir), None);
        let _ = fs::remove_dir_all(&dir);
    }

    /// With a reftable repository (when this git makes them) and a
    /// detached HEAD, the encryption-marker check asks git every time and
    /// keeps nothing.
    #[test]
    fn the_marker_check_keeps_nothing_it_cant_key() {
        if crate::spawn::quiet("git")
            .arg("--version")
            .output()
            .is_err()
        {
            assert!(std::env::var_os("CI").is_none(), "git is required in CI");
            return;
        }
        let base = std::env::temp_dir().join(format!("pw-marker-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let kept = |dir: &Path| removed_by_cache().contains_key(dir);
        let commit = |dir: &Path| {
            fs::write(dir.join("x.txt"), "x").unwrap();
            run_git(Some(dir), &["add", "x.txt"]).unwrap();
            run_git(
                Some(dir),
                &[
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@t",
                    "commit",
                    "-q",
                    "-m",
                    "x",
                ],
            )
            .unwrap();
        };
        // Reftable, if this git can.
        let table = base.join("table");
        fs::create_dir_all(&table).unwrap();
        if run_git(Some(&table), &["init", "-q", "--ref-format=reftable"]).is_ok() {
            commit(&table);
            assert_eq!(head_commit(&table), None);
            let before = git_runs();
            assert_eq!(marker_removed_by(&table).unwrap(), None);
            assert_eq!(marker_removed_by(&table).unwrap(), None);
            assert!(git_runs() >= before + 2, "asked git each time");
            assert!(!kept(&table));
        }
        // Plain refs: kept by HEAD's commit; detached: never.
        let plain = base.join("plain");
        fs::create_dir_all(&plain).unwrap();
        run_git(Some(&plain), &["init", "-q"]).unwrap();
        commit(&plain);
        assert_eq!(marker_removed_by(&plain).unwrap(), None);
        assert!(kept(&plain));
        // Answered from what was kept (other tests run git at the same
        // time, so the count can't tell): a marked answer comes back.
        let head = head_commit(&plain).expect("a branch's commit");
        removed_by_cache().insert(plain.clone(), (head.clone(), Some("kept".into())));
        assert_eq!(marker_removed_by(&plain).unwrap().as_deref(), Some("kept"));
        assert_eq!(
            removed_by_cache().get(&plain),
            Some(&(head, Some("kept".to_string())))
        );
        removed_by_cache().remove(&plain);
        run_git(Some(&plain), &["checkout", "-q", "--detach"]).unwrap();
        // Detached: git is asked, and refuses (fails closed).
        assert!(marker_removed_by(&plain).is_err());
        assert!(!kept(&plain));
        let _ = fs::remove_dir_all(&base);
    }

    /// Every git command runs unable to prompt (gap 15): no terminal
    /// prompt, SSH in batch mode, nothing on standard input, Git Credential
    /// Manager's window off in work nobody watches; without the variables
    /// that point git at another repository, and without the passphrase.
    #[test]
    fn git_never_prompts() {
        let env_of = |cmd: &std::process::Command| -> Vec<(String, Option<String>)> {
            cmd.get_envs()
                .map(|(k, v)| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.map(|v| v.to_string_lossy().into_owned()),
                    )
                })
                .collect()
        };
        let has = |env: &[(String, Option<String>)], k: &str, v: Option<&str>| {
            env.iter().any(|(ek, ev)| ek == k && ev.as_deref() == v)
        };
        let cmd = git_command(Some(Path::new("C:/contoso")), &["fetch"], &[]);
        let env = env_of(&cmd);
        assert!(has(&env, "GIT_TERMINAL_PROMPT", Some("0")), "{env:?}");
        if std::env::var_os("GIT_SSH_COMMAND").is_none() && std::env::var_os("GIT_SSH").is_none() {
            assert!(
                has(&env, "GIT_SSH_COMMAND", Some("ssh -o BatchMode=yes")),
                "{env:?}"
            );
        }
        for var in GIT_LOCAL_ENV
            .iter()
            .chain(&[keystore::ENV_VAR, keystore::NEW_ENV_VAR])
        {
            assert!(has(&env, var, None), "{var} is not removed: {env:?}");
        }
        assert!(!env.iter().any(|(k, _)| k == "GCM_INTERACTIVE"), "{env:?}");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.contains(&"core.symlinks=false".to_string()),
            "{args:?}"
        );
        assert_eq!(args.last().map(String::as_str), Some("fetch"));
        let env = non_interactive(|| env_of(&git_command(None, &["fetch"], &[])));
        assert!(has(&env, "GCM_INTERACTIVE", Some("never")), "{env:?}");
        // Back as it was after the background work.
        let env = env_of(&git_command(None, &["fetch"], &[]));
        assert!(!env.iter().any(|(k, _)| k == "GCM_INTERACTIVE"), "{env:?}");
        // And git really gets nothing to read a password from.
        if run_git(None, &["--version"]).is_ok() {
            let dir = std::env::temp_dir().join(format!("pw-noprompt-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let e = run_git(
                Some(&dir),
                &["ls-remote", "https://127.0.0.1:9/contoso/state.git"],
            );
            assert!(e.is_err());
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// A held lock's time is renewed while its run goes on (gap 22),
    /// so a run longer than [`STALE_LOCK`] keeps it; a lock another run
    /// took over is left alone, and renewing stops with the lock.
    #[test]
    fn a_held_lock_is_kept_fresh() {
        let dir = std::env::temp_dir().join(format!("pw-renew-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lock");
        fs::write(&path, "host H pid 1 token mine").unwrap();
        let old = std::time::SystemTime::now() - STALE_LOCK - Duration::from_secs(60);
        let age = |p: &Path| {
            fs::metadata(p)
                .unwrap()
                .modified()
                .unwrap()
                .elapsed()
                .unwrap_or_default()
        };
        let set_old = |p: &Path| {
            fs::File::options()
                .write(true)
                .open(p)
                .unwrap()
                .set_modified(old)
                .unwrap()
        };
        set_old(&path);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let p = path.clone();
        let worker =
            std::thread::spawn(move || renew_lock(&p, "mine", &rx, Duration::from_millis(20)));
        let start = std::time::Instant::now();
        while age(&path) > STALE_LOCK {
            assert!(start.elapsed() < Duration::from_secs(10), "never renewed");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(age(&path) < Duration::from_secs(60));
        // Taken over by another run: its time is not this run's to renew.
        fs::write(&path, "host H pid 2 token theirs").unwrap();
        // (A renewal that read the file before it was replaced is done.)
        std::thread::sleep(Duration::from_millis(50));
        set_old(&path);
        std::thread::sleep(Duration::from_millis(150));
        assert!(age(&path) > STALE_LOCK);
        // Dropping the lock's sender stops the renewing.
        drop(tx);
        worker.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    /// A history's `.gitattributes` may set line endings and "binary"
    /// only (gap 15).
    #[test]
    fn only_line_ending_attributes_are_allowed() {
        for ok in [
            "",
            "# comment\n\n* text=auto\n",
            "* text=auto eol=lf\n*.age binary\n*.json -diff -merge !filter\n",
            "*.txt text eol=crlf\n*.sln merge=union\n\"a b\" -text\n",
        ] {
            assert_eq!(unsafe_attribute(ok), None, "{ok}");
        }
        for (bad, attr) in [
            ("*.json filter=lfs\n", "filter=lfs"),
            ("* text\n*.json diff=contoso\n", "diff=contoso"),
            ("*.json merge=fabrikam\n", "merge=fabrikam"),
            ("*.json ident\n", "ident"),
            (
                "*.json working-tree-encoding=UTF-16\n",
                "working-tree-encoding=UTF-16",
            ),
            ("\"a \\\" b\" filter=x\n", "filter=x"),
            ("*.json text=crlf\n", "text=crlf"),
            ("*.json -diff=x\n", "-diff=x"),
        ] {
            assert_eq!(unsafe_attribute(bad).as_deref(), Some(attr), "{bad}");
        }
        assert!(unsafe_attribute("[attr]plain filter=x\n").is_some());
        assert!(unsafe_attribute("\"unclosed filter=x\n").is_some());
    }

    /// A repository URL with a password or token is refused, as the app
    /// refuses it (gap 15); a user name alone is fine.
    #[test]
    fn a_remote_with_a_password_or_token_is_refused() {
        let dir = std::env::temp_dir().join(format!("pw-token-url-{}", std::process::id()));
        let new = |remote: &str| {
            Store::new(
                &StateConfig {
                    backend: StateBackend::Git,
                    remote: Some(remote.into()),
                    ..StateConfig::default()
                },
                Some(&dir),
            )
        };
        for bad in [
            "https://someone:secret@git.contoso.com/state.git",
            "https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@git.contoso.com/state.git",
            "https://abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP@dev.azure.com/x",
        ] {
            let e = format!("{:#}", new(bad).err().expect(bad));
            assert!(e.contains("password or token"), "{e}");
            assert!(!e.contains("secret") && !e.contains("ghp_"), "{e}");
        }
        for ok in [
            "https://git.contoso.com/state.git",
            "https://contoso@dev.azure.com/contoso/p/_git/state",
            "git@git.contoso.com:team/state.git",
            "C:/contoso/state.git",
        ] {
            new(ok).expect(ok);
        }
    }

    /// The history's findings state, latest run, points and timings are
    /// read only up to their caps (gap 9): a point too large is
    /// skipped and named, a findings state too large counts as damaged.
    #[test]
    fn history_files_have_size_caps() {
        let dir = std::env::temp_dir().join(format!("pw-caps-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("history")).unwrap();
        fs::create_dir_all(dir.join("timings")).unwrap();
        let big = |rel: &str, plain: u64| {
            let f = fs::File::create(dir.join(rel)).unwrap();
            f.set_len(max_on_disk(plain) + 1).unwrap();
        };
        let store = Store::new(&StateConfig::default(), Some(&dir)).unwrap();
        // Not written: a GiB on disk for a test.
        assert_eq!(max_state_bytes("findings.json"), Some(1 << 30));
        assert_eq!(max_state_bytes(crate::exposed::FILE), None);
        big("last-run.json", 64 << 20);
        let e = format!("{:#}", store.read_state_file("last-run.json").unwrap_err());
        assert!(e.contains("larger than 64 MiB"), "{e}");
        assert!(last_run(&store).is_none());
        let id = "20261018T120000.000Z";
        big(&format!("history/{id}.json"), 16 << 20);
        let (points, skipped) = crate::history::load(&dir).unwrap();
        assert!(points.is_empty());
        assert!(skipped.iter().any(|s| s.contains(id)), "{skipped:?}");
        big(&format!("timings/{id}.json"), 16 << 20);
        assert!(run_timings(&dir, id).is_none());
        // A findings state that isn't one counts as damaged: a run starts
        // afresh, with a note.
        fs::write(dir.join("findings.json"), "not json").unwrap();
        let e = store.load().unwrap_err();
        assert!(e.downcast_ref::<DamagedFindings>().is_some(), "{e:#}");
        assert!(format!("{e:#}").contains("can't be read"), "{e:#}");
        let (state, note) = store.load_for_run().unwrap();
        assert!(state.findings.is_empty());
        let note = note.unwrap();
        assert!(note.contains("no earlier findings"), "{note}");
        assert!(!note.contains("earlier commits"), "a folder: {note}");
        let _ = fs::remove_dir_all(&dir);
    }

    thread_local! {
        /// Run by [`Store::rewrite`] once it has staged every file, before
        /// it takes the pending lock: what a test of this thread set.
        static DURING_REWRITE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn during_rewrite() {
        if let Some(f) = DURING_REWRITE.with(|h| h.borrow_mut().take()) {
            f();
        }
    }

    /// A rewrite that runs past the pending lock's stale age (here: an age
    /// of nothing, as if 30 seconds went by) keeps a save another process
    /// made meanwhile: it is sealed again with the new key, not lost.
    #[test]
    fn a_save_made_during_a_long_rewrite_is_kept() {
        use crate::action_log::{self, Activity, Change};
        let dir = std::env::temp_dir().join(format!("pw-rewrite-pending-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let work = dir.join("work");
        fs::create_dir_all(&work).unwrap();
        if run_git(Some(&work), &["init", "-q"]).is_err() {
            assert!(std::env::var_os("CI").is_none(), "git is required in CI");
            return;
        }
        crate::keystore::use_test_store(&dir.join("ks"));
        let store = git_store(&work);
        store.write_state_file("last-run.json", b"{}").unwrap();
        let first = crypt::SecretString::from("first passphrase here".to_string());
        let second = crypt::SecretString::from("second passphrase here".to_string());
        store.rewrite(Some(&first)).unwrap();
        crypt::give_passphrase(&work, first);
        let change = |at: &str| Change {
            fingerprint: "PW-001-aaaa".into(),
            activity: Activity {
                at: at.into(),
                action: "service-desk/open".into(),
                ..Activity::default()
            },
            records: Vec::new(),
            removed: Vec::new(),
        };
        action_log::add_pending(&store, &change("2026-11-18T14:00:00.000Z")).unwrap();
        assert_eq!(action_log::pending_count(&store), 1);
        let other = git_store(&work);
        DURING_REWRITE.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                action_log::TEST_STALE_AFTER.with(|s| s.set(Some(std::time::Duration::ZERO)));
                action_log::add_pending(&other, &change("2026-11-18T15:00:00.000Z")).unwrap();
                action_log::TEST_STALE_AFTER.with(|s| s.set(None));
            }))
        });
        store.rewrite(Some(&second)).unwrap();
        assert!(
            DURING_REWRITE.with(|h| h.borrow().is_none()),
            "the hook ran"
        );
        crypt::give_passphrase(&work, second);
        let bytes = fs::read(work.join(".git").join(action_log::PENDING_FILE)).unwrap();
        assert!(bytes.starts_with(b"age-encryption.org/"));
        assert_eq!(action_log::pending_count(&store), 2, "both saves kept");
        assert!(!work
            .join(".git")
            .join(format!("{}.lock", action_log::PENDING_FILE))
            .exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The same while decrypting: a save made during the rewrite (sealed
    /// with the old key) is kept, and the file ends up plain.
    #[test]
    fn a_save_made_during_a_long_decrypt_is_kept() {
        use crate::action_log::{self, Activity, Change};
        let dir = std::env::temp_dir().join(format!("pw-decrypt-pending-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let work = dir.join("work");
        fs::create_dir_all(&work).unwrap();
        if run_git(Some(&work), &["init", "-q"]).is_err() {
            assert!(std::env::var_os("CI").is_none(), "git is required in CI");
            return;
        }
        crate::keystore::use_test_store(&dir.join("ks"));
        let store = git_store(&work);
        store.write_state_file("last-run.json", b"{}").unwrap();
        let first = crypt::SecretString::from("first passphrase here".to_string());
        store.rewrite(Some(&first)).unwrap();
        crypt::give_passphrase(&work, first);
        let change = |at: &str| Change {
            fingerprint: "PW-001-aaaa".into(),
            activity: Activity {
                at: at.into(),
                action: "service-desk/open".into(),
                ..Activity::default()
            },
            records: Vec::new(),
            removed: Vec::new(),
        };
        action_log::add_pending(&store, &change("2026-11-18T14:00:00.000Z")).unwrap();
        let pending = work.join(".git").join(action_log::PENDING_FILE);
        assert!(fs::read(&pending)
            .unwrap()
            .starts_with(b"age-encryption.org/"));
        let other = git_store(&work);
        DURING_REWRITE.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                action_log::TEST_STALE_AFTER.with(|s| s.set(Some(std::time::Duration::ZERO)));
                action_log::add_pending(&other, &change("2026-11-18T15:00:00.000Z")).unwrap();
                action_log::TEST_STALE_AFTER.with(|s| s.set(None));
            }))
        });
        store.rewrite(None).unwrap();
        assert!(
            DURING_REWRITE.with(|h| h.borrow().is_none()),
            "the hook ran"
        );
        assert!(!crypt::is_encrypted(&work));
        let bytes = fs::read(&pending).unwrap();
        assert!(bytes.starts_with(b"{"), "plain");
        assert_eq!(action_log::pending_count(&store), 2, "both saves kept");
        let _ = fs::remove_dir_all(&dir);
    }
}
