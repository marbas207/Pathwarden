//! Opening a shared history on a new computer: looking at a git
//! repository or a shared folder before anything is saved, what it holds,
//! whether a passphrase opens it, and whether this account can push to it.
//! The app's Connect to a run history page and `pathwarden history
//! storage probe|connect` / `pathwarden env create --from-git` use this
//! module, so they say the same sentences.
//!
//! Nothing here changes the repository: the clone is made in a folder the
//! caller created ([`probe`]'s `scratch`), with the same checks as every
//! pull ([`Store::pull`]), and the write-access check is `git push
//! --dry-run`, which pushes nothing.

use std::path::{Path, PathBuf};

use crate::config::{Keep, StateBackend, StateConfig};
use crate::crypt;
use crate::store::{self, Store};

/// Where the shared history is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Where {
    /// A git repository; `branch` `None`: the repository's default branch.
    Git { url: String, branch: Option<String> },
    /// A shared folder.
    Folder(PathBuf),
}

impl Where {
    pub fn is_git(&self) -> bool {
        matches!(self, Where::Git { .. })
    }
}

/// Why the shared history can't be connected to (step 1 of the page). Each
/// says itself in two parts: the lead (shown bold) and the rest; git's own
/// message, when there is one, goes behind an (i) ([`Problem::detail`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The URL can't be used as it is (empty, an option, a password in it).
    BadUrl(String),
    /// Git couldn't reach the repository.
    Unreachable { detail: String },
    /// The repository refused the sign-in (or hides itself without one).
    /// `no_helper`: git here has no credential helper, so it couldn't ask
    /// for an account ([`no_helper`]).
    /// `refused`: it refused the account git gave ([`refused`]).
    SignIn {
        detail: String,
        no_helper: bool,
        refused: bool,
    },
    /// The branch asked for isn't there.
    NoBranch {
        branch: String,
        branches: Vec<String>,
    },
    /// It holds other files.
    NotHistory { git: bool },
    /// Nothing in it yet: a new shared history can start there.
    Empty { git: bool },
    /// A newer Pathwarden wrote it.
    Newer { version: Option<String> },
    /// The repository's default branch has a name Pathwarden refuses.
    BadDefaultBranch,
    /// The folder isn't there, or can't be read.
    NoFolder,
    /// Anything else, in its own words.
    Failed(String),
}

impl Problem {
    /// A short key for JSON and the page: "unreachable", "sign_in", ...
    pub fn key(&self) -> &'static str {
        match self {
            Problem::BadUrl(_) => "bad_url",
            Problem::Unreachable { .. } => "unreachable",
            Problem::SignIn { .. } => "sign_in",
            Problem::NoBranch { .. } => "no_branch",
            Problem::NotHistory { .. } => "not_history",
            Problem::Empty { .. } => "empty",
            Problem::Newer { .. } => "newer",
            Problem::BadDefaultBranch => "bad_default_branch",
            Problem::NoFolder => "no_folder",
            Problem::Failed(_) => "failed",
        }
    }

    /// The first sentence, shown bold.
    pub fn lead(&self) -> String {
        match self {
            Problem::BadUrl(m) | Problem::Failed(m) => m.clone(),
            Problem::Unreachable { .. } => "Pathwarden couldn't reach the repository.".into(),
            Problem::SignIn { refused: true, .. } => REFUSED.into(),
            Problem::SignIn { .. } => NOT_SIGNED_IN.into(),
            Problem::NoBranch { branch, .. } => {
                format!("The repository has no branch named {branch}.")
            }
            Problem::NotHistory { git } => format!(
                "This {} isn't a Pathwarden history.",
                if *git { "repository" } else { "folder" }
            ),
            Problem::Empty { git } => format!(
                "This {} is empty.",
                if *git { "repository" } else { "folder" }
            ),
            Problem::Newer { version: Some(v) } => {
                format!("This history was saved by Pathwarden {v}.")
            }
            Problem::Newer { version: None } => {
                "This history was saved by a newer Pathwarden.".into()
            }
            Problem::NoFolder => "Pathwarden couldn't find the folder.".into(),
            Problem::BadDefaultBranch => {
                "The repository's default branch has a name Pathwarden can't use.".into()
            }
        }
    }

    /// What follows the lead (may be empty).
    pub fn rest(&self) -> String {
        match self {
            Problem::BadUrl(_) | Problem::Failed(_) => String::new(),
            Problem::Unreachable { .. } => {
                "Check the URL and that this computer is on the network, then try again.".into()
            }
            Problem::SignIn {
                no_helper: true, ..
            } => format!("{NO_HELPER} then look again."),
            Problem::SignIn { .. } => String::new(),
            Problem::NoBranch { branches, .. } => match branches.len() {
                0 => String::new(),
                1 => format!("Its only branch is {}.", branches[0]),
                _ => format!("Its branches are {}.", and_list(branches)),
            },
            Problem::NotHistory { git } => format!(
                "It holds other files. Choose the {} your team records into.",
                if *git { "repository" } else { "folder" }
            ),
            Problem::Empty { .. } => "You can start a new shared history in it.".into(),
            Problem::Newer { .. } => "Update Pathwarden on this computer to connect to it.".into(),
            Problem::BadDefaultBranch => "Enter a branch.".into(),
            Problem::NoFolder => {
                "Check the path and that this computer can reach it, then try again.".into()
            }
        }
    }

    /// The lead and the rest, as one line.
    pub fn sentence(&self) -> String {
        let rest = self.rest();
        if rest.is_empty() {
            self.lead()
        } else {
            format!("{} {rest}", self.lead())
        }
    }

    /// What git said, for the (i) and `--json`.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Problem::Unreachable { detail } | Problem::SignIn { detail, .. }
                if !detail.is_empty() =>
            {
                Some(detail)
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.sentence())
    }
}

impl std::error::Error for Problem {}

/// "a, b and c".
fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Whether this account can push to the repository ([`push_access`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// `git push --dry-run` went through.
    Yes,
    /// The repository refused it.
    No { detail: String },
    /// It failed for another reason: taken as read only.
    Unclear { detail: String },
}

impl Access {
    pub fn key(&self) -> &'static str {
        match self {
            Access::Yes => "yes",
            Access::No { .. } => "no",
            Access::Unclear { .. } => "unclear",
        }
    }

    /// One sentence for the page and the terminal.
    pub fn sentence(&self) -> &'static str {
        match self {
            Access::Yes => CAN_PUSH,
            Access::No { .. } => CANNOT_PUSH,
            Access::Unclear { .. } => UNCLEAR_PUSH,
        }
    }

    pub fn can_push(&self) -> bool {
        matches!(self, Access::Yes)
    }
}

pub const CAN_PUSH: &str = "Your account can share runs to this run history.";
pub const CANNOT_PUSH: &str = "Your account can read this repository but can't push to it.";
pub const UNCLEAR_PUSH: &str =
    "Pathwarden couldn't tell whether your account can share runs to this run history.";
/// Under [`CANNOT_PUSH`] (and a computer that chose to read only).
pub const READ_ONLY_WORDS: &str = "This computer will only read the shared history. Analyses you \
start here stay on this computer.";
/// Under the push choice.
pub const ADOPTED_WORDS: &str = "What it keeps and its encryption come from the run history.";
/// A URL with a password or token in it, refused (a user name alone is
/// fine: [`crate::config::remote_has_token`]).
pub const PASSWORD_IN_URL: &str =
    "The URL holds a password or token. Remove it: git on this computer signs you in.";
/// The wrong passphrase, on the page and in the terminal.
pub const WRONG_PASSPHRASE: &str = "That passphrase doesn't open this history.";

/// A history that opens with a passphrase kept here for another history
/// ([`crate::keystore::Source::Another`]), on the page and in the terminal.
pub const ANOTHER_PASSPHRASE: &str =
    "This history opens with the passphrase kept on this computer for another history.";

/// Why a history is asked for its passphrase when this computer keeps
/// passphrases from before 0.2 (no key file recorded with them), which are
/// no longer tried on other histories
/// ([`crate::keystore::kept_without_key_file`]), on the page and in the
/// terminal.
pub const OLD_PASSPHRASES: &str = "Enter this history's passphrase once.";

/// What a probe found: a Pathwarden history, and what can be read of it
/// before the passphrase (file names and the plain marker only).
#[derive(Debug, Clone)]
pub struct Found {
    /// The history on disk: the clone in the caller's scratch folder, or
    /// the shared folder itself.
    pub dir: PathBuf,
    /// The repository's URL and branch (the default one resolved), for git.
    pub git: Option<(String, String)>,
    pub encrypted: bool,
    /// What it keeps: full runs (or shared settings) in it say "Full runs
    /// and settings".
    pub keep: Keep,
    /// Runs in the history (`history/<run>`).
    pub runs: usize,
    /// When the latest run was recorded (from its run ID).
    pub latest: Option<i64>,
}

impl Found {
    /// The facts the page and `history storage probe` show, before the
    /// passphrase: (label, sentence, sub-line).
    pub fn facts(
        &self,
        when: impl Fn(i64) -> String,
    ) -> Vec<(&'static str, String, Option<&'static str>)> {
        vec![
            (
                "Encryption",
                if self.encrypted {
                    "Encrypted with a passphrase.".into()
                } else {
                    "Not encrypted.".into()
                },
                None,
            ),
            (
                "What it keeps",
                format!("{}.", self.keep.words()),
                Some(keep_sub(self.keep)),
            ),
            ("Runs", runs_words(self.runs, self.latest.map(when)), None),
        ]
    }
}

/// Under "What it keeps".
pub fn keep_sub(keep: Keep) -> &'static str {
    match keep {
        Keep::Full => {
            "Each run in full, plus shared settings and accepted risks with who accepted them."
        }
        Keep::Names => "The numbers of each run, with each finding's title and domain.",
    }
}

/// "2 runs. The latest was recorded on {when}." (and "No runs yet.").
pub fn runs_words(n: usize, when: Option<String>) -> String {
    match (n, when) {
        (0, _) => "No runs yet.".into(),
        (n, Some(w)) => format!(
            "{}. The latest was recorded on {w}.",
            crate::text::count(n, "run", "runs")
        ),
        (n, None) => format!("{}.", crate::text::count(n, "run", "runs")),
    }
}

/// "The environment Lab already uses this history."
pub fn already_used(name: &str) -> String {
    format!("The environment {name} already uses this history.")
}

/// Start a new shared history, refused where one is already: the lead and
/// the rest.
pub fn already_holds(found: &Found) -> (String, String) {
    let noun = if found.git.is_some() {
        "repository"
    } else {
        "folder"
    };
    let runs = crate::text::count(found.runs, "run", "runs");
    (
        format!("This {noun} already holds a Pathwarden history."),
        format!(
            "{} Connect to it instead, or choose an empty {noun}.",
            if found.encrypted {
                format!("It is encrypted and has {runs}.")
            } else {
                format!("It has {runs}.")
            }
        ),
    )
}

/// An environment that has runs of its own is never connected to a shared
/// history: "Default has 4 runs of its own." and what to do.
pub fn own_runs(name: &str, runs: usize) -> (String, String) {
    (
        format!(
            "{name} has {} of its own.",
            crate::text::count(runs, "run", "runs")
        ),
        "To keep them apart from the shared history, add a new environment for it.".into(),
    )
}

/// The run ID's time: "20261026T235100.000Z" is 2026-10-26 23:51:00 UTC.
fn run_time(id: &str) -> Option<i64> {
    let b = id.as_bytes();
    if b.len() < 15 || b[8] != b'T' {
        return None;
    }
    let n = |a: usize, z: usize| id.get(a..z)?.parse::<i64>().ok();
    crate::time::unix_from_civil(
        n(0, 4)?,
        n(4, 6)?,
        n(6, 8)?,
        n(9, 11)?,
        n(11, 13)?,
        n(13, 15)?,
    )
}

/// What git said, cut to its last few lines.
fn tail(message: &str) -> String {
    let lines: Vec<&str> = message
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    lines[lines.len().saturating_sub(4)..].join("\n")
}

/// Sorts a failed `git ls-remote` or clone into what to tell the user.
fn classify(e: &anyhow::Error) -> Problem {
    let detail = match e.downcast_ref::<store::GitFailed>() {
        Some(f) => f.message.clone(),
        None => {
            let m = format!("{e:#}");
            if m.contains("running git") {
                return Problem::Failed(
                    "Pathwarden couldn't run git. Install git, then try again.".into(),
                );
            }
            m
        }
    };
    let said = tail(&store::redact_url(&detail));
    if is_sign_in(&detail) {
        Problem::SignIn {
            no_helper: no_helper(&detail, None),
            refused: refused(&detail),
            detail: said,
        }
    } else {
        Problem::Unreachable { detail: said }
    }
}

// ------------------------------------------------------------- signing in

/// A git that wasn't let in, in the app's and the command line's words.
pub const NOT_SIGNED_IN: &str = "This computer isn't signed in to the repository.";

/// What follows [`NOT_SIGNED_IN`] when git here has no credential helper;
/// the page ends it ("then sync again.", "then look again.").
pub const NO_HELPER: &str =
    "Git can't ask you to sign in. Install Git for Windows (it includes Git Credential Manager),";

/// A sign-in that worked, and the sync after it.
pub const SIGNED_IN: &str = "Signed in and synced.";

/// A sign-in that didn't.
pub const SIGN_IN_FAILED: &str =
    "Sign-in didn't work. Check that the account can read the repository, then try again.";

/// A sign-in window closed without signing in.
pub const SIGN_IN_CANCELLED: &str = "Sign-in was canceled.";

/// Whether git's `message` says the repository wanted a sign-in it didn't
/// get: no account to give (prompts off, no helper), or one it refused.
pub fn is_sign_in(message: &str) -> bool {
    const SIGN_IN: &[&str] = &[
        "authentication failed",
        "access denied",
        "http basic",
        "could not read username",
        "could not read password",
        "terminal prompts disabled",
        "invalid username or password",
        "logon failed",
        "repository not found",
        "not authorized",
        "unauthorized",
        // Azure DevOps: no such repository, or no access to it.
        "tf401019",
        "you do not have permission",
        // ssh asking for a password it can't get, or refusing one.
        "permission denied, please try again",
        "(keyboard-interactive)",
    ];
    message.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        // What the remote side said: its own lines, or the HTTP answer.
        let remote = lower.contains("remote:");
        // A status code only where the remote or HTTP gave it, as a whole
        // number: a local path such as `C:\x\403\` or `probe-124012` holds
        // one too.
        let status = |code: &str| {
            lower.match_indices(code).any(|(i, _)| {
                let digit = |c: Option<char>| c.is_some_and(|c| c.is_ascii_digit());
                let whole = !digit(lower[..i].chars().next_back())
                    && !digit(lower[i + code.len()..].chars().next());
                let before = &lower[..i];
                whole
                    && (remote
                        || before.ends_with("returned error: ")
                        || before.ends_with("http ")
                        || before.ends_with("http/1.1 ")
                        || before.ends_with("http/2 ")
                        || before.ends_with("status code "))
            })
        };
        // "Permission denied" from ssh (publickey) or the remote only: a
        // local file another program holds (`index.lock`) says it too.
        let denied = lower.contains("permission denied") && (remote || lower.contains("publickey"));
        SIGN_IN.iter().any(|w| lower.contains(w)) || denied || status("401") || status("403")
    })
}

/// Whether git's `message` says it had no account to give: it could not
/// read a user name or password and couldn't ask.
pub fn no_account(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "could not read username",
        "could not read password",
        "terminal prompts disabled",
    ]
    .iter()
    .any(|w| lower.contains(w))
}

/// Whether git's `message` says the repository refused the account git
/// gave it (a credential kept on this computer, for an account that can't
/// read it): a sign-in, just not this one.
pub fn refused(message: &str) -> bool {
    is_sign_in(message) && !no_account(message)
}

/// What a sign-in the repository refused says.
pub const REFUSED: &str = "The repository refused this computer's sign-in.";

/// Whether git's `message` says it had no account to give (it could not
/// read a user name or password and couldn't ask) and git here has no
/// credential helper that could have asked
/// ([`store::has_credential_helper`], in the working copy `dir` when
/// given): signing in can't work until one is set up.
pub fn no_helper(message: &str, dir: Option<&Path>) -> bool {
    no_account(message) && !store::has_credential_helper(dir)
}

/// Whether git's `message` says the sign-in window was closed without
/// signing in: Git Credential Manager's own words for it, not the word
/// anywhere (a repository may be called `cancelled-orders`).
pub fn cancelled(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "user cancelled the authentication prompt",
        "user canceled the authentication prompt",
        "user cancelled the operation",
        "user canceled the operation",
        "operation was canceled by the user",
        "operation was cancelled by the user",
        "authentication was cancelled",
        "authentication was canceled",
        // Git Credential Manager's window closed.
        "a task was canceled.",
        "a task was cancelled.",
    ]
    .iter()
    .any(|w| lower.contains(w))
}

/// What the remote holds, from `git ls-remote --symref`: its branches
/// and the default one.
fn remote_heads(url: &str) -> Result<(Vec<String>, Option<String>), Problem> {
    let out =
        store::run_git(None, &["ls-remote", "--symref", "--", url]).map_err(|e| classify(&e))?;
    let mut heads = Vec::new();
    let mut default = None;
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("ref: ") {
            if let Some((target, name)) = rest.split_once('\t') {
                if name.trim() == "HEAD" {
                    default = target
                        .trim()
                        .strip_prefix("refs/heads/")
                        .map(str::to_string);
                }
            }
            continue;
        }
        if let Some((_, r)) = line.split_once('\t') {
            if let Some(h) = r.trim().strip_prefix("refs/heads/") {
                heads.push(h.to_string());
            }
        }
    }
    heads.sort();
    heads.dedup();
    Ok((heads, default))
}

/// Looks at the shared history in `w` before anything is saved. For git
/// the repository is cloned into `scratch/history` (the same checks as
/// every pull), and `scratch` must be an empty folder the caller made and
/// removes when it is done with it; for a folder `scratch` is unused.
/// Nothing is pushed or written anywhere else.
pub fn probe(w: &Where, scratch: &Path) -> Result<Found, Problem> {
    match w {
        Where::Folder(dir) => probe_folder(dir),
        Where::Git { url, branch } => probe_git(url, branch.as_deref(), scratch),
    }
}

fn probe_git(url: &str, branch: Option<&str>, scratch: &Path) -> Result<Found, Problem> {
    let url = url.trim();
    crate::config::validate_remote(url).map_err(|_| {
        Problem::BadUrl(
            "Enter the repository's URL, such as https://git.example.com/team/history.git.".into(),
        )
    })?;
    if crate::config::remote_has_password(url) || crate::config::remote_has_token(url) {
        return Err(Problem::BadUrl(PASSWORD_IN_URL.into()));
    }
    let branch = branch.map(str::trim).filter(|b| !b.is_empty());
    if let Some(b) = branch {
        crate::config::validate_branch(b)
            .map_err(|_| Problem::BadUrl(format!("{b} is not a branch name.")))?;
    }
    let (heads, default) = remote_heads(url)?;
    if heads.is_empty() {
        return Err(Problem::Empty { git: true });
    }
    let branch = match branch {
        Some(b) if heads.iter().any(|h| h == b) => b.to_string(),
        Some(b) => {
            return Err(Problem::NoBranch {
                branch: b.to_string(),
                branches: heads,
            })
        }
        None => {
            let b = default
                .filter(|d| heads.contains(d))
                .or_else(|| heads.iter().find(|h| *h == "main").cloned())
                .unwrap_or_else(|| heads[0].clone());
            if crate::config::validate_branch(&b).is_err() {
                return Err(Problem::BadDefaultBranch);
            }
            b
        }
    };
    let dir = scratch.join("history");
    let cfg = StateConfig {
        backend: StateBackend::Git,
        remote: Some(url.to_string()),
        branch: Some(branch.clone()),
        ..StateConfig::default()
    };
    let store = Store::new(&cfg, Some(&dir)).map_err(|e| Problem::Failed(format!("{e:#}")))?;
    let pulled = store.lock().and_then(|_lock| store.pull().map(|_| ()));
    // What the branch holds at its top, from the clone's own refs.
    let top = |dir: &Path| -> Option<Vec<String>> {
        store::run_git(
            Some(dir),
            &["ls-tree", "--name-only", &format!("origin/{branch}")],
        )
        .ok()
        .map(|t| t.lines().map(str::to_string).collect())
    };
    let tree = if dir.join(".git").is_dir() {
        top(&dir)
    } else {
        None
    };
    if let Err(e) = pulled {
        return Err(match tree {
            // Cloned: the branch holds something else.
            Some(t) if !holds_history(&t) => {
                if t.iter().all(|n| host_file(n)) {
                    Problem::Empty { git: true }
                } else {
                    Problem::NotHistory { git: true }
                }
            }
            Some(_) => Problem::Failed(format!("{e:#}")),
            None => classify(&e),
        });
    }
    match tree {
        Some(t) if holds_history(&t) => {}
        // Only what a new repository's host adds (a README): empty.
        _ => return Err(Problem::Empty { git: true }),
    }
    let mut found = look(&dir)?;
    found.git = Some((url.to_string(), branch));
    Ok(found)
}

/// Whether the names at a branch's top are a Pathwarden history's.
fn holds_history(top: &[String]) -> bool {
    top.iter().any(|n| {
        n == store::MARKER
            || n == crypt::MARKER
            || n == "findings.json"
            || n == "last-run.json"
            || n == "history"
    })
}

/// What a new repository's host creates in it (README, LICENSE,
/// `.gitignore`, `.gitattributes`).
fn host_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".gitignore", ".gitattributes"].contains(&lower.as_str())
        || ["readme", "license", "licence"]
            .iter()
            .any(|s| lower == *s || lower.starts_with(&format!("{s}.")))
}

fn probe_folder(dir: &Path) -> Result<Found, Problem> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Err(Problem::NoFolder),
    };
    let names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    if names.is_empty() {
        return Err(Problem::Empty { git: false });
    }
    if !holds_history(&names) {
        return Err(if names.iter().all(|n| host_file(n)) {
            Problem::Empty { git: false }
        } else {
            Problem::NotHistory { git: false }
        });
    }
    look(dir)
}

/// What the history in `dir` holds that can be read without its
/// passphrase; refused when a newer Pathwarden wrote it. (A probe's
/// [`Found`] again, read from disk.)
pub fn look(dir: &Path) -> Result<Found, Problem> {
    let encrypted = match crypt::marker(dir) {
        Ok(m) => m.is_some(),
        Err(e) => {
            return Err(match e.downcast_ref::<crypt::CryptError>() {
                Some(crypt::CryptError::Newer(_)) => Problem::Newer { version: None },
                _ => Problem::Failed(format!("{e:#}")),
            })
        }
    };
    if !encrypted {
        if let Ok(bytes) = std::fs::read(dir.join("findings.json")) {
            let newer = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .is_some_and(|v| {
                    !crate::formats::of_json(&v, "version", crate::state::STATE_VERSION).is_known()
                });
            if newer {
                let writer = store::read_state_file(dir, store::ENVIRONMENT_FILE)
                    .ok()
                    .flatten()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .and_then(|v| {
                        v.get("written_by_version")
                            .and_then(|s| s.as_str())
                            .map(str::to_string)
                    })
                    .filter(|s| !s.is_empty());
                return Err(Problem::Newer { version: writer });
            }
        }
    }
    let points = store::list_state_files(dir, "history").unwrap_or_default();
    let latest = points
        .iter()
        .filter_map(|rel| {
            let id = rel.strip_prefix("history/")?.strip_suffix(".json")?;
            run_time(id)
        })
        .max();
    let full = !store::list_bundles(dir).is_empty()
        || store::has_state_file(dir, store::SETTINGS_FILE)
        || store::has_state_file(dir, store::ENVIRONMENT_FILE);
    Ok(Found {
        dir: dir.to_path_buf(),
        git: None,
        encrypted,
        keep: if full { Keep::Full } else { Keep::Names },
        runs: points.len(),
        latest,
    })
}

/// Whether `passphrase` opens the history `found` is ([`WRONG_PASSPHRASE`]
/// when it doesn't).
pub fn opens(found: &Found, passphrase: &crypt::SecretString) -> anyhow::Result<bool> {
    crypt::opens(&found.dir, passphrase)
}

/// Whether this account can push to the repository the clone in `dir`
/// came from: `git push --dry-run`, which signs in as a push would (git's
/// sign-in window may open: the user asked for this) and pushes nothing.
/// Anything but a clear yes or a clear refusal is [`Access::Unclear`].
pub fn push_access(dir: &Path, branch: &str) -> Access {
    let target = format!("HEAD:refs/heads/{branch}");
    match store::run_git(
        Some(dir),
        &["push", "--dry-run", "--porcelain", "origin", &target],
    ) {
        Ok(_) => Access::Yes,
        Err(e) => {
            let message = match e.downcast_ref::<store::GitFailed>() {
                Some(f) => f.message.clone(),
                None => format!("{e:#}"),
            };
            let lower = message.to_ascii_lowercase();
            let detail = tail(&message);
            const REFUSED: &[&str] = &[
                "403",
                "permission",
                "denied",
                "not allowed",
                "read only",
                "read-only",
                "protected branch",
                "write access",
                "unauthorized",
            ];
            if REFUSED.iter().any(|w| lower.contains(w)) {
                Access::No { detail }
            } else {
                Access::Unclear { detail }
            }
        }
    }
}

/// Once the history opens (or isn't encrypted): what the environment is,
/// who recorded the latest run, and which shared settings it carries.
#[derive(Debug, Clone, Default)]
pub struct Contents {
    /// `settings/environment.json`'s name.
    pub name: Option<String>,
    pub domains: Vec<String>,
    /// The latest run's point.
    pub latest: Option<crate::state::HistoryPoint>,
    /// The shared settings, in one sentence ("Tier Zero additions, rule
    /// settings and zones. No accepted risks yet."); `None` without any.
    pub settings: Option<String>,
}

/// [`Contents`] of the history in `dir` (its passphrase given in this
/// process when it is encrypted).
pub fn contents(dir: &Path) -> Contents {
    let env = store::read_state_file(dir, store::ENVIRONMENT_FILE)
        .ok()
        .flatten()
        .filter(|b| b.len() <= 64 << 10)
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        // A newer Pathwarden's record is not read (docs/dev/formats.md).
        .filter(|v| {
            crate::formats::of_json(v, "format", crate::settings_sync::ENVIRONMENT_FORMAT)
                .is_known()
        })
        .and_then(|v| serde_json::from_value::<crate::settings_sync::Environment>(v).ok())
        .unwrap_or_default();
    let latest = crate::history::load(dir)
        .ok()
        .and_then(|(points, _)| crate::since::latest_point(&points).cloned());
    let settings = store::read_state_file(dir, store::SETTINGS_FILE)
        .ok()
        .flatten()
        .filter(|b| b.len() <= 4 << 20)
        .and_then(|b| String::from_utf8(b).ok())
        .map(|text| settings_words(&text));
    // The latest run's domains when the environment's record has none
    // (it is written with the shared settings, before any run).
    let domains = if env.domains.is_empty() {
        store::read_state_file(dir, "last-run.json")
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<crate::state::LastRun>(&b).ok())
            .filter(|l| crate::formats::of_u32(l.version, crate::state::STATE_VERSION).is_known())
            .map(|l| l.domains)
            .unwrap_or_default()
    } else {
        env.domains
    };
    Contents {
        name: env.name.filter(|n| !n.trim().is_empty()),
        domains,
        latest,
        settings,
    }
}

/// The shared settings file's sections, in one sentence.
fn settings_words(text: &str) -> String {
    let Ok(doc) = text.parse::<toml::Table>() else {
        return "They can't be read.".into();
    };
    // A newer format isn't summed up as if it were this version's.
    if !crate::formats::of_toml(&doc, "format", crate::config::CONFIG_FORMAT).is_known() {
        return "They were saved by a newer Pathwarden. Update Pathwarden to sync them.".into();
    }
    let has = |key: &str| match doc.get(key) {
        Some(toml::Value::Table(t)) => !t.is_empty(),
        Some(toml::Value::Array(a)) => !a.is_empty(),
        Some(_) => true,
        None => false,
    };
    let mut parts: Vec<String> = crate::config_edit::SHARED_SECTIONS
        .iter()
        .filter(|(k, _)| *k != "suppress" && has(k))
        .map(|(_, name)| name.to_string())
        .collect();
    let risks = match doc.get("suppress") {
        Some(toml::Value::Array(a)) => a.len(),
        _ => 0,
    };
    if risks > 0 {
        parts.push(crate::text::count(risks, "accepted risk", "accepted risks"));
    }
    // "Tier Zero additions, rule settings and zones": the first as written.
    let lowered: Vec<String> = parts
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if i == 0 || p.starts_with("Tier Zero") {
                p.clone()
            } else {
                let mut c = p.chars();
                c.next()
                    .map(|f| f.to_lowercase().collect::<String>() + c.as_str())
                    .unwrap_or_default()
            }
        })
        .collect();
    let mut out = if lowered.is_empty() {
        "None yet.".to_string()
    } else {
        format!("{}.", and_list(&lowered))
    };
    if risks == 0 && !lowered.is_empty() {
        out.push_str(" No accepted risks yet.");
    }
    out
}

/// The name a new environment for the shared history gets: `base`, or
/// with " 2", " 3" ... when that name is taken here (`taken`, compared
/// ignoring case).
pub fn free_name(base: &str, taken: &[String], max: usize) -> String {
    let base = base.trim();
    let base = if base.is_empty() {
        "Shared history"
    } else {
        base
    };
    let is_taken = |n: &str| taken.iter().any(|t| t.trim().eq_ignore_ascii_case(n));
    if !is_taken(base) && base.chars().count() <= max {
        return base.to_string();
    }
    for i in 2.. {
        let suffix = format!(" {i}");
        let keep = max.saturating_sub(suffix.chars().count());
        let stem: String = base.chars().take(keep).collect();
        let name = format!("{}{suffix}", stem.trim_end());
        if !is_taken(&name) {
            return name;
        }
    }
    unreachable!()
}

/// Moves the clone a probe made into `target`, the folder the environment
/// keeps its history in: `target` must not exist, or be empty.
pub fn place(found: &Found, target: &Path) -> anyhow::Result<()> {
    if let Ok(mut entries) = std::fs::read_dir(target) {
        if entries.next().is_some() {
            anyhow::bail!("{} already holds files", target.display());
        }
        std::fs::remove_dir(target)?;
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A virus scanner may hold a file of the new clone briefly.
    let mut tries = 0;
    loop {
        match std::fs::rename(&found.dir, target) {
            Ok(()) => return Ok(()),
            Err(_) if tries < 10 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => {
                return Err(anyhow::Error::from(e)
                    .context(format!("moving the clone into {}", target.display())))
            }
        }
    }
}

#[cfg(test)]
#[path = "connect_tests.rs"]
mod tests;
