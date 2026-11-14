//! Connecting an environment to a run history, shared by the
//! app's Connect to a run history page ([`crate::connect_ui`]) and the
//! command line (`pathwarden history storage probe|connect`, `pathwarden
//! env create --from-git|--from-folder`). What the repository holds and
//! the sentences come from [`pathwarden_core::connect`].
//!
//! A probe's clone is made in a folder Pathwarden creates for it in the
//! workspace (`.pathwarden-connect/<token>/`), moved into the
//! environment's folder when it connects, and removed on cancel or
//! failure. Only folders made here are ever removed.

use std::path::{Path, PathBuf};

use pathwarden_core::config::{Keep, StateBackend};
use pathwarden_core::config_edit::StateEdit;
use pathwarden_core::connect::{self, Access, Found, Problem, Where};
use pathwarden_core::crypt::{self, SecretString};
use pathwarden_core::keystore;
use serde::{Deserialize, Serialize};

use crate::environments::{self, Registry};
use crate::history_ui;
use crate::workspace::Workspace;

/// Probes' folders, in the workspace.
pub const SCRATCH: &str = ".pathwarden-connect";
/// In a probe's folder: what it looked at (no secrets).
const META: &str = "probe.json";
/// A probe left this long is removed when the next one starts.
const STALE_SECS: i64 = 24 * 3600;

/// What a probe looked at and found, kept between the page's steps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    /// "git" or "folder".
    pub kind: String,
    #[serde(default)]
    pub url: Option<String>,
    /// The branch, resolved.
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    /// The environment to connect, when one was chosen (else a new one).
    #[serde(default)]
    pub env: Option<String>,
    /// [`Access::key`] (git).
    #[serde(default)]
    pub access: Option<String>,
    #[serde(default)]
    pub access_detail: Option<String>,
    /// Remember the passphrase on this computer once connected.
    #[serde(default)]
    pub remember: bool,
    pub made: i64,
}

impl Meta {
    pub fn access(&self) -> Option<Access> {
        let detail = self.access_detail.clone().unwrap_or_default();
        match self.access.as_deref()? {
            "yes" => Some(Access::Yes),
            "no" => Some(Access::No { detail }),
            _ => Some(Access::Unclear { detail }),
        }
    }

    pub fn is_git(&self) -> bool {
        self.kind == "git"
    }
}

/// Whether a probe's history opens here ([`Session::lock`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lock {
    /// Plain, or its own passphrase opens it (given for it, or kept for
    /// its folder).
    Open,
    /// A passphrase this computer has, not given for it, opens it: the
    /// one that opened the same history here in this session, or
    /// (`another`) one kept on this computer for another history, which the
    /// page says ([`connect::ANOTHER_PASSPHRASE`]). `remembered`: it is
    /// kept on this computer, so Remember starts ticked.
    Kept { another: bool, remembered: bool },
    /// Its passphrase must be given.
    Need,
    /// The passphrase this computer has for it doesn't open it
    /// ([`connect::WRONG_PASSPHRASE`]).
    Wrong,
}

/// Why [`connect`] refused before changing anything, when the passphrase
/// must be given first (the page shows the passphrase again).
pub const NEED_PASSPHRASE: &str = "Enter the passphrase to open the history first.";

/// A probe in progress.
#[derive(Debug, Clone)]
pub struct Session {
    pub token: String,
    /// Its folder (`.pathwarden-connect/<token>`).
    pub dir: PathBuf,
    pub meta: Meta,
}

impl Session {
    /// Where the history it looks at is: the clone, or the shared folder.
    pub fn history_dir(&self) -> PathBuf {
        match (&self.meta.folder, self.meta.is_git()) {
            (Some(f), false) => PathBuf::from(f),
            _ => self.dir.join("history"),
        }
    }

    /// What it found, read again from disk.
    pub fn found(&self) -> Result<Found, Problem> {
        let mut f = connect::look(&self.history_dir())?;
        if let (Some(u), Some(b)) = (&self.meta.url, &self.meta.branch) {
            f.git = Some((u.clone(), b.clone()));
        }
        Ok(f)
    }

    /// Whether the history can be read here now: plain, or this computer
    /// has a passphrase that opens it (given with [`open`], or one kept
    /// here: [`crypt::known_passphrase`]). [`connect`] uses the same one.
    pub fn lock(&self, found: &Found) -> Lock {
        if !found.encrypted {
            return Lock::Open;
        }
        let own = crypt::passphrase_for(&found.dir).ok().flatten().is_some();
        match crypt::known_passphrase(&found.dir) {
            Ok(crypt::Known::Opens(_, keystore::Source::Another)) => Lock::Kept {
                another: true,
                remembered: true,
            },
            Ok(crypt::Known::Opens(_, source)) if !own => Lock::Kept {
                another: false,
                remembered: source == keystore::Source::Store,
            },
            Ok(crypt::Known::Opens(..)) => Lock::Open,
            Ok(crypt::Known::Wrong(_)) => Lock::Wrong,
            _ => Lock::Need,
        }
    }

    /// [`Session::lock`] opens it ([`Lock::Open`] or [`Lock::Kept`]).
    pub fn opened(&self, found: &Found) -> bool {
        matches!(self.lock(found), Lock::Open | Lock::Kept { .. })
    }

    fn save(&self) -> Result<(), String> {
        let text = serde_json::to_string_pretty(&self.meta).map_err(|e| e.to_string())?;
        std::fs::write(self.dir.join(META), text).map_err(|e| format!("{e}"))
    }
}

/// Why connecting was refused at the first step: what the repository says
/// ([`Problem`]), or the environment that uses it already.
#[derive(Debug, Clone)]
pub enum Refused {
    Problem(Problem),
    UsedBy { id: String, name: String },
}

impl Refused {
    pub fn key(&self) -> &'static str {
        match self {
            Refused::Problem(p) => p.key(),
            Refused::UsedBy { .. } => "used",
        }
    }

    pub fn lead(&self) -> String {
        match self {
            Refused::Problem(p) => p.lead(),
            Refused::UsedBy { name, .. } => connect::already_used(name),
        }
    }

    pub fn rest(&self) -> String {
        match self {
            Refused::Problem(p) => p.rest(),
            Refused::UsedBy { .. } => String::new(),
        }
    }

    pub fn sentence(&self) -> String {
        let rest = self.rest();
        if rest.is_empty() {
            self.lead()
        } else {
            format!("{} {rest}", self.lead())
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Refused::Problem(p) => p.detail(),
            Refused::UsedBy { .. } => None,
        }
    }
}

fn scratch_root(root: &Path) -> PathBuf {
    root.join(SCRATCH)
}

fn valid_token(t: &str) -> bool {
    t.len() == 32
        && t.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Why a probe can't start without random numbers.
const NO_RANDOM: &str = "Pathwarden couldn't get the random numbers it needs. Try again.";

fn token() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| NO_RANDOM.to_string())?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Removes a probe's folder: only one made here (a token's name, under
/// [`SCRATCH`], holding its [`META`] or nothing).
fn remove_session_dir(dir: &Path) {
    let name_ok = dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(valid_token)
        && dir
            .parent()
            .and_then(|p| p.file_name())
            .is_some_and(|n| n == SCRATCH);
    if !name_ok {
        return;
    }
    let ours =
        dir.join(META).is_file() || std::fs::read_dir(dir).is_ok_and(|mut r| r.next().is_none());
    if ours {
        let _ = remove_tree(dir);
    }
}

/// Removes a folder this code made, git's read-only files included.
fn remove_tree(path: &Path) -> std::io::Result<()> {
    fn writable(dir: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
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
                        let _ = std::fs::set_permissions(e.path(), perms);
                    }
                }
            }
        }
    }
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return std::fs::remove_file(path).or_else(|_| std::fs::remove_dir(path));
    }
    writable(path);
    std::fs::remove_dir_all(path)
}

/// Probes left over from earlier (a closed page): removed.
fn clear_stale(root: &Path, now: i64) {
    let Ok(entries) = std::fs::read_dir(scratch_root(root)) else {
        return;
    };
    for e in entries.flatten() {
        let dir = e.path();
        // Without its record (a probe stopped before it was written): the
        // folder's own time.
        let made = std::fs::read(dir.join(META))
            .ok()
            .and_then(|b| serde_json::from_slice::<Meta>(&b).ok())
            .map(|m| m.made)
            .or_else(|| {
                std::fs::metadata(&dir)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
            })
            .unwrap_or(now);
        if now - made > STALE_SECS {
            remove_session_dir(&dir);
        }
    }
}

/// The probe `token` of the workspace at `root`, if it is there.
pub fn load(root: &Path, token: &str) -> Option<Session> {
    if !valid_token(token) {
        return None;
    }
    let dir = scratch_root(root).join(token);
    let meta: Meta = serde_json::from_slice(&std::fs::read(dir.join(META)).ok()?).ok()?;
    Some(Session {
        token: token.to_string(),
        dir,
        meta,
    })
}

/// Removes probe `token` (Cancel), and the probes' folder once it is empty.
pub fn discard(root: &Path, token: &str) {
    if valid_token(token) {
        remove_session_dir(&scratch_root(root).join(token));
        let _ = std::fs::remove_dir(scratch_root(root));
    }
}

/// Keeps where a run history is (`meta`'s place and environment) under
/// a token, so a link can name it without the URL in its query string:
/// [`take_place`] reads it back once.
pub fn keep_place(root: &Path, meta: &Meta) -> Option<String> {
    let token = token().ok()?;
    let dir = scratch_root(root).join(&token);
    std::fs::create_dir_all(&dir).ok()?;
    let s = Session {
        token: token.clone(),
        dir: dir.clone(),
        meta: Meta {
            kind: if meta.is_git() { "git" } else { "folder" }.into(),
            made: pathwarden_core::analyze::now(),
            ..meta.clone()
        },
    };
    if s.save().is_err() {
        remove_session_dir(&dir);
        return None;
    }
    Some(token)
}

/// The place a [`keep_place`] token (or a probe's) names, once: the token's
/// folder, and a probe's clone, are removed.
pub fn take_place(root: &Path, token: &str) -> Option<Meta> {
    let s = load(root, token)?;
    discard(root, token);
    Some(s.meta)
}

/// The environment of the workspace at `root` whose history is `w`
/// already, if any: (ID, name).
pub fn used_by(root: &Path, w: &Where) -> Option<(String, String)> {
    let ws = Workspace::existing(root).ok()?;
    let reg = ws.named_registry();
    for e in &reg.environments {
        let env_ws = ws.in_env(&e.id);
        let Ok(config) = env_ws.config() else {
            continue;
        };
        let s = &config.state;
        let same = match w {
            Where::Git { url, branch } => {
                s.backend == StateBackend::Git
                    && s.remote
                        .as_deref()
                        .is_some_and(|r| pathwarden_core::store::same_remote(r, url))
                    && branch.as_deref().unwrap_or("main") == s.branch.as_deref().unwrap_or("main")
            }
            Where::Folder(dir) => {
                s.backend == StateBackend::Local
                    && history_ui::locate(&env_ws, None).is_ok_and(|l| {
                        let full = |p: &Path| std::fs::canonicalize(p).ok();
                        full(&l.dir).is_some() && full(&l.dir) == full(dir)
                    })
            }
        };
        if same {
            return Some((e.id.clone(), e.display().to_string()));
        }
    }
    None
}

/// Looks at the run history `w` for the workspace at `root` (blocking:
/// it reaches the network), for environment `env` (else a new one): the
/// clone in a folder made for it, what it holds, and for git whether this
/// account can push. On a refusal nothing is left behind.
pub fn start(root: &Path, w: &Where, env: Option<&str>) -> Result<Session, Refused> {
    let now = pathwarden_core::analyze::now();
    clear_stale(root, now);
    if let Where::Git {
        branch: Some(_), ..
    }
    | Where::Folder(_) = w
    {
        if let Some((id, name)) = used_by(root, w) {
            return Err(Refused::UsedBy { id, name });
        }
    }
    let token = token().map_err(|e| Refused::Problem(Problem::Failed(e)))?;
    let dir = scratch_root(root).join(&token);
    std::fs::create_dir_all(&dir).map_err(|e| {
        Refused::Problem(Problem::Failed(format!(
            "Couldn't create {}: {e}",
            dir.display()
        )))
    })?;
    let mut session = Session {
        token,
        dir: dir.clone(),
        meta: Meta {
            kind: if w.is_git() { "git" } else { "folder" }.into(),
            env: env.map(str::to_string),
            remember: true,
            made: now,
            ..Meta::default()
        },
    };
    // Marked as this code's before anything goes in, so a failure removes it.
    if let Err(e) = session.save() {
        remove_session_dir(&dir);
        return Err(Refused::Problem(Problem::Failed(e)));
    }
    // The clone, and every check, as the user asked for it (git's sign-in
    // window may open).
    let found = match connect::probe(w, &dir) {
        Ok(f) => f,
        Err(p) => {
            discard(root, &session.token);
            return Err(Refused::Problem(p));
        }
    };
    match (&found.git, w) {
        (Some((url, branch)), _) => {
            // The default branch is known now.
            let resolved = Where::Git {
                url: url.clone(),
                branch: Some(branch.clone()),
            };
            if let Some((id, name)) = used_by(root, &resolved) {
                discard(root, &session.token);
                return Err(Refused::UsedBy { id, name });
            }
            let access = connect::push_access(&found.dir, branch);
            session.meta.url = Some(url.clone());
            session.meta.branch = Some(branch.clone());
            session.meta.access = Some(access.key().into());
            session.meta.access_detail = match &access {
                Access::No { detail } | Access::Unclear { detail } => Some(detail.clone()),
                Access::Yes => None,
            };
        }
        (None, Where::Folder(f)) => {
            let full = std::fs::canonicalize(f).unwrap_or_else(|_| f.clone());
            session.meta.folder = Some(plain_path(&full));
        }
        _ => {}
    }
    if let Err(e) = session.save() {
        remove_session_dir(&dir);
        return Err(Refused::Problem(Problem::Failed(e)));
    }
    Ok(session)
}

/// A path without Windows' `\\?\` prefix, as a person writes it.
fn plain_path(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

/// Tries `passphrase` on the probe's history; when it opens it, it is
/// kept for this process (and `remember`ed for when it connects).
pub fn open(session: &mut Session, passphrase: SecretString, remember: bool) -> Result<(), String> {
    let found = session.found().map_err(|p| p.sentence())?;
    match connect::opens(&found, &passphrase) {
        Ok(true) => {}
        Ok(false) => return Err(connect::WRONG_PASSPHRASE.into()),
        Err(e) => return Err(format!("{e:#}")),
    }
    crypt::give_passphrase(&found.dir, passphrase);
    session.meta.remember = remember;
    session.save()
}

/// Runs of `ws`'s environment of its own: analyses here and runs in the
/// history it uses now. Such an environment is never connected to a shared
/// history ([`connect::own_runs`]).
pub fn own_runs(ws: &Workspace, flag: Option<&Path>) -> usize {
    let here = ws.runs().len();
    let recorded = history_ui::locate(ws, flag)
        .ok()
        .map(|l| {
            pathwarden_core::store::list_state_files(&l.dir, "history")
                .unwrap_or_default()
                .len()
        })
        .unwrap_or(0);
    here.max(recorded)
}

/// The name a new environment for this history gets: the history's own,
/// or with a number when this workspace has one by that name.
pub fn suggested_name(root: &Path, contents: &connect::Contents, keep: Option<&str>) -> String {
    let reg = Workspace::existing(root)
        .map(|w| w.named_registry())
        .unwrap_or_default();
    let taken: Vec<String> = reg
        .environments
        .iter()
        .filter(|e| Some(e.id.as_str()) != keep)
        .flat_map(|e| [e.name.clone(), e.display().to_string()])
        .collect();
    let base = contents
        .name
        .clone()
        .unwrap_or_else(|| environments::new_name(&contents.domains));
    connect::free_name(&base, &taken, environments::MAX_NAME)
}

/// "2 runs. The latest, on {when}, was recorded from the command line by
/// X on Y.": the Runs row once the history is open.
pub fn runs_row(
    found: &Found,
    contents: &connect::Contents,
    when: impl Fn(i64) -> String,
) -> String {
    let Some(p) = &contents.latest else {
        return connect::runs_words(found.runs, found.latest.map(&when));
    };
    let manifest = pathwarden_core::store::read_state_file(
        &found.dir,
        &pathwarden_core::store::bundle_rel(&p.run_id, "run.json"),
    )
    .ok()
    .flatten()
    .and_then(|b| serde_json::from_slice::<crate::shared_runs::Manifest>(&b).ok());
    let how = match manifest {
        Some(m) => crate::shared_runs::recorded_words(
            &m.recorded_from,
            m.recorded_by.as_deref(),
            m.recorded_on.as_deref(),
        ),
        None => match p.recorded_by.as_deref() {
            Some(f) => crate::shared_runs::recorded_words(f, None, None),
            None => "recorded by a run".into(),
        },
    };
    format!(
        "{}. The latest, on {}, was {how}.",
        pathwarden_core::text::count(found.runs.max(1), "run", "runs"),
        when(p.at)
    )
}

/// What the user chose on the last step (or on the command line).
#[derive(Debug, Clone)]
pub struct Choices {
    /// The environment's name here.
    pub name: String,
    /// Push runs from this computer (git).
    pub push: bool,
    /// Sync every N minutes (git).
    pub refresh: u32,
    /// Remember the passphrase on this computer, when the page asked
    /// (a passphrase it found here, [`Lock::Kept`]); `None`: as it was
    /// given.
    pub remember: Option<bool>,
}

/// What connecting did.
#[derive(Debug, Clone)]
pub struct Connected {
    pub env_id: String,
    pub env_name: String,
    pub git: bool,
    pub keep: Keep,
    /// Runs in the history.
    pub runs: usize,
    /// Full runs loaded into the app.
    pub full_runs: usize,
    pub refresh: u32,
    pub push: bool,
    /// For the user: the pull's notes, a passphrase that couldn't be stored.
    pub notes: Vec<String>,
}

/// The note Runs shows once connected, and the command line prints.
pub fn landing_words(git: bool, full: bool, full_runs: usize, runs: usize, refresh: u32) -> String {
    let mut s = String::from(if git {
        "Connected to the run history."
    } else {
        "Connected to the shared folder."
    });
    if full {
        s.push_str(&format!(
            " {} {} loaded from the {}.",
            pathwarden_core::text::count(full_runs, "full run", "full runs"),
            if full_runs == 1 { "was" } else { "were" },
            if git { "repository" } else { "folder" }
        ));
    } else {
        s.push_str(&format!(
            " It holds {}.",
            pathwarden_core::text::count(runs, "run", "runs")
        ));
    }
    if git {
        s.push_str(&format!(
            " It is synced again every {}.",
            crate::last_pull::minutes_words(refresh)
        ));
    }
    s
}

impl Connected {
    pub fn words(&self) -> String {
        landing_words(
            self.git,
            self.keep == Keep::Full,
            self.full_runs,
            self.runs,
            self.refresh,
        )
    }
}

/// What [`connect`] puts back when it fails after the environment was
/// made or renamed.
enum Undo {
    /// The environment was made for it: unregistered again.
    Remove,
    /// The chosen environment was renamed: its name (and domains) as before.
    Rename(String, Vec<String>),
}

impl Undo {
    fn run(&self, root: &Path, id: &str) {
        let _ = Registry::update(root, |r| {
            match self {
                Undo::Remove => {
                    r.environments.retain(|e| e.id != id);
                    if r.current.as_deref() == Some(id) {
                        r.current = None;
                    }
                }
                Undo::Rename(name, domains) => r.edit(id, name, domains)?,
            }
            Ok(())
        });
    }
}

/// The folder the environment at `env_dir` keeps the run history in:
/// `pathwarden-state` when it is free, else `pathwarden-shared`, `-2`...
/// `None` in the config when it is the default.
fn target_folder(env_dir: &Path) -> (PathBuf, Option<String>) {
    let free = |p: &Path| std::fs::read_dir(p).map_or(true, |mut r| r.next().is_none());
    let default = env_dir.join(history_ui::DEFAULT_FOLDER);
    if free(&default) {
        return (default, None);
    }
    for i in 1.. {
        let name = if i == 1 {
            "pathwarden-shared".to_string()
        } else {
            format!("pathwarden-shared-{i}")
        };
        let p = env_dir.join(&name);
        if free(&p) {
            return (p, Some(name));
        }
    }
    unreachable!()
}

/// Connects the probe `session` of the workspace at `root` (blocking):
/// the environment it names, or a new one called `choices.name`, keeps the
/// run history from now on, adopting what it keeps and its encryption;
/// the clone moves into the environment's folder, the passphrase (given
/// with [`open`], or `passphrase`) is kept here as asked, and the history
/// is pulled and its full runs loaded. `page`: the app's words for notes.
pub fn connect(
    root: &Path,
    session: &Session,
    choices: &Choices,
    passphrase: Option<SecretString>,
    page: bool,
) -> Result<Connected, String> {
    let found = session.found().map_err(|p| p.sentence())?;
    let ws = Workspace::existing(root).map_err(|e| format!("{e:#}"))?;
    let git = session.meta.is_git();
    // The passphrase first: nothing changes for a history that won't open.
    // Without one given: the one the page opened it with (this session's,
    // or one kept on this computer, as [`Session::lock`] found it). One
    // kept in this account's store is kept for the new folder too.
    let pass = if found.encrypted {
        let (p, remember) = match passphrase {
            Some(p) => {
                if !connect::opens(&found, &p).map_err(|e| format!("{e:#}"))? {
                    return Err(connect::WRONG_PASSPHRASE.into());
                }
                (p, session.meta.remember)
            }
            None => match crypt::known_passphrase(&found.dir).map_err(|e| format!("{e:#}"))? {
                // Remember as the page's box says (it starts ticked for one
                // kept on this computer); else as it was given.
                crypt::Known::Opens(p, source) => {
                    let kept =
                        matches!(source, keystore::Source::Store | keystore::Source::Another);
                    (p, choices.remember.unwrap_or(session.meta.remember || kept))
                }
                crypt::Known::Wrong(_) => return Err(connect::WRONG_PASSPHRASE.into()),
                crypt::Known::Missing => return Err(NEED_PASSPHRASE.into()),
            },
        };
        Some((p, remember))
    } else {
        None
    };
    let check = |w: &Where| -> Result<(), String> {
        match used_by(root, w) {
            Some((_, name)) => Err(connect::already_used(&name)),
            None => Ok(()),
        }
    };
    match (
        &session.meta.url,
        &session.meta.branch,
        &session.meta.folder,
    ) {
        (Some(u), Some(b), _) if git => check(&Where::Git {
            url: u.clone(),
            branch: Some(b.clone()),
        })?,
        (_, _, Some(f)) => check(&Where::Folder(PathBuf::from(f)))?,
        _ => {}
    }
    let name = environments::clean_name(&choices.name)?;
    let contents = connect::contents(&found.dir);
    // The environment: the one chosen, if it has no runs of its own, or a
    // new one.
    // What to put back if connecting fails from here on: the environment
    // made for it removed, or the chosen one's name restored.
    let (id, undo) = match &session.meta.env {
        Some(id) => {
            let reg = ws.named_registry();
            let e = reg.get(id).ok_or("That environment no longer exists.")?;
            let env_ws = ws.in_env(id);
            let n = own_runs(&env_ws, None);
            if n > 0 {
                let (lead, rest) = connect::own_runs(e.display(), n);
                return Err(format!("{lead} {rest}"));
            }
            let raw = ws
                .registry()
                .get(id)
                .map(|r| (r.name.clone(), r.domains.clone()))
                .unwrap_or_default();
            let shown = e.display().to_string();
            crate::environments::rename_env(root, id, &name, &shown)?;
            (id.clone(), Undo::Rename(raw.0, raw.1))
        }
        None => {
            let domains = environments::clean_domains(&contents.domains);
            let id = Registry::update(root, |r| r.create(&name, &domains))?;
            (id, Undo::Remove)
        }
    };
    let undo = |e: String| -> String {
        undo.run(root, &id);
        e
    };
    let env_ws = ws.in_env(&id);
    let env_dir = env_ws.env_dir();
    let made_dir = !env_dir.exists();
    std::fs::create_dir_all(&env_dir)
        .map_err(|e| undo(format!("Couldn't create {}: {e}", env_dir.display())))?;
    // Where the history is kept here.
    let (dir, path) = if git {
        let (target, path) = target_folder(&env_dir);
        if let Err(e) = connect::place(&found, &target) {
            if made_dir {
                // Only when empty: never a folder holding anything.
                let _ = std::fs::remove_dir(&env_dir);
            }
            return Err(undo(format!("{e:#}")));
        }
        (target, path)
    } else {
        (found.dir.clone(), Some(plain_path(&found.dir)))
    };
    let mut notes = Vec::new();
    if let Some((p, remember)) = pass {
        // Remembered: from this computer's store from now on, as Runs keeps
        // it; else for this session only.
        let stored = remember
            && match keystore::store(&dir, &p) {
                Ok(_) => true,
                Err(e) => {
                    notes.push(format!(
                        "The passphrase couldn't be stored on this computer ({e:#}); it is kept for this session."
                    ));
                    false
                }
            };
        if !stored {
            crypt::give_passphrase(&dir, p);
        }
    }
    let push = git && choices.push;
    let refresh = choices
        .refresh
        .clamp(1, pathwarden_core::config::MAX_REFRESH_MINUTES);
    let keep = found.keep;
    let encrypted = found.encrypted;
    let edit = StateEdit {
        backend: if git { "git" } else { "local" }.into(),
        path: path.clone(),
        remote: session.meta.url.clone(),
        branch: session.meta.branch.clone(),
        include_names: false,
        push: git.then_some(push),
        keep: Some(keep.as_str().into()),
        refresh: git.then_some(refresh),
    };
    let share = crate::settings::Share {
        base: None,
        env_name: Some(env_ws.env_name()),
    };
    // Saved without sharing: the pull below brings the shared settings in.
    let saved = crate::settings::apply_for_page(env_ws.config_path(), &share, |d| {
        d.set_state(&edit)?;
        if encrypted {
            d.set_state_encrypted(true)?;
        }
        Ok(())
    });
    if let Err(e) = saved {
        // Put the clone back, for another try.
        if git {
            let _ = std::fs::rename(&dir, session.dir.join("history"));
        }
        let e = undo(e);
        return Err(e);
    }
    // The history pulled, its settings and full runs brought in.
    match history_ui::locate(&env_ws, None) {
        Ok(loc) => {
            let by = if page { "pull now" } else { "command line" };
            match history_ui::refresh_detail(
                Some(&env_ws),
                &loc,
                page,
                pathwarden_core::settings_sync::lock_wait(),
                by,
                &mut |_| {},
            ) {
                Ok(p) => notes.extend(p.notes),
                Err(e) => notes.push(e.into_message()),
            }
        }
        Err(e) => notes.push(e),
    }
    discard(root, &session.token);
    let full_runs = env_ws.runs().iter().filter(|r| r.shared.is_some()).count();
    Ok(Connected {
        env_name: env_ws.env_name(),
        env_id: id,
        git,
        keep,
        runs: found.runs,
        full_runs,
        refresh,
        push,
        notes,
    })
}

/// Start a new run history on `w`, refused when it holds one already:
/// the lead and the rest ([`connect::already_holds`]). Probes in a folder
/// made for it under the workspace at `root`, removed after. A repository
/// that can't be looked at is refused too, with why.
pub fn check_new(root: &Path, w: &Where) -> Result<(), (String, String)> {
    let token = token().map_err(|e| (e, String::new()))?;
    let dir = scratch_root(root).join(&token);
    if std::fs::create_dir_all(&dir).is_err() {
        return Ok(());
    }
    let _ = std::fs::write(
        dir.join(META),
        serde_json::to_string(&Meta {
            kind: "check".into(),
            made: pathwarden_core::analyze::now(),
            ..Meta::default()
        })
        .unwrap_or_default(),
    );
    let out = match connect::probe(w, &dir) {
        Ok(found) => Err(connect::already_holds(&found)),
        Err(Problem::Empty { .. }) | Err(Problem::NoBranch { .. }) => Ok(()),
        // A folder that isn't there yet is made by the first run.
        Err(Problem::NoFolder) => Ok(()),
        Err(p) => Err((p.lead(), p.rest())),
    };
    remove_session_dir(&dir);
    let _ = std::fs::remove_dir(scratch_root(root));
    out
}
