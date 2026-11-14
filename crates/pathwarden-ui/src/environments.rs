//! Environments: named parts of one workspace ("Contoso prod", "Lab",
//! "Client A"), each with its own configuration, run history and schedule.
//!
//! - **Where**: the registry is `environments.json` in the workspace. The
//!   Default environment is the workspace itself: its `pathwarden.toml`,
//!   `pathwarden-state` and `history-local.json` stay where they always
//!   were, so a workspace from before environments is the Default
//!   environment with nothing moved or rewritten. Every other environment
//!   keeps the same files in `environments/<id>/`.
//! - **Runs** stay in the shared `runs/` folder, so every run's address
//!   keeps working; a run's summary names its environment
//!   ([`crate::workspace::RunSummary::environment`]), absent for Default.
//! - **The current environment** scopes every page ([`AppState::ws`]): its
//!   runs, settings, zones, plugins, history and schedule. Pages about one
//!   run (its report, retests, accepting one of its risks) use that run's
//!   environment, whichever is current.
//! - **Assignment** ([`assign`]): an analysis goes to the environment the
//!   user chose, else the one whose domains it shares, else the current one.
//!
//! [`AppState::ws`]: crate::server::AppState::ws

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::extract::{Path as UrlPath, Query, State};
use axum::http::header::{self, HeaderMap};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use serde::{Deserialize, Serialize};

use crate::pages::{self, esc, icon, num};
use crate::server::AppState;
use crate::workspace::{RunSummary, Workspace, CONFIG_FILE};

type Shared = Arc<AppState>;

/// The environment every workspace has: the workspace folder itself.
pub const DEFAULT_ENV: &str = "default";
/// The registry, in the workspace folder.
pub const REGISTRY_FILE: &str = "environments.json";
/// Other environments' folders: `environments/<id>/`.
pub const ENVS_DIR: &str = "environments";
/// The longest environment name.
pub const MAX_NAME: usize = 60;

/// One environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// Its folder name and its value in run summaries: lower-case letters,
    /// digits and dashes ([`valid_id`]).
    pub id: String,
    pub name: String,
    /// Domains whose analyses go here when no environment is chosen
    /// ([`assign`]), upper case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// The built-in demo's environment ([`Registry::ensure_demo`]): only
    /// demo runs go there, and real runs never match it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub demo: bool,
    /// The name pages show when it isn't `name`: an unrenamed Default
    /// environment shows as its domains, or "No environment yet"
    /// ([`Registry::with_names`]). Never saved.
    #[serde(skip)]
    pub shown: Option<String>,
}

/// What an unrenamed Default environment with no runs or domains shows.
pub const NO_ENV_YET: &str = "No environment yet";

/// The name of the environment every workspace starts with. It is never
/// shown: an unrenamed Default shows as its domains ([`Registry::with_names`]).
const DEFAULT_NAME: &str = "Default";

impl Environment {
    fn default_env() -> Self {
        Self {
            id: DEFAULT_ENV.into(),
            name: DEFAULT_NAME.into(),
            domains: Vec::new(),
            demo: false,
            shown: None,
        }
    }

    pub fn is_default(&self) -> bool {
        self.id == DEFAULT_ENV
    }

    /// Default under the name it started with (shown as its domains).
    pub fn is_unnamed_default(&self) -> bool {
        self.is_default() && self.name == DEFAULT_NAME
    }

    /// The name to show ([`Environment::shown`], else its name).
    pub fn display(&self) -> &str {
        self.shown.as_deref().unwrap_or(&self.name)
    }
}

/// `environments.json`: every environment (Default first) and the one the
/// app last showed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(default)]
    pub environments: Vec<Environment>,
    /// IDs of environments removed with their runs
    /// ([`crate::env_remove`]): never given to a new environment, and a run
    /// still naming one (saved while it was being removed) is listed
    /// nowhere until it joins the others in `environments/removed`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
    /// The first environment has a run history in a folder given with
    /// `pathwarden ui --state DIR` ([`set_default_state`]): it counts as
    /// used ([`Registry::default_unused`]) in every process, not only that
    /// one, so `env list` shows it and no new environment takes it over.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub default_used: bool,
}

/// One writer at a time in this process; [`LOCK_FILE`] keeps other
/// processes (the app, `--save`, a scheduled run) out too.
static WRITE: Mutex<()> = Mutex::new(());

/// Records that the folder given with `--state` for the first
/// environment of the workspace at `root` (`pathwarden ui --state DIR`,
/// `pathwarden env remove --state DIR`) holds a run history, in the
/// registry ([`Registry::default_used`]): Default then counts as used
/// everywhere. Nothing changes when it holds none (or `dir` is `None`).
pub fn set_default_state(root: &Path, dir: Option<&Path>) {
    if !dir.is_some_and(holds_history) || Registry::load(root).default_used {
        return;
    }
    // A registry that can't be changed is said where it is changed next.
    let _ = Registry::update(root, |r| {
        r.default_used = true;
        Ok(())
    });
}

/// Whether the state folder `dir` holds a run history: the findings
/// `pathwarden run` keeps, or a history point.
fn holds_history(dir: &Path) -> bool {
    ["findings.json", "last-run.json"]
        .iter()
        .any(|f| dir.join(f).is_file())
        || std::fs::read_dir(dir.join("history")).is_ok_and(|mut e| {
            e.any(|f| f.is_ok_and(|f| f.path().extension().is_some_and(|x| x == "json")))
        })
}

/// The lock file beside the registry, held while it changes.
pub const LOCK_FILE: &str = "environments.json.lock";

/// The copy of the registry kept before each change.
pub const BACKUP_FILE: &str = "environments.json.bak";

impl Registry {
    /// The registry of the workspace at `root`; a workspace without one has
    /// only the Default environment. An unreadable file reads the same way
    /// here, for showing pages; changes go through [`Registry::update`],
    /// which refuses to touch it ([`Registry::try_load`]).
    pub fn load(root: &Path) -> Self {
        Self::try_load(root).unwrap_or_else(|_| Self::tidy(Registry::default()))
    }

    /// [`Registry::load`], or why `environments.json` can't be used: it
    /// exists but can't be read or isn't valid. Nothing is ever written over
    /// such a file.
    pub fn try_load(root: &Path) -> Result<Self, String> {
        let path = root.join(REGISTRY_FILE);
        let r: Registry = match std::fs::read_to_string(&path) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| broken(&path, &e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Registry::default(),
            Err(e) => return Err(broken(&path, &e.to_string())),
        };
        Ok(Self::tidy(r))
    }

    /// Invalid and repeated IDs dropped, Default first, names and domains
    /// cleaned, a current environment that no longer exists forgotten.
    fn tidy(mut r: Registry) -> Self {
        r.environments.retain(|e| valid_id(&e.id));
        let mut seen = std::collections::HashSet::new();
        r.environments.retain(|e| seen.insert(e.id.clone()));
        match r.environments.iter().position(Environment::is_default) {
            Some(0) => {}
            Some(i) => {
                let d = r.environments.remove(i);
                r.environments.insert(0, d);
            }
            None => r.environments.insert(0, Environment::default_env()),
        }
        for e in &mut r.environments {
            e.name = clean_name(&e.name).unwrap_or_else(|_| e.id.clone());
            e.domains = clean_domains(&e.domains);
        }
        if r.current.as_deref().is_some_and(|c| r.get(c).is_none()) {
            r.current = None;
        }
        // A removed ID put back by hand (a restore) is an environment again.
        let mut seen = std::collections::HashSet::new();
        let live: Vec<String> = r.environments.iter().map(|e| e.id.clone()).collect();
        r.removed.retain(|id| {
            valid_id(id) && id != DEFAULT_ENV && !live.contains(id) && seen.insert(id.clone())
        });
        r
    }

    /// Writes the registry (atomically: a temporary file, then renamed),
    /// unless it would come out the same; the file it replaces is kept as
    /// [`BACKUP_FILE`].
    fn save(&self, root: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let path = root.join(REGISTRY_FILE);
        let old = std::fs::read_to_string(&path).ok();
        if old.as_deref() == Some(text.as_str()) {
            return Ok(());
        }
        if let Some(old) = old {
            pathwarden_core::config_edit::write_atomic(&root.join(BACKUP_FILE), &old)
                .map_err(|e| format!("Couldn't keep a copy of {REGISTRY_FILE}: {e}"))?;
        }
        pathwarden_core::config_edit::write_atomic(&path, &text)
            .map_err(|e| format!("Couldn't save {REGISTRY_FILE}: {e}"))
    }

    /// Loads, changes and saves the registry under one lock, held against
    /// other processes too ([`LOCK_FILE`]). A registry that can't be read
    /// is an error and is left as it is. Nothing is written when nothing
    /// changed.
    pub fn update<T>(
        root: &Path,
        change: impl FnOnce(&mut Registry) -> Result<T, String>,
    ) -> Result<T, String> {
        let _guard = WRITE.lock().unwrap_or_else(|e| e.into_inner());
        std::fs::create_dir_all(root)
            .map_err(|e| format!("Couldn't create {}: {e}", root.display()))?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(root.join(LOCK_FILE))
            .map_err(|e| format!("Couldn't open {LOCK_FILE}: {e}"))?;
        lock.lock()
            .map_err(|e| format!("Couldn't lock {LOCK_FILE}: {e}"))?;
        let mut r = Self::try_load(root)?;
        let out = change(&mut r)?;
        r.save(root)?;
        drop(lock);
        Ok(out)
    }

    pub fn get(&self, id: &str) -> Option<&Environment> {
        self.environments.iter().find(|e| e.id == id)
    }

    /// An environment by its name, the name it shows as, or its ID,
    /// ignoring case (`--env NAME`).
    pub fn find(&self, name: &str) -> Option<&Environment> {
        let name = name.trim();
        let by = |f: &dyn Fn(&Environment) -> bool| self.environments.iter().find(|e| f(e));
        by(&|e| e.name.eq_ignore_ascii_case(name))
            .or_else(|| by(&|e| e.display().eq_ignore_ascii_case(name)))
            .or_else(|| by(&|e| e.id.eq_ignore_ascii_case(name)))
    }

    /// The name environment `id` shows as (Default's for an unknown one).
    pub fn name_of(&self, id: &str) -> String {
        self.get(id)
            .or_else(|| self.get(DEFAULT_ENV))
            .map(|e| e.display().to_string())
            .unwrap_or_else(|| NO_ENV_YET.into())
    }

    /// Gives an unrenamed Default environment the name it shows as: its
    /// domains (from its list and its runs, `runs` being every run of the
    /// workspace), else "No environment yet". Nothing is saved.
    pub fn with_names(mut self, runs: &[RunSummary]) -> Self {
        let runs: Vec<(String, Vec<String>)> = runs
            .iter()
            .map(|r| (run_env(&self, r), r.domains.clone()))
            .collect();
        if let Some(d) = self.environments.iter_mut().find(|e| e.is_default()) {
            if d.is_unnamed_default() {
                let mut domains = d.domains.clone();
                for (env, ds) in &runs {
                    if env == DEFAULT_ENV {
                        domains.extend(ds.iter().cloned());
                    }
                }
                let domains = clean_domains(&domains);
                d.shown = Some(if domains.is_empty() {
                    NO_ENV_YET.to_string()
                } else {
                    crate::workspace::environment_of(&domains)
                });
            }
        }
        self
    }

    /// The demo's environment, once there is one.
    pub fn demo_id(&self) -> Option<&str> {
        self.environments
            .iter()
            .find(|e| e.demo)
            .map(|e| e.id.as_str())
    }

    /// The demo's environment, made if there is none ("Demo"); its ID.
    pub fn ensure_demo(&mut self) -> String {
        if let Some(id) = self.demo_id() {
            return id.to_string();
        }
        let name = ["Demo", "Demo data", "Built-in demo"]
            .into_iter()
            .find(|n| self.check_unique(n, None).is_ok())
            .unwrap_or("Pathwarden demo");
        let id = self.new_id(name);
        self.environments.push(Environment {
            id: id.clone(),
            name: name.to_string(),
            domains: Vec::new(),
            demo: true,
            shown: None,
        });
        id
    }

    /// Whether Default (the workspace folder of `root`) was never used:
    /// still unnamed, no domains listed, no runs (`runs`: each real run's
    /// environment and domains), and none of its files: no settings, no run
    /// history (in the workspace folder, or in a folder given with
    /// `pathwarden ui --state`, [`Registry::default_used`]), no labels or runs
    /// kept local. The first new environment then takes its place, so a
    /// fresh workspace never shows an empty one; a Default with anything of
    /// its own is never hidden or taken over.
    pub fn default_unused(&self, root: &Path, runs: &[RunDomains]) -> bool {
        self.get(DEFAULT_ENV)
            .is_some_and(|d| d.is_unnamed_default() && d.domains.is_empty())
            && !runs.iter().any(|r| r.env == DEFAULT_ENV)
            && [
                crate::workspace::CONFIG_FILE,
                crate::history_ui::DEFAULT_FOLDER,
                crate::workspace::LABELS_FILE,
                "history-local.json",
            ]
            .iter()
            .all(|f| !root.join(f).exists())
            && !self.default_used
    }

    /// Default as a new workspace has it: unnamed, no domains (after its
    /// runs and files were removed, [`crate::env_remove`]).
    pub(crate) fn reset_default(&mut self) {
        if let Some(d) = self.environments.iter_mut().find(|e| e.is_default()) {
            *d = Environment::default_env();
        }
        self.default_used = false;
    }

    /// Whether the workspace has more than the Default environment.
    pub fn several(&self) -> bool {
        self.environments.len() > 1
    }

    /// Adds an environment named `name`; returns its ID.
    pub fn create(&mut self, name: &str, domains: &[String]) -> Result<String, String> {
        let name = clean_name(name)?;
        self.check_unique(&name, None)?;
        let id = self.new_id(&name);
        self.environments.push(Environment {
            id: id.clone(),
            name,
            domains: clean_domains(domains),
            demo: false,
            shown: None,
        });
        Ok(id)
    }

    /// Renames environment `id` and sets its domains.
    pub fn edit(&mut self, id: &str, name: &str, domains: &[String]) -> Result<(), String> {
        let name = clean_name(name)?;
        self.check_unique(&name, Some(id))?;
        let env = self
            .environments
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or("That environment no longer exists.")?;
        env.name = name;
        env.domains = clean_domains(domains);
        Ok(())
    }

    fn check_unique(&self, name: &str, except: Option<&str>) -> Result<(), String> {
        if self
            .environments
            .iter()
            .any(|e| Some(e.id.as_str()) != except && e.name.eq_ignore_ascii_case(name))
        {
            return Err(format!("There is already an environment named {name}."));
        }
        Ok(())
    }

    /// A folder name from `name`: lower-case letters and digits, other
    /// characters as dashes, made unique.
    fn new_id(&self, name: &str) -> String {
        let mut base = String::new();
        for c in name.chars() {
            if c.is_ascii_alphanumeric() {
                base.push(c.to_ascii_lowercase());
            } else if !base.ends_with('-') && !base.is_empty() {
                base.push('-');
            }
        }
        let mut base: String = base.trim_end_matches('-').chars().take(32).collect();
        base = base.trim_end_matches('-').to_string();
        if base.is_empty() || base == DEFAULT_ENV {
            base = "environment".into();
        }
        let mut id = base.clone();
        let mut n = 2;
        while self.get(&id).is_some() || self.removed.contains(&id) || reserved_id(&id) {
            id = format!("{base}-{n}");
            n += 1;
        }
        id
    }
}

/// Why a registry file can't be used, and what to do.
fn broken(path: &Path, why: &str) -> String {
    format!(
        "{} can't be read ({why}). Pathwarden won't change it: fix it, or move it away to start over (a copy of the last good one may be in {BACKUP_FILE}).",
        path.display()
    )
}

/// Folder names under `environments/` that are not environments'
/// (`removed`, [`crate::env_remove::REMOVED_DIR`]) or that a removal's folder
/// uses (`env`, `env-later`, `runs`, `collections`): never given to a new
/// environment ([`Registry::new_id`]). [`valid_id`] still accepts them, so an
/// environment that already has one (made before they were reserved) keeps
/// its runs; removing environments then stops until it is removed or renamed
/// by hand ([`crate::env_remove::plan`]).
pub const RESERVED_IDS: &[&str] = &["removed", "env", "env-later", "runs", "collections"];

/// Whether `id` is reserved ([`RESERVED_IDS`]).
pub fn reserved_id(id: &str) -> bool {
    RESERVED_IDS.contains(&id)
}

/// IDs are lower-case letters, digits and dashes (1 to 40), not starting
/// with a dash, so they always name a folder inside `environments/`.
pub fn valid_id(id: &str) -> bool {
    (1..=40).contains(&id.len())
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A name as typed: trimmed, 1 to [`MAX_NAME`] characters, no control or
/// bidi characters.
pub fn clean_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Enter a name for the environment.".into());
    }
    if name.chars().count() > MAX_NAME {
        return Err(format!("Use at most {MAX_NAME} characters for the name."));
    }
    if name
        .chars()
        .any(|c| c.is_control() || pathwarden_core::text::is_bidi_control(c))
    {
        return Err("The name can't contain control characters.".into());
    }
    Ok(name.to_string())
}

/// Domain names: trimmed, upper case, without duplicates or blanks, only
/// characters a DNS name has.
pub fn clean_domains(domains: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in domains {
        let d = d.trim().trim_end_matches('.').to_ascii_uppercase();
        if d.is_empty()
            || d.len() > 253
            || !d
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        {
            continue;
        }
        if !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

/// Splits a typed list of domains (commas, spaces or new lines).
pub fn split_domains(text: &str) -> Vec<String> {
    clean_domains(&tokens(text))
}

fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// A typed list of domains, or which entries aren't domain names. A domain
/// here is a DNS name with at least two labels (`corp.example.com`): what
/// collectors report, and what the data's domains are matched against.
/// Nothing typed is dropped quietly.
pub fn parse_domains(text: &str) -> Result<Vec<String>, String> {
    let bad: Vec<String> = tokens(text)
        .into_iter()
        .filter(|t| !is_domain_name(t.trim_end_matches('.')))
        .collect();
    if bad.is_empty() {
        return Ok(split_domains(text));
    }
    let shown: Vec<String> = bad.iter().take(5).map(|b| format!("\"{b}\"")).collect();
    Err(format!(
        "{} {}: use the DNS name, like corp.example.com, separated by commas or new lines.",
        shown.join(", "),
        if bad.len() == 1 {
            "is not a domain name"
        } else {
            "are not domain names"
        }
    ))
}

fn is_domain_name(d: &str) -> bool {
    d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Why [`still_listed`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotListed {
    /// The environment was removed ([`crate::env_remove`]).
    Removed,
    /// `environments.json` can't be read (why, as [`Registry::try_load`]
    /// says).
    Unreadable(String),
}

/// Whether the environment `ws` is scoped to is still listed, before
/// something is written for it (a run, a label, a history choice), so a
/// removed environment's folder is not made again. The first environment
/// always is.
pub fn still_listed(ws: &Workspace) -> Result<(), NotListed> {
    if ws.is_default_env() {
        return Ok(());
    }
    let reg = Registry::try_load(ws.root()).map_err(NotListed::Unreadable)?;
    if reg.get(ws.env_id()).is_some() {
        Ok(())
    } else {
        Err(NotListed::Removed)
    }
}

/// [`still_listed`] as a message.
pub fn check_listed(ws: &Workspace) -> Result<(), String> {
    still_listed(ws).map_err(|e| match e {
        NotListed::Removed => "That environment was removed, so nothing was saved for it.".into(),
        NotListed::Unreadable(why) => why,
    })
}

/// The folder holding environment `id`'s files: the workspace itself for
/// Default.
pub fn env_dir(root: &Path, id: &str) -> PathBuf {
    if id == DEFAULT_ENV || !valid_id(id) {
        root.to_path_buf()
    } else {
        root.join(ENVS_DIR).join(id)
    }
}

/// Why an analysis went to the environment it did, for the run page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assigned {
    /// The user picked it on Analyze or Collect (or `--env` / `--new-env`).
    Chosen,
    /// Its domain list names the analysis's domains.
    ByDomains,
    /// Its earlier runs covered the analysis's domains.
    ByRuns,
    /// It has some of the analysis's domains and no other environment has
    /// any; the others are new, and go on its list.
    Joined,
    /// No environment had the domains: made for this run.
    New,
    /// The data named no domain: the environment that was current.
    Current,
}

impl Assigned {
    /// Its value in run summaries.
    pub fn as_str(self) -> &'static str {
        match self {
            Assigned::Chosen => "chosen",
            Assigned::ByDomains => "domains",
            Assigned::ByRuns => "runs",
            Assigned::Joined => "joined",
            Assigned::New => "new",
            Assigned::Current => "current",
        }
    }
}

/// The environment a run belongs to: a demo run is the demo environment's
/// (once there is one, [`Registry::ensure_demo`]), so the demo never mixes
/// with real runs; any other run is the environment its summary names, or
/// Default (runs from before environments, an unknown environment). A run
/// of an environment removed with its runs ([`Registry::removed`]) keeps
/// that ID, which no list shows, so it never turns up in Default.
pub fn run_env(reg: &Registry, run: &RunSummary) -> String {
    if run.demo {
        if let Some(id) = reg.demo_id() {
            return id.to_string();
        }
    }
    match run.environment.as_deref() {
        Some(id) if reg.get(id).is_some() || reg.removed.iter().any(|r| r == id) => id.to_string(),
        _ => DEFAULT_ENV.into(),
    }
}

/// One real run as [`decide`] weighs it ([`run_domains`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDomains {
    /// Its environment ([`run_env`]).
    pub env: String,
    pub domains: Vec<String>,
    /// Saved by 0.1.1 or earlier with several domains that no later run
    /// mapped ([`RunSummary::legacy_domains`]): some may be trusted ones.
    pub legacy: bool,
}

/// Every real run's environment and domains, for [`decide`] (demo runs
/// left out).
pub fn run_domains(reg: &Registry, runs: &[RunSummary]) -> Vec<RunDomains> {
    runs.iter()
        .filter(|r| !r.demo)
        .map(|r| RunDomains {
            env: run_env(reg, r),
            domains: r.domains.clone(),
            legacy: r.legacy_domains,
        })
        .collect()
}

/// [`run_domains`] for placing a run that `collected` some domains and
/// only trusts others (`(collected, trusted)`). An old run
/// ([`RunDomains::legacy`]) listing exactly those, together, is that
/// collection's, as [`crate::workspace::migrate_domains`] maps it once
/// this run is saved: it places the run as any run does. `None` (the
/// trusted domains aren't known yet: before a collection, or on the
/// command line before the analysis): no old run asks yet; the analysis
/// checks again with the data.
pub fn run_domains_for(
    reg: &Registry,
    runs: &[RunSummary],
    collection: Option<(&[String], &[String])>,
) -> Vec<RunDomains> {
    let set = |ds: &[String]| {
        let mut v: Vec<String> = ds.iter().map(|d| d.trim().to_ascii_uppercase()).collect();
        v.sort();
        v.dedup();
        v
    };
    let mine = collection.map(|(c, t)| set(&[c, t].concat()));
    let mut out = run_domains(reg, runs);
    for r in out.iter_mut().filter(|r| r.legacy) {
        r.legacy = mine.as_ref().is_some_and(|m| *m != set(&r.domains));
    }
    out
}

/// Where a run goes, from the domains it collected ([`decide`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Exactly one environment has its domains, and none is new.
    Match { id: String, how: Assigned },
    /// No environment has any of them: a new one, named after them
    /// ([`crate::workspace::environment_of`]: "CONTOSO.COM", or "A.LOCAL
    /// and B.LOCAL" for several).
    New { name: String },
    /// Something's off: the domains match two environments, or some match
    /// one and others are new. The user picks.
    Ask(Ask),
    /// The data named no domain: the current environment.
    Current,
}

/// Why a run's environment has to be asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// Each environment that has some of the domains, with those domains,
    /// in registry order.
    pub matches: Vec<(String, Vec<String>)>,
    /// The domains no environment has.
    pub new: Vec<String>,
    /// The domains that match only through runs saved by 0.1.1 or earlier
    /// that no later run mapped: the environment picked lists them too.
    pub legacy: Vec<String>,
}

impl Ask {
    /// The reason in one sentence: "FABRIKAM.LOCAL matches Lab;
    /// WOODGROVE.LOCAL is new." (names as `reg` shows them).
    pub fn reason(&self, reg: &Registry) -> String {
        self.reason_with(reg, &|d| d.to_string(), &|n| n.to_string())
    }

    /// [`Ask::reason`] as HTML, the domains in bold.
    pub fn reason_html(&self, reg: &Registry) -> String {
        let esc = crate::pages::esc;
        self.reason_with(reg, &|d| format!("<strong>{}</strong>", esc(d)), &esc)
    }

    /// The reason, with each domain written by `dom` and each environment
    /// name by `name`.
    fn reason_with(
        &self,
        reg: &Registry,
        dom: &dyn Fn(&str) -> String,
        name: &dyn Fn(&str) -> String,
    ) -> String {
        let list = |items: &[String], f: &dyn Fn(&str) -> String| {
            and_list(&items.iter().map(|i| f(i)).collect::<Vec<_>>())
        };
        // Environments with the same domains share a clause. Domains
        // matched only through old runs get a clause of their own below,
        // so each domain is said once.
        let mut clauses: Vec<(Vec<String>, Vec<String>)> = Vec::new();
        for (id, domains) in &self.matches {
            let domains: Vec<String> = domains
                .iter()
                .filter(|d| !self.legacy.contains(d))
                .cloned()
                .collect();
            if domains.is_empty() {
                continue;
            }
            let name = reg.name_of(id);
            match clauses.iter_mut().find(|(d, _)| *d == domains) {
                Some((_, names)) => names.push(name),
                None => clauses.push((domains, vec![name])),
            }
        }
        let mut parts: Vec<String> = clauses
            .iter()
            .map(|(domains, names)| {
                format!(
                    "{} {} {}",
                    list(domains, dom),
                    if domains.len() == 1 {
                        "matches"
                    } else {
                        "match"
                    },
                    list(names, name)
                )
            })
            .collect();
        if !self.new.is_empty() {
            parts.push(format!(
                "{} {} new",
                list(&self.new, dom),
                if self.new.len() == 1 { "is" } else { "are" }
            ));
        }
        let mut out = if parts.is_empty() {
            String::new()
        } else {
            format!("{}.", parts.join("; "))
        };
        if !self.legacy.is_empty() {
            if !out.is_empty() {
                out.push(' ');
            }
            let names: Vec<String> = self
                .matches
                .iter()
                .filter(|(_, ds)| ds.iter().any(|d| self.legacy.contains(d)))
                .map(|(id, _)| name(&reg.name_of(id)))
                .collect();
            out.push_str(&format!(
                "{} {} {} only through runs saved by Pathwarden 0.1.1 or earlier, which also counted trusted domains: asked once.",
                list(&self.legacy, dom),
                if self.legacy.len() == 1 { "matches" } else { "match" },
                and_list(&names)
            ));
        }
        out
    }

    /// Whether some domains are new (else: two environments match).
    pub fn partial(&self) -> bool {
        !self.new.is_empty()
    }
}

/// "A", "A and B", "A, B and C".
pub fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// How environments have a domain ([`owners`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owned {
    /// On their domain lists.
    Listed,
    /// Through earlier runs of it.
    Runs,
    /// Only through runs saved by 0.1.1 or earlier that no later run
    /// mapped ([`RunDomains::legacy`]): the domain may only have been
    /// trusted there.
    Legacy,
}

/// Which environments have each domain: those whose domain list names it,
/// else those with an earlier run of it (`runs`: each real run's
/// environment and domains). A list wins over runs, so listing a domain
/// for an environment settles where its runs go. The demo's environment
/// never has a domain.
fn owners(reg: &Registry, domain: &str, runs: &[RunDomains]) -> (Vec<String>, Owned) {
    let real = || reg.environments.iter().filter(|e| !e.demo);
    let listed: Vec<String> = real()
        .filter(|e| e.domains.iter().any(|d| d == domain))
        .map(|e| e.id.clone())
        .collect();
    if !listed.is_empty() {
        return (listed, Owned::Listed);
    }
    let by = |legacy: bool| -> Vec<String> {
        real()
            .filter(|e| {
                runs.iter().any(|r| {
                    r.env == e.id
                        && r.legacy == legacy
                        && r.domains.iter().any(|d| d.eq_ignore_ascii_case(domain))
                })
            })
            .map(|e| e.id.clone())
            .collect()
    };
    let by_runs = by(false);
    if !by_runs.is_empty() {
        return (by_runs, Owned::Runs);
    }
    (by(true), Owned::Legacy)
}

/// Where a run of `domains` (the domains it collected, as
/// [`pathwarden_core::analyze::domain_names`] gives them: trusted domains
/// are never in it) goes, by the same rules in the UI and on the command
/// line. Domains compare ignoring case.
///
/// - Every domain belongs to the same one environment ([`owners`]): that
///   one ([`Decision::Match`]).
/// - Some belong to one environment and the rest to none: that one too, so
///   a run that collected one more domain stays with its history
///   ([`Assigned::Joined`]; [`settle`] lists the new ones there).
/// - None belongs to any: a new environment ([`Decision::New`]).
/// - Otherwise something's off: some domains belong to two environments,
///   or to different ones ([`Decision::Ask`]).
/// - A domain an environment has only through runs saved by 0.1.1 or
///   earlier that no later run (nor the run being placed,
///   [`run_domains_for`]) maps (they counted trusted domains) is asked
///   about too, once: the environment picked then lists it.
pub fn decide(reg: &Registry, domains: &[String], runs: &[RunDomains]) -> Decision {
    let wanted = clean_domains(domains);
    if wanted.is_empty() {
        return Decision::Current;
    }
    let mut matches: Vec<(String, Vec<String>)> = Vec::new();
    let mut new = Vec::new();
    let mut all_listed = true;
    let mut legacy = Vec::new();
    for d in &wanted {
        let (envs, how) = owners(reg, d, runs);
        if envs.is_empty() {
            new.push(d.clone());
            continue;
        }
        all_listed &= how == Owned::Listed;
        if how == Owned::Legacy {
            legacy.push(d.clone());
        }
        for id in envs {
            match matches.iter_mut().find(|(e, _)| *e == id) {
                Some((_, ds)) => ds.push(d.clone()),
                None => matches.push((id, vec![d.clone()])),
            }
        }
    }
    // Registry order, for a stable reason and stable cards.
    matches.sort_by_key(|(id, _)| reg.environments.iter().position(|e| e.id == *id));
    match (matches.len(), new.is_empty()) {
        (0, _) => Decision::New {
            name: new_name(&wanted),
        },
        (1, true) if legacy.is_empty() => Decision::Match {
            id: matches.remove(0).0,
            how: if all_listed {
                Assigned::ByDomains
            } else {
                Assigned::ByRuns
            },
        },
        // One more domain than before (or several): the environment that
        // has the others, with no other one in the way.
        (1, false) if legacy.is_empty() => Decision::Match {
            id: matches.remove(0).0,
            how: Assigned::Joined,
        },
        _ => Decision::Ask(Ask {
            matches,
            new,
            legacy,
        }),
    }
}

/// A new environment's name from its domains: the computed name, cut to
/// [`MAX_NAME`] characters.
pub fn new_name(domains: &[String]) -> String {
    let name = crate::workspace::environment_of(&clean_domains(domains));
    if name.chars().count() <= MAX_NAME {
        return name;
    }
    let cut: String = name.chars().take(MAX_NAME - 1).collect();
    format!("{}…", cut.trim_end())
}

/// Where the user (or the command line) put a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// An existing environment, by ID.
    Env(String),
    /// A new environment with this name.
    New(String),
}

/// Where a run goes, all told ([`place`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// To the chosen or matching environment, or a new one ([`settle`];
    /// with `true`, the choice came from the domains, so [`settle`] decides
    /// again under the registry's lock).
    Settle(Choice, Assigned, bool),
    /// Ask the user (the command line stops).
    Ask(Ask),
    /// The data named no domain: the current environment.
    Current,
    /// The built-in demo, to its own environment (never decided).
    Demo(String),
}

/// Where a run of `domains` goes, given the user's `choice`. A choice the
/// user made wins. With `auto`, the choice is one a page made by itself
/// from the domains it could read beforehand (which may not be all of
/// them): the data's own domains decide ([`decide`]), and when something's
/// off the user is asked, whatever the page showed.
pub fn place(
    reg: &Registry,
    domains: &[String],
    runs: &[RunDomains],
    choice: Option<&Choice>,
    auto: bool,
) -> Placement {
    if let (Some(c), false) = (choice, auto) {
        return Placement::Settle(c.clone(), Assigned::Chosen, false);
    }
    match decide(reg, domains, runs) {
        Decision::Match { id, how } => Placement::Settle(Choice::Env(id), how, true),
        Decision::New { name } => Placement::Settle(Choice::New(name), Assigned::New, true),
        Decision::Current => Placement::Current,
        Decision::Ask(ask) => Placement::Ask(ask),
    }
}

/// What [`settle`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    pub id: String,
    /// Made for this run (or the unused Default renamed for it).
    pub created: bool,
    /// Domains put on its list.
    pub added: Vec<String>,
    /// How the run got there (decided again when the choice was automatic).
    pub how: Assigned,
}

/// What [`settle`] came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settling {
    Settled(Settled),
    /// The choice was automatic and the environments changed meanwhile, so
    /// something's off by now: nothing changed, the user is asked (as with
    /// [`Placement::Ask`]).
    Ask(Ask),
}

/// Applies a choice to the registry, under its lock: a new environment is
/// made (or an unused Default takes the name, so a fresh workspace has no
/// empty environment left over); the domains of `domains` that no
/// environment has go on the chosen one's list, so the next run of the same
/// collection lands there without asking. With `automatic` (the choice came
/// from the domains), it is decided again on the registry as it is under
/// the lock, so two runs at once never make two environments for one
/// domain, and the user is asked when something's off by now
/// ([`Settling::Ask`]); a computed name already taken gets " (2)". A typed
/// name already taken is an error.
pub fn settle(
    root: &Path,
    choice: &Choice,
    how: Assigned,
    domains: &[String],
    runs: &[RunDomains],
    automatic: bool,
) -> Result<Settling, String> {
    let wanted = clean_domains(domains);
    let settled = Registry::update(root, |r| {
        let (choice, how) = if automatic {
            match decide(r, &wanted, runs) {
                Decision::Match { id, how } => (Choice::Env(id), how),
                Decision::New { name } => (Choice::New(name), Assigned::New),
                Decision::Current => (choice.clone(), how),
                Decision::Ask(ask) => return Ok(Settling::Ask(ask)),
            }
        } else {
            (choice.clone(), how)
        };
        let auto_name = automatic;
        // A domain only old runs have is listed too, so it is asked once.
        let fresh: Vec<String> = wanted
            .iter()
            .filter(|d| {
                let (envs, how) = owners(r, d, runs);
                envs.is_empty() || how == Owned::Legacy
            })
            .cloned()
            .collect();
        let (id, created) = match &choice {
            Choice::Env(id) => {
                let e = r.get(id).ok_or("That environment no longer exists.")?;
                if e.demo {
                    return Err("Only the demo goes in the demo's environment.".into());
                }
                (id.clone(), false)
            }
            Choice::New(name) => {
                let mut name = clean_name(name)?;
                if auto_name {
                    let base = name.clone();
                    let mut n = 2;
                    while r.check_unique(&name, None).is_err() {
                        name = format!("{base} ({n})");
                        n += 1;
                    }
                }
                if r.default_unused(root, runs) {
                    r.check_unique(&name, Some(DEFAULT_ENV))?;
                    let d = r
                        .environments
                        .iter_mut()
                        .find(|e| e.is_default())
                        .ok_or("The workspace has no Default environment.")?;
                    d.name = name;
                    (DEFAULT_ENV.to_string(), true)
                } else {
                    (r.create(&name, &[])?, true)
                }
            }
        };
        let env = r
            .environments
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or("That environment no longer exists.")?;
        let mut added = Vec::new();
        for d in fresh {
            if !env.domains.contains(&d) {
                env.domains.push(d.clone());
                added.push(d);
            }
        }
        Ok(Settling::Settled(Settled {
            id,
            created,
            added,
            how,
        }))
    })?;
    if let Settling::Settled(s) = &settled {
        let dir = env_dir(root, &s.id);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Couldn't create {}: {e}", dir.display()))?;
    }
    Ok(settled)
}

// ------------------------------------------------------- the command line

/// What `--env NAME` means on the command line: the environment's config
/// and run history in the UI workspace.
#[derive(Debug, Clone)]
pub struct EnvPaths {
    pub id: String,
    pub name: String,
    /// Its `pathwarden.toml`, when it has one (else the defaults apply).
    pub config: Option<PathBuf>,
    /// Its run history folder, as the UI records into it (`[state]` in its
    /// config, a relative path taken from the environment's folder, else
    /// `pathwarden-state` there).
    pub state: PathBuf,
    /// Its folder (labels set in the UI are kept there,
    /// [`crate::workspace::LABELS_FILE`]).
    pub dir: PathBuf,
}

/// Finds environment `name` (its name or ID, ignoring case) in the
/// workspace at `workspace` (default: the UI's per-user workspace).
pub fn cli_paths(workspace: Option<&Path>, name: &str) -> anyhow::Result<EnvPaths> {
    let root = match workspace {
        Some(d) => d.to_path_buf(),
        None => crate::workspace::default_dir()?,
    };
    let ws = Workspace::existing(&root)?;
    let reg = ws.named_registry();
    let Some(env) = reg.find(name) else {
        anyhow::bail!(
            "no environment named {name:?} in {} (there is: {})",
            root.display(),
            names_list(&reg, ws.root(), &ws.all_runs())
        );
    };
    let ws = ws.in_env(&env.id);
    let config = ws.config_path();
    let state = crate::history_ui::locate(&ws, None)
        .map_err(|e| anyhow::anyhow!("environment {}: {e}", env.name))?
        .dir;
    Ok(EnvPaths {
        id: env.id.clone(),
        name: env.display().to_string(),
        config: config.is_file().then_some(config),
        state,
        dir: ws.env_dir(),
    })
}

/// The UI workspace scoped to environment `name`, for commands that change
/// it (`pathwarden history --forget`).
pub fn cli_workspace(workspace: Option<&Path>, name: &str) -> anyhow::Result<Workspace> {
    let root = match workspace {
        Some(d) => d.to_path_buf(),
        None => crate::workspace::default_dir()?,
    };
    let ws = Workspace::existing(&root)?;
    let reg = ws.named_registry();
    let Some(env) = reg.find(name) else {
        anyhow::bail!(
            "no environment named {name:?} in {} (there is: {})",
            root.display(),
            names_list(&reg, ws.root(), &ws.all_runs())
        );
    };
    let id = env.id.clone();
    Ok(ws.in_env(&id))
}

/// Creates an environment, as the app's "New environment" does: `domains`
/// as typed (refused if any isn't a domain name), its folder, and its
/// settings copied from environment `copy` (an ID; empty for the defaults).
/// Returns its ID. Shared with `pathwarden env create`.
pub fn create_environment(
    ws: &Workspace,
    name: &str,
    domains: &str,
    copy: &str,
) -> Result<String, String> {
    let root = ws.root().to_path_buf();
    let copy = copy.trim().to_string();
    let id = Registry::update(&root, |r| {
        if !copy.is_empty() && r.get(&copy).is_none() {
            return Err("The environment to copy settings from no longer exists.".into());
        }
        r.create(name, &parse_domains(domains)?)
    })?;
    let new = ws.in_env(&id);
    let dir = new.env_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("Couldn't create {}: {e}", dir.display()))?;
    if !copy.is_empty() {
        let from = ws.in_env(&copy).config_path();
        if from.is_file() {
            std::fs::copy(&from, new.config_path())
                .map_err(|e| format!("Couldn't copy the settings: {e}"))?;
        }
    }
    Ok(id)
}

/// Sets environment `id`'s domains, as typed (its name stays). Shared with
/// `pathwarden env domains`.
pub fn set_domains(root: &Path, id: &str, domains: &str) -> Result<(), String> {
    Registry::update(root, |r| {
        let name = r
            .get(id)
            .map(|e| e.name.clone())
            .ok_or("That environment no longer exists.")?;
        r.edit(id, &name, &parse_domains(domains)?)
    })
}

/// Makes environment `id` the one the app opens in. Shared with
/// `pathwarden env use`.
pub fn make_current(root: &Path, id: &str) -> Result<(), String> {
    Registry::update(root, |r| {
        if r.get(id).is_none() {
            return Err("That environment no longer exists.".into());
        }
        r.current = Some(id.to_string());
        Ok(())
    })
}

/// [`cli_paths`] for the environment `workspace` has current (the one the
/// app opens in).
pub fn cli_paths_current(workspace: &Path) -> anyhow::Result<EnvPaths> {
    let ws = cli_workspace_or_current(Some(workspace), None)?;
    cli_paths(Some(workspace), ws.env_id())
}

/// [`cli_workspace`] for `name`, or the environment the app has current
/// (the one `pathwarden ui` opens in) when no name is given.
pub fn cli_workspace_or_current(
    workspace: Option<&Path>,
    name: Option<&str>,
) -> anyhow::Result<Workspace> {
    if let Some(name) = name {
        return cli_workspace(workspace, name);
    }
    let root = match workspace {
        Some(d) => d.to_path_buf(),
        None => crate::workspace::default_dir()?,
    };
    let ws = Workspace::existing(&root)?;
    let reg = ws.registry();
    let current = reg
        .current
        .clone()
        .filter(|id| reg.get(id).is_some())
        .unwrap_or_else(|| DEFAULT_ENV.to_string());
    Ok(ws.in_env(&current))
}

/// The environments' names for a message ("GOAD lab, Production"; an
/// unused Default and the demo's left out), or "none yet".
pub fn names_list(reg: &Registry, root: &Path, runs: &[RunSummary]) -> String {
    let unused = reg.default_unused(root, &run_domains(reg, runs));
    let names: Vec<&str> = reg
        .environments
        .iter()
        .filter(|e| !e.demo && !(e.is_default() && unused))
        // A Default with nothing to show as yet goes by its ID.
        .map(|e| {
            if e.display() == NO_ENV_YET {
                e.id.as_str()
            } else {
                e.display()
            }
        })
        .collect();
    if names.is_empty() {
        "none yet".into()
    } else {
        names.join(", ")
    }
}

// ------------------------------------------------------------- the pages

/// The Environments page and the switcher's routes.
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/environments", get(page).post(create))
        .route("/environments/switch", post(switch))
        .route("/environments/{id}/edit", post(edit))
        .route("/environments/{id}/rename", post(rename))
        .route("/environments/{id}/remove", get(remove_page).post(remove))
}

#[derive(Deserialize)]
struct SwitchQuery {
    to: String,
    /// Where to go after, a path on this site (Explore's environment menu
    /// opens the new one's latest run there); else back where the browser
    /// was.
    #[serde(default)]
    then: Option<String>,
}

/// The switcher (a form post, so it works without a script): makes the
/// environment current and goes back to the page the browser was on. A
/// page about one run stays open only if the run is in that environment;
/// otherwise the browser goes to that section's list.
async fn switch(
    State(st): State<Shared>,
    Query(q): Query<SwitchQuery>,
    headers: HeaderMap,
) -> Response {
    if !st.set_env(&q.to) {
        return not_found_page();
    }
    // Only a plain path on this site, never one that could leave it; the
    // one query kept is Explore's Forest view.
    if let Some(then) = q.then.as_deref().filter(|p| {
        let (path, query) = p.split_once('?').unwrap_or((p, ""));
        local_path(&format!("http://here{path}")).as_deref() == Some(path)
            && (query.is_empty() || query == "view=forest")
    }) {
        return Redirect::to(then).into_response();
    }
    let back = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .and_then(local_path)
        .unwrap_or_else(|| "/".into());
    let back = match back.strip_prefix("/runs/") {
        Some(rest) => {
            let id = rest.split('/').next().unwrap_or_default();
            let same = st
                .workspace
                .summary(id)
                .is_some_and(|r| Workspace::env_of(&st.workspace.registry(), &r) == q.to);
            if same {
                back
            } else {
                "/runs".into()
            }
        }
        None => back,
    };
    Redirect::to(&back).into_response()
}

/// The path of a `Referer` on this site (`http://127.0.0.1:PORT/path?q`
/// gives `/path`), never one that could leave it (`//host`, `/\host`).
fn local_path(referer: &str) -> Option<String> {
    let rest = referer.split_once("://")?.1;
    let path = &rest[rest.find('/')?..];
    let path = path.split(['?', '#']).next().unwrap_or("/");
    let ok = path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('\\')
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.~%".contains(&b));
    ok.then(|| path.to_string())
}

fn not_found_page() -> Response {
    (StatusCode::NOT_FOUND, Html(pages::not_found())).into_response()
}

#[derive(Deserialize)]
struct PageQuery {
    /// The folder of a removal that just finished, to say what it did.
    #[serde(default)]
    removed: String,
}

async fn page(State(st): State<Shared>, Query(q): Query<PageQuery>) -> Html<String> {
    let st2 = st.clone();
    Html(
        tokio::task::spawn_blocking(move || {
            let done = crate::env_remove::finished_message(st2.workspace.root(), &q.removed)
                .unwrap_or_default();
            render_with(&st2, None, None, &done)
        })
        .await
        .unwrap_or_default(),
    )
}

/// The page, with `error` shown at the top (and its form `open_form` kept
/// open) after a change that couldn't be made.
fn render(st: &AppState, error: Option<&str>, open_form: Option<&str>) -> String {
    render_with(st, error, open_form, &[])
}

/// [`render`], with what a removal that just finished did (`done`).
fn render_with(
    st: &AppState,
    error: Option<&str>,
    open_form: Option<&str>,
    done: &[String],
) -> String {
    let current = st.env_id();
    let all = st.workspace.all_runs();
    let reg = st.workspace.registry().with_names(&all);
    let unused = reg.default_unused(st.workspace.root(), &run_domains(&reg, &all));
    // A registry that can't be read is never written over: say so.
    let error = match (error, Registry::try_load(st.workspace.root())) {
        (Some(e), _) => Some(e.to_string()),
        (None, Err(e)) => Some(e),
        (None, Ok(_)) => None,
    };
    let error = error.as_deref();
    let mut b = String::new();
    let _ = write!(
        b,
        r#"<div class="page-head"><div><p class="eyebrow">Configure</p><h1 class="panel-title">Environments</h1>
<p class="lead">Each environment has its own settings, run history and schedule. Switch with the Environment menu.</p></div></div>"#
    );
    if let Some(e) = error {
        let _ = write!(
            b,
            r#"<div class="env-error card" role="alert"><strong>Not saved.</strong> {}</div>"#,
            esc(e)
        );
    }
    // Present on load: a status, not an alert; the steps collapsed.
    if let Some(note) = crate::env_remove::reserved_note(st.workspace.root()) {
        let _ = write!(
            b,
            r#"<div class="env-error env-stuck card" role="status"><p><strong>{}</strong></p>"#,
            esc(&note.lead())
        );
        if note.why.is_some() {
            let _ = write!(
                b,
                r#"<details><summary>What to do</summary><p>{}</p><p>To go on by hand, stop Pathwarden and:</p><ol>{}</ol></details>"#,
                esc(&note.reason()),
                note.step_list()
                    .iter()
                    .map(|s| format!("<li>{}</li>", esc(s)))
                    .collect::<String>()
            );
        }
        b.push_str("</div>");
    }
    if let Some((first, rest)) = done.split_first() {
        let _ = write!(
            b,
            r#"<div class="env-done card" role="status"><p><strong>{}</strong></p>{}</div>"#,
            esc(first),
            rest.iter()
                .map(|l| format!("<p>{}</p>", esc(l)))
                .collect::<String>()
        );
    }
    b.push_str(r#"<div class="envs-list">"#);
    // An unused Default is nothing to manage (the first collection takes
    // its place); it shows while it is current, as "No environment yet".
    for e in reg
        .environments
        .iter()
        .filter(|e| !(e.is_default() && unused) || e.id == current)
    {
        let ws = st.workspace.in_env(&e.id);
        let runs: Vec<&RunSummary> = all
            .iter()
            .filter(|r| Workspace::env_of(&reg, r) == e.id)
            .collect();
        let loaded = crate::settings::load_ws(&ws);
        let settings = match &loaded.error {
            Some(_) => format!("{CONFIG_FILE} can't be loaded"),
            None if !loaded.exists => "Not set up yet (the defaults)".into(),
            None => crate::settings::applies_parts(&loaded.config)
                .unwrap_or_else(|| "The defaults".into()),
        };
        let history = crate::history_ui::locate(&ws, st.state_dir_for(&ws).as_deref())
            .map(|l| crate::workspace::shown_path(&l.dir))
            .unwrap_or_else(|e| e);
        let latest = match runs.first() {
            Some(r) => format!(
                r#"{n} · latest <a href="/runs/{id}">{name}</a>, {when}"#,
                n = if runs.len() == 1 {
                    "1 run".to_string()
                } else {
                    format!("{} runs", num(runs.len()))
                },
                id = esc(&r.id),
                name = esc(&r.title()),
                when = pages::time(r.created_at),
            ),
            None => "No runs yet".into(),
        };
        let count = match runs.len() {
            0 => "No runs".to_string(),
            1 => "1 run".to_string(),
            n => format!("{} runs", num(n)),
        };
        let domains = if e.domains.is_empty() {
            r#"<span class="muted">None listed</span>"#.to_string()
        } else {
            esc(&e.domains.join(", "))
        };
        // Its latest collection with timings; none timed, no panel (each
        // run's page still links its own).
        let perf = runs
            .iter()
            .find(|r| {
                st.workspace
                    .run_dir(&r.id)
                    .is_some_and(|d| crate::diagnose::timings_of(&d).is_some())
            })
            .map(|r| {
                crate::diagnose::env_panel(
                    &crate::diagnose::Performance::of(&st.workspace, r),
                    &format!("perf-{}", esc(&e.id)),
                )
            })
            .unwrap_or_default();
        let is_current = e.id == current;
        let switch = if is_current {
            r#"<span class="tag">Current</span>"#.to_string()
        } else {
            format!(
                r#"<form method="post" action="/environments/switch?to={id}"><button type="submit" class="btn small-btn">{i} Switch to it</button></form>"#,
                id = esc(&e.id),
                i = icon("i-arrow"),
            )
        };
        // An unused Default has nothing to remove.
        let remove = if e.is_default() && unused {
            String::new()
        } else {
            format!(
                r#"<div class="er-remove"><a class="btn danger small-btn" href="/environments/{id}/remove">{i} Remove environment…</a><span class="hint">With its {count_lc}, settings and history. The next page shows what goes; you confirm there.</span></div>"#,
                id = esc(&e.id),
                i = icon("i-trash"),
                count_lc = if runs.is_empty() {
                    "runs (none yet)".to_string()
                } else {
                    count.to_lowercase()
                },
            )
        };
        let _ = write!(
            b,
            r#"<section class="env-row card{cur}" id="env-{id}">
  <div class="er-head"><div class="er-name"><h2>{name}</h2><button type="button" class="rr-edit" data-rename aria-label="Rename {name}" title="Rename">{i_edit}</button><form class="inline-edit" method="post" action="/environments/{id}/rename" data-rename-form hidden><input type="text" name="name" value="{name_value}" maxlength="{max}" required autocomplete="off" aria-label="Name"><button type="submit" class="btn primary">Save</button><button type="button" class="btn" data-rename-cancel>Cancel</button></form></div>{demo}<span class="er-count">{count}</span><div class="er-actions">{switch}</div></div>
  <dl class="er-facts">
    <div><dt>Runs</dt><dd>{latest}</dd></div>
    <div><dt>Settings</dt><dd>{settings}</dd></div>
    <div><dt>Domains for automatic assignment</dt><dd>{domains}</dd></div>
    <div class="wide"><dt>Folder</dt><dd><code>{dir}</code></dd></div>
    <div class="wide"><dt>Run history</dt><dd><code>{history}</code></dd></div>
  </dl>
  {perf}
  <details class="er-edit"{open}><summary>{i_edit} Change domains or remove</summary>
    <form method="post" action="/environments/{id}/edit" class="env-form">
      <input type="hidden" name="name" value="{raw_name}">
      <label>Domains <span class="hint">Runs of these domains go to this environment by themselves. Separate them with commas or spaces.</span><textarea name="domains" rows="2" spellcheck="false">{domain_text}</textarea></label>
      <div class="form-actions"><button type="submit" class="btn primary"><svg class="ic" aria-hidden="true"><use href='#i-check'/></svg> Save</button></div>
    </form>
    {remove}
  </details>
</section>"#,
            cur = if is_current { " current" } else { "" },
            id = esc(&e.id),
            name = esc(e.display()),
            name_value = crate::pages::attr(e.display()),
            raw_name = crate::pages::attr(&e.name),
            demo = if e.demo {
                r#" <span class="tag demo">Demo</span>"#
            } else {
                ""
            },
            settings = esc(&settings),
            dir = esc(&crate::workspace::shown_path(&ws.env_dir())),
            history = esc(&history),
            open = if open_form == Some(e.id.as_str()) {
                " open"
            } else {
                ""
            },
            i_edit = icon("i-edit"),
            max = MAX_NAME,
            domain_text = esc(&e.domains.join(", ")),
        );
    }
    b.push_str("</div>");
    let copy_options: String = reg
        .environments
        .iter()
        .filter(|e| !(e.is_default() && unused))
        .map(|e| {
            format!(
                r#"<option value="{}">A copy of the settings of {}</option>"#,
                esc(&e.id),
                esc(e.display())
            )
        })
        .collect();
    let _ = write!(
        b,
        r#"<section class="env-new card" id="new">
  <h2 class="sub">New environment</h2>
  <form method="post" action="/environments" class="env-form" data-env-new>
    <fieldset class="choice env-origin"><legend>Its history</legend>
      <label class="option card"><input type="radio" name="origin" value="local" checked><span><strong>On this computer</strong><span class="muted">An empty history in this environment's folder. You can share it later.</span></span></label>
      <label class="option card"><input type="radio" name="origin" value="connect"><span><strong>Connect to a run history</strong><span class="muted">The runs and settings that teammates or a server already record.</span></span></label>
      <label class="option card"><input type="radio" name="origin" value="new-shared"><span><strong>Start a new run history</strong><span class="muted">An empty history in a git repository or shared folder, for others to join.</span></span></label>
    </fieldset>
    <label data-when-origin="own">Name <span class="hint">For example Demo, Lab or Production.</span><input type="text" name="name" maxlength="{max}" required autocomplete="off"></label>
    <label data-when-origin="own">Domains <span class="hint">Optional. Analyses of these domains go here when no environment is chosen.</span><textarea name="domains" rows="2" spellcheck="false" placeholder="scale.local, emea.scale.local"></textarea></label>
    <label data-when-origin="own">Start with <select name="copy"><option value="">The default settings</option>{copy_options}</select><span class="hint">A copy includes accepted risks and ticketing plugins; review them before the first analysis.</span></label>
    <p class="hint" data-when-origin="connect" hidden>The name and domains come from the run history. You can change the name on the next step.</p>
    <div class="form-actions"><button type="submit" class="btn primary" data-when-origin="own">{i_plus} Create and switch to it</button><button type="submit" class="btn primary" data-when-origin="connect" hidden>{i_arrow} Continue</button></div>
  </form>
</section>"#,
        max = MAX_NAME,
        i_plus = icon("i-plus"),
        i_arrow = icon("i-arrow"),
    );
    let runs = st.ws().runs();
    pages::shell(
        &pages::Ctx::new(st, &runs),
        Some(pages::Nav::Environments),
        "Environments",
        "",
        &b,
    )
}

#[derive(Deserialize)]
struct EnvForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    domains: String,
    #[serde(default)]
    copy: String,
    /// Its history: "local" (start here), "connect" (a run history,
    /// on the next page) or "new-shared" (a new run history, on History
    /// storage once it is made).
    #[serde(default)]
    origin: String,
}

/// After a change: back to the page (303), or the page with the error.
fn answer(st: &AppState, result: Result<String, String>, form: Option<&str>) -> Response {
    match result {
        Ok(anchor) if anchor.is_empty() => Redirect::to("/environments").into_response(),
        Ok(anchor) => Redirect::to(&format!("/environments#{anchor}")).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Html(render(st, Some(&e), form))).into_response(),
    }
}

async fn create(State(st): State<Shared>, Form(f): Form<EnvForm>) -> Response {
    // A run history names the environment itself: the next page.
    if f.origin == "connect" {
        return Redirect::to(crate::connect_ui::PATH).into_response();
    }
    let shared = f.origin == "new-shared";
    let st2 = st.clone();
    let result = tokio::task::spawn_blocking(move || {
        let id = create_environment(&st2.workspace, &f.name, &f.domains, &f.copy)?;
        st2.set_env(&id);
        Ok(format!("env-{id}"))
    })
    .await
    .unwrap_or_else(|_| Err("Saving failed.".into()));
    if shared && result.is_ok() {
        return Redirect::to("/automate/history?origin=new-shared#state").into_response();
    }
    answer(&st, result, None)
}

async fn edit(
    State(st): State<Shared>,
    UrlPath(id): UrlPath<String>,
    Form(f): Form<EnvForm>,
) -> Response {
    let root = st.workspace.root().to_path_buf();
    let result = Registry::update(&root, |r| r.edit(&id, &f.name, &parse_domains(&f.domains)?))
        .map(|()| format!("env-{id}"));
    answer(&st, result, Some(&id))
}

#[derive(Deserialize)]
struct RenameForm {
    #[serde(default)]
    name: String,
}

/// Renames an environment in place (its domains stay as they are).
async fn rename(
    State(st): State<Shared>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
    Form(f): Form<RenameForm>,
) -> Response {
    let shown = st.workspace.named_registry().name_of(&id);
    let result = rename_env(st.workspace.root(), &id, &f.name, &shown).map(|_| format!("env-{id}"));
    // The page's script asks for JSON, to show why it wasn't saved.
    let wants_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("application/json"));
    match result {
        Err(e) if wants_json => (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
        result => answer(&st, result, None),
    }
}

/// Renames environment `id` (the Environments page, `pathwarden env
/// rename`), keeping its domains. `shown` is the name it shows as: an
/// unrenamed Default "renamed" to the name it already shows (its domains)
/// stays unrenamed, so it keeps following its domains. True when the
/// registry changed.
pub fn rename_env(root: &Path, id: &str, name: &str, shown: &str) -> Result<bool, String> {
    Registry::update(root, |r| {
        let e = r.get(id).ok_or("That environment no longer exists.")?;
        if e.is_unnamed_default() && name.trim() == shown {
            return Ok(false);
        }
        let domains = e.domains.clone();
        r.edit(id, name, &domains)?;
        Ok(true)
    })
}

/// `pathwarden ui --state DIR` for environment `id` (the first
/// environment's only).
fn state_flag(st: &AppState, id: &str) -> Option<PathBuf> {
    st.state_dir_for(&st.workspace.in_env(id))
}

/// The confirmation before removing an environment: what goes (runs,
/// settings, history, kept collections, and how much), where it goes, and
/// a field for its name ([`crate::env_remove`]; `pathwarden env remove`
/// prints the same).
async fn remove_page(State(st): State<Shared>, UrlPath(id): UrlPath<String>) -> Response {
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || {
        match crate::env_remove::plan(st2.workspace.root(), &id, state_flag(&st2, &id).as_deref()) {
            Ok(plan) => Html(render_remove(&st2, &plan, None)).into_response(),
            Err(e) => answer(&st2, Err(e), None),
        }
    })
    .await
    .unwrap_or_else(|_| not_found_page())
}

/// The confirmation page for `plan`, with `error` at the top after a
/// confirmation that didn't match.
fn render_remove(st: &AppState, plan: &crate::env_remove::Plan, error: Option<&str>) -> String {
    let mut b = String::new();
    let lines = plan.lines();
    let _ = write!(
        b,
        r#"<div class="page-head"><div><p class="crumb"><a href="/environments">Environments</a></p><h1 class="panel-title">{title}</h1>
<p class="lead">Check what goes before you confirm. Nothing is deleted, but the environment and its runs leave every list.</p></div></div>"#,
        title = esc(&plan.title()),
    );
    if let Some(e) = error {
        let _ = write!(
            b,
            r#"<div class="env-error card" role="alert"><strong>Not removed.</strong> {}</div>"#,
            esc(e)
        );
    }
    let button = match plan.runs {
        0 => format!("Remove {}", plan.name),
        1 => format!("Remove {} and its run", plan.name),
        n => format!("Remove {} and its {} runs", plan.name, num(n)),
    };
    let _ = write!(
        b,
        r#"<section class="env-remove card" aria-label="What goes">
  <ul class="rm-lines">{items}</ul>
  <form method="post" action="/environments/{id}/remove" class="env-form rm-form">
    <input type="hidden" name="runs_key" value="{runs_key}">
    <label>{prompt} <span class="hint">Its name as shown above, or its ID ({raw_id}) if the name is hard to type.</span><input type="text" name="confirm" required autocomplete="off" spellcheck="false" data-must-match="{name}" data-or-match="{raw_id}"></label>
    <div class="form-actions"><button type="submit" class="btn danger solid" data-confirm-button>{i} {button}</button><a class="btn" href="/environments#env-{id}">Keep it</a></div>
  </form>
</section>"#,
        items = lines
            .iter()
            .map(|l| format!("<li>{}</li>", esc(l)))
            .collect::<String>(),
        id = esc(&plan.id),
        raw_id = esc(&plan.id),
        runs_key = esc(&plan.runs_key),
        prompt = esc(&plan.confirm_prompt()),
        name = esc(&plan.name),
        i = icon("i-trash"),
        button = esc(&button),
    );
    let runs = st.ws().runs();
    pages::shell(
        &pages::Ctx::new(st, &runs),
        Some(pages::Nav::Environments),
        &plan.title(),
        "",
        &b,
    )
}

#[derive(Deserialize)]
struct RemoveForm {
    /// The name typed to confirm.
    #[serde(default)]
    confirm: String,
    /// Which runs the confirmation page showed ([`crate::env_remove::runs_key`]).
    #[serde(default)]
    runs_key: Option<String>,
}

/// Removes an environment with its runs, once its name was typed
/// ([`crate::env_remove::remove`]): everything moves to
/// `environments/removed/<id>-<time>`, nothing is deleted. Back to the
/// Environments page, which says what happened.
async fn remove(
    State(st): State<Shared>,
    UrlPath(id): UrlPath<String>,
    Form(f): Form<RemoveForm>,
) -> Response {
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || {
        let root = st2.workspace.root().to_path_buf();
        let flag = state_flag(&st2, &id);
        let plan = match crate::env_remove::plan(&root, &id, flag.as_deref()) {
            Ok(p) => p,
            Err(e) => return answer(&st2, Err(e), None),
        };
        if !plan.confirms(&f.confirm) {
            return (
                StatusCode::BAD_REQUEST,
                Html(render_remove(
                    &st2,
                    &plan,
                    Some(crate::env_remove::NOT_CONFIRMED),
                )),
            )
                .into_response();
        }
        let was_current = st2.env_id() == id;
        match crate::env_remove::remove(&root, &id, flag.as_deref(), f.runs_key.as_deref()) {
            Ok(done) => {
                if was_current {
                    let next = done
                        .now_current
                        .clone()
                        .unwrap_or_else(|| DEFAULT_ENV.into());
                    st2.set_env(&next);
                }
                let folder = done
                    .folder
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                Redirect::to(&format!("/environments?removed={folder}")).into_response()
            }
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Html(render_remove(&st2, &plan, Some(&e))),
            )
                .into_response(),
        }
    })
    .await
    .unwrap_or_else(|_| not_found_page())
}

/// What a run's page (and its Explore page) says about the run's
/// environment, when the workspace has several: nothing if it is the
/// current one; else which one it is, in one sentence, and a button to
/// switch to it.
pub fn run_note(st: &AppState, run_ws: &Workspace) -> String {
    if run_ws.env_id() == st.env_id() {
        return String::new();
    }
    let reg = st.workspace.named_registry();
    if !reg.several() {
        return String::new();
    }
    format!(
        r#"<div class="env-note card" role="note">{i}<div class="en-text">This run is in <strong>{name}</strong>, so its retests and accepted risks use the settings of {name}. <form method="post" action="/environments/switch?to={id}"><button type="submit" class="btn small-btn">Switch to {name}</button></form></div></div>"#,
        i = icon("i-layers"),
        name = esc(&reg.name_of(run_ws.env_id())),
        id = esc(run_ws.env_id()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_domains_are_parsed_or_refused_never_dropped() {
        assert_eq!(
            parse_domains("essos.local, north.sevenkingdoms.local\nESSOS.LOCAL.").unwrap(),
            ["ESSOS.LOCAL", "NORTH.SEVENKINGDOMS.LOCAL"]
        );
        assert_eq!(parse_domains("  ").unwrap(), Vec::<String>::new());
        // The review's input: saved as ["NOT", "A"] before.
        let e = parse_domains("not a domain!!, DOMAIN\\user@x, <script>x</script>, ü.local")
            .unwrap_err();
        assert!(e.contains("\"not\"") && e.contains("\"domain!!\""), "{e}");
        for bad in [
            "corp",
            "a..b",
            "-x.local",
            "x-.local",
            "x.local/",
            "contoso..local",
        ] {
            assert!(parse_domains(bad).is_err(), "{bad}");
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pw-envs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_workspace_without_a_registry_has_default_only() {
        let d = tmp("none");
        let r = Registry::load(&d);
        assert_eq!(r.environments.len(), 1);
        assert!(r.environments[0].is_default());
        assert_eq!(r.environments[0].name, "Default");
        assert!(!d.join(REGISTRY_FILE).exists(), "loading writes nothing");
        assert_eq!(env_dir(&d, DEFAULT_ENV), d);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn create_rename_and_find() {
        let d = tmp("create");
        let id = Registry::update(&d, |r| r.create("Client A", &["contoso.local".into()])).unwrap();
        assert_eq!(id, "client-a");
        let id2 = Registry::update(&d, |r| r.create("Client A!", &[])).unwrap();
        assert_eq!(id2, "client-a-2");
        assert!(Registry::update(&d, |r| r.create(" client a ", &[])).is_err());
        assert!(Registry::update(&d, |r| r.create("", &[])).is_err());
        assert!(Registry::update(&d, |r| r.create("bad\u{202e}name", &[])).is_err());
        let r = Registry::load(&d);
        assert_eq!(r.find("CLIENT A").unwrap().id, "client-a");
        assert_eq!(r.find("client-a-2").unwrap().name, "Client A!");
        assert_eq!(r.get("client-a").unwrap().domains, vec!["CONTOSO.LOCAL"]);
        Registry::update(&d, |r| r.edit(DEFAULT_ENV, "Lab", &[])).unwrap();
        assert_eq!(Registry::load(&d).name_of(DEFAULT_ENV), "Lab");
        assert_eq!(env_dir(&d, "client-a"), d.join(ENVS_DIR).join("client-a"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ids_never_leave_the_folder() {
        for bad in ["", "..", "a/b", "A", "-x", "a\\b", &"x".repeat(41)] {
            assert!(!valid_id(bad), "{bad}");
        }
        assert!(valid_id("client-a-2"));
        let reg = Registry::default();
        assert_eq!(reg.new_id("../.."), "environment");
        assert_eq!(reg.new_id("Default"), "environment");
        // Folder names a removal uses are never an environment's ID.
        assert_eq!(reg.new_id("Removed"), "removed-2");
        assert_eq!(reg.new_id("Env"), "env-2");
        assert_eq!(reg.new_id("Runs"), "runs-2");
        assert_eq!(reg.new_id("Contoso — Prod (EU)"), "contoso-prod-eu");
    }

    #[test]
    fn a_broken_registry_reads_as_default() {
        let d = tmp("broken");
        std::fs::write(d.join(REGISTRY_FILE), "{not json").unwrap();
        assert_eq!(Registry::load(&d).environments.len(), 1);
        std::fs::write(
            d.join(REGISTRY_FILE),
            r#"{"current":"gone","environments":[{"id":"lab","name":"Lab"},{"id":"../x","name":"Evil"},{"id":"lab","name":"Dup"}]}"#,
        )
        .unwrap();
        let r = Registry::load(&d);
        let ids: Vec<&str> = r.environments.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["default", "lab"]);
        assert_eq!(r.current, None);
        let _ = std::fs::remove_dir_all(&d);
    }

    fn names(d: &[&str]) -> Vec<String> {
        d.iter().map(|s| s.to_string()).collect()
    }

    /// GOAD lab lists ESSOS.LOCAL; Production lists FABRIKAM.COM; Default
    /// has a run of SEVENKINGDOMS.LOCAL (and trusts ESSOS.LOCAL, which
    /// never counts); the demo has its environment and a run.
    fn workspace() -> (Registry, Vec<RunDomains>) {
        let mut reg = Registry::load(Path::new("/nonexistent-pathwarden"));
        reg.create("GOAD lab", &names(&["essos.local"])).unwrap();
        reg.create("Production", &names(&["FABRIKAM.COM"])).unwrap();
        let demo = reg.ensure_demo();
        assert_eq!(demo, "demo");
        let run = |env: &str, demo: bool, domains: &[&str], trusted: &[&str]| {
            let mut r: RunSummary = serde_json::from_value(serde_json::json!({
                "id": "20261002-055320-abcdef", "created_at": 1, "collected_at": null,
                "source": "x.zip", "demo": demo, "domains": domains, "objects": 1,
                "files": 1, "exposure_percent": 0.0, "exposed": 0, "population": 0,
                "protection_score": null, "critical": 0, "high": 0, "medium": 0,
                "low": 0, "info": 0, "suppressed": 0, "plan_steps": 0,
                "pathwarden": "0.1.2",
            }))
            .unwrap();
            r.trusted_domains = Some(names(trusted));
            r.environment = (env != DEFAULT_ENV).then(|| env.to_string());
            r
        };
        let runs = vec![
            run(
                DEFAULT_ENV,
                false,
                &["SEVENKINGDOMS.LOCAL"],
                &["ESSOS.LOCAL"],
            ),
            // An old demo run saved in Default: the demo's now.
            run(DEFAULT_ENV, true, &["SCALE.LOCAL"], &[]),
        ];
        assert_eq!(run_env(&reg, &runs[1]), "demo");
        let runs = run_domains(&reg, &runs);
        assert_eq!(runs.len(), 1, "demo runs are left out");
        (reg, runs)
    }

    #[test]
    fn one_matching_environment_takes_the_run() {
        let (reg, runs) = workspace();
        let d = |x: &[&str]| decide(&reg, &names(x), &runs);
        // By its list, ignoring case.
        assert_eq!(
            d(&["Essos.Local"]),
            Decision::Match {
                id: "goad-lab".into(),
                how: Assigned::ByDomains
            }
        );
        // By its runs.
        assert_eq!(
            d(&["sevenkingdoms.local"]),
            Decision::Match {
                id: DEFAULT_ENV.into(),
                how: Assigned::ByRuns
            }
        );
        // No domain at all: the current environment.
        assert_eq!(d(&[]), Decision::Current);
    }

    /// A run that collected one more domain than before stays with the
    /// environment that has the others; one that spans two environments
    /// is still asked about.
    #[test]
    fn a_new_domain_joins_the_environment_of_the_others() {
        let (reg, runs) = workspace();
        let d = |x: &[&str]| decide(&reg, &names(x), &runs);
        assert_eq!(
            d(&["ESSOS.LOCAL", "BRAAVOS.LOCAL"]),
            Decision::Match {
                id: "goad-lab".into(),
                how: Assigned::Joined
            }
        );
        assert_eq!(
            d(&["braavos.local", "SEVENKINGDOMS.LOCAL"]),
            Decision::Match {
                id: DEFAULT_ENV.into(),
                how: Assigned::Joined
            }
        );
        let Decision::Ask(ask) = d(&["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL", "BRAAVOS.LOCAL"]) else {
            panic!("not asked");
        };
        assert_eq!(ask.matches.len(), 2);
    }

    /// An old run is the collection being placed when its domains are
    /// exactly what that collection collected and trusts; before the
    /// trusted domains are known, no old run asks.
    #[test]
    fn the_run_being_placed_explains_old_runs() {
        let mut old: RunSummary = serde_json::from_value(serde_json::json!({
            "id": "20261002-055320-abcdef", "created_at": 1, "collected_at": null,
            "source": "x.zip", "demo": false,
            "domains": ["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"], "objects": 1,
            "files": 1, "exposure_percent": 0.0, "exposed": 0, "population": 0,
            "protection_score": null, "critical": 0, "high": 0, "medium": 0,
            "low": 0, "info": 0, "suppressed": 0, "plan_steps": 0,
            "pathwarden": "0.1.1",
        }))
        .unwrap();
        crate::workspace::migrate_domains(std::slice::from_mut(&mut old));
        assert!(old.legacy_domains);
        let reg = Registry::load(Path::new("/nonexistent-pathwarden"));
        let all = [old];
        let legacy = |c: Option<(&[&str], &[&str])>| {
            let (c, t) = c.map_or((Vec::new(), Vec::new()), |(c, t)| (names(c), names(t)));
            let collection = (!c.is_empty()).then_some((c.as_slice(), t.as_slice()));
            run_domains_for(&reg, &all, collection)[0].legacy
        };
        assert!(run_domains(&reg, &all)[0].legacy);
        assert!(!legacy(None), "not known yet: no question");
        // The same collection: ESSOS.LOCAL collected, SEVENKINGDOMS.LOCAL trusted.
        assert!(!legacy(Some((&["essos.local"], &["SEVENKINGDOMS.LOCAL"]))));
        // Another one: SEVENKINGDOMS.LOCAL alone may only have been trusted.
        assert!(legacy(Some((&["SEVENKINGDOMS.LOCAL"], &[]))));
    }

    /// A domain an environment has only through an old run (0.1.1
    /// counted trusted domains, and no later run mapped it) is asked about
    /// once; the environment picked then lists it.
    #[test]
    fn old_runs_with_several_domains_ask_once() {
        let d = tmp("legacy");
        Registry::update(&d, |r| r.create("Other", &names(&["CONTOSO.COM"]))).unwrap();
        let old = |legacy: bool| RunDomains {
            env: DEFAULT_ENV.into(),
            domains: names(&["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"]),
            legacy,
        };
        let reg = Registry::load(&d);
        let want = names(&["SEVENKINGDOMS.LOCAL"]);
        // A run recorded since (or a mapped one) places it by runs.
        assert_eq!(
            decide(&reg, &want, &[old(false)]),
            Decision::Match {
                id: DEFAULT_ENV.into(),
                how: Assigned::ByRuns
            }
        );
        let runs = [old(true)];
        let Decision::Ask(ask) = decide(&reg, &want, &runs) else {
            panic!("not asked");
        };
        assert!(ask.legacy == want && ask.new.is_empty());
        assert_eq!(ask.matches, [(DEFAULT_ENV.to_string(), want.clone())]);
        // Each domain is said once.
        assert_eq!(
            ask.reason(&reg),
            "SEVENKINGDOMS.LOCAL matches Default only through runs saved by Pathwarden 0.1.1 \
             or earlier, which also counted trusted domains: asked once."
        );
        // Next to a domain that matches the usual way.
        let other = reg.environments.iter().find(|e| e.name == "Other").unwrap();
        let mixed = Ask {
            matches: vec![
                (DEFAULT_ENV.into(), want.clone()),
                (other.id.clone(), names(&["CONTOSO.COM"])),
            ],
            new: names(&["BRAAVOS.LOCAL"]),
            legacy: want.clone(),
        };
        assert_eq!(
            mixed.reason(&reg),
            "CONTOSO.COM matches Other; BRAAVOS.LOCAL is new. SEVENKINGDOMS.LOCAL matches \
             Default only through runs saved by Pathwarden 0.1.1 or earlier, which also \
             counted trusted domains: asked once."
        );
        // Settled by itself it asks too; picked, Default lists it.
        let choice = Choice::Env(DEFAULT_ENV.into());
        assert!(matches!(
            settle(&d, &choice, Assigned::ByRuns, &want, &runs, true).unwrap(),
            Settling::Ask(_)
        ));
        settle(&d, &choice, Assigned::Chosen, &want, &runs, false).unwrap();
        let reg = Registry::load(&d);
        assert_eq!(reg.get(DEFAULT_ENV).unwrap().domains, want);
        assert_eq!(
            decide(&reg, &want, &runs),
            Decision::Match {
                id: DEFAULT_ENV.into(),
                how: Assigned::ByDomains
            }
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn no_matching_environment_makes_one_named_after_the_domains() {
        let (reg, runs) = workspace();
        let d = |x: &[&str]| decide(&reg, &names(x), &runs);
        assert_eq!(
            d(&["contoso.com"]),
            Decision::New {
                name: "CONTOSO.COM".into()
            }
        );
        assert_eq!(
            d(&["B.LOCAL", "a.local"]),
            Decision::New {
                name: "A.LOCAL +1".into()
            }
        );
        assert_eq!(
            d(&["NORTH.CONTOSO.COM", "CONTOSO.COM"]),
            Decision::New {
                name: "CONTOSO.COM +1".into()
            }
        );
        // The demo's domain is not a match: real runs never go there.
        assert_eq!(
            d(&["SCALE.LOCAL"]),
            Decision::New {
                name: "SCALE.LOCAL".into()
            }
        );
        // A domain only trusted by an earlier run is new.
        assert!(matches!(d(&["ESSOS.LOCAL"]), Decision::Match { .. }));
        let mut no_goad = reg.clone();
        no_goad.environments.retain(|e| e.id != "goad-lab");
        assert_eq!(
            decide(&no_goad, &names(&["ESSOS.LOCAL"]), &runs),
            Decision::New {
                name: "ESSOS.LOCAL".into()
            }
        );
        // A long name is cut to fit.
        let long = format!("{}.LOCAL", "X".repeat(70));
        match d(&[&long]) {
            Decision::New { name } => {
                assert_eq!(name.chars().count(), MAX_NAME);
                assert!(clean_name(&name).is_ok());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn something_off_asks_with_the_reason() {
        let (reg, runs) = workspace();
        let d = |x: &[&str]| decide(&reg, &names(x), &runs);
        // Two environments and a new domain (one environment and a new
        // domain joins it: a_new_domain_joins_the_environment_of_the_others).
        let Decision::Ask(ask) = d(&["ESSOS.LOCAL", "fabrikam.com", "BRAAVOS.LOCAL"]) else {
            panic!()
        };
        assert!(ask.partial());
        assert!(
            ask.reason(&reg).ends_with("BRAAVOS.LOCAL is new."),
            "{}",
            ask.reason(&reg)
        );
        // Two environments.
        let Decision::Ask(ask) = d(&["fabrikam.com", "ESSOS.LOCAL"]) else {
            panic!()
        };
        assert!(!ask.partial());
        assert_eq!(
            ask.reason(&reg),
            "ESSOS.LOCAL matches GOAD lab; FABRIKAM.COM matches Production."
        );
        // One domain on two lists.
        let mut both = reg.clone();
        both.edit(
            "production",
            "Production",
            &names(&["FABRIKAM.COM", "ESSOS.LOCAL"]),
        )
        .unwrap();
        let Decision::Ask(ask) = decide(&both, &names(&["ESSOS.LOCAL"]), &runs) else {
            panic!()
        };
        assert_eq!(
            ask.reason(&both),
            "ESSOS.LOCAL matches GOAD lab and Production."
        );
        // A list beats runs: listed for GOAD lab, SEVENKINGDOMS.LOCAL goes
        // there although Default has a run of it.
        let mut listed = reg.clone();
        listed
            .edit(
                "goad-lab",
                "GOAD lab",
                &names(&["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"]),
            )
            .unwrap();
        assert_eq!(
            decide(
                &listed,
                &names(&["SEVENKINGDOMS.LOCAL", "ESSOS.LOCAL"]),
                &runs
            ),
            Decision::Match {
                id: "goad-lab".into(),
                how: Assigned::ByDomains
            }
        );
    }

    #[test]
    fn settling_a_choice_updates_the_lists() {
        let d = tmp("settle");
        let goad =
            Registry::update(&d, |r| r.create("GOAD lab", &names(&["ESSOS.LOCAL"]))).unwrap();
        Registry::update(&d, |r| Ok(r.ensure_demo())).unwrap();
        let none: Vec<RunDomains> = Vec::new();
        let chosen = Assigned::Chosen;
        // Picking GOAD lab for ESSOS.LOCAL and BRAAVOS.LOCAL lists BRAAVOS.LOCAL.
        let s = settled(
            &d,
            &Choice::Env(goad.clone()),
            chosen,
            &names(&["ESSOS.LOCAL", "braavos.local"]),
            &none,
            false,
        );
        assert_eq!(s.added, ["BRAAVOS.LOCAL"]);
        assert!(!s.created);
        assert_eq!(
            Registry::load(&d).get(&goad).unwrap().domains,
            ["ESSOS.LOCAL", "BRAAVOS.LOCAL"]
        );
        // The first new environment takes the unused Default's place.
        let s = settled(
            &d,
            &Choice::New("CONTOSO.COM".into()),
            Assigned::New,
            &names(&["CONTOSO.COM"]),
            &none,
            true,
        );
        assert_eq!((s.id.as_str(), s.created), (DEFAULT_ENV, true));
        let reg = Registry::load(&d);
        assert_eq!(reg.get(DEFAULT_ENV).unwrap().name, "CONTOSO.COM");
        assert_eq!(reg.get(DEFAULT_ENV).unwrap().domains, ["CONTOSO.COM"]);
        // Automatic choices are decided again under the lock: another run
        // made CONTOSO.COM's environment meanwhile, so no second one.
        let s = settled(
            &d,
            &Choice::New("CONTOSO.COM".into()),
            Assigned::New,
            &names(&["CONTOSO.COM"]),
            &none,
            true,
        );
        assert_eq!(
            (s.id.as_str(), s.created, s.how),
            (DEFAULT_ENV, false, Assigned::ByDomains)
        );
        // A computed name already taken (with no domains) gets a number; a
        // typed one is refused.
        Registry::update(&d, |r| r.create("X.COM", &[])).unwrap();
        let s = settled(
            &d,
            &Choice::New("X.COM".into()),
            Assigned::New,
            &names(&["X.COM"]),
            &none,
            true,
        );
        assert_eq!(s.id, "x-com-2");
        assert_eq!(Registry::load(&d).name_of(&s.id), "X.COM (2)");
        assert!(d.join(ENVS_DIR).join("x-com-2").is_dir());
        assert!(settle(&d, &Choice::New("x.com".into()), chosen, &[], &none, false).is_err());
        // Domains another environment has are never listed twice.
        let s = settled(
            &d,
            &Choice::New("Lab".into()),
            chosen,
            &names(&["ESSOS.LOCAL", "N.LOCAL"]),
            &none,
            false,
        );
        assert_eq!(s.added, ["N.LOCAL"]);
        // Real runs never go in the demo's environment.
        assert!(settle(&d, &Choice::Env("demo".into()), chosen, &[], &none, false).is_err());
        // Something's off by now (decided as GOAD lab's before Lab listed
        // N.LOCAL): the user is asked, nothing changed.
        let before = std::fs::read(d.join(REGISTRY_FILE)).unwrap();
        let s = settle(
            &d,
            &Choice::Env(goad.clone()),
            Assigned::ByDomains,
            &names(&["ESSOS.LOCAL", "N.LOCAL"]),
            &none,
            true,
        )
        .unwrap();
        let Settling::Ask(ask) = s else {
            panic!("settled: {s:?}")
        };
        assert_eq!(
            ask.matches
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            [goad.as_str(), "lab"]
        );
        assert_eq!(std::fs::read(d.join(REGISTRY_FILE)).unwrap(), before);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// [`settle`], which must settle.
    fn settled(
        root: &Path,
        choice: &Choice,
        how: Assigned,
        domains: &[String],
        runs: &[RunDomains],
        automatic: bool,
    ) -> Settled {
        match settle(root, choice, how, domains, runs, automatic).unwrap() {
            Settling::Settled(s) => s,
            Settling::Ask(ask) => panic!("asked: {ask:?}"),
        }
    }

    /// A page's own choice never settles something that's off.
    #[test]
    fn an_automatic_choice_still_asks() {
        let (reg, runs) = workspace();
        let page = Choice::Env("goad-lab".into());
        // Its domains in two environments.
        let d = names(&["ESSOS.LOCAL", "FABRIKAM.COM"]);
        assert!(matches!(
            place(&reg, &d, &runs, Some(&page), true),
            Placement::Ask(_)
        ));
        // Chosen by the user, it stands.
        assert_eq!(
            place(&reg, &d, &runs, Some(&page), false),
            Placement::Settle(page.clone(), Assigned::Chosen, false)
        );
        // Matching, the data's domains decide (whatever the page showed).
        assert_eq!(
            place(&reg, &names(&["FABRIKAM.COM"]), &runs, Some(&page), true),
            Placement::Settle(Choice::Env("production".into()), Assigned::ByDomains, true)
        );
    }

    /// A registry that can't be read is never written over; a good one is
    /// kept as a copy before each change, and not rewritten when nothing
    /// changes.
    #[test]
    fn a_broken_registry_is_never_overwritten() {
        let d = tmp("safe");
        std::fs::write(d.join(REGISTRY_FILE), "{not json").unwrap();
        let err = Registry::update(&d, |r| r.create("Lab", &[])).unwrap_err();
        assert!(
            err.contains("can't be read") && err.contains("won't change it"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(d.join(REGISTRY_FILE)).unwrap(),
            "{not json"
        );
        assert!(settle(
            &d,
            &Choice::New("Lab".into()),
            Assigned::Chosen,
            &[],
            &[],
            false
        )
        .is_err());
        assert_eq!(
            std::fs::read_to_string(d.join(REGISTRY_FILE)).unwrap(),
            "{not json"
        );
        // A good one: a copy before each change, no write without one.
        std::fs::remove_file(d.join(REGISTRY_FILE)).unwrap();
        Registry::update(&d, |r| r.create("Lab", &[])).unwrap();
        assert!(
            !d.join(BACKUP_FILE).exists(),
            "nothing to copy the first time"
        );
        let first = std::fs::read_to_string(d.join(REGISTRY_FILE)).unwrap();
        Registry::update(&d, |r| r.create("Prod", &[])).unwrap();
        assert_eq!(std::fs::read_to_string(d.join(BACKUP_FILE)).unwrap(), first);
        let modified = std::fs::metadata(d.join(REGISTRY_FILE))
            .unwrap()
            .modified()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        Registry::update(&d, |_| Ok(())).unwrap();
        assert_eq!(
            std::fs::metadata(d.join(REGISTRY_FILE))
                .unwrap()
                .modified()
                .unwrap(),
            modified,
            "not rewritten"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Default with anything of its own is never "unused".
    #[test]
    fn default_with_files_is_used() {
        let d = tmp("unused");
        let reg = Registry::load(&d);
        assert!(reg.default_unused(&d, &[]));
        for f in [crate::workspace::CONFIG_FILE, crate::workspace::LABELS_FILE] {
            std::fs::write(d.join(f), "").unwrap();
            assert!(!reg.default_unused(&d, &[]), "{f}");
            std::fs::remove_file(d.join(f)).unwrap();
        }
        std::fs::create_dir_all(d.join("pathwarden-state")).unwrap();
        assert!(!reg.default_unused(&d, &[]));
        std::fs::remove_dir_all(d.join("pathwarden-state")).unwrap();
        // A history only in the folder given with `ui --state`, kept
        // in the registry for every process.
        let ext = d.join("elsewhere");
        std::fs::create_dir_all(ext.join("history")).unwrap();
        std::fs::write(ext.join("notes.txt"), "").unwrap();
        set_default_state(&d, Some(&ext));
        let reg = Registry::load(&d);
        assert!(reg.default_unused(&d, &[]), "no history in it");
        std::fs::write(ext.join("history").join("20261018T120000.000Z.json"), "{}").unwrap();
        set_default_state(&d, None);
        assert!(Registry::load(&d).default_unused(&d, &[]), "not given");
        set_default_state(&d, Some(&ext));
        let reg = Registry::load(&d);
        assert!(reg.default_used && !reg.default_unused(&d, &[]));
        std::fs::remove_dir_all(&ext).unwrap();
        assert!(!Registry::load(&d).default_unused(&d, &[]), "kept");
        let mut reset = Registry::load(&d);
        reset.reset_default();
        assert!(reset.default_unused(&d, &[]));
        let _ = std::fs::remove_dir_all(&d);
    }
    #[test]
    fn default_shows_as_its_domains() {
        let d = tmp("names");
        let reg = Registry::load(&d).with_names(&[]);
        assert_eq!(reg.name_of(DEFAULT_ENV), NO_ENV_YET);
        let mut reg = Registry::load(&d);
        reg.environments[0].domains = names(&["ESSOS.LOCAL"]);
        let reg = reg.with_names(&[]);
        assert_eq!(reg.name_of(DEFAULT_ENV), "ESSOS.LOCAL");
        assert_eq!(reg.find("essos.local").unwrap().id, DEFAULT_ENV);
        assert_eq!(reg.find("default").unwrap().id, DEFAULT_ENV);
        // Renamed, it shows its name.
        let mut reg = Registry::load(&d);
        reg.edit(DEFAULT_ENV, "Lab", &[]).unwrap();
        assert_eq!(reg.with_names(&[]).name_of(DEFAULT_ENV), "Lab");
        let _ = std::fs::remove_dir_all(&d);
    }
}
