//! Removing an environment with its runs: the Environments page's
//! **Remove environment** and `pathwarden env remove` share [`plan`] (what
//! goes, shown before anything happens), [`Plan::confirms`] (the typed
//! name) and [`remove`] (doing it), so both say and refuse the same things.
//!
//! - **Nothing is deleted.** What the environment owns moves to
//!   `environments/removed/<id>-<time>/` in the workspace: its runs
//!   (`runs/`), its folder (`env/`: settings, run history, labels) and the
//!   collections its runs kept (`collections/`). `RESTORE.txt` there says
//!   how to put it back; deleting that folder frees the space.
//! - **Only what its records own.** Run folders whose `summary.json` names
//!   the environment, the folder its registry ID names, the first
//!   environment's own files by name, and kept collections no other
//!   environment's run uses. Everything is moved with a rename inside the
//!   workspace ([`movable`]): a path that is a link (symbolic link or
//!   junction) or resolves outside the workspace is never moved, so nothing
//!   outside it is ever touched. Anything that is or holds one of the
//!   workspace's shared folders, or another environment's run history or
//!   settings, stays (resolved paths compared), as does a run history
//!   configured outside the environment's folder; the summary says so.
//!   Links inside a folder that moves move as links and are named.
//! - **Refused**: removing the first environment while runs name an
//!   environment the registry doesn't know (nor a removal record); any
//!   removal while an environment owns the ID `removed` and its folder holds
//!   removals (otherwise it is given a free ID first, [`migrate_reserved`]).
//! - **The first environment** (the workspace folder itself) can be removed
//!   too: its files move out of the workspace folder and it starts over as
//!   a new workspace's (unnamed, no domains, not listed until a run uses
//!   it). Removing the last environment leaves "No environment yet".
//! - **The current environment** gives way to the first environment left
//!   (not the demo's), else to "No environment yet".
//! - **The demo's environment** can be removed like any other (its demo
//!   runs go with it); **Try the demo** makes it again.
//! - **Crash safety.** It all happens under the registry's lock
//!   ([`Registry::update`]), so no run can be placed in the environment
//!   meanwhile. Runs move first, one rename each: a run is either still in
//!   `runs/` (listed, in its environment) or in the removal's folder
//!   (listed nowhere). The registry changes last, so an interruption leaves
//!   the environment listed with the runs not yet moved, and removing it
//!   again finishes in the same folder ([`JOURNAL_FILE`]). A run saved for
//!   it while it was being removed keeps its removed ID
//!   ([`Registry::removed`]), is listed nowhere, and joins the others at the
//!   next start or removal ([`sweep`]).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::environments::{
    self, Environment, Registry, BACKUP_FILE, DEFAULT_ENV, ENVS_DIR, LOCK_FILE, NO_ENV_YET,
    REGISTRY_FILE,
};
use crate::workspace::{self, RunSummary, Workspace};

/// Removed environments' folders: `environments/removed/`.
pub const REMOVED_DIR: &str = "removed";
/// The record in a removal's folder: what was removed, and whether the
/// removal finished.
pub const JOURNAL_FILE: &str = "removal.json";
/// How to put a removed environment back, in a removal's folder.
pub const RESTORE_FILE: &str = "RESTORE.txt";
/// What a name typed to confirm that doesn't match gets.
pub const NOT_CONFIRMED: &str = "Not removed: the name typed doesn't match the environment's name.";

/// The workspace's own folders and files, shared by every environment:
/// never one environment's to move.
const SHARED: &[&str] = &[
    "runs",
    "uploads",
    "collections",
    ENVS_DIR,
    REGISTRY_FILE,
    LOCK_FILE,
    BACKUP_FILE,
];

/// One thing that moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Where it is, in the workspace.
    pub from: PathBuf,
    /// Where it goes, relative to the removal's folder: `runs/<id>`, `env`
    /// (another environment's folder), `env/<name>` (a file of the first
    /// environment's), `collections/<id>`.
    pub to: String,
    pub bytes: u64,
}

/// What removing an environment would do ([`plan`]).
#[derive(Debug, Clone)]
pub struct Plan {
    pub id: String,
    /// The name it shows as.
    pub name: String,
    /// Its registry entry, for `RESTORE.txt`.
    pub entry: Environment,
    /// The first environment (the workspace folder itself).
    pub default: bool,
    pub demo: bool,
    /// How many runs go.
    pub runs: usize,
    /// Which runs go, as one value ([`runs_key`]): the confirmation carries
    /// it, and nothing is removed if it changed meanwhile.
    pub runs_key: String,
    /// Links (symbolic links, junctions) inside what moves: they move as
    /// links, and what they point to is never touched.
    pub links: Vec<PathBuf>,
    /// How many kept collections go.
    pub collections: usize,
    /// Its settings, history or labels go (its folder, or the first
    /// environment's files).
    pub files: bool,
    pub items: Vec<Item>,
    pub bytes: u64,
    /// What stays, and why.
    pub kept: Vec<String>,
    /// It is the current environment.
    pub current: bool,
    /// The environment shown after it, when it is the current one.
    pub next: String,
    pub next_name: String,
    /// The workspace's folder for removed environments.
    pub removed_dir: PathBuf,
}

impl Plan {
    /// "Remove GOAD lab?"
    pub fn title(&self) -> String {
        format!("Remove {}?", self.name)
    }

    /// What goes, where, and what to know, one sentence each: the page's
    /// list and the command line's.
    pub fn lines(&self) -> Vec<String> {
        let mut parts = vec![match self.runs {
            0 => "no runs".to_string(),
            1 => "1 run".to_string(),
            n => format!("{n} runs"),
        }];
        if self.files {
            parts.extend(["its settings", "its run history", "its labels"].map(String::from));
        }
        match self.collections {
            0 => {}
            1 => parts.push("1 kept collection".into()),
            n => parts.push(format!("{n} kept collections")),
        }
        let mut out = vec![format!(
            "Moves out: {} ({} in all).",
            environments::and_list(&parts),
            size_words(self.bytes)
        )];
        out.push(format!(
            "Nothing is deleted: it moves to a new folder in {}. {RESTORE_FILE} there says how to put it back.",
            workspace::shown_path(&self.removed_dir)
        ));
        out.extend(self.kept.iter().cloned());
        out.extend(link_lines(&self.links));
        if self.default {
            out.push("This is the Default environment: it stays in the list, empty.".into());
        }
        if self.demo {
            out.push("This is the demo environment. Try the demo brings it back.".into());
        }
        if self.current {
            out.push(if self.next_name == NO_ENV_YET {
                "It is the only environment: the next collection makes a new one.".to_string()
            } else {
                format!(
                    "It is the current environment: the app switches to {}.",
                    self.next_name
                )
            });
        }
        if !self.demo {
            let (task, unit) = schedule_names(&self.id);
            let name = if cfg!(windows) { task } else { unit };
            out.push(format!(
                "If a schedule runs for it on a server, it keeps running. Remove {name} there to stop it."
            ));
        }
        out
    }

    /// What to type to confirm (its ID works too, for a name that is hard
    /// to type).
    pub fn confirm_prompt(&self) -> String {
        format!("Type {} to confirm", self.name)
    }

    /// Whether `typed` confirms: the environment's name as it shows (or its
    /// ID), ignoring case and surrounding spaces.
    pub fn confirms(&self, typed: &str) -> bool {
        // As the page's script compares (lower case, trimmed).
        let t = typed.trim().to_lowercase();
        !t.is_empty() && (t == self.name.trim().to_lowercase() || t == self.id)
    }
}

/// What [`remove`] did.
#[derive(Debug, Clone)]
pub struct Removed {
    pub id: String,
    pub name: String,
    pub runs: usize,
    pub bytes: u64,
    /// The removal's folder.
    pub folder: PathBuf,
    pub kept: Vec<String>,
    pub links: Vec<PathBuf>,
    /// The environment now current, when the removed one was.
    pub now_current: Option<String>,
    pub now_current_name: String,
    pub demo: bool,
}

impl Removed {
    /// What happened, one sentence each: the page's notice and the command
    /// line's output.
    pub fn lines(&self) -> Vec<String> {
        let runs = match self.runs {
            0 => "its files".to_string(),
            1 => "1 run and its files".to_string(),
            n => format!("{n} runs and its files"),
        };
        let mut out = vec![
            format!(
                "Removed {}: {runs} ({}) moved to {}.",
                self.name,
                size_words(self.bytes),
                workspace::shown_path(&self.folder)
            ),
            format!("Nothing was deleted. {RESTORE_FILE} in that folder says how to put it back; delete that folder to free the space."),
        ];
        out.extend(self.kept.iter().cloned());
        out.extend(link_lines(&self.links));
        if self.now_current.is_some() {
            out.push(format!("Now showing {}.", self.now_current_name));
        }
        if self.demo {
            out.push("Try the demo brings the demo environment back.".into());
        }
        out
    }
}

/// What removing environment `id` of the workspace at `root` would do.
/// `state` is `pathwarden ui --state DIR` (the first environment's history
/// when given).
pub fn plan(root: &Path, id: &str, state: Option<&Path>) -> Result<Plan, String> {
    let mut probe = Registry::try_load(root)?;
    if probe.get(REMOVED_DIR).is_some() || recorded_removals(root, &mut probe) {
        Registry::update(root, |r| {
            recorded_removals(root, r);
            migrate_reserved(root, r).map_err(|s| s.refusal())
        })?;
    }
    let reg = Registry::try_load(root)?;
    plan_in(root, &reg, id, state)
}

/// Written into the folder of an environment whose ID was `removed` before
/// it is renamed ([`migrate_reserved`]): a later try finishes the change
/// only into a folder that holds it, never into a stray `removed-N`.
const RENAMED_FILE: &str = "renamed-from-removed.txt";

/// Where the last try to give the environment with the ID `removed`
/// another failed part way (a file that couldn't be written), next to
/// [`REGISTRY_FILE`]: [`reserved_note`] says it in every process (the app,
/// `pathwarden env list`) until a try gets through.
const PROBLEM_FILE: &str = "reserved-id-problem.json";

/// Why the environment with the reserved ID `removed` (from before 0.1.3)
/// still has it, and what to do by hand: what the start warns, the
/// Environments page and `pathwarden env list` say ([`reserved_note`]),
/// and what stops a removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stuck {
    /// The environment's name.
    pub name: String,
    /// Why Pathwarden can't give it another ID by itself, as a clause
    /// ("its folder … also holds earlier removals"); `None`: nothing
    /// stops it, the next start or removal does it.
    pub why: Option<String>,
    /// What to do by hand (with `why`), one step each, as clauses
    /// ("change its "id" in …").
    pub steps: Vec<String>,
}

/// Said with every [`Stuck`] that has a reason.
const RETRY: &str = "Pathwarden tries again at each start and before each removal.";

impl Stuck {
    /// One sentence: "Lab still has the reserved ID "removed": no
    /// environment can be removed until it gets another."
    pub fn lead(&self) -> String {
        // An environment without a name shows its ID: not "removed still
        // has the ID "removed"".
        let who = if self.name == REMOVED_DIR {
            format!("The environment \"{REMOVED_DIR}\"")
        } else {
            self.name.clone()
        };
        match self.why {
            Some(_) => format!(
                "{who} has an ID Pathwarden now uses itself (\"{REMOVED_DIR}\"), so no environment can be removed until it gets another."
            ),
            None => format!(
                "{who} has an ID Pathwarden now uses itself (\"{REMOVED_DIR}\"): the next start of the app, or the next removal, gives it another."
            ),
        }
    }

    /// Why, and what to do by hand ("" when nothing stops it).
    pub fn detail(&self) -> String {
        match &self.why {
            Some(_) => format!(
                "{} To go on by hand, stop Pathwarden and: {}",
                self.reason(),
                self.steps_text()
            ),
            None => String::new(),
        }
    }

    /// Why, in one sentence with when Pathwarden tries again ("" when
    /// nothing stops it): [`Stuck::detail`] without the steps.
    pub fn reason(&self) -> String {
        match &self.why {
            Some(why) => format!("Pathwarden can't give it another ID by itself: {why}. {RETRY}"),
            None => String::new(),
        }
    }

    /// [`Stuck::steps`] in one sentence: "a; b; and c."
    fn steps_text(&self) -> String {
        let last = self.steps.len().saturating_sub(1);
        let parts: Vec<String> = self
            .steps
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i == last && i > 0 {
                    format!("and {s}")
                } else {
                    s.clone()
                }
            })
            .collect();
        format!("{}.", parts.join("; "))
    }

    /// [`Stuck::steps`] one by one, as sentences, for a list.
    pub fn step_list(&self) -> Vec<String> {
        self.steps
            .iter()
            .map(|s| {
                let mut c = s.chars();
                c.next()
                    .map(|f| f.to_uppercase().chain(c).chain(['.']).collect())
                    .unwrap_or_default()
            })
            .collect()
    }

    /// What a removal it stopped says.
    pub fn refusal(&self) -> String {
        format!("{} Nothing was removed. {}", self.lead(), self.detail())
            .trim_end()
            .to_string()
    }
}

impl std::fmt::Display for Stuck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.lead())?;
        match self.why {
            Some(_) => write!(f, " {}", self.detail()),
            None => Ok(()),
        }
    }
}

/// The change [`migrate_reserved`] makes ([`reserved_check`]).
struct Change {
    /// Where the environment is in the registry.
    pos: usize,
    name: String,
    /// Its new ID, `removed-N`.
    new: String,
    /// `environments/removed`.
    old: PathBuf,
    /// `environments/<new>`.
    target: PathBuf,
    /// Its folder was renamed already (an interrupted earlier try).
    renamed: bool,
}

/// What [`migrate_reserved`] would do for the environment with the ID
/// `removed` in `reg`, or what stops it, without changing anything: the
/// start, a removal, the Environments page and `pathwarden env list` all
/// say the same. `None`: no environment has that ID.
fn reserved_check(root: &Path, reg: &Registry) -> Result<Option<Change>, Stuck> {
    let Some(pos) = reg.environments.iter().position(|e| e.id == REMOVED_DIR) else {
        return Ok(None);
    };
    // Every path said below with one kind of separator.
    let root = &tidy(root);
    let name = reg.environments[pos].display().to_string();
    let old = removed_root(root);
    let envs = root.join(ENVS_DIR);
    let free = |i: &str| reg.get(i).is_none() && !reg.removed.iter().any(|r| r == i);
    // A folder an earlier try renamed (it carries the mark) is finished
    // into, even when a lower `removed-N` has become free since; else the
    // first `removed-N` with no folder at all (a stray one stays as it is).
    let marked = fs::read_dir(&envs)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let id = e.file_name().to_str()?.to_string();
            let n: u32 = id.strip_prefix(&format!("{REMOVED_DIR}-"))?.parse().ok()?;
            Some((n, id))
        })
        .filter(|(_, id)| free(id) && envs.join(id).join(RENAMED_FILE).is_file())
        .min()
        .map(|(_, id)| id);
    let new = marked.unwrap_or_else(|| {
        (2..)
            .map(|n| format!("{REMOVED_DIR}-{n}"))
            .find(|i| free(i) && fs::symlink_metadata(envs.join(i)).is_err())
            .unwrap_or_else(|| format!("{REMOVED_DIR}-env"))
    });
    let target = root.join(ENVS_DIR).join(&new);
    let renamed = target.join(RENAMED_FILE).is_file();
    let stuck = |why: String| Stuck {
        name: name.clone(),
        why: Some(why),
        steps: by_hand(&old, &target, &new, renamed),
    };
    let entries: Vec<PathBuf> = fs::read_dir(&old)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    let removal = |p: &PathBuf| p.join(JOURNAL_FILE).is_file() || legacy_removal(p);
    if renamed {
        // Its folder moved already: `environments/removed` may hold
        // removals again (0.1.x's, moved back, or later ones), but nothing
        // of the environment's (written there after the rename).
        let mut other: Vec<String> = entries
            .iter()
            .filter(|p| !removal(p))
            .map(|p| {
                p.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        if !other.is_empty() {
            other.sort();
            return Err(Stuck {
                name: name.clone(),
                why: Some(format!(
                    "its folder became {} already, but {} holds {} again (written there after that)",
                    target.display(),
                    old.display(),
                    environments::and_list(&other)
                )),
                steps: vec![
                    format!(
                        "keep in {} the copy of {} you want, and take {} out of {} (leave the removals there)",
                        target.display(),
                        environments::and_list(&other),
                        if other.len() == 1 { "it" } else { "them" },
                        old.display()
                    ),
                    "Pathwarden then finishes the change at its next start".to_string(),
                ],
            });
        }
        return Ok(Some(Change {
            pos,
            name,
            new,
            old,
            target,
            renamed,
        }));
    }
    if entries.iter().any(|p| p.join(JOURNAL_FILE).is_file()) {
        return Err(stuck(format!(
            "its folder {} also holds earlier removals",
            old.display()
        )));
    }
    let old_there = fs::symlink_metadata(&old).is_ok();
    if old_there && fs::symlink_metadata(&target).is_ok() {
        return Err(stuck(format!("{} already exists", target.display())));
    }
    if old_there {
        movable(root, &old).map_err(|e| stuck(e.trim_end_matches('.').to_string()))?;
    }
    Ok(Some(Change {
        pos,
        name,
        new,
        old,
        target,
        renamed,
    }))
}

/// What to do by hand to give the environment with the ID `removed` the
/// ID `new` (its folder `old`, to become `target`; `renamed`: it did).
fn by_hand(old: &Path, target: &Path, new: &str, renamed: bool) -> Vec<String> {
    let id = format!("change its \"id\" in {REGISTRY_FILE} to \"{new}\"");
    let summary = Path::new("runs").join("<run>").join("summary.json");
    // A run loaded from a history keeps it as summary.v2.json.
    let runs = format!(
        "in each of its runs' summary.json or summary.v2.json ({}), change \"environment\": \"{REMOVED_DIR}\" to \"{new}\"",
        summary.display()
    );
    if renamed {
        vec![
            format!("its folder is {} already: {id}", target.display()),
            runs,
        ]
    } else {
        vec![
            format!(
                "move that environment's own files from {} to {} (leave the removals there: folders that hold {JOURNAL_FILE}, and folders named like lab-1759000000, made by 0.1.x)",
                old.display(),
                target.display()
            ),
            id,
            runs,
        ]
    }
}

/// `path` with one kind of separator: a workspace given as `C:/ws`, joined
/// with `environments`, reads `C:\ws\environments`.
fn tidy(path: &Path) -> PathBuf {
    path.components().collect()
}

/// [`PROBLEM_FILE`] in this process too, per workspace, for when that
/// file couldn't be written either (a workspace that can't be written).
static LAST_PROBLEMS: std::sync::Mutex<Vec<(PathBuf, Stuck)>> = std::sync::Mutex::new(Vec::new());

/// Keeps why the last try failed part way ([`PROBLEM_FILE`]), or forgets
/// it (`None`: it got through, or there was nothing to do).
fn remember(root: &Path, problem: Option<&Stuck>) {
    let file = root.join(PROBLEM_FILE);
    match problem {
        Some(p) => {
            if let Ok(text) = serde_json::to_string_pretty(p) {
                let _ = fs::write(&file, text);
            }
        }
        None => {
            if fs::symlink_metadata(&file).is_ok() {
                let _ = fs::remove_file(&file);
            }
        }
    }
    let mut all = LAST_PROBLEMS.lock().unwrap_or_else(|e| e.into_inner());
    all.retain(|(r, _)| r != root);
    if let Some(p) = problem {
        all.push((root.to_path_buf(), p.clone()));
    }
}

/// What [`remember`] kept for `root`: [`PROBLEM_FILE`] (written by any
/// process), else this process's own.
fn remembered(root: &Path) -> Option<Stuck> {
    fs::read_to_string(root.join(PROBLEM_FILE))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .or_else(|| {
            LAST_PROBLEMS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .find(|(r, _)| r == root)
                .map(|(_, p)| p.clone())
        })
}

/// An environment that got the ID `removed` before it was reserved owns
/// the folder removals use: it gets a free `removed-N` instead (its folder
/// renamed, its runs' `summary.json` and the registry changed), under the
/// registry's lock. Each step can run again after an interruption: the new
/// ID depends only on the registry (and on which `removed-N` folders exist
/// without [`RENAMED_FILE`]: those are skipped), which changes last.
/// Removals made by 0.1.x in that folder (`<id>-<unix time>`, no record)
/// stay in `environments/removed`. If that folder already holds removals
/// with a record, nothing changes and removing stops with what to do by
/// hand ([`reserved_check`]).
fn migrate_reserved(root: &Path, reg: &mut Registry) -> Result<(), Stuck> {
    let Some(c) = reserved_check(root, reg)? else {
        remember(root, None);
        return Ok(());
    };
    let done = migrate(root, reg, &c);
    remember(root, done.as_ref().err());
    done
}

/// The change [`reserved_check`] found possible.
fn migrate(root: &Path, reg: &mut Registry, c: &Change) -> Result<(), Stuck> {
    let failed = |what: String| Stuck {
        name: c.name.clone(),
        why: Some(what),
        steps: by_hand(
            &c.old,
            &c.target,
            &c.new,
            c.target.join(RENAMED_FILE).is_file(),
        ),
    };
    if !c.renamed && fs::symlink_metadata(&c.old).is_ok() {
        fs::write(
            c.old.join(RENAMED_FILE),
            format!("Pathwarden: this environment ({}) had the ID \"{REMOVED_DIR}\", reserved since 0.1.3; it is now \"{}\".\n", c.name, c.new),
        )
        .map_err(|e| failed(format!("{} couldn't be written ({e})", c.old.join(RENAMED_FILE).display())))?;
        fs::rename(&c.old, &c.target).map_err(|e| {
            failed(format!(
                "{} couldn't be renamed to {} ({e})",
                c.old.display(),
                c.target.display()
            ))
        })?;
    }
    // Removals made by 0.1.x went into the same folder: they stay where
    // removals are kept, not in the environment's settings.
    let legacy: Vec<PathBuf> = fs::read_dir(&c.target)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| legacy_removal(p))
        .collect();
    if !legacy.is_empty() {
        fs::create_dir_all(&c.old)
            .map_err(|e| failed(format!("{} couldn't be made ({e})", c.old.display())))?;
        for p in legacy {
            let to = unique(&c.old.join(p.file_name().unwrap_or_default()));
            fs::rename(&p, &to).map_err(|e| {
                failed(format!(
                    "{} couldn't be moved back to {} ({e})",
                    p.display(),
                    c.old.display()
                ))
            })?;
        }
    }
    #[cfg(test)]
    tests::maybe_fail_summary()
        .map_err(|e| failed(format!("a run summary couldn't be changed ({e})")))?;
    let ws = Workspace::existing(root).map_err(|e| failed(format!("{e:#}")))?;
    for (_, mut s) in scan(root) {
        if s.environment.as_deref() == Some(REMOVED_DIR) {
            s.environment = Some(c.new.clone());
            ws.update_summary(&s)
                .map_err(|e| failed(format!("a run summary couldn't be changed ({e:#})")))?;
        }
    }
    reg.environments[c.pos].id = c.new.clone();
    if reg.current.as_deref() == Some(REMOVED_DIR) {
        reg.current = Some(c.new.clone());
    }
    Ok(())
}

/// Removes environment `id` with its runs ([`plan`], then the moves, then
/// the registry), under the registry's lock. `expect` is the
/// [`Plan::runs_key`] shown when the user confirmed: if the runs changed
/// meanwhile, nothing is removed.
pub fn remove(
    root: &Path,
    id: &str,
    state: Option<&Path>,
    expect: Option<&str>,
) -> Result<Removed, String> {
    Registry::update(root, |reg| {
        recorded_removals(root, reg);
        migrate_reserved(root, reg).map_err(|s| s.refusal())?;
        sweep(root, reg, state);
        let plan = plan_in(root, reg, id, state)?;
        if expect.is_some_and(|k| k != plan.runs_key) {
            return Err(format!(
                "Nothing was removed: {} now has {}. Check the list and confirm again.",
                plan.name,
                match plan.runs {
                    1 => "1 run".to_string(),
                    n => format!("{n} runs"),
                }
            ));
        }
        let (folder, mut journal) = removal_folder(root, &plan)?;
        for (moved, item) in plan.items.iter().enumerate() {
            let to = unique(&folder.join(&item.to));
            let made = to.parent().map(fs::create_dir_all).transpose().map(|_| ());
            let result = made.and_then(|()| {
                #[cfg(test)]
                tests::maybe_fail(moved)?;
                fs::rename(&item.from, &to)
            });
            if let Err(e) = result {
                return Err(format!(
                    "Couldn't move {}: {e}. {moved} of {} moved to {} so far; {} is still listed with the rest. Remove it again to finish.",
                    item.from.display(),
                    plan.items.len(),
                    folder.display(),
                    plan.name
                ));
            }
        }
        // The registry last: until here the environment is listed with
        // whatever was not moved yet.
        if plan.default {
            reg.reset_default();
        } else {
            reg.environments.retain(|e| e.id != id);
            if !reg.removed.iter().any(|r| r == id) {
                reg.removed.push(id.to_string());
            }
        }
        let now_current = if plan.current {
            let remaining = scan(root);
            let runs: Vec<RunSummary> = remaining.into_iter().map(|(_, s)| s).collect();
            let unused = reg.default_unused(root, &environments::run_domains(reg, &runs));
            let next = next_env(reg, None, unused);
            reg.current = Some(next.clone());
            Some(next)
        } else {
            None
        };
        let now_current_name = match &now_current {
            Some(n) => {
                let all = Workspace::existing(root)
                    .map(|w| w.all_runs())
                    .unwrap_or_default();
                let named = reg.clone().with_names(&all);
                let unused = named.default_unused(root, &environments::run_domains(&named, &all));
                if n == DEFAULT_ENV && unused {
                    NO_ENV_YET.to_string()
                } else {
                    named.name_of(n)
                }
            }
            None => String::new(),
        };
        let removed = Removed {
            id: id.to_string(),
            name: plan.name.clone(),
            runs: plan.runs,
            bytes: plan.bytes,
            folder,
            kept: plan.kept.clone(),
            links: plan.links.clone(),
            now_current,
            now_current_name,
            demo: plan.demo,
        };
        // Finished, still under the lock: the record says so (a later
        // removal never resumes into it), with what the page shows next.
        journal.done = true;
        journal.message = removed.lines();
        write_journal(&removed.folder, &journal).map_err(|e| {
            pathwarden_core::logs::session_line(&format!(
                "Removing {}: its record couldn't be finished: {e}",
                removed.name
            ));
            format!(
                "Moved to {}, but {} is still listed. Remove it again to finish.",
                removed.folder.display(),
                removed.name
            )
        })?;
        Ok(removed)
    })
}

/// Which runs (by folder) a removal takes, as one short value: the
/// confirmation carries it, so a run added or gone meanwhile is noticed
/// even when the count is the same.
pub fn runs_key(folders: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<&str> = folders.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let digest = Sha256::digest(sorted.join("\n").as_bytes());
    digest[..12].iter().map(|b| format!("{b:02x}")).collect()
}

/// What to know about links inside what moves (at most 10 named).
fn link_lines(links: &[PathBuf]) -> Vec<String> {
    let mut out: Vec<String> = links
        .iter()
        .take(10)
        .map(|l| {
            format!(
                "{} is a link (a symbolic link or junction): it moves as a link, and what it points to is not touched. Before deleting the removal's folder, remove that link first (rmdir for a folder link, del for a file link; either removes only the link), or use a tool that doesn't follow links.",
                l.display()
            )
        })
        .collect();
    if links.len() > 10 {
        out.push(format!(
            "And {} more links, the same way.",
            links.len() - 10
        ));
    }
    out
}

/// The finished removal recorded in folder `name` of
/// `environments/removed`: what to show after it ("" names nothing).
pub fn finished_message(root: &Path, name: &str) -> Option<Vec<String>> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return None;
    }
    let j = read_journal(&removed_root(root).join(name))?;
    j.done.then_some(j.message)
}

/// At the start (`state`: `pathwarden ui --state DIR`): an environment
/// with the reserved ID `removed` gets another ([`migrate_reserved`]),
/// removed IDs only removal records still name are known again
/// ([`recorded_removals`]), and runs saved for an environment while it was
/// being removed join it ([`sweep`]). Nothing happens (and no lock is
/// taken) when none applies. Why the environment with the ID `removed`
/// couldn't get another, if it couldn't.
pub fn sweep_on_start(root: &Path, state: Option<&Path>) -> Option<Stuck> {
    let reg = Registry::load(root);
    let mut probe = reg.clone();
    let missing = recorded_removals(root, &mut probe);
    let mut problem = None;
    if missing || !reg.removed.is_empty() || reg.get(REMOVED_DIR).is_some() {
        let done = Registry::update(root, |r| {
            recorded_removals(root, r);
            // Retried at each start and before each removal.
            if let Err(e) = migrate_reserved(root, r) {
                problem = Some(e);
            }
            sweep(root, r, state);
            Ok(())
        });
        if let (Err(e), None) = (done, &problem) {
            if let Some(old) = reg.get(REMOVED_DIR) {
                let stuck = Stuck {
                    name: old.display().to_string(),
                    why: Some(format!("{REGISTRY_FILE} couldn't be changed ({e})")),
                    steps: vec![format!(
                        "make {} writable again, then start Pathwarden",
                        tidy(&root.join(REGISTRY_FILE)).display()
                    )],
                };
                remember(root, Some(&stuck));
                problem = Some(stuck);
            }
        }
    }
    problem
}

/// What the Environments page and `pathwarden env list` say while an
/// environment still has the reserved ID `removed` (from before 0.1.3):
/// removing environments is stopped until it gets another, and why
/// ([`reserved_check`], worked out again each time, else what failed in
/// the last try).
pub fn reserved_note(root: &Path) -> Option<Stuck> {
    let reg = Registry::load(root);
    let e = reg.get(REMOVED_DIR)?;
    if let Err(stuck) = reserved_check(root, &reg) {
        return Some(stuck);
    }
    Some(remembered(root).unwrap_or_else(|| Stuck {
        name: e.display().to_string(),
        why: None,
        steps: Vec::new(),
    }))
}

// ------------------------------------------------------------ the rules

/// Whether `path` may be moved out of the workspace at `root`: it exists,
/// is not a link (a symbolic link, a junction or any other reparse point:
/// a rename would move the link, but nothing should ever be done to what it
/// points to), and resolves to a path inside the workspace, not the
/// workspace itself. Its resolved path.
pub fn movable(root: &Path, path: &Path) -> Result<PathBuf, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if is_link(&meta) {
        return Err(format!(
            "{} is a link, so it stays where it is.",
            path.display()
        ));
    }
    let base = fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
    let real = fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if real == base || !real.starts_with(&base) {
        return Err(format!(
            "{} is outside the workspace ({}), so Pathwarden leaves it as it is.",
            path.display(),
            root.display()
        ));
    }
    Ok(real)
}

/// A symbolic link, a junction, or another reparse point.
fn is_link(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// [`movable`], and directly in folder `parent` (resolved): for the first
/// environment's files, which are in the workspace folder itself.
fn movable_in(root: &Path, parent: &Path, path: &Path) -> Result<PathBuf, String> {
    let real = movable(root, path)?;
    let parent = fs::canonicalize(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    if real.parent() != Some(parent.as_path()) {
        return Err(format!(
            "{} is not directly in {}, so Pathwarden leaves it as it is.",
            path.display(),
            parent.display()
        ));
    }
    Ok(real)
}

/// The bytes under `path`, and the links found there: links are never
/// followed (they count as nothing; a rename moves them as links).
pub fn size_of(path: &Path) -> (u64, Vec<PathBuf>) {
    let mut links = Vec::new();
    let bytes = walk(path, &mut links);
    (bytes, links)
}

fn walk(path: &Path, links: &mut Vec<PathBuf>) -> u64 {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return 0;
    };
    if is_link(&meta) {
        links.push(path.to_path_buf());
        return 0;
    }
    if !meta.is_dir() {
        return meta.len();
    }
    fs::read_dir(path)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| walk(&e.path(), links))
        .sum()
}

/// "820 bytes", "14 KB", "3.2 MB", "1.4 GB".
pub fn size_words(bytes: u64) -> String {
    const K: u64 = 1024;
    match bytes {
        b if b < K => format!("{b} bytes"),
        b if b < K * K => format!("{} KB", b.div_ceil(K)),
        b if b < K * K * K => format!("{:.1} MB", b as f64 / (K * K) as f64),
        b => format!("{:.1} GB", b as f64 / (K * K * K) as f64),
    }
}

/// The Windows task and systemd timer a schedule for environment `id`
/// gets ([`crate::collect::schedule`]).
fn schedule_names(id: &str) -> (String, String) {
    if id == DEFAULT_ENV {
        ("Pathwarden".into(), "pathwarden".into())
    } else {
        (format!("Pathwarden-{id}"), format!("pathwarden-{id}"))
    }
}

/// Every saved run: its folder name and summary.
fn scan(root: &Path) -> Vec<(String, RunSummary)> {
    let Ok(ws) = Workspace::existing(root) else {
        return Vec::new();
    };
    fs::read_dir(ws.runs_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let s = ws.summary(&name)?;
            Some((name, s))
        })
        .collect()
}

/// The environment shown after one goes: the first one left that is not
/// the demo's (nor an unused Default), else Default ("No environment yet").
fn next_env(reg: &Registry, without: Option<&str>, default_unused: bool) -> String {
    reg.environments
        .iter()
        .filter(|e| Some(e.id.as_str()) != without)
        .find(|e| !e.demo && !(e.is_default() && default_unused))
        .map(|e| e.id.clone())
        .unwrap_or_else(|| DEFAULT_ENV.into())
}

/// What is never moved, by a removal ([`plan_in`]) or a sweep ([`sweep`]):
/// the workspace's shared folders and files, what the other environments
/// use (their run history and settings), and the folder given with
/// `pathwarden ui --state`. Compared as resolved paths, so `Runs`, `runs.`
/// or a `[state] path` naming one are caught too.
struct Guard {
    /// Each shared path and its name.
    shared: Vec<(PathBuf, String)>,
    /// Each path in use, and why it stays.
    used: Vec<(PathBuf, String)>,
}

impl Guard {
    /// The guard for removing environment `except` (`None` for a sweep:
    /// every listed environment counts). `state`: `pathwarden ui --state`.
    fn new(root: &Path, reg: &Registry, except: Option<&str>, state: Option<&Path>) -> Self {
        let shared = SHARED
            .iter()
            .filter_map(|n| {
                fs::canonicalize(root.join(n))
                    .ok()
                    .map(|p| (p, n.to_string()))
            })
            .collect();
        let mut used = Vec::new();
        if let Some(real) = state.and_then(|s| fs::canonicalize(s).ok()) {
            used.push((
                real,
                "it is the run history set when Pathwarden was started".to_string(),
            ));
        }
        if let Ok(ws) = Workspace::existing(root) {
            let named = reg.clone().with_names(&ws.all_runs());
            for other in named
                .environments
                .iter()
                .filter(|e| Some(e.id.as_str()) != except)
            {
                let ows = ws.in_env(&other.id);
                let flag = if other.is_default() { state } else { None };
                let mut paths = vec![ows.config_path()];
                if let Ok(l) = crate::history_ui::locate(&ows, flag) {
                    paths.push(l.dir);
                }
                for p in paths {
                    if let Ok(real) = fs::canonicalize(&p) {
                        used.push((real, format!("the environment {} uses it", other.display())));
                    }
                }
            }
        }
        Guard { shared, used }
    }

    /// Why `path` must stay, if it must: it is (or holds) a shared path or
    /// one in use.
    fn must_stay(&self, path: &Path) -> Option<String> {
        let real = fs::canonicalize(path).ok()?;
        if let Some((_, n)) = self.shared.iter().find(|(s, _)| s.starts_with(&real)) {
            return Some(format!(
                "{} stays: the workspace's own {n} is (or is in) it.",
                path.display()
            ));
        }
        self.used
            .iter()
            .find(|(u, _)| u.starts_with(&real))
            .map(|(_, why)| format!("{} stays: {why}.", path.display()))
    }
}

/// IDs that removal records in `environments/removed` name.
fn removed_on_disk(root: &Path) -> Vec<String> {
    fs::read_dir(removed_root(root))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| read_journal(&e.path()).map(|j| j.id))
        .collect()
}

/// A removal made by 0.1.x: a folder `<id>-<unix time>` without a record.
fn legacy_removal(path: &Path) -> bool {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return false;
    };
    let Some((id, time)) = name.rsplit_once('-') else {
        return false;
    };
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir() && !is_link(&m))
        && !path.join(JOURNAL_FILE).exists()
        && environments::valid_id(id)
        && time.len() >= 9
        && time.bytes().all(|b| b.is_ascii_digit())
}

/// IDs that removal records name but the registry lists neither as an
/// environment nor as removed (`environments.json` lost its `removed`
/// list, or was put back from an older copy) are added back to
/// [`Registry::removed`], so their runs are listed nowhere and [`sweep`]
/// files them away. Whether any was added.
fn recorded_removals(root: &Path, reg: &mut Registry) -> bool {
    let mut added = false;
    for id in removed_on_disk(root) {
        if id != DEFAULT_ENV
            && environments::valid_id(&id)
            && reg.get(&id).is_none()
            && !reg.removed.contains(&id)
        {
            reg.removed.push(id);
            added = true;
        }
    }
    added
}

fn plan_in(root: &Path, reg: &Registry, id: &str, state: Option<&Path>) -> Result<Plan, String> {
    let ws = Workspace::existing(root).map_err(|e| format!("{e:#}"))?;
    let saved = scan(root);
    let all = ws.all_runs();
    let named = reg.clone().with_names(&all);
    let env = named
        .get(id)
        .ok_or("That environment no longer exists.")?
        .clone();
    let name = env.display().to_string();
    // An environment made before `removed` was reserved owns the folder
    // removals move into.
    if let Some(e) = named.environments.iter().find(|e| e.id == REMOVED_DIR) {
        return Err(format!(
            "Nothing was removed: the environment {1} uses the folder {0}, which Pathwarden needs. Stop Pathwarden, then rename that folder and its \"id\" in {REGISTRY_FILE} (for example to removed-env).",
            removed_root(root).display(),
            e.display()
        ));
    }
    let default_unused = reg.default_unused(root, &environments::run_domains(reg, &all));
    if env.is_default() && default_unused {
        return Err(format!(
            "{name} has nothing to remove: no runs, settings or history."
        ));
    }
    // The first environment's runs include runs naming an environment the
    // registry doesn't know (environments.json missing or older than
    // them): those may be another environment's, so nothing moves. (Runs
    // naming an environment a removal record names are not among them:
    // [`recorded_removals`] made that ID a removed one before this.)
    let mut kept = Vec::new();
    if env.is_default() {
        let unknown: Vec<(&String, String)> = saved
            .iter()
            .filter(|(_, s)| environments::run_env(reg, s) == DEFAULT_ENV)
            .filter_map(|(f, s)| {
                s.environment
                    .clone()
                    .filter(|e| e != DEFAULT_ENV)
                    .map(|e| (f, e))
            })
            .collect();
        if !unknown.is_empty() {
            let mut ids: Vec<&str> = unknown.iter().map(|(_, e)| e.as_str()).collect();
            ids.sort_unstable();
            ids.dedup();
            let mut runs: Vec<String> = unknown
                .iter()
                .take(10)
                .map(|(f, _)| f.to_string())
                .collect();
            if unknown.len() > 10 {
                runs.push(format!("and {} more", unknown.len() - 10));
            }
            return Err(format!(
                "Nothing was removed: some runs belong to environments that are no longer listed ({}): {} in {}. Put back {REGISTRY_FILE} (a copy may be in {BACKUP_FILE}), then try again.",
                ids.join(", "),
                runs.join(", "),
                ws.runs_dir().display()
            ));
        }
    }
    let flag_for = |e: &str| if e == DEFAULT_ENV { state } else { None };
    let guard = Guard::new(root, reg, Some(id), state);
    let must_stay = |path: &Path| guard.must_stay(path);

    let mut items = Vec::new();
    let mut links = Vec::new();
    let mut add = |items: &mut Vec<Item>, from: PathBuf, to: String| {
        let (bytes, found) = size_of(&from);
        links.extend(found);
        items.push(Item { from, to, bytes });
    };

    // Its runs: folders whose summary names it.
    let mine: Vec<&(String, RunSummary)> = saved
        .iter()
        .filter(|(_, s)| environments::run_env(reg, s) == id)
        .collect();
    for (folder, _) in &mine {
        let dir = ws.runs_dir().join(folder);
        // A run that can't be moved would be left behind: nothing moves.
        movable(root, &dir).map_err(|e| format!("{e} Nothing was removed."))?;
        if let Some(why) = must_stay(&dir) {
            return Err(format!("{why} Nothing was removed."));
        }
        add(&mut items, dir, format!("runs/{folder}"));
    }
    let runs = items.len();
    let folders: Vec<String> = mine.iter().map(|(f, _)| f.clone()).collect();

    // Its folder, or the first environment's files.
    let env_ws = ws.in_env(id);
    let history = crate::history_ui::locate(&env_ws, flag_for(id))
        .ok()
        .map(|l| l.dir);
    let mut files = false;
    let mut candidates: Vec<(PathBuf, String)> = Vec::new();
    if env.is_default() {
        let mut names: Vec<String> = [
            workspace::CONFIG_FILE,
            crate::history_ui::KEPT_LOCAL_FILE,
            workspace::LABELS_FILE,
            crate::history_ui::DEFAULT_FOLDER,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // Its run history moves when it is configured directly in the
        // workspace folder; anywhere else it stays. A folder given with
        // `pathwarden ui --state` always stays, wherever it is (the guard
        // keeps it even when it is `pathwarden-state` itself).
        if let (Some(h), Some(_)) = (&history, state) {
            if h.exists() {
                kept.push(format!(
                    "Its run history in {} (set when Pathwarden was started) stays where it is.",
                    h.display()
                ));
            }
        } else if let Some(h) = &history {
            match (movable_in(root, root, h), h.file_name()) {
                (Ok(_), Some(n)) => {
                    let n = n.to_string_lossy().into_owned();
                    if !names.contains(&n) {
                        names.push(n);
                    }
                }
                _ if h.exists() => kept.push(format!(
                    "Its run history in {} is not directly in the workspace folder, so it stays where it is.",
                    h.display()
                )),
                _ => {}
            }
        }
        for n in names {
            let p = root.join(&n);
            if fs::symlink_metadata(&p).is_err() {
                continue;
            }
            match movable_in(root, root, &p) {
                Ok(_) => candidates.push((p, format!("env/{n}"))),
                Err(e) => kept.push(e),
            }
        }
    } else {
        let dir = environments::env_dir(root, id);
        if fs::symlink_metadata(&dir).is_ok() {
            match movable_in(root, &root.join(ENVS_DIR), &dir) {
                Ok(real) => {
                    candidates.push((dir, "env".into()));
                    if let Some(h) = history.filter(|h| h.exists()) {
                        let within = fs::canonicalize(&h).is_ok_and(|h| h.starts_with(&real));
                        if !within {
                            kept.push(format!(
                                "Its run history in {} is outside its folder, so it stays where it is.",
                                h.display()
                            ));
                        }
                    }
                }
                Err(e) => kept.push(e),
            }
        }
    }
    for (from, to) in candidates {
        match must_stay(&from) {
            Some(why) => kept.push(why),
            None => {
                files = true;
                add(&mut items, from, to);
            }
        }
    }

    // Collections its runs kept, unless another environment's run uses them.
    let collections_dir = ws.collections_dir();
    let mut collections = 0;
    let mut seen: Vec<PathBuf> = Vec::new();
    for (_, s) in &mine {
        let Some(kept_at) = s.collection.as_ref().and_then(|c| c.kept.as_deref()) else {
            continue;
        };
        let p = PathBuf::from(kept_at);
        if fs::symlink_metadata(&p).is_err() {
            continue;
        }
        let real = match movable_in(root, &collections_dir, &p) {
            Ok(r) => r,
            Err(e) => {
                kept.push(format!("The kept collection stays: {e}"));
                continue;
            }
        };
        if seen.contains(&real) {
            continue;
        }
        seen.push(real.clone());
        let shared_run = saved.iter().any(|(_, o)| {
            environments::run_env(reg, o) != id
                && o.collection
                    .as_ref()
                    .and_then(|c| c.kept.as_deref())
                    .and_then(|k| fs::canonicalize(k).ok())
                    .is_some_and(|k| k == real)
        });
        if shared_run {
            kept.push(format!(
                "The collection kept in {} is also used by another environment's run, so it stays.",
                p.display()
            ));
            continue;
        }
        if let Some(why) = must_stay(&p) {
            kept.push(why);
            continue;
        }
        let name = real
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "collection".into());
        collections += 1;
        add(&mut items, p, format!("collections/{name}"));
    }

    let current = reg.current.as_deref().unwrap_or(DEFAULT_ENV) == id;
    // After it goes: the first environment left, else "No environment yet".
    let mut after = reg.clone();
    if env.is_default() {
        after.reset_default();
    }
    let unused_after = if env.is_default() {
        true
    } else {
        let left: Vec<RunSummary> = all
            .iter()
            .filter(|r| environments::run_env(reg, r) != id)
            .cloned()
            .collect();
        reg.default_unused(root, &environments::run_domains(reg, &left))
    };
    let next = next_env(&after, (!env.is_default()).then_some(id), unused_after);
    let next_name = if next == DEFAULT_ENV && unused_after {
        NO_ENV_YET.to_string()
    } else {
        named.name_of(&next)
    };
    let bytes = items.iter().map(|i| i.bytes).sum();
    Ok(Plan {
        id: id.to_string(),
        name,
        entry: Environment {
            shown: None,
            ..env.clone()
        },
        default: env.is_default(),
        demo: env.demo,
        runs,
        runs_key: runs_key(&folders),
        links,
        collections,
        files,
        items,
        bytes,
        kept,
        current,
        next,
        next_name,
        removed_dir: removed_root(root),
    })
}

// ------------------------------------------------------- the removal folder

/// `environments/removed` in the workspace.
fn removed_root(root: &Path) -> PathBuf {
    root.join(ENVS_DIR).join(REMOVED_DIR)
}

/// A removal's record ([`JOURNAL_FILE`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Journal {
    id: String,
    name: String,
    /// The registry entry, for a restore.
    entry: Environment,
    /// The first environment (its files were in the workspace folder).
    #[serde(default)]
    default: bool,
    started_at: i64,
    /// False while the removal is under way (or was interrupted).
    done: bool,
    /// What was shown when it finished.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    message: Vec<String>,
}

fn read_journal(folder: &Path) -> Option<Journal> {
    let t = fs::read_to_string(folder.join(JOURNAL_FILE)).ok()?;
    serde_json::from_str(&t).ok()
}

fn write_journal(folder: &Path, j: &Journal) -> Result<(), String> {
    let text = serde_json::to_string_pretty(j).map_err(|e| e.to_string())?;
    pathwarden_core::config_edit::write_atomic(&folder.join(JOURNAL_FILE), &text).map_err(|e| {
        format!(
            "Couldn't write {}: {e}",
            folder.join(JOURNAL_FILE).display()
        )
    })
}

/// The removals of environment `id` (folder, record), oldest first.
fn removals_of(root: &Path, id: &str) -> Vec<(PathBuf, Journal)> {
    let mut out: Vec<(PathBuf, Journal)> = fs::read_dir(removed_root(root))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(&format!("{id}-"))
        })
        .filter_map(|e| {
            let p = e.path();
            let meta = fs::symlink_metadata(&p).ok()?;
            if is_link(&meta) || !meta.is_dir() {
                return None;
            }
            let j = read_journal(&p)?;
            (j.id == id).then_some((p, j))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The folder this removal moves into: an unfinished removal of the same
/// environment's (to finish it), else a new `<id>-<time>`. Checked to be
/// inside the workspace; its record and `RESTORE.txt` written first.
fn removal_folder(root: &Path, plan: &Plan) -> Result<(PathBuf, Journal), String> {
    let base = removed_root(root);
    fs::create_dir_all(&base).map_err(|e| format!("Couldn't create {}: {e}", base.display()))?;
    movable(root, &base).map_err(|e| format!("{e} Nothing was removed."))?;
    if let Some((folder, j)) = removals_of(root, &plan.id)
        .into_iter()
        .rfind(|(_, j)| !j.done)
    {
        return Ok((folder, j));
    }
    let now = pathwarden_core::analyze::now();
    let stamp: String = pathwarden_core::time::format_unix(now)
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let stamp = format!("{}-{}{:02}", &stamp[..8], &stamp[8..], now.rem_euclid(60));
    let folder = unique(&base.join(format!("{}-{stamp}", plan.id)));
    fs::create_dir_all(&folder)
        .map_err(|e| format!("Couldn't create {}: {e}", folder.display()))?;
    movable(root, &folder).map_err(|e| format!("{e} Nothing was removed."))?;
    let j = Journal {
        id: plan.id.clone(),
        name: plan.name.clone(),
        entry: plan.entry.clone(),
        default: plan.default,
        started_at: now,
        done: false,
        message: Vec::new(),
    };
    write_journal(&folder, &j)?;
    let restore = restore_text(root, plan);
    fs::write(folder.join(RESTORE_FILE), restore)
        .map_err(|e| format!("Couldn't write {RESTORE_FILE}: {e}"))?;
    Ok((folder, j))
}

/// `path`, or `path-2`, `path-3`… if it is taken.
fn unique(path: &Path) -> PathBuf {
    if fs::symlink_metadata(path).is_err() {
        return path.to_path_buf();
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    (2..)
        .map(|n| path.with_file_name(format!("{name}-{n}")))
        .find(|p| fs::symlink_metadata(p).is_err())
        .unwrap_or_else(|| path.to_path_buf())
}

/// How to put the environment back, by hand.
fn restore_text(root: &Path, plan: &Plan) -> String {
    let entry = serde_json::to_string(&plan.entry).unwrap_or_default();
    let root = root.display();
    let files = if plan.default {
        format!("3. Move what is in env/ back into the workspace folder ({root}). A new first environment may have made files of the same names there since: move those aside first, or keep them and skip yours.\n")
    } else {
        format!(
            "3. Move env/ back to {root}{sep}{ENVS_DIR}{sep}{id}.\n",
            sep = std::path::MAIN_SEPARATOR,
            id = plan.id
        )
    };
    let registry = if plan.default {
        format!(
            "5. In {root}{sep}{REGISTRY_FILE}, give the entry with \"id\": \"default\" its name and domains again:\n   {entry}\n",
            sep = std::path::MAIN_SEPARATOR
        )
    } else {
        format!(
            "5. In {root}{sep}{REGISTRY_FILE}, add this entry to \"environments\" and take \"{id}\" out of \"removed\":\n   {entry}\n",
            sep = std::path::MAIN_SEPARATOR,
            id = plan.id
        )
    };
    let links = if plan.links.is_empty() {
        String::new()
    } else {
        let list: String = plan
            .links
            .iter()
            .map(|l| format!("   {}\n", l.display()))
            .collect();
        format!(
            "\nLinks: these were symbolic links or junctions where they were, and moved here as links; what they point to was not touched:\n{list}\
             Before deleting this folder, remove each link itself first (rmdir for a folder link, del for a file link), or use a tool that doesn't follow links, so nothing they point to is deleted.\n"
        )
    };
    format!(
        "Pathwarden: the environment {name} was removed with its runs.\n\
         Nothing was deleted; this folder holds all of it.\n\n\
         To put it back:\n\
         1. Stop Pathwarden (the app, and any pathwarden command using this workspace).\n\
         2. Move each folder in runs/ back into {root}{sep}runs.\n\
         {files}\
         4. Move each folder in collections/ (if any) back into {root}{sep}collections.\n\
         {registry}\
         6. Start Pathwarden again.\n\n\
         Folders named env-later/ (if any) hold files written for it after it was removed, and runs/ may have runs saved then: merge env-later/ into the restored folder, or leave it out.\n\
         {links}\n\
         To free the space instead, delete this folder (only this one, not the folder it is in).\n",
        name = plan.name,
        sep = std::path::MAIN_SEPARATOR,
    )
}

/// Runs still naming a removed environment (saved while it was being
/// removed) join its latest removal's folder, as does a folder made again
/// for it. Links and anything outside the workspace are left alone.
/// Called under the registry's lock.
pub(crate) fn sweep(root: &Path, reg: &Registry, state: Option<&Path>) {
    if reg.removed.is_empty() {
        return;
    }
    // The same rules as a removal: what another environment uses stays.
    let guard = Guard::new(root, reg, None, state);
    let latest = |id: &str| removals_of(root, id).pop().map(|(p, _)| p);
    let runs_dir = root.join("runs");
    for (folder, s) in scan(root) {
        let id = environments::run_env(reg, &s);
        if reg.get(&id).is_some() || !reg.removed.contains(&id) {
            continue;
        }
        let from = runs_dir.join(&folder);
        let Some(dest) = latest(&id) else { continue };
        if movable(root, &from).is_err() || guard.must_stay(&from).is_some() {
            continue;
        }
        let to = unique(&dest.join("runs").join(&folder));
        if to.parent().is_some_and(|p| fs::create_dir_all(p).is_ok()) {
            let _ = fs::rename(&from, &to);
        }
    }
    for id in &reg.removed {
        let dir = root.join(ENVS_DIR).join(id);
        if fs::symlink_metadata(&dir).is_err()
            || movable(root, &dir).is_err()
            || guard.must_stay(&dir).is_some()
        {
            continue;
        }
        if let Some(dest) = latest(id) {
            let _ = fs::rename(&dir, unique(&dest.join("env-later")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        /// Fail the move after this many (an interruption).
        static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
        /// Fail giving the old `removed` environment another ID after its
        /// folder moved, before its runs change (a locked summary.json).
        static FAIL_SUMMARY: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn maybe_fail_summary() -> std::io::Result<()> {
        if FAIL_SUMMARY.with(|f| f.get()) {
            return Err(std::io::Error::other("locked (test)"));
        }
        Ok(())
    }

    pub(super) fn maybe_fail(moved: usize) -> std::io::Result<()> {
        if FAIL_AFTER.with(|f| f.get()) == Some(moved) {
            return Err(std::io::Error::other("interrupted (test)"));
        }
        Ok(())
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pw-envrm-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        Workspace::open(&d).unwrap();
        d
    }

    fn run_id(n: u32) -> String {
        format!("20261002-0553{n:02}-abcdef")
    }

    /// Saves a run of environment `env` (`default` for the first).
    fn add_run(root: &Path, n: u32, env: &str, domain: &str) -> String {
        let id = run_id(n);
        let mut r: RunSummary = serde_json::from_value(serde_json::json!({
            "id": id, "created_at": n, "collected_at": null,
            "source": "x.zip", "demo": false, "domains": [domain], "objects": 1,
            "files": 1, "exposure_percent": 0.0, "exposed": 0, "population": 0,
            "protection_score": null, "critical": 0, "high": 0, "medium": 0,
            "low": 0, "info": 0, "suppressed": 0, "plan_steps": 0,
            "pathwarden": "0.1.2", "trusted_domains": [],
        }))
        .unwrap();
        r.environment = (env != DEFAULT_ENV).then(|| env.to_string());
        Workspace::open(root)
            .unwrap()
            .save_run(&r, "<html>report</html>")
            .unwrap();
        id
    }

    fn listed(root: &Path, env: &str) -> usize {
        Workspace::existing(root).unwrap().in_env(env).runs().len()
    }

    /// Lab (two runs, settings) and Default (one run, settings).
    fn two_envs(name: &str) -> PathBuf {
        let d = tmp(name);
        Registry::update(&d, |r| r.create("Lab", &["LAB.LOCAL".into()])).unwrap();
        fs::create_dir_all(d.join("environments/lab/pathwarden-state")).unwrap();
        fs::write(
            d.join("environments/lab/pathwarden.toml"),
            "tier_zero = []\n",
        )
        .unwrap();
        fs::write(d.join("pathwarden.toml"), "tier_zero = []\n").unwrap();
        add_run(&d, 1, "lab", "LAB.LOCAL");
        add_run(&d, 2, "lab", "LAB.LOCAL");
        add_run(&d, 3, DEFAULT_ENV, "CONTOSO.LOCAL");
        d
    }

    #[test]
    fn an_environment_goes_with_its_runs_and_can_come_back() {
        let d = two_envs("runs");
        Registry::update(&d, |r| {
            r.current = Some("lab".into());
            Ok(())
        })
        .unwrap();
        let p = plan(&d, "lab", None).unwrap();
        assert_eq!((p.runs, p.files, p.current), (2, true, true));
        assert_eq!(p.next, DEFAULT_ENV);
        assert!(p.bytes > 0);
        assert!(
            p.lines()[0].starts_with(
                "Moves out: 2 runs, its settings, its run history and its labels ("
            ),
            "{:?}",
            p.lines()
        );
        assert!(p.confirms(" lab ") && p.confirms("LAB") && !p.confirms("") && !p.confirms("La"));
        let r = remove(&d, "lab", None, Some(&p.runs_key)).unwrap();
        assert_eq!(r.runs, 2);
        assert_eq!(r.now_current.as_deref(), Some(DEFAULT_ENV));
        assert!(r.lines()[0].starts_with("Removed Lab: 2 runs and its files"));
        let reg = Registry::load(&d);
        assert!(reg.get("lab").is_none());
        assert_eq!(reg.removed, ["lab"]);
        assert_eq!(reg.current.as_deref(), Some(DEFAULT_ENV));
        assert!(!d.join("environments/lab").exists());
        assert!(
            d.join("runs").join(run_id(3)).exists(),
            "Default's run stays"
        );
        assert_eq!(listed(&d, DEFAULT_ENV), 1);
        // Everything is in the removal's folder, with its record.
        let folder = r.folder.clone();
        assert!(folder.starts_with(d.join("environments/removed")));
        assert!(folder
            .join("runs")
            .join(run_id(1))
            .join("summary.json")
            .is_file());
        assert!(folder.join("env/pathwarden.toml").is_file());
        assert!(folder.join(RESTORE_FILE).is_file());
        let name = folder.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(finished_message(&d, &name).unwrap(), r.lines());
        assert_eq!(finished_message(&d, "../x"), None);
        // A new environment never gets its ID.
        let id = Registry::update(&d, |r| r.create("Lab", &[])).unwrap();
        assert_eq!(id, "lab-2");
        Registry::update(&d, |r| {
            r.environments.retain(|e| e.id != "lab-2");
            Ok(())
        })
        .unwrap();
        // Restore, as RESTORE.txt says: folders back, the entry back.
        for e in fs::read_dir(folder.join("runs")).unwrap().flatten() {
            fs::rename(e.path(), d.join("runs").join(e.file_name())).unwrap();
        }
        fs::rename(folder.join("env"), d.join("environments/lab")).unwrap();
        let mut text = fs::read_to_string(d.join(REGISTRY_FILE)).unwrap();
        let entry = serde_json::to_string(&p.entry).unwrap();
        text = text.replacen(
            "\"environments\": [",
            &format!("\"environments\": [{entry},"),
            1,
        );
        fs::write(d.join(REGISTRY_FILE), text).unwrap();
        let reg = Registry::load(&d);
        assert!(reg.get("lab").is_some() && reg.removed.is_empty());
        assert_eq!(listed(&d, "lab"), 2);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn the_first_environment_can_go_too() {
        let d = two_envs("default");
        Registry::update(&d, |r| {
            r.edit(DEFAULT_ENV, "Production", &["CONTOSO.LOCAL".into()])
        })
        .unwrap();
        fs::write(d.join(workspace::LABELS_FILE), "{}").unwrap();
        fs::create_dir_all(d.join("pathwarden-state")).unwrap();
        let p = plan(&d, DEFAULT_ENV, None).unwrap();
        assert!(p.default && p.current);
        assert_eq!(p.next, "lab");
        assert_eq!(p.next_name, "Lab");
        let r = remove(&d, DEFAULT_ENV, None, None).unwrap();
        assert_eq!(r.runs, 1);
        assert_eq!(r.now_current.as_deref(), Some("lab"));
        // Its files left the workspace folder; the shared ones stayed.
        for f in ["pathwarden.toml", "pathwarden-state", "run-labels.json"] {
            assert!(!d.join(f).exists(), "{f}");
            assert!(r.folder.join("env").join(f).exists(), "{f}");
        }
        for f in ["runs", "uploads", REGISTRY_FILE, "environments/lab"] {
            assert!(d.join(f).exists(), "{f}");
        }
        // It starts over: unnamed, unused, not listed.
        let reg = Registry::load(&d);
        let def = reg.get(DEFAULT_ENV).unwrap();
        assert!(def.is_unnamed_default() && def.domains.is_empty());
        assert!(reg.removed.is_empty());
        assert!(reg.default_unused(&d, &[]));
        assert_eq!(listed(&d, "lab"), 2);
        // Nothing left to remove now.
        let err = plan(&d, DEFAULT_ENV, None).unwrap_err();
        assert!(err.contains("nothing to remove"), "{err}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn the_last_environment_leaves_no_environment_yet() {
        let d = tmp("last");
        add_run(&d, 1, DEFAULT_ENV, "CONTOSO.LOCAL");
        let p = plan(&d, DEFAULT_ENV, None).unwrap();
        assert_eq!(p.next_name, NO_ENV_YET);
        assert!(p.lines().iter().any(|l| l.contains("the last one")));
        let r = remove(&d, DEFAULT_ENV, None, Some(&p.runs_key)).unwrap();
        assert_eq!(r.now_current_name, NO_ENV_YET);
        let ws = Workspace::existing(&d).unwrap();
        assert!(ws.all_runs().is_empty());
        assert_eq!(ws.named_registry().name_of(DEFAULT_ENV), NO_ENV_YET);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_changed_environment_is_not_removed() {
        let d = two_envs("changed");
        let err = remove(&d, "lab", None, Some("0123")).unwrap_err();
        assert!(err.contains("Check the list and confirm again"), "{err}");
        assert_eq!(listed(&d, "lab"), 2);
        assert!(Registry::load(&d).get("lab").is_some());
        assert!(remove(&d, "nope", None, None).is_err());
        let _ = fs::remove_dir_all(&d);
    }

    /// Interrupted half-way: the environment is still listed with the runs
    /// not moved yet, the moved ones are listed nowhere, and removing it
    /// again finishes in the same folder.
    #[test]
    fn an_interrupted_removal_leaves_a_consistent_workspace() {
        let d = two_envs("crash");
        let before = fs::read_to_string(d.join(REGISTRY_FILE)).unwrap();
        FAIL_AFTER.with(|f| f.set(Some(1)));
        let err = remove(&d, "lab", None, None).unwrap_err();
        FAIL_AFTER.with(|f| f.set(None));
        assert!(
            err.contains("1 of 3 moved") && err.contains("Remove it again"),
            "{err}"
        );
        assert_eq!(fs::read_to_string(d.join(REGISTRY_FILE)).unwrap(), before);
        assert_eq!(listed(&d, "lab"), 1, "the run not moved is still Lab's");
        assert_eq!(listed(&d, DEFAULT_ENV), 1, "no run strays into Default");
        let ws = Workspace::existing(&d).unwrap();
        assert_eq!(ws.all_runs().len(), 2, "the moved run is listed nowhere");
        let r = remove(&d, "lab", None, None).unwrap();
        let removals = removals_of(&d, "lab");
        assert_eq!(removals.len(), 1, "finished in the same folder");
        assert!(removals[0].1.done);
        assert_eq!(fs::read_dir(r.folder.join("runs")).unwrap().count(), 2);
        let _ = fs::remove_dir_all(&d);
    }

    /// A run saved for an environment while it was removed is listed
    /// nowhere, and joins the others at the next start.
    #[test]
    fn a_run_saved_meanwhile_follows_its_environment() {
        let d = two_envs("late");
        let r = remove(&d, "lab", None, None).unwrap();
        let late = add_run(&d, 9, "lab", "LAB.LOCAL");
        fs::create_dir_all(d.join("environments/lab/pathwarden-state")).unwrap();
        let ws = Workspace::existing(&d).unwrap();
        assert_eq!(listed(&d, DEFAULT_ENV), 1, "not in Default");
        assert_eq!(ws.all_runs().len(), 2);
        sweep_on_start(&d, None);
        assert!(!d.join("runs").join(&late).exists());
        assert!(r.folder.join("runs").join(&late).exists());
        assert!(r.folder.join("env-later/pathwarden-state").exists());
        assert!(!d.join("environments/lab").exists());
        // Labels and history choices are no longer written for it.
        let lab = Workspace::existing(&d).unwrap().in_env("lab");
        let err = workspace::set_later_label(&lab, "20261009T021000Z", Some("x")).unwrap_err();
        assert!(err.contains("was removed"), "{err}");
        assert!(!d.join("environments/lab").exists());
        let _ = fs::remove_dir_all(&d);
    }

    /// 1: an environment named "Removed" gets another ID, so it never owns
    /// the removals' folder; one that has the ID from before stops removals
    /// with a clear message.
    #[test]
    fn an_environment_named_removed_never_owns_the_removals_folder() {
        let d = two_envs("named-removed");
        let id = Registry::update(&d, |r| r.create("Removed", &[])).unwrap();
        assert_eq!(id, "removed-2");
        add_run(&d, 5, &id, "R.LOCAL");
        let p = plan(&d, &id, None).unwrap();
        assert!(
            p.lines()[1].contains("a new folder in")
                && !p.lines()[1].contains("free the space"),
            "{:?}",
            p.lines()
        );
        let r = remove(&d, &id, None, Some(&p.runs_key)).unwrap();
        assert!(r.folder.parent().unwrap().ends_with("environments/removed"));
        assert_eq!(listed(&d, "lab"), 2);
        let _ = fs::remove_dir_all(&d);
    }

    /// 2 (second review): an environment that got the ID `removed` before
    /// it was reserved gets a free one, with its folder and runs; if that
    /// folder already holds removals, removing stops with what to do.
    #[test]
    fn an_old_environment_with_the_id_removed_gets_another() {
        let add_old = |d: &Path| {
            let mut text = fs::read_to_string(d.join(REGISTRY_FILE)).unwrap();
            text = text.replacen(
                "\"environments\": [",
                "\"environments\": [{\"id\":\"removed\",\"name\":\"Old removed\"},",
                1,
            );
            fs::write(d.join(REGISTRY_FILE), text).unwrap();
        };
        let d = two_envs("old-removed");
        add_old(&d);
        fs::create_dir_all(d.join("environments/removed")).unwrap();
        fs::write(
            d.join("environments/removed/pathwarden.toml"),
            "tier_zero = []\n",
        )
        .unwrap();
        let run = add_run(&d, 7, REMOVED_DIR, "OLD.LOCAL");
        Registry::update(&d, |r| {
            r.current = Some(REMOVED_DIR.into());
            Ok(())
        })
        .unwrap();
        assert_eq!(listed(&d, REMOVED_DIR), 1);
        sweep_on_start(&d, None);
        let reg = Registry::load(&d);
        assert!(reg.get(REMOVED_DIR).is_none());
        assert_eq!(reg.get("removed-2").unwrap().name, "Old removed");
        assert_eq!(reg.current.as_deref(), Some("removed-2"));
        assert!(d.join("environments/removed-2/pathwarden.toml").is_file());
        assert!(!d.join("environments/removed").exists());
        let ws = Workspace::existing(&d).unwrap();
        assert_eq!(
            ws.summary(&run).unwrap().environment.as_deref(),
            Some("removed-2")
        );
        assert_eq!(listed(&d, "removed-2"), 1);
        // Removals work again, into environments/removed.
        let r = remove(&d, "lab", None, None).unwrap();
        assert!(r.folder.parent().unwrap().ends_with("environments/removed"));
        let _ = fs::remove_dir_all(&d);

        // Its folder already holds a removal (an earlier version put them
        // there): stop, and say what to change by hand.
        let d = two_envs("old-removed-full");
        add_old(&d);
        fs::create_dir_all(d.join("environments/removed/lab-20261001-000000")).unwrap();
        fs::write(
            d.join("environments/removed/lab-20261001-000000").join(JOURNAL_FILE),
            r#"{"id":"lab","name":"Lab","entry":{"id":"lab","name":"Lab"},"started_at":1,"done":true}"#,
        )
        .unwrap();
        let err = plan(&d, "lab", None).unwrap_err();
        assert!(
            err.contains("also holds earlier removals")
                && err.contains("summary.json")
                && err.contains("Nothing was removed"),
            "{err}"
        );
        assert!(Registry::load(&d).get(REMOVED_DIR).is_some(), "unchanged");
        // At the start too, and it is said (the Environments page,
        // pathwarden env list), not only when removing.
        let problem = sweep_on_start(&d, None).unwrap();
        assert!(
            problem.to_string().contains("also holds earlier removals"),
            "{problem}"
        );
        // Worked out again, not only kept from the start.
        let note = reserved_note(&d).unwrap();
        assert_eq!(note, problem);
        assert!(
            note.lead()
                .starts_with("Old removed has an ID Pathwarden now uses itself")
                && note.detail().contains("tries again")
                && !note.to_string().contains("Nothing was removed"),
            "{note}"
        );
        // Said as it is now: the removal taken out, nothing stops it.
        fs::remove_dir_all(d.join("environments/removed/lab-20261001-000000")).unwrap();
        let note = reserved_note(&d).unwrap();
        assert!(
            note.why.is_none() && note.lead().contains("next start"),
            "{note}"
        );
        let _ = fs::remove_dir_all(&d);
    }

    fn add_old_removed(d: &Path) {
        let mut text = fs::read_to_string(d.join(REGISTRY_FILE)).unwrap();
        text = text.replacen(
            "\"environments\": [",
            "\"environments\": [{\"id\":\"removed\",\"name\":\"Old removed\"},",
            1,
        );
        fs::write(d.join(REGISTRY_FILE), text).unwrap();
    }

    /// A stray `removed-N` folder (its entry deleted by hand) never
    /// becomes the old environment's: it is skipped, and left as it is.
    #[test]
    fn a_stray_removed_n_folder_is_left_alone() {
        let d = two_envs("stray");
        add_old_removed(&d);
        let stray = d.join("environments/removed-2");
        fs::create_dir_all(&stray).unwrap();
        fs::write(stray.join("pathwarden.toml"), "# stray\n").unwrap();
        assert!(reserved_note(&d).is_some());
        // No folder of its own (nothing to rename): the stray one is not
        // taken for it.
        assert_eq!(sweep_on_start(&d, None), None);
        let reg = Registry::load(&d);
        assert!(reg.get(REMOVED_DIR).is_none() && reg.get("removed-2").is_none());
        assert_eq!(reg.get("removed-3").unwrap().name, "Old removed");
        assert_eq!(
            fs::read_to_string(stray.join("pathwarden.toml")).unwrap(),
            "# stray\n"
        );
        assert!(!stray.join(RENAMED_FILE).exists());
        assert_eq!(reserved_note(&d), None);
        let _ = fs::remove_dir_all(&d);

        // An interrupted rename (the folder moved, the registry not yet
        // changed) finishes into the folder that carries the mark.
        let d = two_envs("resume");
        add_old_removed(&d);
        let moved = d.join("environments/removed-2");
        fs::create_dir_all(&moved).unwrap();
        fs::write(moved.join(RENAMED_FILE), "x").unwrap();
        fs::write(moved.join("pathwarden.toml"), "# mine\n").unwrap();
        assert_eq!(sweep_on_start(&d, None), None);
        assert_eq!(
            Registry::load(&d).get("removed-2").unwrap().name,
            "Old removed"
        );
        let _ = fs::remove_dir_all(&d);

        // A stray removed-2 sends the rename to removed-3, and that try
        // fails after it (a locked summary.json). Once the stray folder is
        // deleted, the next try still finishes into removed-3, the folder
        // with the environment's settings, not the now free removed-2.
        let d = two_envs("stray-resume");
        add_old_removed(&d);
        let stray = d.join("environments/removed-2");
        fs::create_dir_all(&stray).unwrap();
        fs::write(stray.join("pathwarden.toml"), "# stray\n").unwrap();
        let old = d.join("environments/removed");
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("pathwarden.toml"), "# mine\n").unwrap();
        let run = add_run(&d, 9, REMOVED_DIR, "OLD.LOCAL");
        FAIL_SUMMARY.with(|f| f.set(true));
        assert!(sweep_on_start(&d, None).is_some());
        FAIL_SUMMARY.with(|f| f.set(false));
        let moved = d.join("environments/removed-3");
        assert!(moved.join(RENAMED_FILE).is_file());
        fs::remove_dir_all(&stray).unwrap();
        assert_eq!(sweep_on_start(&d, None), None);
        let reg = Registry::load(&d);
        assert!(reg.get("removed-2").is_none());
        assert_eq!(reg.get("removed-3").unwrap().name, "Old removed");
        assert_eq!(
            fs::read_to_string(moved.join("pathwarden.toml")).unwrap(),
            "# mine\n"
        );
        assert_eq!(
            Workspace::existing(&d)
                .unwrap()
                .summary(&run)
                .unwrap()
                .environment
                .as_deref(),
            Some("removed-3")
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// The steps are kept one by one, so a path holding "; " stays in its
    /// step; a nameless environment is named as such; paths use one kind
    /// of separator.
    #[test]
    fn stuck_steps_and_names_read_cleanly() {
        let s = Stuck {
            name: REMOVED_DIR.into(),
            why: Some("x".into()),
            steps: vec!["move it to C:\\a; b\\removed-2".into(), "change it".into()],
        };
        assert_eq!(
            s.step_list(),
            ["Move it to C:\\a; b\\removed-2.", "Change it."]
        );
        assert!(s
            .detail()
            .ends_with("move it to C:\\a; b\\removed-2; and change it."));
        assert!(s
            .lead()
            .starts_with("The environment \"removed\" still has"));
        #[cfg(windows)]
        assert_eq!(
            tidy(Path::new("C:/ws/x\\environments"))
                .display()
                .to_string(),
            "C:\\ws\\x\\environments"
        );
    }

    /// Removals made by 0.1.x (`<id>-<unix time>`, no record) in the
    /// old environment's folder stay in `environments/removed`.
    #[test]
    fn removals_by_0_1_stay_where_removals_are() {
        let d = two_envs("legacy");
        add_old_removed(&d);
        let old = d.join("environments/removed");
        fs::create_dir_all(old.join("pathwarden-state")).unwrap();
        fs::write(old.join("pathwarden.toml"), "tier_zero = []\n").unwrap();
        let legacy = old.join("lab-1759000000");
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("pathwarden.toml"), "# 0.1.x\n").unwrap();
        assert!(legacy_removal(&legacy));
        assert!(!legacy_removal(&old.join("pathwarden-state")));
        assert_eq!(sweep_on_start(&d, None), None);
        let new = d.join("environments/removed-2");
        assert!(new.join("pathwarden.toml").is_file());
        assert!(new.join("pathwarden-state").is_dir());
        assert!(new.join(RENAMED_FILE).is_file());
        assert!(!new.join("lab-1759000000").exists());
        assert!(legacy.join("pathwarden.toml").is_file(), "stays a removal");
        // Removals go on into the same folder.
        let r = remove(&d, "lab", None, None).unwrap();
        assert!(r.folder.parent().unwrap().ends_with("environments/removed"));
        assert!(legacy.is_dir());
        let _ = fs::remove_dir_all(&d);
    }

    /// A try that fails after the folder moved and 0.1.x's
    /// removals went back (a locked summary.json) leaves
    /// `environments/removed` holding those removals again: the next start
    /// finishes the change. Anything of the environment's written there
    /// meanwhile is named, and stops it.
    #[test]
    fn a_change_interrupted_after_the_rename_finishes_at_the_next_start() {
        let d = two_envs("resume-legacy");
        add_old_removed(&d);
        let old = d.join("environments/removed");
        fs::create_dir_all(&old).unwrap();
        fs::write(
            old.join("pathwarden.toml"),
            "tier_zero = []
",
        )
        .unwrap();
        let legacy = old.join("lab-1759000000");
        fs::create_dir_all(&legacy).unwrap();
        let run = add_run(&d, 8, REMOVED_DIR, "OLD.LOCAL");
        FAIL_SUMMARY.with(|f| f.set(true));
        let stuck = sweep_on_start(&d, None).unwrap();
        FAIL_SUMMARY.with(|f| f.set(false));
        assert!(stuck.to_string().contains("locked (test)"), "{stuck}");
        assert!(
            stuck.steps[0].starts_with("its folder is"),
            "{:?}",
            stuck.steps
        );
        assert!(Registry::load(&d).get(REMOVED_DIR).is_some());
        assert!(legacy.is_dir() && !old.join("pathwarden.toml").exists());
        // Said until the next try, which finishes; by another process too
        // (`pathwarden env list`), from the workspace.
        assert_eq!(reserved_note(&d), Some(stuck.clone()));
        LAST_PROBLEMS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(r, _)| *r != d);
        assert_eq!(reserved_note(&d), Some(stuck));
        assert_eq!(sweep_on_start(&d, None), None);
        assert!(!d.join(PROBLEM_FILE).exists(), "forgotten once through");
        let reg = Registry::load(&d);
        assert_eq!(reg.get("removed-2").unwrap().name, "Old removed");
        let ws = Workspace::existing(&d).unwrap();
        assert_eq!(
            ws.summary(&run).unwrap().environment.as_deref(),
            Some("removed-2")
        );
        assert!(legacy.is_dir(), "the 0.1.x removal stays");
        assert_eq!(reserved_note(&d), None);
        let _ = fs::remove_dir_all(&d);

        // Settings written into environments/removed after the rename (the
        // app still on the old ID): named, nothing taken.
        let d = two_envs("resume-conflict");
        add_old_removed(&d);
        let old = d.join("environments/removed");
        fs::create_dir_all(&old).unwrap();
        fs::write(
            old.join("pathwarden.toml"),
            "# mine
",
        )
        .unwrap();
        FAIL_SUMMARY.with(|f| f.set(true));
        assert!(sweep_on_start(&d, None).is_some());
        FAIL_SUMMARY.with(|f| f.set(false));
        fs::create_dir_all(&old).unwrap();
        fs::write(
            old.join("pathwarden.toml"),
            "# later
",
        )
        .unwrap();
        fs::create_dir_all(old.join("lab-1759000000")).unwrap();
        let stuck = sweep_on_start(&d, None).unwrap();
        let text = stuck.to_string();
        assert!(
            text.contains("holds pathwarden.toml again") && !text.contains("lab-1759000000"),
            "{text}"
        );
        assert_eq!(reserved_note(&d), Some(stuck));
        assert_eq!(
            fs::read_to_string(d.join("environments/removed-2/pathwarden.toml")).unwrap(),
            "# mine
"
        );
        // Taken out by hand: the next start finishes.
        fs::remove_file(old.join("pathwarden.toml")).unwrap();
        assert_eq!(sweep_on_start(&d, None), None);
        assert!(Registry::load(&d).get("removed-2").is_some());
        let _ = fs::remove_dir_all(&d);
    }

    /// 3 (second review): a folder given with `--state` inside the
    /// workspace stays, even when it is `pathwarden-state` itself.
    #[test]
    fn a_state_folder_inside_the_workspace_stays() {
        let d = two_envs("state-inside");
        for name in ["flag-hist", "pathwarden-state"] {
            let flag = d.join(name);
            fs::create_dir_all(&flag).unwrap();
            let p = plan(&d, DEFAULT_ENV, Some(&flag)).unwrap();
            assert!(
                !p.items.iter().any(|i| i.from == flag),
                "{name}: {:?}",
                p.items
            );
            assert!(
                p.kept
                    .iter()
                    .any(|k| k.contains("set when Pathwarden was started")),
                "{name}: {:?}",
                p.kept
            );
        }
        let flag = d.join("flag-hist");
        let p = plan(&d, DEFAULT_ENV, Some(&flag)).unwrap();
        remove(&d, DEFAULT_ENV, Some(&flag), Some(&p.runs_key)).unwrap();
        assert!(flag.is_dir());
        let _ = fs::remove_dir_all(&d);
    }

    /// 2: a `[state] path` naming a shared folder (`Runs`) never moves it.
    #[test]
    fn a_history_named_like_a_shared_folder_stays() {
        let d = two_envs("state-runs");
        fs::write(d.join("pathwarden.toml"), "[state]\npath = \"Runs\"\n").unwrap();
        let p = plan(&d, DEFAULT_ENV, None).unwrap();
        assert!(
            !p.items
                .iter()
                .any(|i| i.to == "env/Runs" || i.to == "env/runs"),
            "{:?}",
            p.items
        );
        if cfg!(windows) {
            // Same folder as runs/ there.
            assert!(
                p.kept
                    .iter()
                    .any(|k| k.contains("the workspace's own runs")),
                "{:?}",
                p.kept
            );
        }
        remove(&d, DEFAULT_ENV, None, Some(&p.runs_key)).unwrap();
        assert!(d.join("runs").is_dir());
        assert_eq!(listed(&d, "lab"), 2, "Lab's runs are where they were");
        let _ = fs::remove_dir_all(&d);
    }

    /// 3: a run history another environment uses stays: two environments
    /// sharing an absolute `[state] path`, and settings copied with one.
    #[test]
    fn what_another_environment_uses_stays() {
        let d = two_envs("shared-state");
        let fwd = |p: &Path| p.display().to_string().replace('\\', "/");
        // Default's history is in Lab's folder: Lab's folder stays.
        let in_lab = d.join("environments/lab/hist");
        fs::create_dir_all(&in_lab).unwrap();
        fs::write(
            d.join("pathwarden.toml"),
            format!("[state]\npath = '{}'\n", fwd(&in_lab)),
        )
        .unwrap();
        let p = plan(&d, "lab", None).unwrap();
        assert!(
            !p.files && !p.items.iter().any(|i| i.to == "env"),
            "{:?}",
            p.items
        );
        assert!(
            p.kept
                .iter()
                .any(|k| k.contains("stays: the environment") && k.contains("uses it")),
            "{:?}",
            p.kept
        );
        let r = remove(&d, "lab", None, Some(&p.runs_key)).unwrap();
        assert!(in_lab.is_dir(), "Default's history is untouched");
        assert!(r.folder.join("runs").is_dir());
        // The folder it left is not taken later either: not at the next
        // start, nor when another environment is removed.
        fs::write(in_lab.join("point.json"), "{}").unwrap();
        sweep_on_start(&d, None);
        assert!(in_lab.join("point.json").is_file(), "kept at the start");
        assert!(!r.folder.join("env-later").exists());
        let other = Registry::update(&d, |r| r.create("Other", &[])).unwrap();
        add_run(&d, 6, &other, "O.LOCAL");
        remove(&d, &other, None, None).unwrap();
        assert!(
            in_lab.join("point.json").is_file(),
            "kept by a later removal"
        );
        assert!(!r.folder.join("env-later").exists());
        // Settings copied from Default (same absolute history) to a new
        // environment: removing Default leaves the history it shares.
        let shared = d.join("shared-hist");
        fs::create_dir_all(&shared).unwrap();
        let config = format!("[state]\npath = '{}'\n", fwd(&shared));
        fs::write(d.join("pathwarden.toml"), &config).unwrap();
        let copy = Registry::update(&d, |r| r.create("Copy", &[])).unwrap();
        fs::create_dir_all(d.join("environments").join(&copy)).unwrap();
        fs::write(
            d.join("environments").join(&copy).join("pathwarden.toml"),
            &config,
        )
        .unwrap();
        let p = plan(&d, DEFAULT_ENV, None).unwrap();
        assert!(
            !p.items.iter().any(|i| i.to == "env/shared-hist"),
            "{:?}",
            p.items
        );
        assert!(p.items.iter().any(|i| i.to == "env/pathwarden.toml"));
        assert!(
            p.kept
                .iter()
                .any(|k| k.contains("the environment Copy uses it")),
            "{:?}",
            p.kept
        );
        remove(&d, DEFAULT_ENV, None, Some(&p.runs_key)).unwrap();
        assert!(shared.is_dir());
        let _ = fs::remove_dir_all(&d);
    }

    /// 5: the UI's `--state` is the first environment's only, whichever
    /// environment is removed; given, the first environment's history there
    /// stays.
    #[test]
    fn the_state_flag_is_the_first_environments() {
        let d = two_envs("flag");
        let outside =
            std::env::temp_dir().join(format!("pw-envrm-statedir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        let p = plan(&d, "lab", Some(&outside)).unwrap();
        assert!(
            p.files && !p.kept.iter().any(|k| k.contains("run history")),
            "{:?}",
            p.kept
        );
        fs::create_dir_all(d.join("pathwarden-state")).unwrap();
        let p = plan(&d, DEFAULT_ENV, Some(&outside)).unwrap();
        assert!(
            p.kept
                .iter()
                .any(|k| k.contains("(set when Pathwarden was started)")),
            "{:?}",
            p.kept
        );
        // Without it, the same workspace plans its own history folder.
        let q = plan(&d, DEFAULT_ENV, None).unwrap();
        assert!(!q.kept.iter().any(|k| k.contains("run history")));
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&d);
    }

    /// 6: runs naming an environment the registry doesn't know stop the
    /// first environment's removal (they may be another environment's).
    #[test]
    fn runs_of_unknown_environments_stop_the_first_ones_removal() {
        let d = two_envs("unknown");
        let ghost = add_run(&d, 8, "ghost", "G.LOCAL");
        let err = plan(&d, DEFAULT_ENV, None).unwrap_err();
        assert!(
            err.contains("ghost") && err.contains(&ghost) && err.contains("Nothing was removed"),
            "{err}"
        );
        assert!(d.join("runs").join(&ghost).exists());
        // Lab can still go.
        assert!(plan(&d, "lab", None).is_ok());
        fs::remove_dir_all(d.join("runs").join(&ghost)).unwrap();
        // A run of an environment a removal record names (the
        // registry lost its "removed" entry) is that removal's again: not
        // the first environment's, listed nowhere, and filed away with it.
        let r = remove(&d, "lab", None, None).unwrap();
        let late = add_run(&d, 9, "lab", "LAB.LOCAL");
        Registry::update(&d, |reg| {
            reg.removed.clear();
            Ok(())
        })
        .unwrap();
        assert_eq!(listed(&d, DEFAULT_ENV), 2, "before: counted as Default's");
        let p = plan(&d, DEFAULT_ENV, None).unwrap();
        assert_eq!(p.runs, 1, "only the first environment's own run");
        assert_eq!(Registry::load(&d).removed, ["lab"]);
        assert_eq!(listed(&d, DEFAULT_ENV), 1, "the list agrees with the count");
        remove(&d, DEFAULT_ENV, None, Some(&p.runs_key)).unwrap();
        assert!(!d.join("runs").join(&late).exists());
        assert!(r.folder.join("runs").join(&late).is_dir());
        assert_eq!(listed(&d, DEFAULT_ENV), 0, "the first environment is empty");
        let _ = fs::remove_dir_all(&d);
    }

    /// The start knows removed IDs again from removal records alone,
    /// and files their runs away.
    #[test]
    fn removal_records_bring_back_removed_ids_at_the_start() {
        let d = two_envs("records");
        let r = remove(&d, "lab", None, None).unwrap();
        let late = add_run(&d, 9, "lab", "LAB.LOCAL");
        Registry::update(&d, |reg| {
            reg.removed.clear();
            Ok(())
        })
        .unwrap();
        assert_eq!(sweep_on_start(&d, None), None);
        assert_eq!(Registry::load(&d).removed, ["lab"]);
        assert!(r.folder.join("runs").join(&late).is_dir());
        assert_eq!(listed(&d, DEFAULT_ENV), 1);
        let _ = fs::remove_dir_all(&d);
    }

    /// 7: the confirmation names which runs, not only how many.
    #[test]
    fn the_runs_key_follows_which_runs() {
        let a = runs_key(&["b".into(), "a".into()]);
        assert_eq!(a, runs_key(&["a".into(), "b".into()]));
        assert_ne!(a, runs_key(&["a".into(), "c".into()]));
        let d = two_envs("key");
        let p = plan(&d, "lab", None).unwrap();
        // Same count, other runs.
        fs::remove_dir_all(d.join("runs").join(run_id(2))).unwrap();
        add_run(&d, 4, "lab", "LAB.LOCAL");
        let err = remove(&d, "lab", None, Some(&p.runs_key)).unwrap_err();
        assert!(err.contains("Check the list and confirm again"), "{err}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn kept_collections_go_only_when_no_one_else_uses_them() {
        let d = two_envs("collections");
        let ws = Workspace::existing(&d).unwrap();
        let own = ws.collections_dir().join("job-a");
        let shared = ws.collections_dir().join("job-b");
        for c in [&own, &shared] {
            fs::create_dir_all(c).unwrap();
            fs::write(c.join("x.json"), "{}").unwrap();
        }
        let set = |run: &str, at: &Path| {
            let mut s = ws.summary(run).unwrap();
            s.collection = Some(workspace::CollectionInfo {
                read_started: None,
                method: "builtin".into(),
                scope: "dc-only".into(),
                domain: "LAB.LOCAL".into(),
                server: None,
                ldaps: false,
                current_user: true,
                warnings: Vec::new(),
                kept: Some(at.display().to_string()),
                kerberos_only: None,
                smb_signing: None,
                domains: Vec::new(),
            });
            ws.update_summary(&s).unwrap();
        };
        set(&run_id(1), &own);
        set(&run_id(2), &shared);
        set(&run_id(3), &shared);
        let p = plan(&d, "lab", None).unwrap();
        assert_eq!(p.collections, 1);
        assert!(p
            .kept
            .iter()
            .any(|k| k.contains("also used by another environment")));
        let r = remove(&d, "lab", None, None).unwrap();
        assert!(!own.exists() && shared.exists());
        assert!(r.folder.join("collections/job-a/x.json").is_file());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn the_demo_environment_can_be_reset() {
        let d = tmp("demo");
        let demo = Registry::update(&d, |r| Ok(r.ensure_demo())).unwrap();
        add_run(&d, 1, &demo, "SCALE.LOCAL");
        let p = plan(&d, &demo, None).unwrap();
        assert!(p.demo && !p.lines().iter().any(|l| l.contains("nightly")));
        remove(&d, &demo, None, None).unwrap();
        let mut reg = Registry::load(&d);
        assert!(reg.demo_id().is_none());
        assert_ne!(reg.ensure_demo(), demo, "made again, with a new ID");
        let _ = fs::remove_dir_all(&d);
    }

    // ---------------------------------------------------- path safety

    #[test]
    fn only_paths_inside_the_workspace_move() {
        let d = tmp("paths");
        let outside = std::env::temp_dir().join(format!("pw-envrm-out-{}", std::process::id()));
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.txt"), "mine").unwrap();
        fs::create_dir_all(d.join("runs/x")).unwrap();
        assert!(movable(&d, &d.join("runs/x")).is_ok());
        // The workspace itself, a path outside it, one that climbs out, a
        // missing one.
        assert!(movable(&d, &d).is_err());
        assert!(movable(&d, &outside).is_err());
        assert!(movable(&d, &d.join("runs/../..")).is_err());
        assert!(movable(
            &d,
            &d.join("runs/../../").join(outside.file_name().unwrap())
        )
        .is_err());
        assert!(movable(&d, &d.join("missing")).is_err());
        // Directly in a folder only.
        assert!(movable_in(&d, &d, &d.join("runs")).is_ok());
        assert!(movable_in(&d, &d, &d.join("runs/x")).is_err());
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&d);
    }

    /// A junction (Windows) or symbolic link pointing outside is never
    /// moved, and what it points to is never touched, even when it stands
    /// where an environment's folder or a run would be.
    #[test]
    fn links_pointing_outside_are_refused() {
        let d = two_envs("links");
        let outside = std::env::temp_dir().join(format!("pw-envrm-target-{}", std::process::id()));
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.txt"), "mine").unwrap();
        // Lab's folder is a link to the outside folder.
        fs::remove_dir_all(d.join("environments/lab")).unwrap();
        if !link_dir(&outside, &d.join("environments/lab")) {
            // Junctions need no privilege: on Windows this always runs.
            if cfg!(windows) {
                panic!("couldn't make a junction");
            }
            eprintln!("cannot make links here; skipped");
            let _ = fs::remove_dir_all(&outside);
            let _ = fs::remove_dir_all(&d);
            return;
        }
        assert!(movable(&d, &d.join("environments/lab")).is_err());
        let p = plan(&d, "lab", None).unwrap();
        assert!(!p.files);
        assert!(
            p.kept.iter().any(|k| k.contains("is a link")),
            "{:?}",
            p.kept
        );
        remove(&d, "lab", None, None).unwrap();
        assert!(
            outside.join("keep.txt").is_file(),
            "the target is untouched"
        );
        // A run folder that is a link stops the removal before anything moves.
        let link_run = run_id(7);
        let real = outside.join("run");
        fs::create_dir_all(&real).unwrap();
        fs::copy(
            d.join("runs").join(run_id(3)).join("summary.json"),
            real.join("summary.json"),
        )
        .unwrap();
        assert!(link_dir(&real, &d.join("runs").join(&link_run)));
        let err = plan(&d, DEFAULT_ENV, None).unwrap_err();
        assert!(
            err.contains("is a link") && err.contains("Nothing was removed"),
            "{err}"
        );
        assert!(d.join("runs").join(run_id(3)).exists());
        assert!(real.join("summary.json").is_file());
        // The removed folder itself pointing outside is refused too.
        let _ = remove_link(&d.join("runs").join(&link_run));
        let removed = d.join("environments/removed");
        let moved = d.join("removed-before");
        fs::rename(&removed, &moved).unwrap();
        assert!(link_dir(&outside, &removed));
        let err = remove(&d, DEFAULT_ENV, None, None).unwrap_err();
        assert!(err.contains("Nothing was removed"), "{err}");
        assert!(d.join("runs").join(run_id(3)).exists());
        let _ = remove_link(&removed);
        let _ = remove_link(&d.join("environments/lab"));
        assert!(outside.join("keep.txt").is_file());
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&d);
    }

    /// 4: a link inside a folder that moves moves as a link; the plan and
    /// RESTORE.txt name it, and what it points to is untouched.
    #[test]
    fn links_inside_moved_folders_are_named() {
        let d = two_envs("inner-link");
        let outside = std::env::temp_dir().join(format!("pw-envrm-inner-{}", std::process::id()));
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.txt"), "mine").unwrap();
        let link = d.join("environments").join("lab").join("linked");
        if !link_dir(&outside, &link) {
            if cfg!(windows) {
                panic!("couldn't make a junction");
            }
            let _ = fs::remove_dir_all(&outside);
            let _ = fs::remove_dir_all(&d);
            return;
        }
        let p = plan(&d, "lab", None).unwrap();
        assert_eq!(p.links, std::slice::from_ref(&link));
        assert!(p
            .lines()
            .iter()
            .any(|l| l.contains("linked") && l.contains("moves as a link")));
        let r = remove(&d, "lab", None, Some(&p.runs_key)).unwrap();
        let restore = fs::read_to_string(r.folder.join(RESTORE_FILE)).unwrap();
        assert!(
            restore.contains("linked") && restore.contains("remove each link itself first"),
            "{restore}"
        );
        let moved = r.folder.join("env").join("linked");
        assert!(fs::symlink_metadata(&moved).is_ok_and(|m| is_link(&m)));
        assert!(outside.join("keep.txt").is_file());
        remove_link(&moved).unwrap();
        assert!(outside.join("keep.txt").is_file());
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&d);
    }

    /// Makes `link` point to folder `target`: a junction on Windows (no
    /// privilege needed), a symbolic link elsewhere. False if it can't.
    fn link_dir(target: &Path, link: &Path) -> bool {
        #[cfg(windows)]
        {
            // mklink wants backslashes.
            let win = |p: &Path| p.display().to_string().replace('/', "\\");
            pathwarden_core::spawn::quiet("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(win(link))
                .arg(win(target))
                .output()
                .is_ok_and(|o| o.status.success())
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
    }

    /// Removes a link only (never what it points to).
    fn remove_link(link: &Path) -> std::io::Result<()> {
        // A junction or directory symlink is removed with remove_dir on
        // Windows, which does not touch the target; remove_file elsewhere.
        if cfg!(windows) {
            fs::remove_dir(link)
        } else {
            fs::remove_file(link)
        }
    }

    #[test]
    fn sizes_read_as_words() {
        assert_eq!(size_words(820), "820 bytes");
        assert_eq!(size_words(14 * 1024), "14 KB");
        assert_eq!(size_words(3 * 1024 * 1024 + 300_000), "3.3 MB");
        assert_eq!(size_words(3 << 30), "3.0 GB");
    }
}
