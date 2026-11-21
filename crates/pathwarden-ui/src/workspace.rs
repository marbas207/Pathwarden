//! The workspace: a per-user folder holding finished runs (`runs/<id>/` with
//! `report.html` and `summary.json`), a scratch area for uploads, and an
//! optional `pathwarden.toml` used as the analysis config.
//!
//! **Run IDs.** A run has one ID users see: the run history's
//! (`20261009T021000.042Z`, as `pathwarden run` and `pathwarden history`
//! print it), from [`RunSummary::run_id`]. The run's folder keeps its own
//! name (`20261009-021000-ef92d5`, [`new_run_id`]), which only shows in the
//! address bar: existing workspaces and links keep working, and
//! `/runs/<history ID>` opens the same page ([`Workspace::find_run`]).
//!
//! **Environments.** A `Workspace` value is scoped to one environment
//! ([`crate::environments`]): [`Workspace::config_path`], [`Workspace::runs`]
//! and [`Workspace::env_dir`] are that environment's. Runs of every
//! environment share `runs/`, so [`Workspace::run_dir`] and
//! [`Workspace::summary`] open any run by its ID.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use pathwarden_core::analyze::Analysis;
use pathwarden_core::config::Config;
use pathwarden_core::posture::{ExposureGrade, GradeInputs, Headline, PlanSummary};
use serde::{Deserialize, Serialize};

use crate::environments::{self, Registry, DEFAULT_ENV};

pub const REPORT_FILE: &str = "report.html";
/// A run folder's summary, format 1 (docs/dev/formats.md): a run analysed on
/// this computer, which every version reads.
pub const SUMMARY_FILE: &str = "summary.json";
/// A run folder's summary, format 2: a run loaded from a history's full
/// runs ([`crate::shared_runs::mirror`]). The summary's name is the
/// folder's format, so Pathwarden 0.1.7 and earlier, which look for
/// [`SUMMARY_FILE`] only, never list such a run or serve its report as
/// one of their own.
pub const LOADED_SUMMARY_FILE: &str = "summary.v2.json";
/// The newest run folder format this version reads. A folder holding a
/// `summary.vN.json` of a larger N is a newer Pathwarden's: skipped, and
/// counted ([`Workspace::newer_run_folders`]).
pub const RUN_FORMAT: u32 = 2;
pub const CONFIG_FILE: &str = "pathwarden.toml";

/// What the run lists say of [`Workspace::newer_run_folders`].
pub fn newer_runs_words(n: usize) -> Option<String> {
    match n {
        0 => None,
        1 => Some(
            "1 run on this computer was saved by a newer Pathwarden. Update Pathwarden to open \
             it."
            .into(),
        ),
        n => Some(format!(
            "{} runs on this computer were saved by a newer Pathwarden. Update Pathwarden to \
             open them.",
            pathwarden_core::text::num(n)
        )),
    }
}

/// Why a run can't be saved into a folder a newer Pathwarden saved.
pub const NEWER_FOLDER_WORDS: &str =
    "A newer Pathwarden saved this run on this computer. Update Pathwarden to open it.";

/// The summary file of the run folder `dir`: [`SUMMARY_FILE`] or
/// [`LOADED_SUMMARY_FILE`], whichever it holds.
pub fn summary_file(dir: &Path) -> Option<PathBuf> {
    [SUMMARY_FILE, LOADED_SUMMARY_FILE]
        .into_iter()
        .map(|n| dir.join(n))
        .find(|p| p.is_file())
}

/// The summary file name a run is saved under: format 2 for a run loaded
/// from a history, format 1 for every other.
fn summary_name(summary: &RunSummary) -> &'static str {
    if summary.shared.is_some() {
        LOADED_SUMMARY_FILE
    } else {
        SUMMARY_FILE
    }
}

/// The summary file name a run is saved under in folder `dir`: format 2
/// when the folder or the summary says it was loaded from a history.
fn summary_name_in(dir: &Path, summary: &RunSummary) -> &'static str {
    if loaded_folder(dir) {
        LOADED_SUMMARY_FILE
    } else {
        summary_name(summary)
    }
}

/// Whether run folder `dir` holds a run loaded from a history: its marker,
/// or a format 2 summary.
fn loaded_folder(dir: &Path) -> bool {
    dir.join(crate::shared_runs::LOADED_MARKER).is_file() || dir.join(LOADED_SUMMARY_FILE).is_file()
}

/// Whether a newer Pathwarden saved run folder `dir`: it holds a
/// `summary.vN.json` of a format this version doesn't know (any N above
/// [`RUN_FORMAT`], however large). Such a folder is never listed, opened,
/// written into or removed by this version.
pub fn is_newer_folder(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().any(|e| {
            pathwarden_core::formats::of_name(
                &e.file_name().to_string_lossy(),
                "summary",
                ".json",
                RUN_FORMAT,
            ) == Some(pathwarden_core::formats::Format::Unknown)
        })
    })
}

/// A run loaded from a history by 0.1.9 (its summary at [`SUMMARY_FILE`],
/// beside [`crate::shared_runs::LOADED_MARKER`], or saying `shared`) gets
/// the loaded runs' summary name, so a Pathwarden older than 0.1.9 started
/// on this computer never takes it for one of its own runs. Best effort: a
/// folder that can't be changed stays as it is (and is still treated as
/// loaded).
fn migrate_loaded(dir: &Path) {
    let old = dir.join(SUMMARY_FILE);
    if !old.is_file() {
        return;
    }
    let shared = || {
        fs::read(&old).is_ok_and(|b| {
            // Cheap first: most summaries don't name it at all.
            b.windows(8).any(|w| w == b"\"shared\"")
                && serde_json::from_slice::<serde_json::Value>(
                    b.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&b),
                )
                .is_ok_and(|v| !v["shared"].is_null())
        })
    };
    if dir.join(crate::shared_runs::LOADED_MARKER).is_file() || shared() {
        let _ = fs::rename(&old, dir.join(LOADED_SUMMARY_FILE));
    }
}

#[derive(Debug, Clone)]
pub struct Workspace {
    root: PathBuf,
    /// The environment this value is scoped to ([`crate::environments`]).
    env: String,
}

/// `%LOCALAPPDATA%\Pathwarden` on Windows, `~/Library/Application
/// Support/Pathwarden` on macOS, `$XDG_DATA_HOME/pathwarden` or
/// `~/.local/share/pathwarden` elsewhere.
pub fn default_dir() -> Result<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let dir = if cfg!(windows) {
        env("LOCALAPPDATA")
            .or_else(|| env("USERPROFILE").map(|h| h.join("AppData").join("Local")))
            .map(|d| d.join("Pathwarden"))
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|h| h.join("Library/Application Support/Pathwarden"))
    } else {
        env("XDG_DATA_HOME")
            .or_else(|| env("HOME").map(|h| h.join(".local/share")))
            .map(|d| d.join("pathwarden"))
    };
    dir.context("cannot find a folder for the workspace; pass --workspace DIR")
}

/// A local path as pages show it: under the user's profile, the profile
/// as `%USERPROFILE%` (`~` off Windows), so a screenshot doesn't carry
/// the user name. Pages only; forms and the CLI keep the full path.
pub fn shown_path(path: &Path) -> String {
    hide_profile(&path.display().to_string())
}

/// [`shown_path`] for every path in `text` (what a run analyzed: "C:\...
/// and 2 more").
pub fn hide_profile(text: &str) -> String {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    hide_home(text, home.as_deref())
}

/// [`hide_profile`] with the profile folder given.
fn hide_home(text: &str, home: Option<&Path>) -> String {
    let Some(home) = home else {
        return text.to_string();
    };
    let home = home.display().to_string();
    let home = home.trim_end_matches(['\\', '/']);
    // A profile at a drive's or the file system's root shortens nothing.
    if home.len() < 3 {
        return text.to_string();
    }
    // ASCII case only, so the offsets stay the same.
    let fold = |s: &str| {
        if cfg!(windows) {
            s.to_ascii_lowercase()
        } else {
            s.to_string()
        }
    };
    let (hay, needle) = (fold(text), fold(home));
    let name = if cfg!(windows) { "%USERPROFILE%" } else { "~" };
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    while let Some(i) = hay[from..].find(&needle).map(|i| from + i) {
        let end = i + needle.len();
        // A whole folder: not part of a longer name or path.
        let before = text[..i].chars().next_back();
        let after = text[end..].chars().next();
        let starts = before.is_none_or(|c| !(c.is_alphanumeric() || "\\/_-.".contains(c)));
        let ends = after.is_none_or(|c| c == '\\' || c == '/');
        out.push_str(&text[from..i]);
        if starts && ends {
            out.push_str(name);
        } else {
            out.push_str(&text[i..end]);
        }
        from = end;
    }
    out.push_str(&text[from..]);
    out
}

impl Workspace {
    /// Opens (creating if needed) the workspace at `root`, and clears upload
    /// leftovers from an earlier session that did not finish.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let ws = Self {
            root: root.into(),
            env: DEFAULT_ENV.into(),
        };
        for dir in [ws.root.clone(), ws.runs_dir(), ws.uploads_dir()] {
            fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&ws.root, fs::Permissions::from_mode(0o700));
        }
        if let Ok(entries) = fs::read_dir(ws.uploads_dir()) {
            for e in entries.flatten() {
                let _ = remove_any(&e.path());
            }
        }
        if let Ok(entries) = fs::read_dir(ws.runs_dir()) {
            for e in entries.flatten() {
                if e.file_name().to_string_lossy().starts_with('.') {
                    let _ = remove_any(&e.path());
                }
            }
        }
        Ok(ws)
    }

    /// An existing workspace at `root`, without creating or cleaning
    /// anything (for the command line's `--env`).
    pub fn existing(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        anyhow::ensure!(
            root.is_dir(),
            "no Pathwarden workspace at {} (start `pathwarden ui` once, or pass --workspace DIR)",
            root.display()
        );
        Ok(Self {
            root,
            env: DEFAULT_ENV.into(),
        })
    }

    /// The workspace folder (shared by every environment).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The same workspace, scoped to environment `id` (Default when `id`
    /// isn't valid).
    pub fn in_env(&self, id: &str) -> Self {
        Self {
            root: self.root.clone(),
            env: if environments::valid_id(id) {
                id.to_string()
            } else {
                DEFAULT_ENV.into()
            },
        }
    }

    /// The environment this value is scoped to.
    pub fn env_id(&self) -> &str {
        &self.env
    }

    pub fn is_default_env(&self) -> bool {
        self.env == DEFAULT_ENV
    }

    /// The environment's folder: where its `pathwarden.toml`, default run
    /// history and other files live (the workspace itself for Default).
    pub fn env_dir(&self) -> PathBuf {
        environments::env_dir(&self.root, &self.env)
    }

    /// Every environment of the workspace.
    pub fn registry(&self) -> Registry {
        Registry::load(&self.root)
    }

    /// The environment's name, as pages show it.
    pub fn env_name(&self) -> String {
        self.named_registry().name_of(&self.env)
    }

    /// Every environment, with the names they show as
    /// ([`Registry::with_names`]): for what pages and messages show.
    pub fn named_registry(&self) -> Registry {
        self.registry().with_names(&self.all_runs())
    }

    /// The environment a run belongs to ([`environments::run_env`]): the
    /// demo's for a demo run, else the one its summary names, or Default
    /// (for runs from before environments, and for an environment that no
    /// longer exists).
    pub fn env_of(reg: &Registry, run: &RunSummary) -> String {
        environments::run_env(reg, run)
    }

    /// This workspace scoped to `run`'s environment: for what a page about
    /// one run does (its retests, accepting one of its risks).
    pub fn for_run(&self, run: &RunSummary) -> Self {
        self.in_env(&Self::env_of(&self.registry(), run))
    }

    pub fn runs_dir(&self) -> PathBuf {
        self.root.join("runs")
    }

    pub fn uploads_dir(&self) -> PathBuf {
        self.root.join("uploads")
    }

    /// Raw collections the user chose to keep (Collect wizard). Unlike
    /// `uploads/`, this folder is not emptied when the UI starts.
    pub fn collections_dir(&self) -> PathBuf {
        self.root.join("collections")
    }

    /// The environment's `pathwarden.toml`.
    pub fn config_path(&self) -> PathBuf {
        self.env_dir().join(CONFIG_FILE)
    }

    /// The environment's `pathwarden.toml`, or the defaults when there is none.
    pub fn config(&self) -> Result<Config> {
        let path = self.config_path();
        if !path.exists() {
            return Ok(Config::default());
        }
        Config::from_file(&path).map_err(|e| anyhow::anyhow!("{CONFIG_FILE} in the workspace: {e}"))
    }

    /// The folder of a finished run; `None` for an invalid ID or a missing
    /// run, and for a run folder of a newer format ([`newer_run_folders`]).
    ///
    /// Not a pure lookup: it moves a loaded run's format 1 summary to its
    /// format 2 name ([`migrate_loaded`]), never in a newer version's
    /// folder, which it leaves untouched. Two processes doing so at once
    /// race on one rename; the loser's fails and is ignored, and either way
    /// the folder ends with one summary, read the same.
    pub fn run_dir(&self, id: &str) -> Option<PathBuf> {
        if !valid_run_id(id) {
            return None;
        }
        let dir = self.runs_dir().join(id);
        if is_newer_folder(&dir) {
            return None;
        }
        migrate_loaded(&dir);
        summary_file(&dir).is_some().then_some(dir)
    }

    /// A run's summary as saved. What gets written back starts from this.
    pub fn summary(&self, id: &str) -> Option<RunSummary> {
        let text = fs::read_to_string(summary_file(&self.run_dir(id)?)?).ok()?;
        // A byte order mark (an editor saved the file) would otherwise drop
        // the run from every list without a word.
        pathwarden_core::status_keys::from_slice(text.trim_start_matches('\u{feff}').as_bytes())
            .ok()
    }

    /// How many run folders here a newer Pathwarden saved (a run folder
    /// format above [`RUN_FORMAT`]): never listed, opened or changed.
    pub fn newer_run_folders(&self) -> usize {
        fs::read_dir(self.runs_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| valid_run_id(&e.file_name().to_string_lossy()))
            .filter(|e| is_newer_folder(&e.path()))
            .count()
    }

    /// A run's summary as the run lists show it ([`Workspace::all_runs`]):
    /// a run saved by 0.1.1 with the domains of later runs. For pages that
    /// compare the run with the lists; never written back.
    pub fn run(&self, id: &str) -> Option<RunSummary> {
        let mut saved = self.summary(id)?;
        if saved.trusted_domains.is_some() {
            let reg = self.named_registry();
            saved.env_name = Some(reg.name_of(&Self::env_of(&reg, &saved)));
            return Some(saved);
        }
        self.all_runs()
            .into_iter()
            .find(|r| r.id == saved.id)
            .or(Some(saved))
    }

    /// The environment's finished runs, newest first.
    pub fn runs(&self) -> Vec<RunSummary> {
        let reg = self.registry();
        self.all_runs()
            .into_iter()
            .filter(|r| Self::env_of(&reg, r) == self.env)
            .collect()
    }

    /// Every finished run of every environment, newest first. Runs saved
    /// before trusted domains were left out get the domains a later run of
    /// the same collection has ([`migrate_domains`]).
    pub fn all_runs(&self) -> Vec<RunSummary> {
        let mut runs: Vec<RunSummary> = fs::read_dir(self.runs_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| self.summary(&e.file_name().to_string_lossy()))
            .collect();
        runs.sort_by(|a, b| b.order_key().cmp(&a.order_key()));
        migrate_domains(&mut runs);
        // An unrenamed Default shows as its runs' domains.
        let reg = self.registry().with_names(&runs);
        for r in &mut runs {
            r.env_name = Some(reg.name_of(&Self::env_of(&reg, r)));
        }
        runs
    }

    /// Writes a finished run: into a hidden folder first, then renamed, so a
    /// half-written run never shows up.
    pub fn save_run(&self, summary: &RunSummary, report_html: &str) -> Result<()> {
        self.save_run_with(summary, report_html, &[])
    }

    /// [`Workspace::save_run`] plus extra files for the run's folder (the
    /// object index and event document from [`crate::run_data`]).
    pub fn save_run_with(
        &self,
        summary: &RunSummary,
        report_html: &str,
        extra: &[(&str, Vec<u8>)],
    ) -> Result<()> {
        anyhow::ensure!(valid_run_id(&summary.id), "invalid run ID");
        let target = self.runs_dir().join(&summary.id);
        // A newer Pathwarden's folder is never written into (docs/dev/formats.md).
        anyhow::ensure!(!is_newer_folder(&target), "{}", NEWER_FOLDER_WORDS);
        let tmp = self.runs_dir().join(format!(".{}", summary.id));
        let _ = remove_any(&tmp);
        fs::create_dir_all(&tmp)?;
        for (name, bytes) in extra {
            fs::write(tmp.join(name), bytes)?;
        }
        fs::write(tmp.join(REPORT_FILE), report_html)?;
        fs::write(tmp.join(summary_name(summary)), summary_json(summary)?)?;
        if let Err(e) = fs::rename(&tmp, &target) {
            // No half-made folder left behind.
            let _ = remove_any(&tmp);
            return Err(e).context("saving the run");
        }
        Ok(())
    }

    /// Rewrites a saved run's summary (atomically), for example after it
    /// was imported into the run history.
    pub fn update_summary(&self, summary: &RunSummary) -> Result<()> {
        let dir = self.run_dir(&summary.id).context("no such run")?;
        // The folder decides as much as the summary: a loaded run stays
        // format 2 whatever its summary now says.
        let name = summary_name_in(&dir, summary);
        let path = dir.join(name);
        let tmp = dir.join(format!(".{name}.tmp"));
        fs::write(&tmp, summary_json(summary)?)?;
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(e).context("saving the run");
        }
        // One summary per folder: the other format's goes.
        for other in [SUMMARY_FILE, LOADED_SUMMARY_FILE] {
            if other != name {
                let _ = fs::remove_file(dir.join(other));
            }
        }
        Ok(())
    }

    /// The folder ID of the run with history run ID `run_id`
    /// ([`RunSummary::run_id`]), so a run can be opened by the ID the
    /// command line prints.
    pub fn find_run(&self, run_id: &str) -> Option<String> {
        if !looks_like_history_id(run_id) {
            return None;
        }
        self.all_runs()
            .into_iter()
            .find(|r| r.run_id() == run_id)
            .map(|r| r.id)
    }

    pub fn delete_run(&self, id: &str) -> Result<bool> {
        let Some(dir) = self.run_dir(id) else {
            return Ok(false);
        };
        fs::remove_dir_all(&dir).with_context(|| format!("deleting {}", dir.display()))?;
        Ok(true)
    }
}

fn remove_any(p: &Path) -> std::io::Result<()> {
    if p.is_dir() {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    }
}

/// The current time in Unix milliseconds when it falls in second `at`
/// (a run being saved now), else `None` (a run given an earlier time).
fn millis_within(at: i64) -> Option<i64> {
    let ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()?;
    (ms.div_euclid(1000) == at).then_some(ms)
}

/// A new run ID: `YYYYMMDD-HHMMSS-xxxxxx` (UTC time and 6 random hex digits),
/// so IDs sort by time and never collide.
pub fn new_run_id(now: i64) -> String {
    let mut r = [0u8; 3];
    let _ = getrandom::getrandom(&mut r);
    // format_unix gives "YYYY-MM-DD HH:MM"; seconds come from `now`.
    let t = pathwarden_core::time::format_unix(now);
    let digits: String = t.chars().filter(char::is_ascii_digit).collect();
    format!(
        "{}-{}{:02}-{:02x}{:02x}{:02x}",
        &digits[..8],
        &digits[8..12],
        now.rem_euclid(60),
        r[0],
        r[1],
        r[2]
    )
}

/// Run IDs are exactly `DDDDDDDD-DDDDDD-hhhhhh`, so they can never name a
/// path outside the runs folder.
pub fn valid_run_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 22
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 15 => c == b'-',
            0..=14 => c.is_ascii_digit(),
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// A history run ID's shape: `20261009T021000Z` or `20261009T021000.042Z`.
pub fn looks_like_history_id(id: &str) -> bool {
    let b = id.as_bytes();
    let base = b.len() >= 16
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'T'
        && b[9..15].iter().all(u8::is_ascii_digit);
    base && match &b[15..] {
        [b'Z'] => true,
        [b'.', m @ .., b'Z'] => m.len() == 3 && m.iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

/// Pathwarden 0.1.1 and earlier counted trusted domains as collected
/// ([`pathwarden_core::state::LegacyDomains`]): gives runs saved then the
/// domains a run saved since lists for the same collection, so they keep
/// their environment's name and are compared with the runs after them.
/// `runs` newest first.
pub fn migrate_domains(runs: &mut [RunSummary]) {
    let mut legacy = pathwarden_core::state::LegacyDomains::default();
    for r in runs.iter().rev() {
        if let Some(t) = &r.trusted_domains {
            legacy.learn(&r.domains, t);
        }
    }
    for r in runs.iter_mut().filter(|r| r.trusted_domains.is_none()) {
        match legacy.map(&r.domains) {
            Some(now) => r.domains = now.to_vec(),
            None => r.legacy_domains = r.domains.len() > 1,
        }
    }
}

/// A run's `summary.json`: the status keys' 1.0 names beside the old ones
/// ([`pathwarden_core::status_keys`]).
fn summary_json(summary: &RunSummary) -> Result<String> {
    Ok(serde_json::to_string_pretty(
        &pathwarden_core::status_keys::to_value(summary)?,
    )?)
}

/// What the run list and the run page show without opening the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub id: String,
    /// Unix time the analysis finished.
    pub created_at: i64,
    /// The same in milliseconds, so runs saved within one second keep
    /// their order ([`RunSummary::order_key`]). Absent in summaries written
    /// before 1.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ms: Option<i64>,
    /// Collection time from the collector's file names, when present.
    pub collected_at: Option<i64>,
    /// What was analyzed, in words: "Demo data", "2 uploaded files", a path.
    pub source: String,
    pub demo: bool,
    /// The domains whose data was collected
    /// ([`pathwarden_core::analyze::domain_names`]).
    pub domains: Vec<String>,
    /// Domains the data had an object for but did not collect (trusted
    /// domains). `None` in runs saved before `domains` left them out; such
    /// runs are listed with the domains a run of the same collection gets
    /// now ([`Workspace::all_runs`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_domains: Option<Vec<String>>,
    /// The domains its trust records name that it didn't collect,
    /// as the forest map counts them
    /// ([`pathwarden_core::analyze::Analysis::uncollected_domains`]). `None`
    /// in runs saved before 0.2.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_collected: Option<Vec<String>>,
    /// Set in memory by [`migrate_domains`] (never saved): a run saved by
    /// 0.1.1 or earlier listing several domains that no later run mapped,
    /// so some of them may be trusted ones. Its domains never place a run
    /// without asking ([`crate::environments::decide`]).
    #[serde(skip)]
    pub legacy_domains: bool,
    pub objects: usize,
    pub files: usize,
    pub exposure_percent: f64,
    pub exposed: usize,
    pub population: usize,
    /// Of `population`, the Tier-Zero relevant denominator of
    /// `exposure_percent` on the run's [`RunSummary::basis`] (for basis 3,
    /// the active users and computers; see
    /// [`pathwarden_core::posture::ZonePosture::relevant_population`]).
    /// `#[serde(default)]` for summaries written before risk scoring, which didn't
    /// record it; [`RunSummary::relevant_pop`] falls back to `population`
    /// for those.
    #[serde(default)]
    pub relevant_population: usize,
    /// The exposure basis as written
    /// ([`pathwarden_core::analysis::EXPOSURE_BASIS`]); read it with
    /// [`RunSummary::basis`]. 0 in summaries written before it was recorded.
    #[serde(default)]
    pub exposure_basis: u8,
    pub protection_score: Option<f64>,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub suppressed: usize,
    pub plan_steps: usize,
    /// Accounts that still reach Tier Zero after every change of the plan
    /// (0 when it closes every path). Absent in older summaries; read it
    /// with [`RunSummary::plan_summary`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposed_after: Option<usize>,
    /// Tier Zero's grade ([`ExposureGrade`]) and why. Absent in summaries
    /// written before the grade came from paths and findings; read them with
    /// [`RunSummary::grade`] and [`RunSummary::grade_reason`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<ExposureGrade>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade_reason: Option<String>,
    /// The same as what an attacker can do, the report's reason line
    /// ([`pathwarden_core::posture::StatusReason`]). Absent in older
    /// summaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_reason: Option<String>,
    /// Points the remediation plan drops Tier Zero exposure by (before minus
    /// after, measured on this run's population). 0 in older summaries and
    /// when the plan cuts nothing.
    #[serde(default)]
    pub exposure_delta: f64,
    /// Points the plan's first step alone drops Tier Zero exposure by, as
    /// a fresh run would count it. `None` in older summaries and without a
    /// plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_step_delta: Option<f64>,
    /// Objects skipped at ingest as too large; findings that depend on
    /// them can't be told.
    #[serde(default)]
    pub skipped_objects: usize,
    pub pathwarden: String,
    /// How the data was collected, for runs started from the Collect wizard.
    /// Absent in older summaries and for uploads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<CollectionInfo>,
    /// Whether the run was recorded in the run history (the state that
    /// `pathwarden run` keeps), and anything to know about that. Absent for
    /// runs from before the UI recorded runs ("local only").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<HistoryLink>,
    /// The remediation path's first step in words ("Sign DA-ADMIN21 out of
    /// WS-114 and stop using it there"), for Home. Absent in older summaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_step: Option<String>,
    /// The environment the run belongs to ([`crate::environments`]); absent
    /// for the Default environment, so runs from before environments are
    /// Default's as they are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// The name its environment has now, set as the workspace reads its
    /// runs ([`Workspace::all_runs`]); never saved. What lists show for the
    /// run's environment ([`RunSummary::environment`]).
    #[serde(skip)]
    pub env_name: Option<String>,
    /// How the run got its environment: `chosen`, `domains`, `runs`, `joined` or
    /// `current` ([`crate::environments::Assigned`]). Absent in older runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned: Option<String>,
    /// What the run was ("after GPO fix"), up to [`MAX_LABEL`] characters
    /// ([`clean_label`]); shown instead of the computed name. Absent when
    /// it has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// A run loaded from the history's full runs ([`crate::shared_runs::mirror`]):
    /// who recorded it where, and from which repository. Pathwarden made its
    /// folder and removes it when the history no longer holds it. Absent for
    /// runs analysed here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<crate::shared_runs::SharedFrom>,
    /// Collection completeness over the run's domains, with what each did
    /// not target (a Quick run): what like-with-like comparisons go by.
    /// Absent in summaries written before it was recorded
    /// ([`crate::run_data::completeness`] reads it from the run then).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completeness: Option<pathwarden_core::state::CompletenessPoint>,
    /// The run keeps its account lists ([`crate::run_data::EXPOSED_FILE`]):
    /// which accounts each step cuts off, and which reach Tier Zero now or
    /// no longer. False in runs saved before they were kept.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tier_zero_lists: bool,
    /// Its report's What changed opens to which accounts now reach Tier
    /// Zero and which no longer do ([`pathwarden_core::report::opens_change`]):
    /// the Runs list links its change in accounts there. False when the
    /// accounts weren't compared, and in runs saved before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tier_zero_change: bool,
    /// The Tier Zero settings files the run used, by file name only,
    /// never the folder they came from. Empty in runs saved before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub settings_files: Vec<pathwarden_core::dcsettings::SettingsFileUse>,
    /// Tier Zero settings folders that couldn't be opened when it was
    /// analyzed (how many: never which).
    #[serde(default, skip_serializing_if = "usize_is_zero")]
    pub settings_folders_unread: usize,
    /// OpenGraph and AzureHound sources not read whole: a limit
    /// hit, records too large, read errors. Empty in runs saved before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incomplete_sources: Vec<pathwarden_core::ingest::OgIncomplete>,
    /// The run's OpenGraph statistics, for Run details' "Other sources"
    /// row: never in the summary file, read from the run's folder only
    /// where Run details is shown ([`crate::run_details::with_sources`]).
    #[serde(skip)]
    pub other_sources: Option<Box<pathwarden_core::ingest::OpenGraphStats>>,
}

/// A UI run's place in the run history ([`crate::history_ui`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryLink {
    /// The history's run ID (`20261009T021000.042Z`), when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Why the run was not recorded, in words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_recorded: Option<String>,
    /// What the comparison with the previous run warned about (for example
    /// a domain missing from this collection).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Recorded in the history here, but the push to the shared
    /// repository failed (the next run that can push pushes it): why, in
    /// one sentence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpushed: Option<String>,
    /// What git said about it, for `--verbose` right after the save; not
    /// kept with the run.
    #[serde(skip)]
    pub unpushed_detail: Option<String>,
    /// Not recorded, or not pushed, because the repository wanted a
    /// sign-in git couldn't make ([`pathwarden_core::connect::is_sign_in`]):
    /// Run details offers Sign in.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sign_in: bool,
    /// And git here has no credential helper to ask with.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_helper: bool,
    /// Or the repository refused the account git gave
    /// ([`pathwarden_core::connect::refused`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub refused: bool,
    /// With "Full runs and settings": whether the run went into the history
    /// in full ([`crate::shared_runs`]). Absent when it wasn't meant to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_run: Option<crate::shared_runs::FullRunLink>,
    /// Servers the last run in the history had a Tier Zero settings file
    /// for and this run has none for: Run details says so.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub settings_fewer: Vec<String>,
}

/// For `skip_serializing_if`: a count of none.
fn usize_is_zero(n: &usize) -> bool {
    *n == 0
}

/// How a run's data was collected (the Collect wizard). No credentials: the
/// user name and password are never recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionInfo {
    /// `builtin` or `sharphound`.
    pub method: String,
    /// `dc-only` or `all`.
    pub scope: String,
    pub domain: String,
    /// The domain controller, when one was chosen.
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub ldaps: bool,
    /// Signed in as the current Windows user (true) or with a password.
    #[serde(default)]
    pub current_user: bool,
    /// What the collector warned about (e.g. no sessions were collected).
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Where the raw collection was kept, if the user asked to keep it.
    #[serde(default)]
    pub kept: Option<String>,
    /// Computers were read with Kerberos only. `None` in runs from
    /// before it was recorded; `Some(false)` for SharpHound too, which
    /// signs in to computers its own way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kerberos_only: Option<bool>,
    /// Computers' SMB replies had to be signed, as `kerberos_only`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smb_signing: Option<bool>,
    /// Each domain the run tried to collect, in order, `domain`
    /// first. Older runs have none: they read as `domain` alone
    /// ([`CollectionInfo::domain_outcomes`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<DomainOutcome>,
    /// When the read started, when it resumed one that had stopped
    /// (Unix time). The run is dated by when it finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_started: Option<i64>,
    /// Plain LDAP was allowed (`--allow-unencrypted-ldap`, "Allow plain
    /// LDAP"): with `ldaps`, LDAPS first and plain LDAP where it fails. A
    /// repeat or a schedule of the run allows it too.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub plain_allowed: bool,
    /// LDAPS was asked for but failed on a domain controller, which was
    /// read over plain LDAP (the warnings name it). `ldaps` stays what
    /// was asked.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub plain_fallback: bool,
}

/// How collecting one domain of a run went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainOutcome {
    pub domain: String,
    pub collected: bool,
    /// Objects written, when collected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objects: Option<usize>,
    /// How long it took, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<u64>,
    /// Why it wasn't collected, in one sentence, and the detail behind it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl CollectionInfo {
    /// The run's domains: as recorded, or for an older run, its one domain,
    /// collected.
    pub fn domain_outcomes(&self) -> Vec<DomainOutcome> {
        if !self.domains.is_empty() {
            return self.domains.clone();
        }
        vec![DomainOutcome {
            domain: self.domain.clone(),
            collected: true,
            objects: None,
            seconds: None,
            reason: None,
            detail: None,
        }]
    }

    /// The domains that failed, by name.
    pub fn failed_domains(&self) -> Vec<String> {
        self.domains
            .iter()
            .filter(|d| !d.collected)
            .map(|d| d.domain.clone())
            .collect()
    }
}

impl RunSummary {
    pub fn new(id: &str, created_at: i64, source: String, demo: bool, a: &Analysis) -> Self {
        let t0 = &a.posture.tier_zero;
        let c = &a.posture.findings;
        Self {
            id: id.to_string(),
            created_at,
            created_ms: millis_within(created_at),
            collected_at: a.stats.collected_at,
            source,
            demo,
            domains: a.domains.clone(),
            trusted_domains: Some(a.trusted_domains.clone()),
            not_collected: Some(a.uncollected_domains()),
            legacy_domains: false,
            objects: a.collected_objects(),
            files: a.stats.files.len(),
            exposure_percent: t0.exposure_percent,
            exposed: t0.exposed,
            population: t0.population,
            relevant_population: t0.relevant_population,
            exposure_basis: a.posture.exposure_basis,
            protection_score: t0.protection_score,
            critical: c.critical,
            high: c.high,
            medium: c.medium,
            low: c.low,
            info: c.info,
            suppressed: c.suppressed,
            plan_steps: a.plan.fixes.len(),
            exposed_after: Some(a.plan.exposed_after),
            grade: Some(t0.exposure_grade),
            grade_reason: Some(t0.grade_reason.clone()),
            status_reason: Some(t0.reason.text.clone()),
            exposure_delta: a.plan.exposure_delta,
            next_step_delta: a
                .plan
                .first_fix_exposure_after
                .map(|after| a.plan.exposure_before - after),
            skipped_objects: a.stats.skipped_objects.len(),
            pathwarden: env!("CARGO_PKG_VERSION").to_string(),
            collection: None,
            history: None,
            environment: None,
            env_name: None,
            assigned: None,
            label: None,
            shared: None,
            completeness: pathwarden_core::state::CompletenessPoint::new(&a.posture.completeness),
            tier_zero_lists: false,
            tier_zero_change: false,
            settings_files: a.stats.settings_files(created_at),
            settings_folders_unread: a.stats.settings_folders_unread.len(),
            incomplete_sources: pathwarden_core::ingest::OgIncomplete::all(&a.stats.opengraph),
            other_sources: None,
            next_step: a
                .plan
                .fixes
                .first()
                .map(|f| plain_text(&pathwarden_core::report::step_headline(f))),
        }
    }

    /// The run's ID as users see it, in the run history's format
    /// (`20261009T021000.042Z`): the history's ID when the run was recorded
    /// there, else the ID an import would give it (from the time it was
    /// analyzed, as the History storage page imports). A run listed from
    /// the history already has that ID as its `id`.
    pub fn run_id(&self) -> String {
        if let Some(id) = self.history.as_ref().and_then(|h| h.run_id.as_deref()) {
            return id.to_string();
        }
        if !valid_run_id(&self.id) {
            return self.id.clone();
        }
        pathwarden_core::state::run_id_millis(self.created_at.saturating_mul(1000))
    }

    /// What orders runs by time, oldest first, the same on every page and
    /// command: the history run ID's time in milliseconds (when the run
    /// started), else [`RunSummary::created_ms`], else
    /// [`RunSummary::created_at`]; then the folder ID. Two runs saved in the
    /// same second sort in the order they were saved, not by their folder's
    /// random suffix. Runs one after another start after the last one
    /// finished, so start and finish times order them alike.
    pub fn order_key(&self) -> (i64, &str) {
        let ms = self
            .history
            .as_ref()
            .and_then(|h| h.run_id.as_deref())
            .and_then(pathwarden_core::state::run_id_to_millis)
            .or(self.created_ms)
            .unwrap_or_else(|| self.created_at.saturating_mul(1000));
        (ms, self.id.as_str())
    }

    /// Whether this run was saved after `other` ([`RunSummary::order_key`]).
    pub fn newer_than(&self, other: &RunSummary) -> bool {
        self.order_key() > other.order_key()
    }

    pub fn open_findings(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// The exposure basis of the run's figures
    /// ([`pathwarden_core::state::exposure_basis`]): 0 before risk scoring, 1 for the
    /// capability gate (a relevant population but no basis), else as
    /// recorded. Deltas and trends compare only runs of the same basis.
    pub fn basis(&self) -> u8 {
        pathwarden_core::state::exposure_basis(self.exposure_basis, self.relevant_population)
    }

    /// Whether this run's exposure can be compared with `other`'s.
    pub fn comparable(&self, other: &RunSummary) -> bool {
        self.basis() == other.basis()
    }

    /// The exposure denominator to show beside `exposure_percent`: the
    /// Tier-Zero relevant population. Summaries and history points written
    /// before risk scoring didn't record it (basis 0), and fall back to the whole
    /// `population`, which was their denominator. A recorded value is
    /// always `>= exposed`, so a smaller one means it wasn't recorded.
    /// What an older summary's grade is assessed from: its counts. It
    /// can't tell a broad group's path, which only a fresh analysis finds.
    fn grade_inputs(&self) -> GradeInputs {
        GradeInputs {
            exposed: self.exposed,
            broad_groups: Vec::new(),
            critical: self.critical,
            high_or_medium: self.high + self.medium,
            ..GradeInputs::default()
        }
    }

    /// Tier Zero's grade: as recorded, else assessed from the counts.
    pub fn grade(&self) -> ExposureGrade {
        self.grade
            .unwrap_or_else(|| ExposureGrade::assess(&self.grade_inputs()))
    }

    /// Why Tier Zero has its status, as the report, `pathwarden posture` and
    /// `pathwarden run` say it ([`pathwarden_core::posture::StatusReason`]).
    /// Older summaries have no such line: their grade reason stands in.
    pub fn status_reason(&self) -> String {
        match &self.status_reason {
            Some(r) => r.clone(),
            None => format!("{}.", self.grade_reason().trim_end_matches('.')),
        }
    }

    /// Why Tier Zero has its grade ([`ExposureGrade::reason`]).
    pub fn grade_reason(&self) -> String {
        self.grade_reason
            .clone()
            .unwrap_or_else(|| ExposureGrade::reason(&self.grade_inputs(), "Tier Zero"))
    }

    /// What the plan does, for the headline. Older summaries have no
    /// `exposed_after`: a plan whose drop is the whole exposure closed
    /// every path; otherwise it's unknown.
    pub fn plan_summary(&self) -> Option<PlanSummary> {
        let exposed_after = match self.exposed_after {
            Some(n) => n,
            None if self.plan_steps > 0 && self.exposure_percent - self.exposure_delta < 1e-9 => 0,
            None => return None,
        };
        Some(PlanSummary {
            steps: self.plan_steps,
            exposed_after,
        })
    }

    /// The Tier Zero headline ([`pathwarden_core::posture::headline`]).
    pub fn headline(&self) -> Headline {
        pathwarden_core::posture::headline(
            self.exposed,
            self.relevant_pop(),
            self.exposure_percent,
            self.plan_summary(),
        )
    }

    pub fn relevant_pop(&self) -> usize {
        if self.relevant_population > 0 && self.relevant_population >= self.exposed {
            self.relevant_population
        } else {
            self.population
        }
    }

    /// The name of the environment the run is in, as Environments shows
    /// it; for a run read from elsewhere (a run history), the default name
    /// of its domains ([`environment_of`]).
    pub fn environment(&self) -> String {
        self.env_name
            .clone()
            .unwrap_or_else(|| environment_of(&self.domains))
    }

    /// What lists show for the run: its label, else the computed name.
    pub fn title(&self) -> String {
        self.label.clone().unwrap_or_else(|| self.environment())
    }
}

/// The longest run label.
pub const MAX_LABEL: usize = 60;

/// A run label as typed: trimmed; `None` when empty; at most
/// [`MAX_LABEL`] characters, no control or bidi characters.
pub fn clean_label(label: &str) -> Result<Option<String>, String> {
    let label = label.trim();
    if label.is_empty() {
        return Ok(None);
    }
    if label.chars().count() > MAX_LABEL {
        return Err(format!("Use at most {MAX_LABEL} characters for the label."));
    }
    if label
        .chars()
        .any(|c| c.is_control() || pathwarden_core::text::is_bidi_control(c))
    {
        return Err("The label can't contain control characters.".into());
    }
    Ok(Some(label.to_string()))
}

/// Labels given later (in the UI, or with `pathwarden label`) to runs
/// recorded in an environment's history, by history run ID, in
/// `run-labels.json` in the environment's folder. The history itself is
/// never rewritten: a label set later goes here, over the one the run was
/// recorded with. An empty one removes the recorded one.
pub const LABELS_FILE: &str = "run-labels.json";

#[derive(Debug, Default, Serialize, Deserialize)]
struct LabelsFile {
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

/// The labels set later for history runs ([`LABELS_FILE`]).
pub fn later_labels(ws: &Workspace) -> BTreeMap<String, String> {
    labels_in(&ws.env_dir())
}

/// [`later_labels`] of the environment whose folder is `dir`.
pub fn labels_in(dir: &Path) -> BTreeMap<String, String> {
    fs::read_to_string(dir.join(LABELS_FILE))
        .ok()
        .and_then(|t| serde_json::from_str::<LabelsFile>(&t).ok())
        .map(|f| f.labels)
        .unwrap_or_default()
}

/// Sets (or, with `None`, clears) the label of history run `run_id` in the
/// environment `ws` is scoped to ([`LABELS_FILE`]).
pub fn set_later_label(ws: &Workspace, run_id: &str, label: Option<&str>) -> Result<(), String> {
    environments::check_listed(ws)?;
    static WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = WRITE.lock().unwrap_or_else(|e| e.into_inner());
    let mut labels = later_labels(ws);
    labels.insert(run_id.to_string(), label.unwrap_or_default().to_string());
    let text = serde_json::to_string_pretty(&LabelsFile { labels }).map_err(|e| e.to_string())?;
    let dir = ws.env_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("Couldn't create {}: {e}", dir.display()))?;
    pathwarden_core::config_edit::write_atomic(&dir.join(LABELS_FILE), &text)
        .map_err(|e| format!("Couldn't save the label: {e}"))
}

/// A history point's label: one set later ([`later_labels`]) over the one
/// it was recorded with; an empty one set later means none.
pub fn point_label(
    labels: &BTreeMap<String, String>,
    run_id: &str,
    recorded: Option<&str>,
) -> Option<String> {
    match labels.get(run_id) {
        Some(l) if l.is_empty() => None,
        Some(l) => Some(l.clone()),
        None => recorded.map(str::to_string),
    }
}

/// Sets (or clears) a UI run's label: in its summary, and for the run
/// history ([`set_later_label`]) when the run was recorded there, so
/// Progress shows it too. `ws` is scoped to the run's environment.
pub fn set_run_label(ws: &Workspace, id: &str, label: Option<&str>) -> Result<RunSummary, String> {
    let mut s = ws.summary(id).ok_or("That run no longer exists.")?;
    s.label = label.map(str::to_string);
    ws.update_summary(&s).map_err(|e| format!("{e:#}"))?;
    if let Some(run_id) = s.history.as_ref().and_then(|h| h.run_id.as_deref()) {
        set_later_label(ws, run_id, label)?;
    }
    Ok(s)
}

/// The downloaded report's file name: `pathwarden-<label>-<environment>.html`
/// for a labelled run ("pathwarden-after-gpo-fix-FABRIKAM.LOCAL.html"), else
/// `pathwarden-report-<date and time>.html` as before.
pub fn report_file_name(r: &RunSummary, env: &str) -> String {
    // Letters, digits and dots as they are, anything else one dash.
    fn slug(s: &str, lower: bool) -> String {
        let mut out = String::new();
        for c in s.chars() {
            if c.is_ascii_alphanumeric() || c == '.' {
                out.push(if lower { c.to_ascii_lowercase() } else { c });
            } else if !out.ends_with('-') {
                out.push('-');
            }
        }
        out.trim_matches(|c| c == '-' || c == '.').to_string()
    }
    // pathwarden-<environment>-<label, or the day>.html: the environment's
    // name as Environments shows it, not its domains.
    let env: String = slug(env, false).chars().take(60).collect();
    let env = env.trim_end_matches(['-', '.']);
    let what = match r.label.as_deref().map(|l| slug(l, true)) {
        Some(label) if !label.is_empty() => label.chars().take(60).collect::<String>(),
        _ => pathwarden_core::time::format_iso_date(r.created_at),
    };
    let what = what.trim_end_matches(['-', '.']);
    if env.is_empty() {
        format!("pathwarden-{what}.html")
    } else {
        format!("pathwarden-{env}-{what}.html")
    }
}

/// An environment's default name from its domains: the first forest root
/// (the root with the most child domains, then by name) and how many
/// other domains there are:
///
/// - none: "Active Directory";
/// - one domain: "SCALE.LOCAL";
/// - more: "SCALE.LOCAL +2" (the root, then every other domain
///   counted, child or another root alike).
///
/// Short on purpose: the environment's name is what the pages and the
/// command line show, and it can be renamed.
pub fn environment_of(domains: &[String]) -> String {
    let mut names: Vec<String> = domains.iter().map(|d| d.to_ascii_uppercase()).collect();
    names.sort();
    names.dedup();
    let n = names.len();
    match n {
        0 => return "Active Directory".to_string(),
        1 => return domains[0].clone(),
        _ => {}
    }
    let parent_of = |child: &str, parent: &str| {
        child.len() > parent.len() + 1
            && child.ends_with(parent)
            && child.as_bytes()[child.len() - parent.len() - 1] == b'.'
    };
    let mut roots: Vec<(&str, usize)> = names
        .iter()
        .filter(|d| !names.iter().any(|p| parent_of(d, p)))
        .map(|r| {
            let children = names.iter().filter(|d| parent_of(d, r)).count();
            (r.as_str(), children)
        })
        .collect();
    roots.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let first = roots.first().map_or(names[0].as_str(), |r| r.0);
    let tail = format!(" +{}", n - 1);
    let max = crate::environments::MAX_NAME;
    if first.chars().count() + tail.chars().count() <= max {
        return format!("{first}{tail}");
    }
    // A very long root is cut, never the count.
    let room = max - tail.chars().count();
    let cut: String = first.chars().take(room - 1).collect();
    format!("{cut}…{tail}")
}

/// The text of a bit of report HTML: tags dropped, entities decoded (it is
/// escaped again wherever it is shown).
fn plain_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs saved in the same second keep the order they were saved in,
    /// whatever their folders' random suffixes say.
    #[test]
    fn runs_of_one_second_sort_by_when_they_were_saved() {
        let dir = std::env::temp_dir().join(format!("pw-order-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let ws = Workspace::open(&dir).unwrap();
        let at = 1_794_600_207;
        let save = |folder: &str, history: Option<&str>, ms: Option<i64>| {
            let mut r: RunSummary = serde_json::from_value(serde_json::json!({
                "id": folder, "created_at": at, "collected_at": null,
                "source": "x.zip", "demo": false, "domains": ["CONTOSO.LOCAL"], "objects": 1,
                "files": 1, "exposure_percent": 0.0, "exposed": 0, "population": 0,
                "protection_score": null, "critical": 0, "high": 0, "medium": 0,
                "low": 0, "info": 0, "suppressed": 0, "plan_steps": 0,
                "pathwarden": "1.0.0",
            }))
            .unwrap();
            r.created_ms = ms;
            r.history = history.map(|id| HistoryLink {
                run_id: Some(id.into()),
                ..HistoryLink::default()
            });
            ws.save_run(&r, "<p>").unwrap();
        };
        // The later run has the smaller suffix.
        save("20261113-200327-bc96d7", Some("20261113T200327.102Z"), None);
        save("20261113-200327-382d1b", Some("20261113T200327.823Z"), None);
        let ids: Vec<String> = ws.all_runs().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, ["20261113-200327-382d1b", "20261113-200327-bc96d7"]);
        // Without a history ID, the saved milliseconds decide.
        save("20261113-200327-ffffff", None, Some(at * 1000 + 5));
        save("20261113-200327-000000", None, Some(at * 1000 + 990));
        let ids: Vec<String> = ws.all_runs().into_iter().map(|r| r.id).collect();
        assert_eq!(
            ids,
            [
                "20261113-200327-000000",
                "20261113-200327-382d1b",
                "20261113-200327-bc96d7",
                "20261113-200327-ffffff"
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Hostile run labels (gap 22): a typed one with control or bidi
    /// characters, or too long, is refused; one from the history (another
    /// writer's) never makes a report's file name leave its folder or
    /// carry anything but letters, digits, dots and dashes.
    #[test]
    fn hostile_labels_are_refused_or_made_harmless() {
        for bad in [
            "a\u{202e}gpj.exe".to_string(),
            "a\u{1b}[2J".to_string(),
            "line\nbreak".to_string(),
            "x".repeat(MAX_LABEL + 1),
        ] {
            assert!(clean_label(&bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            clean_label("  after GPO fix ").unwrap().as_deref(),
            Some("after GPO fix")
        );
        assert_eq!(clean_label("   ").unwrap(), None);
        let mut r: RunSummary = serde_json::from_value(serde_json::json!({
            "id": "20261002-055320-abcdef", "created_at": 1, "collected_at": null,
            "source": "x.zip", "demo": false, "domains": ["CONTOSO.LOCAL"], "objects": 1,
            "files": 1, "exposure_percent": 0.0, "exposed": 0, "population": 0,
            "protection_score": null, "critical": 0, "high": 0, "medium": 0,
            "low": 0, "info": 0, "suppressed": 0, "plan_steps": 0,
            "pathwarden": "0.3.0",
        }))
        .unwrap();
        for label in [
            "..\\..\\Windows\\evil",
            "../../etc/<script>alert(1)</script>",
            "C:\\Users\\Public\\x\u{202e}lmth.exe",
            "\"quoted\"; filename=other.exe",
        ] {
            r.label = Some(label.into());
            let name = report_file_name(&r, label);
            assert!(
                name.starts_with("pathwarden-") && name.ends_with(".html"),
                "{name}"
            );
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'),
                "{label:?}: {name}"
            );
            assert!(!name.contains(".."), "{label:?}: {name}");
        }
    }

    /// A path under the profile shows it as `%USERPROFILE%` (`~`); one
    /// elsewhere, or a folder that only starts with the same letters, is
    /// shown as it is.
    #[test]
    fn a_path_under_the_profile_hides_the_user_name() {
        let (home, sep, name) = if cfg!(windows) {
            (r"C:\Users\alice", r"\", "%USERPROFILE%")
        } else {
            ("/home/alice", "/", "~")
        };
        let home = Path::new(home);
        let under = format!("{}{sep}AppData{sep}Pathwarden", home.display());
        let short = format!("{name}{sep}AppData{sep}Pathwarden");
        assert_eq!(hide_home(&under, Some(home)), short);
        assert_eq!(hide_home(&home.display().to_string(), Some(home)), name);
        let alike = format!("{}2{sep}x", home.display());
        assert_eq!(hide_home(&alike, Some(home)), alike);
        let inside = format!("{sep}old{under}");
        assert_eq!(hide_home(&inside, Some(home)), inside);
        let other = if cfg!(windows) {
            r"D:\data"
        } else {
            "/srv/data"
        };
        assert_eq!(hide_home(other, Some(home)), other);
        assert_eq!(hide_home(&under, None), under);
        // In words, each time.
        assert_eq!(
            hide_home(&format!("{under}, {under} and 2 more"), Some(home)),
            format!("{short}, {short} and 2 more")
        );
        if cfg!(windows) {
            assert_eq!(
                hide_home(r"c:\users\ALICE\x", Some(home)),
                r"%USERPROFILE%\x"
            );
        }
    }

    #[test]
    fn plain_text_of_a_step() {
        assert_eq!(
            plain_text(
                r#"Sign <b title="A&amp;B@X.LOCAL">A&amp;B</b> out of <b title="W">W&lt;1&gt;</b>"#
            ),
            "Sign A&B out of W<1>"
        );
    }

    /// Summaries written before `collection` existed still load.
    #[test]
    fn older_summaries_load() {
        let old = r#"{"id":"20261002-055320-abcdef","created_at":1,"collected_at":null,
            "source":"x.zip","demo":false,"domains":["A.LOCAL"],"objects":1,"files":1,
            "exposure_percent":0.0,"exposed":0,"population":0,"protection_score":null,
            "critical":0,"high":0,"medium":0,"low":0,"info":0,"suppressed":0,
            "plan_steps":0,"pathwarden":"0.1.0"}"#;
        let s: RunSummary = serde_json::from_str(old).unwrap();
        assert!(s.collection.is_none());
        let back = serde_json::to_string(&s).unwrap();
        assert!(!back.contains("collection"), "absent stays absent: {back}");
    }

    /// A summary.json saved with a UTF-8 byte order mark still lists.
    #[test]
    fn summaries_with_a_bom_load() {
        let dir = std::env::temp_dir().join(format!("pw-bom-{}", std::process::id()));
        let ws = Workspace::open(&dir).unwrap();
        let id = "20261002-055320-abcdef";
        let run = ws.runs_dir().join(id);
        fs::create_dir_all(&run).unwrap();
        let json = r#"{"id":"20261002-055320-abcdef","created_at":1,"collected_at":null,
            "source":"x.zip","demo":false,"domains":["A.LOCAL"],"objects":1,"files":1,
            "exposure_percent":0.0,"exposed":0,"population":0,"protection_score":null,
            "critical":0,"high":0,"medium":0,"low":0,"info":0,"suppressed":0,
            "plan_steps":0,"pathwarden":"0.1.0"}"#;
        fs::write(run.join(SUMMARY_FILE), format!("\u{feff}{json}")).unwrap();
        let listed = ws.all_runs();
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
    }

    #[test]
    fn environment_names_follow_the_forest_roots() {
        let env = |d: &[&str]| environment_of(&d.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(env(&[]), "Active Directory");
        assert_eq!(env(&["SCALE.LOCAL"]), "SCALE.LOCAL");
        assert_eq!(
            env(&["NORTH.SEVENKINGDOMS.LOCAL", "SEVENKINGDOMS.LOCAL"]),
            "SEVENKINGDOMS.LOCAL +1"
        );
        // The root with the most child domains first, every other domain
        // counted, in any order.
        assert_eq!(
            env(&[
                "ESSOS.LOCAL",
                "NORTH.SEVENKINGDOMS.LOCAL",
                "SEVENKINGDOMS.LOCAL"
            ]),
            "SEVENKINGDOMS.LOCAL +2"
        );
        assert_eq!(
            env(&["Y.B.LOCAL", "A.LOCAL", "X.A.LOCAL", "B.LOCAL", "Z.B.LOCAL"]),
            "B.LOCAL +4"
        );
        assert_eq!(env(&["B.LOCAL", "A.LOCAL"]), "A.LOCAL +1");
        // A suffix that isn't a parent ("XA.LOCAL" vs "A.LOCAL").
        assert_eq!(env(&["XA.LOCAL", "A.LOCAL"]), "A.LOCAL +1");
        // A child without its root collected is a root here.
        assert_eq!(
            env(&["NORTH.SEVENKINGDOMS.LOCAL", "ESSOS.LOCAL"]),
            "ESSOS.LOCAL +1"
        );
        // A very long root is cut, never the count.
        let longest = [
            "HEADQUARTERS-EUROPE-WEST-PRODUCTION-AND-STAGING-SERVICES.EXAMPLE",
            "SALES.HEADQUARTERS-EUROPE-WEST-PRODUCTION-AND-STAGING-SERVICES.EXAMPLE",
            "LABS.EXAMPLE",
        ];
        let name = env(&longest);
        assert!(
            name.chars().count() <= crate::environments::MAX_NAME,
            "{name}"
        );
        assert!(name.starts_with("HEADQUARTERS-EUROPE"), "{name}");
        assert!(name.ends_with("… +2"), "{name}");
        let longest: Vec<String> = longest.iter().map(|s| s.to_string()).collect();
        assert_eq!(crate::environments::new_name(&longest), name);
    }

    /// A run saved by 0.1.1, which counted the trusted domain, takes the
    /// domains of a later run of the same collection: one name, one
    /// environment.
    #[test]
    fn runs_saved_with_trusted_domains_take_the_collected_ones() {
        let run = |id: &str, created: i64, domains: &[&str], trusted: Option<&[&str]>| {
            let mut s: RunSummary = serde_json::from_value(serde_json::json!({
                "id": id, "created_at": created, "collected_at": null,
                "source": "x.zip", "demo": false, "domains": domains, "objects": 1,
                "files": 1, "exposure_percent": 0.0, "exposed": 0, "population": 0,
                "protection_score": null, "critical": 0, "high": 0, "medium": 0,
                "low": 0, "info": 0, "suppressed": 0, "plan_steps": 0,
                "pathwarden": "0.1.1",
            }))
            .unwrap();
            s.trusted_domains = trusted.map(|t| t.iter().map(|d| d.to_string()).collect());
            s
        };
        let essos_trusts: &[&str] = &["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"];
        // Newest first, as `all_runs` lists them.
        let mut runs = vec![
            run("new", 3, &["ESSOS.LOCAL"], Some(&["SEVENKINGDOMS.LOCAL"])),
            run("other", 2, &["CONTOSO.LOCAL", "FABRIKAM.LOCAL"], None),
            run("old", 1, essos_trusts, None),
        ];
        assert_eq!(runs[2].environment(), "ESSOS.LOCAL +1");
        migrate_domains(&mut runs);
        assert_eq!(runs[2].domains, ["ESSOS.LOCAL"]);
        assert_eq!(runs[2].environment(), runs[0].environment());
        assert_eq!(runs[1].domains, ["CONTOSO.LOCAL", "FABRIKAM.LOCAL"]);
        // Parent and child collected separately since: the old pair could
        // be either, so it stays as it was.
        let pair: &[&str] = &["NORTH.SEVENKINGDOMS.LOCAL", "SEVENKINGDOMS.LOCAL"];
        let mut split = vec![
            run("child", 3, &pair[..1], Some(&pair[1..])),
            run("parent", 2, &pair[1..], Some(&pair[..1])),
            run("old", 1, pair, None),
        ];
        migrate_domains(&mut split);
        assert_eq!(split[2].domains, pair);
        // Without a run saved since, nothing to learn from.
        let mut alone = vec![run("old", 1, essos_trusts, None)];
        migrate_domains(&mut alone);
        assert_eq!(alone[0].domains, essos_trusts);
        // Unmapped, it is marked (its domains place a run only after
        // asking); mapped ones and one-domain ones are not.
        assert!(alone[0].legacy_domains && split[2].legacy_domains);
        assert!(!runs[2].legacy_domains && !runs[0].legacy_domains);
        let mut one = vec![run("old", 1, &["ESSOS.LOCAL"], None)];
        migrate_domains(&mut one);
        assert!(!one[0].legacy_domains);
        // The field is written for new runs only.
        let text = serde_json::to_string(&runs[0]).unwrap();
        assert!(text.contains(r#""trusted_domains":["SEVENKINGDOMS.LOCAL"]"#));
        assert!(!serde_json::to_string(&runs[2])
            .unwrap()
            .contains("trusted_domains"));
    }

    /// One ID format for users: the history's, recorded or not.
    #[test]
    fn run_id_is_the_history_format() {
        let mut s: RunSummary = serde_json::from_str(
            r#"{"id":"20261003-040000-abcdef","created_at":1791000000,"collected_at":null,
            "source":"x.zip","demo":false,"domains":[],"objects":1,"files":1,
            "exposure_percent":0.0,"exposed":0,"population":0,"protection_score":null,
            "critical":0,"high":0,"medium":0,"low":0,"info":0,"suppressed":0,
            "plan_steps":0,"pathwarden":"0.1.0"}"#,
        )
        .unwrap();
        // Local only: the ID an import would give it.
        assert_eq!(s.run_id(), "20261003T040000.000Z");
        assert!(looks_like_history_id(&s.run_id()));
        s.history = Some(HistoryLink {
            run_id: Some("20261003T035958.123Z".into()),
            ..Default::default()
        });
        assert_eq!(s.run_id(), "20261003T035958.123Z");
        // A run listed from the history.
        s.id = "20261001T010203.004Z".into();
        s.history = None;
        assert_eq!(s.run_id(), "20261001T010203.004Z");
        for bad in [
            "",
            "20261001T010203.04Z",
            "20261001-010203-abcdef",
            "../x",
            "20261001T010203.0042Z",
        ] {
            assert!(!looks_like_history_id(bad), "{bad}");
        }
        assert!(looks_like_history_id("20261001T010203Z"));
    }

    #[test]
    fn run_ids() {
        let id = new_run_id(1_791_000_000);
        assert!(valid_run_id(&id), "{id}");
        assert!(id.starts_with("20261003-040000-"), "{id}");
        for bad in [
            "",
            "..",
            "../../etc/passwd",
            "20261002-055320-abcdeg",
            "20261002-055320-ABCDEF",
            "20261002/055320-abcdef",
            "20261002-055320-abcdef/..",
            "2026100a-055320-abcdef",
        ] {
            assert!(!valid_run_id(bad), "{bad}");
        }
    }
}
