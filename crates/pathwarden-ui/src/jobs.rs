//! Analyses (and collections followed by an analysis) running in the
//! background. One runs at a time (a large collection can take most of the
//! machine's memory); the browser polls its progress.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use pathwarden_core::analyze::{self, Evaluated, Phase};
use pathwarden_core::config::Config;
use pathwarden_core::record::RecordProgress;
use pathwarden_core::IngestError;
use serde::Serialize;

use crate::environments::{self, Assigned, Choice, Placement, Settling};
use crate::workspace::{CollectionInfo, RunSummary, Workspace};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum JobStatus {
    /// Collecting from Active Directory (collection jobs, before analysis).
    Collecting,
    Running {
        phase: Phase,
    },
    Done {
        run: String,
    },
    Failed {
        error: String,
    },
    /// Cancelled by the user.
    Stopped,
    /// The data is the same collection as an earlier run: nothing was saved,
    /// and the user chooses to open that run or analyze anyway.
    Duplicate {
        /// The UI run with the same data, if it is one (else a run the CLI
        /// or a schedule recorded).
        #[serde(skip_serializing_if = "Option::is_none")]
        run: Option<String>,
        /// When that run was analyzed (Unix time).
        at: i64,
        /// "the run of CONTOSO.LOCAL" or "the scheduled run".
        what: String,
    },
    /// Something's off with the environment ([`environments::decide`]):
    /// the data's domains match two environments, or one only partly.
    /// Nothing was saved; the user picks where the run goes.
    Ask {
        /// The domains the data collected.
        domains: Vec<String>,
        /// "FABRIKAM.LOCAL matches Lab; WOODGROVE.LOCAL is new."
        reason: String,
    },
}

impl JobStatus {
    /// Still collecting or analyzing.
    pub fn is_active(&self) -> bool {
        matches!(self, JobStatus::Collecting | JobStatus::Running { .. })
    }
}

/// What a demo job analyzes, in words ([`Job::source`]).
pub const DEMO_SOURCE: &str = "Demo data";

#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub id: String,
    #[serde(flatten)]
    pub status: JobStatus,
    /// Unix time the analysis started.
    pub started_at: i64,
    pub source: String,
    /// Collection jobs: what the collector is doing and has done.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collect: Option<CollectProgress>,
    /// While reading the data: bytes read and the total.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reading: Option<ReadProgress>,
    /// The demo's first run: its earlier runs recorded so far, while they
    /// are built and after ([`crate::demo_runs`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub earlier: Option<EarlierProgress>,
    /// Collection jobs: set to stop the collector.
    #[serde(skip)]
    pub cancel: Option<Arc<AtomicBool>>,
}

/// A collection's progress, as the Collect page shows it. Holds no secrets:
/// only phases, counts, collector output lines and warnings.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CollectProgress {
    /// "Built-in collector" or "SharpHound".
    pub method: String,
    /// "Quick" or "Full".
    pub depth: String,
    /// The run's domain, upper case: the Collect page's title for one
    /// domain ("Collecting CONTOSO.COM").
    #[serde(skip_serializing_if = "String::is_empty")]
    pub domain: String,
    /// The collector's current step, in its words.
    pub phase: String,
    /// Objects written, by type (`users`, `computers`, ...).
    pub objects: BTreeMap<String, usize>,
    /// The collector's latest status: step, counts, expected totals, percent
    /// and ETA.
    pub status: Option<pathwarden_collect::Status>,
    /// The last lines of collector output.
    pub log: Vec<String>,
    /// Lines of output so far (the log keeps only the last ones).
    pub log_total: usize,
    pub warnings: Vec<String>,
    /// Unix time the collection finished (the analysis starts then).
    pub collected_at: Option<i64>,
    /// Where the raw collection was kept, if the user asked to keep it.
    pub kept: Option<String>,
    /// A run of several domains: each, in order, and how it is
    /// going. Empty for one domain.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<DomainRun>,
    /// The collection failed and its read is kept on disk to resume.
    pub resumable: bool,
    /// Other collectors' files analyzed with the collection: their
    /// names, as the page lists them while collecting.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub also: Vec<String>,
}

/// One domain of a collection of several, as the Collect page lists it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DomainRun {
    pub name: String,
    /// `waiting`, `active`, `done` or `failed`.
    pub state: &'static str,
    /// "Done · 1 min", or why it failed.
    pub text: String,
}

/// How far reading the collector files has got.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ReadProgress {
    pub read: u64,
    pub total: u64,
}

/// How many of the demo's earlier runs are recorded.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct EarlierProgress {
    pub done: usize,
    pub total: usize,
}

/// Lines of collector output kept for the page.
pub const LOG_LINES: usize = 80;

#[derive(Default)]
pub struct Jobs {
    jobs: Mutex<HashMap<String, Job>>,
    /// A connection check (Collect wizard) is running.
    pub(crate) checking: AtomicBool,
    /// Analyses stopped as duplicates, kept until the user decides.
    pending: Mutex<HashMap<String, JobSpec>>,
    /// `pathwarden ui --state DIR` (see [`crate::history_ui`]).
    state_dir: Mutex<Option<PathBuf>>,
    /// Files uploaded on the Collect page to analyze with the collection,
    /// waiting for Start collecting: one set at a time.
    also: Mutex<Option<AlsoFiles>>,
}

/// Other collectors' files uploaded on the Collect page, kept until
/// the collection they go with starts ([`Jobs::stage_also`]).
#[derive(Debug, Clone)]
pub struct AlsoFiles {
    /// What Start collecting names them by.
    pub id: String,
    /// The upload folder (deleted after the analysis, unless uploads are
    /// kept), when files were uploaded.
    pub dir: Option<PathBuf>,
    pub inputs: Vec<PathBuf>,
    /// The files' names, as the page lists them.
    pub names: Vec<String>,
}

impl AlsoFiles {
    /// Deletes the upload folder, unless uploads are kept.
    pub fn discard(&self, keep_uploads: bool) {
        if let (Some(dir), false) = (&self.dir, keep_uploads) {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// What to analyze.
pub struct JobSpec {
    pub id: String,
    pub inputs: Vec<PathBuf>,
    /// An upload folder to delete afterwards (unless uploads are kept).
    pub scratch: Option<PathBuf>,
    /// A second one: other collectors' files uploaded to analyze with a
    /// collection, deleted the same way.
    pub also_scratch: Option<PathBuf>,
    pub source: String,
    pub demo: bool,
    /// The environment the run goes to (an ID), or with `new_env` a new
    /// one by that name; neither lets [`environments::decide`] pick by the
    /// data's domains, asking when something's off.
    pub env: Option<String>,
    pub new_env: Option<String>,
    /// The choice is the one the page made by itself (from the domains it
    /// could read beforehand): the data's own domains decide, and the
    /// choice is used only when they would ask.
    pub env_auto: bool,
    /// The run's label ([`crate::workspace::clean_label`]).
    pub label: Option<String>,
    /// How the data was collected, for runs from the Collect wizard.
    pub collection: Option<CollectionInfo>,
    /// Where the collection's time went (`timings.json`), for runs from
    /// the Collect wizard.
    pub timings: Option<pathwarden_core::diagnostics::CollectionTimings>,
    /// Analyze even data already analyzed ("Re-analyze", "Analyze
    /// anyway"), kept for when the analysis is started again after
    /// [`JobStatus::Ask`].
    pub force: bool,
}

impl JobSpec {
    /// Deletes the upload folders, unless uploads are kept.
    pub fn remove_uploads(&self, keep_uploads: bool) {
        if keep_uploads {
            return;
        }
        for dir in [&self.scratch, &self.also_scratch].into_iter().flatten() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl Jobs {
    /// Keeps files uploaded to analyze with the next collection,
    /// in place of any kept before (deleted unless uploads are kept).
    pub fn stage_also(&self, files: AlsoFiles, keep_uploads: bool) {
        let old = self
            .also
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(files);
        if let Some(old) = old {
            old.discard(keep_uploads);
        }
    }

    /// Takes the files staged as `id` ([`Jobs::stage_also`]), if they are
    /// still waiting.
    pub fn take_also(&self, id: &str) -> Option<AlsoFiles> {
        let mut also = self.also.lock().unwrap_or_else(|e| e.into_inner());
        if also.as_ref().is_some_and(|a| a.id == id) {
            also.take()
        } else {
            None
        }
    }

    /// The run history folder from `--state`, over the workspace config's.
    pub fn state_dir(&self) -> Option<PathBuf> {
        self.state_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// [`Jobs::state_dir`] for the environment `ws` is scoped to: `--state`
    /// is the Default environment's only, so another environment's history
    /// is never written into it.
    pub fn state_dir_for(&self, ws: &Workspace) -> Option<PathBuf> {
        if ws.is_default_env() {
            self.state_dir()
        } else {
            None
        }
    }

    pub fn set_state_dir(&self, dir: Option<PathBuf>) {
        *self.state_dir.lock().unwrap_or_else(|e| e.into_inner()) = dir;
    }

    /// Keeps a stopped analysis until the user decides
    /// ([`JobStatus::Duplicate`], [`JobStatus::Ask`]).
    pub(crate) fn keep_pending(&self, id: &str, spec: JobSpec) {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_string(), spec);
    }

    /// Takes an analysis stopped as a duplicate (to analyze anyway, or to
    /// discard it).
    pub fn take_pending(&self, id: &str) -> Option<JobSpec> {
        let spec = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        if spec.is_some() {
            self.lock().remove(id);
        }
        spec
    }

    pub fn get(&self, id: &str) -> Option<Job> {
        self.lock().get(id).cloned()
    }

    /// The analysis in progress, if any.
    pub fn running(&self) -> Option<Job> {
        self.lock().values().find(|j| j.status.is_active()).cloned()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Job>> {
        // A panic while holding the lock leaves the map usable.
        self.jobs.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn set(&self, id: &str, status: JobStatus) {
        if let Some(j) = self.lock().get_mut(id) {
            j.status = status;
        }
    }

    fn set_reading(&self, id: &str, reading: Option<ReadProgress>) {
        if let Some(j) = self.lock().get_mut(id) {
            j.reading = reading;
        }
    }

    fn set_earlier(&self, id: &str, done: usize) {
        if let Some(j) = self.lock().get_mut(id) {
            let total = crate::demo_runs::EARLIER.len();
            // Only forward.
            let done = j.earlier.map_or(done, |e| e.done.max(done));
            j.earlier = Some(EarlierProgress { done, total });
        }
    }

    /// Changes a collection job's progress.
    pub(crate) fn update_collect(&self, id: &str, f: impl FnOnce(&mut CollectProgress)) {
        if let Some(p) = self.lock().get_mut(id).and_then(|j| j.collect.as_mut()) {
            f(p);
        }
    }

    /// Asks a running collection to stop. False if there is no such job, or
    /// it is past collecting (an analysis cannot be stopped).
    pub fn cancel(&self, id: &str) -> bool {
        let jobs = self.lock();
        match jobs.get(id) {
            Some(Job {
                status: JobStatus::Collecting,
                cancel: Some(flag),
                ..
            }) => {
                flag.store(true, Ordering::SeqCst);
                true
            }
            _ => false,
        }
    }

    /// Registers the job, unless another one is running. Returns false then.
    pub fn try_begin(&self, spec: &JobSpec) -> bool {
        self.insert_if_idle(Job {
            id: spec.id.clone(),
            status: JobStatus::Running {
                phase: Phase::Reading,
            },
            started_at: analyze::now(),
            source: spec.source.clone(),
            collect: None,
            reading: None,
            earlier: None,
            cancel: None,
        })
    }

    /// Registers a collection job, unless another job is running.
    pub(crate) fn try_begin_collect(
        &self,
        id: &str,
        source: String,
        progress: CollectProgress,
        cancel: Arc<AtomicBool>,
    ) -> bool {
        self.insert_if_idle(Job {
            id: id.to_string(),
            status: JobStatus::Collecting,
            started_at: analyze::now(),
            source,
            collect: Some(progress),
            reading: None,
            earlier: None,
            cancel: Some(cancel),
        })
    }

    fn insert_if_idle(&self, job: Job) -> bool {
        let mut jobs = self.lock();
        if jobs.values().any(|j| j.status.is_active()) {
            return false;
        }
        // Keep the map small: forget finished jobs from long ago.
        if jobs.len() > 50 {
            jobs.retain(|_, j| j.status.is_active());
        }
        jobs.insert(job.id.clone(), job);
        true
    }
}

/// Runs a registered job on its own thread. With `check_duplicate`, data
/// that is the same collection as an earlier run stops before anything is
/// saved ([`JobStatus::Duplicate`]); the demo and deliberate re-runs skip
/// the check.
pub fn spawn(
    jobs: Arc<Jobs>,
    ws: Workspace,
    spec: JobSpec,
    keep_uploads: bool,
    check_duplicate: bool,
) {
    std::thread::spawn(move || {
        let id = spec.id.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            analyze_checked(&jobs, &ws, &spec, check_duplicate && !spec.demo)
        }))
        .unwrap_or_else(|_| Err("The analysis stopped. Try again.".into()));
        let status = match result {
            Ok(None) => JobStatus::Done { run: id.clone() },
            Ok(Some(stopped)) => stopped,
            Err(error) => JobStatus::Failed { error },
        };
        if matches!(status, JobStatus::Duplicate { .. } | JobStatus::Ask { .. }) {
            // Kept (uploads too) until the user decides.
            jobs.keep_pending(&id, spec);
        } else {
            spec.remove_uploads(keep_uploads);
        }
        jobs.set(&id, status);
    });
}

/// Analyzes `spec`'s inputs and saves the run (the Collect wizard's
/// collections). `Some` when it stopped for the user to pick the
/// environment ([`JobStatus::Ask`]): nothing was saved.
pub(crate) fn analyze_with(
    jobs: &Jobs,
    ws: &Workspace,
    spec: &JobSpec,
) -> Result<Option<JobStatus>, String> {
    analyze_checked(jobs, ws, spec, false)
}

/// The environment's config and its bytes (`None`: no file, the defaults),
/// to tell whether two environments analyze the same way.
fn config_of(ws: &Workspace) -> Result<(Config, Option<Vec<u8>>), String> {
    Ok((
        ws.config().map_err(|e| format!("{e:#}"))?,
        std::fs::read(ws.config_path()).ok(),
    ))
}

/// The choice a job carries ([`JobSpec::env`], [`JobSpec::new_env`]).
fn choice_of(ws: &Workspace, spec: &JobSpec) -> Option<Choice> {
    let reg = ws.registry();
    match (&spec.env, &spec.new_env) {
        (Some(id), _) if reg.get(id).is_some() => Some(Choice::Env(id.clone())),
        (_, Some(name)) => Some(Choice::New(name.clone())),
        _ => None,
    }
}

/// [`analyze_with`]; with `check_duplicate`, returns the duplicate status
/// instead of saving when the data is the same collection as an earlier run.
fn analyze_checked(
    jobs: &Jobs,
    ws: &Workspace,
    spec: &JobSpec,
    check_duplicate: bool,
) -> Result<Option<JobStatus>, String> {
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();
    let mut progress = JobProgress::new(jobs, &spec.id);
    // Analyzed first with the settings of the environment it most likely
    // goes to: the one chosen, else the current one (a new one starts
    // with the defaults).
    let choice = choice_of(ws, spec);
    let (mut config, used) = match &choice {
        Some(Choice::Env(id)) => config_of(&ws.in_env(id))?,
        Some(Choice::New(_)) => (Config::default(), None),
        None => config_of(ws)?,
    };
    let mut ev = analyze::evaluate(&spec.inputs, &config, &[], &mut progress)
        .map_err(|e| spec_error(&e, spec))?;
    let domains = analyze::domain_names(&ev.graph);
    let trusted = analyze::trusted_domain_names(&ev.graph);
    let reg = ws.registry();
    let all = ws.all_runs();
    let runs = environments::run_domains_for(&reg, &all, Some((&domains, &trusted)));
    // Where it goes: the demo to its own environment; anything else by
    // the choice and its domains, stopping to ask when something's off.
    let placement = if spec.demo {
        Placement::Demo(environments::Registry::update(ws.root(), |r| {
            Ok(r.ensure_demo())
        })?)
    } else {
        environments::place(&reg, &domains, &runs, choice.as_ref(), spec.env_auto)
    };
    // No domain at all: the current environment, unless that is the demo's.
    let current = if reg.demo_id() == Some(ws.env_id()) {
        environments::DEFAULT_ENV.to_string()
    } else {
        ws.env_id().to_string()
    };
    let existing = match &placement {
        Placement::Ask(ask) => {
            return Ok(Some(JobStatus::Ask {
                domains,
                reason: ask.reason(&reg.clone().with_names(&all)),
            }))
        }
        Placement::Demo(id) => Some(id.clone()),
        Placement::Current => Some(current.clone()),
        Placement::Settle(Choice::Env(id), ..) => Some(id.clone()),
        Placement::Settle(Choice::New(_), ..) => None,
    };
    // A collection already analyzed stops before anything is made.
    if let (Some(id), true) = (&existing, check_duplicate) {
        let target = ws.in_env(id);
        if let Some(dup) = duplicate_of(&target, jobs.state_dir_for(&target).as_deref(), &ev) {
            return Ok(Some(dup));
        }
    }
    let (target, how) = match placement {
        Placement::Demo(id) => (id, Assigned::Current),
        Placement::Current => (current, Assigned::Current),
        Placement::Settle(c, how, automatic) => {
            #[cfg(test)]
            tests::before_settle(ws.root());
            match environments::settle(ws.root(), &c, how, &domains, &runs, automatic)? {
                Settling::Settled(s) => (s.id, s.how),
                // The environments changed meanwhile: asked as above (the
                // upload or collection is kept until the user picks).
                Settling::Ask(ask) => {
                    let all = ws.all_runs();
                    return Ok(Some(JobStatus::Ask {
                        domains,
                        reason: ask.reason(&ws.registry().with_names(&all)),
                    }));
                }
            }
        }
        Placement::Ask(_) => unreachable!("returned above"),
    };
    let ws = ws.in_env(&target);
    // Analyzed with other settings than the environment's own: again with
    // its own.
    let (own, own_bytes) = config_of(&ws)?;
    if own_bytes != used {
        config = own;
        ev = analyze::evaluate(&spec.inputs, &config, &[], &mut progress)
            .map_err(|e| spec_error(&e, spec))?;
    }
    let state_dir = jobs.state_dir_for(&ws);
    // The demo's first run: its zone, and its earlier runs before it.
    if spec.demo && crate::demo_runs::needed(&ws) {
        crate::demo_runs::ensure_zone(&ws)?;
        let (own, _) = config_of(&ws)?;
        config = own;
        let scratch = spec.scratch.clone().unwrap_or_else(std::env::temp_dir);
        progress.held = true;
        jobs.set_earlier(&spec.id, 0);
        crate::demo_runs::record(
            &ws,
            &config,
            state_dir.as_deref(),
            &scratch,
            analyze::now(),
            &mut progress,
            &mut |done| jobs.set_earlier(&spec.id, done),
        )?;
        progress.held = false;
        ev = analyze::evaluate(&spec.inputs, &config, &[], &mut progress)
            .map_err(|e| spec_error(&e, spec))?;
    }
    // Data `pathwarden collect` wrote has its timings with it.
    let collected = spec
        .timings
        .is_none()
        .then(|| pathwarden_core::diagnostics::collected_timings(&spec.inputs))
        .flatten();
    save_analysis(
        &ws,
        &config,
        ev,
        SaveRun {
            id: &spec.id,
            source: spec.source.clone(),
            demo: spec.demo,
            label: spec.label.clone(),
            collection: spec.collection.clone(),
            timings: spec
                .timings
                .clone()
                .or_else(|| collected.as_ref().map(|c| c.timings.clone())),
            how,
            state_dir: state_dir.as_deref(),
            started_ms,
            recorded_by: pathwarden_core::record::by::UI,
            finished_at: None,
            inputs: &spec.inputs,
        },
        &mut progress,
    )?;
    if let Some(c) = &collected {
        c.mark_recorded();
    }
    Ok(None)
}

/// How [`save_analysis`] saves a run.
pub struct SaveRun<'a> {
    /// The run's folder ID ([`crate::workspace::new_run_id`]).
    pub id: &'a str,
    /// What was analyzed, in words.
    pub source: String,
    pub demo: bool,
    pub label: Option<String>,
    pub collection: Option<CollectionInfo>,
    /// Saved as the run's `timings.json` ([`pathwarden_core::diagnostics`]).
    pub timings: Option<pathwarden_core::diagnostics::CollectionTimings>,
    /// How the run got its environment.
    pub how: Assigned,
    /// `pathwarden ui --state DIR` ([`Jobs::state_dir_for`]).
    pub state_dir: Option<&'a std::path::Path>,
    pub started_ms: i64,
    /// What records it ([`pathwarden_core::record::by`]).
    pub recorded_by: &'a str,
    /// When it finished, for a run dated in the past (the demo's earlier
    /// runs, [`crate::demo_runs`]); `None`, now.
    pub finished_at: Option<i64>,
    /// The collector files analyzed, hashed into the run's
    /// [`crate::evidence_ui::INPUTS_FILE`] for its evidence packs; empty for
    /// none.
    pub inputs: &'a [std::path::PathBuf],
}

/// Saves an evaluated analysis as a run of the environment `ws` is scoped
/// to, as the UI does (also `pathwarden collect --save` and `run --save`):
/// recorded in the environment's run history (the demo's in its own), the
/// report and its data in the run's folder. The report is stored without
/// the label; it is added when the report is served, so a label changed
/// later shows there too.
pub fn save_analysis<P: RecordProgress>(
    ws: &Workspace,
    config: &Config,
    ev: Evaluated,
    run: SaveRun,
    p: &mut P,
) -> Result<RunSummary, String> {
    env_still_there(ws)?;
    let mut p = KeepWarnings {
        inner: p,
        warnings: Vec::new(),
    };
    // The demo too: its environment has a run history of its own, with its
    // earlier runs ([`crate::demo_runs`]).
    // The history stays locked until the run's full run is in too (`held`).
    let (analysis, mut link, earlier, held) = crate::history_ui::record_analysis_held(
        ws,
        run.state_dir,
        config,
        ev,
        &crate::history_ui::Recording {
            started_ms: run.started_ms,
            recorded_by: run.recorded_by,
            label: run.label.as_deref(),
            finished_at: run.finished_at,
        },
        &mut p,
    );
    // No full run to follow: the history is free again at once.
    let held = held.filter(|_| !run.demo && crate::shared_runs::wanted(config));
    link.warnings = std::mem::take(&mut p.warnings);
    let history = Some(link);
    let finished = run.finished_at.unwrap_or_else(analyze::now);
    // The account lists, made once for the report and the run's files.
    let lists = analysis.exposure_lists(&earlier);
    let html = analysis.report_html_lists(finished, &earlier, &lists, &mut p);
    let mut summary = RunSummary::new(run.id, finished, run.source, run.demo, &analysis);
    summary.collection = run.collection;
    summary.history = history;
    summary.environment = (!ws.is_default_env()).then(|| ws.env_id().to_string());
    summary.assigned = Some(run.how.as_str().to_string());
    summary.label = run.label;
    // The object index and event document the configuration screens use.
    // The event carries the run ID users see (the history's).
    let mut extra = crate::run_data::files_with(&summary.run_id(), &analysis, finished, &lists);
    drop(lists);
    // The earlier run's graph the lists read, if any, is let go.
    pathwarden_core::exposed::release_earlier();
    summary.tier_zero_lists = extra
        .iter()
        .any(|(n, _)| *n == crate::run_data::EXPOSED_FILE);
    summary.tier_zero_change = pathwarden_core::report::opens_change(&html);
    if let Some(b) = run
        .timings
        .as_ref()
        .and_then(|t| serde_json::to_vec_pretty(t).ok())
    {
        extra.push((pathwarden_core::diagnostics::TIMINGS_FILE, b));
    }
    drop(analysis);
    // With "Full runs and settings", the run goes into the history in full
    // too, in a commit of its own after its point's, under the same lock.
    // Marked pending first: a crash before it is in is caught up by the
    // next recording or pull from here.
    let run_id = crate::history_ui::recorded_id(&summary).map(str::to_string);
    let share = run_id.is_some() && held.is_some();
    if share {
        if let Some(h) = summary.history.as_mut() {
            h.full_run = Some(crate::shared_runs::FullRunLink {
                state: crate::shared_runs::FullRunState::Pending,
                why: None,
                left_out: Vec::new(),
            });
        }
    }
    env_still_there(ws)?;
    ws.save_run_with(&summary, &html, &extra)
        .map_err(|e| format!("Couldn't save the report: {e:#}"))?;
    // The collector files' hashes, for the run's evidence packs. Kept on
    // this computer only, not in the full run.
    if let Some(dir) = ws.run_dir(&summary.id) {
        crate::evidence_ui::save_inputs(&dir, run.inputs);
    }
    if let (true, Some(run_id), Some(held)) = (share, run_id, held.as_ref()) {
        let config_text = std::fs::read_to_string(ws.config_path()).ok();
        let bundle = crate::shared_runs::Bundle::build(
            crate::shared_runs::Parts {
                run_id: &run_id,
                summary: &summary,
                report_html: &html,
                extra,
                config_text: config_text.as_deref(),
                recorded_from: run.recorded_by,
                folder: Some(&summary.id),
            },
            crate::shared_runs::file_limit(&config.state, &held.loc.store),
        );
        drop(html);
        let link = crate::shared_runs::share_saved(ws, held, config, bundle);
        if let Some(h) = summary.history.as_mut() {
            h.full_run = link.map(|(l, _)| l);
        }
        // The run is saved either way; this only says how sharing went.
        let _ = ws.update_summary(&summary);
    }
    // What waits to be pushed now, noted for History storage and the
    // footer (they never work it out themselves).
    if !run.demo {
        if let Ok(loc) = crate::history_ui::locate_with(ws, run.state_dir, config) {
            crate::shared_runs::record_waiting(ws, &loc);
            // The history's checks made for its new commits now, so pages
            // showing it run no git.
            let _ = pathwarden_core::store::check_readable(&loc.dir);
        }
    }
    Ok(summary)
}

/// A run is never saved for an environment removed while it was analyzed
/// ([`crate::env_remove`]); one saved in the moment between this check and
/// the save is listed nowhere and joins the removed environment later.
fn env_still_there(ws: &Workspace) -> Result<(), String> {
    environments::still_listed(ws).map_err(|e| match e {
        environments::NotListed::Removed => {
            "The environment this run was going to was removed meanwhile, so the run wasn't saved."
                .to_string()
        }
        environments::NotListed::Unreadable(why) => why,
    })
}

/// Passes progress on, and keeps the comparison's warnings for the run.
struct KeepWarnings<'a, P> {
    inner: &'a mut P,
    warnings: Vec<String>,
}

impl<P: RecordProgress> RecordProgress for KeepWarnings<'_, P> {
    fn warn(&mut self, message: String) {
        self.warnings.push(message.clone());
        self.inner.warn(message);
    }
}

impl<P: RecordProgress> analyze::Progress for KeepWarnings<'_, P> {
    fn phase(&mut self, phase: Phase) {
        self.inner.phase(phase);
    }

    fn bytes(&mut self, read: u64, total: u64) {
        self.inner.bytes(read, total);
    }
}

// The earlier run this data is the same collection as: a (non-demo) UI run
/// of the same domains with the same collection time, or the history's last
/// run. Only collections whose file names carry the time can be told apart.
fn duplicate_of(
    ws: &Workspace,
    state_dir: Option<&std::path::Path>,
    ev: &analyze::Evaluated,
) -> Option<JobStatus> {
    let collected = ev.stats.collected_at?;
    let norm = |d: &[String]| {
        let mut a: Vec<String> = d.iter().map(|x| x.to_ascii_uppercase()).collect();
        a.sort();
        a.dedup();
        a
    };
    let domains = norm(&analyze::domain_names(&ev.graph));
    // Runs saved before trusted domains were left out list them too.
    let known = norm(&analyze::known_domain_names(&ev.graph));
    let same = |d: &[String], legacy: bool| {
        let d = norm(d);
        d == domains || (legacy && d == known)
    };
    if let Some(r) = ws.runs().into_iter().find(|r| {
        !r.demo
            && r.collected_at == Some(collected)
            && same(&r.domains, r.trusted_domains.is_none())
    }) {
        return Some(JobStatus::Duplicate {
            run: Some(r.id.clone()),
            at: r.created_at,
            what: format!("the run of {}", r.environment()),
        });
    }
    let loc = crate::history_ui::locate(ws, state_dir).ok()?;
    let last = pathwarden_core::store::last_run(&loc.store)?;
    let legacy = last.trusted_domains.is_none();
    (last.collected_at == Some(collected) && same(&last.domains, legacy)).then(|| {
        JobStatus::Duplicate {
            run: None,
            at: last.finished_at,
            what: "the run recorded in the history".into(),
        }
    })
}

/// An analysis's progress, into the job: the phase, and bytes read while
/// reading. It only goes forward: data read again (with the environment's
/// own settings, or after the demo's earlier runs) keeps the step shown.
struct JobProgress<'a> {
    jobs: &'a Jobs,
    id: &'a str,
    /// The furthest phase shown, by its place in [`Phase::ALL`].
    furthest: usize,
    /// Nothing is shown (the demo's earlier runs, [`crate::demo_runs`]).
    held: bool,
}

impl<'a> JobProgress<'a> {
    fn new(jobs: &'a Jobs, id: &'a str) -> Self {
        Self {
            jobs,
            id,
            furthest: 0,
            held: false,
        }
    }
}

impl pathwarden_core::record::RecordProgress for JobProgress<'_> {
    // The run keeps them ([`save_analysis`]).
    fn warn(&mut self, _message: String) {}
}

impl analyze::Progress for JobProgress<'_> {
    fn phase(&mut self, phase: Phase) {
        let at = Phase::ALL.iter().position(|&p| p == phase).unwrap_or(0);
        if self.held || at < self.furthest {
            return;
        }
        self.furthest = at;
        if phase != Phase::Reading {
            self.jobs.set_reading(self.id, None);
        }
        self.jobs.set(self.id, JobStatus::Running { phase });
    }

    fn bytes(&mut self, read: u64, total: u64) {
        if self.held || self.furthest > 0 {
            return;
        }
        self.jobs
            .set_reading(self.id, Some(ReadProgress { read, total }));
    }
}

/// Ingest errors in plain words, without the upload folder's path.
fn friendly_error(e: &IngestError, scratch: Option<&std::path::Path>) -> String {
    let text = match e {
        IngestError::Empty => {
            return "No collector files found. Use the .zip that SharpHound or RustHound-CE creates, or the .json files inside it.".into()
        }
        IngestError::Json { .. } => format!(
            "A file couldn't be read as collector data. Is it SharpHound or RustHound-CE output? ({e})"
        ),
        IngestError::Zip { .. } => {
            format!("A .zip file couldn't be opened. It may be damaged or not a zip. ({e})")
        }
        _ => e.to_string(),
    };
    match scratch {
        Some(dir) => strip_scratch(text, dir),
        None => text,
    }
}

/// [`friendly_error`] for a job: neither of its upload folders named.
fn spec_error(e: &IngestError, spec: &JobSpec) -> String {
    let text = friendly_error(e, spec.scratch.as_deref());
    match &spec.also_scratch {
        Some(dir) => strip_scratch(text, dir),
        None => text,
    }
}

/// Upload folders look like `uploads/<id>/<n>/<name>`: keep just `<name>`.
fn strip_scratch(mut t: String, dir: &std::path::Path) -> String {
    let seps = ['/', '\\'];
    for prefix in [
        dir.display().to_string(),
        dir.to_string_lossy().replace('\\', "/"),
    ] {
        if prefix.is_empty() {
            continue;
        }
        while let Some(at) = t.find(&prefix) {
            let after = at + prefix.len();
            let rest = &t[after..];
            let name = rest
                .trim_start_matches(seps)
                .trim_start_matches(|c: char| c.is_ascii_digit())
                .trim_start_matches(seps);
            let end = after + rest.len() - name.len();
            t.replace_range(at..end, "");
        }
    }
    t
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::path::Path;

    /// A change to make to a workspace's environments just before its next
    /// run is settled, by workspace folder.
    type Hook = (PathBuf, Box<dyn FnOnce() + Send>);
    static BEFORE_SETTLE: Mutex<Vec<Hook>> = Mutex::new(Vec::new());

    /// Runs the change set for the workspace at `root`, if any (the
    /// environments changing while the run was analyzed).
    pub(super) fn before_settle(root: &Path) {
        let hook = {
            let mut hooks = BEFORE_SETTLE.lock().unwrap_or_else(|e| e.into_inner());
            hooks
                .iter()
                .position(|(r, _)| r == root)
                .map(|i| hooks.remove(i).1)
        };
        if let Some(change) = hook {
            change();
        }
    }

    /// Runs `spec` as the server does and waits for it to stop.
    fn run(jobs: &Arc<Jobs>, ws: &Workspace, spec: JobSpec) -> JobStatus {
        let id = spec.id.clone();
        assert!(jobs.try_begin(&spec));
        spawn(jobs.clone(), ws.clone(), spec, false, true);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let status = jobs.get(&id).unwrap().status;
            if !status.is_active() {
                return status;
            }
            assert!(std::time::Instant::now() < deadline, "still running");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Environments changed between the decision and the registry's lock,
    /// so that something's off by then: the user is asked, as before the
    /// lock, and the upload is kept to save once they pick.
    #[test]
    fn environments_changing_under_the_lock_ask() {
        let root = std::env::temp_dir().join(format!("pw-jobs-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ws = Workspace::open(&root).unwrap();
        // The upload: ESSOS.LOCAL, which no environment has yet (a new one).
        let scratch = ws.uploads_dir().join("lock");
        std::fs::create_dir_all(&scratch).unwrap();
        let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/rusthound");
        let mut inputs = Vec::new();
        for f in [
            "20261011195626_essos-local_domains.json",
            "20261011195626_essos-local_users.json",
        ] {
            std::fs::copy(data.join(f), scratch.join(f)).unwrap();
            inputs.push(scratch.join(f));
        }
        let spec = |id: &str| JobSpec {
            id: id.into(),
            inputs: inputs.clone(),
            scratch: Some(scratch.clone()),
            also_scratch: None,
            source: "upload".into(),
            demo: false,
            env: None,
            new_env: None,
            env_auto: false,
            label: None,
            collection: None,
            timings: None,
            force: false,
        };
        // Meanwhile two environments came to list ESSOS.LOCAL.
        let r = root.clone();
        BEFORE_SETTLE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((
                root.clone(),
                Box::new(move || {
                    environments::Registry::update(&r, |reg| {
                        reg.create("GOAD lab", &["ESSOS.LOCAL".into()])?;
                        reg.create("Production", &["ESSOS.LOCAL".into()])
                    })
                    .unwrap();
                }),
            ));
        let jobs = Arc::new(Jobs::default());
        let id = crate::workspace::new_run_id(analyze::now());
        match run(&jobs, &ws, spec(&id)) {
            JobStatus::Ask { domains, reason } => {
                assert_eq!(domains, ["ESSOS.LOCAL"]);
                assert_eq!(reason, "ESSOS.LOCAL matches GOAD lab and Production.");
            }
            other => panic!("{other:?}"),
        }
        assert!(ws.all_runs().is_empty(), "nothing saved");
        assert!(inputs.iter().all(|f| f.is_file()), "the upload is kept");
        // The user picks; the kept upload is saved there.
        let mut picked = jobs.take_pending(&id).expect("kept until the user picks");
        picked.env = Some("goad-lab".into());
        let status = run(&jobs, &ws, picked);
        assert!(matches!(status, JobStatus::Done { .. }), "{status:?}");
        let saved = ws.all_runs();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].environment.as_deref(), Some("goad-lab"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn errors_hide_the_upload_folder() {
        let dir = std::path::Path::new("C:/ws/uploads/x");
        let e = IngestError::TooLarge {
            path: "C:/ws/uploads/x/0/big.zip!a.json".into(),
            detail: "huge".into(),
        };
        let msg = friendly_error(&e, Some(dir));
        assert!(msg.starts_with("big.zip!a.json is too large"), "{msg}");
    }
}
