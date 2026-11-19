//! Finding actions in a workspace: which run holds a finding, what applies
//! to it, the request for one action, and what actions did on it (the
//! history's `actions.json`, [`pathwarden_core::action_log`]).
//! `pathwarden action` and the app's action dialog call these same
//! functions, so both offer the same actions, send the same request and
//! save the same thing ([`pathwarden_core::actions`] holds the protocol
//! and the runner).

use pathwarden_core::action_log::{self, ActionsFile, Activity, Change};
use pathwarden_core::actions::{
    self, ActionRecord, Ask, Described, FindingContext, Offered, Outcome, Prepared, Program,
};
use pathwarden_core::config::ActionConfig;
use pathwarden_core::identity::Actor;
use serde_json::Value;

use crate::workspace::{RunSummary, Workspace};

/// The workspace's runs, newest first.
fn runs_newest_first(ws: &Workspace) -> Vec<RunSummary> {
    let mut runs = ws.runs();
    runs.sort_by(|a, b| b.order_key().cmp(&a.order_key()));
    runs
}

/// The findings of run `r` from its event document; `None` when it has
/// none this version reads. An open or held finding found fixed since
/// ([`fixed_since`]) stands as fixed: that is what an action is offered
/// on, and what it is told.
fn findings_of(ws: &Workspace, r: &RunSummary) -> Option<Vec<FindingContext>> {
    let dir = ws.run_dir(&r.id)?;
    let mut all = event_findings(&dir)?;
    let mine: Vec<&str> = all.iter().map(|f| f.fingerprint.as_str()).collect();
    let fixed = fixed_since(ws, r, &dir, &mine);
    for f in all.iter_mut() {
        if matches!(
            f.status,
            actions::FindingStatus::Open | actions::FindingStatus::Held
        ) && fixed.contains(&f.fingerprint)
        {
            f.status = actions::FindingStatus::Fixed;
            if let Some(o) = f.finding.as_object_mut() {
                o.insert("status".into(), Value::from("fixed"));
            }
        }
    }
    Some(all)
}

/// The findings of the event document in run folder `dir`.
fn event_findings(dir: &std::path::Path) -> Option<Vec<FindingContext>> {
    let text = crate::run_data::event_text(dir)?;
    let event: Value = serde_json::from_str(&text).ok()?;
    Some(actions::findings_in_event(&event))
}

/// The findings of run `r` (folder `dir`), `mine`, found fixed since it
/// ran: those whose latest targeted retest says fixed, and those the
/// newest later run that has an event document no longer has open,
/// accepted or held (fixed there, or fixed in a run between and gone
/// since), unless a later retest says otherwise.
fn fixed_since(
    ws: &Workspace,
    r: &RunSummary,
    dir: &std::path::Path,
    mine: &[&str],
) -> std::collections::HashSet<String> {
    use pathwarden_core::retest::Verdict;
    let mut latest: std::collections::HashMap<String, (i64, bool)> =
        std::collections::HashMap::new();
    for x in crate::retest_ui::load_log(dir).results {
        let e = latest.entry(x.fingerprint.clone()).or_insert((x.at, false));
        if x.at >= e.0 {
            *e = (x.at, x.verdict == Verdict::Fixed);
        }
    }
    let later = runs_newest_first(ws)
        .into_iter()
        .filter(|x| x.id != r.id && x.newer_than(r))
        .find_map(|x| {
            let found = ws.run_dir(&x.id).and_then(|d| event_findings(&d))?;
            Some((x, found))
        });
    if let Some((newest, found)) = later {
        let still: std::collections::HashSet<&str> = found
            .iter()
            .filter(|f| f.status != actions::FindingStatus::Fixed)
            .map(|f| f.fingerprint.as_str())
            .collect();
        for fp in mine {
            let fixed = !still.contains(fp);
            match latest.get(*fp) {
                Some((at, _)) if *at >= newest.created_at => {}
                _ => {
                    latest.insert(fp.to_string(), (newest.created_at, fixed));
                }
            }
        }
    }
    latest
        .into_iter()
        .filter(|(_, (_, fixed))| *fixed)
        .map(|(fp, _)| fp)
        .collect()
}

/// Finding `fingerprint` (any case) in run `run` (its folder ID or
/// recorded ID), or without one, in the newest run that has it: open,
/// accepted, fixed or held there.
pub fn find_finding(
    ws: &Workspace,
    run: Option<&str>,
    fingerprint: &str,
) -> Result<(RunSummary, FindingContext), String> {
    let fp = fingerprint.trim();
    let runs = runs_newest_first(ws);
    let find = |r: &RunSummary| {
        findings_of(ws, r)?
            .into_iter()
            .find(|f| f.fingerprint.eq_ignore_ascii_case(fp))
    };
    match run {
        Some(id) => {
            let r = runs
                .iter()
                .find(|r| r.id == id || crate::history_ui::recorded_id(r) == Some(id))
                .ok_or_else(|| {
                    format!(
                        "There is no run {id} with saved findings in environment {}.",
                        ws.env_name()
                    )
                })?;
            let f = find(r).ok_or_else(|| format!("{fp} is not a finding of run {id}."))?;
            Ok((r.clone(), f))
        }
        None => runs
            .iter()
            .find_map(|r| find(r).map(|f| (r.clone(), f)))
            .ok_or_else(|| {
                format!(
                    "No run of environment {} has the finding {fp}.",
                    ws.env_name()
                )
            }),
    }
}

/// The newest run with saved findings, and its findings in the event's
/// order (open and accepted, then fixed, then held).
pub fn latest_findings(ws: &Workspace) -> Option<(RunSummary, Vec<FindingContext>)> {
    runs_newest_first(ws)
        .into_iter()
        .find_map(|r| findings_of(ws, &r).map(|f| (r, f)))
}

/// What actions did, as the environment's run history holds it here (as
/// last pulled: nothing is fetched). Empty when there is no history yet;
/// the error says why it can't be read (one saved by a newer Pathwarden:
/// [`action_log::NEWER_WORDS`]).
pub fn log(ws: &Workspace) -> Result<ActionsFile, String> {
    let loc = crate::history_ui::locate(ws, None)?;
    if !loc.dir.is_dir() {
        return Ok(ActionsFile::default());
    }
    loc.store.check_expected().map_err(|e| format!("{e:#}"))?;
    action_log::load(&loc.store).map_err(|e| format!("{e:#}"))
}

/// The records kept on finding `fingerprint`, in the order they were made
/// (none when the history can't be read). Everything that offers actions
/// reads them from here.
pub fn records_for(ws: &Workspace, fingerprint: &str) -> Vec<ActionRecord> {
    log(ws).map(|l| l.records(fingerprint)).unwrap_or_default()
}

/// The activity on finding `fingerprint`, newest first (none when the
/// history can't be read).
pub fn activity_for(ws: &Workspace, fingerprint: &str) -> Vec<Activity> {
    log(ws).map(|l| l.activity(fingerprint)).unwrap_or_default()
}

/// Saves `change` in the environment's run history at once
/// ([`action_log::save`]): under its lock, after a pull, then committed and
/// pushed when it is in git. Notes for the user; the error says why it
/// wasn't saved.
pub fn save_change(ws: &Workspace, change: &Change) -> Result<Vec<String>, String> {
    save_change_reporting(ws, change).map(|s| s.notes)
}

/// [`save_change`], saying whether it reached the run history
/// ([`action_log::Saved::pushed`]).
pub fn save_change_reporting(ws: &Workspace, change: &Change) -> Result<action_log::Saved, String> {
    let config = ws.config().map_err(|e| format!("{e:#}"))?;
    let loc = crate::history_ui::locate_with(ws, None, &config)?;
    if !loc.records() {
        return Err(
            "This computer only reads the run history ([state] push = false), so this isn't saved there."
                .into(),
        );
    }
    let _lock = loc
        .store
        .lock_waiting(pathwarden_core::settings_sync::lock_wait())
        .map_err(|e| format!("{e:#}"))?;
    let pulled = loc
        .store
        .pull()
        .map_err(|e| format!("Couldn't get the latest history: {e:#}"))?;
    let saved =
        action_log::save_reporting(&loc.store, change, loc.push).map_err(|e| format!("{e:#}"))?;
    Ok(action_log::Saved {
        notes: pulled.into_iter().chain(saved.notes).collect(),
        pushed: saved.pushed,
    })
}

/// What saving a run's outcome did ([`save_outcome`]).
#[derive(Debug, Default)]
pub struct SavedOutcome {
    /// Whether it was saved (a dry run isn't).
    pub saved: bool,
    /// Notes for the user (a push that failed with it committed here).
    pub notes: Vec<String>,
    /// In the run history for everyone; false when kept on this computer
    /// for the next sync.
    pub pushed: bool,
    /// The activity entry's time (`at`), when one was saved.
    pub at: Option<String>,
}

/// Saves what a run of `ready`'s action did on its finding, at once: an
/// entry of activity, and the records it made or changed
/// ([`action_log::run_change`]). A dry run saves nothing.
pub fn save_outcome(
    ws: &Workspace,
    ready: &Ready,
    outcome: &Outcome,
) -> Result<SavedOutcome, String> {
    let current = log(ws)?;
    let fp = &ready.finding.fingerprint;
    let o = &ready.prepared.offered;
    let at = action_log::now_at();
    let Some(change) = action_log::run_change(
        current.findings.get(fp),
        fp,
        &o.address,
        &o.def.label,
        ready.prepared.record.as_ref(),
        outcome,
        crate::history_ui::recorded_id(&ready.run).or(Some(ready.run.id.as_str())),
        &Actor::current(),
        &at,
    ) else {
        return Ok(SavedOutcome::default());
    };
    let s = save_change_reporting(ws, &change)?;
    Ok(SavedOutcome {
        saved: true,
        notes: s.notes,
        pushed: s.pushed,
        at: Some(at),
    })
}

/// [`save_outcome`] for a run someone stopped (Ctrl-C, Cancel): one quick
/// try without the network ([`action_log::save_here`]): under the lock if
/// it is free at once, and in git kept on this computer for the next pull
/// and push. A dry run saves nothing.
pub fn save_outcome_quick(
    ws: &Workspace,
    ready: &Ready,
    outcome: &Outcome,
) -> Result<SavedOutcome, String> {
    let config = ws.config().map_err(|e| format!("{e:#}"))?;
    let loc = crate::history_ui::locate_with(ws, None, &config)?;
    if !loc.records() {
        return Err(
            "This computer only reads the run history ([state] push = false), so this isn't saved there."
                .into(),
        );
    }
    let current = log(ws).unwrap_or_default();
    let fp = &ready.finding.fingerprint;
    let o = &ready.prepared.offered;
    let at = action_log::now_at();
    let Some(change) = action_log::run_change(
        current.findings.get(fp),
        fp,
        &o.address,
        &o.def.label,
        ready.prepared.record.as_ref(),
        outcome,
        crate::history_ui::recorded_id(&ready.run).or(Some(ready.run.id.as_str())),
        &Actor::current(),
        &at,
    ) else {
        return Ok(SavedOutcome::default());
    };
    let lock = loc.store.lock().ok();
    let notes =
        action_log::save_here(&loc.store, &change, lock.is_some()).map_err(|e| format!("{e:#}"))?;
    Ok(SavedOutcome {
        saved: true,
        notes,
        pushed: !loc.store.is_git(),
        at: Some(at),
    })
}

/// Removes record `record_id` from finding `fingerprint` (any case), and
/// logs it: what `pathwarden action records remove` and the app's Remove
/// do. Returns the record removed and notes for the user.
pub fn remove_record(
    ws: &Workspace,
    fingerprint: &str,
    record_id: &str,
) -> Result<(ActionRecord, Vec<String>), String> {
    let current = log(ws)?;
    let fp = current
        .findings
        .keys()
        .find(|k| k.eq_ignore_ascii_case(fingerprint.trim()))
        .cloned()
        .ok_or_else(|| format!("{} has no records.", fingerprint.trim()))?;
    let records = current.records(&fp);
    let r = actions::find_record(&records, record_id)?.clone();
    let change = action_log::remove_change(&fp, &r, &Actor::current(), &action_log::now_at());
    let notes = save_change(ws, &change)?;
    Ok((r, notes))
}

/// Every `[[action]]` block described ([`described`]), in config order.
#[derive(Default)]
pub struct Blocks {
    /// The blocks whose program said what it offers.
    pub ok: Vec<(ActionConfig, Described)>,
    /// The others: name, and why not.
    pub failed: Vec<(String, String)>,
}

impl Blocks {
    /// The programs, as [`actions::offered`] takes them.
    pub fn programs(&self) -> Vec<Program<'_>> {
        self.ok
            .iter()
            .map(|(config, d)| Program {
                config,
                describe: &d.describe,
            })
            .collect()
    }
}

/// Asks every `[[action]]` block's program what it offers (kept in memory
/// while the program and settings stay the same).
pub fn described(actions: &[ActionConfig]) -> Blocks {
    let mut b = Blocks::default();
    for (a, d) in actions::describe_all(actions) {
        match d {
            Ok(d) => b.ok.push((a.clone(), d)),
            Err(e) => b.failed.push((a.name.clone(), e.to_string())),
        }
    }
    b
}

/// What applies to one finding of a run.
pub struct OnFinding {
    pub run: RunSummary,
    pub finding: FindingContext,
    pub offered: Vec<Offered>,
    /// Blocks whose program couldn't say what it offers: name, why.
    pub failed: Vec<(String, String)>,
}

/// The actions offered on finding `fingerprint` ([`find_finding`]), in
/// config order.
pub fn offered_on(
    ws: &Workspace,
    actions: &[ActionConfig],
    run: Option<&str>,
    fingerprint: &str,
) -> Result<OnFinding, String> {
    if pathwarden_core::store::unattended() {
        return Err(actions::ActionError::Unattended.to_string());
    }
    let (run, finding) = find_finding(ws, run, fingerprint)?;
    let blocks = described(actions);
    let records = records_for(ws, &finding.fingerprint);
    let offered = actions::offered(&blocks.programs(), &finding, &records);
    Ok(OnFinding {
        run,
        finding,
        offered,
        failed: blocks.failed,
    })
}

/// A run of an action, ready to start ([`actions::run`]).
pub struct Ready {
    pub run: RunSummary,
    pub finding: FindingContext,
    pub prepared: Prepared,
}

/// Finds the finding, describes the blocks, picks the action `ask` names
/// and builds its request ([`actions::prepare`]). When the action named
/// is of a block whose program couldn't say what it offers, that is the
/// error.
pub fn prepare(
    ws: &Workspace,
    actions: &[ActionConfig],
    run: Option<&str>,
    fingerprint: &str,
    ask: &Ask,
) -> Result<Ready, String> {
    if pathwarden_core::store::unattended() {
        return Err(actions::ActionError::Unattended.to_string());
    }
    if actions.is_empty() {
        return Err("No finding actions are set up.".into());
    }
    let (run, finding) = find_finding(ws, run, fingerprint)?;
    let blocks = described(actions);
    let failed = &blocks.failed;
    let records = records_for(ws, &finding.fingerprint);
    let programs = blocks.programs();
    let prepared = actions::prepare(&programs, &finding, &records, ask).map_err(|e| {
        // The block named didn't describe: say why.
        let name = ask
            .action
            .as_deref()
            .map(|a| a.split('/').next().unwrap_or(a).trim().to_ascii_lowercase());
        name.and_then(|n| {
            failed
                .iter()
                .find(|(f, _)| f.eq_ignore_ascii_case(&n))
                .map(|(_, why)| why.clone())
        })
        .or_else(|| {
            (programs.is_empty() && !failed.is_empty()).then(|| {
                failed
                    .iter()
                    .map(|(_, why)| why.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
        })
        .unwrap_or(e)
    })?;
    Ok(Ready {
        run,
        finding,
        prepared,
    })
}

/// Whether the environment's encrypted history holds a plain actions.json,
/// which is never read ([`action_log::plain_left`]): the command line says
/// [`action_log::PLAIN_LEFT_WORDS`], a page
/// [`action_log::PLAIN_LEFT_PAGE_WORDS`].
pub fn plain_left(ws: &Workspace) -> bool {
    crate::history_ui::locate(ws, None).is_ok_and(|l| action_log::plain_left(&l.store))
}

/// What a plain actions.json in the environment's encrypted history holds
/// (its `newest` latest entries), for someone deciding whether to import
/// it; `None` when there is none.
///
/// The history is pulled first (under its lock), so what is shown is what
/// the repository holds; [`import_plain`] then imports only those same
/// bytes ([`action_log::Summary::hash`]).
pub fn plain_summary(ws: &Workspace, newest: usize) -> Result<Option<action_log::Summary>, String> {
    let loc = crate::history_ui::locate(ws, None)?;
    {
        let _lock = loc
            .store
            .lock_waiting(pathwarden_core::settings_sync::lock_wait())
            .map_err(|e| format!("{e:#}"))?;
        loc.store
            .pull()
            .map_err(|e| format!("Couldn't get the latest history: {e:#}"))?;
    }
    Ok(action_log::read_plain(&loc.store)
        .map_err(|e| format!("{e:#}"))?
        .map(|(f, hash)| action_log::Summary {
            hash,
            ..f.summary(newest)
        }))
}

/// Imports a plain actions.json into the environment's encrypted history
/// ([`action_log::import_plain`]): under its lock, after a pull, in one
/// commit pushed when it is in git. Notes for the user.
pub fn import_plain(ws: &Workspace, shown: &str) -> Result<Vec<String>, String> {
    let config = ws.config().map_err(|e| format!("{e:#}"))?;
    let loc = crate::history_ui::locate_with(ws, None, &config)?;
    let _lock = loc
        .store
        .lock_waiting(pathwarden_core::settings_sync::lock_wait())
        .map_err(|e| format!("{e:#}"))?;
    let pulled = loc
        .store
        .pull()
        .map_err(|e| format!("Couldn't get the latest history: {e:#}"))?;
    let notes =
        action_log::import_plain(&loc.store, loc.push, shown).map_err(|e| format!("{e:#}"))?;
    Ok(pulled.into_iter().chain(notes).collect())
}

/// What a page shows of finding actions on one finding (the report's
/// `report_meta`, the Activity list): the actions offered on it, its
/// records with their chips and follow-ups, and its activity, newest
/// first, each with its line. Built from the history's file read once
/// ([`log`]) and the described blocks ([`Blocks::programs`]).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FindingView {
    /// The actions offered on it, as `<name>/<id>`, in config order.
    pub offered: Vec<String>,
    pub records: Vec<RecordView>,
    /// The latest [`action_log::REPORT_ACTIVITY`], newest first.
    pub activity: Vec<ActivityView>,
    /// How many entries it keeps in all.
    pub activity_count: usize,
}

/// A record on a finding, for a page.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecordView {
    #[serde(flatten)]
    pub record: ActionRecord,
    /// "RITM0001234 · Open", or on a fixed finding whose record is still
    /// open "Fixed — RITM0001234 still Open" ([`action_log::chip`]).
    pub chip: String,
    /// The follow-ups offered on it, as `<name>/<id>`.
    pub follow_ups: Vec<String>,
}

/// An entry of activity, for a page.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActivityView {
    #[serde(flatten)]
    pub entry: Activity,
    /// "Opened RITM0001234 — CORP\a.admin, SECOPS-WS02, Nov 18,
    /// 2026, 2:02 PM" ([`Activity::line`]).
    pub line: String,
    /// What happened, in a few words ([`Activity::summary`]): a page
    /// writes who and when itself, in its own date format.
    pub summary: String,
    /// When, as Unix time, for the page's date format.
    pub at_unix: Option<i64>,
    /// Its log on this computer ([`with_logs`]), for Open log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
}

/// `v` (finding `fingerprint`'s) with each failed activity entry's log on
/// this computer, from the logs folder `logs`
/// ([`pathwarden_core::logs::note_action`]).
pub fn with_logs(
    v: &mut FindingView,
    fingerprint: &str,
    logs: &std::collections::HashMap<(String, String), String>,
) {
    for a in v.activity.iter_mut().filter(|a| !a.entry.ok) {
        a.log = logs
            .get(&(fingerprint.to_string(), a.entry.at.clone()))
            .cloned();
    }
}

/// The logs of the activity entries in the logs folder `logs`.
fn action_logs(
    logs: Option<&std::path::Path>,
) -> std::collections::HashMap<(String, String), String> {
    logs.map(pathwarden_core::logs::action_logs)
        .unwrap_or_default()
}

/// Whether action `def` is meant for a fixed finding: its `when` lists
/// `fixed` (a follow-up such as Close request).
pub fn for_fixed(def: &actions::ActionDef) -> bool {
    def.when
        .as_ref()
        .is_some_and(|w| w.contains(&actions::FindingStatus::Fixed))
}

/// [`FindingView`] of finding `f`. On a fixed finding, the follow-ups
/// meant for a fixed one (`when: fixed`, such as Close request) come
/// first.
pub fn view(file: &ActionsFile, programs: &[Program], f: &FindingContext) -> FindingView {
    let records = file.records(&f.fingerprint);
    let activity = file.activity(&f.fingerprint);
    let fixed = f.status == actions::FindingStatus::Fixed;
    FindingView {
        offered: actions::offered(programs, f, &records)
            .into_iter()
            .map(|o| o.address)
            .collect(),
        records: records
            .iter()
            .map(|r| {
                let mut follow = actions::follow_ups(programs, f, r);
                if fixed {
                    // Stable: the program's order otherwise.
                    follow.sort_by_key(|o| !for_fixed(&o.def));
                }
                RecordView {
                    chip: action_log::chip(&r.record, fixed),
                    follow_ups: follow.into_iter().map(|o| o.address).collect(),
                    record: r.clone(),
                }
            })
            .collect(),
        activity_count: activity.len(),
        activity: activity
            .into_iter()
            .take(action_log::REPORT_ACTIVITY)
            .map(|e| ActivityView {
                line: e.line(),
                summary: e.summary(),
                at_unix: pathwarden_core::time::parse_rfc3339(&e.at),
                log: None,
                entry: e,
            })
            .collect(),
    }
}

/// What a page says once a run's outcome was saved on the finding, for
/// everyone who shares the run history.
pub const SAVED_PAGE_WORDS: &str = "Saved on this finding for everyone on this history.";
/// What a page says when it was saved on this computer only, for now
/// ([`SavedOutcome::pushed`] false).
pub const SAVED_HERE_PAGE_WORDS: &str =
    "Saved on this computer, not shared yet: the next sync shares it.";
/// What a page says of a dry run.
pub const DRY_RUN_PAGE_WORDS: &str = "A test: nothing was sent for real or saved.";

/// What a run of `ready`'s action did, as `pathwarden action run --json`
/// prints it and the app's result card reads it: the outcome, which
/// action on which finding of which run, and whether it was saved (a dry
/// run isn't) and shared (`pushed`). `notes` are what the save said.
pub fn outcome_json(
    ready: &Ready,
    out: &Outcome,
    saved: Option<&Result<SavedOutcome, String>>,
) -> Value {
    let mut v = serde_json::to_value(out).unwrap_or_default();
    v["action"] = Value::from(ready.prepared.offered.address.clone());
    v["label"] = Value::from(ready.prepared.offered.def.label.clone());
    v["fingerprint"] = Value::from(ready.finding.fingerprint.clone());
    v["run"] = Value::from(ready.run.id.clone());
    v["record"] = ready
        .prepared
        .record
        .as_ref()
        .map_or(Value::Null, |r| Value::from(r.record.id.clone()));
    let ok_saved = saved.and_then(|s| s.as_ref().ok());
    v["saved"] = Value::from(ok_saved.is_some_and(|s| s.saved));
    v["pushed"] = Value::from(ok_saved.is_some_and(|s| s.saved && s.pushed));
    v["notes"] = Value::from(ok_saved.map(|s| s.notes.clone()).unwrap_or_default());
    v["not_saved"] = saved
        .and_then(|s| s.as_ref().err())
        .map_or(Value::Null, |e| Value::from(e.clone()));
    v
}

/// Runs a prepared action and saves what it did ([`save_outcome`]; for a
/// run someone stopped, [`save_outcome_quick`], so Cancel stays quick):
/// what the app's job does with the program's lines going to `on_line`.
/// `Err` when the program couldn't start.
pub fn run_and_save(
    ws: &Workspace,
    ready: &Ready,
    on_line: &mut dyn FnMut(&str),
    cancel: &actions::CancelHandle,
) -> Result<(Outcome, Option<Result<SavedOutcome, String>>), String> {
    let out = actions::run(
        &ready.prepared.config,
        &ready.prepared.request,
        on_line,
        cancel,
    )
    .map_err(|e| e.to_string())?;
    let saved = if out.dry_run {
        None
    } else if out.ended == actions::Ended::Cancelled {
        Some(save_outcome_quick(ws, ready, &out))
    } else {
        Some(save_outcome(ws, ready, &out))
    };
    Ok((out, saved))
}

/// A test of block `name` ([`actions::Ask::dry_run`]): its action `action`
/// (its ID; else the first that applies) on the first finding of the
/// latest run it applies to, with the inputs' defaults. What `pathwarden
/// action test` and the app's Test run. The error says why in words.
pub fn test_target(
    ws: &Workspace,
    blocks: &[ActionConfig],
    name: &str,
    action: Option<&str>,
) -> Result<Ready, String> {
    if pathwarden_core::store::unattended() {
        return Err(actions::ActionError::Unattended.to_string());
    }
    let block = blocks
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(name.trim()))
        .ok_or_else(|| format!("There is no finding action {}.", name.trim()))?;
    let described = actions::describe(block).map_err(|e| e.to_string())?;
    let Some((run, findings)) = latest_findings(ws) else {
        return Err(
            "Testing needs one analysis first. Analyze a collection or try the demo.".into(),
        );
    };
    let programs = [Program {
        config: block,
        describe: &described.describe,
    }];
    let wanted = |o: &Offered| action.is_none_or(|id| o.id.eq_ignore_ascii_case(id.trim()));
    let log = log(ws).unwrap_or_default();
    let Some((finding, offered)) = findings.iter().find_map(|f| {
        let records = log.records(&f.fingerprint);
        actions::offered(&programs, f, &records)
            .into_iter()
            .find(|o| wanted(o))
            .map(|o| (f, o))
    }) else {
        return Err(format!(
            "{} applies to no finding of the latest run ({}).",
            match action {
                Some(id) => format!("{}/{}", block.name, id.trim()),
                None => block.name.clone(),
            },
            run.id
        ));
    };
    let ask = Ask {
        action: Some(offered.address.clone()),
        inputs: serde_json::Map::new(),
        dry_run: true,
        record: None,
    };
    prepare(ws, blocks, Some(&run.id), &finding.fingerprint, &ask)
}

/// An action as a page shows it: its button's label, its dialog, and
/// whether it runs on a record or is meant for a fixed finding.
fn act_json(o: &Offered) -> Value {
    let d = &o.def;
    serde_json::json!({
        "label": d.label,
        "description": d.description,
        "sends": d.sends,
        "inputs": d.inputs,
        "once": d.once,
        "record": d.for_ == Some(actions::For::Record),
        "fixed": for_fixed(d),
    })
}

/// What the run page and its report show of finding actions for run `r`
/// ([`FindingView`] per finding): `acts`, every action offered here by
/// address (its label, description, what it sends, its inputs), and `f`,
/// per finding with actions offered, records or activity, its title,
/// where it stands and its view. `None` when the run has no findings this
/// version reads. Built from the history's file read once and the blocks
/// described once.
/// `logs`: the logs folder, for each failed entry's Open log.
pub fn page_data(
    ws: &Workspace,
    blocks: &Blocks,
    r: &RunSummary,
    logs: Option<&std::path::Path>,
) -> Option<Value> {
    let findings = findings_of(ws, r)?;
    let file = log(ws).unwrap_or_default();
    let logs = action_logs(logs);
    let programs = blocks.programs();
    let mut acts = serde_json::Map::new();
    let mut f = serde_json::Map::new();
    for p in &programs {
        for def in &p.describe.actions {
            let o = Offered {
                name: p.config.name.clone(),
                id: def.id.clone(),
                address: format!("{}/{}", p.config.name, def.id),
                def: def.clone(),
            };
            acts.insert(o.address.clone(), act_json(&o));
        }
    }
    for c in &findings {
        let mut v = view(&file, &programs, c);
        with_logs(&mut v, &c.fingerprint, &logs);
        if v.offered.is_empty() && v.records.is_empty() && v.activity.is_empty() {
            continue;
        }
        f.insert(
            c.fingerprint.clone(),
            serde_json::json!({
                "title": c.title,
                "status": c.status,
                "view": v,
            }),
        );
    }
    Some(serde_json::json!({ "acts": acts, "f": f }))
}

/// [`FindingView`] of finding `fingerprint` in run `run` now, for a page
/// to show after an action ran on it. `None` when it can't be read.
pub fn view_now(
    ws: &Workspace,
    actions: &[ActionConfig],
    run: &str,
    fingerprint: &str,
    logs: Option<&std::path::Path>,
) -> Option<FindingView> {
    let (_, finding) = find_finding(ws, Some(run), fingerprint).ok()?;
    let blocks = described(actions);
    let file = log(ws).unwrap_or_default();
    let mut v = view(&file, &blocks.programs(), &finding);
    with_logs(&mut v, &finding.fingerprint, &action_logs(logs));
    Some(v)
}

#[cfg(test)]
#[path = "actions_ui_tests.rs"]
mod tests;
