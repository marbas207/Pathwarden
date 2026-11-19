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
/// none this version reads.
fn findings_of(ws: &Workspace, r: &RunSummary) -> Option<Vec<FindingContext>> {
    let dir = ws.run_dir(&r.id)?;
    let text = crate::run_data::event_text(&dir)?;
    let event: Value = serde_json::from_str(&text).ok()?;
    Some(actions::findings_in_event(&event))
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
    let notes = action_log::save(&loc.store, change, loc.push).map_err(|e| format!("{e:#}"))?;
    Ok(pulled.into_iter().chain(notes).collect())
}

/// What saving a run's outcome did ([`save_outcome`]).
#[derive(Debug, Default)]
pub struct SavedOutcome {
    /// Whether it was saved (a dry run isn't).
    pub saved: bool,
    /// Notes for the user (a push that failed with it committed here).
    pub notes: Vec<String>,
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
    let Some(change) = action_log::run_change(
        current.findings.get(fp),
        fp,
        &o.address,
        &o.def.label,
        ready.prepared.record.as_ref(),
        outcome,
        crate::history_ui::recorded_id(&ready.run).or(Some(ready.run.id.as_str())),
        &Actor::current(),
        &action_log::now_at(),
    ) else {
        return Ok(SavedOutcome::default());
    };
    let notes = save_change(ws, &change)?;
    Ok(SavedOutcome { saved: true, notes })
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
    let Some(change) = action_log::run_change(
        current.findings.get(fp),
        fp,
        &o.address,
        &o.def.label,
        ready.prepared.record.as_ref(),
        outcome,
        crate::history_ui::recorded_id(&ready.run).or(Some(ready.run.id.as_str())),
        &Actor::current(),
        &action_log::now_at(),
    ) else {
        return Ok(SavedOutcome::default());
    };
    let lock = loc.store.lock().ok();
    let notes =
        action_log::save_here(&loc.store, &change, lock.is_some()).map_err(|e| format!("{e:#}"))?;
    Ok(SavedOutcome { saved: true, notes })
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
    /// "RITM10816190 · Open", or on a fixed finding whose record is still
    /// open "Fixed — RITM10816190 still Open" ([`action_log::chip`]).
    pub chip: String,
    /// The follow-ups offered on it, as `<name>/<id>`.
    pub follow_ups: Vec<String>,
}

/// An entry of activity, for a page.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActivityView {
    #[serde(flatten)]
    pub entry: Activity,
    /// "Opened RITM10816190 — NORTH\eddard.stark, SECOPS-WS02, Nov 18,
    /// 2026, 2:02 PM" ([`Activity::line`]).
    pub line: String,
}

/// [`FindingView`] of finding `f`.
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
            .map(|r| RecordView {
                chip: action_log::chip(&r.record, fixed),
                follow_ups: actions::follow_ups(programs, f, r)
                    .into_iter()
                    .map(|o| o.address)
                    .collect(),
                record: r.clone(),
            })
            .collect(),
        activity_count: activity.len(),
        activity: activity
            .into_iter()
            .take(action_log::REPORT_ACTIVITY)
            .map(|e| ActivityView {
                line: e.line(),
                entry: e,
            })
            .collect(),
    }
}

#[cfg(test)]
#[path = "actions_ui_tests.rs"]
mod tests;
