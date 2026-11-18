//! Finding actions in a workspace: which run holds a finding, what applies
//! to it, and the request for one action. `pathwarden action` and the
//! app's action dialog call these same functions, so both offer the same
//! actions and send the same request
//! ([`pathwarden_core::actions`] holds the protocol and the runner).

use pathwarden_core::actions::{
    self, ActionRecord, Ask, Described, FindingContext, Offered, Prepared, Program,
};
use pathwarden_core::config::ActionConfig;
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

/// The records kept on finding `fingerprint`, newest first. None are kept
/// yet: saving what actions did (the history's `actions.json`) fills this
/// in, and everything that offers actions reads them from here.
pub fn records_for(_ws: &Workspace, _fingerprint: &str) -> Vec<ActionRecord> {
    Vec::new()
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
