//! What finding actions did, kept on each finding in the history's
//! `actions.json` (docs/dev/formats.md), so everyone on the same history
//! sees it: every run of an action (its activity) and what the runs
//! created or look after (its records, such as a ticket).
//!
//! `{"version":1,"findings":{<fingerprint>:{"activity":[…],"records":[…]}}}`.
//! It is a file of its own because `findings.json` is rebuilt every run.
//! It is one of the history's state files ([`crate::store`]), so it is
//! encrypted and pushed with the rest. Dry runs aren't kept; the latest
//! [`MAX_ACTIVITY`] runs of a finding are. A record stays until someone
//! removes it, and the removal is itself activity.
//!
//! A change is saved as soon as an action finishes ([`save`]). When
//! another computer pushed first, the change is made again on what it
//! left: finding by finding, activity is the union of both sides (one
//! entry per `at`, `by` and `action`), and records are matched by
//! `action` and `id`, the newer `updated_at` winning ([`merge`]).
//!
//! A file from a newer Pathwarden (a higher `version`) is neither read nor
//! written over ([`NEWER_WORDS`]).

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::actions::{ActionRecord, Outcome, Record};
use crate::identity::Actor;
use crate::store::{KeptUnpushed, Store};

/// The file's name in the history.
pub const FILE: &str = "actions.json";
/// The version this Pathwarden reads and writes.
pub const VERSION: u32 = 1;
/// Most activity entries kept on one finding: the latest.
pub const MAX_ACTIVITY: usize = 100;
/// Most activity entries a finding's `actions` carries for the report
/// ([`FindingActions::activity`]), newest first.
pub const REPORT_ACTIVITY: usize = 20;
/// The commit message of a change (fixed: it names no finding or person).
pub const MESSAGE: &str = "pathwarden: save what a finding action did";
/// What is said when the history's file was saved by a newer Pathwarden.
pub const NEWER_WORDS: &str = "The history's actions.json was saved by a newer Pathwarden, so \
what actions do can't be saved here. Update Pathwarden to save it.";

/// The whole file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionsFile {
    pub version: u32,
    /// By fingerprint.
    #[serde(default)]
    pub findings: BTreeMap<String, FindingLog>,
    /// Fields a later release of version 1 added, kept as they are.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

impl Default for ActionsFile {
    fn default() -> Self {
        ActionsFile {
            version: VERSION,
            findings: BTreeMap::new(),
            other: BTreeMap::new(),
        }
    }
}

/// What actions did on one finding.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FindingLog {
    /// Oldest first.
    #[serde(default)]
    pub activity: Vec<Activity>,
    /// In the order they were first made.
    #[serde(default)]
    pub records: Vec<ActionRecord>,
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

/// What an entry of activity was.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A run of an action (written as no `kind` at all).
    #[default]
    Run,
    /// Someone removed a record.
    Remove,
}

impl Kind {
    fn is_run(&self) -> bool {
        *self == Kind::Run
    }
}

/// One run of an action on a finding, or the removal of a record.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Activity {
    /// RFC 3339, UTC, with milliseconds.
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<String>,
    /// The run the finding was in when the action ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// `<name>/<id>`; for a removal, the action that made the record.
    pub action: String,
    /// The action's label then ("Open a service request").
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub ok: bool,
    /// The result's message, or what went wrong.
    #[serde(default)]
    pub message: String,
    /// The records it made, changed or removed.
    #[serde(default)]
    pub record_ids: Vec<String>,
    /// Always false: dry runs aren't kept.
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default, skip_serializing_if = "Kind::is_run")]
    pub kind: Kind,
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

impl Activity {
    /// What happened, in a few words: the message's first line for a run
    /// that worked ("Opened RITM10816190"), the label and what went wrong
    /// for one that didn't, "Removed RITM10816190" for a removal.
    pub fn summary(&self) -> String {
        let first = |s: &str| {
            let line = s.lines().next().unwrap_or_default().trim();
            crate::actions::clean_text(line.trim_end_matches('.'), 160, false).0
        };
        match self.kind {
            Kind::Remove => format!(
                "Removed {}",
                if self.message.is_empty() {
                    self.record_ids.join(", ")
                } else {
                    first(&self.message)
                }
            ),
            Kind::Run if self.ok && !self.message.trim().is_empty() => first(&self.message),
            Kind::Run if self.ok => self.label.clone(),
            Kind::Run if self.message.trim().is_empty() => format!("{} failed", self.label),
            Kind::Run => format!("{} failed: {}", self.label, first(&self.message)),
        }
    }

    /// Who, where and when: "NORTH\eddard.stark, SECOPS-WS02, Nov 18,
    /// 2026, 2:02 PM" (this computer's time), with the parts that are
    /// known.
    pub fn who_when(&self) -> String {
        let when = crate::time::parse_rfc3339(&self.at)
            .map(crate::time::format_local)
            .unwrap_or_else(|| self.at.clone());
        [self.by.clone(), self.on.clone(), Some(when)]
            .into_iter()
            .flatten()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The line people read: "Opened RITM10816190 — NORTH\eddard.stark,
    /// SECOPS-WS02, Nov 18, 2026, 2:02 PM".
    pub fn line(&self) -> String {
        format!("{} — {}", self.summary(), self.who_when())
    }

    /// What tells two entries apart when two histories are merged.
    fn key(&self) -> (&str, Option<&str>, &str) {
        (&self.at, self.by.as_deref(), &self.action)
    }
}

/// The text of a record's chip: "RITM10816190 · Open"; on a fixed finding
/// whose record is still open, "Fixed — RITM10816190 still Open".
pub fn chip(r: &Record, fixed: bool) -> String {
    let name = r
        .number
        .as_deref()
        .or(r.label.as_deref())
        .filter(|s| !s.is_empty())
        .unwrap_or(&r.id);
    let status = r
        .status
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(if r.open { "Open" } else { "Closed" });
    if fixed && r.open {
        format!("Fixed — {name} still {status}")
    } else {
        format!("{name} · {status}")
    }
}

/// What a finding (in the event, `findings --json`, the exports and the
/// report) carries of what actions did: its records, and how many entries
/// of activity it has.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FindingActions {
    pub records: Vec<ActionRecord>,
    pub activity_count: usize,
    /// The latest [`REPORT_ACTIVITY`] entries, newest first, for the
    /// report: not in the event.
    #[serde(skip)]
    pub activity: Vec<Activity>,
}

impl ActionsFile {
    /// What finding `fingerprint` carries ([`FindingActions`]); `None`
    /// when actions did nothing on it.
    pub fn for_finding(&self, fingerprint: &str) -> Option<FindingActions> {
        let log = self.findings.get(fingerprint)?;
        if log.records.is_empty() && log.activity.is_empty() {
            return None;
        }
        Some(FindingActions {
            records: log.records.clone(),
            activity_count: log.activity.len(),
            activity: log
                .activity
                .iter()
                .rev()
                .take(REPORT_ACTIVITY)
                .cloned()
                .collect(),
        })
    }

    /// Finding `fingerprint`'s records, in the order they were first made.
    pub fn records(&self, fingerprint: &str) -> Vec<ActionRecord> {
        self.findings
            .get(fingerprint)
            .map(|l| l.records.clone())
            .unwrap_or_default()
    }

    /// Finding `fingerprint`'s activity, newest first.
    pub fn activity(&self, fingerprint: &str) -> Vec<Activity> {
        self.findings
            .get(fingerprint)
            .map(|l| l.activity.iter().rev().cloned().collect())
            .unwrap_or_default()
    }

    /// The text written to the history.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text.into_bytes()
    }
}

/// Why the file can't be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    /// Saved by a newer Pathwarden.
    #[error("{NEWER_WORDS}")]
    Newer(u64),
    /// Not a file this version can read.
    #[error("The history's actions.json can't be read: {0}")]
    Damaged(String),
}

/// Reads the file's text. A file without `version` is version 1.
pub fn parse(bytes: &[u8]) -> Result<ActionsFile, LogError> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let v: Value = serde_json::from_slice(bytes).map_err(|e| LogError::Damaged(e.to_string()))?;
    let Some(o) = v.as_object() else {
        return Err(LogError::Damaged("it isn't a JSON object".into()));
    };
    match o.get("version") {
        None | Some(Value::Null) => {}
        Some(n) => match n.as_u64() {
            Some(n) if n > u64::from(VERSION) => return Err(LogError::Newer(n)),
            Some(n) if n >= 1 => {}
            _ => return Err(LogError::Damaged(format!("version {n} isn't a version"))),
        },
    }
    let mut v = v;
    if v.get("version").is_none_or(Value::is_null) {
        v["version"] = Value::from(VERSION);
    }
    serde_json::from_value(v).map_err(|e| LogError::Damaged(e.to_string()))
}

/// The history's file; an empty one when there is none yet.
pub fn load(store: &Store) -> Result<ActionsFile> {
    match store.read_state_file(FILE)? {
        None => Ok(ActionsFile::default()),
        Some(bytes) => Ok(parse(&bytes)?),
    }
}

// ------------------------------------------------------------- merging

/// Adds `entry` to `log`'s activity unless an entry with its `at`, `by`
/// and `action` is there; keeps the activity oldest first, and only the
/// latest [`MAX_ACTIVITY`].
fn add_activity(log: &mut FindingLog, entry: &Activity) {
    if log.activity.iter().any(|a| a.key() == entry.key()) {
        return;
    }
    log.activity.push(entry.clone());
    log.activity.sort_by(|a, b| a.at.cmp(&b.at));
    let over = log.activity.len().saturating_sub(MAX_ACTIVITY);
    log.activity.drain(..over);
}

/// Puts `r` in `log`'s records: a record of the same `action` and `id`
/// is replaced when `r` changed later (`updated_at`), keeping when and by
/// whom the record was first made; else `r` is added.
fn put_record(log: &mut FindingLog, r: &ActionRecord) {
    match log
        .records
        .iter_mut()
        .find(|x| x.action == r.action && x.record.id == r.record.id)
    {
        Some(x) => {
            if r.updated_at > x.updated_at {
                let (by, on, at) = if !x.at.is_empty() && (r.at.is_empty() || x.at <= r.at) {
                    (x.by.clone(), x.on.clone(), x.at.clone())
                } else {
                    (r.by.clone(), r.on.clone(), r.at.clone())
                };
                *x = r.clone();
                (x.by, x.on, x.at) = (by, on, at);
            } else if !r.at.is_empty() && (x.at.is_empty() || r.at < x.at) {
                (x.by, x.on, x.at) = (r.by.clone(), r.on.clone(), r.at.clone());
            }
        }
        None => log.records.push(r.clone()),
    }
}

/// Merges `other` into `into`, finding by finding: activity is the union
/// of both (one entry per `at`, `by` and `action`, the latest
/// [`MAX_ACTIVITY`] kept), and records are matched by `action` and `id`,
/// the newer `updated_at` winning.
pub fn merge(into: &mut ActionsFile, other: &ActionsFile) {
    for (fp, theirs) in &other.findings {
        let ours = into.findings.entry(fp.clone()).or_default();
        for a in &theirs.activity {
            add_activity(ours, a);
        }
        for r in &theirs.records {
            put_record(ours, r);
        }
        for (k, v) in &theirs.other {
            ours.other.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    for (k, v) in &other.other {
        into.other.entry(k.clone()).or_insert_with(|| v.clone());
    }
}

// ------------------------------------------------------------- changes

/// One change to a finding's log: an entry of activity, the records it
/// made or changed, and the records it removed (by `action` and `id`).
#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub fingerprint: String,
    pub activity: Activity,
    pub records: Vec<ActionRecord>,
    pub removed: Vec<(String, String)>,
}

impl Change {
    /// Makes the change in `file`: [`merge`]s it, then takes the removed
    /// records out. Making it twice is making it once.
    pub fn apply(&self, file: &mut ActionsFile) {
        let log = file.findings.entry(self.fingerprint.clone()).or_default();
        add_activity(log, &self.activity);
        for r in &self.records {
            put_record(log, r);
        }
        log.records.retain(|r| {
            !self
                .removed
                .iter()
                .any(|(a, id)| *a == r.action && *id == r.record.id)
        });
    }
}

/// Now, as activity and records record it: RFC 3339, UTC, with
/// milliseconds, so two runs of one second keep apart.
pub fn now_at() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    at_of_ms(ms)
}

/// `ms` (Unix milliseconds) as [`now_at`] writes it.
pub fn at_of_ms(ms: i64) -> String {
    let s = crate::time::format_rfc3339(ms.div_euclid(1000));
    format!("{}.{:03}Z", s.trim_end_matches('Z'), ms.rem_euclid(1000))
}

/// The change a run of an action makes, `None` for a dry run (not kept).
/// `address` and `label` are the action's; `parent` is the record a
/// follow-up ran on. Each record of the result is matched with the one
/// the finding has of the same block and `id` (a follow-up's update),
/// which keeps when and by whom it was first made; a new one is the
/// parent's action's when a follow-up made it, else this action's.
#[allow(clippy::too_many_arguments)]
pub fn run_change(
    log: Option<&FindingLog>,
    fingerprint: &str,
    address: &str,
    label: &str,
    parent: Option<&ActionRecord>,
    outcome: &Outcome,
    run_id: Option<&str>,
    who: &Actor,
    at: &str,
) -> Option<Change> {
    if outcome.dry_run {
        return None;
    }
    let block = address.split('/').next().unwrap_or(address);
    let of_block = |a: &str| a.split('/').next().is_some_and(|b| b == block);
    let mut records = Vec::new();
    for r in &outcome.records {
        let had = log.and_then(|l| {
            l.records
                .iter()
                .find(|x| x.record.id == r.id && of_block(&x.action))
        });
        let action = match (had, parent) {
            (Some(x), _) => x.action.clone(),
            (None, Some(p)) => p.action.clone(),
            (None, None) => address.to_string(),
        };
        records.push(ActionRecord {
            action,
            record: r.clone(),
            by: had.map_or_else(|| who.user.clone(), |x| x.by.clone()),
            on: had.map_or_else(|| who.computer.clone(), |x| x.on.clone()),
            at: had.map_or_else(|| at.to_string(), |x| x.at.clone()),
            updated_at: at.to_string(),
        });
    }
    let mut record_ids: Vec<String> = outcome.records.iter().map(|r| r.id.clone()).collect();
    if let Some(p) = parent {
        if !record_ids.contains(&p.record.id) {
            record_ids.insert(0, p.record.id.clone());
        }
    }
    Some(Change {
        fingerprint: fingerprint.to_string(),
        activity: Activity {
            at: at.to_string(),
            by: who.user.clone(),
            on: who.computer.clone(),
            run_id: run_id.map(str::to_string),
            action: address.to_string(),
            label: label.to_string(),
            ok: outcome.ok,
            message: outcome.message.clone(),
            record_ids,
            ..Activity::default()
        },
        records,
        removed: Vec::new(),
    })
}

/// The change removing record `r` from finding `fingerprint`, logged as
/// activity ("Removed RITM10816190").
pub fn remove_change(fingerprint: &str, r: &ActionRecord, who: &Actor, at: &str) -> Change {
    let name = r
        .record
        .number
        .clone()
        .or_else(|| r.record.label.clone())
        .unwrap_or_else(|| r.record.id.clone());
    Change {
        fingerprint: fingerprint.to_string(),
        activity: Activity {
            at: at.to_string(),
            by: who.user.clone(),
            on: who.computer.clone(),
            action: r.action.clone(),
            label: "Remove a record".into(),
            ok: true,
            message: name,
            record_ids: vec![r.record.id.clone()],
            kind: Kind::Remove,
            ..Activity::default()
        },
        records: Vec::new(),
        removed: vec![(r.action.clone(), r.record.id.clone())],
    }
}

// -------------------------------------------------------------- saving

/// Makes `change` in the history's file and writes it; refused, before
/// anything is written, when the file was saved by a newer Pathwarden.
fn write(store: &Store, change: &Change) -> Result<Vec<String>> {
    let mut file = load(store)?;
    change.apply(&mut file);
    store.write_state_file(FILE, &file.to_bytes())
}

/// Saves `change` in the history at once: written, and when `push` and
/// the history is in git, committed and pushed. When another computer
/// pushed first, the change is made again on what it left
/// ([`Change::apply`], [`merge`]). Hold the history's lock and pull first
/// ([`Store::lock_waiting`], [`Store::pull`]). Returns notes for the user;
/// a push that failed with the change committed here ([`KeptUnpushed`])
/// is one of them, not an error.
pub fn save(store: &Store, change: &Change, push: bool) -> Result<Vec<String>> {
    if store.is_git() && !push {
        bail!(
            "This computer only reads the run history ([state] push = false), so what the \
             action did isn't saved there."
        );
    }
    let mut notes = write(store, change)?;
    if store.is_git() {
        match store.publish_with(MESSAGE, || {
            write(store, change)?;
            Ok(Some(MESSAGE.to_string()))
        }) {
            Ok(p) => notes.extend(p.notes),
            Err(e) => {
                let kept = e.downcast::<KeptUnpushed>()?;
                notes.extend(kept.notes.clone());
                notes.push(kept.sentence("It is saved"));
            }
        }
    }
    Ok(crate::store::once_each(notes))
}

/// Sets what actions did on each of `findings` and `resolved` from `file`
/// ([`ActionsFile::for_finding`]).
pub fn annotate(
    file: &ActionsFile,
    findings: &mut [crate::findings::Finding],
    resolved: &mut [crate::state::Resolved],
) {
    for f in findings {
        f.actions = file.for_finding(&f.fingerprint);
    }
    for r in resolved {
        r.actions = file.for_finding(&r.fingerprint);
    }
}

#[cfg(test)]
#[path = "action_log_tests.rs"]
mod tests;
