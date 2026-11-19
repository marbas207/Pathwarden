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
//! written over ([`NEWER_WORDS`]). Neither is one an older release left in
//! the other form when it changed how the history is stored
//! ([`load`]): the rest of the history goes on working.
//!
//! The file is read as untrusted, as anything a writer of the history can
//! push: at most [`MAX_BYTES`], texts cut to the result's caps, links that
//! aren't `https://` dropped.
//!
//! A save whose push failed is kept on this computer (a file in the
//! working copy's `.git`), made again on whatever every later pull brings,
//! and dropped once a push carried it ([`replay_pending`]).

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::actions::{ActionRecord, Outcome, Record};
use crate::crypt;
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
/// The most bytes of the file read: any writer of the history can push it.
pub const MAX_BYTES: u64 = 16 << 20;
/// What is said when an older release turned encryption off and left the
/// file encrypted.
pub const LEFT_SEALED_WORDS: &str = "What finding actions did (actions.json.age) is still \
encrypted in a history that isn't any more: an older Pathwarden turned encryption off without \
rewriting it, and the key it needs is gone. The rest of the history works. To get it back, \
restore the old .pathwarden-key from the repository's history; to start over, remove \
actions.json.age.";
/// What is said when the file can't be opened with the history's key.
pub const UNREADABLE_WORDS: &str = "What finding actions did (actions.json) can't be opened with \
this history's key: an older Pathwarden changed the passphrase without rewriting it, or the file \
was altered or rolled back. The rest of the history works; what actions did can't be shown or \
saved here, and is kept as it is.";
/// What a reader says of a plain actions.json in an encrypted history,
/// on the command line ([`PLAIN_LEFT_PAGE_WORDS`] on a page).
pub const PLAIN_LEFT_WORDS: &str = "A plain actions.json is in this encrypted history and wasn't \
read. If an older Pathwarden left it when encryption was turned on, import it with `pathwarden \
action log import`.";
/// [`PLAIN_LEFT_WORDS`] for a page: without the command.
pub const PLAIN_LEFT_PAGE_WORDS: &str = "A plain actions.json is in this encrypted history and \
wasn't read. If an older Pathwarden left it when encryption was turned on, it can be imported \
from the command line.";
/// The most bytes of fields a later release keeps on one record
/// ([`Record::other`]); past it the rest are dropped.
pub const MAX_OTHER_BYTES: usize = 8 * 1024;
/// An activity entry's `outcome` for a run someone stopped.
pub const CANCELLED: &str = "cancelled";
/// The working copy's file of saves whose push failed ([`replay_pending`]).
const PENDING_FILE: &str = "pathwarden-actions-pending.json";

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
    /// Records someone removed: a record made before its removal never
    /// comes back (a follow-up that started before it, a computer that
    /// hadn't seen it); one a later run makes anew with the same ID does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<Tombstone>,
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

/// A record someone removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    pub action: String,
    pub id: String,
    /// When it was removed (as activity's `at`).
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// When the record removed was first made (its `at`): a clock behind
    /// the one that made it still removes it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub record_at: String,
}

impl Tombstone {
    /// Whether it removes `r`: the same record, made no later than the
    /// removal or than the record it removed, whichever is later (two
    /// computers' clocks may disagree).
    fn covers(&self, r: &ActionRecord) -> bool {
        let until = if self.record_at > self.at {
            &self.record_at
        } else {
            &self.at
        };
        self.action == r.action && self.id == r.record.id && r.at <= *until
    }
}

/// Most removed records a finding remembers ([`FindingLog::removed`]).
pub const MAX_REMOVED: usize = 100;

/// What an entry of activity was.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Kind {
    /// A run of an action (written as no `kind` at all).
    #[default]
    Run,
    /// Someone removed a record.
    Remove,
    /// One a later release wrote: kept as it is (any JSON), shown by its
    /// label.
    Other(Value),
}

impl Kind {
    fn is_run(&self) -> bool {
        *self == Kind::Run
    }
}

impl Serialize for Kind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Kind::Run => s.serialize_str("run"),
            Kind::Remove => s.serialize_str("remove"),
            Kind::Other(k) => k.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for Kind {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Kind, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::Null => Kind::Run,
            Value::String(k) if k == "run" => Kind::Run,
            Value::String(k) if k == "remove" => Kind::Remove,
            other => Kind::Other(other),
        })
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
    /// How a run that didn't finish ended: `cancelled` when someone
    /// stopped it (Ctrl-C, Cancel). Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
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
        match &self.kind {
            Kind::Other(_) if self.message.trim().is_empty() => self.label.clone(),
            Kind::Other(_) => format!("{}: {}", self.label, first(&self.message)),
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
    if bytes.len() as u64 > MAX_BYTES {
        return Err(LogError::Damaged(format!(
            "it is larger than {} MiB, so it is not read",
            MAX_BYTES >> 20
        )));
    }
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
    let mut file: ActionsFile =
        serde_json::from_value(v).map_err(|e| LogError::Damaged(e.to_string()))?;
    sanitize(&mut file);
    Ok(file)
}

/// `s` cut to `max` characters, without control or bidi characters.
fn cut(s: &mut String, max: usize, lines: bool) {
    *s = crate::actions::clean_text(s, max, lines).0;
}

/// The file as any reader may take it, whoever wrote it: every text cut
/// to the caps a result has, and record links that aren't `https://`
/// dropped, so no event, export or page ever carries one.
pub fn sanitize(file: &mut ActionsFile) {
    use crate::actions::{MAX_LABEL, MAX_MESSAGE, MAX_RECORD_TEXT};
    for log in file.findings.values_mut() {
        for a in &mut log.activity {
            cut(&mut a.label, MAX_LABEL, false);
            cut(&mut a.message, MAX_MESSAGE, true);
            for t in [&mut a.action, &mut a.at] {
                cut(t, MAX_RECORD_TEXT, false);
            }
            for t in
                a.by.iter_mut()
                    .chain(a.on.iter_mut())
                    .chain(a.run_id.iter_mut())
            {
                cut(t, MAX_RECORD_TEXT, false);
            }
            a.record_ids.truncate(crate::actions::MAX_RECORDS + 1);
            for id in &mut a.record_ids {
                cut(id, MAX_RECORD_TEXT, false);
            }
        }
        for r in &mut log.records {
            sanitize_record(&mut r.record);
            for t in r.by.iter_mut().chain(r.on.iter_mut()) {
                cut(t, MAX_RECORD_TEXT, false);
            }
        }
    }
}

/// A record as a result's would be: texts cut, its link only when
/// `https://`.
pub fn sanitize_record(r: &mut Record) {
    use crate::actions::{MAX_FIELD, MAX_FIELDS, MAX_NAME, MAX_RECORD_TEXT};
    cut(&mut r.id, MAX_RECORD_TEXT, false);
    for t in [&mut r.kind, &mut r.label, &mut r.number, &mut r.status]
        .into_iter()
        .flatten()
    {
        cut(t, MAX_RECORD_TEXT, false);
    }
    r.url = r
        .url
        .as_deref()
        .and_then(|u| crate::actions::https_url(u).ok());
    let fields = std::mem::take(&mut r.fields);
    for (k, v) in fields.into_iter().take(MAX_FIELDS) {
        let (k, _) = crate::actions::clean_text(&k, MAX_NAME, false);
        let (v, _) = crate::actions::clean_text(&v, MAX_FIELD, false);
        if !k.is_empty() {
            r.fields.insert(k, v);
        }
    }
    // Fields a later release keeps: passed on as they are (to programs and
    // in the event), so at most [`MAX_OTHER_BYTES`] of them.
    let other = std::mem::take(&mut r.other);
    let mut size = 0;
    for (k, v) in other {
        size += k.len() + serde_json::to_string(&v).map_or(usize::MAX / 2, |t| t.len());
        if size > MAX_OTHER_BYTES {
            break;
        }
        r.other.insert(k, v);
    }
}

/// The history's file; an empty one when there is none yet. Refused (and
/// so never written over) when it was saved by a newer Pathwarden, can't
/// be read, or is in the other form than the history: an older release
/// that turned encryption off left it encrypted ([`LEFT_SEALED_WORDS`]),
/// or one that changed the passphrase left it under the old key
/// ([`UNREADABLE_WORDS`]). A plain one in an encrypted history is never
/// read (anyone who can push could have put it there): [`plain_left`]
/// says so, and `pathwarden action log import` takes it in when someone
/// decides to ([`import_plain`]).
pub fn load(store: &Store) -> Result<ActionsFile> {
    let dir = &store.dir;
    let sealed = dir.join(format!("{FILE}{}", crypt::SUFFIX));
    let there = |p: &std::path::Path| std::fs::symlink_metadata(p).is_ok();
    if !crypt::is_encrypted(dir) {
        if there(&sealed) {
            bail!(LEFT_SEALED_WORDS);
        }
        return match store.read_state_file(FILE)? {
            None => Ok(ActionsFile::default()),
            Some(bytes) => Ok(parse(&bytes)?),
        };
    }
    if !there(&sealed) {
        return Ok(ActionsFile::default());
    }
    match store.read_state_file(FILE) {
        Ok(Some(bytes)) => Ok(parse(&bytes)?),
        Ok(None) => Ok(ActionsFile::default()),
        Err(e) if e.downcast_ref::<crate::store::TooLarge>().is_some() => Err(e),
        Err(e) => {
            // Not this file's fault when nothing of the history opens.
            crate::store::check_readable(dir)?;
            Err(e.context(UNREADABLE_WORDS))
        }
    }
}

/// Whether a plain actions.json is in an encrypted history: never read,
/// never written over or removed by this version; the reader says so
/// ([`PLAIN_LEFT_WORDS`]).
pub fn plain_left(store: &Store) -> bool {
    crypt::is_encrypted(&store.dir)
        && std::fs::symlink_metadata(store.dir.join(FILE)).is_ok_and(|m| m.is_file())
}

/// What a plain actions.json in an encrypted history holds, read as
/// untrusted ([`parse`]); `None` when there is none.
pub fn read_plain(store: &Store) -> Result<Option<ActionsFile>> {
    match crate::store::read_leftover(&store.dir, FILE, MAX_BYTES)? {
        None => Ok(None),
        Some(bytes) => Ok(Some(parse(&bytes)?)),
    }
}

/// A plain file's contents in a few numbers, for the person deciding
/// whether to import it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub findings: usize,
    pub records: usize,
    pub activity: usize,
    /// The latest entries, newest first: (fingerprint, line).
    pub newest: Vec<(String, String)>,
}

impl ActionsFile {
    /// [`Summary`] of it, with its `newest` latest entries.
    pub fn summary(&self, newest: usize) -> Summary {
        let mut all: Vec<(&String, &Activity)> = self
            .findings
            .iter()
            .flat_map(|(fp, l)| l.activity.iter().map(move |a| (fp, a)))
            .collect();
        all.sort_by(|a, b| b.1.at.cmp(&a.1.at));
        Summary {
            findings: self.findings.len(),
            records: self.findings.values().map(|l| l.records.len()).sum(),
            activity: all.len(),
            newest: all
                .into_iter()
                .take(newest)
                .map(|(fp, a)| (fp.clone(), a.line()))
                .collect(),
        }
    }
}

/// Takes a plain actions.json in an encrypted history into the history's
/// own, after someone looked at it ([`read_plain`]): merged as untrusted,
/// encrypted, and the plain copy removed, in one commit pushed when the
/// history is in git and `push`. Hold the lock and pull first. Notes for
/// the user.
pub fn import_plain(store: &Store, push: bool) -> Result<Vec<String>> {
    if store.is_git() && !push {
        bail!("This computer only reads the run history ([state] push = false), so it can't change it.");
    }
    if !crypt::is_encrypted(&store.dir) {
        bail!("The history isn't encrypted, so there is no plain actions.json to import.");
    }
    let take = || -> Result<bool> {
        let Some(plain) = read_plain(store)? else {
            return Ok(false);
        };
        let mut file = load(store)?;
        merge(&mut file, &plain);
        store.write_state_file(FILE, &file.to_bytes())?;
        crate::store::remove_plain_leftover(&store.dir, FILE)?;
        Ok(true)
    };
    if !take()? {
        bail!("There is no plain actions.json in this history.");
    }
    let mut notes = Vec::new();
    if store.is_git() {
        let message = "pathwarden: import a plain actions.json";
        match store.publish_with(message, || Ok(take()?.then(|| message.to_string()))) {
            Ok(p) => notes.extend(p.notes),
            Err(e) => {
                let kept = e.downcast::<KeptUnpushed>()?;
                notes.extend(kept.notes.clone());
                notes.push(kept.sentence("It is imported"));
            }
        }
    }
    Ok(notes)
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
    if log.removed.iter().any(|t| t.covers(r)) {
        return;
    }
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

/// Remembers removal `t` in `log` and takes out what it removes.
fn add_removed(log: &mut FindingLog, t: &Tombstone) {
    if !log.removed.contains(t) {
        log.removed.push(t.clone());
        log.removed.sort_by(|a, b| a.at.cmp(&b.at));
        let over = log.removed.len().saturating_sub(MAX_REMOVED);
        log.removed.drain(..over);
    }
    log.records.retain(|r| !t.covers(r));
}

/// Merges `other` into `into`, finding by finding: activity is the union
/// of both (one entry per `at`, `by` and `action`, the latest
/// [`MAX_ACTIVITY`] kept), records are matched by `action` and `id`, the
/// newer `updated_at` winning, and a removal on either side wins over any
/// record made before it.
pub fn merge(into: &mut ActionsFile, other: &ActionsFile) {
    for (fp, theirs) in &other.findings {
        let ours = into.findings.entry(fp.clone()).or_default();
        for a in &theirs.activity {
            add_activity(ours, a);
        }
        for t in &theirs.removed {
            add_removed(ours, t);
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
/// made or changed, and the records it removed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub fingerprint: String,
    pub activity: Activity,
    #[serde(default)]
    pub records: Vec<ActionRecord>,
    #[serde(default)]
    pub removed: Vec<Tombstone>,
}

impl Change {
    /// Makes the change in `file` as [`merge`] would: its removals first,
    /// so a record they remove never comes back. Making it twice is making
    /// it once.
    pub fn apply(&self, file: &mut ActionsFile) {
        let log = file.findings.entry(self.fingerprint.clone()).or_default();
        add_activity(log, &self.activity);
        for t in &self.removed {
            add_removed(log, t);
        }
        for r in &self.records {
            put_record(log, r);
        }
    }

    /// Whether `file` holds it already: its removals are there, and its
    /// entry of activity is there or the finding's activity is full of
    /// later ones.
    fn is_in(&self, file: &ActionsFile) -> bool {
        file.findings.get(&self.fingerprint).is_some_and(|log| {
            self.removed.iter().all(|t| log.removed.contains(t))
                && (log.activity.iter().any(|a| a.key() == self.activity.key())
                    || (log.activity.len() >= MAX_ACTIVITY
                        && log.activity.iter().all(|a| a.at > self.activity.at)))
        })
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
    let cancelled = outcome.ended == crate::actions::Ended::Cancelled;
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
            ok: outcome.ok && !cancelled,
            message: if cancelled {
                "Cancelled".into()
            } else {
                outcome.message.clone()
            },
            record_ids,
            outcome: cancelled.then(|| CANCELLED.to_string()),
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
        removed: vec![Tombstone {
            action: r.action.clone(),
            id: r.record.id.clone(),
            at: at.to_string(),
            by: who.user.clone(),
            record_at: r.at.clone(),
        }],
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
    // Written: kept here until a push carries it, whatever happens to this
    // push. (A refused write never gets here.)
    if store.is_git() {
        add_pending(store, change)?;
    }
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

// ------------------------------------------------------------- pending

/// The saves on this computer no push has carried yet.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Pending {
    #[serde(default)]
    changes: Vec<Change>,
}

/// The start of an age file: a sealed pending file.
const AGE_HEADER: &[u8] = b"age-encryption.org/";

/// The saves kept here. An error when they are there but can't be read
/// (sealed, and the history's key isn't at hand): then they are left as
/// they are.
fn try_read_pending(store: &Store) -> Result<Pending> {
    let Some(bytes) = store.read_local_file(PENDING_FILE) else {
        return Ok(Pending::default());
    };
    let plain = if bytes.starts_with(AGE_HEADER) {
        let key = crypt::key_for(&store.dir)?;
        crypt::open(&key, &bytes, PENDING_FILE)?
    } else {
        bytes
    };
    // A damaged file is of no use to anyone: started again.
    Ok(serde_json::from_slice(&plain).unwrap_or_default())
}

fn read_pending(store: &Store) -> Pending {
    try_read_pending(store).unwrap_or_default()
}

/// Writes the saves kept here: encrypted with the history's key when the
/// history is encrypted, as its own files are.
fn write_pending(store: &Store, p: &Pending) -> Result<()> {
    let plain = serde_json::to_vec(p)?;
    let bytes = if crypt::is_encrypted(&store.dir) {
        let key = crypt::key_for(&store.dir)?;
        crypt::seal(&key, &plain)?
    } else {
        plain
    };
    store.write_local_file(PENDING_FILE, &bytes)
}

/// Runs `f` holding the pending file's own small lock, so two processes
/// never lose each other's entry (one may hold the history's lock, the
/// other not: a cancelled run's quick save). Waits up to 2 s; a lock older
/// than 30 s is left from a crash and taken over.
fn with_pending_lock<T>(store: &Store, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let path = store.dir.join(".git").join(format!("{PENDING_FILE}.lock"));
    let start = std::time::Instant::now();
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > std::time::Duration::from_secs(30));
                if stale {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                if start.elapsed() > std::time::Duration::from_secs(2) {
                    bail!("the list of saves waiting for a push is in use");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => {
                return Err(anyhow::Error::from(e).context("locking the saves waiting for a push"))
            }
        }
    }
    let out = f();
    let _ = std::fs::remove_file(&path);
    out
}

/// Keeps `change` until a push carries it.
fn add_pending(store: &Store, change: &Change) -> Result<()> {
    if !store.is_git() {
        return Ok(());
    }
    with_pending_lock(store, || {
        let mut p = try_read_pending(store)?;
        if !p.changes.contains(change) {
            p.changes.push(change.clone());
        }
        write_pending(store, &p)
    })
}

/// After a pull: the saves here no push carried yet, made again on what
/// the history holds now (another computer may have pushed over them), so
/// the next commit carries them. Nothing when there are none; a note when
/// they can't be made (the log can't be read), and they are kept.
pub fn replay_pending(store: &Store) -> Option<String> {
    let p = read_pending(store);
    if p.changes.is_empty() {
        return None;
    }
    let result = (|| -> Result<()> {
        let mut file = load(store)?;
        if p.changes.iter().all(|c| c.is_in(&file)) {
            return Ok(());
        }
        for c in &p.changes {
            c.apply(&mut file);
        }
        crate::store::write_state_file(&store.dir, FILE, &file.to_bytes())?;
        Ok(())
    })();
    result.err().map(|e| {
        format!(
            "What finding actions did here that wasn't pushed yet couldn't be put back on the \
             history: {e:#}. It is kept on this computer."
        )
    })
}

/// After a push: the saves it carried are dropped from those kept here.
pub fn prune_pending(store: &Store) {
    if read_pending(store).changes.is_empty() {
        return;
    }
    // A log that can't be read prunes nothing (and refused saves never
    // got in, so nothing grows).
    let Ok(file) = load(store) else {
        return;
    };
    let _ = with_pending_lock(store, || {
        let mut p = try_read_pending(store)?;
        let before = p.changes.len();
        p.changes.retain(|c| !c.is_in(&file));
        if p.changes.len() != before {
            write_pending(store, &p)?;
        }
        Ok(())
    });
}

/// How many saves are kept on this computer for the next push.
pub fn pending_count(store: &Store) -> usize {
    read_pending(store).changes.len()
}

/// Saves `change` at once without the network, for a run someone stopped
/// (Ctrl-C must stay quick): written in the working copy under the lock
/// the caller holds (or none when `locked` is false), and in git kept
/// for the next pull and push ([`replay_pending`]). A folder history
/// without the lock isn't written.
///
/// A log that can't be saved to (a newer, damaged or unreadable file) is
/// refused, and nothing is kept for later.
pub fn save_here(store: &Store, change: &Change, locked: bool) -> Result<()> {
    if locked {
        write(store, change)?;
    } else if store.is_git() {
        // The lock is busy: only kept, once the log is known to take it.
        load(store)?;
    } else {
        bail!("the run history is in use, so the cancelled run wasn't saved");
    }
    add_pending(store, change)
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
