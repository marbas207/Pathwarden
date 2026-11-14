//! Introduced: which specific things are net new over a period, object by
//! object, not only how the counts moved between two runs.
//!
//! "Introduced" means **first seen by Pathwarden**, not when the change was
//! made in the directory: an object or a path carries the time of the run
//! that first found it ("first seen Oct 18 (run 3)").
//!
//! The findings state keeps, besides each finding's own dates:
//!
//! - per tracked finding, when each object it lists appeared, and which of
//!   them came back after leaving ([`ObjectTrack`]);
//! - per zone (Tier Zero and each Privilege Zone), when each edge into it
//!   from outside appeared and when it was resolved, and when each of its
//!   members joined and left ([`PathsTrack`]): a new Domain Admin is a new
//!   member of Tier Zero, not an edge into it from outside.
//!
//! Both hold name-free 64-bit keys ([`object_key`], [`edge_key`]) grouped
//! by the run that set them, each run's keys in one string (a finding's
//! whole track is one string), so a big domain stays small: 17 bytes per
//! object or edge. Objects and edges that left are remembered for
//! [`GONE_DAYS`] (at most [`GONE_MAX`] per finding or zone) to tell one
//! that comes back from a new one. A zone with more than [`ZONE_MAX`] edges
//! (or members) into it is not dated: it is counted instead
//! ([`Introduced::note`]).
//!
//! What a finding or zone listed when tracking began is its baseline, never
//! introduced: object-level dates begin with the first run after this
//! shipped ([`crate::state::FindingsState::tracked_since`]), and earlier
//! runs keep finding-level dates only ([`Introduced::note`]).
//!
//! [`period`] reads all of it into what is net new in a [`Period`]: new
//! findings, findings back after a fix, findings that gained objects (and
//! which), new paths into Tier Zero and each zone, and what was resolved.
//! The report's Findings tab, the app's Progress page, `pathwarden findings
//! --introduced` and `pathwarden changes` all show it, in the same words
//! ([`Introduced::lines`], [`Badge::label`], [`seen_label`]).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::{Deserialize, Serialize};

use crate::findings::{Finding, Severity};
use crate::graph::AdGraph;
use crate::model::NodeKind;
use crate::remediation::RemediationPlan;
use crate::report::num as thousands;
use crate::since::{Line, Next, Tone};
use crate::state::{FindingsState, HistoryPoint, Status};
use crate::zones::Zone;

const DAY: i64 = 86_400;

/// How long an object or edge that left is remembered, so that it reads as
/// back, not new, when it returns.
pub const GONE_DAYS: i64 = 365;

/// Most departed objects (or edges) remembered per finding (or zone); the
/// ones that left longest ago are forgotten first.
pub const GONE_MAX: usize = 20_000;

/// Most edges (and, apart, members) dated per zone. A broad zone (Domain
/// Users) has an edge into it from every session and every admin right on
/// its members, which grows with the domain: past this the zone's edges are
/// counted, not dated, so the state stays bounded.
pub const ZONE_MAX: usize = 50_000;

/// What the state calls Tier Zero among the zones of [`PathsTrack`].
pub const TIER_ZERO: &str = "Tier Zero";

/// Findings, objects and paths a line names at most; the rest are counted.
pub const NAMED: usize = 3;

/// New paths the report lists at most (the newest first); `pathwarden
/// changes` has them all.
pub const PATHS_LISTED: usize = 500;

fn fnv(parts: &[&str]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for b in part.bytes().chain(std::iter::once(0)) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

/// The name-free key of an object (its SID or GUID) in the state.
/// The same key as [`crate::exposed::key`], as 16 hex digits.
pub fn object_key(id: &str) -> String {
    format!("{:016x}", crate::exposed::key(id))
}

/// The name-free key of an edge `from -[kind]-> to` (object IDs and the
/// BloodHound edge name) in the state.
pub fn edge_key(from: &str, kind: &str, to: &str) -> String {
    fnv(&[
        "e",
        &from.trim().to_ascii_uppercase(),
        kind,
        &to.trim().to_ascii_uppercase(),
    ])
}

/// Keys of `items` by time, as stored: each time's keys sorted.
type ByTime = BTreeMap<i64, Vec<String>>;

/// Keys as the state writes them: each time's keys in one string, space
/// separated (17 bytes a key however the file is indented), read back from
/// that or from a list.
mod packed {
    use super::ByTime;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
    #[serde(untagged)]
    pub enum Keys {
        Packed(String),
        List(Vec<String>),
    }

    impl Keys {
        pub fn into_vec(self) -> Vec<String> {
            match self {
                Keys::Packed(s) => s.split_whitespace().map(str::to_string).collect(),
                Keys::List(v) => v,
            }
        }
    }

    pub fn serialize<S: Serializer>(m: &ByTime, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(m.iter().map(|(t, ks)| (t, ks.join(" "))))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ByTime, D::Error> {
        let m = BTreeMap::<i64, Keys>::deserialize(d)?;
        Ok(m.into_iter().map(|(t, k)| (t, k.into_vec())).collect())
    }
}

/// `from..=to` for a [`BTreeMap::range`], which panics on a range that ends
/// before it starts: such a period (a day after the latest run) is empty.
fn span(from: i64, to: i64) -> std::ops::RangeInclusive<i64> {
    from..=to.max(from)
}

/// `t -> [k]` into `k -> t`.
fn by_key(m: &ByTime) -> HashMap<&str, i64> {
    m.iter()
        .flat_map(|(t, ks)| ks.iter().map(move |k| (k.as_str(), *t)))
        .collect()
}

/// Departed keys still worth remembering at `now`: left within
/// [`GONE_DAYS`], the latest [`GONE_MAX`].
fn trim_gone(gone: &mut ByTime, now: i64) {
    gone.retain(|t, _| *t >= now - GONE_DAYS * DAY);
    let mut total: usize = gone.values().map(Vec::len).sum();
    while total > GONE_MAX {
        let Some((&t, _)) = gone.iter().next() else {
            break;
        };
        let ks = gone.get_mut(&t).expect("present");
        let drop = (total - GONE_MAX).min(ks.len());
        ks.drain(..drop);
        total -= drop;
        if ks.is_empty() {
            gone.remove(&t);
        }
    }
    for ks in gone.values_mut() {
        ks.sort_unstable();
        ks.dedup();
    }
}

fn push(m: &mut ByTime, t: i64, k: &str) {
    m.entry(t).or_default().push(k.to_string());
}

/// When each object a finding lists appeared ([`TrackedFinding::objects`]).
///
/// Written as one string, so a finding costs a line however the file is
/// indented ([`ObjectTrack::pack`]); also read back as an object with these
/// fields.
///
/// [`TrackedFinding::objects`]: crate::state::TrackedFinding::objects
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectTrack {
    /// When the finding's objects were first tracked: the ones listed then
    /// are its baseline, never introduced.
    pub since: i64,
    /// The objects listed at the finding's last sighting, by when each
    /// appeared (first seen, or back): time to sorted [`object_key`]s.
    pub seen: ByTime,
    /// Keys in `seen` that had been listed before, left, and came back.
    pub back: Vec<String>,
    /// Objects no longer listed, by when they left ([`GONE_DAYS`]).
    pub gone: ByTime,
}

impl Serialize for ObjectTrack {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.pack())
    }
}

impl<'de> Deserialize<'de> for ObjectTrack {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        /// The fields as an object (state written before tracks were
        /// packed into one string): times are map keys, read as text.
        #[derive(Deserialize)]
        struct Fields {
            since: i64,
            #[serde(default)]
            seen: BTreeMap<String, packed::Keys>,
            #[serde(default)]
            back: Option<packed::Keys>,
            #[serde(default)]
            gone: BTreeMap<String, packed::Keys>,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Form {
            Packed(String),
            Fields(Fields),
        }
        let times = |m: BTreeMap<String, packed::Keys>| -> Result<ByTime, D::Error> {
            m.into_iter()
                .map(|(t, k)| {
                    t.parse::<i64>()
                        .map(|t| (t, k.into_vec()))
                        .map_err(serde::de::Error::custom)
                })
                .collect()
        };
        match Form::deserialize(d)? {
            Form::Packed(s) => ObjectTrack::unpack(&s).map_err(serde::de::Error::custom),
            Form::Fields(f) => Ok(ObjectTrack {
                since: f.since,
                seen: times(f.seen)?,
                back: f.back.map(packed::Keys::into_vec).unwrap_or_default(),
                gone: times(f.gone)?,
            }),
        }
    }
}

impl ObjectTrack {
    /// The track as one string: `since`, the keys first seen then, then
    /// `@t` and the keys seen at `t`, `!` and the keys that came back, `~t`
    /// and the keys that left at `t`. Keys are 16 hex digits, never one of
    /// those marks.
    pub fn pack(&self) -> String {
        let mut out = self.since.to_string();
        let mut add = |mark: Option<String>, ks: &[String]| {
            if let Some(m) = mark {
                out.push(' ');
                out.push_str(&m);
            }
            for k in ks {
                out.push(' ');
                out.push_str(k);
            }
        };
        if let Some(ks) = self.seen.get(&self.since) {
            add(None, ks);
        }
        for (t, ks) in self.seen.iter().filter(|(t, _)| **t != self.since) {
            add(Some(format!("@{t}")), ks);
        }
        if !self.back.is_empty() {
            add(Some("!".into()), &self.back);
        }
        for (t, ks) in &self.gone {
            add(Some(format!("~{t}")), ks);
        }
        out
    }

    /// [`ObjectTrack::pack`] read back.
    pub fn unpack(s: &str) -> Result<Self, String> {
        enum Group {
            Seen(i64),
            Back,
            Gone(i64),
        }
        let bad = |t: &str| format!("not an object track: '{t}'");
        let time = |t: &str| t.parse::<i64>().map_err(|_| bad(t));
        let mut it = s.split_whitespace();
        let since = time(it.next().unwrap_or(""))?;
        let mut t = ObjectTrack {
            since,
            ..Default::default()
        };
        let mut into = Group::Seen(since);
        for tok in it {
            if let Some(at) = tok.strip_prefix('@') {
                into = Group::Seen(time(at)?);
            } else if let Some(at) = tok.strip_prefix('~') {
                into = Group::Gone(time(at)?);
            } else if tok == "!" {
                into = Group::Back;
            } else {
                match into {
                    Group::Seen(at) => push(&mut t.seen, at, tok),
                    Group::Back => t.back.push(tok.to_string()),
                    Group::Gone(at) => push(&mut t.gone, at, tok),
                }
            }
        }
        Ok(t)
    }

    /// The track after a run at `now` in which the finding lists `ids`.
    /// `left_at` is set when the finding had been resolved (then): its
    /// objects all left with it, so those listed again are back. With
    /// `hold` (a run that can't resolve the finding: a collection that
    /// looks incomplete, a domain or a source missing) objects it no longer
    /// lists are kept as listed, not gone, as missing edges are kept open
    /// ([`PathsTrack::update`]).
    pub fn update(
        prev: Option<&ObjectTrack>,
        ids: &[&str],
        now: i64,
        left_at: Option<i64>,
        hold: bool,
    ) -> Self {
        let mut cur: Vec<String> = ids.iter().map(|i| object_key(i)).collect();
        cur.sort_unstable();
        cur.dedup();
        let Some(prev) = prev else {
            let mut seen = ByTime::new();
            if !cur.is_empty() {
                seen.insert(now, cur);
            }
            return ObjectTrack {
                since: now,
                seen,
                ..Default::default()
            };
        };
        let when = by_key(&prev.seen);
        let gone_before = by_key(&prev.gone);
        let back_before: HashSet<&str> = prev.back.iter().map(String::as_str).collect();
        let listed: HashSet<&str> = cur.iter().map(String::as_str).collect();
        let mut t = ObjectTrack {
            since: prev.since,
            ..Default::default()
        };
        // `cur` is sorted, so each time's keys go in sorted.
        for k in &cur {
            match (left_at, when.get(k.as_str())) {
                (None, Some(&at)) => {
                    push(&mut t.seen, at, k);
                    if back_before.contains(k.as_str()) {
                        t.back.push(k.clone());
                    }
                }
                (Some(_), Some(_)) => {
                    push(&mut t.seen, now, k);
                    t.back.push(k.clone());
                }
                (_, None) if gone_before.contains_key(k.as_str()) => {
                    push(&mut t.seen, now, k);
                    t.back.push(k.clone());
                }
                _ => push(&mut t.seen, now, k),
            }
        }
        let left = left_at.unwrap_or(now);
        for (k, at) in when.iter().filter(|(k, _)| !listed.contains(*k)) {
            if hold && left_at.is_none() {
                push(&mut t.seen, *at, k);
                if back_before.contains(k) {
                    t.back.push(k.to_string());
                }
            } else {
                push(&mut t.gone, left, k);
            }
        }
        for (k, at) in &gone_before {
            if !listed.contains(k) && !when.contains_key(k) {
                push(&mut t.gone, *at, k);
            }
        }
        if hold {
            for ks in t.seen.values_mut() {
                ks.sort_unstable();
            }
            t.back.sort_unstable();
        }
        trim_gone(&mut t.gone, now);
        t
    }

    /// Objects that appeared in `[from, to]` beyond the baseline, with when
    /// and whether they came back: newest first.
    pub fn gained(&self, from: i64, to: i64) -> Vec<(&str, i64, bool)> {
        let back: HashSet<&str> = self.back.iter().map(String::as_str).collect();
        let mut out: Vec<(&str, i64, bool)> = self
            .seen
            .range(span(from, to))
            .filter(|(t, _)| **t != self.since)
            .rev()
            .flat_map(|(t, ks)| {
                let back = &back;
                ks.iter()
                    .map(move |k| (k.as_str(), *t, back.contains(k.as_str())))
            })
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        out
    }

    /// Objects that left in `[from, to]`.
    pub fn removed(&self, from: i64, to: i64) -> usize {
        self.gone
            .range(span(from, to))
            .map(|(_, ks)| ks.len())
            .sum()
    }

    /// When each listed object beyond the baseline appeared, and whether it
    /// came back, by key: what the report labels.
    pub fn stamps(&self) -> HashMap<&str, (i64, bool)> {
        self.gained(i64::MIN, i64::MAX)
            .into_iter()
            .map(|(k, t, b)| (k, (t, b)))
            .collect()
    }

    /// How many objects appeared at each time beyond the baseline, oldest
    /// first: what the report's filter counts "+N objects" from.
    pub fn gained_counts(&self) -> Vec<(i64, usize)> {
        self.seen
            .iter()
            .filter(|(t, _)| **t != self.since)
            .map(|(t, ks)| (*t, ks.len()))
            .collect()
    }
}

/// Edges into Tier Zero and each Privilege Zone, and their members, per
/// environment and zone ([`crate::state::FindingsState::paths`]). One state
/// folder may hold the runs of several environments (several domains
/// collected apart): each keeps its own zones, so one environment's run
/// never makes another's edges look new or gone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathsTrack {
    /// By [`env_key`] of the domains a run collected.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub envs: BTreeMap<String, EnvPaths>,
}

/// One environment's zones.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvPaths {
    /// The environment's last run.
    pub at: i64,
    /// The objects that run loaded: a later run with fewer than half holds
    /// what is missing, as findings are held ([`crate::record::prepare`]).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub objects: usize,
    /// [`TIER_ZERO`], or a zone's name as the settings give it.
    pub zones: BTreeMap<String, EdgeTrack>,
    /// The open edges that are a session or a local group membership
    /// (HasSession, AdminTo, CanRDP, CanPSRemote, ExecuteDCOM), whose keys
    /// don't say their kind: a run that did not read sessions or local
    /// groups keeps these when they are missing, and resolves the rest.
    /// `None` in state written before it was recorded: every edge missing
    /// then counts as one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_edges: Option<Vec<String>>,
    /// Of [`Self::host_edges`], the computer units each rests on
    /// ([`crate::opengraph::hosts`]): a later run that didn't read them
    /// again keeps the edge open. `None` in state written before it was
    /// recorded, and when there are none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_hosts: Option<BTreeMap<String, Vec<String>>>,
}

/// The key of the environment that collected the domains of `scopes`
/// ([`crate::state::scopes_of`], sorted): what [`PathsTrack::envs`] is
/// keyed by.
pub fn env_key(scopes: &[String]) -> String {
    let parts: Vec<&str> = std::iter::once("env")
        .chain(scopes.iter().map(String::as_str))
        .collect();
    fnv(&parts)
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// A list of keys as the state writes it: one space-separated string, read
/// back from that or from a list.
mod packed_list {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[String], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.join(" "))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
        Ok(super::packed::Keys::deserialize(d)?.into_vec())
    }
}

/// The edges into one zone, and its members.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeTrack {
    /// When the zone's edges were first tracked: the ones there then are
    /// its baseline, never introduced.
    pub since: i64,
    /// Edges there at the last run, by when each first appeared: time to
    /// sorted [`edge_key`]s.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", with = "packed")]
    pub open: ByTime,
    /// Keys in `open` that had been resolved and came back (a session that
    /// comes and goes with logons): back, not new.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "packed_list")]
    pub back: Vec<String>,
    /// Edges no longer there, by when they were resolved ([`GONE_DAYS`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", with = "packed")]
    pub resolved: ByTime,
    /// More edges than [`ZONE_MAX`] at the last run: how many, none dated.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub undated: usize,
    /// The zone's members ([`object_key`]s), when each joined and left: a
    /// new member of Tier Zero (a new Domain Admin) is no edge from
    /// outside. Absent in state written before members were tracked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<KeyTrack>,
}

/// The members of one zone and when each joined, kept as [`EdgeTrack`]
/// keeps its edges.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyTrack {
    pub since: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", with = "packed")]
    pub open: ByTime,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "packed_list")]
    pub back: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", with = "packed")]
    pub resolved: ByTime,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub undated: usize,
}

impl EdgeTrack {
    /// The edges, read as a [`KeyTrack`] is.
    fn edges(&self) -> Keys<'_> {
        Keys {
            since: self.since,
            open: &self.open,
            back: &self.back,
            resolved: &self.resolved,
            undated: self.undated,
        }
    }

    /// The members, when tracked.
    fn members(&self) -> Option<Keys<'_>> {
        self.members.as_ref().map(|m| Keys {
            since: m.since,
            open: &m.open,
            back: &m.back,
            resolved: &m.resolved,
            undated: m.undated,
        })
    }
}

/// A zone's edges or its members, read alike.
#[derive(Clone, Copy)]
struct Keys<'a> {
    since: i64,
    open: &'a ByTime,
    back: &'a [String],
    resolved: &'a ByTime,
    undated: usize,
}

impl<'a> Keys<'a> {
    /// Keys that appeared in `[from, to]` beyond the baseline, and whether
    /// each came back after it was resolved: newest first.
    fn new_in(&self, from: i64, to: i64) -> Vec<(i64, &'a str, bool)> {
        let since = self.since;
        let back: HashSet<&str> = self.back.iter().map(String::as_str).collect();
        let mut out: Vec<(i64, &str, bool)> = self
            .open
            .range(span(from, to))
            .filter(|(t, _)| **t != since)
            .flat_map(|(t, ks)| {
                let back = &back;
                ks.iter()
                    .map(move |k| (*t, k.as_str(), back.contains(k.as_str())))
            })
            .collect();
        out.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
        out
    }

    /// Keys resolved in `[from, to]`.
    fn resolved_in(&self, from: i64, to: i64) -> usize {
        self.resolved
            .range(span(from, to))
            .map(|(_, ks)| ks.len())
            .sum()
    }
}

/// The keys of one zone after a run at `now` that found `keys` (sorted,
/// without repeats), from what `before` had. A key resolved before that is
/// there again is back, dated `now` but not new. Past [`ZONE_MAX`] they
/// are counted, not dated; under it again, they start a new baseline.
fn roll(
    before: Option<Keys>,
    keys: &[&str],
    now: i64,
    may_resolve: &dyn Fn(&str) -> bool,
) -> KeyTrack {
    if keys.len() > ZONE_MAX {
        return KeyTrack {
            since: now,
            undated: keys.len(),
            ..Default::default()
        };
    }
    let Some(b) = before.filter(|b| b.undated == 0) else {
        let mut open = ByTime::new();
        if !keys.is_empty() {
            open.insert(now, keys.iter().map(|k| k.to_string()).collect());
        }
        return KeyTrack {
            since: now,
            open,
            ..Default::default()
        };
    };
    let when = by_key(b.open);
    let gone = by_key(b.resolved);
    let back_before: HashSet<&str> = b.back.iter().map(String::as_str).collect();
    let here: HashSet<&str> = keys.iter().copied().collect();
    let mut t = KeyTrack {
        since: b.since,
        ..Default::default()
    };
    for k in keys {
        match when.get(k) {
            Some(&at) => {
                push(&mut t.open, at, k);
                if back_before.contains(k) {
                    t.back.push(k.to_string());
                }
            }
            None => {
                push(&mut t.open, now, k);
                if gone.contains_key(k) {
                    t.back.push(k.to_string());
                }
            }
        }
    }
    for (k, at) in when.iter().filter(|(k, _)| !here.contains(*k)) {
        if may_resolve(k) {
            push(&mut t.resolved, now, k);
        } else {
            push(&mut t.open, *at, k);
            if back_before.contains(k) {
                t.back.push(k.to_string());
            }
        }
    }
    for (t0, ks) in b.resolved {
        for k in ks.iter().filter(|k| !here.contains(k.as_str())) {
            push(&mut t.resolved, *t0, k);
        }
    }
    for ks in t.open.values_mut() {
        ks.sort_unstable();
    }
    t.back.sort_unstable();
    trim_gone(&mut t.resolved, now);
    t
}

/// An edge into a zone from outside it: `from` controls `to`, a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZoneEdge {
    pub from: NodeIndex,
    pub kind: crate::model::EdgeKind,
    pub to: NodeIndex,
}

impl ZoneEdge {
    pub fn key(&self, g: &AdGraph) -> String {
        edge_key(
            &g.node(self.from).id,
            self.kind.as_str(),
            &g.node(self.to).id,
        )
    }

    /// The units of the computer a session or local group edge rests on
    /// ([`crate::opengraph::hosts`]); none for other edges.
    pub fn host_units(&self, g: &AdGraph) -> Vec<String> {
        use crate::opengraph::hosts::{host_of, units};
        host_of(g, self.from, self.kind, self.to)
            .map(|(ix, mark)| {
                let n = g.node(ix);
                units(&n.id, mark, n.props.host_lists)
            })
            .unwrap_or_default()
    }
}

/// The members of Tier Zero and each zone, first [`TIER_ZERO`] then the
/// zones in the settings' order.
pub fn zone_members(g: &AdGraph, zones: &[Zone]) -> Vec<(String, Vec<NodeIndex>)> {
    let mut all = vec![(
        TIER_ZERO.to_string(),
        g.nodes()
            .filter(|(_, n)| n.tier_zero && !n.placeholder)
            .map(|(ix, _)| ix)
            .collect(),
    )];
    for z in zones {
        all.push((
            z.name.clone(),
            z.members
                .iter()
                .copied()
                .filter(|ix| !g.node(*ix).placeholder)
                .collect(),
        ));
    }
    all
}

/// The edges into Tier Zero and each zone from outside, as attack paths
/// use them (traversable), first [`TIER_ZERO`] then the zones in the
/// settings' order. An edge into a zone from Tier Zero is not a way in:
/// Tier Zero controls every zone already.
pub fn zone_edges(g: &AdGraph, zones: &[Zone]) -> Vec<(String, Vec<ZoneEdge>)> {
    let into = |members: &mut dyn Iterator<Item = NodeIndex>,
                inside: &dyn Fn(NodeIndex) -> bool| {
        let mut out: Vec<ZoneEdge> = Vec::new();
        for to in members {
            for e in g.inner().edges_directed(to, Direction::Incoming) {
                let from = e.source();
                if !inside(from) && !g.node(from).tier_zero && g.traversable(*e.weight(), to) {
                    out.push(ZoneEdge {
                        from,
                        kind: *e.weight(),
                        to,
                    });
                }
            }
        }
        out.sort_by_key(|e| (e.to, e.from, e.kind));
        out.dedup();
        out
    };
    let mut all = vec![(
        TIER_ZERO.to_string(),
        into(
            &mut g.nodes().filter(|(_, n)| n.tier_zero).map(|(ix, _)| ix),
            &|ix| g.node(ix).tier_zero,
        ),
    )];
    for z in zones {
        all.push((
            z.name.clone(),
            into(&mut z.members.iter().copied(), &|ix| z.contains(ix)),
        ));
    }
    all
}

/// What a run found of one zone: its name, the [`edge_key`]s of the edges
/// into it and the [`object_key`]s of its members.
pub type ZoneKeys = (String, Vec<String>, Vec<String>);

impl PathsTrack {
    /// The edges and members after a run at `now` of the environment `env`
    /// ([`env_key`]) that found `zones` and loaded `objects` objects. With
    /// `may_resolve` false (a collection that looks incomplete, a source
    /// missing) edges and members that are missing are kept, not resolved.
    /// A zone no longer in the settings is dropped. Other environments keep
    /// theirs, until their last run is [`GONE_DAYS`] old.
    pub fn update(
        prev: Option<&PathsTrack>,
        env: &str,
        zones: &[ZoneKeys],
        now: i64,
        objects: usize,
        may_resolve: bool,
    ) -> Self {
        Self::update_with(
            prev,
            env,
            zones,
            now,
            objects,
            may_resolve,
            true,
            &HashSet::new(),
        )
    }

    /// [`PathsTrack::update`], knowing which edges found now are a session
    /// or a local group membership (`host_now`, keys). With
    /// `host_may_resolve` false (a run that did not read sessions or local
    /// groups) such an edge that is missing is kept, not resolved; the
    /// other edges, and members, resolve by `may_resolve` alone.
    #[allow(clippy::too_many_arguments)]
    pub fn update_with(
        prev: Option<&PathsTrack>,
        env: &str,
        zones: &[ZoneKeys],
        now: i64,
        objects: usize,
        may_resolve: bool,
        host_may_resolve: bool,
        host_now: &HashSet<String>,
    ) -> Self {
        let units: HashMap<String, Vec<String>> =
            host_now.iter().map(|k| (k.clone(), Vec::new())).collect();
        Self::update_checked(
            prev,
            env,
            zones,
            now,
            objects,
            (may_resolve, host_may_resolve),
            &units,
            &|_| true,
        )
    }

    /// [`PathsTrack::update_with`], knowing also the computer units each
    /// session or local group edge found now rests on (`host_now`, by edge
    /// key; [`crate::opengraph::hosts`]), and which units this run read
    /// again (`host_read`). A missing such edge whose computer wasn't read
    /// again is kept, not resolved, so a computer down doesn't close its
    /// paths and open them again when it is back.
    #[allow(clippy::too_many_arguments)]
    pub fn update_checked(
        prev: Option<&PathsTrack>,
        env: &str,
        zones: &[ZoneKeys],
        now: i64,
        objects: usize,
        (may_resolve, host_may_resolve): (bool, bool),
        host_now: &HashMap<String, Vec<String>>,
        host_read: &dyn Fn(&str) -> bool,
    ) -> Self {
        fn sorted(keys: &[String]) -> Vec<&str> {
            let mut v: Vec<&str> = keys.iter().map(String::as_str).collect();
            v.sort_unstable();
            v.dedup();
            v
        }
        let before_env = prev.and_then(|p| p.envs.get(env));
        let mut mine = EnvPaths {
            at: now,
            objects,
            zones: BTreeMap::new(),
            host_edges: None,
            edge_hosts: None,
        };
        // A missing edge is a session or an admin right when the last run
        // said so, or (state that didn't record it) may be one.
        let host_before: Option<HashSet<&str>> = before_env
            .and_then(|e| e.host_edges.as_ref())
            .map(|v| v.iter().map(String::as_str).collect());
        let was_host = |k: &str| host_before.as_ref().is_none_or(|h| h.contains(k));
        // The computer units of a host edge, as the last run recorded them.
        let units_before = |k: &str| {
            before_env
                .and_then(|e| e.edge_hosts.as_ref())
                .and_then(|m| m.get(k))
        };
        let host_read_again =
            |k: &str| units_before(k).is_none_or(|us| us.iter().all(|u| host_read(u)));
        let edge_ok =
            |k: &str| may_resolve && (!was_host(k) || (host_may_resolve && host_read_again(k)));
        let member_ok = |_: &str| may_resolve;
        let found: HashSet<&str> = zones
            .iter()
            .flat_map(|(_, edges, _)| edges.iter().map(String::as_str))
            .collect();
        let mut host_edges: BTreeSet<String> = BTreeSet::new();
        let mut edge_hosts: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, edges, members) in zones {
            let before = before_env.and_then(|p| {
                p.zones
                    .iter()
                    .find(|(n, _)| crate::zones::same_name(n, name))
                    .map(|(_, t)| t)
            });
            let e = roll(before.map(EdgeTrack::edges), &sorted(edges), now, &edge_ok);
            let m = roll(
                before.and_then(EdgeTrack::members),
                &sorted(members),
                now,
                &member_ok,
            );
            // Open now: found and a session or admin right, or kept and
            // one before.
            for k in e.open.values().flatten() {
                if let Some(us) = host_now.get(k) {
                    host_edges.insert(k.clone());
                    if !us.is_empty() {
                        edge_hosts.insert(k.clone(), us.clone());
                    }
                } else if !found.contains(k.as_str()) && was_host(k) {
                    host_edges.insert(k.clone());
                    // Kept: its computer still wasn't read.
                    if let Some(us) = units_before(k) {
                        edge_hosts.insert(k.clone(), us.clone());
                    }
                }
            }
            mine.zones.insert(
                name.clone(),
                EdgeTrack {
                    since: e.since,
                    open: e.open,
                    back: e.back,
                    resolved: e.resolved,
                    undated: e.undated,
                    members: Some(m),
                },
            );
        }
        // Held: a zone missing from a run that can't resolve stays as it was.
        if !may_resolve {
            if let Some(p) = before_env {
                for (n, t) in &p.zones {
                    if !mine.zones.keys().any(|m| crate::zones::same_name(m, n)) {
                        mine.zones.insert(n.clone(), t.clone());
                    }
                }
            }
        }
        mine.host_edges = Some(host_edges.into_iter().collect());
        mine.edge_hosts = (!edge_hosts.is_empty()).then_some(edge_hosts);
        let mut out = PathsTrack::default();
        if let Some(p) = prev {
            out.envs.extend(
                p.envs
                    .iter()
                    .filter(|(k, e)| k.as_str() != env && e.at >= now - GONE_DAYS * DAY)
                    .map(|(k, e)| (k.clone(), e.clone())),
            );
        }
        out.envs.insert(env.to_string(), mine);
        out
    }

    /// [`PathsTrack::update`] from the analysis graph and zones of a run of
    /// the domains of `scopes` ([`crate::state::scopes_of`]).
    pub fn record(
        prev: Option<&PathsTrack>,
        scopes: &[String],
        g: &AdGraph,
        zones: &[Zone],
        now: i64,
        may_resolve: bool,
    ) -> Self {
        Self::record_with(prev, scopes, g, zones, now, may_resolve, true)
    }

    /// [`PathsTrack::record`], with `host_may_resolve` false for a run
    /// that did not read sessions or local groups
    /// ([`PathsTrack::update_with`]).
    pub fn record_with(
        prev: Option<&PathsTrack>,
        scopes: &[String],
        g: &AdGraph,
        zones: &[Zone],
        now: i64,
        may_resolve: bool,
        host_may_resolve: bool,
    ) -> Self {
        Self::record_checked(
            prev,
            scopes,
            g,
            zones,
            now,
            (may_resolve, host_may_resolve),
            &|_| true,
        )
    }

    /// [`PathsTrack::record_with`], with which computer units this run read
    /// again (`host_read`, [`crate::opengraph::coverage::RunSources::host_read_or_gone`]):
    /// a session or local group edge whose computer wasn't read is kept
    /// ([`PathsTrack::update_checked`]).
    pub fn record_checked(
        prev: Option<&PathsTrack>,
        scopes: &[String],
        g: &AdGraph,
        zones: &[Zone],
        now: i64,
        (may_resolve, host_may_resolve): (bool, bool),
        host_read: &dyn Fn(&str) -> bool,
    ) -> Self {
        let members = zone_members(g, zones);
        let edges = zone_edges(g, zones);
        let host_now: HashMap<String, Vec<String>> = edges
            .iter()
            .flat_map(|(_, es)| es)
            .filter(|e| crate::posture::Untargeted::of_edge(e.kind).any())
            .map(|e| (e.key(g), e.host_units(g)))
            .collect();
        let keyed: Vec<ZoneKeys> = edges
            .into_iter()
            .zip(members)
            .map(|((z, es), (_, ms))| {
                (
                    z,
                    es.iter().map(|e| e.key(g)).collect(),
                    ms.iter().map(|ix| object_key(&g.node(*ix).id)).collect(),
                )
            })
            .collect();
        let objects = g.nodes().filter(|(_, n)| !n.placeholder).count();
        PathsTrack::update_checked(
            prev,
            &env_key(scopes),
            &keyed,
            now,
            objects,
            (may_resolve, host_may_resolve),
            &host_now,
            host_read,
        )
    }

    /// The zones of the environment `runs` are of; when they don't say
    /// (runs recorded before domains were), of the environment run last.
    pub fn zones_of(&self, runs: &Runs) -> Option<&BTreeMap<String, EdgeTrack>> {
        match runs.env() {
            Some(k) => self.envs.get(&k),
            None => self.envs.values().max_by_key(|e| e.at),
        }
        .map(|e| &e.zones)
    }

    /// Whether a run that loaded `objects` objects looks incomplete next to
    /// the last run of the environment `env`: fewer than half.
    pub fn shrunk(&self, env: &str, objects: usize) -> bool {
        self.envs
            .get(env)
            .is_some_and(|e| e.objects > 0 && objects * 2 < e.objects)
    }
}

// ------------------------------------------------------------------ periods

/// A period to look back over: the app's Introduced filter and Progress
/// picker, `pathwarden findings --introduced` and `pathwarden changes
/// --since`. Measured back from the latest run, not from today, as the
/// Progress range is ([`crate::history::Range`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    /// What the latest run found that the one before had not.
    LastRun,
    /// The `n` days up to the latest run.
    Days(i64),
    /// From the start of a day (Unix time, UTC) up to the latest run.
    From(i64),
    /// From the start of one day to the end of another (UTC).
    Between(i64, i64),
    /// Up to the end of a day (UTC), from the start of the history.
    Until(i64),
    /// The whole history.
    All,
}

impl Period {
    /// `last`, `7d`, `2w`, `1m` (30 days) or `3m` (91 days), `all`, a day
    /// `YYYY-MM-DD` (from then on) or two, `YYYY-MM-DD..YYYY-MM-DD`
    /// (either may be left out: `..YYYY-MM-DD` is up to that day).
    pub fn parse(s: &str) -> Result<Period, String> {
        let s = s.trim().to_ascii_lowercase();
        let bad = || {
            format!(
                "'{s}' is not a period: use last, 7d, 2w, 1m, 3m, all, a day (YYYY-MM-DD) or two (YYYY-MM-DD..YYYY-MM-DD)"
            )
        };
        match s.as_str() {
            "last" | "last-run" | "run" => return Ok(Period::LastRun),
            "all" => return Ok(Period::All),
            "1m" | "month" => return Ok(Period::Days(30)),
            "3m" | "quarter" => return Ok(Period::Days(91)),
            "week" => return Ok(Period::Days(7)),
            _ => {}
        }
        if let Some((a, b)) = s.split_once("..") {
            let day = |d: &str| crate::time::parse_date(d).ok_or_else(bad);
            return match (a.is_empty(), b.is_empty()) {
                (true, true) => Err(bad()),
                (false, true) => day(a).map(Period::From),
                (true, false) => day(b).map(Period::Until),
                (false, false) => {
                    let (a, b) = (day(a)?, day(b)?);
                    if b < a {
                        return Err(format!("'{s}': the second day is before the first"));
                    }
                    Ok(Period::Between(a, b))
                }
            };
        }
        if s.len() == 10 && s.as_bytes().get(4) == Some(&b'-') {
            return crate::time::parse_date(&s)
                .map(Period::From)
                .ok_or_else(bad);
        }
        // A count and its unit, split on a character (the input may end in
        // any character, not only a one-byte one).
        let Some(unit) = s.chars().last() else {
            return Err(bad());
        };
        let n: i64 = s[..s.len() - unit.len_utf8()].parse().map_err(|_| bad())?;
        if !(1..=36_500).contains(&n) {
            return Err(bad());
        }
        match unit {
            'd' => Ok(Period::Days(n)),
            'w' => Ok(Period::Days(n * 7)),
            _ => Err(bad()),
        }
    }

    /// The period of the Progress page's range switch
    /// ([`crate::history::Range`]): the same days.
    pub fn of_range(r: crate::history::Range) -> Period {
        use crate::history::Range;
        match r {
            Range::Week => Period::Days(7),
            Range::Month => Period::Days(30),
            Range::Quarter => Period::Days(91),
            Range::All => Period::All,
        }
    }

    /// What [`Period::parse`] reads back: for links and the command line.
    pub fn key(self) -> String {
        match self {
            Period::LastRun => "last".into(),
            Period::Days(n) => format!("{n}d"),
            Period::From(d) => day_key(d),
            Period::Between(a, b) => format!("{}..{}", day_key(a), day_key(b)),
            Period::Until(b) => format!("..{}", day_key(b)),
            Period::All => "all".into(),
        }
    }

    /// The first and last second of the period, both included, with the
    /// latest run at `latest`. Everything the latest run found carries its
    /// time, so "since the last run" is that one second. "7 days" leaves
    /// out a run exactly a week before the latest, so weekly runs at the
    /// same time put one run's changes in a week, not two.
    pub fn bounds(self, latest: i64) -> (i64, i64) {
        match self {
            Period::LastRun => (latest, latest),
            Period::Days(n) => (latest - n * DAY + 1, latest),
            Period::From(d) => (d, latest),
            Period::Between(a, b) => (a, b + DAY - 1),
            Period::Until(b) => (i64::MIN, b + DAY - 1),
            Period::All => (i64::MIN, latest),
        }
    }

    /// "since the last run", "in the 7 days up to Oct 18", "since Oct 1",
    /// "from Oct 1 to Oct 18", "up to Oct 18": how a heading or a line
    /// says it.
    pub fn describe(self, latest: i64) -> String {
        match self {
            Period::LastRun => "since the last run".into(),
            Period::Days(n) => format!(
                "in the {} up to {}",
                if n == 1 {
                    "day".to_string()
                } else {
                    format!("{n} days")
                },
                day(latest, latest)
            ),
            Period::From(d) => format!("since {}", day(d, latest)),
            Period::Between(a, b) => format!("from {} to {}", day(a, latest), day(b, latest)),
            Period::Until(b) => format!("up to {}", day(b, latest)),
            Period::All => "over the whole history".into(),
        }
    }
}

fn day_key(t: i64) -> String {
    crate::time::format_unix(t)
        .get(..10)
        .unwrap_or("")
        .to_string()
}

/// "Oct 18" (a UTC day), with the year when it isn't `latest`'s ("Oct 18,
/// 2025").
pub fn day(t: i64, latest: i64) -> String {
    let label = crate::time::format_month_day(t);
    let year = crate::time::format_iso_date(t);
    if crate::time::format_iso_date(latest).get(..4) == year.get(..4) {
        label
    } else {
        format!("{label}, {}", &year[..4])
    }
}

/// The runs of one environment, by time: which run number a date is; and,
/// when known, the domains it collected, so a state folder shared with
/// other environments shows only its own findings and zones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Runs {
    at: Vec<i64>,
    /// [`crate::state::scopes_of`] the domains its runs collected; empty
    /// when the history doesn't say (then nothing is left out).
    scopes: Vec<String>,
    /// The scopes of the domains they trust: a finding about an object
    /// there is the environment's too.
    trusted: Vec<String>,
}

impl Runs {
    /// From the times of the environment's runs (any order).
    pub fn new(mut at: Vec<i64>) -> Self {
        at.sort_unstable();
        at.dedup();
        Runs {
            at,
            ..Default::default()
        }
    }

    /// With the environment's domains: [`HistoryPoint::scopes`] and
    /// [`HistoryPoint::trusted_scopes`] of its runs.
    pub fn in_env(mut self, scopes: &[String], trusted: &[String]) -> Self {
        self.scopes = scopes.to_vec();
        self.trusted = trusted.to_vec();
        self.trusted.sort_unstable();
        self.trusted.dedup();
        self
    }

    /// [`Runs::in_env`] with the domains of one of its runs.
    pub fn in_env_of(self, p: &HistoryPoint) -> Self {
        let trusted = p.trusted_scopes.clone().unwrap_or_default();
        self.in_env(&p.scopes, &trusted)
    }

    /// The run recorded at `t`, counting from 1; `None` when none was.
    pub fn number(&self, t: i64) -> Option<usize> {
        self.at.binary_search(&t).ok().map(|i| i + 1)
    }

    pub fn is_empty(&self) -> bool {
        self.at.is_empty()
    }

    pub fn len(&self) -> usize {
        self.at.len()
    }

    /// The environment's key in [`PathsTrack::envs`], when its domains are
    /// known.
    pub fn env(&self) -> Option<String> {
        (!self.scopes.is_empty()).then(|| env_key(&self.scopes))
    }

    /// Whether a finding of the domain `scope` ([`crate::state::scope_key`])
    /// is this environment's: of a domain it collected or trusts, or of
    /// none. Unknown domains (an older history) keep everything.
    pub fn holds(&self, scope: Option<&str>) -> bool {
        match scope {
            None => true,
            Some(s) => {
                self.scopes.is_empty()
                    || self.scopes.iter().any(|x| x == s)
                    || self.trusted.iter().any(|x| x == s)
            }
        }
    }
}

/// What a period since the last run says when the environment has only
/// one run: the report and Progress offer no such period then.
pub const NO_EARLIER: &str = "No run before this one to compare with.";

/// "first seen Oct 18 (run 3)", or "back Oct 18 (run 3)" for an object
/// that had left; the run number when the history has it.
pub fn seen_label(at: i64, back: bool, runs: &Runs, latest: i64) -> String {
    let run = runs
        .number(at)
        .map(|n| format!(" (run {n})"))
        .unwrap_or_default();
    format!(
        "{} {}{run}",
        if back { "back" } else { "first seen" },
        day(at, latest)
    )
}

// ------------------------------------------------------------------- result

/// How a finding is net new in a period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Badge {
    /// First seen in the period.
    New,
    /// Back in the period after it was fixed.
    Back,
    /// Older, with objects that appeared in the period.
    Gained(usize),
}

impl Badge {
    /// "New", "Back", "+3 objects".
    pub fn label(self) -> String {
        match self {
            Badge::New => "New".into(),
            Badge::Back => "Back".into(),
            Badge::Gained(n) => format!("+{} object{}", thousands(n), s(n)),
        }
    }

    /// How a finding is new in `[from, to]`: first seen in it, else back in
    /// it, else the objects that appeared in it (`gained`: how many
    /// appeared when, beyond the baseline). The report's filter does the
    /// same in its script.
    pub fn of(
        first_seen: i64,
        back: Option<i64>,
        gained: &[(i64, usize)],
        from: i64,
        to: i64,
    ) -> Option<Badge> {
        let within = |t: i64| from <= t && t <= to;
        if within(first_seen) {
            return Some(Badge::New);
        }
        if back.is_some_and(within) {
            return Some(Badge::Back);
        }
        let n: usize = gained
            .iter()
            .filter(|(t, _)| within(*t))
            .map(|(_, n)| n)
            .sum();
        (n > 0).then_some(Badge::Gained(n))
    }
}

fn s(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// An object a finding gained in the period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntroObject {
    pub key: String,
    /// When it appeared (first seen, or back).
    pub at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<usize>,
    /// It had been listed before and left.
    pub back: bool,
    /// "first seen Oct 18 (run 3)".
    pub label: String,
    /// From the analysis, when the command or page has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<NodeKind>,
}

/// A finding net new in the period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntroFinding {
    pub fingerprint: String,
    pub rule: String,
    pub severity: Severity,
    /// When the state keeps names, or from the analysis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub badge: Badge,
    /// "New", "Back", "+3 objects".
    pub label: String,
    /// When it was first seen, came back, or last gained an object.
    pub at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<usize>,
    /// The objects it gained in the period, newest first ([`Badge::Gained`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<IntroObject>,
}

/// A finding resolved in the period, or one that lost objects in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutFinding {
    pub fingerprint: String,
    pub rule: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub at: i64,
    /// For a finding still open: how many objects it lost.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects: Option<usize>,
}

/// A new edge into a zone, or one back after it was resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntroPath {
    pub key: String,
    pub at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<usize>,
    /// It had been there before and was resolved ([`GONE_DAYS`]): back,
    /// not new, and not what `changes --fail-on new` fails on.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub back: bool,
    /// "first seen Oct 18 (run 3)", or "back Oct 18 (run 3)".
    pub label: String,
    /// Names and the plan, from the analysis ([`Names`]).
    #[serde(flatten)]
    pub named: Option<PathName>,
}

/// An edge as the analysis names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathName {
    pub from: String,
    pub from_kind: NodeKind,
    pub edge: String,
    pub to: String,
    pub to_kind: NodeKind,
    /// The start's object ID.
    pub from_id: String,
    /// The start in the analysis graph (Explore opens it).
    pub from_node: u32,
    /// The Tier Zero remediation plan's step that cuts it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cut: Option<Cut>,
}

/// How the Tier Zero remediation plan cuts a new path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "by", content = "step")]
pub enum Cut {
    /// The step removes this edge.
    Removes(usize),
    /// The step removes a way to the edge's start.
    Before(usize),
    /// No step is on the edge or right before it, but the plan cuts every
    /// path to Tier Zero: further back, by no single step.
    Upstream,
}

impl Cut {
    /// The step, when one is named.
    pub fn step(self) -> Option<usize> {
        match self {
            Cut::Removes(n) | Cut::Before(n) => Some(n),
            Cut::Upstream => None,
        }
    }

    /// "step 3 removes it", "step 3 cuts the way to it", "no single step;
    /// see the plan".
    pub fn words(self) -> String {
        match self {
            Cut::Removes(n) => format!("step {n} removes it"),
            Cut::Before(n) => format!("step {n} cuts the way to it"),
            Cut::Upstream => "no single step; see the plan".into(),
        }
    }
}

/// One zone's new and resolved edges in the period, and the members that
/// joined and left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZoneIntro {
    pub zone: String,
    /// Newest first: new ones and ones back after they were resolved
    /// ([`IntroPath::back`]).
    pub new: Vec<IntroPath>,
    pub resolved: usize,
    /// Objects that became members in the period (a new Domain Admin is a
    /// new member of Tier Zero): newest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub joined: Vec<IntroMember>,
    /// Members that left it in the period.
    #[serde(skip_serializing_if = "is_zero")]
    pub left: usize,
    /// More edges into it than [`ZONE_MAX`] at the last run: counted, none
    /// dated ([`Introduced::note`]).
    #[serde(skip_serializing_if = "is_zero")]
    pub undated_paths: usize,
    /// More members than [`ZONE_MAX`]: counted, none dated.
    #[serde(skip_serializing_if = "is_zero")]
    pub undated_members: usize,
}

impl ZoneIntro {
    /// Something new or resolved in the period (not only what isn't dated).
    fn changed(&self) -> bool {
        !self.new.is_empty() || self.resolved > 0 || !self.joined.is_empty() || self.left > 0
    }

    /// New paths into it, not back.
    pub fn first_seen_paths(&self) -> usize {
        self.new.iter().filter(|p| !p.back).count()
    }

    /// New members, not back.
    pub fn first_seen_members(&self) -> usize {
        self.joined.iter().filter(|m| !m.back).count()
    }
}

/// An object that joined a zone, or one back in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntroMember {
    pub key: String,
    pub at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<usize>,
    /// It had been a member before and left ([`GONE_DAYS`]).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub back: bool,
    pub label: String,
    /// Its name and the group that put it in the zone, from the analysis
    /// ([`Names`]).
    #[serde(flatten)]
    pub named: Option<MemberName>,
}

/// A zone member as the analysis names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemberName {
    pub name: String,
    pub kind: NodeKind,
    pub id: String,
    /// It in the analysis graph (Explore opens it).
    pub node: u32,
    /// The group in the zone it is a member of, when that is how it is in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

/// Everything net new in a period, and what was resolved in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Introduced {
    /// First and last second of the period (both included).
    pub from: i64,
    pub to: i64,
    /// When objects and paths began to be tracked (`None`: not yet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracked_since: Option<i64>,
    /// The period reaches back to (or before) the run tracking began in:
    /// there only whole findings are dated ([`Introduced::note`]).
    pub predates: bool,
    /// New, back and gained findings: most severe first.
    pub findings: Vec<IntroFinding>,
    /// Findings fixed in the period: most severe first.
    pub fixed: Vec<OutFinding>,
    /// Findings still open that lost objects in it.
    pub fewer: Vec<OutFinding>,
    /// Tier Zero, then the zones, each with something new or resolved.
    pub paths: Vec<ZoneIntro>,
    /// The accounts with an attack path to Tier Zero before the period and
    /// at its end, when the history has both and they compare
    /// ([`Introduced::with_exposure`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure: Option<ExposureMove>,
    /// The commands in the lines: `period` as [`Period::key`] gives it.
    #[serde(skip)]
    period: String,
}

/// The accounts with an attack path to Tier Zero at the run before a
/// period and at its last run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExposureMove {
    pub before: usize,
    pub after: usize,
}

impl Introduced {
    /// With how many accounts reached Tier Zero before the period and at
    /// its end, from the history `points` (any order) of `runs`'
    /// environment. A path can come back, or go, inside findings that stay
    /// open, so the count can move with nothing new or fixed: the lines
    /// then say so instead of "nothing".
    pub fn with_exposure(mut self, points: &[HistoryPoint], runs: &Runs) -> Self {
        let mut mine: Vec<&HistoryPoint> = points
            .iter()
            .filter(|p| !p.inserted)
            .filter(|p| p.scopes.is_empty() || runs.scopes.is_empty() || p.scopes == runs.scopes)
            .collect();
        mine.sort_by(|a, b| a.at.cmp(&b.at).then(a.run_id.cmp(&b.run_id)));
        let after = mine.iter().rev().find(|p| p.at <= self.to);
        let before = mine.iter().rev().find(|p| p.at < self.from);
        self.exposure = match (before, after) {
            (Some(b), Some(a)) if b.basis() == a.basis() && crate::since::comparable(b, a) => {
                Some(ExposureMove {
                    before: b.tier_zero_exposed,
                    after: a.tier_zero_exposed,
                })
            }
            _ => None,
        };
        self
    }
}

/// The latest run the state knows of: when its findings were last seen.
pub fn latest(state: &FindingsState) -> Option<i64> {
    state
        .findings
        .values()
        .map(|t| t.last_seen.max(t.resolved_at.unwrap_or(i64::MIN)))
        .chain(
            state
                .paths
                .iter()
                .flat_map(|p| p.envs.values().map(|e| e.at)),
        )
        .max()
}

/// Everything net new in `period` (with the latest run at `latest`), and
/// what was resolved in it, from the findings state; `runs` numbers the
/// runs and says which environment's findings and zones to read (a state
/// folder may hold several: [`Runs::holds`], [`PathsTrack::zones_of`]).
/// Accepted risks are left out. Name-free: [`Introduced::name`] adds the
/// names an analysis has.
pub fn period(state: &FindingsState, period: Period, latest: i64, runs: &Runs) -> Introduced {
    let (from, to) = period.bounds(latest);
    let within = |t: i64| from <= t && t <= to;
    let mut findings = Vec::new();
    let mut fixed = Vec::new();
    let mut fewer = Vec::new();
    for (fp, t) in &state.findings {
        if !runs.holds(t.scope.as_deref()) {
            // Another environment's, sharing the state folder.
            continue;
        }
        if t.status == Status::Resolved {
            if !t.rule_off && t.resolved_at.is_some_and(within) {
                fixed.push(OutFinding {
                    fingerprint: fp.clone(),
                    rule: t.rule.clone(),
                    severity: t.severity,
                    title: t.title.clone(),
                    at: t.resolved_at.unwrap_or_default(),
                    objects: None,
                });
            }
            continue;
        }
        if t.status != Status::Open {
            continue;
        }
        let gained_counts = t
            .objects
            .as_ref()
            .map(ObjectTrack::gained_counts)
            .unwrap_or_default();
        let badge = Badge::of(t.first_seen, t.regressed_at, &gained_counts, from, to);
        if let Some(badge) = badge {
            let (at, objects) = match badge {
                Badge::New => (t.first_seen, Vec::new()),
                Badge::Back => (t.regressed_at.unwrap_or(t.first_seen), Vec::new()),
                Badge::Gained(_) => {
                    let objects: Vec<IntroObject> = t
                        .objects
                        .as_ref()
                        .map(|o| o.gained(from, to))
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(k, at, back)| IntroObject {
                            key: k.to_string(),
                            at,
                            run: runs.number(at),
                            back,
                            label: seen_label(at, back, runs, latest),
                            id: None,
                            name: None,
                            kind: None,
                        })
                        .collect();
                    (objects.first().map_or(t.last_seen, |o| o.at), objects)
                }
            };
            findings.push(IntroFinding {
                fingerprint: fp.clone(),
                rule: t.rule.clone(),
                severity: t.severity,
                title: t.title.clone(),
                badge,
                label: badge.label(),
                at,
                run: runs.number(at),
                objects,
            });
        }
        if !matches!(badge, Some(Badge::New | Badge::Back)) {
            let n = t.objects.as_ref().map_or(0, |o| o.removed(from, to));
            if n > 0 {
                fewer.push(OutFinding {
                    fingerprint: fp.clone(),
                    rule: t.rule.clone(),
                    severity: t.severity,
                    title: t.title.clone(),
                    at: to,
                    objects: Some(n),
                });
            }
        }
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.badge.cmp(&b.badge))
            .then(b.at.cmp(&a.at))
            .then(a.rule.cmp(&b.rule))
            .then(a.title.cmp(&b.title))
            .then(a.fingerprint.cmp(&b.fingerprint))
    });
    let by_severity = |a: &OutFinding, b: &OutFinding| {
        b.severity
            .cmp(&a.severity)
            .then(a.rule.cmp(&b.rule))
            .then(a.title.cmp(&b.title))
            .then(a.fingerprint.cmp(&b.fingerprint))
    };
    fixed.sort_by(by_severity);
    fewer.sort_by(by_severity);
    let mut paths = Vec::new();
    if let Some(p) = state.paths.as_ref().and_then(|p| p.zones_of(runs)) {
        // Tier Zero first, then the zones by name.
        let mut zones: Vec<(&String, &EdgeTrack)> = p.iter().collect();
        zones.sort_by_key(|(n, _)| (n.as_str() != TIER_ZERO, n.to_lowercase()));
        for (zone, z) in zones {
            let edges = z.edges();
            let new: Vec<IntroPath> = edges
                .new_in(from, to)
                .into_iter()
                .map(|(t, k, back)| IntroPath {
                    key: k.to_string(),
                    at: t,
                    run: runs.number(t),
                    back,
                    label: seen_label(t, back, runs, latest),
                    named: None,
                })
                .collect();
            let members = z.members();
            let joined: Vec<IntroMember> = members
                .map(|m| m.new_in(from, to))
                .unwrap_or_default()
                .into_iter()
                .map(|(t, k, back)| IntroMember {
                    key: k.to_string(),
                    at: t,
                    run: runs.number(t),
                    back,
                    label: seen_label(t, back, runs, latest),
                    named: None,
                })
                .collect();
            let intro = ZoneIntro {
                zone: zone.clone(),
                new,
                resolved: edges.resolved_in(from, to),
                joined,
                left: members.map_or(0, |m| m.resolved_in(from, to)),
                undated_paths: edges.undated,
                undated_members: members.map_or(0, |m| m.undated),
            };
            if intro.changed() || intro.undated_paths > 0 || intro.undated_members > 0 {
                paths.push(intro);
            }
        }
    }
    Introduced {
        from,
        to,
        tracked_since: state.tracked_since,
        predates: state.tracked_since.is_none_or(|t| from <= t),
        findings,
        fixed,
        fewer,
        paths,
        exposure: None,
        period: period.key(),
    }
}

/// The latest run of an environment in the history `points` (oldest
/// first), and its runs, to number them: of `domains` when given, else of
/// the latest run's. A state folder may hold several environments: the
/// runs say which is meant ([`Runs::holds`]).
pub fn runs_of(points: &[HistoryPoint], domains: Option<&[String]>) -> (Option<i64>, Runs) {
    let mut points = points.to_vec();
    crate::state::migrate_points(&mut points);
    let Some(last) = crate::since::latest_point(&points) else {
        return (None, Runs::default());
    };
    let scopes = match domains {
        Some(d) => crate::state::scopes_of(d),
        None => last.scopes.clone(),
    };
    let mine: Vec<&HistoryPoint> = points
        .iter()
        .filter(|p| p.scopes.is_empty() || scopes.is_empty() || p.scopes == scopes)
        .collect();
    let trusted: Vec<String> = mine
        .iter()
        .flat_map(|p| p.trusted_scopes.iter().flatten().cloned())
        .collect();
    // The latest run the findings state is of: never a point added after a
    // newer run.
    let latest = mine
        .iter()
        .filter(|p| !p.inserted)
        .map(|p| p.at)
        .max()
        .or_else(|| mine.iter().map(|p| p.at).max())
        .unwrap_or(last.at);
    (
        Some(latest),
        Runs::new(mine.iter().map(|p| p.at).collect()).in_env(&scopes, &trusted),
    )
}

/// [`Introduced::note`]'s words, for a state whose tracking began at
/// `tracked_since`.
pub fn tracking_note(tracked_since: Option<i64>, runs: &Runs, latest: i64) -> String {
    match tracked_since {
        None => "Objects and paths are not dated yet: the next run starts dating them. Until then only whole findings are.".to_string(),
        Some(t) => {
            let run = runs
                .number(t)
                .map(|n| format!(" (run {n})"))
                .unwrap_or_default();
            format!(
                "Objects and paths are dated from {}{run} on; before that, only whole findings are.",
                day(t, latest)
            )
        }
    }
}

/// What the report's Introduced filter needs, for a report of the run that
/// left `state` (at `latest`): each finding's dates and objects (read from
/// the state as the page renders), the new paths there are (beyond each
/// zone's baseline, the newest [`PATHS_LISTED`], named), and when findings
/// were fixed. The page's script picks a period over them as [`period`]
/// does.
pub struct ForReport<'a> {
    pub state: &'a FindingsState,
    pub latest: i64,
    pub runs: Runs,
    /// There is a run before this one: "since the last run" means something.
    pub has_earlier: bool,
    /// Newest first, with their zone.
    pub paths: Vec<(String, IntroPath)>,
    /// New paths left out of `paths`.
    pub paths_more: usize,
    /// New members of Tier Zero and the zones, newest first, with their
    /// zone (at most [`PATHS_LISTED`]).
    pub members: Vec<(String, IntroMember)>,
    /// When each fixed finding was fixed.
    pub fixed: Vec<i64>,
}

impl<'a> ForReport<'a> {
    pub fn new(
        state: &'a FindingsState,
        latest: i64,
        runs: Runs,
        has_earlier: bool,
        names: &Names,
    ) -> Self {
        let mut all = period(state, Period::All, latest, &runs);
        all.name(names);
        let mut paths: Vec<(String, IntroPath)> = all
            .paths
            .iter()
            .flat_map(|z| z.new.iter().map(|p| (z.zone.clone(), p.clone())))
            .collect();
        let mut members: Vec<(String, IntroMember)> = all
            .paths
            .iter()
            .flat_map(|z| z.joined.iter().map(|m| (z.zone.clone(), m.clone())))
            .collect();
        members.sort_by(|a, b| {
            b.1.at
                .cmp(&a.1.at)
                .then((a.0 != TIER_ZERO).cmp(&(b.0 != TIER_ZERO)))
                .then(a.0.cmp(&b.0))
                .then(a.1.key.cmp(&b.1.key))
        });
        members.truncate(PATHS_LISTED);
        // The newest first; then Tier Zero before the zones, and by name.
        let name = |p: &IntroPath| {
            p.named
                .as_ref()
                .map(|n| (n.from.clone(), n.to.clone()))
                .unwrap_or_default()
        };
        paths.sort_by(|a, b| {
            b.1.at
                .cmp(&a.1.at)
                .then((a.0 != TIER_ZERO).cmp(&(b.0 != TIER_ZERO)))
                .then(a.0.cmp(&b.0))
                .then(name(&a.1).cmp(&name(&b.1)))
                .then(a.1.key.cmp(&b.1.key))
        });
        let paths_more = paths.len().saturating_sub(PATHS_LISTED);
        paths.truncate(PATHS_LISTED);
        ForReport {
            state,
            latest,
            runs,
            has_earlier,
            paths,
            paths_more,
            members,
            fixed: all.fixed.iter().map(|f| f.at).collect(),
        }
    }

    /// The lines of `period`, as `pathwarden changes` says them: what the
    /// page's summary shows for the choices it offers.
    pub fn lines(&self, period: Period) -> Vec<Line> {
        crate::introduced::period(self.state, period, self.latest, &self.runs).lines()
    }

    /// The zones of the report's environment, and their edges and members.
    pub fn zones(&self) -> impl Iterator<Item = (&'a String, &'a EdgeTrack)> {
        self.state
            .paths
            .as_ref()
            .and_then(|p| p.zones_of(&self.runs))
            .into_iter()
            .flatten()
    }

    /// A finding's dates, as the state has them.
    pub fn finding(&self, fingerprint: &str) -> Option<&crate::state::TrackedFinding> {
        self.state.findings.get(fingerprint)
    }

    /// "first seen Oct 18 (run 3)".
    pub fn label(&self, at: i64, back: bool) -> String {
        seen_label(at, back, &self.runs, self.latest)
    }

    /// [`Period::describe`] for the page's choices.
    pub fn describe(&self, period: Period) -> String {
        period.describe(self.latest)
    }

    /// [`tracking_note`].
    pub fn note(&self) -> String {
        tracking_note(self.state.tracked_since, &self.runs, self.latest)
    }
}

/// What an analysis can name: its findings' titles and objects, and the
/// edges into Tier Zero and the zones, with the remediation plan's steps.
pub struct Names<'a> {
    findings: HashMap<&'a str, &'a Finding>,
    paths: HashMap<String, PathName>,
    /// Zone members by [`object_key`], per zone.
    members: HashMap<String, HashMap<String, MemberName>>,
}

impl<'a> Names<'a> {
    /// From an analysis: its findings, graph and zones, and Tier Zero's
    /// remediation `plan` when there is one.
    pub fn new(
        findings: &'a [Finding],
        g: &AdGraph,
        zones: &[Zone],
        plan: Option<&RemediationPlan>,
    ) -> Self {
        let mut paths = HashMap::new();
        for (zone, edges) in zone_edges(g, zones) {
            let t0 = zone == TIER_ZERO;
            for e in edges {
                let (from, to) = (g.node(e.from), g.node(e.to));
                let edge = e.kind.as_str();
                let cut = plan.filter(|_| t0).and_then(|p| {
                    let removes = p.fixes.iter().position(|f| {
                        f.from == from.name && f.to == to.name && f.edges.contains(&e.kind)
                    });
                    match removes {
                        Some(i) => Some(Cut::Removes(i + 1)),
                        None => p
                            .fixes
                            .iter()
                            .position(|f| f.to == from.name)
                            .map(|i| Cut::Before(i + 1))
                            .or((p.exposed_after == 0 && !p.fixes.is_empty())
                                .then_some(Cut::Upstream)),
                    }
                });
                paths.insert(
                    e.key(g),
                    PathName {
                        from: from.name.clone(),
                        from_kind: from.kind,
                        edge: edge.to_string(),
                        to: to.name.clone(),
                        to_kind: to.kind,
                        from_id: from.id.clone(),
                        from_node: e.from.index() as u32,
                        cut,
                    },
                );
            }
        }
        let mut members: HashMap<String, HashMap<String, MemberName>> = HashMap::new();
        for (zone, ixs) in zone_members(g, zones) {
            let inside: HashSet<NodeIndex> = ixs.iter().copied().collect();
            let named = ixs
                .iter()
                .map(|&ix| {
                    let n = g.node(ix);
                    // The group in the zone that puts it there.
                    let via = g
                        .inner()
                        .edges_directed(ix, Direction::Outgoing)
                        .filter(|e| *e.weight() == crate::model::EdgeKind::MemberOf)
                        .map(|e| e.target())
                        .filter(|t| inside.contains(t))
                        .map(|t| g.node(t).name.clone())
                        .min();
                    (
                        object_key(&n.id),
                        MemberName {
                            name: n.name.clone(),
                            kind: n.kind,
                            id: n.id.clone(),
                            node: ix.index() as u32,
                            via,
                        },
                    )
                })
                .collect();
            members.insert(crate::zones::name_key(&zone), named);
        }
        Names {
            findings: findings
                .iter()
                .map(|f| (f.fingerprint.as_str(), f))
                .collect(),
            paths,
            members,
        }
    }

    /// A member of `zone` by its [`object_key`], in this analysis.
    pub fn member(&self, zone: &str, key: &str) -> Option<&MemberName> {
        self.members
            .get(&crate::zones::name_key(zone))
            .and_then(|m| m.get(key))
    }

    /// The path an edge key stands for, in this analysis.
    pub fn path(&self, key: &str) -> Option<&PathName> {
        self.paths.get(key)
    }
}

impl Introduced {
    /// Adds what `names` knows: titles, the gained objects' names, and the
    /// new paths' ends and plan steps.
    pub fn name(&mut self, names: &Names) {
        for f in &mut self.findings {
            let Some(found) = names.findings.get(f.fingerprint.as_str()) else {
                continue;
            };
            f.title = Some(found.title.clone());
            if f.objects.is_empty() {
                continue;
            }
            let by_key: HashMap<String, &crate::findings::Affected> = found
                .affected
                .iter()
                .map(|a| (object_key(&a.id), a))
                .collect();
            for o in &mut f.objects {
                if let Some(a) = by_key.get(&o.key) {
                    o.id = Some(a.id.clone());
                    o.name = Some(a.name.clone());
                    o.kind = Some(a.kind);
                }
            }
        }
        for f in self.fixed.iter_mut().chain(self.fewer.iter_mut()) {
            if let Some(found) = names.findings.get(f.fingerprint.as_str()) {
                f.title = Some(found.title.clone());
            }
        }
        for z in &mut self.paths {
            for p in &mut z.new {
                p.named = names.paths.get(&p.key).cloned();
            }
            for m in &mut z.joined {
                m.named = names.member(&z.zone, &m.key).cloned();
            }
        }
    }

    /// Nothing new and nothing resolved.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
            && self.fixed.is_empty()
            && self.fewer.is_empty()
            && !self.paths.iter().any(ZoneIntro::changed)
    }

    /// New members in all zones (not those back).
    pub fn joined(&self) -> usize {
        self.paths.iter().map(ZoneIntro::first_seen_members).sum()
    }

    /// New paths in all zones (not those back).
    pub fn new_paths(&self) -> usize {
        self.paths.iter().map(ZoneIntro::first_seen_paths).sum()
    }

    /// Paths and members back in all zones after they were resolved.
    pub fn back_in_zones(&self) -> usize {
        self.paths
            .iter()
            .map(|z| z.new.len() + z.joined.len() - z.first_seen_paths() - z.first_seen_members())
            .sum()
    }

    /// The muted note when the period reaches back before objects and paths
    /// were tracked: "Objects and paths are dated from Oct 18 (run 3) on;
    /// before that, only whole findings are."; and when a zone has more
    /// edges or members than are dated ([`ZONE_MAX`]).
    pub fn note(&self, runs: &Runs, latest: i64) -> Option<String> {
        let notes: Vec<String> = self
            .predates
            .then(|| tracking_note(self.tracked_since, runs, latest))
            .into_iter()
            .chain(self.undated_note())
            .collect();
        (!notes.is_empty()).then(|| notes.join(" "))
    }

    /// "Not dated, more than 50,000 per zone: 61,204 paths into Domain
    /// Users."
    pub fn undated_note(&self) -> Option<String> {
        let parts: Vec<String> = self
            .paths
            .iter()
            .flat_map(|z| {
                [
                    (z.undated_paths > 0).then(|| {
                        format!(
                            "{} path{} into {}",
                            thousands(z.undated_paths),
                            s(z.undated_paths),
                            z.zone
                        )
                    }),
                    (z.undated_members > 0).then(|| {
                        format!(
                            "{} member{} of {}",
                            thousands(z.undated_members),
                            s(z.undated_members),
                            z.zone
                        )
                    }),
                ]
            })
            .flatten()
            .collect();
        (!parts.is_empty()).then(|| {
            format!(
                "Not dated, more than {} per zone: {}.",
                thousands(ZONE_MAX),
                parts.join(", ")
            )
        })
    }

    /// "Introduced in the 7 days up to Oct 18 (first seen by Pathwarden)".
    pub fn heading(period: Period, latest: i64) -> String {
        format!(
            "Introduced {} (first seen by Pathwarden)",
            period.describe(latest)
        )
    }

    /// The lines as text for the terminal, as `pathwarden changes` prints
    /// them: under [`Introduced::heading`], with the note when the period
    /// reaches back before objects were dated. `context`: the settings the
    /// commands take ([`crate::since::commands_note`]).
    pub fn render(&self, period: Period, latest: i64, runs: &Runs, context: &[String]) -> String {
        crate::since::render_lines(
            &format!("{}:", Introduced::heading(period, latest)),
            &self.lines(),
            self.note(runs, latest).as_deref(),
            context,
        )
    }

    fn next(&self, args: &[&str]) -> Option<Next> {
        let mut v: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        v.push(self.period.clone());
        Some(Next(v))
    }

    /// The period as lines: new, back and gained findings, new paths per
    /// zone, then what was resolved, each naming the first few. With
    /// nothing at all, one line saying so.
    pub fn lines(&self) -> Vec<Line> {
        self.lines_of(true)
    }

    /// Only what the counts of two runs don't say: findings that gained or
    /// lost objects, and paths that appeared or went. What changed since the
    /// last run adds these to its lines ([`crate::since::SinceLast`]).
    pub fn extra_lines(&self) -> Vec<Line> {
        self.lines_of(false)
    }

    fn lines_of(&self, all: bool) -> Vec<Line> {
        let mut out = Vec::new();
        let count = |b: fn(&Badge) -> bool| self.findings.iter().filter(|f| b(&f.badge)).count();
        let named = |b: fn(&Badge) -> bool| -> Vec<String> {
            name_items(
                self.findings
                    .iter()
                    .filter(|f| b(&f.badge))
                    .map(|f| finding_name(&f.rule, f.severity, f.title.as_deref())),
            )
        };
        let new = count(|b| *b == Badge::New);
        if all && new > 0 {
            out.push(Line {
                introduced: false,
                tier_zero: false,
                tone: Tone::Worse,
                text: format!("{} new finding{}", thousands(new), s(new)),
                items: named(|b| *b == Badge::New),
                next: self.next(&["findings", "--introduced"]),
            });
        }
        let back = count(|b| *b == Badge::Back);
        if all && back > 0 {
            out.push(Line {
                introduced: false,
                tier_zero: false,
                tone: Tone::Worse,
                text: format!(
                    "{} finding{} back after {} fixed",
                    thousands(back),
                    s(back),
                    if back == 1 { "it was" } else { "they were" }
                ),
                items: named(|b| *b == Badge::Back),
                next: self.next(&["findings", "--introduced"]),
            });
        }
        let gained: Vec<&IntroFinding> = self
            .findings
            .iter()
            .filter(|f| matches!(f.badge, Badge::Gained(_)))
            .collect();
        if !gained.is_empty() {
            let objects: usize = gained
                .iter()
                .map(|f| match f.badge {
                    Badge::Gained(n) => n,
                    _ => 0,
                })
                .sum();
            let mut items: Vec<String> = gained
                .iter()
                .take(NAMED)
                .map(|f| {
                    let names: Vec<&str> = f
                        .objects
                        .iter()
                        .filter_map(|o| o.name.as_deref())
                        .take(NAMED)
                        .collect();
                    let more = f.objects.len().saturating_sub(names.len());
                    let list = match (names.is_empty(), more) {
                        (true, _) => String::new(),
                        (false, 0) => format!(" ({})", names.join(", ")),
                        (false, m) => format!(" ({}, and {} more)", names.join(", "), thousands(m)),
                    };
                    format!(
                        "{}: {}{list}",
                        finding_name(&f.rule, f.severity, f.title.as_deref()),
                        f.badge.label()
                    )
                })
                .collect();
            if gained.len() > NAMED {
                items.push(format!("and {} more", thousands(gained.len() - NAMED)));
            }
            out.push(Line {
                introduced: false,
                tier_zero: false,
                tone: Tone::Worse,
                text: format!(
                    "{} older finding{} gained {} object{}",
                    thousands(gained.len()),
                    s(gained.len()),
                    thousands(objects),
                    s(objects)
                ),
                items,
                next: self.next(&["findings", "--introduced"]),
            });
        }
        for z in &self.paths {
            if !z.joined.is_empty() {
                out.push(joined_line(z));
            }
            if z.new.is_empty() {
                continue;
            }
            let n = z.new.len();
            let mut items: Vec<String> = z
                .new
                .iter()
                .take(NAMED)
                .filter_map(|p| p.named.as_ref().map(|nm| path_words(nm, &p.label)))
                .collect();
            if !items.is_empty() && n > items.len() {
                items.push(format!("and {} more", thousands(n - items.len())));
            }
            out.push(Line {
                introduced: false,
                tier_zero: false,
                tone: Tone::Worse,
                text: new_and_back(
                    z.first_seen_paths(),
                    n - z.first_seen_paths(),
                    ("new path", "new paths"),
                    ("path", "paths"),
                    &format!("into {}", z.zone),
                    &format!("back into {}", z.zone),
                ),
                items,
                // The plan that cuts them.
                next: Some(if z.zone == TIER_ZERO {
                    Next(vec!["plan".into()])
                } else {
                    Next(vec!["plan".into(), format!("--zone={}", z.zone)])
                }),
            });
        }
        if all && !self.fixed.is_empty() {
            let n = self.fixed.len();
            let items = name_items(
                self.fixed
                    .iter()
                    .map(|f| finding_name(&f.rule, f.severity, f.title.as_deref())),
            );
            out.push(Line {
                introduced: false,
                tier_zero: false,
                tone: Tone::Better,
                text: format!("{} finding{} fixed", thousands(n), s(n)),
                items,
                next: None,
            });
        }
        if !self.fewer.is_empty() {
            let n = self.fewer.len();
            let objects: usize = self.fewer.iter().filter_map(|f| f.objects).sum();
            let mut items: Vec<String> = self
                .fewer
                .iter()
                .take(NAMED)
                .map(|f| {
                    format!(
                        "{}: -{}",
                        finding_name(&f.rule, f.severity, f.title.as_deref()),
                        thousands(f.objects.unwrap_or(0))
                    )
                })
                .collect();
            if n > NAMED {
                items.push(format!("and {} more", thousands(n - NAMED)));
            }
            out.push(Line {
                introduced: false,
                tier_zero: false,
                tone: Tone::Better,
                text: format!(
                    "{} finding{} lost {} object{}",
                    thousands(n),
                    s(n),
                    thousands(objects),
                    s(objects)
                ),
                items,
                next: None,
            });
        }
        for z in self.paths.iter().filter(|z| z.left > 0) {
            out.push(Line {
                introduced: false,
                tier_zero: false,
                tone: Tone::Better,
                text: format!("{} member{} left {}", thousands(z.left), s(z.left), z.zone),
                items: Vec::new(),
                next: None,
            });
        }
        for z in self.paths.iter().filter(|z| z.resolved > 0) {
            out.push(Line {
                introduced: false,
                tier_zero: false,
                tone: Tone::Better,
                text: format!(
                    "{} path{} into {} gone",
                    thousands(z.resolved),
                    s(z.resolved),
                    z.zone
                ),
                items: Vec::new(),
                next: None,
            });
        }
        let exposure = self
            .exposure
            .filter(|m| all && m.before != m.after)
            .map(|m| {
                let n = m.before.abs_diff(m.after);
                let (more, tone) = if m.after > m.before {
                    ("more", Tone::Worse)
                } else {
                    ("fewer", Tone::Better)
                };
                let text = format!(
                    "{} {more} account{} with an attack path to Tier Zero ({} → {}){}",
                    thousands(n),
                    s(n),
                    thousands(m.before),
                    thousands(m.after),
                    if out.is_empty() {
                        if m.after > m.before {
                            ", through findings already open: nothing new"
                        } else {
                            ", in findings still open: nothing fixed"
                        }
                    } else {
                        ""
                    }
                );
                Line {
                    introduced: false,
                    tier_zero: true,
                    tone,
                    text,
                    items: Vec::new(),
                    next: Some(Next(vec!["plan".into()])),
                }
            });
        if all && out.is_empty() && exposure.is_none() {
            out.push(Line {
                introduced: false,
                tier_zero: false,
                tone: Tone::Same,
                text: "Nothing new, and nothing fixed".into(),
                items: Vec::new(),
                next: None,
            });
        }
        // What is new, back or gained (the worse lines) is what the
        // Introduced filter shows.
        for l in &mut out {
            l.introduced = l.tone == Tone::Worse;
        }
        // The count says what the history says; nothing in it is first
        // seen, so the filter has nothing to show for it.
        out.extend(exposure);
        out
    }
}

impl Introduced {
    /// Every new member and path, zone by zone, one a line, each path with
    /// the step that cuts it: the report's "New in Tier Zero and the zones"
    /// for the terminal (`pathwarden changes --paths`), not cut at
    /// [`NAMED`]. Those the analysis doesn't name (not in it any more) are
    /// counted.
    pub fn listing(&self) -> String {
        let mut out = String::new();
        let zones: Vec<&ZoneIntro> = self
            .paths
            .iter()
            .filter(|z| !z.new.is_empty() || !z.joined.is_empty())
            .collect();
        if zones.is_empty() {
            out.push_str("No new members of Tier Zero or the zones, and no new paths into them, in this period.\n");
            return out;
        }
        out.push_str("New in Tier Zero and the zones:\n");
        for z in zones {
            out.push_str(&format!("  {}\n", z.zone));
            let mut unnamed = 0;
            for m in &z.joined {
                match &m.named {
                    Some(nm) => {
                        out.push_str(&format!("    member  {}\n", member_words(nm, &m.label)))
                    }
                    None => unnamed += 1,
                }
            }
            for p in &z.new {
                match &p.named {
                    Some(nm) => {
                        let when = p.label.strip_prefix("first seen ").unwrap_or(&p.label);
                        let cut = nm.cut.map_or("no plan step".to_string(), Cut::words);
                        out.push_str(&format!(
                            "    path    {} -[{}]-> {} · {when} · {cut}\n",
                            nm.from, nm.edge, nm.to
                        ));
                    }
                    None => unnamed += 1,
                }
            }
            if unnamed > 0 {
                out.push_str(&format!(
                    "    and {} not in this collection (named only from the run that found them)\n",
                    thousands(unnamed)
                ));
            }
        }
        out
    }
}

/// "2 new members of Tier Zero", naming the first few and the group each
/// is in by.
fn joined_line(z: &ZoneIntro) -> Line {
    let n = z.joined.len();
    let mut items: Vec<String> = z
        .joined
        .iter()
        .take(NAMED)
        .filter_map(|m| m.named.as_ref().map(|nm| member_words(nm, &m.label)))
        .collect();
    if !items.is_empty() && n > items.len() {
        items.push(format!("and {} more", thousands(n - items.len())));
    }
    Line {
        introduced: false,
        tier_zero: false,
        tone: Tone::Worse,
        text: new_and_back(
            z.first_seen_members(),
            n - z.first_seen_members(),
            ("new member", "new members"),
            ("member", "members"),
            &format!("of {}", z.zone),
            &format!("back in {}", z.zone),
        ),
        items,
        next: Some(if z.zone == TIER_ZERO {
            Next(vec!["tier-zero".into()])
        } else {
            Next(vec!["zones".into()])
        }),
    }
}

/// "3 new paths into Tier Zero", "2 paths back into Tier Zero", "3 new
/// paths into Tier Zero, 2 back": what came back after it was resolved is
/// said apart from what is new.
fn new_and_back(
    new: usize,
    back: usize,
    new_words: (&str, &str),
    back_words: (&str, &str),
    new_rest: &str,
    back_rest: &str,
) -> String {
    let words =
        |n: usize, w: (&str, &str)| format!("{} {}", thousands(n), if n == 1 { w.0 } else { w.1 });
    match (new, back) {
        (_, 0) => format!("{} {new_rest}", words(new, new_words)),
        (0, _) => format!("{} {back_rest}", words(back, back_words)),
        _ => format!(
            "{} {new_rest}, {} back",
            words(new, new_words),
            thousands(back)
        ),
    }
}

/// The first [`NAMED`] of `names`, the same name said once with how many
/// times ("critical PW-006 Kerberoastable account ×3"), then "and N more".
fn name_items(names: impl Iterator<Item = String>) -> Vec<String> {
    let mut groups: Vec<(String, usize)> = Vec::new();
    for n in names {
        match groups.iter_mut().find(|(g, _)| *g == n) {
            Some((_, c)) => *c += 1,
            None => groups.push((n, 1)),
        }
    }
    let total: usize = groups.iter().map(|(_, c)| c).sum();
    let shown: usize = groups.iter().take(NAMED).map(|(_, c)| c).sum();
    let mut items: Vec<String> = groups
        .into_iter()
        .take(NAMED)
        .map(|(n, c)| if c > 1 { format!("{n} ×{c}") } else { n })
        .collect();
    if total > shown {
        items.push(format!("and {} more", thousands(total - shown)));
    }
    items
}

/// "BOB@CONTOSO.LOCAL, member of DOMAIN ADMINS@CONTOSO.LOCAL · Oct 18
/// (run 3)": `label` is the member's [`seen_label`].
pub fn member_words(m: &MemberName, label: &str) -> String {
    let when = label.strip_prefix("first seen ").unwrap_or(label);
    match &m.via {
        Some(g) => format!("{}, member of {g} · {when}", m.name),
        None => format!("{} · {when}", m.name),
    }
}

/// "critical PW-003 JDOE has GenericAll on DC01", or the rule's own title
/// when no name is known; as what changed since the last run names them.
fn finding_name(rule: &str, severity: Severity, title: Option<&str>) -> String {
    let title = title.map(str::to_string).or_else(|| {
        crate::findings::rules()
            .iter()
            .find(|r| r.id == rule)
            .map(|r| r.title.to_string())
    });
    match title {
        Some(t) => format!("{} {rule} {t}", severity.as_str()),
        None => format!("{} {rule}", severity.as_str()),
    }
}

/// "JDOE@CONTOSO.LOCAL -[GenericAll]-> DOMAIN ADMINS@CONTOSO.LOCAL · Oct 18
/// (run 3) · step 2": short, for a line's items (the terminal cuts them at
/// its width); `label` is the path's [`seen_label`].
pub fn path_words(p: &PathName, label: &str) -> String {
    let when = label.strip_prefix("first seen ").unwrap_or(label);
    let cut = match p.cut {
        Some(Cut::Removes(n)) => format!(" · step {n}"),
        Some(Cut::Before(n)) => format!(" · step {n} on the way"),
        Some(Cut::Upstream) => " · see the plan".to_string(),
        None => String::new(),
    };
    format!("{} -[{}]-> {} · {when}{cut}", p.from, p.edge, p.to)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The findings state's object keys and the exposed accounts' keys
    ///  are one key: what the state has written stays the same.
    #[test]
    fn object_keys_are_the_exposed_keys() {
        let id = "S-1-5-21-3623811015-3361044348-30300820-1013";
        assert_eq!(object_key(id), "9335316a4e48d044");
        assert_eq!(object_key(id), fnv(&["o", id]));
        assert_eq!(
            object_key(&format!(" {} ", id.to_lowercase())),
            object_key(id)
        );
        assert_eq!(crate::exposed::key(id), 0x9335_316a_4e48_d044);
    }

    /// [`PathsTrack::update`] of one environment, "e".
    fn up(prev: Option<&PathsTrack>, zones: &[ZoneKeys], now: i64, may: bool) -> PathsTrack {
        PathsTrack::update(prev, "e", zones, now, 0, may)
    }

    /// The zones of "e".
    fn zt(p: &PathsTrack) -> &BTreeMap<String, EdgeTrack> {
        &p.envs["e"].zones
    }

    fn keys(ids: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = ids.iter().map(|i| object_key(i)).collect();
        v.sort();
        v
    }

    #[test]
    fn objects_are_dated_when_they_appear_and_back_when_they_return() {
        let t1 = ObjectTrack::update(None, &["S-1", "S-2"], 100, None, false);
        assert_eq!(t1.since, 100);
        assert!(t1.gained(0, i64::MAX).is_empty(), "the baseline is not new");
        let t2 = ObjectTrack::update(Some(&t1), &["S-1", "S-2", "S-3"], 200, None, false);
        assert_eq!(
            t2.gained(150, 200),
            vec![(object_key("S-3").as_str(), 200, false)]
        );
        // S-2 leaves, then returns: back, not new.
        let t3 = ObjectTrack::update(Some(&t2), &["S-1", "S-3"], 300, None, false);
        assert_eq!(t3.removed(300, 300), 1);
        let t4 = ObjectTrack::update(Some(&t3), &["S-1", "S-2", "S-3"], 400, None, false);
        assert_eq!(
            t4.gained(400, 400),
            vec![(object_key("S-2").as_str(), 400, true)]
        );
        assert!(t4.gone.is_empty());
        // A resolved finding's objects all left with it.
        let t5 = ObjectTrack::update(Some(&t4), &["S-1", "S-4"], 600, Some(500), false);
        let g: Vec<(String, bool)> = t5
            .gained(600, 600)
            .into_iter()
            .map(|(k, _, b)| (k.to_string(), b))
            .collect();
        assert!(g.contains(&(object_key("S-1"), true)));
        assert!(g.contains(&(object_key("S-4"), false)));
        assert_eq!(t5.removed(500, 500), 2, "S-2 and S-3 left at 500");
        // Departed objects are forgotten after GONE_DAYS.
        let late = 600 + (GONE_DAYS + 1) * DAY;
        let t6 = ObjectTrack::update(Some(&t5), &["S-1", "S-4"], late, None, false);
        assert!(t6.gone.is_empty());
        let t7 = ObjectTrack::update(Some(&t6), &["S-1", "S-2", "S-4"], late + 1, None, false);
        assert!(!t7.gained(late + 1, late + 1)[0].2, "new again");
    }

    #[test]
    fn keys_are_packed_one_string_per_run() {
        let t1 = ObjectTrack::update(None, &["S-1", "S-2"], 100, None, false);
        let t2 = ObjectTrack::update(Some(&t1), &["S-1", "S-2", "S-3"], 200, None, false);
        let text = serde_json::to_string(&t2).unwrap();
        let k = keys(&["S-1", "S-2"]);
        assert_eq!(
            text,
            format!(r#""100 {} {} @200 {}""#, k[0], k[1], object_key("S-3"))
        );
        assert_eq!(serde_json::from_str::<ObjectTrack>(&text).unwrap(), t2);
        // Back and gone too.
        let t3 = ObjectTrack::update(Some(&t2), &["S-1", "S-3"], 300, None, false);
        let t4 = ObjectTrack::update(Some(&t3), &["S-2", "S-3"], 400, None, false);
        let text = serde_json::to_string(&t4).unwrap();
        assert!(text.contains(" ! ") && text.contains(" ~400 "), "{text}");
        assert_eq!(serde_json::from_str::<ObjectTrack>(&text).unwrap(), t4);
        assert!(ObjectTrack::unpack("x").is_err());
        // The fields as an object read too, with lists or packed keys.
        let fields = format!(
            r#"{{"since":100,"seen":{{"100":"{} {}","200":"{}"}}}}"#,
            k[0],
            k[1],
            object_key("S-3")
        );
        assert_eq!(serde_json::from_str::<ObjectTrack>(&fields).unwrap(), t2);
        let listed = format!(
            r#"{{"since":100,"seen":{{"100":["{}","{}"]}},"back":["{}"]}}"#,
            k[0], k[1], k[0]
        );
        let t: ObjectTrack = serde_json::from_str(&listed).unwrap();
        assert_eq!(t.seen[&100], k);
        assert_eq!(t.back, vec![k[0].clone()]);
    }

    #[test]
    fn edges_open_resolve_and_hold() {
        let z = |ks: &[&str]| vec![(TIER_ZERO.to_string(), keys(ks), Vec::new())];
        let p1 = up(None, &z(&["a", "b"]), 100, true);
        let p2 = up(Some(&p1), &z(&["a", "c"]), 200, true);
        let t = &zt(&p2)[TIER_ZERO];
        assert_eq!(t.since, 100);
        assert_eq!(t.open[&200], keys(&["c"]));
        assert_eq!(t.resolved[&200], keys(&["b"]));
        // A run that can't resolve keeps the missing edge open, and keeps
        // a zone it did not see.
        let p3 = up(Some(&p2), &[], 300, false);
        assert_eq!(zt(&p3), zt(&p2));
        let p4 = up(Some(&p2), &z(&["c"]), 300, false);
        assert_eq!(zt(&p4)[TIER_ZERO].open[&100], keys(&["a"]));
        // A zone gone from the settings is dropped.
        assert!(zt(&up(Some(&p2), &[], 300, true)).is_empty());
    }

    /// A broad zone's edges are counted, not dated, past ZONE_MAX; under it
    /// again, they start a new baseline (nothing reads as new).
    #[test]
    fn a_broad_zone_is_counted_not_dated() {
        let many: Vec<String> = (0..=ZONE_MAX).map(|i| format!("{i:016x}")).collect();
        let z = |es: Vec<String>| vec![("Broad".to_string(), es, Vec::new())];
        let p1 = up(None, &z(many.clone()), 100, true);
        let t = &zt(&p1)["Broad"];
        assert!(t.open.is_empty() && t.undated == ZONE_MAX + 1);
        let state = FindingsState {
            paths: Some(p1.clone()),
            tracked_since: Some(100),
            ..Default::default()
        };
        let i = period(&state, Period::All, 100, &Runs::default());
        assert_eq!(
            i.undated_note().unwrap(),
            "Not dated, more than 50,000 per zone: 50,001 paths into Broad."
        );
        assert!(i.is_empty());
        let p2 = up(Some(&p1), &z(many[..10].to_vec()), 200, true);
        let p3 = up(Some(&p2), &z(many[..11].to_vec()), 300, true);
        let t = &zt(&p3)["Broad"];
        assert_eq!((t.since, t.undated), (200, 0));
        assert_eq!(t.open[&300], vec![many[10].clone()]);
    }

    /// A user added to a Tier Zero group joins Tier Zero: the period lists
    /// it as a new member, named with the group, though no edge from
    /// outside points at it.
    #[test]
    fn a_new_tier_zero_member_is_listed() {
        use crate::model::{EdgeKind, Node};
        let mut g = AdGraph::new();
        let node = |g: &mut AdGraph, id: &str, name: &str, kind: NodeKind, t0: bool| {
            let mut n = Node::placeholder(id.to_string(), kind);
            n.placeholder = false;
            n.name = name.to_string();
            n.tier_zero = t0;
            g.upsert(n)
        };
        let da = node(
            &mut g,
            "S-1-5-21-1-512",
            "DOMAIN ADMINS@CONTOSO.LOCAL",
            NodeKind::Group,
            true,
        );
        let bob = node(
            &mut g,
            "S-1-5-21-1-1104",
            "BOB@CONTOSO.LOCAL",
            NodeKind::User,
            false,
        );
        let p1 = PathsTrack::record(None, &[], &g, &[], 100, true);
        assert!(
            p1.envs[&env_key(&[])].zones[TIER_ZERO]
                .members
                .as_ref()
                .unwrap()
                .open[&100]
                .len()
                == 1
        );
        g.add_edge(bob, da, EdgeKind::MemberOf);
        g.node_mut(bob).tier_zero = true;
        let p2 = PathsTrack::record(Some(&p1), &[], &g, &[], 200, true);
        let state = FindingsState {
            paths: Some(p2),
            tracked_since: Some(100),
            ..Default::default()
        };
        let runs = Runs::new(vec![100, 200]);
        let mut i = period(&state, Period::LastRun, 200, &runs);
        assert_eq!(i.joined(), 1);
        i.name(&Names::new(&[], &g, &[], None));
        let line = i.lines().into_iter().next().unwrap();
        assert_eq!(line.text, "1 new member of Tier Zero");
        assert_eq!(
            line.items,
            vec!["BOB@CONTOSO.LOCAL, member of DOMAIN ADMINS@CONTOSO.LOCAL · Jan 1 (run 2)"]
        );
        assert_eq!(line.next.unwrap().0, vec!["tier-zero"]);
    }

    #[test]
    fn periods_parse_and_bound() {
        let latest = crate::time::parse_date("2026-10-18").unwrap() + 3600;
        assert_eq!(Period::parse("7d").unwrap(), Period::Days(7));
        assert_eq!(Period::parse("2W").unwrap(), Period::Days(14));
        assert_eq!(Period::parse("1m").unwrap(), Period::Days(30));
        assert_eq!(Period::parse("last").unwrap(), Period::LastRun);
        assert_eq!(Period::LastRun.bounds(latest), (latest, latest));
        let d = Period::parse("2026-10-01").unwrap();
        assert_eq!(d.key(), "2026-10-01");
        assert_eq!(d.describe(latest), "since Oct 1");
        let r = Period::parse("2026-10-01..2026-10-02").unwrap();
        assert_eq!(r.bounds(latest).1 - r.bounds(latest).0, 2 * DAY - 1);
        assert_eq!(Period::parse(&r.key()).unwrap(), r);
        assert_eq!(
            Period::Days(7).describe(latest),
            "in the 7 days up to Oct 18"
        );
        for bad in [
            "",
            "7",
            "x7d",
            "0d",
            "2026-13-01",
            "2026-10-02..2026-10-01",
            "..",
            // Not one byte at the end (or at all): an error, not a panic.
            "7\u{e9}",
            "7\u{65e5}",
            "\u{e9}",
            "\u{65e5}d",
        ] {
            assert!(Period::parse(bad).is_err(), "{bad}");
        }
        let until = Period::parse("..2026-10-02").unwrap();
        assert_eq!(until.key(), "..2026-10-02");
        assert_eq!(until.describe(latest), "up to Oct 2");
        assert_eq!(until.bounds(latest).0, i64::MIN);
        assert_eq!(
            Period::parse("2026-10-01..").unwrap(),
            Period::parse("2026-10-01").unwrap()
        );
        assert_eq!(day(latest - 365 * DAY, latest), "Oct 18, 2025");
    }

    #[test]
    fn badges_and_labels() {
        assert_eq!(Badge::of(10, None, &[], 5, 20), Some(Badge::New));
        assert_eq!(Badge::of(1, Some(10), &[], 5, 20), Some(Badge::Back));
        assert_eq!(
            Badge::of(1, Some(2), &[(10, 2), (12, 1), (30, 4)], 5, 20),
            Some(Badge::Gained(3))
        );
        assert_eq!(Badge::of(1, None, &[(30, 4)], 5, 20), None);
        // A period after the latest run holds nothing (and doesn't panic).
        let t = ObjectTrack::update(None, &["S-1"], 10, None, false);
        assert!(t.gained(50, 20).is_empty() && t.removed(50, 20) == 0);
        assert_eq!(Badge::Gained(1).label(), "+1 object");
        assert_eq!(Badge::Gained(1200).label(), "+1,200 objects");
        let runs = Runs::new(vec![300, 100, 200]);
        assert_eq!(runs.number(200), Some(2));
        assert_eq!(runs.number(250), None);
        let at = crate::time::parse_date("2026-10-18").unwrap();
        let runs = Runs::new(vec![at - DAY, at]);
        assert_eq!(
            seen_label(at, false, &runs, at),
            "first seen Oct 18 (run 2)"
        );
        assert_eq!(seen_label(at, true, &Runs::default(), at), "back Oct 18");
    }

    fn obs(id: &str, objects: &[&str]) -> crate::state::ObservedFinding {
        serde_json::from_value(serde_json::json!({
            "fingerprint": format!("PW-011-{id}"),
            "rule": "PW-011",
            "severity": "high",
            "category": "hygiene",
            "title": format!("finding {id}"),
            "domain": "CONTOSO.LOCAL",
            "affected": objects.iter().map(|o| serde_json::json!({"id": o, "name": o})).collect::<Vec<_>>(),
        }))
        .unwrap()
    }

    fn texts(i: &Introduced) -> Vec<String> {
        i.lines().into_iter().map(|l| l.text).collect()
    }

    /// The period function: new, back and gained findings with their
    /// objects, fixed findings and lost objects, over the last run or a
    /// longer period.
    #[test]
    fn a_period_lists_what_is_net_new_and_what_was_resolved() {
        use crate::state::reconcile;
        let r1 = reconcile(
            &FindingsState::default(),
            &[obs("A", &["S-1", "S-2"]), obs("B", &["S-1"]), obs("C", &[])],
            100,
            false,
        );
        assert_eq!(r1.state.tracked_since, Some(100));
        let r2 = reconcile(
            &r1.state,
            &[
                obs("A", &["S-1", "S-2", "S-3"]),
                obs("B", &["S-1"]),
                obs("D", &[]),
            ],
            200,
            false,
        );
        let r3 = reconcile(
            &r2.state,
            &[obs("A", &["S-1", "S-3"]), obs("C", &[]), obs("D", &[])],
            300,
            false,
        );
        let runs = Runs::new(vec![100, 200, 300]);
        let last = period(&r3.state, Period::LastRun, 300, &runs);
        assert!(!last.predates);
        let badges: Vec<(&str, Badge)> = last
            .findings
            .iter()
            .map(|f| (f.fingerprint.as_str(), f.badge))
            .collect();
        assert_eq!(badges, vec![("PW-011-C", Badge::Back)]);
        assert_eq!(last.fixed.len(), 1);
        assert_eq!(last.fixed[0].fingerprint, "PW-011-B");
        assert_eq!(last.fewer[0].objects, Some(1), "A lost S-2");
        assert_eq!(
            texts(&last),
            vec![
                "1 finding back after it was fixed",
                "1 finding fixed",
                "1 finding lost 1 object"
            ]
        );
        // Over both later runs: D is new, C back, A gained S-3 (run 2).
        let mut wide = period(&r3.state, Period::From(150), 300, &runs);
        let badges: Vec<(&str, Badge)> = wide
            .findings
            .iter()
            .map(|f| (f.fingerprint.as_str(), f.badge))
            .collect();
        assert!(badges.contains(&("PW-011-D", Badge::New)));
        assert!(badges.contains(&("PW-011-C", Badge::Back)));
        assert!(badges.contains(&("PW-011-A", Badge::Gained(1))));
        let a = wide
            .findings
            .iter()
            .find(|f| f.fingerprint == "PW-011-A")
            .unwrap();
        assert_eq!(a.objects[0].key, object_key("S-3"));
        assert_eq!(a.objects[0].label, "first seen Jan 1 (run 2)");
        // Names come from an analysis's findings.
        let named = vec![{
            let mut f =
                crate::findings::Finding::new("PW-011", Severity::High, &["A"], "finding A");
            f.fingerprint = "PW-011-A".into();
            f.affected = vec![crate::findings::Affected {
                id: "S-3".into(),
                name: "CAROL@CONTOSO.LOCAL".into(),
                kind: NodeKind::User,
                detail: None,
            }];
            f
        }];
        wide.name(&Names::new(&named, &AdGraph::new(), &[], None));
        let a = wide
            .findings
            .iter()
            .find(|f| f.fingerprint == "PW-011-A")
            .unwrap();
        assert_eq!(a.objects[0].name.as_deref(), Some("CAROL@CONTOSO.LOCAL"));
        let line = wide
            .lines()
            .into_iter()
            .find(|l| l.text.contains("gained"))
            .unwrap();
        assert_eq!(line.text, "1 older finding gained 1 object");
        assert_eq!(
            line.items,
            vec!["high PW-011 finding A: +1 object (CAROL@CONTOSO.LOCAL)"]
        );
        assert_eq!(
            line.next.unwrap().0,
            vec!["findings", "--introduced", "1970-01-01"]
        );
        // The whole history reaches back to the run tracking began in.
        let all = period(&r3.state, Period::All, 300, &runs);
        assert!(all.predates);
        assert_eq!(
            all.note(&runs, 300).unwrap(),
            "Objects and paths are dated from Jan 1 (run 1) on; before that, only whole findings are."
        );
    }

    /// A run that can't resolve (an incomplete collection) holds the
    /// objects a finding no longer lists: when the next full run lists them
    /// again, nothing reads as gained. A finding fixed longer ago than
    /// GONE_DAYS forgets its objects.
    #[test]
    fn an_incomplete_run_holds_objects() {
        use crate::state::{reconcile, reconcile_scoped, ResolveScope};
        let full = ResolveScope::everything();
        let partial = ResolveScope::domains(&["CONTOSO.LOCAL".to_string()], false);
        let r1 = reconcile(
            &FindingsState::default(),
            &[obs("A", &["S-1", "S-2"])],
            100,
            false,
        );
        let r2 = reconcile_scoped(&r1.state, &[obs("A", &["S-1"])], 200, false, &partial);
        let held = r2.state.findings["PW-011-A"].objects.as_ref().unwrap();
        assert!(held.gone.is_empty(), "{held:?}");
        let r3 = reconcile_scoped(&r2.state, &[obs("A", &["S-1", "S-2"])], 300, false, &full);
        let runs = Runs::new(vec![100, 200, 300]);
        let all = period(&r3.state, Period::From(150), 300, &runs);
        assert!(all.findings.is_empty() && all.fewer.is_empty(), "{all:?}");
        // Fixed, then forgotten a year on.
        let none: [crate::state::ObservedFinding; 0] = [];
        let r4 = reconcile(&r3.state, &none, 400, false);
        assert!(r4.state.findings["PW-011-A"].objects.is_some());
        let r5 = reconcile(&r4.state, &none, 400 + (GONE_DAYS + 1) * DAY, false);
        assert!(r5.state.findings["PW-011-A"].objects.is_none());
    }

    /// State written before objects were tracked loads, and its first run
    /// after takes what each finding lists as the baseline: nothing reads
    /// as gained.
    #[test]
    fn old_state_files_load_and_start_from_a_baseline() {
        let old = r#"{"version":1,"findings":{"PW-011-A":{"rule":"PW-011","severity":"high","category":"hygiene","status":"open","first_seen":50,"last_seen":50,"times_seen":1}}}"#;
        let state: FindingsState = serde_json::from_str(old).unwrap();
        assert!(state.tracked_since.is_none() && state.paths.is_none());
        assert!(state.findings["PW-011-A"].objects.is_none());
        let none = period(&state, Period::All, 50, &Runs::default());
        assert_eq!(
            none.note(&Runs::default(), 50).unwrap(),
            "Objects and paths are not dated yet: the next run starts dating them. Until then only whole findings are."
        );
        let r = crate::state::reconcile(&state, &[obs("A", &["S-1", "S-2"])], 100, false);
        assert_eq!(r.state.tracked_since, Some(100));
        let last = period(&r.state, Period::LastRun, 100, &Runs::default());
        assert!(last.findings.is_empty(), "{:?}", last.findings);
        assert!(last.predates, "the run tracking began in");
        // Written back, only the new fields are added; read again, equal.
        let text = serde_json::to_string(&r.state).unwrap();
        assert!(text.contains(r#""tracked_since":100"#), "{text}");
        let back: FindingsState = serde_json::from_str(&text).unwrap();
        assert_eq!(
            back.findings["PW-011-A"].objects,
            r.state.findings["PW-011-A"].objects
        );
        assert!(
            !text.to_ascii_uppercase().contains("CONTOSO"),
            "no names: {text}"
        );
        // An event saved before findings listed their objects keeps what
        // the state had.
        let mut bare = obs("A", &[]);
        bare.affected = None;
        let kept = crate::state::reconcile(&r.state, &[bare], 200, false);
        assert_eq!(
            kept.state.findings["PW-011-A"].objects,
            r.state.findings["PW-011-A"].objects
        );
    }

    /// An edge resolved and then there again (a session that comes and
    /// goes with logons) is back, not new: dated when it returned, said
    /// apart, and not counted with the new paths `--fail-on new` fails on.
    #[test]
    fn an_edge_back_after_it_was_resolved_is_back_not_new() {
        let z = |ks: &[&str]| vec![(TIER_ZERO.to_string(), keys(ks), keys(&["m"]))];
        let p1 = up(None, &z(&["a"]), 100, true);
        let p2 = up(Some(&p1), &z(&["a", "b"]), 200, true);
        let p3 = up(Some(&p2), &z(&["a"]), 300, true);
        let p4 = up(Some(&p3), &z(&["a", "b"]), 400, true);
        let t = &zt(&p4)[TIER_ZERO];
        assert_eq!(t.open[&400], keys(&["b"]));
        assert_eq!(t.back, keys(&["b"]));
        assert!(t.resolved.is_empty(), "back, no longer resolved");
        let text = serde_json::to_string(&p4).unwrap();
        assert_eq!(serde_json::from_str::<PathsTrack>(&text).unwrap(), p4);
        let state = FindingsState {
            paths: Some(p4.clone()),
            tracked_since: Some(100),
            ..Default::default()
        };
        let runs = Runs::new(vec![100, 200, 300, 400]);
        let i = period(&state, Period::LastRun, 400, &runs);
        assert_eq!((i.new_paths(), i.back_in_zones()), (0, 1));
        assert!(i.paths[0].new[0].back);
        assert_eq!(i.paths[0].new[0].label, "back Jan 1 (run 4)");
        assert_eq!(texts(&i), ["1 path back into Tier Zero"]);
        // A new one beside it is said apart.
        let p5 = up(Some(&p4), &z(&["a", "b", "c"]), 500, true);
        let state = FindingsState {
            paths: Some(p5.clone()),
            ..state
        };
        let i = period(&state, Period::Days(1), 500, &runs);
        assert_eq!(texts(&i), ["1 new path into Tier Zero, 1 back"]);
        // Still there: still back. Gone again: resolved, no longer back.
        assert_eq!(zt(&p5)[TIER_ZERO].back, keys(&["b"]));
        let p6 = up(Some(&p5), &z(&["a", "c"]), 600, true);
        assert!(zt(&p6)[TIER_ZERO].back.is_empty());
        assert_eq!(zt(&p6)[TIER_ZERO].resolved[&600], keys(&["b"]));
        // A run that can't resolve keeps it back.
        let held = up(Some(&p5), &z(&["a", "c"]), 600, false);
        assert_eq!(zt(&held)[TIER_ZERO].back, keys(&["b"]));
    }

    /// A run that did not read sessions or local groups keeps a missing
    /// session or admin right into a zone (it can't tell it went), and
    /// resolves every other missing edge.
    #[test]
    fn a_quick_run_keeps_sessions_and_admin_rights_and_resolves_the_rest() {
        let z = |es: &[&str]| vec![(TIER_ZERO.to_string(), keys(es), Vec::<String>::new())];
        let none = HashSet::new();
        let host: HashSet<String> = keys(&["h1"]).into_iter().collect();
        let open = |p: &PathsTrack| zt(p)[TIER_ZERO].open.values().flatten().count();
        let gone = |p: &PathsTrack| zt(p)[TIER_ZERO].resolved.values().flatten().count();
        let p1 = PathsTrack::update_with(None, "e", &z(&["h1", "a1"]), 100, 10, true, true, &host);
        assert_eq!(p1.envs["e"].host_edges, Some(keys(&["h1"])));
        // Quick: both missing; the admin right kept, the ACL gone.
        let p2 = PathsTrack::update_with(Some(&p1), "e", &z(&[]), 200, 10, true, false, &none);
        assert_eq!((open(&p2), gone(&p2)), (1, 1));
        assert_eq!(p2.envs["e"].host_edges, Some(keys(&["h1"])));
        // Full: it went.
        let p3 = PathsTrack::update_with(Some(&p2), "e", &z(&[]), 300, 10, true, true, &none);
        assert_eq!((open(&p3), gone(&p3)), (0, 2));
        // State written before the kinds were kept: every missing edge may
        // be one, so a Quick run keeps them all.
        let mut old = p1.clone();
        old.envs.get_mut("e").unwrap().host_edges = None;
        let p4 = PathsTrack::update_with(Some(&old), "e", &z(&[]), 200, 10, true, false, &none);
        assert_eq!((open(&p4), gone(&p4)), (2, 0));
    }

    /// Two environments in one state folder, run in turn: each keeps its
    /// own zones (the other's run neither resolves nor dates them), and a
    /// period of one lists only its findings.
    #[test]
    fn environments_sharing_a_state_keep_apart() {
        use crate::state::{reconcile, scope_key};
        let z = |ks: &[&str]| vec![(TIER_ZERO.to_string(), keys(ks), keys(ks))];
        let a = vec![scope_key("CONTOSO.LOCAL")];
        let b = vec![scope_key("FABRIKAM.LOCAL")];
        let (ka, kb) = (env_key(&a), env_key(&b));
        let p1 = PathsTrack::update(None, &ka, &z(&["a1"]), 100, 10, true);
        let p2 = PathsTrack::update(Some(&p1), &kb, &z(&["b1", "b2"]), 200, 10, true);
        let p3 = PathsTrack::update(Some(&p2), &ka, &z(&["a1"]), 300, 10, true);
        let ta = &p3.envs[&ka].zones[TIER_ZERO];
        assert_eq!((ta.since, ta.resolved.len()), (100, 0));
        assert_eq!(p3.envs[&kb].zones[TIER_ZERO].since, 200);
        // A's findings at 100 and 300; B's at 200.
        let r1 = reconcile(&FindingsState::default(), &[obs("A", &["S-1"])], 100, false);
        let mut r2 = reconcile(&r1.state, &[obs("A", &["S-1"]), obs("B", &[])], 200, false);
        r2.state.findings.get_mut("PW-011-B").unwrap().scope = Some(b[0].clone());
        let mut state = r2.state;
        state.paths = Some(p3.clone());
        let in_a = Runs::new(vec![100, 300]).in_env(&a, &[]);
        let i = period(&state, Period::All, 300, &in_a);
        let fps: Vec<&str> = i.findings.iter().map(|f| f.fingerprint.as_str()).collect();
        assert_eq!(fps, ["PW-011-A"]);
        assert!(i.paths.iter().all(|z| !z.changed()), "baselines only");
        let in_b = Runs::new(vec![200]).in_env(&b, &[]);
        let i = period(&state, Period::All, 200, &in_b);
        let fps: Vec<&str> = i.findings.iter().map(|f| f.fingerprint.as_str()).collect();
        assert_eq!(fps, ["PW-011-B"]);
        assert!(
            i.paths.iter().all(|z| !z.changed()),
            "B's Tier Zero is its baseline"
        );
        // A domain B trusts holds its findings too.
        let trusting = Runs::new(vec![200]).in_env(&b, &a);
        assert_eq!(
            period(&state, Period::All, 200, &trusting).findings.len(),
            2
        );
        // An environment not run in a year is forgotten.
        let later = 200 + GONE_DAYS * DAY + 1;
        let p4 = PathsTrack::update(Some(&p3), &ka, &z(&["a1"]), later, 10, true);
        assert!(p4.envs.contains_key(&ka) && !p4.envs.contains_key(&kb));
        // Fewer than half the environment's objects: held.
        assert!(p3.shrunk(&ka, 4) && !p3.shrunk(&ka, 5) && !p3.shrunk("new", 1));
    }

    /// "7 days" leaves out a run exactly a week before the latest.
    #[test]
    fn a_week_leaves_out_the_run_a_week_before() {
        let (from, to) = Period::Days(7).bounds(8 * DAY);
        assert_eq!((from, to), (DAY + 1, 8 * DAY));
    }

    /// The same finding named many times reads once, with how many.
    #[test]
    fn repeated_names_are_said_once() {
        let items = name_items(
            ["x", "x", "y", "x", "z", "w", "w"]
                .iter()
                .map(|s| s.to_string()),
        );
        assert_eq!(items, ["x ×3", "y", "z", "and 2 more"]);
    }
}
