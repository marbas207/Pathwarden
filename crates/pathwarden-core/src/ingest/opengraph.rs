//! The OpenGraph reader: stitches files written by specialist collectors
//! (TaskHound, MSSQLHound, ...) onto the AD graph.
//!
//! While AD files stream in, OpenGraph files are only recognised and queued
//! (their order relative to AD data is arbitrary). Once every AD file is
//! read, [`Ingestor::ingest_opengraph`] runs two passes over the queue:
//!
//! 1. **nodes**: each node is matched to an AD object by its ID (SID or
//!    GUID) and merged without touching anything AD said; an unknown SID, or
//!    a native kind (`User`, `Computer`, ...), becomes a placeholder, which is
//!    never part of the exposure population; anything else becomes an
//!    external object;
//! 2. **edges**: each endpoint is resolved by ID, or by an allow-listed
//!    property when it matches exactly one object. Native AD edge kinds
//!    (a forged `MemberOf`) are dropped unless the source's pack accepts
//!    them.
//!
//! Each file is therefore read twice; they are small next to AD data. The
//! file is hostile input: every count is capped, a cap hit marks the source
//! incomplete (so it can never prove a finding fixed), and secret-looking
//! properties (`password`, ...) are dropped while parsing.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::Arc;

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::budget::{self, BValue};
use super::{Counted, Ingestor, MAX_ENTRY_BYTES};
use crate::graph::normalize_id;
use crate::kinds::{self, ExtKind};
use crate::model::{EdgeKind, ExtNode, Node, NodeKind, SourceId};
use crate::opengraph::coverage::{CoverageInfo, CoverageState, Sidecar};
use crate::opengraph::pack::{self, End, Pack, UnitRule, DEFAULT_KEEP};
use crate::opengraph::sccm::{self, Rekeyed, SiteInfo, SiteMap};
use crate::opengraph::{is_sid_shaped, EdgeOrigin, KindTable, PackInfo};

/// Limits for OpenGraph files; past one, the source is marked incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OgLimits {
    /// Node records read per source.
    pub max_nodes: usize,
    /// Edge records read per source.
    pub max_edges: usize,
    /// Distinct external kind names per analysis (packs' own not counted).
    pub max_kinds: usize,
    /// Bytes of kept properties per source.
    pub max_kept_bytes: u64,
    /// Memory one node or edge may take while parsed.
    pub max_item_bytes: u64,
}

impl Default for OgLimits {
    fn default() -> Self {
        OgLimits {
            max_nodes: 2_000_000,
            max_edges: 10_000_000,
            max_kinds: 512,
            max_kept_bytes: 64 << 20,
            max_item_bytes: 16 << 20,
        }
    }
}

const MAX_ID_BYTES: usize = 512;
const MAX_KINDS_PER_NODE: usize = 8;
const MAX_MATCHERS: usize = 4;
const MAX_STRING_BYTES: usize = 1024;
const MAX_ARRAY_ITEMS: usize = 64;
const MAX_SOURCES: usize = 1000;

/// Keys an edge endpoint may be matched on besides its ID.
const MATCH_KEYS: &[&str] = &[
    "name",
    "objectid",
    "samaccountname",
    "dnshostname",
    "distinguishedname",
    "email",
    "mail",
    "userprincipalname",
];

/// What the statistics say about OpenGraph input.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OpenGraphStats {
    pub sources: Vec<OgSourceStats>,
    /// Edge kinds no pack in effect describes (kept as context), with counts.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unmapped_kinds: BTreeMap<String, usize>,
    /// Packs in effect.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packs: Vec<PackInfo>,
    /// Kind names past the per-analysis cap (read as `OG_Other`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub kinds_over_cap: usize,
    /// Sidecars that matched no OpenGraph file, or could not be read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unused_sidecars: Vec<String>,
    /// What the packs' corrections changed (see `crate::opengraph::mssql`
    /// and `crate::opengraph::sccm`), one line each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub corrections: Vec<String>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl OpenGraphStats {
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty() && self.unused_sidecars.is_empty()
    }
}

/// One OpenGraph source (every file with the same `source_kind`).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OgSourceStats {
    /// `metadata.source_kind`, a source kind on its nodes, or "OpenGraph".
    pub name: String,
    /// The mapping pack applied, if any.
    pub pack: Option<String>,
    /// Whether that pack is trusted to make edges traversable.
    pub trusted: bool,
    pub files: Vec<String>,
    /// Node records read.
    pub nodes: usize,
    /// Nodes matched to objects in the AD data (merged, AD values kept).
    pub merged: usize,
    /// External objects created.
    pub created: usize,
    /// AD-shaped objects (a SID, or a native kind) not in the AD data:
    /// placeholders, never part of the exposure population.
    pub placeholders: usize,
    /// Edges added.
    pub edges: usize,
    /// Of those, kept as context only although their kind is mapped: the
    /// kind belongs to another source's pack, or a pack condition failed.
    pub context_edges: usize,
    /// Edges whose endpoints did not resolve (missing, or a name or
    /// property matching zero or several objects).
    pub unresolved: usize,
    /// Native AD edges (`MemberOf`, `AdminTo`, ...) dropped: only AD data
    /// may say them, unless the pack accepts them.
    pub dropped_native: usize,
    /// Secret-looking properties dropped.
    pub dropped_secrets: usize,
    /// Records with a missing or invalid ID or kind.
    pub invalid: usize,
    /// Records too large to load.
    pub oversized: usize,
    /// Node IDs another source already gave a different kind (the first wins).
    pub clashes: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps_hit: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    /// AzureHound: role assignments and eligibilities scoped to an
    /// administrative unit or one object, not modeled. They are never taken
    /// for tenant-wide ones.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub scoped_roles: usize,
    /// Read whole: no cap hit, no error.
    pub complete: bool,
    pub coverage: CoverageInfo,
}

impl OgSourceStats {
    /// What the source holds that isn't modeled, in the words the report
    /// and the app's Run details use ("Not modeled: ...").
    pub fn not_modeled(&self) -> Option<String> {
        (self.scoped_roles > 0).then(|| {
            format!(
                "{} {} scoped to an administrative unit or one object",
                self.scoped_roles,
                if self.scoped_roles == 1 {
                    "role assignment"
                } else {
                    "role assignments"
                }
            )
        })
    }
}

/// An OpenGraph or AzureHound source that was not read whole: the
/// limits it hit, the records too large to load and the read errors. The
/// CLI's warnings, the app's Run details row and the run's summary say it
/// from this, in the same words ([`OgIncomplete::sentences`]).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OgIncomplete {
    /// The source's name, as the file gave it (hostile: escape it).
    pub source: String,
    /// The limits it reached ([`OgSourceStats::caps_hit`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limits: Vec<String>,
    /// Records too large to load.
    #[serde(skip_serializing_if = "is_zero")]
    pub too_large: usize,
    /// Read errors.
    #[serde(skip_serializing_if = "is_zero")]
    pub errors: usize,
}

/// A limit's words and the `[opengraph]` key that raises it.
fn limit_words(cap: &str) -> (&'static str, Option<&'static str>) {
    match cap {
        "nodes" => ("the limit on node records", Some("max_nodes")),
        "edges" => ("the limit on edge records", Some("max_edges")),
        "kinds" => ("the limit on kind names", Some("max_kinds")),
        "kept properties" => ("the limit on kept properties", Some("max_kept_mib")),
        _ => ("a limit", None),
    }
}

impl OgIncomplete {
    /// The source not read whole, or `None` when it was.
    pub fn of(s: &OgSourceStats) -> Option<OgIncomplete> {
        (!s.complete).then(|| OgIncomplete {
            source: s.name.clone(),
            limits: s.caps_hit.clone(),
            too_large: s.oversized,
            errors: s.errors.len(),
        })
    }

    /// Every source of `stats` not read whole, in reading order.
    pub fn all(stats: &OpenGraphStats) -> Vec<OgIncomplete> {
        stats.sources.iter().filter_map(OgIncomplete::of).collect()
    }

    /// The `[opengraph]` keys that raise the limits it hit.
    pub fn keys(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = self
            .limits
            .iter()
            .filter_map(|c| limit_words(c).1)
            .collect();
        if self.too_large > 0 {
            out.push("max_record_mib");
        }
        out.dedup();
        out
    }

    /// What it says, one sentence each: the source and why ("AzureHound
    /// was read only part way (the limit on kept properties, 2 records too
    /// large to load)."), the setting that raises the limit, and that
    /// findings resting on it are held. `name` is the source's name as the
    /// caller made it safe to show. With `keys` (the CLI) the setting is
    /// named by its key; a page says where it is, never a key or a command.
    pub fn sentences(&self, name: &str, keys: bool) -> Vec<String> {
        let mut why: Vec<String> = self
            .limits
            .iter()
            .map(|c| limit_words(c).0.to_string())
            .collect();
        if self.too_large > 0 {
            why.push(crate::text::count(
                self.too_large,
                "record too large to load",
                "records too large to load",
            ));
        }
        if self.errors > 0 {
            why.push(crate::text::count(self.errors, "read error", "read errors"));
        }
        let mut out = vec![if why.is_empty() {
            format!("{name} was read only part way.")
        } else {
            format!("{name} was read only part way ({}).", why.join(", "))
        }];
        let k = self.keys();
        if !k.is_empty() {
            let one = k.len() == 1;
            out.push(if keys {
                format!(
                    "Raise the {} with {} under [opengraph] in pathwarden.toml.",
                    if one { "limit" } else { "limits" },
                    crate::text::and_list(&k.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                )
            } else if one {
                "A higher limit can be set in this environment's settings file.".to_string()
            } else {
                "Higher limits can be set in this environment's settings file.".to_string()
            });
        }
        out.push("Findings that rest on it aren't marked fixed.".to_string());
        out
    }
}

/// Where a queued OpenGraph file's bytes are.
pub(super) enum OgInput {
    File {
        path: PathBuf,
        bom: bool,
    },
    Zip {
        path: PathBuf,
        index: usize,
        size: u64,
        bom: bool,
    },
    Text(Arc<[u8]>),
}

pub(super) struct Deferred {
    pub label: String,
    pub input: OgInput,
    pub source_kind: Option<String>,
}

/// The ingestor's OpenGraph queue.
#[derive(Default)]
pub(super) struct OgQueue {
    pub deferred: Vec<Deferred>,
    pub sidecars: Vec<(String, Result<Sidecar, String>)>,
    pub packs: Option<Vec<Pack>>,
    pub done: bool,
    /// AzureHound files (see `super::azurehound`), read after these.
    pub azurehound: Vec<Deferred>,
}

impl OgQueue {
    /// The packs in effect: the embedded ones (or those given), plus the
    /// AzureHound pack when AzureHound data is read. With it in the table,
    /// an `AZ` edge in an OpenGraph file is context only (another source's
    /// pack maps the kind), so a file can't add Entra paths.
    pub(super) fn packs_in_effect(&self) -> Vec<Pack> {
        let mut packs = self
            .packs
            .clone()
            .unwrap_or_else(|| pack::embedded().to_vec());
        if !self.azurehound.is_empty() && !packs.iter().any(|p| p.name() == "azurehound") {
            packs.push(pack::azurehound().clone());
        }
        packs
    }
}

// ------------------------------------------------------------ parsing

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Only node kinds, to find which source a file is.
    Markers,
    Nodes,
    Edges,
}

#[derive(Debug, Default)]
struct OgNode {
    id: Option<String>,
    kinds: Vec<String>,
    props: Vec<(String, Value)>,
}

#[derive(Debug, Default)]
struct Endpoint {
    value: Option<String>,
    match_by: Option<String>,
    kind: Option<String>,
    matchers: Vec<(String, Option<String>, Value)>,
}

#[derive(Debug, Default)]
struct OgEdge {
    kind: Option<String>,
    start: Endpoint,
    end: Endpoint,
    /// Only the properties a pack condition looks at (`assumed`).
    props: Vec<(String, Value)>,
}

enum Item {
    Node(OgNode),
    Edge(OgEdge),
}

const STOP: &str = "pathwarden: stop reading";

struct Ctx<'a> {
    mode: Mode,
    keep: &'a HashSet<String>,
    /// Edge properties to keep (those pack conditions look at).
    edge_keep: &'a HashSet<String>,
    /// Reading the `edges` list (else `nodes`).
    in_edges: bool,
    limit: u64,
    sink: &'a mut dyn FnMut(Item) -> bool,
    metadata: Option<String>,
    secrets: usize,
    oversized: usize,
}

struct Top<'a, 'b>(&'a mut Ctx<'b>);

impl<'de> DeserializeSeed<'de> for Top<'_, '_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Top<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an OpenGraph file (a JSON object)")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "metadata" => {
                    let v = map.next_value::<BValue>()?.0;
                    self.0.metadata = v
                        .get("source_kind")
                        .and_then(Value::as_str)
                        .filter(|s| !s.trim().is_empty() && s.len() <= 64)
                        .map(str::to_owned);
                }
                "graph" => map.next_value_seed(Graph(&mut *self.0))?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

struct Graph<'a, 'b>(&'a mut Ctx<'b>);

impl<'de> DeserializeSeed<'de> for Graph<'_, '_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Graph<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("the graph object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            let wanted = match key.as_str() {
                "nodes" => matches!(self.0.mode, Mode::Nodes | Mode::Markers),
                "edges" => matches!(self.0.mode, Mode::Edges | Mode::Markers),
                _ => false,
            };
            if wanted {
                self.0.in_edges = key == "edges";
                map.next_value_seed(List(&mut *self.0))?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct List<'a, 'b>(&'a mut Ctx<'b>);

impl<'de> DeserializeSeed<'de> for List<'_, '_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for List<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a list of nodes or edges")
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        loop {
            budget::begin(self.0.limit);
            let item = seq.next_element_seed(ItemSeed(&mut *self.0));
            let cost = budget::finish();
            let Some(item) = item? else {
                return Ok(());
            };
            if cost.oversized {
                self.0.oversized += 1;
                continue;
            }
            if !(self.0.sink)(item) {
                return Err(de::Error::custom(STOP));
            }
        }
    }
}

struct ItemSeed<'a, 'b>(&'a mut Ctx<'b>);

impl<'de> DeserializeSeed<'de> for ItemSeed<'_, '_> {
    type Value = Item;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Item, D::Error> {
        d.deserialize_map(self)
    }
}

/// A string from a JSON value: strings as is, numbers written out.
fn text_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

impl<'de> Visitor<'de> for ItemSeed<'_, '_> {
    type Value = Item;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a node or an edge")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Item, A::Error> {
        let ctx = self.0;
        if ctx.in_edges {
            let markers = ctx.mode == Mode::Markers;
            let mut e = OgEdge::default();
            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "kind" => e.kind = text_of(&map.next_value::<BValue>()?.0),
                    "start" if !markers => e.start = endpoint(map.next_value::<BValue>()?.0),
                    "end" if !markers => e.end = endpoint(map.next_value::<BValue>()?.0),
                    "properties" if !markers && !ctx.edge_keep.is_empty() => {
                        e.props = map.next_value_seed(Props(&mut *ctx, true))?;
                    }
                    _ => {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
            }
            return Ok(Item::Edge(e));
        }
        let mut n = OgNode::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "id" if ctx.mode == Mode::Nodes => n.id = text_of(&map.next_value::<BValue>()?.0),
                "kinds" => {
                    if let Value::Array(a) = map.next_value::<BValue>()?.0 {
                        n.kinds = a
                            .iter()
                            .filter_map(|k| k.as_str().map(str::to_owned))
                            .take(MAX_KINDS_PER_NODE * 4)
                            .collect();
                    }
                }
                "properties" if ctx.mode == Mode::Nodes => {
                    n.props = map.next_value_seed(Props(&mut *ctx, false))?;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Item::Node(n))
    }
}

fn endpoint(v: Value) -> Endpoint {
    let mut ep = Endpoint::default();
    match &v {
        // A bare string is an ID.
        Value::String(_) | Value::Number(_) => ep.value = text_of(&v),
        Value::Object(o) => {
            ep.value = o.get("value").and_then(text_of);
            ep.match_by = o
                .get("match_by")
                .and_then(Value::as_str)
                .map(|s| s.to_ascii_lowercase());
            ep.kind = o.get("kind").and_then(Value::as_str).map(str::to_owned);
            if let Some(Value::Array(ms)) = o.get("property_matchers") {
                for m in ms.iter().take(MAX_MATCHERS + 1) {
                    let key = m.get("key").and_then(Value::as_str).unwrap_or_default();
                    let op = m.get("operator").and_then(Value::as_str).map(str::to_owned);
                    let value = m.get("value").cloned().unwrap_or(Value::Null);
                    ep.matchers.push((key.to_ascii_lowercase(), op, value));
                }
            }
        }
        _ => {}
    }
    ep
}

/// A property value worth keeping: primitives and short arrays of them,
/// strings cut to [`MAX_STRING_BYTES`].
fn sanitize(v: Value) -> Option<Value> {
    fn cut(s: String) -> String {
        if s.len() <= MAX_STRING_BYTES {
            return s;
        }
        let mut end = MAX_STRING_BYTES;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
    match v {
        Value::String(s) => Some(Value::String(cut(s))),
        Value::Bool(_) | Value::Number(_) => Some(v),
        Value::Array(a) => Some(Value::Array(
            a.into_iter()
                .filter(|x| matches!(x, Value::String(_) | Value::Bool(_) | Value::Number(_)))
                .take(MAX_ARRAY_ITEMS)
                .map(|x| match x {
                    Value::String(s) => Value::String(cut(s)),
                    x => x,
                })
                .collect(),
        )),
        Value::Null | Value::Object(_) => None,
    }
}

/// A property map; `.1`: an edge's (kept by `edge_keep`).
struct Props<'a, 'b>(&'a mut Ctx<'b>, bool);

impl<'de> DeserializeSeed<'de> for Props<'_, '_> {
    type Value = Vec<(String, Value)>;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Props<'_, '_> {
    type Value = Vec<(String, Value)>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a property map")
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out: Vec<(String, Value)> = Vec::new();
        let keep = if self.1 {
            self.0.edge_keep
        } else {
            self.0.keep
        };
        while let Some(key) = map.next_key::<String>()? {
            let lower = key.to_ascii_lowercase();
            if pack::is_secret_key(&lower) {
                self.0.secrets += 1;
                map.next_value::<IgnoredAny>()?;
            } else if keep.contains(&lower) && !out.iter().any(|(k, _)| *k == lower) {
                if let Some(v) = sanitize(map.next_value::<BValue>()?.0) {
                    out.push((lower, v));
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(out)
    }
}

/// Reads through to a SHA-256.
struct Hashing<'a, R> {
    inner: R,
    hasher: &'a mut Sha256,
}

impl<R: Read> Read for Hashing<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// The properties the reader keeps: of nodes, and of edges.
#[derive(Default)]
struct Keep {
    nodes: HashSet<String>,
    edges: HashSet<String>,
}

/// How one parse ended.
enum Parsed {
    /// Read to the end.
    Whole,
    /// The sink asked to stop (a cap).
    Stopped,
}

/// Parses `reader` in `mode`, handing each node or edge to `sink`.
fn parse(
    reader: &mut dyn Read,
    mode: Mode,
    keep: &Keep,
    limit: u64,
    sink: &mut dyn FnMut(Item) -> bool,
) -> (Result<Parsed, String>, Option<String>, usize, usize) {
    budget::reset();
    let mut buffered = BufReader::with_capacity(1 << 16, budget::Tracked(reader));
    let mut ctx = Ctx {
        mode,
        keep: &keep.nodes,
        edge_keep: &keep.edges,
        in_edges: false,
        limit,
        sink,
        metadata: None,
        secrets: 0,
        oversized: 0,
    };
    let result = {
        let mut de = serde_json::Deserializer::from_reader(&mut buffered);
        let r = Top(&mut ctx).deserialize(&mut de).and_then(|()| de.end());
        match r {
            Ok(()) => Ok(Parsed::Whole),
            Err(e) if e.to_string().starts_with(STOP) => Ok(Parsed::Stopped),
            Err(e) if budget::tripped() => Err(format!(
                "a record larger than {} MiB ({e})",
                budget::HARD_FACTOR * (limit >> 20)
            )),
            Err(e) => Err(e.to_string()),
        }
    };
    if matches!(result, Ok(Parsed::Whole)) {
        // Whatever is left (nothing, for a well-formed file) still counts
        // for the hash.
        let _ = std::io::copy(&mut buffered, &mut std::io::sink());
    }
    (result, ctx.metadata, ctx.secrets, ctx.oversized)
}

// ------------------------------------------------------------ stitching

/// One source being read.
struct SourceRun {
    stats: OgSourceStats,
    pack: Option<usize>,
    files: Vec<usize>,
    kept_bytes: u64,
    /// Stop reading this source's files (a cap was hit).
    halted: bool,
    /// IDs the SCCM correction rewrote.
    rekeyed: usize,
}

impl SourceRun {
    fn cap(&mut self, what: &str) {
        if !self.stats.caps_hit.iter().any(|c| c == what) {
            self.stats.caps_hit.push(what.to_string());
        }
        self.halted = true;
    }
}

/// Lazily built lookups for name and property matching.
#[derive(Default)]
struct MatchIndex {
    by_key: HashMap<&'static str, HashMap<String, Vec<NodeIndex>>>,
}

impl MatchIndex {
    fn get(
        &mut self,
        g: &crate::graph::AdGraph,
        key: &'static str,
    ) -> &HashMap<String, Vec<NodeIndex>> {
        self.by_key
            .entry(key)
            .or_insert_with(|| build_index(g, key))
    }
}

fn build_index(g: &crate::graph::AdGraph, key: &str) -> HashMap<String, Vec<NodeIndex>> {
    let mut out: HashMap<String, Vec<NodeIndex>> = HashMap::new();
    let mut add = |v: &str, ix: NodeIndex| {
        let v = v.trim().to_ascii_uppercase();
        if !v.is_empty() {
            let list = out.entry(v).or_default();
            if !list.contains(&ix) {
                list.push(ix);
            }
        }
    };
    for (ix, n) in g.nodes() {
        let principal = matches!(
            n.kind,
            NodeKind::User | NodeKind::Computer | NodeKind::Group
        );
        match key {
            "objectid" => add(&n.id, ix),
            "name" if !n.placeholder || n.ext.is_some() => {
                if !n.placeholder {
                    add(&n.name, ix);
                }
            }
            "distinguishedname" => {
                if let Some(dn) = &n.props.distinguishedname {
                    add(dn, ix);
                }
            }
            "dnshostname" => {
                if n.kind == NodeKind::Computer && !n.placeholder {
                    add(&n.name, ix);
                }
                if let Some(h) = n.adcs.as_ref().and_then(|a| a.dnshostname.as_ref()) {
                    add(h, ix);
                }
            }
            "samaccountname" if principal && !n.placeholder => {
                add(n.name.split('@').next().unwrap_or(&n.name), ix);
            }
            _ => {}
        }
        if let Some(ext) = &n.ext {
            for (k, v) in &ext.props {
                let same = k == key
                    || (key == "dnshostname" && k == "hostname")
                    || (key == "mail" && k == "email")
                    || (key == "email" && k == "mail");
                if same {
                    if let Some(s) = v.as_str() {
                        add(s, ix);
                    }
                }
            }
        }
    }
    out
}

/// The kind names an analysis has seen, capped.
struct KindNames {
    map: HashMap<String, ExtKind>,
    from_files: usize,
    max: usize,
    over: usize,
}

impl KindNames {
    fn get(&mut self, name: &str) -> (ExtKind, bool) {
        if let Some(&k) = self.map.get(name) {
            return (k, true);
        }
        if self.from_files >= self.max {
            self.over += 1;
            return (kinds::OTHER, false);
        }
        self.from_files += 1;
        let k = kinds::intern(name);
        self.map.insert(name.to_string(), k);
        (k, true)
    }
}

fn node_matches_kind(n: &Node, kind: &str) -> bool {
    n.kind.as_str().eq_ignore_ascii_case(kind)
        || n.ext.as_ref().is_some_and(|e| {
            e.kinds
                .iter()
                .any(|k| kinds::name(*k).eq_ignore_ascii_case(kind))
        })
}

fn native_node_kind(name: &str) -> Option<NodeKind> {
    NodeKind::ALL
        .iter()
        .copied()
        .find(|k| *k != NodeKind::Base && k.as_str().eq_ignore_ascii_case(name))
}

fn base_name(k: EdgeKind) -> &'static str {
    let n = k.as_str();
    n.strip_suffix(" (context)").unwrap_or(n)
}

impl Ingestor {
    /// Packs to use instead of the embedded ones (tests, user packs).
    pub fn with_packs(mut self, packs: Vec<Pack>) -> Self {
        self.og.packs = Some(packs);
        self
    }

    /// Queues an OpenGraph file for [`Ingestor::ingest_opengraph`].
    pub(super) fn defer_opengraph(
        &mut self,
        label: &str,
        input: OgInput,
        source_kind: Option<String>,
    ) {
        self.og.deferred.push(Deferred {
            label: label.to_string(),
            input,
            source_kind,
        });
    }

    /// Reads a coverage sidecar.
    pub(super) fn take_sidecar(&mut self, label: &str, bytes: Result<Vec<u8>, String>) {
        let parsed = bytes.and_then(|b| Sidecar::parse(&b));
        self.og.sidecars.push((label.to_string(), parsed));
    }

    /// Stitches the queued OpenGraph files onto the graph (see the module
    /// documentation). Runs once; without OpenGraph files it changes
    /// nothing.
    pub fn ingest_opengraph(&mut self) {
        if self.og.done {
            return;
        }
        self.og.done = true;
        let deferred = std::mem::take(&mut self.og.deferred);
        let sidecars = std::mem::take(&mut self.og.sidecars);
        if deferred.is_empty() {
            self.stats.opengraph.unused_sidecars = sidecars
                .iter()
                .map(|(label, r)| match r {
                    Ok(_) => format!("{label} (no OpenGraph file to cover)"),
                    Err(e) => format!("{label} ({e})"),
                })
                .collect();
            return;
        }
        let packs: Vec<Pack> = self.og.packs_in_effect();
        let table = KindTable::from_packs(&packs);
        let limits = self.limits.og;
        let mut keep = Keep {
            nodes: DEFAULT_KEEP.iter().map(|s| s.to_string()).collect(),
            edges: HashSet::new(),
        };
        for p in &packs {
            keep.nodes.extend(p.condition_keys().map(str::to_owned));
            keep.edges
                .extend(p.edge_condition_keys().map(str::to_owned));
        }
        // Node keep lists, per pack (all node kinds of a pack share them:
        // a property can arrive before the node's kinds).
        for p in &packs {
            for k in table_node_kinds(p) {
                keep.nodes
                    .extend(p.keep_for(&k).iter().map(|s| s.to_ascii_lowercase()));
            }
        }

        // Which source each file is.
        let mut runs: Vec<SourceRun> = Vec::new();
        for (fi, d) in deferred.iter().enumerate() {
            let name = match &d.source_kind {
                Some(s) => s.clone(),
                None => self.markers(d, &packs, &keep, limits.max_item_bytes),
            };
            let at = match runs
                .iter()
                .position(|r| r.stats.name.eq_ignore_ascii_case(&name))
            {
                Some(i) => i,
                None if runs.len() < MAX_SOURCES => {
                    // An OpenGraph file never gets the AzureHound pack, even
                    // if it calls itself AzureHound: only the AzureHound
                    // reader's own records make Entra paths.
                    let pack = packs
                        .iter()
                        .rposition(|p| p.claims(&name) && p.name() != "azurehound");
                    runs.push(SourceRun {
                        stats: OgSourceStats {
                            name: name.clone(),
                            pack: pack.map(|i| packs[i].name().to_string()),
                            trusted: pack.is_some_and(|i| packs[i].trusted()),
                            complete: true,
                            ..Default::default()
                        },
                        pack,
                        files: Vec::new(),
                        kept_bytes: 0,
                        halted: false,
                        rekeyed: 0,
                    });
                    runs.len() - 1
                }
                None => {
                    self.stats
                        .skipped_files
                        .push(format!("{} (too many OpenGraph sources)", d.label));
                    continue;
                }
            };
            runs[at].files.push(fi);
            runs[at].stats.files.push(d.label.clone());
        }

        let mut names = KindNames {
            map: HashMap::new(),
            from_files: 0,
            max: limits.max_kinds,
            over: 0,
        };
        // Pack kinds are known and don't count against the cap.
        for p in &packs {
            for (k, _) in p.edge_sems() {
                names.map.insert(kinds::name(k).to_string(), k);
            }
            for (k, _) in p.node_sems() {
                names.map.insert(kinds::name(k).to_string(), k);
            }
        }
        self.graph
            .set_og_sources(runs.iter().map(|r| r.stats.name.clone()).collect());
        self.graph.set_kind_table(table);

        // Sources whose pack re-keys SCCM sites: read their sites first, so
        // every ID naming a site can be rewritten in either pass.
        let mut sites = SiteMap::default();
        for run in &runs {
            if !run.pack.is_some_and(|i| packs[i].has_correction("sccm")) {
                continue;
            }
            for &fi in &run.files {
                let d = &deferred[fi];
                let scope = sccm::scope_of(&d.label);
                let mut sink = |item: Item| -> bool {
                    if let Item::Node(n) = item {
                        if let Some(site) = site_info(&n) {
                            sites.add(&scope, &site);
                        }
                    }
                    true
                };
                let _ = self_reader(&self.read, &d.input, false, |r| {
                    parse(r, Mode::Nodes, &keep, limits.max_item_bytes, &mut sink)
                });
            }
        }
        let rekeys = |run: &SourceRun| run.pack.is_some_and(|i| packs[i].has_correction("sccm"));

        // Pass 1: nodes. The node pass also hashes each file for its sidecar.
        let mut hashes: Vec<Option<String>> = vec![None; deferred.len()];
        for (si, run) in runs.iter_mut().enumerate() {
            let rekey = rekeys(run).then_some(&sites);
            for &fi in &run.files.clone() {
                if run.halted {
                    break;
                }
                let d = &deferred[fi];
                let scope = sccm::scope_of(&d.label);
                let mut hasher = Sha256::new();
                if matches!(
                    d.input,
                    OgInput::File { bom: true, .. } | OgInput::Zip { bom: true, .. }
                ) {
                    hasher.update(b"\xEF\xBB\xBF");
                }
                let outcome = {
                    let graph = &mut self.graph;
                    let mut sink = |item: Item| -> bool {
                        let Item::Node(n) = item else { return true };
                        run.stats.nodes += 1;
                        if run.stats.nodes > limits.max_nodes {
                            run.cap("nodes");
                            return false;
                        }
                        let rekey = rekey.map(|m| (m, scope.as_str()));
                        apply_node(graph, si as SourceId, n, run, &mut names, limits, rekey);
                        !run.halted
                    };
                    let hasher = &mut hasher;
                    self_reader(&self.read, &d.input, true, |r| {
                        let mut r = Hashing { inner: r, hasher };
                        parse(&mut r, Mode::Nodes, &keep, limits.max_item_bytes, &mut sink)
                    })
                };
                match outcome {
                    Ok((Ok(Parsed::Whole), _, secrets, oversized)) => {
                        run.stats.dropped_secrets += secrets;
                        run.stats.oversized += oversized;
                        hashes[fi] = Some(hex(&hasher.finalize()));
                    }
                    Ok((Ok(Parsed::Stopped), _, secrets, oversized)) => {
                        run.stats.dropped_secrets += secrets;
                        run.stats.oversized += oversized;
                    }
                    Ok((Err(e), _, secrets, _)) => {
                        run.stats.dropped_secrets += secrets;
                        run.stats.errors.push(format!("{}: {e}", d.label));
                    }
                    Err(e) => run.stats.errors.push(format!("{}: {e}", d.label)),
                }
            }
        }

        // Pass 2: edges.
        let mut index = MatchIndex::default();
        for (si, run) in runs.iter_mut().enumerate() {
            let pack = run.pack.map(|i| &packs[i]);
            let companions: Vec<&Pack> = pack
                .map(|p| {
                    packs
                        .iter()
                        .filter(|c| p.companions().iter().any(|n| n == c.name()))
                        .filter(|c| c.name() != "azurehound")
                        .collect()
                })
                .unwrap_or_default();
            let rekey = rekeys(run).then_some(&sites);
            let mut edges_read = 0usize;
            for &fi in &run.files.clone() {
                // A source halted by a node cap reads no edges: its data is
                // incomplete either way.
                if run.halted {
                    break;
                }
                let d = &deferred[fi];
                let scope = sccm::scope_of(&d.label);
                let outcome = {
                    let graph = &mut self.graph;
                    let mut sink = |item: Item| -> bool {
                        let Item::Edge(e) = item else { return true };
                        edges_read += 1;
                        if edges_read > limits.max_edges {
                            run.cap("edges");
                            return false;
                        }
                        apply_edge(
                            graph,
                            EdgeCtx {
                                src: si as SourceId,
                                pack,
                                companions: &companions,
                                rekey: rekey.map(|m| (m, scope.as_str())),
                            },
                            e,
                            run,
                            &mut names,
                            &mut index,
                            &mut self.stats.opengraph.unmapped_kinds,
                        );
                        !run.halted
                    };
                    self_reader(&self.read, &d.input, false, |r| {
                        parse(r, Mode::Edges, &keep, limits.max_item_bytes, &mut sink)
                    })
                };
                match outcome {
                    Ok((Ok(_), _, _, oversized)) => run.stats.oversized += oversized,
                    Ok((Err(e), ..)) | Err(e) => {
                        let msg = format!("{}: {e}", d.label);
                        if !run.stats.errors.contains(&msg) {
                            run.stats.errors.push(msg);
                        }
                    }
                }
            }
        }

        // Corrections the packs ask for, now that every edge is in.
        let mut corrections = Vec::new();
        if !sites.is_empty() {
            let rekeyed: usize = runs.iter().map(|r| r.rekeyed).sum();
            corrections.push(format!(
                "ConfigManBearPig correction: SCCM sites re-keyed by site server ({rekeyed} IDs \
                 rewritten)"
            ));
        }
        if packs.iter().any(|p| p.has_correction("mssql")) && self.graph.has_og_edges() {
            corrections.extend(crate::opengraph::mssql::apply(&mut self.graph).notes());
        }
        self.stats.opengraph.corrections = corrections;

        self.assign_units();

        // Coverage: every file of a source needs a sidecar that vouches for it.
        let mut used = vec![false; sidecars.len()];
        for run in &mut runs {
            run.stats.complete = run.stats.caps_hit.is_empty()
                && run.stats.errors.is_empty()
                && run.stats.oversized == 0;
            run.stats.coverage =
                coverage_for(&self.graph, run, &deferred, &hashes, &sidecars, &mut used);
        }
        let stats = &mut self.stats.opengraph;
        stats.unused_sidecars = sidecars
            .iter()
            .zip(&used)
            .filter(|(_, u)| !**u)
            .map(|((label, r), _)| match r {
                Ok(_) => format!("{label} (matches no OpenGraph file read)"),
                Err(e) => format!("{label} ({e})"),
            })
            .collect();
        // The source that met the cap was halted there (see `KindNames`).
        stats.kinds_over_cap = names.over;
        stats.packs = self.graph.kind_table().packs().to_vec();
        stats.sources = runs.into_iter().map(|r| r.stats).collect();
    }

    /// For a file without `metadata.source_kind`: the source a node kind
    /// names (`[TH_ScheduledTask, Base, TaskHound]`); else, for a file of
    /// edges alone (ConfigManBearPig writes its AD-side edges untagged),
    /// the source of the pack that describes most of its edge kinds; else
    /// "OpenGraph". The AzureHound pack is never chosen this way.
    fn markers(&self, d: &Deferred, packs: &[Pack], keep: &Keep, limit: u64) -> String {
        let mut found: Option<String> = None;
        let mut by_edges: Vec<usize> = vec![0; packs.len()];
        let mut sink = |item: Item| -> bool {
            match item {
                Item::Node(n) => {
                    if let Some(k) = n.kinds.iter().find(|k| packs.iter().any(|p| p.claims(k))) {
                        found = Some(k.clone());
                        return false;
                    }
                }
                Item::Edge(e) => {
                    if let Some(kind) = &e.kind {
                        if let Some(i) = packs
                            .iter()
                            .position(|p| p.name() != "azurehound" && p.has_edge(kind))
                        {
                            by_edges[i] += 1;
                        }
                    }
                }
            }
            true
        };
        let _ = self_reader(&self.read, &d.input, false, |r| {
            parse(r, Mode::Markers, keep, limit, &mut sink)
        });
        if let Some(k) = found {
            return k;
        }
        let best = by_edges
            .iter()
            .enumerate()
            .filter(|(_, n)| **n > 0)
            .max_by_key(|(i, n)| (**n, std::cmp::Reverse(*i)))
            .map(|(i, _)| i);
        best.and_then(|i| packs[i].source_kinds().first().cloned())
            .unwrap_or_else(|| "OpenGraph".to_string())
    }

    /// Sets each external edge's coverage unit from its pack's rule.
    fn assign_units(&mut self) {
        let g = &self.graph;
        let mut units: Vec<(petgraph::graph::EdgeIndex, Option<String>)> = Vec::new();
        for e in g.inner().edge_references() {
            if g.edge_origin(e.id()).is_none() {
                continue;
            }
            let rule = g
                .kind_table()
                .edge(match e.weight() {
                    EdgeKind::External(k) => *k,
                    _ => continue,
                })
                .map(|s| s.unit.clone())
                .or_else(|| {
                    // A context twin uses its mapped kind's rule.
                    let base = kinds::lookup(base_name(*e.weight()))?;
                    g.kind_table().edge(base).map(|s| s.unit.clone())
                });
            let unit = match rule {
                None | Some(UnitRule::Source) => None,
                Some(UnitRule::Start) => Some(g.node(e.source()).id.clone()),
                Some(UnitRule::End) => Some(g.node(e.target()).id.clone()),
                Some(UnitRule::StartVia(via)) => {
                    let host = g
                        .inner()
                        .edges_directed(e.source(), Direction::Incoming)
                        .find(|h| via.iter().any(|v| v == base_name(*h.weight())))
                        .map(|h| g.node(h.source()).id.clone());
                    // No host found: the start object itself, which no
                    // sidecar lists, so a finding through it is held.
                    Some(host.unwrap_or_else(|| g.node(e.source()).id.clone()))
                }
            };
            units.push((e.id(), unit));
        }
        for (e, unit) in units {
            if let Some(o) = self.graph.edge_origin_mut(e) {
                o.unit = unit;
            }
        }
    }
}

fn table_node_kinds(p: &Pack) -> Vec<String> {
    p.node_sems()
        .into_iter()
        .map(|(k, _)| kinds::name(k).to_string())
        .collect()
}

/// [`Ingestor::with_og_reader`] without borrowing the whole ingestor.
pub(super) fn self_reader<T>(
    read: &Arc<std::sync::atomic::AtomicU64>,
    input: &OgInput,
    counted: bool,
    f: impl FnOnce(&mut dyn Read) -> T,
) -> Result<T, String> {
    // Not counted: a share no read reaches.
    let share = if counted { 1 } else { u64::MAX };
    match input {
        OgInput::Text(bytes) => {
            let mut r = Counted::new(&bytes[..], read, share);
            Ok(f(&mut r))
        }
        OgInput::File { path, bom } => {
            let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
            if *bom {
                file.read_exact(&mut [0u8; 3]).map_err(|e| e.to_string())?;
            }
            let mut r = Counted::new(file.take(MAX_ENTRY_BYTES), read, share);
            Ok(f(&mut r))
        }
        OgInput::Zip {
            path,
            index,
            size,
            bom,
        } => {
            let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
            let mut archive =
                zip::ZipArchive::new(BufReader::new(file)).map_err(|e| e.to_string())?;
            // The archive passed `check_zip` when first read; this entry's
            // headers must still agree.
            let options = zip::ZipReadOptions::new().enforce_header_consistency(true);
            let mut entry = archive
                .by_index_with_options(*index, options)
                .map_err(|e| e.to_string())?;
            if *bom {
                entry.read_exact(&mut [0u8; 3]).map_err(|e| e.to_string())?;
            }
            let rest = size.saturating_sub(if *bom { 3 } else { 0 });
            let mut r = Counted::new((&mut entry).take(rest), read, share);
            Ok(f(&mut r))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn kept_size(props: &[(String, Value)]) -> u64 {
    props
        .iter()
        .map(|(k, v)| (k.len() + v.to_string().len() + 32) as u64)
        .sum()
}

/// The node kind ConfigManBearPig gives a site.
const SCCM_SITE: &str = "SCCM_Site";

/// What an `SCCM_Site` node says about itself (for re-keying).
fn site_info(n: &OgNode) -> Option<SiteInfo> {
    if !n.kinds.iter().any(|k| k == SCCM_SITE) {
        return None;
    }
    let get = |k: &str| {
        n.props
            .iter()
            .find(|(key, _)| key == k)
            .and_then(|(_, v)| text_of(v))
            .filter(|s| !s.trim().is_empty())
    };
    let code = get("sitecode").or_else(|| n.id.clone())?;
    Some(SiteInfo {
        root: get("rootsitecode").unwrap_or_else(|| code.clone()),
        server: get("siteserverfqdn")
            .or_else(|| get("siteservername"))
            .or_else(|| get("siteguid")),
        code,
    })
}

fn apply_node(
    g: &mut crate::graph::AdGraph,
    src: SourceId,
    n: OgNode,
    run: &mut SourceRun,
    names: &mut KindNames,
    limits: OgLimits,
    rekey: Option<(&SiteMap, &str)>,
) {
    let Some(raw_id) = n.id else {
        run.stats.invalid += 1;
        return;
    };
    let mut id = normalize_id(&raw_id);
    if let Some((sites, scope)) = rekey {
        match sites.rekey(scope, &id) {
            Rekeyed::Same => {}
            Rekeyed::New { id: new, .. } => {
                id = new;
                run.rekeyed += 1;
            }
            Rekeyed::Ambiguous => {
                run.stats.invalid += 1;
                return;
            }
        }
    }
    if id.is_empty() || id.len() > MAX_ID_BYTES {
        run.stats.invalid += 1;
        return;
    }
    let valid: Vec<&String> = n
        .kinds
        .iter()
        .filter(|k| kinds::valid_name(k))
        .take(MAX_KINDS_PER_NODE)
        .collect();
    if valid.is_empty() {
        run.stats.invalid += 1;
        return;
    }
    let native = valid.iter().find_map(|k| native_node_kind(k));
    let mut ext: Vec<ExtKind> = Vec::new();
    for k in &valid {
        if native_node_kind(k).is_some() || k.eq_ignore_ascii_case("Base") {
            continue;
        }
        let (kind, ok) = names.get(k);
        if !ok {
            run.cap("kinds");
        }
        if !ext.contains(&kind) {
            ext.push(kind);
        }
    }
    let mut props = n.props;
    run.kept_bytes += kept_size(&props);
    if run.kept_bytes > limits.max_kept_bytes {
        // The name stays: it is what Cypher answers for `name`.
        props.retain(|(k, _)| k == "name");
        run.cap("kept properties");
    }
    let name = props
        .iter()
        .find(|(k, _)| k == "name")
        .and_then(|(_, v)| v.as_str())
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty());

    match g.lookup(&id) {
        Some(ix) => {
            let node = g.node_mut(ix);
            if node.og_created() {
                let theirs = match node.kind {
                    NodeKind::External(k) => Some(k),
                    _ => None,
                };
                if theirs.is_some() && ext.first() != theirs.as_ref() && native.is_none() {
                    run.stats.clashes += 1;
                }
            } else {
                run.stats.merged += 1;
            }
            // A placeholder of unknown kind learns its kind, as for ACEs;
            // nothing else AD said changes.
            if node.placeholder && node.kind == NodeKind::Base {
                if let Some(k) = native {
                    node.kind = k;
                }
            }
            let own = node.kind;
            let e = node.ext.get_or_insert_with(Default::default);
            if !e.sources.contains(&src) {
                e.sources.push(src);
            }
            for k in ext {
                if NodeKind::External(k) != own && !e.kinds.contains(&k) {
                    e.kinds.push(k);
                }
            }
            for (k, v) in props {
                if e.prop(&k).is_none() {
                    e.props.push((k, v));
                }
            }
        }
        None => {
            let og_kind = match (native, ext.first()) {
                (Some(k), _) => k,
                // A SID is an AD principal that was not collected.
                _ if is_sid_shaped(&id) => NodeKind::Base,
                (None, Some(&k)) => NodeKind::External(k),
                (None, None) => NodeKind::Base,
            };
            let mut node = Node::placeholder(id.clone(), og_kind);
            let external = og_kind.is_external();
            if external {
                // An object only this source knows: not a placeholder (it
                // is fully described), but never a principal either.
                node.placeholder = false;
                node.domain = None;
                node.domain_sid = None;
                run.stats.created += 1;
            } else {
                run.stats.placeholders += 1;
            }
            if let Some(name) = name {
                node.name = name;
            } else if external {
                node.name = id.clone();
            }
            let extra: Vec<ExtKind> = ext
                .into_iter()
                .filter(|k| NodeKind::External(*k) != og_kind)
                .collect();
            node.ext = Some(Box::new(ExtNode {
                sources: vec![src],
                kinds: extra,
                props,
                og_created: true,
                ..Default::default()
            }));
            g.upsert(node);
        }
    }
}

/// A placeholder for a SID an edge names that no data has.
fn sid_placeholder(
    g: &mut crate::graph::AdGraph,
    id: &str,
    hint: Option<&str>,
    src: SourceId,
    run: &mut SourceRun,
) -> NodeIndex {
    let kind = hint.and_then(native_node_kind).unwrap_or(NodeKind::Base);
    let ix = g.ensure(id, kind);
    let n = g.node_mut(ix);
    let e = n.ext.get_or_insert_with(|| {
        Box::new(ExtNode {
            og_created: true,
            ..Default::default()
        })
    });
    if !e.sources.contains(&src) {
        e.sources.push(src);
    }
    run.stats.placeholders += 1;
    ix
}

/// What an edge is read against: its source, the source's pack and its
/// companions, and the SCCM site map when the pack re-keys sites.
struct EdgeCtx<'a> {
    src: SourceId,
    pack: Option<&'a Pack>,
    companions: &'a [&'a Pack],
    rekey: Option<(&'a SiteMap, &'a str)>,
}

/// Rewrites an endpoint that names an SCCM site (by ID). `Err` when the
/// reference is ambiguous; `Ok(Some(hierarchy))` when it was re-keyed.
fn rekey_endpoint(
    ep: &mut Endpoint,
    rekey: Option<(&SiteMap, &str)>,
    run: &mut SourceRun,
) -> Result<Option<String>, ()> {
    let Some((sites, scope)) = rekey else {
        return Ok(None);
    };
    if ep.match_by.as_deref().is_some_and(|m| m != "id") {
        return Ok(None);
    }
    let Some(value) = ep.value.as_deref() else {
        return Ok(None);
    };
    match sites.rekey(scope, value) {
        Rekeyed::Same => Ok(None),
        Rekeyed::New { id, hierarchy } => {
            ep.value = Some(id);
            run.rekeyed += 1;
            Ok(Some(hierarchy))
        }
        Rekeyed::Ambiguous => Err(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_edge(
    g: &mut crate::graph::AdGraph,
    ctx: EdgeCtx<'_>,
    mut e: OgEdge,
    run: &mut SourceRun,
    names: &mut KindNames,
    index: &mut MatchIndex,
    unmapped: &mut BTreeMap<String, usize>,
) {
    let EdgeCtx {
        src,
        pack,
        companions,
        rekey,
    } = ctx;
    let Some(name) = e.kind.take().filter(|k| kinds::valid_name(k)) else {
        run.stats.invalid += 1;
        return;
    };
    // Native AD kinds: only AD data may say them, unless the pack accepts.
    let kind = if let Some(native) = EdgeKind::from_name(&name) {
        if !pack.is_some_and(|p| p.native().contains(&native)) {
            run.stats.dropped_native += 1;
            return;
        }
        native
    } else {
        let (k, ok) = names.get(&name);
        if !ok {
            run.cap("kinds");
        }
        let mapped_here =
            pack.is_some_and(|p| p.has_edge(&name)) || companions.iter().any(|c| c.has_edge(&name));
        let derived = g.kind_table().edge(k).is_some_and(|s| s.derived);
        if mapped_here && !derived {
            EdgeKind::External(k)
        } else if g.kind_table().edge(k).is_some() {
            // Another source's pack maps this kind: it can't vouch for
            // this file, so the edge is context only.
            run.stats.context_edges += 1;
            EdgeKind::External(kinds::context_alias(k))
        } else {
            *unmapped.entry(name.clone()).or_default() += 1;
            EdgeKind::External(k)
        }
    };
    let (Ok(h_start), Ok(h_end)) = (
        rekey_endpoint(&mut e.start, rekey, run),
        rekey_endpoint(&mut e.end, rekey, run),
    ) else {
        run.stats.unresolved += 1;
        return;
    };
    let Some(from) = resolve(g, &e.start, src, run, index) else {
        run.stats.unresolved += 1;
        return;
    };
    let Some(to) = resolve(g, &e.end, src, run, index) else {
        run.stats.unresolved += 1;
        return;
    };
    // Two SCCM hierarchies: an edge between them is ConfigManBearPig
    // joining every site it saw, not a relationship.
    let cross_hierarchy = matches!((&h_start, &h_end), (Some(a), Some(b)) if a != b);
    let kind = match kind {
        EdgeKind::External(k) => {
            let get = |at: End, key: &str| -> Option<&Value> {
                match at {
                    End::Edge => e.props.iter().find(|(p, _)| p == key).map(|(_, v)| v),
                    End::Start | End::End => g
                        .node(if at == End::Start { from } else { to })
                        .ext
                        .as_ref()
                        .and_then(|x| x.prop(key)),
                }
            };
            let context = cross_hierarchy
                || g.kind_table().edge(k).is_some_and(|sem| {
                    sem.unless.iter().any(|c| c.holds(get))
                        || !sem.when.iter().all(|c| c.holds(get))
                });
            if context {
                run.stats.context_edges += 1;
                EdgeKind::External(kinds::context_alias(k))
            } else {
                kind
            }
        }
        native => native,
    };
    if g.add_og_edge(
        from,
        to,
        kind,
        EdgeOrigin {
            source: src,
            unit: None,
        },
    ) {
        run.stats.edges += 1;
    }
}

/// `DOMAIN\user` (TaskHound's run-as accounts) as the `USER@DNS.DOMAIN`
/// name AD data gives the account, when the collection read the domain's
/// NetBIOS name (the built-in collector's stored credentials file).
fn netbios_name(g: &crate::graph::AdGraph, v: &str) -> Option<String> {
    let (domain, user) = v.trim().split_once('\\')?;
    let user = user.trim();
    if user.is_empty() || user.contains(['\\', '@']) {
        return None;
    }
    let dns = g.netbios().get(domain)?;
    Some(format!("{}@{dns}", user.to_ascii_uppercase()))
}

fn resolve(
    g: &mut crate::graph::AdGraph,
    ep: &Endpoint,
    src: SourceId,
    run: &mut SourceRun,
    index: &mut MatchIndex,
) -> Option<NodeIndex> {
    let by = ep.match_by.as_deref().unwrap_or("id");
    let matchers: Vec<(&str, String)> = match by {
        "id" => {
            let id = normalize_id(ep.value.as_deref()?);
            if id.is_empty() || id.len() > MAX_ID_BYTES {
                return None;
            }
            if let Some(ix) = g.lookup(&id) {
                return Some(ix);
            }
            // An AD principal that was not collected; anything else that
            // isn't there is a dangling reference.
            return is_sid_shaped(&id)
                .then(|| sid_placeholder(g, &id, ep.kind.as_deref(), src, run));
        }
        "name" => {
            let v = ep.value.clone()?;
            // `DOMAIN\user` as the account's name when the collection read
            // the NetBIOS name and that name matches; else the name as given
            // (a real name may hold a backslash).
            let alt = netbios_name(g, &v).filter(|alt| {
                index
                    .get(g, "name")
                    .get(&alt.trim().to_ascii_uppercase())
                    .is_some_and(|c| !c.is_empty())
            });
            vec![("name", alt.unwrap_or(v))]
        }
        "property" => {
            if ep.matchers.is_empty() || ep.matchers.len() > MAX_MATCHERS {
                return None;
            }
            let mut out = Vec::new();
            for (key, op, value) in &ep.matchers {
                if op
                    .as_deref()
                    .is_some_and(|o| !o.eq_ignore_ascii_case("equals"))
                {
                    return None;
                }
                let key = MATCH_KEYS.iter().find(|k| **k == key.as_str())?;
                out.push((*key, text_of(value)?));
            }
            out
        }
        _ => return None,
    };
    let mut candidates: Option<Vec<NodeIndex>> = None;
    for (key, value) in matchers {
        let key: &'static str = MATCH_KEYS.iter().find(|k| **k == key)?;
        let found = index
            .get(g, key)
            .get(&value.trim().to_ascii_uppercase())
            .cloned()
            .unwrap_or_default();
        candidates = Some(match candidates {
            None => found,
            Some(c) => c.into_iter().filter(|ix| found.contains(ix)).collect(),
        });
    }
    let mut c = candidates?;
    if let Some(kind) = &ep.kind {
        c.retain(|&ix| node_matches_kind(g.node(ix), kind));
    }
    // Exactly one match, or nothing: a name shared by two objects must not
    // pick one at random.
    (c.len() == 1).then(|| c[0])
}

fn coverage_for(
    g: &crate::graph::AdGraph,
    run: &SourceRun,
    deferred: &[Deferred],
    hashes: &[Option<String>],
    sidecars: &[(String, Result<Sidecar, String>)],
    used: &mut [bool],
) -> CoverageInfo {
    let mut info = CoverageInfo::default();
    let mut found: Vec<&Sidecar> = Vec::new();
    for &fi in &run.files {
        let d = &deferred[fi];
        let Some(hash) = &hashes[fi] else {
            info.notes.push(format!(
                "{} was not read whole, so no sidecar can vouch for it",
                d.label
            ));
            continue;
        };
        let file_name = d.label.rsplit(['/', '\\', '!']).next().unwrap_or(&d.label);
        let mut matched = false;
        for (i, (label, parsed)) in sidecars.iter().enumerate() {
            let Ok(s) = parsed else { continue };
            if !s.binds(file_name, hash) {
                if s.payloads.iter().any(|p| {
                    p.file
                        .rsplit(['/', '\\'])
                        .next()
                        .is_some_and(|b| b.eq_ignore_ascii_case(file_name))
                }) {
                    info.notes.push(format!(
                        "{label}: its SHA-256 for {file_name} does not match the file"
                    ));
                    used[i] = true;
                }
                continue;
            }
            used[i] = true;
            if !s.source_kind.eq_ignore_ascii_case(&run.stats.name) {
                info.notes.push(format!(
                    "{label} is for {}, not {}",
                    s.source_kind, run.stats.name
                ));
                continue;
            }
            matched = true;
            found.push(s);
        }
        if !matched {
            info.notes.push(format!("no coverage file for {file_name}"));
        }
    }
    let all_files = !found.is_empty() && found.len() >= run.files.len() && info.notes.is_empty();
    if !all_files {
        info.state = if found.is_empty() && info.notes.iter().all(|n| n.starts_with("no coverage"))
        {
            CoverageState::None
        } else {
            CoverageState::Invalid
        };
        return info;
    }
    info.state = CoverageState::Sidecar;
    info.complete = found.iter().all(|s| s.complete);
    info.asserted_by = found[0].asserted_by.clone();
    info.unit_type = Some(found[0].units.kind.clone());
    info.collected_at = found.iter().filter_map(|s| s.collected_at).max();
    let mut ok: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    let mut domains: Vec<String> = Vec::new();
    for s in &found {
        ok.extend(s.units.ok.iter().map(|u| unit_id(g, u)));
        failed.extend(s.units.failed.iter().map(|f| unit_id(g, &f.id)));
        if s.units.all_in_domains {
            domains.extend(s.domains.iter().map(|d| d.trim().to_ascii_uppercase()));
        }
    }
    for list in [&mut ok, &mut failed, &mut domains] {
        list.sort();
        list.dedup();
    }
    info.ok = ok;
    info.failed = failed;
    info.all_in_domains = domains;
    info
}

/// A unit as an object ID where it names one (by ID, or by a unique name or
/// host name), else as written (upper-cased).
fn unit_id(g: &crate::graph::AdGraph, unit: &str) -> String {
    let u = normalize_id(unit);
    if let Some(ix) = g.lookup(&u) {
        return g.node(ix).id.clone();
    }
    let matches: Vec<&Node> = g
        .nodes()
        .map(|(_, n)| n)
        .filter(|n| !n.placeholder && n.name == u)
        .take(2)
        .collect();
    match matches.as_slice() {
        [one] => one.id.clone(),
        _ => u,
    }
}
