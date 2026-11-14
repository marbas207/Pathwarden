//! The AzureHound reader: Entra ID objects and the relationships AzureHound
//! states (group membership, ownership, role assignments), stitched onto the
//! AD graph as external objects of the built-in `azurehound` pack's kinds.
//!
//! AzureHound (`azurehound list az-ad`) writes BloodHound CE's Azure format:
//!
//! ```json
//! {"data":[{"kind":"AZUser","data":{"id":"…","userPrincipalName":"…","tenantId":"…"}}, …],
//!  "meta":{"type":"azure","version":5,"count":N}}
//! ```
//!
//! Files are recognised by `meta.type == "azure"` while the AD data streams
//! in, queued, and read after every AD and OpenGraph file, in two passes
//! (nodes, then edges), the way the OpenGraph reader works. What the role
//! assignments imply (password resets, adding secrets, ...) and the hybrid
//! links to AD objects are derived later, in [`crate::entra::derive`].
//!
//! The file is hostile input, as an OpenGraph file is:
//! - the same caps ([`super::OgLimits`]): nodes and edges per source, kept
//!   property bytes, and memory per parsed record. A list inside a record
//!   (the members of a large group) is charged per element, so a big group
//!   doesn't make its record oversized;
//! - only an allow-list of properties is kept (no credentials: AzureHound
//!   writes `passwordCredentials` and `keyCredentials` metadata for
//!   applications), strings cut to 1 KiB, and secret-looking keys counted
//!   as dropped;
//! - an ID that another source (AD data, an OpenGraph file) already has is
//!   a clash: the record is skipped, so an Entra object can never merge into
//!   an AD object or borrow its edges. AD objects are only reached through
//!   the hybrid edges `crate::entra` derives;
//! - edges only join objects this reader created; anything else is
//!   unresolved;
//! - past any cap, or after a read error, the source is incomplete: its
//!   findings can open but never resolve.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{BufReader, Read};

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use super::budget::{self, BValue};
use super::opengraph::{self_reader, Deferred, OgInput, OgLimits, OgSourceStats};
use super::raw::RawMeta;
use super::Ingestor;
use crate::entra::{self, truthy, SOURCE};
use crate::graph::{normalize_id, AdGraph};
use crate::kinds;
use crate::model::{EdgeKind, ExtNode, Node, NodeKind, SourceId};
use crate::opengraph::coverage::{CoverageInfo, CoverageState};
use crate::opengraph::{pack, EdgeOrigin, KindTable};

const MAX_ID_BYTES: usize = 512;
const MAX_STRING_BYTES: usize = 1024;
/// AzureHound's kept properties may use this many times OpenGraph's
/// budget (1 GiB by default): they are a fixed list of fields, each a value
/// of at most [`MAX_STRING_BYTES`], so a tenant of half a million objects
/// keeps about 270 MB, where 64 MiB stopped the read at ~110k objects.
const KEPT_FACTOR: u64 = 16;

/// Whether a collector file's `meta` block says it is AzureHound output.
pub(super) fn is_azure(meta: &Option<RawMeta>) -> bool {
    meta.as_ref()
        .is_some_and(|m| m.kind.eq_ignore_ascii_case("azure"))
}

/// Fields of a record's `data` that are kept, by their JSON name, and the
/// (lower-case) name they are kept under. Everything else is skipped while
/// parsing.
const FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("displayName", "displayname"),
    ("userPrincipalName", "userprincipalname"),
    (
        "onPremisesSecurityIdentifier",
        "onpremisessecurityidentifier",
    ),
    ("onPremisesSyncEnabled", "onpremisessyncenabled"),
    ("accountEnabled", "accountenabled"),
    ("userType", "usertype"),
    ("tenantId", "tenantid"),
    ("tenantName", "tenantname"),
    ("appId", "appid"),
    ("appDisplayName", "appdisplayname"),
    ("publisherDomain", "publisherdomain"),
    ("servicePrincipalType", "serviceprincipaltype"),
    ("deviceId", "deviceid"),
    ("operatingSystem", "operatingsystem"),
    ("trustType", "trusttype"),
    ("isManaged", "ismanaged"),
    ("isAssignableToRole", "isassignabletorole"),
    ("securityEnabled", "securityenabled"),
    ("templateId", "roletemplateid"),
    ("isBuiltIn", "isbuiltin"),
    ("collected", "collected"),
    ("defaultDomain", "defaultdomain"),
    ("groupId", "groupid"),
    ("servicePrincipalId", "serviceprincipalid"),
    ("roleDefinitionId", "roledefinitionid"),
    ("principalId", "principalid"),
    ("directoryScopeId", "directoryscopeid"),
    // App role assignments (Microsoft Graph application permissions).
    ("appRoleId", "approleid"),
    ("principalType", "principaltype"),
    ("resourceId", "resourceid"),
];

/// Properties kept on the objects (the rest of [`FIELDS`] only link records).
const KEEP: &[&str] = &[
    "displayname",
    "userprincipalname",
    "onpremisessecurityidentifier",
    "onpremisessyncenabled",
    "accountenabled",
    "usertype",
    "tenantid",
    "tenantname",
    "appid",
    "serviceprincipaltype",
    "deviceid",
    "operatingsystem",
    "trusttype",
    "ismanaged",
    "isassignabletorole",
    "securityenabled",
    "roletemplateid",
    "defaultdomain",
];

/// Lists inside a record, read element by element.
const LISTS: &[&str] = &["members", "owners", "roleAssignments", "fics"];

/// Wrapper objects some AzureHound versions nest an object in.
const WRAPPERS: &[&str] = &[
    "user",
    "group",
    "servicePrincipal",
    "application",
    "app",
    "device",
    "role",
    "tenant",
];

/// One element of `members`, `owners`, `roleAssignments` or `fics`.
#[derive(Debug, Default, Clone)]
struct Item {
    /// `member.id` / `owner.id`.
    id: Option<String>,
    principal: Option<String>,
    role: Option<String>,
    scope: Option<String>,
    /// A federated identity credential's `fic.issuer` and `fic.subject`.
    issuer: Option<String>,
    subject: Option<String>,
    /// A federated identity credential's application (`appId`).
    app: Option<String>,
}

/// One `{"kind": ..., "data": ...}` record.
#[derive(Debug, Default)]
struct Record {
    kind: Option<String>,
    fields: BTreeMap<&'static str, Value>,
    items: Vec<Item>,
}

impl Record {
    fn s(&self, key: &str) -> Option<String> {
        self.fields
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    }

    /// AzureHound omits false booleans: missing is false.
    fn b(&self, key: &str) -> bool {
        self.fields.get(key).is_some_and(truthy)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Nodes,
    Edges,
}

const STOP: &str = "pathwarden: stop reading";

struct Ctx<'a> {
    mode: Mode,
    limit: u64,
    sink: &'a mut dyn FnMut(Record) -> bool,
    secrets: usize,
    oversized: usize,
    /// The record went over its budget before a list (which restarts it).
    over_before_list: bool,
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
        f.write_str("an AzureHound file (a JSON object)")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "data" {
                map.next_value_seed(Records(&mut *self.0))?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct Records<'a, 'b>(&'a mut Ctx<'b>);

impl<'de> DeserializeSeed<'de> for Records<'_, '_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Records<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a list of records")
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
            let rec = seq.next_element_seed(RecordSeed(&mut *self.0));
            let cost = budget::finish();
            // Taken first: a record over budget after its list too must not
            // leave the mark for the next one.
            let before = std::mem::take(&mut self.0.over_before_list);
            let over = cost.oversized || before;
            let Some(rec) = rec? else {
                return Ok(());
            };
            if over {
                self.0.oversized += 1;
                continue;
            }
            if !(self.0.sink)(rec) {
                return Err(de::Error::custom(STOP));
            }
        }
    }
}

struct RecordSeed<'a, 'b>(&'a mut Ctx<'b>);

impl<'de> DeserializeSeed<'de> for RecordSeed<'_, '_> {
    type Value = Record;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Record, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for RecordSeed<'_, '_> {
    type Value = Record;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a {kind, data} record")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Record, A::Error> {
        let mut rec = Record::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "kind" => {
                    rec.kind = map
                        .next_value::<BValue>()?
                        .0
                        .as_str()
                        .filter(|k| kinds::valid_name(k))
                        .map(str::to_owned);
                }
                // The data doesn't depend on the kind, so the two keys may
                // come in either order.
                "data" => map.next_value_seed(DataSeed {
                    ctx: &mut *self.0,
                    rec: &mut rec,
                })?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(rec)
    }
}

struct DataSeed<'a, 'b> {
    ctx: &'a mut Ctx<'b>,
    rec: &'a mut Record,
}

impl<'de> DeserializeSeed<'de> for DataSeed<'_, '_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DataSeed<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a data object")
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if LISTS.contains(&key.as_str()) {
                // Read (relationships) or skipped (objects) element by
                // element, so a group of 160k members is never one item.
                let keep = self.ctx.mode == Mode::Edges;
                if budget::finish().oversized {
                    self.ctx.over_before_list = true;
                }
                map.next_value_seed(ListSeed {
                    ctx: &mut *self.ctx,
                    items: &mut self.rec.items,
                    keep,
                })?;
                // The rest of the record gets a budget of its own.
                budget::begin(self.ctx.limit);
            } else if let Some(&(_, kept)) = FIELDS.iter().find(|(json, _)| *json == key) {
                let v = map.next_value::<BValue>()?.0;
                if let Some(v) = sanitize(v) {
                    self.rec.fields.entry(kept).or_insert(v);
                }
            } else if WRAPPERS.contains(&key.as_str()) {
                map.next_value_seed(DataSeed {
                    ctx: &mut *self.ctx,
                    rec: &mut *self.rec,
                })?;
            } else {
                if pack::is_secret_key(&key) {
                    self.ctx.secrets += 1;
                }
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct ListSeed<'a, 'b> {
    ctx: &'a mut Ctx<'b>,
    items: &'a mut Vec<Item>,
    /// False in the objects pass: the elements are only skipped.
    keep: bool,
}

impl<'de> DeserializeSeed<'de> for ListSeed<'_, '_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ListSeed<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a list")
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        loop {
            // Each element on its own budget: a group's member list may be
            // far larger than one record's budget.
            budget::begin(self.ctx.limit);
            if !self.keep {
                let v = seq.next_element::<IgnoredAny>();
                budget::finish();
                if v?.is_none() {
                    return Ok(());
                }
                continue;
            }
            let v = seq.next_element::<BValue>();
            let cost = budget::finish();
            let Some(v) = v? else {
                return Ok(());
            };
            if cost.oversized {
                self.ctx.oversized += 1;
                continue;
            }
            self.items.push(item_of(&v.0));
        }
    }
}

fn id_text(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= MAX_ID_BYTES)
        .map(str::to_owned)
}

fn item_of(v: &Value) -> Item {
    let nested = |k: &str| v.get(k).and_then(|o| id_text(o.get("id")));
    let fic = |k: &str| v.get("fic").and_then(|o| id_text(o.get(k)));
    Item {
        id: nested("member").or_else(|| nested("owner")),
        principal: id_text(v.get("principalId")),
        role: id_text(v.get("roleDefinitionId")),
        scope: v
            .get("directoryScopeId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        issuer: fic("issuer"),
        subject: fic("subject"),
        app: id_text(v.get("appId")),
    }
}

/// Primitives only, strings cut to [`MAX_STRING_BYTES`].
fn sanitize(v: Value) -> Option<Value> {
    match v {
        Value::String(mut s) => {
            if s.len() > MAX_STRING_BYTES {
                let mut end = MAX_STRING_BYTES;
                while !s.is_char_boundary(end) {
                    end -= 1;
                }
                s.truncate(end);
            }
            Some(Value::String(s))
        }
        Value::Bool(_) | Value::Number(_) => Some(v),
        _ => None,
    }
}

/// Parses one AzureHound file in `mode`, handing each record to `sink`.
/// Returns whether it was read to the end (`Ok(true)`), stopped by the sink
/// (`Ok(false)`), or failed; and the secrets and oversized records counted.
fn parse(
    reader: &mut dyn Read,
    mode: Mode,
    limit: u64,
    sink: &mut dyn FnMut(Record) -> bool,
) -> (Result<bool, String>, usize, usize) {
    budget::reset();
    let mut buffered = BufReader::with_capacity(1 << 16, budget::Tracked(reader));
    let mut ctx = Ctx {
        mode,
        limit,
        sink,
        secrets: 0,
        oversized: 0,
        over_before_list: false,
    };
    let result = {
        let mut de = serde_json::Deserializer::from_reader(&mut buffered);
        match Top(&mut ctx).deserialize(&mut de).and_then(|()| de.end()) {
            Ok(()) => Ok(true),
            Err(e) if e.to_string().starts_with(STOP) => Ok(false),
            Err(e) if budget::tripped() => Err(format!(
                "a record larger than {} MiB ({e})",
                budget::HARD_FACTOR * (limit >> 20)
            )),
            Err(e) => Err(e.to_string()),
        }
    };
    (result, ctx.secrets, ctx.oversized)
}

/// What the files say about each tenant, for coverage.
#[derive(Default)]
struct Tenants {
    /// `AZTenant` records with `collected: true`.
    collected: BTreeSet<String>,
    /// Tenants with at least one `AZUser` record.
    users: BTreeSet<String>,
    /// Tenants with at least one `AZRoleAssignment` record.
    assignments: BTreeSet<String>,
    /// Every tenant a record names.
    seen: BTreeSet<String>,
}

struct Run {
    stats: OgSourceStats,
    kept_bytes: u64,
    halted: bool,
    edges_read: usize,
}

impl Run {
    fn cap(&mut self, what: &str) {
        if !self.stats.caps_hit.iter().any(|c| c == what) {
            self.stats.caps_hit.push(what.to_string());
        }
        self.halted = true;
    }
}

impl Ingestor {
    /// Queues an AzureHound file for [`Ingestor::ingest_azurehound`].
    pub(super) fn defer_azurehound(&mut self, label: &str, input: OgInput) {
        self.og.azurehound.push(Deferred {
            label: label.to_string(),
            input,
            source_kind: Some(SOURCE.to_string()),
        });
    }

    /// Adds the queued AzureHound files to the graph (see the module
    /// documentation). Runs after the OpenGraph files; without AzureHound
    /// files it changes nothing.
    pub fn ingest_azurehound(&mut self) {
        if self.og.azurehound.is_empty() {
            return;
        }
        let packs = self.og.packs_in_effect();
        let files = std::mem::take(&mut self.og.azurehound);
        if !self
            .graph
            .kind_table()
            .packs()
            .iter()
            .any(|p| p.name == "azurehound")
        {
            self.graph.set_kind_table(KindTable::from_packs(&packs));
        }
        let limits = self.limits.og;
        let src = self.graph.add_og_source(SOURCE);
        let mut run = Run {
            stats: OgSourceStats {
                name: SOURCE.to_string(),
                pack: Some("azurehound".to_string()),
                trusted: true,
                files: files.iter().map(|d| d.label.clone()).collect(),
                complete: true,
                ..Default::default()
            },
            kept_bytes: 0,
            halted: false,
            edges_read: 0,
        };
        let mut tenants = Tenants::default();
        // Records too large, per file, as the objects pass counted them:
        // both passes meet every record, so the relationships pass adds
        // only the ones the first didn't reach (it stopped on an error).
        let mut too_large = vec![0usize; files.len()];

        for mode in [Mode::Nodes, Mode::Edges] {
            for (fi, d) in files.iter().enumerate() {
                if run.halted {
                    break;
                }
                let graph = &mut self.graph;
                let run_ref = &mut run;
                let tenants_ref = &mut tenants;
                let mut sink = |rec: Record| -> bool {
                    match mode {
                        Mode::Nodes => apply_node(graph, src, rec, run_ref, tenants_ref, limits),
                        Mode::Edges => apply_edges(graph, src, rec, run_ref, limits),
                    }
                    !run_ref.halted
                };
                let outcome = self_reader(&self.read, &d.input, mode == Mode::Nodes, |r| {
                    parse(r, mode, limits.max_item_bytes, &mut sink)
                });
                match outcome {
                    Ok((result, secrets, oversized)) => {
                        if mode == Mode::Nodes {
                            run.stats.dropped_secrets += secrets;
                            too_large[fi] = oversized;
                            run.stats.oversized += oversized;
                        } else {
                            run.stats.oversized += oversized.saturating_sub(too_large[fi]);
                        }
                        if let Err(e) = result {
                            let msg = format!("{}: {e}", d.label);
                            if !run.stats.errors.contains(&msg) {
                                run.stats.errors.push(msg);
                            }
                        }
                    }
                    Err(e) => {
                        let msg = format!("{}: {e}", d.label);
                        if !run.stats.errors.contains(&msg) {
                            run.stats.errors.push(msg);
                        }
                    }
                }
            }
        }

        run.stats.complete = run.stats.caps_hit.is_empty()
            && run.stats.errors.is_empty()
            && run.stats.oversized == 0;
        run.stats.coverage = coverage(&tenants, run.stats.complete);
        let og = &mut self.stats.opengraph;
        if og.packs.is_empty() {
            og.packs = self.graph.kind_table().packs().to_vec();
        }
        og.sources.push(run.stats);
    }
}

/// A tenant is covered when the files hold its `AZTenant` record marked
/// `collected`, at least one user and at least one role assignment record
/// for it, and the source was read whole. Every other tenant a record names
/// is listed as failed: findings in it are held.
fn coverage(t: &Tenants, complete: bool) -> CoverageInfo {
    let mut info = CoverageInfo {
        state: CoverageState::Collector,
        unit_type: Some("tenant".to_string()),
        asserted_by: Some("collector".to_string()),
        complete,
        ..Default::default()
    };
    for id in t.seen.iter().chain(t.collected.iter()) {
        if info.ok.contains(id) || info.failed.contains(id) {
            continue;
        }
        let missing: Vec<&str> = [
            (!t.collected.contains(id)).then_some("no AZTenant record marked collected"),
            (!t.users.contains(id)).then_some("no users"),
            (!t.assignments.contains(id)).then_some("no role assignments"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if missing.is_empty() {
            info.ok.push(id.clone());
        } else {
            info.notes
                .push(format!("tenant {id}: {}", missing.join(", ")));
            info.failed.push(id.clone());
        }
    }
    info
}

fn tenant_of(rec: &Record) -> Option<String> {
    rec.s("tenantid")
        .map(|t| normalize_id(&t))
        .filter(|t| !t.is_empty() && t.len() <= MAX_ID_BYTES)
}

/// Whether `ix` is an object this reader created.
fn ours(g: &AdGraph, ix: petgraph::graph::NodeIndex, src: SourceId) -> bool {
    let n = g.node(ix);
    n.og_created()
        && n.kind.is_external()
        && n.ext.as_ref().is_some_and(|e| e.sources.contains(&src))
}

fn apply_node(
    g: &mut AdGraph,
    src: SourceId,
    rec: Record,
    run: &mut Run,
    tenants: &mut Tenants,
    limits: OgLimits,
) {
    let Some(kind) = rec.kind.clone() else {
        run.stats.invalid += 1;
        return;
    };
    let tenant = tenant_of(&rec);
    if let Some(t) = &tenant {
        tenants.seen.insert(t.clone());
    }
    let upper = |s: Option<String>| s.map(|v| v.to_ascii_uppercase());
    let at_tenant = |name: Option<String>| {
        let name = name?.to_ascii_uppercase();
        Some(match rec.s("tenantname") {
            Some(t) => format!("{name}@{}", t.to_ascii_uppercase()),
            None => name,
        })
    };
    // Whether Cypher answers the name, as BloodHound CE has one: a
    // name Pathwarden makes up for display (a user's display name without
    // a UPN, an application without its publisher domain) answers null.
    let mut bh_named = true;
    // BloodHound CE's name when it differs from the one shown (a tenant's).
    let mut bh_name: Option<String> = None;
    let (id, name) = match kind.as_str() {
        "AZUser" => {
            if let Some(t) = &tenant {
                tenants.users.insert(t.clone());
            }
            bh_named = rec.s("userprincipalname").is_some_and(|u| !u.is_empty());
            (
                rec.s("id"),
                upper(rec.s("userprincipalname")).or_else(|| at_tenant(rec.s("displayname"))),
            )
        }
        "AZGroup" | "AZServicePrincipal" | "AZDevice" => {
            (rec.s("id"), at_tenant(rec.s("displayname")))
        }
        // BloodHound keys an application on its appId: role assignments
        // scoped to an application and app owner records name it so.
        "AZApp" => {
            bh_named = rec.s("publisherdomain").is_some_and(|d| !d.is_empty());
            let name = rec.s("displayname").map(|n| {
                let domain = rec.s("publisherdomain").or_else(|| rec.s("tenantname"));
                match domain {
                    Some(d) => format!("{n}@{d}").to_ascii_uppercase(),
                    None => n.to_ascii_uppercase(),
                }
            });
            (rec.s("appid"), name)
        }
        // `<role id>@<tenant id>`, as BloodHound builds it.
        "AZRole" => (
            rec.s("id")
                .zip(tenant.clone())
                .map(|(r, t)| format!("{r}@{t}")),
            at_tenant(rec.s("displayname")),
        ),
        "AZTenant" => {
            // Other tenants appear as trusts (collected false): not objects.
            if !rec.b("collected") {
                return;
            }
            let Some(t) = tenant.clone() else {
                run.stats.invalid += 1;
                return;
            };
            tenants.collected.insert(t.clone());
            // BloodHound CE names a tenant by its display name; the default
            // domain reads better on screen and stays the shown name.
            bh_name = upper(rec.s("displayname")).filter(|n| !n.is_empty());
            (
                Some(t),
                upper(rec.s("defaultdomain")).or_else(|| upper(rec.s("displayname"))),
            )
        }
        "AZRoleAssignment" => {
            if let Some(t) = &tenant {
                tenants.assignments.insert(t.clone());
            }
            return;
        }
        // Edge records (read in the second pass), and kinds this slice
        // doesn't model (Azure resources, Key Vaults, ...).
        _ => return,
    };
    run.stats.nodes += 1;
    if run.stats.nodes > limits.max_nodes {
        run.cap("nodes");
        return;
    }
    let (Some(raw_id), Some(_)) = (id, tenant.as_ref()) else {
        run.stats.invalid += 1;
        return;
    };
    let id = normalize_id(&raw_id);
    if id.is_empty() || id.len() > MAX_ID_BYTES {
        run.stats.invalid += 1;
        return;
    }
    let ext_kind = kinds::intern(&kind);
    if let Some(ix) = g.lookup(&id) {
        // The same object in two files of the tenant is fine; anything
        // else (an AD object, another source's object) is a clash.
        if !(ours(g, ix, src) && g.node(ix).kind == NodeKind::External(ext_kind)) {
            run.stats.clashes += 1;
        }
        return;
    }
    let mut props: Vec<(String, Value)> = rec
        .fields
        .iter()
        .filter(|(k, _)| KEEP.contains(k))
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    if let Some(n) = bh_name {
        props.retain(|(k, _)| k != "name");
        props.push(("name".to_string(), Value::String(n)));
    }
    if let Some(t) = &tenant {
        // Upper-cased like every ID, so it matches the tenant object.
        props.retain(|(k, _)| k != "tenantid");
        props.push(("tenantid".to_string(), Value::String(t.clone())));
    }
    run.kept_bytes += props
        .iter()
        .map(|(k, v)| (k.len() + v.to_string().len() + 32) as u64)
        .sum::<u64>();
    if run.kept_bytes > limits.max_kept_bytes.saturating_mul(KEPT_FACTOR) {
        props.clear();
        run.cap("kept properties");
    }
    let mut node = Node::placeholder(id.clone(), NodeKind::External(ext_kind));
    node.placeholder = false;
    node.domain = None;
    node.domain_sid = None;
    let name = name.filter(|n| !n.is_empty());
    let named = name.is_some() && bh_named;
    node.name = name.unwrap_or_else(|| id.clone());
    node.ext = Some(Box::new(ExtNode {
        sources: vec![src],
        kinds: Vec::new(),
        props,
        og_created: true,
        named,
    }));
    g.upsert(node);
    run.stats.created += 1;
}

fn apply_edges(g: &mut AdGraph, src: SourceId, rec: Record, run: &mut Run, limits: OgLimits) {
    let Some(kind) = rec.kind.as_deref() else {
        return;
    };
    let tenant = tenant_of(&rec);
    let id_of = |s: Option<String>| s.map(|v| normalize_id(&v));
    // (from, to, kind)
    let mut edges: Vec<(String, String, &'static str)> = Vec::new();
    match kind {
        "AZGroupMember" | "AZGroupOwner" | "AZServicePrincipalOwner" | "AZAppOwner" => {
            let target = match kind {
                "AZServicePrincipalOwner" => rec.s("serviceprincipalid"),
                // The top-level appId is the application's appId (the inner
                // ones are its object ID).
                "AZAppOwner" => rec.s("appid"),
                _ => rec.s("groupid"),
            };
            let Some(target) = id_of(target) else {
                run.stats.invalid += 1;
                return;
            };
            let edge = if kind == "AZGroupMember" {
                "AZMemberOf"
            } else {
                "AZOwns"
            };
            for it in &rec.items {
                match &it.id {
                    Some(m) => edges.push((normalize_id(m), target.clone(), edge)),
                    None => run.stats.invalid += 1,
                }
            }
        }
        "AZRoleAssignment" => {
            let Some(t) = tenant.clone() else {
                run.stats.invalid += 1;
                return;
            };
            let top_role = rec.s("roledefinitionid");
            for it in &rec.items {
                let (Some(p), Some(role)) = (&it.principal, it.role.clone().or(top_role.clone()))
                else {
                    run.stats.invalid += 1;
                    continue;
                };
                if !role_edge(&mut edges, p, &role, it.scope.as_deref(), &t, false) {
                    run.stats.scoped_roles += 1;
                }
            }
        }
        // A Microsoft Graph application permission granted to a service
        // principal: stated as BloodHound CE ingests it, from the service
        // principal to Microsoft Graph's (context only); what it allows is
        // derived in `crate::entra`. Other APIs' app roles, and app roles
        // granted to users or groups, give no directory rights.
        "AZAppRoleAssignment" => {
            let graph_api = rec
                .s("appid")
                .is_some_and(|a| a.eq_ignore_ascii_case(entra::MS_GRAPH_APP_ID));
            let to_sp = rec
                .s("principaltype")
                .is_some_and(|t| t.eq_ignore_ascii_case("ServicePrincipal"));
            if !(graph_api && to_sp) {
                return;
            }
            let Some(perm) = rec.s("approleid").and_then(|r| entra::graph_permission(&r)) else {
                return;
            };
            let (Some(p), Some(res)) = (id_of(rec.s("principalid")), id_of(rec.s("resourceid")))
            else {
                run.stats.invalid += 1;
                return;
            };
            edges.push((p, res, perm.stated));
        }
        // A federated identity credential: tokens an external issuer gives
        // a subject sign in as the application. The issuer and subject are
        // one object, whichever applications trust them.
        "AZFederatedIdentityCredential" => {
            let Some(t) = tenant.clone() else {
                run.stats.invalid += 1;
                return;
            };
            let top_app = rec.s("appid");
            for it in &rec.items {
                let (Some(issuer), Some(subject), Some(app)) = (
                    it.issuer.as_deref(),
                    it.subject.as_deref(),
                    it.app.clone().or(top_app.clone()),
                ) else {
                    run.stats.invalid += 1;
                    continue;
                };
                if let Some(ix) = external_identity(g, src, issuer, subject, &t, run, limits) {
                    edges.push((
                        g.node(ix).id.clone(),
                        normalize_id(&app),
                        "AZAuthenticatesTo",
                    ));
                }
                if run.halted {
                    return;
                }
            }
        }
        "AZRoleEligibilityScheduleInstance" => {
            let (Some(t), Some(p), Some(role)) = (
                tenant.clone(),
                rec.s("principalid"),
                rec.s("roledefinitionid"),
            ) else {
                run.stats.invalid += 1;
                return;
            };
            let scope = rec.s("directoryscopeid");
            if !role_edge(&mut edges, &p, &role, scope.as_deref(), &t, true) {
                run.stats.scoped_roles += 1;
            }
        }
        "AZServicePrincipal" => {
            // The application signs in as its service principal, when the
            // application is registered in a collected tenant.
            if let (Some(app), Some(sp)) = (id_of(rec.s("appid")), id_of(rec.s("id"))) {
                if g.lookup(&app)
                    .is_some_and(|ix| entra::az_kind(g.node(ix)) == Some("AZApp"))
                {
                    edges.push((app, sp, "AZRunsAs"));
                }
            }
        }
        _ => return,
    }
    for (from, to, kind) in edges {
        run.edges_read += 1;
        if run.edges_read > limits.max_edges {
            run.cap("edges");
            return;
        }
        let ends = (g.lookup(&from), g.lookup(&to));
        let (Some(a), Some(b)) = ends else {
            run.stats.unresolved += 1;
            continue;
        };
        if !ours(g, a, src) || !ours(g, b, src) {
            run.stats.unresolved += 1;
            continue;
        }
        // The edge belongs to the tenant of its record, or of its target.
        let unit = tenant
            .clone()
            .or_else(|| entra::tenant_of(g.node(b)))
            .unwrap_or_else(|| "UNKNOWN TENANT".to_string());
        if g.add_og_edge(
            a,
            b,
            EdgeKind::External(kinds::intern(kind)),
            EdgeOrigin {
                source: src,
                unit: Some(unit),
            },
        ) {
            run.stats.edges += 1;
        }
    }
}

/// The edge a role assignment (or eligibility) states. Tenant-wide ones
/// target the role object; an Application Administrator or Cloud
/// Application Administrator assignment scoped to one application targets
/// the application. Every other scoped one (an administrative unit, one
/// object) gives no edge, so it is never taken for tenant-wide: AzureHound
/// doesn't collect administrative units' members, so what it reaches is
/// unknown. Returns false for those (counted as not modeled).
fn role_edge(
    edges: &mut Vec<(String, String, &'static str)>,
    principal: &str,
    role: &str,
    scope: Option<&str>,
    tenant: &str,
    eligible: bool,
) -> bool {
    let template = role.trim().to_ascii_lowercase();
    match scope.map(str::trim) {
        None | Some("") | Some("/") => {
            edges.push((
                normalize_id(principal),
                normalize_id(&format!("{role}@{tenant}")),
                if eligible {
                    "AZRoleEligible"
                } else {
                    "AZHasRole"
                },
            ));
            true
        }
        Some(s) if !eligible => {
            let kind = match template.as_str() {
                entra::APPLICATION_ADMIN => "AZAppAdmin",
                entra::CLOUD_APPLICATION_ADMIN => "AZCloudAppAdmin",
                _ => return false,
            };
            let app = s.trim_start_matches('/');
            if app.is_empty() || app.contains('/') {
                return false;
            }
            edges.push((normalize_id(principal), normalize_id(app), kind));
            true
        }
        Some(_) => false,
    }
}

/// The object for an external identity a federated identity credential
/// trusts: one per issuer and subject (a GitHub repository and branch, a
/// Kubernetes service account, another tenant's managed identity). Its ID
/// can't be an Entra or AD ID: `FIC|<issuer>|<subject>`.
fn external_identity(
    g: &mut AdGraph,
    src: SourceId,
    issuer: &str,
    subject: &str,
    tenant: &str,
    run: &mut Run,
    limits: OgLimits,
) -> Option<petgraph::graph::NodeIndex> {
    let id = normalize_id(&format!("FIC|{issuer}|{subject}"));
    if id.len() > MAX_ID_BYTES {
        run.stats.invalid += 1;
        return None;
    }
    let kind = kinds::intern(entra::EXTERNAL_IDENTITY);
    if let Some(ix) = g.lookup(&id) {
        if ours(g, ix, src) && g.node(ix).kind == NodeKind::External(kind) {
            return Some(ix);
        }
        run.stats.clashes += 1;
        return None;
    }
    run.stats.nodes += 1;
    if run.stats.nodes > limits.max_nodes {
        run.cap("nodes");
        return None;
    }
    let cut = |s: &str| sanitize(Value::String(s.to_string())).unwrap_or(Value::Null);
    let mut props = vec![
        ("issuer".to_string(), cut(issuer)),
        ("subject".to_string(), cut(subject)),
        ("tenantid".to_string(), Value::String(tenant.to_string())),
    ];
    run.kept_bytes += props
        .iter()
        .map(|(k, v)| (k.len() + v.to_string().len() + 32) as u64)
        .sum::<u64>();
    if run.kept_bytes > limits.max_kept_bytes.saturating_mul(KEPT_FACTOR) {
        props.clear();
        run.cap("kept properties");
    }
    let mut node = Node::placeholder(id, NodeKind::External(kind));
    node.placeholder = false;
    node.domain = None;
    node.domain_sid = None;
    node.name = entra::external_identity_name(issuer, subject);
    node.ext = Some(Box::new(ExtNode {
        sources: vec![src],
        kinds: Vec::new(),
        props,
        og_created: true,
        // BloodHound CE has one object per credential, named after it:
        // Cypher answers no name for this one.
        named: false,
    }));
    let ix = g.upsert(node);
    run.stats.created += 1;
    Some(ix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records(text: &str, mode: Mode) -> Vec<Record> {
        let mut out = Vec::new();
        let mut sink = |r: Record| {
            out.push(r);
            true
        };
        let (r, _, _) = parse(&mut text.as_bytes(), mode, 1 << 20, &mut sink);
        r.unwrap();
        out
    }

    #[test]
    fn reads_records_in_either_key_order() {
        let text = r##"{"data":[
            {"kind":"AZUser","data":{"id":"u1","userPrincipalName":"a@x","tenantId":"T","passwordProfile":"x"}},
            {"data":{"id":"g1","displayName":"G"},"kind":"AZGroup"},
            {"kind":"AZGroupMember","data":{"groupId":"g1","members":[{"groupId":"g1","member":{"@odata.type":"#microsoft.graph.user","id":"u1"}}]}}
          ],"meta":{"type":"azure","version":5,"count":3}}"##;
        let n = records(text, Mode::Nodes);
        assert_eq!(n.len(), 3);
        assert_eq!(n[0].s("userprincipalname").as_deref(), Some("a@x"));
        assert_eq!(n[1].kind.as_deref(), Some("AZGroup"));
        assert!(n[2].items.is_empty(), "lists are skipped in the node pass");
        let e = records(text, Mode::Edges);
        assert_eq!(e[2].items[0].id.as_deref(), Some("u1"));
    }

    #[test]
    fn a_large_member_list_is_charged_per_member() {
        let members: Vec<String> = (0..5000)
            .map(|i| {
                format!(
                    r#"{{"groupId":"g","member":{{"id":"m{i}","displayName":"{}"}}}}"#,
                    "x".repeat(200)
                )
            })
            .collect();
        let text = format!(
            r#"{{"data":[{{"kind":"AZGroupMember","data":{{"groupId":"g","members":[{}]}}}}]}}"#,
            members.join(",")
        );
        // The list is over 1 MiB, four times the limit; each member is far below.
        let mut got = Vec::new();
        let mut sink = |r: Record| {
            got.push(r);
            true
        };
        let (r, _, oversized) = parse(&mut text.as_bytes(), Mode::Edges, 256 << 10, &mut sink);
        r.unwrap();
        assert_eq!(oversized, 0);
        assert_eq!(got[0].items.len(), 5000);
    }

    /// The objects pass skips a member list past the hard limit element by
    /// element too, and goes on to the records after it (a tenant's
    /// all-staff groups once stopped it, losing the devices after them).
    #[test]
    fn the_objects_pass_skips_a_large_member_list_and_reads_on() {
        let members: Vec<String> = (0..5000)
            .map(|i| {
                format!(
                    r#"{{"groupId":"g","member":{{"id":"m{i}","displayName":"{}"}}}}"#,
                    "x".repeat(200)
                )
            })
            .collect();
        let text = format!(
            r#"{{"data":[{{"kind":"AZGroupMember","data":{{"groupId":"g","members":[{}]}}}},{{"kind":"AZDevice","data":{{"id":"d1","displayName":"D"}}}}]}}"#,
            members.join(",")
        );
        // Past twice the 256 KiB limit, where a record fails.
        assert!(text.len() > 2 * (256 << 10));
        let mut got = Vec::new();
        let mut sink = |r: Record| {
            got.push(r);
            true
        };
        let (r, _, oversized) = parse(&mut text.as_bytes(), Mode::Nodes, 256 << 10, &mut sink);
        assert_eq!(r, Ok(true));
        assert_eq!(oversized, 0);
        assert_eq!(got.len(), 2);
        assert!(got[0].items.is_empty());
        assert_eq!(got[1].kind.as_deref(), Some("AZDevice"));
    }

    /// A record over its budget before its member list stays oversized:
    /// the list's own budget doesn't clear it, and over budget after the
    /// list too, the mark doesn't pass to the next record.
    #[test]
    fn a_record_over_budget_before_its_list_stays_oversized() {
        let text = format!(
            r#"{{"data":[{{"kind":"AZGroupMember","data":{{"note":"{x}","groupId":"g","members":[{{"groupId":"g","member":{{"id":"m"}}}}],"tail":"{x}"}}}},{{"kind":"AZDevice","data":{{"id":"d1"}}}}]}}"#,
            x = "x".repeat(400 << 10)
        );
        for mode in [Mode::Nodes, Mode::Edges] {
            let mut got = Vec::new();
            let mut sink = |r: Record| {
                got.push(r);
                true
            };
            let (r, _, oversized) = parse(&mut text.as_bytes(), mode, 256 << 10, &mut sink);
            assert_eq!(r, Ok(true), "{mode:?}");
            assert_eq!(oversized, 1, "{mode:?}");
            assert_eq!(got.len(), 1, "{mode:?}");
            assert_eq!(got[0].kind.as_deref(), Some("AZDevice"));
        }
    }

    /// Only tenant-wide and application-scoped assignments give an edge.
    #[test]
    fn scoped_role_assignments_are_never_tenant_wide() {
        let ga = entra::GLOBAL_ADMIN;
        for (scope, eligible) in [
            (
                "/administrativeUnits/cccccccc-0000-0000-0000-000000000001",
                false,
            ),
            (
                "/administrativeUnits/cccccccc-0000-0000-0000-000000000001",
                true,
            ),
            ("/bbbbbbbb-0000-0000-0000-000000000001", false),
        ] {
            let mut edges = Vec::new();
            assert!(!role_edge(&mut edges, "p", ga, Some(scope), "T", eligible));
            assert!(edges.is_empty(), "{scope}");
        }
        let mut edges = Vec::new();
        assert!(role_edge(&mut edges, "p", ga, Some("/"), "T", false));
        assert!(role_edge(
            &mut edges,
            "p",
            entra::APPLICATION_ADMIN,
            Some("/app1"),
            "T",
            false
        ));
        assert_eq!(edges[1].2, "AZAppAdmin");
    }

    #[test]
    fn reads_federated_credentials_and_app_role_assignments() {
        let text = r##"{"data":[
            {"kind":"AZFederatedIdentityCredential","data":{"appId":"A1","tenantId":"T","fics":[
                {"appId":"A1","fic":{"id":"F1","issuer":"https://issuer.example","subject":"repo:contoso/x:ref:refs/heads/main","audiences":["api://AzureADTokenExchange"]}}]}},
            {"kind":"AZAppRoleAssignment","data":{"appRoleId":"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8","principalId":"S1","principalType":"ServicePrincipal","resourceId":"G1","appId":"00000003-0000-0000-c000-000000000000","tenantId":"T"}}
          ]}"##;
        let e = records(text, Mode::Edges);
        let fic = &e[0].items[0];
        assert_eq!(fic.issuer.as_deref(), Some("https://issuer.example"));
        assert_eq!(
            fic.subject.as_deref(),
            Some("repo:contoso/x:ref:refs/heads/main")
        );
        assert_eq!(fic.app.as_deref(), Some("A1"));
        assert_eq!(e[1].s("resourceid").as_deref(), Some("G1"));
        assert_eq!(
            entra::graph_permission(&e[1].s("approleid").unwrap()).map(|p| p.name),
            Some("RoleManagement.ReadWrite.Directory")
        );
    }

    #[test]
    fn coverage_needs_tenant_users_and_assignments() {
        let mut t = Tenants::default();
        for id in ["A", "B"] {
            t.seen.insert(id.into());
            t.users.insert(id.into());
        }
        t.collected.insert("A".into());
        t.assignments.insert("A".into());
        let c = coverage(&t, true);
        assert_eq!(c.ok, ["A"]);
        assert_eq!(c.failed, ["B"]);
        assert_eq!(c.state, CoverageState::Collector);
    }
}
