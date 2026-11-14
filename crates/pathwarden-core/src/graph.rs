use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::{DiGraph, EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use crate::model::{EdgeKind, Node, NodeKind, PropBag, PropStrings, PropValue, SourceId};
use crate::opengraph::{EdgeOrigin, EdgeSem, KindTable};
use crate::sysvol::{FileGrant, SysvolDomain};

pub fn normalize_id(id: &str) -> String {
    normalized(id).into_owned()
}

/// [`normalize_id`] without allocating when the id is already normal, which
/// collector ids nearly always are (this runs for every edge at ingest).
fn normalized(id: &str) -> Cow<'_, str> {
    let t = id.trim();
    if t.bytes().any(|b| b.is_ascii_lowercase()) {
        Cow::Owned(t.to_ascii_uppercase())
    } else {
        Cow::Borrowed(t)
    }
}

/// The in-memory directory graph. Nodes are keyed by ObjectIdentifier and edges
/// are de-duplicated on (source, target, kind).
#[derive(Default)]
pub struct AdGraph {
    g: DiGraph<Node, EdgeKind>,
    index: foldhash::HashMap<String, NodeIndex>,
    /// Every edge, for [`Self::add_edge`]'s check. Built when next needed
    /// after [`Self::add_distinct_edges`] (`edge_set_pending`).
    edge_set: foldhash::HashSet<(NodeIndex, NodeIndex, EdgeKind)>,
    edge_set_pending: bool,
    /// ACE edges granted only through inheritance from a parent container.
    inherited: HashSet<(NodeIndex, NodeIndex, EdgeKind)>,
    esc: Vec<crate::adcs::EscInstance>,
    /// What OpenGraph files added: the kind table from the mapping packs,
    /// source names, and where each external edge came from.
    og: OgData,
    /// SYSVOL and NETLOGON data (see [`crate::sysvol`]).
    sysvol: SysvolData,
    /// Local rights set by Group Policy: the OUs and domains whose linked
    /// GPOs grant each `AdminTo`, `CanRDP`, `ExecuteDCOM` or `CanPSRemote`.
    gpo_local: HashMap<(NodeIndex, NodeIndex, EdgeKind), Vec<NodeIndex>>,
    /// Which settings of a GPO put a member in a local group, by (GPO,
    /// member, right). Built-in collector only.
    gpo_set: HashMap<(NodeIndex, NodeIndex, EdgeKind), Vec<crate::sysvol::GpoSetting>>,
    /// GPOs whose record in `gpo_set` is not whole.
    gpo_set_incomplete: HashSet<NodeIndex>,
    /// Tier Zero settings files applied to domain controllers (see
    /// [`crate::dcsettings`]).
    dc_settings: Vec<crate::dcsettings::DcSettingsFile>,
    /// Each OU's and domain's GPO links, in the collector's order, with
    /// whether each is enforced: for which GPO wins on a computer
    /// ([`crate::sysvol::policy`]).
    gp_links: HashMap<NodeIndex, Vec<(NodeIndex, bool)>>,
    /// OUs that block inheritance.
    blocks_inheritance: HashSet<NodeIndex>,
    /// Tier Zero settings files applied to Enterprise CAs.
    ca_settings: Vec<crate::dcsettings::CaSettingsFile>,
    /// The management agents the settings files read on hosts (see
    /// [`crate::hostprobe`]).
    host_probes: Vec<crate::hostprobe::HostProbe>,
    /// What the stored credentials sidecars added (see [`crate::storedcreds`]).
    stored: StoredData,
    /// The keys of the property names kept in nodes' [`PropBag`]s.
    prop_keys: HashMap<Box<str>, u16>,
    dropped_prop_keys: usize,
    /// The property strings many nodes share.
    prop_strings: PropStrings,
    /// See [`Self::keep_all_properties`].
    props_kept: bool,
}

/// What the SYSVOL sidecars added. Empty without them.
#[derive(Default)]
struct SysvolData {
    /// Where each `WriteGPOFiles` / `WriteLogonScript` right was found.
    grants: HashMap<(NodeIndex, NodeIndex, EdgeKind), Vec<FileGrant>>,
    domains: Vec<SysvolDomain>,
}

/// What the stored credentials sidecars added. Empty without them.
#[derive(Default)]
struct StoredData {
    /// What stores each `HasStoredCredential` edge's credential.
    via: HashMap<(NodeIndex, NodeIndex), Vec<crate::storedcreds::StoredVia>>,
    domains: Vec<crate::storedcreds::StoredDomain>,
    netbios: crate::storedcreds::NetbiosMap,
}

/// OpenGraph state of an analysis graph. Empty without OpenGraph files.
#[derive(Default)]
struct OgData {
    table: KindTable,
    sources: Vec<String>,
    origin: HashMap<(NodeIndex, NodeIndex, EdgeKind), EdgeOrigin>,
}

impl AdGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty graph with room for `nodes` objects and `edges` edges, for
    /// building a large one in one go ([`crate::object_index`]).
    pub fn with_capacity(nodes: usize, edges: usize) -> Self {
        AdGraph {
            g: DiGraph::with_capacity(nodes, edges),
            index: HashMap::with_capacity_and_hasher(nodes, Default::default()),
            ..Self::default()
        }
    }

    pub fn inner(&self) -> &DiGraph<Node, EdgeKind> {
        &self.g
    }

    /// Marks this graph as keeping every collector property
    /// ([`crate::LoadOptions::all_properties`]): Cypher then answers every
    /// property from the nodes' [`PropBag`]s, as the collector wrote it.
    pub fn keep_all_properties(&mut self) {
        self.props_kept = true;
    }

    /// Whether the nodes keep every collector property
    /// ([`Self::keep_all_properties`]).
    pub fn props_kept(&self) -> bool {
        self.props_kept
    }

    /// A [`PropBag`] of the collector properties in `m`, skipping nulls and
    /// objects. Keys are interned here; past `u16::MAX` distinct names the
    /// rest are dropped and counted ([`Self::dropped_prop_keys`]).
    pub fn prop_bag(&mut self, m: &serde_json::Map<String, serde_json::Value>) -> PropBag {
        let mut entries = Vec::with_capacity(m.len());
        for (k, v) in m {
            let key = match self.prop_keys.get(k.as_str()) {
                Some(&id) => id,
                None => match u16::try_from(self.prop_keys.len()) {
                    Ok(id) => {
                        self.prop_keys.insert(k.as_str().into(), id);
                        id
                    }
                    Err(_) => {
                        self.dropped_prop_keys += 1;
                        continue;
                    }
                },
            };
            entries.push((key, v));
        }
        PropBag::encode(entries, &mut self.prop_strings)
    }

    /// The key a property name has in this graph's [`PropBag`]s, or `None`
    /// when no node kept it.
    pub fn prop_key(&self, name: &str) -> Option<u16> {
        self.prop_keys.get(name).copied()
    }

    /// Properties not kept because the graph already had `u16::MAX`
    /// distinct property names (hostile or broken input).
    pub fn dropped_prop_keys(&self) -> usize {
        self.dropped_prop_keys
    }

    /// A kept collector property of a node ([`Self::prop_bag`]).
    pub fn extra_prop(&self, ix: NodeIndex, name: &str) -> Option<PropValue> {
        self.g[ix]
            .props
            .extra
            .get(self.prop_key(name)?, &self.prop_strings)
    }

    pub fn node_count(&self) -> usize {
        self.g.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.g.edge_count()
    }

    pub fn node(&self, ix: NodeIndex) -> &Node {
        &self.g[ix]
    }

    pub fn node_mut(&mut self, ix: NodeIndex) -> &mut Node {
        &mut self.g[ix]
    }

    pub fn nodes(&self) -> impl Iterator<Item = (NodeIndex, &Node)> {
        self.g.node_indices().map(move |ix| (ix, &self.g[ix]))
    }

    pub fn lookup(&self, id: &str) -> Option<NodeIndex> {
        self.index.get(normalized(id).as_ref()).copied()
    }

    /// Returns the node for `id`, creating a placeholder if it has not been seen.
    pub fn ensure(&mut self, id: &str, hint: NodeKind) -> NodeIndex {
        let id = normalized(id);
        if let Some(&ix) = self.index.get(id.as_ref()) {
            let n = &mut self.g[ix];
            if n.placeholder && n.kind == NodeKind::Base && hint != NodeKind::Base {
                n.kind = hint;
            }
            return ix;
        }
        let id = id.into_owned();
        let ix = self.g.add_node(Node::placeholder(id.clone(), hint));
        self.index.insert(id, ix);
        ix
    }

    /// Inserts a collected object, replacing a placeholder if one exists. When the
    /// same object appears twice (overlapping collections) the first copy wins.
    pub fn upsert(&mut self, node: Node) -> NodeIndex {
        if let Some(&ix) = self.index.get(&node.id) {
            if self.g[ix].placeholder {
                self.g[ix] = node;
            }
            return ix;
        }
        let id = node.id.clone();
        let ix = self.g.add_node(node);
        self.index.insert(id, ix);
        ix
    }

    /// Like [`upsert`](Self::upsert), but when the object was already
    /// collected the two records are merged: values the first one lacks are
    /// taken from `node`, and values it has are kept. The same object can
    /// appear in several collections (each domain's collection writes a stub
    /// for the forest's built-in groups), and a partial record must not
    /// hide what a fuller one says.
    pub fn upsert_merged(&mut self, node: Node) -> NodeIndex {
        let Some(&ix) = self.index.get(&node.id) else {
            return self.upsert(node);
        };
        let n = &mut self.g[ix];
        if n.placeholder {
            *n = node;
            return ix;
        }
        if n.props.name.is_none() && node.props.name.is_some() {
            n.name = node.name;
        }
        if n.domain.is_none() {
            n.domain = node.domain;
        }
        if n.domain_sid.is_none() {
            n.domain_sid = node.domain_sid;
        }
        n.is_dc |= node.is_dc;
        if n.adcs.is_none() {
            n.adcs = node.adcs;
        }
        n.props.fill_missing(node.props);
        ix
    }

    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, kind: EdgeKind) -> bool {
        // Self-edges (e.g. the SELF ACE) never extend an attack path.
        if from == to || !self.edge_set().insert((from, to, kind)) {
            return false;
        }
        self.g.add_edge(from, to, kind);
        true
    }

    /// Adds edges known to be distinct, none from an object to itself,
    /// without [`Self::add_edge`]'s check on each: for building a large
    /// graph from the edges of one ([`crate::object_index`]).
    pub fn add_distinct_edges(
        &mut self,
        edges: impl IntoIterator<Item = (NodeIndex, NodeIndex, EdgeKind)>,
    ) {
        for (from, to, kind) in edges {
            debug_assert_ne!(from, to);
            self.g.add_edge(from, to, kind);
        }
        self.edge_set_pending = true;
    }

    fn edge_set(&mut self) -> &mut foldhash::HashSet<(NodeIndex, NodeIndex, EdgeKind)> {
        if self.edge_set_pending {
            self.edge_set_pending = false;
            self.edge_set = self
                .g
                .edge_references()
                .map(|e| (e.source(), e.target(), *e.weight()))
                .collect();
        }
        &mut self.edge_set
    }

    /// Adds an edge that comes from an ACE. If the same right is granted both
    /// explicitly and through inheritance, the explicit grant is what needs fixing.
    pub fn add_ace_edge(
        &mut self,
        from: NodeIndex,
        to: NodeIndex,
        kind: EdgeKind,
        inherited: bool,
    ) {
        let added = self.add_edge(from, to, kind);
        if !inherited {
            self.inherited.remove(&(from, to, kind));
        } else if added {
            self.inherited.insert((from, to, kind));
        }
    }

    /// AD CS abuse found during post-processing.
    pub fn esc_instances(&self) -> &[crate::adcs::EscInstance] {
        &self.esc
    }

    pub(crate) fn set_esc_instances(&mut self, esc: Vec<crate::adcs::EscInstance>) {
        self.esc = esc;
    }

    /// Whether an attacker moves along an edge of `kind` into `target`.
    /// Remote logon rights on a domain controller (RDP, PowerShell remoting,
    /// DCOM) give a non-admin session there, not control of the domain: turning
    /// that into domain compromise needs a local privilege escalation, which is
    /// not something the directory shows. They are reported as hygiene (PW-023)
    /// instead of as paths, so they don't dominate the plan.
    pub fn traversable(&self, kind: EdgeKind, target: NodeIndex) -> bool {
        match kind {
            EdgeKind::External(k) => self.og.table.edge(k).is_some_and(|s| s.traversable),
            _ => kind.is_traversable() && !(kind.is_remote_logon() && self.g[target].is_dc),
        }
    }

    /// The mapping-pack semantics of an external edge kind, if a pack in
    /// effect describes it.
    pub fn edge_sem(&self, kind: EdgeKind) -> Option<&EdgeSem> {
        match kind {
            EdgeKind::External(k) => self.og.table.edge(k),
            _ => None,
        }
    }

    /// The kind table from the mapping packs in effect.
    pub fn kind_table(&self) -> &KindTable {
        &self.og.table
    }

    pub(crate) fn set_kind_table(&mut self, table: KindTable) {
        self.og.table = table;
    }

    /// Names of the OpenGraph sources read, indexed by [`SourceId`].
    pub fn og_sources(&self) -> &[String] {
        &self.og.sources
    }

    pub(crate) fn set_og_sources(&mut self, names: Vec<String>) {
        self.og.sources = names;
    }

    /// The source ID of `name`, adding it to the list when it is new. For
    /// data sources other than OpenGraph files (the SYSVOL sidecar), added
    /// after those.
    pub(crate) fn add_og_source(&mut self, name: &str) -> SourceId {
        if let Some(i) = self.og.sources.iter().position(|s| s == name) {
            return i as SourceId;
        }
        self.og.sources.push(name.to_string());
        (self.og.sources.len() - 1) as SourceId
    }

    /// Where the file permissions behind a `WriteGPOFiles` or
    /// `WriteLogonScript` edge were found.
    pub fn file_grants(&self, e: EdgeIndex) -> &[FileGrant] {
        if self.sysvol.grants.is_empty() {
            return &[];
        }
        self.g
            .edge_endpoints(e)
            .and_then(|(a, b)| self.sysvol.grants.get(&(a, b, self.g[e])))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn add_file_grants(
        &mut self,
        from: NodeIndex,
        to: NodeIndex,
        kind: EdgeKind,
        grants: Vec<FileGrant>,
    ) {
        let list = self.sysvol.grants.entry((from, to, kind)).or_default();
        for gr in grants {
            if !list.contains(&gr) {
                list.push(gr);
            }
        }
    }

    /// The OUs and domains whose linked GPOs grant this local right. Empty
    /// for rights read from the computer itself.
    pub fn gpo_grants(&self, e: EdgeIndex) -> &[NodeIndex] {
        if self.gpo_local.is_empty() {
            return &[];
        }
        self.g
            .edge_endpoints(e)
            .and_then(|(a, b)| self.gpo_local.get(&(a, b, self.g[e])))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// The domains (upper case) of the computers linked GPOs grant a local
    /// right on, one entry per right granted.
    pub fn gpo_grant_domains(&self) -> impl Iterator<Item = String> + '_ {
        self.gpo_local
            .keys()
            .filter_map(|&(_, to, _)| self.g[to].domain.as_deref())
            .map(str::to_ascii_uppercase)
    }

    pub(crate) fn add_gpo_grant(
        &mut self,
        from: NodeIndex,
        to: NodeIndex,
        kind: EdgeKind,
        container: NodeIndex,
    ) {
        self.add_edge(from, to, kind);
        let list = self.gpo_local.entry((from, to, kind)).or_default();
        if !list.contains(&container) {
            list.push(container);
        }
    }

    /// Whether the built-in collector recorded which GPO settings put
    /// members in local groups.
    pub fn has_gpo_settings(&self) -> bool {
        !self.gpo_set.is_empty()
    }

    /// The settings of `gpo` that put `member` in the local group behind
    /// `kind`. Empty without the built-in collector's record.
    pub fn gpo_settings(
        &self,
        gpo: NodeIndex,
        member: NodeIndex,
        kind: EdgeKind,
    ) -> &[crate::sysvol::GpoSetting] {
        if self.gpo_set.is_empty() {
            return &[];
        }
        self.gpo_set
            .get(&(gpo, member, kind))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Whether `gpo`'s record is not whole (cut or partly unreadable), so
    /// no GPO should be named where it is linked.
    pub fn gpo_record_incomplete(&self, gpo: NodeIndex) -> bool {
        self.gpo_set_incomplete.contains(&gpo)
    }

    pub(crate) fn add_gpo_setting(
        &mut self,
        gpo: NodeIndex,
        member: NodeIndex,
        kind: EdgeKind,
        set: crate::sysvol::GpoSetting,
    ) {
        let list = self.gpo_set.entry((gpo, member, kind)).or_default();
        if !list.contains(&set) {
            list.push(set);
        }
    }

    pub(crate) fn mark_gpo_record_incomplete(&mut self, gpo: NodeIndex) {
        self.gpo_set_incomplete.insert(gpo);
    }

    /// What each domain's SYSVOL sidecar said.
    pub fn sysvol_domains(&self) -> &[SysvolDomain] {
        &self.sysvol.domains
    }

    /// The GPOs linked to an OU or domain, in the collector's order, with
    /// whether each link is enforced.
    pub fn gp_links(&self, container: NodeIndex) -> &[(NodeIndex, bool)] {
        self.gp_links.get(&container).map_or(&[], Vec::as_slice)
    }

    pub(crate) fn set_gp_links(&mut self, container: NodeIndex, links: Vec<(NodeIndex, bool)>) {
        self.gp_links.insert(container, links);
    }

    /// Whether an OU blocks inheritance of the GPOs linked above it.
    pub fn blocks_inheritance(&self, ou: NodeIndex) -> bool {
        self.blocks_inheritance.contains(&ou)
    }

    pub(crate) fn set_blocks_inheritance(&mut self, ou: NodeIndex) {
        self.blocks_inheritance.insert(ou);
    }

    pub(crate) fn sysvol_domains_mut(&mut self) -> &mut [SysvolDomain] {
        &mut self.sysvol.domains
    }

    pub(crate) fn add_sysvol_domain(&mut self, d: SysvolDomain) {
        self.sysvol.domains.push(d);
    }

    /// What stores the credential of a `HasStoredCredential` edge (the
    /// services and scheduled tasks, at most
    /// [`crate::storedcreds::MAX_NAMES_PER_EDGE`]).
    pub fn stored_via(&self, e: EdgeIndex) -> &[crate::storedcreds::StoredVia] {
        if self.stored.via.is_empty() || self.g[e] != EdgeKind::HasStoredCredential {
            return &[];
        }
        self.g
            .edge_endpoints(e)
            .and_then(|ends| self.stored.via.get(&ends))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn add_stored_via(
        &mut self,
        from: NodeIndex,
        to: NodeIndex,
        vias: Vec<crate::storedcreds::StoredVia>,
    ) {
        let list = self.stored.via.entry((from, to)).or_default();
        for v in vias {
            if list.len() < crate::storedcreds::MAX_NAMES_PER_EDGE
                && !list.iter().any(|x| x.via == v.via && x.name == v.name)
            {
                list.push(v);
            }
        }
    }

    /// What each domain's stored credentials sidecar said.
    pub fn stored_domains(&self) -> &[crate::storedcreds::StoredDomain] {
        &self.stored.domains
    }

    pub(crate) fn add_stored_domain(&mut self, d: crate::storedcreds::StoredDomain) {
        self.stored.domains.push(d);
    }

    /// The forest's domains by NetBIOS name, as the collection read them.
    pub fn netbios(&self) -> &crate::storedcreds::NetbiosMap {
        &self.stored.netbios
    }

    pub(crate) fn add_netbios(&mut self, names: &[crate::storedcreds::NetbiosName]) {
        self.stored.netbios.add(names);
    }

    /// The Tier Zero settings files applied to domain controllers.
    pub fn dc_settings_files(&self) -> &[crate::dcsettings::DcSettingsFile] {
        &self.dc_settings
    }

    pub(crate) fn add_dc_settings_file(&mut self, f: crate::dcsettings::DcSettingsFile) {
        self.dc_settings.push(f);
    }

    /// The Tier Zero settings files applied to Enterprise CAs.
    pub fn ca_settings_files(&self) -> &[crate::dcsettings::CaSettingsFile] {
        &self.ca_settings
    }

    pub(crate) fn add_ca_settings_file(&mut self, f: crate::dcsettings::CaSettingsFile) {
        self.ca_settings.push(f);
    }

    /// The management agents settings files read on hosts.
    pub fn host_probes(&self) -> &[crate::hostprobe::HostProbe] {
        &self.host_probes
    }

    pub(crate) fn add_host_probe(&mut self, p: crate::hostprobe::HostProbe) {
        self.host_probes.push(p);
    }

    /// The name of an OpenGraph source.
    pub fn source_name(&self, s: SourceId) -> &str {
        self.og
            .sources
            .get(s as usize)
            .map(String::as_str)
            .unwrap_or("OpenGraph")
    }

    /// Adds an edge read from an OpenGraph file, remembering its source. An
    /// edge AD data already has keeps no OpenGraph origin: the directory's
    /// own record wins.
    pub(crate) fn add_og_edge(
        &mut self,
        from: NodeIndex,
        to: NodeIndex,
        kind: EdgeKind,
        origin: EdgeOrigin,
    ) -> bool {
        if !self.add_edge(from, to, kind) {
            return false;
        }
        self.og.origin.insert((from, to, kind), origin);
        true
    }

    /// Changes the kind of the edge `a -old-> b` that an OpenGraph file
    /// added (a correction makes it context only), keeping its origin.
    /// False when there is no such edge. When `a -kind-> b` exists already
    /// the edge is removed instead (its twin says the same), which moves
    /// another edge's index: callers keep endpoints, not edge indices.
    pub(crate) fn rekind_og_edge(
        &mut self,
        a: NodeIndex,
        b: NodeIndex,
        old: EdgeKind,
        kind: EdgeKind,
    ) -> bool {
        let Some(e) = self.g.edges_connecting(a, b).find(|e| *e.weight() == old) else {
            return false;
        };
        let e = e.id();
        if old == kind {
            return true;
        }
        let Some(origin) = self.og.origin.remove(&(a, b, old)) else {
            return false;
        };
        self.edge_set().remove(&(a, b, old));
        if self.edge_set().insert((a, b, kind)) {
            self.g[e] = kind;
            self.og.origin.insert((a, b, kind), origin);
        } else {
            self.g.remove_edge(e);
        }
        true
    }

    /// Where an edge came from, when an OpenGraph file added it.
    pub fn edge_origin(&self, e: EdgeIndex) -> Option<&EdgeOrigin> {
        if self.og.origin.is_empty() {
            return None;
        }
        let (a, b) = self.g.edge_endpoints(e)?;
        self.og.origin.get(&(a, b, self.g[e]))
    }

    pub(crate) fn edge_origin_mut(&mut self, e: EdgeIndex) -> Option<&mut EdgeOrigin> {
        let (a, b) = self.g.edge_endpoints(e)?;
        let kind = self.g[e];
        self.og.origin.get_mut(&(a, b, kind))
    }

    /// Whether any OpenGraph edge was added.
    pub fn has_og_edges(&self) -> bool {
        !self.og.origin.is_empty()
    }

    /// The source name of an edge an OpenGraph file added.
    pub fn edge_source_name(&self, e: EdgeIndex) -> Option<&str> {
        self.edge_origin(e).map(|o| self.source_name(o.source))
    }

    pub fn is_inherited(&self, e: EdgeIndex) -> bool {
        self.g
            .edge_endpoints(e)
            .is_some_and(|(a, b)| self.inherited.contains(&(a, b, self.g[e])))
    }

    /// The OU, container or domain that directly contains `ix`.
    pub fn parent(&self, ix: NodeIndex) -> Option<NodeIndex> {
        self.g
            .edges_directed(ix, Direction::Incoming)
            .find(|e| *e.weight() == EdgeKind::Contains)
            .map(|e| e.source())
    }

    /// Finds objects by ObjectIdentifier, exact name, or name without the
    /// `@DOMAIN` suffix. Matching is case-insensitive.
    pub fn find(&self, query: &str) -> Vec<NodeIndex> {
        if let Some(ix) = self.lookup(query) {
            return vec![ix];
        }
        let q = query.trim().to_ascii_uppercase();
        let exact: Vec<_> = self
            .nodes()
            .filter(|(_, n)| n.name == q)
            .map(|(ix, _)| ix)
            .collect();
        if !exact.is_empty() || q.contains('@') {
            return exact;
        }
        let prefix = format!("{q}@");
        self.nodes()
            .filter(|(_, n)| n.name == q || n.name.starts_with(&prefix))
            .map(|(ix, _)| ix)
            .collect()
    }

    /// [`AdGraph::find`] for the ends of an attack path: when the name
    /// matches users, computers or groups and also other objects (a
    /// certificate template named like the account that uses it), only
    /// those principals.
    pub fn find_principal(&self, query: &str) -> Vec<NodeIndex> {
        let all = self.find(query);
        let principals: Vec<NodeIndex> = all
            .iter()
            .copied()
            .filter(|&ix| {
                matches!(
                    self.node(ix).kind,
                    NodeKind::User | NodeKind::Computer | NodeKind::Group
                )
            })
            .collect();
        if principals.is_empty() {
            all
        } else {
            principals
        }
    }

    /// All principals that are members of `group`, directly or through nesting.
    pub fn transitive_members(&self, group: NodeIndex) -> Vec<NodeIndex> {
        let mut seen = HashSet::from([group]);
        let mut queue = VecDeque::from([group]);
        let mut out = Vec::new();
        while let Some(v) = queue.pop_front() {
            for e in self.g.edges_directed(v, Direction::Incoming) {
                if *e.weight() == EdgeKind::MemberOf
                    && !self
                        .og
                        .origin
                        .contains_key(&(e.source(), v, EdgeKind::MemberOf))
                    && seen.insert(e.source())
                {
                    out.push(e.source());
                    queue.push_back(e.source());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(g: &mut AdGraph, id: &str, kind: NodeKind, name: &str) -> NodeIndex {
        let mut n = Node::placeholder(id.into(), kind);
        n.placeholder = false;
        n.name = name.into();
        g.upsert(n)
    }

    /// A name shared by an account and a certificate template starts a
    /// path at the account.
    #[test]
    fn paths_start_at_principals() {
        let mut g = AdGraph::new();
        let user = object(
            &mut g,
            "S-1-5-21-1-2-3-1105",
            NodeKind::User,
            "ESC1@CORP.LOCAL",
        );
        object(
            &mut g,
            "0B5B0A3C-0000-4000-8000-000000000001",
            NodeKind::CertTemplate,
            "ESC1@CORP.LOCAL",
        );
        assert_eq!(g.find("esc1").len(), 2);
        assert_eq!(g.find_principal("esc1"), [user]);
        // No principal by that name: whatever matches.
        let ca = object(
            &mut g,
            "0B5B0A3C-0000-4000-8000-000000000002",
            NodeKind::EnterpriseCa,
            "CORP-CA@CORP.LOCAL",
        );
        assert_eq!(g.find_principal("corp-ca"), [ca]);
    }
}
