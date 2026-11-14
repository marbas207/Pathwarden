//! The `GraphView` seam and its implementation over the full [`AdGraph`].
//!
//! THE LOAD-BEARING RULE (design §1.4): the Cypher engine evaluates over the
//! **raw adjacency** — every edge that exists — and never over
//! [`AdGraph::traversable`], which is the attack-path filter that deliberately
//! drops edges (remote logon into a DC, "weak" edges, ...). A Cypher query is a
//! literal graph query; it honours only the relationship types written in the
//! pattern. So the adjacency methods below iterate the underlying petgraph
//! directly, and consult `traversable()` only for the composite types that
//! ask for attack-path edges by name ([`AD_ATTACK_PATHS`],
//! [`AZ_ATTACK_PATHS`]).
//!
//! The trait is the seam that will later also back the UI's persisted
//! `ExploreGraph` (design Phase 2). Both impls expose the same raw adjacency, so
//! the evaluator's results do not depend on which view backs it.

use petgraph::graph::EdgeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction as PgDirection;

use crate::analysis::{self, ReachTree};
use crate::graph::AdGraph;
use crate::model::{EdgeKind, Node, NodeKind, PropValue};
use crate::NodeIndex;

use super::ast::Direction;
use super::value::Value;

/// An opaque handle to a node within a [`GraphView`]. For [`AdGraphView`] it is
/// the petgraph node index.
pub type NodeRef = u32;

/// An opaque handle to one stored relationship. For [`AdGraphView`] it is
/// the petgraph edge index.
pub type EdgeId = u32;

/// BloodHound CE's composite type for "every edge an attack path follows".
pub const AD_ATTACK_PATHS: &str = "AD_ATTACK_PATHS";

/// BloodHound CE's composite type for the Azure (Entra) attack edges.
pub const AZ_ATTACK_PATHS: &str = "AZ_ATTACK_PATHS";

/// The label of objects marked as owned.
pub const TAG_OWNED: &str = "Tag_Owned";

/// What a relationship pattern's types select, resolved against the data.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TypeSel {
    /// Types named one by one.
    pub kinds: Vec<EdgeKind>,
    /// `AD_ATTACK_PATHS`: every edge Pathwarden's attack paths follow
    /// (`pathwarden path`), OpenGraph and AzureHound kinds included.
    pub attack: bool,
    /// `AZ_ATTACK_PATHS`: the AzureHound ones among those.
    pub azure_attack: bool,
}

impl TypeSel {
    /// Whether it selects nothing (every type named is absent).
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty() && !self.attack && !self.azure_attack
    }
}

/// The read-only, raw-adjacency view the Cypher evaluator runs against.
///
/// **Handles are dense:** the evaluator sizes per-node tables by
/// `node_handles().len()` and indexes them by handle, so a view's handles
/// must be exactly `0..node_handles().len()`, and the [`ReachTree`] that
/// [`Self::shortest_tree`] returns is indexed by the same handles.
pub trait GraphView {
    /// Every node handle in the graph.
    fn node_handles(&self) -> Vec<NodeRef>;

    /// The node's ObjectIdentifier, upper-cased (the parity normal form).
    fn objectid(&self, n: NodeRef) -> String;

    /// Whether the node carries `label`. Recognises concrete BHE node labels
    /// (`User`, `Group`, ...), the `Base` superlabel (every native AD node),
    /// the virtual `Tag_Tier_Zero` label (the tier-zero flag) and
    /// `Tag_Owned` (objects marked as owned). See design §1.2.
    fn matches_label(&self, n: NodeRef, label: &str) -> bool;

    /// A BHE node property by its lowercase key, or [`Value::Null`] when the
    /// node does not carry it.
    fn prop(&self, n: NodeRef, key: &str) -> Value;

    /// The name of a relationship type, or `None` if this graph has no such
    /// type. Matched case-sensitively, as Neo4j and BHE do: `memberof` is
    /// not `MemberOf`, and matches nothing.
    fn canonical_rel_type(&self, type_name: &str) -> Option<String>;

    /// The relationship type `type_name` was probably meant as, when it
    /// matches one only ignoring case (`memberof` -> `MemberOf`).
    fn suggest_rel_type(&self, _type_name: &str) -> Option<String> {
        None
    }

    /// The label `label` was probably meant as, when it matches one only
    /// ignoring case (`user` -> `User`).
    fn suggest_label(&self, _label: &str) -> Option<String> {
        None
    }

    /// A note about a label the query uses, like a `Tag_Owned` no object
    /// carries.
    fn label_note(&self, _label: &str) -> Option<String> {
        None
    }

    /// Notes about the data the query ran on, for the result's warnings.
    fn notes(&self) -> Vec<String> {
        Vec::new()
    }

    /// The relationship types a pattern names, resolved (absent ones
    /// dropped).
    fn type_sel(&self, types: &[String]) -> TypeSel;

    /// The stored relationships at `n` that `sel` selects, read from `n` in
    /// `dir`: `Right` takes those running n -> x, `Left` x -> n, `Both`
    /// either. Each comes with the node at its other end, in storage order.
    fn edges(&self, n: NodeRef, dir: Direction, sel: &TypeSel) -> Vec<(EdgeId, NodeRef)>;

    /// The type of a stored relationship.
    fn edge_type(&self, e: EdgeId) -> String {
        self.edge_kind(e).as_str().to_string()
    }

    /// The kind of a stored relationship.
    fn edge_kind(&self, e: EdgeId) -> EdgeKind;

    /// The OpenGraph source that says a relationship exists, if one does.
    fn edge_source(&self, _e: EdgeId) -> Option<String> {
        None
    }

    /// The object's name as Pathwarden shows it, for printing paths.
    fn name(&self, n: NodeRef) -> String;

    /// The object's kind.
    fn kind(&self, n: NodeRef) -> NodeKind;

    /// The (source, target) of a stored relationship.
    fn edge_ends(&self, e: EdgeId) -> (NodeRef, NodeRef);

    /// Breadth-first search toward `root` along relationships `sel`
    /// selects: every node `a` it reaches has a shortest path
    /// `(a)-[dir]-...-(root)`, as the attack-path analysis searches (the same
    /// tree `pathwarden path` walks). Follows at most `max_depth`
    /// relationships, and stops as soon as `visit` (called on each node as it
    /// is reached) says to. A node `stop` names is reached but not passed
    /// through (the root always is).
    fn shortest_tree(
        &self,
        root: NodeRef,
        dir: Direction,
        sel: &TypeSel,
        max_depth: Option<u32>,
        stop: &dyn Fn(NodeRef) -> bool,
        visit: &mut dyn FnMut(NodeRef) -> bool,
    ) -> ReachTree;
}

/// A [`GraphView`] over the full in-memory [`AdGraph`] — complete `Props`, every
/// edge. This is the authoritative, full-fidelity surface used by the CLI.
pub struct AdGraphView<'a> {
    g: &'a AdGraph,
    /// Objects marked as owned, sorted.
    owned: Vec<NodeRef>,
}

impl<'a> AdGraphView<'a> {
    pub fn new(g: &'a AdGraph) -> Self {
        AdGraphView {
            g,
            owned: Vec::new(),
        }
    }

    /// Marks `owned` as owned: they carry `Tag_Owned`, and `owned` in
    /// `system_tags`, as BloodHound CE marks them.
    pub fn with_owned(mut self, owned: impl IntoIterator<Item = NodeIndex>) -> Self {
        self.owned = owned.into_iter().map(|ix| ix.index() as NodeRef).collect();
        self.owned.sort_unstable();
        self.owned.dedup();
        self
    }

    fn ix(n: NodeRef) -> NodeIndex {
        NodeIndex::new(n as usize)
    }

    fn is_owned(&self, n: NodeRef) -> bool {
        self.owned.binary_search(&n).is_ok()
    }

    /// Whether `sel` selects an edge of `kind` into `target`.
    fn selects(&self, sel: &TypeSel, kind: EdgeKind, target: NodeIndex) -> bool {
        if sel.kinds.contains(&kind) {
            return true;
        }
        if !(sel.attack || sel.azure_attack) || !self.g.traversable(kind, target) {
            return false;
        }
        sel.attack
            || self
                .g
                .edge_sem(kind)
                .is_some_and(|s| s.pack == crate::entra::PACK)
    }
}

impl AdGraphView<'_> {
    /// A property as the data has it, secrets included.
    fn stored_prop(&self, n: NodeRef, key: &str) -> Value {
        let node = self.g.node(Self::ix(n));
        if let Some(v) = virtual_prop(node, key, self.is_owned(n)) {
            return v;
        }
        if self.g.props_kept() && !node.props.extra.is_empty() {
            // Everything the collector wrote, as it wrote it (the fields are
            // normalised for analysis); null where it wrote nothing, except
            // a name ingest knows (see `known_name`).
            return match self.g.extra_prop(Self::ix(n), key) {
                Some(v) => from_prop(v),
                None if key == "name" => known_name(node),
                None => Value::Null,
            };
        }
        // A graph loaded for analysis, or an object no collector record
        // described (a trust's target domain, AzureHound and OpenGraph
        // objects): the fields, then what OpenGraph kept.
        match typed_prop(node, key) {
            Some(v) if !v.is_null() => v,
            _ => node
                .ext
                .as_ref()
                .and_then(|e| e.prop(key))
                .map(from_json)
                .unwrap_or(Value::Null),
        }
    }
}

/// What a secret property answers when the object has one.
pub const HIDDEN: &str = "(hidden)";

/// Properties named like secrets that are not: BloodHound's flags and
/// policy values about passwords and LAPS.
const NOT_SECRET: &[&str] = &[
    "pwdlastset",
    "pwdneverexpires",
    "passwordnotreqd",
    "haslaps",
    "minpwdlength",
    "minpwdage",
    "maxpwdage",
    "pwdhistorylength",
    "pwdproperties",
    "encryptedtextpwdallowed",
    "expirepasswordsonsmartcardonlyaccounts",
    "restrictoutboundntlm",
];

/// Whether a property may hold a secret (a password, a LAPS password, a
/// key or hash), by the rule OpenGraph ingest drops them by. Queries see
/// [`HIDDEN`] for it, so the CLI and the app never answer a guess.
pub fn is_secret_prop(key: &str) -> bool {
    crate::opengraph::pack::is_secret_key(key)
        && !NOT_SECRET.iter().any(|k| k.eq_ignore_ascii_case(key))
}

impl GraphView for AdGraphView<'_> {
    fn node_handles(&self) -> Vec<NodeRef> {
        self.g
            .inner()
            .node_indices()
            .map(|ix| ix.index() as NodeRef)
            .collect()
    }

    fn objectid(&self, n: NodeRef) -> String {
        self.g.node(Self::ix(n)).id.clone()
    }

    fn matches_label(&self, n: NodeRef, label: &str) -> bool {
        let node = self.g.node(Self::ix(n));
        match label {
            // Virtual label: the tier-zero flag (design §1.2, Gap 2).
            "Tag_Tier_Zero" => node.tier_zero,
            TAG_OWNED => self.is_owned(n),
            // Superlabel: every native AD node also carries Base (Gap 1).
            "Base" => !node.kind.is_external(),
            // Concrete BHE node label, matched case-sensitively as BHE does.
            other => node.kind.as_str() == other,
        }
    }

    fn prop(&self, n: NodeRef, key: &str) -> Value {
        let v = self.stored_prop(n, key);
        // A secret answers whether it is there, never what it is: WHERE
        // could otherwise guess it a character at a time.
        if is_secret_prop(key) && !v.is_null() {
            return Value::Str(HIDDEN.into());
        }
        v
    }

    fn notes(&self) -> Vec<String> {
        match self.g.dropped_prop_keys() {
            0 => Vec::new(),
            n => vec![format!(
                "{n} property values were not kept: the data has more than {} distinct property names",
                u32::from(u16::MAX) + 1
            )],
        }
    }

    fn label_note(&self, label: &str) -> Option<String> {
        owned_note(label, self.owned.is_empty())
    }

    fn canonical_rel_type(&self, type_name: &str) -> Option<String> {
        canonical_rel_type(type_name)
    }

    fn suggest_rel_type(&self, type_name: &str) -> Option<String> {
        suggest_rel_type(type_name)
    }

    fn suggest_label(&self, label: &str) -> Option<String> {
        suggest_label(label)
    }

    fn type_sel(&self, types: &[String]) -> TypeSel {
        type_sel(types)
    }

    fn edge_kind(&self, e: EdgeId) -> EdgeKind {
        self.g.inner()[EdgeIndex::new(e as usize)]
    }

    fn edge_source(&self, e: EdgeId) -> Option<String> {
        self.g
            .edge_source_name(EdgeIndex::new(e as usize))
            .map(str::to_owned)
    }

    fn name(&self, n: NodeRef) -> String {
        self.g.node(Self::ix(n)).name.clone()
    }

    fn kind(&self, n: NodeRef) -> NodeKind {
        self.g.node(Self::ix(n)).kind
    }

    fn edges(&self, n: NodeRef, dir: Direction, sel: &TypeSel) -> Vec<(EdgeId, NodeRef)> {
        let ix = Self::ix(n);
        let mut out = Vec::new();
        if matches!(dir, Direction::Right | Direction::Both) {
            for e in self.g.inner().edges_directed(ix, PgDirection::Outgoing) {
                if self.selects(sel, *e.weight(), e.target()) {
                    out.push((e.id().index() as EdgeId, e.target().index() as NodeRef));
                }
            }
        }
        if matches!(dir, Direction::Left | Direction::Both) {
            for e in self.g.inner().edges_directed(ix, PgDirection::Incoming) {
                // Undirected, a self-loop came already as an outgoing edge.
                if dir == Direction::Both && e.source() == ix {
                    continue;
                }
                if self.selects(sel, *e.weight(), e.target()) {
                    out.push((e.id().index() as EdgeId, e.source().index() as NodeRef));
                }
            }
        }
        out
    }

    fn edge_ends(&self, e: EdgeId) -> (NodeRef, NodeRef) {
        let (a, b) = self
            .g
            .inner()
            .edge_endpoints(EdgeIndex::new(e as usize))
            .expect("an edge of this graph");
        (a.index() as NodeRef, b.index() as NodeRef)
    }

    fn shortest_tree(
        &self,
        root: NodeRef,
        dir: Direction,
        sel: &TypeSel,
        max_depth: Option<u32>,
        stop: &dyn Fn(NodeRef) -> bool,
        visit: &mut dyn FnMut(NodeRef) -> bool,
    ) -> ReachTree {
        // Toward the root: `(a)-[]->(root)` steps back along edges into it.
        let dirs: &[PgDirection] = match dir {
            Direction::Right => &[PgDirection::Incoming],
            Direction::Left => &[PgDirection::Outgoing],
            Direction::Both => &[PgDirection::Incoming, PgDirection::Outgoing],
        };
        analysis::search(
            self.g,
            [Self::ix(root)],
            dirs,
            |e| self.selects(sel, *e.weight(), e.target()),
            |_| true,
            |ix| !stop(ix.index() as NodeRef),
            max_depth,
            |ix| visit(ix.index() as NodeRef),
        )
    }
}

/// The edge kind a relationship type names, exactly (the edge tables match
/// names case-insensitively, Cypher does not).
pub(super) fn rel_kind(type_name: &str) -> Option<EdgeKind> {
    EdgeKind::from_name_or_external(type_name).filter(|k| k.as_str() == type_name)
}

/// The note on `Tag_Owned` when nothing is marked.
pub(super) fn owned_note(label: &str, none_owned: bool) -> Option<String> {
    (label == TAG_OWNED && none_owned)
        .then(|| "No object is marked as owned, so Tag_Owned matches nothing.".to_string())
}

/// [`GraphView::canonical_rel_type`] for views over this process's kinds.
pub(super) fn canonical_rel_type(type_name: &str) -> Option<String> {
    if matches!(type_name, AD_ATTACK_PATHS | AZ_ATTACK_PATHS) {
        return Some(type_name.to_string());
    }
    rel_kind(type_name).map(|k| k.as_str().to_string())
}

/// [`GraphView::suggest_rel_type`] for views over this process's kinds.
pub(super) fn suggest_rel_type(type_name: &str) -> Option<String> {
    [AD_ATTACK_PATHS, AZ_ATTACK_PATHS]
        .into_iter()
        .find(|c| c.eq_ignore_ascii_case(type_name))
        .map(str::to_string)
        .or_else(|| EdgeKind::from_name_or_external(type_name).map(|k| k.as_str().to_string()))
        .filter(|name| name != type_name)
}

/// [`GraphView::suggest_label`] for views over this process's kinds.
pub(super) fn suggest_label(label: &str) -> Option<String> {
    NodeKind::ALL
        .iter()
        .map(|k| k.as_str())
        .chain(["Base", "Tag_Tier_Zero", TAG_OWNED])
        .find(|name| name.eq_ignore_ascii_case(label))
        .or_else(|| crate::kinds::find_ignore_case(label))
        .filter(|name| *name != label)
        .map(str::to_string)
}

/// [`GraphView::type_sel`] for views over this process's kinds.
pub(super) fn type_sel(types: &[String]) -> TypeSel {
    let mut sel = TypeSel::default();
    for t in types {
        match t.as_str() {
            AD_ATTACK_PATHS => sel.attack = true,
            AZ_ATTACK_PATHS => sel.azure_attack = true,
            _ => {
                if let Some(k) = rel_kind(t) {
                    if !sel.kinds.contains(&k) {
                        sel.kinds.push(k);
                    }
                }
            }
        }
    }
    sel
}

/// The keys [`virtual_prop`] answers (a test checks the two agree).
pub const VIRTUAL_PROPS: &[&str] = &["objectid", "system_tags"];

/// A property every node answers, whatever the load kept: `objectid`, and
/// `system_tags`, BloodHound CE's tags from before the Tag_ labels (design
/// §1.2): `admin_tier_0` on Tier Zero objects, `owned` on owned ones, null
/// elsewhere as in BHE.
pub(super) fn virtual_prop(node: &Node, key: &str, owned: bool) -> Option<Value> {
    // Keep in step with [`VIRTUAL_PROPS`].
    match key {
        "objectid" => Some(Value::Str(node.id.clone())),
        "system_tags" => Some(match (node.tier_zero, owned) {
            (true, true) => Value::Str("admin_tier_0 owned".into()),
            (true, false) => Value::Str("admin_tier_0".into()),
            (false, true) => Value::Str("owned".into()),
            (false, false) => Value::Null,
        }),
        _ => None,
    }
}

/// A property of a graph loaded without every collector property: the
/// [`Props`](crate::model::Props) field of that name, normalised for
/// analysis; `None` for a property no field holds. Only `pathwarden query`
/// gives BloodHound's values; this keeps hand-built and analysis graphs
/// answerable.
pub(super) fn typed_prop(node: &Node, key: &str) -> Option<Value> {
    let p = &node.props;
    let s = |o: &Option<String>| o.clone().map(Value::Str).unwrap_or(Value::Null);
    let b = |o: Option<bool>| o.map(Value::Bool).unwrap_or(Value::Null);
    let i = |o: Option<i64>| o.map(Value::Int).unwrap_or(Value::Null);
    Some(match key {
        "name" => known_name(node),
        "domain" => s(&p.domain),
        "domainsid" => s(&p.domainsid),
        "distinguishedname" => s(&p.distinguishedname),
        "description" => s(&p.description),
        "operatingsystem" => s(&p.operatingsystem),
        "logonscript" => s(&p.logonscript),
        "enabled" => b(p.enabled),
        "hasspn" => b(p.hasspn),
        "dontreqpreauth" => b(p.dontreqpreauth),
        "admincount" => b(p.admincount),
        "unconstraineddelegation" => b(p.unconstraineddelegation),
        "trustedtoauth" => b(p.trustedtoauth),
        "sensitive" => b(p.sensitive),
        "pwdneverexpires" => b(p.pwdneverexpires),
        "passwordnotreqd" => b(p.passwordnotreqd),
        "haslaps" => b(p.haslaps),
        "isdc" => b(p.isdc),
        "pwdlastset" => i(p.pwdlastset),
        "lastlogontimestamp" => i(p.lastlogontimestamp),
        "whencreated" => i(p.whencreated),
        // The field can't tell "none written" from "an empty list"; null,
        // as BHE answers for the objects that have no SPNs written.
        "serviceprincipalnames" if p.serviceprincipalnames.is_empty() => Value::Null,
        "serviceprincipalnames" => Value::List(
            p.serviceprincipalnames
                .iter()
                .cloned()
                .map(Value::Str)
                .collect(),
        ),
        _ => return None,
    })
}

/// The node's name where a record gave one, as BHE would have it: a
/// collector record's `name`, a trust's TargetDomainName (BHE writes it onto
/// the target domain), the name an OpenGraph file wrote (its case kept), or
/// an AzureHound record's name. Otherwise null, as in BHE: a reference known
/// only by its SID (even one Pathwarden names for display, like an
/// uncollected `KEY ADMINS@DOMAIN` or a SID an OpenGraph edge names), or a
/// record without a name (Pathwarden shows its ID or SID instead).
fn known_name(node: &Node) -> Value {
    // A collector record's own name wins over one an OpenGraph file added.
    if node.props.name.is_some() || node.props.named_by_trust {
        return Value::Str(node.name.clone());
    }
    let Some(ext) = node.ext.as_deref() else {
        return Value::Null;
    };
    match ext.prop("name") {
        Some(serde_json::Value::String(s)) => Value::Str(s.clone()),
        _ if ext.named => Value::Str(node.name.clone()),
        _ => Value::Null,
    }
}

/// An OpenGraph property as Cypher sees it: scalars and lists of them.
fn from_json(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            None => n.as_f64().map(Value::Float).unwrap_or(Value::Null),
        },
        serde_json::Value::String(s) => Value::Str(s.clone()),
        serde_json::Value::Array(a) => {
            Value::List(a.iter().map(from_json).filter(|v| !v.is_null()).collect())
        }
        serde_json::Value::Null | serde_json::Value::Object(_) => Value::Null,
    }
}

fn from_prop(v: PropValue) -> Value {
    match v {
        PropValue::Bool(b) => Value::Bool(b),
        PropValue::Int(i) => Value::Int(i),
        PropValue::Float(f) => Value::Float(f),
        PropValue::Str(s) => Value::Str(s),
        PropValue::List(l) => Value::List(l.into_iter().map(from_prop).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`VIRTUAL_PROPS`] names exactly the keys [`virtual_prop`] answers.
    #[test]
    fn virtual_props_list_is_complete() {
        let mut node = Node::placeholder("S-1-5-21-1-1-1101".into(), NodeKind::User);
        node.tier_zero = true;
        for k in VIRTUAL_PROPS {
            assert!(virtual_prop(&node, k, true).is_some(), "{k}");
        }
        for k in
            super::super::PROP_KEYS
                .iter()
                .chain(&["name", "samaccountname", "tier_zero", "owned"])
        {
            assert!(
                VIRTUAL_PROPS.contains(k) || virtual_prop(&node, k, true).is_none(),
                "{k} is answered but not in VIRTUAL_PROPS"
            );
        }
    }

    #[test]
    fn kept_properties_read_as_written() {
        let mut g = AdGraph::new();
        g.keep_all_properties();
        let map = serde_json::json!({
            "name": "svc@example.local",
            "samaccountname": "svc",
            "description": "",
            "enabled": "true",
            "lastlogon": 1791753032,
            "pwdlastset": -1,
            "sidhistory": ["S-1-5-21-9-9-9-1000"],
            "email": null,
            "nested": {"a": 1},
        });
        let mut node = Node::placeholder("S-1-5-21-1-1-1101".into(), NodeKind::User);
        node.placeholder = false;
        node.props.extra = g.prop_bag(map.as_object().unwrap());
        // Nulls and objects are not kept.
        assert_eq!(node.props.extra.len(), 7);
        node.tier_zero = true;
        let n = g.upsert(node).index() as NodeRef;
        let view = AdGraphView::new(&g);
        let s = |v: &str| Value::Str(v.into());
        assert_eq!(view.prop(n, "samaccountname"), s("svc"));
        // As written: not upper-cased, "" not null, "true" not a boolean.
        assert_eq!(view.prop(n, "name"), s("svc@example.local"));
        assert_eq!(view.prop(n, "description"), s(""));
        assert_eq!(view.prop(n, "enabled"), s("true"));
        assert_eq!(view.prop(n, "lastlogon"), Value::Int(1791753032));
        assert_eq!(view.prop(n, "pwdlastset"), Value::Int(-1));
        assert_eq!(
            view.prop(n, "sidhistory"),
            Value::List(vec![s("S-1-5-21-9-9-9-1000")])
        );
        assert_eq!(view.prop(n, "email"), Value::Null);
        assert_eq!(view.prop(n, "nested"), Value::Null);
        assert_eq!(view.prop(n, "nosuchkey"), Value::Null);
        assert_eq!(view.prop(n, "objectid"), s("S-1-5-21-1-1-1101"));
        assert_eq!(view.prop(n, "system_tags"), s("admin_tier_0"));
    }

    /// A secret answers whether it is there, never what it is, whichever
    /// way a query reads it: WHERE, a function, an inline map.
    #[test]
    fn secrets_are_hidden_from_queries() {
        let mut g = AdGraph::new();
        g.keep_all_properties();
        let map = serde_json::json!({
            "name": "svc@example.local",
            "userpassword": "Summer2026!",
            "ms-mcs-admpwd": "Xy7-laps",
            "pwdlastset": 1791753032,
            "haslaps": true,
        });
        let mut node = Node::placeholder("S-1-5-21-1-1-1101".into(), NodeKind::User);
        node.placeholder = false;
        node.props.extra = g.prop_bag(map.as_object().unwrap());
        let n = g.upsert(node).index() as NodeRef;
        let view = AdGraphView::new(&g);
        assert_eq!(view.prop(n, "userpassword"), Value::Str(HIDDEN.into()));
        assert_eq!(view.prop(n, "ms-mcs-admpwd"), Value::Str(HIDDEN.into()));
        assert_eq!(view.prop(n, "unixpassword"), Value::Null);
        // Named like secrets, but not: flags and dates stay readable.
        assert_eq!(view.prop(n, "pwdlastset"), Value::Int(1791753032));
        assert_eq!(view.prop(n, "haslaps"), Value::Bool(true));
        let count = |q: &str| {
            super::super::run(&view, q, &Default::default())
                .unwrap()
                .rows
                .len()
        };
        for q in [
            "MATCH (n:User) WHERE n.userpassword STARTS WITH 'S' RETURN n",
            "MATCH (n:User) WHERE n.userpassword = 'Summer2026!' RETURN n",
            "MATCH (n:User) WHERE toLower(n.userpassword) CONTAINS 'summer' RETURN n",
            "MATCH (n:User) WHERE coalesce(n.userpassword, 'x') ENDS WITH '!' RETURN n",
            "MATCH (n:User) WHERE n.`ms-mcs-admpwd` STARTS WITH 'X' RETURN n",
            "MATCH (n:User {userpassword: 'Summer2026!'}) RETURN n",
        ] {
            assert_eq!(count(q), 0, "{q}");
        }
        // Which accounts carry one is still a fair question.
        assert_eq!(
            count("MATCH (n:Base) WHERE n.userpassword IS NOT NULL OR n.unixpassword IS NOT NULL RETURN n"),
            1
        );
        assert!(is_secret_prop("msds-managedpassword"));
        assert!(is_secret_prop("mslaps-encryptedpassword"));
        assert!(!is_secret_prop("PwdLastSet"));
    }

    /// An object only referenced (a placeholder) has no name in BHE.
    #[test]
    fn a_placeholder_has_no_name() {
        for kept in [false, true] {
            let mut g = AdGraph::new();
            if kept {
                g.keep_all_properties();
            }
            let ix = g.upsert(Node::placeholder(
                "S-1-5-21-1-1-1101".into(),
                NodeKind::User,
            ));
            let view = AdGraphView::new(&g);
            assert_eq!(view.prop(ix.index() as NodeRef, "name"), Value::Null);
        }
    }

    /// A name ingest knows answers even without a collector record: a
    /// trust's target domain (BHE writes TargetDomainName onto it), and an
    /// object only AzureHound or OpenGraph described.
    #[test]
    fn a_name_ingest_knows_answers_without_a_record() {
        for kept in [false, true] {
            let mut g = AdGraph::new();
            if kept {
                g.keep_all_properties();
            }
            let mut target = Node::placeholder("S-1-5-21-7-7-7".into(), NodeKind::Domain);
            target.name = "REVENANT.CORP".into();
            target.props.named_by_trust = true;
            let target = g.upsert(target).index() as NodeRef;
            let az_kind = NodeKind::External(crate::kinds::intern("AZUser"));
            let mut az = Node::placeholder("AZ-USER-1".into(), az_kind);
            az.placeholder = false;
            az.name = "ALICE@CONTOSO.ONMICROSOFT.COM".into();
            az.ext = Some(Box::new(crate::model::ExtNode {
                og_created: true,
                named: true,
                ..Default::default()
            }));
            let az = g.upsert(az).index() as NodeRef;
            // OpenGraph: the name as the file wrote it, not upper-cased.
            let mut og = Node::placeholder("WIDGET-1".into(), NodeKind::User);
            og.placeholder = false;
            og.name = "WIDGET CONSOLE".into();
            og.ext = Some(Box::new(crate::model::ExtNode {
                props: vec![("name".into(), serde_json::json!("Widget console"))],
                og_created: true,
                ..Default::default()
            }));
            let og = g.upsert(og).index() as NodeRef;
            let view = AdGraphView::new(&g);
            let s = |v: &str| Value::Str(v.into());
            assert_eq!(view.prop(target, "name"), s("REVENANT.CORP"), "{kept}");
            assert_eq!(
                view.prop(az, "name"),
                s("ALICE@CONTOSO.ONMICROSOFT.COM"),
                "{kept}"
            );
            assert_eq!(view.prop(og, "name"), s("Widget console"), "{kept}");
        }
    }

    /// No record gave these a name, so BHE has none, though Pathwarden
    /// names them for display: an uncollected well-known group, and a
    /// collected record without a `name`.
    #[test]
    fn a_name_only_pathwarden_made_up_is_null() {
        for kept in [false, true] {
            let mut g = AdGraph::new();
            if kept {
                g.keep_all_properties();
            }
            // Key Admins (-526), referenced and never collected, named for
            // display as postprocessing does.
            let mut ka = Node::placeholder("S-1-5-21-9-9-9-526".into(), NodeKind::Group);
            ka.name = "KEY ADMINS@PHANTOM.CORP".into();
            let ka = g.upsert(ka).index() as NodeRef;
            // A collected record without a name: ingest shows its SID.
            let mut bare = Node::placeholder("S-1-5-21-9-9-9-1500".into(), NodeKind::User);
            bare.placeholder = false;
            let bare = g.upsert(bare).index() as NodeRef;
            let view = AdGraphView::new(&g);
            assert_eq!(view.prop(ka, "name"), Value::Null, "{kept}");
            assert_eq!(view.prop(bare, "name"), Value::Null, "{kept}");
        }
    }

    /// A property the collector didn't write reads as null, as in BHE, so
    /// `IS NULL` matches it and `<> 'x'` doesn't.
    #[test]
    fn a_property_the_collector_did_not_write_reads_as_null() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/rusthound");
        for all in [false, true] {
            let opts = crate::LoadOptions {
                all_properties: all,
                ..Default::default()
            };
            let (g, _) = crate::load(&[&dir], &opts).unwrap();
            let view = AdGraphView::new(&g);
            // Domain Admins: the collector writes no SPN list for groups.
            let da = g
                .lookup("S-1-5-21-907917752-839331996-494631781-512")
                .unwrap();
            let da = da.index() as NodeRef;
            assert_eq!(view.prop(da, "serviceprincipalnames"), Value::Null, "{all}");
            for (q, want) in [
                (
                    "MATCH (n:Group) WHERE n.serviceprincipalnames IS NULL RETURN n",
                    true,
                ),
                (
                    "MATCH (n:Group) WHERE n.serviceprincipalnames <> 'x' RETURN n",
                    false,
                ),
            ] {
                let r = super::super::run(&view, q, &Default::default()).unwrap();
                assert_eq!(
                    r.node_ids().contains(&view.objectid(da)),
                    want,
                    "{q} all={all}"
                );
            }
        }
    }

    /// A load keeps every property only when asked (`pathwarden query`).
    #[test]
    fn a_load_keeps_every_property_only_when_asked() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/rusthound");
        let admin = "S-1-5-21-907917752-839331996-494631781-500";
        for all in [false, true] {
            let opts = crate::LoadOptions {
                all_properties: all,
                ..Default::default()
            };
            let (g, _) = crate::load(&[&dir], &opts).unwrap();
            let view = AdGraphView::new(&g);
            let n = g.lookup(admin).unwrap().index() as NodeRef;
            let want = if all {
                Value::Str("Administrator".into())
            } else {
                Value::Null
            };
            assert_eq!(view.prop(n, "samaccountname"), want, "all={all}");
            assert_eq!(view.prop(n, "userpassword").is_null(), !all);
            // Fields and the raw value agree here.
            assert_eq!(view.prop(n, "admincount"), Value::Bool(true));
        }
    }

    #[test]
    fn suggests_what_a_wrong_case_meant() {
        let g = AdGraph::new();
        let view = AdGraphView::new(&g);
        assert_eq!(
            view.suggest_rel_type("memberof").as_deref(),
            Some("MemberOf")
        );
        assert_eq!(view.suggest_rel_type("MemberOf"), None);
        assert_eq!(view.suggest_rel_type("nosuchtype"), None);
        assert_eq!(view.suggest_label("user").as_deref(), Some("User"));
        assert_eq!(
            view.suggest_label("tag_tier_zero").as_deref(),
            Some("Tag_Tier_Zero")
        );
        assert_eq!(view.suggest_label("User"), None);
        // AzureHound and OpenGraph kinds too.
        crate::kinds::intern("AZUser");
        assert_eq!(view.suggest_label("azuser").as_deref(), Some("AZUser"));
        assert_eq!(view.suggest_label("AZUser"), None);
    }
}
