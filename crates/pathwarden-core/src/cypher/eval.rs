//! The evaluator: pattern matching + `WHERE` + `RETURN` over a [`GraphView`].
//!
//! Every query runs under a wall-clock deadline and a row cap, and a
//! variable-length relationship without an upper bound under a hop cap, so
//! an expensive pattern stops early and says so rather than hangs (design
//! §3.2). Matching uses the raw adjacency the view exposes, honouring only
//! the relationship types the pattern names (design §1.4); the composite
//! `AD_ATTACK_PATHS` names the edges attack paths follow.
//!
//! - A chain of fixed and variable-length relationships is matched depth
//!   first from whichever end has fewer candidates, each relationship used
//!   at most once per row, as in Neo4j.
//! - `shortestPath()` and `allShortestPaths()` run the analysis's
//!   breadth-first search from each node the arrows point to, so
//!   `shortestPath` over `AD_ATTACK_PATHS` finds the path `pathwarden path`
//!   finds. An attack path (`AD_ATTACK_PATHS`, `AZ_ATTACK_PATHS`) ends at
//!   the first Tier Zero object it meets, as the analysis's paths do.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::ast::*;
use super::value::{self, Value};
use super::view::{EdgeId, GraphView, NodeRef, TypeSel};
use crate::NodeIndex;

/// How many relationships a variable-length relationship without an upper
/// bound (`*`, `*1..`) follows outside `shortestPath()`.
pub const DEFAULT_MAX_HOPS: u32 = 10;

/// The largest bound (upper or lower) a variable-length relationship may
/// write outside `shortestPath()`, where every path is enumerated.
pub const MAX_WRITTEN_HOPS: u32 = 25;

/// The most relationships one row of a chain can walk outside
/// `shortestPath()`: the sum of each relationship's upper bound (the hop
/// cap where none is written; a fixed relationship counts one). Matching
/// recurses once per relationship, so this also bounds its stack.
pub const MAX_CHAIN_HOPS: u32 = 50;

/// The relationships all returned paths may hold together, by default:
/// past it the rows stop, as at the row cap. Rows of long paths cost
/// memory the row cap alone does not bound.
pub const DEFAULT_MAX_PATH_STEPS: usize = 250_000;

/// Hard limits on a single evaluation.
#[derive(Debug, Clone)]
pub struct EvalLimits {
    /// Maximum rows returned before the result is marked truncated.
    pub max_rows: usize,
    /// Wall-clock budget for the whole evaluation.
    pub timeout: Duration,
    /// The hop cap of a variable-length relationship without an upper
    /// bound, outside `shortestPath()` (which needs none). At most
    /// [`MAX_WRITTEN_HOPS`].
    pub max_hops: u32,
    /// The relationships all returned paths may hold together.
    pub max_path_steps: usize,
}

impl Default for EvalLimits {
    fn default() -> Self {
        EvalLimits {
            max_rows: 100_000,
            timeout: Duration::from_secs(10),
            max_hops: DEFAULT_MAX_HOPS,
            max_path_steps: DEFAULT_MAX_PATH_STEPS,
        }
    }
}

/// One projected value in a result row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "entity", rename_all = "lowercase")]
pub enum Cell {
    /// A node, by its upper-cased ObjectIdentifier.
    Node { id: String },
    /// A relationship: (source objectid, TYPE, target objectid).
    Rel {
        src: String,
        #[serde(rename = "type")]
        kind: String,
        tgt: String,
    },
    /// A path: its nodes in order, and the relationship between each two
    /// (in its stored direction, which a `<-` hop reverses).
    Path {
        nodes: Vec<String>,
        relationships: Vec<Hop>,
        /// The view's edge handles of the relationships, to draw the path.
        #[serde(skip)]
        edges: Vec<EdgeId>,
        /// The pattern reads it against its relationships (every one
        /// `<-`): drawn from the other end, it runs with them.
        #[serde(skip)]
        backward: bool,
        /// The view's handles of the nodes.
        #[serde(skip)]
        handles: Vec<NodeRef>,
    },
}

/// One relationship of a returned path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Hop {
    pub src: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub tgt: String,
}

/// The normalised result both front-ends and the parity harness consume.
#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    /// RETURN column names (alias or variable).
    pub columns: Vec<String>,
    /// Whether a column returns paths (true when no row came back too).
    #[serde(skip)]
    pub returns_paths: bool,
    /// Projected rows.
    pub rows: Vec<Vec<Cell>>,
    /// The relationships the matched rows went through, de-duplicated
    /// (useful even when the RETURN projects only nodes), including those
    /// of rows DISTINCT folded together. Bounded by LIMIT (matching stops)
    /// and by the row cap: at most that many are kept
    /// ([`Self::relationships_truncated`]), while matching goes on for rows.
    pub relationships: Vec<(String, String, String)>,
    /// True when the row cap or the deadline cut the rows short. A LIMIT
    /// the query asked for is not a truncation.
    pub truncated: bool,
    /// True when it was the deadline.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub timed_out: bool,
    /// True when it was the cap on the relationships the returned paths
    /// hold together ([`EvalLimits::max_path_steps`]).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub path_steps_capped: bool,
    /// True when more relationships matched than the row cap keeps (rows
    /// DISTINCT folded together can go through many). The rows are complete
    /// unless [`Self::truncated`] says otherwise.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub relationships_truncated: bool,
    /// The hop cap, when it stopped a variable-length relationship that had
    /// more relationships to follow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hop_cap: Option<u32>,
    /// Each cap that cut the answer short, in a sentence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stopped: Vec<String>,
    /// Notes for the user that don't stop the query, like a label or
    /// relationship type in the wrong case (which matches nothing).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub elapsed_ms: u128,
}

impl QueryResult {
    /// The de-duplicated, sorted set of node ObjectIdentifiers in the RETURN
    /// projection, the nodes of returned paths included — the "id-set" the
    /// parity harness compares.
    pub fn node_ids(&self) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        for cell in self.rows.iter().flatten() {
            match cell {
                Cell::Node { id } => {
                    ids.insert(id.clone());
                }
                Cell::Path { nodes, .. } => ids.extend(nodes.iter().cloned()),
                Cell::Rel { .. } => {}
            }
        }
        ids
    }

    /// The returned paths, row by row.
    pub fn paths(&self) -> impl Iterator<Item = &Cell> {
        self.rows
            .iter()
            .flatten()
            .filter(|c| matches!(c, Cell::Path { .. }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    /// The query names a variable the MATCH pattern did not bind.
    UnboundVariable(String),
    /// A value of the wrong type where a boolean is needed (`WHERE 1`), or
    /// a node where a value is (`WHERE n = 1`), as Neo4j refuses them.
    Type(String),
    /// A shape this build parses but does not evaluate yet.
    Unsupported(String),
    /// Deadline configured as zero-length, or otherwise unusable.
    BadLimits(String),
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = match self {
            EvalError::UnboundVariable(v) => {
                format!("variable '{v}' is not defined: the MATCH pattern does not bind it")
            }
            EvalError::Type(m) | EvalError::Unsupported(m) | EvalError::BadLimits(m) => m.clone(),
        };
        f.write_str(&super::sentence(&m))
    }
}

/// A variable-to-node binding environment. Tiny (a few entries), so a Vec
/// beats a map.
struct Env<'a> {
    binds: &'a [(String, NodeRef)],
}

impl Env<'_> {
    fn get(&self, var: &str) -> Option<NodeRef> {
        self.binds.iter().find(|(v, _)| v == var).map(|(_, n)| *n)
    }
}

pub fn evaluate(
    view: &dyn GraphView,
    q: &Query,
    limits: &EvalLimits,
) -> Result<QueryResult, EvalError> {
    if limits.max_rows == 0 {
        return Err(EvalError::BadLimits("max_rows must be at least 1".into()));
    }
    let max_hops = limits.max_hops.clamp(1, MAX_WRITTEN_HOPS);
    check(q, max_hops)?;
    let start = Instant::now();
    // A huge timeout means "no deadline" rather than an overflow panic.
    let deadline = start
        .checked_add(limits.timeout)
        .unwrap_or_else(|| start + Duration::from_secs(365 * 86_400));
    let columns: Vec<String> = q.ret.items.iter().map(|it| it.name().to_string()).collect();

    // WHERE, split into the AND-ed tests of one node (checked as soon as
    // that node is matched) and the rest (checked on a whole row).
    let mut local: Vec<(String, Vec<&Expr>)> = Vec::new();
    let mut rest: Vec<&Expr> = Vec::new();
    let mut conjuncts = Vec::new();
    if let Some(e) = &q.where_clause {
        split_and(e, &mut conjuncts);
    }
    let node_vars: BTreeSet<&str> = q
        .pattern
        .nodes()
        .filter_map(|np| np.var.as_deref())
        .collect();
    for c in &conjuncts {
        let mut vars = Vec::new();
        variables(c, &mut vars);
        vars.sort_unstable();
        vars.dedup();
        match vars.as_slice() {
            [one] if node_vars.contains(one) => match local.iter_mut().find(|(v, _)| v == one) {
                Some((_, tests)) => tests.push(c),
                None => local.push((one.to_string(), vec![c])),
            },
            _ => rest.push(c),
        }
    }

    let mut ctx = Ctx {
        view,
        deadline,
        max_rows: limits.max_rows,
        max_hops,
        max_path_steps: limits.max_path_steps.max(1),
        path_steps: 0,
        path_steps_capped: false,
        backward: !q.pattern.hops.is_empty()
            && q.pattern.rels().all(|r| r.direction == Direction::Left),
        limit: q
            .ret
            .limit
            .map(|l| usize::try_from(l).unwrap_or(usize::MAX)),
        q,
        local,
        rest,
        several_tests: conjuncts.len() > 1,
        rows: Vec::new(),
        relationships: BTreeSet::new(),
        seen_rows: BTreeSet::new(),
        distinct: q.ret.distinct,
        truncated: false,
        timed_out: false,
        relationships_truncated: false,
        hop_cap: None,
        steps: 0,
    };

    // LIMIT 0 asks for nothing.
    if ctx.limit != Some(0) {
        match q.pattern.shortest {
            Some(kind) => ctx.match_shortest(kind)?,
            None if q.pattern.hops.is_empty() => ctx.match_node()?,
            None => ctx.match_chain()?,
        }
    }

    let mut stopped = Vec::new();
    if ctx.timed_out {
        stopped.push(format!(
            "Stopped at the {} time limit: there may be more rows.",
            seconds(limits.timeout)
        ));
    } else if ctx.path_steps_capped {
        stopped.push(format!(
            "Stopped at {} relationships across the returned paths: there are more rows.",
            crate::text::num(ctx.max_path_steps)
        ));
    } else if ctx.truncated {
        stopped.push(format!(
            "Stopped at the {}-row cap: there are more rows.",
            crate::text::num(limits.max_rows)
        ));
    } else if ctx.relationships_truncated {
        stopped.push(format!(
            "The rows are complete; the relationships stop at {}.",
            crate::text::num(limits.max_rows)
        ));
    }
    if let Some(n) = ctx.hop_cap {
        stopped.push(format!(
            "Paths longer than {} were not followed: a variable-length relationship without an upper bound stops there.",
            crate::text::count(n as usize, "relationship", "relationships")
        ));
    }

    let rows = ctx.rows_out();
    let relationships = ctx.relationships_out();
    Ok(QueryResult {
        columns,
        returns_paths: q
            .ret
            .items
            .iter()
            .any(|it| q.pattern.path_var.as_deref() == Some(it.var.as_str())),
        rows,
        relationships,
        truncated: ctx.truncated,
        timed_out: ctx.timed_out,
        path_steps_capped: ctx.path_steps_capped,
        relationships_truncated: ctx.relationships_truncated,
        hop_cap: ctx.hop_cap,
        stopped,
        warnings: case_hints(view, q)
            .into_iter()
            .chain(view.notes())
            .collect(),
        elapsed_ms: start.elapsed().as_millis(),
    })
}

/// "10-second", "500-millisecond".
fn seconds(d: Duration) -> String {
    match d.as_secs() {
        0 => format!("{}-millisecond", d.as_millis()),
        s => format!("{}-second", crate::text::num(s as usize)),
    }
}

/// The AND-ed parts of a WHERE.
fn split_and<'a>(e: &'a Expr, out: &mut Vec<&'a Expr>) {
    match e {
        Expr::And(a, b) => {
            split_and(a, out);
            split_and(b, out);
        }
        other => out.push(other),
    }
}

/// Refuses, before matching anything, what Neo4j refuses: a variable the
/// pattern does not bind (in WHERE or RETURN), and what this build cannot
/// evaluate yet. Matching would otherwise read it as null and silently
/// return nothing.
pub(super) fn check(q: &Query, max_hops: u32) -> Result<(), EvalError> {
    let p = &q.pattern;
    if p.rels().any(|r| r.types.is_empty()) {
        return Err(EvalError::Unsupported(
            "name a relationship type, like -[:MemberOf]-> (untyped relationships are not supported yet)"
                .into(),
        ));
    }
    if p.shortest.is_none() {
        // Every path is enumerated, one recursion per relationship: bound
        // each relationship, and the chain.
        let mut total: u32 = 0;
        for r in p.rels() {
            let most = match r.length {
                None => 1,
                Some(Length { min, max }) => {
                    let written = max.unwrap_or(0).max(min);
                    if written > MAX_WRITTEN_HOPS {
                        return Err(EvalError::Unsupported(format!(
                            "a variable-length relationship follows at most {MAX_WRITTEN_HOPS} relationships, not {written}; shortestPath() has no such limit"
                        )));
                    }
                    max.unwrap_or(max_hops.max(min))
                }
            };
            total = total.saturating_add(most);
        }
        if total > MAX_CHAIN_HOPS {
            return Err(EvalError::Unsupported(format!(
                "a pattern follows at most {MAX_CHAIN_HOPS} relationships in all, not {total}"
            )));
        }
    }
    let node_vars: Vec<&str> = p.nodes().filter_map(|np| np.var.as_deref()).collect();
    let rel_vars: Vec<&str> = p.rels().filter_map(|r| r.var.as_deref()).collect();
    let path_var = p.path_var.as_deref();
    // One name, one thing.
    for (i, r) in rel_vars.iter().enumerate() {
        if node_vars.contains(r) || path_var == Some(*r) || rel_vars[..i].contains(r) {
            return Err(EvalError::Type(format!(
                "variable '{r}' names two things in the pattern"
            )));
        }
    }
    if let Some(pv) = path_var {
        if node_vars.contains(&pv) {
            return Err(EvalError::Type(format!(
                "variable '{pv}' names two things in the pattern"
            )));
        }
    }
    let classify = |v: &str, place: &str| -> Result<(), EvalError> {
        if node_vars.contains(&v) {
            Ok(())
        } else if rel_vars.contains(&v) {
            Err(EvalError::Unsupported(format!(
                "relationship variable '{v}' can't be used in {place} yet; leave it out, as in -[:Type]->"
            )))
        } else if path_var == Some(v) {
            Err(EvalError::Unsupported(format!(
                "path variable '{v}' can only be returned; path functions in {place} are not supported yet"
            )))
        } else {
            Err(EvalError::UnboundVariable(v.to_string()))
        }
    };
    if let Some(e) = &q.where_clause {
        let mut used = Vec::new();
        variables(e, &mut used);
        for v in used {
            classify(v, "WHERE")?;
        }
    }
    for it in &q.ret.items {
        if path_var != Some(it.var.as_str()) {
            classify(&it.var, "RETURN")?;
        }
    }
    // A WHERE that can't be a boolean is an error even when no node
    // reaches it (`MATCH (n:NoSuch) WHERE 1`, `WHERE NOT 1`).
    match &q.where_clause {
        Some(e) => boolean_position("WHERE", e),
        None => Ok(()),
    }
}

/// Refuses a literal that isn't a boolean or null, or a bare node, where a
/// boolean is needed, looking through NOT, AND and OR.
fn boolean_position(what: &str, e: &Expr) -> Result<(), EvalError> {
    match e {
        Expr::Literal(v) if !matches!(v, Value::Bool(_) | Value::Null) => Err(EvalError::Type(
            format!("{what} needs a boolean, found {}", value::type_name(v)),
        )),
        Expr::Variable(var) => Err(node_as_value(var)),
        Expr::Not(a) => boolean_position("NOT", a),
        Expr::And(a, b) => boolean_position("AND", a).and(boolean_position("AND", b)),
        Expr::Or(a, b) => boolean_position("OR", a).and(boolean_position("OR", b)),
        _ => Ok(()),
    }
}

pub(super) fn node_as_value(var: &str) -> EvalError {
    EvalError::Type(format!(
        "'{var}' is a node, not a value: compare one of its properties, like {var}.objectid"
    ))
}

/// The variables an expression reads.
fn variables<'a>(e: &'a Expr, out: &mut Vec<&'a str>) {
    match e {
        Expr::Literal(_) => {}
        Expr::Property { var, .. } | Expr::Variable(var) | Expr::HasLabels { var, .. } => {
            out.push(var)
        }
        Expr::Func { args, .. } => {
            for a in args {
                variables(a, out);
            }
        }
        Expr::Compare { lhs, rhs, .. } | Expr::StringOp { lhs, rhs, .. } => {
            variables(lhs, out);
            variables(rhs, out);
        }
        Expr::IsNull { expr, .. } | Expr::Not(expr) => variables(expr, out),
        Expr::And(a, b) | Expr::Or(a, b) => {
            variables(a, out);
            variables(b, out);
        }
    }
}

/// The labels a WHERE tests (`n:User`).
fn where_labels<'a>(e: &'a Expr, out: &mut Vec<&'a String>) {
    match e {
        Expr::HasLabels { labels, .. } => out.extend(labels),
        Expr::Func { args, .. } => {
            for a in args {
                where_labels(a, out);
            }
        }
        Expr::Compare { lhs, rhs, .. } | Expr::StringOp { lhs, rhs, .. } => {
            where_labels(lhs, out);
            where_labels(rhs, out);
        }
        Expr::IsNull { expr, .. } | Expr::Not(expr) => where_labels(expr, out),
        Expr::And(a, b) | Expr::Or(a, b) => {
            where_labels(a, out);
            where_labels(b, out);
        }
        Expr::Literal(_) | Expr::Property { .. } | Expr::Variable(_) => {}
    }
}

/// Labels and relationship types that match nothing but would match with
/// another case: `:memberof` matched MemberOf before types became
/// case-sensitive, so say what it probably meant. Also a label the data
/// can't have yet, like `Tag_Owned` with nothing marked owned.
fn case_hints(view: &dyn GraphView, q: &Query) -> Vec<String> {
    let mut labels: Vec<&String> = q.pattern.nodes().flat_map(|np| &np.labels).collect();
    if let Some(e) = &q.where_clause {
        where_labels(e, &mut labels);
    }
    let mut hints = Vec::new();
    for label in labels {
        if let Some(meant) = view.suggest_label(label) {
            hints.push(format!(
                "no label {label} (labels are case-sensitive; did you mean {meant}?)"
            ));
        }
        if let Some(note) = view.label_note(label) {
            hints.push(note);
        }
    }
    for t in q.pattern.rels().flat_map(|r| &r.types) {
        if view.canonical_rel_type(t).is_none() {
            if let Some(meant) = view.suggest_rel_type(t) {
                hints.push(format!(
                    "no relationship type {t} (types are case-sensitive; did you mean {meant}?)"
                ));
            }
        }
    }
    let mut seen = BTreeSet::new();
    hints.retain(|h| seen.insert(h.clone()));
    hints
}

/// A relationship of the chain as matching walks it.
struct Step {
    dir: Direction,
    sel: TypeSel,
    /// `None`: exactly one relationship.
    length: Option<(u32, u32)>,
    /// Whether the upper bound is the hop cap, not one the query wrote.
    capped: bool,
}

/// The chain in the order matching walks it, from the anchor.
struct Walk<'q> {
    nodes: Vec<&'q NodePattern>,
    steps: Vec<Step>,
    /// Walked from the last node to the first: rows are put back in the
    /// pattern's order.
    reversed: bool,
}

/// Where a walk is: the nodes and relationships so far, and the bindings.
#[derive(Default)]
struct State {
    nodes: Vec<NodeRef>,
    edges: Vec<EdgeId>,
    binds: Vec<(String, NodeRef)>,
}

struct Ctx<'a> {
    view: &'a dyn GraphView,
    deadline: Instant,
    max_rows: usize,
    max_hops: u32,
    /// The query's LIMIT.
    limit: Option<usize>,
    q: &'a Query,
    /// The WHERE tests of one node variable each.
    local: Vec<(String, Vec<&'a Expr>)>,
    /// The other WHERE tests.
    rest: Vec<&'a Expr>,
    /// Whether the WHERE is several AND-ed tests (for its error messages).
    several_tests: bool,
    /// Rows as handles; turned into IDs only at the end.
    rows: Vec<Vec<Slot>>,
    relationships: BTreeSet<EdgeId>,
    seen_rows: BTreeSet<Vec<Slot>>,
    distinct: bool,
    max_path_steps: usize,
    /// Relationships the kept rows' paths hold together.
    path_steps: usize,
    path_steps_capped: bool,
    /// Every relationship of the pattern is `<-`.
    backward: bool,
    truncated: bool,
    timed_out: bool,
    relationships_truncated: bool,
    hop_cap: Option<u32>,
    /// Relationships followed since the clock was last read.
    steps: u32,
}

/// What a match step tells its caller: go on, or stop matching.
type Flow = Result<bool, EvalError>;

/// A projected value while matching: handles, small and cheap to compare.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    Node(NodeRef),
    Path {
        nodes: Vec<NodeRef>,
        edges: Vec<EdgeId>,
    },
}

impl Ctx<'_> {
    /// Whether the budget is spent; once it is, the result says so.
    fn out_of_time(&mut self) -> bool {
        if self.timed_out {
            return true;
        }
        if Instant::now() >= self.deadline {
            self.truncated = true;
            self.timed_out = true;
            return true;
        }
        false
    }

    /// [`Self::out_of_time`], reading the clock every 256 steps.
    fn tick(&mut self) -> bool {
        self.steps += 1;
        if self.steps >= 256 {
            self.steps = 0;
            return self.out_of_time();
        }
        self.timed_out
    }

    /// Offers a matched row and the relationships it went through. Returns
    /// true when matching should stop: LIMIT has its rows (complete), or
    /// the row cap is passed (truncated). A row DISTINCT already has is not
    /// kept again, but its relationships are, so `RETURN DISTINCT g` still
    /// reports every relationship it matched.
    fn offer(&mut self, row: Vec<Slot>, rels: &[EdgeId]) -> bool {
        if self.distinct && self.seen_rows.contains(&row) {
            self.keep_relationships(rels);
            return false;
        }
        if self.rows.len() >= self.max_rows {
            self.truncated = true;
            return true;
        }
        let steps: usize = row
            .iter()
            .map(|c| match c {
                Slot::Path { edges, .. } => edges.len(),
                Slot::Node(_) => 0,
            })
            .sum();
        if self.path_steps + steps > self.max_path_steps {
            self.truncated = true;
            self.path_steps_capped = true;
            return true;
        }
        self.path_steps += steps;
        if self.distinct {
            self.seen_rows.insert(row.clone());
        }
        self.keep_relationships(rels);
        self.rows.push(row);
        // LIMIT reached: the answer is complete, stop without looking for
        // another row. (The row cap needs one more to say it cut anything.)
        self.rows.len() >= self.limit.unwrap_or(usize::MAX)
    }

    /// Keeps matched relationships, up to the row cap. Past it the rest are
    /// only counted as cut ([`QueryResult::relationships_truncated`]);
    /// matching goes on, since the rows may still be complete.
    fn keep_relationships(&mut self, rels: &[EdgeId]) {
        for &rel in rels {
            if self.relationships.contains(&rel) {
                continue;
            }
            if self.relationships.len() >= self.max_rows {
                self.relationships_truncated = true;
                return;
            }
            self.relationships.insert(rel);
        }
    }

    /// The rows with object IDs, made once matching is done.
    fn rows_out(&mut self) -> Vec<Vec<Cell>> {
        let rows = std::mem::take(&mut self.rows);
        rows.into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|slot| match slot {
                        Slot::Node(h) => Cell::Node {
                            id: self.view.objectid(h),
                        },
                        Slot::Path { nodes, edges } => Cell::Path {
                            nodes: nodes.iter().map(|&n| self.view.objectid(n)).collect(),
                            relationships: edges.iter().map(|&e| self.hop(e)).collect(),
                            edges,
                            backward: self.backward,
                            handles: nodes,
                        },
                    })
                    .collect()
            })
            .collect()
    }

    /// The relationships matched, as (source, type, target) IDs, sorted.
    fn relationships_out(&self) -> Vec<(String, String, String)> {
        let set: BTreeSet<(String, String, String)> = self
            .relationships
            .iter()
            .map(|&e| {
                let h = self.hop(e);
                (h.src, h.kind, h.tgt)
            })
            .collect();
        set.into_iter().collect()
    }

    /// Labels, inline properties, and the WHERE tests of that node alone.
    fn node_ok(&self, h: NodeRef, np: &NodePattern) -> Result<bool, EvalError> {
        if !np.labels.iter().all(|l| self.view.matches_label(h, l)) {
            return Ok(false);
        }
        for (key, want) in &np.props {
            let got = self.view.prop(h, key);
            if value::equals(&got, want) != Some(true) {
                return Ok(false);
            }
        }
        let Some(var) = &np.var else {
            return Ok(true);
        };
        let Some((_, tests)) = self.local.iter().find(|(v, _)| v == var) else {
            return Ok(true);
        };
        let binds = [(var.clone(), h)];
        self.tests_hold(tests, &binds)
    }

    /// Whether every test is true (false and null fail; anything else is a
    /// type error, as in Neo4j).
    fn tests_hold(&self, tests: &[&Expr], binds: &[(String, NodeRef)]) -> Result<bool, EvalError> {
        let what = if self.several_tests { "AND" } else { "WHERE" };
        let env = Env { binds };
        for t in tests {
            if truth(&self.eval(t, &env)?, what)? != Some(true) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The nodes a node pattern can be (in storage order), or `None` when
    /// the deadline passed while looking.
    fn candidates(&mut self, np: &NodePattern) -> Result<Option<Vec<NodeRef>>, EvalError> {
        let mut out = Vec::new();
        for h in self.view.node_handles() {
            if self.tick() {
                return Ok(None);
            }
            if self.node_ok(h, np)? {
                out.push(h);
            }
        }
        Ok(Some(out))
    }

    fn match_node(&mut self) -> Result<(), EvalError> {
        let np = &self.q.pattern.start;
        for h in self.view.node_handles() {
            if self.out_of_time() {
                break;
            }
            if !self.node_ok(h, np)? {
                continue;
            }
            let binds = bind(np, h);
            let state = State {
                nodes: vec![h],
                edges: Vec::new(),
                binds,
            };
            if self.emit(&state, false)? {
                break;
            }
        }
        Ok(())
    }

    /// A row the pattern matched: the remaining WHERE tests, then RETURN.
    /// `reversed`: the state walked the pattern from its end.
    fn emit(&mut self, st: &State, reversed: bool) -> Flow {
        if !self.tests_hold(&self.rest, &st.binds)? {
            return Ok(false);
        }
        let (mut nodes, mut edges) = (st.nodes.clone(), st.edges.clone());
        if reversed {
            nodes.reverse();
            edges.reverse();
        }
        let env = Env { binds: &st.binds };
        let mut row = Vec::with_capacity(self.q.ret.items.len());
        for item in &self.q.ret.items {
            if self.q.pattern.path_var.as_deref() == Some(item.var.as_str()) {
                row.push(Slot::Path {
                    nodes: nodes.clone(),
                    edges: edges.clone(),
                });
                continue;
            }
            let h = env
                .get(&item.var)
                .ok_or_else(|| EvalError::UnboundVariable(item.var.clone()))?;
            row.push(Slot::Node(h));
        }
        Ok(self.offer(row, &edges))
    }

    fn hop(&self, e: EdgeId) -> Hop {
        let (a, b) = self.view.edge_ends(e);
        Hop {
            src: self.view.objectid(a),
            kind: self.view.edge_type(e),
            tgt: self.view.objectid(b),
        }
    }

    /// The step a relationship pattern walks, read in `dir`.
    fn step(&self, rel: &RelPattern, dir: Direction) -> Step {
        let sel = self.view.type_sel(&rel.types);
        let (length, capped) = match rel.length {
            None => (None, false),
            Some(Length {
                min,
                max: Some(max),
            }) => (Some((min, max)), false),
            Some(Length { min, max: None }) => (Some((min, self.max_hops.max(min))), true),
        };
        Step {
            dir,
            sel,
            length,
            capped,
        }
    }

    /// A chain of relationships: walked depth first from the end with
    /// fewer candidates.
    fn match_chain(&mut self) -> Result<(), EvalError> {
        let p = &self.q.pattern;
        let mut nodes: Vec<&NodePattern> = p.nodes().collect();
        let first = nodes[0];
        let last = nodes[nodes.len() - 1];
        let Some(from_start) = self.candidates(first)? else {
            return Ok(());
        };
        let Some(from_end) = self.candidates(last)? else {
            return Ok(());
        };
        let reversed = from_end.len() < from_start.len();
        let (anchors, steps) = if reversed {
            nodes.reverse();
            let steps = p
                .rels()
                .rev()
                .map(|r| self.step(r, r.direction.flip()))
                .collect();
            (from_end, steps)
        } else {
            (
                from_start,
                p.rels().map(|r| self.step(r, r.direction)).collect(),
            )
        };
        let walk = Walk {
            nodes,
            steps,
            reversed,
        };
        for a in anchors {
            if self.out_of_time() {
                break;
            }
            let mut st = State {
                nodes: vec![a],
                edges: Vec::new(),
                binds: bind(walk.nodes[0], a),
            };
            if self.extend(&walk, 0, a, &mut st)? {
                break;
            }
        }
        Ok(())
    }

    /// Goes on from node `pos` of the walk, matched as `cur`.
    fn extend(&mut self, walk: &Walk, pos: usize, cur: NodeRef, st: &mut State) -> Flow {
        if pos + 1 == walk.nodes.len() {
            return self.emit(st, walk.reversed);
        }
        let step = &walk.steps[pos];
        match step.length {
            None => {
                for (e, x) in self.view.edges(cur, step.dir, &step.sel) {
                    if self.tick() {
                        return Ok(true);
                    }
                    if st.edges.contains(&e) {
                        continue;
                    }
                    st.edges.push(e);
                    st.nodes.push(x);
                    let stop = self.arrive(walk, pos + 1, x, st)?;
                    st.edges.pop();
                    st.nodes.pop();
                    if stop {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Some((min, max)) => self.hops(walk, pos, cur, 0, min, max, st),
        }
    }

    /// `cur` is `depth` relationships into the variable-length step `pos`.
    #[allow(clippy::too_many_arguments)]
    fn hops(
        &mut self,
        walk: &Walk,
        pos: usize,
        cur: NodeRef,
        depth: u32,
        min: u32,
        max: u32,
        st: &mut State,
    ) -> Flow {
        if depth >= min && self.arrive(walk, pos + 1, cur, st)? {
            return Ok(true);
        }
        let step = &walk.steps[pos];
        if depth == max {
            // Only the cap a query didn't write is worth a note.
            if step.capped
                && self
                    .view
                    .edges(cur, step.dir, &step.sel)
                    .iter()
                    .any(|(e, _)| !st.edges.contains(e))
            {
                self.hop_cap = Some(max);
            }
            return Ok(false);
        }
        for (e, x) in self.view.edges(cur, step.dir, &step.sel) {
            if self.tick() {
                return Ok(true);
            }
            if st.edges.contains(&e) {
                continue;
            }
            st.edges.push(e);
            st.nodes.push(x);
            let stop = self.hops(walk, pos, x, depth + 1, min, max, st)?;
            st.edges.pop();
            st.nodes.pop();
            if stop {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Node `pos` of the walk is `x`: check it, bind it, go on.
    fn arrive(&mut self, walk: &Walk, pos: usize, x: NodeRef, st: &mut State) -> Flow {
        let np = walk.nodes[pos];
        let mut pushed = false;
        if let Some(var) = &np.var {
            match st.binds.iter().find(|(v, _)| v == var) {
                // One variable twice, `(a)-[:T]->(a)`: the same node.
                Some((_, h)) if *h != x => return Ok(false),
                Some(_) => {}
                None => {
                    if !self.node_ok(x, np)? {
                        return Ok(false);
                    }
                    st.binds.push((var.clone(), x));
                    pushed = true;
                }
            }
        } else if !self.node_ok(x, np)? {
            return Ok(false);
        }
        let flow = self.extend(walk, pos, x, st);
        if pushed {
            st.binds.pop();
        }
        flow
    }

    /// `shortestPath()` / `allShortestPaths()`: a breadth-first search from
    /// each node the arrows point to (the analysis's search, as
    /// `pathwarden path` runs it), one row per pair of end nodes it joins.
    /// An attack path ends at the first Tier Zero object it meets, as the
    /// analysis's paths do: over attack-path types the search reaches Tier
    /// Zero objects but goes no further, so no path runs on from one (control
    /// of Tier Zero is control of everything). Named types (`MemberOf*`) are
    /// followed through Tier Zero.
    fn match_shortest(&mut self, kind: Shortest) -> Result<(), EvalError> {
        let p = &self.q.pattern;
        let (rel, end) = &p.hops[0];
        let Length { min, max } = rel.length.unwrap_or(Length {
            min: 1,
            max: Some(1),
        });
        // Search from the node the arrows point to, as `pathwarden path`
        // does: `(t)<-[]-(s)` is `(s)-[]->(t)`, put back in order after.
        let (src_np, tgt_np, dir, flipped) = match rel.direction {
            Direction::Left => (end, &p.start, Direction::Right, true),
            Direction::Right => (&p.start, end, Direction::Right, false),
            Direction::Both => (&p.start, end, Direction::Both, false),
        };
        let sel = self.view.type_sel(&rel.types);
        let Some(sources) = self.candidates(src_np)? else {
            return Ok(());
        };
        let Some(mut targets) = self.candidates(tgt_np)? else {
            return Ok(());
        };
        if sources.is_empty() || targets.is_empty() {
            return Ok(());
        }
        let n = self.view.node_handles().len();
        let mut is_source = vec![false; n];
        for &s in &sources {
            is_source[s as usize] = true;
        }
        let view = self.view;
        let stop_t0 = sel.attack || sel.azure_attack;
        let stop = |x: NodeRef| stop_t0 && view.matches_label(x, TIER_ZERO);
        // Few sources: search forward from each first, and look only at
        // the targets one reaches, each until the sources that reach it are
        // found.
        let mut reaching: Option<Vec<Vec<bool>>> = None;
        if sources.len() <= FEW_SOURCES && sources.len() < targets.len() {
            let mut trees = Vec::with_capacity(sources.len());
            for &s in &sources {
                let mut timed_out = false;
                let tree = self
                    .view
                    .shortest_tree(s, dir.flip(), &sel, max, &stop, &mut |_| {
                        timed_out = timed_out || Instant::now() >= self.deadline;
                        timed_out
                    });
                if timed_out {
                    self.truncated = true;
                    self.timed_out = true;
                    return Ok(());
                }
                trees.push(
                    targets
                        .iter()
                        .map(|&t| tree.reaches(NodeIndex::new(t as usize)))
                        .collect::<Vec<bool>>(),
                );
            }
            let keep: Vec<bool> = (0..targets.len())
                .map(|i| trees.iter().any(|r| r[i]))
                .collect();
            let mut i = 0;
            targets.retain(|_| {
                i += 1;
                keep[i - 1]
            });
            let kept: Vec<usize> = (0..keep.len()).filter(|&i| keep[i]).collect();
            reaching = Some(
                kept.iter()
                    .map(|&i| trees.iter().map(|r| r[i]).collect())
                    .collect(),
            );
        }
        let same_var = src_np.var.is_some() && src_np.var == tgt_np.var;
        for (ti, &t) in targets.iter().enumerate() {
            if self.out_of_time() {
                return Ok(());
            }
            // Sources to find before the search can stop.
            let want = match &reaching {
                Some(r) => r[ti].iter().filter(|&&b| b).count(),
                None => sources.len(),
            };
            let mut order = Vec::new();
            let mut found = 0;
            let deadline = self.deadline;
            let mut timed_out = false;
            let tree = self.view.shortest_tree(t, dir, &sel, max, &stop, &mut |x| {
                order.push(x);
                if is_source[x as usize] {
                    found += 1;
                }
                timed_out = timed_out || (order.len() % 256 == 0 && Instant::now() >= deadline);
                found >= want || timed_out
            });
            if timed_out {
                self.truncated = true;
                self.timed_out = true;
                return Ok(());
            }
            let mut layers = Layers {
                tree: &tree,
                root: t,
                dir,
                sel: &sel,
                stop_t0,
                closer: Default::default(),
            };
            for s in order {
                if !is_source[s as usize] || (s == t && min > 0) || (same_var && s != t) {
                    continue;
                }
                let mut binds = bind(src_np, s);
                if !same_var {
                    binds.extend(bind(tgt_np, t));
                }
                let stop = match kind {
                    Shortest::One => {
                        let path = tree_path(&tree, s);
                        self.emit_path(s, path, binds, flipped)?
                    }
                    Shortest::All => self.all_shortest(&mut layers, s, binds, flipped)?,
                };
                if stop {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// A row for the path `edges` from `s`, put back in the pattern's order
    /// when the search ran against it.
    fn emit_path(
        &mut self,
        s: NodeRef,
        edges: Vec<EdgeId>,
        binds: Vec<(String, NodeRef)>,
        flipped: bool,
    ) -> Flow {
        let mut nodes = vec![s];
        for &e in &edges {
            let (a, b) = self.view.edge_ends(e);
            let cur = nodes[nodes.len() - 1];
            nodes.push(if a == cur { b } else { a });
        }
        let st = State {
            nodes,
            edges,
            binds,
        };
        self.emit(&st, flipped)
    }

    /// Every shortest path from `s` to `t` in the tree's layers: each step
    /// goes one layer closer to `t`.
    fn all_shortest(
        &mut self,
        layers: &mut Layers,
        s: NodeRef,
        binds: Vec<(String, NodeRef)>,
        flipped: bool,
    ) -> Flow {
        let mut edges = Vec::new();
        // Depth-first over the layers, with an explicit stack of the
        // choices left at each layer.
        let mut stack: Vec<Vec<(EdgeId, NodeRef)>> = vec![layers.closer(self.view, s)];
        let mut cur = vec![s];
        while let Some(choices) = stack.last_mut() {
            if self.tick() {
                return Ok(true);
            }
            let here = cur[cur.len() - 1];
            if here == layers.root {
                if self.emit_path(s, edges.clone(), binds.clone(), flipped)? {
                    return Ok(true);
                }
                stack.pop();
                cur.pop();
                edges.pop();
                continue;
            }
            match choices.pop() {
                Some((e, x)) => {
                    edges.push(e);
                    cur.push(x);
                    stack.push(layers.closer(self.view, x));
                }
                None => {
                    stack.pop();
                    cur.pop();
                    edges.pop();
                }
            }
        }
        Ok(false)
    }

    /// Evaluates a WHERE expression to a [`Value`].
    fn eval(&self, e: &Expr, env: &Env) -> Result<Value, EvalError> {
        Ok(match e {
            Expr::Literal(v) => v.clone(),
            Expr::Property { var, key } => match env.get(var) {
                Some(h) => self.view.prop(h, key),
                None => return Err(EvalError::UnboundVariable(var.clone())),
            },
            Expr::HasLabels { var, labels } => match env.get(var) {
                Some(h) => Value::Bool(labels.iter().all(|l| self.view.matches_label(h, l))),
                None => return Err(EvalError::UnboundVariable(var.clone())),
            },
            Expr::Func { func, args } => {
                let mut vals = Vec::with_capacity(args.len());
                for a in args {
                    if let Expr::Variable(v) = a {
                        return Err(node_as_value(v));
                    }
                    vals.push(self.eval(a, env)?);
                }
                match func {
                    Func::Coalesce => vals
                        .into_iter()
                        .find(|v| !v.is_null())
                        .unwrap_or(Value::Null),
                    Func::ToLower | Func::ToUpper => match vals.into_iter().next() {
                        Some(Value::Str(s)) if *func == Func::ToLower => {
                            Value::Str(s.to_lowercase())
                        }
                        Some(Value::Str(s)) => Value::Str(s.to_uppercase()),
                        Some(Value::Null) | None => Value::Null,
                        Some(other) => {
                            return Err(EvalError::Type(format!(
                                "{}() needs a string, found {}",
                                if *func == Func::ToLower {
                                    "toLower"
                                } else {
                                    "toUpper"
                                },
                                value::type_name(&other)
                            )))
                        }
                    },
                }
            }
            // A bound node is never null.
            Expr::IsNull { expr, negated } if matches!(**expr, Expr::Variable(_)) => {
                Value::Bool(*negated)
            }
            Expr::Variable(var) => return Err(node_as_value(var)),
            // Nodes compare by identity: `a <> b` (Neo4j). A node is never
            // equal to a value, and does not order.
            Expr::Compare { lhs, op, rhs }
                if matches!(**lhs, Expr::Variable(_)) || matches!(**rhs, Expr::Variable(_)) =>
            {
                let side = |e: &Expr| -> Result<Result<NodeRef, Value>, EvalError> {
                    match e {
                        Expr::Variable(v) => env
                            .get(v)
                            .map(Ok)
                            .ok_or_else(|| EvalError::UnboundVariable(v.clone())),
                        other => Ok(Err(self.eval(other, env)?)),
                    }
                };
                let eq = match (side(lhs)?, side(rhs)?) {
                    (Ok(a), Ok(b)) => Some(a == b),
                    (Err(Value::Null), _) | (_, Err(Value::Null)) => None,
                    _ => Some(false),
                };
                match op {
                    CompOp::Eq => eq.map(Value::Bool).unwrap_or(Value::Null),
                    CompOp::Neq => eq.map(|e| Value::Bool(!e)).unwrap_or(Value::Null),
                    _ => Value::Null,
                }
            }
            Expr::Compare { lhs, op, rhs } => {
                let l = self.eval(lhs, env)?;
                let r = self.eval(rhs, env)?;
                // Equality is false across types; ordering is null.
                let b = match op {
                    CompOp::Eq => value::equals(&l, &r),
                    CompOp::Neq => value::equals(&l, &r).map(|e| !e),
                    _ => value::compare(&l, &r).map(|ord| {
                        use std::cmp::Ordering::*;
                        match op {
                            CompOp::Lt => ord == Less,
                            CompOp::Gt => ord == Greater,
                            CompOp::Lte => ord != Greater,
                            _ => ord != Less,
                        }
                    }),
                };
                b.map(Value::Bool).unwrap_or(Value::Null)
            }
            Expr::StringOp { lhs, op, rhs } => {
                let l = self.eval(lhs, env)?;
                let r = self.eval(rhs, env)?;
                match (l, r) {
                    (Value::Str(a), Value::Str(b)) => {
                        // Case-sensitive, no wildcards — BHE semantics.
                        let b = match op {
                            StringOp::Contains => a.contains(&b),
                            StringOp::StartsWith => a.starts_with(&b),
                            StringOp::EndsWith => a.ends_with(&b),
                        };
                        Value::Bool(b)
                    }
                    _ => Value::Null,
                }
            }
            Expr::IsNull { expr, negated } => {
                let v = self.eval(expr, env)?;
                Value::Bool(v.is_null() != *negated)
            }
            // Cypher's three-valued (Kleene) logic: null is "unknown", so
            // `NOT null` is null (the row is dropped), `false AND null` is
            // false and `true OR null` is true.
            Expr::And(a, b) => match (
                truth(&self.eval(a, env)?, "AND")?,
                truth(&self.eval(b, env)?, "AND")?,
            ) {
                (Some(false), _) | (_, Some(false)) => Value::Bool(false),
                (Some(true), Some(true)) => Value::Bool(true),
                _ => Value::Null,
            },
            Expr::Or(a, b) => match (
                truth(&self.eval(a, env)?, "OR")?,
                truth(&self.eval(b, env)?, "OR")?,
            ) {
                (Some(true), _) | (_, Some(true)) => Value::Bool(true),
                (Some(false), Some(false)) => Value::Bool(false),
                _ => Value::Null,
            },
            Expr::Not(a) => match truth(&self.eval(a, env)?, "NOT")? {
                Some(b) => Value::Bool(!b),
                None => Value::Null,
            },
        })
    }
}

/// One search's layers, for `allShortestPaths`: how far each node is from
/// the root, and, worked out once per node, its relationships one layer
/// closer.
struct Layers<'t> {
    tree: &'t crate::analysis::ReachTree,
    root: NodeRef,
    dir: Direction,
    sel: &'t TypeSel,
    /// Attack-path types: no path passes through a Tier Zero object.
    stop_t0: bool,
    closer: std::collections::HashMap<NodeRef, Vec<(EdgeId, NodeRef)>>,
}

impl Layers<'_> {
    fn depth(&self, n: NodeRef) -> Option<u32> {
        self.tree.depth(NodeIndex::new(n as usize))
    }

    /// The relationships from `n` one layer closer to the root, last first
    /// (they are popped).
    fn closer(&mut self, view: &dyn GraphView, n: NodeRef) -> Vec<(EdgeId, NodeRef)> {
        if let Some(v) = self.closer.get(&n) {
            return v.clone();
        }
        let v = match self.depth(n) {
            None | Some(0) => Vec::new(),
            Some(d) => {
                let mut v: Vec<(EdgeId, NodeRef)> = view
                    .edges(n, self.dir, self.sel)
                    .into_iter()
                    .filter(|&(_, x)| self.depth(x) == Some(d - 1))
                    .filter(|&(_, x)| {
                        x == self.root || !self.stop_t0 || !view.matches_label(x, TIER_ZERO)
                    })
                    .collect();
                v.reverse();
                v
            }
        };
        self.closer.insert(n, v.clone());
        v
    }
}

/// The virtual label of Tier Zero objects.
const TIER_ZERO: &str = "Tag_Tier_Zero";

/// Up to this many sources, `shortestPath` first searches forward from
/// each, to skip the targets none of them reaches.
const FEW_SOURCES: usize = 64;

/// The edges of `s`'s path to the tree's root.
fn tree_path(tree: &crate::analysis::ReachTree, s: NodeRef) -> Vec<EdgeId> {
    tree.path(NodeIndex::new(s as usize))
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.index() as EdgeId)
        .collect()
}

/// A value as a truth value: a boolean, or `None` for null (unknown).
/// Anything else is a type error where a boolean is needed (`WHERE 1`,
/// `n.name AND true`), as in Neo4j.
fn truth(v: &Value, what: &str) -> Result<Option<bool>, EvalError> {
    match v {
        Value::Bool(b) => Ok(Some(*b)),
        Value::Null => Ok(None),
        other => Err(EvalError::Type(format!(
            "{what} needs a boolean, found {}",
            value::type_name(other)
        ))),
    }
}

/// Binds a single node pattern's variable (if any) to a handle.
fn bind(np: &NodePattern, h: NodeRef) -> Vec<(String, NodeRef)> {
    match &np.var {
        Some(v) => vec![(v.clone(), h)],
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::lexer::lex;
    use super::super::parser::parse;
    use super::super::view::AdGraphView;
    use super::*;
    use crate::graph::AdGraph;
    use crate::model::{EdgeKind, Node, NodeKind};

    /// A tiny hand-built graph: two users (one Kerberoastable), one group, and
    /// a MemberOf edge from the Kerberoastable user to the group.
    fn tiny() -> AdGraph {
        let mut g = AdGraph::new();
        let mut spn = Node::placeholder("S-1-5-21-1-1-1101".into(), NodeKind::User);
        spn.placeholder = false;
        spn.name = "SVC@EXAMPLE.LOCAL".into();
        spn.props.name = Some(spn.name.clone());
        spn.props.hasspn = Some(true);
        spn.props.enabled = Some(true);
        let spn_ix = g.upsert(spn);

        let mut plain = Node::placeholder("S-1-5-21-1-1-1102".into(), NodeKind::User);
        plain.placeholder = false;
        plain.name = "ALICE@EXAMPLE.LOCAL".into();
        plain.props.hasspn = Some(false);
        plain.props.enabled = Some(true);
        g.upsert(plain);

        let mut grp = Node::placeholder("S-1-5-21-1-1-512".into(), NodeKind::Group);
        grp.placeholder = false;
        grp.name = "DOMAIN ADMINS@EXAMPLE.LOCAL".into();
        grp.tier_zero = true;
        let grp_ix = g.upsert(grp);

        g.add_edge(spn_ix, grp_ix, EdgeKind::MemberOf);
        g
    }

    fn run_ids(g: &AdGraph, src: &str) -> BTreeSet<String> {
        let view = AdGraphView::new(g);
        let q = parse(lex(src).unwrap()).unwrap();
        let r = evaluate(&view, &q, &EvalLimits::default()).unwrap();
        r.node_ids()
    }

    #[test]
    fn not_of_null_drops_the_row() {
        // Groups have no `enabled`: `null = true` is null and `NOT null` is
        // null, so nothing matches (it returned every group).
        let g = tiny();
        assert!(run_ids(&g, "MATCH (n:Group) WHERE NOT n.enabled = true RETURN n").is_empty());
        // false AND null is false; true OR null is true.
        assert!(run_ids(
            &g,
            "MATCH (n:Group) WHERE false AND n.enabled = true RETURN n"
        )
        .is_empty());
        assert_eq!(
            run_ids(
                &g,
                "MATCH (n:Group) WHERE true OR n.enabled = true RETURN n"
            )
            .len(),
            1
        );
    }

    #[test]
    fn a_repeated_variable_means_the_same_node() {
        let g = tiny();
        assert!(run_ids(&g, "MATCH (a)-[:MemberOf]->(a) RETURN a").is_empty());
        assert_eq!(run_ids(&g, "MATCH (a)-[:MemberOf]->(b) RETURN a").len(), 1);
    }

    #[test]
    fn unsupported_shapes_are_errors_not_empty_results() {
        for q in ["MATCH (a)-->(b) RETURN a", "MATCH (a)-[]->(b) RETURN a"] {
            assert!(parse(lex(q).unwrap()).is_err(), "{q}");
        }
        // The evaluator refuses an untyped relationship too, whoever built
        // the query.
        let mut q = parse(lex("MATCH (a)-[:MemberOf]->(b) RETURN a").unwrap()).unwrap();
        q.pattern.hops[0].0.types.clear();
        let g = tiny();
        let err = evaluate(&AdGraphView::new(&g), &q, &EvalLimits::default()).unwrap_err();
        assert!(matches!(err, EvalError::Unsupported(_)));
        let deep = format!(
            "MATCH (n) WHERE {}true{} RETURN n",
            "(".repeat(1000),
            ")".repeat(1000)
        );
        assert!(parse(lex(&deep).unwrap()).is_err());
        let nots = format!("MATCH (n) WHERE {}true RETURN n", "NOT ".repeat(5000));
        assert!(parse(lex(&nots).unwrap()).is_err());
    }

    #[test]
    fn a_huge_timeout_does_not_overflow() {
        let g = tiny();
        let view = AdGraphView::new(&g);
        let q = parse(lex("MATCH (n:User) RETURN n").unwrap()).unwrap();
        let limits = EvalLimits {
            timeout: Duration::from_secs(u64::MAX),
            ..EvalLimits::default()
        };
        assert_eq!(evaluate(&view, &q, &limits).unwrap().node_ids().len(), 2);
    }

    #[test]
    fn label_match_returns_all_of_a_kind() {
        let g = tiny();
        let ids = run_ids(&g, "MATCH (n:User) RETURN n");
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("S-1-5-21-1-1-1101"));
        assert!(ids.contains("S-1-5-21-1-1-1102"));
    }

    #[test]
    fn base_superlabel_matches_every_native_node() {
        let g = tiny();
        let ids = run_ids(&g, "MATCH (n:Base) RETURN n");
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn tier_zero_virtual_label() {
        let g = tiny();
        let ids = run_ids(&g, "MATCH (n:Tag_Tier_Zero) RETURN n");
        assert_eq!(ids, BTreeSet::from(["S-1-5-21-1-1-512".to_string()]));
    }

    #[test]
    fn where_bool_filter_is_kerberoastable() {
        let g = tiny();
        let ids = run_ids(&g, "MATCH (n:User) WHERE n.hasspn = true RETURN n");
        assert_eq!(ids, BTreeSet::from(["S-1-5-21-1-1-1101".to_string()]));
    }

    #[test]
    fn where_strict_typing_rejects_text_for_bool() {
        let g = tiny();
        // "true" is text, not the boolean — BHE strict typing means no match.
        let ids = run_ids(&g, r#"MATCH (n:User) WHERE n.hasspn = "true" RETURN n"#);
        assert!(ids.is_empty());
    }

    #[test]
    fn cross_type_equality_is_false_not_null() {
        let g = tiny();
        // Both users have a boolean hasspn: = "true" is false, so NOT of it
        // and <> are true for both (they were null, and matched nothing).
        assert!(run_ids(&g, r#"MATCH (n:User) WHERE n.hasspn = "true" RETURN n"#).is_empty());
        assert_eq!(
            run_ids(&g, r#"MATCH (n:User) WHERE NOT n.hasspn = "true" RETURN n"#).len(),
            2
        );
        assert_eq!(
            run_ids(&g, r#"MATCH (n:User) WHERE n.hasspn <> "true" RETURN n"#).len(),
            2
        );
        assert_eq!(
            run_ids(&g, "MATCH (n:User) WHERE 1 <> '1' RETURN n").len(),
            2
        );
        assert!(run_ids(&g, "MATCH (n:User) WHERE 1 = '1' RETURN n").is_empty());
        // Ordering across types is null either way round.
        assert!(run_ids(&g, "MATCH (n:User) WHERE n.hasspn < 1 RETURN n").is_empty());
        assert!(run_ids(&g, "MATCH (n:User) WHERE NOT n.hasspn < 1 RETURN n").is_empty());
        // Groups have no hasspn: null = / <> anything is null.
        assert!(run_ids(&g, "MATCH (n:Group) WHERE n.hasspn <> true RETURN n").is_empty());
        assert!(run_ids(&g, "MATCH (n:Group) WHERE NOT n.hasspn = 'x' RETURN n").is_empty());
        // Inline property maps use the same equality.
        assert_eq!(
            run_ids(&g, "MATCH (n:User {hasspn: true}) RETURN n").len(),
            1
        );
        assert!(run_ids(&g, "MATCH (n:User {hasspn: 'true'}) RETURN n").is_empty());
    }

    #[test]
    fn where_string_equality_case_sensitive() {
        let g = tiny();
        let ok = run_ids(
            &g,
            r#"MATCH (n:User) WHERE n.name = "SVC@EXAMPLE.LOCAL" RETURN n"#,
        );
        assert_eq!(ok.len(), 1);
        let wrong_case = run_ids(
            &g,
            r#"MATCH (n:User) WHERE n.name = "svc@example.local" RETURN n"#,
        );
        assert!(wrong_case.is_empty());
    }

    #[test]
    fn relationship_pattern_over_raw_adjacency() {
        let g = tiny();
        let view = AdGraphView::new(&g);
        let q = parse(lex("MATCH (a)-[:MemberOf]->(b) RETURN a, b").unwrap()).unwrap();
        let r = evaluate(&view, &q, &EvalLimits::default()).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(
            r.relationships,
            vec![(
                "S-1-5-21-1-1-1101".to_string(),
                "MemberOf".to_string(),
                "S-1-5-21-1-1-512".to_string()
            )]
        );
        // RETURN a, b projects both node ids.
        assert_eq!(r.node_ids().len(), 2);
    }

    #[test]
    fn relationship_types_are_case_sensitive() {
        // As in Neo4j and BHE: a type spelled differently is another type,
        // which this graph does not have.
        let g = tiny();
        assert_eq!(run_ids(&g, "MATCH (a)-[:MemberOf]->(b) RETURN a").len(), 1);
        assert!(run_ids(&g, "MATCH (a)-[:memberof]->(b) RETURN a").is_empty());
        assert!(run_ids(&g, "MATCH (a)-[:MEMBEROF]->(b) RETURN a").is_empty());
        assert_eq!(
            run_ids(&g, "MATCH (a)-[:memberof|MemberOf]->(b) RETURN a").len(),
            1
        );
    }

    #[test]
    fn relationship_direction_left() {
        let g = tiny();
        let view = AdGraphView::new(&g);
        let q = parse(lex("MATCH (g)<-[:MemberOf]-(u) RETURN g, u").unwrap()).unwrap();
        let r = evaluate(&view, &q, &EvalLimits::default()).unwrap();
        // Same single edge, viewed from the group side.
        assert_eq!(
            r.relationships,
            vec![(
                "S-1-5-21-1-1-1101".to_string(),
                "MemberOf".to_string(),
                "S-1-5-21-1-1-512".to_string()
            )]
        );
    }

    #[test]
    fn limit_is_the_answer_not_a_truncation() {
        let g = tiny();
        let view = AdGraphView::new(&g);
        let q = parse(lex("MATCH (n:User) RETURN n LIMIT 1").unwrap()).unwrap();
        let r = evaluate(&view, &q, &EvalLimits::default()).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert!(!r.truncated);
        let q = parse(lex("MATCH (n:User) RETURN n LIMIT 0").unwrap()).unwrap();
        assert!(evaluate(&view, &q, &EvalLimits::default())
            .unwrap()
            .rows
            .is_empty());
    }

    /// Three users, each a member of one group.
    fn fan() -> AdGraph {
        let mut g = AdGraph::new();
        let grp = g.upsert(Node::placeholder(
            "S-1-5-21-1-1-512".into(),
            NodeKind::Group,
        ));
        for rid in 1101..1104 {
            let u = g.upsert(Node::placeholder(
                format!("S-1-5-21-1-1-{rid}"),
                NodeKind::User,
            ));
            g.add_edge(u, grp, EdgeKind::MemberOf);
        }
        g
    }

    fn run_with(g: &AdGraph, src: &str, max_rows: usize) -> QueryResult {
        let view = AdGraphView::new(g);
        let q = parse(lex(src).unwrap()).unwrap();
        let limits = EvalLimits {
            max_rows,
            ..EvalLimits::default()
        };
        evaluate(&view, &q, &limits).unwrap()
    }

    #[test]
    fn limit_and_the_row_cap_bound_relationships_too() {
        let g = fan();
        let all = run_with(&g, "MATCH (u)-[:MemberOf]->(g) RETURN u", 100);
        assert_eq!((all.rows.len(), all.relationships.len()), (3, 3));
        assert!(!all.truncated);
        // LIMIT: one row, its one relationship, complete.
        let r = run_with(&g, "MATCH (u)-[:MemberOf]->(g) RETURN u LIMIT 1", 100);
        assert_eq!((r.rows.len(), r.relationships.len()), (1, 1));
        assert!(!r.truncated);
        // The row cap: two rows, their two relationships, truncated.
        let r = run_with(&g, "MATCH (u)-[:MemberOf]->(g) RETURN u", 2);
        assert_eq!((r.rows.len(), r.relationships.len()), (2, 2));
        assert!(r.truncated);
        // A cap the answer fits exactly is not a truncation.
        let r = run_with(&g, "MATCH (u)-[:MemberOf]->(g) RETURN u", 3);
        assert_eq!((r.rows.len(), r.relationships.len()), (3, 3));
        assert!(!r.truncated);
        // DISTINCT folds the rows, not the relationships they went through.
        let r = run_with(&g, "MATCH (u)-[:MemberOf]->(g) RETURN DISTINCT g", 100);
        assert_eq!((r.rows.len(), r.relationships.len()), (1, 3));
        assert!(!r.truncated);
        // ... up to the row cap; the rows are still complete.
        let r = run_with(&g, "MATCH (u)-[:MemberOf]->(g) RETURN DISTINCT g", 2);
        assert_eq!((r.rows.len(), r.relationships.len()), (1, 2));
        assert!(!r.truncated && r.relationships_truncated);
        let r = run_with(&g, "MATCH (u)-[:MemberOf]->(g) RETURN DISTINCT g", 3);
        assert_eq!((r.rows.len(), r.relationships.len()), (1, 3));
        assert!(!r.truncated && !r.relationships_truncated);
    }

    /// A full relationship budget must not stop the rows: two groups of
    /// three members, `RETURN DISTINCT g` under a cap of 2 still finds both
    /// groups, and keeps at most 2 relationships.
    #[test]
    fn a_full_relationship_budget_does_not_drop_rows() {
        let mut g = fan();
        let grp = g.upsert(Node::placeholder(
            "S-1-5-21-1-1-513".into(),
            NodeKind::Group,
        ));
        for rid in 1201..1204 {
            let u = g.upsert(Node::placeholder(
                format!("S-1-5-21-1-1-{rid}"),
                NodeKind::User,
            ));
            g.add_edge(u, grp, EdgeKind::MemberOf);
        }
        let r = run_with(&g, "MATCH (u)-[:MemberOf]->(g) RETURN DISTINCT g", 2);
        assert_eq!((r.rows.len(), r.relationships.len()), (2, 2));
        assert!(!r.truncated && r.relationships_truncated);
        // Without DISTINCT the rows hit the cap first.
        let r = run_with(&g, "MATCH (u)-[:MemberOf]->(g) RETURN u", 5);
        assert_eq!((r.rows.len(), r.relationships.len()), (5, 5));
        assert!(r.truncated);
    }

    #[test]
    fn limit_above_the_cap_is_truncated() {
        let g = fan();
        let r = run_with(&g, "MATCH (u)-[:MemberOf]->(g) RETURN u LIMIT 3", 2);
        assert_eq!(r.rows.len(), 2);
        assert!(r.truncated);
        let r = run_with(&g, "MATCH (u)-[:MemberOf]->(g) RETURN u LIMIT 2", 2);
        assert_eq!(r.rows.len(), 2);
        assert!(!r.truncated);
    }

    #[test]
    fn node_match_cap_exact_fit_is_not_truncated() {
        let g = fan();
        assert!(!run_with(&g, "MATCH (n:User) RETURN n", 3).truncated);
        assert!(run_with(&g, "MATCH (n:User) RETURN n", 2).truncated);
    }

    /// Counts property reads, to see how far matching went.
    struct Counting<'a> {
        inner: AdGraphView<'a>,
        props: std::cell::Cell<usize>,
    }

    impl GraphView for Counting<'_> {
        fn node_handles(&self) -> Vec<NodeRef> {
            self.inner.node_handles()
        }
        fn objectid(&self, n: NodeRef) -> String {
            self.inner.objectid(n)
        }
        fn matches_label(&self, n: NodeRef, l: &str) -> bool {
            self.inner.matches_label(n, l)
        }
        fn prop(&self, n: NodeRef, k: &str) -> Value {
            self.props.set(self.props.get() + 1);
            self.inner.prop(n, k)
        }
        fn canonical_rel_type(&self, t: &str) -> Option<String> {
            self.inner.canonical_rel_type(t)
        }
        fn type_sel(&self, types: &[String]) -> TypeSel {
            self.inner.type_sel(types)
        }
        fn edges(&self, n: NodeRef, dir: Direction, sel: &TypeSel) -> Vec<(EdgeId, NodeRef)> {
            self.inner.edges(n, dir, sel)
        }
        fn edge_kind(&self, e: EdgeId) -> crate::model::EdgeKind {
            self.inner.edge_kind(e)
        }
        fn name(&self, n: NodeRef) -> String {
            self.inner.name(n)
        }
        fn kind(&self, n: NodeRef) -> crate::model::NodeKind {
            self.inner.kind(n)
        }
        fn edge_ends(&self, e: EdgeId) -> (NodeRef, NodeRef) {
            self.inner.edge_ends(e)
        }
        fn shortest_tree(
            &self,
            root: NodeRef,
            dir: Direction,
            sel: &TypeSel,
            max_depth: Option<u32>,
            stop: &dyn Fn(NodeRef) -> bool,
            visit: &mut dyn FnMut(NodeRef) -> bool,
        ) -> crate::analysis::ReachTree {
            self.inner
                .shortest_tree(root, dir, sel, max_depth, stop, visit)
        }
    }

    #[test]
    fn limit_stops_matching_once_it_has_its_rows() {
        let g = fan();
        let v = Counting {
            inner: AdGraphView::new(&g),
            props: Default::default(),
        };
        let q =
            parse(lex("MATCH (n:User) WHERE n.enabled IS NULL RETURN n LIMIT 1").unwrap()).unwrap();
        let r = evaluate(&v, &q, &EvalLimits::default()).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(v.props.get(), 1, "evaluated WHERE past the LIMIT");
    }

    #[test]
    fn a_type_named_twice_is_walked_once() {
        let g = fan();
        let r = run_with(&g, "MATCH (u)-[:MemberOf|MemberOf]->(g) RETURN u", 100);
        assert_eq!(r.rows.len(), 3);
    }

    fn eval_err(src: &str) -> EvalError {
        let g = tiny();
        let view = AdGraphView::new(&g);
        let q = parse(lex(src).unwrap()).unwrap();
        evaluate(&view, &q, &EvalLimits::default()).unwrap_err()
    }

    #[test]
    fn what_neo4j_refuses_is_an_error_not_an_empty_result() {
        // A variable the pattern doesn't bind (Neo4j: "Variable not defined").
        for q in [
            "MATCH (n:User) WHERE m.name = 'x' RETURN n",
            "MATCH (n:User) WHERE NOT m.enabled RETURN n",
            "MATCH (n:User) RETURN m",
        ] {
            assert_eq!(eval_err(q), EvalError::UnboundVariable("m".into()), "{q}");
        }
        // A non-boolean where one is needed, or a node where a value is.
        for q in [
            "MATCH (n:User) WHERE 1 RETURN n",
            "MATCH (n:User) WHERE n RETURN n",
            "MATCH (n:User) WHERE n.name RETURN n",
            "MATCH (n:User) WHERE n.name AND true RETURN n",
            "MATCH (n:User) WHERE NOT 'x' RETURN n",
            // Even where no node reaches the WHERE.
            "MATCH (n:NoSuch) WHERE 1 RETURN n",
            "MATCH (n:NoSuch) WHERE n RETURN n",
            "MATCH (n:NoSuch) WHERE NOT 1 RETURN n",
            "MATCH (n:NoSuch) WHERE true AND 'x' RETURN n",
        ] {
            assert!(matches!(eval_err(q), EvalError::Type(_)), "{q}");
        }
        // Nodes compare by identity; a node is never equal to a value.
        let g = tiny();
        assert_eq!(
            run_ids(&g, "MATCH (a)-[:MemberOf]-(b) WHERE a <> b RETURN a").len(),
            2
        );
        assert!(run_ids(&g, "MATCH (a)-[:MemberOf]-(b) WHERE a = b RETURN a").is_empty());
        assert!(run_ids(&g, "MATCH (n:User) WHERE n = 1 RETURN n").is_empty());
        assert_eq!(run_ids(&g, "MATCH (n:User) WHERE n <> 1 RETURN n").len(), 2);
        assert!(run_ids(&g, "MATCH (n:User) WHERE n <> null RETURN n").is_empty());
        // A bound node is never null.
        assert_eq!(
            run_ids(&g, "MATCH (n:User) WHERE n IS NOT NULL RETURN n").len(),
            2
        );
        assert!(run_ids(&g, "MATCH (n:User) WHERE n IS NULL RETURN n").is_empty());
    }

    #[test]
    fn inline_maps_take_literals_and_negative_numbers() {
        assert!(
            parse(lex("MATCH (a)-[:MemberOf]->(g {domain: a.domain}) RETURN g").unwrap()).is_err()
        );
        let mut g = tiny();
        let ix = g.lookup("S-1-5-21-1-1-1102").unwrap();
        g.node_mut(ix).props.pwdlastset = Some(-1);
        assert_eq!(
            run_ids(&g, "MATCH (n:User) WHERE n.pwdlastset = -1 RETURN n").len(),
            1
        );
        assert_eq!(
            run_ids(&g, "MATCH (n:User {pwdlastset: -1}) RETURN n").len(),
            1
        );
        assert!(run_ids(&g, "MATCH (n:User) WHERE n.pwdlastset < -1.5 RETURN n").is_empty());
        assert_eq!(
            run_ids(
                &g,
                "MATCH (n:User) WHERE n.pwdlastset > -9223372036854775808 RETURN n"
            )
            .len(),
            1
        );
        assert_eq!(
            run_ids(&g, "MATCH (n:User) WHERE n.pwdlastset < 1.8e19 RETURN n").len(),
            1
        );
        assert!(parse(lex("MATCH (n) WHERE n.x = 9223372036854775808 RETURN n").unwrap()).is_err());
        assert!(
            parse(lex("MATCH (n) WHERE n.x = - 9223372036854775808 RETURN n").unwrap()).is_err()
        );
    }

    #[test]
    fn a_wrong_case_says_what_it_probably_meant() {
        let g = tiny();
        let view = AdGraphView::new(&g);
        let q = parse(lex("MATCH (a:user)-[:memberof]->(b) RETURN a").unwrap()).unwrap();
        let r = evaluate(&view, &q, &EvalLimits::default()).unwrap();
        assert!(r.rows.is_empty());
        assert_eq!(r.warnings.len(), 2, "{:?}", r.warnings);
        assert!(r.warnings[0].contains("did you mean User?"));
        assert!(r.warnings[1].contains("did you mean MemberOf?"));
        let q = parse(lex("MATCH (a:User)-[:MemberOf]->(b) RETURN a").unwrap()).unwrap();
        assert!(evaluate(&view, &q, &EvalLimits::default())
            .unwrap()
            .warnings
            .is_empty());
    }

    #[test]
    fn max_rows_cap_marks_truncated() {
        let g = tiny();
        let view = AdGraphView::new(&g);
        let limits = EvalLimits {
            max_rows: 1,
            timeout: Duration::from_secs(10),
            ..EvalLimits::default()
        };
        let q = parse(lex("MATCH (n:User) RETURN n").unwrap()).unwrap();
        let r = evaluate(&view, &q, &limits).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert!(r.truncated);
    }

    #[test]
    fn unbound_return_variable_errors() {
        let g = tiny();
        let view = AdGraphView::new(&g);
        let q = parse(lex("MATCH (n:User) RETURN m").unwrap()).unwrap();
        let err = evaluate(&view, &q, &EvalLimits::default()).unwrap_err();
        assert!(matches!(err, EvalError::UnboundVariable(_)));
    }

    // ---- paths -------------------------------------------------------

    const U: &str = "S-1-5-21-1-1-1101";
    const U2: &str = "S-1-5-21-1-1-1102";
    const G1: &str = "S-1-5-21-1-1-1201";
    const G2: &str = "S-1-5-21-1-1-1202";
    const DA: &str = "S-1-5-21-1-1-512";
    const DC: &str = "S-1-5-21-1-1-1000";

    fn add(g: &mut AdGraph, id: &str, kind: NodeKind, tier_zero: bool) -> crate::NodeIndex {
        let mut n = Node::placeholder(id.into(), kind);
        n.placeholder = false;
        n.name = format!("{id}@EXAMPLE.LOCAL");
        n.props.name = Some(n.name.clone());
        n.tier_zero = tier_zero;
        g.upsert(n)
    }

    /// U -MemberOf-> G1 -MemberOf-> G2 -GenericAll-> DA (Tier Zero), with
    /// G2 -MemberOf-> G1 closing a cycle; U2 -MemberOf-> G2, and U2 can
    /// RDP into a domain controller (which attack paths skip).
    fn nested() -> AdGraph {
        let mut g = AdGraph::new();
        let u = add(&mut g, U, NodeKind::User, false);
        let u2 = add(&mut g, U2, NodeKind::User, false);
        let g1 = add(&mut g, G1, NodeKind::Group, false);
        let g2 = add(&mut g, G2, NodeKind::Group, false);
        let da = add(&mut g, DA, NodeKind::Group, true);
        let dc = add(&mut g, DC, NodeKind::Computer, true);
        g.node_mut(dc).is_dc = true;
        g.add_edge(u, g1, EdgeKind::MemberOf);
        g.add_edge(g1, g2, EdgeKind::MemberOf);
        g.add_edge(g2, g1, EdgeKind::MemberOf);
        g.add_edge(g2, da, EdgeKind::GenericAll);
        g.add_edge(u2, g2, EdgeKind::MemberOf);
        g.add_edge(u2, dc, EdgeKind::CanRdp);
        g
    }

    fn run_q(g: &AdGraph, src: &str) -> QueryResult {
        run_lim(g, src, &EvalLimits::default())
    }

    fn run_lim(g: &AdGraph, src: &str, limits: &EvalLimits) -> QueryResult {
        let view = AdGraphView::new(g);
        let q = parse(lex(src).unwrap()).unwrap();
        evaluate(&view, &q, limits).unwrap()
    }

    /// Each returned path as its node IDs, sorted.
    fn paths(r: &QueryResult) -> Vec<Vec<String>> {
        let mut v: Vec<Vec<String>> = r
            .paths()
            .map(|c| match c {
                Cell::Path { nodes, .. } => nodes.clone(),
                _ => unreachable!(),
            })
            .collect();
        v.sort();
        v
    }

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn variable_length_paths_use_each_relationship_once() {
        let g = nested();
        let r = run_q(&g, "MATCH p=(u:User)-[:MemberOf*1..]->(x:Group) RETURN p");
        // The cycle is walked once each way, then every edge is used.
        assert_eq!(
            paths(&r),
            vec![
                ids(&[U, G1]),
                ids(&[U, G1, G2]),
                ids(&[U, G1, G2, G1]),
                ids(&[U2, G2]),
                ids(&[U2, G2, G1]),
                ids(&[U2, G2, G1, G2]),
            ]
        );
        assert!(!r.truncated && r.hop_cap.is_none() && r.stopped.is_empty());
        // Every relationship of a path is reported.
        assert_eq!(r.relationships.len(), 4);
        let n = |q: &str| run_q(&g, q).rows.len();
        assert_eq!(n("MATCH p=(u:User)-[:MemberOf*..1]->(x) RETURN p"), 2);
        assert_eq!(n("MATCH p=(u:User)-[:MemberOf*2]->(x) RETURN p"), 2);
        assert_eq!(n("MATCH p=(u:User)-[:MemberOf*2..3]->(x) RETURN p"), 4);
        // Zero hops: the start itself, if it fits the end.
        assert_eq!(n("MATCH p=(u:User)-[:MemberOf*0..1]->(x:User) RETURN p"), 2);
        // Undirected: no relationship twice, so no walking back.
        assert_eq!(n("MATCH p=(u:User)-[:MemberOf*2]-(x:User) RETURN p"), 0);
        // The same in the other direction, anchored at the other end.
        assert_eq!(
            n(&format!(
                "MATCH p=(x:Group)<-[:MemberOf*1..]-(u:User) WHERE x.objectid = '{G2}' RETURN p"
            )),
            3
        );
    }

    #[test]
    fn a_path_reads_in_the_patterns_order() {
        let g = nested();
        let r = run_q(
            &g,
            &format!("MATCH p=(x:Group)<-[:MemberOf*..1]-(u:User) WHERE x.objectid = '{G1}' AND u.objectid = '{U}' RETURN p"),
        );
        let Cell::Path {
            nodes,
            relationships,
            edges,
            backward,
            ..
        } = &r.rows[0][0]
        else {
            panic!("a path")
        };
        assert!(*backward, "read with <-");
        assert_eq!(nodes, &ids(&[G1, U]));
        // The relationship keeps its stored direction.
        assert_eq!(
            relationships,
            &vec![Hop {
                src: U.into(),
                kind: "MemberOf".into(),
                tgt: G1.into()
            }]
        );
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn the_hop_cap_says_when_it_cut_paths() {
        let g = nested();
        let limits = EvalLimits {
            max_hops: 1,
            ..EvalLimits::default()
        };
        let r = run_lim(&g, "MATCH p=(u:User)-[:MemberOf*]->(x) RETURN p", &limits);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.hop_cap, Some(1));
        assert_eq!(
            r.stopped,
            vec!["Paths longer than 1 relationship were not followed: a variable-length relationship without an upper bound stops there.".to_string()]
        );
        // A lower bound past the cap: it stops at the lower bound, and says
        // that number.
        let r = run_lim(
            &g,
            "MATCH p=(u:User)-[:MemberOf*2..]->(x) RETURN p",
            &limits,
        );
        assert_eq!(r.hop_cap, Some(2));
        assert!(
            r.stopped[0].starts_with("Paths longer than 2 relationships were not followed"),
            "{:?}",
            r.stopped
        );
        // A bound the query wrote is its answer, not a cut.
        let r = run_lim(
            &g,
            "MATCH p=(u:User)-[:MemberOf*..1]->(x) RETURN p",
            &limits,
        );
        assert_eq!((r.rows.len(), r.hop_cap), (2, None));
        // Nothing past the cap: no note.
        let r = run_lim(&g, "MATCH p=(u:User)-[:GenericAll*]->(x) RETURN p", &limits);
        assert_eq!((r.rows.len(), r.hop_cap), (0, None));
    }

    #[test]
    fn a_written_bound_past_the_limit_is_refused_outside_shortest_path() {
        let g = nested();
        let view = AdGraphView::new(&g);
        let q = parse(lex("MATCH p=(u)-[:MemberOf*..30]->(x) RETURN p").unwrap()).unwrap();
        let err = evaluate(&view, &q, &EvalLimits::default()).unwrap_err();
        assert!(matches!(err, EvalError::Unsupported(_)), "{err}");
        assert!(err.to_string().contains("at most 25"));
        let q = parse(lex("MATCH p=shortestPath((u)-[:MemberOf*..30]->(x)) RETURN p").unwrap())
            .unwrap();
        assert!(evaluate(&view, &q, &EvalLimits::default()).is_ok());
        // A lower bound counts too: `*100000..` would recurse 100,000 deep.
        for (q, what) in [
            ("MATCH p=(u)-[:MemberOf*100000..]-(x) RETURN p", "not 100000"),
            ("MATCH p=(u)-[:MemberOf*26]->(x) RETURN p", "not 26"),
            // The whole chain: 25 + 25 + 1.
            (
                "MATCH p=(a)-[:MemberOf*..25]->(b)-[:MemberOf*..25]->(c)-[:AdminTo]->(d) RETURN p",
                "at most 50 relationships in all, not 51",
            ),
            // An unbounded * counts as the hop cap: 25 + 25 + 10.
            (
                "MATCH p=(a)-[:MemberOf*..25]->(b)-[:MemberOf*..25]->(c)-[:MemberOf*]->(d) RETURN p",
                "not 60",
            ),
        ] {
            let err = eval_err(q);
            assert!(matches!(err, EvalError::Unsupported(_)), "{q}: {err}");
            assert!(err.to_string().contains(what), "{q}: {err}");
            assert!(err.to_string().ends_with('.'), "{err}");
        }
        // Fifty-one fixed relationships.
        let long = format!("MATCH p=(a){} RETURN p", "-[:MemberOf]->()".repeat(51));
        assert!(eval_err(&long).to_string().contains("not 51"));
        let ok = format!("MATCH p=(a){} RETURN p", "-[:MemberOf]->()".repeat(50));
        let q = parse(lex(&ok).unwrap()).unwrap();
        assert!(evaluate(&view, &q, &EvalLimits::default()).is_ok());
        // shortestPath has no such limit: its search does not recurse.
        let q = parse(lex("MATCH p=shortestPath((u)-[:MemberOf*1..100000]-(x)) RETURN p").unwrap())
            .unwrap();
        assert!(evaluate(&view, &q, &EvalLimits::default()).is_ok());
    }

    #[test]
    fn returned_paths_are_bounded_by_their_relationships() {
        let g = nested();
        let limits = EvalLimits {
            max_path_steps: 3,
            ..EvalLimits::default()
        };
        let r = run_lim(
            &g,
            "MATCH p=(u:User)-[:MemberOf*1..]->(x) RETURN p",
            &limits,
        );
        // [U, G1] and [U, G1, G2] hold 3; the next would pass the cap.
        assert_eq!(r.rows.len(), 2);
        assert!(r.truncated && r.path_steps_capped && !r.timed_out);
        assert_eq!(
            r.stopped,
            vec![
                "Stopped at 3 relationships across the returned paths: there are more rows."
                    .to_string()
            ]
        );
        // Node rows hold none.
        let r = run_lim(&g, "MATCH (u:User)-[:MemberOf*1..]->(x) RETURN u", &limits);
        assert_eq!(r.rows.len(), 6);
        assert!(!r.truncated);
    }

    #[test]
    fn errors_are_sentences() {
        let e = super::super::run(
            &AdGraphView::new(&nested()),
            "MATCH (n) WITH n RETURN n",
            &EvalLimits::default(),
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "query not supported: WITH is not supported yet (position 10)."
        );
        assert!(eval_err("MATCH (n:User) RETURN m")
            .to_string()
            .starts_with("Variable 'm' is not defined"));
    }

    #[test]
    fn shortest_path_over_attack_edges_is_the_analysis_path() {
        let g = nested();
        let r = run_q(
            &g,
            "MATCH p=shortestPath((s:User)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero)) WHERE s<>t RETURN p",
        );
        // RDP into a domain controller is no attack path.
        assert_eq!(paths(&r), vec![ids(&[U, G1, G2, DA]), ids(&[U2, G2, DA])]);
        for row in &r.rows {
            let Cell::Path { nodes, edges, .. } = &row[0] else {
                panic!()
            };
            let from = g.lookup(&nodes[0]).unwrap();
            let to = g.lookup(nodes.last().unwrap()).unwrap();
            let want = crate::analysis::shortest_path(&g, from, to).unwrap();
            let want: Vec<EdgeId> = want.edges.iter().map(|e| e.index() as EdgeId).collect();
            assert_eq!(edges, &want);
        }
        // Named types are the raw edges, attack path or not.
        let r = run_q(
            &g,
            "MATCH p=shortestPath((s:User)-[:CanRDP*1..]->(t:Tag_Tier_Zero)) RETURN p",
        );
        assert_eq!(paths(&r), vec![ids(&[U2, DC])]);
        // `(t)<-[]-(s)`: the same search, the path read from t.
        let r = run_q(
            &g,
            "MATCH p=shortestPath((t:Group)<-[:AD_ATTACK_PATHS*1..]-(s:Base)) WHERE t.objectid ENDS WITH '-512' AND s<>t RETURN p",
        );
        assert_eq!(
            paths(&r),
            vec![
                ids(&[DA, G2]),
                ids(&[DA, G2, U2]),
                ids(&[DA, G2, G1]),
                ids(&[DA, G2, G1, U])
            ]
        );
    }

    /// User -> group -> Tier Zero domain, which has rights on Domain Admins
    /// (Tier Zero) and on a user who is not.
    fn through_tier_zero() -> AdGraph {
        let mut g = AdGraph::new();
        let u = add(&mut g, U, NodeKind::User, false);
        let grp = add(&mut g, G1, NodeKind::Group, false);
        let dom = add(&mut g, "S-1-5-21-1-1", NodeKind::Domain, true);
        let da = add(&mut g, DA, NodeKind::Group, true);
        let other = add(&mut g, U2, NodeKind::User, false);
        g.add_edge(u, grp, EdgeKind::MemberOf);
        g.add_edge(grp, dom, EdgeKind::GenericAll);
        g.add_edge(dom, da, EdgeKind::GenericAll);
        g.add_edge(dom, other, EdgeKind::GenericAll);
        g
    }

    #[test]
    fn a_path_to_tier_zero_ends_at_the_first_tier_zero_object() {
        let g = through_tier_zero();
        let dom = "S-1-5-21-1-1";
        for f in ["shortestPath", "allShortestPaths"] {
            let r = run_q(
                &g,
                &format!("MATCH p={f}((s:User)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero)) WHERE s<>t RETURN p"),
            );
            assert_eq!(paths(&r), vec![ids(&[U, G1, dom])], "{f}");
            // Read from the target, the same.
            let r = run_q(
                &g,
                &format!("MATCH p={f}((t:Tag_Tier_Zero)<-[:AD_ATTACK_PATHS*1..]-(s:User)) WHERE s<>t RETURN p"),
            );
            assert_eq!(paths(&r), vec![ids(&[dom, G1, U])], "{f}");
            // Domain Admins by its ID: only through the domain, so no path.
            let r = run_q(
                &g,
                &format!("MATCH p={f}((s:User)-[:AD_ATTACK_PATHS*1..]->(t:Group)) WHERE t.objectid ENDS WITH '-512' RETURN p"),
            );
            assert!(paths(&r).is_empty(), "{f}");
        }
        // Nor to an object that is not Tier Zero: from an owned object to
        // anything, the paths stop at the domain.
        let r = run_q(
            &g,
            &format!("MATCH p=shortestPath((s:Base)-[:AD_ATTACK_PATHS*1..]->(t:Base)) WHERE s.objectid = '{U}' AND s<>t RETURN p"),
        );
        assert_eq!(paths(&r), vec![ids(&[U, G1]), ids(&[U, G1, dom])]);
        // Named types are followed through Tier Zero.
        let r = run_q(
            &g,
            &format!("MATCH p=shortestPath((s:User)-[:MemberOf|GenericAll*1..]->(t:User)) WHERE s.objectid = '{U}' AND t.objectid = '{U2}' RETURN p"),
        );
        assert_eq!(paths(&r), vec![ids(&[U, G1, dom, U2])]);
    }

    #[test]
    fn shortest_path_bounds_and_end_nodes() {
        let g = nested();
        let n = |q: &str| run_q(&g, q).rows.len();
        // An upper bound limits the search.
        assert_eq!(
            n("MATCH p=shortestPath((s:User)-[:AD_ATTACK_PATHS*..2]->(t:Tag_Tier_Zero)) RETURN p"),
            1
        );
        // Zero hops: every node to itself; s<>t drops them.
        assert_eq!(
            n("MATCH p=shortestPath((s:User)-[:MemberOf*0..]->(t:User)) RETURN p"),
            2
        );
        assert_eq!(
            n("MATCH p=shortestPath((s:User)-[:MemberOf*0..]->(t:User)) WHERE s<>t RETURN p"),
            0
        );
        // One row per pair of end nodes.
        assert_eq!(
            n("MATCH p=shortestPath((s:User)-[:MemberOf*]->(t:Group)) RETURN p"),
            4
        );
        // Returning the end nodes only.
        let r = run_q(
            &g,
            "MATCH shortestPath((s:User)-[:AD_ATTACK_PATHS*]->(t:Tag_Tier_Zero)) RETURN DISTINCT t",
        );
        assert_eq!(r.node_ids(), BTreeSet::from([DA.to_string()]));
        // LIMIT stops the search.
        assert_eq!(
            n("MATCH p=shortestPath((s:Base)-[:AD_ATTACK_PATHS*]->(t:Tag_Tier_Zero)) RETURN p LIMIT 1"),
            1
        );
    }

    /// a -> b -> d and a -> c -> d: two shortest paths.
    #[test]
    fn all_shortest_paths_returns_each_one() {
        let mut g = AdGraph::new();
        let ids_ = [
            "S-1-5-21-2-2-1",
            "S-1-5-21-2-2-2",
            "S-1-5-21-2-2-3",
            "S-1-5-21-2-2-4",
        ];
        let [a, b, c, d] = ids_.map(|id| add(&mut g, id, NodeKind::Group, false));
        g.add_edge(a, b, EdgeKind::MemberOf);
        g.add_edge(a, c, EdgeKind::MemberOf);
        g.add_edge(b, d, EdgeKind::MemberOf);
        g.add_edge(c, d, EdgeKind::MemberOf);
        g.add_edge(a, d, EdgeKind::GenericAll);
        let q = |f: &str| {
            format!("MATCH p={f}((s)-[:MemberOf*]->(t)) WHERE s.objectid = '{}' AND t.objectid = '{}' RETURN p", ids_[0], ids_[3])
        };
        let r = run_q(&g, &q("allShortestPaths"));
        assert_eq!(
            paths(&r),
            vec![
                ids(&[ids_[0], ids_[1], ids_[3]]),
                ids(&[ids_[0], ids_[2], ids_[3]])
            ]
        );
        assert_eq!(run_q(&g, &q("shortestPath")).rows.len(), 1);
        // With the direct edge, one hop is shortest.
        let r = run_q(
            &g,
            &format!(
                "MATCH p=allShortestPaths((s)-[:MemberOf|GenericAll*]->(t)) WHERE s.objectid = '{}' AND t.objectid = '{}' RETURN p",
                ids_[0], ids_[3]
            ),
        );
        assert_eq!(paths(&r), vec![ids(&[ids_[0], ids_[3]])]);
    }

    #[test]
    fn chains_of_relationships() {
        let g = nested();
        let r = run_q(
            &g,
            "MATCH p=(u:User)-[:MemberOf]->(x:Group)-[:GenericAll]->(t:Tag_Tier_Zero) RETURN p",
        );
        assert_eq!(paths(&r), vec![ids(&[U2, G2, DA])]);
        let r = run_q(
            &g,
            "MATCH p=(u:User)-[:MemberOf*1..]->(x:Group)-[:GenericAll]->(t) RETURN u, t",
        );
        assert_eq!(r.rows.len(), 3);
        assert_eq!(r.columns, vec!["u".to_string(), "t".to_string()]);
        // A relationship variable binds, unused.
        assert_eq!(
            run_q(&g, "MATCH p=(u:User)-[r:MemberOf]->(x) RETURN p")
                .rows
                .len(),
            2
        );
        // `(a)-[]->(b)-[]->(a)`: the same node at both ends.
        assert_eq!(
            run_q(&g, "MATCH (a)-[:MemberOf]->(b)-[:MemberOf]->(a) RETURN a")
                .rows
                .len(),
            2
        );
        // A node pattern alone is a path of no relationships.
        let r = run_q(&g, "MATCH p=(n:Tag_Tier_Zero) RETURN p");
        assert_eq!(paths(&r), vec![ids(&[DC]), ids(&[DA])]);
    }

    #[test]
    fn owned_objects_carry_tag_owned() {
        let g = nested();
        let u = g.lookup(U).unwrap();
        let view = AdGraphView::new(&g).with_owned([u]);
        let run = |q: &str| super::super::run(&view, q, &EvalLimits::default()).unwrap();
        assert_eq!(
            run("MATCH (n:Tag_Owned) RETURN n").node_ids(),
            BTreeSet::from([U.to_string()])
        );
        assert_eq!(
            run("MATCH (n) WHERE n.system_tags CONTAINS 'owned' RETURN n").node_ids(),
            BTreeSet::from([U.to_string()])
        );
        let r = run("MATCH p=shortestPath((s:Base)-[:AD_ATTACK_PATHS*1..]->(t:Base)) WHERE (s:Tag_Owned) AND (t:Tag_Tier_Zero) AND s<>t RETURN p");
        assert_eq!(paths(&r), vec![ids(&[U, G1, G2, DA])]);
        assert!(r.warnings.is_empty());
        // Nothing owned: nothing matches, and a note says why.
        let r = run_q(&g, "MATCH (n) WHERE n:Tag_Owned RETURN n");
        assert!(r.rows.is_empty());
        assert_eq!(
            r.warnings,
            vec!["No object is marked as owned, so Tag_Owned matches nothing.".to_string()]
        );
    }

    #[test]
    fn label_tests_and_functions_in_where() {
        let g = nested();
        let n = |q: &str| run_q(&g, q).rows.len();
        assert_eq!(n("MATCH (n) WHERE (n:User OR n:Computer) RETURN n"), 3);
        assert_eq!(n("MATCH (n:Base) WHERE NOT (n:Tag_Tier_Zero) RETURN n"), 4);
        assert_eq!(n("MATCH (n) WHERE n:Group:Tag_Tier_Zero RETURN n"), 1);
        assert_eq!(
            n("MATCH (n:User) WHERE NOT coalesce(n.gmsa, false) = true RETURN n"),
            2
        );
        assert_eq!(
            n("MATCH (n:User) WHERE coalesce(n.gmsa, n.msa) IS NULL RETURN n"),
            2
        );
        assert_eq!(
            n("MATCH (n:User) WHERE toLower(n.name) ENDS WITH '@example.local' RETURN n"),
            2
        );
        assert_eq!(
            n("MATCH (n:User) WHERE toUpper(n.nosuch) = 'X' RETURN n"),
            0
        );
        assert!(matches!(
            eval_err("MATCH (n:User) WHERE toLower(n.enabled) = 'x' RETURN n"),
            EvalError::Type(_)
        ));
    }

    #[test]
    fn relationship_and_path_variables_are_refused_where_they_are_read() {
        for (q, what) in [
            (
                "MATCH (a)-[r:MemberOf]->(b) WHERE r.isacl = true RETURN a",
                "Relationship variable 'r'",
            ),
            (
                "MATCH (a)-[r:MemberOf]->(b) RETURN r",
                "Relationship variable 'r'",
            ),
            (
                "MATCH p=(a)-[:MemberOf]->(b) WHERE p.x = 1 RETURN a",
                "Path variable 'p'",
            ),
            ("MATCH p=(a)-[:MemberOf]->(p) RETURN a", "names two things"),
            ("MATCH (a)-[a:MemberOf]->(b) RETURN b", "names two things"),
        ] {
            let err = eval_err(q);
            assert!(err.to_string().contains(what), "{q}: {err}");
        }
    }

    #[test]
    fn the_deadline_says_it_stopped_the_query() {
        let g = nested();
        let limits = EvalLimits {
            timeout: Duration::ZERO,
            ..EvalLimits::default()
        };
        for q in [
            "MATCH (n) RETURN n",
            "MATCH p=(u)-[:MemberOf*]->(x) RETURN p",
            "MATCH p=shortestPath((s)-[:AD_ATTACK_PATHS*]->(t:Tag_Tier_Zero)) RETURN p",
        ] {
            let r = run_lim(&g, q, &limits);
            assert!(r.truncated && r.timed_out, "{q}");
            assert!(r.stopped[0].contains("time limit"), "{q}: {:?}", r.stopped);
        }
        // The row cap says so too.
        let r = run_lim(
            &g,
            "MATCH (n) RETURN n",
            &EvalLimits {
                max_rows: 2,
                ..EvalLimits::default()
            },
        );
        assert!(r.truncated && !r.timed_out);
        assert_eq!(
            r.stopped,
            vec!["Stopped at the 2-row cap: there are more rows.".to_string()]
        );
    }
}
