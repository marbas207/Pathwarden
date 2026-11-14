//! A hand-rolled, dependency-free Cypher engine compatible with the subset of
//! openCypher that BloodHound CE's Explore box accepts.
//!
//! A lexer, a recursive-descent parser and an evaluator for one
//! `MATCH` of nodes and typed relationships, fixed or variable-length,
//! optionally inside `shortestPath()` / `allShortestPaths()` and named by
//! a path variable, with a `WHERE` and a `RETURN` of nodes and paths. What
//! it doesn't run yet is refused by name ("WITH is not supported yet"), never mis-parsed.
//!
//! The load-bearing rule: the engine evaluates over the graph's **raw
//! adjacency** (every edge that exists), honouring only the relationship
//! types the query names. Attack-path semantics apply only where the query
//! asks for them, with BloodHound CE's composite type `AD_ATTACK_PATHS`
//! (the edges [`crate::graph::AdGraph::traversable`] lets attack paths
//! follow). See [`view`] for where that rule lives.
//!
//! Public entry point: [`run`]. The engine is backed by a [`GraphView`]; the
//! CLI uses [`AdGraphView`] over the full in-memory graph. The same seam will
//! later back the UI over a persisted graph (design Phase 2), so results do not
//! depend on the front-end.
//!
//! **Secrets:** a query loaded with every collector property could test
//! secret values (`userpassword`, `unixpassword`, `unicodepwd`,
//! `ms-mcs-admpwd`, `mslaps-*`, `msds-managedpassword*`) in WHERE and learn
//! them one guess at a time. So a property named like a secret
//! ([`is_secret_prop`]) answers [`HIDDEN`] when the object has one, and
//! null when not, in the CLI and the app alike: queries can still ask which
//! accounts carry one, never what it is.

mod ast;
mod eval;
mod lexer;
mod parser;
mod run_view;
mod value;
mod view;

pub use eval::{
    Cell, EvalError, EvalLimits, Hop, QueryResult, DEFAULT_MAX_HOPS, DEFAULT_MAX_PATH_STEPS,
    MAX_CHAIN_HOPS, MAX_WRITTEN_HOPS,
};
pub use run_view::{NoProps, PropCell, RunProps, RunView, PROPS_VERSION, PROP_KEYS};
pub use value::Value;
pub use view::{
    is_secret_prop, AdGraphView, EdgeId, GraphView, NodeRef, TypeSel, AD_ATTACK_PATHS,
    AZ_ATTACK_PATHS, HIDDEN, TAG_OWNED,
};

/// `msg` as a sentence: a capital first letter and a final period.
pub(crate) fn sentence(msg: &str) -> String {
    let mut chars = msg.trim().chars();
    let mut out = match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect::<String>(),
        None => return String::new(),
    };
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

/// Anything that can go wrong running a query: a lex error, a parse error, or
/// an evaluation error. All carry a user-facing message.
#[derive(Debug)]
pub enum CypherError {
    Lex(lexer::LexError),
    Parse(parser::ParseError),
    Eval(EvalError),
}

impl std::fmt::Display for CypherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CypherError::Lex(e) => write!(f, "query syntax error: {e}"),
            CypherError::Parse(e) if e.unsupported => write!(f, "query not supported: {e}"),
            CypherError::Parse(e) => write!(f, "query syntax error: {e}"),
            CypherError::Eval(e) => write!(f, "query error: {e}"),
        }
    }
}

impl std::error::Error for CypherError {}

impl CypherError {
    /// The message as a sentence, without what kind of error it is: what
    /// the app shows under the query box (the CLI's adds the kind first).
    pub fn message(&self) -> String {
        match self {
            CypherError::Lex(e) => e.to_string(),
            CypherError::Parse(e) => e.to_string(),
            CypherError::Eval(e) => e.to_string(),
        }
    }
}

impl From<lexer::LexError> for CypherError {
    fn from(e: lexer::LexError) -> Self {
        CypherError::Lex(e)
    }
}

impl From<parser::ParseError> for CypherError {
    fn from(e: parser::ParseError) -> Self {
        CypherError::Parse(e)
    }
}

impl From<EvalError> for CypherError {
    fn from(e: EvalError) -> Self {
        CypherError::Eval(e)
    }
}

/// A returned path as the analysis describes an attack path (names, kinds,
/// each step), for printing it hop by hop as `pathwarden path` does: the
/// same shape as `pathwarden path --json`. A path read against its
/// relationships (`(t)<-[]-(s)`) is turned around to run with them, from s
/// to t; a step that runs against its relationship (an undirected or mixed
/// pattern) is marked `backward`. `view` is the one the query ran on; the
/// path's `edges` are its edge handles (see [`crate::analysis::AttackPath`]).
/// `None` for a cell that isn't a path.
pub fn attack_path(view: &dyn GraphView, cell: &Cell) -> Option<crate::analysis::AttackPath> {
    use petgraph::graph::EdgeIndex;
    let Cell::Path {
        handles,
        edges,
        backward,
        ..
    } = cell
    else {
        return None;
    };
    let (mut nodes, mut edges) = (handles.clone(), edges.clone());
    if nodes.len() != edges.len() + 1 {
        return None;
    }
    let forward = |nodes: &[NodeRef], i: usize, e: EdgeId| view.edge_ends(e).0 == nodes[i];
    // Turned around only when the pattern read it with `<-`: an undirected
    // row stays as it was matched.
    if *backward
        && edges
            .iter()
            .enumerate()
            .all(|(i, &e)| !forward(&nodes, i, e))
    {
        nodes.reverse();
        edges.reverse();
    }
    let steps = edges
        .iter()
        .enumerate()
        .map(|(i, &e)| crate::analysis::PathStep {
            from: view.name(nodes[i]),
            from_kind: view.kind(nodes[i]),
            edge: view.edge_kind(e),
            to: view.name(nodes[i + 1]),
            to_kind: view.kind(nodes[i + 1]),
            source: view.edge_source(e),
            backward: !forward(&nodes, i, e),
        })
        .collect();
    Some(crate::analysis::AttackPath {
        source: view.name(nodes[0]),
        target: view.name(nodes[nodes.len() - 1]),
        steps,
        edges: edges.iter().map(|&e| EdgeIndex::new(e as usize)).collect(),
    })
}

/// A query's answer as `pathwarden query --json` prints it and the app's
/// Explore page receives it: the result, and with paths, each one hop by
/// hop as `pathwarden path --json` gives it (made as it is written, so the
/// paths are never held twice).
pub struct Answer<'a> {
    pub view: &'a dyn GraphView,
    pub result: &'a QueryResult,
}

impl serde::Serialize for Answer<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        struct Paths<'a>(&'a Answer<'a>);
        impl serde::Serialize for Paths<'_> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_seq(
                    self.0
                        .result
                        .paths()
                        .filter_map(|c| attack_path(self.0.view, c)),
                )
            }
        }
        #[derive(serde::Serialize)]
        struct Out<'a> {
            #[serde(flatten)]
            result: &'a QueryResult,
            #[serde(skip_serializing_if = "Option::is_none")]
            paths: Option<Paths<'a>>,
        }
        Out {
            result: self.result,
            paths: self.result.returns_paths.then_some(Paths(self)),
        }
        .serialize(s)
    }
}

/// Parses and evaluates `cypher` against `view` under `limits`, returning the
/// normalised id-set result.
pub fn run(
    view: &dyn GraphView,
    cypher: &str,
    limits: &EvalLimits,
) -> Result<QueryResult, CypherError> {
    let tokens = lexer::lex(cypher)?;
    let query = parser::parse(tokens)?;
    let result = eval::evaluate(view, &query, limits)?;
    Ok(result)
}

/// What a query reads and returns, from its text alone (it isn't run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {
    /// The properties it reads (`n.key` in WHERE, `{key: value}` in a
    /// pattern): what a saved run must keep for it to answer as it does
    /// over every collector property.
    pub properties: std::collections::BTreeSet<String>,
    /// Whether it returns paths (a `p = ...` path variable), not objects.
    pub returns_paths: bool,
}

/// The [`Shape`] of `cypher`, or why it can't run: every refusal the
/// engine can make from the text alone, including those it otherwise
/// makes only once a row reaches them (a node used as a value inside a
/// function or a string test, a literal of the wrong type for
/// `toLower()`). Only a property value of the wrong type is left for run
/// time.
pub fn shape(cypher: &str) -> Result<Shape, CypherError> {
    /// What evaluating `e` refuses whatever the data: `var_ok` where a bare
    /// node may stand (a comparison's side, `IS NULL`).
    fn refused(e: &ast::Expr, var_ok: bool) -> Result<(), EvalError> {
        use ast::Expr;
        match e {
            Expr::Variable(v) if !var_ok => Err(eval::node_as_value(v)),
            Expr::Literal(_)
            | Expr::Variable(_)
            | Expr::Property { .. }
            | Expr::HasLabels { .. } => Ok(()),
            Expr::Func { func, args } => {
                for a in args {
                    refused(a, false)?;
                    if let (ast::Func::ToLower | ast::Func::ToUpper, Expr::Literal(v)) = (func, a) {
                        if !matches!(v, value::Value::Str(_) | value::Value::Null) {
                            let name = if *func == ast::Func::ToLower {
                                "toLower"
                            } else {
                                "toUpper"
                            };
                            return Err(EvalError::Type(format!(
                                "{name}() needs a string, found {}",
                                value::type_name(v)
                            )));
                        }
                    }
                }
                Ok(())
            }
            Expr::Compare { lhs, rhs, .. } => refused(lhs, true).and(refused(rhs, true)),
            Expr::StringOp { lhs, rhs, .. } => refused(lhs, false).and(refused(rhs, false)),
            Expr::IsNull { expr, .. } => refused(expr, true),
            Expr::Not(a) => refused(a, false),
            Expr::And(a, b) | Expr::Or(a, b) => refused(a, false).and(refused(b, false)),
        }
    }
    fn walk(e: &ast::Expr, out: &mut std::collections::BTreeSet<String>) {
        use ast::Expr;
        match e {
            Expr::Property { key, .. } => {
                out.insert(key.clone());
            }
            Expr::Literal(_) | Expr::Variable(_) | Expr::HasLabels { .. } => {}
            Expr::Func { args, .. } => args.iter().for_each(|a| walk(a, out)),
            Expr::Compare { lhs, rhs, .. } | Expr::StringOp { lhs, rhs, .. } => {
                walk(lhs, out);
                walk(rhs, out);
            }
            Expr::IsNull { expr, .. } | Expr::Not(expr) => walk(expr, out),
            Expr::And(a, b) | Expr::Or(a, b) => {
                walk(a, out);
                walk(b, out);
            }
        }
    }
    let query = parser::parse(lexer::lex(cypher)?)?;
    eval::check(&query, DEFAULT_MAX_HOPS.clamp(1, eval::MAX_WRITTEN_HOPS))?;
    if let Some(w) = &query.where_clause {
        refused(w, true)?;
    }
    let mut properties: std::collections::BTreeSet<String> = query
        .pattern
        .nodes()
        .flat_map(|n| n.props.iter().map(|(k, _)| k.clone()))
        .collect();
    if let Some(w) = &query.where_clause {
        walk(w, &mut properties);
    }
    let returns_paths = query
        .ret
        .items
        .iter()
        .any(|it| query.pattern.path_var.as_deref() == Some(it.var.as_str()));
    Ok(Shape {
        properties,
        returns_paths,
    })
}

/// The properties a saved run answers without keeping them: they come from
/// the object itself (its ID, its Tier Zero and owned marks).
pub use view::VIRTUAL_PROPS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::AdGraph;
    use crate::model::{EdgeKind, Node, NodeKind};

    const A: &str = "S-1-5-21-1-1-1101";
    const B: &str = "S-1-5-21-1-1-1201";

    fn pair() -> AdGraph {
        let mut g = AdGraph::new();
        let mut ix = Vec::new();
        for (id, kind) in [(A, NodeKind::User), (B, NodeKind::Group)] {
            let mut n = Node::placeholder(id.into(), kind);
            n.placeholder = false;
            n.name = format!("{id}@EXAMPLE.LOCAL");
            ix.push(g.upsert(n));
        }
        g.add_edge(ix[0], ix[1], EdgeKind::MemberOf);
        g
    }

    fn steps(g: &AdGraph, q: &str) -> Vec<(String, String, bool)> {
        let view = AdGraphView::new(g);
        let r = run(&view, q, &EvalLimits::default()).unwrap();
        let p = attack_path(&view, &r.rows[0][0]).unwrap();
        p.steps
            .iter()
            .map(|s| (s.from.clone(), s.to.clone(), s.backward))
            .collect()
    }

    /// `<-` is turned around to run with its relationships; an undirected
    /// row stays as matched, its step marked backward.
    #[test]
    fn only_a_left_pattern_is_turned_around() {
        let g = pair();
        let (a, b) = (format!("{A}@EXAMPLE.LOCAL"), format!("{B}@EXAMPLE.LOCAL"));
        assert_eq!(
            steps(
                &g,
                &format!("MATCH p=(g)<-[:MemberOf]-(u) WHERE g.objectid = '{B}' RETURN p")
            ),
            vec![(a.clone(), b.clone(), false)]
        );
        assert_eq!(
            steps(
                &g,
                &format!("MATCH p=(g)-[:MemberOf]-(u) WHERE g.objectid = '{B}' RETURN p")
            ),
            vec![(b, a, true)]
        );
    }

    #[test]
    fn shape_lists_where_and_pattern_keys() {
        let s = shape(
            "MATCH (n:User {enabled: true}) WHERE n.hasspn = true AND NOT toLower(n.name) CONTAINS 'x' RETURN n",
        )
        .unwrap();
        assert_eq!(
            s.properties.into_iter().collect::<Vec<_>>(),
            vec!["enabled", "hasspn", "name"]
        );
        assert!(!s.returns_paths);
        assert!(
            shape("MATCH p=(a)-[:MemberOf]->(b) RETURN p")
                .unwrap()
                .returns_paths
        );
        assert!(shape("MATCH (n) WITH n RETURN n").is_err());
        // What the engine refuses only once a row reaches it, from the text.
        for q in [
            "MATCH (a)-[r:MemberOf]->(b) WHERE r.isacl = true RETURN a",
            "MATCH (n:User) WHERE toLower(n) = 'x' RETURN n",
            "MATCH (n:User) WHERE n CONTAINS 'x' RETURN n",
            "MATCH (n:User) WHERE toUpper(1) = 'X' RETURN n",
            "MATCH (n:User) WHERE NOT n RETURN n",
            "MATCH (n:User) WHERE m.name = 'x' RETURN n",
        ] {
            assert!(shape(q).is_err(), "{q}");
        }
        assert!(
            shape("MATCH (a)-[:MemberOf]->(b) WHERE a <> b AND a IS NOT NULL RETURN a").is_ok()
        );
    }

    #[test]
    fn sentences() {
        assert_eq!(
            sentence("with is not supported yet"),
            "With is not supported yet."
        );
        assert_eq!(sentence("Done."), "Done.");
        assert_eq!(sentence(""), "");
    }
}
