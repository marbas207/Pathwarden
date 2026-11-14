//! The typed syntax tree for Pathwarden's Cypher subset: one `MATCH` of a
//! chain of nodes and relationships (fixed or variable length, optionally
//! inside `shortestPath()` / `allShortestPaths()` and named by a path
//! variable), an optional `WHERE`, and a `RETURN` of nodes and paths.

use super::value::Value;

/// A whole read-only query: `MATCH <pattern> [WHERE <expr>] RETURN <items>`.
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub pattern: Pattern,
    pub where_clause: Option<Expr>,
    pub ret: Return,
}

/// The single `MATCH` pattern: `[p =] [shortestPath(] (a)-[..]-(b)... [)]`.
#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    /// `p` in `p = ...`.
    pub path_var: Option<String>,
    /// `shortestPath(...)` or `allShortestPaths(...)` around the chain.
    pub shortest: Option<Shortest>,
    /// The first node of the chain.
    pub start: NodePattern,
    /// Each relationship and the node after it, left to right.
    pub hops: Vec<(RelPattern, NodePattern)>,
}

impl Pattern {
    /// Every node pattern, left to right.
    pub fn nodes(&self) -> impl Iterator<Item = &NodePattern> {
        std::iter::once(&self.start).chain(self.hops.iter().map(|(_, n)| n))
    }

    /// Every relationship pattern, left to right.
    pub fn rels(&self) -> impl DoubleEndedIterator<Item = &RelPattern> {
        self.hops.iter().map(|(r, _)| r)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shortest {
    /// `shortestPath()`: one shortest path per pair of end nodes.
    One,
    /// `allShortestPaths()`: every shortest path per pair of end nodes.
    All,
}

/// `(var:Label:Label {k: v, ...})`. Any part may be absent.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NodePattern {
    pub var: Option<String>,
    pub labels: Vec<String>,
    /// Inline property map of literal values, matched as equalities.
    pub props: Vec<(String, Value)>,
}

/// `-[var:TYPE|TYPE2*min..max]->` and its direction.
#[derive(Debug, Clone, PartialEq)]
pub struct RelPattern {
    /// Bound but not usable yet: a query that reads it is refused.
    pub var: Option<String>,
    pub types: Vec<String>,
    pub direction: Direction,
    /// `None` is exactly one relationship; `Some` is a variable length.
    pub length: Option<Length>,
}

/// The hop counts of a variable-length relationship: `*` is `1..`, `*3`
/// is `3..3`, `*2..` is `2..`, `*..4` is `1..4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Length {
    pub min: u32,
    /// `None`: no upper bound written (the engine's hop cap applies).
    pub max: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// `(a)-[:T]->(b)`: the stored edge runs a -> b.
    Right,
    /// `(a)<-[:T]-(b)`: the stored edge runs b -> a.
    Left,
    /// `(a)-[:T]-(b)`: either orientation.
    Both,
}

impl Direction {
    /// The same relationship read from the other end.
    pub fn flip(self) -> Self {
        match self {
            Direction::Right => Direction::Left,
            Direction::Left => Direction::Right,
            Direction::Both => Direction::Both,
        }
    }
}

/// `RETURN [DISTINCT] a, p AS alias [LIMIT n]`.
#[derive(Debug, Clone, PartialEq)]
pub struct Return {
    pub distinct: bool,
    pub items: Vec<ReturnItem>,
    pub limit: Option<u64>,
}

/// A single `RETURN` item: a bound node or path variable.
#[derive(Debug, Clone, PartialEq)]
pub struct ReturnItem {
    pub var: String,
    pub alias: Option<String>,
}

impl ReturnItem {
    /// The column name shown to the caller: the alias if given, else the var.
    pub fn name(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.var)
    }
}

/// A `WHERE` / inline-property expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Literal(Value),
    /// `n.key`
    Property {
        var: String,
        key: String,
    },
    /// A bare bound variable (rare in `WHERE`; kept for completeness).
    Variable(String),
    /// `n:Label` (or `n:A:B`, every label): a label test in `WHERE`.
    HasLabels {
        var: String,
        labels: Vec<String>,
    },
    /// `coalesce(...)`, `toLower(...)`, `toUpper(...)`.
    Func {
        func: Func,
        args: Vec<Expr>,
    },
    Compare {
        lhs: Box<Expr>,
        op: CompOp,
        rhs: Box<Expr>,
    },
    StringOp {
        lhs: Box<Expr>,
        op: StringOp,
        rhs: Box<Expr>,
    },
    IsNull {
        expr: Box<Expr>,
        negated: bool,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

/// The functions the engine evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Func {
    /// The first argument that isn't null.
    Coalesce,
    ToLower,
    ToUpper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompOp {
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringOp {
    Contains,
    StartsWith,
    EndsWith,
}
