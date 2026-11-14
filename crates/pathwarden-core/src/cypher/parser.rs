//! A recursive-descent parser for Pathwarden's Cypher subset (design §3.2).
//!
//! Grammar implemented:
//! ```text
//! query      := MATCH pattern [WHERE expr] RETURN ret
//! pattern    := [ident '='] ( (shortestPath | allShortestPaths) '(' chain ')' | chain )
//! chain      := nodePat ( rel nodePat )*
//! nodePat    := '(' [ident] (':' ident)* [ '{' propMap '}' ] ')'
//! rel        := ['<'] '-' '[' [ident] ':' ident ('|' ident)* [range] ']' '-' ['>']
//! range      := '*' [int] [ '..' [int] ]
//! ret        := [DISTINCT] retItem (',' retItem)* [LIMIT int]
//! retItem    := ident [AS ident]
//! expr       := orExpr
//! orExpr     := andExpr (OR andExpr)*
//! andExpr    := notExpr (AND notExpr)*
//! notExpr    := NOT notExpr | compare
//! compare    := primary [ (= <> < > <= >=) primary
//!                        | (CONTAINS | STARTS WITH | ENDS WITH) primary
//!                        | IS [NOT] NULL ]
//! primary    := '(' expr ')' | literal | func '(' expr (',' expr)* ')'
//!             | ident [ '.' ident | (':' ident)+ ]
//! func       := coalesce | toLower | toUpper
//! literal    := string | ['-'] number | true | false | null
//! propMap    := ident ':' literal (',' ident ':' literal)*
//! ```
//! Anything outside this subset is refused with a positioned, user-facing
//! message that names what is missing, never silently mis-parsed.

use super::ast::*;
use super::lexer::{Tok, Token};
use super::value::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub pos: usize,
    pub msg: String,
    /// Valid Cypher this build does not run yet (not a syntax error).
    pub unsupported: bool,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&super::sentence(&format!(
            "{} (position {})",
            self.msg, self.pos
        )))
    }
}

pub fn parse(tokens: Vec<Token>) -> Result<Query, ParseError> {
    let mut p = Parser {
        toks: tokens,
        i: 0,
        depth: 0,
    };
    let q = p.query()?;
    p.expect(&Tok::Eof)?;
    Ok(q)
}

struct Parser {
    toks: Vec<Token>,
    i: usize,
    /// Nesting of parentheses and NOTs: capped, so a hostile query is an
    /// error and not a stack overflow (parsing, evaluating and dropping the
    /// tree all recurse).
    depth: usize,
}

/// How deep parentheses and NOTs may nest.
const MAX_DEPTH: usize = 64;

/// Clauses that are valid Cypher but not run by this build, with what to
/// call them in the refusal.
const UNSUPPORTED_CLAUSES: &[(&str, &str)] = &[
    ("OPTIONAL", "OPTIONAL MATCH"),
    ("MATCH", "a second MATCH"),
    ("WITH", "WITH"),
    ("UNWIND", "UNWIND"),
    ("UNION", "UNION"),
    ("CALL", "CALL"),
    ("ORDER", "ORDER BY"),
    ("SKIP", "SKIP"),
    ("FOREACH", "FOREACH"),
];

/// Clauses that change the graph: a query only reads.
const WRITE_CLAUSES: &[&str] = &[
    "CREATE", "MERGE", "SET", "DELETE", "DETACH", "REMOVE", "LOAD",
];

/// Words that begin an expression this build does not evaluate.
const UNSUPPORTED_EXPRESSIONS: &[(&str, &str)] = &[
    ("CASE", "CASE expressions"),
    ("EXISTS", "EXISTS"),
    ("COUNT", "COUNT"),
    ("ANY", "ANY()"),
    ("ALL", "ALL()"),
    ("NONE", "NONE()"),
    ("SINGLE", "SINGLE()"),
];

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.i].tok
    }

    fn peek_at(&self, ahead: usize) -> &Tok {
        &self.toks[(self.i + ahead).min(self.toks.len() - 1)].tok
    }

    fn pos(&self) -> usize {
        self.toks[self.i].pos
    }

    fn bump(&mut self) -> Tok {
        let t = self.toks[self.i].tok.clone();
        if self.i + 1 < self.toks.len() {
            self.i += 1;
        }
        t
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.depth -= 1;
            return self.err(format!("the query nests deeper than {MAX_DEPTH} levels"));
        }
        Ok(())
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            pos: self.pos(),
            msg: msg.into(),
            unsupported: false,
        })
    }

    /// Refuses valid Cypher this build does not run: `what` is not
    /// supported yet.
    fn unsupported<T>(&self, what: impl std::fmt::Display) -> Result<T, ParseError> {
        Err(ParseError {
            pos: self.pos(),
            msg: format!("{what} not supported yet"),
            unsupported: true,
        })
    }

    fn expect(&mut self, want: &Tok) -> Result<(), ParseError> {
        if self.peek() == want {
            self.bump();
            Ok(())
        } else {
            self.err(format!(
                "expected {}, found {}",
                want.describe(),
                self.peek().describe()
            ))
        }
    }

    /// Consumes an identifier equal to `kw` (case-insensitive) if present.
    fn eat_kw(&mut self, kw: &str) -> bool {
        if self.is_kw(kw) {
            self.bump();
            return true;
        }
        false
    }

    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Tok::Ident(s) if s.eq_ignore_ascii_case(kw))
    }

    fn expect_kw(&mut self, kw: &str) -> Result<(), ParseError> {
        if self.eat_kw(kw) {
            Ok(())
        } else {
            self.err(format!(
                "expected keyword {kw}, found {}",
                self.peek().describe()
            ))
        }
    }

    fn ident(&mut self) -> Result<String, ParseError> {
        match self.peek().clone() {
            Tok::Ident(s) => {
                self.bump();
                Ok(s)
            }
            other => self.err(format!(
                "expected an identifier, found {}",
                other.describe()
            )),
        }
    }

    /// Refuses a clause this build doesn't run, if one comes next.
    fn refuse_clause(&self) -> Result<(), ParseError> {
        if let Tok::Ident(word) = self.peek() {
            if WRITE_CLAUSES.iter().any(|w| w.eq_ignore_ascii_case(word)) {
                return self.err(format!(
                    "{} changes the graph; queries here only read it",
                    word.to_ascii_uppercase()
                ));
            }
            if let Some((_, name)) = UNSUPPORTED_CLAUSES
                .iter()
                .find(|(kw, _)| kw.eq_ignore_ascii_case(word))
            {
                return self.unsupported(format!("{name} is"));
            }
        }
        Ok(())
    }

    // ---- clauses ------------------------------------------------------------

    fn query(&mut self) -> Result<Query, ParseError> {
        if !self.is_kw("MATCH") {
            self.refuse_clause()?;
        }
        self.expect_kw("MATCH")?;
        let pattern = self.pattern()?;
        let where_clause = if self.eat_kw("WHERE") {
            Some(self.expr()?)
        } else {
            None
        };
        self.refuse_clause()?;
        self.expect_kw("RETURN")?;
        let ret = self.ret()?;
        self.refuse_clause()?;
        Ok(Query {
            pattern,
            where_clause,
            ret,
        })
    }

    fn pattern(&mut self) -> Result<Pattern, ParseError> {
        let path_var = if matches!(self.peek(), Tok::Ident(_)) && *self.peek_at(1) == Tok::Eq {
            let v = self.ident()?;
            self.bump();
            Some(v)
        } else {
            None
        };
        let shortest = if *self.peek_at(1) == Tok::LParen {
            if self.eat_kw("shortestPath") {
                Some(Shortest::One)
            } else if self.eat_kw("allShortestPaths") {
                Some(Shortest::All)
            } else if matches!(self.peek(), Tok::Ident(_)) {
                return self.unsupported(format!("{} in a pattern is", self.peek().describe()));
            } else {
                None
            }
        } else {
            None
        };
        if shortest.is_some() {
            self.expect(&Tok::LParen)?;
        }
        let start = self.node_pattern()?;
        let mut hops = Vec::new();
        // A relationship begins with '<' or '-' right after a node pattern.
        while matches!(self.peek(), Tok::Dash | Tok::Lt) {
            let rel = self.rel_pattern()?;
            let node = self.node_pattern()?;
            hops.push((rel, node));
        }
        if let Some(kind) = shortest {
            let name = match kind {
                Shortest::One => "shortestPath",
                Shortest::All => "allShortestPaths",
            };
            self.expect(&Tok::RParen)?;
            let [(rel, _)] = hops.as_mut_slice() else {
                return self.err(format!(
                    "{name}() takes one relationship, like {name}((a)-[:MemberOf*1..]->(b))"
                ));
            };
            let length = rel.length.get_or_insert(Length {
                min: 1,
                max: Some(1),
            });
            if length.min > 1 {
                return self.err(format!(
                    "{name}() takes a lower bound of 0 or 1, not {}",
                    length.min
                ));
            }
        }
        if matches!(self.peek(), Tok::Comma) {
            return self.unsupported("several patterns in one MATCH (a comma) are");
        }
        Ok(Pattern {
            path_var,
            shortest,
            start,
            hops,
        })
    }

    fn node_pattern(&mut self) -> Result<NodePattern, ParseError> {
        self.expect(&Tok::LParen)?;
        let mut np = NodePattern::default();
        if let Tok::Ident(_) = self.peek() {
            np.var = Some(self.ident()?);
        }
        while matches!(self.peek(), Tok::Colon) {
            self.bump();
            np.labels.push(self.ident()?);
        }
        if matches!(self.peek(), Tok::LBrace) {
            np.props = self.prop_map()?;
        }
        self.expect(&Tok::RParen)?;
        Ok(np)
    }

    fn prop_map(&mut self) -> Result<Vec<(String, Value)>, ParseError> {
        self.expect(&Tok::LBrace)?;
        let mut props = Vec::new();
        if matches!(self.peek(), Tok::RBrace) {
            self.bump();
            return Ok(props);
        }
        loop {
            let key = self.ident()?;
            self.expect(&Tok::Colon)?;
            let pos = self.pos();
            let Expr::Literal(val) = self.primary()? else {
                // Would need the other variables bound first; matching it
                // as null would silently find nothing.
                return Err(ParseError {
                    pos,
                    msg: "an inline property map takes literal values only; compare other variables in WHERE".into(),
                    unsupported: false,
                });
            };
            props.push((key, val));
            if matches!(self.peek(), Tok::Comma) {
                self.bump();
                continue;
            }
            break;
        }
        self.expect(&Tok::RBrace)?;
        Ok(props)
    }

    fn rel_pattern(&mut self) -> Result<RelPattern, ParseError> {
        let mut left_arrow = false;
        if matches!(self.peek(), Tok::Lt) {
            self.bump();
            left_arrow = true;
        }
        self.expect(&Tok::Dash)?;
        let mut types = Vec::new();
        let mut var = None;
        let mut length = None;
        if matches!(self.peek(), Tok::LBracket) {
            self.bump();
            if let Tok::Ident(_) = self.peek() {
                var = Some(self.ident()?);
            }
            if matches!(self.peek(), Tok::Colon) {
                self.bump();
                types.push(self.ident()?);
                while matches!(self.peek(), Tok::Pipe) {
                    self.bump();
                    // `:A|:B`, an older spelling of `:A|B`.
                    if matches!(self.peek(), Tok::Colon) {
                        self.bump();
                    }
                    types.push(self.ident()?);
                }
            }
            if matches!(self.peek(), Tok::Star) {
                self.bump();
                length = Some(self.range()?);
            }
            if matches!(self.peek(), Tok::LBrace) {
                return self.unsupported("relationship property maps are");
            }
            self.expect(&Tok::RBracket)?;
        }
        if types.is_empty() {
            // Walking every type isn't supported yet; an empty result would
            // read as "no such relationship".
            return self.err("name a relationship type, like -[:MemberOf]-> (untyped relationships are not supported yet)");
        }
        self.expect(&Tok::Dash)?;
        let mut right_arrow = false;
        if matches!(self.peek(), Tok::Gt) {
            self.bump();
            right_arrow = true;
        }
        let direction = match (left_arrow, right_arrow) {
            (false, true) => Direction::Right,
            (true, false) => Direction::Left,
            (false, false) => Direction::Both,
            (true, true) => return self.err("a relationship cannot point both ways"),
        };
        Ok(RelPattern {
            var,
            types,
            direction,
            length,
        })
    }

    /// The hop counts after `*`: `*`, `*N`, `*N..`, `*..M`, `*N..M`.
    fn range(&mut self) -> Result<Length, ParseError> {
        let min = self.hop_count()?;
        if matches!(self.peek(), Tok::Dot) && *self.peek_at(1) == Tok::Dot {
            self.bump();
            self.bump();
            let max = self.hop_count()?;
            let min = min.unwrap_or(1);
            if let Some(max) = max {
                if max < min {
                    return self.err(format!("the hop range *{min}..{max} is empty"));
                }
            }
            return Ok(Length { min, max });
        }
        Ok(match min {
            // `*3`: exactly three.
            Some(n) => Length {
                min: n,
                max: Some(n),
            },
            None => Length { min: 1, max: None },
        })
    }

    fn hop_count(&mut self) -> Result<Option<u32>, ParseError> {
        match self.peek().clone() {
            Tok::Int(n) => match u32::try_from(n) {
                Ok(n) => {
                    self.bump();
                    Ok(Some(n))
                }
                Err(_) => self.err(format!("{n} is not a hop count")),
            },
            _ => Ok(None),
        }
    }

    fn ret(&mut self) -> Result<Return, ParseError> {
        let distinct = self.eat_kw("DISTINCT");
        let mut items = vec![self.ret_item()?];
        while matches!(self.peek(), Tok::Comma) {
            self.bump();
            items.push(self.ret_item()?);
        }
        self.refuse_clause()?;
        let limit = if self.eat_kw("LIMIT") {
            match self.peek().clone() {
                Tok::Int(n) if n >= 0 => {
                    self.bump();
                    Some(n as u64)
                }
                other => {
                    return self.err(format!(
                        "expected a LIMIT count, found {}",
                        other.describe()
                    ))
                }
            }
        } else {
            None
        };
        Ok(Return {
            distinct,
            items,
            limit,
        })
    }

    fn ret_item(&mut self) -> Result<ReturnItem, ParseError> {
        if matches!(self.peek(), Tok::Star) {
            return self.unsupported("RETURN * is");
        }
        let var = self.ident()?;
        // Refuse expressions and functions early with a clear message.
        match self.peek() {
            Tok::Dot => {
                return self.unsupported(format!(
                    "returning a property ({var}.{}) is; return the node {var}",
                    match self.peek_at(1) {
                        Tok::Ident(k) => k.as_str(),
                        _ => "...",
                    }
                ))
            }
            Tok::LParen => return self.unsupported(format!("{var}() in RETURN is")),
            _ => {}
        }
        let alias = if self.eat_kw("AS") {
            Some(self.ident()?)
        } else {
            None
        };
        Ok(ReturnItem { var, alias })
    }

    // ---- expressions --------------------------------------------------------

    fn expr(&mut self) -> Result<Expr, ParseError> {
        self.or_expr()
    }

    fn or_expr(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.and_expr()?;
        loop {
            if self.eat_kw("OR") {
                let rhs = self.and_expr()?;
                lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
            } else if self.is_kw("XOR") {
                return self.unsupported("XOR is");
            } else {
                return Ok(lhs);
            }
        }
    }

    fn and_expr(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.not_expr()?;
        while self.eat_kw("AND") {
            let rhs = self.not_expr()?;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn not_expr(&mut self) -> Result<Expr, ParseError> {
        if self.eat_kw("NOT") {
            self.enter()?;
            let e = self.not_expr();
            self.depth -= 1;
            Ok(Expr::Not(Box::new(e?)))
        } else {
            self.compare()
        }
    }

    fn compare(&mut self) -> Result<Expr, ParseError> {
        let lhs = self.operand()?;
        // Comparison operators.
        let op = match self.peek() {
            Tok::Eq => Some(CompOp::Eq),
            Tok::Neq => Some(CompOp::Neq),
            Tok::Lt => Some(CompOp::Lt),
            Tok::Gt => Some(CompOp::Gt),
            Tok::Lte => Some(CompOp::Lte),
            Tok::Gte => Some(CompOp::Gte),
            Tok::RegexMatch => return self.unsupported("regular expressions (=~) are"),
            _ => None,
        };
        if let Some(op) = op {
            self.bump();
            let rhs = self.operand()?;
            return Ok(Expr::Compare {
                lhs: Box::new(lhs),
                op,
                rhs: Box::new(rhs),
            });
        }
        // String predicates.
        let string_op = if self.eat_kw("CONTAINS") {
            Some(StringOp::Contains)
        } else if self.eat_kw("STARTS") {
            self.expect_kw("WITH")?;
            Some(StringOp::StartsWith)
        } else if self.eat_kw("ENDS") {
            self.expect_kw("WITH")?;
            Some(StringOp::EndsWith)
        } else {
            None
        };
        if let Some(op) = string_op {
            let rhs = self.operand()?;
            return Ok(Expr::StringOp {
                lhs: Box::new(lhs),
                op,
                rhs: Box::new(rhs),
            });
        }
        if self.is_kw("IN") {
            return self.unsupported("IN is");
        }
        // IS [NOT] NULL.
        if self.eat_kw("IS") {
            let negated = self.eat_kw("NOT");
            self.expect_kw("NULL")?;
            return Ok(Expr::IsNull {
                expr: Box::new(lhs),
                negated,
            });
        }
        Ok(lhs)
    }

    /// A value in a comparison: a primary not followed by arithmetic.
    fn operand(&mut self) -> Result<Expr, ParseError> {
        let e = self.primary()?;
        if matches!(self.peek(), Tok::Star | Tok::Dash) {
            return self.unsupported("arithmetic is");
        }
        Ok(e)
    }

    fn primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek().clone() {
            Tok::LParen => {
                self.bump();
                self.enter()?;
                let e = self.expr();
                self.depth -= 1;
                let e = e?;
                // `(n)-[:MemberOf]->()`: a pattern, not a parenthesised value.
                if matches!(e, Expr::Variable(_) | Expr::HasLabels { .. })
                    && matches!(self.peek(), Tok::RParen)
                    && matches!(self.peek_at(1), Tok::Dash | Tok::Lt)
                {
                    return self.unsupported("patterns in WHERE are");
                }
                self.expect(&Tok::RParen)?;
                Ok(e)
            }
            Tok::LBracket => self.unsupported("lists ([...]) are"),
            Tok::Str(s) => {
                self.bump();
                Ok(Expr::Literal(Value::Str(s)))
            }
            Tok::Int(n) => {
                self.bump();
                Ok(Expr::Literal(Value::Int(n)))
            }
            Tok::Float(f) => {
                self.bump();
                Ok(Expr::Literal(Value::Float(f)))
            }
            // A negative number (BHE queries test `pwdlastset = -1`).
            Tok::Dash => {
                let dash = self.pos();
                self.bump();
                match self.peek().clone() {
                    Tok::Int(n) => {
                        self.bump();
                        Ok(Expr::Literal(Value::Int(-n)))
                    }
                    // Only as one literal: `- 9223372036854775808` would
                    // negate a number too large to exist.
                    Tok::IntMinMagnitude if self.pos() != dash + 1 => {
                        self.err("integer 9223372036854775808 is too large")
                    }
                    Tok::IntMinMagnitude => {
                        self.bump();
                        Ok(Expr::Literal(Value::Int(i64::MIN)))
                    }
                    Tok::Float(f) => {
                        self.bump();
                        Ok(Expr::Literal(Value::Float(-f)))
                    }
                    other => self.err(format!(
                        "expected a number after '-', found {}",
                        other.describe()
                    )),
                }
            }
            Tok::Ident(word) => {
                // Keyword literals first.
                if word.eq_ignore_ascii_case("true") {
                    self.bump();
                    return Ok(Expr::Literal(Value::Bool(true)));
                }
                if word.eq_ignore_ascii_case("false") {
                    self.bump();
                    return Ok(Expr::Literal(Value::Bool(false)));
                }
                if word.eq_ignore_ascii_case("null") {
                    self.bump();
                    return Ok(Expr::Literal(Value::Null));
                }
                if *self.peek_at(1) == Tok::LParen {
                    return self.function(&word);
                }
                if let Some((_, what)) = UNSUPPORTED_EXPRESSIONS
                    .iter()
                    .find(|(kw, _)| kw.eq_ignore_ascii_case(&word))
                {
                    return self.unsupported(format!("{what} in WHERE is"));
                }
                let var = self.ident()?;
                match self.peek() {
                    Tok::Dot => {
                        self.bump();
                        let key = self.ident()?;
                        if matches!(self.peek(), Tok::Dot | Tok::LParen) {
                            return self.unsupported("nested properties and methods are");
                        }
                        Ok(Expr::Property { var, key })
                    }
                    Tok::Colon => {
                        let mut labels = Vec::new();
                        while matches!(self.peek(), Tok::Colon) {
                            self.bump();
                            labels.push(self.ident()?);
                        }
                        Ok(Expr::HasLabels { var, labels })
                    }
                    _ => Ok(Expr::Variable(var)),
                }
            }
            Tok::IntMinMagnitude => self.err("integer 9223372036854775808 is too large"),
            other => self.err(format!("expected a value, found {}", other.describe())),
        }
    }

    /// `name(args)`: the few functions the engine evaluates; any other is
    /// refused by name.
    fn function(&mut self, name: &str) -> Result<Expr, ParseError> {
        let func = match name.to_ascii_lowercase().as_str() {
            "coalesce" => Func::Coalesce,
            "tolower" => Func::ToLower,
            "toupper" => Func::ToUpper,
            _ => return self.unsupported(format!("the function {name}() is")),
        };
        self.bump();
        self.expect(&Tok::LParen)?;
        self.enter()?;
        let mut args = Vec::new();
        let result = loop {
            match self.expr() {
                Ok(e) => args.push(e),
                Err(e) => break Err(e),
            }
            if matches!(self.peek(), Tok::Comma) {
                self.bump();
                continue;
            }
            break self.expect(&Tok::RParen);
        };
        self.depth -= 1;
        result?;
        let arity_ok = match func {
            Func::Coalesce => !args.is_empty(),
            Func::ToLower | Func::ToUpper => args.len() == 1,
        };
        if !arity_ok {
            return self.err(format!(
                "{name}() takes {}",
                match func {
                    Func::Coalesce => "at least one argument",
                    _ => "one argument",
                }
            ));
        }
        Ok(Expr::Func { func, args })
    }
}

#[cfg(test)]
mod tests {
    use super::super::lexer::lex;
    use super::*;

    fn p(src: &str) -> Result<Query, ParseError> {
        parse(lex(src).unwrap())
    }

    #[test]
    fn parses_label_match() {
        let q = p("MATCH (n:Group) RETURN n").unwrap();
        assert!(q.pattern.hops.is_empty());
        assert_eq!(q.pattern.start.var.as_deref(), Some("n"));
        assert_eq!(q.pattern.start.labels, vec!["Group".to_string()]);
        assert_eq!(q.ret.items[0].var, "n");
        assert!(q.where_clause.is_none());
    }

    #[test]
    fn parses_where_bool_and_string() {
        let q = p(r#"MATCH (n:User) WHERE n.hasspn = true AND n.enabled = true RETURN n"#).unwrap();
        assert!(matches!(q.where_clause, Some(Expr::And(..))));
    }

    #[test]
    fn parses_contains() {
        let q =
            p(r#"MATCH (c:Computer) WHERE c.operatingsystem CONTAINS "Server" RETURN c"#).unwrap();
        assert!(matches!(
            q.where_clause,
            Some(Expr::StringOp {
                op: StringOp::Contains,
                ..
            })
        ));
    }

    #[test]
    fn parses_relationship_right() {
        let q = p("MATCH (a)-[:MemberOf]->(b) RETURN a, b").unwrap();
        let [(rel, _)] = q.pattern.hops.as_slice() else {
            panic!("expected one relationship")
        };
        assert_eq!(rel.direction, Direction::Right);
        assert_eq!(rel.types, vec!["MemberOf".to_string()]);
        assert_eq!(rel.length, None);
        assert_eq!(q.ret.items.len(), 2);
    }

    #[test]
    fn parses_relationship_left_and_alternation() {
        let q = p("MATCH (a)<-[:MemberOf|Owns]-(b) RETURN a").unwrap();
        let rel = &q.pattern.hops[0].0;
        assert_eq!(rel.direction, Direction::Left);
        assert_eq!(rel.types, vec!["MemberOf".to_string(), "Owns".to_string()]);
        let q = p("MATCH (a)-[:MemberOf|:Owns]->(b) RETURN a").unwrap();
        assert_eq!(q.pattern.hops[0].0.types.len(), 2);
    }

    #[test]
    fn parses_inline_props_and_limit() {
        let q = p(r#"MATCH (n:User {name:"JON"}) RETURN DISTINCT n LIMIT 5"#).unwrap();
        assert_eq!(q.pattern.start.props.len(), 1);
        assert!(q.ret.distinct);
        assert_eq!(q.ret.limit, Some(5));
    }

    fn length(src: &str) -> Option<Length> {
        p(src).unwrap().pattern.hops[0].0.length
    }

    #[test]
    fn parses_variable_lengths() {
        let l = |min, max| Some(Length { min, max });
        assert_eq!(length("MATCH (a)-[:MemberOf*]->(b) RETURN a"), l(1, None));
        assert_eq!(
            length("MATCH (a)-[:MemberOf*1..]->(b) RETURN a"),
            l(1, None)
        );
        assert_eq!(
            length("MATCH (a)-[:MemberOf*0..]->(b) RETURN a"),
            l(0, None)
        );
        assert_eq!(
            length("MATCH (a)-[:MemberOf*..3]->(b) RETURN a"),
            l(1, Some(3))
        );
        assert_eq!(
            length("MATCH (a)-[:MemberOf*2..4]->(b) RETURN a"),
            l(2, Some(4))
        );
        assert_eq!(
            length("MATCH (a)-[:MemberOf*3]->(b) RETURN a"),
            l(3, Some(3))
        );
        assert!(p("MATCH (a)-[:MemberOf*3..2]->(b) RETURN a").is_err());
        assert!(p("MATCH (a)-[:MemberOf*-1]->(b) RETURN a").is_err());
    }

    #[test]
    fn parses_paths_and_shortest_paths() {
        let q = p("MATCH p=shortestPath((s:Group)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero)) WHERE s<>t RETURN p LIMIT 1000").unwrap();
        assert_eq!(q.pattern.path_var.as_deref(), Some("p"));
        assert_eq!(q.pattern.shortest, Some(Shortest::One));
        let q = p("MATCH p = allShortestPaths((s)-[:MemberOf*]-(t)) RETURN p").unwrap();
        assert_eq!(q.pattern.shortest, Some(Shortest::All));
        // A fixed length is one hop.
        let q = p("MATCH p=shortestPath((s)-[:MemberOf]->(t)) RETURN p").unwrap();
        assert_eq!(
            q.pattern.hops[0].0.length,
            Some(Length {
                min: 1,
                max: Some(1)
            })
        );
        let q = p("MATCH p=(a)-[:MemberOf]->(b)-[:AdminTo]->(c) RETURN p").unwrap();
        assert_eq!(q.pattern.hops.len(), 2);
        assert!(p("MATCH p=shortestPath((a)-[:X*2..]->(b)) RETURN p").is_err());
        assert!(p("MATCH p=shortestPath((a)-[:X*]->(b)-[:Y]->(c)) RETURN p").is_err());
        assert!(p("MATCH p=shortestPath((a)) RETURN p").is_err());
    }

    #[test]
    fn parses_label_tests_and_functions() {
        let q = p("MATCH (n) WHERE (n:User OR n:Computer) AND NOT (n:Tag_Tier_Zero) AND NOT coalesce(n.gmsa, false) = true AND toLower(n.name) CONTAINS 'svc' RETURN n").unwrap();
        assert!(q.where_clause.is_some());
        assert!(p("MATCH (n) WHERE toLower(n.a, n.b) = 'x' RETURN n").is_err());
        assert!(p("MATCH (n) WHERE coalesce() = 'x' RETURN n").is_err());
    }

    /// Valid Cypher this build doesn't run says what is missing.
    #[test]
    fn unsupported_constructs_are_named() {
        for (q, what) in [
            ("MATCH (n) RETURN n.name", "returning a property (n.name)"),
            ("MATCH (n) RETURN count(n)", "count() in RETURN"),
            ("MATCH (n) WITH n RETURN n", "WITH"),
            ("WITH 1 AS x MATCH (n) RETURN n", "WITH"),
            ("OPTIONAL MATCH (n) RETURN n", "OPTIONAL MATCH"),
            ("MATCH (n) MATCH (m) RETURN n", "a second MATCH"),
            ("MATCH (n), (m) RETURN n", "several patterns"),
            ("MATCH (n) RETURN n ORDER BY n", "ORDER BY"),
            (
                "MATCH (n) WHERE n.name =~ 'a.*' RETURN n",
                "regular expressions",
            ),
            ("MATCH (n) WHERE n.name IN ['a'] RETURN n", "IN"),
            (
                "MATCH (n) WHERE n.x < datetime().epochseconds RETURN n",
                "datetime()",
            ),
            ("MATCH (n) WHERE n.x < 5 * 2 RETURN n", "arithmetic"),
            (
                "MATCH (n) WHERE (n)-[:MemberOf]->() RETURN n",
                "patterns in WHERE",
            ),
            ("MATCH (n) WHERE ['a'] RETURN n", "lists"),
            (
                "MATCH (n)-[:X {a: 1}]->(m) RETURN n",
                "relationship property maps",
            ),
            ("MATCH (n) RETURN *", "RETURN *"),
        ] {
            let err = p(q).unwrap_err();
            assert!(err.unsupported, "{q}: {err}");
            assert!(err.msg.contains(what), "{q}: {err}");
            assert!(err.msg.ends_with("not supported yet"), "{q}: {err}");
        }
        let err = p("MATCH (n) DELETE n").unwrap_err();
        assert!(err.msg.contains("only read"), "{err}");
    }

    #[test]
    fn a_relationship_variable_parses() {
        let q = p("MATCH p=(n)-[r:GenericAll]->(m) RETURN p").unwrap();
        assert_eq!(q.pattern.hops[0].0.var.as_deref(), Some("r"));
    }

    #[test]
    fn reports_position_on_error() {
        let err = p("MATCH (n:Group RETURN n").unwrap_err();
        // Missing ')': the error should point somewhere sensible and name it.
        assert!(err.msg.contains("')'"));
        assert!(!err.unsupported);
    }
}
