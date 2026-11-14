//! The runtime value type and Neo4j's comparison rules, which BHE's Cypher
//! follows.
//!
//! Nothing coerces. Equality ([`equals`]) between values of different types
//! is `false` — `1 = '1'` and `true = 'true'` are false, so their `<>` is
//! true — and anything involving `null` is `null`. Ordering ([`compare`],
//! for `< > <= >=`) between different types is `null`, as is any ordering
//! with `null`. A `null` never satisfies a `WHERE`, and `NOT null` is `null`.
//! This matters for parity: `WHERE n.enabled = "true"` must not match a
//! boolean `true`, and `WHERE NOT n.enabled = "true"` must match it.

use std::cmp::Ordering;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
}

impl Value {
    /// Cypher truthiness as a `WHERE` predicate sees it: only a literal `true`
    /// passes. `null` and every non-boolean are not true.
    pub fn is_true(&self) -> bool {
        matches!(self, Value::Bool(true))
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

/// A value's type as an error message names it.
pub fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Int(_) => "an integer",
        Value::Float(_) => "a float",
        Value::Str(_) => "a string",
        Value::List(_) => "a list",
    }
}

/// Cypher `a = b`: `None` is `null`. Numbers compare by value (`1 = 1.0`);
/// other values of different types are not equal. Lists are equal when
/// their elements are, pairwise: a pair that differs makes them unequal,
/// else a `null` pair makes the answer `null`.
pub fn equals(a: &Value, b: &Value) -> Option<bool> {
    use Value::*;
    match (a, b) {
        (Null, _) | (_, Null) => None,
        (List(x), List(y)) => {
            if x.len() != y.len() {
                return Some(false);
            }
            let mut unknown = false;
            for (p, q) in x.iter().zip(y) {
                match equals(p, q) {
                    Some(false) => return Some(false),
                    None => unknown = true,
                    Some(true) => {}
                }
            }
            (!unknown).then_some(true)
        }
        (Int(_) | Float(_), Int(_) | Float(_)) => Some(compare(a, b) == Some(Ordering::Equal)),
        (Bool(x), Bool(y)) => Some(x == y),
        (Str(x), Str(y)) => Some(x == y),
        _ => Some(false),
    }
}

/// Orders two values for `< > <= >=`. Numbers cross-compare (int vs
/// float); every other cross-type pair, lists, and anything involving
/// `null` are not comparable and return `None` — the caller turns that
/// into the Cypher `null` result, which never satisfies a `WHERE`.
pub fn compare(a: &Value, b: &Value) -> Option<Ordering> {
    use Value::*;
    match (a, b) {
        (Null, _) | (_, Null) => None,
        (Bool(x), Bool(y)) => Some(x.cmp(y)),
        (Int(x), Int(y)) => Some(x.cmp(y)),
        (Float(x), Float(y)) => x.partial_cmp(y),
        (Int(x), Float(y)) => (*x as f64).partial_cmp(y),
        (Float(x), Int(y)) => x.partial_cmp(&(*y as f64)),
        (Str(x), Str(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_typing_refuses_cross_type() {
        // A text "true" does not order against the boolean true.
        assert_eq!(
            compare(&Value::Str("true".into()), &Value::Bool(true)),
            None
        );
        // Null is never comparable.
        assert_eq!(compare(&Value::Null, &Value::Int(1)), None);
    }

    #[test]
    fn equality_across_types_is_false_and_with_null_is_null() {
        let s = |v: &str| Value::Str(v.into());
        // Neo4j: 1 = '1' is false (not null), true = 'true' is false.
        assert_eq!(equals(&Value::Int(1), &s("1")), Some(false));
        assert_eq!(equals(&Value::Bool(true), &s("true")), Some(false));
        assert_eq!(
            equals(&Value::List(vec![]), &Value::Bool(false)),
            Some(false)
        );
        assert_eq!(equals(&Value::Int(1), &Value::Float(1.0)), Some(true));
        assert_eq!(
            equals(&Value::Float(f64::NAN), &Value::Float(f64::NAN)),
            Some(false)
        );
        // Null on either side, even null = null, is null.
        assert_eq!(equals(&Value::Null, &Value::Null), None);
        assert_eq!(equals(&Value::Null, &s("x")), None);
        // Lists: pairwise; a differing pair wins over a null one.
        let l = |v: Vec<Value>| Value::List(v);
        assert_eq!(
            equals(&l(vec![s("a"), s("b")]), &l(vec![s("a"), s("b")])),
            Some(true)
        );
        assert_eq!(
            equals(&l(vec![s("a")]), &l(vec![s("a"), s("b")])),
            Some(false)
        );
        assert_eq!(
            equals(
                &l(vec![Value::Int(1), Value::Null]),
                &l(vec![Value::Int(2), Value::Null])
            ),
            Some(false)
        );
        assert_eq!(
            equals(
                &l(vec![Value::Int(1), Value::Null]),
                &l(vec![Value::Int(1), Value::Null])
            ),
            None
        );
    }

    #[test]
    fn numbers_cross_compare() {
        assert_eq!(
            compare(&Value::Int(2), &Value::Float(2.0)),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare(&Value::Int(1), &Value::Float(2.0)),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn strings_are_case_sensitive() {
        // BHE string comparison is case-sensitive.
        assert_eq!(
            compare(&Value::Str("A".into()), &Value::Str("a".into())),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare(&Value::Str("x".into()), &Value::Str("x".into())),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn only_bool_true_is_true() {
        assert!(Value::Bool(true).is_true());
        assert!(!Value::Bool(false).is_true());
        assert!(!Value::Null.is_true());
        assert!(!Value::Str("true".into()).is_true());
    }
}
