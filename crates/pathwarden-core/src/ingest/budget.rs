//! A memory budget for each collector object while it is parsed.
//!
//! A few kilobytes of compressed JSON can describe an object that takes
//! gigabytes once parsed (`"Aces":[{},{},…]` costs about 80 bytes of memory
//! per 3 bytes of input). Each object is therefore charged, as it is parsed,
//! for the input bytes read and for every list element and JSON value kept.
//! Once an object goes over its budget, the rest of its lists are skipped
//! without being kept and the object is reported as oversized rather than
//! ingested. A single value too large to skip (a string of hundreds of
//! megabytes) fails the file instead, through [`Tracked`].
//!
//! The state is per thread: one object is parsed at a time on a thread.

use std::borrow::Cow;
use std::cell::Cell;
use std::fmt;
use std::io::Read;
use std::marker::PhantomData;

use serde::de::{
    self, Deserialize, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor,
};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Default)]
struct State {
    /// Bytes pulled from the input on this thread so far ([`Tracked`]).
    pulled: u64,
    /// `pulled` when the current object started.
    start: u64,
    /// Memory charged to the current object.
    cost: u64,
    /// The current object's budget; 0 when no object is being parsed.
    limit: u64,
    over: bool,
    /// [`Tracked`] stopped the input because one object grew too large.
    tripped: bool,
}

thread_local! {
    static STATE: Cell<State> = const {
        Cell::new(State {
            pulled: 0,
            start: 0,
            cost: 0,
            limit: 0,
            over: false,
            tripped: false,
        })
    };
}

fn update<T>(f: impl FnOnce(&mut State) -> T) -> T {
    STATE.with(|s| {
        let mut st = s.get();
        let out = f(&mut st);
        s.set(st);
        out
    })
}

/// What parsing one object cost.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectCost {
    /// Estimated memory: input bytes plus the values kept.
    pub bytes: u64,
    /// Over budget: the object was not kept whole and must not be ingested.
    pub oversized: bool,
}

/// Starts charging a new object against `limit` bytes.
pub fn begin(limit: u64) {
    update(|s| {
        s.start = s.pulled;
        s.cost = 0;
        s.limit = limit.max(1);
        s.over = false;
    })
}

/// Stops charging and returns what the object cost.
pub fn finish() -> ObjectCost {
    update(|s| {
        let bytes = s.cost + (s.pulled - s.start);
        s.limit = 0;
        ObjectCost {
            bytes,
            oversized: s.over,
        }
    })
}

/// Clears the per-thread state (a new file).
pub fn reset() {
    update(|s| *s = State::default())
}

thread_local! {
    /// See [`keep_all_properties`].
    static KEEP_ALL: Cell<bool> = const { Cell::new(false) };
}

/// Makes [`known_properties`] on this thread keep every property the
/// collector wrote (for Cypher queries, [`crate::LoadOptions::all_properties`])
/// rather than only the [`KNOWN_PROPERTIES`]. Still under the object's budget.
pub fn keep_all_properties(all: bool) {
    KEEP_ALL.with(|k| k.set(all))
}

/// True once [`Tracked`] cut the input off because of one oversized object.
pub fn tripped() -> bool {
    STATE.with(|s| s.get().tripped)
}

/// Charges `n` bytes to the current object. Returns false when the object
/// is (now) over budget, in which case the value should be skipped.
fn charge(n: u64) -> bool {
    update(|s| {
        if s.limit == 0 {
            return true;
        }
        if !s.over {
            s.cost += n;
            if s.cost + (s.pulled - s.start) > s.limit {
                s.over = true;
            }
        }
        !s.over
    })
}

/// How many times an object's budget may be read from the input before the
/// input is cut off (the object could not be skipped in time, for example
/// one enormous string).
pub const HARD_FACTOR: u64 = 2;

/// Counts the bytes pulled from a reader for the current object's budget,
/// and fails the read once one object has used [`HARD_FACTOR`] times its
/// budget. Put it under the parser's buffer: it is called once per refill.
pub struct Tracked<R>(pub R);

impl<R: Read> Read for Tracked<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.read(buf)?;
        let over = update(|s| {
            s.pulled += n as u64;
            if s.limit == 0 {
                return false;
            }
            let used = s.pulled - s.start;
            if used + s.cost > s.limit {
                s.over = true;
            }
            if used > s.limit.saturating_mul(HARD_FACTOR) {
                s.tripped = true;
                return true;
            }
            false
        });
        if over {
            return Err(std::io::Error::other(
                "a single collector object is too large to load safely",
            ));
        }
        Ok(n)
    }
}

/// `deserialize_with` for lists: `null` is empty (like `nullable`), and
/// elements past the object's budget are skipped instead of kept.
pub fn capped_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    d.deserialize_option(OptionalSeq(PhantomData))
}

/// A list under the object's budget (see [`capped_vec`]).
pub struct Capped<T>(pub Vec<T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Capped<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        capped_vec(d).map(Capped)
    }
}

struct OptionalSeq<T>(PhantomData<T>);

impl<'de, T: Deserialize<'de>> Visitor<'de> for OptionalSeq<T> {
    type Value = Vec<T>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a list or null")
    }
    fn visit_none<E>(self) -> Result<Vec<T>, E> {
        Ok(Vec::new())
    }
    fn visit_unit<E>(self) -> Result<Vec<T>, E> {
        Ok(Vec::new())
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Vec<T>, D::Error> {
        d.deserialize_seq(self)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Vec<T>, A::Error> {
        collect_seq(seq)
    }
}

fn collect_seq<'de, A: SeqAccess<'de>, T: Deserialize<'de>>(
    mut seq: A,
) -> Result<Vec<T>, A::Error> {
    let mut out = Vec::new();
    loop {
        if charge(std::mem::size_of::<T>() as u64) {
            match seq.next_element::<T>()? {
                Some(v) => out.push(v),
                None => return Ok(out),
            }
        } else if seq.next_element::<IgnoredAny>()?.is_none() {
            return Ok(out);
        }
    }
}

/// A JSON value under the object's budget: array elements and object
/// members past the budget are skipped.
#[derive(Debug, Default)]
pub struct BValue(pub Value);

impl<'de> Deserialize<'de> for BValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ValueVisitor).map(BValue)
    }
}

/// `deserialize_with` for an optional [`Value`] under the object's budget.
pub fn opt_value<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Ok(Option::<BValue>::deserialize(d)?.map(|v| v.0))
}

/// `deserialize_with` for a [`Value`] under the object's budget.
pub fn value<'de, D: Deserializer<'de>>(d: D) -> Result<Value, D::Error> {
    Ok(BValue::deserialize(d)?.0)
}

/// `deserialize_with` for a list of values under the object's budget.
pub fn value_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Value>, D::Error> {
    Ok(capped_vec::<D, BValue>(d)?
        .into_iter()
        .map(|v| v.0)
        .collect())
}

const ENTRY_COST: u64 = (std::mem::size_of::<String>() + std::mem::size_of::<Value>() + 16) as u64;

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Value, A::Error> {
        let items: Vec<BValue> = collect_seq(seq)?;
        Ok(Value::Array(items.into_iter().map(|v| v.0).collect()))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if charge(ENTRY_COST) {
                out.insert(key, map.next_value::<BValue>()?.0);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(Value::Object(out))
    }
}

/// The collector properties Pathwarden reads (see `Props::from_map` and
/// `AdcsProps::from_map`). Everything else is skipped while parsing, so an
/// unknown property costs nothing however large it is.
pub const KNOWN_PROPERTIES: &[&str] = &[
    // Props
    "name",
    "domain",
    "domainsid",
    "distinguishedname",
    "description",
    "operatingsystem",
    "enabled",
    "hasspn",
    "dontreqpreauth",
    "admincount",
    "unconstraineddelegation",
    "trustedtoauth",
    "sensitive",
    "pwdneverexpires",
    "passwordnotreqd",
    "haslaps",
    "isdc",
    "pwdlastset",
    "lastlogontimestamp",
    "whencreated",
    "serviceprincipalnames",
    "certificatemappingmethodsraw",
    "strongcertificatebindingenforcementraw",
    "logonscript",
    "useraccountcontrol",
    // Users: matching the accounts services run as by UPN.
    "userprincipalname",
    // Users: SharpHound's group / standalone managed service account flags.
    "gmsa",
    "msa",
    // Domains: false on the objects RustHound-CE writes for trusted domains.
    "collected",
    // OUs: which GPO wins on a computer.
    "blocksinheritance",
    // Names a certificate template whose ObjectIdentifier is empty
    // (RustHound-CE up to 2.5.23).
    "objectguid",
    // AdcsProps
    "schemaversion",
    "ekus",
    "certificateapplicationpolicy",
    "effectiveekus",
    "authorizedsignatures",
    "enrolleesuppliessubject",
    "requiresmanagerapproval",
    "nosecurityextension",
    "authenticationenabled",
    "schannelauthenticationenabled",
    "subjectaltrequireupn",
    "subjectaltrequirespn",
    "subjectaltrequiredns",
    "subjectaltrequiredomaindns",
    "applicationpolicies",
    "certificatepolicy",
    "caname",
    "dnshostname",
    "certthumbprint",
    "certchain",
    "certthumbprints",
    "certtemplateoid",
    "oid",
    // Enterprise CA registry: whether the values were really read.
    "isuserspecifiessanenabledcollected",
    "enrollmentagentrestrictionscollected",
    // InterfaceFlags (ESC11), written only when read.
    "enforceencryptionforrequests",
];

/// `deserialize_with` for `Properties`: keeps the [`KNOWN_PROPERTIES`] (under
/// the object's budget) and skips the rest without allocating.
pub fn known_properties<'de, D: Deserializer<'de>>(d: D) -> Result<Map<String, Value>, D::Error> {
    d.deserialize_option(PropsVisitor)
}

struct PropsVisitor;

impl<'de> Visitor<'de> for PropsVisitor {
    type Value = Map<String, Value>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an object of properties or null")
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Map::new())
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Map::new())
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = Map::new();
        let all = KEEP_ALL.with(Cell::get);
        while let Some(key) = map.next_key_seed(KnownKey(all))? {
            match key {
                Some(key) if charge(ENTRY_COST) => {
                    out.insert(key.into_owned(), map.next_value::<BValue>()?.0);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(out)
    }
}

/// A property name: `Some` for a known one, `None` (not allocated)
/// otherwise. With `KnownKey(true)` every name is kept.
struct KnownKey(bool);

impl<'de> DeserializeSeed<'de> for KnownKey {
    type Value = Option<Cow<'static, str>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for KnownKey {
    type Value = Option<Cow<'static, str>>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a property name")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(match KNOWN_PROPERTIES.iter().copied().find(|k| *k == v) {
            Some(k) => Some(Cow::Borrowed(k)),
            None if self.0 => Some(Cow::Owned(v.to_owned())),
            None => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every property key `Props::from_map` and `AdcsProps::from_map` read
    /// is kept by the parser.
    #[test]
    fn known_properties_cover_the_model() {
        let src = include_str!("../model.rs");
        let start = src.find("impl Props {").unwrap();
        let end = src
            .find("/// Issuance does not need extra authorized signatures.")
            .unwrap();
        let region = &src[start..end];
        let mut keys = Vec::new();
        for (at, _) in region.match_indices("(\"") {
            let rest = &region[at + 2..];
            let Some(close) = rest.find("\")") else {
                continue;
            };
            let key = &rest[..close];
            if !key.is_empty() && key.bytes().all(|b| b.is_ascii_lowercase()) {
                keys.push(key);
            }
        }
        assert!(keys.len() > 40, "{keys:?}");
        for k in keys {
            assert!(
                KNOWN_PROPERTIES.contains(&k),
                "property '{k}' is read but not kept"
            );
        }
    }

    #[test]
    fn keeps_known_properties_and_skips_the_rest() {
        let text = r#"{"name":"A","x":[1,2,3],"enabled":true,"y":{"z":"w"}}"#;
        let mut de = serde_json::Deserializer::from_str(text);
        let m = known_properties(&mut de).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m["name"], "A");
        assert_eq!(m["enabled"], true);
    }

    #[test]
    fn keeps_every_property_when_asked() {
        let text = r#"{"name":"A","samaccountname":"a","y":{"z":"w"}}"#;
        keep_all_properties(true);
        let m = known_properties(&mut serde_json::Deserializer::from_str(text)).unwrap();
        keep_all_properties(false);
        assert_eq!(m.len(), 3);
        assert_eq!(m["samaccountname"], "a");
        let m = known_properties(&mut serde_json::Deserializer::from_str(text)).unwrap();
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn lists_stop_at_the_budget() {
        let text = format!("[{}0]", "0,".repeat(10_000));
        begin(1000);
        let v: Vec<u8> = capped_vec(&mut serde_json::Deserializer::from_str(&text)).unwrap();
        let cost = finish();
        assert!(cost.oversized);
        assert!(v.len() < 1001, "{}", v.len());
        // Outside an object nothing is charged.
        let v: Vec<u8> = capped_vec(&mut serde_json::Deserializer::from_str(&text)).unwrap();
        assert_eq!(v.len(), 10_001);
        let v: Vec<u8> = capped_vec(&mut serde_json::Deserializer::from_str("null")).unwrap();
        assert!(v.is_empty());
    }
}
