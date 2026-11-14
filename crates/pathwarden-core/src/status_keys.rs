//! The status keys' names in what Pathwarden writes (docs/dev/formats.md).
//!
//! Before 1.0 the Tier Zero status was written as a "grade" and the
//! protected share as a "score". From 1.0 every file and every `--json`
//! carries the new names beside the old ones, with the same values; the old
//! ones are written until 2.0, so 1.x readers keep working. Readers take
//! the new key when the old one is missing ([`prefer_new`], [`get`]).

use serde_json::Value;

/// Old key → new key.
pub const RENAMED: &[(&str, &str)] = &[
    ("exposure_grade", "exposure_status"),
    ("grade_reason", "status_reason"),
    ("protection_score", "protected_percent"),
    ("tier_zero_grade", "tier_zero_status"),
    ("grade", "status"),
];

/// Adds the new key beside each old one, in every object of `v`. A new key
/// that is already there is left as it is (a `status` of another meaning
/// next to a `grade` is never overwritten).
pub fn add_new(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (old, new) in RENAMED {
                if let Some(x) = map.get(*old).cloned() {
                    if !map.contains_key(*new) {
                        map.insert((*new).to_string(), x);
                    }
                }
            }
            for x in map.values_mut() {
                add_new(x);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(add_new),
        _ => {}
    }
}

/// `value` as JSON with the new keys beside the old ones ([`add_new`]).
pub fn to_value<T: serde::Serialize>(value: &T) -> serde_json::Result<Value> {
    let mut v = serde_json::to_value(value)?;
    add_new(&mut v);
    Ok(v)
}

/// For a reader that knows the old names: a file that has only the new
/// key (a later writer) gets its value under the old name too. Where both
/// are there, the old one is read: 1.x writes them equal, and a run
/// summary's own `status_reason` (the sentence) is not its
/// `grade_reason`. The new keys are left in place (readers ignore keys
/// they don't know).
pub fn prefer_new(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (old, new) in RENAMED {
                // A `status` with no grade beside it is another status.
                if *old == "grade" || map.contains_key(*old) {
                    continue;
                }
                if let Some(x) = map.get(*new).cloned() {
                    map.insert((*old).to_string(), x);
                }
            }
            for x in map.values_mut() {
                prefer_new(x);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(prefer_new),
        _ => {}
    }
}

/// `T` from JSON bytes written with the old names, the new ones, or both
/// (the new ones win).
pub fn from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> serde_json::Result<T> {
    let mut v: Value = serde_json::from_slice(bytes)?;
    prefer_new(&mut v);
    serde_json::from_value(v)
}

/// The value of `new`, else of `old`, in `map`: for readers of written JSON.
pub fn get<'a>(v: &'a Value, old: &str) -> Option<&'a Value> {
    let new = RENAMED.iter().find(|(o, _)| *o == old).map(|(_, n)| *n)?;
    v.get(new).filter(|x| !x.is_null()).or_else(|| v.get(old))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn new_keys_go_beside_the_old_ones() {
        let mut v = json!({
            "tier_zero": {"exposure_grade": "High", "grade_reason": "x", "protection_score": 50.0},
            "zones": [{"zone": "A", "grade": "Low"}],
            "tier_zero_grade": {"before": "Low", "after": "High"},
            "job": {"grade": "Low", "status": "done"},
        });
        add_new(&mut v);
        assert_eq!(v["tier_zero"]["exposure_status"], "High");
        assert_eq!(v["tier_zero"]["status_reason"], "x");
        assert_eq!(v["tier_zero"]["protected_percent"], 50.0);
        assert_eq!(v["tier_zero"]["exposure_grade"], "High");
        assert_eq!(v["zones"][0]["status"], "Low");
        assert_eq!(v["tier_zero_status"]["after"], "High");
        // A status of its own is kept.
        assert_eq!(v["job"]["status"], "done");
    }

    #[test]
    fn readers_prefer_the_new_keys() {
        let mut v = json!({"protected_percent": 20.0, "tier_zero_status": "High", "status": "x"});
        prefer_new(&mut v);
        assert_eq!(v["protection_score"], 20.0);
        assert_eq!(v["tier_zero_grade"], "High");
        // No grade beside it: not taken for one.
        assert!(v.get("grade").is_none());
        // Both there: the old one is read (a summary's own status_reason).
        let mut v = json!({"grade_reason": "a", "status_reason": "a."});
        prefer_new(&mut v);
        assert_eq!(v["grade_reason"], "a");
        let v = json!({"exposure_grade": "Low", "exposure_status": "High"});
        assert_eq!(get(&v, "exposure_grade").unwrap(), "High");
        let v = json!({"exposure_grade": "Low"});
        assert_eq!(get(&v, "exposure_grade").unwrap(), "Low");
    }
}
