//! Reading a file's format number the same way everywhere
//! (docs/dev/formats.md): absent means 1; a whole number from 1 to the newest
//! this version knows is readable; anything else (a larger number, zero,
//! a negative one, a string, a fraction) is a format this version doesn't
//! know, and the file is never read as one of its own.

/// What a file's format number says to this version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A format this version reads.
    Known(u32),
    /// Not one this version knows: a newer Pathwarden's, or not a format
    /// number at all.
    Unknown,
}

impl Format {
    pub fn is_known(self) -> bool {
        matches!(self, Format::Known(_))
    }
}

fn of_number(n: Option<i128>, newest: u32) -> Format {
    match n {
        Some(n) if (1..=i128::from(newest)).contains(&n) => Format::Known(n as u32),
        _ => Format::Unknown,
    }
}

/// The format a typed `version: u32` field gives, once the file has been
/// read into its struct. The one exception to "0 is unknown": here 0 is
/// what an absent field reads as under `#[serde(default)]`, so it reads as
/// 1 (no version Pathwarden wrote ever said 0, so nothing is misread);
/// any number above `newest` is a format this version doesn't know. (A
/// field that isn't a whole number never gets this far: the struct
/// doesn't read.)
pub fn of_u32(n: u32, newest: u32) -> Format {
    if n <= newest {
        Format::Known(n.max(1))
    } else {
        Format::Unknown
    }
}

/// The format a JSON file's `key` gives (`"version"`, `"format"`).
pub fn of_json(value: &serde_json::Value, key: &str, newest: u32) -> Format {
    match value.get(key) {
        None | Some(serde_json::Value::Null) => Format::Known(1),
        Some(v) => of_number(
            v.as_u64()
                .map(i128::from)
                .or_else(|| v.as_i64().map(i128::from)),
            newest,
        ),
    }
}

/// The format a TOML file's top-level `key` gives.
pub fn of_toml(table: &toml::Table, key: &str, newest: u32) -> Format {
    match table.get(key) {
        None => Format::Known(1),
        Some(v) => of_number(v.as_integer().map(i128::from), newest),
    }
}

/// The format a file name gives: `<stem>.v<N><ext>` (`summary.v2.json`),
/// `None` when the name isn't one. A number too large to hold is a format
/// this version doesn't know.
pub fn of_name(name: &str, stem: &str, ext: &str, newest: u32) -> Option<Format> {
    let digits = name
        .strip_prefix(stem)?
        .strip_prefix(".v")?
        .strip_suffix(ext)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(match digits.parse::<u32>() {
        Ok(n) => of_number(Some(i128::from(n)), newest),
        Err(_) => Format::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn numbers_read_one_way() {
        let f = |v: serde_json::Value| of_json(&json!({ "format": v }), "format", 2);
        assert_eq!(of_json(&json!({}), "format", 2), Format::Known(1));
        assert_eq!(f(json!(null)), Format::Known(1));
        assert_eq!(f(json!(1)), Format::Known(1));
        assert_eq!(f(json!(2)), Format::Known(2));
        for v in [
            json!(3),
            json!(0),
            json!(-1),
            json!("1"),
            json!(1.0),
            json!(2.5),
            json!([]),
        ] {
            assert_eq!(f(v.clone()), Format::Unknown, "{v}");
        }
        let t = |s: &str| of_toml(&s.parse::<toml::Table>().unwrap(), "format", 1);
        assert_eq!(t(""), Format::Known(1));
        assert_eq!(t("format = 1"), Format::Known(1));
        for s in ["format = 2", "format = 0", "format = \"1\"", "format = 1.0"] {
            assert_eq!(t(s), Format::Unknown, "{s}");
        }
        let n = |s: &str| of_name(s, "summary", ".json", 2);
        assert_eq!(n("summary.json"), None);
        assert_eq!(n("summary.v2.json"), Some(Format::Known(2)));
        assert_eq!(n("summary.v3.json"), Some(Format::Unknown));
        assert_eq!(n("summary.v99999999999.json"), Some(Format::Unknown));
        assert_eq!(n("summary.vx.json"), None);
        assert_eq!(n("summary.v.json"), None);
    }
}
