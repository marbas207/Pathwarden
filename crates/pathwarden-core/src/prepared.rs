//! Prepared queries: the BloodHound Query Library's Active Directory
//! queries, run on a run's graph from the app's Explore page (Query tab,
//! Prepared) and `pathwarden query --prepared`, from this one list.
//!
//! The library ships as a pinned copy in `queries/` (`Queries.json`, its MIT
//! `LICENSE`, and `SOURCE`, the release it came from), compiled in: it is
//! never fetched at run time. `scripts/update-queries.ps1` refreshes it at
//! release time.
//!
//! Only queries that run, and give the same answer in the app and the CLI,
//! are offered. The rest are listed in `queries/unsupported.toml` with why:
//! Cypher Pathwarden doesn't run yet, or a field saved runs don't
//! keep. The prepared-queries test keeps that list current. A query that
//! overlaps a built-in finding names it (`queries/findings.toml`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

const QUERIES: &str = include_str!("../queries/Queries.json");
const SOURCE: &str = include_str!("../queries/SOURCE");
const UNSUPPORTED: &str = include_str!("../queries/unsupported.toml");
const FINDINGS: &str = include_str!("../queries/findings.toml");

/// The library's license, as its release has it.
pub const LICENSE: &str = include_str!("../queries/LICENSE");

/// The library's categories in the order the list shows them; any other
/// comes after these, by name.
pub const CATEGORIES: &[&str] = &[
    "Shortest Paths",
    "Dangerous Privileges",
    "Kerberos Interaction",
    "Active Directory Certificate Services",
    "NTLM Relay Attacks",
    "Active Directory Hygiene",
    "Domain Information",
    "Cross Platform Attack Paths",
    "Configuration Weakness",
];

/// Where the pinned copy came from (`queries/SOURCE`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Source {
    /// "BloodHound Query Library".
    pub library: String,
    pub url: String,
    /// The release, like `queries-2026-08-20`.
    pub tag: String,
    /// The sha256 of the release's Queries.json.
    pub sha256: String,
    /// The sha256 of the Queries.json shipped here (its Active Directory
    /// queries).
    pub shipped_sha256: String,
    /// "2025 SpecterOps".
    pub copyright: String,
}

impl Source {
    /// "BloodHound Query Library © 2025 SpecterOps. MIT License."
    pub fn notice(&self) -> String {
        format!("{} \u{a9} {}. MIT License.", self.library, self.copyright)
    }
}

/// One query as the library writes it.
#[derive(Debug, Clone, Deserialize)]
struct Raw {
    name: String,
    guid: String,
    category: String,
    description: Option<String>,
    query: String,
    revision: u32,
    #[serde(default)]
    resources: Vec<String>,
    #[serde(default)]
    acknowledgements: Vec<String>,
}

/// Why a library query isn't offered (yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsupported {
    /// Pathwarden's Cypher refuses it, with this message.
    Cypher(String),
    /// It reads fields a saved run doesn't keep, so the app would answer
    /// otherwise than `pathwarden query -i`.
    Fields(Vec<String>),
}

impl Unsupported {
    /// Why, as a sentence.
    pub fn reason(&self) -> String {
        match self {
            Unsupported::Cypher(m) => format!("Pathwarden can't run this query: {m}"),
            Unsupported::Fields(f) => format!(
                "This query reads {}, which saved runs don't keep.",
                crate::text::and_list(f)
            ),
        }
    }
}

/// A finding a query overlaps.
#[derive(Debug, Clone, Serialize)]
pub struct Overlap {
    /// "PW-006".
    pub rule: String,
    pub title: String,
}

/// A prepared query.
#[derive(Debug, Clone, Serialize)]
pub struct Prepared {
    pub guid: String,
    pub name: String,
    pub category: String,
    /// The library's own words, when it has any.
    pub description: Option<String>,
    /// Who wrote it, as the library credits them.
    pub acknowledgements: Vec<String>,
    /// Links to read more.
    pub resources: Vec<String>,
    pub revision: u32,
    /// The Cypher, as the library writes it.
    pub query: String,
    /// "paths" or "objects".
    pub returns: &'static str,
    /// The built-in finding it overlaps.
    pub finding: Option<Overlap>,
    /// It has a placeholder to replace (a host name, a SID): it opens in the
    /// Cypher editor instead of running.
    pub edit_first: bool,
    /// Whether it is offered.
    pub supported: bool,
    /// Why it isn't.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip)]
    pub unsupported: Option<Unsupported>,
}

/// The pinned library, read once.
pub struct Library {
    pub source: Source,
    /// Every Active Directory query of the library, in its order.
    pub all: Vec<Prepared>,
    /// Entries left out because they aren't well formed, each with why
    /// (a test keeps this empty).
    pub rejected: Vec<String>,
}

/// Whether `s` is a GUID as the library writes them (hex, 8-4-4-4-12).
pub fn is_guid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[derive(Deserialize, Default)]
struct UnsupportedFile {
    #[serde(default)]
    cypher: BTreeMap<String, String>,
    #[serde(default)]
    fields: BTreeMap<String, Vec<String>>,
}

/// Whether a query asks for an edit before it runs: a comment that says
/// to replace something ("// Replace 'HOSTNAME' with ...").
pub fn has_placeholder(query: &str) -> bool {
    query.lines().any(|l| {
        let l = l.trim_start();
        l.strip_prefix("//")
            .map(|c| c.trim_start().to_ascii_lowercase().starts_with("replace"))
            .unwrap_or(false)
    })
}

/// The pinned library's unsupported list, as shipped.
pub fn shipped_unsupported() -> BTreeMap<String, Unsupported> {
    let file: UnsupportedFile = toml::from_str(UNSUPPORTED).expect("queries/unsupported.toml");
    let mut out = BTreeMap::new();
    for (g, m) in file.cypher {
        out.insert(g, Unsupported::Cypher(m));
    }
    for (g, f) in file.fields {
        out.insert(g, Unsupported::Fields(f));
    }
    out
}

/// The overlapping findings, as shipped: GUID to rule.
pub fn shipped_findings() -> BTreeMap<String, String> {
    toml::from_str(FINDINGS).expect("queries/findings.toml")
}

/// The pinned library.
pub fn library() -> &'static Library {
    static LIB: OnceLock<Library> = OnceLock::new();
    LIB.get_or_init(|| {
        let source: Source = toml::from_str(SOURCE).expect("queries/SOURCE");
        let raw: Vec<Raw> = serde_json::from_str(QUERIES).expect("queries/Queries.json");
        let unsupported = shipped_unsupported();
        let findings = shipped_findings();
        let mut rejected = Vec::new();
        let all = raw
            .into_iter()
            .filter(|r| {
                let ok = is_guid(&r.guid);
                if !ok {
                    rejected.push(format!(
                        "queries/Queries.json: {:?} has {:?} for its GUID, which is not a GUID.",
                        r.name, r.guid
                    ));
                }
                ok
            })
            .map(|mut r| {
                r.guid = r.guid.to_ascii_lowercase();
                let unsupported = unsupported.get(&r.guid).cloned();
                let returns = match crate::cypher::shape(&r.query) {
                    Ok(s) if s.returns_paths => "paths",
                    _ => "objects",
                };
                let finding = findings.get(&r.guid).map(|rule| Overlap {
                    rule: rule.clone(),
                    title: crate::findings::rules()
                        .iter()
                        .find(|i| i.id == rule)
                        .map(|i| i.title.to_string())
                        .unwrap_or_default(),
                });
                Prepared {
                    edit_first: has_placeholder(&r.query),
                    supported: unsupported.is_none(),
                    reason: unsupported.as_ref().map(Unsupported::reason),
                    unsupported,
                    finding,
                    returns,
                    guid: r.guid,
                    name: r.name,
                    category: r.category,
                    description: r.description.filter(|d| !d.trim().is_empty()),
                    acknowledgements: r.acknowledgements,
                    resources: r.resources,
                    revision: r.revision,
                    query: r.query,
                }
            })
            .collect();
        Library {
            source,
            all,
            rejected,
        }
    })
}

/// Where a category sorts in the list.
fn category_rank(c: &str) -> usize {
    CATEGORIES
        .iter()
        .position(|k| *k == c)
        .unwrap_or(CATEGORIES.len())
}

impl Library {
    /// The queries offered, by category (in [`CATEGORIES`] order) and then
    /// by name: the list the app and `--list-prepared` show.
    pub fn offered(&self) -> Vec<&Prepared> {
        let mut v: Vec<&Prepared> = self.all.iter().filter(|q| q.supported).collect();
        v.sort_by(|a, b| {
            (
                category_rank(&a.category),
                &a.category,
                a.name.to_lowercase(),
            )
                .cmp(&(
                    category_rank(&b.category),
                    &b.category,
                    b.name.to_lowercase(),
                ))
        });
        v
    }

    /// The query with this GUID, offered or not.
    pub fn by_guid(&self, guid: &str) -> Option<&Prepared> {
        self.all.iter().find(|q| q.guid.eq_ignore_ascii_case(guid))
    }

    /// The query `key` names: a GUID, a GUID's first 8 or more characters
    /// (one query's only), or a query's exact name in any case. A query
    /// that isn't offered is found too, so the caller can say why.
    pub fn find(&self, key: &str) -> Result<&Prepared, Lookup<'_>> {
        let key = key.trim();
        if let Some(q) = self.by_guid(key) {
            return Ok(q);
        }
        let lower = key.to_ascii_lowercase();
        if lower.len() >= 8 && lower.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            let hits: Vec<&Prepared> = self
                .all
                .iter()
                .filter(|q| q.guid.starts_with(&lower))
                .collect();
            match hits.len() {
                1 => return Ok(hits[0]),
                0 => {}
                _ => return Err(Lookup::Several(hits)),
            }
        }
        if let Some(q) = self.all.iter().find(|q| q.name.eq_ignore_ascii_case(key)) {
            return Ok(q);
        }
        let words = key.to_lowercase();
        let hits: Vec<&Prepared> = self
            .offered()
            .into_iter()
            .filter(|q| !words.is_empty() && q.name.to_lowercase().contains(&words))
            .collect();
        if hits.is_empty() {
            Err(Lookup::None)
        } else {
            Err(Lookup::Several(hits))
        }
    }
}

/// The list as the app's Explore page and `pathwarden query
/// --list-prepared --json` give it: where it came from, its notice, and the
/// queries offered, in list order.
#[derive(Serialize)]
pub struct Listing<'a> {
    pub library: &'a Source,
    pub notice: String,
    pub queries: Vec<&'a Prepared>,
}

/// The [`Listing`] of the pinned library.
pub fn listing() -> Listing<'static> {
    let lib = library();
    Listing {
        library: &lib.source,
        notice: lib.source.notice(),
        queries: lib.offered(),
    }
}

/// Why [`Library::find`] found no one query.
pub enum Lookup<'a> {
    /// No query has that name or GUID.
    None,
    /// These queries match it in part.
    Several(Vec<&'a Prepared>),
}

/// What a query needs that Pathwarden lacks, as of this build, from its
/// text alone: what `queries/unsupported.toml` must say about it (`None`:
/// it is offered). The prepared-queries test compares the two.
pub fn check(query: &str) -> Option<Unsupported> {
    let refused = |e: crate::cypher::CypherError| {
        let m = e.message();
        // Where in the text is for someone editing it, not for a reason.
        let m = match m.rfind(" (position ") {
            Some(i) if m[i..].trim_end_matches('.').ends_with(')') => m[..i].to_string(),
            _ => m,
        };
        Some(Unsupported::Cypher(crate::cypher::sentence(&m)))
    };
    let shape = match crate::cypher::shape(query) {
        Ok(s) => s,
        Err(e) => return refused(e),
    };
    let missing: Vec<String> = shape.properties.into_iter().filter(|k| !kept(k)).collect();
    if missing.is_empty() {
        None
    } else {
        Some(Unsupported::Fields(missing))
    }
}

/// Whether a saved run answers property `key` as the full graph does.
pub fn kept(key: &str) -> bool {
    crate::cypher::PROP_KEYS.contains(&key) || crate::cypher::VIRTUAL_PROPS.contains(&key)
}

/// `queries/unsupported.toml` for these queries as this build finds them:
/// what to write when the test says the shipped one is out of date.
pub fn unsupported_toml(all: &[(&str, &str, Option<Unsupported>)]) -> String {
    let mut cypher = String::new();
    let mut fields = String::new();
    for (guid, name, why) in all {
        match why {
            Some(Unsupported::Cypher(m)) => {
                cypher.push_str(&format!("{:?} = {:?}  # {}\n", guid, m, name));
            }
            Some(Unsupported::Fields(f)) => {
                let list: Vec<String> = f.iter().map(|k| format!("{k:?}")).collect();
                fields.push_str(&format!("{:?} = [{}]  # {}\n", guid, list.join(", "), name));
            }
            None => {}
        }
    }
    format!(
        "# Library queries Pathwarden doesn't offer yet (#142), by GUID, with why.\n\
         # The prepared-queries test (cargo test -p pathwarden-ui --test prepared)\n\
         # checks this list against what the build runs; with\n\
         # PATHWARDEN_WRITE_PREPARED=1 it rewrites it.\n\
         \n\
         # Pathwarden's Cypher refuses them, with this message.\n\
         [cypher]\n{cypher}\n\
         # They read fields saved runs don't keep, so the app would answer\n\
         # otherwise than `pathwarden query -i`.\n\
         [fields]\n{fields}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_copy_reads() {
        let lib = library();
        assert!(lib.source.tag.starts_with("queries-"));
        assert_eq!(
            lib.source.notice(),
            "BloodHound Query Library \u{a9} 2025 SpecterOps. MIT License."
        );
        assert!(LICENSE.starts_with("MIT License"));
        assert!(lib.all.len() > 100);
        assert!(lib.rejected.is_empty(), "{:?}", lib.rejected);
        use sha2::{Digest, Sha256};
        let sha: String = Sha256::digest(QUERIES.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(sha, lib.source.shipped_sha256, "queries/SOURCE");
    }

    #[test]
    fn guids() {
        assert!(is_guid("6e9beb8a-ad14-43de-bda1-644d174a5906"));
        for bad in [
            "",
            "6e9b",
            "6e9beb8a-ad14-43de-bda1-644d174a590",
            "zzzzzzzz-ad14-43de-bda1-644d174a5906",
            "\u{e9}e9beb8a-ad14-43de-bda1-644d174a590",
        ] {
            assert!(!is_guid(bad), "{bad}");
        }
    }

    #[test]
    fn placeholders() {
        assert!(has_placeholder(
            "// Replace 'HOSTNAME' with x\nMATCH (n) RETURN n"
        ));
        assert!(has_placeholder("MATCH (n)\n  //replace the SID\nRETURN n"));
        assert!(!has_placeholder("MATCH (n) // Domain Users\nRETURN n"));
    }
}
