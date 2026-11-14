//! Mapping packs: what an OpenGraph collector's kinds mean to Pathwarden.
//!
//! A pack is TOML, one per collector. First-party packs are compiled in
//! ([`embedded`]) and reviewed like code. A pack decides, per edge kind:
//! whether it is traversable, what removing it costs, whether the plan may
//! cut it, its fix text, and how its coverage unit is derived. Kinds no pack
//! describes are kept as context and never traversed. An untrusted pack
//! (`trusted = false`) only labels kinds: all its edges are context.
//!
//! ```toml
//! [pack]
//! name = "taskhound"
//! title = "TaskHound"
//! version = 1
//! source_kinds = ["TaskHound"]   # metadata.source_kind, or a kind on the nodes
//! kind_prefix = "TH_"            # the only kinds this pack may describe
//! trusted = true
//!
//! [[node]]
//! kind = "TH_ScheduledTask"
//! label = "Scheduled task"
//! icon = "clock"
//! color = "#8B5CF6"
//! keep = ["hostname", "runas"]
//!
//! [[edge]]
//! kind = "TH_HasTaskWithStoredCreds"
//! traversable = true
//! cost = 2
//! unit = "start"
//! fix = "Remove the stored credentials from {to} on {from}."
//! ```
//!
//! A pack that fails validation is refused as a whole, never half-applied.

use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;

use crate::kinds::{self, ExtKind};
use crate::model::EdgeKind;

/// First-party packs, in precedence order.
pub fn embedded() -> &'static [Pack] {
    static PACKS: std::sync::OnceLock<Vec<Pack>> = std::sync::OnceLock::new();
    PACKS.get_or_init(|| {
        EMBEDDED
            .iter()
            .map(|(file, text)| {
                Pack::parse(text).unwrap_or_else(|e| panic!("embedded pack {file} is invalid: {e}"))
            })
            .collect()
    })
}

/// The source text of the first-party packs.
pub const EMBEDDED: &[(&str, &str)] = &[
    ("taskhound.toml", include_str!("../../packs/taskhound.toml")),
    (
        "mssqlhound.toml",
        include_str!("../../packs/mssqlhound.toml"),
    ),
    (
        "configmanbearpig.toml",
        include_str!("../../packs/configmanbearpig.toml"),
    ),
];

/// The AzureHound pack. Not one of the [`embedded`] OpenGraph packs: it
/// is applied only when AzureHound data is read (see `crate::entra`), so
/// analyses without it are unchanged.
pub fn azurehound() -> &'static Pack {
    static PACK: std::sync::OnceLock<Pack> = std::sync::OnceLock::new();
    PACK.get_or_init(|| {
        Pack::parse(AZUREHOUND).unwrap_or_else(|e| panic!("azurehound.toml is invalid: {e}"))
    })
}

/// The source text of the AzureHound pack.
pub const AZUREHOUND: &str = include_str!("../../packs/azurehound.toml");

/// Icons the explorer can draw; any other name falls back to a generic
/// shape. Names are Font Awesome solid icon names.
pub const ICONS: &[&str] = &[
    "clock",
    "gears",
    "gear",
    "database",
    "server",
    "sitemap",
    "user-gear",
    "key",
    "cloud",
    "user",
    "users",
    "user-shield",
    "lock",
    "shield",
    "terminal",
    "folder",
    "file",
    "desktop",
    "network-wired",
    "link",
    "id-card",
    "certificate",
    "box",
    "cube",
    "circle",
];

/// How each [`ICONS`] name is drawn: the inner markup of a 24x24 line
/// icon (stroked in the current color, no fill), the same drawings as
/// `EXT_GLYPHS` in the explorer's script. The report's and the app's icon
/// sprites carry them as `i-x-NAME` symbols ([`icon_symbols`]).
pub const ICON_GLYPHS: &[(&str, &str)] = &[
    (
        "clock",
        r#"<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>"#,
    ),
    (
        "gears",
        r#"<circle cx="9" cy="10" r="3"/><path d="M9 3.5v2M9 14.5v2M2.5 10h2M13.5 10h2M4.4 5.4l1.4 1.4M12.2 13.2l1.4 1.4M4.4 14.6l1.4-1.4M12.2 6.8l1.4-1.4"/><circle cx="17" cy="17" r="2.2"/><path d="M17 13.3v1.5M17 19.2v1.5M13.3 17h1.5M19.2 17h1.5"/>"#,
    ),
    (
        "gear",
        r#"<circle cx="12" cy="12" r="3.2"/><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8"/>"#,
    ),
    (
        "database",
        r#"<ellipse cx="12" cy="6" rx="7" ry="2.8"/><path d="M5 6v12c0 1.5 3.1 2.8 7 2.8s7-1.3 7-2.8V6M5 12c0 1.5 3.1 2.8 7 2.8s7-1.3 7-2.8"/>"#,
    ),
    (
        "server",
        r#"<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>"#,
    ),
    (
        "sitemap",
        r#"<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>"#,
    ),
    (
        "user-gear",
        r#"<circle cx="10" cy="8" r="4"/><path d="M3 21c0-4.2 3.1-7 7-7 1.3 0 2.5.3 3.5.9"/><circle cx="18" cy="17.5" r="2"/><path d="M18 13.8v1.7M18 19.5v1.7M14.3 17.5H16M20 17.5h1.7"/>"#,
    ),
    (
        "key",
        r#"<circle cx="8" cy="15" r="4"/><path d="M11 12 20 3M16.5 6.5l2.5 2.5M14 9l2 2"/>"#,
    ),
    (
        "cloud",
        r#"<path d="M7 18h10.5a4 4 0 0 0 .4-8A6 6 0 0 0 6.3 9.5 4.3 4.3 0 0 0 7 18z"/>"#,
    ),
    (
        "user",
        r#"<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>"#,
    ),
    (
        "users",
        r#"<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.8 2.9-6 6.5-6s6.5 2.2 6.5 6"/><path d="M15.5 4.8a3.5 3.5 0 0 1 0 6.4M17.5 14.3c2.4.6 4 2.6 4 5.7"/>"#,
    ),
    (
        "user-shield",
        r#"<circle cx="9" cy="8" r="4"/><path d="M2.5 21c0-4.2 2.9-7 6.5-7 1 0 1.9.2 2.7.5"/><path d="M17.5 12.5 14 14v2.8c0 2.2 1.5 3.8 3.5 4.7 2-.9 3.5-2.5 3.5-4.7V14z"/>"#,
    ),
    (
        "lock",
        r#"<rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>"#,
    ),
    (
        "shield",
        r#"<path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6z"/>"#,
    ),
    (
        "terminal",
        r#"<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M12.5 15H17"/>"#,
    ),
    (
        "folder",
        r#"<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>"#,
    ),
    (
        "file",
        r#"<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5"/>"#,
    ),
    (
        "desktop",
        r#"<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>"#,
    ),
    (
        "network-wired",
        r#"<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="2.5" y="16" width="6" height="5" rx="1"/><rect x="15.5" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M5.5 16v-4h13v4"/>"#,
    ),
    (
        "link",
        r#"<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.2 1.2"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.2-1.2"/>"#,
    ),
    (
        "id-card",
        r#"<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2.2"/><path d="M5.8 16c.5-1.6 1.7-2.5 3.2-2.5s2.7.9 3.2 2.5M14.5 10h4M14.5 13.5h3"/>"#,
    ),
    (
        "certificate",
        r#"<circle cx="12" cy="9" r="5"/><path d="M9 13.5 7.5 21l4.5-2.5 4.5 2.5-1.5-7.5"/>"#,
    ),
    (
        "box",
        r#"<path d="M3.5 7.5 12 3l8.5 4.5v9L12 21l-8.5-4.5z"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9"/>"#,
    ),
    (
        "cube",
        r#"<path d="M12 3 4 7.5v9L12 21l8-4.5v-9z"/><path d="M4 7.5 12 12l8-4.5M12 12v9"/>"#,
    ),
    ("circle", r#"<circle cx="12" cy="12" r="8"/>"#),
];

/// The sprite id for an [`ICONS`] name (`i-x-NAME`); `None` for any other
/// name, so a pack's icon name never reaches a page as it is.
pub fn icon_symbol_id(name: &str) -> Option<String> {
    ICON_GLYPHS
        .iter()
        .any(|(n, _)| *n == name)
        .then(|| format!("i-x-{name}"))
}

/// Every [`ICON_GLYPHS`] drawing as an SVG `<symbol id="i-x-NAME">`, one
/// per line, for a page's icon sprite.
pub fn icon_symbols() -> String {
    ICON_GLYPHS
        .iter()
        .map(|(n, d)| format!("<symbol id=\"i-x-{n}\" viewBox=\"0 0 24 24\">{d}</symbol>\n"))
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackFile {
    pack: Header,
    #[serde(default, rename = "node")]
    nodes: Vec<NodeEntry>,
    #[serde(default, rename = "edge")]
    edges: Vec<EdgeEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    name: String,
    #[serde(default)]
    title: Option<String>,
    version: u32,
    source_kinds: Vec<String>,
    kind_prefix: String,
    #[serde(default)]
    trusted: bool,
    #[serde(default)]
    native: Vec<String>,
    /// Kinds outside `kind_prefix` the pack may describe (BloodHound's
    /// hybrid edges, `SyncedToEntraUser`, have no `AZ` prefix).
    #[serde(default)]
    extra_kinds: Vec<String>,
    #[serde(default)]
    description: Option<String>,
    /// Built-in corrections the reader applies to this source's data
    /// ([`CORRECTIONS`]): fixes for a collector's known bugs that a
    /// per-edge mapping can't express.
    #[serde(default)]
    corrections: Vec<String>,
    /// Other packs whose kinds a file of this source may carry (a
    /// ConfigManBearPig file holds MSSQLHound kinds). Such edges keep that
    /// pack's meaning and trust; this pack vouches for nothing extra.
    #[serde(default)]
    companions: Vec<String>,
}

/// Corrections a pack may ask for (see `crate::opengraph::mssql` and
/// `crate::opengraph::sccm`).
pub const CORRECTIONS: &[&str] = &["mssql", "sccm"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeEntry {
    kind: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    color: Option<String>,
    #[serde(default)]
    keep: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EdgeEntry {
    kind: String,
    #[serde(default)]
    traversable: bool,
    #[serde(default)]
    cost: Option<u64>,
    #[serde(default)]
    cuttable: Option<bool>,
    #[serde(default)]
    fix: Option<String>,
    #[serde(default)]
    control: Option<bool>,
    #[serde(default)]
    rule: Option<String>,
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    description: Option<String>,
    /// The edge is context only when one of these holds:
    /// `{ "start.isgmsa" = true }` (a kept property of either end, or of
    /// the edge itself: `edge.assumed`).
    #[serde(default)]
    unless: BTreeMap<String, toml::Value>,
    /// The edge is context only unless all of these hold. A value may be
    /// `{ same_as = "edge.remotelogin" }`: two properties are equal.
    #[serde(default)]
    when: BTreeMap<String, toml::Value>,
    /// Made by a correction from other edges, never read from a file: an
    /// edge of this kind in a file is context only.
    #[serde(default)]
    derived: bool,
}

/// How an external edge's coverage unit is found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitRule {
    /// The whole source is one unit (all or nothing).
    Source,
    /// The start object.
    Start,
    /// The end object.
    End,
    /// The unit of the object that reaches the start object through one of
    /// these edge kinds (for a task: the computer that holds it).
    StartVia(Vec<String>),
}

impl UnitRule {
    fn parse(s: &str) -> Result<Self, String> {
        Ok(match s.trim() {
            "source" => UnitRule::Source,
            "start" => UnitRule::Start,
            "end" => UnitRule::End,
            other => {
                let Some(kinds) = other.strip_prefix("start.via:") else {
                    return Err(format!(
                        "unit '{other}' is not one of source, start, end, start.via:<kind>"
                    ));
                };
                let kinds: Vec<String> = kinds.split('|').map(|k| k.trim().to_string()).collect();
                if kinds.iter().any(|k| !kinds::valid_name(k)) {
                    return Err(format!("unit '{other}' names an invalid kind"));
                }
                UnitRule::StartVia(kinds)
            }
        })
    }
}

/// What a pack says about an external edge kind.
#[derive(Debug, Clone)]
pub struct EdgeSem {
    /// Paths go through it. Always false in an untrusted pack.
    pub traversable: bool,
    /// What the pack would say if trusted (for display).
    pub declared_traversable: bool,
    /// Relative effort of removing it (1 to 100).
    pub cost: u64,
    /// The plan may cut it. False means "fix it elsewhere": the plan routes
    /// around it, as for an intra-forest trust.
    pub cuttable: bool,
    /// Fix template with `{from}`, `{to}` and `{source}`.
    pub fix: Option<String>,
    /// One such edge into Tier Zero counts as control (PW-030).
    pub control: bool,
    /// A specific rule reports it instead of PW-030.
    pub rule: Option<String>,
    pub unit: UnitRule,
    pub description: Option<String>,
    /// The pack's name and display title.
    pub pack: String,
    pub source_title: String,
    /// Context only when one of these holds.
    pub unless: Vec<Cond>,
    /// Context only unless all of these hold.
    pub when: Vec<Cond>,
    /// Made by a correction; an edge of this kind in a file is context.
    pub derived: bool,
}

/// What a condition looks at: an end of the edge, or the edge itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    Start,
    End,
    Edge,
}

impl End {
    fn prefix(self) -> &'static str {
        match self {
            End::Start => "start",
            End::End => "end",
            End::Edge => "edge",
        }
    }

    fn parse(key: &str) -> Option<(End, String)> {
        let (at, prop) = key.split_once('.')?;
        let at = match at {
            "start" => End::Start,
            "end" => End::End,
            "edge" => End::Edge,
            _ => return None,
        };
        let prop = prop.trim().to_ascii_lowercase();
        (!prop.is_empty() && !is_secret_key(&prop)).then_some((at, prop))
    }
}

/// What a condition compares a property with.
#[derive(Debug, Clone, PartialEq)]
pub enum Test {
    Equals(serde_json::Value),
    /// Another property (of either end or the edge) with the same value.
    SameAs(End, String),
}

/// A pack condition: `edge.assumed = true`.
#[derive(Debug, Clone, PartialEq)]
pub struct Cond {
    pub at: End,
    pub key: String,
    pub test: Test,
}

impl Cond {
    /// Whether it holds, given a property lookup. A missing property never
    /// matches (so `unless` keeps the edge and `when` makes it context).
    pub fn holds<'a>(&self, get: impl Fn(End, &str) -> Option<&'a serde_json::Value>) -> bool {
        let Some(v) = get(self.at, &self.key) else {
            return false;
        };
        match &self.test {
            Test::Equals(want) => loosely_equal(v, want),
            Test::SameAs(at, key) => get(*at, key).is_some_and(|w| loosely_equal(v, w)),
        }
    }

    fn describe(&self) -> String {
        let rhs = match &self.test {
            Test::Equals(v) => v.to_string(),
            Test::SameAs(at, key) => format!("{}.{key}", at.prefix()),
        };
        format!("{}.{} = {rhs}", self.at.prefix(), self.key)
    }
}

/// `true` equals `"true"` and `"True"`: collectors disagree on types.
pub fn loosely_equal(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    let norm = |v: &serde_json::Value| match v {
        serde_json::Value::String(s) => s.trim().to_ascii_lowercase(),
        other => other.to_string().to_ascii_lowercase(),
    };
    norm(a) == norm(b)
}

impl EdgeSem {
    /// The fix text for an edge from `from` to `to`.
    pub fn fix_text(&self, from: &str, to: &str) -> Option<String> {
        self.fix.as_ref().map(|t| {
            t.replace("{from}", from)
                .replace("{to}", to)
                .replace("{source}", &self.source_title)
        })
    }
}

/// What a pack says about an external node kind (display only).
#[derive(Debug, Clone)]
pub struct NodeSem {
    pub label: Option<String>,
    /// A name from [`ICONS`], or `None` for the generic shape.
    pub icon: Option<String>,
    /// `#RGB` or `#RRGGBB`, validated.
    pub color: Option<String>,
    pub pack: String,
}

/// A pack's node kind, for display (the Mappings page).
#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeView {
    pub kind: String,
    pub label: Option<String>,
    /// A name from [`ICONS`] (others are dropped).
    pub icon: Option<String>,
    /// `#RGB` or `#RRGGBB`, validated.
    pub color: Option<String>,
}

/// A pack's edge kind, for display (the Mappings page).
#[derive(Debug, Clone, serde::Serialize)]
pub struct EdgeView {
    pub kind: String,
    /// As the pack declares it; an untrusted pack's edges are context only
    /// whatever this says.
    pub traversable: bool,
    pub cost: u64,
    pub cuttable: bool,
    pub fix: Option<String>,
    pub rule: Option<String>,
    pub unit: String,
    pub description: Option<String>,
    /// Conditions that make it context only, as `end.isgmsa = true`.
    pub unless: Vec<String>,
    /// Conditions that must all hold, or it is context only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<String>,
    /// Made by a correction, never read from a file.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub derived: bool,
}

/// An edge entry with its parsed unit rule and conditions.
#[derive(Debug, Clone)]
struct EdgeDef {
    entry: EdgeEntry,
    unit: UnitRule,
    unless: Vec<Cond>,
    when: Vec<Cond>,
}

/// A validated mapping pack.
#[derive(Debug, Clone)]
pub struct Pack {
    header: Header,
    nodes: Vec<NodeEntry>,
    edges: Vec<EdgeDef>,
    native: Vec<EdgeKind>,
}

/// Properties every external node keeps (besides what packs ask for).
pub const DEFAULT_KEEP: &[&str] = &[
    "name",
    "displayname",
    "description",
    "hostname",
    "dnshostname",
    "email",
];

/// Whether a property name looks like it holds a secret. Such properties
/// are never kept, whatever a pack asks for.
pub fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    const PATTERNS: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "privatekey",
        "private_key",
        "credential",
        "hash",
        "ntlm",
        "aeskey",
        "krbkey",
        "cleartext",
        "plaintext",
        "laps",
        "dpapi",
        // Trust keys, BitLocker and TPM recovery material, LSA secrets.
        "trustauth",
        "initialauth",
        "mstpm-ownerinformation",
        "msfve-keypackage",
        "currentvalue",
        "priorvalue",
    ];
    // "credentialsstored" says whether a task stores one, not the secret.
    if k == "credentialsstored" {
        return false;
    }
    PATTERNS.iter().any(|p| k.contains(p))
}

fn valid_color(c: &str) -> bool {
    let Some(hex) = c.strip_prefix('#') else {
        return false;
    };
    (hex.len() == 3 || hex.len() == 6) && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_template(t: &str) -> Result<(), String> {
    let mut rest = t;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Err(format!("unclosed placeholder in '{t}'"));
        };
        let name = &after[..close];
        if !matches!(name, "from" | "to" | "source") {
            return Err(format!(
                "unknown placeholder {{{name}}} in '{t}' (use {{from}}, {{to}} or {{source}})"
            ));
        }
        rest = &after[close + 1..];
    }
    Ok(())
}

fn json_of(v: &toml::Value) -> Result<serde_json::Value, String> {
    Ok(match v {
        toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
        toml::Value::String(s) => serde_json::Value::String(s.clone()),
        toml::Value::Integer(i) => serde_json::Value::from(*i),
        _ => {
            return Err(
                "condition values must be booleans, strings, integers or { same_as = \"...\" }"
                    .into(),
            )
        }
    })
}

/// Parses an edge kind's `unless` or `when` conditions.
fn conditions(
    kind: &str,
    what: &str,
    map: &BTreeMap<String, toml::Value>,
) -> Result<Vec<Cond>, String> {
    let mut out = Vec::new();
    for (key, value) in map {
        let Some((at, prop)) = End::parse(key) else {
            return Err(format!(
                "{what} key '{key}' of {kind} must be start.<property>, end.<property> or \
                 edge.<property>, and not a secret-looking property"
            ));
        };
        let test = match value {
            toml::Value::Table(t) => {
                let other = match (t.len(), t.get("same_as")) {
                    (1, Some(toml::Value::String(o))) => End::parse(o),
                    _ => None,
                };
                let Some((oat, okey)) = other else {
                    return Err(format!(
                        "{what} value of {kind} {key} must be a value or {{ same_as = \"edge.<property>\" }}"
                    ));
                };
                Test::SameAs(oat, okey)
            }
            v => Test::Equals(json_of(v)?),
        };
        out.push(Cond {
            at,
            key: prop,
            test,
        });
    }
    Ok(out)
}

impl Pack {
    /// Parses and validates a pack.
    pub fn parse(text: &str) -> Result<Pack, String> {
        let file: PackFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let h = &file.pack;
        let name_ok = !h.name.is_empty()
            && h.name.len() <= 64
            && h.name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !name_ok {
            return Err(format!(
                "pack name '{}' must be letters, digits, - or _",
                h.name
            ));
        }
        // A prefix ends in `_`, or is at least two capitals: BloodHound's
        // own Azure kinds (AZUser, AZOwns) have no separator.
        let capitals =
            h.kind_prefix.len() >= 2 && h.kind_prefix.bytes().all(|b| b.is_ascii_uppercase());
        if !kinds::valid_name(&h.kind_prefix) || !(h.kind_prefix.ends_with('_') || capitals) {
            return Err(format!(
                "kind_prefix '{}' must be letters and digits ending in _",
                h.kind_prefix
            ));
        }
        for k in &h.extra_kinds {
            if !kinds::valid_name(k) || EdgeKind::from_name(k).is_some() {
                return Err(format!(
                    "extra kind '{k}' is not a valid, non-native kind name"
                ));
            }
        }
        if h.source_kinds.is_empty() || h.source_kinds.iter().any(|s| !kinds::valid_name(s)) {
            return Err("source_kinds must list valid kind names".into());
        }
        if let Some(c) = h
            .corrections
            .iter()
            .find(|c| !CORRECTIONS.contains(&c.as_str()))
        {
            return Err(format!(
                "correction '{c}' is not one of {}",
                CORRECTIONS.join(", ")
            ));
        }
        let pack_name = |n: &String| {
            !n.is_empty()
                && n.len() <= 64
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        if h.companions.iter().any(|c| !pack_name(c) || *c == h.name) {
            return Err("companions must name other packs".into());
        }
        let mut native = Vec::new();
        for n in &h.native {
            let k = EdgeKind::from_name(n)
                .ok_or_else(|| format!("native '{n}' is not a native edge kind"))?;
            native.push(k);
        }
        let own = |kind: &str, what: &str| -> Result<(), String> {
            if !kinds::valid_name(kind) {
                return Err(format!("{what} kind '{kind}' is not a valid kind name"));
            }
            if EdgeKind::from_name(kind).is_some()
                || crate::model::NodeKind::ALL
                    .iter()
                    .any(|k| k.as_str().eq_ignore_ascii_case(kind))
            {
                return Err(format!(
                    "{what} kind '{kind}' is a native kind; list native edges under `native`"
                ));
            }
            if !kind.starts_with(&h.kind_prefix) && !h.extra_kinds.iter().any(|k| k == kind) {
                return Err(format!(
                    "{what} kind '{kind}' does not start with the pack's prefix '{}'",
                    h.kind_prefix
                ));
            }
            Ok(())
        };
        let mut seen = HashSet::new();
        for n in &file.nodes {
            own(&n.kind, "node")?;
            if !seen.insert(("node", n.kind.clone())) {
                return Err(format!("node kind '{}' is listed twice", n.kind));
            }
            if let Some(c) = &n.color {
                if !valid_color(c) {
                    return Err(format!("color '{c}' of {} is not #RGB or #RRGGBB", n.kind));
                }
            }
            if let Some(i) = &n.icon {
                let ok = !i.is_empty()
                    && i.len() <= 32
                    && i.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
                if !ok {
                    return Err(format!("icon '{i}' of {} is not an icon name", n.kind));
                }
            }
            if let Some(k) = n.keep.iter().find(|k| is_secret_key(k)) {
                return Err(format!("{} keeps '{k}', which looks like a secret", n.kind));
            }
        }
        let mut edges = Vec::new();
        for e in &file.edges {
            own(&e.kind, "edge")?;
            if !seen.insert(("edge", e.kind.clone())) {
                return Err(format!("edge kind '{}' is listed twice", e.kind));
            }
            if let Some(c) = e.cost {
                if !(1..=100).contains(&c) {
                    return Err(format!("cost of {} must be 1 to 100", e.kind));
                }
            }
            if let Some(f) = &e.fix {
                valid_template(f)?;
            }
            if let Some(r) = &e.rule {
                if !crate::findings::rules().iter().any(|x| x.id == r) {
                    return Err(format!("{} names rule {r}, which does not exist", e.kind));
                }
            }
            let unit = UnitRule::parse(e.unit.as_deref().unwrap_or("source"))?;
            let unless = conditions(&e.kind, "unless", &e.unless)?;
            let when = conditions(&e.kind, "when", &e.when)?;
            edges.push(EdgeDef {
                entry: e.clone(),
                unit,
                unless,
                when,
            });
        }
        Ok(Pack {
            header: file.pack,
            nodes: file.nodes,
            edges,
            native,
        })
    }

    pub fn name(&self) -> &str {
        &self.header.name
    }

    pub fn title(&self) -> &str {
        self.header.title.as_deref().unwrap_or(&self.header.name)
    }

    pub fn version(&self) -> u32 {
        self.header.version
    }

    pub fn trusted(&self) -> bool {
        self.header.trusted
    }

    pub fn description(&self) -> Option<&str> {
        self.header.description.as_deref()
    }

    /// The same pack, trusted or not (`[opengraph] trust` marks a reviewed
    /// pack trusted).
    pub fn with_trusted(mut self, trusted: bool) -> Self {
        self.header.trusted = trusted;
        self
    }

    /// The source kinds this pack applies to.
    pub fn source_kinds(&self) -> &[String] {
        &self.header.source_kinds
    }

    /// The built-in corrections it asks for ([`CORRECTIONS`]).
    pub fn corrections(&self) -> &[String] {
        &self.header.corrections
    }

    /// Whether it asks for the correction `name`.
    pub fn has_correction(&self, name: &str) -> bool {
        self.header.corrections.iter().any(|c| c == name)
    }

    /// Packs whose kinds a file of this source may carry.
    pub fn companions(&self) -> &[String] {
        &self.header.companions
    }

    /// The node kinds it describes, for display.
    pub fn node_views(&self) -> Vec<NodeView> {
        self.nodes
            .iter()
            .map(|n| NodeView {
                kind: n.kind.clone(),
                label: n.label.clone(),
                icon: n.icon.clone().filter(|i| ICONS.contains(&i.as_str())),
                color: n.color.clone(),
            })
            .collect()
    }

    /// The edge kinds it describes, as written (traversable as declared,
    /// whether or not the pack is trusted), for display.
    pub fn edge_views(&self) -> Vec<EdgeView> {
        self.edges
            .iter()
            .map(|d| (&d.entry, d))
            .map(|(e, d)| EdgeView {
                kind: e.kind.clone(),
                traversable: e.traversable,
                cost: e.cost.unwrap_or(1),
                cuttable: e.cuttable.unwrap_or(true),
                fix: e.fix.clone(),
                rule: e.rule.clone(),
                unit: e.unit.clone().unwrap_or_else(|| "source".into()),
                description: e.description.clone(),
                unless: d.unless.iter().map(Cond::describe).collect(),
                when: d.when.iter().map(Cond::describe).collect(),
                derived: e.derived,
            })
            .collect()
    }

    pub fn kind_prefix(&self) -> &str {
        &self.header.kind_prefix
    }

    /// Whether a source that calls itself `source_kind` is this pack's.
    pub fn claims(&self, source_kind: &str) -> bool {
        self.header
            .source_kinds
            .iter()
            .any(|s| s.eq_ignore_ascii_case(source_kind))
    }

    /// Whether this pack describes the edge kind `name`.
    pub fn has_edge(&self, name: &str) -> bool {
        (name.starts_with(&self.header.kind_prefix)
            || self.header.extra_kinds.iter().any(|k| k == name))
            && self.edges.iter().any(|d| d.entry.kind == name)
    }

    /// Native edge kinds accepted from this source.
    pub fn native(&self) -> &[EdgeKind] {
        &self.native
    }

    /// Extra properties to keep for nodes of kind `name`.
    pub fn keep_for(&self, name: &str) -> &[String] {
        self.nodes
            .iter()
            .find(|n| n.kind == name)
            .map(|n| n.keep.as_slice())
            .unwrap_or(&[])
    }

    /// Every node property a condition looks at (kept so conditions can
    /// be checked).
    pub fn condition_keys(&self) -> impl Iterator<Item = &str> {
        self.condition_refs()
            .filter(|(at, _)| *at != End::Edge)
            .map(|(_, k)| k)
    }

    /// Every edge property a condition looks at (`edge.assumed`): the only
    /// edge properties the reader keeps.
    pub fn edge_condition_keys(&self) -> impl Iterator<Item = &str> {
        self.condition_refs()
            .filter(|(at, _)| *at == End::Edge)
            .map(|(_, k)| k)
    }

    fn condition_refs(&self) -> impl Iterator<Item = (End, &str)> {
        self.edges
            .iter()
            .flat_map(|d| d.unless.iter().chain(d.when.iter()))
            .flat_map(|c| {
                let other = match &c.test {
                    Test::SameAs(at, key) => Some((*at, key.as_str())),
                    Test::Equals(_) => None,
                };
                std::iter::once((c.at, c.key.as_str())).chain(other)
            })
    }

    pub(crate) fn edge_sems(&self) -> Vec<(ExtKind, EdgeSem)> {
        self.edges
            .iter()
            .map(|d| {
                let e = &d.entry;
                let sem = EdgeSem {
                    traversable: e.traversable && self.trusted(),
                    declared_traversable: e.traversable,
                    cost: e.cost.unwrap_or(1),
                    cuttable: e.cuttable.unwrap_or(true),
                    fix: e.fix.clone(),
                    control: e.control.unwrap_or(e.traversable),
                    rule: e.rule.clone(),
                    unit: d.unit.clone(),
                    description: e.description.clone(),
                    pack: self.name().to_string(),
                    source_title: self.title().to_string(),
                    unless: d.unless.clone(),
                    when: d.when.clone(),
                    derived: e.derived,
                };
                (kinds::intern(&e.kind), sem)
            })
            .collect()
    }

    pub(crate) fn node_sems(&self) -> Vec<(ExtKind, NodeSem)> {
        self.nodes
            .iter()
            .map(|n| {
                let sem = NodeSem {
                    label: n.label.clone(),
                    icon: n.icon.clone().filter(|i| ICONS.contains(&i.as_str())),
                    color: n.color.clone(),
                    pack: self.name().to_string(),
                };
                (kinds::intern(&n.kind), sem)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_icon_has_one_drawing_and_nothing_else_does() {
        let drawn: Vec<&str> = ICON_GLYPHS.iter().map(|(n, _)| *n).collect();
        assert_eq!(drawn, ICONS);
        for name in ICONS {
            assert_eq!(icon_symbol_id(name), Some(format!("i-x-{name}")));
        }
        for bad in ["", "nope", "id-card\" onload=\"x", "i-x-key", "KEY"] {
            assert_eq!(icon_symbol_id(bad), None, "{bad}");
        }
        let symbols = icon_symbols();
        assert_eq!(symbols.matches("<symbol ").count(), ICONS.len());
        assert!(!symbols.contains("mask") && !symbols.contains(" id=\"m"));
    }

    const OK: &str = r##"
[pack]
name = "test"
version = 1
source_kinds = ["TestHound"]
kind_prefix = "TT_"
trusted = true

[[node]]
kind = "TT_Thing"
icon = "clock"
color = "#abc"

[[edge]]
kind = "TT_Controls"
traversable = true
cost = 3
unit = "start"
fix = "Remove {from} from {to} ({source})."
"##;

    #[test]
    fn embedded_packs_load() {
        let packs = embedded();
        assert!(packs.iter().any(|p| p.name() == "taskhound" && p.trusted()));
        assert!(packs
            .iter()
            .any(|p| p.name() == "mssqlhound" && !p.trusted()));
    }

    #[test]
    fn the_azurehound_pack_loads() {
        let p = azurehound();
        assert!(p.trusted() && p.claims("AzureHound"));
        assert!(p.has_edge("AZResetPassword") && p.has_edge("SyncedToEntraUser"));
        assert!(!p.has_edge("TH_RunsAs"));
        assert!(!embedded().iter().any(|e| e.name() == "azurehound"));
        // Every traversable kind is reported by an Entra rule, never PW-030.
        for (_, sem) in p.edge_sems() {
            assert!(!sem.traversable || sem.rule.is_some());
        }
    }

    #[test]
    fn a_valid_pack_parses() {
        let p = Pack::parse(OK).unwrap();
        assert!(p.claims("testhound"));
        assert!(p.has_edge("TT_Controls"));
        let (_, sem) = &p.edge_sems()[0];
        assert!(sem.traversable && sem.cuttable && sem.control);
        assert_eq!(sem.cost, 3);
        assert_eq!(sem.fix_text("A", "B").unwrap(), "Remove A from B (test).");
    }

    #[test]
    fn invalid_packs_are_refused_whole() {
        let bad = [
            (
                OK.replace("kind = \"TT_Controls\"", "kind = \"XX_Controls\""),
                "prefix",
            ),
            (
                OK.replace("kind = \"TT_Controls\"", "kind = \"MemberOf\""),
                "native",
            ),
            (OK.replace("#abc", "red; background:url(x)"), "color"),
            (OK.replace("{source}", "{prop:password}"), "placeholder"),
            (OK.replace("cost = 3", "cost = 0"), "cost"),
            (
                OK.replace("unit = \"start\"", "unit = \"everything\""),
                "unit",
            ),
            (
                OK.replace("trusted = true", "trusted = true\nsurprise = 1"),
                "unknown field",
            ),
            (OK.replace("icon = \"clock\"", "icon = \"<svg>\""), "icon"),
            (
                OK.replace("[pack]", "[pack]\nnative = [\"NotAKind\"]"),
                "native list",
            ),
            (
                format!("{OK}\n[[edge]]\nkind = \"TT_Other\"\nrule = \"PW-999\"\n"),
                "rule",
            ),
            (
                OK.replace(
                    "[[node]]\nkind = \"TT_Thing\"",
                    "[[node]]\nkind = \"TT_Thing\"\nkeep = [\"password\"]",
                ),
                "secret keep",
            ),
        ];
        for (text, why) in bad {
            assert!(Pack::parse(&text).is_err(), "{why} should be refused");
        }
    }

    #[test]
    fn new_packs_are_untrusted_until_validated() {
        for name in ["mssqlhound", "configmanbearpig"] {
            let p = embedded().iter().find(|p| p.name() == name).unwrap();
            assert!(!p.trusted(), "{name}");
            for (_, sem) in p.edge_sems() {
                assert!(!sem.traversable, "{name}");
            }
        }
        let sccm = embedded()
            .iter()
            .find(|p| p.name() == "configmanbearpig")
            .unwrap();
        assert!(sccm.has_correction("sccm") && sccm.companions() == ["mssqlhound"]);
        assert!(sccm.edge_condition_keys().any(|k| k == "assumed"));
        // Every traversable SCCM kind is context when ConfigManBearPig
        // marks it assumed.
        for (k, sem) in sccm.edge_sems() {
            if sem.declared_traversable {
                assert!(
                    sem.unless
                        .iter()
                        .any(|c| c.at == End::Edge && c.key == "assumed"),
                    "{}",
                    kinds::name(k)
                );
            }
        }
    }

    #[test]
    fn conditions_on_edges_and_between_properties() {
        let text = format!(
            "{OK}\n[[edge]]\nkind = \"TT_Link\"\ntraversable = true\nwhen = {{ \"edge.remotelogin\" = {{ same_as = \"edge.remotecurrentlogin\" }}, \"edge.impersonation\" = false }}\nunless = {{ \"edge.assumed\" = true }}\n"
        );
        let p = Pack::parse(&text).unwrap();
        let mut keys: Vec<&str> = p.edge_condition_keys().collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "assumed",
                "impersonation",
                "remotecurrentlogin",
                "remotelogin"
            ]
        );
        let (_, sem) = p
            .edge_sems()
            .into_iter()
            .find(|(k, _)| kinds::name(*k) == "TT_Link")
            .unwrap();
        let props = |pairs: &[(&str, serde_json::Value)]| -> Vec<(String, serde_json::Value)> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect()
        };
        let check = |p: &[(String, serde_json::Value)]| {
            let get = |at: End, key: &str| {
                (at == End::Edge)
                    .then(|| p.iter().find(|(k, _)| k == key).map(|(_, v)| v))
                    .flatten()
            };
            sem.when.iter().all(|c| c.holds(get)) && !sem.unless.iter().any(|c| c.holds(get))
        };
        use serde_json::json;
        assert!(check(&props(&[
            ("remotelogin", json!("LinkAdmin")),
            ("remotecurrentlogin", json!("linkadmin")),
            ("impersonation", json!(false)),
        ])));
        assert!(!check(&props(&[
            ("remotelogin", json!("sa")),
            ("remotecurrentlogin", json!("scanner")),
            ("impersonation", json!(false)),
        ])));
        // A missing property fails a `when`.
        assert!(!check(&props(&[("impersonation", json!(false))])));
        assert!(!check(&props(&[
            ("remotelogin", json!("a")),
            ("remotecurrentlogin", json!("a")),
            ("impersonation", json!("False")),
            ("assumed", json!(true)),
        ])));
        let view = p
            .edge_views()
            .into_iter()
            .find(|v| v.kind == "TT_Link")
            .unwrap();
        assert!(view
            .when
            .contains(&"edge.remotelogin = edge.remotecurrentlogin".to_string()));

        for (bad, why) in [
            ("[pack]\ncorrections = [\"magic\"]", "unknown correction"),
            ("[pack]\ncompanions = [\"test\"]", "itself as companion"),
            (
                "[[edge]]\nkind = \"TT_X\"\nwhen = { \"node.a\" = 1 }",
                "bad end",
            ),
            (
                "[[edge]]\nkind = \"TT_X\"\nunless = { \"edge.password\" = 1 }",
                "secret",
            ),
            (
                "[[edge]]\nkind = \"TT_X\"\nwhen = { \"edge.a\" = { like = \"x\" } }",
                "bad table",
            ),
        ] {
            let text = if let Some(rest) = bad.strip_prefix("[pack]\n") {
                OK.replace("[pack]\n", &format!("[pack]\n{rest}\n"))
            } else {
                format!("{OK}\n{bad}\n")
            };
            assert!(Pack::parse(&text).is_err(), "{why} should be refused");
        }
    }

    #[test]
    fn untrusted_packs_are_context_only() {
        let p = Pack::parse(&OK.replace("trusted = true", "trusted = false")).unwrap();
        let (_, sem) = &p.edge_sems()[0];
        assert!(!sem.traversable && sem.declared_traversable);
    }

    #[test]
    fn secret_keys() {
        for k in [
            "password",
            "Password",
            "passwordanalysis",
            "clientSecret",
            "nthash",
            "apiToken",
            "trustAuthIncoming",
            "trustAuthOutgoing",
            "initialAuthIncoming",
            "initialAuthOutgoing",
            "currentValue",
            "priorValue",
            "msTPM-OwnerInformation",
            "msFVE-KeyPackage",
        ] {
            assert!(is_secret_key(k), "{k}");
        }
        for k in ["name", "runas", "credentialsstored", "logontype", "isgmsa"] {
            assert!(!is_secret_key(k), "{k}");
        }
    }
}
