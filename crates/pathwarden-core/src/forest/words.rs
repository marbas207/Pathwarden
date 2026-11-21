//! What the forest map says in words: one place for the app's Forest view,
//! `pathwarden summary` and the report, so they never say it differently.
//! [`ForestMap::derive`] fills each map's word fields from its data; a map
//! saved before they existed gets them when it is read
//! ([`ForestMap::document`]).

use serde::{Deserialize, Serialize};

use super::{Crossing, DomainNode, DomainRole, ForestMap, TrustEdge, TrustWay};
use crate::text::count;

/// Why the trust is where its risk shows: the trust itself is not a step
/// of any attack path, though rights that cross it are.
pub const NOT_A_PATH_STEP: &str = "The trust is not an attack path step; rights that cross it \
are. Forged SID history shows here, not in the paths.";

/// A domain the data has only from another domain's record of a trust
/// (it may trust that domain or be trusted by it).
pub const NOT_COLLECTED: &str = "Not collected (known from a trust)";

/// What a trust inside a forest leaves out of what crosses it.
pub const TIER_ZERO_NOT_LISTED: &str =
    "Tier Zero's rights aren't listed: inside a forest, Tier Zero already controls every domain";

/// PW-012 fired on a forest trust's flag alone.
pub const PW012_FLAG_ALONE: &str = "PW-012 is raised from the collector's flag alone; whether \
SID history can be forged across this trust is not in the data";

/// How to find out what the collector's flag can't tell (PW-012 on a forest
/// trust's flag alone).
pub const COLLECT_TRUST_ATTRIBUTES: &str = "collect the trust attributes (RustHound-CE or a \
newer SharpHound gives them)";

/// A way, or a trust, whose SID filtering the data can't tell.
pub const SID_FILTERING_UNKNOWN: &str = "SID filtering unknown";

/// PW-012 fired on a record that is inbound only.
pub const PW012_INBOUND_ONLY: &str = "PW-012 is raised on a record that is inbound only: what the \
trusting side filters is set on its own record, which is not in the data";

/// SID filtering read from the collector's flag, not the trust attributes.
pub const FLAG_ONLY: &str =
    "from the collector's summary flag; the trust's attributes weren't collected";

/// The definitions behind each ⓘ of the Forest view, by key.
pub fn definitions() -> Vec<(&'static str, String)> {
    vec![
        ("attack", "Accounts with an attack path to Tier Zero: the domain's active users and computers outside Tier Zero that can reach any Tier Zero object, as the Tier Zero headline counts them.".into()),
        ("takeover", "Forest takeover: a trust inside one forest. The forest, not the domain, is the security boundary, so whoever controls either domain controls the whole forest. It is how forests work, not a misconfiguration.".into()),
        ("sidhist", format!("SID history abuse: the trusting side filters only the built-in and privileged SIDs (RIDs under 1000), so whoever controls the trusted side can forge SID history it accepts for its other accounts and groups (PW-012). {NOT_A_PATH_STEP}")),
        ("not_collected", format!("{NOT_COLLECTED}: the data has this domain only from another domain's record of a trust, which it may trust or be trusted by. What it filters and who is in it are unknown until it is collected.")),
        ("forest", "A forest: domains joined by trusts inside one forest. The forest, not the domain, is the security boundary.".into()),
        ("inside", "Solid violet: a trust inside one forest. Every one is a forest takeover: whoever controls either domain controls the forest.".into()),
        ("between", format!("Dashed: a trust between two forests. {NOT_A_PATH_STEP}")),
        ("between_abuse", "Red dashed: a trust between forests across which SID history can be forged (PW-012). Such a trust is both between forests and abusable.".into()),
        ("way_in", "Arrows point the way principals go: from the trusted domain into the domain that trusts it. Two heads: both ways.".into()),
        ("unknown", "SID filtering unknown: the trusting side was not collected, its record does not trust the other side, or the collector didn't record this trust's attributes.".into()),
        ("ways", "Each way: principals of one domain going into the domain that trusts them. SID filtering and selective authentication are set by the trusting side, on its own record of the trust.".into()),
        ("crossing", "What crosses it: rights principals of one domain hold in the other: memberships in its groups (not the groups everyone is in), local admin rights, ACEs that grant control and SID history entries. Across forests, Tier Zero's rights count too. These rights are attack path steps.".into()),
    ]
}

/// The definition behind ⓘ `key`.
pub fn definition(key: &str) -> String {
    definitions()
        .into_iter()
        .find(|(k, _)| *k == key)
        .map(|(_, d)| d)
        .unwrap_or_default()
}

/// A domain's attack paths, in words: "5 of 5 active accounts", "have an
/// attack path to Tier Zero", "100%".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PathWords {
    pub count: String,
    pub tail: String,
    pub percent: String,
}

/// What a trust's label and lists call out, first to last.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TrustFlag {
    /// `takeover`, `not_collected`, `abuse`, `unknown` (PW-012 where the
    /// data can't tell), `filtering_on`, `filtering_off`,
    /// `filtering_unknown`.
    pub kind: String,
    pub text: String,
}

impl TrustFlag {
    fn new(kind: &str, text: impl Into<String>) -> Self {
        TrustFlag {
            kind: kind.into(),
            text: text.into(),
        }
    }

    /// The flag a list of trusts tags it with: forest takeover, SID
    /// history abuse, or SID filtering unknown under PW-012.
    pub fn is_tag(&self) -> bool {
        matches!(self.kind.as_str(), "takeover" | "abuse" | "unknown")
    }
}

impl DomainRole {
    /// "forest root", "tree root", "child domain", "role unknown".
    pub fn label(self) -> &'static str {
        match self {
            DomainRole::ForestRoot => "forest root",
            DomainRole::TreeRoot => "tree root",
            DomainRole::Child => "child domain",
            DomainRole::Unknown => "role unknown",
        }
    }
}

impl ForestMap {
    /// Fills the word fields of every domain, trust, way and crossing.
    pub fn derive(&mut self) {
        for d in &mut self.domains {
            derive_domain(d);
        }
        let collected: Vec<(String, bool)> = self
            .domains
            .iter()
            .map(|d| (d.name.to_ascii_uppercase(), d.collected))
            .collect();
        let is_collected = |n: &str| {
            collected
                .iter()
                .find(|(x, _)| x.eq_ignore_ascii_case(n))
                .map(|(_, c)| *c)
        };
        for t in &mut self.trusts {
            for w in &mut t.ways {
                derive_way(w, is_collected(&w.to));
            }
            derive_trust(t, &is_collected);
            for c in &mut t.crossing {
                c.counts = c.counts_text();
            }
        }
        for c in &mut self.indirect {
            c.counts = c.counts_text();
        }
    }

    /// The trust to open on: SID history abuse first, then PW-012 where
    /// the data can't tell, then any between forests, then the first.
    pub fn focus(&self) -> Option<usize> {
        let ts = &self.trusts;
        ts.iter()
            .position(|t| t.abusable_sid_history)
            .or_else(|| ts.iter().position(TrustEdge::sid_filtering_unknown))
            .or_else(|| ts.iter().position(|t| !t.intra_forest))
            .or((!ts.is_empty()).then_some(0))
    }
}

fn derive_domain(d: &mut DomainNode) {
    d.role_text = d.role.label().to_string();
    d.paths = None;
    d.note = None;
    if !d.collected {
        d.note = Some(NOT_COLLECTED.into());
        return;
    }
    match d.exposure_percent {
        None => d.note = Some("No accounts outside Tier Zero".into()),
        Some(p) => {
            d.paths = Some(PathWords {
                count: format!(
                    "{} of {}",
                    crate::text::num(d.exposed),
                    count(d.relevant_population, "active account", "active accounts")
                ),
                tail: format!(
                    "{} an attack path to Tier Zero",
                    if d.exposed == 1 { "has" } else { "have" }
                ),
                percent: crate::posture::share_percent(p),
            })
        }
    }
}

fn derive_way(w: &mut TrustWay, to_collected: Option<bool>) {
    let (filtering, note) = match w.sid_filtering {
        Some(on) => (
            if on {
                "SID filtering on"
            } else {
                "SID filtering off"
            },
            (!w.attributes_known).then(|| FLAG_ONLY.to_string()),
        ),
        None => (
            SID_FILTERING_UNKNOWN,
            Some(if let Some(why) = &w.sid_filtering_unknown {
                why.clone()
            } else if to_collected == Some(true) {
                format!("{}'s record does not trust {}", w.to, w.from)
            } else {
                format!("{} not collected", w.to)
            }),
        ),
    };
    w.filtering = filtering.into();
    w.filtering_note = note;
    w.selective = match w.selective_auth {
        Some(true) => "selective authentication",
        Some(false) => "no selective authentication",
        None => "selective authentication not in the data",
    }
    .into();
    w.abuse_text = w.sid_history_abuse.then(|| {
        format!(
            "whoever controls {} can forge SID history {} accepts (for accounts with RID 1000 and above)",
            w.from, w.to,
        )
    });
}

fn derive_trust(t: &mut TrustEdge, is_collected: &dyn Fn(&str) -> Option<bool>) {
    let mut flags = Vec::new();
    if t.enables_forest_takeover {
        flags.push(TrustFlag::new("takeover", "Forest takeover"));
        let missing: Vec<&str> = [t.source.as_str(), t.target.as_str()]
            .into_iter()
            .filter(|n| is_collected(n) == Some(false))
            .collect();
        if !missing.is_empty() {
            flags.push(TrustFlag::new(
                "not_collected",
                format!("{} not collected", missing.join(", ")),
            ));
        }
    } else if t.abusable_sid_history {
        flags.push(TrustFlag::new("abuse", "SID history abuse · PW-012"));
    } else if t.sid_filtering_unknown() {
        flags.push(TrustFlag::new(
            "unknown",
            format!("{SID_FILTERING_UNKNOWN} · PW-012"),
        ));
    } else if !t.intra_forest && !t.ways.is_empty() {
        flags.push(match t.sid_filtering {
            Some(true) => TrustFlag::new("filtering_on", "SID filtering on"),
            Some(false) => TrustFlag::new("filtering_off", "SID filtering off"),
            None => TrustFlag::new("filtering_unknown", SID_FILTERING_UNKNOWN),
        });
    }
    t.flags = flags;
    t.pw012_note = t.sid_filtering_unknown().then(|| {
        if t.ways.iter().any(|w| w.sid_filtering_unknown.is_some()) {
            format!("{PW012_FLAG_ALONE}; to know, {COLLECT_TRUST_ATTRIBUTES}")
        } else {
            PW012_INBOUND_ONLY.to_string()
        }
    });
    t.crossing_note = t.intra_forest.then(|| TIER_ZERO_NOT_LISTED.to_string());
    t.way_word = match t.direction.as_str() {
        "Bidirectional" => "two-way",
        "Outbound" | "Inbound" => "one-way",
        _ => "disabled",
    }
    .into();
}

impl Crossing {
    /// "1 group membership, 2 control ACEs", as `pathwarden summary` and
    /// the app say it.
    pub fn counts_text(&self) -> String {
        let mut parts = Vec::new();
        for (n, one, many) in [
            (self.memberships, "group membership", "group memberships"),
            (self.admin_rights, "admin right", "admin rights"),
            (self.aces, "control ACE", "control ACEs"),
            (self.sid_history, "SID history entry", "SID history entries"),
        ] {
            if n > 0 {
                parts.push(count(n, one, many));
            }
        }
        parts.join(", ")
    }
}
