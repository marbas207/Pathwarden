//! Which other domains a collection of one domain can also collect, from a
//! run's forest map: what the Collect page lists under "Trusted
//! domains" and `pathwarden collect --trusted` takes.
//!
//! A domain can be read with an account from the collected domain (`home`)
//! when it trusts `home`: every domain of `home`'s forest; a domain of
//! another forest a forest trust joins when that trust lets `home`'s forest
//! in (two-way, or one-way from the other side); a domain an external trust
//! joins to `home` itself, likewise. Selective authentication may still keep
//! the account out: offered, not ticked. So is a domain of another forest or
//! an external trust whose own side of the trust wasn't collected: the flag
//! sits on its trust object, so the run can't know (lab item 53). A trust that only lets the other
//! domain's accounts in, a disabled trust, a domain known only by its SID,
//! and a domain beyond a forest trust (no trust reaches it from `home`) are
//! listed, with the reason, and can't be ticked.

use serde::Serialize;

use super::{DomainRole, ForestMap, TrustEdge};

/// Whether a trusted domain is ticked, offered or can't be collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Pick {
    /// It trusts the collected domain: ticked.
    On,
    /// It trusts it with selective authentication, or across a forest or
    /// external trust whose trusting side wasn't collected, so whether it
    /// does is unknown: the account may not be allowed in. Not ticked.
    Maybe,
    /// It can't be collected with this account ([`TrustedDomain::why`]).
    Off,
}

/// A domain of the forest map besides the collected one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedDomain {
    /// Its DNS name, or its SID when that is all the data has.
    pub name: String,
    /// What joins it to the collected domain: "Child domain · same forest ·
    /// two-way", "External trust · it trusts your domain".
    pub chip: String,
    pub pick: Pick,
    /// Why it isn't ticked, in one sentence.
    pub why: Option<String>,
}

/// The words for a domain the account may not be allowed into.
pub const MAYBE_SELECTIVE: &str = "Your account may not be allowed to sign in there.";
/// The words for a trust that lets only the other domain's accounts in.
pub const OFF_ONE_WAY: &str = "This trust doesn't let accounts from your domain in.";
pub const OFF_DISABLED: &str = "This trust is disabled.";
pub const OFF_SID_ONLY: &str = "Only its SID is known, so there's no name to connect to.";
pub const OFF_BEYOND_FOREST: &str =
    "It's beyond a forest trust, so accounts from your domain can't sign in there.";

/// The words for a domain an external trust joins to another domain of the
/// forest: external trusts aren't transitive.
pub fn off_other_domain(other: &str) -> String {
    format!("Its trust is with {other}, not with your domain.")
}

/// The other domains of `map`, for collecting `home` (any case): ticked
/// ones first, then the ones offered, then the ones that can't be; in the
/// map's order within each. Empty when `home` isn't in the map.
pub fn trusted_domains(map: &ForestMap, home: &str) -> Vec<TrustedDomain> {
    let Some(h) = map.domain(home) else {
        return Vec::new();
    };
    let mut out: Vec<TrustedDomain> = map
        .domains
        .iter()
        .filter(|d| !d.name.eq_ignore_ascii_case(&h.name))
        .map(|d| choose(map, &h.name, h.forest, d))
        .collect();
    out.sort_by_key(|t| t.pick);
    out
}

/// The names `pathwarden collect --trusted` collects: the ticked ones.
pub fn readable(choices: &[TrustedDomain]) -> Vec<String> {
    choices
        .iter()
        .filter(|t| t.pick == Pick::On)
        .map(|t| t.name.clone())
        .collect()
}

fn is_sid(name: &str) -> bool {
    name.get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("S-1-"))
}

fn role_word(role: DomainRole) -> &'static str {
    match role {
        DomainRole::ForestRoot => "Forest root",
        DomainRole::TreeRoot => "Tree root",
        DomainRole::Child => "Child domain",
        DomainRole::Unknown => "Domain",
    }
}

/// The trust's type in words: "Forest trust", "External trust".
fn type_word(t: &TrustEdge) -> String {
    match t.trust_type.to_ascii_lowercase().as_str() {
        "forest" => "Forest trust".into(),
        "external" => "External trust".into(),
        "parentchild" => "Parent-child trust".into(),
        "crosslink" => "Shortcut trust".into(),
        "" | "unknown" => "Trust".into(),
        other => format!("{} trust", capitalized(other)),
    }
}

fn capitalized(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// How `t` joins `from`'s side to `to`'s side (`inside_from`, `inside_to`
/// say which ends are which): whether `to`'s side lets `from`'s accounts
/// in, whether the other way is used too, whether selective authentication
/// applies, and whether it is disabled.
struct Way {
    lets_in: bool,
    back: bool,
    /// `Some(true)` when a record says so, `Some(false)` when the trusting
    /// side's record says no, `None` when the trusting side wasn't collected
    /// (or its record lacks the flag): the flag sits on the trusting side's
    /// own trust object, which the run never read (lab item 53).
    selective: Option<bool>,
    disabled: bool,
}

fn way(t: &TrustEdge, inside_from: &dyn Fn(&str) -> bool, inside_to: &dyn Fn(&str) -> bool) -> Way {
    let lets_in = t
        .ways
        .iter()
        .any(|w| inside_from(&w.from) && inside_to(&w.to));
    let back = t
        .ways
        .iter()
        .any(|w| inside_to(&w.from) && inside_from(&w.to));
    // Any record with the flag makes it selective (the cautious side);
    // otherwise as the trusting side records it, unknown without its record.
    let selective = if t.records.iter().any(|r| r.selective_auth == Some(true)) {
        Some(true)
    } else {
        t.ways
            .iter()
            .find(|w| inside_from(&w.from) && inside_to(&w.to))
            .and_then(|w| w.selective_auth)
    };
    let disabled = t.direction.eq_ignore_ascii_case("Disabled") || t.ways.is_empty();
    Way {
        lets_in,
        back,
        selective,
        disabled,
    }
}

/// Selective authentication on a trust between forests or an external
/// trust: known, offered unticked with the chip saying so; unknown (the
/// trusting side wasn't collected), offered unticked too, since the
/// account may be refused there.
fn mark_selective(out: &mut TrustedDomain, chip: &mut String, selective: Option<bool>) {
    match selective {
        Some(false) => {}
        Some(true) => {
            chip.push_str(" · selective authentication");
            out.pick = Pick::Maybe;
            out.why = Some(MAYBE_SELECTIVE.into());
        }
        None => {
            out.pick = Pick::Maybe;
            out.why = Some(MAYBE_SELECTIVE.into());
        }
    }
}

fn choose(map: &ForestMap, home: &str, home_forest: usize, d: &super::DomainNode) -> TrustedDomain {
    let same = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    let forest_of = |name: &str| map.domain(name).map(|n| n.forest);
    let direct = map.trusts.iter().find(|t| {
        (same(&t.source, home) && same(&t.target, &d.name))
            || (same(&t.target, home) && same(&t.source, &d.name))
    });
    let is_home = |n: &str| same(n, home);
    let is_d = |n: &str| same(n, &d.name);
    let mut out = TrustedDomain {
        name: d.name.clone(),
        chip: String::new(),
        pick: Pick::On,
        why: None,
    };
    let off = |out: &mut TrustedDomain, why: &str| {
        out.pick = Pick::Off;
        out.why = Some(why.to_string());
    };

    if d.forest == home_forest {
        // Inside the forest every domain trusts every other.
        let mut chip = format!("{} · same forest", role_word(d.role));
        if let Some(t) = direct {
            let w = way(t, &is_home, &is_d);
            if w.disabled {
                off(&mut out, OFF_DISABLED);
            } else if w.lets_in && w.back {
                chip.push_str(" · two-way");
            }
        }
        out.chip = chip;
    } else if let Some(t) = direct {
        let w = way(t, &is_home, &is_d);
        let mut chip = type_word(t);
        if w.disabled {
            off(&mut out, OFF_DISABLED);
        } else if !w.lets_in {
            chip.push_str(" · one-way");
            off(&mut out, OFF_ONE_WAY);
        } else {
            chip.push_str(if w.back {
                " · two-way"
            } else {
                " · it trusts your domain"
            });
            mark_selective(&mut out, &mut chip, w.selective);
        }
        out.chip = chip;
    } else {
        // Another forest: a forest trust between the two forests.
        let in_home_forest = |n: &str| forest_of(n) == Some(home_forest);
        let in_d_forest = |n: &str| forest_of(n) == Some(d.forest);
        let forest_trust = map.trusts.iter().find(|t| {
            t.trust_type.eq_ignore_ascii_case("forest")
                && ((in_home_forest(&t.source) && in_d_forest(&t.target))
                    || (in_home_forest(&t.target) && in_d_forest(&t.source)))
        });
        match forest_trust {
            Some(t) => {
                let w = way(t, &in_home_forest, &in_d_forest);
                let mut chip = format!("{} · forest trust", role_word(d.role));
                if w.disabled {
                    off(&mut out, OFF_DISABLED);
                } else if !w.lets_in {
                    chip.push_str(" · one-way");
                    off(&mut out, OFF_ONE_WAY);
                } else {
                    chip.push_str(if w.back {
                        " · two-way"
                    } else {
                        " · it trusts your forest"
                    });
                    mark_selective(&mut out, &mut chip, w.selective);
                }
                out.chip = chip;
            }
            None => {
                // Known only through another domain's trust: an external
                // trust of another domain of the forest (not transitive),
                // or a domain beyond another forest.
                let via = map
                    .trusts
                    .iter()
                    .find(|t| is_d(&t.source) || is_d(&t.target));
                out.chip = via.map(type_word).unwrap_or_else(|| "Trust".into());
                let other = via.map(|t| {
                    if is_d(&t.source) {
                        &t.target
                    } else {
                        &t.source
                    }
                });
                match other.filter(|o| in_home_forest(o)) {
                    Some(o) => off(&mut out, &off_other_domain(o)),
                    None => off(&mut out, OFF_BEYOND_FOREST),
                }
            }
        }
    }
    if is_sid(&d.name) {
        // Its trust's type is all there is to say.
        if let Some(t) = direct {
            out.chip = type_word(t);
        }
        off(&mut out, OFF_SID_ONLY);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn map_of(dir: &str) -> ForestMap {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata")
            .join(dir);
        let config = crate::config::Config::default();
        let opts = crate::LoadOptions::default();
        crate::analyze::run(&[dir], &config, &opts.extra_tier_zero, &mut |_| {})
            .unwrap()
            .forest_map()
    }

    /// Every kind of trust the Collect page shows, from one collected
    /// domain's records.
    #[test]
    fn each_trust_says_whether_its_domain_can_be_collected() {
        let map = map_of("trusts");
        let got: Vec<(String, String, Pick, Option<String>)> =
            trusted_domains(&map, "contoso.local")
                .into_iter()
                .map(|t| (t.name, t.chip, t.pick, t.why))
                .collect();
        let want = |n: &str, chip: &str, pick: Pick, why: Option<&str>| {
            (
                n.to_string(),
                chip.to_string(),
                pick,
                why.map(str::to_string),
            )
        };
        assert_eq!(
            got,
            [
                want(
                    "CHILD.CONTOSO.LOCAL",
                    "Child domain · same forest · two-way",
                    Pick::On,
                    None
                ),
                // Not collected: whether they use selective
                // authentication is on their own trust objects.
                want(
                    "FABRIKAM.COM",
                    "Forest trust · two-way",
                    Pick::Maybe,
                    Some(MAYBE_SELECTIVE)
                ),
                want(
                    "TAILSPIN.COM",
                    "External trust · it trusts your domain",
                    Pick::Maybe,
                    Some(MAYBE_SELECTIVE)
                ),
                want(
                    "WINGTIP.COM",
                    "External trust · two-way · selective authentication",
                    Pick::Maybe,
                    Some(MAYBE_SELECTIVE)
                ),
                want(
                    "ADVENTURE-WORKS.COM",
                    "External trust",
                    Pick::Off,
                    Some(OFF_DISABLED)
                ),
                want(
                    "NORTHWIND.COM",
                    "External trust · one-way",
                    Pick::Off,
                    Some(OFF_ONE_WAY)
                ),
                want(
                    "S-1-5-21-8000-8000-8000",
                    "External trust",
                    Pick::Off,
                    Some(OFF_SID_ONLY)
                ),
            ],
            "{got:#?}"
        );
        assert_eq!(
            readable(&trusted_domains(&map, "CONTOSO.LOCAL")),
            ["CHILD.CONTOSO.LOCAL"]
        );
        assert!(trusted_domains(&map, "elsewhere.local").is_empty());
    }

    /// From a child domain: the rest of its forest, and the domains of
    /// another forest a forest trust lets in; a domain only another domain
    /// trusts is beyond reach.
    #[test]
    fn a_forest_trust_reaches_the_other_forest_and_no_further() {
        let mut map = map_of("trusts");
        let fabrikam = map.domain("FABRIKAM.COM").unwrap().forest;
        // A child of FABRIKAM.COM, and a domain FABRIKAM.COM alone trusts.
        let mut child = map.domain("FABRIKAM.COM").unwrap().clone();
        child.name = "EU.FABRIKAM.COM".into();
        child.role = DomainRole::Child;
        map.domains.push(child.clone());
        let mut beyond = child.clone();
        beyond.name = "LITWARE.COM".into();
        beyond.forest = map.forests.len();
        beyond.role = DomainRole::Unknown;
        map.domains.push(beyond);
        let mut t = map
            .trusts
            .iter()
            .find(|t| t.target == "TAILSPIN.COM")
            .unwrap()
            .clone();
        t.source = "FABRIKAM.COM".into();
        t.target = "LITWARE.COM".into();
        map.trusts.push(t);
        let from_child = trusted_domains(&map, "CHILD.CONTOSO.LOCAL");
        let pick = |n: &str| from_child.iter().find(|t| t.name == n).cloned().unwrap();
        assert_eq!(pick("CONTOSO.LOCAL").pick, Pick::On);
        assert_eq!(
            pick("CONTOSO.LOCAL").chip,
            "Forest root · same forest · two-way"
        );
        // FABRIKAM.COM's side of the forest trust wasn't collected.
        assert_eq!(pick("FABRIKAM.COM").pick, Pick::Maybe);
        assert_eq!(
            pick("FABRIKAM.COM").chip,
            "Forest root · forest trust · two-way"
        );
        assert_eq!(pick("EU.FABRIKAM.COM").pick, Pick::Maybe, "{fabrikam}");
        let litware = pick("LITWARE.COM");
        assert_eq!(litware.pick, Pick::Off);
        assert_eq!(litware.why.as_deref(), Some(OFF_BEYOND_FOREST));
        // External trusts aren't transitive: TAILSPIN.COM trusts CONTOSO
        // only.
        assert_eq!(pick("TAILSPIN.COM").pick, Pick::Off);
        assert_eq!(
            pick("TAILSPIN.COM").why.as_deref(),
            Some("Its trust is with CONTOSO.LOCAL, not with your domain.")
        );
    }

    /// Sets how `trusting`'s side records the trust's way into it, as when
    /// that domain was collected too.
    fn record_side(map: &mut ForestMap, trusting: &str, selective: Option<bool>) {
        for t in &mut map.trusts {
            for w in &mut t.ways {
                if w.to.eq_ignore_ascii_case(trusting) {
                    w.selective_auth = selective;
                }
            }
        }
    }

    /// Lab item 53 (GOAD): the last run read only the home forest's record
    /// of the forest trust, and the flag sits on the other forest's record.
    /// Unknown is offered, not ticked; once its side is read, it decides.
    #[test]
    fn selective_authentication_unknown_until_the_trusting_side_is_read() {
        let mut map = map_of("trusts");
        let fabrikam = |map: &ForestMap| {
            trusted_domains(map, "CONTOSO.LOCAL")
                .into_iter()
                .find(|t| t.name == "FABRIKAM.COM")
                .unwrap()
        };
        let unknown = fabrikam(&map);
        assert_eq!(unknown.pick, Pick::Maybe);
        assert_eq!(unknown.why.as_deref(), Some(MAYBE_SELECTIVE));
        assert!(!unknown.chip.contains("selective"), "{}", unknown.chip);
        assert!(!readable(&trusted_domains(&map, "CONTOSO.LOCAL")).contains(&unknown.name));

        record_side(&mut map, "FABRIKAM.COM", Some(true));
        let on = fabrikam(&map);
        assert_eq!(on.pick, Pick::Maybe);
        assert_eq!(on.chip, "Forest trust · two-way · selective authentication");

        record_side(&mut map, "FABRIKAM.COM", Some(false));
        let off = fabrikam(&map);
        assert_eq!((off.pick, off.why), (Pick::On, None));
        assert!(readable(&trusted_domains(&map, "CONTOSO.LOCAL")).contains(&off.name));

        // Inside the forest selective authentication doesn't apply: the
        // child domain is ticked though its side wasn't collected.
        let child = trusted_domains(&map, "CONTOSO.LOCAL")
            .into_iter()
            .find(|t| t.name == "CHILD.CONTOSO.LOCAL")
            .unwrap();
        assert_eq!(child.pick, Pick::On);
    }
}
