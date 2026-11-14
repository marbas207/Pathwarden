//! Which GPO's registry policy wins on a computer, from the
//! GPO links of the OUs and domain above it and what each GPO's
//! `Registry.pol` sets ([`super::regpol`]).
//!
//! Group Policy applies a computer's GPOs domain first, then each OU down
//! to the computer's own, and the last to set a value wins; enforced links
//! come after all of those, the domain's last, so an enforced link high up
//! wins over everything below it. An OU that blocks inheritance stops the
//! non-enforced links above it. Two GPOs linked to the same OU that set a
//! value differently are not decided here: the collectors' link order is
//! not documented well enough to trust, so both values are kept as
//! possible ([`Outcome::Either`]).
//!
//! Disabled links are left out where the built-in collector read the
//! links' status (`gPLink`); RustHound-CE writes disabled links as links.
//! Where the status isn't known (SharpHound or RustHound-CE data alone), a
//! GPO that deletes a value doesn't override a lower one for sure: both are
//! possible.
//!
//! What this can't see: site-linked GPOs (not collected), WMI filters and
//! security filtering (a GPO may not apply to a computer it is linked
//! above), and local policy. That is why what it finds is "inferred".

use std::collections::{HashMap, HashSet};

use petgraph::graph::NodeIndex;

use super::regpol::{self, PolicyValue};
use super::sccm;
use super::CheckStatus;
use crate::graph::AdGraph;
use crate::model::NodeKind;

/// A registry value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Number(u64),
}

/// What one setting comes to on a computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No GPO that applies sets it, or the one that wins deletes it.
    Unset,
    /// Set by this GPO.
    Set(Value, NodeIndex),
    /// GPOs linked to the same OU or domain set it differently: one of
    /// these (`None`: deleted).
    Either(Vec<(Option<Value>, NodeIndex)>),
}

impl Outcome {
    /// The values it may have, with the GPO of each.
    pub fn values(&self) -> Vec<(&Value, NodeIndex)> {
        match self {
            Outcome::Unset => Vec::new(),
            Outcome::Set(v, g) => vec![(v, *g)],
            Outcome::Either(list) => list
                .iter()
                .filter_map(|(v, g)| Some((v.as_ref()?, *g)))
                .collect(),
        }
    }
}

/// What the built-in collector read of GPO links' status: the disabled
/// links, by (container DN, GPO ID), both upper case, and the domains
/// (upper case) whose links' status it read.
#[derive(Debug, Default)]
pub struct LinkStatus {
    disabled: HashSet<(String, String)>,
    read: HashSet<String>,
}

impl LinkStatus {
    pub fn new(g: &AdGraph) -> Self {
        let mut out = LinkStatus::default();
        for d in g.sysvol_domains() {
            if let Some(list) = &d.disabled_links {
                out.read.insert(d.domain.clone());
                out.disabled.extend(list.iter().cloned());
            }
        }
        out
    }

    fn disabled(&self, g: &AdGraph, container: NodeIndex, gpo: NodeIndex) -> bool {
        let Some(dn) = g.node(container).props.distinguishedname.as_deref() else {
            return false;
        };
        self.disabled
            .contains(&(dn.to_ascii_uppercase(), g.node(gpo).id.to_ascii_uppercase()))
    }

    fn known(&self, g: &AdGraph, container: NodeIndex) -> bool {
        g.node(container)
            .domain
            .as_ref()
            .is_some_and(|d| self.read.contains(d))
    }
}

/// The GPOs linked to one OU or domain, in one pass ([`levels`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Level {
    pub gpos: Vec<NodeIndex>,
    /// The links' status was read: disabled ones are left out.
    pub known: bool,
}

/// The registry policy every sidecar recorded, by GPO, and the domains
/// whose GPOs were read.
pub struct Policies<'a> {
    by_gpo: HashMap<NodeIndex, &'a [PolicyValue]>,
    /// Domains (upper case) whose `Registry.pol` files were read, with how.
    read: HashMap<&'a str, CheckStatus>,
    /// The links' status.
    pub links: LinkStatus,
}

impl<'a> Policies<'a> {
    pub fn new(g: &'a AdGraph) -> Self {
        let mut by_gpo = HashMap::new();
        let mut read: HashMap<&str, CheckStatus> = HashMap::new();
        for d in g.sysvol_domains() {
            for (gpo, values) in &d.policy {
                by_gpo.insert(*gpo, values.as_slice());
            }
            let status = d
                .checks
                .registry_pol
                .as_ref()
                .map_or(CheckStatus::NotCollected, |c| c.status);
            // Two sidecars for one domain: the better read counts.
            let e = read.entry(d.domain.as_str()).or_insert(status);
            if status == CheckStatus::Complete || *e == CheckStatus::NotCollected {
                *e = status;
            }
        }
        Policies {
            by_gpo,
            read,
            links: LinkStatus::new(g),
        }
    }

    /// Whether `domain`'s GPOs were read at all (in full or in part).
    pub fn read_in(&self, domain: &str) -> bool {
        self.read
            .get(domain)
            .is_some_and(|s| *s != CheckStatus::NotCollected)
    }

    pub fn is_empty(&self) -> bool {
        self.by_gpo.is_empty()
    }

    /// What `gpo` does to the value `name` of `key`: `None` when it doesn't
    /// touch it, `Some(None)` when it deletes it. The last entry in its
    /// file wins.
    fn effect(&self, gpo: NodeIndex, key: &str, name: &str) -> Option<Option<Value>> {
        let mut out = None;
        for v in self.by_gpo.get(&gpo)?.iter() {
            if v.key != key || !(v.name == name || (v.delete && v.name == "*")) {
                continue;
            }
            out = Some(if v.delete {
                None
            } else if let Some(t) = &v.text {
                Some(Value::Text(t.clone()))
            } else {
                v.number.map(Value::Number)
            });
        }
        out
    }

    /// What the value `name` of `key` comes to through `levels`
    /// ([`levels`]).
    pub fn outcome(&self, levels: &[Level], key: &str, name: &str) -> Outcome {
        let mut out = Outcome::Unset;
        for level in levels {
            let mut effects: Vec<(Option<Value>, NodeIndex)> = Vec::new();
            for &gpo in &level.gpos {
                if let Some(e) = self.effect(gpo, key, name) {
                    if !effects.iter().any(|(v, _)| *v == e) {
                        effects.push((e, gpo));
                    }
                }
            }
            out = match effects.len() {
                0 => continue,
                1 => match effects.pop().expect("one") {
                    (Some(v), gpo) => Outcome::Set(v, gpo),
                    (None, _) if level.known => Outcome::Unset,
                    // Its link may be disabled: the lower value may stand.
                    (None, gpo) => match out {
                        Outcome::Unset => Outcome::Unset,
                        Outcome::Set(v, g) => Outcome::Either(vec![(Some(v), g), (None, gpo)]),
                        Outcome::Either(mut list) => {
                            if !list.iter().any(|(v, _)| v.is_none()) {
                                list.push((None, gpo));
                            }
                            Outcome::Either(list)
                        }
                    },
                },
                _ => Outcome::Either(effects),
            };
        }
        out
    }
}

/// The OUs and the domain above `ix`, the domain first. `None` when the
/// directory doesn't place it under a domain.
fn chain(g: &AdGraph, ix: NodeIndex) -> Option<Vec<NodeIndex>> {
    let mut out = Vec::new();
    let mut at = ix;
    for _ in 0..256 {
        at = g.parent(at)?;
        match g.node(at).kind {
            NodeKind::Domain => {
                out.push(at);
                out.reverse();
                return Some(out);
            }
            NodeKind::Ou => out.push(at),
            // `CN=Computers` and other containers take no GPO links.
            _ => {}
        }
    }
    None
}

/// The GPOs that apply to the computer `ix`, by level in the order Group
/// Policy processes them (the last to set a value wins): the non-enforced
/// links from the domain (or the lowest OU that blocks inheritance) down,
/// then the enforced links from the computer's OU up. `None` when the
/// directory doesn't place it under a domain.
pub fn levels(g: &AdGraph, status: &LinkStatus, ix: NodeIndex) -> Option<Vec<Level>> {
    let chain = chain(g, ix)?;
    let from = chain
        .iter()
        .rposition(|&c| g.blocks_inheritance(c))
        .unwrap_or(0);
    let links = |c: NodeIndex, enforced: bool| -> Level {
        Level {
            gpos: g
                .gp_links(c)
                .iter()
                .filter(|(gpo, e)| *e == enforced && !status.disabled(g, c, *gpo))
                .map(|(gpo, _)| *gpo)
                .collect(),
            known: status.known(g, c),
        }
    };
    let mut out: Vec<Level> = chain[from..].iter().map(|&c| links(c, false)).collect();
    out.extend(chain.iter().rev().map(|&c| links(c, true)));
    out.retain(|l| !l.gpos.is_empty());
    Some(out)
}

/// The GPOs that apply to any of `hosts` (by [`levels`]).
pub fn applying(
    g: &AdGraph,
    status: &LinkStatus,
    hosts: impl IntoIterator<Item = NodeIndex>,
) -> HashSet<NodeIndex> {
    hosts
        .into_iter()
        .filter_map(|h| levels(g, status, h))
        .flatten()
        .flat_map(|l| l.gpos)
        .collect()
}

/// The WSUS server a computer takes its updates from, as Group Policy
/// sets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wsus {
    /// The server URLs (`WUServer`), with the GPO that sets each. One
    /// unless GPOs at one level set it differently.
    pub urls: Vec<(String, NodeIndex)>,
    /// `UseWUServer` and `WUServer` are each set by one GPO: no other
    /// value is possible from the links.
    pub certain: bool,
}

/// [`Wsus`] for the computer `ix`, or `None` when the GPOs that apply
/// don't point it at a WSUS server.
pub fn wsus(g: &AdGraph, p: &Policies, ix: NodeIndex) -> Option<Wsus> {
    let levels = levels(g, &p.links, ix)?;
    let used = p.outcome(&levels, regpol::WINDOWS_UPDATE_AU, "USEWUSERVER");
    let on = used.values().iter().any(|(v, _)| **v == Value::Number(1));
    if !on {
        return None;
    }
    let server = p.outcome(&levels, regpol::WINDOWS_UPDATE, "WUSERVER");
    let urls: Vec<(String, NodeIndex)> = server
        .values()
        .into_iter()
        .filter_map(|(v, gpo)| match v {
            Value::Text(t) if !t.trim().is_empty() => Some((t.trim().to_string(), gpo)),
            _ => None,
        })
        .collect();
    if urls.is_empty() {
        return None;
    }
    let certain = matches!(used, Outcome::Set(..)) && matches!(server, Outcome::Set(..));
    Some(Wsus { urls, certain })
}

/// The SCCM client setup a GPO sets on a computer: the client is pushed
/// to it by Group Policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcmSetup {
    /// The GPO that sets it (the first, when several may).
    pub gpo: NodeIndex,
    /// The site code its setup parameters name, when they all name one.
    pub site_code: Option<String>,
}

/// [`CcmSetup`] for the computer `ix`.
pub fn ccm_setup(g: &AdGraph, p: &Policies, ix: NodeIndex) -> Option<CcmSetup> {
    let levels = levels(g, &p.links, ix)?;
    let set = p.outcome(&levels, regpol::CCM_SETUP, "SETUPPARAMETERS");
    let texts: Vec<(&str, NodeIndex)> = set
        .values()
        .into_iter()
        .filter_map(|(v, gpo)| match v {
            Value::Text(t) => Some((t.as_str(), gpo)),
            Value::Number(_) => None,
        })
        .collect();
    let gpo = texts.first()?.1;
    let mut codes: Vec<Option<String>> = texts.iter().map(|(t, _)| sccm::site_code_in(t)).collect();
    codes.sort();
    codes.dedup();
    let site_code = match codes.as_slice() {
        [Some(c)] => Some(c.clone()),
        _ => None,
    };
    Some(CcmSetup { gpo, site_code })
}

/// The host a WSUS URL names (`http://wsus01.contoso.local:8530/x` gives
/// `wsus01.contoso.local`), and whether it is plain HTTP. `None` for
/// something that isn't an HTTP(S) URL.
pub fn url_host(url: &str) -> Option<(String, bool)> {
    let u = url.trim();
    let lower = u.to_ascii_lowercase();
    let (rest, http) = match lower.strip_prefix("http://") {
        Some(r) => (r, true),
        None => (lower.strip_prefix("https://")?, false),
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = if authority.starts_with('[') {
        // An IPv6 address: never a computer name.
        return Some((authority.to_string(), http));
    } else {
        authority.split(':').next()?
    };
    let host = host.trim_end_matches('.');
    (!host.is_empty()).then(|| (host.to_string(), http))
}

/// Whether `host` is an IP address rather than a name.
pub fn is_ip(host: &str) -> bool {
    host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_from_urls() {
        assert_eq!(
            url_host("http://WSUS01.contoso.local:8530"),
            Some(("wsus01.contoso.local".into(), true))
        );
        assert_eq!(
            url_host(" https://wsus01:8531/ClientWebService "),
            Some(("wsus01".into(), false))
        );
        assert_eq!(url_host("HTTP://10.0.0.5"), Some(("10.0.0.5".into(), true)));
        assert_eq!(url_host("wsus01:8530"), None);
        assert_eq!(url_host("http://"), None);
        assert!(is_ip("10.0.0.5"));
        assert!(is_ip("[fe80::1]"));
        assert!(!is_ip("wsus01"));
    }
}
