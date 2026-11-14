//! AD CS (certificate services) abuse, following BloodHound CE's edge logic
//! (`packages/go/analysis/ad/esc*.go`):
//!
//! 1. Link the PKI: which CAs are trusted for NT authentication, which root they
//!    chain to, which issuance policies templates carry.
//! 2. Keep only *eligible* Enterprise CAs: an enabled hosting computer, a chain to
//!    a root CA for the domain, and membership of that domain's NTAuth store.
//!    Certificates from any other CA cannot be used to log on.
//! 3. For each template published to an eligible CA, test each ESC condition and
//!    add an edge from every principal who can abuse it to what it compromises
//!    (the domain, or for ESC13 the linked group).

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::Serialize;

use crate::dcsettings::{self, Mapping, Verdict, Weakness};
use crate::graph::AdGraph;
use crate::model::{AdcsProps, EdgeKind, NodeKind, EKU_ANY_PURPOSE, EKU_CERT_REQUEST_AGENT};
use crate::postprocess::forest_components;
use crate::sid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Esc {
    Esc1,
    Esc3,
    Esc4,
    Esc6a,
    Esc6b,
    Esc8,
    Esc9a,
    Esc9b,
    Esc10a,
    Esc10b,
    Esc11,
    Esc13,
}

impl Esc {
    pub fn label(self) -> &'static str {
        match self {
            Esc::Esc1 => "ESC1",
            Esc::Esc3 => "ESC3",
            Esc::Esc4 => "ESC4",
            Esc::Esc6a => "ESC6a",
            Esc::Esc6b => "ESC6b",
            Esc::Esc8 => "ESC8",
            Esc::Esc9a => "ESC9a",
            Esc::Esc9b => "ESC9b",
            Esc::Esc10a => "ESC10a",
            Esc::Esc10b => "ESC10b",
            Esc::Esc11 => "ESC11",
            Esc::Esc13 => "ESC13",
        }
    }

    /// The graph edge this abuse adds, if any. ESC8 and ESC11 (NTLM relay) need
    /// coercion of a specific victim, so they are reported without an edge.
    pub fn edge(self) -> Option<EdgeKind> {
        Some(match self {
            Esc::Esc1 => EdgeKind::AdcsEsc1,
            Esc::Esc3 => EdgeKind::AdcsEsc3,
            Esc::Esc4 => EdgeKind::AdcsEsc4,
            Esc::Esc6a => EdgeKind::AdcsEsc6a,
            Esc::Esc6b => EdgeKind::AdcsEsc6b,
            Esc::Esc9a => EdgeKind::AdcsEsc9a,
            Esc::Esc9b => EdgeKind::AdcsEsc9b,
            Esc::Esc10a => EdgeKind::AdcsEsc10a,
            Esc::Esc10b => EdgeKind::AdcsEsc10b,
            Esc::Esc13 => EdgeKind::AdcsEsc13,
            Esc::Esc8 | Esc::Esc11 => return None,
        })
    }
}

/// One exploitable AD CS condition: who can abuse which template on which CA,
/// and what they gain.
#[derive(Debug, Clone)]
pub struct EscInstance {
    pub esc: Esc,
    pub ca: NodeIndex,
    pub template: Option<NodeIndex>,
    /// ESC3: the template enrolled on behalf of others. ESC13: the linked group.
    pub related: Option<NodeIndex>,
    /// Principals that can perform the abuse (minimal: groups rather than
    /// each of their members).
    pub sources: Vec<NodeIndex>,
    /// ESC9/ESC10: accounts whose certificate mapping an attacker can hijack.
    pub victims: Vec<NodeIndex>,
    /// Domains (or, for ESC13, the group) compromised.
    pub targets: Vec<NodeIndex>,
    /// Domains where abuse depends on a domain controller setting the
    /// collector could not read. No attack edges lead to them.
    pub unverified: Vec<NodeIndex>,
    /// ESC6/ESC9/ESC10: the domain controllers that make `targets` open.
    pub weak_dcs: Vec<WeakDc>,
}

struct EligibleCa {
    ca: NodeIndex,
    host: NodeIndex,
    domains: Vec<NodeIndex>,
}

pub fn run(g: &mut AdGraph) {
    let pki = link_pki(g);
    for (a, b, kind) in pki {
        g.add_edge(a, b, kind);
    }
    let cas = eligible_cas(g);
    let mut edges: Vec<(NodeIndex, NodeIndex, EdgeKind)> = Vec::new();
    for ca in &cas {
        edges.extend(
            ca.domains
                .iter()
                .map(|&d| (ca.host, d, EdgeKind::GoldenCert)),
        );
    }
    let mut found = Vec::new();
    let forests = forest_components(g);
    for ca in &cas {
        templates_on(g, ca, &forests, &mut found);
    }
    esc3(g, &cas, &mut found, &mut edges);
    for inst in &found {
        if let Some(kind) = inst.esc.edge() {
            for &s in &inst.sources {
                for &t in &inst.targets {
                    edges.push((s, t, kind));
                }
            }
        }
    }
    for (a, b, kind) in edges {
        g.add_edge(a, b, kind);
    }
    g.set_esc_instances(found);
}

fn props(g: &AdGraph, ix: NodeIndex) -> Option<&AdcsProps> {
    g.node(ix).adcs.as_deref()
}

fn of_kind(g: &AdGraph, kind: NodeKind) -> Vec<NodeIndex> {
    g.nodes()
        .filter(|(_, n)| n.kind == kind && !n.placeholder)
        .map(|(ix, _)| ix)
        .collect()
}

fn neighbors(g: &AdGraph, ix: NodeIndex, dir: Direction, kinds: &[EdgeKind]) -> Vec<NodeIndex> {
    let mut out: Vec<NodeIndex> = g
        .inner()
        .edges_directed(ix, dir)
        .filter(|e| kinds.contains(e.weight()))
        .map(|e| match dir {
            Direction::Incoming => e.source(),
            Direction::Outgoing => e.target(),
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn holders(g: &AdGraph, target: NodeIndex, kinds: &[EdgeKind]) -> Vec<NodeIndex> {
    neighbors(g, target, Direction::Incoming, kinds)
}

const TEMPLATE_ENROLL: &[EdgeKind] = &[
    EdgeKind::Enroll,
    EdgeKind::GenericAll,
    EdgeKind::AllExtendedRights,
];

fn link_pki(g: &AdGraph) -> Vec<(NodeIndex, NodeIndex, EdgeKind)> {
    let thumb = |ix| props(g, ix).and_then(|p| p.certthumbprint.clone());
    let cas = of_kind(g, NodeKind::EnterpriseCa);
    let anchors: Vec<NodeIndex> = of_kind(g, NodeKind::RootCa)
        .into_iter()
        .chain(of_kind(g, NodeKind::AiaCa))
        .collect();
    let stores = of_kind(g, NodeKind::NtAuthStore);
    let mut edges = Vec::new();

    for &ca in &cas {
        let Some(t) = thumb(ca) else { continue };
        for &s in &stores {
            if props(g, s).is_some_and(|p| p.certthumbprints.contains(&t)) {
                edges.push((ca, s, EdgeKind::TrustedForNtAuth));
            }
        }
        for &a in &anchors {
            if thumb(a).as_ref() == Some(&t) {
                edges.push((ca, a, EdgeKind::EnterpriseCaFor));
            }
        }
    }
    let signers: Vec<NodeIndex> = cas.iter().chain(&anchors).copied().collect();
    for &x in &signers {
        let Some(issuer) = props(g, x).and_then(|p| p.certchain.get(1)) else {
            continue;
        };
        for &y in &signers {
            if y != x && thumb(y).as_ref() == Some(issuer) {
                edges.push((x, y, EdgeKind::IssuedSignedBy));
            }
        }
    }
    let policies = of_kind(g, NodeKind::IssuancePolicy);
    for t in of_kind(g, NodeKind::CertTemplate) {
        let Some(tp) = props(g, t) else { continue };
        let t_domain = g.node(t).domain_sid.as_deref().filter(|d| !d.is_empty());
        for &p in &policies {
            let same_domain = t_domain.is_some() && g.node(p).domain_sid.as_deref() == t_domain;
            let oid = props(g, p).and_then(|pp| pp.certtemplateoid.as_ref());
            if same_domain && oid.is_some_and(|oid| tp.certificatepolicy.contains(oid)) {
                edges.push((t, p, EdgeKind::ExtendedByPolicy));
            }
        }
    }
    edges
}

fn eligible_cas(g: &AdGraph) -> Vec<EligibleCa> {
    let mut out = Vec::new();
    for ca in of_kind(g, NodeKind::EnterpriseCa) {
        let host = holders(g, ca, &[EdgeKind::HostsCaService])
            .into_iter()
            .find(|&h| {
                let n = g.node(h);
                n.kind == NodeKind::Computer && !n.placeholder && n.props.enabled == Some(true)
            });
        let Some(host) = host else { continue };

        // CA -> (IssuedSignedBy | EnterpriseCAFor)* -> RootCA -> RootCAFor -> Domain
        let mut root_domains = HashSet::new();
        let mut seen = HashSet::from([ca]);
        let mut queue = VecDeque::from([ca]);
        while let Some(v) = queue.pop_front() {
            if g.node(v).kind == NodeKind::RootCa {
                root_domains.extend(neighbors(g, v, Direction::Outgoing, &[EdgeKind::RootCaFor]));
            }
            for next in neighbors(
                g,
                v,
                Direction::Outgoing,
                &[EdgeKind::IssuedSignedBy, EdgeKind::EnterpriseCaFor],
            ) {
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
        // CA -> TrustedForNTAuth -> NTAuthStore -> NTAuthStoreFor -> Domain
        let ntauth_domains: HashSet<NodeIndex> =
            neighbors(g, ca, Direction::Outgoing, &[EdgeKind::TrustedForNtAuth])
                .into_iter()
                .flat_map(|s| neighbors(g, s, Direction::Outgoing, &[EdgeKind::NtAuthStoreFor]))
                .collect();
        let mut domains: Vec<NodeIndex> = root_domains
            .intersection(&ntauth_domains)
            .copied()
            .collect();
        domains.sort_unstable();
        if !domains.is_empty() {
            out.push(EligibleCa { ca, host, domains });
        }
    }
    out
}

/// Everyone and Authenticated Users stand for "every principal".
fn is_everyone(g: &AdGraph, set: &[NodeIndex]) -> bool {
    set.iter().any(|&p| sid::is_implicit_group(&g.node(p).id))
}

fn effective(g: &AdGraph, set: &[NodeIndex]) -> HashSet<NodeIndex> {
    let mut out: HashSet<NodeIndex> = set.iter().copied().collect();
    for &p in set {
        out.extend(g.transitive_members(p));
    }
    out
}

/// Principals that hold a right from *every* set, after expanding groups,
/// reduced to the outermost ones (a group, not each of its members). A set
/// granted to Everyone / Authenticated Users is satisfied by anyone.
fn cross(g: &AdGraph, sets: &[&[NodeIndex]]) -> Vec<NodeIndex> {
    if sets.iter().any(|s| s.is_empty()) {
        return Vec::new();
    }
    let specific: Vec<&[NodeIndex]> = sets
        .iter()
        .copied()
        .filter(|s| !is_everyone(g, s))
        .collect();
    let mut out: Vec<NodeIndex> = if specific.is_empty() {
        sets.iter()
            .flat_map(|s| s.iter().copied())
            .filter(|&p| sid::is_implicit_group(&g.node(p).id))
            .collect()
    } else {
        let mut acc = effective(g, specific[0]);
        for s in &specific[1..] {
            let e = effective(g, s);
            acc.retain(|p| e.contains(p));
        }
        acc.iter()
            .copied()
            .filter(|&p| {
                !g.inner()
                    .edges_directed(p, Direction::Outgoing)
                    .any(|e| *e.weight() == EdgeKind::MemberOf && acc.contains(&e.target()))
            })
            .collect()
    };
    out.sort_unstable();
    out.dedup();
    out
}

/// Individual accounts (of `kinds`) that hold a right from every set.
fn accounts(g: &AdGraph, sets: &[&[NodeIndex]], kinds: &[NodeKind]) -> Vec<NodeIndex> {
    if sets.iter().any(|s| s.is_empty()) {
        return Vec::new();
    }
    let specific: Vec<&[NodeIndex]> = sets
        .iter()
        .copied()
        .filter(|s| !is_everyone(g, s))
        .collect();
    let mut out: Vec<NodeIndex> = if specific.is_empty() {
        g.nodes().map(|(ix, _)| ix).collect()
    } else {
        let mut acc = effective(g, specific[0]);
        for s in &specific[1..] {
            let e = effective(g, s);
            acc.retain(|p| e.contains(p));
        }
        acc.into_iter().collect()
    };
    out.retain(|&ix| {
        let n = g.node(ix);
        kinds.contains(&n.kind) && !n.placeholder
    });
    out.sort_unstable();
    out
}

/// Templates that require a DNS name in the SAN can only be abused by
/// principals that have one, so users are excluded.
fn dns_filter(g: &AdGraph, template: &AdcsProps, mut sources: Vec<NodeIndex>) -> Vec<NodeIndex> {
    if template.requires_dns_san() {
        sources.retain(|&s| g.node(s).kind != NodeKind::User);
    }
    sources
}

/// Domain controllers in the same forest as `domain`.
fn forest_dcs<'a>(
    g: &'a AdGraph,
    domain: NodeIndex,
    forests: &HashMap<String, usize>,
) -> impl Iterator<Item = (NodeIndex, &'a crate::model::Node)> + 'a {
    let name = g.node(domain).name.clone();
    let forest = forests.get(&name).copied();
    let forests = forests.clone();
    g.nodes().filter(move |(_, n)| {
        n.kind == NodeKind::Computer
            && n.is_dc
            && match (&n.domain, forest) {
                (Some(d), Some(f)) => forests.get(d) == Some(&f),
                (Some(d), None) => *d == name,
                (None, _) => false,
            }
    })
}

/// A domain controller that accepts weak certificate mappings, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WeakDc {
    pub dc: NodeIndex,
    pub mapping: Mapping,
    pub why: Weakness,
}

/// Whether a domain controller setting makes an abuse possible.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Gate {
    /// The DCs that accept weak mappings.
    Open(Vec<WeakDc>),
    Closed,
    /// Not collected, or not set where the default depends on a patch level
    /// that is not known.
    Unknown,
}

/// Open if any DC in the forest is open; unknown if none is open but some
/// (or all, when there are no DCs in the data) could not be read. Kerberos:
/// StrongCertificateBindingEnforcement ([`dcsettings::kdc_weak_mapping`]);
/// Schannel: CertificateMappingMethods' UPN bit
/// ([`dcsettings::schannel_upn_mapping`]). Both read the DC's OS build.
fn forest_gate(
    g: &AdGraph,
    d: NodeIndex,
    forests: &HashMap<String, usize>,
    mapping: Mapping,
) -> Gate {
    let (mut any, mut unknown, mut weak) = (false, false, Vec::new());
    for (dc, n) in forest_dcs(g, d, forests) {
        any = true;
        match dcsettings::verdict(&n.props, mapping) {
            Verdict::Weak(why) => weak.push(WeakDc { dc, mapping, why }),
            Verdict::Unknown => unknown = true,
            Verdict::Strong => {}
        }
    }
    if !weak.is_empty() {
        Gate::Open(weak)
    } else if any && !unknown {
        Gate::Closed
    } else {
        Gate::Unknown
    }
}

/// Domains split by a gate. Closed domains are dropped.
#[derive(Default)]
struct Gated {
    open: Vec<NodeIndex>,
    unknown: Vec<NodeIndex>,
    /// The weak DCs behind `open`.
    weak: Vec<WeakDc>,
}

fn gated(
    g: &AdGraph,
    domains: &[NodeIndex],
    forests: &HashMap<String, usize>,
    mapping: Mapping,
) -> Gated {
    let mut out = Gated::default();
    for &d in domains {
        match forest_gate(g, d, forests, mapping) {
            Gate::Open(weak) => {
                out.open.push(d);
                out.weak.extend(weak);
            }
            Gate::Unknown => out.unknown.push(d),
            Gate::Closed => {}
        }
    }
    out.weak.sort_unstable();
    out.weak.dedup();
    out
}

const WRITE_OVER_ACCOUNT: &[EdgeKind] = &[
    EdgeKind::GenericAll,
    EdgeKind::GenericWrite,
    EdgeKind::Owns,
    EdgeKind::WriteOwner,
    EdgeKind::WriteDacl,
];

/// Principals that can rewrite a victim's UPN/dNSHostName to impersonate someone.
/// `Base` is a principal of unknown kind: RustHound-CE (from 2.5.30) types
/// a foreign or unresolved one so, where earlier versions said `Group`.
fn hijackers(g: &AdGraph, victims: &[NodeIndex]) -> Vec<NodeIndex> {
    let mut out: Vec<NodeIndex> = victims
        .iter()
        .flat_map(|&v| holders(g, v, WRITE_OVER_ACCOUNT))
        .filter(|&a| {
            matches!(
                g.node(a).kind,
                NodeKind::User | NodeKind::Group | NodeKind::Computer | NodeKind::Base
            )
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn templates_on(
    g: &AdGraph,
    ca: &EligibleCa,
    forests: &HashMap<String, usize>,
    found: &mut Vec<EscInstance>,
) {
    let Some(cap) = props(g, ca.ca) else { return };
    let ca_enr = holders(g, ca.ca, &[EdgeKind::Enroll]);
    let inst = |esc, template, sources: Vec<NodeIndex>, targets: Vec<NodeIndex>| EscInstance {
        esc,
        ca: ca.ca,
        template,
        related: None,
        sources,
        victims: Vec::new(),
        targets,
        unverified: Vec::new(),
        weak_dcs: Vec::new(),
    };

    if !cap.vulnerableendpoints.is_empty() {
        found.push(inst(Esc::Esc8, None, Vec::new(), ca.domains.clone()));
    }

    for t in holders(g, ca.ca, &[EdgeKind::PublishedTo]) {
        let Some(tp) = props(g, t) else { continue };
        let t_enr = holders(g, t, TEMPLATE_ENROLL);
        let approval_off = tp.requiresmanagerapproval == Some(false);
        let auth = tp.authenticationenabled == Some(true);
        let schannel = tp.schannelauthenticationenabled == Some(true);
        let no_sigs = tp.no_extra_signatures();
        let supplies_subject = tp.enrolleesuppliessubject;

        // ESC11: the CA takes requests over RPC without packet privacy, so a
        // relayed NTLM logon enrolls as its victim in any authentication
        // template that needs no approval.
        if cap.enforceencryptionforrequests == Some(false) && approval_off && auth && no_sigs {
            found.push(inst(Esc::Esc11, Some(t), Vec::new(), ca.domains.clone()));
        }

        let mut push = |i: EscInstance| {
            if !i.sources.is_empty() && !(i.targets.is_empty() && i.unverified.is_empty()) {
                found.push(i);
            }
        };

        // ESC1: requester chooses the identity in an authentication certificate.
        if approval_off && auth && no_sigs && supplies_subject == Some(true) {
            push(inst(
                Esc::Esc1,
                Some(t),
                cross(g, &[&t_enr, &ca_enr]),
                ca.domains.clone(),
            ));
        }

        // ESC4: write access to the template turns it into ESC1.
        {
            let controllers = holders(
                g,
                t,
                &[
                    EdgeKind::Owns,
                    EdgeKind::GenericAll,
                    EdgeKind::WriteDacl,
                    EdgeKind::WriteOwner,
                ],
            );
            let generic_write = holders(g, t, &[EdgeKind::GenericWrite]);
            let enroll = holders(g, t, &[EdgeKind::Enroll, EdgeKind::AllExtendedRights]);
            let name_flag = holders(g, t, &[EdgeKind::WritePkiNameFlag]);
            let enrollment_flag = holders(g, t, &[EdgeKind::WritePkiEnrollmentFlag]);
            let mut sources = cross(g, &[&ca_enr, &controllers]);
            sources.extend(cross(g, &[&ca_enr, &generic_write, &enroll]));
            if auth && no_sigs {
                sources.extend(cross(g, &[&ca_enr, &enroll, &name_flag, &enrollment_flag]));
                if supplies_subject == Some(true) {
                    sources.extend(cross(g, &[&ca_enr, &enroll, &enrollment_flag]));
                }
                if approval_off {
                    sources.extend(cross(g, &[&ca_enr, &enroll, &name_flag]));
                }
            }
            sources.sort_unstable();
            sources.dedup();
            push(inst(Esc::Esc4, Some(t), sources, ca.domains.clone()));
        }

        // ESC6: the CA honours requester-supplied SANs on any template.
        if cap.isuserspecifiessanenabled == Some(true) && approval_off && no_sigs {
            let sources = dns_filter(g, tp, cross(g, &[&t_enr, &ca_enr]));
            let mut gated_inst = |esc, mapping| {
                let gate = gated(g, &ca.domains, forests, mapping);
                let mut i = inst(esc, Some(t), sources.clone(), gate.open);
                i.unverified = gate.unknown;
                i.weak_dcs = gate.weak;
                push(i);
            };
            if tp.nosecurityextension == Some(true) && auth {
                gated_inst(Esc::Esc6a, Mapping::Kerberos);
            }
            if schannel {
                gated_inst(Esc::Esc6b, Mapping::Schannel);
            }
        }

        // ESC9 / ESC10: weak certificate mapping plus write access to an enrollee.
        if approval_off && no_sigs && supplies_subject == Some(false) {
            let by_upn =
                tp.subjectaltrequireupn == Some(true) || tp.subjectaltrequirespn == Some(true);
            let by_dns = tp.subjectaltrequiredns == Some(true);
            let mut variant = |esc, kinds: &[NodeKind], mapping| {
                let victims = accounts(g, &[&t_enr, &ca_enr], kinds);
                let gate = gated(g, &ca.domains, forests, mapping);
                let mut i = inst(esc, Some(t), hijackers(g, &victims), gate.open);
                i.victims = victims;
                i.unverified = gate.unknown;
                i.weak_dcs = gate.weak;
                push(i);
            };
            let users_and_computers = [NodeKind::User, NodeKind::Computer];
            if auth && tp.nosecurityextension == Some(true) {
                if by_upn {
                    variant(Esc::Esc9a, &users_and_computers, Mapping::Kerberos);
                }
                if by_dns {
                    variant(Esc::Esc9b, &[NodeKind::Computer], Mapping::Kerberos);
                }
            }
            if schannel {
                if by_upn {
                    variant(Esc::Esc10a, &users_and_computers, Mapping::Schannel);
                }
                if by_dns {
                    variant(Esc::Esc10b, &[NodeKind::Computer], Mapping::Schannel);
                }
            }
        }

        // ESC13: the template's issuance policy is linked to a group.
        if approval_off && auth && no_sigs {
            let sources = dns_filter(g, tp, cross(g, &[&ca_enr, &t_enr]));
            for policy in neighbors(g, t, Direction::Outgoing, &[EdgeKind::ExtendedByPolicy]) {
                for group in neighbors(g, policy, Direction::Outgoing, &[EdgeKind::OidGroupLink]) {
                    let mut i = inst(Esc::Esc13, Some(t), sources.clone(), vec![group]);
                    i.related = Some(group);
                    push(i);
                }
            }
        }
    }
}

/// ESC3: enroll for an enrollment agent certificate, then request an
/// authentication certificate on behalf of any user.
fn esc3(
    g: &AdGraph,
    cas: &[EligibleCa],
    found: &mut Vec<EscInstance>,
    edges: &mut Vec<(NodeIndex, NodeIndex, EdgeKind)>,
) {
    for eca1 in cas {
        let eca1_enr = holders(g, eca1.ca, &[EdgeKind::Enroll]);
        for ct1 in holders(g, eca1.ca, &[EdgeKind::PublishedTo]) {
            let Some(p1) = props(g, ct1) else { continue };
            let agent_ok = p1.requiresmanagerapproval == Some(false)
                && (p1.schemaversion == Some(1) || p1.authorizedsignatures == Some(0));
            if !agent_ok {
                continue;
            }
            let ct1_enr = holders(g, ct1, TEMPLATE_ENROLL);
            for eca2 in cas
                .iter()
                .filter(|c| g.node(c.ca).domain_sid == g.node(eca1.ca).domain_sid)
            {
                let eca2_enr = holders(g, eca2.ca, &[EdgeKind::Enroll]);
                let restricted = props(g, eca2.ca).is_some_and(|p| p.enrollmentagentrestricted);
                for ct2 in holders(g, eca2.ca, &[EdgeKind::PublishedTo]) {
                    let Some(p2) = props(g, ct2) else { continue };
                    if p2.authenticationenabled != Some(true)
                        || p2.requiresmanagerapproval != Some(false)
                    {
                        continue;
                    }
                    let on_behalf = match p2.schemaversion {
                        Some(1) => {
                            p1.effectiveekus.is_empty()
                                || p1.has_eku(EKU_CERT_REQUEST_AGENT)
                                || p1.has_eku(EKU_ANY_PURPOSE)
                        }
                        Some(v) if v >= 2 => {
                            p1.has_eku(EKU_CERT_REQUEST_AGENT)
                                && !p1.has_eku(EKU_ANY_PURPOSE)
                                && ct1 != ct2
                                && p2.authorizedsignatures == Some(1)
                                && p2
                                    .applicationpolicies
                                    .iter()
                                    .any(|a| a == EKU_CERT_REQUEST_AGENT)
                        }
                        _ => false,
                    };
                    if !on_behalf {
                        continue;
                    }
                    edges.push((ct1, ct2, EdgeKind::EnrollOnBehalfOf));
                    let ct2_enr = holders(g, ct2, TEMPLATE_ENROLL);
                    let agents = holders(g, ct2, &[EdgeKind::DelegatedEnrollmentAgent]);
                    let mut sets: Vec<&[NodeIndex]> =
                        vec![&ct1_enr, &ct2_enr, &eca1_enr, &eca2_enr];
                    if restricted {
                        sets.push(&agents);
                    }
                    let sources = dns_filter(g, p1, cross(g, &sets));
                    if !sources.is_empty() {
                        found.push(EscInstance {
                            esc: Esc::Esc3,
                            ca: eca1.ca,
                            template: Some(ct1),
                            related: Some(ct2),
                            sources,
                            victims: Vec::new(),
                            unverified: Vec::new(),
                            weak_dcs: Vec::new(),
                            targets: eca1.domains.clone(),
                        });
                    }
                }
            }
        }
    }
}
