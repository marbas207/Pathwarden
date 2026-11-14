//! Management planes: systems that control Tier Zero from outside the
//! directory's own permissions. Whoever controls an SCCM site server, a SCOM
//! management server or an Entra Connect server controls what it manages.
//!
//! Everything here is read from the directory data collectors already
//! produce (SharpHound / RustHound-CE JSON). Each detection carries a
//! [`Confidence`]:
//!
//! - **Strong**: the directory says it outright. An Entra Connect sync
//!   account (`MSOL_…`, or a description written by the installer) that can
//!   DCSync, the server its description names (or that can read its gMSA
//!   password), and the Seamless SSO computer account `AZUREADSSOACC`.
//! - **Inferred**: directory structure that the product creates. Full
//!   Control on `CN=System Management` (granted to SCCM site servers), SCOM's
//!   AD integration groups under `CN=OperationsManager` (whose members are
//!   the agents of a management server), product SPNs (`MSOMSdkSvc/`,
//!   `MSOMHSvc/`, `SCVMM/`, Hyper-V's live migration and console SPNs), the
//!   SPN SCCM clients register (`CmRcService/`), readers of the Entra
//!   Connect sync service account (`ADSyncMSA…`), the `ADSyncAdmins` group,
//!   and a group named exactly `ESX Admins`.
//! - **Heuristic**: names only (`SVC_VEEAM`, `WSUS01`, `ESX01`).
//!
//! Strong detections, and inferred ones that are linked to a Tier Zero host,
//! are treated as Tier Zero ("manages Tier Zero"); the rest are reported for
//! review (PW-028). Domain controllers and CA hosts that are SCOM agents or
//! SCCM clients get a `ManagesHost` edge from their management server when
//! the directory names exactly one.
//!
//! The built-in collector adds what the directory data lacks:
//! the registry policy GPOs set ([`crate::sysvol::policy`]), which
//! names the WSUS server of each domain controller and CA host and the SCCM
//! client setup pushed to them, and SCCM's site objects
//! ([`crate::sysvol::sccm`]), which tie a site server to its site. A
//! `ManagesHost` edge that rests on them carries their source, so a run
//! without them (SharpHound data) holds what they found instead of calling
//! it fixed.
//!
//! The Tier Zero host probe adds what only the hosts' own
//! registry shows ([`crate::hostprobe`]): an SCCM client and its site, the
//! SCOM management servers an agent reports to, the WSUS server it really
//! uses, the Hyper-V host of a virtual DC, and backup agents. A server it
//! names gets `ManagesHost` only when exactly one computer has that name
//! ([`Computers::find_host`]); a name that matches none is reviewed, never
//! guessed. What rests on a host's probe carries its source, so a later run
//! without a current, trusted file from that host holds it.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use crate::graph::AdGraph;
use crate::hostprobe;
use crate::model::{EdgeKind, Node, NodeKind};
use crate::sid;
use crate::sysvol::policy::{self, Policies};
use crate::sysvol::Part;

/// Every Tier Zero reason this module gives starts with this, so a system
/// Pathwarden classified can be told from one configured as Tier Zero.
pub const REASON_PREFIX: &str = "Management plane: ";

/// Made Tier Zero because it looks like a management plane, not because it
/// was configured or is Tier Zero by definition.
pub fn is_plane_reason(n: &Node) -> bool {
    n.tier_zero
        && n.tier_zero_reason
            .as_deref()
            .is_some_and(|r| r.starts_with(REASON_PREFIX))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Plane {
    EntraConnect,
    SeamlessSso,
    Sccm,
    Scom,
    Wsus,
    Backup,
    Virtualization,
    /// A `ManagesHost` edge from another source (an OpenGraph file).
    Other,
}

impl Plane {
    /// For people ("the SCCM site server").
    pub fn name(self) -> &'static str {
        match self {
            Plane::EntraConnect => "Entra Connect",
            Plane::SeamlessSso => "Seamless SSO",
            Plane::Sccm => "SCCM",
            Plane::Scom => "SCOM",
            Plane::Wsus => "WSUS",
            Plane::Backup => "backup",
            Plane::Virtualization => "virtualization",
            Plane::Other => "management",
        }
    }

    /// For fingerprints: never changes.
    pub fn key(self) -> &'static str {
        match self {
            Plane::EntraConnect => "entra-connect",
            Plane::SeamlessSso => "seamless-sso",
            Plane::Sccm => "sccm",
            Plane::Scom => "scom",
            Plane::Wsus => "wsus",
            Plane::Backup => "backup",
            Plane::Virtualization => "virtualization",
            Plane::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Confidence {
    Heuristic,
    Inferred,
    Strong,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Heuristic => "heuristic (name only)",
            Confidence::Inferred => "inferred from directory structure",
            Confidence::Strong => "strong",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A computer running the management product.
    Server,
    /// An account (or computer account) of the product.
    Account,
    /// A group named after the product.
    Group,
    /// A Tier Zero host that runs the product's agent (an SCCM client, a
    /// SCOM agent) whose server the directory doesn't name. Its
    /// [`Detection::manages`] holds the server candidates instead.
    Client,
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub plane: Plane,
    pub confidence: Confidence,
    pub role: Role,
    pub object: NodeIndex,
    /// What ties detections together: the sync account's SID for Entra
    /// Connect, the management group for SCOM.
    pub key: String,
    /// Why, in a sentence fragment ("named in the description of MSOL_…").
    pub evidence: String,
    /// The Tier Zero objects it controls, when known. For a
    /// [`Role::Client`], the server candidates in its forest; for an
    /// `ADSyncAdmins` group, the Entra Connect servers it administers (it is
    /// Tier Zero only while one of them is).
    pub manages: Vec<NodeIndex>,
    /// Treated as Tier Zero (unless configured otherwise), with this reason.
    pub tier_zero: Option<String>,
    /// The built-in collector's sources it rests on beyond the directory
    /// data (`SYSVOL registry policy (DOMAIN)`, `SCCM site objects
    /// (DOMAIN)`): its `ManagesHost` edges carry the first, and its
    /// findings all of them.
    pub sources: Vec<String>,
}

/// Every management plane the graph shows. Needs derived edges (DCSync), so
/// it runs after post-processing; it does not depend on Tier Zero marks.
pub fn detect(g: &AdGraph) -> Vec<Detection> {
    let hosts = tier_zero_hosts(g);
    let policies = Policies::new(g);
    let probes = Probes::new(g, &hosts);
    let mut out = Vec::new();
    entra_connect(g, &mut out);
    seamless_sso(g, &mut out);
    out.extend(sccm(g, &hosts, &policies, &probes));
    wsus(g, &hosts, &policies, &probes, &mut out);
    let mut scom = scom(g, &hosts);
    scom_agents(g, &hosts, &scom, &mut out);
    probe_scom(g, &probes, &mut scom, &mut out);
    out.extend(scom);
    probe_hyper_v(g, &probes, &mut out);
    probe_backup(g, &probes, &mut out);
    by_spn(g, &hosts, &mut out);
    hyper_v(g, &mut out);
    esx_admins(g, &mut out);
    by_name(g, &mut out);
    out
}

/// Adds `ManagesHost` from each SCOM management server to the Tier Zero
/// hosts that are its agents, from an SCCM site server to the Tier Zero
/// hosts that are SCCM clients in its forest when it is the only site server
/// there (or of their site), and from a WSUS server to the Tier Zero hosts
/// Group Policy points at it. An edge that rests on the built-in
/// collector's sidecar carries that source. Part of post-processing.
pub fn add_edges(g: &mut AdGraph) {
    let hosts = tier_zero_hosts(g);
    let policies = Policies::new(g);
    let probes = Probes::new(g, &hosts);
    let mut found = scom(g, &hosts);
    probe_scom(g, &probes, &mut found, &mut Vec::new());
    found.extend(sccm(g, &hosts, &policies, &probes));
    wsus(g, &hosts, &policies, &probes, &mut found);
    probe_hyper_v(g, &probes, &mut found);
    drop(policies);
    drop(probes);
    // The probe's servers come last: one the directory or SYSVOL already
    // ties to the host gets no second edge.
    found.sort_by_key(|d| d.sources.first().is_some_and(|s| hostprobe::is_source(s)));
    let mut edges: Vec<(NodeIndex, NodeIndex, Option<String>)> = Vec::new();
    for d in found.into_iter().filter(|d| d.role == Role::Server) {
        for h in d.manages {
            let source = d.sources.first().cloned();
            let probed = source.as_deref().is_some_and(hostprobe::is_source);
            if probed && edges.iter().any(|(s, t, _)| *s == d.object && *t == h) {
                continue;
            }
            edges.push((d.object, h, source));
        }
    }
    for (server, host, source) in edges {
        match source {
            Some(name) => {
                let origin = crate::opengraph::EdgeOrigin {
                    source: g.add_og_source(&name),
                    unit: None,
                };
                g.add_og_edge(server, host, EdgeKind::ManagesHost, origin);
            }
            None => {
                g.add_edge(server, host, EdgeKind::ManagesHost);
            }
        }
    }
}

/// Domain controllers and the computers hosting an Enterprise CA: the hosts
/// a management plane must not manage from outside Tier Zero.
pub(crate) fn tier_zero_hosts(g: &AdGraph) -> HashSet<NodeIndex> {
    let mut hosts: HashSet<NodeIndex> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Computer && n.is_dc)
        .map(|(ix, _)| ix)
        .collect();
    hosts.extend(
        g.inner()
            .edge_references()
            .filter(|e| *e.weight() == EdgeKind::HostsCaService)
            .filter(|e| g.edge_origin(e.id()).is_none())
            .map(|e| e.source()),
    );
    hosts
}

/// [`tier_zero_hosts`] in index order, for stable output.
fn sorted(hosts: &HashSet<NodeIndex>) -> Vec<NodeIndex> {
    let mut v: Vec<NodeIndex> = hosts.iter().copied().collect();
    v.sort_unstable();
    v
}

/// The first of `n`'s service principal names that starts with `prefix`
/// (given in upper case), in any case.
fn spn<'a>(n: &'a Node, prefix: &str) -> Option<&'a String> {
    n.props.serviceprincipalnames.iter().find(|s| {
        s.len() >= prefix.len()
            && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    })
}

/// Whether `a` and `b` are in the same forest (by their domains).
fn same_forest(g: &AdGraph, forests: &HashMap<String, usize>, a: NodeIndex, b: NodeIndex) -> bool {
    let (Some(da), Some(db)) = (g.node(a).domain.as_ref(), g.node(b).domain.as_ref()) else {
        return false;
    };
    match (forests.get(da), forests.get(db)) {
        (Some(x), Some(y)) => x == y,
        _ => da == db,
    }
}

fn node_names(g: &AdGraph, ixs: &[NodeIndex]) -> String {
    ixs.iter()
        .map(|&ix| g.node(ix).name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The name without `@DOMAIN`, and for computers without the DNS suffix.
fn short_name(n: &Node) -> &str {
    let name = n.name.split('@').next().unwrap_or(&n.name);
    let name = if n.kind == NodeKind::Computer {
        name.split('.').next().unwrap_or(name)
    } else {
        name
    };
    name.trim_end_matches('$')
}

fn collected(n: &Node) -> bool {
    !n.placeholder && !n.og_created()
}

/// Computers by short name, for resolving the host names products write
/// into descriptions and group names.
struct Computers(HashMap<String, Vec<NodeIndex>>);

impl Computers {
    fn new(g: &AdGraph) -> Self {
        let mut map: HashMap<String, Vec<NodeIndex>> = HashMap::new();
        for (ix, n) in g.nodes() {
            if n.kind == NodeKind::Computer && collected(n) {
                map.entry(short_name(n).to_string()).or_default().push(ix);
            }
        }
        Computers(map)
    }

    /// The computer called `host` (any case, a short name or an FQDN):
    /// the one in `domain` if there is one, else the only one anywhere.
    fn find(&self, g: &AdGraph, host: &str, domain: Option<&str>) -> Option<NodeIndex> {
        let short = host.split('.').next()?.trim().to_ascii_uppercase();
        let all = self.0.get(&short)?;
        let local: Vec<NodeIndex> = all
            .iter()
            .copied()
            .filter(|&c| domain.is_some() && g.node(c).domain.as_deref() == domain)
            .collect();
        match (local.as_slice(), all.as_slice()) {
            ([one], _) => Some(*one),
            ([], [one]) => Some(*one),
            _ => None,
        }
    }
}

impl Computers {
    /// The computer a host name names, strictly: a name with dots matches
    /// a computer's full name exactly (any case, without a trailing dot);
    /// a short name matches only within `domain`, and only one computer.
    /// For names written into settings (a WSUS URL, a management point),
    /// where a guess would make the wrong computer Tier Zero.
    fn find_host(&self, g: &AdGraph, host: &str, domain: Option<&str>) -> Option<NodeIndex> {
        let host = host.trim().trim_end_matches('.').to_ascii_uppercase();
        let short = host.split('.').next()?;
        let all = self.0.get(short)?;
        let found: Vec<NodeIndex> = if host.contains('.') {
            all.iter()
                .copied()
                .filter(|&c| {
                    let n = g.node(c);
                    n.name.trim_end_matches('.').eq_ignore_ascii_case(&host)
                        || n.domain
                            .as_deref()
                            .is_some_and(|d| format!("{short}.{d}").eq_ignore_ascii_case(&host))
                })
                .collect()
        } else {
            all.iter()
                .copied()
                .filter(|&c| domain.is_some() && g.node(c).domain.as_deref() == domain)
                .collect()
        };
        match found.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    }
}

/// The Tier Zero hosts' probes ([`hostprobe::views`]), by host.
struct Probes<'a>(BTreeMap<NodeIndex, hostprobe::View<'a>>);

impl<'a> Probes<'a> {
    fn new(g: &'a AdGraph, hosts: &HashSet<NodeIndex>) -> Self {
        let mut v = hostprobe::views(g);
        v.retain(|ix, _| hosts.contains(ix));
        Probes(v)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn get(&self, host: NodeIndex) -> Option<&hostprobe::View<'a>> {
        self.0.get(&host)
    }

    fn iter(&self) -> impl Iterator<Item = (NodeIndex, &hostprobe::View<'a>)> {
        self.0.iter().map(|(ix, v)| (*ix, v))
    }
}

/// Why a computer the probe names can't be made Tier Zero, or `None` when
/// it can. Only a current, trusted file may make a computer Tier Zero, and
/// only one the built-in collector shows wasn't created through the
/// machine account quota (by any domain user): with SharpHound data that
/// isn't known, so the server is reviewed instead.
fn promotion_block(g: &AdGraph, server: NodeIndex, trusted: bool) -> Option<&'static str> {
    if !trusted {
        Some(
            "only a settings file over 90 days old, or one from a settings folder that nothing \
             shows who wrote, names it",
        )
    } else if quota_made(g, server) {
        Some("a computer created through the machine account quota")
    } else if !quota_known(g, server) {
        Some(
            "a computer the collection doesn't show the creator of (the built-in collector reads \
             it), so it may have been created through the machine account quota",
        )
    } else {
        None
    }
}

/// Whether the built-in collector read which computers of `ix`'s domain
/// were created through the machine account quota.
fn quota_known(g: &AdGraph, ix: NodeIndex) -> bool {
    let domain = g.node(ix).domain.as_deref();
    g.sysvol_domains()
        .iter()
        .any(|d| d.quota_read && domain.is_some_and(|x| x.eq_ignore_ascii_case(&d.domain)))
}

/// A review's confidence: Strong when a current, trusted file shows the
/// agent and nothing left the server's creator unknown; Inferred otherwise.
fn review_confidence(strong: bool) -> Confidence {
    if strong {
        Confidence::Strong
    } else {
        Confidence::Inferred
    }
}

/// The source of `host`'s probe ([`hostprobe::source`]).
fn probe_source(g: &AdGraph, host: NodeIndex) -> String {
    hostprobe::source(&g.node(host).name)
}

/// Where the probe's evidence comes from, for evidence sentences.
const FROM_FILE: &str = "its Tier Zero settings file";

/// SCOM management servers the probe names for each Tier Zero host
/// (`Parent Health Services` `NetworkName`). A name that is exactly one
/// computer, from a current, trusted file, manages the host (in `scom`);
/// every other name, or an agent that names none, is a review (in `out`,
/// merged with the host's SPN review when there is one).
fn probe_scom(
    g: &AdGraph,
    probes: &Probes<'_>,
    scom: &mut Vec<Detection>,
    out: &mut Vec<Detection>,
) {
    if probes.is_empty() {
        return;
    }
    let computers = Computers::new(g);
    for (host, v) in probes.iter() {
        if !v.any(hostprobe::Part::Scom, |a| a.scom_agent().is_some()) {
            continue;
        }
        let pairs: Vec<((String, String), bool)> = v.answers(hostprobe::Part::Scom, |a| {
            a.scom_agent()
                .unwrap_or_default()
                .into_iter()
                .map(|(mg, s)| (mg.to_string(), s.to_string()))
                .collect()
        });
        let n = g.node(host);
        let domain = n.domain.as_deref();
        let mut strong = v.trusted(hostprobe::Part::Scom, |a| a.scom_agent().is_some());
        let mut reviewed: Vec<String> = Vec::new();
        let mut candidates: Vec<NodeIndex> = Vec::new();
        let mut promoted = false;
        for ((mg, name), trusted) in &pairs {
            match computers.find_host(g, name, domain) {
                Some(s) if s == host => {}
                Some(s) => match promotion_block(g, s, *trusted) {
                    None => {
                        promoted = true;
                        scom.push(Detection {
                            plane: Plane::Scom,
                            confidence: Confidence::Strong,
                            role: Role::Server,
                            object: s,
                            key: format!("{}/{}", domain.unwrap_or(""), mg.to_ascii_uppercase()),
                            evidence: format!(
                                "named as the management server of {} for management group {mg} \
                                 in its registry ({FROM_FILE})",
                                n.name
                            ),
                            manages: vec![host],
                            sources: vec![probe_source(g, host)],
                            tier_zero: Some(format!(
                                "SCOM management server (management group {mg}) for {}",
                                n.name
                            )),
                        });
                    }
                    Some(why) => {
                        strong &= *trusted && quota_known(g, s);
                        if !candidates.contains(&s) {
                            candidates.push(s);
                        }
                        reviewed.push(format!("{name} (management group {mg}), {why}"));
                    }
                },
                None => reviewed.push(format!(
                    "{name} (management group {mg}), which is not exactly one computer in the \
                     collection"
                )),
            }
        }
        if pairs.is_empty() || !reviewed.is_empty() {
            let evidence = if pairs.is_empty() {
                format!(
                    "has the SCOM agent in its registry ({FROM_FILE}), which names no management \
                     server"
                )
            } else {
                format!(
                    "reports to the SCOM management server {}, as its registry shows ({FROM_FILE})",
                    reviewed.join("; ")
                )
            };
            let source = probe_source(g, host);
            // The host's own review (its SPN) takes the probe's words: one
            // finding per host.
            match out
                .iter_mut()
                .find(|c| c.plane == Plane::Scom && c.role == Role::Client && c.object == host)
            {
                Some(c) => {
                    c.evidence = format!("{}; it {evidence}", c.evidence);
                    if !c.sources.contains(&source) {
                        c.sources.push(source);
                    }
                    c.manages.extend(candidates);
                }
                None => out.push(Detection {
                    plane: Plane::Scom,
                    confidence: review_confidence(strong),
                    role: Role::Client,
                    object: host,
                    key: n.id.clone(),
                    evidence,
                    manages: candidates,
                    sources: vec![source],
                    tier_zero: None,
                }),
            }
        } else if promoted {
            // Its server is known now: no review for the SPN.
            out.retain(|c| !(c.plane == Plane::Scom && c.role == Role::Client && c.object == host));
        }
    }
}

/// The Hyper-V host each virtual Tier Zero host names in its registry
/// (`PhysicalHostNameFullyQualified`), as [`probe_scom`]: exactly one
/// computer, from a current, trusted file, manages it; otherwise the host
/// is reviewed.
fn probe_hyper_v(g: &AdGraph, probes: &Probes<'_>, out: &mut Vec<Detection>) {
    if probes.is_empty() {
        return;
    }
    let computers = Computers::new(g);
    for (host, v) in probes.iter() {
        if !v.any(hostprobe::Part::HyperV, |a| a.hyper_v_guest().is_some()) {
            continue;
        }
        let names: Vec<(String, bool)> = v.answers(hostprobe::Part::HyperV, |a| {
            a.hyper_v_guest()
                .flatten()
                .map(|h| vec![h.to_string()])
                .unwrap_or_default()
        });
        let n = g.node(host);
        let mut strong = v.trusted(hostprobe::Part::HyperV, |a| a.hyper_v_guest().is_some());
        let mut reviewed: Vec<String> = Vec::new();
        let mut candidates: Vec<NodeIndex> = Vec::new();
        for (name, trusted) in &names {
            match computers.find_host(g, name, n.domain.as_deref()) {
                Some(s) if s == host => {}
                Some(s) => match promotion_block(g, s, *trusted) {
                    None => out.push(Detection {
                        plane: Plane::Virtualization,
                        confidence: Confidence::Strong,
                        role: Role::Server,
                        object: s,
                        key: g.node(s).id.clone(),
                        evidence: format!(
                            "the Hyper-V host that {} names in its registry \
                             (PhysicalHostNameFullyQualified, {FROM_FILE})",
                            n.name
                        ),
                        manages: vec![host],
                        sources: vec![probe_source(g, host)],
                        tier_zero: Some(format!("Hyper-V host of {}", n.name)),
                    }),
                    Some(why) => {
                        strong &= *trusted && quota_known(g, s);
                        candidates.push(s);
                        reviewed.push(format!("{name}, {why}"));
                    }
                },
                None => reviewed.push(format!(
                    "{name}, which is not exactly one computer in the collection"
                )),
            }
        }
        if names.is_empty() || !reviewed.is_empty() {
            let evidence = if names.is_empty() {
                format!(
                    "is a Hyper-V virtual machine, and its registry ({FROM_FILE}) doesn't name its \
                     host"
                )
            } else {
                format!(
                    "is a Hyper-V virtual machine on {}, as its registry shows ({FROM_FILE})",
                    reviewed.join("; ")
                )
            };
            out.push(Detection {
                plane: Plane::Virtualization,
                confidence: review_confidence(strong),
                role: Role::Client,
                object: host,
                key: n.id.clone(),
                evidence,
                manages: candidates,
                sources: vec![probe_source(g, host)],
                tier_zero: None,
            });
        }
    }
}

/// What [`Detection::key`] starts with for a Tier Zero host that runs a
/// backup agent, followed by the product: PW-028 reports them together,
/// one finding per product and domain.
pub const BACKUP_KEY: &str = "backup-agent/";

/// The backup products the script looks for, as it names them.
const BACKUP_PRODUCTS: &[&str] = &["Veeam", "Commvault", "NetBackup", "DPM"];

/// A product a file names: one of [`BACKUP_PRODUCTS`], or "other".
fn backup_product(name: &str) -> String {
    BACKUP_PRODUCTS
        .iter()
        .find(|p| p.eq_ignore_ascii_case(name.trim()))
        .map_or_else(|| "other".to_string(), |p| p.to_string())
}

/// Tier Zero hosts that run a backup agent, one detection per product: the
/// probe can't tell which server backs them up, so they are reviewed.
fn probe_backup(g: &AdGraph, probes: &Probes<'_>, out: &mut Vec<Detection>) {
    for (host, v) in probes.iter() {
        // Products the script knows by name; anything else a file says is
        // "other", so a file can't make up findings of its own.
        let agents: Vec<((String, String), bool)> = v.answers(hostprobe::Part::Backup, |a| {
            a.backup_agents()
                .into_iter()
                .map(|b| (backup_product(&b.product), b.service.clone()))
                .collect()
        });
        let mut products: Vec<&str> = agents.iter().map(|((p, _), _)| p.as_str()).collect();
        products.sort_unstable();
        products.dedup();
        for product in products {
            let mine: Vec<&((String, String), bool)> =
                agents.iter().filter(|((p, _), _)| p == product).collect();
            let services: Vec<&str> = mine.iter().map(|((_, s), _)| s.as_str()).collect();
            out.push(Detection {
                plane: Plane::Backup,
                confidence: review_confidence(mine.iter().any(|(_, t)| *t)),
                role: Role::Client,
                object: host,
                key: format!("{BACKUP_KEY}{product}"),
                evidence: format!(
                    "runs {} (service {}), as its registry shows ({FROM_FILE})",
                    if product == "other" {
                        "a backup agent of another product".to_string()
                    } else {
                        format!("the {product} backup agent")
                    },
                    services.join(", ")
                ),
                manages: Vec::new(),
                sources: vec![probe_source(g, host)],
                tier_zero: None,
            });
        }
    }
}

/// Whether the built-in collector saw `ix` created through the machine
/// account quota (`mS-DS-CreatorSID` set): any domain user may have made
/// it, so a setting that names it doesn't make it Tier Zero unreviewed.
fn quota_made(g: &AdGraph, ix: NodeIndex) -> bool {
    let id = g.node(ix).id.to_ascii_uppercase();
    g.sysvol_domains()
        .iter()
        .any(|d| d.quota_computers.contains(&id))
}

/// The domains `ix` can DCSync, directly or through its (nested) groups.
fn dcsync_domains(g: &AdGraph, ix: NodeIndex) -> Vec<NodeIndex> {
    let mut seen = HashSet::from([ix]);
    let mut queue = VecDeque::from([ix]);
    let mut out = Vec::new();
    while let Some(v) = queue.pop_front() {
        for e in g.inner().edges_directed(v, Direction::Outgoing) {
            if g.edge_origin(e.id()).is_some() {
                continue;
            }
            match *e.weight() {
                EdgeKind::DcSync if !out.contains(&e.target()) => out.push(e.target()),
                EdgeKind::MemberOf if seen.insert(e.target()) => queue.push_back(e.target()),
                _ => {}
            }
        }
    }
    out
}

/// Entra Connect (and Cloud Sync) on-premises connector accounts.
fn is_sync_account(n: &Node) -> bool {
    let short = short_name(n).to_ascii_uppercase();
    let described = n.props.description.as_deref().is_some_and(|d| {
        let d = d.to_ascii_lowercase();
        [
            "azure active directory connect",
            "azure ad connect",
            "entra connect",
        ]
        .iter()
        .any(|p| d.contains(p))
    });
    !is_adsync_service_account(n)
        && (short.starts_with("MSOL_")
            || short.starts_with("PROVAGENTGMSA")
            || short.starts_with("PGMSA_")
            || described)
}

/// The managed service account the Entra Connect installer creates for the
/// sync service (`ADSyncMSA<hex>`). Whoever reads its password can decrypt
/// the connector credentials the server stores.
fn is_adsync_service_account(n: &Node) -> bool {
    matches!(n.kind, NodeKind::User | NodeKind::Computer)
        && short_name(n).to_ascii_uppercase().starts_with("ADSYNCMSA")
}

/// The domain group that administers the Entra Connect sync engine (a
/// custom install, or a server that is a DC, uses domain groups).
fn is_adsync_admins(n: &Node) -> bool {
    n.kind == NodeKind::Group && short_name(n).eq_ignore_ascii_case("ADSYNCADMINS")
}

/// The host the Entra Connect installer names in the sync account's
/// description ("... running on computer AADC01 configured to ...").
pub fn described_host(description: &str) -> Option<String> {
    const MARK: &str = "running on computer ";
    let at = description.to_ascii_lowercase().find(MARK)? + MARK.len();
    let host: String = description[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    let host = host.trim_end_matches('.').to_ascii_uppercase();
    (!host.is_empty()).then_some(host)
}

fn entra_connect(g: &AdGraph, out: &mut Vec<Detection>) {
    let computers = Computers::new(g);
    for (ix, n) in g.nodes() {
        if n.kind != NodeKind::User || !collected(n) || !is_sync_account(n) {
            continue;
        }
        let domains = dcsync_domains(g, ix);
        if domains.is_empty() {
            out.push(Detection {
                plane: Plane::EntraConnect,
                confidence: Confidence::Heuristic,
                role: Role::Account,
                object: ix,
                key: n.id.clone(),
                evidence: "named like an Entra Connect sync account, but it holds no \
                           replication rights"
                    .into(),
                manages: Vec::new(),
                sources: Vec::new(),
                tier_zero: None,
            });
            continue;
        }
        let domain_names: Vec<&str> = domains.iter().map(|&d| g.node(d).name.as_str()).collect();
        out.push(Detection {
            plane: Plane::EntraConnect,
            confidence: Confidence::Strong,
            role: Role::Account,
            object: ix,
            key: n.id.clone(),
            evidence: format!(
                "an Entra Connect sync account that can DCSync {}",
                domain_names.join(", ")
            ),
            manages: domains.clone(),
            sources: Vec::new(),
            tier_zero: Some(format!(
                "Entra Connect sync account (can DCSync {} by design)",
                domain_names.join(", ")
            )),
        });

        // The server that stores its password: the one the installer named,
        // and any computer that can read it (a gMSA, for Cloud Sync).
        let mut servers: Vec<(NodeIndex, String)> = Vec::new();
        if let Some(host) = n.props.description.as_deref().and_then(described_host) {
            if let Some(c) = computers.find(g, &host, n.domain.as_deref()) {
                servers.push((c, format!("named in the description of {}", n.name)));
            }
        }
        for e in g.inner().edges_directed(ix, Direction::Incoming) {
            let reader = g.node(e.source());
            if *e.weight() == EdgeKind::ReadGmsaPassword
                && reader.kind == NodeKind::Computer
                && g.edge_origin(e.id()).is_none()
                && !servers.iter().any(|(s, _)| *s == e.source())
            {
                servers.push((e.source(), format!("can read the password of {}", n.name)));
            }
        }
        for (server, why) in servers {
            out.push(Detection {
                plane: Plane::EntraConnect,
                confidence: Confidence::Strong,
                role: Role::Server,
                object: server,
                key: n.id.clone(),
                evidence: why,
                manages: vec![ix],
                sources: Vec::new(),
                tier_zero: Some(format!(
                    "Entra Connect server (holds the credentials of {}, which can DCSync)",
                    n.name
                )),
            });
        }
    }
    adsync(g, out);
}

/// Computers that can read the password of the Entra Connect sync service
/// account, and the `ADSyncAdmins` group. Runs after the sync accounts and
/// their servers are in `out`.
fn adsync(g: &AdGraph, out: &mut Vec<Detection>) {
    // Sync accounts that can DCSync.
    let accounts: Vec<(NodeIndex, String)> = out
        .iter()
        .filter(|d| {
            d.plane == Plane::EntraConnect
                && d.role == Role::Account
                && d.confidence == Confidence::Strong
        })
        .map(|d| (d.object, d.key.clone()))
        .collect();
    let mut found = Vec::new();
    for (ix, n) in g.nodes() {
        if !collected(n) || !is_adsync_service_account(n) {
            continue;
        }
        let mut readers: Vec<NodeIndex> = g
            .inner()
            .edges_directed(ix, Direction::Incoming)
            .filter(|e| {
                *e.weight() == EdgeKind::ReadGmsaPassword
                    && g.edge_origin(e.id()).is_none()
                    && g.node(e.source()).kind == NodeKind::Computer
                    && !privileged_anyway(g.node(e.source()))
            })
            .map(|e| e.source())
            .collect();
        readers.sort_unstable();
        readers.dedup();
        let synced: Vec<&(NodeIndex, String)> = accounts
            .iter()
            .filter(|(a, _)| g.node(*a).domain == n.domain)
            .collect();
        for reader in readers {
            let evidence = format!(
                "can read the password of {}, the Entra Connect sync service account",
                n.name
            );
            if synced.is_empty() {
                found.push(Detection {
                    plane: Plane::EntraConnect,
                    confidence: Confidence::Inferred,
                    role: Role::Server,
                    object: reader,
                    key: n.id.clone(),
                    evidence,
                    manages: Vec::new(),
                    sources: Vec::new(),
                    tier_zero: None,
                });
                continue;
            }
            // The sync accounts this reader is already known to serve: only
            // those are its own; otherwise any of the domain's may be.
            let is_server_of = |key: &str| {
                out.iter().any(|d| {
                    d.plane == Plane::EntraConnect
                        && d.role == Role::Server
                        && d.object == reader
                        && d.key == key
                })
            };
            let own: Vec<&&(NodeIndex, String)> = synced
                .iter()
                .filter(|(_, key)| is_server_of(key.as_str()))
                .collect();
            let strong = !own.is_empty();
            let relevant: Vec<&&(NodeIndex, String)> =
                if strong { own } else { synced.iter().collect() };
            for (account, key) in relevant.into_iter().map(|a| &**a) {
                found.push(Detection {
                    plane: Plane::EntraConnect,
                    confidence: if strong {
                        Confidence::Strong
                    } else {
                        Confidence::Inferred
                    },
                    role: Role::Server,
                    object: reader,
                    key: key.clone(),
                    evidence: evidence.clone(),
                    manages: vec![*account],
                    sources: Vec::new(),
                    tier_zero: Some(format!(
                        "Entra Connect server (runs the sync service as {}, which decrypts the \
                         credentials of {}, which can DCSync)",
                        n.name,
                        g.node(*account).name
                    )),
                });
            }
        }
    }
    out.extend(found);

    // ADSyncAdmins: Tier Zero while an Entra Connect server in its domain is.
    let mut groups = Vec::new();
    for (ix, n) in g.nodes() {
        if !collected(n) || !is_adsync_admins(n) {
            continue;
        }
        let mut servers: Vec<NodeIndex> = out
            .iter()
            .filter(|d| {
                d.plane == Plane::EntraConnect
                    && d.role == Role::Server
                    && d.tier_zero.is_some()
                    && g.node(d.object).domain == n.domain
            })
            .map(|d| d.object)
            .collect();
        servers.sort_unstable();
        servers.dedup();
        let tier_zero = (!servers.is_empty()).then(|| {
            format!(
                "Entra Connect administrators (ADSyncAdmins controls the sync engine on {})",
                node_names(g, &servers)
            )
        });
        groups.push(Detection {
            plane: Plane::EntraConnect,
            confidence: Confidence::Inferred,
            role: Role::Group,
            object: ix,
            key: n.id.clone(),
            evidence: "named ADSyncAdmins, the group that administers the Entra Connect sync \
                       engine"
                .into(),
            manages: servers,
            sources: Vec::new(),
            tier_zero,
        });
    }
    out.extend(groups);
}

const SSO_SPN: &str = "AUTOLOGON.MICROSOFTAZUREAD-SSO.COM";

/// The Seamless SSO computer accounts (`AZUREADSSOACC`).
pub fn sso_accounts(g: &AdGraph) -> Vec<NodeIndex> {
    let mut out = Vec::new();
    seamless_sso(g, &mut out);
    out.into_iter().map(|d| d.object).collect()
}

fn seamless_sso(g: &AdGraph, out: &mut Vec<Detection>) {
    for (ix, n) in g.nodes() {
        if n.kind != NodeKind::Computer || !collected(n) {
            continue;
        }
        let named = short_name(n).eq_ignore_ascii_case("AZUREADSSOACC");
        let spn = n
            .props
            .serviceprincipalnames
            .iter()
            .any(|s| s.to_ascii_uppercase().contains(SSO_SPN));
        if !named && !spn {
            continue;
        }
        out.push(Detection {
            plane: Plane::SeamlessSso,
            confidence: Confidence::Strong,
            role: Role::Account,
            object: ix,
            key: n.id.clone(),
            evidence: if spn {
                "has the Seamless SSO service principal name".into()
            } else {
                "the Seamless SSO computer account".into()
            },
            manages: Vec::new(),
            sources: Vec::new(),
            tier_zero: Some(
                "Seamless SSO account (AZUREADSSOACC): its Kerberos key signs in to Entra ID as \
                 any synced user"
                    .into(),
            ),
        });
    }
}

fn is_system_management(n: &Node) -> bool {
    n.kind == NodeKind::Container
        && n.props
            .distinguishedname
            .as_deref()
            .is_some_and(|dn| dn.starts_with("CN=SYSTEM MANAGEMENT,CN=SYSTEM,"))
}

/// A principal that holds rights because of what it is, not because a
/// product was installed (administrators, broad groups, the DCs).
fn privileged_anyway(n: &Node) -> bool {
    sid::tier_zero_reason(&n.id).is_some() || sid::is_broad_group(&n.id) || n.is_dc
}

/// SCCM site servers publish their site to `CN=System Management`, and the
/// installation guide grants each one Full Control of it.
fn site_servers(g: &AdGraph, out: &mut Vec<Detection>) {
    for (container, c) in g.nodes() {
        if !is_system_management(c) {
            continue;
        }
        let mut found: Vec<(NodeIndex, String)> = Vec::new();
        for e in g.inner().edges_directed(container, Direction::Incoming) {
            if *e.weight() != EdgeKind::GenericAll
                || g.is_inherited(e.id())
                || g.edge_origin(e.id()).is_some()
            {
                continue;
            }
            let holder = g.node(e.source());
            if privileged_anyway(holder) {
                continue;
            }
            match holder.kind {
                NodeKind::Computer if holder.is_enabled() => {
                    found.push((e.source(), String::new()))
                }
                NodeKind::Group => {
                    for m in g.transitive_members(e.source()) {
                        let member = g.node(m);
                        if member.kind == NodeKind::Computer && !member.is_dc && member.is_enabled()
                        {
                            found.push((m, format!(" through {}", holder.name)));
                        }
                    }
                }
                _ => {}
            }
        }
        found.sort();
        found.dedup_by_key(|(ix, _)| *ix);
        for (server, through) in found {
            out.push(Detection {
                plane: Plane::Sccm,
                confidence: Confidence::Inferred,
                role: Role::Server,
                object: server,
                key: g.node(server).id.clone(),
                evidence: format!(
                    "has Full Control of {}{through}, which SCCM grants its site servers",
                    c.props.distinguishedname.as_deref().unwrap_or(&c.name)
                ),
                manages: Vec::new(),
                sources: Vec::new(),
                tier_zero: None,
            });
        }
    }
}

/// The service principal name the SCCM Remote Control service registers
/// on clients.
const CMRC_SPN: &str = "CMRCSERVICE/";

/// The SCCM site codes of computers: the owner of a site's object (the
/// site server that published it) and each management point's host, from
/// the SCCM site objects the built-in collector keeps. With the sources
/// (`SCCM site objects (DOMAIN)`) each code came from, and every code a
/// forest's objects name.
struct SiteCodes {
    of: HashMap<NodeIndex, Vec<(String, String)>>,
    by_forest: HashMap<usize, Vec<(String, String)>>,
    /// Site codes the objects don't tie to one server for sure: two site
    /// objects with the code, or an owner and a management point host that
    /// differ. They narrow nothing.
    unsure: HashSet<String>,
}

impl SiteCodes {
    fn new(g: &AdGraph, computers: &Computers, forests: &HashMap<String, usize>) -> Self {
        let mut of: HashMap<NodeIndex, Vec<(String, String)>> = HashMap::new();
        let mut by_forest: HashMap<usize, Vec<(String, String)>> = HashMap::new();
        // Per site code: site objects seen, owners and management point
        // hosts.
        let mut seen: HashMap<String, (usize, HashSet<NodeIndex>, HashSet<NodeIndex>)> =
            HashMap::new();
        for d in g.sysvol_domains() {
            let source = Part::SccmSites.source(&d.domain);
            let mut add = |ix: NodeIndex, code: &str| {
                let e = of.entry(ix).or_default();
                if !e.iter().any(|(c, _)| c == code) {
                    e.push((code.to_string(), source.clone()));
                }
            };
            for s in &d.sccm.sites {
                let e = seen.entry(s.site_code.clone()).or_default();
                e.0 += 1;
                let owner = s.owner.as_deref().and_then(|o| g.lookup(o));
                if let Some(ix) = owner.filter(|&ix| g.node(ix).kind == NodeKind::Computer) {
                    e.1.insert(ix);
                    if !quota_made(g, ix) {
                        add(ix, &s.site_code);
                    }
                }
            }
            for m in &d.sccm.management_points {
                if let Some(ix) = computers.find_host(g, &m.host, Some(&d.domain)) {
                    seen.entry(m.site_code.clone()).or_default().2.insert(ix);
                    if !quota_made(g, ix) {
                        add(ix, &m.site_code);
                    }
                }
            }
            if let Some(&f) = forests.get(&d.domain) {
                let codes = by_forest.entry(f).or_default();
                for code in d.sccm.sites.iter().map(|s| &s.site_code) {
                    if !codes.iter().any(|(c, _)| c == code) {
                        codes.push((code.clone(), source.clone()));
                    }
                }
            }
        }
        let unsure = seen
            .into_iter()
            .filter(|(_, (sites, owners, mps))| {
                *sites > 1 || (!owners.is_empty() && !mps.is_empty() && owners != mps)
            })
            .map(|(code, _)| code)
            .collect();
        SiteCodes {
            of,
            by_forest,
            unsure,
        }
    }

    /// The site server candidates of site `code`, with the sources that
    /// say so. None for a code the objects don't tie to one server.
    fn of_site(&self, candidates: &[NodeIndex], code: &str) -> (Vec<NodeIndex>, Vec<String>) {
        let mut servers = Vec::new();
        if self.unsure.contains(code) {
            return (servers, Vec::new());
        }
        let mut sources = Vec::new();
        for &c in candidates {
            if let Some((_, source)) = self
                .of
                .get(&c)
                .and_then(|codes| codes.iter().find(|(x, _)| x == code))
            {
                servers.push(c);
                if !sources.contains(source) {
                    sources.push(source.clone());
                }
            }
        }
        (servers, sources)
    }

    /// The only site code the objects of a forest name, with its source.
    fn only_site(&self, forest: Option<usize>) -> Option<&(String, String)> {
        match self.by_forest.get(&forest?)?.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }
}

/// A Tier Zero host that is an SCCM client, and why.
struct SccmClient {
    host: NodeIndex,
    evidence: String,
    /// How it is known, in short ("the CmRcService/ service principal
    /// name"), for its site server's evidence.
    how: String,
    /// The site the GPO's setup parameters name.
    site_code: Option<String>,
    /// The sources the client evidence rests on when the directory data
    /// alone doesn't show it (a GPO's client setup).
    sources: Vec<String>,
    /// Something besides an untrusted or stale settings file shows it is a
    /// client: only then may its site server become Tier Zero.
    trusted: bool,
}

/// The Tier Zero hosts that are SCCM clients: the `CmRcService/` SPN, the
/// SCCM client setup a GPO pushes to them, or the client in their registry
/// (the probe, whose `AssignedSiteCode` names the site before the GPO's).
fn sccm_clients(
    g: &AdGraph,
    hosts: &HashSet<NodeIndex>,
    p: &Policies,
    probes: &Probes<'_>,
) -> Vec<SccmClient> {
    let mut out = Vec::new();
    for host in sorted(hosts) {
        let n = g.node(host);
        let by_spn = spn(n, CMRC_SPN);
        let setup = if p.is_empty() {
            None
        } else {
            policy::ccm_setup(g, p, host)
        };
        let sccm_part = hostprobe::Part::Sccm;
        let probe = probes
            .get(host)
            .filter(|v| v.any(sccm_part, |a| a.sccm_client().is_some()));
        // A current, trusted file shows the client.
        let probe_trusted =
            probe.is_some_and(|v| v.trusted(sccm_part, |a| a.sccm_client().is_some()));
        // The sites the files name, with whether a current, trusted file
        // names each. Only such a file's site picks a site server; another
        // file's is evidence only, and never overrides the GPO's.
        let sites: Vec<(String, bool)> = probe
            .map(|v| {
                v.answers(sccm_part, |a| {
                    a.sccm_client()
                        .flatten()
                        .map(|c| vec![c.to_ascii_uppercase()])
                        .unwrap_or_default()
                })
            })
            .unwrap_or_default();
        let probe_site: Option<String> =
            sites.iter().rev().find(|(_, t)| *t).map(|(c, _)| c.clone());
        let unverified_sites: Vec<&str> = sites
            .iter()
            .filter(|(c, t)| !t && Some(c) != probe_site.as_ref())
            .map(|(c, _)| c.as_str())
            .collect();
        let mut evidence = Vec::new();
        let mut how = Vec::new();
        if let Some(name) = by_spn {
            evidence.push(format!(
                "has the service principal name {name}, which the SCCM Remote Control service \
                 registers on clients"
            ));
            how.push("the CmRcService/ service principal name".to_string());
        }
        // What shows it is a client, and what names its site.
        let mut client_sources = Vec::new();
        let mut gpo_source = None;
        if let Some(s) = &setup {
            let site = s
                .site_code
                .as_deref()
                .map(|c| format!(" for site {c}"))
                .unwrap_or_default();
            evidence.push(format!(
                "gets the SCCM client{site} from the GPO {}",
                g.node(s.gpo).name
            ));
            how.push(format!(
                "the client setup in the GPO {}",
                g.node(s.gpo).name
            ));
            gpo_source = g
                .node(s.gpo)
                .domain
                .as_deref()
                .map(|d| Part::RegistryPol.source(d));
            client_sources.extend(gpo_source.clone());
        }
        if probe.is_some() {
            let site = probe_site
                .as_deref()
                .map(|c| format!(" assigned to site {c}"))
                .unwrap_or_default();
            let trust = if probe_trusted {
                String::new()
            } else {
                ", which is over 90 days old or from a settings folder that nothing shows who \
                 wrote"
                    .to_string()
            };
            evidence.push(format!(
                "has the SCCM client{site} in its registry (HKLM\\SOFTWARE\\Microsoft\\CCM, \
                 {FROM_FILE}{trust})"
            ));
            if !unverified_sites.is_empty() {
                evidence.push(format!(
                    "has site {} in a settings file that can't be relied on",
                    unverified_sites.join(" or ")
                ));
            }
            how.push("the SCCM client in its registry".to_string());
            client_sources.push(probe_source(g, host));
        }
        if evidence.is_empty() {
            continue;
        }
        let site_code = probe_site
            .clone()
            .or_else(|| setup.as_ref().and_then(|s| s.site_code.clone()));
        let site_source = match (&probe_site, &site_code) {
            (Some(_), _) => Some(probe_source(g, host)),
            (None, Some(_)) => gpo_source,
            _ => None,
        };
        // The SPN alone shows it is a client: the rest only adds the site.
        let mut sources = if by_spn.is_some() {
            Vec::new()
        } else {
            client_sources
        };
        if let Some(s) = site_source {
            if !sources.contains(&s) {
                sources.push(s);
            }
        }
        out.push(SccmClient {
            host,
            evidence: evidence.join("; it "),
            how: how.join(" and "),
            site_code,
            sources,
            trusted: by_spn.is_some() || setup.is_some() || probe_trusted,
        });
    }
    out
}

/// SCCM site servers, and the Tier Zero hosts that are SCCM clients: with
/// one site server in the client's forest, it manages the client (and is
/// Tier Zero). With several, the SCCM site objects narrow them to the
/// client's site (the one its GPO names, or the forest's only site); one
/// left manages it. Otherwise the client is reported for review.
fn sccm(
    g: &AdGraph,
    hosts: &HashSet<NodeIndex>,
    p: &Policies,
    probes: &Probes<'_>,
) -> Vec<Detection> {
    let mut out = Vec::new();
    site_servers(g, &mut out);
    let clients = sccm_clients(g, hosts, p, probes);
    if clients.is_empty() {
        return out;
    }
    let forests = crate::postprocess::forest_components(g);
    let computers = Computers::new(g);
    let sites = SiteCodes::new(g, &computers, &forests);
    let mut found = Vec::new();
    // Why each server manages its clients: the only one in the forest, or
    // the only one of the site.
    let mut by_site: HashMap<NodeIndex, String> = HashMap::new();
    // How its clients are known.
    let mut how: HashMap<NodeIndex, Vec<String>> = HashMap::new();
    for mut c in clients {
        let host = c.host;
        let mut candidates: Vec<NodeIndex> = out
            .iter()
            .map(|d| d.object)
            .filter(|&s| same_forest(g, &forests, s, host))
            .collect();
        candidates.sort_unstable();
        candidates.dedup();
        let mut chosen: Option<(NodeIndex, Vec<String>)> = None;
        if !c.trusted {
            // Only a file that can't be relied on shows the client: it is
            // reviewed, and no site server becomes Tier Zero for it.
        } else if let [server] = candidates[..] {
            chosen = Some((server, Vec::new()));
        } else if candidates.len() > 1 {
            let forest = g.node(host).domain.as_ref().and_then(|d| forests.get(d));
            let site = match &c.site_code {
                Some(code) => Some((code.clone(), None)),
                None => sites
                    .only_site(forest.copied())
                    .map(|(code, source)| (code.clone(), Some(source.clone()))),
            };
            if let Some((code, source)) = site {
                // A code two site objects publish (two hierarchies, or a
                // site rebuilt): ambiguous, so it narrows nothing.
                if sites.unsure.contains(&code) {
                    c.evidence.push_str(&format!(
                        "; its site code {code} is published by more than one SCCM site object, \
                         so which site server it means is ambiguous"
                    ));
                }
                let (servers, mut sources) = sites.of_site(&candidates, &code);
                if let [server] = servers[..] {
                    sources.extend(source);
                    by_site.insert(server, code);
                    chosen = Some((server, sources));
                }
            }
        }
        if let Some((server, sources)) = chosen {
            let h = how.entry(server).or_default();
            if !h.contains(&c.how) {
                h.push(c.how.clone());
            }
            if let Some(d) = out.iter_mut().find(|d| d.object == server) {
                d.manages.push(host);
                for s in sources.into_iter().chain(c.sources) {
                    if !d.sources.contains(&s) {
                        d.sources.push(s);
                    }
                }
            }
            continue;
        }
        let mut sources = c.sources;
        // What the site objects said is part of why it stays unknown.
        if candidates.len() > 1 {
            if let Some(d) = g.node(host).domain.as_deref() {
                if g.sysvol_domains()
                    .iter()
                    .any(|s| s.domain == d && s.checks.sccm_sites.is_some())
                {
                    sources.push(Part::SccmSites.source(d));
                }
            }
        }
        found.push(Detection {
            plane: Plane::Sccm,
            confidence: Confidence::Inferred,
            role: Role::Client,
            object: host,
            key: g.node(host).id.clone(),
            evidence: c.evidence,
            manages: candidates,
            sources,
            tier_zero: None,
        });
    }
    for d in out.iter_mut().filter(|d| !d.manages.is_empty()) {
        let clients = node_names(g, &d.manages);
        let one = d.manages.len() == 1;
        let only = match by_site.get(&d.object) {
            Some(code) => format!(
                "the only site server of site {code} (the SCCM site objects) in {} forest",
                if one { "its" } else { "their" }
            ),
            None => format!(
                "the only site server in {} forest",
                if one { "its" } else { "their" }
            ),
        };
        let known = how.get(&d.object).map(|h| h.join("; ")).unwrap_or_default();
        d.evidence = format!(
            "{}; {clients} {} an SCCM {} ({known}), and it is {only}",
            d.evidence,
            if one { "is" } else { "are" },
            if one { "client" } else { "clients" },
        );
        d.tier_zero = Some(format!("SCCM site server for {clients}"));
    }
    out.extend(found);
    out
}

/// WSUS servers that Group Policy points Tier Zero hosts at
/// (`WUServer` with `UseWUServer`, in the registry policy the built-in
/// collector reads from SYSVOL). A server that is a computer in the
/// collection manages them (Inferred: a WMI filter or security filtering
/// may keep the GPO off a host); one that isn't (an IP address, an alias,
/// a server outside the collection) leaves each host to review.
fn wsus(
    g: &AdGraph,
    hosts: &HashSet<NodeIndex>,
    p: &Policies,
    probes: &Probes<'_>,
    out: &mut Vec<Detection>,
) {
    if p.is_empty() && probes.is_empty() {
        return;
    }
    let computers = Computers::new(g);
    // Per server: its hosts, URLs, the GPOs that name it and the hosts
    // whose registry names it (the probe).
    #[derive(Default)]
    struct Named {
        hosts: Vec<NodeIndex>,
        urls: Vec<String>,
        gpos: Vec<NodeIndex>,
        read_on: Vec<NodeIndex>,
    }
    fn push<T: PartialEq>(v: &mut Vec<T>, x: T) {
        if !v.contains(&x) {
            v.push(x);
        }
    }
    let mut servers: BTreeMap<NodeIndex, Named> = BTreeMap::new();
    for host in sorted(hosts) {
        // Each URL, with the GPO that sets it (`None`: the host's registry).
        let mut urls: Vec<(String, Option<NodeIndex>)> = Vec::new();
        if !p.is_empty() {
            if let Some(w) = policy::wsus(g, p, host) {
                urls.extend(w.urls.into_iter().map(|(u, gpo)| (u, Some(gpo))));
            }
        }
        // The registry's URLs only a file that can't be relied on names.
        let mut untrusted: HashSet<String> = HashSet::new();
        if let Some(v) = probes.get(host) {
            let found = v.answers(hostprobe::Part::Wsus, |a| {
                a.wsus_urls().into_iter().map(str::to_string).collect()
            });
            for (u, trusted) in found {
                if !urls.iter().any(|(x, _)| x.eq_ignore_ascii_case(&u)) {
                    if !trusted {
                        untrusted.insert(u.clone());
                    }
                    urls.push((u, None));
                }
            }
        }
        if urls.is_empty() {
            continue;
        }
        let domain = g.node(host).domain.as_deref();
        let mut unresolved: Vec<(String, Option<NodeIndex>)> = Vec::new();
        // Named servers a domain user may have created.
        let mut made: Vec<NodeIndex> = Vec::new();
        // Servers only the probe names that it may not make Tier Zero.
        let mut blocked: Vec<String> = Vec::new();
        for (url, gpo) in &urls {
            let server = policy::url_host(url)
                .filter(|(h, _)| !policy::is_ip(h))
                .and_then(|(h, _)| computers.find_host(g, &h, domain));
            match server {
                Some(s) if s == host => {}
                Some(s) if quota_made(g, s) => {
                    made.push(s);
                    unresolved.push((url.clone(), *gpo));
                }
                Some(s)
                    if gpo.is_none()
                        && promotion_block(g, s, !untrusted.contains(url)).is_some() =>
                {
                    let why = promotion_block(g, s, !untrusted.contains(url)).unwrap_or_default();
                    blocked.push(format!("{}, {why}", g.node(s).name));
                    unresolved.push((url.clone(), *gpo));
                }
                Some(s) => {
                    let e = servers.entry(s).or_default();
                    push(&mut e.hosts, host);
                    push(&mut e.urls, url.clone());
                    match gpo {
                        Some(gpo) => push(&mut e.gpos, *gpo),
                        None => push(&mut e.read_on, host),
                    }
                }
                None => unresolved.push((url.clone(), *gpo)),
            }
        }
        if unresolved.is_empty() {
            continue;
        }
        let gpos: Vec<NodeIndex> = unresolved.iter().filter_map(|(_, g)| *g).collect();
        let read_on: Vec<NodeIndex> = if unresolved.iter().any(|(_, g)| g.is_none()) {
            vec![host]
        } else {
            Vec::new()
        };
        let urls = unresolved
            .iter()
            .map(|(u, _)| u.as_str())
            .collect::<Vec<_>>()
            .join(" or ");
        let set_by = wsus_set_by(g, &gpos, &read_on, true);
        let (key, evidence) = if !blocked.is_empty() && made.is_empty() {
            (
                format!("{WSUS_UNCONFIRMED_KEY}{}", g.node(host).id),
                format!(
                    "takes its updates from {urls}, which {set_by}: {}",
                    blocked.join("; ")
                ),
            )
        } else if made.is_empty() {
            (
                g.node(host).id.clone(),
                format!(
                    "takes its updates from {urls}, which {set_by} and which is not a computer in \
                     the collection"
                ),
            )
        } else {
            (
                format!("{WSUS_QUOTA_KEY}{}", g.node(host).id),
                format!(
                    "takes its updates from {urls}, which {set_by}. {} was created through the \
                     machine account quota, so any domain user may have made it",
                    node_names(g, &made)
                ),
            )
        };
        let mut sources = policy_sources(g, &gpos);
        sources.extend(read_on.iter().map(|&h| probe_source(g, h)));
        out.push(Detection {
            plane: Plane::Wsus,
            confidence: Confidence::Inferred,
            role: Role::Client,
            object: host,
            key,
            evidence,
            manages: Vec::new(),
            sources,
            tier_zero: None,
        });
    }
    for (server, named) in servers {
        let clients = node_names(g, &named.hosts);
        let mut sources = policy_sources(g, &named.gpos);
        sources.extend(named.read_on.iter().map(|&h| probe_source(g, h)));
        out.push(Detection {
            plane: Plane::Wsus,
            confidence: Confidence::Inferred,
            role: Role::Server,
            object: server,
            key: g.node(server).id.clone(),
            evidence: format!(
                "the WSUS server ({}) that {} for {clients}",
                named.urls.join(", "),
                wsus_set_by(g, &named.gpos, &named.read_on, false)
            ),
            manages: named.hosts,
            sources,
            tier_zero: Some(format!("WSUS server for {clients}")),
        });
    }
}

/// Who sets a WSUS URL, in words: "the GPO X sets", "the registry of DC01
/// names (its Tier Zero settings file)", or both. `own`: said of the one
/// host whose registry it is ("its registry names").
fn wsus_set_by(g: &AdGraph, gpos: &[NodeIndex], read_on: &[NodeIndex], own: bool) -> String {
    let mut parts = Vec::new();
    if !gpos.is_empty() {
        parts.push(format!("the GPO {} sets", node_names(g, gpos)));
    }
    if !read_on.is_empty() {
        parts.push(if own {
            format!("its registry names ({FROM_FILE})")
        } else {
            format!(
                "the registry of {} names (Tier Zero settings files)",
                node_names(g, read_on)
            )
        });
    }
    parts.join(" and ")
}

/// What [`Detection::key`] starts with for a Tier Zero host whose WSUS
/// server was created through the machine account quota.
pub const WSUS_QUOTA_KEY: &str = "wsus-quota/";

/// What [`Detection::key`] starts with for a Tier Zero host whose WSUS
/// server only a settings file names that can't make it Tier Zero (over 90
/// days old, unverified, or naming a computer whose creator isn't known).
pub const WSUS_UNCONFIRMED_KEY: &str = "wsus-unconfirmed/";

/// The registry policy sources of the domains of `gpos`.
fn policy_sources(g: &AdGraph, gpos: &[NodeIndex]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for &gpo in gpos {
        if let Some(d) = g.node(gpo).domain.as_deref() {
            let s = Part::RegistryPol.source(d);
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

/// The relative names of a distinguished name, outermost last
/// (`CN=A,CN=B,DC=X` gives `["A", "B", "X"]`).
fn rdns(dn: &str) -> Vec<&str> {
    dn.split(',')
        .map(|r| r.split_once('=').map_or(r, |(_, v)| v).trim())
        .collect()
}

/// The management server a SCOM AD integration group is for. The groups are
/// named `<group>_<server>_PrimarySG_<n>` (or `SecondarySG`), and either
/// name may contain underscores, so every split is tried against the
/// computers that exist.
fn scom_server(
    g: &AdGraph,
    computers: &Computers,
    cn: &str,
    mg: &str,
    domain: Option<&str>,
) -> Option<NodeIndex> {
    let cut = cn.find("_PRIMARYSG").or_else(|| cn.find("_SECONDARYSG"))?;
    let head = &cn[..cut];
    let head = head
        .strip_prefix(mg)
        .and_then(|h| h.strip_prefix('_'))
        .unwrap_or(head);
    let mut candidates = vec![head];
    candidates.extend(head.match_indices('_').map(|(i, _)| &head[i + 1..]));
    candidates
        .into_iter()
        .filter(|c| !c.is_empty())
        .find_map(|c| computers.find(g, c, domain))
}

/// A group in a management group's container under `CN=OperationsManager`
/// (its members are agents, not SCOM servers).
fn is_scom_group(n: &Node) -> bool {
    n.kind == NodeKind::Group
        && n.props.distinguishedname.as_deref().is_some_and(|dn| {
            let names = rdns(dn);
            names.len() >= 3 && names[2].eq_ignore_ascii_case("OPERATIONSMANAGER")
        })
}

/// SCOM's AD integration: under `CN=OperationsManager`, one container per
/// management group holding a group per management server whose members
/// are the agents assigned to it.
fn scom(g: &AdGraph, hosts: &HashSet<NodeIndex>) -> Vec<Detection> {
    let computers = Computers::new(g);
    let mut out = Vec::new();
    for (group, n) in g.nodes() {
        if n.kind != NodeKind::Group || !collected(n) {
            continue;
        }
        if !is_scom_group(n) {
            continue;
        }
        let names = rdns(n.props.distinguishedname.as_deref().unwrap_or_default());
        let (cn, mg) = (names[0].to_ascii_uppercase(), names[1].to_ascii_uppercase());
        let managed: Vec<NodeIndex> = {
            let mut m: Vec<NodeIndex> = g
                .transitive_members(group)
                .into_iter()
                .filter(|m| hosts.contains(m))
                .collect();
            m.sort_unstable();
            m
        };
        let key = format!("{}/{mg}", n.domain.as_deref().unwrap_or(""));
        let Some(server) = scom_server(g, &computers, &cn, &mg, n.domain.as_deref()) else {
            if !managed.is_empty() {
                out.push(Detection {
                    plane: Plane::Scom,
                    confidence: Confidence::Inferred,
                    role: Role::Group,
                    object: group,
                    key,
                    evidence: format!(
                        "a SCOM AD integration group of management group {mg} with Tier Zero \
                         agents, whose management server isn't in the collection"
                    ),
                    manages: managed,
                    sources: Vec::new(),
                    tier_zero: None,
                });
            }
            continue;
        };
        let reason = (!managed.is_empty()).then(|| {
            let names: Vec<&str> = managed.iter().map(|&h| g.node(h).name.as_str()).collect();
            format!(
                "SCOM management server (management group {mg}) for {}",
                names.join(", ")
            )
        });
        out.push(Detection {
            plane: Plane::Scom,
            confidence: Confidence::Inferred,
            role: Role::Server,
            object: server,
            key,
            evidence: format!(
                "the management server of SCOM AD integration group {}",
                n.name
            ),
            manages: managed,
            sources: Vec::new(),
            tier_zero: reason,
        });
    }
    out
}

/// The SCOM Health Service SPN. Management servers and gateways register
/// it, and agents may too.
const HEALTH_SPN: &str = "MSOMHSVC/";

/// What [`Detection::key`] starts with for a computer that has only the
/// SCOM Health Service SPN (a gateway, or an agent that registered it);
/// PW-028 reports them together, one finding per domain.
pub const SCOM_HEALTH_KEY: &str = "scom-health/";

/// Tier Zero hosts with the SCOM Health Service SPN that no AD integration
/// group ties to a management server: agents whose server is unknown.
fn scom_agents(
    g: &AdGraph,
    hosts: &HashSet<NodeIndex>,
    scom: &[Detection],
    out: &mut Vec<Detection>,
) {
    for host in sorted(hosts) {
        let Some(name) = spn(g.node(host), HEALTH_SPN) else {
            continue;
        };
        // A server, or a group whose server isn't in the collection,
        // already reports it. (The probe, which runs after, merges into
        // this review or, with a trusted server, replaces it.)
        if scom
            .iter()
            .any(|d| matches!(d.role, Role::Server | Role::Group) && d.manages.contains(&host))
        {
            continue;
        }
        out.push(Detection {
            plane: Plane::Scom,
            confidence: Confidence::Inferred,
            role: Role::Client,
            object: host,
            key: g.node(host).id.clone(),
            evidence: format!(
                "has the SCOM Health Service service principal name {name}, which SCOM agents \
                 register"
            ),
            manages: Vec::new(),
            sources: Vec::new(),
            tier_zero: None,
        });
    }
}

/// Service principal names only these products register.
fn by_spn(g: &AdGraph, hosts: &HashSet<NodeIndex>, out: &mut Vec<Detection>) {
    // (prefix, plane, what, on servers only: computers that aren't Tier
    // Zero hosts). The Data Access SPN comes before the Health Service one,
    // so a management server that has both is reported on its own.
    const SPNS: &[(&str, Plane, &str, bool)] = &[
        (
            "MSOMSDKSVC/",
            Plane::Scom,
            "SCOM Data Access service",
            false,
        ),
        (HEALTH_SPN, Plane::Scom, "SCOM Health Service", true),
        (
            "SCVMM/",
            Plane::Virtualization,
            "System Center Virtual Machine Manager",
            false,
        ),
    ];
    let mut seen: HashSet<(NodeIndex, Plane)> = out.iter().map(|d| (d.object, d.plane)).collect();
    for (ix, n) in g.nodes() {
        if !matches!(n.kind, NodeKind::Computer | NodeKind::User) || !collected(n) {
            continue;
        }
        for &(prefix, plane, what, servers) in SPNS {
            if servers && (n.kind != NodeKind::Computer || hosts.contains(&ix)) {
                continue;
            }
            let Some(spn) = spn(n, prefix) else {
                continue;
            };
            if !seen.insert((ix, plane)) {
                continue;
            }
            // Health Service hosts can be many (agents may register it):
            // one finding per domain.
            let key = if prefix == HEALTH_SPN {
                format!("{SCOM_HEALTH_KEY}{}", n.domain.as_deref().unwrap_or(""))
            } else {
                n.id.clone()
            };
            out.push(Detection {
                plane,
                confidence: Confidence::Inferred,
                role: if n.kind == NodeKind::Computer {
                    Role::Server
                } else {
                    Role::Account
                },
                object: ix,
                key,
                evidence: format!("has the {what} service principal name {spn}"),
                manages: Vec::new(),
                sources: Vec::new(),
                tier_zero: None,
            });
        }
    }
}

/// What [`Detection::key`] starts with for a Hyper-V host; PW-028 reports
/// them together, one finding per domain.
pub const HYPER_V_KEY: &str = "hyper-v/";

/// Hyper-V hosts register these for live migration and the VM console.
const HYPER_V_SPNS: &[&str] = &[
    "MICROSOFT VIRTUAL SYSTEM MIGRATION SERVICE/",
    "MICROSOFT VIRTUAL CONSOLE SERVICE/",
];

/// Failover cluster nodes register this.
const CLUSTER_SPN: &str = "MSSERVERCLUSTERMGMTAPI/";

/// Hyper-V runs on Windows Server: a computer whose operating system is
/// known and isn't Windows Server is not counted.
fn windows_server_or_unknown(n: &Node) -> bool {
    n.props
        .operatingsystem
        .as_deref()
        .is_none_or(|os| os.to_ascii_uppercase().contains("WINDOWS SERVER"))
}

fn hyper_v(g: &AdGraph, out: &mut Vec<Detection>) {
    let seen: HashSet<NodeIndex> = out
        .iter()
        .filter(|d| d.plane == Plane::Virtualization)
        .map(|d| d.object)
        .collect();
    let mut found = Vec::new();
    for (ix, n) in g.nodes() {
        if n.kind != NodeKind::Computer
            || !collected(n)
            || privileged_anyway(n)
            || !windows_server_or_unknown(n)
            || seen.contains(&ix)
        {
            continue;
        }
        let Some(name) = HYPER_V_SPNS.iter().find_map(|p| spn(n, p)) else {
            continue;
        };
        let cluster = if spn(n, CLUSTER_SPN).is_some() {
            ", and is a failover cluster node"
        } else {
            ""
        };
        found.push(Detection {
            plane: Plane::Virtualization,
            confidence: Confidence::Inferred,
            role: Role::Server,
            object: ix,
            key: format!("{HYPER_V_KEY}{}", n.domain.as_deref().unwrap_or("")),
            evidence: format!("has the Hyper-V service principal name {name}{cluster}"),
            manages: Vec::new(),
            sources: Vec::new(),
            tier_zero: None,
        });
    }
    out.extend(found);
}

/// A group named exactly `ESX Admins`: ESXi hosts joined to the domain make
/// its members administrators by default, whatever its SID (CVE-2024-37085).
pub fn is_esx_admins(n: &Node) -> bool {
    n.kind == NodeKind::Group && short_name(n).eq_ignore_ascii_case("ESX ADMINS")
}

fn esx_admins(g: &AdGraph, out: &mut Vec<Detection>) {
    for (ix, n) in g.nodes() {
        if !collected(n) || !is_esx_admins(n) {
            continue;
        }
        out.push(Detection {
            plane: Plane::Virtualization,
            confidence: Confidence::Inferred,
            role: Role::Group,
            object: ix,
            key: n.id.clone(),
            evidence: "named ESX Admins, which domain-joined ESXi hosts make administrators by \
                       default"
                .into(),
            manages: Vec::new(),
            sources: Vec::new(),
            tier_zero: None,
        });
    }
}

/// Name words that point at ESXi or vCenter (not Hyper-V or VMM).
const ESXI_WORDS: &[&str] = &["ESX", "VCENTER", "VCSA", "VSPHERE"];

/// What in `domain` suggests ESXi hosts or vCenter: computers whose
/// operating system is ESXi or VMware's, and objects named like them (other
/// than the ESX Admins group itself), each with why.
pub fn esxi_evidence(g: &AdGraph, domain: &str) -> Vec<(NodeIndex, String)> {
    let mut out = Vec::new();
    for (ix, n) in g.nodes() {
        if !collected(n)
            || !n.is_enabled()
            || n.domain.as_deref() != Some(domain)
            || !matches!(
                n.kind,
                NodeKind::User | NodeKind::Computer | NodeKind::Group
            )
            || is_esx_admins(n)
            || built_in(&n.id)
        {
            continue;
        }
        let os = n.props.operatingsystem.as_deref().filter(|os| {
            let os = os.to_ascii_uppercase();
            os.contains("ESX") || os.contains("VMWARE")
        });
        if let (NodeKind::Computer, Some(os)) = (n.kind, os) {
            out.push((ix, format!("operating system {os}")));
        } else if let Some((Plane::Virtualization, word)) = name_match(short_name(n)) {
            if ESXI_WORDS.contains(&word) {
                out.push((ix, format!("its name contains {word}")));
            }
        }
    }
    out
}

/// Words in object names that suggest a management product. A name matches
/// when one of its words (split at anything not a letter or digit) starts
/// with one of these.
const NAMES: &[(Plane, &[&str])] = &[
    (Plane::Sccm, &["SCCM", "MECM", "MEMCM", "CONFIGMGR"]),
    (Plane::Scom, &["SCOM", "OPSMGR"]),
    (Plane::Wsus, &["WSUS"]),
    (
        Plane::Backup,
        &[
            "VEEAM",
            "COMMVAULT",
            "NETBACKUP",
            "BACKUPEXEC",
            "RUBRIK",
            "COHESITY",
            "ARCSERVE",
            "ACRONIS",
            "NETWORKER",
            "AVAMAR",
            "DPM",
        ],
    ),
    (
        Plane::Virtualization,
        &["ESX", "VCENTER", "VCSA", "VSPHERE", "SCVMM", "HYPERV"],
    ),
];

/// The plane a name suggests, and the word that matched.
pub fn name_match(name: &str) -> Option<(Plane, &'static str)> {
    let upper = name.to_ascii_uppercase().replace("HYPER-V", "HYPERV");
    for word in upper.split(|c: char| !c.is_ascii_alphanumeric()) {
        for &(plane, prefixes) in NAMES {
            if let Some(p) = prefixes.iter().find(|p| word.starts_with(*p)) {
                return Some((plane, p));
            }
        }
    }
    None
}

/// Windows' own groups and accounts (`BUILTIN\Hyper-V Administrators`,
/// RIDs below 1000): they exist whether or not a product is installed.
fn built_in(id: &str) -> bool {
    let (_, s) = sid::split_prefixed(id);
    s.starts_with("S-1-5-32-") || sid::domain_rid(id).is_some_and(|rid| rid < 1000)
}

fn by_name(g: &AdGraph, out: &mut Vec<Detection>) {
    let mut seen: HashSet<NodeIndex> = out.iter().map(|d| d.object).collect();
    let mut found = Vec::new();
    for (ix, n) in g.nodes() {
        if !matches!(
            n.kind,
            NodeKind::User | NodeKind::Computer | NodeKind::Group
        ) || !collected(n)
            || !n.is_enabled()
            || privileged_anyway(n)
            || seen.contains(&ix)
            || is_scom_group(n)
            || built_in(&n.id)
        {
            continue;
        }
        let Some((plane, word)) = name_match(short_name(n)) else {
            continue;
        };
        seen.insert(ix);
        let role = match n.kind {
            NodeKind::Computer => Role::Server,
            NodeKind::Group => Role::Group,
            _ => Role::Account,
        };
        found.push(Detection {
            plane,
            confidence: Confidence::Heuristic,
            role,
            object: ix,
            key: n.domain.clone().unwrap_or_default(),
            evidence: format!("its name contains {word}"),
            manages: Vec::new(),
            sources: Vec::new(),
            tier_zero: None,
        });
        // The computers in a product's group are likely its servers.
        if n.kind == NodeKind::Group {
            for m in g.transitive_members(ix) {
                let member = g.node(m);
                if member.kind == NodeKind::Computer
                    && collected(member)
                    && member.is_enabled()
                    && !member.is_dc
                    && seen.insert(m)
                {
                    found.push(Detection {
                        plane,
                        confidence: Confidence::Heuristic,
                        role: Role::Server,
                        object: m,
                        key: member.domain.clone().unwrap_or_default(),
                        evidence: format!("member of {}", n.name),
                        manages: Vec::new(),
                        sources: Vec::new(),
                        tier_zero: None,
                    });
                }
            }
        }
    }
    out.extend(found);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_from_the_installer_description() {
        let d = "Account created by Microsoft Azure Active Directory Connect with installation \
                 identifier 1a2b3c running on computer aadc01 configured to synchronize to tenant \
                 contoso.onmicrosoft.com. This account must have directory replication permissions.";
        assert_eq!(described_host(d).as_deref(), Some("AADC01"));
        assert_eq!(
            described_host("running on computer AADC01.CONTOSO.LOCAL.").as_deref(),
            Some("AADC01.CONTOSO.LOCAL")
        );
        assert_eq!(described_host("sync account"), None);
    }

    #[test]
    fn names_match_on_word_starts() {
        assert_eq!(name_match("SVC_VEEAM"), Some((Plane::Backup, "VEEAM")));
        assert_eq!(name_match("VEEAMBR01"), Some((Plane::Backup, "VEEAM")));
        assert_eq!(
            name_match("ESX Admins"),
            Some((Plane::Virtualization, "ESX"))
        );
        assert_eq!(
            name_match("Hyper-V Hosts"),
            Some((Plane::Virtualization, "HYPERV"))
        );
        assert_eq!(name_match("WSUS01"), Some((Plane::Wsus, "WSUS")));
        assert_eq!(name_match("SCCM Site Servers"), Some((Plane::Sccm, "SCCM")));
        // Inside a word is not a match.
        assert_eq!(name_match("MYVEEAM"), None);
        assert_eq!(name_match("SALES"), None);
        assert_eq!(name_match("BACKUP01"), None);
    }

    #[test]
    fn distinguished_name_parts() {
        assert_eq!(
            rdns("CN=MG1_SCOM01_PRIMARYSG_1,CN=MG1,CN=OPERATIONSMANAGER,DC=CONTOSO,DC=LOCAL"),
            [
                "MG1_SCOM01_PRIMARYSG_1",
                "MG1",
                "OPERATIONSMANAGER",
                "CONTOSO",
                "LOCAL"
            ]
        );
    }
}
