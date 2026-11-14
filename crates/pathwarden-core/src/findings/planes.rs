//! PW-025, PW-028, PW-029, PW-037 and PW-038: management planes (detected
//! in [`crate::mgmt`]).

use std::collections::BTreeMap;

use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use super::{Context, Finding, Severity};
use crate::graph::AdGraph;
use crate::mgmt::{self, Confidence, Detection, Plane, Role};
use crate::model::{EdgeKind, NodeKind};

const MS_ENTRA_CONNECT_ACCOUNTS: &str = "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions";
const MS_ENTRA_CONNECT_HARDENING: &str = "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites#harden-your-microsoft-entra-connect-server";
const MS_ACCESS_MODEL: &str = "https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model";
const MISCONFIGURATION_MANAGER: &str = "https://github.com/subat0mik/Misconfiguration-Manager";
const MS_SCOM_AD: &str =
    "https://learn.microsoft.com/en-us/system-center/scom/manage-ad-integration-agent-assignment";
const MS_HYPER_V_MIGRATION: &str = "https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/deploy/set-up-hosts-for-live-migration-without-failover-clustering";
const MS_ESX_ADMINS: &str = "https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/";
const BROADCOM_ESX_ADMINS: &str = "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24505";
const MS_SSO_KEY: &str =
    "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-faq";
const MS_WSUS_SSL: &str = "https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus#25-secure-wsus-with-the-secure-sockets-layer-protocol";
const GOSECURE_WSUS: &str =
    "https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/";

fn names(g: &AdGraph, ixs: &[NodeIndex], limit: usize) -> String {
    let mut s: Vec<&str> = ixs
        .iter()
        .take(limit)
        .map(|&ix| g.node(ix).name.as_str())
        .collect();
    if ixs.len() > limit {
        s.push("...");
    }
    s.join(", ")
}

fn refs(plane: Plane) -> &'static [&'static str] {
    match plane {
        Plane::EntraConnect | Plane::SeamlessSso => {
            &[MS_ENTRA_CONNECT_ACCOUNTS, MS_ENTRA_CONNECT_HARDENING]
        }
        Plane::Sccm => &[MISCONFIGURATION_MANAGER, MS_ACCESS_MODEL],
        Plane::Scom => &[MS_SCOM_AD, MS_ACCESS_MODEL],
        Plane::Wsus => &[GOSECURE_WSUS, MS_ACCESS_MODEL],
        _ => &[MS_ACCESS_MODEL],
    }
}

/// A management server and what it controls, merged over its detections.
struct Server {
    plane: Plane,
    confidence: Confidence,
    evidence: Vec<String>,
    manages: Vec<NodeIndex>,
    edges: Vec<EdgeIndex>,
    /// The built-in collector's sources it rests on.
    sources: Vec<String>,
}

/// PW-025: a system that manages Tier Zero computers (or holds a Tier Zero
/// credential) and wasn't declared Tier Zero. Pathwarden treats it as Tier
/// Zero from the moment it finds it, so PW-003 covers it; this
/// finding stays until it is declared (or stops managing Tier Zero).
pub(super) fn managed_from_outside(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let detections = mgmt::detect(g);
    let mut servers: BTreeMap<NodeIndex, Server> = BTreeMap::new();
    for d in detections
        .iter()
        .filter(|d| d.role == Role::Server && d.tier_zero.is_some())
    {
        let s = servers.entry(d.object).or_insert_with(|| Server {
            plane: d.plane,
            confidence: d.confidence,
            evidence: Vec::new(),
            manages: Vec::new(),
            edges: Vec::new(),
            sources: Vec::new(),
        });
        if !s.evidence.contains(&d.evidence) {
            s.evidence.push(d.evidence.clone());
        }
        for src in &d.sources {
            if !s.sources.contains(src) {
                s.sources.push(src.clone());
            }
        }
        for &m in &d.manages {
            if !s.manages.contains(&m) {
                s.manages.push(m);
            }
        }
    }
    for e in g.inner().edge_references() {
        if *e.weight() != EdgeKind::ManagesHost || !g.node(e.target()).tier_zero {
            continue;
        }
        let s = servers.entry(e.source()).or_insert_with(|| Server {
            plane: Plane::Other,
            confidence: Confidence::Inferred,
            evidence: vec![match g.edge_source_name(e.id()) {
                Some(source) => format!("{source} reports that it manages Tier Zero computers"),
                None => "it manages Tier Zero computers".to_string(),
            }],
            manages: Vec::new(),
            edges: Vec::new(),
            sources: Vec::new(),
        });
        s.edges.push(e.id());
        if !s.manages.contains(&e.target()) {
            s.manages.push(e.target());
        }
    }

    let mut out = Vec::new();
    for (ix, s) in servers {
        let n = g.node(ix);
        let classified = mgmt::is_plane_reason(n);
        // Configured as Tier Zero, or Tier Zero anyway (a DC): nothing to do.
        if n.tier_zero && !classified {
            continue;
        }
        // Configured as not Tier Zero, with no path to report.
        if !n.tier_zero && s.edges.is_empty() {
            continue;
        }
        out.push(server_finding(ctx, ix, &s, classified));
    }

    // Entra Connect accounts whose server isn't known (or isn't Tier Zero).
    for d in &detections {
        if d.plane != Plane::EntraConnect || d.role != Role::Account || d.tier_zero.is_none() {
            continue;
        }
        if !g.node(d.object).tier_zero {
            continue; // Configured as not Tier Zero: PW-002 reports its DCSync.
        }
        let has_server = detections
            .iter()
            .any(|s| s.role == Role::Server && s.key == d.key && g.node(s.object).tier_zero);
        if !has_server {
            out.push(unknown_sync_server(ctx, d));
        }
    }
    out
}

fn server_finding(ctx: &Context, ix: NodeIndex, s: &Server, classified: bool) -> Finding {
    let g = ctx.graph;
    let n = g.node(ix);
    let targets = names(g, &s.manages, 5);
    let what = match s.plane {
        Plane::EntraConnect => format!("stores the credentials of {targets}, which can DCSync"),
        _ => format!("manages {targets}"),
    };
    let kind = match s.plane {
        Plane::Other => "management server".to_string(),
        p => format!("{} server", p.name()),
    };
    let status = if classified {
        format!(
            "It was not configured as Tier Zero, so Pathwarden treats it as Tier Zero from this \
             run on: PW-003 reports who controls {0}, PW-001 and the remediation path count \
             every route to it, and Tier Zero sign-ins to it are no longer PW-004 findings.",
            n.name
        )
    } else {
        format!(
            "It is set as not Tier Zero in the settings, so every \
             path to {} is a path to Tier Zero.",
            n.name
        )
    };
    let fix = match s.plane {
        Plane::EntraConnect => format!(
            "Keep {0} only if it still runs Entra Connect. If it does, add it under Additional Tier Zero \
             in Settings, allow only Tier Zero admins to sign in to and administer it, and fix \
             what PW-003 reports about it. If it doesn't, disable {targets} and remove \
             its replication rights on the domain.",
            n.name
        ),
        _ => format!(
            "Either take {targets} out of {0}'s management (uninstall the agent, or manage them \
             from a system that is Tier Zero), or declare {0} Tier Zero (add it under \
             Additional Tier Zero in Settings) and fix what PW-003 reports about it.",
            n.name
        ),
    };
    let detail = format!("{} ({})", s.evidence.join("; "), s.confidence.as_str());
    let mut f = Finding::new(
        "PW-025",
        Severity::High,
        &[s.plane.key(), &n.id],
        format!("{} ({kind}) controls Tier Zero", n.name),
    )
    .domain(n.domain.as_ref())
    .floor(Severity::High)
    .summary(format!(
        "{} {what}. Whoever controls {} controls those Tier Zero objects. {status} Evidence \
         ({}): {}.",
        n.name,
        n.name,
        s.confidence.as_str(),
        s.evidence.join("; ")
    ))
    .remediation(fix)
    .affect_with(
        g,
        std::iter::once((ix, Some(detail))).chain(s.manages.iter().map(|&m| (m, None))),
    )
    .entry([ix])
    .hits(s.manages.iter().copied())
    .path(s.edges.first().map(|&e| ctx.edge_path(ix, e)))
    .evidence(s.edges.iter().copied())
    .refs(refs(s.plane));
    f.sources = s.sources.clone();
    f
}

fn unknown_sync_server(ctx: &Context, d: &Detection) -> Finding {
    let g = ctx.graph;
    let n = g.node(d.object);
    let named = n
        .props
        .description
        .as_deref()
        .and_then(mgmt::described_host);
    let why = match named {
        Some(host) => format!(
            "its description names {host}, which is not a Tier Zero computer in the collection"
        ),
        None => "its description names no server".to_string(),
    };
    Finding::new(
        "PW-025",
        Severity::High,
        &[Plane::EntraConnect.key(), &n.id],
        format!("The Entra Connect server of {} is not identified", n.name),
    )
    .domain(n.domain.as_ref())
    .floor(Severity::High)
    .summary(format!(
        "{} is an Entra Connect sync account: {}. Pathwarden treats it as Tier Zero. The server \
         that stores its password controls the domain as well, but Pathwarden can't tell which \
         one it is: {why}.",
        n.name, d.evidence
    ))
    .remediation(format!(
        "Find the server that uses {0} (on Entra Connect servers, the Synchronization Service \
         Manager or `Get-ADSyncConnector` shows the connector account) and add it to `tier_zero` \
         in pathwarden.toml. If no server uses {0} any more, disable it and remove its replication \
         rights on the domain.",
        n.name
    ))
    .affect_with(
        g,
        std::iter::once((d.object, Some(d.evidence.clone())))
            .chain(d.manages.iter().map(|&m| (m, None))),
    )
    .entry([d.object])
    .hits(d.manages.iter().copied())
    .refs(refs(Plane::EntraConnect))
}

/// PW-028: what looks like a management plane but isn't tied to Tier Zero
/// by the directory data. Product structures (SCCM's System Management
/// permissions, SCOM groups, product SPNs) are one finding each; name
/// matches are one finding per product and domain.
pub(super) fn review(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let detections = mgmt::detect(g);
    let mut out = Vec::new();
    let mut by_name: BTreeMap<(Plane, String), Vec<&Detection>> = BTreeMap::new();
    let mut per_domain: BTreeMap<(&'static str, String), Vec<&Detection>> = BTreeMap::new();
    let mut backups: BTreeMap<(String, String), Vec<&Detection>> = BTreeMap::new();
    for d in &detections {
        let n = g.node(d.object);
        // Backup agents: one finding per product and domain.
        if d.role == Role::Client && d.key.starts_with(mgmt::BACKUP_KEY) {
            backups
                .entry((
                    d.key[mgmt::BACKUP_KEY.len()..].to_string(),
                    n.domain.clone().unwrap_or_default(),
                ))
                .or_default()
                .push(d);
            continue;
        }
        // Tier Zero computers whose server is unknown: Tier Zero themselves,
        // and reported for that reason, until every candidate server is
        // Tier Zero.
        if d.role == Role::Client {
            let decided = d.plane == Plane::Sccm
                && !d.manages.is_empty()
                && d.manages.iter().all(|&s| g.node(s).tier_zero);
            if !decided {
                out.push(client(ctx, d));
            }
            continue;
        }
        if n.tier_zero {
            continue;
        }
        // A group that administers management servers (ADSyncAdmins) is
        // reviewed when it isn't Tier Zero, even with a reason: its servers
        // were configured as not Tier Zero.
        let waits_for_servers = d.role == Role::Group && !d.manages.is_empty();
        if d.tier_zero.is_some() && !waits_for_servers {
            continue;
        }
        // PW-029 reports the ESX Admins group.
        if mgmt::is_esx_admins(n) {
            continue;
        }
        let group = if d.key.starts_with(mgmt::HYPER_V_KEY) {
            Some(HYPER_V)
        } else if d.key.starts_with(mgmt::SCOM_HEALTH_KEY) {
            Some(SCOM_HEALTH)
        } else {
            None
        };
        if let Some(kind) = group {
            per_domain
                .entry((kind, n.domain.clone().unwrap_or_default()))
                .or_default()
                .push(d);
            continue;
        }
        match d.confidence {
            Confidence::Inferred => out.push(inferred(ctx, d)),
            Confidence::Heuristic => by_name
                .entry((d.plane, n.domain.clone().unwrap_or_default()))
                .or_default()
                .push(d),
            Confidence::Strong => {}
        }
    }
    for ((plane, domain), list) in by_name {
        let ixs: Vec<NodeIndex> = list.iter().map(|d| d.object).collect();
        let shown = if domain.is_empty() {
            "the collection"
        } else {
            domain.as_str()
        };
        out.push(
            Finding::new(
                "PW-028",
                Severity::Low,
                &[plane.key(), "names", &domain],
                format!("Possible {} systems in {shown}, by name", plane.name()),
            )
            .domain((!domain.is_empty()).then_some(&domain))
            .summary(format!(
                "{} named like {} components: {}. A name proves nothing, so this is for review. \
                 If one of them is {} server, or an account or group that administers one, and \
                 it manages domain controllers, CA servers or other Tier Zero systems, it is part \
                 of Tier Zero. {}",
                if ixs.len() == 1 {
                    "1 object is".to_string()
                } else {
                    format!("{} objects are", ixs.len())
                },
                plane.name(),
                names(g, &ixs, 8),
                match plane {
                    Plane::Sccm | Plane::EntraConnect => format!("an {}", plane.name()),
                    _ => format!("a {}", plane.name()),
                },
                why_it_matters(plane)
            ))
            .remediation(review_fix(&names(g, &ixs, 3)))
            .affect_with(g, list.iter().map(|d| (d.object, Some(d.evidence.clone())))),
        );
    }
    for ((kind, domain), list) in per_domain {
        out.push(hosts_by_domain(ctx, kind, &domain, &list));
    }
    for ((product, domain), list) in backups {
        out.push(backup_agents(ctx, &product, &domain, &list));
    }
    out
}

/// PW-028 (Medium): Tier Zero computers of a domain that run one product's
/// backup agent, from their Tier Zero settings files. Whoever controls the
/// backup server holds copies of them, and runs code through the agent;
/// the files can't say which server that is.
fn backup_agents(ctx: &Context, product: &str, domain: &str, list: &[&Detection]) -> Finding {
    let g = ctx.graph;
    let mut hosts: Vec<NodeIndex> = list.iter().map(|d| d.object).collect();
    hosts.sort_unstable();
    hosts.dedup();
    let shown = if domain.is_empty() {
        "the collection"
    } else {
        domain
    };
    let confidence = if list.iter().all(|d| d.confidence == Confidence::Strong) {
        Confidence::Strong
    } else {
        Confidence::Inferred
    };
    let what = if product == "other" {
        "backup agents of other products".to_string()
    } else {
        format!("the {product} backup agent")
    };
    let mut sources: Vec<String> = list.iter().flat_map(|d| d.sources.clone()).collect();
    sources.sort();
    sources.dedup();
    let mut f = Finding::new(
        "PW-028",
        Severity::Medium,
        &[Plane::Backup.key(), "agents", product, domain],
        if product == "other" {
            format!("Tier Zero computers in {shown} run other backup agents")
        } else {
            format!("Tier Zero computers in {shown} run the {product} backup agent")
        },
    )
    .domain((!domain.is_empty()).then(|| domain.to_string()).as_ref())
    .summary(format!(
        "{} {} {what}, as {} Tier Zero settings {} ({}; {}). {} Pathwarden \
         can't tell which backup server protects them, so it doesn't treat one as Tier Zero.",
        crate::text::count(hosts.len(), "Tier Zero computer", "Tier Zero computers"),
        if hosts.len() == 1 { "runs" } else { "run" },
        if hosts.len() == 1 { "its" } else { "their" },
        if hosts.len() == 1 {
            "file shows"
        } else {
            "files show"
        },
        names(g, &hosts, 8),
        confidence.as_str(),
        why_it_matters(Plane::Backup)
    ))
    .remediation(format!(
        "Find the {} server that protects {} (its console lists the computers it \
         protects). Add it, with its configuration database and the repositories that hold \
         these backups, to `tier_zero` in pathwarden.toml, and allow only Tier Zero admins to \
         administer it. Then accept this finding as a risk with that reason. Uninstall the \
         agent where nothing backs up with it.",
        if product == "other" {
            "backup"
        } else {
            product
        },
        names(g, &hosts, 3)
    ))
    .affect_with(g, list.iter().map(|d| (d.object, Some(d.evidence.clone()))))
    .refs(refs(Plane::Backup));
    f.sources = sources;
    f
}

const HYPER_V: &str = "hyper-v";
const SCOM_HEALTH: &str = "health-service";

/// PW-028 (High): a domain controller or CA host is an SCCM client or a
/// SCOM agent, and the directory doesn't say which server manages it.
fn client(ctx: &Context, d: &Detection) -> Finding {
    let g = ctx.graph;
    let n = g.node(d.object);
    let (title, server, fix) = match d.plane {
        Plane::Sccm => (
            format!(
                "{} is an SCCM client, and its site server is unknown",
                n.name
            ),
            "site server",
            format!(
                "Find the site server {0} reports to (Configuration Manager in the Control Panel \
                 of {0}, or the registry value `AssignedSiteCode` under \
                 `HKLM\\SOFTWARE\\Microsoft\\SMS\\Mobile Client`). Then uninstall the SCCM client \
                 from {0}, or add every site server of its forest, with the SMS Provider and site \
                 database servers, to `tier_zero` in pathwarden.toml. If its site server isn't in \
                 the collection, check it and accept this finding as a risk with that reason.",
                n.name
            ),
        ),
        Plane::Wsus if d.key.starts_with(mgmt::WSUS_QUOTA_KEY) => (
            format!(
                "{} takes its updates from a computer a domain user may have created",
                n.name
            ),
            "WSUS server",
            format!(
                "Check who created the computer the GPO names, and who controls it now. If it \
                 is the real WSUS server, remove its creator's rights on it, add it to \
                 `tier_zero` in pathwarden.toml and accept this finding as a risk with that \
                 reason. If it isn't, point {0} at the real WSUS server in the GPO that sets it.",
                n.name
            ),
        ),
        Plane::Wsus if d.key.starts_with(mgmt::WSUS_UNCONFIRMED_KEY) => (
            format!(
                "{} takes its updates from a WSUS server Pathwarden can't confirm",
                n.name
            ),
            "WSUS server",
            format!(
                "Run the Tier Zero settings script on {0} again and give its file with the \
                 collection, or collect with the built-in collector, so Pathwarden can confirm \
                 the WSUS server and who created it. If it is a Tier Zero system, add it to \
                 `tier_zero` in pathwarden.toml and accept this finding as a risk with that \
                 reason.",
                n.name
            ),
        ),
        Plane::Wsus => (
            format!(
                "{} takes its updates from a WSUS server outside the collection",
                n.name
            ),
            "WSUS server",
            format!(
                "Find the WSUS server the URL names (an alias in DNS, or an address). If it is a \
                 Tier Zero system, add it to `tier_zero` in pathwarden.toml and accept this \
                 finding as a risk with that reason. If it isn't, point {0} at a WSUS server \
                 that is Tier Zero, or let it take updates from Microsoft, in the GPO that sets \
                 it.",
                n.name
            ),
        ),
        Plane::Virtualization => (
            format!(
                "{} is a Hyper-V virtual machine, and its host is unknown",
                n.name
            ),
            "Hyper-V host",
            format!(
                "Find the Hyper-V host that runs {0} (Hyper-V Manager or Failover Cluster Manager \
                 lists its virtual machines). Add it, with its cluster and the System Center \
                 Virtual Machine Manager that manages it, to `tier_zero` in pathwarden.toml, and \
                 allow only Tier Zero admins to administer it. Then accept this finding as a \
                 risk with that reason.",
                n.name
            ),
        ),
        Plane::Backup => (
            format!(
                "{} runs a backup agent, and its backup server is unknown",
                n.name
            ),
            "backup server",
            format!(
                "Find the backup server that protects {0} (the backup console lists the \
                 computers it protects). Add it, with its configuration database and the \
                 repositories that hold the backups of {0}, to `tier_zero` in pathwarden.toml, \
                 and allow only Tier Zero admins to administer it. Then accept this finding as \
                 a risk with that reason. If nothing backs up {0} with that agent, uninstall it.",
                n.name
            ),
        ),
        _ => (
            format!(
                "{} is a SCOM agent, and its management server is unknown",
                n.name
            ),
            "management server",
            format!(
                "Find the management server {0} reports to (the registry key `Parent Health \
                 Services` under `HKLM\\SOFTWARE\\Microsoft\\Microsoft Operations \
                 Manager\\3.0\\Agent Management Groups`). Uninstall the agent from {0}, or \
                 monitor it from a management group run from Tier Zero. If that management server \
                 is Tier Zero, add it to `tier_zero` in pathwarden.toml and accept this finding as \
                 a risk with that reason: the directory still doesn't show which server it reports \
                 to.",
                n.name
            ),
        ),
    };
    let candidates = match (d.plane, d.manages.as_slice()) {
        (Plane::Sccm, []) => " The collection has no SCCM site server in its forest.".to_string(),
        (Plane::Sccm, list) => format!(
            " Its forest has {} site servers ({}), so Pathwarden can't tell which one manages \
             it.{}",
            list.len(),
            names(g, list, 5),
            if d.sources.iter().any(|s| s.starts_with("SCCM site objects")) {
                " The SCCM site objects don't narrow them to one."
            } else {
                " The SCCM site objects were not read, and they may name its site's server."
            }
        ),
        (Plane::Wsus | Plane::Virtualization | Plane::Backup, _) => String::new(),
        _ if d.sources.iter().any(|s| crate::hostprobe::is_source(s)) => String::new(),
        _ => " No SCOM AD integration group assigns it to a management server.".to_string(),
    };
    let mut f = Finding::new(
        "PW-028",
        Severity::High,
        &[d.plane.key(), "client", &n.id],
        title,
    )
    .domain(n.domain.as_ref())
    .summary(format!(
        "{} {} ({}). {}{candidates} Whoever controls its {server} controls {}, so that server \
         is part of Tier Zero.",
        n.name,
        d.evidence,
        d.confidence.as_str(),
        why_it_matters(d.plane),
        n.name
    ))
    .remediation(fix)
    .affect_with(
        g,
        std::iter::once((d.object, Some(d.evidence.clone()))).chain(
            d.manages
                .iter()
                .map(|&m| (m, Some(format!("{server} candidate")))),
        ),
    )
    .refs(refs(d.plane));
    f.sources = d.sources.clone();
    f
}

/// PW-028 (Medium): the hosts of a domain found by an SPN that many
/// computers can have, in one finding: Hyper-V hosts, and computers with
/// the SCOM Health Service SPN (gateways, and agents that register it).
fn hosts_by_domain(ctx: &Context, kind: &str, domain: &str, list: &[&Detection]) -> Finding {
    let g = ctx.graph;
    let ixs: Vec<NodeIndex> = list.iter().map(|d| d.object).collect();
    let shown = if domain.is_empty() {
        "the collection"
    } else {
        domain
    };
    let have = if ixs.len() == 1 {
        "1 computer has".to_string()
    } else {
        format!("{} computers have", ixs.len())
    };
    let (plane, title, what, then, refs): (Plane, String, &str, &str, &[&'static str]) =
        if kind == SCOM_HEALTH {
            (
                Plane::Scom,
                format!("SCOM Health Service hosts in {shown}"),
                "the SCOM Health Service service principal name (`MSOMHSvc/`)",
                "Management servers and gateways register it, and agents may too. If one of them \
                 is the management server or gateway of a domain controller or CA server, it is \
                 part of Tier Zero, and so is everyone who administers it.",
                &[MS_SCOM_AD, MS_ACCESS_MODEL],
            )
        } else {
            (
                Plane::Virtualization,
                format!("Hyper-V hosts in {shown}"),
                "the Hyper-V live migration or console service principal names",
                "If one of them runs a domain controller or a CA server, it is part of Tier Zero, \
                 and so is everyone who administers it.",
                &[MS_HYPER_V_MIGRATION, MS_ACCESS_MODEL],
            )
        };
    Finding::new(
        "PW-028",
        Severity::Medium,
        &[plane.key(), kind, domain],
        title,
    )
    .domain((!domain.is_empty()).then(|| domain.to_string()).as_ref())
    .summary(format!(
        "{have} {what}: {} ({}). {} {then}",
        names(g, &ixs, 8),
        Confidence::Inferred.as_str(),
        why_it_matters(plane)
    ))
    .remediation(review_fix(&names(g, &ixs, 3)))
    .affect_with(g, list.iter().map(|d| (d.object, Some(d.evidence.clone()))))
    .refs(refs)
}

fn why_it_matters(plane: Plane) -> &'static str {
    match plane {
        Plane::Sccm => {
            "An SCCM site server, and every SCCM Full Administrator, can run code as SYSTEM on \
             every SCCM client."
        }
        Plane::Scom => {
            "A SCOM management server, and every SCOM administrator, can run code as SYSTEM on \
             every agent."
        }
        Plane::Wsus => {
            "Whoever controls the WSUS server (or, over plain HTTP, the network path to it) can \
             push a malicious update to every computer that uses it."
        }
        Plane::Backup => {
            "Backup servers hold copies of the domain controllers (and with them every password \
             hash), and their agents run as SYSTEM on the computers they protect."
        }
        Plane::Virtualization => {
            "Whoever administers a hypervisor or its manager controls every virtual machine it \
             runs, including virtual domain controllers, through their disks and consoles."
        }
        Plane::EntraConnect => {
            "Whoever controls an Entra Connect server can read the credentials it stores, \
             including those of its sync account."
        }
        _ => "",
    }
}

fn review_fix(what: &str) -> String {
    format!(
        "Check whether {what} manages domain controllers, CA servers or other Tier Zero systems \
         (the guide lists what to look for). If it does, add it to `tier_zero` in \
         pathwarden.toml: Pathwarden then reports who controls it. If it doesn't, accept this \
         finding as a risk with that reason."
    )
}

fn inferred(ctx: &Context, d: &Detection) -> Finding {
    let g = ctx.graph;
    let n = g.node(d.object);
    if d.role == Role::Group && d.plane == Plane::Scom {
        // SCOM agents that are Tier Zero computers, with no server to tie them to.
        return Finding::new(
            "PW-028",
            Severity::High,
            &[d.plane.key(), &d.key],
            format!("{} lists Tier Zero computers as SCOM agents", n.name),
        )
        .domain(n.domain.as_ref())
        .summary(format!(
            "{} is {}. Its members {} are SCOM agents of that server, which can run code as \
             SYSTEM on them. Pathwarden would treat the server as Tier Zero, but can't find it in \
             the collection.",
            n.name,
            d.evidence,
            names(g, &d.manages, 5)
        ))
        .remediation(
            "Find the management server (the SCOM console lists the management servers of the \
             group, and the group name contains its name). Then take the Tier Zero computers out of \
             its agent assignment, or add the server under Additional Tier Zero in Settings.",
        )
        .affect_with(
            g,
            std::iter::once((d.object, Some(d.evidence.clone())))
                .chain(d.manages.iter().map(|&m| (m, None))),
        )
        .refs(refs(d.plane));
    }
    let what = match (d.plane, d.role) {
        (Plane::Sccm, _) => "an SCCM site server".to_string(),
        (Plane::Scom, Role::Account) => "the SCOM Data Access account".to_string(),
        (Plane::Scom, _) => "a SCOM management server".to_string(),
        (Plane::Virtualization, _) => "a Virtual Machine Manager server or account".to_string(),
        (Plane::EntraConnect, Role::Group) => "the Entra Connect administrators group".to_string(),
        (Plane::EntraConnect, _) => "an Entra Connect server".to_string(),
        (p, _) => format!("a {} system", p.name()),
    };
    let configured: String;
    let unknown = match d.plane {
        Plane::Sccm => {
            " The directory shows SCCM clients only by the service principal name of SCCM \
             Remote Control (`CmRcService/`), which not every client has, so Pathwarden can't \
             tell which domain controllers or CA servers this site server manages. Their \
             registry (`HKLM\\SOFTWARE\\Microsoft\\CCM`) shows it, and collection doesn't read \
             it yet."
        }
        Plane::Scom => {
            " No Tier Zero computer is assigned to it through SCOM's AD integration, but agents \
             installed by hand don't show in the directory."
        }
        Plane::EntraConnect if d.role == Role::Group && !d.manages.is_empty() => {
            configured = format!(
                " Its Entra Connect servers ({}) are configured as not Tier Zero, so Pathwarden \
                 doesn't treat the group as Tier Zero either.",
                names(g, &d.manages, 5)
            );
            configured.as_str()
        }
        Plane::EntraConnect => {
            " No Entra Connect sync account in its domain can DCSync, so the directory shows no \
             Tier Zero credentials on the server."
        }
        _ => " The directory doesn't show which computers it manages.",
    };
    Finding::new(
        "PW-028",
        Severity::Medium,
        &[d.plane.key(), &n.id],
        format!("{} looks like {what}", n.name),
    )
    .domain(n.domain.as_ref())
    .summary(format!(
        "{} {} ({}). {}{unknown}",
        n.name,
        d.evidence,
        d.confidence.as_str(),
        why_it_matters(d.plane)
    ))
    .remediation(review_fix(&n.name))
    .affect_with(g, [(d.object, Some(d.evidence.clone()))])
    .refs(refs(d.plane))
}

/// PW-029: the ESX Admins group (CVE-2024-37085). ESXi hosts joined to the
/// domain make every member of a group with that name an administrator. One
/// finding per group with members or controllers outside Tier Zero (High
/// when the domain shows ESXi or vCenter systems, Low otherwise), and one
/// per domain that shows them but has no such group (Medium: whoever can
/// create or rename a group can make one).
pub(super) fn esx_admins(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let mut groups: BTreeMap<String, Vec<NodeIndex>> = BTreeMap::new();
    for (ix, n) in g.nodes() {
        if mgmt::is_esx_admins(n) && !n.placeholder && !n.og_created() {
            if let Some(d) = &n.domain {
                groups.entry(d.clone()).or_default().push(ix);
            }
        }
    }
    let mut domains: Vec<String> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Domain && !n.placeholder && !n.og_created())
        .map(|(_, n)| n.name.clone())
        .collect();
    domains.extend(groups.keys().cloned());
    domains.sort();
    domains.dedup();

    let mut out = Vec::new();
    for domain in domains {
        let evidence = mgmt::esxi_evidence(g, &domain);
        let seen = names(
            g,
            &evidence.iter().map(|(ix, _)| *ix).collect::<Vec<_>>(),
            5,
        );
        match groups.get(&domain) {
            None if evidence.is_empty() => {}
            None => out.push(
                Finding::new(
                    "PW-029",
                    Severity::Medium,
                    &["esx-admins", "missing", &domain],
                    format!("{domain} shows signs of ESXi or vCenter but has no ESX Admins group"),
                )
                .domain(Some(&domain))
                .summary(format!(
                    "ESXi hosts joined to the domain make a group named ESX Admins an \
                     administrator group by default (CVE-2024-37085). {domain} has no such \
                     group, so anyone who can create a group, or rename one they control, can \
                     make themselves ESXi administrators. The directory shows signs of ESXi or \
                     vCenter: {seen}."
                ))
                .remediation(
                    "Turn the automatic grant off on every ESXi host joined to the domain (the \
                     advanced setting Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd; \
                     ESXi 8.0 Update 3 turns it off by default). Until then, create an empty ESX \
                     Admins group that only Tier Zero admins can change.",
                )
                .affect_with(g, evidence.iter().map(|(ix, why)| (*ix, Some(why.clone()))))
                .refs(&[MS_ESX_ADMINS, BROADCOM_ESX_ADMINS]),
            ),
            Some(list) => {
                for &group in list {
                    if let Some(f) = esx_group(ctx, group, &evidence, &seen) {
                        out.push(f);
                    }
                }
            }
        }
    }
    out
}

fn esx_group(
    ctx: &Context,
    group: NodeIndex,
    evidence: &[(NodeIndex, String)],
    seen: &str,
) -> Option<Finding> {
    let g = ctx.graph;
    let n = g.node(group);
    let mut members: Vec<NodeIndex> = g
        .transitive_members(group)
        .into_iter()
        .filter(|&m| {
            let m = g.node(m);
            matches!(m.kind, NodeKind::User | NodeKind::Computer) && !m.tier_zero && m.is_enabled()
        })
        .collect();
    members.sort_unstable();
    members.dedup();
    let mut controllers: BTreeMap<NodeIndex, Vec<&'static str>> = BTreeMap::new();
    for e in g.inner().edges_directed(group, Direction::Incoming) {
        let kind = *e.weight();
        if super::rules::reported_as_control(kind)
            && g.traversable(kind, group)
            && g.edge_origin(e.id()).is_none()
            && !g.node(e.source()).tier_zero
        {
            let rights = controllers.entry(e.source()).or_default();
            if !rights.contains(&kind.as_str()) {
                rights.push(kind.as_str());
            }
        }
    }
    if members.is_empty() && controllers.is_empty() {
        return None;
    }
    let severity = if evidence.is_empty() {
        Severity::Low
    } else {
        Severity::High
    };
    let mut who = Vec::new();
    if !members.is_empty() {
        who.push(format!(
            "Members outside Tier Zero: {}.",
            names(g, &members, 5)
        ));
    }
    if !controllers.is_empty() {
        let list: Vec<NodeIndex> = controllers.keys().copied().collect();
        who.push(format!(
            "Principals outside Tier Zero that can change it: {}.",
            names(g, &list, 5)
        ));
    }
    let context = if evidence.is_empty() {
        "The directory shows no signs of ESXi or vCenter, so this is for review.".to_string()
    } else {
        format!("The directory shows signs of ESXi or vCenter: {seen}.")
    };
    Some(
        Finding::new(
            "PW-029",
            severity,
            &["esx-admins", &n.id],
            format!(
                "{} makes accounts outside Tier Zero ESXi administrators",
                n.name
            ),
        )
        .domain(n.domain.as_ref())
        .summary(format!(
            "ESXi hosts joined to the domain make every member of a group named ESX Admins an \
             ESXi administrator by default (CVE-2024-37085), and an ESXi administrator controls \
             every virtual machine on the host, virtual domain controllers included. {} {context}",
            who.join(" ")
        ))
        .remediation(format!(
            "Turn the automatic grant off on every ESXi host joined to the domain (the advanced \
             setting Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd; ESXi 8.0 Update 3 \
             turns it off by default), and grant ESXi administration to a group only Tier Zero \
             admins control. Then remove the members outside Tier Zero from {0} and the rights \
             others hold on it, and keep {0} empty.",
            n.name
        ))
        .affect_with(
            g,
            std::iter::once((group, Some("ESX Admins".to_string())))
                .chain(members.iter().map(|&m| (m, Some("member".to_string()))))
                .chain(
                    controllers
                        .iter()
                        .map(|(&c, rights)| (c, Some(rights.join(", ")))),
                )
                .chain(evidence.iter().map(|(ix, why)| (*ix, Some(why.clone())))),
        )
        .refs(&[MS_ESX_ADMINS, BROADCOM_ESX_ADMINS]),
    )
}

/// PW-037: the Seamless SSO account's Kerberos key is older than
/// `[rules] sso_key_age_days` (30 by default, Microsoft's recommendation).
pub(super) fn sso_key_age(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let limit = ctx.settings.sso_key_age_days;
    mgmt::sso_accounts(g)
        .into_iter()
        .filter_map(|ix| {
            let n = g.node(ix);
            if !n.is_enabled() {
                return None;
            }
            let days = ctx.days_since(n.props.pwdlastset.filter(|&t| t > 0)?);
            (days > limit).then(|| {
                let days = crate::report::num(days.max(0) as usize);
                Finding::new(
                    "PW-037",
                    Severity::Medium,
                    &[&n.id],
                    format!("The Kerberos key of {} is {days} days old", n.name),
                )
                .domain(n.domain.as_ref())
                .summary(format!(
                    "{} is the Seamless SSO account: whoever has its Kerberos key can sign in \
                     to Entra ID as any synchronized user. The key was last changed {days} days \
                     ago, and it should be rolled over at least every {limit} days (Microsoft \
                     recommends 30), so that a stolen key stops working.",
                    n.name
                ))
                .remediation(format!(
                    "Roll the Seamless SSO key over on the Entra Connect server, as Microsoft \
                     describes (the AzureADSSO PowerShell module's Update-AzureADSSOForest, run \
                     for each forest), and repeat it at least every {limit} days."
                ))
                .affect(g, [ix])
                .refs(&[MS_SSO_KEY])
            })
        })
        .collect()
}

/// PW-038: Tier Zero computers that Group Policy points at a WSUS server
/// over plain HTTP. Anyone on the network path between them and the server
/// can answer the update check with a malicious "update" (WSUSpect,
/// pywsus): Windows trusts what the server sends over HTTP. One finding per
/// domain, from the registry policy the built-in collector reads.
pub(super) fn wsus_http(ctx: &Context) -> Vec<Finding> {
    use crate::sysvol::policy::{self, Policies};
    let g = ctx.graph;
    let p = Policies::new(g);
    let probes = crate::hostprobe::views(g);
    if p.is_empty() && probes.is_empty() {
        return Vec::new();
    }
    // Per domain: (host, URL, the GPO that sets it, or `None` for the
    // host's own registry, which the probe read).
    type Http = (NodeIndex, String, Option<NodeIndex>);
    let mut by_domain: BTreeMap<String, Vec<Http>> = BTreeMap::new();
    for (ix, n) in g.nodes() {
        if n.kind != NodeKind::Computer || !n.tier_zero || !n.is_enabled() || n.placeholder {
            continue;
        }
        let mut urls: Vec<(String, Option<NodeIndex>)> = Vec::new();
        if !p.is_empty() {
            if let Some(w) = policy::wsus(g, &p, ix) {
                urls.extend(w.urls.into_iter().map(|(u, gpo)| (u, Some(gpo))));
            }
        }
        if let Some(v) = probes.get(&ix) {
            // Only a current, trusted file's URLs: another file's are a
            // review at most (PW-028), never PW-038.
            let found = v.answers(crate::hostprobe::Part::Wsus, |a| {
                a.wsus_urls().into_iter().map(str::to_string).collect()
            });
            for u in found.into_iter().filter(|(_, t)| *t).map(|(u, _)| u) {
                if !urls.iter().any(|(x, _)| x.eq_ignore_ascii_case(&u)) {
                    urls.push((u, None));
                }
            }
        }
        for (url, gpo) in urls {
            if policy::url_host(&url).is_some_and(|(_, http)| http) {
                by_domain
                    .entry(n.domain.clone().unwrap_or_default())
                    .or_default()
                    .push((ix, url, gpo));
            }
        }
    }
    by_domain
        .into_iter()
        .map(|(domain, list)| {
            let mut hosts: Vec<NodeIndex> = list.iter().map(|(h, _, _)| *h).collect();
            hosts.dedup();
            let mut urls: Vec<&str> = list.iter().map(|(_, u, _)| u.as_str()).collect();
            urls.sort_unstable();
            urls.dedup();
            let mut gpos: Vec<NodeIndex> = list.iter().filter_map(|(_, _, gpo)| *gpo).collect();
            gpos.sort_unstable();
            gpos.dedup();
            // Hosts whose own registry (the probe) names an HTTP URL.
            let mut read_on: Vec<NodeIndex> = list
                .iter()
                .filter(|(_, _, gpo)| gpo.is_none())
                .map(|(h, _, _)| *h)
                .collect();
            read_on.dedup();
            let set_by = match (gpos.is_empty(), read_on.is_empty()) {
                (false, true) => format!("as the GPO {} sets", names(g, &gpos, 5)),
                (true, _) => "as their registry shows (Tier Zero settings files)".to_string(),
                (false, false) => format!(
                    "as the GPO {} sets and the registry of {} shows",
                    names(g, &gpos, 5),
                    names(g, &read_on, 5)
                ),
            };
            let fix_where = if gpos.is_empty() {
                "the Windows Update policy of these computers".to_string()
            } else {
                names(g, &gpos, 3)
            };
            let shown = if domain.is_empty() {
                "the collection".to_string()
            } else {
                domain.clone()
            };
            let mut f = Finding::new(
                "PW-038",
                Severity::High,
                &["wsus-http", &domain],
                format!("Tier Zero computers in {shown} take updates from WSUS over HTTP"),
            )
            .domain((!domain.is_empty()).then_some(&domain))
            .summary(format!(
                "{} {} updates from {} over plain HTTP, {set_by} ({}; {}). Anyone on the \
                 network path to the WSUS server can answer the update check with a signed \
                 Microsoft tool running their command, as SYSTEM, so an attacker on that \
                 network can take over these Tier Zero computers.",
                crate::text::count(hosts.len(), "Tier Zero computer", "Tier Zero computers"),
                if hosts.len() == 1 { "takes" } else { "take" },
                urls.join(", "),
                names(g, &hosts, 8),
                Confidence::Inferred.as_str()
            ))
            .remediation(format!(
                "Set up WSUS with TLS (a certificate on the WSUS server, and SSL required on \
                 its web services). Then change the URL in {fix_where} to https:// with the TLS \
                 port (8531 by default). Until then, keep the WSUS server and the network path \
                 to it inside Tier Zero."
            ))
            .affect_with(
                g,
                hosts
                    .iter()
                    .map(|&h| (h, Some("takes updates over HTTP".to_string())))
                    .chain(
                        gpos.iter()
                            .map(|&gpo| (gpo, Some("sets the WSUS server".to_string()))),
                    ),
            )
            .refs(&[MS_WSUS_SSL, GOSECURE_WSUS]);
            f.sources = gpos
                .iter()
                .filter_map(|&gpo| g.node(gpo).domain.as_deref())
                .map(|d| crate::sysvol::Part::RegistryPol.source(d))
                .chain(
                    read_on
                        .iter()
                        .map(|&h| crate::hostprobe::source(&g.node(h).name)),
                )
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            f
        })
        .collect()
}

const VMWARE_SECURITY: &str =
    "https://www.vmware.com/docs/vmware-vsphere-8-0-security-configuration-guide";
const MS_OPENSSH: &str = "https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration";

/// Per domain: the Tier Zero computers whose probe ([`crate::hostprobe`])
/// says `f`.
fn probed_hosts(
    g: &AdGraph,
    part: crate::hostprobe::Part,
    f: impl Fn(&crate::hostprobe::Agents) -> bool,
) -> BTreeMap<String, Vec<NodeIndex>> {
    let mut out: BTreeMap<String, Vec<NodeIndex>> = BTreeMap::new();
    for (ix, v) in crate::hostprobe::views(g) {
        let n = g.node(ix);
        if n.kind != NodeKind::Computer || !n.tier_zero || n.placeholder || !v.any(part, &f) {
            continue;
        }
        out.entry(n.domain.clone().unwrap_or_default())
            .or_default()
            .push(ix);
    }
    out
}

fn probe_sources(g: &AdGraph, hosts: &[NodeIndex]) -> Vec<String> {
    hosts
        .iter()
        .map(|&h| crate::hostprobe::source(&g.node(h).name))
        .collect()
}

/// "it is"/"they are" and the like, for one host or several.
fn one_or_many(one: bool, a: &'static str, b: &'static str) -> &'static str {
    if one {
        a
    } else {
        b
    }
}

/// PW-039: Tier Zero computers that run VMware Tools are VMware virtual
/// machines. Whoever administers their ESXi hosts or vCenter controls them
/// through their disks, snapshots and consoles, and Pathwarden doesn't
/// model the hypervisor, so those administrators don't show in its paths.
/// One finding per domain, from the Tier Zero host probe.
pub(super) fn tier_zero_vms(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    probed_hosts(
        g,
        crate::hostprobe::Part::Vmware,
        crate::hostprobe::Agents::vmware_tools,
    )
    .into_iter()
    .map(|(domain, hosts)| {
        let shown = if domain.is_empty() {
            "the collection".to_string()
        } else {
            domain.clone()
        };
        let one = hosts.len() == 1;
        let mut f = Finding::new(
            "PW-039",
            Severity::Medium,
            &["vmware-guests", &domain],
            if one {
                format!("A Tier Zero computer in {shown} is a VMware virtual machine")
            } else {
                format!("Tier Zero computers in {shown} are VMware virtual machines")
            },
        )
        .domain((!domain.is_empty()).then_some(&domain))
        .summary(format!(
            "{} {} VMware Tools, so {} ({}). Whoever administers the ESXi hosts or the \
                 vCenter that run {} can copy {} disks, read {} memory and use {} consoles, \
                 which gives them the domain. Pathwarden doesn't model the hypervisor, so those \
                 administrators don't show in its attack paths.",
            crate::text::count(hosts.len(), "Tier Zero computer", "Tier Zero computers"),
            one_or_many(one, "runs", "run"),
            one_or_many(
                one,
                "it is a VMware virtual machine",
                "they are VMware virtual machines"
            ),
            names(g, &hosts, 8),
            one_or_many(one, "it", "them"),
            one_or_many(one, "its", "their"),
            one_or_many(one, "its", "their"),
            one_or_many(one, "its", "their"),
        ))
        .remediation(
            "Treat the ESXi hosts and the vCenter that run these virtual machines as Tier \
                 Zero: allow only Tier Zero admins to administer them, keep their management \
                 network apart, and turn off the ESX Admins automatic grant (PW-029). Encrypt \
                 the virtual machines, so a copied disk can't be read elsewhere. Then accept \
                 this finding as a risk with that reason.",
        )
        .affect_with(
            g,
            hosts
                .iter()
                .map(|&h| (h, Some("runs VMware Tools".to_string()))),
        )
        .refs(&[MS_ACCESS_MODEL, VMWARE_SECURITY]);
        f.sources = probe_sources(g, &hosts);
        f
    })
    .collect()
}

/// The sentence PW-023 adds when the Tier Zero host probe finds the
/// OpenSSH server on domain controllers of the finding's domain: its own
/// `sshd_config`, not the built-in logon groups, decides who may log on
/// over SSH, and Pathwarden doesn't read it. A note only: the finding
/// still rests on the logon rights, so its fingerprint and what holds it
/// don't change.
pub(super) fn ssh_note(ctx: &Context, findings: &mut [Finding]) {
    let g = ctx.graph;
    let by_domain = probed_hosts(
        g,
        crate::hostprobe::Part::Sshd,
        crate::hostprobe::Agents::sshd,
    );
    if by_domain.is_empty() {
        return;
    }
    for f in findings.iter_mut().filter(|f| f.rule == "PW-023") {
        let Some(hosts) = f.domain.as_ref().and_then(|d| by_domain.get(d)) else {
            continue;
        };
        let dcs: Vec<NodeIndex> = hosts.iter().copied().filter(|&h| g.node(h).is_dc).collect();
        if dcs.is_empty() {
            continue;
        }
        f.summary.push_str(&format!(
            " Note: {} also {} an SSH server (sshd), as {} Tier Zero settings {} shows. Who may \
             log on over SSH is set in its sshd_config, not by these groups, and Pathwarden \
             doesn't read that file.",
            names(g, &dcs, 5),
            one_or_many(dcs.len() == 1, "runs", "run"),
            one_or_many(dcs.len() == 1, "its", "their"),
            one_or_many(dcs.len() == 1, "file", "files"),
        ));
        if !f.references.contains(&MS_OPENSSH) {
            f.references.push(MS_OPENSSH);
        }
    }
}
