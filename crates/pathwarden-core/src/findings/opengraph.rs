//! Rules that a mapping pack names for an edge kind (`rule = "PW-0xx"`),
//! instead of the generic PW-030:
//!
//! - PW-033: a Tier Zero account's password is stored on hosts outside
//!   Tier Zero (TaskHound: a scheduled task or service that stores it; the
//!   built-in collector: a service or a scheduled task,
//!   `HasStoredCredential`). One finding per account, whatever the number
//!   of tasks, services, hosts and sources.
//! - PW-034: a SQL Server instance runs as a Tier Zero account
//!   (MSSQLHound's service account, as Pathwarden's derived
//!   `MSSQL_RunsAs`), so whoever administers the instance controls Tier
//!   Zero. One finding per instance and account.
//! - PW-035: a Tier Zero host is an SCCM client (ConfigManBearPig's
//!   `SCCM_SameHostAs`) that principals outside Tier Zero control through
//!   SCCM. One finding per host.
//!
//! Each rests on another collector's data, so its findings carry that
//! source, and are held rather than resolved when the source is missing or
//! has no coverage (see `docs/opengraph.md`).

use std::collections::{BTreeMap, HashSet, VecDeque};

use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use super::{Context, Finding, Severity};
use crate::graph::AdGraph;
use crate::model::{EdgeKind, NodeKind};
use crate::storedcreds::Via;

const MS_GMSA: &str = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview";
const MS_SQL_SERVICE_ACCOUNTS: &str = "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions";
const MS_ACCESS_MODEL: &str = "https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model";
const MISCONFIGURATION_MANAGER: &str = "https://github.com/subat0mik/Misconfiguration-Manager";

/// Traversable edges a trusted pack reports through `rule`.
fn edges_of<'a>(g: &'a AdGraph, rule: &'a str) -> impl Iterator<Item = EdgeIndex> + 'a {
    g.inner().edge_references().filter_map(move |e| {
        let sem = g.edge_sem(*e.weight())?;
        (sem.traversable && sem.rule.as_deref() == Some(rule) && g.edge_origin(e.id()).is_some())
            .then_some(e.id())
    })
}

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

/// AD principals outside Tier Zero that reach `target` through traversable
/// edges without passing through Tier Zero, nearest first (at most
/// `limit`).
fn controllers(g: &AdGraph, target: NodeIndex, limit: usize) -> Vec<NodeIndex> {
    let mut seen = HashSet::from([target]);
    let mut queue = VecDeque::from([target]);
    let mut out = Vec::new();
    while let Some(v) = queue.pop_front() {
        for e in g.inner().edges_directed(v, Direction::Incoming) {
            let u = e.source();
            if !g.traversable(*e.weight(), v) || !seen.insert(u) {
                continue;
            }
            let n = g.node(u);
            if n.tier_zero {
                continue;
            }
            if !n.kind.is_external() && !n.placeholder {
                out.push(u);
                if out.len() >= limit {
                    return out;
                }
            }
            queue.push_back(u);
        }
    }
    out
}

/// The fix text of each edge, without repeats, at most three.
fn fixes(g: &AdGraph, edges: &[EdgeIndex]) -> String {
    let mut out: Vec<String> = Vec::new();
    for &e in edges {
        let text = crate::remediation::fix_for(g, e);
        if !out.contains(&text) && out.len() < 3 {
            out.push(text);
        }
    }
    out.join(" ")
}

fn source_of(g: &AdGraph, edges: &[EdgeIndex]) -> String {
    edges
        .iter()
        .find_map(|&e| g.edge_source_name(e))
        .unwrap_or("OpenGraph")
        .to_string()
}

/// What stores one Tier Zero account's password, from either source.
#[derive(Default)]
struct Stored {
    /// TaskHound's run-as edges (task or service → account).
    runs_as: Vec<EdgeIndex>,
    /// The edges that store it: TaskHound's host → task or service, the
    /// built-in collector's host → account (`HasStoredCredential`).
    stores: Vec<EdgeIndex>,
    hosts: Vec<NodeIndex>,
    /// What each host stores it in, for the affected objects.
    details: Vec<(NodeIndex, Option<String>)>,
    /// The first path: a store, then its run-as edge if any.
    path: Vec<EdgeIndex>,
    /// Tasks and services, counted.
    things: usize,
    /// TaskHound's source name, when it reported the account.
    taskhound: Option<String>,
    /// The built-in collector reported it: in a service, in a scheduled
    /// task.
    native: bool,
    native_services: bool,
    native_tasks: bool,
}

/// PW-033: a Tier Zero account whose password a task or service stores on
/// hosts outside Tier Zero. TaskHound's data and the built-in collector's
/// (services read from the hosts' registry) give one finding per account.
pub(super) fn stored_credentials(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    if !g.has_og_edges() {
        return Vec::new();
    }
    let mut by_account: BTreeMap<NodeIndex, Stored> = BTreeMap::new();
    for e in edges_of(g, "PW-033") {
        let (holder, account) = g.inner().edge_endpoints(e).expect("edge of this graph");
        if !g.node(account).tier_zero || g.node(holder).tier_zero {
            continue;
        }
        // The hosts that store it: who reaches the task or service.
        let stores: Vec<(EdgeIndex, NodeIndex)> = g
            .inner()
            .edges_directed(holder, Direction::Incoming)
            .filter(|i| g.traversable(*i.weight(), holder) && !g.node(i.source()).tier_zero)
            .map(|i| (i.id(), i.source()))
            .collect();
        if stores.is_empty() {
            continue;
        }
        let entry = by_account.entry(account).or_default();
        entry.runs_as.push(e);
        entry.things += 1;
        if entry.taskhound.is_none() {
            entry.taskhound = Some(source_of(g, &[e]));
        }
        if entry.path.is_empty() {
            entry.path = vec![stores[0].0, e];
        }
        let kind = match g.node(holder).kind {
            NodeKind::External(k) => g
                .kind_table()
                .node(k)
                .and_then(|s| s.label.clone())
                .unwrap_or_else(|| crate::kinds::name(k).to_string()),
            k => k.as_str().to_string(),
        };
        entry.details.push((
            holder,
            Some(format!("{kind} on {}", g.node(stores[0].1).name)),
        ));
        for (s, host) in stores {
            if !entry.stores.contains(&s) {
                entry.stores.push(s);
            }
            if !entry.hosts.contains(&host) {
                entry.hosts.push(host);
            }
        }
    }
    for e in g.inner().edge_references() {
        if *e.weight() != EdgeKind::HasStoredCredential {
            continue;
        }
        let (host, account) = (e.source(), e.target());
        if !g.node(account).tier_zero || g.node(host).tier_zero {
            continue;
        }
        let vias = g.stored_via(e.id());
        let entry = by_account.entry(account).or_default();
        entry.native = true;
        entry.native_services |= vias.is_empty() || vias.iter().any(|v| v.via == Via::Service);
        entry.native_tasks |= vias.iter().any(|v| v.via == Via::Task);
        entry.things += vias.len().max(1);
        entry.stores.push(e.id());
        if entry.path.is_empty() {
            entry.path = vec![e.id()];
        }
        if !entry.hosts.contains(&host) {
            entry.hosts.push(host);
        }
        // "Service SqlAgent; scheduled tasks \Sync, \Backup (disabled)".
        let mut parts: Vec<String> = Vec::new();
        for (via, one, many) in [
            (Via::Service, "Service", "Services"),
            (Via::Task, "Scheduled task", "Scheduled tasks"),
        ] {
            let of: Vec<_> = vias.iter().filter(|v| v.via == via).collect();
            if of.is_empty() {
                continue;
            }
            let names: Vec<String> = of
                .iter()
                .take(5)
                .map(|v| {
                    if v.disabled {
                        format!("{} (disabled)", v.name)
                    } else {
                        v.name.clone()
                    }
                })
                .collect();
            let mut list = names.join(", ");
            if of.len() > names.len() {
                list.push_str(", ...");
            }
            let label = if of.len() == 1 { one } else { many };
            parts.push(if parts.is_empty() {
                format!("{label} {list}")
            } else {
                format!("{} {list}", label.to_lowercase())
            });
        }
        entry.details.push((
            host,
            Some(format!("{}, as reported by the computer", parts.join("; "))),
        ));
    }
    by_account
        .into_iter()
        .map(|(account, st)| {
            let a = g.node(account);
            let sources: Vec<&str> = st
                .taskhound
                .as_deref()
                .into_iter()
                .chain(st.native.then_some("the built-in collector"))
                .collect();
            let said_by = capitalized(&sources.join(" and "));
            let what = match (st.taskhound.is_some(), st.native_services, st.native_tasks) {
                (false, true, false) => crate::text::count(st.things, "service", "services"),
                (false, false, true) => {
                    crate::text::count(st.things, "scheduled task", "scheduled tasks")
                }
                _ => crate::text::count(
                    st.things,
                    "scheduled task or service",
                    "scheduled tasks or services",
                ),
            };
            // What the built-in collector read on the hosts.
            let config = match (st.native_services, st.native_tasks) {
                (true, true) => "service and scheduled task configuration",
                (false, true) => "scheduled task configuration",
                _ => "service configuration",
            };
            let confirm = match (&st.taskhound, st.native) {
                (Some(th), false) => format!(
                    " This rests on {th} data, not on the directory: confirm it on the computers."
                ),
                (Some(th), true) => format!(
                    " This rests on {th} data and the computers' {config} as read, not on the \
                     directory: confirm it on the computers."
                ),
                (None, _) => {
                    format!(" This rests on the computers' {config} as read, not on the directory.")
                }
            };
            let again = match (&st.taskhound, st.native) {
                (Some(th), false) => format!(
                    "Then collect again with {th} (with its coverage file) to confirm the change."
                ),
                (None, _) => "Then run a Full collection again to confirm the change.".to_string(),
                (Some(th), true) => format!(
                    "Then run a Full collection again, and {th} with its coverage file, to \
                     confirm the change."
                ),
            };
            let mut affected: Vec<(NodeIndex, Option<String>)> = vec![(account, None)];
            for &h in &st.hosts {
                if !st.details.iter().any(|(d, _)| *d == h) {
                    affected.push((h, None));
                }
            }
            affected.extend(st.details.iter().cloned());
            let host0 = g
                .inner()
                .edge_endpoints(st.path[0])
                .map_or(st.hosts[0], |(h, _)| h);
            // "1 service that runs as ... and stores", "2 services that run".
            let (run, store) = if st.things == 1 {
                ("runs", "stores")
            } else {
                ("run", "store")
            };
            Finding::new(
                "PW-033",
                Severity::High,
                &[&a.id],
                format!(
                    "Tier Zero account {}'s password is stored on {} outside Tier Zero",
                    a.name,
                    if st.hosts.len() == 1 {
                        g.node(st.hosts[0]).name.clone()
                    } else {
                        format!("{} computers", st.hosts.len())
                    }
                ),
            )
            .domain(a.domain.as_ref())
            .floor(Severity::High)
            .summary(format!(
                "{said_by} reports {what} that {run} as {} ({}) and {store} its password on {}. \
                 Windows keeps such a password where any administrator of the computer can read it \
                 (the task credential store, the LSA secrets), so whoever administers those hosts \
                 controls {}.{confirm}",
                a.name,
                a.tier_zero_reason.as_deref().unwrap_or("Tier Zero"),
                names(g, &st.hosts, 5),
                a.name
            ))
            .remediation(format!("{} {again}", fixes(g, &st.stores)))
            .affect_with(g, affected)
            .entry(st.hosts.iter().copied())
            .hits([account])
            .path(Some(crate::analysis::render_path(g, host0, &st.path)))
            .evidence(st.runs_as.iter().chain(st.stores.iter()).copied())
            .refs(&[MS_GMSA])
        })
        .collect()
}

/// `s` with its first letter in upper case.
fn capitalized(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// PW-034: a SQL Server instance that runs as a Tier Zero account.
pub(super) fn sql_runs_as_tier_zero(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    if !g.has_og_edges() {
        return Vec::new();
    }
    let mut pairs: BTreeMap<(NodeIndex, NodeIndex), Vec<EdgeIndex>> = BTreeMap::new();
    for e in edges_of(g, "PW-034") {
        let (server, account) = g.inner().edge_endpoints(e).expect("edge of this graph");
        if g.node(server).tier_zero || !g.node(account).tier_zero {
            continue;
        }
        pairs.entry((server, account)).or_default().push(e);
    }
    pairs
        .into_iter()
        .filter_map(|((server, account), edges)| {
            let admins = controllers(g, server, 50);
            if admins.is_empty() {
                return None;
            }
            let (s, a) = (g.node(server), g.node(account));
            let source = source_of(g, &edges);
            let hosts: Vec<NodeIndex> = g
                .inner()
                .edges_directed(server, Direction::Incoming)
                .filter(|i| i.weight().as_str() == "MSSQL_HostFor")
                .map(|i| i.source())
                .collect();
            let host_note = if hosts.is_empty() {
                String::new()
            } else {
                format!(
                    " The local administrators of {} control the instance too.",
                    names(g, &hosts, 3)
                )
            };
            Some(
                Finding::new(
                    "PW-034",
                    Severity::High,
                    &[&s.id, &a.id],
                    format!("SQL Server {} runs as Tier Zero account {}", s.name, a.name),
                )
                .domain(a.domain.as_ref())
                .floor(Severity::High)
                .summary(format!(
                    "{source} reports that the SQL Server instance {} runs as {} ({}). Whoever \
                     controls the instance (a sysadmin login, xp_cmdshell, a SQL Agent job) runs code as \
                     {} and can use it on the network, so the instance is effectively Tier Zero. \
                     Principals outside Tier Zero that control it include {}.{host_note} This rests on \
                     {source} data: confirm the service account in SQL Server Configuration Manager.",
                    s.name,
                    a.name,
                    a.tier_zero_reason.as_deref().unwrap_or("Tier Zero"),
                    a.name,
                    names(g, &admins, 5),
                ))
                .remediation(format!(
                    "{} Until then, treat {} as Tier Zero: remove sysadmin (and CONTROL SERVER, \
                     IMPERSONATE ANY LOGIN) from logins outside Tier Zero, and limit the local \
                     administrators of its host. Then collect again with {source} to confirm.",
                    fixes(g, &edges),
                    s.name
                ))
                .affect(g, [server, account].into_iter().chain(hosts.iter().copied()))
                .entry([server])
                .hits([account])
                .path(Some(ctx.edge_path(server, edges[0])))
                .evidence(edges)
                .refs(&[MS_SQL_SERVICE_ACCOUNTS, MS_GMSA]),
            )
        })
        .collect()
}

/// PW-035: a Tier Zero host that principals outside Tier Zero control
/// through SCCM.
pub(super) fn sccm_controls_tier_zero(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    if !g.has_og_edges() {
        return Vec::new();
    }
    let mut by_host: BTreeMap<NodeIndex, Vec<EdgeIndex>> = BTreeMap::new();
    for e in edges_of(g, "PW-035") {
        let (device, host) = g.inner().edge_endpoints(e).expect("edge of this graph");
        if g.node(device).tier_zero || !g.node(host).tier_zero {
            continue;
        }
        by_host.entry(host).or_default().push(e);
    }
    by_host
        .into_iter()
        .filter_map(|(host, edges)| {
            let devices: Vec<NodeIndex> = edges
                .iter()
                .filter_map(|&e| g.inner().edge_endpoints(e).map(|(d, _)| d))
                .collect();
            let mut admins: Vec<NodeIndex> = Vec::new();
            for &d in &devices {
                for a in controllers(g, d, 50) {
                    if !admins.contains(&a) {
                        admins.push(a);
                    }
                }
            }
            if admins.is_empty() {
                return None;
            }
            let h = g.node(host);
            let source = source_of(g, &edges);
            let sites: Vec<NodeIndex> = devices
                .iter()
                .flat_map(|&d| g.inner().edges_directed(d, Direction::Incoming))
                .filter(|i| i.weight().as_str() == "SCCM_HasClient")
                .map(|i| i.source())
                .collect();
            let site_note = if sites.is_empty() {
                String::new()
            } else {
                format!(" It is a client of the site {}.", names(g, &sites, 3))
            };
            // The administrators' own grants, as fixes (their mapping to an
            // SCCM administrative user), after taking the host out.
            let upstream: Vec<EdgeIndex> = admins
                .iter()
                .flat_map(|&a| g.inner().edges_directed(a, Direction::Outgoing))
                .filter(|o| {
                    o.weight().as_str() == "SCCM_IsMappedTo"
                        && g.traversable(*o.weight(), o.target())
                })
                .map(|o| o.id())
                .collect();
            let mut fix = fixes(g, &edges);
            if !upstream.is_empty() {
                fix = format!(
                    "{fix} Otherwise remove the rights of the SCCM administrators outside Tier Zero over \
                     it: {}",
                    fixes(g, &upstream)
                );
            }
            Some(
                Finding::new(
                    "PW-035",
                    Severity::High,
                    &[&h.id],
                    format!("Tier Zero host {} is managed by SCCM from outside Tier Zero", h.name),
                )
                .domain(h.domain.as_ref())
                .floor(Severity::High)
                .summary(format!(
                    "{source} reports that {} ({}) is an SCCM client.{site_note} Whoever administers \
                     SCCM over it (a Full or Application Administrator of a collection that holds it, an \
                     administrator of the whole site, or whoever controls the site database) can deploy \
                     code that runs on it as SYSTEM. Principals outside Tier Zero that can include {}. \
                     This rests on {source} data: confirm it in the Configuration Manager console.",
                    h.name,
                    h.tier_zero_reason.as_deref().unwrap_or("Tier Zero"),
                    names(g, &admins, 5),
                ))
                .remediation(format!(
                    "{fix} Then collect again with {source} to confirm the change."
                ))
                .affect(g, std::iter::once(host).chain(devices.iter().copied()))
                .entry(devices.iter().copied())
                .hits([host])
                .path(Some(ctx.edge_path(devices[0], edges[0])))
                .evidence(edges.iter().copied().chain(upstream))
                .refs(&[MISCONFIGURATION_MANAGER, MS_ACCESS_MODEL]),
            )
        })
        .collect()
}
