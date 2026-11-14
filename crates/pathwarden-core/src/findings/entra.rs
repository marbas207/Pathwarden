//! Entra ID rules (AzureHound data, see [`crate::entra`]):
//!
//! - PW-031: a principal outside Tier Zero controls an Entra Tier Zero
//!   object (a Global Administrator, a Tier Zero role, a service principal
//!   holding one, the tenant). The Entra counterpart of PW-003. Includes the
//!   crossing from AD: an on-premises account synchronized to an Entra
//!   Tier Zero account.
//! - PW-032: the crossing from Entra ID to on-premises: an Entra object
//!   that Entra principals control leads to an AD object that is Tier Zero
//!   or has a path to it (password writeback to a synchronized account, an
//!   Intune-managed hybrid-joined computer).
//!
//! Both rest on AzureHound data, so their findings carry it as a source and
//! the tenant as their coverage unit: a tenant that wasn't collected holds
//! them ("can't tell").

use std::collections::BTreeMap;

use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use super::{Context, Finding, Severity};
use crate::entra;
use crate::graph::AdGraph;
use crate::model::EdgeKind;

const BH_EDGES: &str = "https://bloodhound.specterops.io/resources/edges/az-reset-password";
const MS_PRIVILEGED: &str =
    "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions";
const MS_HYBRID_ADMINS: &str =
    "https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks";
const BH_SYNCED: &str = "https://bloodhound.specterops.io/resources/edges/synced-to-ad-user";

fn rule_of(g: &AdGraph, e: EdgeIndex) -> Option<&str> {
    let sem = g.edge_sem(g.inner()[e])?;
    (sem.traversable && g.edge_origin(e).is_some())
        .then_some(sem.rule.as_deref())
        .flatten()
}

fn kind_name(k: EdgeKind) -> &'static str {
    k.as_str()
}

/// Holders of an Entra role object (active or eligible), for messages.
fn role_holders(g: &AdGraph, role: NodeIndex) -> Vec<NodeIndex> {
    g.inner()
        .edges_directed(role, Direction::Incoming)
        .filter(|e| matches!(kind_name(*e.weight()), "AZHasRole" | "AZRoleEligible"))
        .map(|e| e.source())
        .collect()
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

fn rights_of(g: &AdGraph, edges: &[EdgeIndex]) -> String {
    let mut kinds: Vec<&str> = edges.iter().map(|&e| kind_name(g.inner()[e])).collect();
    kinds.sort_unstable();
    kinds.dedup();
    kinds.join(", ")
}

/// "AZUser ALICE@..." style: the kind label of an Entra object.
fn label(g: &AdGraph, ix: NodeIndex) -> String {
    let n = g.node(ix);
    let label = match n.kind {
        crate::model::NodeKind::External(k) => g
            .kind_table()
            .node(k)
            .and_then(|s| s.label.clone())
            .unwrap_or_else(|| n.kind.as_str().to_string()),
        k => k.as_str().to_string(),
    };
    format!("{label} {}", n.name)
}

/// "A, B and C".
fn list_words(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The fix for `AZMG...` edges from the service principal `u`: the
/// Microsoft Graph application permissions it is granted that give them.
fn graph_grants(g: &AdGraph, u: NodeIndex, edges: &[EdgeIndex]) -> Option<String> {
    if edges.is_empty() || entra::az_kind(g.node(u)) != Some("AZServicePrincipal") {
        return None;
    }
    let held = entra::granted(g, u);
    let mut names: Vec<&str> = Vec::new();
    for &e in edges {
        let target = g
            .inner()
            .edge_endpoints(e)
            .and_then(|(_, b)| entra::az_kind(g.node(b)));
        for p in entra::permissions_for(kind_name(g.inner()[e]), target) {
            if held.contains(&p) && !names.contains(&p.name) {
                names.push(p.name);
            }
        }
    }
    if names.is_empty() {
        return None;
    }
    Some(format!(
        "Remove the Microsoft Graph application {} {} from {} (its app role assignments on Microsoft Graph), \
         or grant a narrower one.",
        if names.len() == 1 {
            "permission"
        } else {
            "permissions"
        },
        list_words(&names),
        g.node(u).name
    ))
}

/// When `v` is Tier Zero because of a Microsoft Graph permission (it holds
/// one, or its service principal does): the other way out, removing it.
fn tier_zero_grants(g: &AdGraph, v: NodeIndex) -> Option<String> {
    let src = entra::source_id(g);
    let sp = match entra::az_kind(g.node(v))? {
        "AZServicePrincipal" => v,
        "AZApp" => g
            .inner()
            .edges_directed(v, Direction::Outgoing)
            .find(|e| {
                kind_name(*e.weight()) == "AZRunsAs"
                    && g.edge_origin(e.id()).is_some_and(|o| Some(o.source) == src)
            })?
            .target(),
        _ => return None,
    };
    let held = entra::granted(g, sp);
    let names: Vec<&str> = entra::TIER_ZERO_PERMISSIONS
        .iter()
        .filter(|p| held.contains(p))
        .map(|p| p.name)
        .collect();
    if names.is_empty() {
        return None;
    }
    let sp_name = &g.node(sp).name;
    Some(format!(
        "Or remove the Microsoft Graph application {} {} from {sp_name}, which {} it Tier Zero.",
        if names.len() == 1 {
            "permission"
        } else {
            "permissions"
        },
        list_words(&names),
        if names.len() == 1 { "makes" } else { "make" }
    ))
}

/// PW-031.
pub(super) fn entra_control(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    if entra::source_id(g).is_none() {
        return Vec::new();
    }
    // A role is a foothold only if somebody holds it (or may activate it).
    let foothold = |u: NodeIndex| {
        entra::az_kind(g.node(u)) != Some("AZRole") || !role_holders(g, u).is_empty()
    };
    let mut pairs: BTreeMap<(NodeIndex, NodeIndex), Vec<EdgeIndex>> = BTreeMap::new();
    for e in g.inner().edge_references() {
        if rule_of(g, e.id()) != Some("PW-031") {
            continue;
        }
        let (u, v) = (e.source(), e.target());
        let (from, to) = (g.node(u), g.node(v));
        if from.tier_zero || !to.tier_zero || !entra::is_entra(to) || !foothold(u) {
            continue;
        }
        pairs.entry((u, v)).or_default().push(e.id());
    }
    // An application and the service principal it runs as are one Tier
    // Zero identity: control of both from one principal is one finding,
    // on the application (its credentials sign in as the principal).
    let src = entra::source_id(g);
    let runs_as = |e: &petgraph::graph::EdgeReference<'_, EdgeKind>| {
        kind_name(*e.weight()) == "AZRunsAs"
            && g.edge_origin(e.id()).is_some_and(|o| Some(o.source) == src)
    };
    let mut also: BTreeMap<(NodeIndex, NodeIndex), Vec<NodeIndex>> = BTreeMap::new();
    let keys: Vec<(NodeIndex, NodeIndex)> = pairs.keys().copied().collect();
    for (u, sp) in keys {
        if entra::az_kind(g.node(sp)) != Some("AZServicePrincipal") {
            continue;
        }
        let app = g
            .inner()
            .edges_directed(sp, Direction::Incoming)
            .filter(|i| runs_as(i))
            .map(|i| i.source())
            .find(|&a| entra::az_kind(g.node(a)) == Some("AZApp") && pairs.contains_key(&(u, a)));
        if let Some(app) = app {
            if let Some(edges) = pairs.remove(&(u, sp)) {
                pairs.entry((u, app)).or_default().extend(edges);
                also.entry((u, app)).or_default().push(sp);
            }
        }
    }
    pairs
        .into_iter()
        .map(|((u, v), edges)| {
            let sps = also.remove(&(u, v)).unwrap_or_default();
            let (from, to) = (g.node(u), g.node(v));
            let rights = rights_of(g, &edges);
            let synced = edges
                .iter()
                .any(|&e| kind_name(g.inner()[e]) == "SyncedToEntraUser");
            let role = entra::az_kind(from) == Some("AZRole");
            let title = if synced {
                format!(
                    "On-premises account {} is synchronized to Entra Tier Zero account {}",
                    from.name, to.name
                )
            } else if role {
                format!(
                    "Entra role {} can take over Tier Zero {}",
                    from.name,
                    label(g, v)
                )
            } else if entra::is_entra(from) {
                // Kind labels: an application and its service principal
                // usually share a name.
                format!(
                    "{} can take over Tier Zero {}",
                    label(g, u),
                    label(g, v)
                )
            } else {
                format!("{} can take over Entra Tier Zero {}", from.name, label(g, v))
            };
            let who = if role {
                let holders = role_holders(g, u);
                format!(
                    "Every holder of the Entra role {} ({}: {})",
                    from.name,
                    holders.len(),
                    names(g, &holders, 5)
                )
            } else if entra::is_entra(from) {
                label(g, u)
            } else {
                format!("{} (Active Directory)", from.name)
            };
            let federated = edges
                .iter()
                .any(|&e| kind_name(g.inner()[e]) == "AZAuthenticatesTo");
            let how = if federated {
                let p = |k: &str| {
                    from.ext
                        .as_ref()
                        .and_then(|x| x.prop(k))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                        .to_string()
                };
                format!(
                    " A federated identity credential on it trusts tokens that {} issues for the subject {}: \
                     whoever can get one (push to the repository, run as the workload) signs in as the \
                     application, with no secret.",
                    p("issuer"),
                    p("subject"),
                )
            } else if synced {
                " The accounts share a password: whoever resets or learns the on-premises password \
                 signs in to Entra ID as it (password hash sync, pass-through authentication or \
                 federation). MFA or Conditional Access may slow an attacker down; they don't \
                 change who is entitled to the account."
                    .to_string()
            } else {
                String::new()
            };
            // A relationship the plan can't cut (a role's ability) is fixed
            // where the access comes from: the role's assignments.
            // Microsoft Graph permissions are named exactly (the pack's
            // fix text can only list the ones that may give the edge).
            let (graph, rest): (Vec<EdgeIndex>, Vec<EdgeIndex>) = edges
                .iter()
                .partition(|&&e| kind_name(g.inner()[e]).starts_with("AZMG"));
            let grants = graph_grants(g, u, &graph);
            let mut fix = match &grants {
                Some(_) if rest.is_empty() => String::new(),
                Some(_) => crate::remediation::fix_for_edges(g, &rest),
                None => crate::remediation::fix_for_edges(g, &edges),
            };
            let uncuttable = edges
                .iter()
                .all(|&e| g.edge_sem(g.inner()[e]).is_some_and(|s| !s.cuttable));
            if uncuttable && entra::is_entra(from) {
                let mut upstream: Vec<String> = Vec::new();
                let mut more = 0usize;
                for i in g.inner().edges_directed(u, Direction::Incoming) {
                    let cuttable = g
                        .edge_sem(*i.weight())
                        .is_some_and(|s| s.traversable && s.cuttable);
                    if !cuttable || g.node(i.source()).tier_zero {
                        continue;
                    }
                    let text = crate::remediation::fix_for(g, i.id());
                    if upstream.contains(&text) {
                        continue;
                    }
                    if upstream.len() < 3 {
                        upstream.push(text);
                    } else {
                        more += 1;
                    }
                }
                if !upstream.is_empty() {
                    if more > 0 {
                        upstream.push(format!("({more} more like this.)"));
                    }
                    fix = format!("{} Otherwise: {fix}", upstream.join(" "));
                }
            }
            if let Some(grants) = grants {
                fix = if fix.is_empty() {
                    grants
                } else {
                    format!("{grants} {fix}")
                };
            }
            if let Some(also) = tier_zero_grants(g, v) {
                fix = format!("{fix} {also}");
            }
            Finding::new("PW-031", Severity::High, &[&from.id, &to.id], title)
                .domain(from.domain.as_ref())
                .floor(Severity::High)
                .summary(format!(
                    "{who} is outside Tier Zero but has {rights} on {} ({}). Whoever controls {} \
                     controls {}, and with it the Entra tenant.{how} This rests on AzureHound data: \
                     confirm it in the Entra admin center.",
                    if sps.is_empty() {
                        label(g, v)
                    } else {
                        format!("{} and the service principal it runs as", label(g, v))
                    },
                    to.tier_zero_reason.as_deref().unwrap_or("Tier Zero"),
                    from.name,
                    to.name
                ))
                .remediation(format!(
                    "{fix} Then collect again with AzureHound to confirm the change."
                ))
                .affect(g, [u, v].into_iter().chain(sps.iter().copied()))
                .entry([u])
                .hits([v])
                .path(Some(ctx.edge_path(u, edges[0])))
                .evidence(edges)
                .refs(&[MS_PRIVILEGED, BH_EDGES])
        })
        .collect()
}

/// PW-032.
pub(super) fn entra_to_on_premises(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    if entra::source_id(g).is_none() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for e in g.inner().edge_references() {
        if rule_of(g, e.id()) != Some("PW-032") {
            continue;
        }
        let (u, v) = (e.source(), e.target());
        let (from, to) = (g.node(u), g.node(v));
        if from.tier_zero || !(to.tier_zero || ctx.reaches_tier_zero(v)) {
            continue;
        }
        // Who controls the Entra end from the Entra side. Without anyone,
        // this is not a path from Entra ID.
        let mut controllers: Vec<(NodeIndex, EdgeIndex)> = g
            .inner()
            .edges_directed(u, Direction::Incoming)
            .filter(|i| entra::is_entra(g.node(i.source())) && g.traversable(*i.weight(), u))
            .map(|i| (i.source(), i.id()))
            .collect();
        if controllers.is_empty() {
            continue;
        }
        // Roles first: they name the administrators involved.
        controllers.sort_by_key(|(c, _)| (entra::az_kind(g.node(*c)) != Some("AZRole"), *c));
        let (c0, e0) = controllers[0];
        let mut edges = vec![e0, e.id()];
        if !to.tier_zero {
            if let Some(rest) = ctx.to_tier_zero.path(v) {
                edges.extend(rest);
            }
        }
        let path = crate::analysis::render_path(g, c0, &edges);
        let by: Vec<String> = controllers
            .iter()
            .take(3)
            .map(|&(c, i)| format!("{} ({})", g.node(c).name, kind_name(g.inner()[i])))
            .collect();
        let more = controllers.len().saturating_sub(3);
        let kind = kind_name(g.inner()[e.id()]);
        // The Entra end, labelled: a synchronized copy has the AD name.
        let from_l = label(g, u);
        let (title, floor) = if to.tier_zero {
            (
                format!(
                    "Entra ID controls on-premises Tier Zero {} through {}",
                    to.name, from_l
                ),
                Severity::High,
            )
        } else {
            (
                format!(
                    "Entra ID controls {} through {}, and {} has a path to Tier Zero",
                    to.name, from_l, to.name
                ),
                Severity::Medium,
            )
        };
        let how = match kind {
            "SyncedToADUser" => format!(
                "{} is the Entra copy of {}, and the Entra Connect connector account can reset {}'s \
                 password: with password writeback, a password reset in Entra ID sets it on-premises.",
                from_l, to.name, to.name
            ),
            "SyncedToADComputer" => format!(
                "{} is the hybrid-joined, Intune-managed Entra device of {}: an Intune \
                 administrator can run scripts on it as SYSTEM.",
                from_l, to.name
            ),
            _ => format!("{} leads to {} ({kind}).", from_l, to.name),
        };
        let more_text = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        out.push(
            Finding::new("PW-032", Severity::High, &[&from.id, &to.id], title)
                .domain(to.domain.as_ref())
                .floor(floor)
                .summary(format!(
                    "{how} {} can be controlled from Entra ID by {}{more_text}, so a cloud \
                     administrator (or whoever compromises one) reaches {} ({}). This rests on \
                     AzureHound data and on assumptions listed in docs/entra.md: confirm it in the lab \
                     or the Entra admin center.",
                    from_l,
                    by.join(", "),
                    to.name,
                    to.tier_zero_reason
                        .as_deref()
                        .unwrap_or("has a path to Tier Zero")
                ))
                .remediation(format!(
                    "{} Then collect again with AzureHound to confirm the change.",
                    crate::remediation::fix_for(g, e.id())
                ))
                .affect(g, [u, v])
                .entry([u])
                .hits(if to.tier_zero {
                    Some(v)
                } else {
                    ctx.tier_zero_end(v)
                })
                .path(Some(path))
                .evidence([e.id(), e0])
                .refs(&[MS_HYBRID_ADMINS, BH_SYNCED]),
        );
    }
    out
}
