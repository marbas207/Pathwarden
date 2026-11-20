use std::collections::{BTreeMap, HashSet};

use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use super::{Context, Finding, RuleInfo, Severity};
use crate::graph::AdGraph;
use crate::model::{EdgeKind, Node, NodeKind};
use crate::remediation::{edge_fix, edge_fix_in, sdprop_origin, Keepers};
use crate::sid;

const ATTACK_DCSYNC: &str = "https://attack.mitre.org/techniques/T1003/006/";
const ATTACK_KERBEROAST: &str = "https://attack.mitre.org/techniques/T1558/003/";
const ATTACK_ASREP: &str = "https://attack.mitre.org/techniques/T1558/004/";
const MS_PROTECTED_USERS: &str = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group";
const MS_PRIVILEGED_ACCESS: &str = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models";
const MS_LAPS: &str =
    "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview";

pub(super) static ALL: &[RuleInfo] = &[
    RuleInfo {
        id: "PW-001",
        title: "Broad group has a path to Tier Zero",
        run: broad_group_path,
    },
    RuleInfo {
        id: "PW-002",
        title: "Account or group outside Tier Zero can DCSync",
        run: dcsync,
    },
    RuleInfo {
        id: "PW-003",
        title: "Account or group outside Tier Zero controls a Tier Zero object",
        run: tier_zero_control,
    },
    RuleInfo {
        id: "PW-004",
        title: "Tier Zero account signed in to computers outside Tier Zero",
        run: tier_zero_sessions,
    },
    RuleInfo {
        id: "PW-005",
        title: "Unconstrained delegation outside domain controllers",
        run: unconstrained_delegation,
    },
    RuleInfo {
        id: "PW-006",
        title: "Kerberoastable account with Tier Zero access",
        run: kerberoastable,
    },
    RuleInfo {
        id: "PW-007",
        title: "Kerberos pre-authentication disabled (AS-REP roasting)",
        run: asrep_roastable,
    },
    RuleInfo {
        id: "PW-008",
        title: "Tier Zero accounts without delegation protection",
        run: unprotected_tier_zero,
    },
    RuleInfo {
        id: "PW-009",
        title: "Stale Tier Zero accounts",
        run: stale_tier_zero,
    },
    RuleInfo {
        id: "PW-010",
        title: "Old Tier Zero passwords",
        run: old_tier_zero_passwords,
    },
    RuleInfo {
        id: "PW-011",
        title: "Computers without LAPS",
        run: missing_laps,
    },
    RuleInfo {
        id: "PW-012",
        title: "Trust between forests with weak SID filtering",
        run: sid_filtering,
    },
    RuleInfo {
        id: "PW-013",
        title: "Accounts that may have an empty password",
        run: password_not_required,
    },
    RuleInfo {
        id: "PW-015",
        title: "AD CS ESC1: template lets requesters choose any identity",
        run: super::adcs::esc1,
    },
    RuleInfo {
        id: "PW-016",
        title: "AD CS ESC3: enrollment agent abuse",
        run: super::adcs::esc3,
    },
    RuleInfo {
        id: "PW-017",
        title: "AD CS ESC4: write access to a template from outside Tier Zero",
        run: super::adcs::esc4,
    },
    RuleInfo {
        id: "PW-018",
        title: "AD CS ESC6: CA accepts requester-supplied SANs",
        run: super::adcs::esc6,
    },
    RuleInfo {
        id: "PW-019",
        title: "AD CS ESC8: NTLM relay to web enrollment",
        run: super::adcs::esc8,
    },
    RuleInfo {
        id: "PW-020",
        title: "AD CS ESC9/ESC10: weak certificate mapping",
        run: super::adcs::esc9_10,
    },
    RuleInfo {
        id: "PW-021",
        title: "AD CS ESC13: issuance policy linked to a group",
        run: super::adcs::esc13,
    },
    RuleInfo {
        id: "PW-022",
        title: "Account or group outside a Privilege Zone controls a zone object",
        run: zone_control,
    },
    RuleInfo {
        id: "PW-023",
        title: "Account or group outside Tier Zero can sign in to domain controllers",
        run: dc_logon,
    },
    RuleInfo {
        id: "PW-014",
        title: "krbtgt password not rotated",
        run: krbtgt_age,
    },
    // PW-026 and PW-027: SYSVOL. PW-025 is taken by the
    // management-plane rules.
    RuleInfo {
        id: "PW-026",
        title: "Group Policy Preferences password present in SYSVOL",
        run: super::sysvol::gpp_passwords,
    },
    RuleInfo {
        id: "PW-027",
        title: "SYSVOL permissions differ from the GPO's AD permissions",
        run: super::sysvol::sysvol_drift,
    },
    RuleInfo {
        id: "PW-025",
        title: "Tier Zero computers managed by a system outside Tier Zero",
        run: super::planes::managed_from_outside,
    },
    RuleInfo {
        id: "PW-028",
        title: "Possible management system: check whether it manages Tier Zero",
        run: super::planes::review,
    },
    RuleInfo {
        id: "PW-029",
        title: "ESX Admins group open to accounts outside Tier Zero (CVE-2024-37085)",
        run: super::planes::esx_admins,
    },
    RuleInfo {
        id: "PW-030",
        title: "Object outside Tier Zero controls a Tier Zero object through another system",
        run: external_control,
    },
    // PW-031 and PW-032: Entra ID and hybrid paths.
    RuleInfo {
        id: "PW-031",
        title: "Object outside Tier Zero controls an Entra ID Tier Zero object",
        run: super::entra::entra_control,
    },
    RuleInfo {
        id: "PW-032",
        title: "Entra ID controls on-premises Tier Zero (hybrid path)",
        run: super::entra::entra_to_on_premises,
    },
    // PW-033 to PW-035: rules OpenGraph mapping packs name.
    RuleInfo {
        id: "PW-033",
        title: "Tier Zero account's password stored on computers outside Tier Zero",
        run: super::opengraph::stored_credentials,
    },
    RuleInfo {
        id: "PW-034",
        title: "SQL Server runs as a Tier Zero account",
        run: super::opengraph::sql_runs_as_tier_zero,
    },
    RuleInfo {
        id: "PW-035",
        title: "Tier Zero computers managed by SCCM from outside Tier Zero",
        run: super::opengraph::sccm_controls_tier_zero,
    },
    RuleInfo {
        id: "PW-036",
        title: "AD CS ESC11: NTLM relay to the CA's RPC interface",
        run: super::adcs::esc11,
    },
    RuleInfo {
        id: "PW-037",
        title: "Seamless SSO Kerberos key not rotated",
        run: super::planes::sso_key_age,
    },
    RuleInfo {
        id: "PW-038",
        title: "Tier Zero computers take updates from WSUS over HTTP",
        run: super::planes::wsus_http,
    },
    RuleInfo {
        id: "PW-039",
        title: "Tier Zero computers are virtual machines on a hypervisor Pathwarden doesn't check",
        run: super::planes::tier_zero_vms,
    },
];

/// How each rule rates its findings when no severity is set for it
/// ([`super::default_label`]): whether they are attack paths (rated by
/// exposure when that is on; a few of their cases are not paths and keep
/// the rule's level), and the levels the rule itself gives. A test keeps
/// it in step with [`ALL`].
pub(super) const DEFAULT_LEVELS: &[(&str, bool, &[Severity])] = {
    use Severity::{Critical, High, Low, Medium};
    &[
        ("PW-001", true, &[Critical]),
        ("PW-002", true, &[Critical]),
        ("PW-003", true, &[Critical, High]),
        ("PW-004", true, &[High]),
        ("PW-005", true, &[Critical]),
        ("PW-006", true, &[Critical, High]),
        ("PW-007", true, &[Critical, High, Medium]),
        ("PW-008", false, &[Medium]),
        ("PW-009", false, &[Medium]),
        ("PW-010", false, &[Medium]),
        ("PW-011", false, &[Medium]),
        ("PW-012", false, &[High]),
        ("PW-013", false, &[High, Low]),
        ("PW-014", false, &[Medium]),
        ("PW-015", true, &[Critical]),
        ("PW-016", true, &[Critical]),
        ("PW-017", true, &[Critical]),
        ("PW-018", true, &[Critical, High, Medium]),
        ("PW-019", true, &[High]),
        ("PW-020", true, &[High, Medium]),
        ("PW-021", true, &[Critical, High]),
        ("PW-022", true, &[High]),
        ("PW-023", false, &[Critical, High]),
        ("PW-025", true, &[High]),
        ("PW-026", false, &[Critical]),
        ("PW-027", false, &[High, Medium]),
        ("PW-028", false, &[High, Medium, Low]),
        ("PW-029", false, &[High, Medium, Low]),
        ("PW-030", true, &[High]),
        ("PW-031", true, &[High]),
        ("PW-032", true, &[High, Medium]),
        ("PW-033", true, &[High]),
        ("PW-034", true, &[High]),
        ("PW-035", true, &[High]),
        ("PW-036", true, &[High]),
        ("PW-037", false, &[Medium]),
        ("PW-038", false, &[High]),
        ("PW-039", false, &[Medium]),
    ]
};

/// Collected (not placeholder), enabled objects of a kind.
fn live(g: &AdGraph, kind: NodeKind) -> impl Iterator<Item = (NodeIndex, &Node)> {
    g.nodes()
        .filter(move |(_, n)| n.kind == kind && !n.placeholder && n.is_enabled())
}

/// "1 account is", "12 accounts are".
fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// "today", "3 days ago", "14 months ago", "3 years ago".
fn ago(days: i64) -> String {
    match days {
        d if d <= 0 => "today".to_string(),
        1 => "yesterday".to_string(),
        d if d < 60 => format!("{d} days ago"),
        d if d < 730 => format!("{} months ago", d / 30),
        d => format!("{} years ago", d / 365),
    }
}

fn by_domain(
    g: &AdGraph,
    ixs: impl IntoIterator<Item = NodeIndex>,
) -> BTreeMap<String, Vec<NodeIndex>> {
    let mut out: BTreeMap<String, Vec<NodeIndex>> = BTreeMap::new();
    for ix in ixs {
        let domain = g
            .node(ix)
            .domain
            .clone()
            .unwrap_or_else(|| "UNKNOWN".into());
        out.entry(domain).or_default().push(ix);
    }
    out
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

/// Whether `ix` is a member, directly or through nesting, of a group with `rid`.
/// Everything in a group with this RID (in any domain), directly or nested.
/// Walks down from the groups: walking up from each account would scan the
/// outgoing edges of every group on the way, and a group like Domain Admins
/// has rights over every object in the directory.
fn members_of_rid(g: &AdGraph, rid: u32) -> HashSet<NodeIndex> {
    g.nodes()
        .filter(|(_, n)| sid::domain_rid(&n.id) == Some(rid))
        .flat_map(|(ix, _)| g.transitive_members(ix))
        .collect()
}

fn broad_group_path(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    g.nodes()
        .filter(|(_, n)| sid::is_broad_group(&n.id))
        .filter_map(|(ix, n)| {
            let path = ctx.path_to_tier_zero(ix)?;
            // A broad group configured as Tier Zero has no path to report.
            if path.steps.is_empty() {
                return None;
            }
            // A single direct control edge is already reported precisely by PW-003.
            if path.steps.len() == 1 && reported_as_control(path.steps[0].edge) {
                return None;
            }
            let first = &path.steps[0];
            // Every right the group holds on the first step's object: the
            // path stays open while any one of them is left.
            let first_edges: Vec<EdgeIndex> = path
                .edges
                .first()
                .and_then(|&e| g.inner().edge_endpoints(e))
                .map(|(a, b)| {
                    g.inner()
                        .edges_connecting(a, b)
                        .filter(|e| g.traversable(*e.weight(), b))
                        .map(|e| e.id())
                        .collect()
                })
                .unwrap_or_default();
            let (fix, kinds) = if first_edges.is_empty() {
                (edge_fix_in(g, first.edge, &first.from, &first.to), Vec::new())
            } else {
                (
                    crate::remediation::fix_for_edges_advised(g, &first_edges, Keepers::Any),
                    kinds_of(g, &first_edges),
                )
            };
            Some(
                Finding::new("PW-001", Severity::Critical, &[&n.id], format!("{} has a path to Tier Zero", n.name))
                    .domain(n.domain.as_ref())
                    .summary(format!(
                        "Every member of {} can reach Tier Zero in {}. Nearly every account is \
                         in this group, so any phished user or compromised workstation leads to domain compromise.{}",
                        n.name,
                        crate::text::count(path.steps.len(), "step", "steps"),
                        deny_note(&kinds)
                    ))
                    .remediation(format!(
                        "Break the path where it starts. {fix} Grant rights to dedicated groups for each tier \
                         instead of broad ones. {}",
                        super::PLAN_TAB_SENTENCE
                    ))
                    .affect(g, [ix])
                    .entry([ix])
                    .hits(ctx.tier_zero_end(ix))
                    .path(Some(path)),
            )
        })
        .collect()
}

fn dcsync(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let has_dcsync = |p: NodeIndex, d: NodeIndex| {
        g.inner()
            .edges_connecting(p, d)
            .any(|e| *e.weight() == EdgeKind::DcSync)
    };
    g.inner()
        .edge_references()
        .filter(|e| *e.weight() == EdgeKind::DcSync && !g.node(e.source()).tier_zero)
        // Members of a group that can DCSync are reported once, on the group.
        .filter(|e| {
            !g.inner()
                .edges_directed(e.source(), Direction::Outgoing)
                .any(|m| *m.weight() == EdgeKind::MemberOf && has_dcsync(m.target(), e.target()))
        })
        .map(|e| {
            let (p, d) = (g.node(e.source()), g.node(e.target()));
            Finding::new("PW-002", Severity::Critical, &[&p.id, &d.id], format!("{} can DCSync {}", p.name, d.name))
                .domain(d.domain.as_ref())
                .floor(Severity::High)
                .summary(format!(
                    "{} holds both directory replication permissions (Replicating Directory Changes and \
                     Replicating Directory Changes All) on the domain object {}. It can request the password \
                     hash of any account, including krbtgt, which is full domain compromise.{}",
                    p.name,
                    d.name,
                    deny_note(&[EdgeKind::GetChanges])
                ))
                .remediation(format!(
                    "{} By default only Domain Controllers, Enterprise Domain Controllers and Administrators \
                     hold them. If {} is the sync account of Entra Connect (or a similar sync product), keep \
                     the rights and manage the account and its server as Tier Zero (add them under Additional \
                     Tier Zero in Settings). If that sync server has been retired, disable the account and \
                     remove the rights.{}",
                    edge_fix(EdgeKind::DcSync, &p.name, &d.name),
                    p.name,
                    stale_note(ctx, e.source())
                ))
                .headline_for(g, e.source(), e.target(), &[EdgeKind::DcSync])
                .affect(g, [e.source(), e.target()])
                .entry([e.source()])
                .hits([e.target()])
                .path(Some(ctx.edge_path(e.source(), e.id())))
                .refs(&[ATTACK_DCSYNC])
        })
        .collect()
}

/// Edges PW-003 reports as "X controls Tier Zero object Y". The rest either
/// have a dedicated rule or are not a problem on their own.
pub(super) fn reported_as_control(kind: EdgeKind) -> bool {
    kind.is_traversable()
        && !kind.is_adcs_abuse()
        && !matches!(
            kind,
            EdgeKind::MemberOf
                | EdgeKind::HasSession
                | EdgeKind::SameForestTrust
                | EdgeKind::DcSync
                | EdgeKind::CoerceToTgt
                // Management of Tier Zero hosts is PW-025.
                | EdgeKind::ManagesHost
                // A Tier Zero password stored outside Tier Zero is PW-033.
                | EdgeKind::HasStoredCredential
                // Sitting in an ordinary OU is not a problem by itself;
                // control of that OU is, and path analysis covers it.
                | EdgeKind::Contains
        )
}

fn tier_zero_control(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    // SDProp copies AdminSDHolder's permissions onto every protected account and
    // group (adminCount=1) about once an hour. A right held on AdminSDHolder
    // therefore shows up on all of them; it can only be fixed at the source, so
    // it is reported once, there.
    let copied = |src: NodeIndex, kind: EdgeKind, target: NodeIndex| {
        sdprop_origin(g, src, kind, target).is_some()
    };
    // One finding per principal and object: several rights on the same object
    // are one ticket and one fix.
    let mut pairs: BTreeMap<(NodeIndex, NodeIndex), Vec<EdgeIndex>> = BTreeMap::new();
    for e in g.inner().edge_references() {
        if reported_as_control(*e.weight())
            && g.traversable(*e.weight(), e.target())
            && !g.node(e.source()).tier_zero
            && g.node(e.target()).tier_zero
            && !copied(e.source(), *e.weight(), e.target())
        {
            pairs
                .entry((e.source(), e.target()))
                .or_default()
                .push(e.id());
        }
    }
    pairs
        .into_iter()
        .map(|((src, target), edges)| {
            let (from, to) = (g.node(src), g.node(target));
            let rights = rights_of(g, &edges);
            let broad = sid::is_broad_group(&from.id);
            let severity = if broad { Severity::Critical } else { Severity::High };
            let who = if from.placeholder {
                format!("{} (an object not present in the collected data, for example a deleted or foreign account)", from.name)
            } else {
                from.name.clone()
            };
            let mut propagated: Vec<NodeIndex> = if to.is_adminsdholder() {
                edges
                    .iter()
                    .flat_map(|&e| {
                        let kind = g.inner()[e];
                        g.inner()
                            .edges_directed(src, Direction::Outgoing)
                            .filter(move |c| *c.weight() == kind)
                            .map(|c| c.target())
                            .collect::<Vec<_>>()
                    })
                    .filter(|&t| edges.iter().any(|&e| copied(src, g.inner()[e], t)))
                    .collect()
            } else {
                Vec::new()
            };
            propagated.sort_unstable();
            propagated.dedup();
            let sdprop_note = if propagated.is_empty() {
                String::new()
            } else {
                format!(
                    " SDProp has copied this onto {}, including {}; they are not \
                     reported separately and are fixed by removing it here.",
                    crate::text::count(propagated.len(), "protected account or group", "protected accounts and groups"),
                    names(g, &propagated, 5)
                )
            };
            let kinds = kinds_of(g, &edges);
            Finding::new("PW-003", severity, &[&from.id, &to.id], format!("{} has {rights} on {}", from.name, to.name))
                .domain(to.domain.as_ref())
                .floor(Severity::High)
                .summary(format!(
                    "{who} is outside Tier Zero but has {} on the Tier Zero {} {} ({}). Whoever controls {} \
                     controls {}.{sdprop_note}{}",
                    rights_words(&kinds),
                    to.kind.noun().unwrap_or("object"),
                    to.name,
                    to.tier_zero_reason.as_deref().unwrap_or("Tier Zero"),
                    from.name,
                    to.name,
                    deny_note(&kinds)
                ))
                .remediation(format!(
                    "{}{}",
                    advised_fixes_for(g, &edges, Keepers::TierZero),
                    stale_note(ctx, src)
                ))
                .headline_for(g, src, target, &kinds)
                .affect(g, [src, target].into_iter().chain(propagated.iter().copied()))
                .entry([src])
                .hits(std::iter::once(target).chain(propagated.iter().copied()))
                .path(Some(ctx.edge_path(src, edges[0])))
                // Every right of the pair, not only the sample: what it
                // rests on (an admin right, an ACL) comes from them.
                .evidence(edges.iter().copied())
        })
        .collect()
}

/// PW-030: the OpenGraph analog of PW-003. A traversable external edge (as a
/// trusted mapping pack defines it) from outside Tier Zero into a Tier Zero
/// object, unless the pack names a specific rule for its kind. One finding
/// per pair of objects; the kinds are left out of the fingerprint, so a
/// collector renaming an edge doesn't reopen tickets.
fn external_control(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    if !g.has_og_edges() {
        return Vec::new();
    }
    // An external object nothing can reach is no foothold (a task that
    // stores no password still names the account it runs as).
    let reachable = |u: NodeIndex| {
        !g.node(u).kind.is_external()
            || g.inner()
                .edges_directed(u, Direction::Incoming)
                .any(|i| g.traversable(*i.weight(), u))
    };
    let mut pairs: BTreeMap<(NodeIndex, NodeIndex), Vec<EdgeIndex>> = BTreeMap::new();
    for e in g.inner().edge_references() {
        let Some(sem) = g.edge_sem(*e.weight()) else {
            continue;
        };
        if !sem.traversable || !sem.control || sem.rule.is_some() || g.edge_origin(e.id()).is_none()
        {
            continue;
        }
        let (u, v) = (e.source(), e.target());
        if g.node(u).tier_zero || !g.node(v).tier_zero || !reachable(u) {
            continue;
        }
        pairs.entry((u, v)).or_default().push(e.id());
    }
    pairs
        .into_iter()
        .map(|((u, v), edges)| {
            let (from, to) = (g.node(u), g.node(v));
            let source = edges
                .iter()
                .find_map(|&e| g.edge_source_name(e))
                .unwrap_or("OpenGraph")
                .to_string();
            let rights = rights_of(g, &edges);
            let mut fix = fixes_for(g, &edges);
            // A relationship the pack says not to cut (a task's run-as
            // account) is fixed where the access comes from.
            let uncuttable = edges
                .iter()
                .all(|&e| g.edge_sem(g.inner()[e]).is_some_and(|s| !s.cuttable));
            if uncuttable {
                let mut upstream: Vec<String> = Vec::new();
                for i in g.inner().edges_directed(u, Direction::Incoming) {
                    let cuttable = g.edge_sem(*i.weight()).is_some_and(|s| s.traversable && s.cuttable);
                    if cuttable {
                        let text = crate::remediation::fix_for(g, i.id());
                        if !upstream.contains(&text) && upstream.len() < 3 {
                            upstream.push(text);
                        }
                    }
                }
                if !upstream.is_empty() {
                    fix = upstream.join(" ");
                }
            }
            let what = if from.kind.is_external() {
                format!("{} ({})", from.name, from.kind.as_str())
            } else {
                from.name.clone()
            };
            Finding::new(
                "PW-030",
                Severity::High,
                &[&from.id, &to.id],
                format!("{} controls {} through {source}", from.name, to.name),
            )
            .domain(to.domain.as_ref())
            .floor(Severity::High)
            .summary(format!(
                "{source} reports that {what}, which is outside Tier Zero, has {rights} on Tier Zero object {} ({}). Whoever controls {} controls {}. This rests on {source} data, not on the directory: confirm it with the system it describes.",
                to.name,
                to.tier_zero_reason.as_deref().unwrap_or("Tier Zero"),
                from.name,
                to.name
            ))
            .remediation(format!(
                "{fix} Then collect again with {source} (with its coverage file) to confirm the change."
            ))
            .affect(g, [u, v])
            .entry([u])
            .hits([v])
            .path(Some(ctx.edge_path(u, edges[0])))
            .evidence(edges)
        })
        .collect()
}

/// "GenericAll, WriteDacl" for a set of edges.
/// The distinct kinds of `edges`, sorted.
fn kinds_of(g: &AdGraph, edges: &[EdgeIndex]) -> Vec<EdgeKind> {
    let mut kinds: Vec<EdgeKind> = edges.iter().map(|&e| g.inner()[e]).collect();
    kinds.sort_unstable();
    kinds.dedup();
    kinds
}

/// "GenericWrite, WriteOwner and WriteDacl".
fn rights_words(kinds: &[EdgeKind]) -> String {
    match kinds {
        [] => String::new(),
        [one] => one.as_str().to_string(),
        [rest @ .., last] => format!(
            "{} and {}",
            rest.iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            last.as_str()
        ),
    }
}

/// " J.DOE last signed in 14 months ago: if it is no longer used, disable
/// it.", for an enabled user or computer that hasn't signed in for over
/// `stale_days`. Nothing without its last sign-in, or for a group.
fn stale_note(ctx: &Context, ix: NodeIndex) -> String {
    let n = ctx.graph.node(ix);
    if n.placeholder || !n.is_enabled() || !matches!(n.kind, NodeKind::User | NodeKind::Computer) {
        return String::new();
    }
    match n.props.lastlogontimestamp {
        Some(t) if t > 0 && ctx.days_since(t) > ctx.settings.stale_days => format!(
            " {} last signed in {}: if it is no longer used, disable it.",
            n.name,
            ago(ctx.days_since(t))
        ),
        _ => String::new(),
    }
}

/// The deny-entry note for a finding about directory permissions, as a
/// sentence to append (with its leading space), or nothing.
fn deny_note(kinds: &[EdgeKind]) -> String {
    crate::remediation::deny_note(kinds)
        .map(|n| format!(" {n}"))
        .unwrap_or_default()
}

/// [`fixes_for`] with what to keep instead and who should hold the right.
fn advised_fixes_for(g: &AdGraph, edges: &[EdgeIndex], keepers: Keepers) -> String {
    crate::remediation::fix_for_edges_advised(g, edges, keepers)
}

fn rights_of(g: &AdGraph, edges: &[EdgeIndex]) -> String {
    let mut kinds: Vec<EdgeKind> = edges.iter().map(|&e| g.inner()[e]).collect();
    kinds.sort_unstable();
    kinds.dedup();
    kinds
        .iter()
        .map(|k| k.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The fix for each edge, without repeating identical advice.
fn fixes_for(g: &AdGraph, edges: &[EdgeIndex]) -> String {
    crate::remediation::fix_for_edges(g, edges)
}

fn tier_zero_sessions(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    live(g, NodeKind::User)
        .filter(|(_, n)| n.tier_zero)
        .filter_map(|(ix, n)| {
            let hosts: Vec<NodeIndex> = g
                .inner()
                .edges_directed(ix, Direction::Incoming)
                .filter(|e| *e.weight() == EdgeKind::HasSession && !g.node(e.source()).tier_zero)
                .map(|e| e.source())
                .collect();
            if hosts.is_empty() {
                return None;
            }
            Some(
                Finding::new("PW-004", Severity::High, &[&n.id], format!("{} is signed in to {}", n.name, crate::text::count(hosts.len(), "computer outside Tier Zero", "computers outside Tier Zero")))
                    .domain(n.domain.as_ref())
                    .floor(Severity::High)
                    .summary(format!(
                        "Tier Zero account {} was signed in to {} when the data was collected. Anyone with admin \
                         rights on those computers can take its credentials from memory.",
                        n.name,
                        names(g, &hosts, 10)
                    ))
                    .remediation(format!(
                        "Use a separate admin account per tier so {0} signs in only to Tier Zero systems; enforce \
                         it with deny-logon user rights or an Authentication Policy Silo. Then sign {0} out of these \
                         computers or restart them.",
                        n.name
                    ))
                    .affect(g, std::iter::once(ix).chain(hosts.iter().copied()))
                    .entry(hosts.iter().copied())
                    .hits([ix])
                    .refs(&[MS_PROTECTED_USERS]),
            )
        })
        .collect()
}

fn unconstrained_delegation(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    g.inner()
        .edge_references()
        .filter(|e| *e.weight() == EdgeKind::CoerceToTgt)
        .map(|e| {
            let n = g.node(e.source());
            Finding::new("PW-005", Severity::Critical, &[&n.id], format!("{} has unconstrained delegation", n.name))
                .domain(n.domain.as_ref())
                .floor(Severity::High)
                .summary(format!(
                    "{} is trusted for unconstrained delegation. An attacker who controls it can coerce a domain \
                     controller to authenticate to it (PrinterBug, PetitPotam) and capture the DC's Kerberos \
                     ticket, so it is effectively Tier Zero.",
                    n.name
                ))
                .remediation(format!(
                    "Disable unconstrained delegation on {0} and move legitimate needs to Kerberos constrained \
                     delegation (KCD) or resource-based constrained delegation (RBCD). Review the services {0} \
                     hosts and name only the back-end services that need delegated authentication. Until \
                     unconstrained delegation is removed, treat {0} as Tier Zero, with the same administrative \
                     controls and monitoring as domain controllers. Turn off the Print Spooler on domain \
                     controllers where you can, against coercion through the print service (PrinterBug). Keep \
                     domain controllers up to date against other coercion such as PetitPotam.",
                    n.name
                ))
                .headline_for(g, e.source(), e.target(), &[EdgeKind::CoerceToTgt])
                .affect(g, [e.source(), e.target()])
                .entry([e.source()])
                .hits([e.target()])
                .path(Some(ctx.edge_path(e.source(), e.id())))
        })
        .collect()
}

fn kerberoastable(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    live(g, NodeKind::User)
        .filter(|(ix, n)| {
            n.props.hasspn == Some(true)
                && sid::domain_rid(&n.id) != Some(502)
                // A gMSA's or sMSA's password is 240 random bytes the domain
                // rotates: its tickets can't be cracked.
                && n.props.managedpassword != Some(true)
                && (n.tier_zero || ctx.reaches_tier_zero(*ix))
        })
        .map(|(ix, n)| {
            let severity = if n.tier_zero { Severity::Critical } else { Severity::High };
            let days = n.props.pwdlastset.filter(|&t| t > 0).map(|t| ctx.days_since(t));
            let age = days
                .map(|d| {
                    format!(
                        " Its password was last set {} day{} ago.",
                        crate::report::num(d.max(0) as usize),
                        if d == 1 { "" } else { "s" }
                    )
                })
                .unwrap_or_default();
            let reach = if n.tier_zero { "is Tier Zero" } else { "has a path to Tier Zero" };
            Finding::new("PW-006", severity, &[&n.id], format!("Kerberoastable account {} {reach}", n.name))
                .domain(n.domain.as_ref())
                .password_age(days)
                .summary(format!(
                    "{} has a service principal name, so any domain user can request a ticket encrypted with \
                     its password and crack it offline. The account {reach}.{age}",
                    n.name
                ))
                .remediation(format!(
                    "Move the service to a group managed service account (gMSA), or remove the service \
                     principal names {0} doesn't need. If the SPN must stay, give the account a random \
                     password of 25 or more characters, and allow only AES encryption for it ('This account \
                     supports Kerberos AES 128 bit encryption' and 'AES 256 bit encryption'), then change the \
                     password once more so the account has AES keys: a password set before the domain \
                     supported AES has none, and with AES only the service would stop working. {1}If the \
                     service is no longer used, \
                     disable the account.",
                    n.name,
                    if n.tier_zero {
                        format!("If {} is Tier Zero only through a group it doesn't need, take it out of that group. ", n.name)
                    } else {
                        String::new()
                    }
                ))
                .affect(g, [ix])
                .entry_everyone_if(true)
                .hits(if n.tier_zero { Some(ix) } else { ctx.tier_zero_end(ix) })
                .path(ctx.path_to_tier_zero(ix))
                .refs(&[ATTACK_KERBEROAST])
        })
        .collect()
}

fn asrep_roastable(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    live(g, NodeKind::User)
        .filter(|(_, n)| n.props.dontreqpreauth == Some(true))
        .map(|(ix, n)| {
            let severity = if n.tier_zero {
                Severity::Critical
            } else if ctx.reaches_tier_zero(ix) {
                Severity::High
            } else {
                Severity::Medium
            };
            Finding::new("PW-007", severity, &[&n.id], format!("{} does not require Kerberos pre-authentication", n.name))
                .domain(n.domain.as_ref())
                .password_age(n.props.pwdlastset.filter(|&t| t > 0).map(|t| ctx.days_since(t)))
                .summary(format!(
                    "Anyone on the network can request authentication data for {} that is encrypted with its \
                     password, without credentials, and crack it offline.",
                    n.name
                ))
                .remediation(format!(
                    "Clear the account option 'Do not require Kerberos preauthentication' (the \
                     userAccountControl flag DONT_REQ_PREAUTH) on {}. If an application needs it, give the \
                     account a random password of 25 or more characters. If the account is no longer used, \
                     disable it.",
                    n.name
                ))
                .affect(g, [ix])
                .entry_everyone_if(n.tier_zero || ctx.reaches_tier_zero(ix))
                .hits(if n.tier_zero { Some(ix) } else { ctx.tier_zero_end(ix) })
                .path(ctx.path_to_tier_zero(ix))
                .refs(&[ATTACK_ASREP])
        })
        .collect()
}

fn unprotected_tier_zero(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let protected_users = members_of_rid(g, 525);
    let users = live(g, NodeKind::User)
        .filter(|(ix, n)| {
            n.tier_zero
                && n.props.sensitive != Some(true)
                && sid::domain_rid(&n.id) != Some(502)
                && !protected_users.contains(ix)
        })
        .map(|(ix, _)| ix);
    by_domain(g, users)
        .into_iter()
        .map(|(domain, ixs)| {
            Finding::new("PW-008", Severity::Medium, &[&domain], format!("{} in {domain} can be delegated", crate::text::count(ixs.len(), "Tier Zero account", "Tier Zero accounts")))
                .domain(Some(&domain))
                .summary(format!(
                    "{} neither in Protected Users nor marked 'sensitive and cannot be delegated', so {} \
                     credentials can be cached on other systems or delegated to them.",
                    count(ixs.len(), "Tier Zero account is", "Tier Zero accounts are"),
                    if ixs.len() == 1 { "its" } else { "their" },
                ))
                .remediation(
                    "Add these Tier Zero user accounts to the Protected Users group. Members can't use NTLM, \
                     delegation or cached sign-ins, so don't add service accounts; for those, set the account \
                     option 'Account is sensitive and cannot be delegated' (the userAccountControl flag \
                     NOT_DELEGATED) instead.",
                )
                .affect(g, ixs)
                .refs(&[MS_PROTECTED_USERS])
        })
        .collect()
}

fn stale_tier_zero(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let limit = ctx.settings.stale_days;
    let users = live(g, NodeKind::User)
        .filter(|(_, n)| n.tier_zero)
        .filter(|(_, n)| match n.props.lastlogontimestamp {
            Some(t) if t > 0 => ctx.days_since(t) > limit,
            Some(_) => true, // never signed in
            None => false,
        })
        .map(|(ix, _)| ix);
    by_domain(g, users)
        .into_iter()
        .map(|(domain, ixs)| {
            Finding::new("PW-009", Severity::Medium, &[&domain], format!("{} in {domain}", crate::text::count(ixs.len(), "stale Tier Zero account", "stale Tier Zero accounts")))
                .domain(Some(&domain))
                .summary(format!(
                    "{} not signed in for over {limit} days, or never. Unused privileged accounts are \
                     rarely watched, so misuse can go unnoticed.",
                    count(ixs.len(), "enabled Tier Zero account has", "enabled Tier Zero accounts have"),
                ))
                .remediation(
                    "Disable these accounts, and delete them after your retention period. If one is still \
                     needed but not for Tier Zero work, remove it from the privileged groups instead.",
                )
                .affect_with(
                    g,
                    ixs.into_iter().map(|ix| {
                        let detail = match g.node(ix).props.lastlogontimestamp {
                            Some(t) if t > 0 => format!("last signed in {}", ago(ctx.days_since(t))),
                            _ => "never signed in".to_string(),
                        };
                        (ix, Some(detail))
                    }),
                )
        })
        .collect()
}

fn old_tier_zero_passwords(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let limit = ctx.settings.password_age_days;
    let users = live(g, NodeKind::User)
        .filter(|(_, n)| n.tier_zero && sid::domain_rid(&n.id) != Some(502))
        .filter(|(_, n)| {
            n.props
                .pwdlastset
                .is_some_and(|t| t > 0 && ctx.days_since(t) > limit)
        })
        .map(|(ix, _)| ix);
    by_domain(g, users)
        .into_iter()
        .map(|(domain, ixs)| {
            Finding::new("PW-010", Severity::Medium, &[&domain], format!("{} older than {limit} days in {domain}", crate::text::count(ixs.len(), "Tier Zero password", "Tier Zero passwords")))
                .domain(Some(&domain))
                .summary(format!(
                    "{} older than {limit} days. Old passwords are more likely to have been exposed in past \
                     breaches, backups or memory dumps.",
                    count(ixs.len(), "Tier Zero account has a password", "Tier Zero accounts have passwords"),
                ))
                .remediation(
                    "Change these passwords. Move service accounts to group managed service accounts (gMSAs), \
                     which the domain rotates. If an account no longer needs Tier Zero rights, remove it from \
                     the privileged groups; if it isn't used, disable it.",
                )
                .affect_with(
                    g,
                    ixs.into_iter().map(|ix| {
                        let days = g.node(ix).props.pwdlastset.map(|t| ctx.days_since(t));
                        (ix, days.map(|d| format!("password set {}", ago(d))))
                    }),
                )
        })
        .collect()
}

fn missing_laps(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let computers = live(g, NodeKind::Computer)
        // A standalone managed service account (sMSA) is typed as a computer
        // but has no interactive local administrator, so LAPS doesn't apply.
        .filter(|(_, n)| {
            !n.is_dc && n.props.haslaps == Some(false) && n.props.managedpassword != Some(true)
        })
        .map(|(ix, _)| ix);
    by_domain(g, computers)
        .into_iter()
        .map(|(domain, ixs)| {
            Finding::new("PW-011", Severity::Medium, &[&domain], format!("{} in {domain} without LAPS", crate::text::count(ixs.len(), "computer", "computers")))
                .domain(Some(&domain))
                .summary(format!(
                    "{} that LAPS doesn't manage. Unmanaged local admin passwords are often the same across \
                     computers, so one compromise spreads to the others.",
                    count(
                        ixs.len(),
                        "computer has a local administrator password",
                        "computers have local administrator passwords"
                    ),
                ))
                .remediation(
                    "Deploy Windows LAPS to these computers, and allow only the admins of each tier to read the \
                     stored passwords. Computers that can't run Windows LAPS, such as Linux computers and \
                     appliances, need another way to get a unique local password. Delete computer objects that \
                     no longer exist.",
                )
                .affect(g, ixs)
                .refs(&[MS_LAPS])
        })
        .collect()
}

/// PW-012's severity on a forest trust's `SidFilteringEnabled` flag alone
/// ([`sid_filtering_flag_only`]): High, as for a trust known not to filter.
/// The data can't show whether SID history is enabled, but if it is
/// the impact is forest-wide, and the unknown is no reason to rank it lower;
/// the finding's text says to verify first. docs/rules.md, docs/coverage.md,
/// docs/running.md and guides/PW-012.md say it in words.
pub const PW012_FLAG_ONLY_SEVERITY: Severity = Severity::High;

/// The trusting and the trusted side of a trust record: the trusting side
/// grants access and sets SID filtering on its own trust object. An inbound
/// record is the other domain trusting this one.
fn trusting_trusted(t: &crate::ingest::TrustInfo) -> (&str, &str) {
    if t.direction == "Inbound" {
        (&t.target, &t.source)
    } else {
        (&t.source, &t.target)
    }
}

fn sid_filtering(ctx: &Context) -> Vec<Finding> {
    ctx.trusts
        .iter()
        .filter(|t| t.sid_history_abusable())
        .map(|t| {
            if t.sid_filtering_flag_only() {
                return sid_filtering_flag_only(t);
            }
            let (trusting, trusted) = trusting_trusted(t);
            // Named for the setting the fix changes. Both kinds still filter
            // RIDs under 1000 and the built-in SIDs (MS-PAC 4.1.2.2), so
            // neither title says filtering is off.
            let title = if t.trust_type.eq_ignore_ascii_case("forest") {
                format!("Trust {} → {} lets SID history through (SID filtering relaxed)", t.source, t.target)
            } else {
                format!("Trust {} → {} has SID filtering relaxed", t.source, t.target)
            };
            Finding::new("PW-012", Severity::High, &[&t.source, &t.target], title)
                .domain(Some(&t.source))
                .summary(format!(
                    "The {} trust between {} and {} filters only the built-in and privileged SIDs (RIDs under \
                     1000). An attacker who compromises {trusted} can forge SID history {trusting} accepts for \
                     its accounts and groups with RIDs of 1000 and above, and gains what those hold directly or \
                     through domain-local groups. Domain Admins and Enterprise Admins are still filtered.",
                    t.trust_type, t.source, t.target
                ))
                .remediation(if t.trust_type.eq_ignore_ascii_case("forest") {
                    // Forest trusts filter SIDs by default; "disabled" here means
                    // SID history was enabled across the trust.
                    format!(
                        "Turn SID history off across the forest trust so SID filtering applies again, on a \
                         domain controller of {trusting}: `netdom trust {trusting} /domain:{trusted} \
                         /enablesidhistory:no`. If a migration still needs SID history, plan when it ends and \
                         turn it off then."
                    )
                } else {
                    format!(
                        "Enable SID filtering (quarantine) on the external trust, on a domain controller of \
                         {trusting}: `netdom trust {trusting} /domain:{trusted} /quarantine:yes`. If a migration \
                         still needs SID history, plan when it ends and turn it off then."
                    )
                })
        })
        .collect()
}

/// PW-012 on a forest trust's `SidFilteringEnabled` flag alone. The flag
/// only reports quarantine, which forest trusts don't use, so it normally
/// reads "off" whether or not SID history is enabled across the trust: the
/// finding says it can't tell, as the Forest view does, and asks for the
/// trust attributes ([`PW012_FLAG_ONLY_SEVERITY`]).
fn sid_filtering_flag_only(t: &crate::ingest::TrustInfo) -> Finding {
    use crate::forest::{COLLECT_TRUST_ATTRIBUTES, FOREST_FLAG_UNKNOWN, SID_FILTERING_UNKNOWN};
    let (trusting, trusted) = trusting_trusted(t);
    Finding::new(
        "PW-012",
        PW012_FLAG_ONLY_SEVERITY,
        &[&t.source, &t.target],
        format!(
            "Trust {} → {}: {SID_FILTERING_UNKNOWN} (the collected data doesn't say)",
            t.source, t.target
        ),
    )
    .domain(Some(&t.source))
    .summary(format!(
        "{SID_FILTERING_UNKNOWN} on the {} trust between {} and {}: {FOREST_FLAG_UNKNOWN}. SID \
         history may be forgeable across it: if SID history is enabled (TREAT_AS_EXTERNAL), an \
         attacker who compromises {trusted} can forge SID history {trusting} accepts, for accounts \
         and groups with RIDs of 1000 and above. To know, {COLLECT_TRUST_ATTRIBUTES}.",
        t.trust_type, t.source, t.target
    ))
    .remediation(format!(
        "First find out whether SID history is enabled across the trust. Either \
         {COLLECT_TRUST_ATTRIBUTES}, or on a domain controller of {trusting} run \
         `(Get-ADTrust -Filter \"Target -eq '{trusted}'\").TrustAttributes -band 0x40`: non-zero \
         means SID history is enabled (TREAT_AS_EXTERNAL; Get-ADTrust shows TrustAttributes in \
         decimal, and 72 = 0x48 includes 0x40), 0 means the forest trust filters SIDs. If it is \
         enabled, turn it off so SID filtering applies again: `netdom trust {trusting} \
         /domain:{trusted} /enablesidhistory:no`. If a migration still needs SID history, plan when \
         it ends and turn it off then."
    ))
}

fn password_not_required(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let users = live(g, NodeKind::User)
        // Trust accounts carry PASSWD_NOTREQD by design and cannot log on.
        .filter(|(_, n)| {
            n.props.passwordnotreqd == Some(true) && n.props.trustaccount != Some(true)
        })
        .map(|(ix, _)| ix);
    by_domain(g, users)
        .into_iter()
        .map(|(domain, ixs)| {
            let severity = if ixs.iter().any(|&ix| g.node(ix).tier_zero) { Severity::High } else { Severity::Low };
            Finding::new("PW-013", severity, &[&domain], format!("{} in {domain} {} an empty password", crate::text::count(ixs.len(), "account", "accounts"), if ixs.len() == 1 { "allows" } else { "allow" }))
                .domain(Some(&domain))
                .summary(format!(
                    "{} the userAccountControl flag PASSWD_NOTREQD set, so {} password may be empty whatever \
                     the password policy says. Pathwarden can't tell whether a password is actually empty.",
                    count(ixs.len(), "enabled account has", "enabled accounts have"),
                    if ixs.len() == 1 { "its" } else { "their" },
                ))
                .remediation(
                    "Clear the flag PASSWD_NOTREQD (userAccountControl 0x20) on each account, then reset its \
                     password: clearing the flag doesn't change a password that is already empty. Disable the \
                     accounts that are no longer used.",
                )
                .affect_with(
                    g,
                    ixs.into_iter()
                        .map(|ix| (ix, g.node(ix).tier_zero.then(|| "Tier Zero".to_string()))),
                )
        })
        .collect()
}

fn krbtgt_age(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let limit = ctx.settings.krbtgt_age_days;
    g.nodes()
        .filter(|(_, n)| n.kind == NodeKind::User && !n.placeholder && sid::domain_rid(&n.id) == Some(502))
        .filter_map(|(ix, n)| {
            let days = ctx.days_since(n.props.pwdlastset.filter(|&t| t > 0)?);
            (days > limit).then(|| {
                let days = crate::report::num(days.max(0) as usize);
                Finding::new("PW-014", Severity::Medium, &[&n.id], format!("{}'s password is {days} days old", n.name))
                    .domain(n.domain.as_ref())
                    .summary(format!(
                        "The krbtgt key signs every Kerberos ticket in the domain. It was last changed {days} days \
                         ago, so a golden ticket forged with a key stolen at any time since then still works."
                    ))
                    .remediation(
                        "Rotate the krbtgt password twice, waiting at least the maximum ticket lifetime (10 hours \
                         by default) between rotations, using Microsoft's New-KrbtgtKeys script. Repeat at least \
                         every 180 days.",
                    )
                    .affect(g, [ix])
            })
        })
        .collect()
}

/// PW-003 for each Privilege Zone: control of a zone object by a principal
/// that is neither in the zone nor in Tier Zero.
fn zone_control(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let mut out = Vec::new();
    for zone in ctx.zones {
        let mut pairs: BTreeMap<(NodeIndex, NodeIndex), Vec<EdgeIndex>> = BTreeMap::new();
        for &target in &zone.members {
            for e in g.inner().edges_directed(target, Direction::Incoming) {
                let src = e.source();
                // A zone account's password stored on a computer outside
                // the zone: PW-033 is Tier Zero's, the zone's is here.
                let kind = *e.weight();
                if (reported_as_control(kind) || kind == EdgeKind::HasStoredCredential)
                    && g.traversable(kind, e.target())
                    && !zone.contains(src)
                    && !g.node(src).tier_zero
                {
                    pairs.entry((src, target)).or_default().push(e.id());
                }
            }
        }
        for ((src, target), edges) in pairs {
            let (from, to) = (g.node(src), g.node(target));
            let rights = rights_of(g, &edges);
            let kinds = kinds_of(g, &edges);
            out.push(
                Finding::new(
                    "PW-022",
                    Severity::High,
                    &[&zone.name, &from.id, &to.id],
                    format!("{} has {rights} on {} (zone {})", from.name, to.name, zone.name),
                )
                .domain(to.domain.as_ref())
                .summary(format!(
                    "{} is outside the {} zone but has {} on {}, which belongs to it. Whoever controls {} \
                     controls {}, so the zone boundary doesn't hold.{}",
                    from.name,
                    zone.name,
                    rights_words(&kinds),
                    crate::remediation::the_kind(to.kind, &to.name),
                    from.name,
                    to.name,
                    deny_note(&kinds)
                ))
                .remediation(format!(
                    "{} If {} administers this zone, add it to the zone instead.{}",
                    advised_fixes_for(g, &edges, Keepers::Zone),
                    from.name,
                    stale_note(ctx, src)
                ))
                .headline_for(g, src, target, &kinds)
                .affect(g, [src, target])
                .entry([src])
                .hits([target])
                .path(Some(ctx.edge_path(src, edges[0])))
                .evidence(edges.iter().copied()),
            );
        }
    }
    out
}

/// Remote logon rights a principal holds on a domain's DCs, and one edge to
/// show as the example path.
type Grant = (Vec<EdgeKind>, Vec<NodeIndex>, EdgeIndex);

/// PW-023: remote logon rights on domain controllers, with a note on the
/// SSH servers the Tier Zero host probe finds on them.
fn dc_logon(ctx: &Context) -> Vec<Finding> {
    let mut out = dc_remote_logon(ctx);
    super::planes::ssh_note(ctx, &mut out);
    out
}

/// Principals outside Tier Zero that can log on to domain controllers
/// remotely. Not an attack path by itself (see `AdGraph::traversable`), but a
/// session on a DC is one privilege escalation away from the domain.
fn dc_remote_logon(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    // One finding per principal and domain: on domain controllers these rights
    // come from the domain's built-in groups, shared by every DC, so one
    // change fixes all of them.
    let mut grants: BTreeMap<(NodeIndex, String), Grant> = BTreeMap::new();
    for e in g.inner().edge_references() {
        let (src, dc) = (g.node(e.source()), g.node(e.target()));
        if !e.weight().is_remote_logon() || !dc.is_dc || src.tier_zero {
            continue;
        }
        let Some(domain) = dc.domain.clone() else {
            continue;
        };
        let entry = grants
            .entry((e.source(), domain))
            .or_insert_with(|| (Vec::new(), Vec::new(), e.id()));
        entry.0.push(*e.weight());
        entry.1.push(e.target());
    }
    grants
        .into_iter()
        .map(|((src, domain), (mut kinds, mut dcs, first))| {
            kinds.sort_unstable();
            kinds.dedup();
            dcs.sort_unstable();
            dcs.dedup();
            let from = g.node(src);
            let how: Vec<&str> = kinds
                .iter()
                .map(|k| match k {
                    EdgeKind::CanRdp => "Remote Desktop",
                    EdgeKind::CanPsRemote => "PowerShell remoting",
                    _ => "DCOM",
                })
                .collect();
            let groups: Vec<String> = kinds
                .iter()
                .map(|k| match k {
                    EdgeKind::CanRdp => "Remote Desktop Users (S-1-5-32-555)",
                    EdgeKind::CanPsRemote => "Remote Management Users (S-1-5-32-580)",
                    _ => "Distributed COM Users (S-1-5-32-562)",
                })
                .map(String::from)
                .collect();
            let severity = if sid::is_broad_group(&from.id) { Severity::Critical } else { Severity::High };
            Finding::new("PW-023", severity, &[&from.id, &domain], format!(
                "{} can sign in to {} in {domain} ({})",
                from.name,
                crate::text::count(dcs.len(), "domain controller", "domain controllers"),
                how.join(", ")
            ))
            .domain(Some(&domain))
            .summary(format!(
                "{} is outside Tier Zero but can open a session on domain controllers through {}: {}. A session \
                 on a DC is one local privilege escalation away from the whole domain, and it exposes the DC to \
                 whatever runs in that account's session.",
                from.name,
                how.join(" and "),
                names(g, &dcs, 10)
            ))
            .remediation(format!(
                "Remove {} from the built-in {} {} of {domain}. On domain controllers these are domain \
                 groups shared by every DC, not local groups, so one change covers all of them. Also check the \
                 GPOs linked to the Domain Controllers OU for user rights that grant the same sign-in (for example \
                 'Allow log on through Remote Desktop Services'). Only Tier Zero administrators should sign in \
                 to domain controllers.{}",
                from.name,
                if groups.len() == 1 { "group" } else { "groups" },
                and_or(&groups),
                stale_note(ctx, src)
            ))
            .affect(g, std::iter::once(src).chain(dcs))
            .path(Some(ctx.edge_path(src, first)))
            .refs(&[MS_PRIVILEGED_ACCESS])
        })
        .collect()
}

fn and_or(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}
