//! Targeted retest: re-read only the objects one finding involves, merge them
//! into that finding's part of the original graph, and run its rule again.
//!
//! The full graph of a run is not kept (the collector files are deleted after
//! analysis, and the object index has no permissions). Instead, each run keeps
//! a [`Slice`]: for every finding that can be retested this way, the objects
//! to re-read (affected objects, the nodes of its example path, its domain,
//! the groups that make those objects Tier Zero), plus one hop of context
//! around them (whoever holds rights on them, the groups they are in) and
//! every edge between those nodes. That is enough to rebuild the finding's
//! evidence, small enough to keep with the run, and holds nothing that the
//! report does not already show.
//!
//! A retest then:
//!
//! 1. rebuilds the slice's graph;
//! 2. replaces each re-read object's properties, and the edges recorded on
//!    its own directory entry: permissions on it (ACEs), its members,
//!    delegation settings and SID history. An object the search didn't
//!    return is deleted only when the directory says so ([`HostReads::deleted`]:
//!    a Base search on its SID or GUID answered noSuchObject, or found its
//!    tombstone). Otherwise it may only be hidden from this account (a Deny
//!    Read), so it keeps what the slice had and decides nothing: the finding
//!    is fixed when it is gone even so, still open when it is there with the
//!    object taken as deleted, and "can't tell" in between;
//! 3. recomputes derived edges (DCSync, coercion) and Tier Zero, where only
//!    re-read objects lose an original Tier Zero mark;
//! 4. runs the finding's rule on the result and looks for its fingerprint.
//!
//! Sessions and local group rights come from each computer, not from LDAP.
//! A finding that rests on them names the computers on its path
//! ([`SliceFinding::hosts`]: the sources of its `HasSession` edges, the
//! targets of its `AdminTo`, `CanRDP`, `CanPSRemote` and `ExecuteDCOM`
//! edges), and the collector reads just those ([`HostRead`], at most
//! [`MAX_HOSTS`]). A computer that was read replaces what the slice had of
//! it; one that couldn't be read keeps it, and the verdict says so
//! ([`Slice::retest_with`]): fixed when the finding is gone even with what
//! the unread computers had, still open when it is there with only what was
//! read, "can't tell" in between.
//!
//! A Tier Zero password stored on computers (PW-033, as the built-in
//! collector read it) is checked the same way: the computers that
//! store it ([`SliceHost::services`], [`SliceHost::tasks`]) get their
//! services and scheduled tasks read again, and their `HasStoredCredential`
//! edges come from that read (its `pathwarden-storedcreds.json`); one not
//! read in full keeps what the slice had of it. TaskHound's data can't be
//! read again.
//!
//! The limits, which the UI states: only those objects and computers are
//! refreshed, so a new path elsewhere is not detected; exposure is not
//! re-measured (the slice is not the whole directory).

use std::collections::{HashMap, HashSet};

use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::{Deserialize, Serialize};

use super::{AffectedView, FindingView, Verdict};
use crate::findings::{self, Context, Finding, RuleSettings};
use crate::graph::AdGraph;
use crate::ingest::TrustInfo;
use crate::model::{EdgeKind, Node, NodeKind};
use crate::{postprocess, sid, tierzero, NodeIndex};

pub const SLICE_VERSION: u32 = 1;

/// Most objects one targeted retest re-reads. Larger findings (every
/// computer without LAPS, say) are retested with a new collection.
pub const MAX_REFRESH: usize = 500;

/// Rules whose evidence an LDAP re-read can't refresh, with the reason.
/// Sessions and local groups (Tier Zero sessions, remote logon to domain
/// controllers) are read from the computers on the finding's path instead
/// ([`SliceFinding::hosts`]).
fn unsupported(rule: &str) -> Option<&'static str> {
    Some(match rule {
        "PW-012" => {
            "Trusts are retested with a new collection. Collect again to retest this finding."
        }
        "PW-015" | "PW-016" | "PW-017" | "PW-018" | "PW-019" | "PW-020" | "PW-021" | "PW-036" => {
            "AD CS findings depend on templates, CAs and their settings across the forest. \
             Collect again to retest this finding."
        }
        "PW-022" => "Zone findings are retested with a new collection. Collect again to retest this finding.",
        "PW-026" | "PW-027" | "PW-038" => {
            "SYSVOL files and their permissions are read from the domain controller's SYSVOL \
             share, not the directory. Collect again with the built-in collector to retest \
             this finding."
        }
        "PW-025" | "PW-028" | "PW-029" => {
            "Management system findings depend on accounts, groups and containers across the \
             domain. Collect again to retest this finding."
        }
        "PW-033" => {
            "This finding rests on what the computers store (their services, or TaskHound's \
             data), which a directory re-read can't refresh. Run a full collection again, or \
             TaskHound with its coverage file, and analyze."
        }
        "PW-039" => {
            "This finding rests on the Tier Zero settings files read on the hosts, which a \
             directory re-read can't refresh. Run the settings script on them again, and \
             analyze with the new files."
        }
        "PW-030" | "PW-034" | "PW-035" => {
            "This finding rests on another collector's data (OpenGraph), which a directory \
             re-read can't refresh. Run that collector again, with its coverage file, and analyze."
        }
        _ => return None,
    })
}

/// Edges recorded on the target's directory entry: its permissions (ACEs),
/// its members, who may act on its behalf, and its GPO links.
fn recorded_on_target(kind: EdgeKind) -> bool {
    use EdgeKind::*;
    matches!(
        kind,
        MemberOf
            | AllowedToAct
            | GpLink
            | GenericAll
            | GenericWrite
            | WriteOwner
            | WriteDacl
            | Owns
            | AddMember
            | AddSelf
            | ForceChangePassword
            | AllExtendedRights
            | AddKeyCredentialLink
            | AddAllowedToAct
            | ReadLapsPassword
            | ReadGmsaPassword
            | SyncLapsPassword
            | WriteSpn
            | WriteAccountRestrictions
            | WriteGpLink
            | GetChanges
            | GetChangesAll
            | GetChangesInFilteredSet
            | OwnsLimitedRights
            | WriteOwnerLimitedRights
    )
}

/// Edges recorded on the source's directory entry.
fn recorded_on_source(kind: EdgeKind) -> bool {
    matches!(kind, EdgeKind::AllowedToDelegate | EdgeKind::HasSidHistory)
}

/// Edges post-processing derives again from the merged graph.
fn derived(kind: EdgeKind) -> bool {
    matches!(kind, EdgeKind::DcSync | EdgeKind::CoerceToTgt)
}

/// Only SIDs and GUIDs can be looked up in the directory (not the
/// domain-prefixed well-known principals collectors invent).
fn searchable(id: &str) -> bool {
    id.starts_with("S-1-5-21-") || is_guid(id)
}

fn is_guid(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// One edge of the slice: endpoints by position in [`Slice::nodes`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceEdge(pub u32, pub u32, pub EdgeKind, #[serde(default)] pub bool);

/// What the slice knows about one finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceFinding {
    pub fingerprint: String,
    pub rule: String,
    /// Object IDs to re-read; empty when the finding can't be retested this way.
    #[serde(default)]
    pub refresh: Vec<String>,
    /// The finding's affected objects (ID, name).
    #[serde(default)]
    pub affected: Vec<AffectedView>,
    /// Distinguished names of the groups among `refresh`: their members are
    /// read too, so member names resolve.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Why this finding can't be retested by re-reading objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported: Option<String>,
    /// The computers on its path whose sessions or local groups it rests
    /// on. `None` in slices saved before they were recorded: then they come
    /// from the slice's edges ([`Slice::hosts_of`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<SliceHost>>,
}

impl SliceFinding {
    pub fn targetable(&self) -> bool {
        self.unsupported.is_none() && !self.refresh.is_empty()
    }
}

/// A computer on a finding's path, and what of it the finding rests on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceHost {
    /// Its object ID (SID).
    pub id: String,
    /// Sessions on it (it is the source of a `HasSession` edge).
    #[serde(default)]
    pub sessions: bool,
    /// Its local groups (the target of an `AdminTo`, `CanRDP`,
    /// `CanPSRemote` or `ExecuteDCOM` edge).
    #[serde(default)]
    pub local_groups: bool,
    /// A service on it stores the finding's account's password (the
    /// source of a `HasStoredCredential` edge a service gave).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub services: bool,
    /// A scheduled task on it stores the password.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tasks: bool,
}

impl SliceHost {
    /// The finding rests on a password it stores: its services and tasks
    /// are read again.
    pub fn stored(&self) -> bool {
        self.services || self.tasks
    }
}

/// Most computers one retest reads. A finding with more is checked on the
/// first ones and answers "can't tell" unless those decide it.
pub const MAX_HOSTS: usize = 50;

/// Edges read from a computer's local groups (they end at it).
pub fn local_group_edge(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::AdminTo | EdgeKind::CanRdp | EdgeKind::CanPsRemote | EdgeKind::ExecuteDcom
    )
}

/// What reading one computer gave, as the collector reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRead {
    /// Its object ID (SID).
    pub id: String,
    /// Its name (FQDN), for the words.
    #[serde(default)]
    pub name: String,
    /// Its sessions were read: `None` when they weren't asked for. Read
    /// means a list that names logged-on users answered (WKSSVC or Remote
    /// Registry); SRVSVC alone lists only network connections.
    #[serde(default)]
    pub sessions: Option<bool>,
    /// Its local groups were read (every group asked answered): `None`
    /// when they weren't asked for.
    #[serde(default)]
    pub local_groups: Option<bool>,
    /// Its services were read in full: `None` when its stored
    /// credentials weren't asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<bool>,
    /// Its scheduled tasks were read in full: likewise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks: Option<bool>,
    /// Why something asked wasn't read, in the collector's words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// Nothing asked was read because the computer didn't answer (port 445
    /// closed, no route, timed out).
    #[serde(default)]
    pub unreachable: bool,
    /// It was skipped, never signed in to: the domain has no
    /// Kerberos name for it, or its SMB replies weren't signed. `why` says
    /// which.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub skipped: bool,
}

/// What the retest could read of the computers on the finding's path.
#[derive(Debug, Clone, Default)]
pub struct HostReads {
    /// One per computer asked.
    pub reads: Vec<HostRead>,
    /// Why no computer was read, in a sentence, when none was (signed in
    /// as the current account outside Windows, a build without the
    /// collector, the check turned off).
    pub skipped: Option<String>,
    /// Object IDs (as the slice has them) the search didn't return and the
    /// directory said are deleted: a Base search on the SID or GUID
    /// answered noSuchObject, or returned the tombstone. Another object the
    /// search didn't return is not taken as deleted.
    pub deleted: Vec<String>,
}

/// The sentence for computers that couldn't be read: `failed` of `total`,
/// all of them unreachable or not.
pub fn hosts_not_read(failed: usize, total: usize, unreachable: bool) -> String {
    let how = if unreachable { "reached" } else { "read" };
    if total == 1 {
        format!("The computer on its path couldn't be {how}, so it can't be checked.")
    } else {
        format!(
            "{failed} of {total} computers on its path couldn't be {how}, so it can't be checked."
        )
    }
}

/// The sentence for a finding with more computers on its path than a
/// retest reads.
pub fn hosts_over_cap(total: usize) -> String {
    format!(
        "It has {total} computers on its path and a retest reads at most {MAX_HOSTS}, so it \
         can't be checked."
    )
}

/// Why no computer is read when signed in as the current account where it
/// can't read them (outside Windows). On Windows the account reads them
/// with Windows' own calls.
pub const HOSTS_NEED_PASSWORD: &str =
    "Reading the computers on its path needs a user and password here.";
/// Why no computer is read in a build without the built-in collector.
pub const HOSTS_NO_COLLECTOR: &str = "This build has no built-in collector, so it can't read \
     the computers on its path.";

/// The part of a run's graph that targeted retests need.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slice {
    pub version: u32,
    pub nodes: Vec<Node>,
    pub edges: Vec<SliceEdge>,
    #[serde(default)]
    pub trusts: Vec<TrustInfo>,
    pub findings: Vec<SliceFinding>,
}

/// The nodes of a finding's example path (paths name nodes, not IDs).
fn path_nodes(f: &Finding, by_name: &HashMap<(&str, NodeKind), NodeIndex>) -> Vec<NodeIndex> {
    let Some(p) = &f.path else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for s in &p.steps {
        for (name, kind) in [(&s.from, s.from_kind), (&s.to, s.to_kind)] {
            if let Some(&ix) = by_name.get(&(name.as_str(), kind)) {
                out.push(ix);
            }
        }
    }
    out
}

/// The computers on a finding's sample path and evidence whose sessions or
/// local groups it rests on, and for the rules that read those straight
/// from the data ([`crate::posture::HOST_DATA_RULES`]: Tier Zero sessions,
/// remote logon to domain controllers) its affected computers; and the
/// computers that store a password it rests on (the sources of its
/// `HasStoredCredential` edges, with what stores it: a service, a scheduled
/// task). Sorted by ID.
fn finding_hosts(g: &AdGraph, f: &Finding) -> Vec<SliceHost> {
    let mut by_id: std::collections::BTreeMap<String, SliceHost> = Default::default();
    let mut add = |n: &Node, what: SliceHost| {
        if n.kind != NodeKind::Computer || n.placeholder || !searchable(&n.id) {
            return;
        }
        let h = by_id.entry(n.id.clone()).or_insert_with(|| SliceHost {
            id: n.id.clone(),
            ..SliceHost::default()
        });
        h.sessions |= what.sessions;
        h.local_groups |= what.local_groups;
        h.services |= what.services;
        h.tasks |= what.tasks;
    };
    let edges = f
        .evidence
        .iter()
        .chain(f.path.iter().flat_map(|p| p.edges.iter()));
    for &e in edges {
        let Some((a, b)) = g.inner().edge_endpoints(e) else {
            continue;
        };
        match g.inner()[e] {
            EdgeKind::HasSession => add(
                g.node(a),
                SliceHost {
                    sessions: true,
                    ..SliceHost::default()
                },
            ),
            k if local_group_edge(k) => add(
                g.node(b),
                SliceHost {
                    local_groups: true,
                    ..SliceHost::default()
                },
            ),
            EdgeKind::HasStoredCredential => {
                let vias = g.stored_via(e);
                add(
                    g.node(a),
                    SliceHost {
                        services: vias.is_empty()
                            || vias
                                .iter()
                                .any(|v| v.via == crate::storedcreds::Via::Service),
                        tasks: vias.iter().any(|v| v.via == crate::storedcreds::Via::Task),
                        ..SliceHost::default()
                    },
                )
            }
            _ => {}
        }
    }
    let rule = crate::posture::Untargeted::of_rule(f.rule);
    if crate::posture::HOST_DATA_RULES
        .iter()
        .any(|(r, _)| r.eq_ignore_ascii_case(f.rule))
    {
        for a in &f.affected {
            if let Some(ix) = g.lookup(&a.id) {
                add(
                    g.node(ix),
                    SliceHost {
                        sessions: rule.sessions,
                        local_groups: rule.local_groups,
                        ..SliceHost::default()
                    },
                );
            }
        }
    }
    by_id.into_values().collect()
}

impl Slice {
    /// The computers on `sf`'s path to read: as recorded, or for a slice
    /// saved before they were, from the slice's edges between the objects
    /// it re-reads.
    pub fn hosts_of(&self, sf: &SliceFinding) -> Vec<SliceHost> {
        if let Some(h) = &sf.hosts {
            return h.clone();
        }
        let refresh: HashSet<&str> = sf.refresh.iter().map(String::as_str).collect();
        let mut by_id: std::collections::BTreeMap<String, SliceHost> = Default::default();
        for SliceEdge(a, b, kind, _) in &self.edges {
            let (from, to) = (&self.nodes[*a as usize], &self.nodes[*b as usize]);
            if !refresh.contains(from.id.as_str()) || !refresh.contains(to.id.as_str()) {
                continue;
            }
            let (host, sessions) = match kind {
                EdgeKind::HasSession => (from, true),
                k if local_group_edge(*k) => (to, false),
                _ => continue,
            };
            if host.kind != NodeKind::Computer {
                continue;
            }
            let h = by_id.entry(host.id.clone()).or_insert_with(|| SliceHost {
                id: host.id.clone(),
                ..SliceHost::default()
            });
            h.sessions |= sessions;
            h.local_groups |= !sessions;
        }
        by_id.into_values().collect()
    }

    /// Builds the slice for a finished analysis.
    pub fn build(g: &AdGraph, trusts: &[TrustInfo], findings: &[Finding]) -> Slice {
        let by_name: HashMap<(&str, NodeKind), NodeIndex> = g
            .nodes()
            .map(|(ix, n)| ((n.name.as_str(), n.kind), ix))
            .collect();
        let by_id = |id: &str| g.lookup(id);

        let mut keep: Vec<NodeIndex> = Vec::new();
        let mut in_slice: HashSet<NodeIndex> = HashSet::new();
        let mut out_findings = Vec::new();
        for f in findings {
            // A Tier Zero password stored on computers, as the built-in
            // collector read them: those computers are read again.
            // TaskHound's data can't be.
            let native_stored = f.rule == "PW-033"
                && !f.sources.is_empty()
                && f.sources.iter().all(|s| crate::storedcreds::is_source(s));
            let mut sf = SliceFinding {
                fingerprint: f.fingerprint.clone(),
                rule: f.rule.to_string(),
                refresh: Vec::new(),
                affected: f
                    .affected
                    .iter()
                    .map(|a| AffectedView {
                        id: a.id.clone(),
                        name: a.name.clone(),
                    })
                    .collect(),
                groups: Vec::new(),
                hosts: None,
                unsupported: if native_stored {
                    None
                } else {
                    unsupported(f.rule).map(str::to_string).or_else(|| {
                        (!f.sources.is_empty()).then(|| {
                            format!(
                                "Part of this finding's evidence comes from {}, which a \
                                 directory re-read can't refresh. Collect again to retest it.",
                                f.sources.join(", ")
                            )
                        })
                    })
                },
            };
            if sf.unsupported.is_some() {
                out_findings.push(sf);
                continue;
            }
            let mut core: Vec<NodeIndex> = f.affected.iter().filter_map(|a| by_id(&a.id)).collect();
            core.extend(path_nodes(f, &by_name));
            let hosts = finding_hosts(g, f);
            core.extend(hosts.iter().filter_map(|h| by_id(&h.id)));
            if let Some(d) = &f.domain {
                if let Some(&ix) = by_name.get(&(d.as_str(), NodeKind::Domain)) {
                    core.push(ix);
                }
            }
            // The groups that make these objects Tier Zero, and each domain's
            // Protected Users (PW-008's fix is membership there).
            let mut extra = Vec::new();
            for &ix in &core {
                let n = g.node(ix);
                if let Some(group) = n
                    .tier_zero_reason
                    .as_deref()
                    .and_then(|r| r.strip_prefix("Member of "))
                {
                    if let Some(&gx) = by_name.get(&(group, NodeKind::Group)) {
                        extra.push(gx);
                    }
                }
                if n.kind == NodeKind::Domain {
                    if let Some(px) = by_id(&format!("{}-525", n.id)) {
                        extra.push(px);
                    }
                }
            }
            core.extend(extra);
            let mut seen = HashSet::new();
            core.retain(|&ix| {
                let n = g.node(ix);
                !n.placeholder && searchable(&n.id) && seen.insert(ix)
            });
            if core.is_empty() {
                sf.unsupported = Some(
                    "None of this finding's objects can be looked up in the directory.".into(),
                );
            } else if core.len() > MAX_REFRESH {
                sf.unsupported = Some(format!(
                    "This finding involves {} objects, too many to re-read one by one. Collect \
                     again to retest it.",
                    core.len()
                ));
            } else {
                sf.refresh = core.iter().map(|&ix| g.node(ix).id.clone()).collect();
                let kept: HashSet<&str> = sf.refresh.iter().map(String::as_str).collect();
                sf.hosts = Some(
                    hosts
                        .into_iter()
                        .filter(|h| kept.contains(h.id.as_str()))
                        .collect(),
                );
                sf.groups = core
                    .iter()
                    .map(|&ix| g.node(ix))
                    .filter(|n| n.kind == NodeKind::Group)
                    .filter_map(|n| n.props.distinguishedname.clone())
                    .collect();
                // The objects, and one hop of context: who holds rights on
                // them or is their member, and the groups they are in.
                for &ix in &core {
                    if in_slice.insert(ix) {
                        keep.push(ix);
                    }
                    let broad = sid::is_broad_group(&g.node(ix).id);
                    for e in g.inner().edges_directed(ix, Direction::Incoming) {
                        let k = *e.weight();
                        if recorded_on_target(k)
                            && !(broad && k == EdgeKind::MemberOf)
                            && in_slice.insert(e.source())
                        {
                            keep.push(e.source());
                        }
                    }
                    for e in g.inner().edges_directed(ix, Direction::Outgoing) {
                        if *e.weight() == EdgeKind::MemberOf && in_slice.insert(e.target()) {
                            keep.push(e.target());
                        }
                    }
                }
            }
            out_findings.push(sf);
        }

        let pos: HashMap<NodeIndex, u32> = keep
            .iter()
            .enumerate()
            .map(|(i, &ix)| (ix, i as u32))
            .collect();
        let mut edges = Vec::new();
        for &ix in &keep {
            for e in g.inner().edges_directed(ix, Direction::Outgoing) {
                if let Some(&to) = pos.get(&e.target()) {
                    edges.push(SliceEdge(pos[&ix], to, *e.weight(), g.is_inherited(e.id())));
                }
            }
        }
        Slice {
            version: SLICE_VERSION,
            nodes: keep.iter().map(|&ix| g.node(ix).clone()).collect(),
            edges,
            trusts: trusts.to_vec(),
            findings: out_findings,
        }
    }

    pub fn finding(&self, fingerprint: &str) -> Option<&SliceFinding> {
        self.findings
            .iter()
            .find(|f| f.fingerprint.eq_ignore_ascii_case(fingerprint))
    }

    /// The slice's graph merged with re-read objects (`fresh`, as ingested
    /// from the targeted collection), refreshing the objects in `refresh`.
    pub fn merged(&self, fresh: &AdGraph, refresh: &HashSet<String>) -> Merged {
        self.merged_with(fresh, refresh, &HostMerge::default())
    }

    /// [`Slice::merged`], with what was read of the computers on the path:
    /// their sessions and local groups replaced from `fresh` where they were
    /// read, left out where `hosts` says to drop them.
    pub fn merged_with(
        &self,
        fresh: &AdGraph,
        refresh: &HashSet<String>,
        hosts: &HostMerge,
    ) -> Merged {
        // The slice's own host edges of these computers give way.
        let stale_session =
            |from: &str| hosts.read_sessions.contains(from) || hosts.drop_sessions.contains(from);
        let stale_group =
            |to: &str| hosts.read_groups.contains(to) || hosts.drop_groups.contains(to);
        let stale_stored =
            |from: &str| hosts.read_stored.contains(from) || hosts.drop_stored.contains(from);
        let mut g = AdGraph::new();
        let mut found = HashSet::new();
        let mut missing = Vec::new();
        let mut hidden = Vec::new();
        let mut gone_ids: HashSet<&str> = HashSet::new();
        let mut extra_tier_zero = Vec::new();
        for n in &self.nodes {
            // A management plane is Tier Zero because of objects a slice
            // rarely holds (its sync account, its SCOM group): keep the mark.
            if refresh.contains(&n.id) && crate::mgmt::is_plane_reason(n) {
                extra_tier_zero.push(n.id.clone());
            }
            let mut node = if refresh.contains(&n.id) {
                match fresh.lookup(&n.id).map(|ix| fresh.node(ix)) {
                    Some(f) if !f.placeholder => {
                        found.insert(n.id.clone());
                        f.clone()
                    }
                    _ if hosts.deleted.contains(&n.id) || hosts.hidden_as_deleted => {
                        // Not in the directory any more: deleted (or, to
                        // see whether the finding stands without it, taken
                        // as deleted).
                        if hosts.deleted.contains(&n.id) {
                            missing.push(n.name.clone());
                        } else {
                            hidden.push(n.name.clone());
                        }
                        gone_ids.insert(n.id.as_str());
                        let mut gone = n.clone();
                        gone.placeholder = true;
                        gone.props.enabled = Some(false);
                        gone
                    }
                    _ => {
                        // Not returned, and not said to be deleted: maybe
                        // hidden from this account. What the slice had.
                        hidden.push(n.name.clone());
                        if n.tier_zero {
                            extra_tier_zero.push(n.id.clone());
                        }
                        n.clone()
                    }
                }
            } else {
                if n.tier_zero {
                    extra_tier_zero.push(n.id.clone());
                }
                n.clone()
            };
            node.tier_zero = false;
            node.tier_zero_reason = None;
            g.upsert(node);
        }
        let deleted = gone_ids;

        // Edges kept from the original: everything except what the re-read
        // entries now say, and edges derived again below.
        for SliceEdge(a, b, kind, inherited) in &self.edges {
            let (from, to) = (&self.nodes[*a as usize].id, &self.nodes[*b as usize].id);
            if derived(*kind)
                || deleted.contains(from.as_str())
                || deleted.contains(to.as_str())
                || (recorded_on_target(*kind) && found.contains(to))
                || (recorded_on_source(*kind) && found.contains(from))
                || (*kind == EdgeKind::HasSession && stale_session(from))
                || (local_group_edge(*kind) && stale_group(to))
                || (*kind == EdgeKind::HasStoredCredential && stale_stored(from))
            {
                continue;
            }
            let (Some(x), Some(y)) = (g.lookup(from), g.lookup(to)) else {
                continue;
            };
            if *kind == EdgeKind::HasStoredCredential {
                // As the collection's file gave it: the services' source
                // of the computer's domain, the computer its unit.
                let host = &self.nodes[*a as usize];
                let source = crate::storedcreds::source(host.domain.as_deref().unwrap_or(""));
                add_stored(&mut g, x, y, &source, from, Vec::new());
                continue;
            }
            g.add_ace_edge(x, y, *kind, *inherited);
        }

        // Edges from the re-read entries.
        let fi = fresh.inner();
        for e in fi.edge_references() {
            let (a, b, kind) = (fresh.node(e.source()), fresh.node(e.target()), *e.weight());
            let take = (recorded_on_target(kind) && found.contains(&b.id))
                || (recorded_on_source(kind) && found.contains(&a.id))
                // A primary group is recorded on the member.
                || (kind == EdgeKind::MemberOf && found.contains(&a.id))
                || (kind == EdgeKind::Contains && (found.contains(&a.id) || found.contains(&b.id)))
                // What was read of the computers on the path.
                || (kind == EdgeKind::HasSession && hosts.read_sessions.contains(&a.id))
                || (local_group_edge(kind) && hosts.read_groups.contains(&b.id))
                // A password a computer read again still stores, read in
                // full or not.
                || kind == EdgeKind::HasStoredCredential;
            if !take {
                continue;
            }
            let x = g.lookup(&a.id).unwrap_or_else(|| g.upsert(stub(a)));
            let y = g.lookup(&b.id).unwrap_or_else(|| g.upsert(stub(b)));
            if kind == EdgeKind::HasStoredCredential {
                let source = fresh
                    .edge_source_name(e.id())
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        crate::storedcreds::source(a.domain.as_deref().unwrap_or(""))
                    });
                add_stored(
                    &mut g,
                    x,
                    y,
                    &source,
                    &a.id,
                    fresh.stored_via(e.id()).to_vec(),
                );
                continue;
            }
            g.add_ace_edge(x, y, kind, fresh.is_inherited(e.id()));
        }
        // Passwords still stored under an account's old name.
        for (host, account) in &hosts.extra_stored {
            let (Some(x), Some(y)) = (g.lookup(host), g.lookup(account)) else {
                continue;
            };
            let domain = g.node(x).domain.clone().unwrap_or_default();
            add_stored(
                &mut g,
                x,
                y,
                &crate::storedcreds::source(&domain),
                host,
                Vec::new(),
            );
        }

        postprocess::run(&mut g);
        tierzero::mark(&mut g, &extra_tier_zero);
        Merged {
            graph: g,
            found: found.len(),
            missing,
            hidden,
        }
    }

    /// Retests one finding against re-read objects, reading none of the
    /// computers on its path. `now` is the time ages (stale accounts,
    /// password age) are measured from.
    pub fn retest(
        &self,
        fingerprint: &str,
        fresh: &AdGraph,
        now: i64,
    ) -> Result<TargetedOutcome, String> {
        let none = HostReads {
            reads: Vec::new(),
            skipped: Some(HOSTS_NOT_READ.to_string()),
            deleted: Vec::new(),
        };
        self.retest_with(fingerprint, fresh, &none, now)
    }

    /// The computers a retest of `sf` reads (at most [`MAX_HOSTS`], the
    /// first by ID) and how many are on its path.
    pub fn host_targets(&self, sf: &SliceFinding) -> (Vec<SliceHost>, usize) {
        let all = self.hosts_of(sf);
        let total = all.len();
        (all.into_iter().take(MAX_HOSTS).collect(), total)
    }

    /// Retests one finding against re-read objects and what was read of the
    /// computers on its path (`hosts`). A computer whose sessions or local
    /// groups the finding rests on and that wasn't read decides nothing: the
    /// finding is fixed when it is gone even with what the slice had of
    /// those computers, still open when it is there without it, and "can't
    /// tell" otherwise, with why.
    pub fn retest_with(
        &self,
        fingerprint: &str,
        fresh: &AdGraph,
        hosts: &HostReads,
        now: i64,
    ) -> Result<TargetedOutcome, String> {
        let sf = self
            .finding(fingerprint)
            .ok_or_else(|| "This finding is not in the run.".to_string())?;
        if let Some(why) = &sf.unsupported {
            return Err(why.clone());
        }
        let refresh: HashSet<String> = sf.refresh.iter().cloned().collect();
        // A computer that is no longer in the directory has no path.
        let gone = |id: &str| fresh.lookup(id).is_none_or(|ix| fresh.node(ix).placeholder);
        let needed: Vec<SliceHost> = self
            .hosts_of(sf)
            .into_iter()
            .filter(|h| !gone(&h.id))
            .collect();
        let reads: HashMap<&str, &HostRead> =
            hosts.reads.iter().map(|r| (r.id.as_str(), r)).collect();
        let mut merge = HostMerge::default();
        let mut unread: Vec<(&SliceHost, Option<&HostRead>)> = Vec::new();
        let mut read = 0;
        for h in &needed {
            let r = reads.get(h.id.as_str()).copied();
            let sessions = r.and_then(|r| r.sessions) == Some(true);
            let groups = r.and_then(|r| r.local_groups) == Some(true);
            // Its services and its tasks, both read in full, whatever stored
            // the password before: it may have moved from one to the other,
            // and a part not read (or switched off) leaves that gap open.
            let stored =
                r.and_then(|r| r.services) == Some(true) && r.and_then(|r| r.tasks) == Some(true);
            if h.sessions && sessions {
                merge.read_sessions.insert(h.id.clone());
            }
            if h.local_groups && groups {
                merge.read_groups.insert(h.id.clone());
            }
            if h.stored() && stored {
                merge.read_stored.insert(h.id.clone());
            }
            if (h.sessions && !sessions) || (h.local_groups && !groups) || (h.stored() && !stored) {
                unread.push((h, r));
            } else {
                read += 1;
            }
        }
        merge.extra_stored = self.stored_by_old_name(fresh, &needed);
        merge.deleted = hosts.deleted.iter().cloned().collect();

        let merged = self.merged_with(fresh, &refresh, &merge);
        if merged.found == 0 && merged.missing.is_empty() {
            return Ok(TargetedOutcome {
                verdict: Verdict::CantTell,
                details: vec![
                    "None of this finding's objects were found in the directory. Is this the \
                     right domain, and can this account read it?"
                        .into(),
                ],
                refreshed: 0,
                missing: merged.missing,
                hidden: merged.hidden,
                finding: None,
                hosts_read: 0,
                hosts: needed.len(),
            });
        }
        let settings = RuleSettings {
            now,
            ..RuleSettings::default()
        };
        let disabled: Vec<String> = findings::rules()
            .iter()
            .filter(|r| r.id != sf.rule)
            .map(|r| r.id.to_string())
            .collect();
        let evaluate = |g: &AdGraph| -> Option<Finding> {
            let ctx = Context::new(g, &self.trusts, &settings);
            findings::evaluate(&ctx, &disabled)
                .into_iter()
                .find(|f| f.fingerprint.eq_ignore_ascii_case(&sf.fingerprint))
        };
        let mut still = evaluate(&merged.graph);
        let mut cant_tell = None;
        if still.is_some() && (!unread.is_empty() || !merged.hidden.is_empty()) {
            // Without what the slice had of the computers not read, and of
            // the objects not returned: there with only what was read is
            // still open.
            let mut without = merge.clone();
            without.hidden_as_deleted = true;
            for (h, _) in &unread {
                if h.sessions {
                    without.drop_sessions.insert(h.id.clone());
                }
                if h.local_groups {
                    without.drop_groups.insert(h.id.clone());
                }
                if h.stored() {
                    without.drop_stored.insert(h.id.clone());
                }
            }
            still = evaluate(&self.merged_with(fresh, &refresh, &without).graph);
            if still.is_none() {
                let mut words = hidden_words(&merged.hidden);
                if !unread.is_empty() {
                    words.extend(unread_words(&unread, needed.len(), hosts));
                }
                cant_tell = Some(words);
            }
        }
        let mut details = Vec::new();
        let verdict = match (&still, cant_tell) {
            (_, Some(words)) => {
                details = words;
                Verdict::CantTell
            }
            (Some(f), None) => {
                let now_ids: HashSet<&str> = f.affected.iter().map(|a| a.id.as_str()).collect();
                let remaining: Vec<&AffectedView> = sf
                    .affected
                    .iter()
                    .filter(|a| now_ids.contains(a.id.as_str()))
                    .collect();
                if sf.affected.len() > 1 {
                    details.push(format!(
                        "{} of {} affected objects remain",
                        remaining.len(),
                        sf.affected.len()
                    ));
                }
                if let Some(p) = &f.path {
                    let hops: Vec<String> = p
                        .steps
                        .iter()
                        .map(|s| format!("-[{}]-> {}", s.edge.as_str(), s.to))
                        .collect();
                    details.push(format!("path still there: {} {}", p.source, hops.join(" ")));
                }
                Verdict::StillOpen
            }
            (None, None) => {
                for m in &merged.missing {
                    details.push(format!("{m} no longer exists in the directory"));
                }
                Verdict::Fixed
            }
        };
        Ok(TargetedOutcome {
            verdict,
            details,
            refreshed: merged.found,
            missing: merged.missing,
            hidden: merged.hidden,
            finding: still.as_ref().map(FindingView::from),
            hosts_read: read,
            hosts: needed.len(),
        })
    }
}

/// Why a finding can't be told: the objects the directory didn't return and
/// didn't say are deleted, in a sentence naming up to five.
fn hidden_words(hidden: &[String]) -> Vec<String> {
    if hidden.is_empty() {
        return Vec::new();
    }
    let mut names: Vec<&str> = hidden.iter().take(5).map(String::as_str).collect();
    if hidden.len() > 5 {
        names.push("...");
    }
    vec![format!(
        "{} the directory didn't return and didn't say {} deleted ({}): this account may not be \
         allowed to read {}.",
        crate::text::count(hidden.len(), "object", "objects"),
        if hidden.len() == 1 { "was" } else { "were" },
        names.join(", "),
        if hidden.len() == 1 { "it" } else { "them" }
    )]
}

/// Why a finding can't be told: the computers on its path that weren't
/// read, in sentences, and up to five of them with the reason.
fn unread_words(
    unread: &[(&SliceHost, Option<&HostRead>)],
    total: usize,
    hosts: &HostReads,
) -> Vec<String> {
    let mut out = Vec::new();
    let failed: Vec<&HostRead> = unread.iter().filter_map(|(_, r)| *r).collect();
    let not_asked = unread.len() - failed.len();
    if let Some(why) = hosts.skipped.as_ref().filter(|_| failed.is_empty()) {
        out.push(why.clone());
        return out;
    }
    if !failed.is_empty() {
        let unreachable = failed.iter().all(|r| r.unreachable);
        out.push(hosts_not_read(failed.len(), total, unreachable));
        for r in failed.iter().take(5) {
            let name = if r.name.is_empty() { &r.id } else { &r.name };
            // A reason may be a sentence of its own: one period.
            let why = r.why.as_deref().unwrap_or("not read").trim_end_matches('.');
            if r.skipped {
                out.push(format!("{name} was skipped: {why}."));
            } else {
                out.push(format!("{name}: {why}."));
            }
        }
    }
    if not_asked > 0 {
        out.push(if total > MAX_HOSTS {
            hosts_over_cap(total)
        } else {
            HOSTS_NOT_READ.to_string()
        });
    }
    out
}

/// Why the computers on a finding's path weren't read, when nothing more
/// specific is known (`pathwarden retest targeted --no-hosts`).
pub const HOSTS_NOT_READ: &str = "The computers on its path were not read, so it can't be checked.";

/// What a merge does with the sessions and local groups of the computers
/// on the path, by object ID.
#[derive(Debug, Clone, Default)]
pub struct HostMerge {
    /// Sessions read: the slice's give way to the re-read ones.
    pub read_sessions: HashSet<String>,
    /// Local groups read: likewise.
    pub read_groups: HashSet<String>,
    /// Sessions not read, left out (to see whether the finding stands
    /// without them).
    pub drop_sessions: HashSet<String>,
    /// Local groups not read, left out.
    pub drop_groups: HashSet<String>,
    /// Services and tasks read in full: the slice's stored passwords
    /// of these computers give way to the re-read ones.
    pub read_stored: HashSet<String>,
    /// Services or tasks not read in full: the slice's stored passwords of
    /// these computers left out.
    pub drop_stored: HashSet<String>,
    /// (computer, account) by object ID: a password a computer read again
    /// still stores under a name the account had in the run, and the
    /// directory no longer gives it (renamed since).
    pub extra_stored: Vec<(String, String)>,
    /// Object IDs the directory said are deleted ([`HostReads::deleted`]).
    pub deleted: HashSet<String>,
    /// Objects not returned and not said to be deleted are taken as
    /// deleted too (to see whether the finding stands without them).
    pub hidden_as_deleted: bool,
}

impl Slice {
    /// The accounts the computers in `needed` still store under a name
    /// they had in the run (`fresh`'s unresolved accounts, resolved against
    /// the slice's users by their names then): renamed since, the password
    /// is still there.
    fn stored_by_old_name(&self, fresh: &AdGraph, needed: &[SliceHost]) -> Vec<(String, String)> {
        let hosts: HashSet<&str> = needed
            .iter()
            .filter(|h| h.stored())
            .map(|h| h.id.as_str())
            .collect();
        let pending: Vec<(String, &str)> = fresh
            .stored_domains()
            .iter()
            .flat_map(|sd| sd.unresolved.iter())
            .map(|(hix, account)| (fresh.node(*hix).id.clone(), account.as_str()))
            .filter(|(h, _)| hosts.contains(h.as_str()))
            .collect();
        if pending.is_empty() {
            return Vec::new();
        }
        let mut old = AdGraph::new();
        for n in self
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::User && !n.placeholder)
        {
            old.upsert(n.clone());
        }
        let mut out = Vec::new();
        for (host, account) in pending {
            if let Some(ix) = crate::storedcreds::resolve_in(fresh, &old, account) {
                let pair = (host, old.node(ix).id.clone());
                if !out.contains(&pair) {
                    out.push(pair);
                }
            }
        }
        out
    }
}

/// A `HasStoredCredential` edge (`host` → account) as the collection's file
/// gives it: from `source`, with `unit` (the computer) as its coverage
/// unit, and what stores it.
fn add_stored(
    g: &mut AdGraph,
    host: NodeIndex,
    account: NodeIndex,
    source: &str,
    unit: &str,
    vias: Vec<crate::storedcreds::StoredVia>,
) {
    let origin = crate::opengraph::EdgeOrigin {
        source: g.add_og_source(source),
        unit: Some(unit.to_string()),
    };
    g.add_og_edge(host, account, EdgeKind::HasStoredCredential, origin);
    if !vias.is_empty() {
        g.add_stored_via(host, account, vias);
    }
}

/// A node from the re-read data that the slice did not have.
fn stub(n: &Node) -> Node {
    let mut n = n.clone();
    n.tier_zero = false;
    n.tier_zero_reason = None;
    n
}

pub struct Merged {
    pub graph: AdGraph,
    /// Re-read objects that were found.
    pub found: usize,
    /// Names of re-read objects the directory said are deleted.
    pub missing: Vec<String>,
    /// Names of re-read objects not returned and not said to be deleted
    /// (maybe hidden from the account): kept as the slice had them, unless
    /// [`HostMerge::hidden_as_deleted`].
    pub hidden: Vec<String>,
}

/// The result of a targeted retest.
#[derive(Debug, Clone, Serialize)]
pub struct TargetedOutcome {
    pub verdict: Verdict,
    pub details: Vec<String>,
    /// Objects re-read from the directory.
    pub refreshed: usize,
    /// Objects the directory said are deleted.
    pub missing: Vec<String>,
    /// Objects not returned and not said to be deleted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hidden: Vec<String>,
    /// The finding as it is now, when still open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding: Option<FindingView>,
    /// Computers on its path whose sessions or local groups were read.
    pub hosts_read: usize,
    /// Computers on its path whose sessions or local groups it rests on.
    pub hosts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::Ingestor;

    fn forest() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest")
    }

    fn slice() -> Slice {
        let a = crate::analyze::run(&[forest()], &Default::default(), &[], &mut |_| {}).unwrap();
        let s = Slice::build(&a.graph, &a.stats.trusts, &a.findings);
        // As stored with a run.
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap()
    }

    fn fp(s: &Slice, rule: &str) -> String {
        s.findings
            .iter()
            .find(|f| f.rule == rule)
            .unwrap()
            .fingerprint
            .clone()
    }

    /// The fixture's objects with `ids`, each changed by `edit`, as the
    /// re-read collection.
    fn reread(ids: &[String], edit: impl Fn(&mut serde_json::Value)) -> AdGraph {
        let mut ing = Ingestor::new();
        for file in ["users", "computers", "groups", "domains", "gpos", "ous"] {
            let text =
                std::fs::read_to_string(forest().join(format!("contoso_{file}.json"))).unwrap();
            let mut doc: serde_json::Value = serde_json::from_str(&text).unwrap();
            let data = doc["data"].as_array_mut().unwrap();
            data.retain(|o| {
                ids.iter()
                    .any(|i| i == o["ObjectIdentifier"].as_str().unwrap())
            });
            for o in data.iter_mut() {
                edit(o);
            }
            doc["meta"]["count"] = (data.len() as u64).into();
            ing.ingest_text(&format!("{file}.json"), &doc.to_string())
                .unwrap();
        }
        ing.finish().0
    }

    /// Everything a finding's retest re-reads.
    fn refresh_of(s: &Slice, fp: &str) -> Vec<String> {
        s.finding(fp).unwrap().refresh.clone()
    }

    const CAROL: &str = "S-1-5-21-2000-2000-2000-1202";
    const CHILD_DA: &str = "S-1-5-21-2000-2000-2000-1201";
    const CHILD: &str = "S-1-5-21-2000-2000-2000";
    const SVC_SYNC: &str = "S-1-5-21-1000-1000-1000-1106";
    const NOW: i64 = 1_791_417_600;

    #[test]
    fn slices_cover_targetable_findings() {
        let s = slice();
        let pw003 = s.finding(&fp(&s, "PW-003")).unwrap();
        assert!(pw003.targetable());
        for id in [CAROL, CHILD_DA, CHILD] {
            assert!(
                pw003.refresh.iter().any(|r| r == id),
                "{id} in {:?}",
                pw003.refresh
            );
        }
        // Sessions aren't in LDAP: they are read from the computer on the
        // path.
        let pw004 = s.finding(&fp(&s, "PW-004")).unwrap();
        assert!(pw004.targetable());
        assert_eq!(
            pw004.hosts.as_deref(),
            Some(
                &[SliceHost {
                    id: SRV01.into(),
                    sessions: true,
                    ..Default::default()
                }][..]
            )
        );
        // An ACL finding rests on no computer.
        assert_eq!(pw003.hosts.as_deref(), Some(&[][..]));
        assert!(
            s.nodes.len() < 60,
            "a slice, not the forest: {}",
            s.nodes.len()
        );
    }

    #[test]
    fn a_removed_ace_is_fixed_and_an_unchanged_one_still_open() {
        let s = slice();
        let f = fp(&s, "PW-003");
        let ids = refresh_of(&s, &f);

        // Unchanged: still open, with the path.
        let same = reread(&ids, |_| {});
        let r = s.retest(&f, &same, NOW).unwrap();
        assert_eq!(r.verdict, Verdict::StillOpen, "{r:?}");
        assert!(r.details.iter().any(|d| d.contains("GenericAll")), "{r:?}");
        assert_eq!(r.refreshed, ids.len());

        // CAROL's GenericAll on CHILD_DA removed: fixed.
        let fixed = reread(&ids, |o| {
            if o["ObjectIdentifier"] == CHILD_DA {
                o["Aces"] = serde_json::json!([]);
            }
        });
        let r = s.retest(&f, &fixed, NOW).unwrap();
        assert_eq!(r.verdict, Verdict::Fixed, "{r:?}");
    }

    #[test]
    fn a_split_dcsync_grant_and_deleted_objects() {
        let s = slice();
        let f = fp(&s, "PW-002");
        let ids = refresh_of(&s, &f);
        let same = reread(&ids, |_| {});
        assert_eq!(
            s.retest(&f, &same, NOW).unwrap().verdict,
            Verdict::StillOpen
        );

        // GetChangesAll (held through SYNC_OPERATORS) revoked on the domain.
        let revoked = reread(&ids, |o| {
            if let Some(aces) = o["Aces"].as_array_mut() {
                aces.retain(|a| {
                    a["RightName"] != "GetChangesAll"
                        || a["PrincipalSID"] != "S-1-5-21-1000-1000-1000-1151"
                });
            }
        });
        assert_eq!(s.retest(&f, &revoked, NOW).unwrap().verdict, Verdict::Fixed);

        // The account deleted, as the directory says: fixed, and said so.
        let rest: Vec<String> = ids.iter().filter(|i| *i != SVC_SYNC).cloned().collect();
        let gone = reread(&rest, |_| {});
        let proven = HostReads {
            reads: Vec::new(),
            skipped: Some(HOSTS_NOT_READ.into()),
            deleted: vec![SVC_SYNC.into()],
        };
        let r = s.retest_with(&f, &gone, &proven, NOW).unwrap();
        assert_eq!(r.verdict, Verdict::Fixed);
        assert_eq!(
            r.details,
            ["SVC_SYNC@CONTOSO.LOCAL no longer exists in the directory"]
        );

        // Not returned, and the directory didn't say it was
        // deleted (a Deny Read hides it): can't tell, never fixed.
        let r = s.retest(&f, &gone, NOW).unwrap();
        assert_eq!(r.verdict, Verdict::CantTell, "{r:?}");
        assert_eq!(r.hidden, ["SVC_SYNC@CONTOSO.LOCAL"]);
        assert!(r.missing.is_empty());
        assert_eq!(
            r.details,
            [
                "1 object the directory didn't return and didn't say was deleted \
              (SVC_SYNC@CONTOSO.LOCAL): this account may not be allowed to read it."
            ]
        );
        // Hidden, but the grant is gone from the domain anyway: fixed.
        let revoked_rest = reread(&rest, |o| {
            if let Some(aces) = o["Aces"].as_array_mut() {
                aces.retain(|a| {
                    a["RightName"] != "GetChangesAll"
                        || a["PrincipalSID"] != "S-1-5-21-1000-1000-1000-1151"
                });
            }
        });
        assert_eq!(
            s.retest(&f, &revoked_rest, NOW).unwrap().verdict,
            Verdict::Fixed
        );

        // Nothing found at all: can't tell.
        let nothing = reread(&["S-1-5-21-9-9-9-9".to_string()], |_| {});
        assert_eq!(
            s.retest(&f, &nothing, NOW).unwrap().verdict,
            Verdict::CantTell
        );
    }

    #[test]
    fn property_fixes_and_aggregates() {
        let s = slice();
        // AS-REP roasting: pre-authentication required again.
        let f = fp(&s, "PW-007");
        let fixed = reread(&refresh_of(&s, &f), |o| {
            o["Properties"]["dontreqpreauth"] = false.into();
        });
        assert_eq!(s.retest(&f, &fixed, NOW).unwrap().verdict, Verdict::Fixed);

        // LAPS on one of two computers: still open, 1 of 2 remain.
        let f = fp(&s, "PW-011");
        let ids = refresh_of(&s, &f);
        let first = s.finding(&f).unwrap().affected[0].id.clone();
        let one = reread(&ids, |o| {
            if o["ObjectIdentifier"] == first.as_str() {
                o["Properties"]["haslaps"] = true.into();
            }
        });
        let r = s.retest(&f, &one, NOW).unwrap();
        assert_eq!(r.verdict, Verdict::StillOpen);
        assert!(
            r.details
                .contains(&"1 of 2 affected objects remain".to_string()),
            "{r:?}"
        );
        let both = reread(&ids, |o| {
            o["Properties"]["haslaps"] = true.into();
        });
        assert_eq!(s.retest(&f, &both, NOW).unwrap().verdict, Verdict::Fixed);

        // Tier Zero accounts in CHILD marked "sensitive": the delegation
        // finding there is fixed.
        let f = s
            .findings
            .iter()
            .find(|x| x.rule == "PW-008" && x.affected.iter().any(|a| a.id == CHILD_DA))
            .unwrap()
            .fingerprint
            .clone();
        let ids = refresh_of(&s, &f);
        let r = s.retest(&f, &reread(&ids, |_| {}), NOW).unwrap();
        assert_eq!(r.verdict, Verdict::StillOpen, "{r:?}");
        let sensitive = reread(&ids, |o| {
            o["Properties"]["sensitive"] = true.into();
        });
        assert_eq!(
            s.retest(&f, &sensitive, NOW).unwrap().verdict,
            Verdict::Fixed
        );
    }

    #[test]
    fn unsupported_rules_say_why() {
        let s = slice();
        let err = s
            .retest(&fp(&s, "PW-012"), &AdGraph::new(), NOW)
            .unwrap_err();
        assert!(err.contains("Collect again"), "{err}");
        assert!(s.retest("PW-999-0", &AdGraph::new(), NOW).is_err());
    }

    const SRV01: &str = "S-1-5-21-1000-1000-1000-1001";

    /// What the collector reports of SRV01: `sessions` and `groups` read
    /// or not.
    fn srv01(sessions: Option<bool>, groups: Option<bool>, unreachable: bool) -> HostReads {
        HostReads {
            reads: vec![HostRead {
                id: SRV01.into(),
                name: "SRV01.CONTOSO.LOCAL".into(),
                sessions,
                local_groups: groups,
                why: (sessions == Some(false) || groups == Some(false)).then(|| {
                    if unreachable {
                        "port 445 didn't answer".to_string()
                    } else {
                        "access denied".to_string()
                    }
                }),
                unreachable,
                skipped: false,
                ..Default::default()
            }],
            skipped: None,
            deleted: Vec::new(),
        }
    }

    /// SVC_SQL -[AdminTo]-> SRV01 -[HasSession]-> DA_ALICE: the path rests
    /// on SRV01's local groups and sessions.
    #[test]
    fn a_path_through_a_session_is_checked_on_its_computer() {
        let s = slice();
        let f = fp(&s, "PW-006");
        let sf = s.finding(&f).unwrap();
        assert_eq!(
            s.hosts_of(sf),
            [SliceHost {
                id: SRV01.into(),
                sessions: true,
                local_groups: true,
                ..Default::default()
            }]
        );
        let ids = refresh_of(&s, &f);
        assert!(ids.iter().any(|i| i == SRV01));

        // Read, and the session is still there: still open.
        let same = reread(&ids, |_| {});
        let r = s
            .retest_with(&f, &same, &srv01(Some(true), Some(true), false), NOW)
            .unwrap();
        assert_eq!(r.verdict, Verdict::StillOpen, "{r:?}");
        assert_eq!((r.hosts_read, r.hosts), (1, 1));

        // Read, and nobody is logged on: fixed.
        let logged_off = reread(&ids, |o| {
            if o["ObjectIdentifier"] == SRV01 {
                o["Sessions"]["Results"] = serde_json::json!([]);
            }
        });
        let r = s
            .retest_with(&f, &logged_off, &srv01(Some(true), Some(true), false), NOW)
            .unwrap();
        assert_eq!(r.verdict, Verdict::Fixed, "{r:?}");

        // Not reached: the slice's session decides nothing.
        let r = s
            .retest_with(&f, &logged_off, &srv01(Some(false), Some(false), true), NOW)
            .unwrap();
        assert_eq!(r.verdict, Verdict::CantTell, "{r:?}");
        assert_eq!(
            r.details,
            [
                "The computer on its path couldn't be reached, so it can't be checked.",
                "SRV01.CONTOSO.LOCAL: port 445 didn't answer."
            ]
        );
        assert_eq!(r.hosts_read, 0);

        // Local groups read and SVC_SQL no longer an administrator there:
        // fixed whatever the sessions, read or not.
        let no_admin = reread(&ids, |o| {
            if o["ObjectIdentifier"] == SRV01 {
                o["LocalGroups"] = serde_json::json!([{
                    "ObjectIdentifier": "S-1-5-21-1000-1000-1000-1001-544",
                    "Name": "ADMINISTRATORS@SRV01", "Results": [], "Collected": true
                }]);
            }
        });
        let r = s
            .retest_with(&f, &no_admin, &srv01(Some(false), Some(true), false), NOW)
            .unwrap();
        assert_eq!(r.verdict, Verdict::Fixed, "{r:?}");

        // Nothing read (the current Windows account): can't tell, and why.
        let r = s
            .retest_with(
                &f,
                &same,
                &HostReads {
                    reads: Vec::new(),
                    skipped: Some(HOSTS_NEED_PASSWORD.into()),
                    deleted: Vec::new(),
                },
                NOW,
            )
            .unwrap();
        assert_eq!(r.verdict, Verdict::CantTell);
        assert_eq!(r.details, [HOSTS_NEED_PASSWORD]);
    }

    /// Tier Zero sessions (PW-004) are read on the hosts it lists.
    #[test]
    fn tier_zero_sessions_are_read_on_their_hosts() {
        let s = slice();
        let f = fp(&s, "PW-004");
        let ids = refresh_of(&s, &f);
        let same = reread(&ids, |_| {});
        let read = srv01(Some(true), None, false);
        assert_eq!(
            s.retest_with(&f, &same, &read, NOW).unwrap().verdict,
            Verdict::StillOpen
        );
        let logged_off = reread(&ids, |o| {
            if o["ObjectIdentifier"] == SRV01 {
                o["Sessions"]["Results"] = serde_json::json!([]);
            }
        });
        assert_eq!(
            s.retest_with(&f, &logged_off, &read, NOW).unwrap().verdict,
            Verdict::Fixed
        );
        // Denied: can't tell, read not reached.
        let r = s
            .retest_with(&f, &logged_off, &srv01(Some(false), None, false), NOW)
            .unwrap();
        assert_eq!(r.verdict, Verdict::CantTell);
        assert!(r.details[0].contains("couldn't be read"), "{r:?}");

        // Skipped with Kerberos only: can't tell, naming the
        // computer and why it was skipped.
        let mut skipped = srv01(Some(false), None, false);
        skipped.reads[0].why = Some(crate::ingest::SKIP_NO_KERBEROS_NAME.into());
        skipped.reads[0].skipped = true;
        let r = s.retest_with(&f, &logged_off, &skipped, NOW).unwrap();
        assert_eq!(r.verdict, Verdict::CantTell);
        assert_eq!(
            r.details[1],
            "SRV01.CONTOSO.LOCAL was skipped: the domain has no Kerberos name for it."
        );
    }

    #[test]
    fn at_most_fifty_computers_are_read() {
        let mut s = slice();
        let f = fp(&s, "PW-006");
        let many: Vec<SliceHost> = (0..72)
            .map(|i| SliceHost {
                id: format!("S-1-5-21-1000-1000-1000-{}", 5000 + i),
                sessions: true,
                ..Default::default()
            })
            .collect();
        let sf = s.findings.iter_mut().find(|x| x.fingerprint == f).unwrap();
        sf.hosts = Some(many);
        let (asked, total) = s.host_targets(s.finding(&f).unwrap());
        assert_eq!((asked.len(), total), (MAX_HOSTS, 72));
        let unread: Vec<(&SliceHost, Option<&HostRead>)> =
            asked.iter().map(|h| (h, None)).collect();
        assert_eq!(
            unread_words(&unread, 72, &HostReads::default()),
            ["It has 72 computers on its path and a retest reads at most 50, so it can't be checked."]
        );
        assert_eq!(
            hosts_not_read(2, 3, true),
            "2 of 3 computers on its path couldn't be reached, so it can't be checked."
        );
    }

    #[test]
    fn ids_that_can_be_looked_up() {
        assert!(searchable("S-1-5-21-1-2-3-500"));
        assert!(searchable("2B9A4F6C-0E2A-4B8D-9E55-1C2D3E4F5A6B"));
        assert!(!searchable("CONTOSO.LOCAL-S-1-5-32-544"));
        assert!(!searchable("S-1-5-11"));
    }
}
