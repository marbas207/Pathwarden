//! MSSQLHound correction (`corrections = ["mssql"]`): what the reader fixes
//! in MSSQLHound data after every edge is read, because a per-edge mapping
//! can't express it. Reviewed against MSSQLHound 92efaeb
//! (`internal/collector/collector.go`, `internal/bloodhound/edges.go`).
//!
//! 1. **`public`.** Every login is a member of the server's `public` role,
//!    and every database user of its database's `public` role. MSSQLHound
//!    leaves `public` out of its own permission search, so a grant to
//!    `public` (`GRANT IMPERSONATE ON LOGIN::sa TO public`) can go unseen.
//!    The reader adds the missing `MSSQL_MemberOf` edges to `public` when
//!    the file has that role, so a grant to it reaches every login.
//! 2. **DENY.** MSSQLHound writes permission edges for GRANTs only, but
//!    lists a principal's permissions (DENY included) in
//!    `explicitPermissions`. A server-level permission listed there with no
//!    edge of its own is therefore denied. When a principal denied
//!    `CONTROL SERVER` or `IMPERSONATE ANY LOGIN` reaches a role whose only
//!    control is that permission, its membership of the role is context
//!    only: DENY wins over a GRANT through a role. Members of `sysadmin`
//!    are exempt (SQL Server checks no permission for them).
//! 3. **`MSSQL_ExecuteAsOwner`** (a TRUSTWORTHY database to its server) is
//!    kept only when the database's owner itself controls the server in the
//!    graph. MSSQLHound decides it from the owner's effective permissions,
//!    which count a DENY on a role as a grant.
//! 4. **`MSSQL_GetAdminTGS`** (a service account forging a ticket as an
//!    administrator) is kept only when an enabled login of a domain
//!    principal controls the server. MSSQLHound counts disabled logins.
//! 5. **`MSSQL_RunsAs`** (derived; server to its service account): when a
//!    domain user runs the service (`MSSQL_ServiceAccountFor`), whoever
//!    controls the instance runs code as that account (`xp_cmdshell`, SQL
//!    Agent jobs) and acts as it on the network.
//!
//! Every change only makes edges context only, or adds the derived and
//! `public` edges; the trust of the pack still decides whether any of them
//! is a path.

use std::collections::{HashSet, VecDeque};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use crate::graph::AdGraph;
use crate::kinds::{self, ExtKind};
use crate::model::{EdgeKind, NodeKind};
use crate::opengraph::EdgeOrigin;

/// What the correction changed, for the statistics.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Changes {
    pub public_added: usize,
    pub denied: usize,
    pub execute_as_owner: usize,
    pub admin_tgs: usize,
    pub runs_as: usize,
}

impl Changes {
    /// One line per change, for the data sources table.
    pub fn notes(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut note = |n: usize, what: &str| {
            if n > 0 {
                out.push(format!("MSSQLHound correction: {n} {what}"));
            }
        };
        note(self.public_added, "implicit membership(s) of public added");
        note(self.denied, "role membership(s) context only (DENY)");
        note(
            self.execute_as_owner,
            "MSSQL_ExecuteAsOwner context only (the owner does not control the server)",
        );
        note(
            self.admin_tgs,
            "MSSQL_GetAdminTGS context only (no enabled domain login controls the server)",
        );
        note(
            self.runs_as,
            "MSSQL_RunsAs derived from the service account",
        );
        out
    }
}

fn ext(name: &str) -> Option<ExtKind> {
    kinds::lookup(name)
}

fn is_kind(g: &AdGraph, ix: NodeIndex, name: &str) -> bool {
    matches!(g.node(ix).kind, NodeKind::External(k) if kinds::name(k) == name)
}

fn prop<'a>(g: &'a AdGraph, ix: NodeIndex, key: &str) -> Option<&'a serde_json::Value> {
    g.node(ix).ext.as_ref().and_then(|e| e.prop(key))
}

fn is_true(v: Option<&serde_json::Value>) -> bool {
    v.is_some_and(|v| crate::opengraph::pack::loosely_equal(v, &serde_json::Value::Bool(true)))
}

/// Whether `e`'s pack would make it a path once trusted.
fn declared(g: &AdGraph, kind: EdgeKind) -> bool {
    g.edge_sem(kind).is_some_and(|s| s.declared_traversable)
}

/// The edges `from -kind-> *`.
fn out_of(g: &AdGraph, from: NodeIndex, kind: ExtKind) -> Vec<NodeIndex> {
    g.inner()
        .edges_directed(from, Direction::Outgoing)
        .filter(|e| *e.weight() == EdgeKind::External(kind))
        .map(|e| e.target())
        .collect()
}

/// Whether `from` controls `server` through MSSQL relationships its pack
/// declares traversable, staying among MSSQL objects.
fn controls(g: &AdGraph, from: NodeIndex, server: NodeIndex) -> bool {
    let skip: HashSet<Option<ExtKind>> = [
        ext("MSSQL_ExecuteAsOwner"),
        ext("MSSQL_GetAdminTGS"),
        ext("MSSQL_RunsAs"),
    ]
    .into_iter()
    .filter(Option::is_some)
    .collect();
    let mut seen = HashSet::from([from]);
    let mut queue = VecDeque::from([from]);
    while let Some(u) = queue.pop_front() {
        if u == server {
            return true;
        }
        for e in g.inner().edges_directed(u, Direction::Outgoing) {
            let EdgeKind::External(k) = *e.weight() else {
                continue;
            };
            if skip.contains(&Some(k)) || !declared(g, *e.weight()) {
                continue;
            }
            let v = e.target();
            if !g.node(v).kind.is_external() {
                continue;
            }
            if seen.insert(v) {
                queue.push_back(v);
            }
        }
    }
    false
}

/// The `public` role of the server (or database) a principal's ID names:
/// `NAME@<server>` gives `PUBLIC@<server>`; `NAME@<server>\<db>` gives
/// `PUBLIC@<server>\<db>`.
fn public_of(id: &str) -> Option<String> {
    let (_, scope) = id.rsplit_once('@')?;
    (!scope.is_empty()).then(|| format!("PUBLIC@{scope}"))
}

/// Applies the correction to the MSSQL edges in `g`.
pub(crate) fn apply(g: &mut AdGraph) -> Changes {
    let mut c = Changes::default();
    let (Some(member_of), Some(_)) = (ext("MSSQL_MemberOf"), ext("MSSQL_Login")) else {
        return c;
    };
    if g.kind_table().edge(member_of).is_none() {
        return c;
    }
    add_public(g, member_of, &mut c);
    apply_deny(g, member_of, &mut c);
    check_execute_as_owner(g, &mut c);
    check_admin_tgs(g, &mut c);
    derive_runs_as(g, &mut c);
    c
}

/// Every login's (and database user's) membership of `public`, as the
/// derived, uncuttable `MSSQL_PublicMember`: MSSQLHound's own
/// `MSSQL_MemberOf` edges to `public` are re-kinded, and missing ones added.
fn add_public(g: &mut AdGraph, member_of: ExtKind, c: &mut Changes) {
    let Some(public_member) =
        ext("MSSQL_PublicMember").filter(|k| g.kind_table().edge(*k).is_some_and(|s| s.derived))
    else {
        return;
    };
    let mut add: Vec<(NodeIndex, NodeIndex, EdgeOrigin)> = Vec::new();
    let mut rekind: Vec<(NodeIndex, NodeIndex)> = Vec::new();
    for (ix, n) in g.nodes() {
        if !(is_kind(g, ix, "MSSQL_Login") || is_kind(g, ix, "MSSQL_DatabaseUser")) {
            continue;
        }
        let Some(public) = public_of(&n.id).and_then(|p| g.lookup(&p)) else {
            continue;
        };
        if public == ix || !out_of(g, ix, public_member).is_empty() {
            continue;
        }
        if out_of(g, ix, member_of).contains(&public) {
            rekind.push((ix, public));
            continue;
        }
        let Some(&source) = n.ext.as_ref().and_then(|e| e.sources.first()) else {
            continue;
        };
        add.push((ix, public, EdgeOrigin { source, unit: None }));
    }
    for (a, b) in rekind {
        g.rekind_og_edge(
            a,
            b,
            EdgeKind::External(member_of),
            EdgeKind::External(public_member),
        );
    }
    for (a, b, origin) in add {
        if g.add_og_edge(a, b, EdgeKind::External(public_member), origin) {
            c.public_added += 1;
        }
    }
}

/// Server-level permissions whose DENY the correction models, with the
/// edge kind a GRANT of each gets.
const DENIABLE: &[(&str, &str)] = &[
    ("CONTROL SERVER", "MSSQL_ControlServer"),
    ("IMPERSONATE ANY LOGIN", "MSSQL_ImpersonateAnyLogin"),
];

fn apply_deny(g: &mut AdGraph, member_of: ExtKind, c: &mut Changes) {
    let mut demote: Vec<(NodeIndex, NodeIndex)> = Vec::new();
    for (ix, n) in g.nodes() {
        if !(is_kind(g, ix, "MSSQL_Login") || is_kind(g, ix, "MSSQL_ServerRole")) {
            continue;
        }
        let Some(serde_json::Value::Array(perms)) = prop(g, ix, "explicitpermissions") else {
            continue;
        };
        let listed = |p: &str| {
            perms
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s.trim().eq_ignore_ascii_case(p)))
        };
        let denied: Vec<ExtKind> = DENIABLE
            .iter()
            .filter(|(perm, _)| listed(perm))
            .filter_map(|(_, kind)| ext(kind))
            .filter(|k| out_of(g, ix, *k).is_empty())
            .collect();
        if denied.is_empty() {
            continue;
        }
        // The closure of roles through membership, from each direct role.
        let roles_from = |start: NodeIndex| {
            let mut seen = HashSet::from([start]);
            let mut queue = VecDeque::from([start]);
            while let Some(u) = queue.pop_front() {
                for v in out_of(g, u, member_of) {
                    if seen.insert(v) {
                        queue.push_back(v);
                    }
                }
            }
            seen
        };
        let sysadmin = public_of(&n.id)
            .map(|p| format!("SYSADMIN{}", &p["PUBLIC".len()..]))
            .and_then(|s| g.lookup(&s));
        if sysadmin.is_some_and(|s| roles_from(ix).contains(&s)) {
            continue;
        }
        for r in out_of(g, ix, member_of) {
            let mut controls = 0usize;
            let mut only_denied = true;
            for role in roles_from(r) {
                for e in g.inner().edges_directed(role, Direction::Outgoing) {
                    let EdgeKind::External(k) = *e.weight() else {
                        continue;
                    };
                    if k == member_of || !declared(g, *e.weight()) {
                        continue;
                    }
                    controls += 1;
                    if !denied.contains(&k) {
                        only_denied = false;
                    }
                }
            }
            if controls > 0 && only_denied {
                demote.push((ix, r));
            }
        }
    }
    let to = EdgeKind::External(kinds::context_alias(member_of));
    for (a, b) in demote {
        if g.rekind_og_edge(a, b, EdgeKind::External(member_of), to) {
            c.denied += 1;
        }
    }
}

fn check_execute_as_owner(g: &mut AdGraph, c: &mut Changes) {
    let (Some(kind), Some(owns)) = (ext("MSSQL_ExecuteAsOwner"), ext("MSSQL_Owns")) else {
        return;
    };
    let mut demote = Vec::new();
    for e in g.inner().edge_references() {
        if *e.weight() != EdgeKind::External(kind) {
            continue;
        }
        let (db, server) = (e.source(), e.target());
        let owners: Vec<NodeIndex> = g
            .inner()
            .edges_directed(db, Direction::Incoming)
            .filter(|i| *i.weight() == EdgeKind::External(owns))
            .map(|i| i.source())
            .filter(|&o| is_kind(g, o, "MSSQL_Login"))
            .collect();
        if !owners.iter().any(|&o| controls(g, o, server)) {
            demote.push((db, server));
        }
    }
    let to = EdgeKind::External(kinds::context_alias(kind));
    for (a, b) in demote {
        if g.rekind_og_edge(a, b, EdgeKind::External(kind), to) {
            c.execute_as_owner += 1;
        }
    }
}

fn check_admin_tgs(g: &mut AdGraph, c: &mut Changes) {
    let (Some(kind), Some(has_login)) = (ext("MSSQL_GetAdminTGS"), ext("MSSQL_HasLogin")) else {
        return;
    };
    let mut demote = Vec::new();
    for e in g.inner().edge_references() {
        if *e.weight() != EdgeKind::External(kind) {
            continue;
        }
        let server = e.target();
        let suffix = format!("@{}", g.node(server).id);
        let admin = g.nodes().any(|(l, n)| {
            is_kind(g, l, "MSSQL_Login")
                && n.id.ends_with(&suffix)
                && !is_true(prop(g, l, "disabled"))
                && g.inner().edges_directed(l, Direction::Incoming).any(|i| {
                    *i.weight() == EdgeKind::External(has_login)
                        && !g.node(i.source()).kind.is_external()
                })
                && controls(g, l, server)
        });
        if !admin {
            demote.push((e.source(), server));
        }
    }
    let to = EdgeKind::External(kinds::context_alias(kind));
    for (a, b) in demote {
        if g.rekind_og_edge(a, b, EdgeKind::External(kind), to) {
            c.admin_tgs += 1;
        }
    }
}

fn derive_runs_as(g: &mut AdGraph, c: &mut Changes) {
    let (Some(sa_for), Some(runs_as)) = (ext("MSSQL_ServiceAccountFor"), ext("MSSQL_RunsAs"))
    else {
        return;
    };
    if g.kind_table().edge(runs_as).is_none() {
        return;
    }
    let mut add = Vec::new();
    for e in g.inner().edge_references() {
        if *e.weight() != EdgeKind::External(sa_for) {
            continue;
        }
        let (account, server) = (e.source(), e.target());
        // A domain user. The server's own computer account (a virtual or
        // built-in service account) is the host's identity: that is
        // MSSQL_ExecuteOnHost's business.
        if g.node(account).kind != NodeKind::User || !is_kind(g, server, "MSSQL_Server") {
            continue;
        }
        if let Some(origin) = g.edge_origin(e.id()) {
            add.push((server, account, origin.clone()));
        }
    }
    for (a, b, origin) in add {
        if g.add_og_edge(a, b, EdgeKind::External(runs_as), origin) {
            c.runs_as += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_roles() {
        assert_eq!(
            public_of("CORP\\ALICE@S-1-5-21-1-2-3-1109:1433").as_deref(),
            Some("PUBLIC@S-1-5-21-1-2-3-1109:1433")
        );
        assert_eq!(
            public_of("DBO@S-1-5-21-1-2-3-1109:1433\\CM_PS1").as_deref(),
            Some("PUBLIC@S-1-5-21-1-2-3-1109:1433\\CM_PS1")
        );
        assert_eq!(public_of("NOSERVER"), None);
    }
}
