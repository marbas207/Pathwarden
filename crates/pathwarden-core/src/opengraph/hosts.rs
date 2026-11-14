//! A computer's sessions and local groups as units: a finding that rests on
//! a session or a local group right on a computer, and a run that saw one,
//! hold until that computer's lists are read again (or it is gone).
//!
//! A unit is name-free: its kind's mark, a 64-bit hash of the computer's
//! ID (16 hex digits) and the list it stands for, `s:0123456789abcdefp`
//! for the privileged sessions list. A list is read again only when the
//! collector says so (`Collected: true`): a computer counts as read only
//! when every list read before is read now, so a list that fails alone
//! (privileged sessions as a non-admin) holds what it showed.

use petgraph::graph::{EdgeIndex, NodeIndex};

use crate::graph::AdGraph;
use crate::model::NodeKind;

/// The mark of a session unit.
pub const SESSION_HOST: &str = "s:";
/// The mark of a local group unit.
pub const LOCAL_GROUP_HOST: &str = "l:";
/// After a mark: every computer of that kind, for a finding that rests on
/// more than it lists ([`crate::findings::MAX_HOST_REQUIRES`]).
pub const ANY_HOST: &str = "*";
/// The list of a unit that stands for any list of its kind: read once any
/// is. A finding's computer whose lists of the kind none was read when it
/// was seen.
pub const ANY_LIST: char = '*';
/// As [`ANY_LIST`], for a computer recorded on the first run after an
/// upgrade from a version that didn't record computers: it holds the
/// findings that don't say which computers they rest on, not the reach
/// findings.
pub const SEEDED: char = '~';

/// Session lists ([`crate::model::Props::host_lists`]): bit and unit
/// letter. Sessions, privileged sessions, registry sessions.
pub const SESSION_LISTS: [(u8, char); 3] = [(1, 's'), (2, 'p'), (4, 'r')];
/// Local group lists: Administrators (544), Remote Desktop Users (555),
/// Distributed COM Users (562), Remote Management Users (580).
pub const GROUP_LISTS: [(u8, char); 4] = [(8, 'a'), (16, 'r'), (32, 'd'), (64, 'p')];
/// Every session list's bit.
pub const SESSION_BITS: u8 = 7;
/// Every local group list's bit.
pub const GROUP_BITS: u8 = 120;

/// The local group list bit of a local group's RID.
pub fn group_bit(rid: u32) -> Option<u8> {
    match rid {
        544 => Some(8),
        555 => Some(16),
        562 => Some(32),
        580 => Some(64),
        _ => None,
    }
}

fn lists(mark: &str) -> &'static [(u8, char)] {
    if mark == SESSION_HOST {
        &SESSION_LISTS
    } else {
        &GROUP_LISTS
    }
}

/// The bits of `mark`'s kind.
pub fn kind_bits(mark: &str) -> u8 {
    if mark == SESSION_HOST {
        SESSION_BITS
    } else {
        GROUP_BITS
    }
}

/// A 64-bit hash of a computer's ID, as 16 hex digits.
pub fn host_hash(id: &str) -> String {
    let f = crate::findings::fingerprint("host", &[&id.trim().to_ascii_uppercase()]);
    f.rsplit('-').next().unwrap_or_default().to_string()
}

/// The units of computer `id` for `mark`'s kind: one per list `bits` says
/// was read, or [`ANY_LIST`]'s when none was.
pub fn units(id: &str, mark: &str, bits: u8) -> Vec<String> {
    units_of_hash(&host_hash(id), mark, bits)
}

/// [`units`] of the computer whose [`host_hash`] is `h`.
pub fn units_of_hash(h: &str, mark: &str, bits: u8) -> Vec<String> {
    let read: Vec<String> = lists(mark)
        .iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, c)| format!("{mark}{h}{c}"))
        .collect();
    if read.is_empty() {
        vec![format!("{mark}{h}{ANY_LIST}")]
    } else {
        read
    }
}

/// The unit that stands for every list of `mark`'s kind of computer `id`,
/// with `list` [`ANY_LIST`] or [`SEEDED`].
pub fn any_unit(id_hash: &str, mark: &str, list: char) -> String {
    format!("{mark}{id_hash}{list}")
}

/// A unit's mark, computer hash and list letter; `None` for anything else
/// (a stored credential unit, an [`ANY_HOST`] unit).
pub fn parse(u: &str) -> Option<(&'static str, &str, char)> {
    let mark = if u.starts_with(SESSION_HOST) {
        SESSION_HOST
    } else if u.starts_with(LOCAL_GROUP_HOST) {
        LOCAL_GROUP_HOST
    } else {
        return None;
    };
    let rest = &u[mark.len()..];
    if rest.len() != 17 || !rest.is_char_boundary(16) {
        return None;
    }
    let (h, c) = rest.split_at(16);
    Some((mark, h, c.chars().next()?))
}

/// Whether `u` is a session or local group unit, or an [`ANY_HOST`] one.
pub fn is_unit(u: &str) -> bool {
    u.starts_with(SESSION_HOST) || u.starts_with(LOCAL_GROUP_HOST)
}

/// The bit of a unit's list letter in `mark`'s kind; every bit of the kind
/// for [`ANY_LIST`] and [`SEEDED`].
pub fn list_bit(mark: &str, c: char) -> u8 {
    lists(mark)
        .iter()
        .find(|(_, l)| *l == c)
        .map_or(kind_bits(mark), |(b, _)| *b)
}

/// The computer an edge rests on, and its kind's mark: the computer of a
/// session (HasSession, from the computer), or the member computer whose
/// local groups grant an admin or logon right (AdminTo, CanRDP,
/// CanPSRemote, ExecuteDCOM, to the computer). A domain controller's
/// rights come from the directory, not from reading the computer.
pub(crate) fn edge_host(g: &AdGraph, e: EdgeIndex) -> Option<(NodeIndex, &'static str)> {
    let (from, to) = g.inner().edge_endpoints(e)?;
    host_of(g, from, g.inner()[e], to)
}

/// [`edge_host`] of an edge of `kind` from `from` to `to`.
pub(crate) fn host_of(
    g: &AdGraph,
    from: NodeIndex,
    kind: crate::model::EdgeKind,
    to: NodeIndex,
) -> Option<(NodeIndex, &'static str)> {
    let parts = crate::posture::Untargeted::of_edge(kind);
    if parts.sessions {
        let n = g.node(from);
        (n.kind == NodeKind::Computer && !n.placeholder).then_some((from, SESSION_HOST))
    } else if parts.local_groups {
        crate::posture::local_groups_on_host(g, to).then_some((to, LOCAL_GROUP_HOST))
    } else {
        None
    }
}

/// The units of the computer an edge rests on ([`edge_host`]), by the lists
/// read on it.
pub(crate) fn edge_units(g: &AdGraph, e: EdgeIndex) -> Vec<String> {
    match edge_host(g, e) {
        Some((ix, mark)) => {
            let n = g.node(ix);
            units(&n.id, mark, n.props.host_lists)
        }
        None => Vec::new(),
    }
}

/// How many computers `keys` name (units of one computer's lists count
/// once).
pub fn computers<'a>(keys: impl IntoIterator<Item = &'a String>) -> usize {
    keys.into_iter()
        .filter_map(|k| parse(k).map(|(m, h, _)| (m, h)))
        .collect::<std::collections::HashSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_are_short_and_read_back() {
        let u = units("S-1-5-21-1-2-3-1001", SESSION_HOST, 1 | 2);
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].len(), 2 + 16 + 1);
        let (m, h, c) = parse(&u[1]).unwrap();
        assert_eq!((m, h.len(), c), (SESSION_HOST, 16, 'p'));
        assert_eq!(list_bit(m, c), 2);
        let none = units("s-1-5-21-1-2-3-1001", LOCAL_GROUP_HOST, 1);
        assert!(none[0].ends_with(ANY_LIST), "no local group list read");
        assert_eq!(list_bit(LOCAL_GROUP_HOST, ANY_LIST), GROUP_BITS);
        assert_eq!(parse("s:*"), None);
        assert_eq!(computers(&[u[0].clone(), u[1].clone(), none[0].clone()]), 2);
    }
}
