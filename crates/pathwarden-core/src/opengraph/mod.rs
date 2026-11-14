//! BloodHound OpenGraph support: what specialist collectors (TaskHound,
//! MSSQLHound, ...) write, and how Pathwarden gives their kinds meaning.
//!
//! - [`pack`]: mapping packs (TOML, compiled in) decide which external edge
//!   kinds are traversable, what removing one costs, and its fix text. A
//!   data file never does.
//! - [`coverage`]: the `pathwarden.coverage.v1` sidecar that says which
//!   units (computers, instances) a collector really covered, so a missing
//!   finding can be told apart from missing data.
//! - The reader itself lives in [`crate::ingest`] (it shares the streaming
//!   machinery): it detects OpenGraph files, then stitches them onto the AD
//!   graph in two passes (nodes, then edges) after every AD file is read.
//!
//! See `docs/opengraph.md`.

pub mod coverage;
pub mod hosts;
pub mod mssql;
pub mod pack;
pub mod sccm;
pub mod trust;

use std::collections::HashMap;

use serde::Serialize;

use crate::kinds::ExtKind;
use crate::model::SourceId;

pub use pack::{EdgeSem, NodeSem, Pack, UnitRule};

/// Semantics of external kinds for one analysis, from the packs in effect.
#[derive(Debug, Clone, Default)]
pub struct KindTable {
    edges: HashMap<ExtKind, EdgeSem>,
    nodes: HashMap<ExtKind, NodeSem>,
    /// Packs in effect, in order.
    packs: Vec<PackInfo>,
}

/// A pack in effect, as recorded in a run.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PackInfo {
    pub name: String,
    pub title: String,
    pub version: u32,
    pub trusted: bool,
}

impl KindTable {
    pub fn edge(&self, k: ExtKind) -> Option<&EdgeSem> {
        self.edges.get(&k)
    }

    pub fn node(&self, k: ExtKind) -> Option<&NodeSem> {
        self.nodes.get(&k)
    }

    pub fn packs(&self) -> &[PackInfo] {
        &self.packs
    }

    /// The table for `packs`, in order: a later pack's entry for a kind
    /// replaces an earlier one's.
    pub fn from_packs(packs: &[Pack]) -> Self {
        let mut t = KindTable::default();
        for p in packs {
            t.packs.push(PackInfo {
                name: p.name().to_string(),
                title: p.title().to_string(),
                version: p.version(),
                trusted: p.trusted(),
            });
            for (k, sem) in p.edge_sems() {
                t.edges.insert(k, sem);
            }
            for (k, sem) in p.node_sems() {
                t.nodes.insert(k, sem);
            }
        }
        t
    }
}

/// Where an external edge came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeOrigin {
    pub source: SourceId,
    /// The coverage unit the edge depends on (an object ID), from the
    /// pack's `unit` rule; `None` when the whole source is the unit.
    pub unit: Option<String>,
}

/// The name-free key of a source in the state: a hash of its name.
pub fn source_key(name: &str) -> String {
    crate::findings::fingerprint("source", &[&name.trim().to_ascii_uppercase()])
}

/// The name-free key of one coverage unit of a source.
pub fn unit_key(source: &str, unit: &str) -> String {
    crate::findings::fingerprint(
        "unit",
        &[
            &source.trim().to_ascii_uppercase(),
            &unit.trim().to_ascii_uppercase(),
        ],
    )
}

/// The name-free key of a computer as a unit of a stored credentials source:
/// a [`unit_key`] marked as a computer's, so a later run can tell
/// that computer's absence from the directory (deleted, so it no longer
/// holds the credential) from its not being read.
pub fn host_unit_key(source: &str, host_id: &str) -> String {
    format!("{HOST_UNIT}{}", unit_key(source, host_id))
}

/// The mark of [`host_unit_key`].
pub const HOST_UNIT: &str = "h:";

pub use hosts::{LOCAL_GROUP_HOST, SESSION_HOST};

/// Whether `key` is a computer's unit: stored credentials
/// ([`host_unit_key`]), sessions or local groups ([`hosts`]).
pub fn is_host_key(key: &str) -> bool {
    key.starts_with(HOST_UNIT) || hosts::is_unit(key)
}

/// Whether `id` looks like a SID (`S-1-...`, optionally domain-prefixed
/// the SharpHound way).
pub fn is_sid_shaped(id: &str) -> bool {
    let (_, sid) = crate::sid::split_prefixed(id);
    let Some(rest) = sid.strip_prefix("S-1-") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('-')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_shapes() {
        assert!(is_sid_shaped("S-1-5-21-1-2-3-1104"));
        assert!(is_sid_shaped("CONTOSO.LOCAL-S-1-5-32-544"));
        assert!(!is_sid_shaped("S-1-"));
        assert!(!is_sid_shaped("S-1-5-21-x"));
        assert!(!is_sid_shaped("APP01.CONTOSO.LOCAL"));
        assert!(!is_sid_shaped("sa@S-1-5-21-1-2-3-1109:1433"));
    }
}
