//! External (OpenGraph) kind names, interned process-wide.
//!
//! OpenGraph files bring node and edge kinds Pathwarden does not know
//! (`TH_ScheduledTask`, `MSSQL_HasLogin`, ...). Each distinct name gets a
//! small [`ExtKind`] number so [`crate::model::NodeKind`] and
//! [`crate::model::EdgeKind`] stay `Copy` and cheap to compare in the
//! search loops. The table only grows and is capped at [`MAX_KINDS`]
//! names: past the cap every new name becomes [`OTHER`], so a hostile file
//! can't grow the memory of a long-running UI process.
//!
//! Names carry no meaning here. What a kind does (traversable, cost, fix
//! text) is decided per analysis by the mapping packs
//! ([`crate::opengraph::pack`]), never by the interner or the data file.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Most distinct names interned per process.
pub const MAX_KINDS: usize = 1024;

/// Every name past [`MAX_KINDS`] collapses into this one.
pub const OTHER_NAME: &str = "OG_Other";

/// An interned external kind name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExtKind(u16);

/// The kind every name past the cap becomes.
pub const OTHER: ExtKind = ExtKind(0);

/// Suffix of a context-only alias (see [`context_alias`]). A space can't
/// appear in a kind name read from a file, so no file can name an alias.
const CONTEXT_SUFFIX: &str = " (context)";

struct Table {
    names: Vec<&'static str>,
    by_name: HashMap<&'static str, ExtKind>,
    overflowed: usize,
}

fn table() -> &'static Mutex<Table> {
    static T: OnceLock<Mutex<Table>> = OnceLock::new();
    T.get_or_init(|| {
        let mut by_name = HashMap::new();
        by_name.insert(OTHER_NAME, OTHER);
        Mutex::new(Table {
            names: vec![OTHER_NAME],
            by_name,
            overflowed: 0,
        })
    })
}

fn lock() -> std::sync::MutexGuard<'static, Table> {
    table().lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether `name` is acceptable as a kind name in an OpenGraph file:
/// `^[A-Za-z0-9_]{1,64}$`, and not the reserved `tag_` prefix.
pub fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !name.to_ascii_lowercase().starts_with("tag_")
}

/// The kind for `name`, adding it if there is room. Past the cap it is
/// [`OTHER`] (and counted in [`overflowed`]).
pub fn intern(name: &str) -> ExtKind {
    let mut t = lock();
    if let Some(&k) = t.by_name.get(name) {
        return k;
    }
    if t.names.len() >= MAX_KINDS {
        t.overflowed += 1;
        return OTHER;
    }
    let leaked: &'static str = Box::leak(name.to_string().into_boxed_str());
    let k = ExtKind(t.names.len() as u16);
    t.names.push(leaked);
    t.by_name.insert(leaked, k);
    k
}

/// The kind already interned for `name`, without adding it.
pub fn lookup(name: &str) -> Option<ExtKind> {
    lock().by_name.get(name).copied()
}

/// The kind name equal to `name` ignoring case, if one is interned (for a
/// "did you mean" hint).
pub fn find_ignore_case(name: &str) -> Option<&'static str> {
    lock()
        .names
        .iter()
        .copied()
        .find(|n| n.eq_ignore_ascii_case(name))
}

/// The name of `k`.
pub fn name(k: ExtKind) -> &'static str {
    lock()
        .names
        .get(k.0 as usize)
        .copied()
        .unwrap_or(OTHER_NAME)
}

/// How many names were refused because the table was full.
pub fn overflowed() -> usize {
    lock().overflowed
}

/// A context-only twin of `k`: the same name with " (context)" appended.
/// Edges whose kind a pack maps, but that came from a source the pack does
/// not cover (or that fail the pack's `unless` condition), are kept under
/// this twin, which no pack can make traversable.
pub fn context_alias(k: ExtKind) -> ExtKind {
    let n = name(k);
    if n.ends_with(CONTEXT_SUFFIX) {
        return k;
    }
    intern(&format!("{n}{CONTEXT_SUFFIX}"))
}

/// Whether `k` is a context-only twin made by [`context_alias`].
pub fn is_context_alias(k: ExtKind) -> bool {
    name(k).ends_with(CONTEXT_SUFFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_validated() {
        assert!(valid_name("TH_RunsAs"));
        assert!(valid_name("MSSQL_HasLogin"));
        assert!(!valid_name(""));
        assert!(!valid_name("has space"));
        assert!(!valid_name("tag_Tier_Zero"));
        assert!(!valid_name(&"A".repeat(65)));
        assert!(!valid_name("<script>"));
    }

    #[test]
    fn interning_is_stable_and_aliases_are_distinct() {
        let a = intern("Test_KindA");
        assert_eq!(intern("Test_KindA"), a);
        assert_eq!(name(a), "Test_KindA");
        assert_eq!(lookup("Test_KindA"), Some(a));
        assert_eq!(lookup("Test_Never"), None);
        let c = context_alias(a);
        assert_ne!(c, a);
        assert!(is_context_alias(c));
        assert_eq!(context_alias(c), c);
        assert_eq!(name(c), "Test_KindA (context)");
    }
}
