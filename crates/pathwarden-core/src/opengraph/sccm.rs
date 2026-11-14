//! ConfigManBearPig correction (`corrections = ["sccm"]`): SCCM sites
//! re-keyed per hierarchy.
//!
//! ConfigManBearPig keys an `SCCM_Site` node by its bare site code (`PS1`),
//! and the objects that belong to a site by `<name>@<site code>`
//! (`CORP\ALICE@PS1`, `SMS00001@PS1`). Site codes are three characters and
//! the defaults repeat (`PS1`, `CAS`), so two hierarchies in one analysis
//! (two forests, two collections) merge into one site, and an edge written
//! for one would attach to the other.
//!
//! The reader therefore gives each site an ID of its own,
//! `<site code>@<site server>` (the site server's FQDN, or its name or the
//! site GUID when that is all the file says), and rewrites every ID and
//! edge end that names a site code accordingly:
//!
//! - A site code is looked up first among the sites of the same
//!   collection (the same `.zip`, or the same folder), then among all sites
//!   read. One site: rewritten. Several: the reference is **ambiguous** and
//!   the edge is skipped (counted as unresolved), never attached to a guess.
//! - Each site records its hierarchy (the re-keyed ID of its root site), and
//!   so does every object re-keyed through it. An edge between objects of
//!   two different hierarchies is context only.

use std::collections::HashMap;

/// One site, as its node in a file describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteInfo {
    /// The bare site code the file uses (`PS1`).
    pub code: String,
    /// The code of its hierarchy's root site (its CAS, or itself).
    pub root: String,
    /// What tells this site apart from another with the same code: its
    /// site server (FQDN or name) or site GUID.
    pub server: Option<String>,
}

#[derive(Debug, Clone)]
struct Site {
    id: String,
    root_code: String,
}

/// What a reference to a site resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rekeyed {
    /// Not a site reference: use the ID as it is.
    Same,
    /// The re-keyed ID, and the hierarchy it belongs to.
    New { id: String, hierarchy: String },
    /// A site code that more than one site has: skip it.
    Ambiguous,
}

/// Every site read, by collection.
#[derive(Debug, Default, Clone)]
pub struct SiteMap {
    /// scope → code → sites.
    scopes: HashMap<String, HashMap<String, Vec<Site>>>,
    /// code → sites, every scope.
    all: HashMap<String, Vec<Site>>,
}

/// The collection a file belongs to: its `.zip`, or its folder.
pub fn scope_of(label: &str) -> String {
    if let Some((zip, _)) = label.split_once('!') {
        return zip.to_ascii_uppercase();
    }
    match label.rfind(['/', '\\']) {
        Some(at) => label[..at].to_ascii_uppercase(),
        None => String::new(),
    }
}

fn norm(s: &str) -> String {
    s.trim().to_ascii_uppercase()
}

impl SiteMap {
    pub fn is_empty(&self) -> bool {
        self.all.is_empty()
    }

    /// Records a site read in `scope`.
    pub fn add(&mut self, scope: &str, site: &SiteInfo) {
        let code = norm(&site.code);
        if code.is_empty() || code.contains('@') {
            return;
        }
        let server = site
            .server
            .as_deref()
            .map(norm)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                format!(
                    "COLLECTION {}",
                    crate::findings::fingerprint("scope", &[scope])
                )
            });
        let id = format!("{code}@{server}");
        let root = norm(&site.root);
        let entry = Site {
            id: id.clone(),
            root_code: if root.is_empty() { code.clone() } else { root },
        };
        let list = self
            .scopes
            .entry(norm(scope))
            .or_default()
            .entry(code.clone())
            .or_default();
        if !list.iter().any(|s| s.id == id) {
            list.push(entry.clone());
        }
        let all = self.all.entry(code).or_default();
        if !all.iter().any(|s| s.id == id) {
            all.push(entry);
        }
    }

    /// The one site `code` names, from `scope` first.
    fn site(&self, scope: &str, code: &str) -> Option<Result<&Site, ()>> {
        fn pick(list: &[Site]) -> Result<&Site, ()> {
            match list {
                [one] => Ok(one),
                _ => Err(()),
            }
        }
        if let Some(list) = self.scopes.get(&norm(scope)).and_then(|m| m.get(code)) {
            return Some(pick(list));
        }
        self.all.get(code).map(|l| pick(l))
    }

    /// The hierarchy of a site: its root site's re-keyed ID (or the root
    /// code, when the root site is not in the data).
    fn hierarchy(&self, scope: &str, site: &Site) -> String {
        if site.root_code == site.id.split('@').next().unwrap_or_default() {
            return site.id.clone();
        }
        match self.site(scope, &site.root_code) {
            Some(Ok(root)) => root.id.clone(),
            _ => format!("{}@?", site.root_code),
        }
    }

    /// Re-keys an ID read in `scope`: a bare site code, or
    /// `<name>@<site code>`.
    pub fn rekey(&self, scope: &str, id: &str) -> Rekeyed {
        if self.all.is_empty() {
            return Rekeyed::Same;
        }
        let up = norm(id);
        let (prefix, code) = match up.rsplit_once('@') {
            Some((p, c)) if !p.is_empty() => (Some(p), c),
            Some(_) => return Rekeyed::Same,
            None => (None, up.as_str()),
        };
        let Some(found) = self.site(scope, code) else {
            return Rekeyed::Same;
        };
        let Ok(site) = found else {
            return Rekeyed::Ambiguous;
        };
        let hierarchy = self.hierarchy(scope, site);
        let id = match prefix {
            Some(p) => format!("{p}@{}", site.id),
            None => site.id.clone(),
        };
        Rekeyed::New { id, hierarchy }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(code: &str, root: &str, server: &str) -> SiteInfo {
        SiteInfo {
            code: code.into(),
            root: root.into(),
            server: Some(server.into()),
        }
    }

    #[test]
    fn sites_are_rekeyed_per_collection() {
        let mut m = SiteMap::default();
        m.add("A.ZIP", &site("CAS", "CAS", "cas.a.local"));
        m.add("A.ZIP", &site("PS1", "CAS", "ps1.a.local"));
        m.add("B.ZIP", &site("PS1", "PS1", "ps1.b.local"));
        // In its own collection, a code is one site.
        assert_eq!(
            m.rekey("a.zip", "PS1"),
            Rekeyed::New {
                id: "PS1@PS1.A.LOCAL".into(),
                hierarchy: "CAS@CAS.A.LOCAL".into()
            }
        );
        assert_eq!(
            m.rekey("B.ZIP", "corp\\alice@ps1"),
            Rekeyed::New {
                id: "CORP\\ALICE@PS1@PS1.B.LOCAL".into(),
                hierarchy: "PS1@PS1.B.LOCAL".into()
            }
        );
        // Outside both, PS1 is two sites: ambiguous; CAS is one.
        assert_eq!(m.rekey("C.ZIP", "PS1"), Rekeyed::Ambiguous);
        assert!(matches!(
            m.rekey("C.ZIP", "SMS00001@CAS"),
            Rekeyed::New { .. }
        ));
        // Not site references.
        assert_eq!(m.rekey("A.ZIP", "S-1-5-21-1-2-3-1104"), Rekeyed::Same);
        assert_eq!(m.rekey("A.ZIP", "GUID:1A2B"), Rekeyed::Same);
        assert_eq!(
            m.rekey("A.ZIP", "SA@S-1-5-21-1-2-3-1109:1433"),
            Rekeyed::Same
        );
        assert_eq!(
            scope_of("C:\\x\\cmbp.zip!sccm_nodes-1.json"),
            "C:\\X\\CMBP.ZIP"
        );
        assert_eq!(scope_of("/data/cmbp/sccm_edges-1.json"), "/DATA/CMBP");
    }
}
