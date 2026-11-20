//! The mapping packs a config puts in effect, and marking one trusted
//! (`[opengraph] trust`): shared by the app's Mappings page and
//! `pathwarden mappings`, so both list the same packs and refuse with the
//! same words.

use std::path::Path;

use crate::config::Config;
use crate::opengraph::pack::{self, EdgeView, Pack};
use crate::text::{count, num};

/// A pack as Mappings lists it.
#[derive(Debug, Clone)]
pub struct PackEntry {
    pub pack: Pack,
    /// `None` for a built-in pack, else the `[[mapping]]` path.
    pub path: Option<String>,
    /// Trusted because `[opengraph] trust` names it (not the pack itself).
    pub trusted_by_config: bool,
    /// Written by a sync from the shared history: trusted only when someone
    /// here reviewed it at this text ([`crate::pack_origin`]).
    pub from_repo: Option<crate::pack_origin::RepoPack>,
}

impl PackEntry {
    /// How far the pack is trusted, as Mappings labels it.
    pub fn trust_label(&self) -> &'static str {
        if self.from_repo.is_some() {
            if self.pack.trusted() {
                "From the repository · trusted here"
            } else {
                "From the repository · not trusted here"
            }
        } else if !self.pack.trusted() {
            "Untrusted mapping: context only"
        } else if self.trusted_by_config {
            "Trusted by you"
        } else {
            "Trusted"
        }
    }

    /// Where the pack comes from: "Built in", or "Your pack (<file name>)".
    pub fn origin(&self) -> String {
        match (&self.path, &self.from_repo) {
            (None, _) => "Built in".to_string(),
            (Some(_), Some(_)) => "From the repository".to_string(),
            (Some(path), None) => format!(
                "Your pack ({})",
                std::path::Path::new(path)
                    .file_name()
                    .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned())
            ),
        }
    }

    /// What the pack maps, in one line: "3 object kinds · 2 relationship
    /// kinds, 1 of them attack paths once trusted". Empty when it maps
    /// nothing.
    pub fn summary(&self) -> String {
        let p = &self.pack;
        let nodes = p.node_views().len();
        let edges = p.edge_views();
        let paths = edges.iter().filter(|e| e.traversable).count();
        let mut what = Vec::new();
        if nodes > 0 {
            what.push(count(nodes, "object kind", "object kinds"));
        }
        if !edges.is_empty() {
            // Untrusted, none of them is an attack path yet.
            let once = if p.trusted() { "" } else { " once trusted" };
            let tail = match paths {
                0 => String::new(),
                n if n == edges.len() && n == 1 => format!(", an attack path{once}"),
                n if n == edges.len() => format!(", all attack paths{once}"),
                n => format!(", {} of them attack paths{once}", num(n)),
            };
            what.push(format!(
                "{}{tail}",
                count(edges.len(), "relationship kind", "relationship kinds")
            ));
        }
        what.join(" · ")
    }

    /// What a relationship kind of this pack is, as its card labels it:
    /// "Attack path", "Path once trusted" or "Context only".
    pub fn edge_role(&self, e: &EdgeView) -> &'static str {
        match (e.traversable, self.pack.trusted()) {
            (true, true) => "Attack path",
            (true, false) => "Path once trusted",
            (false, _) => "Context only",
        }
    }
}

/// The facts the card lists after a relationship kind: cost, whether it is
/// cut, the rule that reports it, its coverage unit and when it is context
/// only.
pub fn edge_facts(e: &EdgeView) -> Vec<String> {
    let mut facts = Vec::new();
    if e.traversable {
        facts.push(format!("path weight {}", e.cost));
        if !e.cuttable {
            facts.push("fixed elsewhere in the remediation path".into());
        }
    }
    if let Some(r) = &e.rule {
        facts.push(format!("reported by {r}"));
    }
    facts.push(format!("coverage per {}", e.unit));
    for u in &e.unless {
        facts.push(format!("context only when {u}"));
    }
    facts
}

/// A fix template as plain text: `{from}` and `{to}` read "start" and
/// "end" (the objects the relationship goes from and to), `{source}` the
/// pack's title. The page marks the two words up; the terminal prints this.
pub fn fix_text(template: &str, source: &str) -> String {
    template
        .replace("{from}", "start")
        .replace("{to}", "end")
        .replace("{source}", source)
}

/// The packs in effect for `config` (built-in, then `[[mapping]]` read
/// relative to `base`, trust applied), and the `[[mapping]]` packs that
/// were refused, with why.
pub fn packs_in_effect(config: &Config, base: &Path) -> (Vec<PackEntry>, Vec<(String, String)>) {
    let mut out: Vec<PackEntry> = pack::embedded()
        .iter()
        .map(|p| PackEntry {
            pack: p.clone(),
            path: None,
            trusted_by_config: false,
            from_repo: None,
        })
        .collect();
    let mut refused = Vec::new();
    for (path, read, from_repo) in config.read_user_packs(base) {
        match read {
            Ok(p) => out.push(PackEntry {
                pack: p,
                path: Some(path),
                trusted_by_config: false,
                from_repo,
            }),
            Err(e) => refused.push((path, e)),
        }
    }
    for e in &mut out {
        // Trust by name never reaches a pack from the repository.
        if e.from_repo.is_none() && !e.pack.trusted() && config.opengraph.trusts(e.pack.name()) {
            e.pack = e.pack.clone().with_trusted(true);
            e.trusted_by_config = true;
        }
    }
    (out, refused)
}

/// The message for trusting a pack without confirming the review.
pub const CONFIRM: &str = "Confirm that you reviewed the pack before trusting it.";

/// How a trust change is saved ([`trust_change`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustChange {
    /// Add the name to (or remove it from) `[opengraph] trust`.
    Name(String),
    /// A pack from the repository, at this `[[mapping]]` path: trusted on
    /// this computer, at the text it holds now
    /// ([`crate::pack_origin::mark_reviewed`]). The name is its name.
    Reviewed {
        path: String,
        name: String,
        /// The digest of the text it holds now.
        digest: Option<String>,
    },
}

/// [`trust_target`], for every pack: a pack from the repository is trusted
/// on this computer at the text it holds now, never by name.
pub fn trust_change(
    packs: &[PackEntry],
    name: &str,
    trusted: bool,
    confirmed: bool,
) -> Result<TrustChange, String> {
    let name = name.trim();
    let from_repo = packs.iter().find(|e| {
        e.pack.name().eq_ignore_ascii_case(name) && e.from_repo.is_some() && e.path.is_some()
    });
    if let Some(e) = from_repo {
        if trusted && !confirmed {
            return Err(CONFIRM.into());
        }
        return Ok(TrustChange::Reviewed {
            path: e.path.clone().unwrap_or_default(),
            name: e.pack.name().to_string(),
            digest: e.from_repo.as_ref().and_then(|r| r.current_sha256.clone()),
        });
    }
    trust_target(packs, name, trusted, confirmed).map(TrustChange::Name)
}

/// The pack name to add to (`trusted`) or remove from `[opengraph] trust`,
/// as the pack spells it, or why it can't be, in this order: the pack must
/// exist, a pack trusted by its own file is changed in that file, and
/// trusting needs `confirmed` (the review).
pub fn trust_target(
    packs: &[PackEntry],
    name: &str,
    trusted: bool,
    confirmed: bool,
) -> Result<String, String> {
    let name = name.trim();
    let Some(e) = packs
        .iter()
        .find(|e| e.pack.name().eq_ignore_ascii_case(name))
    else {
        return Err("There is no mapping pack by that name.".into());
    };
    if e.pack.trusted() && !e.trusted_by_config {
        return Err("That pack is trusted by its own file; edit the pack to change it.".into());
    }
    if trusted && !confirmed {
        return Err(CONFIRM.into());
    }
    Ok(e.pack.name().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_needs_a_review_and_a_pack_that_ships_untrusted() {
        let config = Config::default();
        let (packs, refused) = packs_in_effect(&config, Path::new("."));
        assert!(refused.is_empty());
        let untrusted = packs
            .iter()
            .find(|e| !e.pack.trusted())
            .expect("an untrusted built-in pack");
        let name = untrusted.pack.name().to_ascii_uppercase();
        assert_eq!(
            trust_target(&packs, &name, true, false),
            Err(CONFIRM.into())
        );
        assert_eq!(
            trust_target(&packs, &name, true, true).as_deref(),
            Ok(untrusted.pack.name())
        );
        // Removing trust needs no confirmation.
        assert!(trust_target(&packs, &name, false, false).is_ok());
        // An unknown pack is named as such, before any review is asked for.
        for trusted in [false, true] {
            assert!(trust_target(&packs, "no-such-pack", trusted, false)
                .unwrap_err()
                .contains("no mapping pack"));
        }
        if let Some(own) = packs.iter().find(|e| e.pack.trusted()) {
            assert!(trust_target(&packs, own.pack.name(), false, false)
                .unwrap_err()
                .contains("its own file"));
        }
    }
}
