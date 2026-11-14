//! Mapping packs that came from a shared history ([`crate::settings_sync`]).
//!
//! Trust never travels: a pack another machine pushed is only labels here
//! until someone on this computer reviews it and trusts it, and that trust
//! holds for the text they reviewed. This file, next to `pathwarden.toml`
//! and never committed, records which packs a sync wrote (path and the
//! digest of their text, who added them) and the digest each was trusted
//! at here, if it was. A pack whose text changes (another push) is
//! untrusted again until it is reviewed again; a pack's own `trusted =
//! true` and `[opengraph] trust` (by name) count for nothing here.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The file, next to `pathwarden.toml`.
pub const FILE: &str = ".pathwarden-packs-from-repo.json";

/// Every pack a sync wrote.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Origins {
    #[serde(default)]
    pub packs: Vec<RepoPack>,
}

/// One pack a sync wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoPack {
    /// As `[[mapping]] path` names it.
    pub path: String,
    /// [`text_digest`] of the text the sync wrote.
    pub sha256: String,
    /// Who pushed it, on which computer and when (the settings commit's
    /// record), for the Mappings page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_at: Option<String>,
    /// The digest of the text someone here reviewed and trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_sha256: Option<String>,
    /// Not in the file: the record of packs from the repository couldn't be
    /// read, so this pack (in `packs/`) is taken to be one, untrusted.
    #[serde(skip)]
    pub unreadable: bool,
    /// Not in the file: the digest of the text the pack holds now, which a
    /// review must name ([`mark_reviewed`]).
    #[serde(skip)]
    pub current_sha256: Option<String>,
}

/// A pack's text as compared: no byte order mark, LF line ends.
pub fn normalize(text: &str) -> String {
    text.trim_start_matches('\u{feff}').replace("\r\n", "\n")
}

/// The digest of a pack's [`normalize`]d text.
pub fn text_digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(normalize(text).as_bytes()))
}

/// A `[[mapping]] path` as compared: `/` between parts, any case.
pub fn path_key(path: &str) -> String {
    path.trim().replace('\\', "/").to_lowercase()
}

impl Origins {
    /// The record of the pack at `path`, when a sync wrote it.
    pub fn find(&self, path: &str) -> Option<&RepoPack> {
        let k = path_key(path);
        self.packs.iter().find(|p| path_key(&p.path) == k)
    }

    /// Whether the pack at `path`, now holding `text`, is trusted here:
    /// reviewed at exactly this text. `None` when no sync wrote it.
    pub fn trusted(&self, path: &str, text: &str) -> Option<bool> {
        self.find(path)
            .map(|p| p.reviewed_sha256.as_deref() == Some(text_digest(text).as_str()))
    }

    /// Records a pack a sync wrote; a review of earlier text stays recorded
    /// but no longer matches.
    pub fn record(&mut self, pack: RepoPack) {
        let k = path_key(&pack.path);
        match self.packs.iter_mut().find(|p| path_key(&p.path) == k) {
            Some(p) => {
                let reviewed = p.reviewed_sha256.take();
                *p = RepoPack {
                    reviewed_sha256: reviewed,
                    ..pack
                };
            }
            None => self.packs.push(pack),
        }
    }
}

/// The records next to the `pathwarden.toml` in `dir`: none when there is
/// no file; an error when there is one that can't be read, in which case
/// every pack in `packs/` counts as from the repository and untrusted
/// ([`crate::config::Config::read_user_packs`]): losing or breaking this
/// file never trusts a pack.
pub fn load(dir: &Path) -> Result<Origins, String> {
    match std::fs::read(dir.join(FILE)) {
        Ok(b) => serde_json::from_slice(&b)
            .map_err(|e| format!("{} can't be read: {e}", dir.join(FILE).display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Origins::default()),
        Err(e) => Err(format!("{} can't be read: {e}", dir.join(FILE).display())),
    }
}

/// Writes the records next to the `pathwarden.toml` in `dir`.
pub fn save(dir: &Path, origins: &Origins) -> Result<(), String> {
    let mut text = serde_json::to_string_pretty(origins).map_err(|e| e.to_string())?;
    text.push('\n');
    crate::config_edit::write_atomic(&dir.join(FILE), &text)
        .map_err(|e| format!("Could not write {}: {e}", dir.join(FILE).display()))
}

/// The message for a review of a pack whose text changed since.
pub const CHANGED_SINCE_REVIEW: &str =
    "The pack's text changed since it was shown (the repository may have sent a new one): review it again.";

/// Trusts (or stops trusting) the pack at `path` of the `pathwarden.toml`
/// at `config_path`, a pack from the repository, on this computer: what
/// `pathwarden mappings trust NAME --reviewed --digest SHA` and the
/// Mappings page's Mark as trusted do for such a pack. Trusting names the
/// digest of the text that was reviewed (`reviewed`, as Mappings and
/// `mappings show` give it): when the file holds other text now, nothing
/// is trusted. Written under the settings' save lock, so a sync writing the
/// pack meanwhile can't slip in between. A record lost or broken is made
/// again.
pub fn mark_reviewed(
    config_path: &Path,
    path: &str,
    trusted: bool,
    reviewed: Option<&str>,
) -> Result<(), String> {
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    crate::config_edit::with_lock(config_path, || {
        let mut o = load(dir).unwrap_or_default();
        let k = path_key(path);
        let text = std::fs::read_to_string(dir.join(path.trim()))
            .map_err(|e| format!("Could not read {path}: {e}"))?;
        let now = text_digest(&text);
        if trusted && reviewed.map(str::trim) != Some(now.as_str()) {
            return Err(CHANGED_SINCE_REVIEW.into());
        }
        if !o.packs.iter().any(|p| path_key(&p.path) == k) {
            o.packs.push(RepoPack {
                path: path.trim().to_string(),
                sha256: now.clone(),
                ..RepoPack::default()
            });
        }
        if let Some(p) = o.packs.iter_mut().find(|p| path_key(&p.path) == k) {
            p.reviewed_sha256 = trusted.then_some(now);
        }
        save(dir, &o)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_holds_for_the_reviewed_text_only() {
        let mut o = Origins::default();
        assert_eq!(o.trusted("packs/a.toml", "x"), None);
        o.record(RepoPack {
            path: "packs/a.toml".into(),
            sha256: text_digest("x"),
            ..Default::default()
        });
        assert_eq!(o.trusted("packs/A.toml", "x"), Some(false));
        o.packs[0].reviewed_sha256 = Some(text_digest("x\r\n"));
        assert_eq!(o.trusted(r"packs\a.toml", "x\n"), Some(true));
        assert_eq!(o.trusted("packs/a.toml", "x\n"), Some(true));
        // A new text from the repository keeps the old review, which no
        // longer matches.
        o.record(RepoPack {
            path: "packs/a.toml".into(),
            sha256: text_digest("y"),
            ..Default::default()
        });
        assert_eq!(o.trusted("packs/a.toml", "y"), Some(false));
    }
}
