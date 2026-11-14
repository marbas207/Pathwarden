//! Tier Zero settings folders reviewed on this computer.
//!
//! `settings_folders` travels with the shared settings, but using a folder
//! does not: a folder another machine pushed is listed, and not read here,
//! until someone on this computer chooses to use it, as a mapping pack from
//! the repository is only labels until it is trusted here
//! ([`crate::pack_origin`]). Reading a folder makes this computer, and the
//! account a scheduled run uses, connect to it, so a folder someone else
//! picked must not be read without a look.
//!
//! This file, next to `pathwarden.toml` and never committed, lists the
//! folders added or reviewed here, and only those are used: an allow-list.
//! A folder that reached the settings any other way (the shared history,
//! a hand edit, a copied file) waits for Use, whether or not settings are
//! shared. Losing or breaking this file makes every folder wait again.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The file, next to `pathwarden.toml`.
pub const FILE: &str = ".pathwarden-folders-reviewed.json";

/// The folders reviewed (or added) on this computer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Reviewed {
    #[serde(default)]
    pub folders: Vec<ReviewedFolder>,
}

/// One folder used on this computer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewedFolder {
    pub path: String,
    /// When (RFC 3339, UTC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

/// A folder as compared: trimmed, without a trailing separator; on Windows
/// with `\` between parts and in any case (its paths ignore case), elsewhere
/// as written.
pub fn key(path: &str) -> String {
    let p = path.trim();
    if cfg!(windows) || p.starts_with(r"\\") {
        p.replace('/', "\\").trim_end_matches('\\').to_lowercase()
    } else {
        p.trim_end_matches('/').to_string()
    }
}

impl Reviewed {
    pub fn contains(&self, path: &str) -> bool {
        let k = key(path);
        self.folders.iter().any(|f| key(&f.path) == k)
    }
}

/// The record next to the `pathwarden.toml` in `dir`. None when there is
/// no file; a file that can't be read counts as no review at all.
pub fn load(dir: &Path) -> Reviewed {
    std::fs::read(dir.join(FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Marks `folders` used (or no longer) on this computer, for the
/// `pathwarden.toml` at `config_path`: what adding a folder here, and the
/// Settings page's Use, do. Written under the settings' save lock.
pub fn mark(config_path: &Path, folders: &[String], used: bool) -> Result<(), String> {
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    crate::config_edit::with_lock(config_path, || {
        let mut r = load(dir);
        for f in folders {
            let k = key(f);
            r.folders.retain(|x| key(&x.path) != k);
            if used {
                r.folders.push(ReviewedFolder {
                    path: f.trim().to_string(),
                    at: Some(crate::time::format_rfc3339(crate::analyze::now())),
                });
            }
        }
        let mut text = serde_json::to_string_pretty(&r).map_err(|e| e.to_string())?;
        text.push('\n');
        crate::config_edit::write_atomic(&dir.join(FILE), &text)
            .map_err(|e| format!("Could not write {}: {e}", dir.join(FILE).display()))
    })
}

/// Of `folders`, those the shared history carries (`from_repo`, as
/// [`key`]) and this computer hasn't reviewed (`reviewed`): listed, not
/// read.
pub fn unreviewed(folders: &[String], from_repo: &[String], reviewed: &Reviewed) -> Vec<String> {
    folders
        .iter()
        .filter(|f| from_repo.contains(&key(f)) && !reviewed.contains(f))
        .cloned()
        .collect()
}

/// The folders of `config` (read from `config_path`) not used on this
/// computer: every one that wasn't added or reviewed here. Using a folder
/// is an allow-list, so a folder that arrives any other way (the shared
/// settings, a hand edit, a copied file) waits, whether or not the shared
/// history is active. What the Settings page and `pathwarden config
/// settings-folders list` mark.
pub fn waiting(config: &crate::config::Config, config_path: &Path) -> Vec<String> {
    if config.settings_folders.is_empty() {
        return Vec::new();
    }
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    let reviewed = load(base);
    config
        .settings_folders
        .iter()
        .filter(|f| !reviewed.contains(f))
        .cloned()
        .collect()
}

/// Of `folders`, those the shared history carries
/// ([`crate::settings_sync::repo_settings_folders`]): how the Settings
/// page words a folder that waits.
pub fn from_repo(config: &crate::config::Config, config_path: &Path) -> Vec<String> {
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    let repo = crate::settings_sync::repo_settings_folders(&config.state, base);
    config
        .settings_folders
        .iter()
        .filter(|f| repo.contains(&key(f)))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_from_the_repository_waits_for_a_review_here() {
        let folders = vec![r"\\fs01\t0".to_string(), r"D:\t0".to_string()];
        let repo = vec![key(r"\\FS01\t0\")];
        let mut r = Reviewed::default();
        assert_eq!(unreviewed(&folders, &repo, &r), [r"\\fs01\t0"]);
        r.folders.push(ReviewedFolder {
            path: r"\\FS01\t0\".into(),
            at: None,
        });
        assert!(unreviewed(&folders, &repo, &r).is_empty());
        // Not in the repository: used, reviewed or not.
        assert!(unreviewed(&folders, &[], &Reviewed::default()).is_empty());
    }
}
