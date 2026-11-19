//! The environment's shared settings travel through the history repository:
//! Tier Zero additions, rule settings, accepted risks with
//! who accepted them, zones, management planes and mapping packs
//! ([`config_edit::SHARED_SECTIONS`]), in `settings/pathwarden.toml` on the
//! state branch, with `settings/environment.json` saying what the
//! environment is and which Pathwarden wrote them.
//!
//! It is on when the history is a git repository and keeps "Full runs and
//! settings" (`[state] keep = "full"`). Each section is settled on its own,
//! and a section changed on both sides entry by entry (`settings_merge.rs`):
//!
//! - **A machine that pushes** commits a change to the shared settings as
//!   soon as it is saved (the app, `pathwarden config`, `pathwarden zones`):
//!   "pathwarden settings: 1 Tier Zero addition", with git's author and
//!   Pathwarden's own record of who made it on which computer.
//! - **On every pull** each section here and in the repository is compared
//!   with what it was at the last sync (`.git/pathwarden-settings-base.json`,
//!   never committed): changed in the repository only, the repository's is
//!   applied here; changed here only (an offline edit, a push that failed),
//!   it is pushed, on top of the repository's other sections; changed on
//!   both sides, it is merged entry by entry (a Tier Zero object, an
//!   accepted risk, a zone, a single rule setting, ...): each side's
//!   changes to different entries go to the other. Only an entry changed
//!   to different values on both sides, or changed on one and removed on
//!   the other, is a clash ([`Clash`]): it keeps this computer's value
//!   here and the repository's there until `pathwarden config sync
//!   --use-repo` or `--keep-local` (or the app's choice next to it)
//!   settles it. Runs go on with the settings here. A section this version
//!   can't take apart, or whose last sync isn't known, is settled whole.
//! - **A computer's first sync** with a history (a section never synced
//!   here) has nothing to compare against: every section the repository
//!   holds is applied here, whatever this computer had (a new install's
//!   default `[rules]` among them), and sections only this computer has are
//!   kept and pushed (on a reader, kept and recorded as absent, so a shared
//!   version later differs from the shared ones until someone chooses). Before anything of this computer's
//!   is replaced, its `pathwarden.toml` and the mapping packs replaced are
//!   saved beside them as `<file>.before-connect-<date>`; a copy that fails
//!   changes nothing. One line says what was taken and where the copies are
//!   ([`first_sync_words`]). After that, a change on one side is a change;
//!   a base file that can't be read is not a first sync.
//! - **A machine that only reads** (`[state] push = false`) may change the
//!   shared settings here: those sections are reported as changed here, not
//!   in the repository, and stay; the other sections follow the
//!   repository. `--use-repo` drops the changes here.
//!
//! Settings are applied through [`config_edit`]: under the save lock, with
//! the file's comments, the other sections and its line ends kept. Every
//! read and write of the repository's files goes through
//! [`Store::read_state_file`] / [`Store::write_state_file`]. Mapping packs
//! that arrive are never trusted here until reviewed here
//! ([`crate::pack_origin`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Keep, StateBackend, StateConfig};
use crate::config_edit::{self, ConfigDoc, MAPPING_FILES, NEVER_SHARED, SHARED_SECTIONS};
use crate::store::{KeptUnpushed, Published, Store, ENVIRONMENT_FILE, SETTINGS_FILE};

#[path = "settings_merge.rs"]
mod merge;
use merge::{Pick, Split};

/// This Pathwarden's version, as `environment.json` records the writer's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What `settings/pathwarden.toml` starts with.
const HEADER: &str = "# The shared settings of this environment, written by Pathwarden from \
pathwarden.toml\n# (Tier Zero additions, rule settings, accepted risks, zones, management \
planes, mapping packs).\n# Change them in Pathwarden (Settings, or `pathwarden config`) on a \
machine that pushes:\n# Pathwarden replaces this file on every change.\n";

/// In `.git`: each section as it was at the last sync.
const BASE_FILE: &str = "pathwarden-settings-base.json";

/// In `.git`: what the last sync applied here, for the app to say once.
const APPLIED_FILE: &str = "pathwarden-settings-applied.json";

/// In `.git`: the differences this computer's app was told about and
/// dismissed ([`dismiss`]), by [`Status::differs_key`]. Never committed.
const DISMISSED_FILE: &str = "pathwarden-settings-dismissed.json";

/// In `.git`: the entries the last merge brought here from the
/// repository ([`MergedHere`]). Never committed.
const MERGED_FILE: &str = "pathwarden-settings-merged.json";

/// Largest `settings/pathwarden.toml` read.
const MAX_SETTINGS_BYTES: usize = 4 << 20;

/// Largest `settings/environment.json` read.
const MAX_ENVIRONMENT_BYTES: usize = 64 << 10;

/// Most packs that travel inside the settings file.
const MAX_MAPPING_FILES: usize = 32;

/// The folder (next to `pathwarden.toml`) mapping packs travel from and to.
pub const PACKS_DIR: &str = "packs";

/// Why settings don't travel through this history, or `None` when they do.
pub fn inactive(state: &StateConfig) -> Option<&'static str> {
    if state.backend != StateBackend::Git {
        return Some(
            "Settings are shared only through a history in a git repository; this history is a \
             folder.",
        );
    }
    if state.keep() != Keep::Full {
        return Some(
            "The history keeps numbers with names, so settings are not shared. They travel with \
             \"Full runs and settings\" ([state] keep = \"full\").",
        );
    }
    None
}

/// Where a `[state] path` is, for a `pathwarden.toml` whose relative paths
/// start at `base`: the configured folder, or `pathwarden-state`.
pub fn state_dir(state: &StateConfig, base: &Path) -> PathBuf {
    let p = state
        .path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or("pathwarden-state");
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

/// The `[[mapping]]` paths (as [`crate::pack_origin::path_key`]) of packs
/// the shared history owns, for a `pathwarden.toml` whose relative paths
/// start at `base`: those the repository's settings carry in the working
/// copy, and those of the last sync. Data the sync owns, so a pack's trust
/// never rests on a file next to `pathwarden.toml` alone.
pub fn repo_pack_paths(state: &StateConfig, base: &Path) -> Vec<String> {
    if inactive(state).is_some() {
        return Vec::new();
    }
    let dir = state_dir(state, base);
    let mut out = Vec::new();
    let small = |b: &Vec<u8>| b.len() <= MAX_SETTINGS_BYTES;
    if let Some(text) = crate::store::read_state_file(&dir, SETTINGS_FILE)
        .ok()
        .flatten()
        .filter(small)
        .and_then(|b| String::from_utf8(b).ok())
    {
        if let Ok(raw) = text.parse::<toml::Table>() {
            for key in ["mapping", MAPPING_FILES] {
                out.extend(
                    raw.get(key)
                        .and_then(toml::Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|t| t.as_table().and_then(mapping_path))
                        .map(crate::pack_origin::path_key),
                );
            }
        }
    }
    let base_file = dir.join(".git").join(BASE_FILE);
    if let Some(base) = std::fs::read(base_file)
        .ok()
        .and_then(|b| serde_json::from_slice::<Base>(&b).ok())
    {
        let mapping = base.sections.get("mapping").and_then(|s| s.value.as_ref());
        out.extend(
            mapping
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .filter_map(|t| t.get("path").and_then(|p| p.as_str()))
                .map(crate::pack_origin::path_key),
        );
    }
    out.sort();
    out.dedup();
    out
}

/// The Tier Zero settings folders the shared history carries (as
/// [`crate::folder_origin::key`]): in the repository's settings in the
/// working copy, and in the last sync's. A folder listed here is read only
/// once this computer reviewed it ([`crate::folder_origin`]).
pub fn repo_settings_folders(state: &StateConfig, base: &Path) -> Vec<String> {
    if inactive(state).is_some() {
        return Vec::new();
    }
    let dir = state_dir(state, base);
    let mut out: Vec<String> = Vec::new();
    let strings = |v: Option<&toml::Value>| -> Vec<String> {
        v.and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(crate::folder_origin::key))
            .collect()
    };
    if let Some(raw) = crate::store::read_state_file(&dir, SETTINGS_FILE)
        .ok()
        .flatten()
        .filter(|b| b.len() <= MAX_SETTINGS_BYTES)
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|t| t.parse::<toml::Table>().ok())
    {
        out.extend(strings(raw.get("settings_folders")));
    }
    if let Some(base) = std::fs::read(dir.join(".git").join(BASE_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<Base>(&b).ok())
    {
        if let Some(v) = base
            .sections
            .get("settings_folders")
            .and_then(|s| s.value.as_ref())
        {
            out.extend(
                v.as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|s| s.as_str().map(crate::folder_origin::key)),
            );
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The plain words of a shared section's key ("Accepted risks").
pub fn section_name(key: &str) -> &'static str {
    SHARED_SECTIONS
        .iter()
        .find(|(k, _)| *k == key)
        .map_or("", |(_, n)| *n)
}

fn section_key(key: &str) -> Option<&'static str> {
    SHARED_SECTIONS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(k, _)| *k)
}

// ------------------------------------------------------------ the sides

/// One side's shared settings, as compared: the sections present (empty
/// ones count as absent), each `[[mapping]]` with its pack's text.
#[derive(Debug, Clone, Default)]
struct Side {
    table: toml::Table,
    /// Each present section's digest.
    digests: BTreeMap<&'static str, String>,
}

impl Side {
    fn new(table: toml::Table) -> Self {
        let digests = SHARED_SECTIONS
            .iter()
            .filter_map(|(k, _)| table.get(*k).map(|v| (*k, digest(v))))
            .collect();
        Side { table, digests }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.digests.get(key).map(String::as_str)
    }

    fn all(&self) -> String {
        let mut h = Sha256::new();
        for (k, d) in &self.digests {
            h.update(format!("{k}={d}\n"));
        }
        format!("{:x}", h.finalize())
    }
}

/// A digest of a value that ignores how it is written: key order, quoting,
/// CRLF in strings.
fn digest(v: &toml::Value) -> String {
    let mut s = String::new();
    canon(v, &mut s);
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

fn canon(v: &toml::Value, out: &mut String) {
    use std::fmt::Write;
    match v {
        toml::Value::String(s) => {
            let s = s.replace("\r\n", "\n");
            let _ = write!(out, "s{}", serde_json::Value::String(s));
        }
        toml::Value::Integer(i) => {
            let _ = write!(out, "i{i}");
        }
        toml::Value::Float(f) => {
            let _ = write!(out, "f{f:?}");
        }
        toml::Value::Boolean(b) => {
            let _ = write!(out, "b{b}");
        }
        toml::Value::Datetime(d) => {
            let _ = write!(out, "d{d}");
        }
        toml::Value::Array(a) => {
            out.push('[');
            for x in a {
                canon(x, out);
                out.push(',');
            }
            out.push(']');
        }
        toml::Value::Table(t) => {
            let mut keys: Vec<&String> = t.keys().collect();
            keys.sort();
            out.push('{');
            for k in keys {
                let _ = write!(out, "{}:", serde_json::Value::String(k.clone()));
                canon(&t[k], out);
                out.push(',');
            }
            out.push('}');
        }
    }
}

fn is_empty_value(v: &toml::Value) -> bool {
    match v {
        toml::Value::Array(a) => a.is_empty(),
        toml::Value::Table(t) => t.is_empty(),
        _ => false,
    }
}

/// Why the `[[mapping]]` pack at `path` can't travel, or its text (line
/// ends LF, no byte order mark). Only a pack in the environment's `packs`
/// folder travels ([`pack_path`]).
fn shareable_pack(dir: &Path, path: &str) -> Result<String, String> {
    let rel = pack_path(path)?;
    let full = dir.join(&rel);
    if has_link(dir, &rel) {
        return Err("it is reached through a symbolic link or junction".into());
    }
    let meta = std::fs::metadata(&full).map_err(|e| format!("it can't be read ({e})"))?;
    if meta.len() > crate::config::MAX_PACK_BYTES {
        return Err("it is larger than 1 MiB".into());
    }
    let text = std::fs::read_to_string(&full).map_err(|e| format!("it can't be read ({e})"))?;
    Ok(crate::pack_origin::normalize(&text))
}

/// Checks a `[[mapping]]` path for travel: a `.toml` file in the
/// environment's `packs` folder (`packs/acme.toml`), each part plain
/// letters, digits, `.`, `_` or `-`, none hidden, ending in a dot or a
/// space, or a name Windows reserves (`CON`, `NUL`, `COM1`, ...).
fn pack_path(path: &str) -> Result<PathBuf, String> {
    crate::config::check_pack_path(path)?;
    let parts: Vec<&str> = path.trim().split(['/', '\\']).collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case(PACKS_DIR) {
        return Err(format!(
            "only packs in the environment's `{PACKS_DIR}` folder travel"
        ));
    }
    for part in &parts {
        let plain = !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            && !part.starts_with('.')
            && !part.ends_with('.');
        if !plain || reserved_name(part) {
            return Err(format!(
                "`{part}` is not a plain file or folder name (letters, digits, . _ -)"
            ));
        }
    }
    Ok(parts.iter().collect())
}

/// A name Windows reserves for a device, with or without an extension.
fn reserved_name(part: &str) -> bool {
    let stem = part
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
}

/// Whether `rel` under `dir`, or any folder on the way, is a symbolic link
/// or junction.
fn has_link(dir: &Path, rel: &Path) -> bool {
    let mut at = dir.to_path_buf();
    rel.components().any(|c| {
        at.push(c);
        std::fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_symlink())
    })
}

fn mapping_path(t: &toml::Table) -> Option<&str> {
    t.get("path").and_then(toml::Value::as_str)
}

/// Mapping packs that travel: (path as written, text).
type Packs = Vec<(String, String)>;

/// The shared side of a `pathwarden.toml` text; `dir` is its folder, where
/// mapping packs are read. Also returns notes (packs that don't travel)
/// and the packs that do, as (path, text).
fn local_side(text: &str, dir: &Path) -> Result<(Side, Vec<String>, Packs)> {
    let raw: toml::Table = text.parse().context("reading pathwarden.toml")?;
    let mut table = toml::Table::new();
    let mut notes = Vec::new();
    let mut packs = Vec::new();
    for (key, _) in SHARED_SECTIONS {
        let Some(v) = raw.get(*key) else { continue };
        let v = if *key == "mapping" {
            let mut list = Vec::new();
            for t in v
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_table())
            {
                let Some(path) = mapping_path(t) else {
                    continue;
                };
                match shareable_pack(dir, path) {
                    Ok(text) => {
                        let mut t = t.clone();
                        t.insert("text".into(), toml::Value::String(text.clone()));
                        list.push(toml::Value::Table(t));
                        packs.push((path.to_string(), text));
                    }
                    Err(why) => notes.push(format!(
                        "The mapping pack {path} is not shared: {why}. Copy it to the other \
                         machines yourself."
                    )),
                }
            }
            toml::Value::Array(list)
        } else {
            v.clone()
        };
        if !is_empty_value(&v) {
            table.insert((*key).into(), v);
        }
    }
    Ok((Side::new(table), notes, packs))
}

/// The repository's side, from `settings/pathwarden.toml`; also returns
/// notes on what this version leaves out.
fn repo_side(text: &str) -> Result<(Side, Vec<String>)> {
    if text.len() > MAX_SETTINGS_BYTES {
        bail!("the repository's settings/pathwarden.toml is larger than 4 MiB; it is not read");
    }
    let raw: toml::Table = text
        .parse()
        .context("reading the repository's settings/pathwarden.toml")?;
    // A newer format (docs/dev/formats.md): nothing of it is applied here, and
    // nothing is pushed over it ([`NewerFile`]).
    if !crate::formats::of_toml(&raw, "format", crate::config::CONFIG_FORMAT).is_known() {
        return Err(NewerFile.into());
    }
    let mut notes = Vec::new();
    let named: Vec<String> = raw
        .get("mapping")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|t| t.as_table().and_then(mapping_path))
        .map(crate::pack_origin::path_key)
        .collect();
    let list = raw.get(MAPPING_FILES).and_then(toml::Value::as_array);
    if list.is_some_and(|l| l.len() > MAX_MAPPING_FILES) {
        bail!(
            "the repository's settings carry more than {MAX_MAPPING_FILES} mapping packs; they \
             are not read"
        );
    }
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    for f in list.into_iter().flatten().filter_map(|f| f.as_table()) {
        let (Some(path), Some(text)) = (
            f.get("path").and_then(toml::Value::as_str),
            f.get("text").and_then(toml::Value::as_str),
        ) else {
            continue;
        };
        if !named.contains(&crate::pack_origin::path_key(path)) {
            notes.push(format!(
                "The repository's settings carry a pack for {path}, which no [[mapping]] names; \
                 it is left out."
            ));
            continue;
        }
        files.insert(
            crate::pack_origin::path_key(path),
            crate::pack_origin::normalize(text),
        );
    }
    let mut table = toml::Table::new();
    for (key, _) in SHARED_SECTIONS {
        let Some(v) = raw.get(*key) else { continue };
        let v = if *key == "mapping" {
            let mut list = Vec::new();
            for t in v
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_table())
            {
                let mut t = t.clone();
                if let Some(text) =
                    mapping_path(&t).and_then(|p| files.get(&crate::pack_origin::path_key(p)))
                {
                    t.insert("text".into(), toml::Value::String(text.clone()));
                }
                list.push(toml::Value::Table(t));
            }
            toml::Value::Array(list)
        } else {
            v.clone()
        };
        if !is_empty_value(&v) {
            table.insert((*key).into(), v);
        }
    }
    for key in raw.keys() {
        if NEVER_SHARED.contains(&key.as_str()) {
            notes.push(format!(
                "The repository's settings hold `{key}`, which is never shared; it is not used \
                 here and is removed with the next change pushed."
            ));
        } else if !config_edit::is_shared_key(key) && key != MAPPING_FILES && key != "format" {
            notes.push(format!(
                "The repository's settings hold `{key}`, which this version of Pathwarden \
                 doesn't know (a newer one wrote it); it is left out here and kept in the \
                 repository."
            ));
        }
    }
    Ok((Side::new(table), notes))
}

// ------------------------------------------------------------- the base

/// Each section as it was at the last sync. A section missing from it was
/// never synced here.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
struct Base {
    #[serde(default)]
    sections: BTreeMap<String, BaseSection>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct BaseSection {
    /// `None`: the section was absent.
    digest: Option<String>,
    /// Its value then, for the app to show what changed on each side.
    #[serde(default)]
    value: Option<serde_json::Value>,
}

/// The digest a section has in a base file that can't be read: it matches
/// neither side, so a section that differs is changed on both, never
/// taken as a first sync.
const UNKNOWN: &str = "unknown: the base file could not be read";

impl Base {
    /// The base, `None` when there is none (never synced here). One that is
    /// there but can't be read or parsed is not a first sync: every section
    /// is [`UNKNOWN`] in it, so one that differs is shown as differing from the shared ones.
    fn read(store: &Store) -> Option<Self> {
        let parsed = match store.read_local_file(BASE_FILE) {
            Some(bytes) => serde_json::from_slice::<Base>(&bytes).ok(),
            None if store.dir.join(".git").join(BASE_FILE).exists() => None,
            None => return None,
        };
        Some(parsed.unwrap_or_else(Base::unknown))
    }

    /// Every section [`UNKNOWN`].
    fn unknown() -> Self {
        Base {
            sections: SHARED_SECTIONS
                .iter()
                .map(|(k, _)| {
                    (
                        k.to_string(),
                        BaseSection {
                            digest: Some(UNKNOWN.into()),
                            value: None,
                        },
                    )
                })
                .collect(),
        }
    }

    /// Records `key` as absent at this sync: a section kept only on this
    /// computer, so a shared version that arrives later is a change on
    /// both sides, never a first sync.
    fn set_absent(&mut self, key: &str) {
        self.sections.insert(
            key.to_string(),
            BaseSection {
                digest: None,
                value: None,
            },
        );
    }

    fn write(&self, store: &Store) -> Result<()> {
        store.write_local_file(BASE_FILE, &serde_json::to_vec_pretty(self)?)
    }

    /// `None`: never synced; `Some(None)`: absent then.
    fn get(&self, key: &str) -> Option<Option<&str>> {
        self.sections.get(key).map(|s| s.digest.as_deref())
    }

    /// Records section `key` as `value` at this sync (`None`: absent).
    fn set_value(&mut self, key: &str, value: Option<toml::Value>) {
        self.sections.insert(
            key.to_string(),
            BaseSection {
                digest: value.as_ref().map(digest),
                value: value.and_then(|v| serde_json::to_value(v).ok()),
            },
        );
    }

    /// Section `key` as entries, when the base knows it entry by entry:
    /// `None` when it was never synced, or its value isn't known.
    fn entries(&self, key: &str) -> Option<merge::Entries> {
        let s = self.sections.get(key)?;
        let v: Option<toml::Value> = match (&s.digest, &s.value) {
            (None, _) => None,
            (Some(_), Some(v)) => Some(serde_json::from_value(v.clone()).ok()?),
            (Some(_), None) => return None,
        };
        merge::entries(key, v.as_ref())
    }

    fn set(&mut self, key: &str, side: &Side) {
        let value = side
            .table
            .get(key)
            .and_then(|v| serde_json::to_value(v).ok());
        self.sections.insert(
            key.to_string(),
            BaseSection {
                digest: side.get(key).map(str::to_string),
                value,
            },
        );
    }
}

// ------------------------------------------------------------- status

/// Where a shared section changed since the last sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Changed {
    /// The same here and in the repository.
    InStep,
    /// Changed here, not in the repository.
    Here,
    /// Changed in the repository, not here.
    Repository,
    /// Changed here and in the repository: some entry has two values
    /// ([`Clash`]), or the section can't be merged entry by entry.
    Both,
    /// Changed here and in the repository, in different entries: merged at
    /// the next sync.
    Merge,
}

impl Changed {
    pub fn words(self) -> &'static str {
        match self {
            Changed::InStep => "up to date",
            Changed::Here => "not shared yet",
            Changed::Repository => "shared update: applied at the next sync",
            Changed::Both => "differs from the shared settings",
            Changed::Merge => "changed here and in the shared settings: merged at the next sync",
        }
    }
}

/// Section names (as [`section_name`] gives them) in a sentence: "Rule
/// settings and zones", or "rule settings and zones" when not `first`.
/// "Tier Zero" keeps its capitals.
pub fn names_in_a_sentence(names: &[&str], first: bool) -> String {
    let lower = |n: &str| {
        if n.starts_with("Tier Zero") {
            return n.to_string();
        }
        let mut c = n.chars();
        c.next()
            .map(|f| f.to_lowercase().collect::<String>() + c.as_str())
            .unwrap_or_default()
    };
    let words: Vec<String> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            if i == 0 && first {
                (*n).to_string()
            } else {
                lower(n)
            }
        })
        .collect();
    match words.as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The one line a first sync leaves: "Rule settings and zones were taken
/// from the run history. This computer's earlier settings are saved in
/// pathwarden.toml.before-connect-2026-11-18." `backups` are the copies'
/// names (from the folder of `pathwarden.toml`); none when nothing of this
/// computer's was replaced. `folder_rights`: a copy keeps its folder's
/// permissions (a file system with none to set).
pub fn first_sync_words(sections: &[&str], backups: &[&str], folder_rights: bool) -> String {
    let mut s = format!(
        "{} were taken from the run history.",
        names_in_a_sentence(sections, true)
    );
    let files = match backups {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    if !files.is_empty() {
        s.push_str(&format!(
            " This computer's earlier settings are saved in {files}."
        ));
        if folder_rights {
            s.push_str(if backups.len() == 1 {
                " The copy keeps the folder's permissions."
            } else {
                " The copies keep the folder's permissions."
            });
        }
    }
    s
}

/// A note that may hold the first-sync line ([`first_sync_words`]) among
/// other sentences: (that line, the rest). The command line says the line
/// as a note, the rest as it says any other.
pub fn split_first_sync(note: &str) -> (Option<String>, String) {
    const TAKEN: &str = " were taken from the run history.";
    const SAVED: &str = " This computer's earlier settings are saved in ";
    let Some(at) = note.find(TAKEN) else {
        return (None, note.to_string());
    };
    // The line starts after the sentence before it (section names hold no
    // full stops); it ends with "taken ... history.", or after the copies'
    // names (which hold full stops, never one before a space).
    let start = note[..at].rfind(". ").map_or(0, |i| i + 2);
    let mut end = at + TAKEN.len();
    if note[end..].starts_with(SAVED) {
        let names = end + SAVED.len();
        end = note[names..]
            .find(". ")
            .map_or(note.len(), |i| names + i + 1);
    }
    let line = note[start..end].trim().to_string();
    let rest = format!("{} {}", note[..start].trim(), note[end..].trim())
        .trim()
        .to_string();
    (Some(line), rest)
}

/// "This computer's rule settings differ from the shared ones.": the
/// first sentence about sections changed on both sides.
pub fn differ_words(sections: &[&str]) -> String {
    format!(
        "This computer's {} differ from the shared ones.",
        names_in_a_sentence(sections, false)
    )
}

/// One shared section's state.
#[derive(Debug, Clone, Serialize)]
pub struct Section {
    /// As in `pathwarden.toml` (`suppress`, `zone`, ...).
    pub key: &'static str,
    /// In plain words ("Accepted risks").
    pub name: &'static str,
    pub state: Changed,
}

/// An entry with two values: changed to different values here and in the
/// repository since the last sync, or changed on one side and removed on
/// the other. Until someone chooses, this computer keeps its value for it
/// (and the repository its own); everything else merges.
#[derive(Debug, Clone, Serialize)]
pub struct Clash {
    /// The section's key (`rules`).
    pub section: &'static str,
    /// What `pathwarden config sync --section` takes for it:
    /// `rules.stale_days`; the section's own key when the whole section
    /// is settled as one ([`Clash::whole`]).
    pub id: String,
    /// In plain words: "Stale Tier Zero account", "Rule settings".
    pub name: String,
    /// This computer's value in words ("30 days", "removed"); empty for a
    /// whole section.
    pub here: String,
    /// The repository's.
    pub shared: String,
    /// The values, short enough for a button ("30"), when they are.
    pub here_short: Option<String>,
    pub shared_short: Option<String>,
    /// The whole section has two versions: it can't be merged entry by
    /// entry (a form this version can't take apart, or a last sync that
    /// isn't known).
    pub whole: bool,
    /// The entry's ID within its section (`stale_days`).
    #[serde(skip)]
    pub entry: String,
    /// What each side holds, for [`Status::differs_key`].
    #[serde(skip)]
    sides: String,
}

impl Clash {
    /// "Stale Tier Zero account: 30 days here, 60 days shared".
    pub fn words(&self) -> String {
        if self.whole {
            format!("{}: changed here and in the shared settings", self.name)
        } else {
            format!("{}: {} here, {} shared", self.name, self.here, self.shared)
        }
    }
}

/// "Stale Tier Zero account has two values.", "Stale Tier Zero account and 2
/// more have two values.": the first clash, and how many more.
pub fn clash_words(clashes: &[Clash]) -> String {
    match clashes {
        [] => String::new(),
        [one] if one.whole => format!("{} have two versions.", one.name),
        [one] => format!("{} has two values.", one.name),
        [first, rest @ ..] => format!("{} and {} more have two values.", first.name, rest.len()),
    }
}

/// The last change to the shared settings in the repository.
#[derive(Debug, Clone, Serialize)]
pub struct LastChange {
    pub commit: String,
    /// The first line of the commit message.
    pub summary: String,
    /// Git's author, as `Name <email>`.
    pub git_author: String,
    /// When, as git gives it (ISO 8601).
    pub at: String,
    /// Who made the change, as Pathwarden recorded it (`DOMAIN\user`).
    /// Written by whoever pushed: a record, not a proof.
    pub by: Option<String>,
    /// On which computer.
    pub on: Option<String>,
    /// The sections it changed, in plain words, when it says.
    pub sections: Vec<&'static str>,
}

/// What is shared, and where it changed ([`status`]).
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub state: Changed,
    pub sections: Vec<Section>,
    /// Whether the repository holds shared settings at all.
    pub in_repository: bool,
    /// Why the repository's settings can't be read here, when they can't:
    /// nothing is synced until they can (the sections then say nothing of
    /// the repository's side).
    pub unreadable: Option<String>,
    /// [`Status::unreadable`] in the app's words (no commands).
    #[serde(skip)]
    pub unreadable_page: Option<String>,
    /// The repository's file itself is damaged (not a history this
    /// computer can't open): `--keep-local` can replace it.
    pub damaged: bool,
    /// The repository's file is of a newer format ([`NewerFile`]): never
    /// replaced from here.
    pub newer_format: bool,
    /// The history is encrypted: when it isn't, the shared settings are in
    /// the repository in plain text.
    pub encrypted: bool,
    /// Whether this computer pushes (`[state] push`).
    pub pushes: bool,
    /// Some section was never synced here (with no base, every one): the
    /// next sync takes the history's for it.
    pub first_sync: bool,
    /// The Pathwarden that last wrote the repository's settings.
    pub written_by_version: Option<String>,
    /// That Pathwarden is newer than this one.
    pub newer_writer: bool,
    pub last_change: Option<LastChange>,
    /// What is left out, and why: packs that don't travel, sections a newer
    /// version wrote.
    pub notes: Vec<String>,
    /// The entries with two values, section by section in the order they
    /// are shown, then by entry.
    pub clashes: Vec<Clash>,
    /// The entries with two values ([`Status::clashes`]), with what each
    /// side holds, as one digest: `None` when there are none. A dismissal
    /// holds for this exact set ([`dismiss`]).
    pub differs_key: Option<String>,
}

impl Status {
    /// "The repository's settings can't be read here: why." when they
    /// can't, for the command line, or for the app's pages (`page`, no
    /// commands). Only a damaged file is offered `--keep-local`: without
    /// the passphrase, or with a history refused here, it fails too.
    pub fn unreadable_words(&self, page: bool) -> Option<String> {
        let why = self.unreadable.as_deref()?;
        // A newer format: its own sentence, the same everywhere.
        if self.newer_format {
            return Some(NEWER_SETTINGS_WORDS.into());
        }
        let why = if page {
            self.unreadable_page.as_deref().unwrap_or(why)
        } else {
            why
        };
        let why = why.trim_end().trim_end_matches('.');
        Some(if self.damaged && self.pushes && !page {
            format!(
                "The repository's settings can't be read here: {why}. Nothing is synced until \
                 they can; `pathwarden config sync --keep-local` replaces them with the settings \
                 here."
            )
        } else {
            format!(
                "The repository's settings can't be read here: {why}. Nothing is synced until \
                 they can."
            )
        })
    }

    /// The sections in a state other than in step.
    pub fn changed(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.state != Changed::InStep)
    }

    /// The sections in state `c`.
    pub fn in_state(&self, c: Changed) -> Vec<&'static str> {
        self.sections
            .iter()
            .filter(|s| s.state == c)
            .map(|s| s.name)
            .collect()
    }

    /// "Accepted risks (differ from the shared ones), Zones (not shared
    /// yet)".
    pub fn changed_words(&self) -> String {
        self.changed()
            .map(|s| {
                format!(
                    "{} ({})",
                    s.name,
                    match s.state {
                        Changed::Here if self.pushes => "not shared yet",
                        Changed::Here => "only on this computer",
                        Changed::Repository => "shared update",
                        Changed::Merge => "merged at the next sync",
                        _ => "differ from the shared ones",
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Where the shared settings are: the history (pulled, its lock held), the
/// `pathwarden.toml` they are kept in here, and this machine's part.
pub struct Place<'a> {
    pub store: &'a Store,
    pub config_path: &'a Path,
    /// Whether this computer pushes (`[state] push`).
    pub pushes: bool,
    /// The environment's name, for `environment.json` (`None` keeps the
    /// repository's).
    pub env_name: Option<&'a str>,
}

impl Place<'_> {
    fn dir(&self) -> &Path {
        self.config_path.parent().unwrap_or_else(|| Path::new("."))
    }
}

/// Everything compared, read once.
struct Read {
    local: Side,
    packs: Packs,
    repo_text: Option<String>,
    repo: Side,
    base: Option<Base>,
    /// The sections changed on both sides that merge entry by entry.
    splits: BTreeMap<&'static str, Split>,
    status: Status,
}

fn read_local(p: &Place) -> Result<String> {
    match std::fs::read_to_string(p.config_path) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.config_path.display())),
    }
}

fn read_repo(store: &Store) -> Result<Option<String>> {
    // The size first, from the file system: a huge file is never read.
    // (With repository encryption the file on disk is the encrypted one.)
    // Plain or encrypted (`.age`), whichever is there; an encrypted file is
    // a little larger than its content.
    let sealed = format!("{SETTINGS_FILE}{}", crate::crypt::SUFFIX);
    let max = MAX_SETTINGS_BYTES as u64;
    let too_big = [(SETTINGS_FILE, max), (sealed.as_str(), max + 4096)]
        .iter()
        .any(|(f, limit)| std::fs::metadata(store.dir.join(f)).is_ok_and(|m| m.len() > *limit));
    let big = || {
        BadFile(
            "the repository's settings/pathwarden.toml is larger than 4 MiB; it is not read".into(),
        )
    };
    if too_big {
        return Err(big().into());
    }
    let Some(bytes) = store.read_state_file(SETTINGS_FILE)? else {
        return Ok(None);
    };
    if bytes.len() > MAX_SETTINGS_BYTES {
        return Err(big().into());
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

/// The repository's settings file itself is damaged (too large, not
/// readable as settings): unlike a history this computer can't open (no
/// passphrase, refused), keeping the settings here can replace it.
#[derive(Debug)]
struct BadFile(String);

impl std::fmt::Display for BadFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BadFile {}

/// The repository's settings file is of a format this version doesn't
/// know (docs/dev/formats.md): not damaged, so `--keep-local` never replaces
/// it, and nothing is pushed over it.
#[derive(Debug)]
pub struct NewerFile;

/// What [`NewerFile`] says, on every page and on the command line.
pub const NEWER_SETTINGS_WORDS: &str = "The repository's settings were saved by a newer \
Pathwarden. Update Pathwarden to sync them.";

impl std::fmt::Display for NewerFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(NEWER_SETTINGS_WORDS)
    }
}

impl std::error::Error for NewerFile {}

fn is_newer_file(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<NewerFile>().is_some())
}

/// Whether the repository's settings file is of a format this version
/// doesn't know: checked before every write of the shared settings,
/// forced or not.
fn repo_settings_newer(store: &Store) -> bool {
    matches!(read_repo(store), Ok(Some(t)) if repo_side(&t).is_err_and(|e| is_newer_file(&e)))
}

/// Why the repository's settings can't be read, for the app's pages: the
/// passphrase in plain words, without the commands.
/// `refused`: the history is refused here ([`Store::check_expected`]).
/// Never the command line's text, which names commands.
fn page_why(e: &anyhow::Error, refused: bool) -> String {
    use crate::crypt::CryptError;
    if refused {
        return "this computer expects the history encrypted, and it isn't (it may have been \
                decrypted on another computer); see History storage"
            .into();
    }
    if is_newer_file(e) {
        return NEWER_SETTINGS_WORDS.into();
    }
    if let Some(b) = e.chain().find_map(|c| c.downcast_ref::<BadFile>()) {
        return b.0.clone();
    }
    match e.chain().find_map(|c| c.downcast_ref::<CryptError>()) {
        Some(CryptError::NeedPassphrase) => "this history is encrypted, and no passphrase for it \
            is stored on this computer (enter it on Runs)"
            .into(),
        Some(CryptError::WrongPassphrase(_)) => {
            "the passphrase this computer has doesn't open this history".into()
        }
        Some(CryptError::Newer(_)) => {
            "a newer Pathwarden encrypted this history; update Pathwarden to read it".into()
        }
        Some(CryptError::Damaged(_)) => "the encrypted settings file doesn't decrypt".into(),
        None => "this history was refused here; see History storage".into(),
    }
}

/// Whether `e`, from reading the repository's settings, is a damaged file
/// ([`BadFile`], or an encrypted file that doesn't decrypt with the right
/// passphrase at hand).
fn damaged(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<BadFile>().is_some()
            || matches!(
                c.downcast_ref::<crate::crypt::CryptError>(),
                Some(crate::crypt::CryptError::Damaged(_))
            )
    })
}

fn read_all(p: &Place) -> Result<Read> {
    read_all_or(p, None)
}

/// [`read_all`]; with `refused` (why the history is refused here), nothing
/// is read from the repository, and its settings are reported unreadable.
fn read_all_or(p: &Place, refused: Option<anyhow::Error>) -> Result<Read> {
    let local_text = read_local(p)?;
    let (local, mut notes, packs) = local_side(&local_text, p.dir())?;
    // A repository file that can't be read stops nothing here: it is
    // reported, and `--keep-local` can replace a damaged one.
    let mut unreadable = None;
    let mut unreadable_page = None;
    let mut damaged_file = false;
    let mut newer_file = false;
    let is_refused = refused.is_some();
    let read = match refused {
        Some(e) => Err(e),
        None => read_repo(p.store).and_then(|t| match t {
            Some(t) => repo_side(&t)
                .map(|(side, n)| (Some(t), side, n))
                .map_err(|e| {
                    if is_newer_file(&e) {
                        e
                    } else {
                        BadFile(format!("{e:#}")).into()
                    }
                }),
            None => Ok((None, Side::default(), Vec::new())),
        }),
    };
    let (repo_text, repo) = match read {
        Ok((t, side, n)) => {
            notes.extend(n);
            (t, side)
        }
        Err(e) => {
            damaged_file = damaged(&e);
            newer_file = is_newer_file(&e);
            unreadable_page = Some(page_why(&e, is_refused));
            unreadable = Some(format!("{e:#}"));
            (None, Side::default())
        }
    };
    let base = Base::read(p.store);
    let env = if is_refused {
        None
    } else {
        environment(p.store)
    };
    let written_by_version = env.as_ref().map(|e| e.written_by_version.clone());
    let newer_writer = written_by_version
        .as_deref()
        .is_some_and(|v| newer(v, VERSION));
    if newer_writer {
        notes.push(format!(
            "These settings come from Pathwarden {}; this is {VERSION}. What it added that this \
             version doesn't know is kept, but not used here.",
            written_by_version.as_deref().unwrap_or_default()
        ));
    }
    let (sections, splits, clashes) = if unreadable.is_some() {
        let sections = SHARED_SECTIONS
            .iter()
            .map(|(key, name)| Section {
                key,
                name,
                state: Changed::InStep,
            })
            .collect();
        (sections, BTreeMap::new(), Vec::new())
    } else {
        judge_all(&local, &repo, base.as_ref())
    };
    let state = overall(&sections);
    let differs_key = key_of_differences(&clashes);
    let status = Status {
        state,
        sections,
        in_repository: repo_text.is_some() || unreadable.is_some(),
        unreadable,
        unreadable_page,
        damaged: damaged_file,
        clashes,
        differs_key,
        newer_format: newer_file,
        encrypted: p.store.is_encrypted(),
        pushes: p.pushes,
        // As each section is judged: some section was never synced here.
        first_sync: SHARED_SECTIONS
            .iter()
            .any(|(k, _)| never_synced(base.as_ref(), k)),
        written_by_version,
        newer_writer,
        last_change: if is_refused {
            None
        } else {
            last_change(p.store)
        },
        notes,
    };
    Ok(Read {
        local,
        packs,
        repo_text,
        repo,
        base,
        splits,
        status,
    })
}

/// Each section's state; the sections changed on both sides that merge
/// entry by entry; and the entries with two values.
fn judge_all(
    local: &Side,
    repo: &Side,
    base: Option<&Base>,
) -> (Vec<Section>, BTreeMap<&'static str, Split>, Vec<Clash>) {
    let mut sections = Vec::new();
    let mut splits = BTreeMap::new();
    let mut clashes = Vec::new();
    for (key, name) in SHARED_SECTIONS {
        let (l, r) = (local.get(key), repo.get(key));
        let b = base.and_then(|b| b.get(key));
        let split = (l != r && b.is_some())
            .then(|| {
                Some(Split {
                    base: base?.entries(key)?,
                    local: merge::entries(key, local.table.get(*key))?,
                    repo: merge::entries(key, repo.table.get(*key))?,
                })
            })
            .flatten();
        let state = match &split {
            Some(sp) => {
                let plan = sp.plan(&|_| None);
                clashes.extend(entry_clashes(key, sp, &plan.clashes));
                match (
                    !plan.clashes.is_empty(),
                    !plan.to_local.is_empty(),
                    !plan.to_repo.is_empty(),
                ) {
                    (true, _, _) => Changed::Both,
                    (_, true, true) => Changed::Merge,
                    (_, false, true) => Changed::Here,
                    (_, true, false) => Changed::Repository,
                    _ => Changed::InStep,
                }
            }
            None => {
                let c = compare(l, r, b);
                if c == Changed::Both {
                    clashes.push(Clash {
                        section: key,
                        id: key.to_string(),
                        name: name.to_string(),
                        here: String::new(),
                        shared: String::new(),
                        here_short: None,
                        shared_short: None,
                        whole: true,
                        entry: String::new(),
                        sides: format!("{}|{}", l.unwrap_or("-"), r.unwrap_or("-")),
                    });
                }
                c
            }
        };
        if let (Some(sp), true) = (split, matches!(state, Changed::Both | Changed::Merge)) {
            splits.insert(*key, sp);
        }
        sections.push(Section { key, name, state });
    }
    (sections, splits, clashes)
}

/// The clashes `ids` of section `key`, in words.
fn entry_clashes(key: &'static str, sp: &Split, ids: &[String]) -> Vec<Clash> {
    ids.iter()
        .map(|id| {
            let (l, r) = (sp.local.get(id), sp.repo.get(id));
            let name = l
                .or(r)
                .or(sp.base.get(id))
                .map_or_else(|| id.clone(), |e| e.label.clone());
            Clash {
                section: key,
                id: format!("{key}.{id}"),
                name,
                here: merge::words(key, id, l),
                shared: merge::words(key, id, r),
                here_short: merge::short(key, id, l),
                shared_short: merge::short(key, id, r),
                whole: false,
                entry: id.clone(),
                sides: format!(
                    "{}|{}",
                    l.map_or("-", |e| e.eff.as_str()),
                    r.map_or("-", |e| e.eff.as_str())
                ),
            }
        })
        .collect()
}

/// Whether section `key` was never synced here: no base, or none for it.
fn never_synced(base: Option<&Base>, key: &str) -> bool {
    base.and_then(|b| b.get(key)).is_none()
}

/// One section: `base` is `None` when it was never synced, `Some(None)`
/// when it was absent then.
fn compare(local: Option<&str>, repo: Option<&str>, base: Option<Option<&str>>) -> Changed {
    if local == repo {
        return Changed::InStep;
    }
    match base {
        // Never synced: only this computer has it, so it is shared; else
        // the repository's wins (the first sync takes the history's).
        None if repo.is_none() => Changed::Here,
        None => Changed::Repository,
        Some(b) => match (local != b, repo != b) {
            (true, false) => Changed::Here,
            (false, true) => Changed::Repository,
            _ => Changed::Both,
        },
    }
}

fn overall(sections: &[Section]) -> Changed {
    let has = |c: Changed| sections.iter().any(|s| s.state == c);
    // Each section is settled on its own: only one with an entry of two
    // values needs a choice.
    if has(Changed::Both) {
        Changed::Both
    } else if has(Changed::Merge) {
        Changed::Merge
    } else if has(Changed::Here) {
        Changed::Here
    } else if has(Changed::Repository) {
        Changed::Repository
    } else {
        Changed::InStep
    }
}

/// [`Status::differs_key`]: each entry with two values, with what each
/// side holds.
fn key_of_differences(clashes: &[Clash]) -> Option<String> {
    let mut h = Sha256::new();
    for c in clashes {
        h.update(format!("{}={}\n", c.id, c.sides));
    }
    (!clashes.is_empty()).then(|| format!("{:x}", h.finalize()))
}

/// [`Status::differs_key`] for the working copy as the last pull left it,
/// without the rest of [`status`] (no git is run): what a page's rail asks
/// on every page. `None` when nothing differs, or the settings can't be read.
pub fn differs_key(p: &Place) -> Option<String> {
    if p.store.check_expected().is_err() {
        return None;
    }
    let (local, _, _) = local_side(&read_local(p).ok()?, p.dir()).ok()?;
    let repo = repo_side(&read_repo(p.store).ok()??).ok()?.0;
    let base = Base::read(p.store);
    key_of_differences(&judge_all(&local, &repo, base.as_ref()).2)
}

/// A file [`differs_key`] (and so the rail's dot) depends on, with when it
/// was last written and its size: `None` when it isn't there.
pub type Input = (PathBuf, Option<(std::time::SystemTime, u64)>);

/// What [`differs_key`] and a dismissal read, as [`Input`]s: this
/// computer's `pathwarden.toml` and its packs, the repository's shared
/// settings, the base and the dismissal. While none of these changed, a
/// cached answer holds; checking costs a few file system lookups.
pub fn dot_inputs(p: &Place) -> Vec<Input> {
    let stat = |f: PathBuf| {
        let m = std::fs::metadata(&f)
            .ok()
            .and_then(|m| Some((m.modified().ok()?, m.len())));
        (f, m)
    };
    let git = p.store.dir.join(".git");
    let mut out = vec![
        stat(p.config_path.to_path_buf()),
        stat(p.store.dir.join(SETTINGS_FILE)),
        stat(
            p.store
                .dir
                .join(format!("{SETTINGS_FILE}{}", crate::crypt::SUFFIX)),
        ),
        stat(git.join(BASE_FILE)),
        stat(git.join(DISMISSED_FILE)),
    ];
    // The packs folder, a few levels and files deep: the packs that travel.
    let mut dirs = vec![(p.dir().join(PACKS_DIR), 0)];
    let mut files = Vec::new();
    while let Some((dir, depth)) = dirs.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten().take(256) {
            let path = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() && depth < 4 => dirs.push((path, depth + 1)),
                Ok(t) if t.is_file() => files.push(path),
                _ => {}
            }
        }
        if files.len() > 512 {
            break;
        }
    }
    files.sort();
    out.extend(files.into_iter().map(stat));
    out
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Dismissed {
    #[serde(default)]
    key: Option<String>,
}

/// The differences this computer's app was told about and dismissed:
/// [`Status::differs_key`] then, if any.
pub fn dismissed_key(store: &Store) -> Option<String> {
    serde_json::from_slice::<Dismissed>(&store.read_local_file(DISMISSED_FILE)?)
        .ok()?
        .key
}

/// Dismisses the rail's notice of these differences (`key`, a
/// [`Status::differs_key`]) on this computer, for this history: kept in the
/// clone's `.git`, never shared. A new difference, or either side changing
/// again, is another key and shows again. The line about what the merge
/// recorded at `merged_at` brought goes with it.
pub fn dismiss(store: &Store, key: &str, merged_at: Option<i64>) -> Result<()> {
    if merged_at.is_some() {
        mark_merged(store, true, merged_at);
    }
    store.write_local_file(
        DISMISSED_FILE,
        &serde_json::to_vec_pretty(&Dismissed {
            key: Some(key.to_string()),
        })?,
    )
}

/// An entry the last merge brought here from the repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedEntry {
    /// Its section's key (`tier_zero`).
    pub section: String,
    /// Its ID in the section.
    pub id: String,
    /// What a person reads: "APP01$".
    pub label: String,
    /// It is new here (not a change to one this computer had).
    #[serde(default)]
    pub added: bool,
    /// What happened, in words: "APP01$ added to Tier Zero".
    pub words: String,
    /// The entry as it came (what the merge compares): once it is edited
    /// here, it is this computer's again and no longer marked.
    #[serde(default)]
    pub eff: String,
}

/// What the last merge brought here from the repository, with who made the
/// last shared change and when: the app marks those entries "shared" until
/// a later sync brings others, and says it once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedHere {
    /// When it was merged (Unix seconds).
    pub at: i64,
    pub entries: Vec<MergedEntry>,
    pub by: Option<String>,
    pub on: Option<String>,
    /// When the repository's change was made (RFC 3339).
    pub changed_at: Option<String>,
    /// The app showed its line once with nothing else to say.
    #[serde(default)]
    pub seen: bool,
    /// Dismissed with the note about entries with two values.
    #[serde(default)]
    pub dismissed: bool,
}

impl MergedHere {
    /// "APP01$ added to Tier Zero": what came, in a sentence's words.
    pub fn words(&self) -> String {
        self.entries
            .iter()
            .map(|e| e.words.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn record_merged(store: &Store, entries: Vec<MergedEntry>) {
    let last = last_change(store);
    let rec = MergedHere {
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64),
        entries,
        by: last.as_ref().and_then(|c| c.by.clone()),
        on: last.as_ref().and_then(|c| c.on.clone()),
        changed_at: last.as_ref().map(|c| c.at.clone()),
        seen: false,
        dismissed: false,
    };
    if let Ok(b) = serde_json::to_vec_pretty(&rec) {
        let _ = store.write_local_file(MERGED_FILE, &b);
    }
}

/// What the last merge brought here, if anything.
pub fn merged_here(store: &Store) -> Option<MergedHere> {
    serde_json::from_slice(&store.read_local_file(MERGED_FILE)?).ok()
}

/// The entries the last merge brought that this computer still holds as
/// they came, as (section, ID): what the app marks "shared". One edited here
/// since is this computer's again.
pub fn merged_marks(p: &Place, m: &MergedHere) -> Vec<(String, String)> {
    let Some(local) = read_local(p)
        .ok()
        .and_then(|t| local_side(&t, p.dir()).ok())
        .map(|s| s.0)
    else {
        return Vec::new();
    };
    m.entries
        .iter()
        .filter(|e| {
            let Some(key) = section_key(&e.section) else {
                return false;
            };
            merge::entries(key, local.table.get(key))
                .and_then(|es| es.get(&e.id).map(|x| e.eff.is_empty() || x.eff == e.eff))
                .unwrap_or(false)
        })
        .map(|e| (e.section.clone(), e.id.clone()))
        .collect()
}

/// Marks what the last merge brought as shown (`dismissed`: with the note's
/// Dismiss), so its line isn't shown again. `at`: only the record the page
/// showed ([`MergedHere::at`]); a newer one a sync wrote since stays.
pub fn mark_merged(store: &Store, dismissed: bool, at: Option<i64>) {
    let Some(mut m) = merged_here(store) else {
        return;
    };
    if at.is_some_and(|a| a != m.at) {
        return;
    }
    if m.seen && (m.dismissed || !dismissed) {
        return;
    }
    m.seen = true;
    m.dismissed |= dismissed;
    if let Ok(b) = serde_json::to_vec_pretty(&m) {
        let _ = store.write_local_file(MERGED_FILE, &b);
    }
}

/// Forgets a dismissal: once nothing differs, the next difference shows.
pub fn clear_dismissed(store: &Store) {
    if dismissed_key(store).is_some() {
        let _ = store.write_local_file(
            DISMISSED_FILE,
            &serde_json::to_vec_pretty(&Dismissed::default()).unwrap_or_default(),
        );
    }
}

/// Where the shared settings changed since the last sync, section by
/// section. Changes nothing. A history refused here
/// ([`Store::check_expected`]) is read for nothing: its settings are
/// reported as unreadable, with why.
pub fn status(p: &Place) -> Result<Status> {
    let refused = p.store.check_expected().err();
    Ok(read_all_or(p, refused)?.status)
}

// -------------------------------------------------------------- diffs

/// A line of a section, marked against the last sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffLine {
    /// `+` added, `-` removed, ` ` as at the last sync.
    pub mark: char,
    pub text: String,
}

/// What a section that changed looks like on each side, against the last
/// sync ([`section_diffs`]).
#[derive(Debug, Clone, Serialize)]
pub struct SectionDiff {
    pub key: &'static str,
    pub name: &'static str,
    pub state: Changed,
    pub here: Vec<DiffLine>,
    pub repository: Vec<DiffLine>,
    /// When `pathwarden.toml` was last written here (Unix seconds).
    pub here_at: Option<i64>,
}

/// Each section that is not in step, as lines on each side marked against
/// the last sync: what the app shows to settle a conflict, and the items a
/// reader changed here.
pub fn section_diffs(p: &Place) -> Result<Vec<SectionDiff>> {
    p.store.check_expected()?;
    let r = read_all(p)?;
    let here_at = std::fs::metadata(p.config_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);
    let json = |s: &Side, key: &str| s.table.get(key).and_then(|v| serde_json::to_value(v).ok());
    Ok(r.status
        .sections
        .iter()
        .filter(|s| s.state != Changed::InStep)
        .map(|s| {
            let base = r
                .base
                .as_ref()
                .and_then(|b| b.sections.get(s.key))
                .and_then(|b| b.value.clone());
            let lines_base = section_lines(s.key, base.as_ref());
            SectionDiff {
                key: s.key,
                name: s.name,
                state: s.state,
                here: diff(
                    &lines_base,
                    &section_lines(s.key, json(&r.local, s.key).as_ref()),
                ),
                repository: diff(
                    &lines_base,
                    &section_lines(s.key, json(&r.repo, s.key).as_ref()),
                ),
                here_at,
            }
        })
        .collect())
}

/// A section as lines, one per item: what a person compares.
fn section_lines(key: &str, v: Option<&serde_json::Value>) -> Vec<String> {
    use serde_json::Value as J;
    let Some(v) = v else { return Vec::new() };
    let text = |v: &J| match v {
        J::String(s) => s.clone(),
        J::Object(o) if o.len() == 1 && o.contains_key("$__toml_private_datetime") => {
            o.values().next().map(|d| d.to_string()).unwrap_or_default()
        }
        other => other.to_string(),
    };
    let s = |t: &serde_json::Map<String, J>, k: &str| t.get(k).map(text).unwrap_or_default();
    let tables = |v: &J| -> Vec<serde_json::Map<String, J>> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_object().cloned())
            .collect()
    };
    match key {
        "tier_zero" | "settings_folders" => v.as_array().into_iter().flatten().map(text).collect(),
        "management_planes" => v
            .get("not_tier_zero")
            .and_then(J::as_array)
            .into_iter()
            .flatten()
            .map(|x| format!("not Tier Zero: {}", text(x)))
            .collect(),
        "rules" => v
            .as_object()
            .into_iter()
            .flatten()
            .flat_map(|(k, x)| match (k.as_str(), x.as_object()) {
                // One line per rule whose severity is set, and by whom.
                ("severities", Some(set)) => set
                    .iter()
                    .map(|(rule, e)| {
                        let level = match e {
                            J::Object(o) => s(o, "severity"),
                            other => text(other),
                        };
                        let who = e
                            .as_object()
                            .and_then(|o| o.get("by"))
                            .map(|b| format!(" (set by {})", text(b)))
                            .unwrap_or_default();
                        format!("severity of {rule} = {level}{who}")
                    })
                    .collect::<Vec<_>>(),
                _ => vec![format!("{k} = {}", text(x))],
            })
            .collect(),
        "suppress" => tables(v)
            .iter()
            .map(|t| {
                let target = match t.get("fingerprint") {
                    Some(f) => text(f),
                    None => format!("every {} finding", s(t, "rule")),
                };
                let until = t
                    .get("expires")
                    .map(|e| format!(" (until {})", text(e)))
                    .unwrap_or_default();
                let notes = t.get("notes").and_then(J::as_array).map_or(0, Vec::len);
                let notes = if notes > 0 {
                    format!(" · {}", crate::text::count(notes, "note", "notes"))
                } else {
                    String::new()
                };
                format!("{target}: {}{until}{notes}", s(t, "reason"))
            })
            .collect(),
        "zone" => tables(v)
            .iter()
            .map(|t| {
                let n = ["members", "groups", "ous"]
                    .iter()
                    .map(|k| t.get(*k).and_then(J::as_array).map_or(0, Vec::len))
                    .sum::<usize>();
                format!(
                    "{}: {}",
                    s(t, "name"),
                    crate::text::count(n, "member, group or OU", "members, groups and OUs")
                )
            })
            .collect(),
        "mapping" => tables(v).iter().map(|t| s(t, "path")).collect(),
        _ => Vec::new(),
    }
}

/// `side` against `base`: each line of `side` (`+` when new), then each
/// line of `base` it lost (`-`).
fn diff(base: &[String], side: &[String]) -> Vec<DiffLine> {
    let mut out: Vec<DiffLine> = side
        .iter()
        .map(|l| DiffLine {
            mark: if base.contains(l) { ' ' } else { '+' },
            text: l.clone(),
        })
        .collect();
    out.extend(base.iter().filter(|l| !side.contains(l)).map(|l| DiffLine {
        mark: '-',
        text: l.clone(),
    }));
    out
}

// --------------------------------------------------------------- sync

/// How [`sync`] settles each section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolve {
    /// As on every pull: take the side that changed; leave a section that
    /// changed on both sides as it is.
    Auto,
    /// Take the repository's sections (`config sync --use-repo`): the keys
    /// given, or when none, those changed on both sides, and on a computer
    /// that doesn't push those changed here too. The rest as [`Resolve::Auto`].
    UseRepo(Vec<String>),
    /// Push the sections here over the repository's (`config sync
    /// --keep-local`; a computer that pushes): the keys given, or when
    /// none, those changed on both sides. The rest as [`Resolve::Auto`].
    KeepLocal(Vec<String>),
}

/// What [`sync`] did, section by section (their plain words).
#[derive(Debug, Default)]
pub struct Done {
    /// Sections the repository's were applied here.
    pub applied: Vec<&'static str>,
    /// Of [`Done::applied`], those taken on this computer's first sync of
    /// them: the history's replaced whatever was here.
    pub first: Vec<&'static str>,
    /// Of [`Done::applied`], every section never synced here: those of
    /// [`Done::first`], and those this computer had nothing of. The
    /// first-sync line names them.
    pub taken: Vec<&'static str>,
    /// Where this computer's files were saved before the first sync
    /// replaced them: `pathwarden.toml`, and mapping packs it overwrote.
    pub backups: Vec<PathBuf>,
    /// [`Done::backups`] as the first-sync line names them, from the
    /// folder of `pathwarden.toml` (`packs/acme.toml.before-connect-…`).
    pub backup_names: Vec<String>,
    /// A copy keeps its folder's permissions: the file system has none to
    /// set.
    pub folder_rights: bool,
    /// Sections pushed from here.
    pub pushed: Vec<&'static str>,
    /// The commit's first line, when something was committed.
    pub summary: Option<String>,
    pub published: Option<Published>,
    /// Committed here, but the push failed; the next run that pushes takes
    /// it along.
    pub kept: Option<KeptUnpushed>,
    /// Changed here on a computer that doesn't push: they stay here.
    pub here_only: Vec<&'static str>,
    /// Sections with an entry of two values (or, settled whole, changed
    /// on both sides): left as they are on both.
    pub conflict: Vec<&'static str>,
    /// What the merge brought here from the repository, in words
    /// ("APP01$ added to Tier Zero").
    pub merged: Vec<String>,
    /// The sections those entries are in (keys).
    pub merged_sections: Vec<&'static str>,
    /// What the merge shared from here, in words.
    pub shared: Vec<String>,
    /// The entries with two values a choice settled, one sentence each
    /// ("Stale Tier Zero account: now 60 days, from the shared settings.").
    pub settled: Vec<String>,
    /// The repository has no shared settings yet, and this computer doesn't
    /// push.
    pub nothing_shared: bool,
    /// The repository's settings can't be read here: why. Nothing was
    /// synced.
    pub unreadable: Option<String>,
    /// Packs of the repository's that were not written here, and why: the
    /// rest of their section was applied without them.
    pub skipped: Vec<String>,
    /// What writing the history had to say: one short sentence each
    /// ([`crate::store::write_state_file`]).
    pub notes: Vec<String>,
}

/// What [`sync`] did, and the state it left.
#[derive(Debug)]
pub struct Outcome {
    pub done: Done,
    pub status: Status,
}

impl Outcome {
    /// Whether the settings here changed (a run then reads them again).
    pub fn applied(&self) -> bool {
        !self.done.applied.is_empty() || !self.done.merged.is_empty()
    }

    /// Whether some section changed on both sides is left to settle.
    pub fn conflict(&self) -> bool {
        !self.done.conflict.is_empty()
    }

    /// Whether this needs someone's attention: a section to settle, a
    /// push that failed, a repository file that can't be read.
    pub fn problem(&self) -> bool {
        self.conflict() || self.done.kept.is_some() || self.done.unreadable.is_some()
    }

    /// A few sentences for the command line, or `None` when there is
    /// nothing to say.
    pub fn sentence(&self) -> Option<String> {
        self.words(false, true)
    }

    /// [`Outcome::sentence`] without the entries with two values: for
    /// `pathwarden config sync`, which lists them on lines of their own.
    pub fn sentence_without_clashes(&self) -> Option<String> {
        self.words(false, false)
    }

    /// [`Outcome::sentence`] for the app's pages: plain words, no
    /// commands (they live in the docs).
    pub fn page_sentence(&self) -> Option<String> {
        self.words(true, true)
    }

    fn words(&self, page: bool, clashes: bool) -> Option<String> {
        let d = &self.done;
        let mut out = Vec::new();
        if d.unreadable.is_some() {
            out.extend(self.status.unreadable_words(page));
        }
        out.extend(d.skipped.iter().cloned());
        out.extend(d.notes.iter().cloned());
        if !d.taken.is_empty() {
            let names: Vec<&str> = d.backup_names.iter().map(String::as_str).collect();
            out.push(first_sync_words(&d.taken, &names, d.folder_rights));
        }
        let updates: Vec<&str> = d
            .applied
            .iter()
            .copied()
            .filter(|a| !d.taken.contains(a))
            .collect();
        if !updates.is_empty() {
            out.push(format!(
                "Shared updates applied here: {}.",
                updates.join(", ")
            ));
        }
        if !d.merged.is_empty() {
            out.push(format!(
                "Merged from the shared settings: {}.",
                d.merged.join("; ")
            ));
        }
        if let (Some(s), Some(p)) = (&d.summary, &d.published) {
            if p.pushed {
                let plain = if self.status.encrypted {
                    ""
                } else {
                    ", in plain text (not encrypted)"
                };
                // Only merged entries went: they are named.
                if d.pushed.is_empty() && !d.shared.is_empty() {
                    out.push(format!(
                        "Shared from this computer{plain}: {}.",
                        d.shared.join("; ")
                    ));
                } else {
                    // The first share says no more than that it is shared.
                    out.push(match s.strip_prefix("pathwarden settings: ").unwrap_or(s) {
                        "shared from this environment" => {
                            format!("Shared with this history{plain}.")
                        }
                        what => format!("Shared with this history{plain}: {what}."),
                    });
                }
            }
        }
        out.extend(d.settled.iter().cloned());
        if let Some(k) = &d.kept {
            out.push(k.sentence("The shared settings change is committed"));
        }
        if !d.here_only.is_empty() {
            out.push(if page {
                format!(
                    "Only on this computer: {}. This computer only reads the history, so they \
                     stay here; Use shared settings on Settings replaces them.",
                    d.here_only.join(", ")
                )
            } else {
                format!(
                    "Only on this computer: {}. This computer only reads the history, so they \
                     stay here; `pathwarden config sync --use-repo` replaces them with the \
                     shared settings.",
                    d.here_only.join(", ")
                )
            });
        }
        let waiting = &self.status.clashes;
        if clashes && !waiting.is_empty() {
            let first = clash_words(waiting);
            let each: Vec<String> = waiting.iter().map(Clash::words).collect();
            out.push(if page {
                format!("{first} Choose on Settings. Until then, runs here use this computer's.")
            } else {
                let ids: Vec<&str> = waiting.iter().map(|c| c.id.as_str()).collect();
                let keep = if self.status.pushes {
                    ", `--keep-local` keeps this computer's and shares it"
                } else {
                    ""
                };
                format!(
                    "{first} {}. Until you choose, runs here use this computer's; everything \
                     else is merged. `pathwarden config sync --use-repo` takes the shared \
                     value{keep} (`--section` {} for one).",
                    each.join("; "),
                    ids.join(" or ")
                )
            });
        } else if clashes && !d.conflict.is_empty() {
            // Changed again on another computer while this one pushed.
            let differ = differ_words(&d.conflict);
            out.push(if page {
                format!("{differ} Choose on Settings. Until then, runs here use this computer's.")
            } else {
                format!(
                    "{differ} `pathwarden config sync` merges them again. Until then, runs here \
                     use this computer's."
                )
            });
        }
        (!out.is_empty()).then(|| out.join(" "))
    }
}

/// Brings the shared settings here and in the repository together, each
/// section on its own, as [`Resolve`] says. Hold the history's lock and
/// pull first.
pub fn sync(p: &Place, resolve: Resolve) -> Result<Outcome> {
    // A history refused here (encryption expected, removed, or a key
    // replaced) is refused for settings too: never read or written plain.
    p.store.check_expected()?;
    let r = read_all(p)?;
    let (chosen, use_repo) = match &resolve {
        Resolve::Auto => (Vec::new(), false),
        Resolve::UseRepo(k) => (k.clone(), true),
        Resolve::KeepLocal(k) => (k.clone(), false),
    };
    // Each choice names a section, or one entry with two values
    // (`rules.stale_days`).
    let mut sections_named: Vec<&'static str> = Vec::new();
    let mut entries_named: Vec<(&'static str, String)> = Vec::new();
    for k in &chosen {
        let k = k.trim();
        if let Some(s) = section_key(k) {
            sections_named.push(s);
            continue;
        }
        if let Some(c) = r
            .status
            .clashes
            .iter()
            .find(|c| !c.whole && c.id.eq_ignore_ascii_case(k))
        {
            entries_named.push((c.section, c.entry.clone()));
            continue;
        }
        if r.status.unreadable.is_none()
            && k.split_once('.')
                .is_some_and(|(s, _)| section_key(s).is_some())
        {
            bail!(
                "`{k}` has one value here and in the shared settings, so there is nothing to \
                 choose. `pathwarden config sync --status` lists the settings with two values."
            );
        }
        bail!(
            "`{k}` is not a shared section; use one of {}, or a setting with two values \
             (`pathwarden config sync --status` lists them)",
            SHARED_SECTIONS
                .iter()
                .map(|(k, _)| *k)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    match &resolve {
        Resolve::UseRepo(_) if r.repo_text.is_none() => {
            bail!("The repository has no shared settings yet, so there is nothing to use.")
        }
        Resolve::KeepLocal(_) if !p.pushes => bail!(
            "This computer doesn't push to the history ([state] push = false), so its settings \
             can't go to the repository. `pathwarden config sync --use-repo` drops the changes \
             here."
        ),
        _ => {}
    }
    // A repository file that can't be read: only keeping the settings here
    // (all of them, replacing it) goes on.
    if let Some(why) = &r.status.unreadable {
        // A newer Pathwarden's file is never replaced from here.
        if matches!(resolve, Resolve::KeepLocal(_)) && r.status.newer_format {
            bail!("{NEWER_SETTINGS_WORDS}");
        }
        // Only a damaged file is replaced: a history this computer can't
        // open (no passphrase, refused) isn't overwritten blind.
        if matches!(resolve, Resolve::KeepLocal(_)) && !r.status.damaged {
            bail!(
                "The repository's settings can't be read here ({}), so they can't be replaced \
                 from here either.",
                why.trim_end_matches('.')
            );
        }
        if !matches!(resolve, Resolve::KeepLocal(_)) {
            let done = Done {
                unreadable: Some(why.clone()),
                ..Done::default()
            };
            return Ok(Outcome {
                done,
                status: r.status,
            });
        }
    } else if let Resolve::KeepLocal(_) = &resolve {
        // Only what changed here can be kept: never a section the
        // repository changed alone, which keeping would undo.
        // On a first sync, this computer's own section may be kept too
        // when it is named: the history's would replace it otherwise.
        let unsynced_here = |k: &str| never_synced(r.base.as_ref(), k) && r.local.get(k).is_some();
        for k in &sections_named {
            let s = r.status.sections.iter().find(|s| s.key == *k);
            let keepable = |s: &&Section| {
                matches!(s.state, Changed::Here | Changed::Both | Changed::Merge)
                    || (s.state == Changed::Repository && unsynced_here(s.key))
            };
            if let Some(s) = s.filter(|s| !keepable(s)) {
                bail!(
                    "{} {}: there is no change of this computer's to keep. Only a section not \
                     shared yet, or one that differs from the shared settings, can be kept.",
                    s.name,
                    match s.state {
                        Changed::Repository => "has only a shared update",
                        _ => "is up to date",
                    }
                );
            }
        }
    }
    let keep_local = matches!(resolve, Resolve::KeepLocal(_));
    let mut take_repo: Vec<&'static str> = Vec::new();
    let mut take_local: Vec<&'static str> = Vec::new();
    // Sections merged entry by entry, and what each moves.
    let mut merged: Vec<(&'static str, merge::Plan)> = Vec::new();
    // Clashes (or whole sections) this computer's value was kept for:
    // (section, name, value).
    let mut kept_here: Vec<(&'static str, String, String)> = Vec::new();
    let mut done = Done::default();
    for s in &r.status.sections {
        let named = sections_named.contains(&s.key);
        if let Some(sp) = r.splits.get(s.key) {
            // A reader that takes the shared settings drops its own
            // changes, as for a section changed only here.
            if use_repo && !p.pushes && (named || chosen.is_empty()) {
                take_repo.push(s.key);
                continue;
            }
            let pick = |id: &str| -> Option<Pick> {
                if resolve == Resolve::Auto {
                    return None;
                }
                let picked = named
                    || chosen.is_empty()
                    || entries_named.iter().any(|(k, e)| *k == s.key && e == id);
                picked.then_some(if use_repo { Pick::Shared } else { Pick::Here })
            };
            let plan = sp.plan(&pick);
            if !plan.clashes.is_empty() {
                done.conflict.push(s.name);
            }
            for id in &plan.settled {
                let c = r
                    .status
                    .clashes
                    .iter()
                    .find(|c| c.section == s.key && &c.entry == id);
                if let Some(c) = c {
                    if plan.to_local.contains(id) {
                        done.settled.push(format!(
                            "{}: now {}, from the shared settings.",
                            c.name, c.shared
                        ));
                    } else {
                        // Said once the push is known.
                        kept_here.push((s.key, c.name.clone(), c.here.clone()));
                    }
                }
            }
            merged.push((s.key, plan));
            continue;
        }
        // Keeping this computer's on a first sync keeps what it had of the
        // sections never synced here, rather than taking the history's.
        let unsynced_here = s.state == Changed::Repository
            && never_synced(r.base.as_ref(), s.key)
            && r.local.get(s.key).is_some();
        let by_default = chosen.is_empty()
            && (s.state == Changed::Both
                || (use_repo && s.state == Changed::Here && !p.pushes)
                || (keep_local && unsynced_here));
        let picked = resolve != Resolve::Auto && (named || by_default);
        match s.state {
            Changed::InStep => {}
            _ if picked && use_repo => take_repo.push(s.key),
            _ if picked => take_local.push(s.key),
            Changed::Repository => take_repo.push(s.key),
            Changed::Here if p.pushes => take_local.push(s.key),
            Changed::Here => done.here_only.push(s.name),
            Changed::Both | Changed::Merge => done.conflict.push(s.name),
        }
        if picked && s.state == Changed::Both {
            if use_repo {
                done.settled
                    .push(format!("{}: the shared settings are used here.", s.name));
            } else {
                kept_here.push((s.key, s.name.to_string(), String::new()));
            }
        }
    }
    let mut base = r.base.clone().unwrap_or_default();
    for s in &r.status.sections {
        if s.state == Changed::InStep {
            base.set(s.key, &r.local);
        }
        // Kept only on this computer, never synced: absent at this sync,
        // so a shared version that arrives later differs from it, never replaces it.
        if s.state == Changed::Here
            && done.here_only.contains(&s.name)
            && never_synced(r.base.as_ref(), s.key)
        {
            base.set_absent(s.key);
        }
    }
    // What this computer takes of the merged sections' entries.
    let merged_here: Vec<(&'static str, Vec<String>)> = merged
        .iter()
        .filter(|(_, p)| !p.to_local.is_empty())
        .map(|(k, p)| (*k, p.to_local.clone()))
        .collect();
    let mut left_out: Vec<(&'static str, String)> = Vec::new();
    if !take_repo.is_empty() || !merged_here.is_empty() {
        // Never synced here: the history's replace this computer's, which
        // are saved first.
        let unsynced: Vec<&'static str> = take_repo
            .iter()
            .copied()
            .filter(|k| never_synced(r.base.as_ref(), k))
            .collect();
        let applied = apply_repo(p, &r, &take_repo, &unsynced, &merged_here)?;
        done.applied = applied.names;
        done.first = applied.first.iter().map(|k| section_name(k)).collect();
        done.taken = unsynced.iter().map(|k| section_name(k)).collect();
        done.backups = applied.backups;
        done.backup_names = applied.backup_names;
        done.folder_rights = applied.folder_rights;
        done.skipped = applied.skipped;
        left_out = applied.left_out;
        for k in &take_repo {
            base.set(k, &r.repo);
        }
        // In words, and kept for the app: what came from the repository.
        let mut entries = Vec::new();
        for (key, ids) in &merged_here {
            let sp = &r.splits[key];
            for id in ids {
                if left_out.iter().any(|(k, i)| k == key && i == id) {
                    continue;
                }
                let (old, new) = (sp.local.get(id), sp.repo.get(id));
                entries.push(MergedEntry {
                    section: key.to_string(),
                    id: id.clone(),
                    label: new.or(old).map(|e| e.label.clone()).unwrap_or_default(),
                    added: old.is_none() && new.is_some(),
                    words: merge::change(key, id, old, new),
                    eff: new.map(|e| e.eff.clone()).unwrap_or_default(),
                });
            }
        }
        done.merged = entries.iter().map(|e| e.words.clone()).collect();
        for e in &entries {
            if let Some(k) = section_key(&e.section) {
                if !done.merged_sections.contains(&k) {
                    done.merged_sections.push(k);
                }
            }
        }
        if !entries.is_empty() {
            record_merged(p.store, entries);
        }
    }
    // The merged sections as the repository holds them, with what came here
    // and nothing of this computer's yet: recorded before pushing, so a push
    // that fails, races or is kept never makes what came look like this
    // computer's change.
    let left_of = |key: &str| -> Vec<String> {
        left_out
            .iter()
            .filter(|(k, _)| *k == key)
            .map(|(_, i)| i.clone())
            .collect()
    };
    for (key, plan) in &merged {
        let sp = &r.splits[key];
        base.set_value(
            key,
            merge::build(key, &sp.after(plan, false, &left_of(key))),
        );
    }
    if !merged_here.is_empty() && r.repo_text.is_some() && r.base.as_ref() != Some(&base) {
        base.write(p.store)?;
    }
    // What the repository takes of the merged sections' entries.
    let merged_there: Vec<(&'static str, Vec<String>, Option<toml::Value>)> = merged
        .iter()
        .filter(|(_, plan)| p.pushes && !plan.to_repo.is_empty())
        .map(|(k, plan)| {
            let sp = &r.splits[k];
            (*k, plan.to_repo.clone(), merge::build(k, &sp.in_repo(plan)))
        })
        .collect();
    let mut pushed: Vec<&'static str> = Vec::new();
    let mut raced: Vec<&'static str> = Vec::new();
    if p.pushes && (!take_local.is_empty() || r.repo_text.is_none() || !merged_there.is_empty()) {
        let forced = matches!(resolve, Resolve::KeepLocal(_));
        let (went, lost) = push_local(p, &r, &take_local, &merged_there, forced, &mut done)?;
        if done.kept.is_none() {
            // The pushed sections are this side's now; the repository's
            // others stay as the last sync left them.
            let local = local_side(&read_local(p)?, p.dir())?.0;
            for k in went.iter().filter(|k| !r.splits.contains_key(*k)) {
                base.set(k, &local);
            }
        }
        done.pushed = went
            .iter()
            .filter(|k| take_local.contains(k) || r.repo_text.is_none())
            .map(|k| section_name(k))
            .collect();
        done.conflict.extend(lost.iter().map(|k| section_name(k)));
        pushed = went;
        raced = lost;
    }
    let went_up = |key: &str| pushed.contains(&key) && !raced.contains(&key) && done.kept.is_none();
    for (key, plan) in &merged {
        let sp = &r.splits[key];
        if !plan.to_repo.is_empty() && went_up(key) {
            done.shared.extend(
                plan.to_repo
                    .iter()
                    .map(|id| merge::change(key, id, sp.repo.get(id), sp.local.get(id))),
            );
            base.set_value(key, merge::build(key, &sp.after(plan, true, &left_of(key))));
        }
        if !p.pushes && !plan.to_repo.is_empty() && !done.here_only.contains(&section_name(key)) {
            done.here_only.push(section_name(key));
        }
    }
    for (key, name, value) in &kept_here {
        let what = if value.is_empty() {
            "this computer's are kept".to_string()
        } else {
            format!("kept {value}")
        };
        done.settled.push(if went_up(key) {
            if value.is_empty() {
                format!("{name}: this computer's are kept and shared.")
            } else {
                format!("{name}: {what} and pushed it to the shared settings.")
            }
        } else {
            format!("{name}: {what}; it goes to the shared settings with the next sync.")
        });
    }
    done.conflict.dedup();
    if r.repo_text.is_none() && !p.pushes {
        done.nothing_shared = true;
    }
    if r.base.as_ref() != Some(&base) && r.repo_text.is_some() || done.published.is_some() {
        base.write(p.store)?;
    }
    let changed = !done.applied.is_empty() || !done.merged.is_empty() || done.summary.is_some();
    let status = if changed {
        read_all(p)?.status
    } else {
        r.status
    };
    // Nothing differs any more: a dismissal of the last difference goes.
    if status.differs_key.is_none() && status.unreadable.is_none() {
        clear_dismissed(p.store);
    }
    Ok(Outcome { done, status })
}

/// Replaces the sections `keys` here with the repository's, under the save
/// lock, and writes the packs that come with them. A pack that can't be
/// written here is left out, with its `[[mapping]]` entry, and named.
/// `unsynced`: those of `keys` never synced here. Those this computer had
/// its own (non-empty) version of are a first sync's ([`Applied::first`]):
/// before anything is replaced, `pathwarden.toml` and every pack file it
/// overwrites are saved beside them ([`save_before_connect`]), and if a
/// copy fails nothing is replaced. `merged`: entries of sections merged
/// entry by entry, taken one by one ([`merge::apply`]).
fn apply_repo(
    p: &Place,
    r: &Read,
    keys: &[&'static str],
    unsynced: &[&'static str],
    merged: &[(&'static str, Vec<String>)],
) -> Result<ApplyDone> {
    let repo_text = r.repo_text.as_deref().unwrap_or_default();
    let dir = p.dir().to_path_buf();
    let state_dir = std::fs::canonicalize(&p.store.dir).unwrap_or_else(|_| p.store.dir.clone());
    // Compared part by part, in any case: `packs/state.toml` is not inside
    // `packs/state`.
    let lower = |p: &Path| PathBuf::from(p.to_string_lossy().replace('\\', "/").to_lowercase());
    let last = last_change(p.store);
    let mut skipped: Vec<String> = Vec::new();
    let mut left_out: Vec<(&'static str, String)> = Vec::new();
    // The mapping packs merged in: by ID.
    let merged_packs: Vec<String> = merged
        .iter()
        .filter(|(k, _)| *k == "mapping")
        .flat_map(|(_, ids)| ids.clone())
        .collect();
    let done = config_edit::with_lock(p.config_path, || {
        let original = std::fs::read_to_string(p.config_path).unwrap_or_default();
        let (now, _, _) = local_side(&original, &dir).map_err(|e| format!("{e:#}"))?;
        if keys
            .iter()
            .chain(merged.iter().map(|(k, _)| k))
            .any(|k| now.get(k) != r.local.get(k))
        {
            return Err(format!(
                "{} changed while the repository's settings were read; nothing was changed. \
                 Run `pathwarden config sync` again.",
                p.config_path.display()
            ));
        }
        // Every file is checked, then written to a temporary file, and only
        // then are they all put in place.
        let mut files: Vec<(PathBuf, String)> = Vec::new();
        let mut origins = crate::pack_origin::load(&dir).unwrap_or_default();
        let mut bad: Vec<String> = Vec::new();
        // Pack files here the repository's replace: (file, its name from
        // this folder).
        let mut overwritten: Vec<(PathBuf, String)> = Vec::new();
        let packs_too = keys.contains(&"mapping") || !merged_packs.is_empty();
        if packs_too {
            let canon_dir = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
            let packs = r
                .repo
                .table
                .get("mapping")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_table())
                .filter(|t| {
                    keys.contains(&"mapping")
                        || mapping_path(t).is_some_and(|p| {
                            merged_packs.contains(&crate::pack_origin::path_key(p))
                        })
                });
            for t in packs {
                let Some(path) = mapping_path(t) else {
                    continue;
                };
                let check = || -> Result<(PathBuf, String), String> {
                    let text = t
                        .get("text")
                        .and_then(toml::Value::as_str)
                        .ok_or("the repository doesn't carry its text")?;
                    let rel = pack_path(path)?;
                    crate::config::check_pack_text(text)?;
                    if has_link(&canon_dir, &rel) {
                        return Err("a folder on the way is a symbolic link or junction".into());
                    }
                    let target = canon_dir.join(&rel);
                    if lower(&target).starts_with(lower(&state_dir)) {
                        return Err("it would be written into the history folder".into());
                    }
                    // Only a pack replaces a pack: never another file, nor
                    // one that can't be read as text.
                    let not_a_pack = || {
                        format!(
                            "it would replace {}, which is not a mapping pack",
                            target.display()
                        )
                    };
                    match std::fs::read(&target) {
                        Ok(bytes) => {
                            let existing = String::from_utf8(bytes).map_err(|_| not_a_pack())?;
                            if crate::pack_origin::normalize(&existing) != text
                                && crate::config::check_pack_text(&existing).is_err()
                            {
                                return Err(not_a_pack());
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            return Err(format!("{} can't be read ({e})", target.display()));
                        }
                    }
                    Ok((target, text.to_string()))
                };
                match check() {
                    Ok((target, text)) => {
                        origins.record(crate::pack_origin::RepoPack {
                            path: path.to_string(),
                            sha256: crate::pack_origin::text_digest(&text),
                            added_by: last.as_ref().and_then(|c| c.by.clone()),
                            added_on: last.as_ref().and_then(|c| c.on.clone()),
                            added_at: last.as_ref().map(|c| c.at.clone()),
                            ..Default::default()
                        });
                        // A pack file here the repository's replaces: noted,
                        // for a first sync's copy.
                        // (Checked above: absent, or a pack that reads.)
                        if std::fs::read(&target).is_ok_and(|e| {
                            crate::pack_origin::normalize(&String::from_utf8_lossy(&e)) != text
                        }) {
                            let rel = target
                                .strip_prefix(&canon_dir)
                                .map(|r| r.to_string_lossy().replace('\\', "/"))
                                .unwrap_or_else(|_| target.to_string_lossy().into_owned());
                            overwritten.push((target.clone(), rel));
                        }
                        files.push((target, text));
                    }
                    Err(why) => {
                        skipped.push(format!(
                            "The repository's mapping pack {path} was left out here: {why}."
                        ));
                        bad.push(crate::pack_origin::path_key(path));
                    }
                }
            }
        }
        let mut doc = ConfigDoc::parse(&original)?;
        doc.replace_shared(
            repo_text,
            keys,
            &|t| {
                t.get("path")
                    .and_then(|v| v.as_str())
                    .is_some_and(|path| shareable_pack(&dir, path).is_err())
            },
            &|t| {
                t.get("path")
                    .and_then(|v| v.as_str())
                    .is_some_and(|path| bad.contains(&crate::pack_origin::path_key(path)))
            },
        )?;
        if !merged_packs.is_empty() {
            // A pack the merge removes here takes its record with it.
            let still: Vec<String> = r
                .repo
                .table
                .get("mapping")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_table().and_then(mapping_path))
                .map(crate::pack_origin::path_key)
                .collect();
            origins.packs.retain(|o| {
                let k = crate::pack_origin::path_key(&o.path);
                !merged_packs.contains(&k) || still.contains(&k)
            });
        }
        if !merged.is_empty() {
            let from = ConfigDoc::parse(config_edit::strip_header(repo_text))
                .map_err(|e| format!("the repository's settings are not valid TOML: {e}"))?;
            for (key, ids) in merged {
                // A pack that can't be written here stays as it is here.
                let ids: Vec<String> = ids
                    .iter()
                    .filter(|id| {
                        let out = *key == "mapping" && bad.contains(id);
                        if out {
                            left_out.push((*key, (*id).clone()));
                        }
                        !out
                    })
                    .cloned()
                    .collect();
                merge::apply(doc.doc_mut(), key, &ids, from.doc())?;
            }
            doc.renumber();
        }
        let text = config_edit::same_line_ends(&original, &doc.text());
        config_edit::check(&text)
            .map_err(|e| format!("The repository's settings can't be used here: {e}"))?;
        if packs_too {
            let mut o = serde_json::to_string_pretty(&origins).map_err(|e| e.to_string())?;
            o.push('\n');
            files.push((dir.join(crate::pack_origin::FILE), o));
        }
        files.push((p.config_path.to_path_buf(), text));
        // A first sync's: sections never synced here that this computer had
        // its own version of, packs it had among them.
        let packs_replaced = unsynced.contains(&"mapping") && !overwritten.is_empty();
        let first: Vec<&'static str> = unsynced
            .iter()
            .copied()
            .filter(|k| now.get(k).is_some() || (*k == "mapping" && packs_replaced))
            .collect();
        // Saved before anything is replaced: no copy, no change.
        let mut copies: Vec<(PathBuf, String)> = Vec::new();
        let mut folder_rights = false;
        if !first.is_empty() {
            let own = p.config_path.file_name().map_or_else(
                || "pathwarden.toml".into(),
                |n| n.to_string_lossy().into_owned(),
            );
            let mut sources: Vec<(PathBuf, String)> = vec![(p.config_path.to_path_buf(), own)];
            if packs_replaced {
                sources.extend(overwritten.iter().cloned());
            }
            for (file, name) in sources {
                match save_before_connect(&file) {
                    Ok(Some((copy, plain))) => {
                        folder_rights |= plain;
                        let copy_name = copy
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        let shown = match name.rsplit_once('/') {
                            Some((folder, _)) => format!("{folder}/{copy_name}"),
                            None => copy_name,
                        };
                        copies.push((copy, shown));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        for (c, _) in &copies {
                            let _ = std::fs::remove_file(c);
                        }
                        return Err(format!(
                            "{e}. Nothing was changed: this computer's settings are saved \
                             before the history's replace them."
                        ));
                    }
                }
            }
        }
        write_all(&files)?;
        Ok((first, copies, folder_rights))
    })
    .map_err(anyhow::Error::msg)?;
    let (first, copies, folder_rights) = done;
    let names: Vec<&'static str> = keys.iter().map(|k| section_name(k)).collect();
    if keys.is_empty() {
        // Only entries merged: the merge's own record says what came.
        return Ok(ApplyDone {
            names,
            first,
            backups: Vec::new(),
            backup_names: Vec::new(),
            folder_rights,
            skipped,
            left_out,
        });
    }
    // A first sync's notice the app hasn't shown yet stays: this record
    // adds to it.
    let earlier = unseen_applied(p.store, false).filter(|a| a.first.is_some());
    let mut first_names: Vec<String> = earlier
        .as_ref()
        .and_then(|a| a.first.clone())
        .unwrap_or_default();
    for k in unsynced {
        let n = section_name(k).to_string();
        if !first_names.contains(&n) {
            first_names.push(n);
        }
    }
    let mut backups: Vec<String> = earlier
        .as_ref()
        .map(|a| a.backups.clone())
        .unwrap_or_default();
    backups.extend(copies.iter().map(|(_, n)| n.clone()));
    let mut sections: Vec<String> = earlier
        .as_ref()
        .map(|a| a.sections.clone())
        .unwrap_or_default();
    for n in &names {
        if !sections.iter().any(|s| s == n) {
            sections.push(n.to_string());
        }
    }
    let me = Applied {
        first: (!first_names.is_empty()).then_some(first_names),
        backups,
        folder_rights: folder_rights || earlier.as_ref().is_some_and(|a| a.folder_rights),
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64),
        sections,
        summary: last.as_ref().map(|c| c.summary.clone()),
        by: last.as_ref().and_then(|c| c.by.clone()),
        on: last.as_ref().and_then(|c| c.on.clone()),
        changed_at: last.as_ref().map(|c| c.at.clone()),
        seen: false,
    };
    p.store
        .write_local_file(APPLIED_FILE, &serde_json::to_vec_pretty(&me)?)?;
    Ok(ApplyDone {
        names,
        first,
        backups: copies.iter().map(|(c, _)| c.clone()).collect(),
        backup_names: copies.into_iter().map(|(_, n)| n).collect(),
        folder_rights,
        skipped,
        left_out,
    })
}

/// What [`apply_repo`] did.
struct ApplyDone {
    /// The sections applied, in plain words.
    names: Vec<&'static str>,
    /// Those a first sync took over this computer's own (keys).
    first: Vec<&'static str>,
    /// The copies saved first, and their names from the folder of
    /// `pathwarden.toml`.
    backups: Vec<PathBuf>,
    backup_names: Vec<String>,
    /// A copy keeps its folder's rights: the file system has no
    /// permissions to set.
    folder_rights: bool,
    /// Packs left out, and why.
    skipped: Vec<String>,
    /// Entries merged in that were left out (packs that can't be written
    /// here): (section, ID).
    left_out: Vec<(&'static str, String)>,
}

#[cfg(test)]
thread_local! {
    /// Tests: the next copies fail, as a full disk would.
    static FAIL_COPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Tests: making the next copies private fails: `Some(true)` as on a
    /// file system without permissions, `Some(false)` as a refusal.
    static PRIVATE_FAILS: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Whether `e`, from setting a file's permissions, says the file system
/// has none to set (FAT and exFAT, some SMB and NAS shares): the file then
/// keeps its folder's rights, as the original does. Any other failure is
/// a refusal.
fn permissions_unsupported(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::Unsupported {
        return true;
    }
    match e.raw_os_error() {
        // ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED.
        #[cfg(windows)]
        Some(1 | 50) => true,
        // EPERM on a file this process just created is a file system that
        // keeps no modes (vfat, exFAT); ENOTSUP / EOPNOTSUPP.
        #[cfg(target_os = "linux")]
        Some(1 | 95) => true,
        #[cfg(target_os = "macos")]
        Some(1 | 45 | 102) => true,
        _ => false,
    }
}

/// Saves a file this computer has (its `pathwarden.toml`, or a mapping
/// pack; read under the save lock) beside it as
/// `<name>.before-connect-<YYYY-MM-DD>` (this computer's date; `-2`, `-3`,
/// ... when that one is taken), before a first sync replaces it. Never
/// overwrites a file. The copy is private to this account (mode 600 from
/// its creation on Unix; this account, Administrators and SYSTEM on
/// Windows); when that is refused the copy is removed and fails, and on a
/// file system with no permissions to set it keeps its folder's rights, as
/// the original does (the second value then). `None` when the file isn't
/// there.
fn save_before_connect(config_path: &Path) -> Result<Option<(PathBuf, bool)>, String> {
    use std::io::Write as _;
    #[cfg(test)]
    if FAIL_COPY.with(std::cell::Cell::get) {
        return Err(format!(
            "Could not save a copy of {}: failing for the test",
            config_path.display()
        ));
    }
    let bytes = match std::fs::read(config_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Could not read {}: {e}", config_path.display())),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let day = crate::time::format_iso_date(now + crate::time::local_offset(now));
    let name = config_path
        .file_name()
        .map_or_else(|| "pathwarden.toml".into(), |n| n.to_string_lossy());
    for i in 1..1000 {
        let suffix = if i == 1 {
            String::new()
        } else {
            format!("-{i}")
        };
        let target = config_path.with_file_name(format!("{name}.before-connect-{day}{suffix}"));
        let mut open = std::fs::OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            open.mode(0o600);
        }
        let mut f = match open.open(&target) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("Could not save {}: {e}", target.display())),
        };
        // Private before it holds anything, or no copy, unless the file
        // system has no permissions to set.
        let private = crate::perms::make_output_file_private(&target);
        #[cfg(test)]
        let private = match PRIVATE_FAILS.with(std::cell::Cell::get) {
            Some(true) => Err(std::io::Error::from(std::io::ErrorKind::Unsupported)),
            Some(false) => Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            None => private,
        };
        let folder_rights = match private {
            Ok(()) => false,
            Err(e) if permissions_unsupported(&e) => true,
            Err(e) => {
                drop(f);
                let _ = std::fs::remove_file(&target);
                return Err(format!(
                    "Could not make {} private to this account: {e}",
                    target.display()
                ));
            }
        };
        if let Err(e) = f.write_all(&bytes).and_then(|()| f.sync_all()) {
            drop(f);
            let _ = std::fs::remove_file(&target);
            return Err(format!("Could not save {}: {e}", target.display()));
        }
        return Ok(Some((target, folder_rights)));
    }
    Err(format!(
        "Could not save a copy of {} before the first sync: too many copies today.",
        config_path.display()
    ))
}

/// Writes every file to a temporary one beside it, then renames them all
/// into place: a failure before the renames leaves everything as it was.
fn write_all(files: &[(PathBuf, String)]) -> Result<(), String> {
    let mut temps: Vec<(PathBuf, &Path)> = Vec::new();
    let clean = |temps: &[(PathBuf, &Path)]| {
        for (t, _) in temps {
            let _ = std::fs::remove_file(t);
        }
    };
    for (target, text) in files {
        if std::fs::symlink_metadata(target).is_ok_and(|m| m.file_type().is_symlink()) {
            clean(&temps);
            return Err(format!(
                "{} is a symbolic link; not written",
                target.display()
            ));
        }
        if let Some(parent) = target.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                clean(&temps);
                return Err(format!("Could not create {}: {e}", parent.display()));
            }
        }
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let tmp = target.with_file_name(format!(".{name}.{}.sync.tmp", std::process::id()));
        if let Err(e) = std::fs::write(&tmp, text) {
            clean(&temps);
            return Err(format!("Could not write {}: {e}", tmp.display()));
        }
        temps.push((tmp, target));
    }
    for (i, (tmp, target)) in temps.iter().enumerate() {
        if let Err(e) = std::fs::rename(tmp, target) {
            clean(&temps[i..]);
            return Err(format!("Could not write {}: {e}", target.display()));
        }
    }
    Ok(())
}

/// A section merged entry by entry, for [`push_local`]: its key, the entries
/// the repository takes from here, and the section that makes.
type MergedThere = (&'static str, Vec<String>, Option<toml::Value>);

/// Commits the sections `keys` from here, on top of the repository's
/// other sections, and pushes. `forced`: even when the repository changed
/// them meanwhile (`--keep-local`). `merged`: sections merged entry by
/// entry, with the entries the repository takes from here and the section
/// that makes. Returns the sections pushed, and those another machine
/// changed while this was pushing (left as they are).
fn push_local(
    p: &Place,
    r: &Read,
    keys: &[&'static str],
    merged: &[MergedThere],
    forced: bool,
    done: &mut Done,
) -> Result<(Vec<&'static str>, Vec<&'static str>)> {
    // Read again: applying the repository's other sections changed the
    // file, not these.
    let local_text = read_local(p)?;
    let doc = ConfigDoc::parse(&local_text).map_err(anyhow::Error::msg)?;
    let dir = p.dir().to_path_buf();
    let share = |t: &toml_edit::Table| {
        t.get("path")
            .and_then(|v| v.as_str())
            .is_some_and(|path| shareable_pack(&dir, path).is_ok())
    };
    // The first push takes every section from here.
    let initial = r.repo_text.is_none();
    let mut taken: Vec<&'static str> = if initial {
        SHARED_SECTIONS.iter().map(|(k, _)| *k).collect()
    } else {
        keys.to_vec()
    };
    let mut raced: Vec<&'static str> = Vec::new();
    let mut merging: Vec<&'static str> = merged.iter().map(|(k, ..)| *k).collect();
    // The repository's file with the merged sections' entries from here.
    let merge_into = |repo: Option<&str>, merging: &[&'static str]| -> Result<Option<String>> {
        if merging.is_empty() {
            return Ok(repo.map(str::to_string));
        }
        let mut rd = ConfigDoc::parse(repo.map(config_edit::strip_header).unwrap_or_default())
            .map_err(anyhow::Error::msg)?;
        for (k, ids, _) in merged.iter().filter(|(k, ..)| merging.contains(k)) {
            merge::apply(rd.doc_mut(), k, ids, doc.doc()).map_err(anyhow::Error::msg)?;
            if *k == "mapping" {
                // The packs' text travels beside them: this computer's for
                // the packs from here, the repository's for the others.
                let text_of = |side: &Side, key: &str| -> Option<String> {
                    side.table
                        .get("mapping")?
                        .as_array()?
                        .iter()
                        .filter_map(|t| t.as_table())
                        .find(|t| {
                            mapping_path(t).map(crate::pack_origin::path_key).as_deref()
                                == Some(key)
                        })?
                        .get("text")?
                        .as_str()
                        .map(str::to_string)
                };
                let paths: Vec<String> = rd
                    .doc()
                    .get("mapping")
                    .and_then(toml_edit::Item::as_array_of_tables)
                    .into_iter()
                    .flatten()
                    .filter_map(|t| t.get("path").and_then(|v| v.as_str()).map(str::to_string))
                    .collect();
                let mut files = toml_edit::ArrayOfTables::new();
                for path in paths {
                    let key = crate::pack_origin::path_key(&path);
                    let side = if ids.contains(&key) {
                        &r.local
                    } else {
                        &r.repo
                    };
                    if let Some(text) = text_of(side, &key) {
                        let mut t = toml_edit::Table::new();
                        t.insert("path", toml_edit::value(path.as_str()));
                        t.insert("text", toml_edit::value(text));
                        files.push(t);
                    }
                }
                let root = rd.doc_mut().as_table_mut();
                root.remove(MAPPING_FILES);
                if !files.is_empty() {
                    root.insert(MAPPING_FILES, toml_edit::Item::ArrayOfTables(files));
                }
            }
        }
        rd.renumber();
        Ok(Some(rd.text()))
    };
    let build = |repo: Option<&str>,
                 taken: &[&'static str],
                 merging: &[&'static str]|
     -> Result<(String, ChangeRecord, String)> {
        let into = merge_into(repo, merging)?;
        let text = doc.shared_text(
            HEADER,
            &|k| taken.contains(&k),
            &share,
            &r.packs,
            into.as_deref(),
        );
        let (after, _) = repo_side(&text)?;
        for k in taken {
            if after.get(k) != r.local.get(k) {
                bail!("the shared settings written for the repository don't read back the same");
            }
        }
        for (k, _, want) in merged.iter().filter(|(k, ..)| merging.contains(k)) {
            if !merge::same(k, after.table.get(*k), want.as_ref()) {
                bail!("the shared settings merged for the repository don't read back the same");
            }
        }
        let before = match repo {
            Some(t) => repo_side(t)?.0,
            None => Side::default(),
        };
        // The first share into a repository without settings: nothing
        // there to compare with, so nothing "changed".
        let mut parts = match repo {
            Some(_) => describe(&before.table, &after.table),
            None => Vec::new(),
        };
        if (initial || repo.is_none()) && parts.is_empty() {
            parts.push("shared from this environment".into());
        }
        let changed: Vec<&str> = taken
            .iter()
            .chain(merging)
            .copied()
            .filter(|k| before.get(k) != after.get(k))
            .collect();
        let rec = change_record(&parts, &changed);
        let message = commit_message_of(&rec, private_messages(p.store));
        Ok((text, rec, message))
    };
    // What the writes have to say (an upgrade of the history's binding
    // that couldn't rewrite every file), for the sync's notes.
    let said = std::cell::RefCell::new(Vec::<String>::new());
    let write = |text: &str, rec: &ChangeRecord| -> Result<()> {
        // A newer Pathwarden's files are never written over
        // (docs/dev/formats.md), forced or not.
        if repo_settings_newer(p.store) {
            bail!("{NEWER_SETTINGS_WORDS}");
        }
        if environment_newer(p.store) {
            bail!(
                "The repository's {ENVIRONMENT_FILE} was saved by a newer Pathwarden. Update \
                 Pathwarden to change the shared settings."
            );
        }
        let mut notes = p.store.write_state_file(SETTINGS_FILE, text.as_bytes())?;
        let mut json = serde_json::to_string_pretty(&environment_now(p))?;
        json.push('\n');
        notes.extend(
            p.store
                .write_state_file(ENVIRONMENT_FILE, json.as_bytes())?,
        );
        let mut json = serde_json::to_string_pretty(rec)?;
        json.push('\n');
        notes.extend(
            p.store
                .write_state_file(LAST_CHANGE_FILE, json.as_bytes())?,
        );
        // Only the last try's notes say how it stands.
        *said.borrow_mut() = notes;
        Ok(())
    };
    let (text, rec, message) = build(r.repo_text.as_deref(), &taken, &merging)?;
    write(&text, &rec)?;
    let summary = rec.summary.clone();
    let result = p.store.publish_with(&message, || {
        // Another machine pushed first: the working copy is at its state.
        // Kept over a file that can't be read: built afresh.
        let now = match read_repo(p.store) {
            Ok(n) => n.filter(|t| !forced || repo_side(t).is_ok()),
            Err(_) if forced => None,
            Err(e) => return Err(e),
        };
        if !forced {
            let now_side = match &now {
                Some(t) => repo_side(t)?.0,
                None => Side::default(),
            };
            // A section it changed meanwhile is left to settle.
            let (keep, lost): (Vec<_>, Vec<_>) = taken
                .iter()
                .partition(|k| initial || now_side.get(k) == r.repo.get(k));
            raced.extend(lost);
            taken = keep;
            merging.retain(|k| {
                let same = now_side.get(k) == r.repo.get(k);
                if !same {
                    raced.push(k);
                }
                same
            });
        }
        if taken.is_empty() && merging.is_empty() {
            return Ok(None);
        }
        let (text, rec, message) = build(now.as_deref(), &taken, &merging)?;
        write(&text, &rec)?;
        Ok(Some(message))
    });
    done.notes = crate::store::once_each(said.take());
    taken.extend(merging);
    match result {
        Ok(published) => {
            if !taken.is_empty() {
                done.summary = Some(summary);
            }
            done.published = Some(published);
            Ok((taken, raced))
        }
        Err(e) => match e.downcast::<KeptUnpushed>() {
            Ok(k) => {
                done.summary = Some(summary);
                done.kept = Some(k);
                Ok((taken, raced))
            }
            Err(e) => Err(e),
        },
    }
}

/// When a sync applied the repository's settings here, for the app to say
/// once ("Accepted risks updated from the repository").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Applied {
    /// When it was applied (Unix seconds).
    pub at: i64,
    /// The sections, in plain words.
    pub sections: Vec<String>,
    /// The last settings commit's first line, and who made it where and
    /// when, as recorded.
    pub summary: Option<String>,
    pub by: Option<String>,
    pub on: Option<String>,
    pub changed_at: Option<String>,
    /// The sections taken on this computer's first sync, when it was one.
    #[serde(default)]
    pub first: Option<Vec<String>>,
    /// The copies saved before the first sync, by their names from the
    /// folder of `pathwarden.toml` (`pathwarden.toml.before-connect-…`,
    /// `packs/acme.toml.before-connect-…`).
    #[serde(default)]
    pub backups: Vec<String>,
    /// A copy keeps its folder's permissions (a file system without
    /// permissions to set).
    #[serde(default)]
    pub folder_rights: bool,
    /// The app showed it.
    #[serde(default)]
    pub seen: bool,
}

/// What the last sync applied here, if it was not shown yet. `mark_seen`:
/// it won't be returned again.
pub fn unseen_applied(store: &Store, mark_seen: bool) -> Option<Applied> {
    let mut a: Applied = serde_json::from_slice(&store.read_local_file(APPLIED_FILE)?).ok()?;
    if a.seen {
        return None;
    }
    if mark_seen {
        a.seen = true;
        let _ = serde_json::to_vec_pretty(&a).map(|b| store.write_local_file(APPLIED_FILE, &b));
        a.seen = false;
    }
    Some(a)
}

/// Pushes settings commits a failed push left here, when this computer
/// pushes (`config sync`). A note for the user.
pub fn push_kept(store: &Store, pushes: bool) -> Option<String> {
    if !pushes || !store.has_unpushed() {
        return None;
    }
    match store.publish_with("pathwarden: changes kept from an earlier push", || Ok(None)) {
        Ok(p) if p.pushed => {
            Some("Changes kept here from an earlier failed push were pushed.".into())
        }
        Ok(_) => None,
        Err(e) => Some(match e.downcast::<KeptUnpushed>() {
            Ok(k) => k.sentence("Changes kept from an earlier push are still committed"),
            Err(e) => format!("Changes kept from an earlier push could not be pushed: {e:#}"),
        }),
    }
}

// ------------------------------------------------------- the messages

/// What changed from `old` to `new`, in a few words each: "1 Tier Zero
/// addition", "2 accepted risks changed".
fn describe(old: &toml::Table, new: &toml::Table) -> Vec<String> {
    let mut out = Vec::new();
    let count = |n: usize, one: &str, many: &str| crate::text::count(n, one, many);
    let strings = |t: &toml::Table, k: &str| -> Vec<String> {
        t.get(k)
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_lowercase()))
            .collect()
    };
    let (a, b) = (strings(old, "tier_zero"), strings(new, "tier_zero"));
    let added = b.iter().filter(|x| !a.contains(x)).count();
    let removed = a.iter().filter(|x| !b.contains(x)).count();
    if added > 0 {
        out.push(count(added, "Tier Zero addition", "Tier Zero additions"));
    }
    if removed > 0 {
        out.push(count(removed, "Tier Zero removal", "Tier Zero removals"));
    }
    if strings(old, "settings_folders") != strings(new, "settings_folders") {
        out.push("Tier Zero settings folders changed".into());
    }
    if old.get("rules") != new.get("rules") {
        out.push("rule settings changed".into());
    }
    let keyed = |t: &toml::Table, k: &str, id: &dyn Fn(&toml::Table) -> String| {
        t.get(k)
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_table())
            .map(|t| (id(t), t.clone()))
            .collect::<BTreeMap<String, toml::Table>>()
    };
    let risk_id = |t: &toml::Table| {
        t.get("fingerprint")
            .or(t.get("rule"))
            .and_then(toml::Value::as_str)
            .unwrap_or_default()
            .to_lowercase()
    };
    let zone_id = |t: &toml::Table| {
        crate::zones::name_key(
            t.get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or_default(),
        )
    };
    let notes = |t: &toml::Table| {
        t.get("notes")
            .and_then(toml::Value::as_array)
            .map_or(0, Vec::len)
    };
    let without_notes = |t: &toml::Table| {
        let mut t = t.clone();
        t.remove("notes");
        digest(&toml::Value::Table(t))
    };
    for (key, id, one, many) in [
        (
            "suppress",
            &risk_id as &dyn Fn(&toml::Table) -> String,
            "accepted risk",
            "accepted risks",
        ),
        ("zone", &zone_id, "zone", "zones"),
    ] {
        let (a, b) = (keyed(old, key, id), keyed(new, key, id));
        let added = b.keys().filter(|k| !a.contains_key(*k)).count();
        let removed = a.keys().filter(|k| !b.contains_key(*k)).count();
        let changed = b
            .iter()
            .filter(|(k, t)| {
                a.get(*k)
                    .is_some_and(|o| without_notes(o) != without_notes(t))
            })
            .count();
        for (n, what) in [(added, "added"), (changed, "changed"), (removed, "removed")] {
            if n > 0 {
                out.push(format!("{} {what}", count(n, one, many)));
            }
        }
        if key == "suppress" {
            let more: usize = b
                .iter()
                .filter_map(|(k, t)| a.get(k).map(|o| notes(t).saturating_sub(notes(o))))
                .sum();
            if more > 0 {
                out.push(format!("{} added", count(more, "note", "notes")));
            }
        }
    }
    if old.get("management_planes") != new.get("management_planes") {
        out.push("management planes changed".into());
    }
    if old.get("mapping") != new.get("mapping") {
        out.push("mapping packs changed".into());
    }
    out
}

/// The last change to the shared settings, as `settings/last-change.json`
/// keeps it in the repository: a state file, so with repository encryption
/// it is encrypted too, while the commit message then says nothing more
/// than "pathwarden settings" ([`private_messages`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChangeRecord {
    /// The record's format ([`LAST_CHANGE_FORMAT`], docs/dev/formats.md):
    /// absent (before 0.2) means 1. One of a newer format isn't shown; the
    /// commit says what changed instead.
    #[serde(default = "first_format")]
    pub format: u32,
    /// "pathwarden settings: 1 Tier Zero addition".
    pub summary: String,
    /// The sections it changed (`tier_zero`, `suppress`, ...).
    #[serde(default)]
    pub sections: Vec<String>,
    /// Who made it in Pathwarden, on which computer: a record, not a proof.
    #[serde(default)]
    pub by: Option<String>,
    #[serde(default)]
    pub on: Option<String>,
    /// When, RFC 3339 in UTC.
    #[serde(default)]
    pub at: String,
    #[serde(default)]
    pub version: String,
}

/// Where [`ChangeRecord`] is kept.
pub const LAST_CHANGE_FILE: &str = crate::store::LAST_CHANGE_FILE;

/// Whether settings commits must not say what changed or who changed it:
/// when the history is encrypted. Their message is then only "pathwarden
/// settings", and who and what are kept in the encrypted
/// settings/last-change.json.
fn private_messages(store: &Store) -> bool {
    store.is_encrypted()
}

fn change_record(parts: &[String], sections: &[&str]) -> ChangeRecord {
    let what = if parts.is_empty() {
        "environment details".to_string()
    } else {
        parts.join(", ")
    };
    let me = crate::identity::Actor::current();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    ChangeRecord {
        format: LAST_CHANGE_FORMAT,
        summary: format!("pathwarden settings: {what}"),
        sections: sections.iter().map(|s| s.to_string()).collect(),
        by: me.user,
        on: me.computer,
        at: crate::time::format_rfc3339(now),
        version: VERSION.to_string(),
    }
}

/// The commit message: what changed, then the sections, who changed it in
/// Pathwarden (git records its own author too) and with which version; or,
/// when the history is encrypted, only "pathwarden settings".
fn commit_message_of(rec: &ChangeRecord, private: bool) -> String {
    if private {
        return "pathwarden settings\n".into();
    }
    let mut m = format!("{}\n\n", rec.summary);
    if !rec.sections.is_empty() {
        m.push_str(&format!("Sections: {}\n", rec.sections.join(", ")));
    }
    if let Some(u) = &rec.by {
        m.push_str(&format!("Changed-by: {u}\n"));
    }
    if let Some(c) = &rec.on {
        m.push_str(&format!("Changed-on: {c}\n"));
    }
    m.push_str(&format!("Pathwarden: {}\n", rec.version));
    m
}

#[cfg(test)]
fn commit_message(parts: &[String], sections: &[&str]) -> String {
    commit_message_of(&change_record(parts, sections), false)
}

/// The repository's `last-change.json`, when it reads and is of a format
/// this version knows: a newer Pathwarden's record isn't shown as this
/// one's.
fn change_record_in(store: &Store) -> Option<ChangeRecord> {
    store
        .read_state_file(LAST_CHANGE_FILE)
        .ok()
        .flatten()
        .filter(|b| b.len() <= MAX_ENVIRONMENT_BYTES)
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .filter(|v| crate::formats::of_json(v, "format", LAST_CHANGE_FORMAT).is_known())
        .and_then(|v| serde_json::from_value(v).ok())
}

fn last_change(store: &Store) -> Option<LastChange> {
    let c = store.last_settings_commit()?;
    // The repository's own record first: it is all there is when the
    // commit messages say nothing.
    if let Some(rec) = change_record_in(store) {
        return Some(LastChange {
            summary: rec.summary,
            git_author: format!("{} <{}>", c.author, c.email),
            at: if rec.at.is_empty() {
                c.at.clone()
            } else {
                rec.at
            },
            by: rec.by,
            on: rec.on,
            sections: rec
                .sections
                .iter()
                .filter_map(|k| section_key(k.trim()))
                .map(section_name)
                .collect(),
            commit: c.commit,
        });
    }
    let trailer = |k: &str| {
        c.message
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    Some(LastChange {
        summary: c.message.lines().next().unwrap_or_default().to_string(),
        git_author: format!("{} <{}>", c.author, c.email),
        at: c.at.clone(),
        by: trailer("Changed-by:"),
        on: trailer("Changed-on:"),
        sections: trailer("Sections:")
            .map(|s| {
                s.split(',')
                    .filter_map(|k| section_key(k.trim()))
                    .map(section_name)
                    .collect()
            })
            .unwrap_or_default(),
        commit: c.commit,
    })
}

// -------------------------------------------------------- environment

/// `settings/environment.json`: what the environment is, and which
/// Pathwarden wrote its settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Environment {
    /// The record's format ([`ENVIRONMENT_FORMAT`], docs/dev/formats.md):
    /// absent (before 0.2) means 1.
    #[serde(default = "first_format")]
    pub format: u32,
    #[serde(default)]
    pub name: Option<String>,
    /// The domains of the latest run.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Scope keys of the domains the latest run collected
    /// ([`crate::state::HistoryPoint::scopes`]).
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub trusted_scopes: Vec<String>,
    #[serde(default)]
    pub written_by_version: String,
}

/// The newest `environment.json` format this version reads.
pub const ENVIRONMENT_FORMAT: u32 = 1;

/// The newest `last-change.json` format this version reads.
pub const LAST_CHANGE_FORMAT: u32 = 1;

fn first_format() -> u32 {
    1
}

/// The repository's `environment.json`, when it has one (and it is no
/// larger than 64 KiB), of a format this version reads.
pub fn environment(store: &Store) -> Option<Environment> {
    let v = environment_value(store)?;
    if !crate::formats::of_json(&v, "format", ENVIRONMENT_FORMAT).is_known() {
        return None;
    }
    serde_json::from_value(v).ok()
}

/// `environment.json` as JSON, when it is there, no larger than 64 KiB,
/// and JSON at all.
pub fn environment_value(store: &Store) -> Option<serde_json::Value> {
    let bytes = store.read_state_file(ENVIRONMENT_FILE).ok()??;
    if bytes.len() > MAX_ENVIRONMENT_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Whether the repository's `environment.json` is of a format this
/// version doesn't know: it is then never written over. (One that isn't
/// JSON, or is too large to read, is damaged, and is replaced.)
fn environment_newer(store: &Store) -> bool {
    environment_value(store)
        .is_some_and(|v| !crate::formats::of_json(&v, "format", ENVIRONMENT_FORMAT).is_known())
}

fn environment_now(p: &Place) -> Environment {
    let old = environment(p.store).unwrap_or_default();
    let last = crate::store::last_run(p.store);
    let points = crate::history::load(&p.store.dir)
        .map(|(points, _)| points)
        .unwrap_or_default();
    let latest = crate::since::latest_point(&points);
    Environment {
        format: ENVIRONMENT_FORMAT,
        name: p.env_name.map(str::to_string).or(old.name),
        domains: last.map(|l| l.domains).unwrap_or(old.domains),
        scopes: latest.map(|l| l.scopes.clone()).unwrap_or(old.scopes),
        trusted_scopes: latest
            .and_then(|l| l.trusted_scopes.clone())
            .unwrap_or(old.trusted_scopes),
        written_by_version: VERSION.to_string(),
    }
}

/// Whether version `a` ("0.1.9") is newer than `b`.
fn newer(a: &str, b: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> {
        v.trim()
            .split(['.', '-', '+'])
            .take(3)
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    };
    parts(a) > parts(b)
}

// ------------------------------------------------------ the callers

/// After a save of `config_path`: whether the shared settings changed
/// (from `before` to `after`, the file's text), so the change should be
/// shared.
pub fn shared_changed(before: &str, after: &str, config_path: &Path) -> bool {
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    match (local_side(before, dir), local_side(after, dir)) {
        (Ok((a, ..)), Ok((b, ..))) => a.all() != b.all(),
        _ => true,
    }
}

/// What became of the shared settings after a pull or a save, for the
/// user: in the command line's words (with commands) and the pages'
/// (without: the commands live in the docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Note {
    pub text: String,
    /// The same, for the app's pages.
    pub page: String,
    /// It needs attention: a section to settle, a push that failed, the
    /// history in use, the repository out of reach.
    pub problem: bool,
}

impl Note {
    fn both(text: String, page: String, problem: bool) -> Self {
        Note {
            text,
            page,
            problem,
        }
    }
}

impl std::fmt::Display for Note {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// After a pull: [`sync`] as on every pull, told as a note for the user
/// (`None` when there is nothing to say). A failure is a note too: a run
/// never stops over settings. The second value says whether the settings
/// here changed, so a run reads them again.
pub fn after_pull(p: &Place) -> (Option<Note>, bool) {
    let d = after_pull_detail(p);
    let applied = !d.applied.is_empty();
    (d.note, applied)
}

/// What [`after_pull_detail`] did.
#[derive(Debug, Default)]
pub struct AfterPull {
    /// [`after_pull`]'s note.
    pub note: Option<Note>,
    /// The sections the repository's were applied here, by key
    /// (`tier_zero`, `rules`, ...).
    pub applied: Vec<&'static str>,
    /// Some entry has two values ([`Clash`]).
    pub conflict: bool,
}

/// [`after_pull`], with the sections it applied and whether one waits for
/// a choice: what the app's pull status and notes say.
pub fn after_pull_detail(p: &Place) -> AfterPull {
    match sync(p, Resolve::Auto) {
        Ok(o) => AfterPull {
            note: o
                .sentence()
                .map(|text| Note::both(text, o.page_sentence().unwrap_or_default(), o.problem())),
            applied: {
                let mut keys: Vec<&'static str> = o
                    .done
                    .applied
                    .iter()
                    .filter_map(|name| {
                        SHARED_SECTIONS
                            .iter()
                            .find(|(_, n)| n == name)
                            .map(|(k, _)| *k)
                    })
                    .collect();
                for k in &o.done.merged_sections {
                    if !keys.contains(k) {
                        keys.push(k);
                    }
                }
                keys
            },
            conflict: o.conflict(),
        },
        Err(e) => {
            let t = format!("The shared settings could not be synced: {e:#}");
            AfterPull {
                note: Some(Note::both(t.clone(), t, true)),
                ..AfterPull::default()
            }
        }
    }
}

/// How long a save, a sync or a recording waits for a run (or another
/// save) that holds the history, before it gives up and says so: 60
/// seconds, or `PATHWARDEN_LOCK_WAIT` seconds (0: don't wait).
pub fn lock_wait() -> std::time::Duration {
    let secs = std::env::var("PATHWARDEN_LOCK_WAIT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(60)
        .min(3600);
    std::time::Duration::from_secs(secs)
}

/// After a save of `config_path` changed the shared settings: takes the
/// history's lock (waiting up to [`lock_wait`] for a run or another save
/// that holds it), pulls and [`sync`]s, so a machine that pushes shares the
/// change at once. Git can't prompt for a sign-in meanwhile
/// ([`crate::store::non_interactive`]). `base` is where a relative
/// `[state] path` starts (the environment's folder in the app's workspace,
/// the current folder for `-c FILE`). Returns a note for the user; never
/// fails the save.
pub fn share_after_save(config_path: &Path, base: &Path, env_name: Option<&str>) -> Option<Note> {
    let text = std::fs::read_to_string(config_path).ok()?;
    let config = config_edit::check(&text).ok()?;
    let state = &config.state;
    // A computer that only reads keeps its changes here: the next pull
    // reports them.
    if inactive(state).is_some() || !state.pushes() {
        return None;
    }
    let problem = |text: String, page: String| Some(Note::both(text, page, true));
    let store = match Store::new(state, Some(&state_dir(state, base))) {
        Ok(s) => s,
        Err(e) => {
            let t = format!("Saved here; the shared settings could not be synced: {e:#}");
            return problem(t.clone(), t);
        }
    };
    let Ok(_lock) = store.lock_waiting(lock_wait()) else {
        return problem(
            "Saved here. The history is in use (a run is recording, or another change is being \
             shared), so the change goes to the repository with the next run or `pathwarden \
             config sync`."
                .into(),
            "Saved here. The history is in use (a run is recording, or another change is being \
             shared), so the change goes to the repository with the next run or Sync now."
                .into(),
        );
    };
    crate::store::non_interactive(|| {
        let pulled = match store.pull() {
            Ok(n) => n,
            Err(e) => {
                return problem(
                    format!(
                        "Saved here. The repository could not be reached ({e:#}), so the change \
                         goes there with the next run or `pathwarden config sync`."
                    ),
                    format!(
                        "Saved here. The repository could not be reached ({e:#}), so the change \
                         goes there with the next run or Sync now."
                    ),
                )
            }
        };
        let place = Place {
            store: &store,
            config_path,
            pushes: state.pushes(),
            env_name,
        };
        let (note, _) = after_pull(&place);
        let problem = note.as_ref().is_some_and(|n| n.problem);
        let join = |page: bool| -> Vec<String> {
            pulled
                .iter()
                .cloned()
                .chain(
                    note.as_ref()
                        .map(|n| if page { n.page.clone() } else { n.text.clone() }),
                )
                .filter(|t| !t.is_empty())
                .collect()
        };
        let (text, page) = (join(false), join(true));
        (!text.is_empty()).then(|| Note::both(text.join(" "), page.join(" "), problem))
    })
}

#[cfg(test)]
#[path = "settings_sync_tests.rs"]
mod first_sync_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn side(text: &str) -> Side {
        local_side(text, Path::new(".")).unwrap().0
    }

    #[test]
    fn digests_ignore_form_and_other_sections() {
        let a =
            side("tier_zero = ['A@X']\n[rules]\nstale_days = 30\n[state]\nbackend = \"local\"\n");
        let b = side("[rules]\n# c\nstale_days   = 30\n\ntier_zero = [\"A@X\"]\n");
        // `tier_zero` after a table belongs to it: not the same.
        assert_ne!(a.all(), b.all());
        let b = side(
            "tier_zero = [\"A@X\",]\n[rules]\n# c\nstale_days   = 30\n[[output]]\nplugin = \"x\"\n",
        );
        assert_eq!(a.all(), b.all());
        // Empty sections are absent ones.
        let c = side("tier_zero = []\n[rules]\n");
        assert!(c.digests.is_empty());
        assert_eq!(c.all(), Side::default().all());
        // CRLF inside a string doesn't count.
        let d = side("[[suppress]]\nrule = \"PW-011\"\nreason = \"\"\"a\r\nb\"\"\"\n");
        let e = side("[[suppress]]\nrule = \"PW-011\"\nreason = \"\"\"a\nb\"\"\"\n");
        assert_eq!(d.all(), e.all());
    }

    #[test]
    fn sections_compare_with_the_base() {
        use Changed::*;
        assert_eq!(compare(Some("a"), Some("a"), None), InStep);
        assert_eq!(compare(Some("a"), Some("b"), Some(Some("a"))), Repository);
        assert_eq!(compare(Some("b"), Some("a"), Some(Some("a"))), Here);
        assert_eq!(compare(Some("b"), Some("c"), Some(Some("a"))), Both);
        assert_eq!(compare(None, Some("a"), Some(None)), Repository);
        assert_eq!(compare(Some("a"), None, Some(None)), Here);
        // Never synced.
        assert_eq!(compare(None, Some("a"), None), Repository);
        assert_eq!(compare(Some("a"), None, None), Here);
        // Both sides, never synced: the history's wins.
        assert_eq!(compare(Some("a"), Some("b"), None), Repository);
        let mut base = Base::default();
        base.set("tier_zero", &side("tier_zero = ['A']\n"));
        base.set("rules", &side(""));
        assert_eq!(base.get("rules"), Some(None));
        assert_eq!(base.get("zone"), None);
        let back: Base = serde_json::from_slice(&serde_json::to_vec(&base).unwrap()).unwrap();
        assert_eq!(back, base);
    }

    #[test]
    fn changes_are_described_in_a_few_words() {
        let old = side(
            "tier_zero = ['A', 'B']\n[[suppress]]\nrule = 'PW-011'\nreason = 'r'\n[[zone]]\nname = 'Servers'\ngroups = ['G']\n",
        );
        let new = side(
            "tier_zero = ['a', 'C']\n[rules]\nstale_days = 30\n[[suppress]]\nrule = 'PW-011'\nreason = 'other'\n[[suppress.notes]]\ntext = 'n'\n[[suppress]]\nfingerprint = 'PW-004-1'\nreason = 'r'\n",
        );
        assert_eq!(
            describe(&old.table, &new.table),
            [
                "1 Tier Zero addition",
                "1 Tier Zero removal",
                "rule settings changed",
                "1 accepted risk added",
                "1 accepted risk changed",
                "1 note added",
                "1 zone removed",
            ]
        );
        let m = commit_message(&describe(&old.table, &old.table), &["rules"]);
        assert!(
            m.starts_with("pathwarden settings: environment details\n\nSections: rules\n"),
            "{m}"
        );
        assert!(m.contains(&format!("Pathwarden: {VERSION}")), "{m}");
    }

    #[test]
    fn diffs_mark_what_each_side_changed() {
        let base = vec!["A".to_string(), "B".to_string()];
        let side = vec!["A".to_string(), "C".to_string()];
        let d = diff(&base, &side);
        let marks: Vec<(char, &str)> = d.iter().map(|l| (l.mark, l.text.as_str())).collect();
        assert_eq!(marks, [(' ', "A"), ('+', "C"), ('-', "B")]);
        let v = serde_json::to_value(side_value(
            "[[suppress]]\nrule = 'PW-011'\nreason = 'r'\nexpires = '2027-01-31'\n",
            "suppress",
        ))
        .unwrap();
        assert_eq!(
            section_lines("suppress", Some(&v)),
            ["every PW-011 finding: r (until 2027-01-31)"]
        );
    }

    fn side_value(text: &str, key: &str) -> toml::Value {
        side(text).table.get(key).cloned().unwrap()
    }

    #[test]
    fn pack_paths_stay_in_the_packs_folder() {
        for ok in [
            "packs/acme.toml",
            "packs/sub/a-b_c.1.TOML",
            r"Packs\acme.toml",
        ] {
            assert!(pack_path(ok).is_ok(), "{ok}");
        }
        for bad in [
            "acme.toml",
            "a/b/c.toml",
            "../acme.toml",
            "/etc/acme.toml",
            "C:/acme.toml",
            r"C:\acme.toml",
            "packs/../../x.toml",
            "packs/.hidden/x.toml",
            "packs/sub./x.toml",
            "packs/sub /x.toml",
            "packs/CON.toml",
            "packs/nul/x.toml",
            "packs/com1.toml",
            "packs/x.txt",
            "packs/a b.toml",
            r"\\server\share\x.toml",
        ] {
            assert!(pack_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_push_never_writes_over_a_newer_settings_file() {
        // Read while the repository's file was this version's; a newer
        // Pathwarden's push lands before this one writes. The write itself
        // refuses, forced or not, past any refusal at the sync's level.
        let dir = std::env::temp_dir().join(format!("pw-push-newer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = dir.join("state");
        std::fs::create_dir_all(state.join("settings")).unwrap();
        let config_path = dir.join("pathwarden.toml");
        std::fs::write(&config_path, "tier_zero = [\"B\"]\n").unwrap();
        let repo = state.join(SETTINGS_FILE);
        std::fs::write(&repo, "tier_zero = [\"A\"]\n").unwrap();
        let store = Store::new(&crate::config::StateConfig::default(), Some(&state)).unwrap();
        let place = Place {
            store: &store,
            config_path: &config_path,
            pushes: true,
            env_name: None,
        };
        let r = read_all(&place).unwrap();
        assert!(r.status.unreadable.is_none());
        let newer = "format = 2\ntier_zero = [\"C\"]\n";
        std::fs::write(&repo, newer).unwrap();
        for forced in [true, false] {
            let e = push_local(
                &place,
                &r,
                &["tier_zero"],
                &[],
                forced,
                &mut Done::default(),
            )
            .unwrap_err();
            assert_eq!(format!("{e:#}"), NEWER_SETTINGS_WORDS, "{forced}");
            assert_eq!(std::fs::read_to_string(&repo).unwrap(), newer, "{forced}");
        }
        // environment.json the same.
        std::fs::write(&repo, "tier_zero = [\"A\"]\n").unwrap();
        let env = state.join(ENVIRONMENT_FILE);
        std::fs::write(&env, "{\"format\": 2}").unwrap();
        let e =
            push_local(&place, &r, &["tier_zero"], &[], true, &mut Done::default()).unwrap_err();
        assert!(
            format!("{e:#}").contains("was saved by a newer Pathwarden"),
            "{e:#}"
        );
        assert_eq!(std::fs::read_to_string(&env).unwrap(), "{\"format\": 2}");
        assert_eq!(
            std::fs::read_to_string(&repo).unwrap(),
            "tier_zero = [\"A\"]\n"
        );
        // A push that goes through writes last-change.json at format 1,
        // which reads back; one of a newer format isn't read.
        std::fs::remove_file(&env).unwrap();
        push_local(&place, &r, &["tier_zero"], &[], true, &mut Done::default()).unwrap();
        let last = state.join(LAST_CHANGE_FILE);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&last).unwrap()).unwrap();
        assert_eq!(v["format"], 1, "{v}");
        assert!(change_record_in(&store).is_some());
        for newer in [serde_json::json!(2), serde_json::json!("1")] {
            let mut v = v.clone();
            v["format"] = newer;
            std::fs::write(&last, v.to_string()).unwrap();
            assert!(change_record_in(&store).is_none(), "{v}");
        }
        let mut old = v.clone();
        old.as_object_mut().unwrap().remove("format");
        std::fs::write(&last, old.to_string()).unwrap();
        assert!(change_record_in(&store).is_some(), "before 0.2: format 1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn newer_formats_are_not_applied() {
        // The repository's settings of a newer format: refused, whole.
        let e = repo_side("format = 2\ntier_zero = [\"A\"]\n").unwrap_err();
        assert_eq!(format!("{e:#}"), NEWER_SETTINGS_WORDS);
        // Not damaged: `--keep-local` never replaces it.
        assert!(!damaged(&e));
        // A format that isn't a whole number isn't read as 1.
        for text in ["format = \"2\"\n", "format = 1.0\n", "format = 0\n"] {
            assert!(repo_side(text).is_err_and(|e| is_newer_file(&e)), "{text}");
        }
        // Format 1 is this version's, and no note.
        let (side, notes) = repo_side("format = 1\ntier_zero = [\"A\"]\n").unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        assert!(side.get("tier_zero").is_some());
        // environment.json: written at format 1; read before it said one.
        let env: Environment = serde_json::from_str(r#"{"name":"Lab"}"#).unwrap();
        assert_eq!(env.format, 1);
        let e = Environment {
            format: ENVIRONMENT_FORMAT,
            ..Default::default()
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["format"], 1);
    }

    #[test]
    fn versions_compare_as_numbers() {
        assert!(newer("0.1.10", "0.1.9"));
        assert!(newer("0.2.0", "0.1.9"));
        assert!(!newer("0.1.7", "0.1.7"));
        assert!(!newer("0.1.6", "0.1.7"));
    }

    #[test]
    fn repository_files_have_limits() {
        let big = format!("tier_zero = [\"{}\"]\n", "x".repeat(MAX_SETTINGS_BYTES));
        assert!(repo_side(&big).is_err());
        let mut many = String::from("[[mapping]]\npath = \"packs/a.toml\"\n");
        for i in 0..=MAX_MAPPING_FILES {
            many.push_str(&format!(
                "[[mapping_files]]\npath = \"packs/{i}.toml\"\ntext = \"\"\n"
            ));
        }
        assert!(repo_side(&many).is_err());
        // A pack no [[mapping]] names is left out; a section never shared
        // is named.
        let (s, notes) = repo_side(
            "[[mapping]]\npath = \"packs/a.toml\"\n[[mapping_files]]\npath = \"packs/b.toml\"\ntext = \"x\"\n[state]\nbackend = \"local\"\n",
        )
        .unwrap();
        let m = s.table["mapping"].as_array().unwrap()[0]
            .as_table()
            .unwrap();
        assert!(m.get("text").is_none());
        assert!(
            notes.iter().any(|n| n.contains("packs/b.toml")),
            "{notes:?}"
        );
        assert!(
            notes.iter().any(|n| n.contains("never shared")),
            "{notes:?}"
        );
    }
}
