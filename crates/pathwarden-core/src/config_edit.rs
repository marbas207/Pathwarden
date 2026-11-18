//! Editing `pathwarden.toml` in place, for the local UI. Comments, ordering
//! and keys Pathwarden does not manage stay exactly as the user wrote them
//! (the file is edited as a TOML document, not re-serialized), so the same
//! file can keep being edited by hand.
//!
//! Every edit is checked with [`check`] (the parser and validation every
//! command uses, plus the checks `pathwarden run` makes on `[state]` and
//! plugin commands) before it may be written, and [`write_atomic`] replaces
//! the file in one step. A file that core cannot load is never written.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use serde::Deserialize;
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use crate::config::{validate_branch, validate_remote, Config};
use crate::zones::{self, ZoneConfig};
use crate::{findings, plugins, time};

/// The annotated example config: the starting point for a new file, so its
/// explanations are there for whoever opens it later.
pub const TEMPLATE: &str = include_str!("../../../pathwarden.example.toml");

/// Most entries a list (Tier Zero, a zone's members) may hold.
const MAX_ITEMS: usize = 10_000;
/// Longest single value: names, IDs, distinguished names, reasons.
const MAX_LEN: usize = 2_048;

/// The sections of `pathwarden.toml` that travel through a shared history
/// (`[state] keep = "full"`, [`crate::settings_sync`]), as (key, plain
/// words), in the order they are shown and written. Both directions use
/// this one list: what a writer commits and what a pull applies. Never
/// shared: `[state]` (this machine's folders, the remote), `[[output]]`
/// (plugin targets), `[ingest]` and `[opengraph]`. `[[mapping]]` packs
/// travel only when their file is inside the environment's folder.
pub const SHARED_SECTIONS: &[(&str, &str)] = &[
    ("tier_zero", "Tier Zero additions"),
    ("settings_folders", "Tier Zero settings folders"),
    ("rules", "Rule settings"),
    ("suppress", "Accepted risks"),
    ("zone", "Zones"),
    ("management_planes", "Management planes"),
    ("mapping", "Mapping packs"),
];

/// The message for an edit that targets an entry someone else changed.
pub const CHANGED: &str =
    "pathwarden.toml changed since this page was loaded. Reload the page and try again.";

/// The message for a zone named "Tier Zero": reports, `--zone` and the
/// history would take it for Tier Zero itself.
pub const TIER_ZERO_NAME: &str =
    "Tier Zero is built in and protected above every zone: give the zone another name.";

/// Whether a zone name reads as "Tier Zero", "Tier 0" or "T0": in any
/// case, with any spaces or punctuation, and in full-width characters.
pub fn is_tier_zero_name(name: &str) -> bool {
    let squashed: String = name
        .chars()
        // Full-width forms (U+FF01..U+FF5E) read as their ASCII letters.
        .map(|c| match c {
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            _ => c,
        })
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    matches!(squashed.as_str(), "tierzero" | "tier0" | "t0" | "tzero")
}

/// Why zone `i` needs a new name, when it has one a save would refuse: a
/// file written by hand or by an older version can still hold a zone
/// called "Tier Zero". It loads and analyzes, but reads as Tier Zero
/// itself in the reports and zone filters, so the Zones page and
/// `pathwarden zones list` say so. (Two zones with one name don't load.)
pub fn zone_name_problem(list: &[ZoneConfig], i: usize) -> Option<String> {
    is_tier_zero_name(&list.get(i)?.name)
        .then(|| "Rename this zone: Tier Zero is built in, so reports and zone filters would take it for Tier Zero.".into())
}

/// Parses and validates a config text as every command would load it.
pub fn check(text: &str) -> Result<Config, String> {
    let config = Config::parse(text).map_err(|e| e.to_string())?;
    let state = &config.state;
    if let Some(remote) = &state.remote {
        validate_remote(remote)?;
    }
    if let Some(branch) = &state.branch {
        validate_branch(branch)?;
    }
    for o in &config.outputs {
        if let Some(program) = o.command.as_ref().and_then(|c| c.first()) {
            plugins::check_program(program).map_err(|e| format!("[[output]] {}: {e}", o.plugin))?;
        }
        for (k, v) in &o.settings {
            if !k.ends_with("_env") {
                continue;
            }
            match v.as_str() {
                Some(name) if name.is_empty() || plugins::valid_env_name(name) => {}
                _ => {
                    return Err(format!(
                        "[[output]] {}: {k} must name an environment variable (letters, digits and _), got {v}",
                        o.plugin
                    ))
                }
            }
        }
    }
    for a in &config.actions {
        if let Some(program) = a.command.as_ref().and_then(|c| c.first()) {
            plugins::check_program(program).map_err(|e| format!("[[action]] {}: {e}", a.name))?;
        }
        for (k, v) in &a.settings {
            if !k.ends_with("_env") {
                continue;
            }
            match v.as_str() {
                Some(name) if name.is_empty() || plugins::valid_env_name(name) => {}
                _ => {
                    return Err(format!(
                        "[[action]] {}: {k} must name an environment variable (letters, digits and _), got {v}",
                        a.name
                    ))
                }
            }
        }
    }
    Ok(config)
}

/// Writes `text` to `path` through a temporary file in the same folder, so
/// the file is either the old one or the new one, never half written.
pub fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pathwarden.toml".into());
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let written = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()
    })();
    let result = written.and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// How long a save waits for another one to finish.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Runs `change` while holding an exclusive OS lock on
/// `.pathwarden.toml.lock` next to `path`, so the app and `pathwarden
/// config` (or two of either) never change the file at the same moment and
/// lose one change. The lock is on the open file, so the system releases it
/// when the process ends, however it ends: a lock file left on disk blocks
/// nothing, and there is no stale lock to take over. Waits up to 10 seconds
/// for another save, then refuses; it never goes on without the lock.
pub fn with_lock<T>(path: &Path, change: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    with_lock_within(path, LOCK_WAIT, change)
}

/// Sets or clears `[state] encrypted` in the pathwarden.toml at `path`,
/// under [`with_lock`]: what `history storage set --encrypt` and
/// `--no-encrypt` record about the history this config uses.
pub fn set_state_encrypted_in(path: &Path, on: bool) -> Result<(), String> {
    with_lock(path, || {
        let mut doc = ConfigDoc::load(path)?;
        doc.set_state_encrypted(on)?;
        let text = doc.text_for_file();
        check(&text).map_err(|e| format!("Not saved: {e}"))?;
        write_atomic(path, &text).map_err(|e| format!("Could not save {}: {e}", path.display()))
    })
}

fn with_lock_within<T>(
    path: &Path,
    wait: std::time::Duration,
    change: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pathwarden.toml".into());
    let lock = dir.join(format!(".{name}.lock"));
    let started = std::time::Instant::now();
    let held = loop {
        let why = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock)
        {
            Ok(f) => match f.try_lock() {
                Ok(()) => break f,
                Err(std::fs::TryLockError::WouldBlock) => None,
                // The file system can't lock (it never will): say so now.
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(format!(
                        "Could not lock {} to save {name}: {e}",
                        lock.display()
                    ))
                }
            },
            // A folder that isn't there or can't be written: waiting won't help.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                return Err(format!(
                    "Could not lock {} to save {name}: {e}",
                    lock.display()
                ))
            }
            // Something passing (on Windows a scanner can hold the file).
            Err(e) => Some(e.to_string()),
        };
        if started.elapsed() >= wait {
            return Err(match why {
                None => format!(
                    "Another Pathwarden (the app or a command) is saving {name}. Try again in a moment."
                ),
                Some(e) => format!("Could not lock {} to save {name}: {e}", lock.display()),
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    let result = change();
    drop(held);
    result
}

/// `[state] refresh = n` in `t`, for a history kept in `backend`: only
/// git pulls, so a folder is refused; 1 to 1440 minutes; the default (5)
/// removes the key, so a file that keeps it still reads in 0.1.7.
fn set_refresh(t: &mut dyn TableLike, backend: &str, n: u32) -> Result<(), String> {
    use crate::config::{DEFAULT_REFRESH_MINUTES, MAX_REFRESH_MINUTES};
    if backend != "git" {
        return Err(
            "Sync every applies to a git repository: a folder history is read as it is.".into(),
        );
    }
    if !(1..=MAX_REFRESH_MINUTES).contains(&n) {
        return Err(format!("Sync every 1 to {MAX_REFRESH_MINUTES} minutes."));
    }
    if n == DEFAULT_REFRESH_MINUTES {
        t.remove("refresh");
    } else {
        set_value(t, "refresh", Value::from(n as i64));
    }
    Ok(())
}

/// No control characters (a newline in a name would be a different entry
/// in some tools), not empty after trimming, and of a sane length.
/// The most Tier Zero settings folders one file lists.
pub const MAX_SETTINGS_FOLDERS: usize = 32;

/// A Tier Zero settings folder must be a full path: a share
/// (`\\fs01\pathwarden-t0`), a drive path (`D:\t0`) or, elsewhere, an
/// absolute path. A relative one would mean another folder on each
/// computer that shares the settings.
///
/// Only a plain share or a local path: never a device path (`\\?\`,
/// `\\.\`, which reach pipes and raw devices), a WebDAV or other
/// redirected share (`\\host@SSL\...`, `\\host@8080\...`, `DavWWWRoot`), or
/// a URL, since reading the folder makes this computer, and a schedule's
/// account, sign in to the host it names.
pub fn check_settings_folder(f: &str) -> Result<(), String> {
    let f = f.trim();
    let b = f.as_bytes();
    let lower = f.to_ascii_lowercase();
    if lower.starts_with(r"\\?\")
        || lower.starts_with(r"\\.\")
        || lower.starts_with("//?/")
        || lower.starts_with("//./")
        || lower.contains("://")
        || lower.contains("davwwwroot")
    {
        return Err(format!(
            "{f} is not a plain folder or share: use a share such as \\\\fs01\\pathwarden-t0, or a local path."
        ));
    }
    let unc = f.starts_with(r"\\") && {
        let mut parts = f[2..].split('\\');
        let host = parts.next().unwrap_or_default();
        let share = parts.next().unwrap_or_default();
        // A host name or address: no `@SSL`, `@port` or other suffix.
        !host.is_empty()
            && host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
            && !share.is_empty()
            && !share.contains(['@', '/', ':'])
    };
    if f.starts_with(r"\\") && !unc {
        return Err(format!(
            "{f} is not a plain folder or share: use a share such as \\\\fs01\\pathwarden-t0, or a local path."
        ));
    }
    let drive =
        b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/');
    let unix = f.starts_with('/') && !f.starts_with("//");
    if !(unc || drive || unix) {
        return Err(format!(
            "{f} is not a full folder path: use a share such as \\\\fs01\\pathwarden-t0, or a path that starts with a drive letter."
        ));
    }
    if f.len() > 1024 {
        return Err("A settings folder path is longer than 1024 characters.".into());
    }
    if f.split(['\\', '/']).any(|p| p == "..") {
        return Err(format!(
            "{f} goes up a folder (..): give the folder itself."
        ));
    }
    Ok(())
}

fn clean(what: &str, s: &str) -> Result<String, String> {
    let t = s.trim();
    if t.chars().any(char::is_control) {
        return Err(format!("{what} contains a control character"));
    }
    if t.chars().count() > MAX_LEN {
        return Err(format!("{what} is longer than {MAX_LEN} characters"));
    }
    Ok(t.to_string())
}

/// A note's text: several lines allowed (a form's text box), with line
/// endings as `\n`, spaces at the ends of lines and more than one blank
/// line in a row dropped. Other control characters and bidi controls are
/// refused, as everywhere.
fn clean_note(s: &str) -> Result<String, String> {
    let text = s
        .replace("\r\n", "\n")
        .replace(['\r', '\u{2028}', '\u{2029}'], "\n");
    if text
        .chars()
        .any(|c| (c.is_control() && c != '\n') || crate::text::is_bidi_control(c))
    {
        return Err("The note contains a control character".into());
    }
    let mut out = String::with_capacity(text.len());
    let mut blank = 0;
    for line in text.trim().lines().map(str::trim_end) {
        if line.is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(line);
    }
    if out.chars().count() > MAX_LEN {
        return Err(format!("The note is longer than {MAX_LEN} characters"));
    }
    Ok(out)
}

/// A text value for the file: as Pathwarden writes any string, or, with
/// line breaks, as one escaped string (`"one\ntwo"`) rather than a
/// multi-line one, so the file's own line endings never become part of it.
fn text_value(s: &str) -> Value {
    if !s.contains('\n') {
        return Value::from(s);
    }
    let mut v: Value = serde_json::to_string(s)
        .ok()
        .and_then(|j| j.parse().ok())
        .unwrap_or_else(|| Value::from(s));
    v.decor_mut().clear();
    v
}

/// Trimmed, without empties or duplicates (case-insensitive), in order.
fn clean_list(what: &str, items: &[String]) -> Result<Vec<String>, String> {
    if items.len() > MAX_ITEMS {
        return Err(format!("{what}: more than {MAX_ITEMS} entries"));
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for i in items {
        let c = clean(what, i)?;
        if !c.is_empty() && seen.insert(c.to_ascii_uppercase()) {
            out.push(c);
        }
    }
    Ok(out)
}

fn opt(what: &str, s: &Option<String>) -> Result<Option<String>, String> {
    Ok(match s {
        Some(v) => Some(clean(what, v)?).filter(|v| !v.is_empty()),
        None => None,
    })
}

/// Sets a value, keeping the old value's surrounding whitespace and trailing
/// comment (`table = "incident"   # or sc_req_item`).
fn set_value(t: &mut dyn TableLike, key: &str, mut v: Value) {
    match t.get_mut(key) {
        Some(item) => {
            if let Some(old) = item.as_value() {
                *v.decor_mut() = old.decor().clone();
            }
            *item = Item::Value(v);
        }
        None => {
            t.insert(key, Item::Value(v));
        }
    }
}

fn set_opt(t: &mut dyn TableLike, key: &str, v: Option<String>) {
    match v {
        Some(v) => set_value(t, key, Value::from(v)),
        None => {
            t.remove(key);
        }
    }
}

fn is_multiline(arr: &Array) -> bool {
    let has_newline = |s: Option<&str>| s.is_some_and(|s| s.contains('\n'));
    has_newline(arr.trailing().as_str())
        || arr
            .iter()
            .any(|v| has_newline(v.decor().prefix().and_then(|p| p.as_str())))
}

/// Makes the array hold exactly `items`: entries still wanted keep their
/// place and comments, the rest are removed, new ones are appended. Comments
/// in the array (the example's commented-out entries) are kept.
fn sync_array(arr: &mut Array, items: &[String]) {
    let multiline = is_multiline(arr);
    let wanted: HashSet<&str> = items.iter().map(String::as_str).collect();
    let mut seen = HashSet::new();
    arr.retain(|v| {
        v.as_str()
            .is_some_and(|s| wanted.contains(s) && seen.insert(s.to_string()))
    });
    for s in items {
        if seen.insert(s.clone()) {
            // A comment on the last entry's line (`"A", # why`) belongs to
            // that entry: it moves in front of the new one, not after it.
            let mut prefix = "\n  ".to_string();
            if multiline && !arr.is_empty() {
                let trailing = arr.trailing().as_str().unwrap_or_default().to_string();
                if let Some((head, rest)) = trailing.split_once('\n') {
                    if head.trim_start().starts_with('#') {
                        prefix = format!("{head}\n  ");
                        arr.set_trailing(format!("\n{rest}"));
                    }
                }
            }
            arr.push(s.as_str());
            if multiline {
                if let Some(v) = arr.get_mut(arr.len() - 1) {
                    v.decor_mut().set_prefix(prefix);
                }
            }
        }
    }
    if multiline {
        arr.set_trailing_comma(true);
    }
}

/// Sets a list of strings. An empty list removes the key unless `keep_empty`.
fn set_strings(t: &mut dyn TableLike, key: &str, items: &[String], keep_empty: bool) {
    if items.is_empty() && !keep_empty {
        t.remove(key);
        return;
    }
    match t.get_mut(key).and_then(Item::as_array_mut) {
        Some(arr) => sync_array(arr, items),
        None => set_value(
            t,
            key,
            Value::Array(items.iter().map(String::as_str).collect()),
        ),
    }
}

/// Sets or takes off rules' severities in `[rules.severities]` (`rules`
/// is `[rules]`): a new or changed level is written with `by`; one that
/// stays as it was keeps its entry, and its record of who set it. The
/// table goes when it is left empty.
fn set_severities(
    rules: &mut dyn TableLike,
    levels: &[(&'static str, Option<findings::Severity>)],
    by: &Stamp,
) -> Result<(), String> {
    if !rules.contains_key("severities") {
        if levels.iter().all(|(_, l)| l.is_none()) {
            return Ok(());
        }
        let mut t = Table::new();
        t.set_implicit(false);
        rules.insert("severities", Item::Table(t));
    }
    let t = rules
        .get_mut("severities")
        .and_then(Item::as_table_like_mut)
        .ok_or("`severities` in [rules] is not a table; edit it by hand")?;
    for (rule, level) in levels {
        // The entry as written, in any case.
        let key = t
            .iter()
            .map(|(k, _)| k.to_string())
            .find(|k| k.trim().eq_ignore_ascii_case(rule));
        let current = key.as_deref().and_then(|k| {
            let item = t.get(k)?;
            item.as_str()
                .or_else(|| item.as_table_like()?.get("severity")?.as_str())
                .map(str::to_string)
        });
        match level {
            None => {
                if let Some(k) = &key {
                    t.remove(k);
                }
            }
            Some(l)
                if current
                    .as_deref()
                    .is_some_and(|c| c.trim().eq_ignore_ascii_case(l.as_str())) => {}
            Some(l) => {
                if let Some(k) = &key {
                    t.remove(k);
                }
                let mut entry = InlineTable::new();
                entry.insert("severity", Value::from(l.as_str()));
                by.write(&mut entry, "");
                t.insert(rule, Item::Value(Value::InlineTable(entry)));
            }
        }
    }
    if t.is_empty() {
        rules.remove("severities");
    }
    Ok(())
}

fn str_of<'a>(t: &'a Table, key: &str) -> Option<&'a str> {
    t.get(key).and_then(Item::as_str)
}

/// [`CHANGED`] unless the entry's finding ID or rule reads `expect` (any
/// case); nothing to check when `expect` is `None`.
fn check_target(t: &Table, expect: Option<&str>) -> Result<(), String> {
    let Some(expect) = expect else { return Ok(()) };
    let current = str_of(t, "fingerprint")
        .or_else(|| str_of(t, "rule"))
        .unwrap_or_default();
    if expect.trim().eq_ignore_ascii_case(current.trim()) {
        Ok(())
    } else {
        Err(CHANGED.into())
    }
}

/// "finding PW-004-…" or "every PW-011 finding".
fn target_words(fingerprint: Option<&str>, rule: Option<&str>) -> String {
    match (fingerprint, rule) {
        (Some(f), _) => format!("finding {f}"),
        (None, Some(r)) => format!("every {r} finding"),
        (None, None) => "nothing".into(),
    }
}

/// Appends a note (`by`, `on`, `at`, `text`) to an accepted risk's notes,
/// in whichever form they are written.
fn push_note(t: &mut Table, text: &str, by: &Stamp) -> Result<(), String> {
    if !t.contains_key("notes") {
        t.insert("notes", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let fields = |n: &mut dyn TableLike| {
        by.write_note(n);
        set_value(n, "text", text_value(text));
    };
    match t.get_mut("notes") {
        Some(Item::ArrayOfTables(list)) => {
            if list.len() >= MAX_ITEMS {
                return Err(format!("This accepted risk already has {MAX_ITEMS} notes."));
            }
            let mut n = Table::new();
            fields(&mut n);
            list.push(n);
        }
        // `notes = [{ ... }]`, as someone may write it by hand.
        Some(Item::Value(Value::Array(list))) => {
            if list.len() >= MAX_ITEMS {
                return Err(format!("This accepted risk already has {MAX_ITEMS} notes."));
            }
            let mut n = InlineTable::new();
            fields(&mut n);
            list.push(n);
        }
        _ => {
            return Err(
                "`notes` of this accepted risk is written in a form this page can't edit; edit it by hand"
                    .into(),
            )
        }
    }
    Ok(())
}

/// Rule settings, as the Settings page sends them.
#[derive(Debug, Clone, Deserialize)]
pub struct RulesEdit {
    #[serde(deserialize_with = "whole_days")]
    pub stale_days: i64,
    #[serde(deserialize_with = "whole_days")]
    pub password_age_days: i64,
    #[serde(deserialize_with = "whole_days")]
    pub krbtgt_age_days: i64,
    /// The Seamless SSO key age (PW-037). `None` (a request from a page
    /// that doesn't send it) leaves the file as it is.
    #[serde(default, deserialize_with = "some_whole_days")]
    pub sso_key_age_days: Option<i64>,
    /// `exposure` or `static`.
    pub severity: String,
    pub disabled: Vec<String>,
    /// Severities to set, by rule ID: `critical`, `high`, `medium` or
    /// `low`, or `default` to take the setting off. Rules not listed keep
    /// theirs.
    #[serde(default)]
    pub severities: std::collections::BTreeMap<String, String>,
}

/// A number of days as a form sends it. A fraction (1.5) becomes 0, which
/// [`ConfigDoc::set_rules`] refuses with its message ("a whole number from
/// 1 to 36500"), rather than failing to read the request at all.
fn whole_days<'de, D: serde::Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    let v = f64::deserialize(d)?;
    Ok(if v.fract() == 0.0 && v.abs() <= 1e15 {
        v as i64
    } else {
        0
    })
}

/// [`whole_days`], for a field that may be left out.
fn some_whole_days<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    whole_days(d).map(Some)
}

/// One accepted risk.
#[derive(Debug, Clone, Deserialize)]
pub struct SuppressionEdit {
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub rule: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub expires: Option<String>,
}

/// Who makes a change, on which computer, and when: what an accepted risk
/// records about the people who accepted, changed or annotated it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    /// [`crate::identity::Actor::user`].
    pub by: Option<String>,
    /// [`crate::identity::Actor::computer`].
    pub on: Option<String>,
    /// RFC 3339, UTC.
    pub at: String,
}

impl Stamp {
    /// This process's account and computer, now: what every edit from the
    /// app and `pathwarden config` records.
    pub fn now() -> Stamp {
        let me = crate::identity::Actor::current();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        Stamp {
            by: me.user,
            on: me.computer,
            at: time::format_rfc3339(now),
        }
    }

    /// A note's `by`, `on` and `at`.
    fn write_note(&self, t: &mut dyn TableLike) {
        self.write(t, "");
    }

    /// Sets `{prefix}by`, `{prefix}on` and `{prefix}at` (an unknown name is
    /// left out, not written empty).
    fn write(&self, t: &mut dyn TableLike, prefix: &str) {
        set_opt(t, &format!("{prefix}by"), self.by.clone());
        set_opt(t, &format!("{prefix}on"), self.on.clone());
        set_value(t, &format!("{prefix}at"), Value::from(self.at.as_str()));
    }
}

/// Where run state lives.
#[derive(Debug, Clone, Deserialize)]
pub struct StateEdit {
    /// `local` or `git`.
    pub backend: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub remote: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub include_names: bool,
    /// Git: commit and push recorded runs. `None` leaves the setting as it is.
    #[serde(default)]
    pub push: Option<bool>,
    /// What the history keeps: `names` or `full`. `None` leaves the setting
    /// as it is.
    #[serde(default)]
    pub keep: Option<String>,
    /// Git: how often the app pulls while it is open, in minutes
    /// (`[state] refresh`, 1 to 1440). `None` leaves the setting as it is.
    #[serde(default)]
    pub refresh: Option<u32>,
}

/// One Privilege Zone.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ZoneEdit {
    pub name: String,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub ous: Vec<String>,
}

/// A plugin setting value.
#[derive(Debug, Clone, PartialEq)]
pub enum Setting {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl From<&Setting> for Value {
    fn from(s: &Setting) -> Self {
        match s {
            Setting::Str(v) => Value::from(v.as_str()),
            Setting::Int(v) => Value::from(*v),
            Setting::Bool(v) => Value::from(*v),
        }
    }
}

/// Changes to one `[[output]]` entry. Settings not named here are kept.
#[derive(Debug, Clone, Default)]
pub struct OutputEdit {
    pub plugin: String,
    /// `None` removes `command`.
    pub command: Option<Vec<String>>,
    /// Scalar settings to set.
    pub set: Vec<(String, Setting)>,
    /// Settings to remove.
    pub remove: Vec<String>,
    /// Remove every other scalar setting (a form that shows them all).
    pub replace_scalars: bool,
    /// Replace the `fields` table (ServiceNow, Jira); `None` leaves it alone.
    pub fields: Option<Vec<(String, String)>>,
    /// Field values that are JSON arrays or objects are written as such
    /// (Jira's `components = [{ name = "..." }]`); otherwise every value is
    /// a string.
    pub json_fields: bool,
}

/// Changes to one `[[action]]` block ([`ConfigDoc::upsert_action`]).
/// Settings not named here are kept. Who may change the program and the
/// `*_env` settings is [`crate::plugin_form::check_action`]'s rule.
#[derive(Debug, Clone, Default)]
pub struct ActionEdit {
    /// The block's name; empty leaves the default (`plugin`, else
    /// `action-N`).
    pub name: String,
    /// `pathwarden-action-<plugin>`; with `command` `None`.
    pub plugin: Option<String>,
    /// The program and its arguments; with `plugin` `None`.
    pub command: Option<Vec<String>>,
    /// `None` leaves it; `Some(0)` removes it (the default).
    pub timeout_seconds: Option<u64>,
    /// `None` leaves it; `Some("")` removes it.
    pub min_severity: Option<String>,
    /// `None` leaves them; `Some(empty)` removes the filter.
    pub rules: Option<Vec<String>>,
    /// `None` leaves them; `Some(empty)` removes the filter.
    pub categories: Option<Vec<String>>,
    /// Scalar settings to set.
    pub set: Vec<(String, Setting)>,
    /// Settings to remove.
    pub remove: Vec<String>,
}

/// The name in effect of `[[action]]` block `i` as the file has it: its
/// `name`, else its `plugin`, else `action-N` ([`crate::config::ActionConfig::name`]).
fn action_name_of(t: &Table, i: usize) -> String {
    str_of(t, "name")
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .or_else(|| str_of(t, "plugin").map(str::trim))
        .map(str::to_string)
        .unwrap_or_else(|| format!("action-{}", i + 1))
}

/// A `pathwarden.toml` open for editing.
pub struct ConfigDoc {
    doc: DocumentMut,
    /// The file has Windows line endings: it is written back with them.
    crlf: bool,
}

impl ConfigDoc {
    pub fn parse(text: &str) -> Result<Self, String> {
        text.parse::<DocumentMut>()
            .map(|doc| Self {
                doc,
                crlf: text.contains("\r\n"),
            })
            .map_err(|e| format!("pathwarden.toml is not valid TOML: {e}"))
    }

    /// The text to write back to the file: [`ConfigDoc::text`] with the
    /// file's own line endings (a file with Windows line endings keeps
    /// them, so a save doesn't show every line as changed).
    pub fn text_for_file(&self) -> String {
        let text = self.text();
        if self.crlf {
            text.replace("\r\n", "\n").replace('\n', "\r\n")
        } else {
            text
        }
    }

    /// A new file, from the annotated example.
    pub fn template() -> Self {
        Self::parse(TEMPLATE).expect("the example config is valid TOML")
    }

    /// The file at `path`, or the template when there is none yet.
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::template()),
            Err(e) => Err(format!("Could not read {}: {e}", path.display())),
        }
    }

    pub fn text(&self) -> String {
        self.doc.to_string()
    }

    /// The document as every command would load it, or why it can't be.
    pub fn validate(&self) -> Result<Config, String> {
        check(&self.text())
    }

    /// A top-level table, created when missing.
    fn table(&mut self, key: &str) -> Result<&mut dyn TableLike, String> {
        let root = self.doc.as_table_mut();
        if !root.contains_key(key) {
            root.insert(key, Item::Table(Table::new()));
        }
        root.get_mut(key)
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| format!("`{key}` in pathwarden.toml is not a table; edit it by hand"))
    }

    /// A `[[key]]` list of tables, created when missing.
    fn tables(&mut self, key: &str) -> Result<&mut ArrayOfTables, String> {
        let root = self.doc.as_table_mut();
        if !root.contains_key(key) {
            root.insert(key, Item::ArrayOfTables(ArrayOfTables::new()));
        }
        root.get_mut(key)
            .and_then(Item::as_array_of_tables_mut)
            .ok_or_else(|| {
                format!("`{key}` in pathwarden.toml is written in a form this page can't edit; edit it by hand")
            })
    }

    /// Entry `index` of `[[key]]` when its `id_key` still reads `expect`
    /// (case-insensitive), or a new entry at the end.
    fn entry(
        &mut self,
        key: &str,
        index: Option<usize>,
        id_key: &str,
        expect: Option<&str>,
    ) -> Result<&mut Table, String> {
        match index {
            Some(i) => {
                let t = self.tables(key)?.get_mut(i).ok_or(CHANGED)?;
                let current = str_of(t, id_key).unwrap_or_default();
                if expect.is_some_and(|e| !e.trim().eq_ignore_ascii_case(current.trim())) {
                    return Err(CHANGED.into());
                }
                Ok(t)
            }
            None => {
                let mut table = Table::new();
                let after = self.tables(key)?.iter().last().and_then(last_position);
                match after {
                    // Right after the last entry (and its sub-tables), so
                    // entries of one kind stay together.
                    Some(p) => table.set_position(p),
                    // The first entry goes at the end, after the comments
                    // that close the file (the example's commented-out
                    // entries), which would otherwise follow it as if they
                    // were part of it.
                    None => {
                        let trailing = self.doc.trailing().as_str().unwrap_or_default().to_string();
                        if trailing.contains('#') {
                            table.decor_mut().set_prefix(format!("{trailing}\n"));
                            self.doc.set_trailing("");
                        }
                    }
                }
                let list = self.tables(key)?;
                list.push(table);
                let last = list.len() - 1;
                Ok(list.get_mut(last).expect("just pushed"))
            }
        }
    }

    fn remove_entry(
        &mut self,
        key: &str,
        index: usize,
        id_key: &str,
        expect: &str,
    ) -> Result<(), String> {
        let list = self.tables(key)?;
        let t = list.get(index).ok_or(CHANGED)?;
        if !expect
            .trim()
            .eq_ignore_ascii_case(str_of(t, id_key).unwrap_or_default().trim())
        {
            return Err(CHANGED.into());
        }
        // Comments in front of the entry (such as the example's, taken over
        // when it was added) are kept: they return to the end of the file.
        let prefix = t
            .decor()
            .prefix()
            .and_then(|p| p.as_str())
            .unwrap_or_default()
            .to_string();
        list.remove(index);
        if list.is_empty() {
            self.doc.as_table_mut().remove(key);
        }
        if prefix.contains('#') {
            let trailing = self.doc.trailing().as_str().unwrap_or_default().to_string();
            let prefix = prefix.strip_suffix('\n').unwrap_or(&prefix);
            self.doc.set_trailing(format!("{prefix}{trailing}"));
        }
        Ok(())
    }

    // ------------------------------------------------------------ editors

    /// `tier_zero = [...]`
    pub fn set_tier_zero(&mut self, items: &[String]) -> Result<(), String> {
        let items = clean_list("Tier Zero", items)?;
        set_strings(self.doc.as_table_mut(), "tier_zero", &items, true);
        Ok(())
    }

    /// `settings_folders`: the Tier Zero settings folders, each a
    /// full path or a share ([`check_settings_folder`]). An empty list takes
    /// the key off.
    pub fn set_settings_folders(&mut self, items: &[String]) -> Result<(), String> {
        if items.len() > MAX_SETTINGS_FOLDERS {
            return Err(format!(
                "Tier Zero settings folders: more than {MAX_SETTINGS_FOLDERS}."
            ));
        }
        let items = clean_list("A settings folder", items)?;
        for i in &items {
            check_settings_folder(i)?;
        }
        set_strings(self.doc.as_table_mut(), "settings_folders", &items, false);
        Ok(())
    }

    /// Adds `pack` to `[opengraph] trust` (or removes it): a reviewed
    /// mapping pack whose traversable kinds then make paths and findings.
    pub fn set_pack_trust(&mut self, pack: &str, trusted: bool) -> Result<(), String> {
        let pack = pack.trim();
        if !crate::config::valid_pack_name(pack) {
            return Err(format!("'{pack}' is not a pack name"));
        }
        let t = self.table("opengraph")?;
        let mut items: Vec<String> = t
            .get("trust")
            .and_then(Item::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        items.retain(|n| !n.trim().eq_ignore_ascii_case(pack));
        if trusted {
            items.push(pack.to_string());
        }
        set_strings(t, "trust", &items, false);
        Ok(())
    }

    /// `[rules]`, and in it `[rules.severities]`: a severity set or changed
    /// records `by` as who set it; one left as it was keeps its record.
    pub fn set_rules(&mut self, r: &RulesEdit, by: &Stamp) -> Result<(), String> {
        for (what, v) in [
            ("Stale account days", r.stale_days),
            ("Password age days", r.password_age_days),
            ("krbtgt password age days", r.krbtgt_age_days),
            ("Seamless SSO key age days", r.sso_key_age_days.unwrap_or(1)),
        ] {
            if !(1..=36_500).contains(&v) {
                return Err(format!("{what} must be a whole number from 1 to 36500"));
            }
        }
        let severity = r.severity.trim().to_ascii_lowercase();
        if !matches!(severity.as_str(), "exposure" | "static") {
            return Err("Severity must be \"exposure\" or \"static\"".into());
        }
        let known = findings::rules();
        let mut disabled = Vec::new();
        for d in clean_list("Disabled rules", &r.disabled)? {
            let Some(rule) = known.iter().find(|k| k.id.eq_ignore_ascii_case(&d)) else {
                return Err(format!("{d} is not a rule (see `pathwarden rules`)"));
            };
            disabled.push(rule.id.to_string());
        }
        let mut levels: Vec<(&'static str, Option<findings::Severity>)> = Vec::new();
        for (id, level) in &r.severities {
            let Some(rule) = known.iter().find(|k| k.id.eq_ignore_ascii_case(id.trim())) else {
                return Err(format!("{} is not a rule Pathwarden has.", id.trim()));
            };
            let level = level.trim();
            let set = if level.is_empty() || level.eq_ignore_ascii_case("default") {
                None
            } else {
                Some(
                    findings::Severity::parse_settable(level)
                        .map_err(|e| format!("Severity of {}: {e}", rule.id))?,
                )
            };
            levels.push((rule.id, set));
        }
        let t = self.table("rules")?;
        set_strings(t, "disabled", &disabled, true);
        set_value(t, "stale_days", Value::from(r.stale_days));
        set_value(t, "password_age_days", Value::from(r.password_age_days));
        set_value(t, "krbtgt_age_days", Value::from(r.krbtgt_age_days));
        if let Some(days) = r.sso_key_age_days {
            set_value(t, "sso_key_age_days", Value::from(days));
        }
        set_value(t, "severity", Value::from(severity));
        if !levels.is_empty() {
            set_severities(t, &levels, by)?;
        }
        Ok(())
    }

    /// Adds (`index` None) or replaces a `[[suppress]]` entry. `expect` is
    /// the entry's reason as the page showed it, `expect_target` its finding
    /// ID or rule (checked when given), so an edit never lands on another
    /// entry that took its place. A new entry records `by` as who accepted
    /// it (`accepted_*`); a change to its reason or review date records `by`
    /// as the last change (`changed_*`), and a new reason keeps the old one
    /// as a note ("Reason changed from: …"). A new target (another finding or
    /// rule) is a new acceptance: `accepted_*` become `by`, and a note says
    /// what it covered before and who had accepted it. Saved unchanged, it
    /// records nothing.
    pub fn upsert_suppression(
        &mut self,
        index: Option<usize>,
        expect: Option<&str>,
        expect_target: Option<&str>,
        s: &SuppressionEdit,
        by: &Stamp,
    ) -> Result<(), String> {
        let reason = clean("Reason", &s.reason)?;
        if reason.is_empty() {
            return Err("Give a reason: why is this risk accepted, and who decided?".into());
        }
        let fingerprint = opt("Finding ID", &s.fingerprint)?;
        let rule = opt("Rule", &s.rule)?;
        let rules = findings::rules();
        let (fingerprint, rule) = match (fingerprint, rule) {
            (Some(_), Some(_)) | (None, None) => {
                return Err("Choose either one finding (by its ID) or a whole rule.".into())
            }
            (None, Some(r)) => (
                None,
                Some(
                    rules
                        .iter()
                        .find(|k| k.id.eq_ignore_ascii_case(&r))
                        .ok_or_else(|| format!("{r} is not a rule (see `pathwarden rules`)"))?
                        .id
                        .to_string(),
                ),
            ),
            (Some(fp), None) => {
                let rule = rules.iter().find(|k| {
                    fp.len() == k.id.len() + 17
                        && fp.is_char_boundary(k.id.len())
                        && fp[..k.id.len()].eq_ignore_ascii_case(k.id)
                        && fp.as_bytes()[k.id.len()] == b'-'
                        && fp[k.id.len() + 1..].bytes().all(|b| b.is_ascii_hexdigit())
                });
                let Some(rule) = rule else {
                    return Err(format!(
                        "{fp} is not a finding ID. It looks like PW-004-13b0863341b2e306: the rule, then 16 letters and digits. The report shows it as \"Finding ID\" under each finding."
                    ));
                };
                // The rule part upper case, the hash lower case, as findings print it.
                let hash = fp[rule.id.len() + 1..].to_ascii_lowercase();
                (Some(format!("{}-{hash}", rule.id)), None)
            }
        };
        let expires = opt("Expiry date", &s.expires)?;
        if let Some(d) = &expires {
            if time::parse_date(d).is_none() || d.len() != 10 {
                return Err(format!("{d} is not a date (YYYY-MM-DD)"));
            }
            // A day already over would accept nothing: the finding counts as
            // open again after it (Config::apply_suppressions). An entry
            // that has expired keeps its date when saved unchanged.
            let kept = index.and_then(|i| {
                let t = self.tables("suppress").ok()?.get(i)?;
                str_of(t, "expires").map(str::to_string)
            });
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            if kept.as_deref() != Some(d.as_str()) && crate::config::expired(d, now) {
                return Err(format!(
                    "{} has already passed (dates are in UTC): from the day after its date, an accepted risk counts as open again. Choose a later date, or none.",
                    crate::time::day_of(d)
                ));
            }
        }
        let t = self.entry("suppress", index, "reason", expect)?;
        if index.is_some() {
            check_target(t, expect_target)?;
        }
        let same = |key: &str, new: &Option<String>| {
            str_of(t, key).map(str::to_ascii_lowercase)
                == new.as_deref().map(str::to_ascii_lowercase)
        };
        let retargeted =
            index.is_some() && !(same("fingerprint", &fingerprint) && same("rule", &rule));
        // A reason written by hand with spaces around it is the same reason
        // (the form trims what it sends back).
        let same_reason = str_of(t, "reason").map(str::trim) == Some(reason.as_str());
        let changed = index.is_some()
            && (retargeted || !same_reason || str_of(t, "expires") != expires.as_deref());
        // Where the old target key was, so a new one takes its place.
        let order: Vec<String> = t.iter().map(|(k, _)| k.to_string()).collect();
        let old_key = if str_of(t, "fingerprint").is_some() {
            "fingerprint"
        } else {
            "rule"
        };
        let new_key = if fingerprint.is_some() {
            "fingerprint"
        } else {
            "rule"
        };
        // What it covered and who had accepted it, for the note a new
        // target leaves.
        let before = retargeted.then(|| {
            let was = target_words(str_of(t, "fingerprint"), str_of(t, "rule"));
            let who = crate::config::stamp_words(
                &str_of(t, "accepted_by").map(str::to_string),
                &str_of(t, "accepted_on").map(str::to_string),
                &str_of(t, "accepted_at").map(str::to_string),
            );
            (was, who)
        });
        let now = target_words(fingerprint.as_deref(), rule.as_deref());
        // A new reason keeps the old one as a note, so the record shows
        // what was decided before.
        let old_reason = index
            .and_then(|_| str_of(t, "reason"))
            .filter(|_| !same_reason)
            .map(|old| old.trim().to_string());
        set_opt(t, "fingerprint", fingerprint);
        set_opt(t, "rule", rule);
        if index.is_none() || !same_reason {
            set_value(t, "reason", Value::from(reason));
        }
        set_opt(t, "expires", expires);
        if retargeted && old_key != new_key {
            let rank = |k: &str| {
                let k = if k == new_key { old_key } else { k };
                order.iter().position(|o| o == k).unwrap_or(usize::MAX)
            };
            t.sort_values_by(|a, _, b, _| rank(a.get()).cmp(&rank(b.get())));
        }
        if let Some((was, who)) = before {
            // A new acceptance: of something else, by whoever changed it.
            for k in ["changed_by", "changed_on", "changed_at"] {
                t.remove(k);
            }
            by.write(t, "accepted_");
            let who = match who {
                Some(w) => format!("it had been accepted {w}"),
                None => "who had accepted it wasn't recorded".into(),
            };
            push_note(t, &format!("Changed from {was} to {now}; {who}."), by)?;
        } else if index.is_none() {
            by.write(t, "accepted_");
        } else if changed {
            by.write(t, "changed_");
        }
        if let Some(old) = old_reason {
            push_note(t, &format!("Reason changed from: {old}"), by)?;
        }
        Ok(())
    }

    /// Removes `[[suppress]]` entry `index` when its reason still reads
    /// `expect_reason` and its finding ID or rule `expect_target` (when given).
    pub fn remove_suppression(
        &mut self,
        index: usize,
        expect_reason: &str,
        expect_target: Option<&str>,
    ) -> Result<(), String> {
        let t = self.entry("suppress", Some(index), "reason", Some(expect_reason))?;
        check_target(t, expect_target)?;
        self.remove_entry("suppress", index, "reason", expect_reason)
    }

    /// Adds a note to `[[suppress]]` entry `index` (`[[suppress.notes]]`,
    /// after its other notes), with who wrote it, where and when. `expect`
    /// is the entry's reason as the page showed it. Notes are kept in the
    /// order they were added; a note doesn't change the entry's `changed_*`.
    pub fn add_suppression_note(
        &mut self,
        index: usize,
        expect: &str,
        expect_target: Option<&str>,
        text: &str,
        by: &Stamp,
    ) -> Result<(), String> {
        let text = clean_note(text)?;
        if text.is_empty() {
            return Err("Write the note: what was decided, checked or changed?".into());
        }
        let t = self.entry("suppress", Some(index), "reason", Some(expect))?;
        check_target(t, expect_target)?;
        push_note(t, &text, by)
    }

    /// `[state]`
    /// `[state] encrypted`: set when the history here is encrypted, removed
    /// when it isn't.
    pub fn set_state_encrypted(&mut self, on: bool) -> Result<(), String> {
        let t = self.table("state")?;
        if on {
            set_value(t, "encrypted", Value::from(true));
        } else {
            t.remove("encrypted");
        }
        Ok(())
    }

    /// `[state] full_runs_kept`: how many full runs the history keeps at its
    /// tip. The default (50) removes the key, so a file that keeps the
    /// default still reads in Pathwarden 0.1.7.
    pub fn set_full_runs_kept(&mut self, n: usize) -> Result<(), String> {
        use crate::config::{DEFAULT_FULL_RUNS_KEPT, MAX_FULL_RUNS_KEPT};
        if !(1..=MAX_FULL_RUNS_KEPT).contains(&n) {
            return Err(format!(
                "Keep between 1 and {MAX_FULL_RUNS_KEPT} full runs."
            ));
        }
        let t = self.table("state")?;
        if n == DEFAULT_FULL_RUNS_KEPT {
            t.remove("full_runs_kept");
        } else {
            set_value(t, "full_runs_kept", Value::from(n as i64));
        }
        Ok(())
    }

    /// `[state] full_run_file_mb`: the largest file a full run keeps, in
    /// MB. The default (75) removes the key.
    pub fn set_full_run_file_mb(&mut self, mb: u64) -> Result<(), String> {
        use crate::config::{DEFAULT_FULL_RUN_FILE_MB, MAX_FULL_RUN_FILE_MB};
        if !(1..=MAX_FULL_RUN_FILE_MB).contains(&mb) {
            return Err(format!("Choose between 1 and {MAX_FULL_RUN_FILE_MB} MB."));
        }
        let t = self.table("state")?;
        if mb == DEFAULT_FULL_RUN_FILE_MB {
            t.remove("full_run_file_mb");
        } else {
            set_value(t, "full_run_file_mb", Value::from(mb as i64));
        }
        Ok(())
    }

    /// Whether saving `s` ([`Self::set_state`]) would keep the history
    /// somewhere else: another backend, repository, branch or folder (for
    /// git, the checkout folder too). A remote sent back as the page shows
    /// it (credentials hidden) is the same remote.
    pub fn state_moves(&self, s: &StateEdit) -> Result<bool, String> {
        let backend = s.backend.trim().to_ascii_lowercase();
        let path = opt("Folder", &s.path)?;
        let mut remote = opt("Repository", &s.remote)?;
        let branch = opt("Branch", &s.branch)?;
        let state = self.doc.get("state");
        let was = |key: &str| {
            state
                .and_then(|t| t.get(key))
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        };
        if let (Some(r), Some(cur)) = (&remote, &was("remote")) {
            if r != cur && *r == crate::config::redact_urls(cur) {
                remote = Some(cur.clone());
            }
        }
        let was_backend = was("backend")
            .map(|b| b.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "local".into());
        // No folder or branch is the default one.
        let or = |v: Option<String>, default: &str| v.unwrap_or_else(|| default.to_string());
        let folder = |v| or(v, "pathwarden-state");
        let main = |v| or(v, "main");
        Ok(was_backend != backend
            || folder(was("path")) != folder(path)
            || (backend == "git"
                && (was("remote") != remote || main(was("branch")) != main(branch))))
    }

    pub fn set_state(&mut self, s: &StateEdit) -> Result<(), String> {
        let backend = s.backend.trim().to_ascii_lowercase();
        if !matches!(backend.as_str(), "local" | "git") {
            return Err("Choose where to keep state: a local folder or a git repository.".into());
        }
        let path = opt("Folder", &s.path)?;
        let mut remote = opt("Repository", &s.remote)?;
        let branch = opt("Branch", &s.branch)?;
        // The page shows the remote with its credentials redacted; sending
        // that back unchanged keeps the saved URL. A new URL may not carry a
        // password at all.
        let current = self
            .doc
            .get("state")
            .and_then(|t| t.get("remote"))
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        if let (Some(r), Some(cur)) = (&remote, &current) {
            if r != cur && *r == crate::config::redact_urls(cur) {
                remote = Some(cur.clone());
            }
        }
        if let Some(r) = &remote {
            if Some(r) != current.as_ref()
                && (crate::config::remote_has_password(r) || crate::config::remote_has_token(r))
            {
                return Err(
                    "Don't put a password or token in the repository URL: git would \
                            store it in plain text. Use a URL without it and sign in through \
                            git's credential helper (Git Credential Manager on Windows)."
                        .into(),
                );
            }
        }
        if backend == "git" {
            let Some(r) = &remote else {
                return Err("Enter the repository URL to keep state in.".into());
            };
            validate_remote(r)?;
        }
        if let Some(b) = &branch {
            validate_branch(b)?;
        }
        let t = self.table("state")?;
        // `encrypted` speaks for one history: a move to another one (a
        // folder, or for git a repository or branch; not where it's
        // checked out) carries nothing over.
        let was = |key: &str| t.get(key).and_then(|v| v.as_str()).map(str::to_owned);
        let moved = was("backend").unwrap_or_else(|| "local".into()) != backend
            || if backend == "git" {
                was("remote") != remote || was("branch") != branch
            } else {
                was("path") != path
            };
        if moved {
            t.remove("encrypted");
        }
        set_value(t, "backend", Value::from(backend.as_str()));
        set_opt(t, "path", path);
        set_opt(t, "remote", remote);
        set_opt(t, "branch", branch);
        if s.include_names {
            set_value(t, "include_names", Value::from(true));
        } else {
            t.remove("include_names");
        }
        match s.push {
            Some(false) => set_value(t, "push", Value::from(false)),
            Some(true) => {
                t.remove("push");
            }
            None => {}
        }
        match s.keep.as_deref().map(|k| k.trim().to_ascii_lowercase()) {
            Some(k) if k == "full" => set_value(t, "keep", Value::from("full")),
            // The default.
            Some(k) if k == "names" => {
                t.remove("keep");
            }
            Some(k) => {
                return Err(format!(
                    "What the history keeps is \"names\" or \"full\", not {k:?}."
                ))
            }
            None => {}
        }
        if let Some(n) = s.refresh {
            set_refresh(t, &backend, n)?;
        }
        Ok(())
    }

    /// `[state] refresh` alone: how often the app pulls a git history
    /// while it is open, in minutes. Refused for a folder history.
    pub fn set_state_refresh(&mut self, n: u32) -> Result<(), String> {
        let backend = self
            .doc
            .get("state")
            .and_then(|t| t.get("backend"))
            .and_then(|v| v.as_str())
            .unwrap_or("local")
            .trim()
            .to_ascii_lowercase();
        let t = self.table("state")?;
        set_refresh(t, &backend, n)
    }

    /// Adds (`index` None) or replaces a `[[zone]]`. `expect` is the zone's
    /// name as the page showed it.
    pub fn upsert_zone(
        &mut self,
        index: Option<usize>,
        expect: Option<&str>,
        z: &ZoneEdit,
    ) -> Result<(), String> {
        let name = clean("Zone name", &z.name)?;
        if name.is_empty() {
            return Err("Give the zone a name.".into());
        }
        if name.len() > 100 {
            return Err("Keep the zone name under 100 characters.".into());
        }
        if is_tier_zero_name(&name) {
            return Err(TIER_ZERO_NAME.into());
        }
        // Zones are picked by name (`--zone`, the reports, the history).
        let taken = self
            .doc
            .get("zone")
            .and_then(Item::as_array_of_tables)
            .is_some_and(|list| {
                list.iter().enumerate().any(|(i, t)| {
                    Some(i) != index
                        && str_of(t, "name").is_some_and(|n| zones::same_name(n, &name))
                })
            });
        if taken {
            return Err(format!("There is already a zone named {name}."));
        }
        let members = clean_list("Members", &z.members)?;
        let groups = clean_list("Groups", &z.groups)?;
        let ous = clean_list("OUs", &z.ous)?;
        if members.is_empty() && groups.is_empty() && ous.is_empty() {
            return Err("Add at least one object, group or OU to the zone.".into());
        }
        let t = self.entry("zone", index, "name", expect)?;
        set_value(t, "name", Value::from(name));
        set_strings(t, "members", &members, false);
        set_strings(t, "groups", &groups, false);
        set_strings(t, "ous", &ous, false);
        Ok(())
    }

    pub fn remove_zone(&mut self, index: usize, expect_name: &str) -> Result<(), String> {
        self.remove_entry("zone", index, "name", expect_name)
    }

    /// Adds (`index` None) or changes an `[[output]]`. `expect` is the
    /// plugin name as the page showed it.
    pub fn upsert_output(
        &mut self,
        index: Option<usize>,
        expect: Option<&str>,
        o: &OutputEdit,
    ) -> Result<(), String> {
        let plugin = o.plugin.trim().to_string();
        if plugin.is_empty()
            || plugin.len() > 64
            || !plugin
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err("Plugin name: use lowercase letters, digits and dashes.".into());
        }
        let command = match &o.command {
            Some(argv) => {
                let argv: Vec<String> = argv
                    .iter()
                    .map(|a| clean("Command", a))
                    .collect::<Result<_, _>>()?;
                let argv: Vec<String> = argv.into_iter().filter(|a| !a.is_empty()).collect();
                let program = argv.first().ok_or("Enter the program to run.")?;
                plugins::check_program(program)?;
                Some(argv)
            }
            None => None,
        };
        let mut set = Vec::new();
        for (k, v) in &o.set {
            if !valid_key(k) || matches!(k.as_str(), "plugin" | "command" | "fields") {
                return Err(format!(
                    "Setting name {k:?}: use lowercase letters, digits and _"
                ));
            }
            let v = match v {
                Setting::Str(s) => Setting::Str(clean(k, s)?),
                other => other.clone(),
            };
            set.push((k.clone(), v));
        }
        let fields = match &o.fields {
            Some(f) => {
                let mut out = Vec::new();
                for (k, v) in f {
                    let k = clean("Field name", k)?;
                    if k.is_empty() {
                        continue;
                    }
                    if !valid_key(&k) {
                        return Err(format!(
                            "Field name {k:?}: use lowercase letters, digits and _"
                        ));
                    }
                    out.push((k.clone(), clean(&k, v)?));
                }
                Some(out)
            }
            None => None,
        };

        let t = self.entry("output", index, "plugin", expect)?;
        set_value(t, "plugin", Value::from(plugin));
        match command {
            Some(argv) => set_value(
                t,
                "command",
                Value::Array(argv.iter().map(String::as_str).collect()),
            ),
            None => {
                t.remove("command");
            }
        }
        if o.replace_scalars {
            let stale: Vec<String> = t
                .iter()
                .filter(|(k, v)| {
                    !matches!(*k, "plugin" | "command")
                        && v.as_value()
                            .is_some_and(|v| !v.is_array() && !v.is_inline_table())
                        && !set.iter().any(|(s, _)| s == k)
                })
                .map(|(k, _)| k.to_string())
                .collect();
            for k in stale {
                t.remove(&k);
            }
        }
        for k in &o.remove {
            t.remove(k);
        }
        for (k, v) in &set {
            set_value(t, k, Value::from(v));
        }
        if let Some(fields) = fields {
            set_fields(t, &fields, o.json_fields);
        }
        Ok(())
    }

    pub fn remove_output(&mut self, index: usize, expect_plugin: &str) -> Result<(), String> {
        self.remove_entry("output", index, "plugin", expect_plugin)
    }

    /// The index of the `[[action]]` block named `name` (its name in
    /// effect, any case).
    pub fn action_index(&self, name: &str) -> Option<usize> {
        self.doc
            .get("action")
            .and_then(Item::as_array_of_tables)?
            .iter()
            .enumerate()
            .position(|(i, t)| action_name_of(t, i).eq_ignore_ascii_case(name.trim()))
    }

    /// Adds (`at` None) or changes an `[[action]]` block: `at` is its index
    /// and its name in effect as the page or command showed it, refused
    /// ([`CHANGED`]) when the block there has another name now. The
    /// program, filters and settings are checked as [`check`] checks a
    /// file. The block always gets a `name`: the one given, else the one
    /// it has, else its plugin's, else its program's or script's file
    /// name ([`crate::config::action_name_for`]), with `-2`, `-3`… when
    /// another block has it. A name given that another block has is
    /// refused.
    pub fn upsert_action(
        &mut self,
        at: Option<(usize, &str)>,
        a: &ActionEdit,
    ) -> Result<(), String> {
        let index = at.map(|(i, _)| i);
        let name = clean("Action name", &a.name)?;
        if !name.is_empty() && !crate::config::valid_plugin_name(&name) {
            return Err("Action name: use lowercase letters, digits and dashes.".into());
        }
        let plugin = match &a.plugin {
            Some(p) => {
                let p = clean("Plugin", p)?;
                if !crate::config::valid_plugin_name(&p) {
                    return Err("Plugin name: use lowercase letters, digits and dashes.".into());
                }
                Some(p)
            }
            None => None,
        };
        let command = match &a.command {
            Some(argv) => {
                let argv: Vec<String> = argv
                    .iter()
                    .map(|x| clean("Command", x))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|x| !x.is_empty())
                    .collect();
                let program = argv.first().ok_or("Enter the program to run.")?;
                plugins::check_program(program)?;
                Some(argv)
            }
            None => None,
        };
        match (&plugin, &command) {
            (Some(_), Some(_)) => return Err("Give a plugin or a command, not both.".into()),
            (None, None) => return Err("Name the program: a plugin or a command.".into()),
            _ => {}
        }
        if let Some(t) = a.timeout_seconds {
            if t > crate::config::ACTION_TIMEOUT_MAX {
                return Err(format!(
                    "Time limit: at most {} seconds.",
                    crate::config::ACTION_TIMEOUT_MAX
                ));
            }
        }
        let min_severity = match a.min_severity.as_deref().map(str::trim) {
            Some("") => Some(None),
            Some(v) => Some(Some(
                v.parse::<findings::Severity>()
                    .map_err(|_| {
                        format!("Minimum severity {v:?}: use critical, high, medium, low or info.")
                    })?
                    .as_str(),
            )),
            None => None,
        };
        let rules = match &a.rules {
            Some(r) => Some(clean_list("Rules", r)?),
            None => None,
        };
        let categories = match &a.categories {
            Some(c) => {
                let mut out = Vec::new();
                for v in clean_list("Categories", c)? {
                    let cat = v
                        .parse::<findings::Category>()
                        .map_err(|_| format!("Category {v:?}: use attack_path or hygiene."))?;
                    out.push(
                        serde_json::to_value(cat)
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_string))
                            .unwrap_or(v),
                    );
                }
                Some(out)
            }
            None => None,
        };
        let mut set = Vec::new();
        for (k, v) in &a.set {
            if !valid_key(k) || crate::config::ACTION_KEYS.contains(&k.as_str()) {
                return Err(format!(
                    "Setting name {k:?}: use lowercase letters, digits and _, and not one of {}",
                    crate::config::ACTION_KEYS.join(", ")
                ));
            }
            let v = match v {
                Setting::Str(s) => Setting::Str(clean(k, s)?),
                other => other.clone(),
            };
            set.push((k.clone(), v));
        }
        let mut current = None;
        if let Some((i, expect)) = at {
            let list = self.tables("action")?;
            let t = list.get(i).ok_or(CHANGED)?;
            let now = action_name_of(t, i);
            if !expect.trim().eq_ignore_ascii_case(&now) {
                return Err(CHANGED.into());
            }
            current = Some(now);
        }
        // Names are how actions are addressed (`<name>/<id>`), so every
        // block gets one that stays when blocks move.
        let taken = |n: &str, me: &Self| me.action_index(n).is_some_and(|i| Some(i) != index);
        let name = if !name.is_empty() {
            if taken(&name, self) {
                return Err(format!(
                    "There is already an action named {name}: give this one another name."
                ));
            }
            name
        } else if let Some(now) = current {
            now
        } else {
            let base = crate::config::action_name_for(plugin.as_deref(), command.as_deref());
            let mut n = 1;
            let mut candidate = base.clone();
            while taken(&candidate, self) {
                n += 1;
                candidate = format!("{base}-{n}");
            }
            candidate
        };
        let t = self.entry("action", index, "name", None)?;
        set_value(t, "name", Value::from(name));
        match plugin {
            Some(p) => {
                set_value(t, "plugin", Value::from(p));
                t.remove("command");
            }
            None => {
                t.remove("plugin");
            }
        }
        if let Some(argv) = command {
            set_value(
                t,
                "command",
                Value::Array(argv.iter().map(String::as_str).collect()),
            );
        }
        match a.timeout_seconds {
            Some(0) => {
                t.remove("timeout_seconds");
            }
            Some(n) => set_value(t, "timeout_seconds", Value::from(n as i64)),
            None => {}
        }
        match min_severity {
            Some(Some(v)) => set_value(t, "min_severity", Value::from(v)),
            Some(None) => {
                t.remove("min_severity");
            }
            None => {}
        }
        if let Some(r) = rules {
            set_strings(t, "rules", &r, false);
        }
        if let Some(c) = categories {
            set_strings(t, "categories", &c, false);
        }
        for k in &a.remove {
            if !crate::config::ACTION_KEYS.contains(&k.as_str()) {
                t.remove(k);
            }
        }
        for (k, v) in &set {
            set_value(t, k, Value::from(v));
        }
        Ok(())
    }

    /// Removes `[[action]]` block `index`, when its name in effect still
    /// reads `expect_name`.
    pub fn remove_action(&mut self, index: usize, expect_name: &str) -> Result<(), String> {
        let list = self.tables("action")?;
        let t = list.get(index).ok_or(CHANGED)?;
        if !expect_name
            .trim()
            .eq_ignore_ascii_case(&action_name_of(t, index))
        {
            return Err(CHANGED.into());
        }
        let raw = str_of(t, "name").unwrap_or_default().to_string();
        self.remove_entry("action", index, "name", &raw)
    }

    // ------------------------------------------------- shared settings

    /// The shared history's `settings/pathwarden.toml` with the sections
    /// `take` names taken from this file (each as written here, comments
    /// inside it kept) and the others as `repo` (the repository's file as
    /// it is, `None` when it has none) holds them, after `header`. When
    /// `mapping` is taken, `[[mapping]]` entries `share_mapping` refuses
    /// are left out and `packs` (path, contents) go along as
    /// `[[mapping_files]]`. Top-level keys of `repo` this version doesn't
    /// know, which a newer Pathwarden wrote, are kept; the sections that are
    /// never shared ([`NEVER_SHARED`]) are dropped. Lines end in LF.
    pub fn shared_text(
        &self,
        header: &str,
        take: &dyn Fn(&str) -> bool,
        share_mapping: &dyn Fn(&Table) -> bool,
        packs: &[(String, String)],
        repo: Option<&str>,
    ) -> String {
        let mut out = repo
            .map(strip_header)
            .and_then(|t| t.parse::<DocumentMut>().ok())
            .unwrap_or_default();
        let root = out.as_table_mut();
        for key in NEVER_SHARED {
            root.remove(key);
        }
        for (key, _) in SHARED_SECTIONS {
            if !take(key) {
                continue;
            }
            let item = match self.doc.get(key) {
                Some(item) if *key == "mapping" => {
                    let mut list = ArrayOfTables::new();
                    for t in item.as_array_of_tables().into_iter().flatten() {
                        if share_mapping(t) {
                            list.push(t.clone());
                        }
                    }
                    (!list.is_empty()).then_some(Item::ArrayOfTables(list))
                }
                Some(item) if !is_empty_item(item) => Some(item.clone()),
                _ => None,
            };
            match item {
                Some(item) => {
                    root.insert(key, item);
                }
                None => {
                    root.remove(key);
                }
            }
            if *key == "mapping" {
                root.remove(MAPPING_FILES);
                if !packs.is_empty() {
                    let mut files = ArrayOfTables::new();
                    for (path, text) in packs {
                        let mut t = Table::new();
                        t.insert("path", Item::Value(Value::from(path.as_str())));
                        t.insert("text", Item::Value(Value::from(text.as_str())));
                        files.push(t);
                    }
                    root.insert(MAPPING_FILES, Item::ArrayOfTables(files));
                }
            }
        }
        // A blank line before each top-level table; the local file's
        // explanations stay there.
        for (_, item) in root.iter_mut() {
            match item {
                Item::Table(t) => t.decor_mut().set_prefix("\n"),
                Item::ArrayOfTables(a) => {
                    for t in a.iter_mut() {
                        t.decor_mut().set_prefix("\n");
                    }
                }
                _ => {}
            }
        }
        for (mut key, _) in root.iter_mut() {
            key.leaf_decor_mut().set_prefix("");
        }
        renumber(&mut out);
        format!("{header}{out}").replace("\r\n", "\n")
    }

    /// Replaces the sections `keys` (of [`SHARED_SECTIONS`]) of this file
    /// with those of `repo` (the shared history's
    /// `settings/pathwarden.toml`), leaving every other section, and the
    /// comments in front of each replaced one, as they are. A section
    /// `repo` lacks is removed here (an empty one is left). `[[mapping]]`
    /// entries `local_only` accepts (packs that never travel) are kept
    /// after the repository's.
    pub fn replace_shared(
        &mut self,
        repo: &str,
        keys: &[&str],
        local_only: &dyn Fn(&Table) -> bool,
        left_out: &dyn Fn(&Table) -> bool,
    ) -> Result<(), String> {
        let repo = strip_header(repo)
            .parse::<DocumentMut>()
            .map_err(|e| format!("the repository's settings are not valid TOML: {e}"))?;
        let root = self.doc.as_table_mut();
        for (key, _) in SHARED_SECTIONS {
            if !keys.contains(key) {
                continue;
            }
            let mut new = repo.get(key).cloned();
            if *key == "mapping" {
                let mut list = ArrayOfTables::new();
                for t in new
                    .as_ref()
                    .and_then(Item::as_array_of_tables)
                    .into_iter()
                    .flatten()
                {
                    if !left_out(t) {
                        list.push(t.clone());
                    }
                }
                for t in root
                    .get(key)
                    .and_then(Item::as_array_of_tables)
                    .into_iter()
                    .flatten()
                {
                    if local_only(t) {
                        list.push(t.clone());
                    }
                }
                new = (!list.is_empty()).then_some(Item::ArrayOfTables(list));
            }
            let old = root.get(key);
            match new {
                None => {
                    if old.is_some_and(|o| !is_empty_item(o)) {
                        root.remove(key);
                    }
                }
                Some(mut item) => {
                    // The comments in front of the section here stay.
                    let prefix = old.and_then(|o| match o {
                        Item::Table(t) => t.decor().prefix().cloned(),
                        Item::ArrayOfTables(a) => {
                            a.get(0).and_then(|t| t.decor().prefix().cloned())
                        }
                        _ => None,
                    });
                    if let Some(p) = prefix {
                        match &mut item {
                            Item::Table(t) => t.decor_mut().set_prefix(p),
                            Item::ArrayOfTables(a) => {
                                if let Some(t) = a.get_mut(0) {
                                    t.decor_mut().set_prefix(p);
                                }
                            }
                            _ => {}
                        }
                    }
                    root.insert(key, item);
                }
            }
        }
        renumber(&mut self.doc);
        Ok(())
    }
}

/// Sections of `pathwarden.toml` that never travel through a shared
/// history: this machine's history folder and remote, plugin targets and
/// finding actions (a writer must never make a reader run a program), and
/// limits and pack trust that stay each machine's, and how it collects.
pub const NEVER_SHARED: &[&str] = &[
    "state",
    "output",
    "action",
    "ingest",
    "opengraph",
    "collect",
];

/// `text` without the comment lines (and blank ones) it starts with: the
/// header Pathwarden writes on the repository's settings file.
fn strip_header(text: &str) -> &str {
    let mut rest = text;
    loop {
        let line_end = rest.find('\n').map_or(rest.len(), |i| i + 1);
        let line = rest[..line_end].trim();
        if line_end == 0 || !(line.is_empty() || line.starts_with('#')) {
            return rest;
        }
        rest = &rest[line_end..];
    }
}

/// In the shared history's `settings/pathwarden.toml`: the contents of the
/// `[[mapping]]` packs (`path`, `text`), which travel with it.
pub const MAPPING_FILES: &str = "mapping_files";

/// Whether `key` is one of [`SHARED_SECTIONS`].
pub fn is_shared_key(key: &str) -> bool {
    SHARED_SECTIONS.iter().any(|(k, _)| *k == key)
}

/// An empty list or table: the same as none.
fn is_empty_item(item: &Item) -> bool {
    match item {
        Item::None => true,
        Item::Table(t) => t.is_empty(),
        Item::ArrayOfTables(a) => a.is_empty(),
        Item::Value(Value::Array(a)) => a.is_empty(),
        Item::Value(Value::InlineTable(t)) => t.is_empty(),
        Item::Value(_) => false,
    }
}

/// Numbers every table of `doc` in the order it holds them, depth first,
/// so each `[[suppress.notes]]` is written under its own `[[suppress]]`
/// even when tables came from another document (whose positions would
/// otherwise interleave with this one's).
fn renumber(doc: &mut DocumentMut) {
    fn walk(t: &mut Table, next: &mut usize) {
        for (_, item) in t.iter_mut() {
            match item {
                Item::Table(s) => {
                    s.set_position(*next);
                    *next += 1;
                    walk(s, next);
                }
                Item::ArrayOfTables(a) => {
                    for s in a.iter_mut() {
                        s.set_position(*next);
                        *next += 1;
                        walk(s, next);
                    }
                }
                _ => {}
            }
        }
    }
    let mut next = 1;
    walk(doc.as_table_mut(), &mut next);
}

/// `text` with the line ends of `like`: CRLF throughout when `like` uses
/// them (a file saved on Windows), as it was.
pub fn same_line_ends(like: &str, text: &str) -> String {
    let lf = text.replace("\r\n", "\n");
    if like.contains("\r\n") {
        lf.replace('\n', "\r\n")
    } else {
        lf
    }
}

/// The document position of the last table among `t` and its sub-tables.
fn last_position(t: &Table) -> Option<usize> {
    let mut max = t.position();
    for (_, item) in t.iter() {
        let sub = match item {
            Item::Table(s) => last_position(s),
            Item::ArrayOfTables(a) => a.iter().filter_map(last_position).max(),
            _ => None,
        };
        max = max.max(sub);
    }
    max
}

fn valid_key(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 64
        && k.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Replaces the `fields` table's contents, in whichever form it is written
/// (`fields = { ... }` or `[output.fields]`).
fn set_fields(t: &mut Table, fields: &[(String, String)], json: bool) {
    let value = |v: &str| -> Value {
        let s = v.trim();
        if json && (s.starts_with('[') || s.starts_with('{')) {
            if let Some(v) = serde_json::from_str::<serde_json::Value>(s)
                .ok()
                .and_then(|j| json_value(&j))
            {
                return v;
            }
        }
        Value::from(v)
    };
    if fields.is_empty() {
        t.remove("fields");
        return;
    }
    match t.get_mut("fields").and_then(Item::as_table_like_mut) {
        Some(existing) => {
            let stale: Vec<String> = existing
                .iter()
                .map(|(k, _)| k.to_string())
                .filter(|k| !fields.iter().any(|(f, _)| f == k))
                .collect();
            for k in stale {
                existing.remove(&k);
            }
            for (k, v) in fields {
                set_value(existing, k, value(v));
            }
        }
        None => {
            let mut inline = InlineTable::new();
            for (k, v) in fields {
                inline.insert(k, value(v));
            }
            inline.fmt();
            t.insert("fields", Item::Value(Value::InlineTable(inline)));
        }
    }
}

/// A JSON value as a TOML one (`null` has none).
fn json_value(j: &serde_json::Value) -> Option<Value> {
    Some(match j {
        serde_json::Value::Null => return None,
        serde_json::Value::Bool(b) => Value::from(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::from(i),
            None => Value::from(n.as_f64()?),
        },
        serde_json::Value::String(s) => Value::from(s.as_str()),
        serde_json::Value::Array(a) => {
            let mut out = Array::new();
            for v in a {
                out.push(json_value(v)?);
            }
            Value::Array(out)
        }
        serde_json::Value::Object(m) => {
            let mut out = InlineTable::new();
            for (k, v) in m {
                out.insert(k, json_value(v)?);
            }
            Value::InlineTable(out)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What counts as moving the history: another backend, folder,
    /// repository or branch; the defaults written out or left out, and the
    /// remote sent back with its credentials hidden, don't.
    #[test]
    fn state_moves_only_for_another_place() {
        let s = |backend: &str, path: Option<&str>, remote: Option<&str>, branch: Option<&str>| {
            StateEdit {
                backend: backend.into(),
                path: path.map(Into::into),
                remote: remote.map(Into::into),
                branch: branch.map(Into::into),
                include_names: true,
                push: None,
                keep: None,
                refresh: None,
            }
        };
        let fresh = ConfigDoc::template();
        assert!(!fresh.state_moves(&s("local", None, None, None)).unwrap());
        assert!(!fresh
            .state_moves(&s("local", Some("pathwarden-state"), None, None))
            .unwrap());
        assert!(fresh
            .state_moves(&s("local", Some("D:\\h"), None, None))
            .unwrap());
        assert!(fresh
            .state_moves(&s("git", None, Some("https://example.com/h.git"), None))
            .unwrap());
        let git = ConfigDoc::parse(
            "[state]\nbackend = \"git\"\nremote = \"https://u:tok@example.com/h.git\"\n",
        )
        .unwrap();
        let shown = crate::config::redact_urls("https://u:tok@example.com/h.git");
        assert!(!git
            .state_moves(&s("git", None, Some(&shown), Some("main")))
            .unwrap());
        assert!(git
            .state_moves(&s("git", None, Some(&shown), Some("other")))
            .unwrap());
        assert!(git
            .state_moves(&s("git", None, Some("https://example.com/x.git"), None))
            .unwrap());
        assert!(git.state_moves(&s("local", None, None, None)).unwrap());
    }

    const HAND_WRITTEN: &str = r#"# My Pathwarden settings, maintained by the identity team.
tier_zero = [
  "BACKUP01.CONTOSO.LOCAL", # backs up the DCs
]

[rules]
# Reviewed 2026-09.
stale_days = 60 # shorter than default
severity = "static"

[[zone]]
name = "Finance"
members = ["FINSQL01.CONTOSO.LOCAL"]

[[output]]
plugin = "servicenow"
instance = "https://contoso.service-now.com"
table = "incident"                 # or "sc_req_item"
on_closed_but_present = "comment"  # a key the form doesn't show

[output.fields]
assignment_group = "Identity"

[output.severity_map.critical]
urgency = "1"
"#;

    fn doc(text: &str) -> ConfigDoc {
        ConfigDoc::parse(text).unwrap()
    }

    fn rules(stale: i64) -> RulesEdit {
        RulesEdit {
            stale_days: stale,
            password_age_days: 365,
            krbtgt_age_days: 180,
            sso_key_age_days: None,
            severity: "exposure".into(),
            disabled: vec!["pw-011".into()],
            severities: Default::default(),
        }
    }

    #[test]
    fn pull_every_is_written_only_when_it_is_not_five() {
        let text = "# Our history\n[state]\nbackend = \"git\" # shared\nremote = \"https://example.com/s.git\"\n# Pulled often\n";
        let mut d = ConfigDoc::parse(text).unwrap();
        d.set_state_refresh(15).unwrap();
        let t = d.text();
        assert!(t.contains("refresh = 15"), "{t}");
        assert!(
            t.contains("# Our history") && t.contains("# shared") && t.contains("# Pulled often"),
            "{t}"
        );
        assert_eq!(check(&t).unwrap().state.refresh_minutes(), 15);
        d.set_state_refresh(5).unwrap();
        let t = d.text();
        assert!(!t.contains("refresh"), "{t}");
        assert!(t.contains("# shared"), "{t}");
        assert_eq!(check(&t).unwrap().state.refresh_minutes(), 5);
        for n in [0, 1441] {
            assert!(d.set_state_refresh(n).unwrap_err().contains("1 to 1440"));
        }
        // Through the form's Save too, and never for a folder.
        let edit = |backend: &str, refresh| StateEdit {
            backend: backend.into(),
            path: None,
            remote: Some("https://example.com/s.git".into()),
            branch: None,
            include_names: false,
            push: None,
            keep: None,
            refresh,
        };
        d.set_state(&edit("git", Some(1440))).unwrap();
        assert!(d.text().contains("refresh = 1440"), "{}", d.text());
        // Left as it is when the form doesn't say.
        d.set_state(&edit("git", None)).unwrap();
        assert!(d.text().contains("refresh = 1440"), "{}", d.text());
        let e = d.set_state(&edit("local", Some(10))).unwrap_err();
        assert!(e.contains("git repository"), "{e}");
        let mut f = ConfigDoc::parse("[state]\nbackend = \"local\"\n").unwrap();
        assert!(f
            .set_state_refresh(10)
            .unwrap_err()
            .contains("git repository"));
        assert!(ConfigDoc::parse("").unwrap().set_state_refresh(10).is_err());
    }

    #[test]
    fn comments_and_unknown_keys_survive() {
        let mut d = doc(HAND_WRITTEN);
        d.set_tier_zero(&[
            "BACKUP01.CONTOSO.LOCAL".into(),
            "VAULT01.CONTOSO.LOCAL".into(),
        ])
        .unwrap();
        d.set_rules(&rules(45), &Stamp::now()).unwrap();
        d.upsert_zone(
            Some(0),
            Some("finance"),
            &ZoneEdit {
                name: "Finance".into(),
                members: vec!["FINSQL01.CONTOSO.LOCAL".into()],
                groups: vec!["FINANCE ADMINS@CONTOSO.LOCAL".into()],
                ous: vec![],
            },
        )
        .unwrap();
        d.upsert_output(
            Some(0),
            Some("servicenow"),
            &OutputEdit {
                plugin: "servicenow".into(),
                set: vec![("table".into(), Setting::Str("sc_req_item".into()))],
                fields: Some(vec![("assignment_group".into(), "IAM".into())]),
                json_fields: false,
                ..Default::default()
            },
        )
        .unwrap();
        let text = d.text();
        let c = d.validate().unwrap();
        for kept in [
            "# My Pathwarden settings, maintained by the identity team.",
            "\"BACKUP01.CONTOSO.LOCAL\", # backs up the DCs",
            "# Reviewed 2026-09.",
            "stale_days = 45 # shorter than default",
            "table = \"sc_req_item\"                 # or \"sc_req_item\"",
            "on_closed_but_present = \"comment\"  # a key the form doesn't show",
            "[output.fields]\nassignment_group = \"IAM\"",
            "[output.severity_map.critical]\nurgency = \"1\"",
        ] {
            assert!(text.contains(kept), "lost {kept:?} in:\n{text}");
        }
        assert_eq!(c.tier_zero.len(), 2);
        assert_eq!(c.rules.stale_days, 45);
        assert_eq!(c.rules.disabled, ["PW-011"]);
        assert_eq!(c.zones[0].groups, ["FINANCE ADMINS@CONTOSO.LOCAL"]);
        assert_eq!(c.outputs[0].settings["on_closed_but_present"], "comment");
        assert!(c.outputs[0].settings.contains_key("severity_map"));
        // Order is kept: the rules table still comes before the zone.
        assert!(text.find("[rules]").unwrap() < text.find("[[zone]]").unwrap());

        // A new entry goes after the last one and its sub-tables, so the
        // sub-tables stay with the entry they belong to.
        d.upsert_output(
            None,
            None,
            &OutputEdit {
                plugin: "teams".into(),
                command: Some(vec!["pwsh".into(), "C:\\t.ps1".into()]),
                ..Default::default()
            },
        )
        .unwrap();
        d.upsert_zone(
            None,
            None,
            &ZoneEdit {
                name: "Payroll".into(),
                members: vec!["PAY01".into()],
                ..Default::default()
            },
        )
        .unwrap();
        let c = d.validate().unwrap();
        assert!(c.outputs[0].settings.contains_key("fields"));
        assert!(!c.outputs[1].settings.contains_key("fields"));
        let text = d.text();
        assert!(
            text.find("name = \"Payroll\"").unwrap() < text.find("[[output]]").unwrap(),
            "{text}"
        );
    }

    #[test]
    fn a_new_file_keeps_the_examples_comments() {
        let mut d = ConfigDoc::template();
        d.set_tier_zero(&["AADCONNECT01.CONTOSO.LOCAL".into()])
            .unwrap();
        d.upsert_suppression(
            None,
            None,
            None,
            &SuppressionEdit {
                fingerprint: Some("PW-004-13B0863341B2E306".into()),
                rule: None,
                reason: "Break-glass account".into(),
                expires: Some("2027-01-31".into()),
            },
            &stamp("ned"),
        )
        .unwrap();
        d.upsert_zone(
            None,
            None,
            &ZoneEdit {
                name: "Tier 1".into(),
                ous: vec!["OU=SERVERS,DC=CONTOSO,DC=LOCAL".into()],
                ..Default::default()
            },
        )
        .unwrap();
        let text = d.text();
        let c = d.validate().unwrap();
        assert!(text.contains("# Systems and accounts your organization treats as Tier Zero"));
        assert!(text.contains("tier_zero = [\n  \"AADCONNECT01.CONTOSO.LOCAL\",\n  # \"AADCONNECT01.CONTOSO.LOCAL\","), "{text}");
        assert!(text.contains("# Accepted risks."));
        // New entries follow the example's closing comments, not split them.
        assert!(
            text.find("# branch = \"main\"").unwrap() < text.find("[[zone]]\nname").unwrap(),
            "{text}"
        );
        assert!(
            text.find("# expires = \"2026-12-31\"").unwrap()
                < text.find("\n[[suppress]]\nfingerprint").unwrap(),
            "{text}"
        );
        assert_eq!(
            c.suppress[0].fingerprint.as_deref(),
            Some("PW-004-13b0863341b2e306")
        );
        assert_eq!(c.zones[0].name, "Tier 1");
        // Removing the only zone removes the [[zone]] list, not the comments.
        d.remove_zone(0, "TIER 1").unwrap();
        assert!(!d.text().contains("[[zone]]\nname"));
        assert!(d.text().contains("# [[zone]]"));
    }

    #[test]
    fn invalid_values_are_rejected() {
        let mut d = ConfigDoc::template();
        assert!(d.set_rules(&rules(0), &Stamp::now()).is_err());
        let mut r = rules(90);
        r.disabled = vec!["PW-999".into()];
        assert!(d.set_rules(&r, &Stamp::now()).is_err());
        let bad = |fp: Option<&str>, rule: Option<&str>, reason: &str, exp: Option<&str>| {
            ConfigDoc::template()
                .upsert_suppression(
                    None,
                    None,
                    None,
                    &SuppressionEdit {
                        fingerprint: fp.map(Into::into),
                        rule: rule.map(Into::into),
                        reason: reason.into(),
                        expires: exp.map(Into::into),
                    },
                    &stamp("ned"),
                )
                .is_err()
        };
        assert!(bad(Some("PW-004-13b0863341b2e306"), None, "  ", None));
        assert!(bad(Some("PW-004-xyz"), None, "r", None));
        assert!(bad(
            Some("PW-004-13b0863341b2e306"),
            Some("PW-004"),
            "r",
            None
        ));
        assert!(bad(None, None, "r", None));
        assert!(bad(None, Some("PW-004"), "r", Some("next week")));
        assert!(bad(None, Some("PW-004"), "line\nbreak", None));
        assert!(!bad(None, Some("pw-004"), "r", Some("2027-01-31")));

        let state = |backend: &str, remote: Option<&str>, branch: Option<&str>| {
            ConfigDoc::template().set_state(&StateEdit {
                backend: backend.into(),
                path: None,
                remote: remote.map(Into::into),
                branch: branch.map(Into::into),
                include_names: false,
                push: None,
                keep: None,
                refresh: None,
            })
        };
        assert!(state("git", None, None).is_err());
        assert!(state("git", Some("--upload-pack=x"), None).is_err());
        assert!(state("git", Some("https://example.com/s.git"), Some("-x")).is_err());
        assert!(state("git", Some("https://example.com/s.git"), Some("a..b")).is_err());
        assert!(state("svn", None, None).is_err());
        assert!(state("git", Some("https://example.com/s.git"), Some("main")).is_ok());
        // A new URL with a password is refused.
        let e = state("git", Some("https://u:tok@example.com/s.git"), None).unwrap_err();
        assert!(e.contains("credential helper"), "{e}");
        assert!(!e.contains("u:tok"), "{e}");
        // One already saved (by hand) survives a save of the redacted form.
        let mut d = ConfigDoc::parse(
            "[state]\nbackend = \"git\"\nremote = \"https://u:tok@example.com/s.git\"\n",
        )
        .unwrap();
        let edit = |remote: &str| StateEdit {
            backend: "git".into(),
            path: None,
            remote: Some(remote.into()),
            branch: None,
            include_names: false,
            push: None,
            keep: None,
            refresh: None,
        };
        d.set_state(&edit("https://***@example.com/s.git")).unwrap();
        assert!(d.text().contains("https://u:tok@example.com/s.git"));
        d.set_state(&edit("https://example.com/other.git")).unwrap();
        assert!(!d.text().contains("u:tok"));

        // `encrypted` speaks for one history: it stays when the working
        // copy moves, and goes when the history does.
        let mut d = ConfigDoc::parse(
            "[state]\nbackend = \"git\"\nremote = \"https://example.com/s.git\"\npath = \"a\"\n",
        )
        .unwrap();
        d.set_state_encrypted(true).unwrap();
        let git_at = |path: &str, remote: &str| StateEdit {
            backend: "git".into(),
            path: Some(path.into()),
            remote: Some(remote.into()),
            branch: None,
            include_names: false,
            push: None,
            keep: None,
            refresh: None,
        };
        d.set_state(&git_at("b", "https://example.com/s.git"))
            .unwrap();
        assert!(d.text().contains("encrypted = true"), "{}", d.text());
        d.set_state(&git_at("b", "https://example.com/other.git"))
            .unwrap();
        assert!(!d.text().contains("encrypted"), "{}", d.text());
        let mut d =
            ConfigDoc::parse("[state]\nbackend = \"local\"\npath = \"a\"\nencrypted = true\n")
                .unwrap();
        d.set_state(&StateEdit {
            backend: "local".into(),
            path: Some("elsewhere".into()),
            remote: None,
            branch: None,
            include_names: false,
            push: None,
            keep: None,
            refresh: None,
        })
        .unwrap();
        assert!(!d.text().contains("encrypted"), "{}", d.text());

        let output = |command: Option<Vec<&str>>, set: Vec<(&str, Setting)>| {
            ConfigDoc::template().upsert_output(
                None,
                None,
                &OutputEdit {
                    plugin: "teams".into(),
                    command: command.map(|c| c.into_iter().map(Into::into).collect()),
                    set: set.into_iter().map(|(k, v)| (k.into(), v)).collect(),
                    ..Default::default()
                },
            )
        };
        assert!(output(Some(vec!["teams.exe"]), vec![]).is_err());
        assert!(output(Some(vec!["powershell", "-File", "C:\\t.ps1"]), vec![]).is_ok());
        assert!(output(None, vec![("Bad Key", Setting::Str("x".into()))]).is_err());
        // An env setting must name a variable; the whole document is checked.
        let mut d = ConfigDoc::template();
        d.upsert_output(
            None,
            None,
            &OutputEdit {
                plugin: "teams".into(),
                set: vec![("webhook_env".into(), Setting::Str("https://x".into()))],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(d.validate().is_err());
    }

    #[test]
    fn a_zone_cant_be_called_tier_zero() {
        let mut d = ConfigDoc::template();
        for name in [
            "Tier Zero",
            "  tier zero ",
            "TIER-ZERO",
            "Tier 0",
            "tier_zero",
            "T0",
            "t-0",
            "Tier Zero.",
            "(Tier 0)",
            "Tier\u{FF10}",
            "\u{FF34}\u{FF10}",
        ] {
            let z = ZoneEdit {
                name: name.into(),
                members: vec!["A".into()],
                ..Default::default()
            };
            assert_eq!(d.upsert_zone(None, None, &z), Err(TIER_ZERO_NAME.into()));
        }
        for name in [
            "Tier Zero adjacent",
            "Tier 1",
            "Zero trust",
            "T1",
            "T0 jump hosts",
        ] {
            assert!(!is_tier_zero_name(name), "{name}");
        }
        // Nor two zones one name; a zone keeps its own when edited.
        let mut d = doc(HAND_WRITTEN);
        let z = ZoneEdit {
            name: "FINANCE".into(),
            members: vec!["A".into()],
            ..Default::default()
        };
        assert_eq!(
            d.upsert_zone(None, None, &z),
            Err("There is already a zone named FINANCE.".into())
        );
        assert!(d.upsert_zone(Some(0), Some("Finance"), &z).is_ok());
        // Names match in any case, accents included.
        let mut d = ConfigDoc::template();
        let z = |name: &str| ZoneEdit {
            name: name.into(),
            members: vec!["A".into()],
            ..Default::default()
        };
        d.upsert_zone(None, None, &z("Évier")).unwrap();
        assert!(d.upsert_zone(None, None, &z("évier")).is_err());
    }

    #[test]
    fn zones_a_save_would_refuse_are_flagged() {
        let zone = |name: &str| ZoneConfig {
            name: name.into(),
            members: vec!["A".into()],
            ..Default::default()
        };
        let list = [zone("Tier 0"), zone("T0"), zone("Web")];
        assert!(zone_name_problem(&list, 0)
            .unwrap()
            .contains("Tier Zero is built in"));
        assert!(zone_name_problem(&list, 1).is_some());
        assert_eq!(zone_name_problem(&list, 2), None);
        assert_eq!(zone_name_problem(&list, 9), None);
    }

    fn stamp(user: &str) -> Stamp {
        Stamp {
            by: Some(format!("NORTH\\{user}")),
            on: Some("SECOPS-WS02".into()),
            at: "2026-10-22T14:03:11Z".into(),
        }
    }

    fn risk(fp: &str, reason: &str, expires: Option<&str>) -> SuppressionEdit {
        SuppressionEdit {
            fingerprint: Some(fp.into()),
            rule: None,
            reason: reason.into(),
            expires: expires.map(Into::into),
        }
    }

    /// The form the docs give, as written by hand before attribution.
    const OLD_RISKS: &str = r#"# Accepted by the CAB.
[[suppress]]
fingerprint = "PW-004-13b0863341b2e306"
reason = "Break-glass account" # CHG0012345
expires = "2027-01-31"

[[suppress]]
rule = "PW-011"
reason = "LAPS rollout tracked in PRJ0042"

# The end.
"#;

    #[test]
    fn accepting_records_who_where_and_when() {
        let mut d = doc(OLD_RISKS);
        d.upsert_suppression(
            None,
            None,
            None,
            &risk("PW-003-39f2ede7c479090b", "Lab only", None),
            &stamp("eddard.stark"),
        )
        .unwrap();
        let text = d.text();
        assert!(
            text.contains(
                "[[suppress]]\nfingerprint = \"PW-003-39f2ede7c479090b\"\nreason = \"Lab only\"\naccepted_by = 'NORTH\\eddard.stark'\naccepted_on = \"SECOPS-WS02\"\naccepted_at = \"2026-10-22T14:03:11Z\"\n"
            ),
            "{text}"
        );
        // Comments and the entries already there are untouched.
        assert!(text.starts_with("# Accepted by the CAB.\n[[suppress]]\nfingerprint = \"PW-004-13b0863341b2e306\"\nreason = \"Break-glass account\" # CHG0012345\n"), "{text}");
        assert!(text.contains("# The end."));
        let c = d.validate().unwrap();
        assert_eq!(c.suppress.len(), 3);
        // The old ones read as not recorded.
        assert!(c.suppress[0].accepted_by.is_none() && c.suppress[0].accepted_at.is_none());
        assert_eq!(
            c.suppress[0].acceptance().accepted_line(),
            crate::config::NOT_RECORDED
        );
        let new = &c.suppress[2];
        assert_eq!(new.accepted_by.as_deref(), Some("NORTH\\eddard.stark"));
        assert_eq!(new.accepted_on.as_deref(), Some("SECOPS-WS02"));
        assert_eq!(new.accepted_at.as_deref(), Some("2026-10-22T14:03:11Z"));
        assert!(new.changed_at.is_none() && new.notes.is_empty());
        assert_eq!(
            new.acceptance().accepted_line(),
            "accepted by NORTH\\eddard.stark on SECOPS-WS02, Oct 22, 2026"
        );
    }

    #[test]
    fn an_unknown_name_is_left_out() {
        let mut d = ConfigDoc::template();
        let nobody = Stamp {
            by: None,
            on: Some("PW-SCHED01".into()),
            at: "2026-10-22T14:03:11Z".into(),
        };
        d.upsert_suppression(
            None,
            None,
            None,
            &risk("PW-004-13b0863341b2e306", "r", None),
            &nobody,
        )
        .unwrap();
        assert!(!d.text().contains("\naccepted_by ="), "{}", d.text());
        let c = d.validate().unwrap();
        assert_eq!(
            c.suppress[0].acceptance().accepted_line(),
            "accepted by an unknown user on PW-SCHED01, Oct 22, 2026"
        );
    }

    #[test]
    fn changes_record_the_last_change_and_keep_who_accepted() {
        let mut d = doc(OLD_RISKS);
        d.upsert_suppression(
            None,
            None,
            None,
            &risk("PW-003-39f2ede7c479090b", "Lab only", None),
            &stamp("eddard.stark"),
        )
        .unwrap();
        // Saved unchanged (the hash in upper case is the same finding): nothing recorded.
        let before = d.text();
        d.upsert_suppression(
            Some(2),
            Some("lab only"),
            None,
            &risk("PW-003-39F2EDE7C479090B", "Lab only", None),
            &stamp("robb.stark"),
        )
        .unwrap();
        assert_eq!(d.text(), before);
        // A new review date is a change.
        let mut later = stamp("robb.stark");
        later.at = "2026-11-02T09:15:00Z".into();
        d.upsert_suppression(
            Some(2),
            Some("Lab only"),
            None,
            &risk("PW-003-39f2ede7c479090b", "Lab only", Some("2099-01-31")),
            &later,
        )
        .unwrap();
        let c = d.validate().unwrap();
        let s = &c.suppress[2];
        assert_eq!(s.accepted_by.as_deref(), Some("NORTH\\eddard.stark"));
        assert_eq!(s.changed_by.as_deref(), Some("NORTH\\robb.stark"));
        assert_eq!(s.changed_at.as_deref(), Some("2026-11-02T09:15:00Z"));
        assert_eq!(
            s.acceptance().changed_line().as_deref(),
            Some("changed by NORTH\\robb.stark on SECOPS-WS02, Nov 2, 2026")
        );
        // So is a new reason; the time moves on.
        later.at = "2026-11-03T10:00:00Z".into();
        d.upsert_suppression(
            Some(2),
            Some("Lab only"),
            None,
            &risk(
                "PW-003-39f2ede7c479090b",
                "Lab only, CHG7",
                Some("2099-01-31"),
            ),
            &later,
        )
        .unwrap();
        let c = d.validate().unwrap();
        assert_eq!(
            c.suppress[2].changed_at.as_deref(),
            Some("2026-11-03T10:00:00Z")
        );
        assert_eq!(
            c.suppress[2].accepted_at.as_deref(),
            Some("2026-10-22T14:03:11Z")
        );
        // The old reason is kept as a note, with who changed it; a new
        // review date alone left none.
        let notes = &c.suppress[2].notes;
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].text, "Reason changed from: Lab only");
        assert_eq!(notes[0].by.as_deref(), Some("NORTH\\robb.stark"));
        assert_eq!(notes[0].on.as_deref(), Some("SECOPS-WS02"));
        assert_eq!(notes[0].at.as_deref(), Some("2026-11-03T10:00:00Z"));
        // Saved unchanged again: no note, nothing recorded.
        let before = d.text();
        d.upsert_suppression(
            Some(2),
            Some("Lab only, CHG7"),
            Some("PW-003-39f2ede7c479090b"),
            &risk(
                "PW-003-39f2ede7c479090b",
                "Lab only, CHG7",
                Some("2099-01-31"),
            ),
            &stamp("someone.else"),
        )
        .unwrap();
        assert_eq!(d.text(), before);
        // An old entry changed: the change is recorded, who accepted it stays unknown.
        d.upsert_suppression(
            Some(1),
            Some("LAPS rollout tracked in PRJ0042"),
            None,
            &SuppressionEdit {
                fingerprint: None,
                rule: Some("PW-011".into()),
                reason: "LAPS rollout tracked in PRJ0042".into(),
                expires: Some("2099-12-31".into()),
            },
            &later,
        )
        .unwrap();
        let c = d.validate().unwrap();
        assert!(c.suppress[1].accepted_by.is_none());
        assert_eq!(
            c.suppress[1].changed_by.as_deref(),
            Some("NORTH\\robb.stark")
        );
        assert!(d.text().contains("# The end."));
    }

    #[test]
    fn notes_are_appended_in_order() {
        let mut d = doc(OLD_RISKS);
        d.add_suppression_note(
            0,
            "break-glass account",
            None,
            "Checked with the CAB.",
            &stamp("ned"),
        )
        .unwrap();
        let mut later = stamp("robb");
        later.at = "2026-11-02T09:15:00Z".into();
        d.add_suppression_note(0, "Break-glass account", None, "Renewed for Q1.", &later)
            .unwrap();
        d.add_suppression_note(
            1,
            "LAPS rollout tracked in PRJ0042",
            None,
            "Half done.",
            &later,
        )
        .unwrap();
        let text = d.text();
        // Each entry's notes follow it, before the next entry.
        let first = text.find("Checked with the CAB.").unwrap();
        let second = text.find("Renewed for Q1.").unwrap();
        let rule = text.find("rule = \"PW-011\"").unwrap();
        let third = text.find("Half done.").unwrap();
        assert!(first < second && second < rule && rule < third, "{text}");
        assert!(text.contains("[[suppress.notes]]\nby = 'NORTH\\ned'\non = \"SECOPS-WS02\"\nat = \"2026-10-22T14:03:11Z\"\ntext = \"Checked with the CAB.\"\n"), "{text}");
        assert!(text.contains("reason = \"Break-glass account\" # CHG0012345"));
        assert!(text.contains("# The end."));
        let c = d.validate().unwrap();
        let n = &c.suppress[0].notes;
        assert_eq!(n.len(), 2);
        assert_eq!(n[0].text, "Checked with the CAB.");
        assert_eq!(n[1].by.as_deref(), Some("NORTH\\robb"));
        assert_eq!(n[1].at.as_deref(), Some("2026-11-02T09:15:00Z"));
        // A note is not a change of the entry.
        assert!(c.suppress[0].changed_at.is_none());
        assert_eq!(c.suppress[1].notes.len(), 1);
        // Editing the entry later keeps its notes.
        d.upsert_suppression(
            Some(0),
            Some("Break-glass account"),
            None,
            &risk(
                "PW-004-13b0863341b2e306",
                "Break-glass, CHG2",
                Some("2099-01-31"),
            ),
            &later,
        )
        .unwrap();
        // ... and adds one for the old reason, after them.
        let n = &d.validate().unwrap().suppress[0].notes;
        assert_eq!(n.len(), 3);
        assert_eq!(n[2].text, "Reason changed from: Break-glass account");
    }

    #[test]
    fn notes_are_checked() {
        let mut d = doc(OLD_RISKS);
        let ned = stamp("ned");
        assert!(d
            .add_suppression_note(0, "Break-glass account", None, "  ", &ned)
            .is_err());
        assert!(d
            .add_suppression_note(0, "Break-glass account", None, "a\u{7}b", &ned)
            .is_err());
        assert!(d
            .add_suppression_note(0, "Break-glass account", None, "a\u{202e}b", &ned)
            .is_err());
        assert_eq!(
            d.add_suppression_note(0, "Something else", None, "x", &ned),
            Err(CHANGED.into())
        );
        assert_eq!(
            d.add_suppression_note(5, "x", None, "x", &ned),
            Err(CHANGED.into())
        );
        // Notes written inline by hand get the next one inline too.
        let mut d = doc(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\nnotes = [{ text = \"by hand\" }]\n",
        );
        d.add_suppression_note(0, "r", None, "from the app", &ned)
            .unwrap();
        let c = d.validate().unwrap();
        assert_eq!(c.suppress[0].notes.len(), 2);
        assert_eq!(c.suppress[0].notes[0].by, None);
        assert_eq!(c.suppress[0].notes[1].text, "from the app");
    }

    #[test]
    fn keys_from_a_newer_version_survive_an_edit() {
        let mut d = doc(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\nticket = \"CHG7\" # from 0.1.8\n\n[[suppress.notes]]\ntext = \"x\"\nvisibility = \"team\"\n",
        );
        let ned = stamp("ned");
        d.upsert_suppression(
            Some(0),
            Some("r"),
            Some("PW-011"),
            &SuppressionEdit {
                fingerprint: None,
                rule: Some("PW-011".into()),
                reason: "r2".into(),
                expires: None,
            },
            &ned,
        )
        .unwrap();
        d.add_suppression_note(0, "r2", Some("pw-011"), "y", &ned)
            .unwrap();
        let text = d.text();
        assert!(text.contains("ticket = \"CHG7\" # from 0.1.8\n"), "{text}");
        assert!(text.contains("visibility = \"team\"\n"), "{text}");
        let c = d.validate().unwrap();
        assert_eq!(c.suppress[0].notes.len(), 3);
        assert_eq!(c.warnings.len(), 2);
    }

    /// The reported case: two risks with one reason; after the first is
    /// removed, an edit meant for it must not land on the second.
    #[test]
    fn an_edit_checks_what_the_risk_covers() {
        let two = "[[suppress]]\nrule = \"PW-011\"\nreason = \"CAB approved\"\n\n[[suppress]]\nfingerprint = \"PW-004-13b0863341b2e306\"\nreason = \"CAB approved\"\n";
        let mut d = doc(two);
        let ned = stamp("ned");
        d.remove_suppression(0, "CAB approved", Some("PW-011"))
            .unwrap();
        // Entry 0 is now the finding: a note for the rule is refused.
        let before = d.text();
        assert_eq!(
            d.add_suppression_note(0, "CAB approved", Some("PW-011"), "x", &ned),
            Err(CHANGED.into())
        );
        assert_eq!(
            d.upsert_suppression(
                Some(0),
                Some("CAB approved"),
                Some("PW-011"),
                &SuppressionEdit {
                    fingerprint: None,
                    rule: Some("PW-011".into()),
                    reason: "CAB approved".into(),
                    expires: Some("2099-01-01".into()),
                },
                &ned,
            ),
            Err(CHANGED.into())
        );
        assert_eq!(
            d.remove_suppression(0, "CAB approved", Some("PW-011")),
            Err(CHANGED.into())
        );
        assert_eq!(d.text(), before);
        // With its own target (any case) it works.
        d.add_suppression_note(
            0,
            "cab approved",
            Some("pw-004-13B0863341B2E306"),
            "x",
            &ned,
        )
        .unwrap();
    }

    #[test]
    fn a_new_target_is_a_new_acceptance() {
        let mut d = doc(
            "[[suppress]]\nfingerprint = \"PW-004-13b0863341b2e306\"\nreason = \"r\"\naccepted_by = 'NORTH\\eddard.stark'\naccepted_on = \"SECOPS-WS02\"\naccepted_at = \"2026-10-22T14:03:11Z\"\nchanged_by = \"x\"\nchanged_at = \"2026-10-23T00:00:00Z\"\n\n[[suppress.notes]]\ntext = \"kept\"\n",
        );
        let mut robb = stamp("robb.stark");
        robb.at = "2026-11-02T09:15:00Z".into();
        d.upsert_suppression(
            Some(0),
            Some("r"),
            Some("PW-004-13b0863341b2e306"),
            &SuppressionEdit {
                fingerprint: None,
                rule: Some("PW-004".into()),
                reason: "r".into(),
                expires: None,
            },
            &robb,
        )
        .unwrap();
        let c = d.validate().unwrap();
        let s = &c.suppress[0];
        assert_eq!(s.rule.as_deref(), Some("PW-004"));
        assert!(s.fingerprint.is_none());
        assert_eq!(s.accepted_by.as_deref(), Some("NORTH\\robb.stark"));
        assert_eq!(s.accepted_at.as_deref(), Some("2026-11-02T09:15:00Z"));
        assert!(s.changed_by.is_none() && s.changed_at.is_none());
        assert_eq!(s.notes.len(), 2);
        assert_eq!(s.notes[0].text, "kept");
        assert_eq!(
            s.notes[1].text,
            "Changed from finding PW-004-13b0863341b2e306 to every PW-004 finding; it had been accepted by NORTH\\eddard.stark on SECOPS-WS02, Oct 22, 2026."
        );
        assert_eq!(s.notes[1].by.as_deref(), Some("NORTH\\robb.stark"));
        // From an entry with no attribution, the note says so.
        let mut d = doc("[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\n");
        d.upsert_suppression(
            Some(0),
            Some("r"),
            None,
            &SuppressionEdit {
                fingerprint: None,
                rule: Some("PW-012".into()),
                reason: "r".into(),
                expires: None,
            },
            &robb,
        )
        .unwrap();
        let c = d.validate().unwrap();
        assert!(c.suppress[0].notes[0]
            .text
            .ends_with("; who had accepted it wasn't recorded."));
    }

    /// A hand-written reason with spaces around it, edited only for its
    /// review date: a change of the date, not of the reason.
    #[test]
    fn spaces_around_a_reason_are_not_a_new_reason() {
        let mut d = doc("[[suppress]]\nrule = \"PW-011\"\nreason = \"Kiosks  \"\n");
        d.upsert_suppression(
            Some(0),
            Some("Kiosks  "),
            Some("PW-011"),
            &SuppressionEdit {
                fingerprint: None,
                rule: Some("PW-011".into()),
                reason: "Kiosks  ".into(),
                expires: Some("2099-01-01".into()),
            },
            &stamp("ned"),
        )
        .unwrap();
        let c = d.validate().unwrap();
        assert!(c.suppress[0].notes.is_empty(), "{:?}", c.suppress[0].notes);
        assert_eq!(c.suppress[0].changed_by.as_deref(), Some("NORTH\\ned"));
        // Saved again unchanged, trimmed or not: nothing recorded.
        let before = d.text();
        for reason in ["Kiosks", "Kiosks  "] {
            d.upsert_suppression(
                Some(0),
                Some(reason),
                Some("PW-011"),
                &SuppressionEdit {
                    fingerprint: None,
                    rule: Some("PW-011".into()),
                    reason: reason.into(),
                    expires: Some("2099-01-01".into()),
                },
                &stamp("robb"),
            )
            .unwrap();
            assert_eq!(d.text(), before);
        }
    }

    /// A new target takes the old one's place in the entry.
    #[test]
    fn a_new_target_keeps_its_place() {
        let mut d = doc(
            "[[suppress]]\nfingerprint = \"PW-004-13b0863341b2e306\" # the break-glass account\nreason = \"r\"\naccepted_by = \"ned\"\n",
        );
        d.upsert_suppression(
            Some(0),
            Some("r"),
            Some("PW-004-13b0863341b2e306"),
            &SuppressionEdit {
                fingerprint: None,
                rule: Some("PW-004".into()),
                reason: "r".into(),
                expires: None,
            },
            &stamp("robb"),
        )
        .unwrap();
        let text = d.text();
        assert!(
            text.starts_with("[[suppress]]\nrule = \"PW-004\"\nreason = \"r\"\naccepted_by = "),
            "{text}"
        );
        d.validate().unwrap();
    }

    #[test]
    fn long_values_are_counted_in_characters() {
        let ned = stamp("ned");
        let mut d = doc("[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\n");
        // 2,048 two-byte characters fit; one more doesn't.
        d.add_suppression_note(0, "r", None, &"é".repeat(MAX_LEN), &ned)
            .unwrap();
        let e = d
            .add_suppression_note(0, "r", None, &"é".repeat(MAX_LEN + 1), &ned)
            .unwrap_err();
        assert!(e.contains("longer than 2048 characters"), "{e}");
    }

    #[test]
    fn notes_may_have_several_lines() {
        let ned = stamp("ned");
        let mut d = doc(OLD_RISKS);
        d.add_suppression_note(
            0,
            "Break-glass account",
            None,
            "  First line\r\nsecond \"line\"  \r\n\r\n\r\n\r\nafter a gap\rlast  ",
            &ned,
        )
        .unwrap();
        let text = d.text();
        // One escaped string: the file's line endings never get into it.
        assert!(
            text.contains("text = \"First line\\nsecond \\\"line\\\"\\n\\nafter a gap\\nlast\"\n"),
            "{text}"
        );
        assert!(text.contains("reason = \"Break-glass account\" # CHG0012345"));
        assert!(text.contains("# The end."));
        let c = d.validate().unwrap();
        assert_eq!(
            c.suppress[0].notes[0].text,
            "First line\nsecond \"line\"\n\nafter a gap\nlast"
        );
        assert_eq!(c.suppress[1].reason, "LAPS rollout tracked in PRJ0042");
        // And again after another save.
        let mut d = doc(&text);
        d.add_suppression_note(0, "Break-glass account", None, "one more", &ned)
            .unwrap();
        let c = d.validate().unwrap();
        assert_eq!(c.suppress[0].notes.len(), 2);
        assert!(c.suppress[0].notes[0].text.contains("\n\nafter a gap"));
    }

    #[test]
    fn unicode_line_separators_are_line_breaks_in_notes() {
        let mut d = doc(OLD_RISKS);
        d.add_suppression_note(
            0,
            "Break-glass account",
            None,
            "one\u{2028}two\u{2029}three",
            &stamp("ned"),
        )
        .unwrap();
        let c = d.validate().unwrap();
        assert_eq!(c.suppress[0].notes[0].text, "one\ntwo\nthree");
    }

    #[test]
    fn windows_line_endings_are_kept() {
        let crlf = OLD_RISKS.replace('\n', "\r\n");
        let mut d = doc(&crlf);
        d.add_suppression_note(0, "Break-glass account", None, "two\nlines", &stamp("ned"))
            .unwrap();
        let out = d.text_for_file();
        assert!(
            !out.replace("\r\n", "").contains('\n'),
            "a bare LF: {out:?}"
        );
        assert!(out.starts_with("# Accepted by the CAB.\r\n[[suppress]]\r\n"));
        assert!(out.contains("text = \"two\\nlines\"\r\n"));
        let c = check(&out).unwrap();
        assert_eq!(c.suppress[0].notes[0].text, "two\nlines");
        // A file with Unix line endings stays so.
        let mut d = doc(OLD_RISKS);
        d.add_suppression_note(0, "Break-glass account", None, "x", &stamp("ned"))
            .unwrap();
        assert!(!d.text_for_file().contains('\r'));
    }

    #[test]
    fn forms_this_page_cant_edit_are_left_alone() {
        let ned = stamp("ned");
        // `notes` that isn't a list.
        let mut d = doc("[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\nnotes = \"x\"\n");
        let e = d.add_suppression_note(0, "r", None, "y", &ned).unwrap_err();
        assert!(e.contains("can't edit"), "{e}");
        // `suppress = [ { ... } ]` written inline.
        let inline = "suppress = [{ rule = \"PW-011\", reason = \"r\" }]\n";
        let mut d = doc(inline);
        assert!(d
            .add_suppression_note(0, "r", None, "y", &ned)
            .unwrap_err()
            .contains("can't edit"));
        assert!(d
            .upsert_suppression(
                None,
                None,
                None,
                &risk("PW-004-13b0863341b2e306", "r", None),
                &ned
            )
            .unwrap_err()
            .contains("can't edit"));
        assert!(d
            .remove_suppression(0, "r", None)
            .unwrap_err()
            .contains("can't edit"));
        assert_eq!(d.text(), inline);
    }

    #[test]
    fn saves_take_turns_under_an_os_lock() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let dir = std::env::temp_dir().join(format!("pw-config-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pathwarden.toml");
        let lock = dir.join(".pathwarden.toml.lock");
        // A lock file left behind (a crashed process): blocks nothing.
        std::fs::write(&lock, "12345").unwrap();
        assert_eq!(with_lock(&path, || Ok(7)), Ok(7));
        // Held by another handle: waits, then refuses, without running.
        let other = std::fs::OpenOptions::new().write(true).open(&lock).unwrap();
        other.lock().unwrap();
        let ran = std::cell::Cell::new(false);
        let started = std::time::Instant::now();
        let e = with_lock_within(&path, std::time::Duration::from_millis(300), || {
            ran.set(true);
            Ok(())
        })
        .unwrap_err();
        assert!(e.contains("Another Pathwarden"), "{e}");
        assert!(!ran.get() && started.elapsed() >= std::time::Duration::from_millis(300));
        // Released: the waiting save goes ahead.
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            other.unlock().unwrap();
            other
        });
        assert_eq!(with_lock(&path, || Ok(1)), Ok(1));
        drop(t.join().unwrap());
        // Many at once: never two inside.
        let inside = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..6)
            .map(|_| {
                let (inside, most, path) = (inside.clone(), most.clone(), path.clone());
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        with_lock(&path, || {
                            let n = inside.fetch_add(1, Ordering::SeqCst) + 1;
                            most.fetch_max(n, Ordering::SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(5));
                            inside.fetch_sub(1, Ordering::SeqCst);
                            Ok(())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(most.load(Ordering::SeqCst), 1);
        // A folder that isn't there: refused at once, not after 10 seconds.
        let started = std::time::Instant::now();
        let e = with_lock(&dir.join("missing").join("pathwarden.toml"), || Ok(())).unwrap_err();
        assert!(e.contains("Could not lock"), "{e}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        // An error from the change still lets the next one in.
        assert_eq!(
            with_lock(&path, || Err::<(), _>("no".to_string())),
            Err("no".into())
        );
        assert_eq!(with_lock(&path, || Ok(2)), Ok(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_edits_are_refused() {
        let mut d = doc(HAND_WRITTEN);
        let z = ZoneEdit {
            name: "X".into(),
            members: vec!["A".into()],
            ..Default::default()
        };
        assert_eq!(
            d.upsert_zone(Some(0), Some("Payroll"), &z),
            Err(CHANGED.into())
        );
        assert_eq!(
            d.upsert_zone(Some(3), Some("Finance"), &z),
            Err(CHANGED.into())
        );
        assert_eq!(d.remove_output(0, "teams"), Err(CHANGED.into()));
        assert!(d.remove_output(0, "servicenow").is_ok());
        assert!(d.validate().unwrap().outputs.is_empty());
    }

    #[test]
    fn generic_plugin_settings_are_replaced() {
        let mut d = ConfigDoc::template();
        let edit = |set: Vec<(&str, &str)>| OutputEdit {
            plugin: "teams".into(),
            command: Some(vec![
                "pwsh".into(),
                "-File".into(),
                "C:\\p\\teams.ps1".into(),
            ]),
            set: set
                .into_iter()
                .map(|(k, v)| (k.to_string(), Setting::Str(v.into())))
                .collect(),
            replace_scalars: true,
            ..Default::default()
        };
        d.upsert_output(
            None,
            None,
            &edit(vec![("webhook_env", "TEAMS_HOOK"), ("min_change", "new")]),
        )
        .unwrap();
        d.upsert_output(
            Some(0),
            Some("teams"),
            &edit(vec![("webhook_env", "TEAMS_HOOK")]),
        )
        .unwrap();
        let c = d.validate().unwrap();
        assert_eq!(
            c.outputs[0].settings.len(),
            1,
            "{:?}",
            c.outputs[0].settings
        );
        assert_eq!(c.outputs[0].command.as_ref().unwrap()[0], "pwsh");
    }

    #[test]
    fn pack_trust_is_added_and_removed() {
        let mut d = ConfigDoc::parse(HAND_WRITTEN).unwrap();
        d.set_pack_trust("mssqlhound", true).unwrap();
        d.set_pack_trust("MSSQLHound", true).unwrap();
        let c = d.validate().unwrap();
        assert_eq!(c.opengraph.trust, vec!["MSSQLHound".to_string()]);
        assert!(d.text().contains("# My Pathwarden settings"));
        d.set_pack_trust("mssqlhound", false).unwrap();
        assert!(d.validate().unwrap().opengraph.trust.is_empty());
        assert!(d.set_pack_trust("a\"b", true).is_err());
    }

    #[test]
    fn writes_atomically() {
        let dir = std::env::temp_dir().join(format!("pw-config-edit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pathwarden.toml");
        write_atomic(&path, "a = 1\n").unwrap();
        write_atomic(&path, "tier_zero = []\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "tier_zero = []\n");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Numbering the tables again changes nothing in a file as written.
    #[test]
    fn renumbering_keeps_a_file_as_it_is() {
        let mut d = ConfigDoc::template();
        d.upsert_suppression(
            None,
            None,
            None,
            &SuppressionEdit {
                fingerprint: None,
                rule: Some("PW-011".into()),
                reason: "r".into(),
                expires: None,
            },
            &Stamp {
                by: Some("ned".into()),
                on: None,
                at: "2026-10-22T14:03:11Z".into(),
            },
        )
        .unwrap();
        let before = d.text();
        renumber(&mut d.doc);
        assert_eq!(d.text(), before);
    }

    /// The shared sections go one way and come back the other: the
    /// comments and other sections here stay, notes stay under their own
    /// risk, unknown keys of a newer version travel, and CRLF stays CRLF.
    #[test]
    fn shared_sections_travel_and_the_rest_stays() {
        let writer = "# Mine\ntier_zero = [\"A@X\"]\n\n[rules]\nstale_days = 30\n\n[state]\nbackend = \"local\"\n\n[[suppress]]\nrule = \"PW-011\"\nreason = \"r1\"\nreview_board = \"CAB\"\n\n[[suppress.notes]]\ntext = \"n1\"\n\n[[suppress]]\nfingerprint = \"PW-004-1\"\nreason = \"r2\"\n\n[[suppress.notes]]\ntext = \"n2\"\n\n[[output]]\nplugin = \"jira\"\n";
        let w = ConfigDoc::parse(writer).unwrap();
        let shared = w.shared_text(
            "# header\n",
            &|_| true,
            &|_| true,
            &[],
            Some("# old header\n[future]\nx = 1\n\n[state]\nbackend = \"local\"\n"),
        );
        assert!(shared.starts_with("# header\n"), "{shared}");
        assert!(!shared.contains("old header"), "{shared}");
        assert!(
            !shared.contains("[state]") && !shared.contains("[[output]]"),
            "never shared, even when the repository held it: {shared}"
        );
        assert!(shared.contains("[future]"), "{shared}");
        // Built on the repository's: only the sections taken change.
        let theirs = "[rules]\nstale_days = 45\n\n[[zone]]\nname = \"Web\"\nmembers = [\"W\"]\n";
        let merged = w.shared_text("", &|k| k == "tier_zero", &|_| true, &[], Some(theirs));
        let c = check(&merged).unwrap();
        assert_eq!((c.tier_zero.len(), c.rules.stale_days), (1, 45));
        assert_eq!(c.zones[0].name, "Web");
        assert!(c.suppress.is_empty());
        // A reader with CRLF line ends, its own [state], comments and output.
        let reader = "# Reader's notes\r\n[state]\r\nbackend = \"git\"\r\nremote = \"r\"\r\n\r\n# about rules\r\n[rules]\r\nstale_days = 60\r\n\r\n[[output]]\r\nplugin = \"teams\"\r\n";
        let mut r = ConfigDoc::parse(reader).unwrap();
        let all: Vec<&str> = SHARED_SECTIONS.iter().map(|(k, _)| *k).collect();
        r.replace_shared(&shared, &all, &|_| false, &|_| false)
            .unwrap();
        let text = same_line_ends(reader, &r.text());
        assert!(
            !text.replace("\r\n", "").contains('\n'),
            "CRLF throughout: {text:?}"
        );
        let c = check(&text).unwrap();
        assert_eq!(c.tier_zero, ["A@X"]);
        assert_eq!(c.rules.stale_days, 30);
        assert_eq!(c.suppress.len(), 2);
        assert_eq!(c.suppress[0].notes[0].text, "n1");
        assert_eq!(c.suppress[1].notes[0].text, "n2");
        assert_eq!(c.outputs[0].plugin, "teams");
        assert_eq!(c.state.remote.as_deref(), Some("r"));
        assert!(
            text.contains("# Reader's notes") && text.contains("# about rules"),
            "{text}"
        );
        assert!(text.contains("review_board"), "{text}");
        assert!(!text.contains("[future]"), "{text}");
        // A section the repository lacks goes.
        let mut r = ConfigDoc::parse(&text).unwrap();
        r.replace_shared("tier_zero = []\n", &all, &|_| false, &|_| false)
            .unwrap();
        let c = check(&r.text()).unwrap();
        assert!(c.suppress.is_empty() && c.tier_zero.is_empty());
        assert_eq!(
            c.rules.stale_days,
            crate::config::RulesConfig::default().stale_days
        );
    }

    /// Only the sections named are replaced: comments inside the others
    /// stay.
    #[test]
    fn sections_in_step_are_left_alone() {
        let here =
            "tier_zero = [\"A\"]\n\n[rules]\n# reviewed with the CAB\nstale_days = 30 # ours\n";
        let mut d = ConfigDoc::parse(here).unwrap();
        d.replace_shared(
            "tier_zero = [\"B\"]\n[rules]\nstale_days = 30\n",
            &["tier_zero"],
            &|_| false,
            &|_| false,
        )
        .unwrap();
        let text = d.text();
        assert!(
            text.contains("# reviewed with the CAB") && text.contains("# ours"),
            "{text}"
        );
        assert_eq!(check(&text).unwrap().tier_zero, ["B"]);
    }
}
