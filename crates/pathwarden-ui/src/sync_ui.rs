//! Shared settings on the app's pages, from the approved
//! mock-ups: the line under a configuration page's title ("Shared through
//! … · up to date"), each section's tag, the choice for a section that
//! differs from the shared settings, the note after a pull applied the
//! repository's, and a save's sharing, which runs after the page has its
//! answer. Pages never reach the network to draw this: they read the
//! working copy as the last pull left it
//! ([`pathwarden_core::settings_sync::status`]).
//!
//! The commands live in the docs, not on the pages: `pathwarden config sync`
//! does what the buttons do, from the same code.

use std::collections::HashMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use pathwarden_core::settings_sync::{
    self, Applied, Changed, Clash, MergedHere, Note, Place, Resolve, SectionDiff, Status,
};
use serde::Deserialize;

use crate::pages::{self, esc, icon};
use crate::server::AppState;
use crate::workspace::Workspace;

type Shared = Arc<AppState>;

/// What the pages show about the shared settings of an environment.
pub struct View {
    pub status: Status,
    pub diffs: Vec<SectionDiff>,
    /// What the last pull applied here, when not shown yet.
    pub applied: Option<Applied>,
    /// The repository, short: `git.example.com/sec/goad-pathwarden`.
    pub remote: String,
    /// Whether this computer pushes.
    pub pushes: bool,
    /// The differences on show were dismissed on this computer: the note
    /// is one line, and the rail shows no dot.
    pub dismissed: bool,
    /// What the last merge brought here: its entries are marked "shared"
    /// until a later sync brings others.
    pub merged: Option<MergedHere>,
    /// Say what the last merge brought, under the note ("Merged from the
    /// shared settings: …"): until dismissed with it, or once when there is
    /// no note.
    pub merged_line: bool,
    /// The entries marked "shared": what the last merge brought, not
    /// edited here since, as (section, ID).
    pub marks: Vec<(String, String)>,
}

/// The shared settings of `ws`, when its history shares them. `mark_seen`:
/// the note about what the last pull applied is shown now, not again.
pub fn view(ws: &Workspace, flag: Option<&Path>, mark_seen: bool) -> Option<View> {
    let config = ws.config().ok()?;
    settings_sync::inactive(&config.state)
        .is_none()
        .then_some(())?;
    let loc = crate::history_ui::locate_with(ws, flag, &config).ok()?;
    let place = Place {
        store: &loc.store,
        config_path: &ws.config_path(),
        pushes: loc.push,
        env_name: None,
    };
    let status = settings_sync::status(&place).ok()?;
    let diffs = settings_sync::section_diffs(&place).unwrap_or_default();
    let applied = settings_sync::unseen_applied(&loc.store, mark_seen);
    let dismissed = status
        .differs_key
        .as_ref()
        .is_some_and(|k| settings_sync::dismissed_key(&loc.store).as_ref() == Some(k));
    // Nothing differs any more: the next difference shows again.
    if status.differs_key.is_none() && status.unreadable.is_none() {
        settings_sync::clear_dismissed(&loc.store);
    }
    let merged = settings_sync::merged_here(&loc.store);
    let merged_line = merged.as_ref().is_some_and(|m| {
        if status.clashes.is_empty() {
            !m.seen
        } else {
            !m.dismissed && !dismissed
        }
    });
    // Said once with nothing else to say.
    if merged_line && mark_seen && status.clashes.is_empty() {
        settings_sync::mark_merged(&loc.store, false, merged.as_ref().map(|m| m.at));
    }
    let marks = merged
        .as_ref()
        .map(|m| settings_sync::merged_marks(&place, m))
        .unwrap_or_default();
    Some(View {
        status,
        diffs,
        applied,
        remote: loc.git.map(|(r, _)| short_remote(&r)).unwrap_or_default(),
        pushes: loc.push,
        dismissed,
        merged,
        merged_line,
        marks,
    })
}

/// [`view`] of the current environment, on a blocking thread (reading the
/// last settings commit runs git).
pub async fn view_for(st: &AppState, mark_seen: bool) -> Option<View> {
    let ws = st.ws();
    let flag = st.state_dir_for(&ws);
    tokio::task::spawn_blocking(move || view(&ws, flag.as_deref(), mark_seen))
        .await
        .ok()
        .flatten()
}

/// `https://git.example.com/sec/x.git` -> `git.example.com/sec/x`.
fn short_remote(r: &str) -> String {
    let r = r.trim();
    let r = r.split_once("://").map_or(r, |(_, rest)| rest);
    let r = r.rsplit_once('@').map_or(r, |(_, rest)| rest);
    r.trim_end_matches('/').trim_end_matches(".git").to_string()
}

/// The page a section is changed on: (page, link, name).
fn page_of(key: &str) -> (&'static str, &'static str, &'static str) {
    match key {
        "zone" => ("zones", "/zones", "Zones"),
        _ => ("settings", "/settings", "Settings"),
    }
}

pub(crate) fn tip(id: &str, about: &str, rows: &[(String, String)], open: bool) -> String {
    let mut t = String::new();
    for (k, v) in rows {
        let _ = write!(
            t,
            r#"<span class="src-row"><span>{}</span><span>{v}</span></span>"#,
            esc(k)
        );
    }
    format!(
        r#"<span class="tip{open}"><button type="button" class="tip-btn" aria-label="About: {about}" aria-describedby="tip-{id}">{i}</button><span class="tip-text wide" role="tooltip" id="tip-{id}">{t}</span></span>"#,
        open = if open { " open" } else { "" },
        about = esc(about),
        i = icon("i-info"),
    )
}

/// "NORTH\a.admin on SECOPS-WS02".
pub(crate) fn who(by: &Option<String>, on: &Option<String>) -> Option<String> {
    // Names come from whoever pushed: no direction controls that could
    // make one read as another.
    let plain = |s: &String| -> String {
        s.chars()
            .filter(|c| {
                !matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
            })
            .collect()
    };
    let (by, on) = (by.as_ref().map(plain), on.as_ref().map(plain));
    match (&by, &on) {
        (Some(b), Some(o)) => Some(format!("{b} on {o}")),
        (Some(b), None) => Some(b.clone()),
        (None, Some(o)) => Some(format!("on {o}")),
        (None, None) => None,
    }
}

pub(crate) fn when(at: &str) -> String {
    pathwarden_core::time::parse_rfc3339(at)
        .map(pages::time)
        .unwrap_or_else(|| esc(at))
}

fn sections_words(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// What a configuration page says at its top about the shared settings,
/// only when there is something to act on: the repository's settings can't
/// be read here, or some setting has two values (the note names the first,
/// its ⓘ all of them; one quiet line once dismissed), and under it what
/// the last merge brought. Otherwise nothing.
pub fn sync_line(v: &View, page: &str) -> String {
    let s = &v.status;
    // Not "up to date": nothing here says what the repository holds.
    if let Some(words) = s.unreadable_words(true) {
        return format!(
            r#"<div class="note warn sync-conflict sync-unreadable" role="status">{}<div><p>{}</p></div></div>"#,
            icon("i-alert"),
            esc(&words)
        );
    }
    let merged = merged_words(v);
    let clashes = &s.clashes;
    if clashes.is_empty() {
        return merged;
    }
    let first = settings_sync::clash_words(clashes);
    if v.dismissed {
        return format!(
            r#"<p class="sync-quiet" role="status">{}<span>{}</span></p>"#,
            icon("i-alert"),
            esc(&first)
        );
    }
    let shared_by = shared_by(v);
    let mut rows: Vec<(String, String)> = Vec::new();
    match clashes.as_slice() {
        [one] if !one.whole => {
            rows.push(("This computer".into(), esc(&one.here)));
            rows.push((
                "Shared".into(),
                if shared_by.is_empty() {
                    esc(&one.shared)
                } else {
                    format!("{}, {shared_by}", esc(&one.shared))
                },
            ));
            rows.push((
                "Until you choose".into(),
                format!(
                    "Runs here use {}. Everything else is merged.",
                    esc(&one.here)
                ),
            ));
        }
        _ => {
            for c in clashes {
                rows.push((
                    c.name.clone(),
                    if c.whole {
                        "Changed here and in the shared settings".into()
                    } else {
                        format!("{} here, {} shared", esc(&c.here), esc(&c.shared))
                    },
                ));
            }
            rows.push((
                "Until you choose".into(),
                "Runs here use this computer's values. Everything else is merged.".into(),
            ));
        }
    }
    // Chosen next to the setting, on this page or the one it is on.
    let elsewhere = clashes
        .iter()
        .map(|c| page_of(c.section))
        .find(|p| p.0 != page)
        .filter(|_| clashes.iter().all(|c| page_of(c.section).0 != page))
        .map(|(_, href, name)| format!(r#" Choose on <a href="{href}">{name}</a>."#))
        .unwrap_or_default();
    format!(
        r#"<div class="note warn sync-conflict dismissable" role="status">{}<div><p><strong>{}</strong> {}{elsewhere}</p></div><button type="button" class="linkish sync-dismiss" data-sync-dismiss="{}"{at} title="Hide this notice">Dismiss</button></div>{merged}"#,
        icon("i-alert"),
        esc(&first),
        tip(&format!("conf-{page}"), "Two values", &rows, false),
        esc(s.differs_key.as_deref().unwrap_or_default()),
        at = match v.merged.as_ref().filter(|_| v.merged_line) {
            Some(m) => format!(r#" data-merged-at="{}""#, m.at),
            None => String::new(),
        },
    )
}

/// "Merged from the shared settings: <b>APP01$</b> added to Tier
/// Zero.", while it is to be said ([`View::merged_line`]).
fn merged_words(v: &View) -> String {
    let Some(m) = v.merged.as_ref().filter(|_| v.merged_line) else {
        return String::new();
    };
    if m.entries.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = m
        .entries
        .iter()
        .map(|e| {
            let words = esc(&e.words);
            let label = esc(&e.label);
            match words.strip_prefix(&label) {
                Some(rest) if !label.is_empty() => format!("<strong>{label}</strong>{rest}"),
                _ => words,
            }
        })
        .collect();
    format!(
        r#"<p class="sync-merged">{}<span>Merged from the shared settings: {}.</span></p>"#,
        icon("i-sync"),
        parts.join("; ")
    )
}

/// "CORP\a.admin, Nov 18, 5:55 PM": who made the last shared change,
/// and when.
fn shared_by(v: &View) -> String {
    let Some(c) = &v.status.last_change else {
        return String::new();
    };
    let who =
        c.by.clone()
            .map(|b| who(&Some(b), &None).unwrap_or_default())
            .or_else(|| who(&None, &c.on))
            .map(|w| esc(&w));
    match who {
        Some(w) => format!("{w}, {}", when(&c.at)),
        None => when(&c.at),
    }
}

/// The clashes of section `key`.
pub fn clashes_in<'a>(v: &'a View, key: &str) -> Vec<&'a Clash> {
    v.status
        .clashes
        .iter()
        .filter(|c| c.section == key && !c.whole)
        .collect()
}

/// Whether the jump link to section `key` gets the amber dot: it has a
/// setting with two values, not dismissed.
pub fn jump_dot(v: &View, key: &str) -> bool {
    !v.dismissed && v.status.clashes.iter().any(|c| c.section == key)
}

/// The choice for one setting with two values, right under its field
/// (`id`: `rules.stale_days`): the shared value, who and when, and the
/// buttons ("Use 60", "Keep 30"; only "Use" on a computer that doesn't
/// push). `None` when it has one value.
pub fn clash_row(v: &View, id: &str) -> Option<String> {
    let c = v.status.clashes.iter().find(|c| c.id == id && !c.whole)?;
    Some(clash_html(v, c, false))
}

/// The choices for the settings with two values of section `key` that
/// have no field of their own (all but `fields`), at the top of its card.
pub fn clash_list(v: &View, key: &str, fields: &[&str]) -> String {
    let rows: String = clashes_in(v, key)
        .into_iter()
        .filter(|c| !fields.contains(&c.id.as_str()))
        .map(|c| clash_html(v, c, true))
        .collect();
    if rows.is_empty() {
        rows
    } else {
        format!(r#"<div class="clash-list">{rows}</div>"#)
    }
}

fn clash_html(v: &View, c: &Clash, named: bool) -> String {
    let by = shared_by(v);
    let use_label = match &c.shared_short {
        Some(s) => format!("Use {}", esc(s)),
        None => "Use shared".into(),
    };
    let keep_label = match &c.here_short {
        Some(s) => format!("Keep {}", esc(s)),
        None => "Keep this computer's".into(),
    };
    let keep = if v.pushes {
        format!(
            r#"<button type="button" class="btn small-btn" data-sync-action="keep_local" data-sync-section="{id}">{keep_label}</button>"#,
            id = esc(&c.id)
        )
    } else {
        String::new()
    };
    let head = if named {
        format!("<strong>{}</strong>: {} here. ", esc(&c.name), esc(&c.here))
    } else {
        String::new()
    };
    format!(
        r#"<div class="clash-row" role="group" aria-label="{name} has two values"><p>{head}Shared: <strong>{shared}</strong>{who}</p><div class="acts"><button type="button" class="btn small-btn" data-sync-action="use_repo" data-sync-section="{id}">{use_label}</button>{keep}<span class="save-status muted small" aria-live="polite"></span></div></div>"#,
        name = pages::attr(&c.name),
        shared = esc(&c.shared),
        who = if by.is_empty() {
            String::new()
        } else {
            format!(r#"<span class="who">{by}</span>"#)
        },
        id = esc(&c.id),
    )
}

/// The mark on an entry the last merge brought here ("shared ·
/// CORP\a.admin, Nov 18"), or nothing.
pub fn merged_mark(v: &View, key: &str, id: &str) -> String {
    let Some(m) = &v.merged else {
        return String::new();
    };
    if !v.marks.iter().any(|(s, i)| s == key && i == id) {
        return String::new();
    }
    let day = m
        .changed_at
        .as_deref()
        .and_then(pathwarden_core::time::parse_rfc3339)
        .map(|t| pages::time_as(t, "day"));
    let who = m.by.clone().or_else(|| m.on.clone()).map(|w| esc(&w));
    let rest = match (who, day) {
        (Some(w), Some(d)) => format!(" · {w}, {d}"),
        (Some(w), None) => format!(" · {w}"),
        (None, Some(d)) => format!(" · {d}"),
        (None, None) => String::new(),
    };
    format!(r#"<span class="chip-from">shared{rest}</span>"#)
}

/// A section's state in the pages' words: "Not shared yet" ("Only on this
/// computer" on one that only reads), "Shared update: applied at the next
/// sync", "Differs from the shared settings", "Up to date".
pub fn state_words(v: &View, c: Changed) -> &'static str {
    match c {
        Changed::Here if v.pushes => "Not shared yet",
        Changed::Here => "Only on this computer",
        Changed::Repository => "Shared change, applies at the next sync",
        Changed::Merge => "Shared change, applies at the next sync",
        Changed::Both => BOTH_TAG,
        Changed::InStep => "Up to date",
    }
}

/// The tag of a section changed on both sides.
pub const BOTH_TAG: &str = "Differs from the shared settings";

/// A section's state, as a tag beside its title. Sections up to date are
/// tagged only while another needs a choice.
pub fn tag(v: &View, key: &str) -> String {
    let Some(x) = v.status.sections.iter().find(|x| x.key == key) else {
        return String::new();
    };
    // An entry with two values: how many, in the section's words.
    let n = clashes_in(v, key).len();
    if n > 0 {
        let (one, many) = match key {
            "suppress" => ("accepted risk", "accepted risks"),
            "zone" => ("zone", "zones"),
            "mapping" => ("mapping pack", "mapping packs"),
            "tier_zero" | "settings_folders" => ("entry", "entries"),
            _ => ("setting", "settings"),
        };
        let words = if n == 1 {
            format!("1 {one} has two values")
        } else {
            format!("{n} {many} have two values")
        };
        return format!(r#"<span class="stag clash">{words}</span>"#);
    }
    let class = match x.state {
        Changed::Here | Changed::Repository | Changed::Merge => "stag chg",
        Changed::Both => "stag clash",
        Changed::InStep if v.status.state == Changed::Both => "stag",
        Changed::InStep => return String::new(),
    };
    format!(
        r#"<span class="{class}">{}</span>"#,
        state_words(v, x.state)
    )
}

fn state(v: &View, key: &str) -> Changed {
    v.status
        .sections
        .iter()
        .find(|x| x.key == key)
        .map_or(Changed::InStep, |x| x.state)
}

/// For a section settled whole that changed here and in the repository
/// (it can't be merged entry by entry): what each side holds, marked
/// against the last sync, and the two ways out (one on a computer that
/// doesn't push). `None` for any other section.
pub fn conflict(v: &View, key: &str) -> Option<String> {
    if state(v, key) != Changed::Both
        || !v.status.clashes.iter().any(|c| c.section == key && c.whole)
    {
        return None;
    }
    let d = v.diffs.iter().find(|d| d.key == key)?;
    let list = |lines: &[settings_sync::DiffLine]| {
        let mut b = String::from("<ul>");
        for l in lines {
            let (class, m) = match l.mark {
                '+' => (" class=\"add\"", "+"),
                '-' => (" class=\"del\"", "−"),
                _ => ("", ""),
            };
            let _ = write!(
                b,
                r#"<li{class}><span class="m">{m}</span>{}</li>"#,
                esc(&l.text)
            );
        }
        if lines.is_empty() {
            b.push_str(r#"<li class="muted">Nothing</li>"#);
        }
        b.push_str("</ul>");
        b
    };
    let here_when = d
        .here_at
        .map(|t| format!(" · changed by you, {}", pages::time(t)))
        .unwrap_or_default();
    let repo_who = v
        .status
        .last_change
        .as_ref()
        .map(|c| {
            let w = who(&c.by, &c.on)
                .map(|w| format!("{}, ", esc(&w)))
                .unwrap_or_default();
            format!(" · {w}{}", when(&c.at))
        })
        .unwrap_or_default();
    let mut b = format!(
        r#"<div class="cmp"><div><h3>This computer <span class="muted">{here_when}</span></h3>{}</div><div><h3>Shared <span class="muted">{repo_who}</span></h3>{}</div></div><div class="cmp-actions"><span class="act"><button type="button" class="btn" data-sync-action="use_repo" data-sync-section="{key}">Use shared</button><span class="act-help">Replaces this computer's settings with the shared ones</span></span>"#,
        list(&d.here),
        list(&d.repository),
        key = esc(key),
    );
    if v.pushes {
        let _ = write!(
            b,
            r#"<span class="act"><button type="button" class="btn primary" data-sync-action="keep_local" data-sync-section="{key}">Keep this computer's</button><span class="act-help">Overwrites the shared settings for everyone</span></span>"#,
            key = esc(key),
        );
    }
    b.push_str(r#"<span class="save-status muted small" aria-live="polite"></span></div>"#);
    Some(b)
}

/// For a section changed here on a computer that doesn't push: the way back
/// to the repository's, for the section's own buttons. Empty otherwise.
pub fn reader_action(v: &View, key: &str) -> String {
    if v.pushes || state(v, key) != Changed::Here {
        return String::new();
    }
    format!(
        r#"<span class="act"><button type="button" class="btn" data-sync-action="use_repo" data-sync-section="{}">Use shared settings</button><span class="act-help">Replaces local settings with the shared ones</span></span>"#,
        esc(key)
    )
}

/// The items of section `key` changed here (marked `here` in its list).
pub fn here_items(v: &View, key: &str) -> Vec<String> {
    if state(v, key) != Changed::Here {
        return Vec::new();
    }
    v.diffs
        .iter()
        .find(|d| d.key == key)
        .map(|d| {
            d.here
                .iter()
                .filter(|l| l.mark == '+')
                .map(|l| l.text.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// The note shown once after a pull applied the repository's settings:
/// "Accepted risks updated from the run history", with who, when and what;
/// after a first sync, what it took and where this computer's earlier
/// settings are ([`settings_sync::first_sync_words`]).
pub fn pulled_note(v: &View) -> String {
    let Some(a) = &v.applied else {
        return String::new();
    };
    let names: Vec<&str> = a.sections.iter().map(String::as_str).collect();
    let text = match &a.first {
        Some(first) if !first.is_empty() => {
            let first: Vec<&str> = first.iter().map(String::as_str).collect();
            let backups: Vec<&str> = a.backups.iter().map(String::as_str).collect();
            esc(&settings_sync::first_sync_words(
                &first,
                &backups,
                a.folder_rights,
            ))
        }
        _ => format!(
            "{} updated from the run history",
            esc(&sections_words(&names))
        ),
    };
    let mut rows = Vec::new();
    if let Some(w) = who(&a.by, &a.on) {
        rows.push(("By".to_string(), esc(&w)));
    }
    if let Some(at) = &a.changed_at {
        rows.push(("When".to_string(), when(at)));
    }
    if let Some(s) = &a.summary {
        rows.push((
            "What".to_string(),
            esc(s.strip_prefix("pathwarden settings: ").unwrap_or(s)),
        ));
    }
    rows.push(("Applies".to_string(), "From the next analysis".to_string()));
    format!(
        r#"<div class="saved-note card pulled" id="pulled" role="status">{}<div>{text} {}</div><button type="button" class="fl-remove" data-close-note aria-label="Close">{}</button></div>"#,
        icon("i-history"),
        tip("pulled", "What came from the run history", &rows, false),
        icon("i-x"),
    )
}

/// The row History storage's In use shows for shared settings.
pub fn storage_row(v: &View) -> String {
    let s = &v.status;
    let both: Vec<&str> = s
        .sections
        .iter()
        .filter(|x| x.state == Changed::Both)
        .map(|x| x.name)
        .collect();
    let mut rows: Vec<(String, String)> = s
        .sections
        .iter()
        .filter(|x| x.state != Changed::InStep)
        .map(|x| {
            (
                x.name.to_string(),
                format!(
                    r#"<a href="/settings">{}</a>"#,
                    esc(state_words(v, x.state))
                ),
            )
        })
        .collect();
    if !rows.is_empty() {
        rows.push(("Other settings".into(), "Up to date".into()));
    }
    let state = if s.unreadable.is_some() {
        r#" · <span class="sync-chg">the shared settings can't be read here</span> · <a href="/settings">Why</a>"#
            .to_string()
    } else if !both.is_empty() {
        let (_, href, _) = s
            .sections
            .iter()
            .find(|x| x.state == Changed::Both)
            .map_or(("settings", "/settings", "Settings"), |x| page_of(x.key));
        let words = settings_sync::clash_words(&s.clashes);
        format!(
            r#" · <span class="sync-chg">{}</span> · <a href="{href}">Review</a>"#,
            esc(words.trim_end_matches('.'))
        )
    } else if s.state == Changed::InStep && s.in_repository {
        " · up to date".to_string()
    } else if !s.in_repository {
        " · not shared yet".to_string()
    } else {
        format!(" · {}", esc(&s.changed_words()))
    };
    if !both.is_empty() {
        rows.push((
            "Runs".into(),
            "Use this computer's settings until you choose".into(),
        ));
    }
    // Plain text by choice: said, not left to the Encryption row.
    let state = if s.encrypted || s.unreadable.is_some() {
        state
    } else {
        rows.push((
            "Encryption".into(),
            "Off: anyone who can read the repository sees these settings and who accepted each \
             risk"
                .into(),
        ));
        format!(r#"{state} · <span class="sync-chg">in plain text (not encrypted)</span>"#)
    };
    let tip = if rows.is_empty() {
        String::new()
    } else {
        format!(" {}", tip("hsync", "Shared settings", &rows, false))
    };
    format!(
        r#"<div><dt>Settings</dt><dd>Shared{state}{tip}<span class="fact-sub">Paths, plugins and this section stay local.</span></dd></div>"#
    )
}

// ------------------------------------------------- sharing a save

/// A save's sharing: running, or what came of it.
#[derive(Clone)]
enum Sharing {
    Running,
    Done(Option<Note>),
}

/// Each save's sharing, by the ID its answer carries.
static SHARES: Mutex<Option<HashMap<u64, Sharing>>> = Mutex::new(None);
static NEXT_SHARE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
/// One queue per `pathwarden.toml`: an environment's saves are shared one
/// after the other, in order, never at once.
type Queues = HashMap<PathBuf, Arc<Mutex<()>>>;
static QUEUES: Mutex<Option<Queues>> = Mutex::new(None);

fn set_sharing(id: u64, s: Sharing) {
    let mut m = SHARES.lock().unwrap_or_else(|e| e.into_inner());
    let m = m.get_or_insert_with(HashMap::new);
    // Old answers nobody asks for any more go after a while.
    if m.len() > 256 {
        let oldest = *m.keys().min().unwrap_or(&0);
        m.retain(|k, _| *k > oldest + 128);
    }
    m.insert(id, s);
}

fn queue(path: &Path) -> Arc<Mutex<()>> {
    let mut q = QUEUES.lock().unwrap_or_else(|e| e.into_inner());
    q.get_or_insert_with(HashMap::new)
        .entry(path.to_path_buf())
        .or_default()
        .clone()
}

/// Shares a saved change (`pending`, from
/// [`crate::settings::apply_for_page`]) on a blocking thread after the page
/// has its answer, after any earlier save of the same environment;
/// `/api/settings/sharing?id=` says how it went. Returns the ID, or `None`
/// when there is nothing to share.
pub fn share_later(pending: crate::settings::PendingShare) -> Option<u64> {
    if !pending.needed() {
        return None;
    }
    let id = NEXT_SHARE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let q = queue(pending.path());
    set_sharing(id, Sharing::Running);
    tokio::task::spawn_blocking(move || {
        let _turn = q.lock().unwrap_or_else(|e| e.into_inner());
        let note = pending.run();
        set_sharing(id, Sharing::Done(note));
    });
    Some(id)
}

/// Whether any save's sharing ([`share_later`]) is still running: for
/// tests, which must not pull while one may.
pub fn shares_running() -> bool {
    SHARES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|m| m.values().any(|s| matches!(s, Sharing::Running)))
}

#[derive(Deserialize)]
pub(crate) struct SharingQuery {
    #[serde(default)]
    id: u64,
}

/// `GET /api/settings/sharing?id=N`: how that save's sharing went:
/// `{"running": true}`, or `{"running": false, "note": …, "problem": …}`
/// in the pages' words.
pub(crate) async fn sharing(
    State(_st): State<Shared>,
    axum::extract::Query(q): axum::extract::Query<SharingQuery>,
) -> Response {
    let s = SHARES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(&q.id).cloned());
    Json(match s {
        Some(Sharing::Running) => serde_json::json!({ "running": true }),
        Some(Sharing::Done(n)) => serde_json::json!({
            "running": false,
            "note": n.as_ref().map(|n| n.page.clone()),
            "problem": n.as_ref().is_some_and(|n| n.problem),
        }),
        None => serde_json::json!({ "running": false, "note": null }),
    })
    .into_response()
}

#[derive(Deserialize)]
pub(crate) struct DismissBody {
    /// The differences shown ([`Status::differs_key`]).
    key: String,
    /// The merge whose line was shown with them ([`MergedHere::at`]).
    #[serde(default)]
    merged_at: Option<i64>,
}

/// `POST /api/settings/dismiss`: the note's Dismiss. Hides the rail's dot
/// on this computer while these same differences stand; refused when they
/// changed since the page was drawn (the page reloads to show them).
pub(crate) async fn dismiss(State(st): State<Shared>, Json(body): Json<DismissBody>) -> Response {
    let ws = st.ws();
    let flag = st.state_dir_for(&ws);
    let done = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let loc = crate::history_ui::locate(&ws, flag.as_deref())?;
        let place = Place {
            store: &loc.store,
            config_path: &ws.config_path(),
            pushes: loc.push,
            env_name: None,
        };
        match settings_sync::differs_key(&place) {
            Some(k) if k == body.key => {
                settings_sync::dismiss(&loc.store, &k, body.merged_at).map_err(|e| format!("{e:#}"))
            }
            _ => Err("This page is out of date. Reload it.".into()),
        }
    })
    .await;
    match done {
        Ok(Ok(())) => Json(serde_json::json!({ "saved": true })).into_response(),
        Ok(Err(e)) => crate::settings::json_error(StatusCode::CONFLICT, e),
        Err(_) => crate::settings::json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't save the choice. Try again; if it keeps failing, see Settings › Logs.",
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct SyncBody {
    /// `use_repo` or `keep_local`.
    action: String,
    /// The section's key (`tier_zero`, `suppress`, ...).
    section: String,
}

/// `POST /api/settings/sync`: the conflict's buttons (and a reader's
/// "Use shared settings") for one section, as `pathwarden config sync
/// --use-repo|--keep-local --section KEY`.
pub(crate) async fn sync_section(State(st): State<Shared>, Json(body): Json<SyncBody>) -> Response {
    let ws = st.ws();
    let flag = st.state_dir_for(&ws);
    let done =
        tokio::task::spawn_blocking(move || -> Result<Option<String>, String> {
            let resolve = match body.action.as_str() {
                "use_repo" => Resolve::UseRepo(vec![body.section.clone()]),
                "keep_local" => Resolve::KeepLocal(vec![body.section.clone()]),
                _ => return Err("Choose the shared settings or this computer's.".into()),
            };
            let loc = crate::history_ui::locate(&ws, flag.as_deref())?;
            let _lock = loc.store.lock_waiting(settings_sync::lock_wait()).map_err(|e| {
            pathwarden_core::logs::session_line(&format!("The history is in use: {e:#}"));
            "A run is saving to the history. Try again in a moment.".to_string()
        })?;
            pathwarden_core::store::non_interactive(|| {
                loc.store
                    .pull()
                    .map_err(|e| {
                        pathwarden_core::logs::session_line(&format!(
                            "Couldn't get the latest from the repository: {e:#}"
                        ));
                        crate::history_ui::UNREACHABLE.to_string()
                    })?;
                let name = ws.env_name();
                let place = Place {
                    store: &loc.store,
                    config_path: &ws.config_path(),
                    pushes: loc.push,
                    env_name: Some(&name),
                };
                let o = settings_sync::sync(&place, resolve).map_err(|e| format!("{e:#}"))?;
                // Kept in the last sync's record.
                crate::last_pull::set_conflict(&loc.store, o.conflict());
                // Shown on this page now: the note about it isn't kept for later.
                let _ = settings_sync::unseen_applied(&loc.store, true);
                Ok(o.page_sentence())
            })
        })
        .await;
    match done {
        Ok(Ok(note)) => Json(serde_json::json!({ "saved": true, "note": note })).into_response(),
        Ok(Err(e)) => crate::settings::json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => crate::settings::json_error(StatusCode::INTERNAL_SERVER_ERROR, "Syncing failed."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remotes_are_shown_short() {
        assert_eq!(
            short_remote("https://***@git.example.com/sec/goad-pathwarden.git"),
            "git.example.com/sec/goad-pathwarden"
        );
        assert_eq!(short_remote("C:/repos/state.git"), "C:/repos/state");
        assert_eq!(sections_words(&["A", "B", "C"]), "A, B and C");
    }
}
