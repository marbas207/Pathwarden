//! Shared settings on the app's pages, from the approved
//! mock-ups: the line under a configuration page's title ("Shared through
//! … · in step"), each section's tag, the choice for a section changed
//! here and in the repository, the note after a pull applied the
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
    self, Applied, Changed, Note, Place, Resolve, SectionDiff, Status,
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
    Some(View {
        status,
        diffs,
        applied,
        remote: loc.git.map(|(r, _)| short_remote(&r)).unwrap_or_default(),
        pushes: loc.push,
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

/// A section's name as the conflict line says it ("Tier Zero differs").
fn short_name(key: &str) -> &'static str {
    match key {
        "tier_zero" => "Tier Zero",
        "settings_folders" => "Tier Zero settings folders",
        "rules" => "Rules",
        "suppress" => "Accepted risks",
        "zone" => "Zones",
        "management_planes" => "Management planes",
        "mapping" => "Mapping packs",
        _ => "",
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

/// "NORTH\eddard.stark on SECOPS-WS02".
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

/// The line under a configuration page's title: where the settings are
/// shared and whether they are in step, with the details behind ⓘ; or,
/// when a section changed here and in the repository, the note that asks
/// for a choice.
pub fn sync_line(v: &View, page: &str) -> String {
    let s = &v.status;
    // Not "in step": nothing here says what the repository holds.
    if let Some(words) = s.unreadable_words(true) {
        return format!(
            r#"<div class="note warn sync-conflict sync-unreadable" role="status">{}<div><p>{}</p></div></div>"#,
            icon("i-alert"),
            esc(&words)
        );
    }
    let both_keys: Vec<&str> = s
        .sections
        .iter()
        .filter(|x| x.state == Changed::Both)
        .map(|x| x.key)
        .collect();
    let both: Vec<&str> = both_keys.iter().map(|k| short_name(k)).collect();
    // Chosen on this page, or on the page the section is on.
    let elsewhere = both_keys.iter().map(|k| page_of(k)).find(|p| p.0 != page);
    let choose = match elsewhere {
        None => "choose below.".to_string(),
        Some((_, href, name)) => format!(r#"choose on <a href="{href}">{name}</a>."#),
    };
    let others_in_step = s
        .sections
        .iter()
        .all(|x| x.state == Changed::InStep || x.state == Changed::Both);
    if !both.is_empty() {
        let rows = vec![
            (
                "Runs".to_string(),
                "Keep going, with the settings on this computer.".to_string(),
            ),
            (
                "Repository".to_string(),
                format!("<code>{}</code>", esc(&v.remote)),
            ),
            (
                "Other sections".to_string(),
                if others_in_step {
                    "In step".to_string()
                } else {
                    esc(&s.changed_words())
                },
            ),
        ];
        return format!(
            r#"<div class="note warn sync-conflict" role="status">{}<div><p><strong>Settings changed here and in the repository.</strong> {} {}: {choose} {}</p></div></div>"#,
            icon("i-alert"),
            esc(&sections_words(&both)),
            if both.len() == 1 { "differs" } else { "differ" },
            tip(&format!("conf-{page}"), "While this is open", &rows, false)
        );
    }
    let changed = |c: Changed| s.sections.iter().filter(|x| x.state == c).count();
    let n = |k: usize| crate::pages::num(k);
    let sections = |k: usize| if k == 1 { "section" } else { "sections" };
    let (class, words) = if !s.in_repository {
        (
            "chg",
            if v.pushes {
                "not in the repository yet".to_string()
            } else {
                "nothing shared in the repository yet".to_string()
            },
        )
    } else if changed(Changed::Here) > 0 {
        let k = changed(Changed::Here);
        (
            "chg",
            if v.pushes {
                format!("{} {} changed here, not pushed yet", n(k), sections(k))
            } else {
                format!(
                    "{} {} changed here, not in the repository",
                    n(k),
                    sections(k)
                )
            },
        )
    } else if changed(Changed::Repository) > 0 {
        let k = changed(Changed::Repository);
        (
            "chg",
            format!("{} {} changed in the repository", n(k), sections(k)),
        )
    } else {
        ("ok", "in step".to_string())
    };
    let mut rows: Vec<(String, String)> = Vec::new();
    if !v.pushes {
        rows.push((
            "This computer".into(),
            if changed(Changed::Here) > 0 {
                "Reads the repository, doesn't push: your change stays here".into()
            } else {
                "Reads the repository, doesn't push".into()
            },
        ));
    }
    let changed_rows: Vec<_> = s
        .sections
        .iter()
        .filter(|x| x.state != Changed::InStep)
        .collect();
    if changed_rows.is_empty() {
        rows.push((
            "Shared".into(),
            "Tier Zero additions, rules, accepted risks, zones, management planes and mapping \
             packs"
                .into(),
        ));
        if let Some(c) = &s.last_change {
            if !c.sections.is_empty() {
                rows.push(("Last change".into(), esc(&sections_words(&c.sections))));
            }
            if let Some(w) = who(&c.by, &c.on) {
                rows.push(("By".into(), esc(&w)));
            }
            rows.push(("When".into(), when(&c.at)));
        }
    } else {
        for x in &changed_rows {
            rows.push((
                x.name.to_string(),
                match x.state {
                    Changed::Here => "Changed here".into(),
                    Changed::Repository => {
                        "Changed in the repository: applied with the next sync".into()
                    }
                    _ => "Changed here and in the repository".into(),
                },
            ));
        }
        rows.push(("Other sections".into(), "In step".into()));
    }
    if let Some(w) = &s.written_by_version {
        rows.push((
            "Written by".into(),
            if s.newer_writer {
                format!("Pathwarden {} (newer than this one)", esc(w))
            } else {
                format!("Pathwarden {}", esc(w))
            },
        ));
    }
    // Plain text by choice: said on the line, never the "in step" colour.
    let (line_class, class, plain) = if s.encrypted {
        ("sync-line", class, "")
    } else {
        rows.push((
            "Encryption".into(),
            "Off: anyone who can read the repository sees these settings and who accepted each \
             risk"
                .into(),
        ));
        (
            "sync-line plain",
            if class == "ok" { "" } else { class },
            r#"<span class="sep">·</span><span class="chg">in plain text (not encrypted)</span>"#,
        )
    };
    format!(
        r#"<p class="{line_class}">{}<span>Shared through <code>{}</code></span><span class="sep">·</span><span class="{class}">{}</span>{plain}{}</p>"#,
        icon("i-history"),
        esc(&v.remote),
        esc(&words),
        tip(&format!("sync-{page}"), "Shared settings", &rows, false),
    )
}

/// A section's state, as a tag beside its title. Sections in step are
/// tagged only while another needs a choice.
pub fn tag(v: &View, key: &str) -> String {
    let Some(x) = v.status.sections.iter().find(|x| x.key == key) else {
        return String::new();
    };
    match x.state {
        Changed::Here => r#"<span class="stag chg">Changed here</span>"#.into(),
        Changed::Repository => r#"<span class="stag chg">Changed in the repository</span>"#.into(),
        Changed::Both => {
            r#"<span class="stag both">Changed here and in the repository</span>"#.into()
        }
        Changed::InStep if v.status.state == Changed::Both => {
            r#"<span class="stag">In step</span>"#.into()
        }
        Changed::InStep => String::new(),
    }
}

fn state(v: &View, key: &str) -> Changed {
    v.status
        .sections
        .iter()
        .find(|x| x.key == key)
        .map_or(Changed::InStep, |x| x.state)
}

/// For a section changed here and in the repository: what each side holds,
/// marked against the last sync, and the two ways out (one on a computer
/// that doesn't push). `None` for any other section.
pub fn conflict(v: &View, key: &str) -> Option<String> {
    if state(v, key) != Changed::Both {
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
        r#"<div class="cmp"><div><h3>Here <span class="muted">{here_when}</span></h3>{}</div><div><h3>In the repository <span class="muted">{repo_who}</span></h3>{}</div></div><div class="cmp-actions"><span class="act"><button type="button" class="btn" data-sync-action="use_repo" data-sync-section="{key}">Use the repository's</button><span class="act-help">Drops your change here</span></span>"#,
        list(&d.here),
        list(&d.repository),
        key = esc(key),
    );
    if v.pushes {
        let _ = write!(
            b,
            r#"<span class="act"><button type="button" class="btn primary" data-sync-action="keep_local" data-sync-section="{key}">Keep mine and push</button><span class="act-help">Replaces the repository's on every machine</span></span>"#,
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
        r#"<span class="act"><button type="button" class="btn" data-sync-action="use_repo" data-sync-section="{}">Use the repository's</button><span class="act-help">Drops your change</span></span>"#,
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
/// "Accepted risks updated from the repository", with who, when and what.
pub fn pulled_note(v: &View) -> String {
    let Some(a) = &v.applied else {
        return String::new();
    };
    let names: Vec<&str> = a.sections.iter().map(String::as_str).collect();
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
        r#"<div class="saved-note card pulled" id="pulled" role="status">{}<div>{} updated from the repository {}</div><button type="button" class="fl-remove" data-close-note aria-label="Close">{}</button></div>"#,
        icon("i-history"),
        esc(&sections_words(&names)),
        tip("pulled", "What came from the repository", &rows, false),
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
        .map(|x| short_name(x.key))
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
                    esc(&upper_first(x.state.words()))
                ),
            )
        })
        .collect();
    if !rows.is_empty() {
        rows.push(("Other sections".into(), "In step".into()));
    }
    let state = if s.unreadable.is_some() {
        r#" · <span class="sync-chg">the repository's settings can't be read here</span> · <a href="/settings">Why</a>"#
            .to_string()
    } else if !both.is_empty() {
        let (_, href, name) = s
            .sections
            .iter()
            .find(|x| x.state == Changed::Both)
            .map_or(("settings", "/settings", "Settings"), |x| page_of(x.key));
        format!(
            r#" · <span class="sync-chg">{} changed here and in the repository</span> · <a href="{href}">Resolve in {name}</a>"#,
            esc(&sections_words(&both))
        )
    } else if s.state == Changed::InStep && s.in_repository {
        " · in step".to_string()
    } else if !s.in_repository {
        " · not in the repository yet".to_string()
    } else {
        format!(" · {}", esc(&s.changed_words()))
    };
    if !both.is_empty() {
        rows.push((
            "Runs".into(),
            "Keep going with the settings on this computer.".into(),
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

fn upper_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
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
pub(crate) struct SyncBody {
    /// `use_repo` or `keep_local`.
    action: String,
    /// The section's key (`tier_zero`, `suppress`, ...).
    section: String,
}

/// `POST /api/settings/sync`: the conflict's buttons (and a reader's
/// "Use the repository's") for one section, as `pathwarden config sync
/// --use-repo|--keep-local --section KEY`.
pub(crate) async fn sync_section(State(st): State<Shared>, Json(body): Json<SyncBody>) -> Response {
    let ws = st.ws();
    let flag = st.state_dir_for(&ws);
    let done =
        tokio::task::spawn_blocking(move || -> Result<Option<String>, String> {
            let resolve = match body.action.as_str() {
                "use_repo" => Resolve::UseRepo(vec![body.section.clone()]),
                "keep_local" => Resolve::KeepLocal(vec![body.section.clone()]),
                _ => return Err("Choose the repository's or yours.".into()),
            };
            let loc = crate::history_ui::locate(&ws, flag.as_deref())?;
            let _lock = loc.store.lock_waiting(settings_sync::lock_wait()).map_err(|e| {
            format!("The history is in use (a run is recording); try again in a moment. ({e:#})")
        })?;
            pathwarden_core::store::non_interactive(|| {
                loc.store
                    .pull()
                    .map_err(|e| format!("Couldn't get the latest from the repository: {e:#}"))?;
                let name = ws.env_name();
                let place = Place {
                    store: &loc.store,
                    config_path: &ws.config_path(),
                    pushes: loc.push,
                    env_name: Some(&name),
                };
                let o = settings_sync::sync(&place, resolve).map_err(|e| format!("{e:#}"))?;
                // The footer's "Settings wait for a choice" goes with it.
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
