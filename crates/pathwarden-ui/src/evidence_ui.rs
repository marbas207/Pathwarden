//! Evidence packs and findings files from the run page, and the
//! signing key and pack checks in Settings.
//!
//! Everything here is shared with the command line, which calls the same
//! functions: [`build_pack`] for `pathwarden evidence --run`,
//! [`findings_doc`] for `pathwarden export --run`, and the key functions for
//! `pathwarden evidence key`. The pack itself is made by
//! [`pathwarden_core::evidence`], as `pathwarden evidence -i` makes it.
//!
//! - **The pack** compares a run (the "after") with an earlier run of its
//!   environment (the "before"), as a retest does, and holds the verdicts,
//!   both sides' findings, the history, the hashes of the run's collector
//!   files (recorded at analysis, [`INPUTS_FILE`]) and the run's
//!   stored report. It is signed with this computer's key.
//! - **The key** lives in a folder only this account can read, in the
//!   workspace ([`KEY_DIR`]).
//! - **A findings file** is the run's event document as SARIF or DefectDojo
//!   JSON, with what the run history knows of each finding.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use axum::extract::{DefaultBodyLimit, Multipart, Path as UrlPath, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pathwarden_core::evidence::content::{self, After, Fresh, Inputs, Sources};
use pathwarden_core::evidence::{self, pack, PublicKey, SecretKey};
use pathwarden_core::retest::{self as core_retest, Baseline, FindingView, RetestReport};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::pages::{esc, icon, time_as, tip};
use crate::retest_ui::env_key;
use crate::run_data;
use crate::server::Shared;
use crate::workspace::{self, RunSummary, Workspace};

/// The folder of the workspace that holds this computer's signing key.
pub const KEY_DIR: &str = "evidence-key";
/// The hashes of the collector files a run analyzed, saved with the run.
pub const INPUTS_FILE: &str = "inputs.json";

/// Largest pack the app checks (a pack holds the report: a few MB).
const MAX_PACK: usize = 64 << 20;

/// Part of `/static/app.css` (see `server`): the dialogs and Settings'
/// sections.
pub const EVIDENCE_CSS: &str = include_str!("assets/evidence.css");
const EVIDENCE_JS: &str = include_str!("assets/evidence.js");

pub fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/static/evidence.js",
            get(|| async {
                ([(header::CONTENT_TYPE, "text/javascript")], EVIDENCE_JS).into_response()
            }),
        )
        .route("/api/runs/{id}/evidence", get(pack_form).post(make_pack))
        .route("/api/runs/{id}/evidence/findings", get(baseline_findings))
        .route("/api/evidence/download/{token}", get(download_pack))
        .route("/api/runs/{id}/findings-file", get(findings_file_info))
        .route("/runs/{id}/findings-file", get(findings_file_download))
        .route("/api/evidence/key", post(key_action))
        .route("/evidence/public-key", get(public_key_download))
        .route(
            "/api/evidence/verify",
            post(verify_upload).layer(DefaultBodyLimit::max(MAX_PACK)),
        )
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

fn attachment(name: &str, content_type: &'static str, body: Vec<u8>) -> Response {
    let mut r = (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        r.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    r
}

// ------------------------------------------------------------ the key

/// This computer's signing key, as Settings shows it.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub fingerprint: String,
    /// When the key file was written (Unix time), if known.
    pub created: Option<i64>,
    /// The key's folder.
    pub dir: PathBuf,
    /// The public key file's text (`evidence.pub`).
    pub public_text: String,
}

impl KeyInfo {
    pub fn json(&self) -> Value {
        json!({
            "fingerprint": self.fingerprint,
            "created": self.created,
            "dir": self.dir.display().to_string(),
        })
    }
}

/// The key folder of the workspace `ws` belongs to.
pub fn key_dir(ws: &Workspace) -> PathBuf {
    ws.root().join(KEY_DIR)
}

/// This computer's signing key, if it has one; an error when the key file
/// is there but unreadable.
pub fn signing_key(ws: &Workspace) -> Result<Option<SecretKey>, String> {
    let file = key_dir(ws).join(evidence::KEY_FILE);
    if !file.exists() {
        return Ok(None);
    }
    evidence::read_secret_key(&file)
        .map(Some)
        .map_err(|e| format!("{e:#}"))
}

/// [`signing_key`] as Settings shows it.
pub fn key_info(ws: &Workspace) -> Result<Option<KeyInfo>, String> {
    let Some(key) = signing_key(ws)? else {
        return Ok(None);
    };
    let dir = key_dir(ws);
    let created = std::fs::metadata(dir.join(evidence::KEY_FILE))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);
    let pk = key.public();
    Ok(Some(KeyInfo {
        fingerprint: pk.fingerprint(),
        created,
        dir,
        public_text: pk.file_text(),
    }))
}

/// Makes `key` this computer's signing key: the key folder is created
/// private if it isn't there, and a key already in it is replaced only with
/// `replace` (else this fails).
fn install_key(ws: &Workspace, key: &SecretKey, replace: bool) -> Result<KeyInfo, String> {
    use pathwarden_core::perms;
    let dir = key_dir(ws);
    match std::fs::symlink_metadata(&dir) {
        Err(_) => perms::create_private_dir(&dir)
            .map_err(|e| format!("Couldn't create {}: {e}", dir.display()))?,
        // A link (or junction) could point the key anywhere.
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
            return Err(format!(
                "{} isn't a plain folder (a link, or a file), so the key isn't kept there. Remove it and try again.",
                dir.display()
            ))
        }
        Ok(_) => {
            // Made readable by others since: private again, or refused.
            if !perms::readable_by_others(&dir).is_empty() {
                let _ = perms::make_private(&dir);
                let still = perms::readable_by_others(&dir);
                if !still.is_empty() {
                    return Err(format!(
                        "Others ({}) can read the key folder {}, and Pathwarden couldn't make it private. Fix its permissions, then try again.",
                        still.join(", "),
                        dir.display()
                    ));
                }
            }
        }
    }
    if dir.join(evidence::KEY_FILE).exists() && !replace {
        return Err("This computer already has a signing key.".into());
    }
    evidence::replace_key_files(&dir, key).map_err(|e| format!("{e:#}"))?;
    let secret = dir.join(evidence::KEY_FILE);
    if !perms::readable_by_others(&secret).is_empty() {
        let _ = perms::make_output_file_private(&secret);
    }
    key_info(ws)?.ok_or_else(|| "The key wasn't saved.".to_string())
}

/// Why the key isn't private, in a sentence: its folder is a link, or
/// others can read the folder or the key file. `None` when it is private.
pub fn key_exposure(ws: &Workspace) -> Option<String> {
    use pathwarden_core::perms;
    let dir = key_dir(ws);
    if std::fs::symlink_metadata(&dir).is_ok_and(|m| m.file_type().is_symlink()) {
        return Some(
            "The key folder is a link, so the key may be kept anywhere. Remove the link, then create or use a key."
                .to_string(),
        );
    }
    let mut who: Vec<String> = Vec::new();
    for w in perms::readable_by_others(&dir)
        .into_iter()
        .chain(perms::readable_by_others(&dir.join(evidence::KEY_FILE)))
    {
        if !who.contains(&w) {
            who.push(w);
        }
    }
    (!who.is_empty()).then(|| {
        format!(
            "{} can read this key. Replace it to make its folder private again.",
            who.join(", ")
        )
    })
}

/// Creates this computer's signing key (`replace`: in place of the one it
/// has). The app's "Create a key" and "Replace key", and
/// `pathwarden evidence key new [--replace]`.
pub fn create_key(ws: &Workspace, replace: bool) -> Result<KeyInfo, String> {
    let key = SecretKey::generate().map_err(|e| format!("{e:#}"))?;
    install_key(ws, &key, replace)
}

/// Makes the secret key in `text` (an `evidence.key` file) this computer's
/// signing key, in place of the one it has. "Use another key file", and
/// `pathwarden evidence key use <FILE>`.
pub fn use_key(ws: &Workspace, text: &str) -> Result<KeyInfo, String> {
    let key = SecretKey::parse(text).map_err(|e| format!("That isn't a signing key: {e:#}."))?;
    install_key(ws, &key, true)
}

// ------------------------------------------------------------ runs

/// A run by the ID `pathwarden runs list` prints: its folder ID or its
/// history run ID.
pub fn find_run(ws: &Workspace, id: &str) -> anyhow::Result<RunSummary> {
    if let Some(r) = ws.run(id) {
        return Ok(r);
    }
    if let Some(r) = ws.find_run(id).and_then(|folder| ws.run(&folder)) {
        return Ok(r);
    }
    anyhow::bail!(
        "no run {id} on this computer in environment {}; `pathwarden runs list` lists its runs",
        ws.env_name()
    )
}

/// The runs a pack of `r` can compare with: the earlier runs of its
/// environment that have their findings, newest first.
pub fn earlier_runs(ws: &Workspace, r: &RunSummary) -> Vec<RunSummary> {
    let key = env_key(r);
    let mut out: Vec<RunSummary> = ws
        .for_run(r)
        .runs()
        .into_iter()
        .filter(|x| env_key(x) == key && r.newer_than(x))
        // Never a run loaded from the history ([`LOADED_RUN`]).
        .filter(|x| x.shared.is_none())
        .filter(|x| {
            ws.run_dir(&x.id)
                .is_some_and(|d| d.join(run_data::EVENT_FILE).is_file())
        })
        .collect();
    out.sort_by(|a, b| b.order_key().cmp(&a.order_key()));
    out
}

/// Why a run loaded from the shared history gets no pack: its findings
/// and report came from whoever can write the history, and a pack signed
/// with this computer's key would vouch for them.
pub const LOADED_RUN: &str = "Made on another computer: make the pack there.";

/// Why a pack of `r` can't be made, if it can't.
pub fn pack_blocked(ws: &Workspace, r: &RunSummary) -> Option<&'static str> {
    if r.shared.is_some() {
        return Some(LOADED_RUN);
    }
    if !ws
        .run_dir(&r.id)
        .is_some_and(|d| d.join(run_data::EVENT_FILE).is_file())
    {
        return Some("This run has no saved findings.");
    }
    if earlier_runs(ws, r).is_empty() {
        return Some("Needs an earlier run of this environment to compare with.");
    }
    None
}

/// The event document of the run in `dir`, as JSON.
fn event_json(dir: &Path) -> Result<Value, String> {
    let bytes = run_data::read_event(dir).map_err(run_data::event_error)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("The run's findings can't be read: {e}"))
}

fn views(event: &Value) -> Result<core_retest::EventFindings, String> {
    core_retest::parse_event(&event.to_string())
}

/// The collector file hashes saved with the run in `dir`, if it has them.
pub fn inputs_of(dir: &Path) -> Option<Inputs> {
    let bytes = std::fs::read(dir.join(INPUTS_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Saves the hashes of `paths` (the collector files analyzed) with the run
/// in `dir` ([`INPUTS_FILE`]). Nothing is saved when one can't be read.
pub fn save_inputs(dir: &Path, paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    if let Ok(i) = content::hash_inputs(paths) {
        if let Ok(b) = serde_json::to_vec_pretty(&i) {
            let _ = std::fs::write(dir.join(INPUTS_FILE), b);
        }
    }
}

/// The run history of `r`'s environment: its findings state and points.
fn history_of(
    ws: &Workspace,
    state_dir: Option<&Path>,
    r: &RunSummary,
) -> (
    Option<pathwarden_core::state::FindingsState>,
    Vec<pathwarden_core::state::HistoryPoint>,
) {
    let ws = ws.for_run(r);
    let Ok(loc) = crate::history_ui::locate(&ws, state_dir) else {
        return (None, Vec::new());
    };
    let state = pathwarden_core::history::findings_state_in(&loc.dir)
        .ok()
        .flatten();
    let points = pathwarden_core::history::load(&loc.dir)
        .map(|(p, _)| p)
        .unwrap_or_default();
    (state, points)
}

/// The pack's file name: `pathwarden-evidence-<run>.zip`.
pub fn pack_file_name(r: &RunSummary, redact: bool) -> String {
    format!(
        "pathwarden-evidence-{}{}.zip",
        r.run_id().replace('.', "-"),
        if redact { "-redacted" } else { "" }
    )
}

/// What to put in a pack ([`build_pack`]).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PackOptions {
    /// The run to compare with (folder or history ID); default the newest
    /// earlier run of the environment.
    pub against: Option<String>,
    /// Only these findings (fingerprints) and the findings of these rules;
    /// both empty, every finding open in the earlier run.
    pub findings: Vec<String>,
    pub rules: Vec<String>,
    /// Leave out the report and every object and domain name.
    pub redact: bool,
}

/// A pack ready to sign and save.
pub struct Built {
    pub contents: evidence::Contents,
    pub report: RetestReport,
    /// The run it compares with.
    pub baseline: RunSummary,
    pub file_name: String,
}

/// Picks the run to compare with.
fn pick_baseline(
    ws: &Workspace,
    r: &RunSummary,
    against: Option<&str>,
) -> Result<RunSummary, String> {
    let earlier = earlier_runs(ws, r);
    match against.map(str::trim).filter(|a| !a.is_empty()) {
        None => earlier.into_iter().next().ok_or_else(|| {
            "There is no earlier run of this environment to compare with.".to_string()
        }),
        Some(a) => earlier
            .into_iter()
            .find(|x| x.id == a || x.run_id() == a)
            .ok_or_else(|| {
                let loaded = ws
                    .for_run(r)
                    .runs()
                    .into_iter()
                    .any(|x| x.shared.is_some() && (x.id == a || x.run_id() == a));
                if loaded {
                    format!(
                        "Run {a} was made on another computer. Compare with a run made here."
                    )
                } else {
                    format!("Run {a} isn't an earlier run of this environment with saved findings.")
                }
            }),
    }
}

/// The open findings of the run to compare with, for picking some: (ID,
/// rule, title).
pub fn baseline_open(
    ws: &Workspace,
    r: &RunSummary,
    against: Option<&str>,
) -> Result<(RunSummary, Vec<FindingView>), String> {
    let b = pick_baseline(ws, r, against)?;
    let dir = ws
        .run_dir(&b.id)
        .ok_or_else(|| "That run no longer exists.".to_string())?;
    let ev = views(&event_json(&dir)?)?;
    let open = ev.findings.into_iter().filter(|f| !f.suppressed).collect();
    Ok((b, open))
}

/// Builds the evidence pack of run `r` against an earlier run, as
/// `pathwarden evidence --run` and the run page make it. `fingerprint` is
/// the signing key's (for the README), `now` the pack's time.
pub fn build_pack(
    ws: &Workspace,
    state_dir: Option<&Path>,
    r: &RunSummary,
    opts: &PackOptions,
    fingerprint: &str,
    now: i64,
) -> Result<Built, String> {
    if r.shared.is_some() {
        return Err(LOADED_RUN.to_string());
    }
    let dir = ws
        .run_dir(&r.id)
        .ok_or_else(|| "That run no longer exists.".to_string())?;
    let b = pick_baseline(ws, r, opts.against.as_deref())?;
    let bdir = ws
        .run_dir(&b.id)
        .ok_or_else(|| "The run to compare with is gone.".to_string())?;
    let after_event = event_json(&dir)?;
    let after = views(&after_event)?;
    let before = views(&event_json(&bdir)?)?;

    // As the run page's retest column judges a later run
    // ([`crate::retest_ui`]): what the earlier run didn't target, and what
    // this one covered.
    let by_scope = |x: &RunSummary| {
        run_data::completeness(ws, x)
            .map(|c| c.untargeted_by_scope(&x.domains))
            .unwrap_or_default()
    };
    let before_untargeted: HashMap<String, pathwarden_core::posture::Untargeted> =
        by_scope(&b).into_iter().collect();
    let mut before_views = before.findings;
    for v in &mut before_views {
        let u = v
            .scope
            .as_ref()
            .and_then(|s| before_untargeted.get(s))
            .copied()
            .unwrap_or_default();
        v.not_targeted = u.parts();
    }
    let label = format!("run {}", b.run_id());
    let base = Baseline::from_views(before_views, label.clone());
    let sources = run_data::run_sources(&dir).unwrap_or_default();
    let base_sources = run_data::run_sources(&bdir);
    let had = base_sources
        .as_ref()
        .map(|s| s.all_keys())
        .unwrap_or_default();
    let coverage = core_retest::Coverage {
        domains: r.domains.clone(),
        complete: !(b.objects > 0 && r.objects * 2 < b.objects) && r.skipped_objects == 0,
        sources,
        // A run saved before runs recorded their computers.
        legacy_hosts: base_sources.is_none_or(|s| s.host_reads.is_empty()),
        ..core_retest::Coverage::default()
    }
    .compared_with(&had)
    .with_untargeted_scopes(by_scope(r));
    let selection = core_retest::Selection {
        fingerprints: opts.findings.clone(),
        rules: opts.rules.clone(),
    };
    let report = core_retest::compare(&base, &after.findings, &coverage, &selection)
        .map_err(|e| format!("{e}."))?;

    // The findings the pack covers: retested and new.
    let covered: BTreeSet<&str> = report
        .results
        .iter()
        .map(|x| x.fingerprint.as_str())
        .chain(report.new.iter().map(|n| n.fingerprint.as_str()))
        .collect();
    let fresh: Vec<Fresh> = after_event["findings"]
        .as_array()
        .map(|a| a.iter().filter_map(Fresh::from_event).collect())
        .unwrap_or_default();
    let fresh: Vec<Fresh> = fresh
        .into_iter()
        .filter(|f| covered.contains(f.fingerprint.as_str()))
        .collect();
    let (state, history) = history_of(ws, state_dir, r);
    // The history's findings state is as of its latest run: for an older
    // run it would tell what came after, so it is left out (and the pack
    // says so).
    let state_left_out = state.is_some() && history.iter().any(|p| p.at > r.created_at);
    let state = state.filter(|_| !state_left_out);
    let inputs = inputs_of(&dir);
    let baseline_inputs = inputs_of(&bdir);
    let settings = dir.join(crate::shared_runs::SETTINGS_FILE);
    let config_sha256 = settings
        .is_file()
        .then(|| pack::hash_file(&settings).ok().map(|(h, _)| h))
        .flatten();
    let html = if opts.redact {
        None
    } else {
        let html = std::fs::read_to_string(dir.join(workspace::REPORT_FILE))
            .map_err(|_| "This run has no saved report.".to_string())?;
        Some(crate::run_list::report_as_now(html, Some(r)))
    };
    let after_run_id = r.run_id();
    let baseline_run_id = b.run_id();
    let src = Sources {
        created_at: now,
        redact: opts.redact,
        report: &report,
        baseline_kind: "run",
        baseline_label: &label,
        baseline_run_id: Some(&baseline_run_id),
        baseline_collected_at: b.collected_at,
        baseline_views: &base.open,
        baseline_inputs: baseline_inputs.as_ref(),
        after: After::Run {
            analyzed_at: r.created_at,
            recorded: crate::history_ui::recorded_id(r).is_some(),
        },
        after_run_id: &after_run_id,
        after_collected_at: r.collected_at,
        inputs: inputs.as_ref(),
        domains: &r.domains,
        objects: r.objects,
        fresh: &fresh,
        state: state.as_ref(),
        state_left_out,
        history: &history,
        config_name: config_sha256
            .as_ref()
            .map(|_| crate::shared_runs::SETTINGS_FILE.to_string()),
        config_sha256,
        config_note: Some("the run's settings were not kept with it"),
        binary_sha256: content::binary_hash(),
        selection_findings: &opts.findings,
        selection_rules: &opts.rules,
    };
    let withhold = opts.redact.then(|| {
        // Trusted domains are named too (in trust findings, for one).
        let mut extra: Vec<String> = r.trusted_domains.clone().unwrap_or_default();
        extra.extend(b.domains.iter().cloned());
        extra.extend(b.trusted_domains.iter().flatten().cloned());
        content::names_to_withhold(&r.domains, &base.open, &fresh, &extra)
    });
    let contents = evidence::contents(&src, fingerprint, html, withhold.as_ref())
        .map_err(|e| format!("{e:#}"))?;
    Ok(Built {
        contents,
        report,
        file_name: pack_file_name(r, opts.redact),
        baseline: b,
    })
}

/// "5 fixed · 56 still open · 0 can't tell · 2 new".
pub fn counts_line(c: &core_retest::RetestCounts) -> String {
    format!(
        "{} fixed · {} still open · {} can't tell · {} new",
        c.fixed, c.still_open, c.cant_tell, c.new
    )
}

// ------------------------------------------------------------ findings files

/// The findings file's name: `pathwarden-findings-<run>.sarif|.json`.
pub fn findings_file_name(r: &RunSummary, format: pathwarden_export::Format) -> String {
    format!(
        "pathwarden-findings-{}.{}",
        r.run_id().replace('.', "-"),
        format.extension()
    )
}

/// Run `r`'s findings as the exporters read them: its event document, with
/// what the run history knows of each finding (when it was first seen, and
/// the findings the run couldn't check). `pathwarden export --run` and the
/// run page's "Findings file".
pub fn findings_doc(
    ws: &Workspace,
    state_dir: Option<&Path>,
    r: &RunSummary,
) -> Result<pathwarden_export::Doc, String> {
    let dir = ws
        .run_dir(&r.id)
        .ok_or_else(|| "That run no longer exists.".to_string())?;
    let bytes = run_data::read_event(&dir).map_err(run_data::event_error)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut doc = pathwarden_export::Doc::from_event(&text).map_err(|e| format!("{e:#}"))?;
    let (state, points) = history_of(ws, state_dir, r);
    // As for a pack: the findings state is the history's latest run's, so
    // for an older run only what it says about then is used (when each
    // finding was first seen), not what is open now.
    let later = points.iter().any(|p| p.at > r.created_at);
    if let Some(state) = state {
        use pathwarden_core::state::Status;
        let present: BTreeSet<String> =
            doc.findings.iter().map(|f| f.fingerprint.clone()).collect();
        for f in &mut doc.findings {
            let Some(t) = state.findings.get(&f.fingerprint) else {
                continue;
            };
            if t.first_seen <= r.created_at && f.first_seen.is_none_or(|s| t.first_seen < s) {
                f.first_seen = Some(t.first_seen);
                if f.change.as_deref() == Some("new") {
                    f.change = Some("open".into());
                }
            }
        }
        // Open in the history, seen by then, and not in this run: the run
        // couldn't check them (as `pathwarden run --event` lists them).
        // Only for the history's latest run: an older run's would come from
        // what later runs found.
        let mut held: Vec<String> = state
            .findings
            .iter()
            .filter(|_| !later)
            .filter(|(fp, t)| {
                t.status != Status::Resolved
                    && t.first_seen <= r.created_at
                    && !present.contains(fp.as_str())
            })
            .map(|(fp, _)| fp.clone())
            .collect();
        held.retain(|fp| !doc.held.contains(fp));
        doc.held.extend(held);
    }
    Ok(doc)
}

// ------------------------------------------------------------ the run page

/// The run page's Download menu: the report, an evidence pack and a
/// findings file. `blocked` says why a pack can't be made.
pub fn download_menu(r: &RunSummary, blocked: Option<&str>) -> String {
    let chev = r#"<svg class="ic chev" aria-hidden="true" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg>"#;
    let pack = match blocked {
        None => format!(
            r#"<li><button type="button" class="menu-item" data-ev-open>{i}<span><strong>Evidence pack…</strong><span class="muted small">Signed proof of which findings this run shows fixed.</span></span></button></li>"#,
            i = icon("i-lock")
        ),
        Some(why) => format!(
            r#"<li><button type="button" class="menu-item" disabled>{i}<span><strong>Evidence pack…</strong><span class="muted small">{why}</span></span></button></li>"#,
            i = icon("i-lock"),
            why = esc(why)
        ),
    };
    format!(
        r#"<details class="menu new-menu dl-menu"><summary class="btn">{i_dl} Download {chev}</summary><ul class="menu-list card menu-right">
<li><a href="/runs/{id}/report?download=1" download>{i_dl}<span><strong>Report</strong><span class="muted small">The HTML report, as shown here.</span></span></a></li>
{pack}
<li><button type="button" class="menu-item" data-ff-open>{i_file}<span><strong>Findings file…</strong><span class="muted small">SARIF or DefectDojo JSON.</span></span></button></li>
</ul></details>"#,
        id = esc(&r.id),
        i_dl = icon("i-download"),
        i_file = icon("i-file"),
    )
}

/// The run page's two dialogs: Evidence pack and Findings file.
pub fn dialogs(r: &RunSummary) -> String {
    let heading = format!(
        "{}, run of {}",
        esc(&r.title()),
        time_as(r.created_at, "date")
    );
    format!(
        r##"<dialog id="ev-dialog" class="card rt-dialog ev-dialog" aria-labelledby="ev-title" data-run="{id}">
  <form method="dialog" class="rt-close-form"><button class="rt-x" value="close" aria-label="Close">{i_x}</button></form>
  <p class="eyebrow">Evidence pack</p>
  <h2 class="sub" id="ev-title">{heading}</h2>
  <div id="ev-make">
  <p class="muted small lead-line">Signed proof of which findings this run shows fixed.</p>
  <form class="ev-form" id="ev-form" autocomplete="off">
    <div class="field"><label for="ev-base">Compared with</label>
      <select class="input" id="ev-base"></select></div>
    <div class="field"><label id="ev-sel-label">Findings</label>
      <fieldset class="choice" aria-labelledby="ev-sel-label">
        <label class="option card"><input type="radio" name="ev-sel" value="all" checked><span><strong>Every finding open in that run</strong><span class="muted" id="ev-all-count"></span></span></label>
        <label class="option card"><input type="radio" name="ev-sel" value="some"><span><strong>Some findings</strong><span class="muted">Pick findings or whole rules.</span></span></label>
      </fieldset>
      <div id="ev-some" hidden>
        <div class="picker"><div class="pathfield card">{i_search}<label class="sr-only" for="ev-q">Search that run's findings</label><input type="search" id="ev-q" placeholder="Search that run's findings by title, rule or ID" autocomplete="off" spellcheck="false"></div><ul class="results card" id="ev-results" role="listbox" hidden></ul></div>
        <ul class="ev-chips" id="ev-chips"></ul>
      </div>
    </div>
    <div class="field"><label id="ev-key-label">Signed with</label><div id="ev-key" aria-labelledby="ev-key-label"></div></div>
    <label class="check-row"><input type="checkbox" id="ev-redact"><span><strong>Leave out names and the report {tip_redact}</strong><span class="muted">For someone who shouldn't see the directory.</span></span></label>
    <p class="rt-limit ev-limit" id="ev-limit">{i_alert}<span>Holds names and the full report. Share it like the report.</span></p>
    <p class="ev-error" id="ev-error" role="alert" hidden></p>
    <div class="ev-foot"><span class="file" id="ev-file"></span><button type="submit" class="btn primary" id="ev-submit" disabled>{i_lock} Make evidence pack</button></div>
  </form>
  </div>
  <div id="ev-done" hidden>
    <div class="ev-res good" id="ev-res">
      <p class="head">{i_check}<strong>Saved to Downloads.</strong></p>
      <dl>
        <dt>File</dt><dd><code id="ev-r-file"></code></dd>
        <dt>Shows</dt><dd id="ev-r-shows"></dd>
        <dt>Checked</dt><dd id="ev-r-checked"></dd>
        <dt>Signed with</dt><dd><code id="ev-r-fp"></code><button type="button" class="copy-btn" data-copy="ev-r-fp" title="Copy" aria-label="Copy the fingerprint">{i_file}</button></dd>
        <dt>Pack SHA-256</dt><dd><code id="ev-r-sha"></code><button type="button" class="copy-btn" data-copy="ev-r-sha" title="Copy" aria-label="Copy the pack's SHA-256">{i_file}</button></dd>
      </dl>
    </div>
    <p class="rt-limit ev-limit" id="ev-r-limit">{i_alert}<span>Holds names and the full report. Share it like the report.</span></p>
    <div class="ev-foot"><span class="muted small">Send the fingerprint separately from the pack. {tip_fp}</span><form method="dialog"><button class="btn" value="done">Done</button></form></div>
  </div>
</dialog>
<dialog id="ff-dialog" class="card rt-dialog ev-dialog" aria-labelledby="ff-title" data-run="{id}">
  <form method="dialog" class="rt-close-form"><button class="rt-x" value="close" aria-label="Close">{i_x}</button></form>
  <p class="eyebrow">Findings file</p>
  <h2 class="sub" id="ff-title">{heading}</h2>
  <p class="muted small lead-line" id="ff-lead"></p>
  <div class="ev-form">
    <div class="field"><label id="ff-fmt-label">Format</label>
      <fieldset class="choice two" aria-labelledby="ff-fmt-label">
        <label class="option card"><input type="radio" name="ff-fmt" value="sarif" checked><span><strong>SARIF 2.1.0</strong><span class="muted">For code scanning tools and SIEMs.</span></span></label>
        <label class="option card"><input type="radio" name="ff-fmt" value="defectdojo"><span><strong>DefectDojo</strong><span class="muted">Generic Findings Import JSON.</span></span></label>
      </fieldset></div>
    <p class="rt-limit" id="ff-held" hidden>{i_alert}<span><span id="ff-held-text"></span> {tip_held}</span></p>
    <p class="ev-error" id="ff-error" role="alert" hidden></p>
    <div class="ev-foot"><span class="file" id="ff-file"></span><a class="btn primary" id="ff-download" href="/runs/{id}/findings-file?format=sarif" download>{i_dl} Download</a></div>
  </div>
</dialog>
<script src="/static/evidence.js" defer></script>
"##,
        id = esc(&r.id),
        i_x = icon("i-x"),
        i_alert = icon("i-alert"),
        i_lock = icon("i-lock"),
        i_check = icon("i-check"),
        i_file = icon("i-file"),
        i_dl = icon("i-download"),
        i_search = icon("i-search"),
        tip_redact = tip(
            "tip-ev-redact",
            "leaving out names",
            "No HTML report, object names or domain names. Findings are listed by ID and rule. Pathwarden checks every file for names before saving the pack."
        ),
        tip_fp = tip(
            "tip-ev-fp",
            "sending the fingerprint",
            "The auditor checks the pack against a fingerprint they got from you some other way: your website, the contract, or a call. A fingerprint inside the pack proves nothing."
        ),
        tip_held = tip(
            "tip-ff-held",
            "findings left out",
            "Their domain or data source wasn't collected in this run, so Pathwarden can't tell if they are still there."
        ),
    )
}

// ------------------------------------------------------------ Settings

/// Settings' two sections: the signing key, and checking a pack.
pub fn settings_sections(ws: &Workspace) -> String {
    let i_file = icon("i-file");
    let key = match key_info(ws) {
        Ok(Some(k)) => format!(
            r##"<header class="with-action"><div><h2 class="sub">Evidence signing key</h2><p class="muted">Signs the evidence packs made on this computer. {tip}</p></div><a class="btn" href="/evidence/public-key" download>{i_dl} Public key</a></header>
<dl class="key-facts">
  <div><dt>Fingerprint</dt><dd><code id="key-fp">{fp}</code><button type="button" class="copy-btn" data-copy="key-fp" title="Copy" aria-label="Copy the fingerprint">{i_file}</button></dd></div>
  {created}
  <div><dt>Kept in</dt><dd><code>{dir}</code></dd></div>
</dl>
<p class="hint key-hint">Publish the fingerprint where auditors find it without the packs: your website, the contract, or a signed email.</p>
<div class="card-actions"><button type="button" class="btn" data-key-use>Use another key file</button><button type="button" class="btn danger" data-key-replace>Replace key</button><span class="save-status muted small" id="key-status" aria-live="polite"></span></div>"##,
            tip = tip_key(),
            i_dl = icon("i-download"),
            fp = esc(&k.fingerprint),
            created = k
                .created
                .map(|t| format!(
                    "<div><dt>Created</dt><dd>{}.</dd></div>",
                    time_as(t, "full")
                ))
                .unwrap_or_default(),
            dir = esc(&k.dir.display().to_string()),
        ),
        Ok(None) => format!(
            r##"<header><h2 class="sub">Evidence signing key</h2><p class="muted">Signs the evidence packs made on this computer. {tip}</p></header>
<p class="muted">No signing key yet.</p>
<div class="card-actions"><button type="button" class="btn primary" data-key-create>{i_plus} Create a key</button><button type="button" class="btn" data-key-use>Use a key file</button><span class="save-status muted small" id="key-status" aria-live="polite"></span></div>"##,
            tip = tip_key(),
            i_plus = icon("i-plus"),
        ),
        Err(e) => format!(
            r##"<header><h2 class="sub">Evidence signing key</h2></header>
<p class="rt-limit">{i_alert}<span>The signing key can't be read: {e}</span></p>
<div class="card-actions"><button type="button" class="btn" data-key-use>Use another key file</button><button type="button" class="btn danger" data-key-replace>Replace key</button><span class="save-status muted small" id="key-status" aria-live="polite"></span></div>"##,
            i_alert = icon("i-alert"),
            e = esc(&e),
        ),
    };
    format!(
        r##"<section class="card setting" id="evidence">
{key}{exposed}
<input type="file" id="key-file" accept=".key,text/plain" hidden>
</section>
<dialog id="key-replace" class="card">
  <form method="dialog">
    <h2 class="sub">Replace the signing key?</h2>
    <p>New packs are signed with a new key, so auditors need its fingerprint. The old key is deleted; packs made before still check against its fingerprint.</p>
    <div class="dialog-actions"><button class="btn" value="cancel">Cancel</button><button class="btn danger" value="replace">Replace key</button></div>
  </form>
</dialog>
<section class="card setting" id="verify">
<header><h2 class="sub">Check an evidence pack</h2><p class="muted">Checks the signature, the signer and every file of a pack you received.</p></header>
<form id="verify-form" autocomplete="off" novalidate>
<div class="verify-grid">
  <div class="field"><label id="vf-pack-label">Pack</label><div class="ev-file" aria-labelledby="vf-pack-label">{i_file}<span class="name" id="vf-name">No pack chosen.</span><button type="button" class="btn small-btn" id="vf-choose">Choose</button></div><input type="file" id="vf-pack" accept=".zip,application/zip" hidden></div>
  <div class="field"><label for="vf-fp">Expected signer {tip_vf}</label><input class="input mono" id="vf-fp" spellcheck="false" placeholder="SHA256:…"><p class="hint">A fingerprint, or <a href="#" id="vf-keylink">a public key file</a>.</p><input type="file" id="vf-key" accept=".pub,text/plain" hidden></div>
</div>
<div class="card-actions"><button type="submit" class="btn primary" id="vf-submit" disabled>{i_check} Check pack</button><span class="save-status muted small" id="vf-status" aria-live="polite"></span></div>
</form>
<div id="vf-result"></div>
</section>
<script src="/static/evidence.js" defer></script>
"##,
        i_check = icon("i-check"),
        exposed = key_exposure(ws)
            .map(|why| format!(
                r#"<p class="rt-limit key-exposed" role="alert">{}<span>{}</span></p>"#,
                icon("i-alert"),
                esc(&why)
            ))
            .unwrap_or_default(),
        tip_vf = tip(
            "tip-vf",
            "the expected signer",
            "The fingerprint the sender published, or their public key file. Without one, Pathwarden can only say the pack is unchanged, not who made it."
        ),
    )
}

fn tip_key() -> String {
    tip(
        "tip-key",
        "the signing key",
        "Anyone with the key can sign packs as you. It is kept in a folder only your account can read. Back it up somewhere just as private.",
    )
}

/// A pack check, as Settings shows it.
pub fn verification_json(v: &pack::Verification) -> Value {
    let shows = v
        .manifest
        .as_ref()
        .filter(|_| v.signed_by.is_some())
        .map(|m| {
            let s = &m.summary;
            let n = |k: &str| s["counts"][k].as_u64().unwrap_or(0);
            json!({
                "counts": format!(
                    "{} fixed · {} still open · {} can't tell · {} new",
                    n("fixed"), n("still_open"), n("cant_tell"), n("new")
                ),
                "baseline_kind": s["baseline"]["kind"],
                "baseline_run_id": s["baseline"]["run_id"],
                "created_at": m.created_at,
                "pathwarden": m.pathwarden,
                "redacted": m.redacted,
            })
        });
    json!({
        "outcome": v.outcome,
        "problems": v.problems,
        "signed_by": v.signed_by,
        "files_ok": v.files_ok,
        "files_checked": v.files_checked,
        "shows": shows,
    })
}

// ------------------------------------------------------------ API

fn run_of(st: &Shared, id: &str) -> Result<RunSummary, Box<Response>> {
    if !workspace::valid_run_id(id) {
        return Err(Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "That run no longer exists.",
        )));
    }
    st.workspace.run(id).ok_or_else(|| {
        Box::new(json_error(
            StatusCode::NOT_FOUND,
            "That run no longer exists.",
        ))
    })
}

/// The pack dialog's choices: the runs to compare with, the key.
async fn pack_form(State(st): State<Shared>, UrlPath(id): UrlPath<String>) -> Response {
    let r = match run_of(&st, &id) {
        Ok(r) => r,
        Err(e) => return *e,
    };
    let st2 = st.clone();
    let done = tokio::task::spawn_blocking(move || {
        let ws = &st2.workspace;
        let earlier = earlier_runs(ws, &r);
        let key = key_info(ws);
        (earlier, key, r)
    })
    .await;
    let Ok((earlier, key, r)) = done else {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't load the pack's choices. Try again.",
        );
    };
    Json(json!({
        "earlier": earlier.iter().enumerate().map(|(i, x)| json!({
            "id": x.id,
            "created_at": x.created_at,
            "label": x.label,
            "open": x.open_findings(),
            "previous": i == 0,
        })).collect::<Vec<_>>(),
        "key": match &key {
            Ok(Some(k)) => k.json(),
            _ => Value::Null,
        },
        "key_error": key.err(),
        "file": pack_file_name(&r, false),
        "file_redacted": pack_file_name(&r, true),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct AgainstQuery {
    against: Option<String>,
}

/// The open findings of the run to compare with, for "Some findings".
async fn baseline_findings(
    State(st): State<Shared>,
    UrlPath(id): UrlPath<String>,
    Query(q): Query<AgainstQuery>,
) -> Response {
    let r = match run_of(&st, &id) {
        Ok(r) => r,
        Err(e) => return *e,
    };
    let st2 = st.clone();
    let done = tokio::task::spawn_blocking(move || {
        baseline_open(&st2.workspace, &r, q.against.as_deref())
    })
    .await;
    match done {
        Ok(Ok((_, open))) => Json(json!({
            "findings": open.iter().map(|f| json!({
                "fp": f.fingerprint,
                "rule": f.rule,
                "title": f.title.clone().unwrap_or_else(|| f.rule.clone()),
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Ok(Err(e)) => json_error(StatusCode::CONFLICT, e),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't list the findings to compare with. Try again.",
        ),
    }
}

/// A pack made and not yet downloaded.
struct Made {
    token: String,
    name: String,
    bytes: Vec<u8>,
    /// When it was made (Unix time).
    at: i64,
}

static MADE: Mutex<Vec<Made>> = Mutex::new(Vec::new());
/// How long a made pack waits for its download.
const MADE_TTL: i64 = 600;

fn token() -> Option<String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).ok()?;
    Some(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Makes the pack: signed with this computer's key, checked, and kept for
/// its download.
async fn make_pack(
    State(st): State<Shared>,
    UrlPath(id): UrlPath<String>,
    Json(opts): Json<PackOptions>,
) -> Response {
    let r = match run_of(&st, &id) {
        Ok(r) => r,
        Err(e) => return *e,
    };
    let st2 = st.clone();
    let done = tokio::task::spawn_blocking(move || -> Result<Value, (StatusCode, String)> {
        let ws = &st2.workspace;
        let key = signing_key(ws)
            .map_err(|e| {
                (
                    StatusCode::CONFLICT,
                    format!("The signing key can't be read: {e}"),
                )
            })?
            .ok_or((
                StatusCode::CONFLICT,
                "No signing key yet. Create one first.".to_string(),
            ))?;
        let fingerprint = key.public().fingerprint();
        let state_dir = st2.state_dir_for(&ws.for_run(&r));
        let built = build_pack(
            ws,
            state_dir.as_deref(),
            &r,
            &opts,
            &fingerprint,
            pathwarden_core::analyze::now(),
        )
        .map_err(|e| (StatusCode::CONFLICT, e))?;
        let (bytes, _) = pack::zip_bytes(&built.contents.files, built.contents.header, &key)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
        // Checked as an auditor would, with this key.
        let check = pack::verify_zip(
            &bytes,
            &pack::Expected {
                key: Some(key.public()),
                fingerprint: None,
            },
        );
        let sha = pack::sha256_hex(&bytes);
        let t = token().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't make a key: Windows gave no secure random numbers. Try again.".to_string(),
        ))?;
        let now = pathwarden_core::analyze::now();
        {
            let mut m = MADE.lock().unwrap_or_else(|e| e.into_inner());
            m.retain(|x| now - x.at < MADE_TTL);
            if m.len() >= 4 {
                m.remove(0);
            }
            m.push(Made {
                token: t.clone(),
                name: built.file_name.clone(),
                bytes,
                at: now,
            });
        }
        Ok(json!({
            "file": built.file_name,
            "download": format!("/api/evidence/download/{t}"),
            "shows": counts_line(&built.report.counts),
            "against": built.baseline.created_at,
            "verified": check.outcome == pack::Outcome::Verified,
            "files_ok": check.files_ok,
            "files_checked": check.files_checked,
            "problems": check.problems,
            "signed_by": fingerprint,
            "sha256": sha,
            "redacted": opts.redact,
        }))
    })
    .await;
    match done {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err((s, e))) => json_error(s, e),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Making the pack stopped. Try again.",
        ),
    }
}

/// A made pack, once.
async fn download_pack(UrlPath(t): UrlPath<String>) -> Response {
    let found = {
        let mut m = MADE.lock().unwrap_or_else(|e| e.into_inner());
        m.iter().position(|x| x.token == t).map(|i| m.remove(i))
    };
    match found {
        Some(m) => attachment(&m.name, "application/zip", m.bytes),
        None => (
            StatusCode::NOT_FOUND,
            "This pack was already downloaded. Make it again.",
        )
            .into_response(),
    }
}

/// The findings file dialog's facts: open findings, and those the run
/// couldn't check.
async fn findings_file_info(State(st): State<Shared>, UrlPath(id): UrlPath<String>) -> Response {
    let r = match run_of(&st, &id) {
        Ok(r) => r,
        Err(e) => return *e,
    };
    let st2 = st.clone();
    let done = tokio::task::spawn_blocking(move || {
        let ws = &st2.workspace;
        let state_dir = st2.state_dir_for(&ws.for_run(&r));
        findings_doc(ws, state_dir.as_deref(), &r).map(|d| (d, r))
    })
    .await;
    match done {
        Ok(Ok((doc, r))) => Json(json!({
            "open": doc.findings.iter().filter(|f| f.suppressed.is_none()).count(),
            "held": doc.held.len(),
            "sarif": findings_file_name(&r, pathwarden_export::Format::Sarif),
            "defectdojo": findings_file_name(&r, pathwarden_export::Format::Defectdojo),
        }))
        .into_response(),
        Ok(Err(e)) => json_error(StatusCode::CONFLICT, e),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't read the findings file's details. Try again.",
        ),
    }
}

#[derive(Deserialize)]
struct FormatQuery {
    format: Option<String>,
}

async fn findings_file_download(
    State(st): State<Shared>,
    UrlPath(id): UrlPath<String>,
    Query(q): Query<FormatQuery>,
) -> Response {
    let format = match q.format.as_deref() {
        Some("defectdojo") => pathwarden_export::Format::Defectdojo,
        Some("sarif") | None => pathwarden_export::Format::Sarif,
        Some(_) => return (StatusCode::BAD_REQUEST, "Choose SARIF or DefectDojo.").into_response(),
    };
    let r = match run_of(&st, &id) {
        Ok(r) => r,
        Err(e) => return *e,
    };
    let st2 = st.clone();
    let done = tokio::task::spawn_blocking(move || {
        let ws = &st2.workspace;
        let state_dir = st2.state_dir_for(&ws.for_run(&r));
        let doc = findings_doc(ws, state_dir.as_deref(), &r)?;
        let text = pathwarden_export::text(&doc, format).map_err(|e| format!("{e:#}"))?;
        Ok::<_, String>((findings_file_name(&r, format), text))
    })
    .await;
    match done {
        Ok(Ok((name, text))) => attachment(&name, "application/json", text.into_bytes()),
        Ok(Err(e)) => (StatusCode::CONFLICT, e).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't make the findings file. Try again.",
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct KeyRequest {
    /// `create`, `replace` or `use`.
    action: String,
    /// With `use`: the key file's text.
    #[serde(default)]
    text: Option<String>,
}

async fn key_action(State(st): State<Shared>, Json(req): Json<KeyRequest>) -> Response {
    let st2 = st.clone();
    let done = tokio::task::spawn_blocking(move || {
        let ws = &st2.workspace;
        let text = zeroize::Zeroizing::new(req.text.unwrap_or_default());
        match req.action.as_str() {
            "create" => create_key(ws, false),
            "replace" => create_key(ws, true),
            "use" => use_key(ws, &text),
            _ => Err("Pathwarden couldn't do that. Reload the page and try again.".to_string()),
        }
    })
    .await;
    match done {
        Ok(Ok(k)) => Json(k.json()).into_response(),
        Ok(Err(e)) => json_error(StatusCode::CONFLICT, e),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't change the signing key. Try again.",
        ),
    }
}

async fn public_key_download(State(st): State<Shared>) -> Response {
    match key_info(&st.workspace) {
        Ok(Some(k)) => attachment(
            evidence::PUB_FILE,
            "text/plain; charset=utf-8",
            k.public_text.into_bytes(),
        ),
        _ => (StatusCode::NOT_FOUND, "No signing key yet.").into_response(),
    }
}

/// Checks an uploaded pack: the zip, and a fingerprint or public key file.
async fn verify_upload(mut form: Multipart) -> Response {
    let mut zip: Option<Vec<u8>> = None;
    let mut fingerprint = String::new();
    let mut key_text = String::new();
    loop {
        let field = match form.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => {
                return json_error(StatusCode::BAD_REQUEST, "The upload was cut off. Try again.")
            }
        };
        let name = field.name().unwrap_or_default().to_string();
        let Ok(bytes) = field.bytes().await else {
            return json_error(StatusCode::BAD_REQUEST, "The upload was cut off. Try again.");
        };
        match name.as_str() {
            "pack" => zip = Some(bytes.to_vec()),
            "fingerprint" => fingerprint = String::from_utf8_lossy(&bytes).trim().to_string(),
            "key" => key_text = String::from_utf8_lossy(&bytes).into_owned(),
            _ => {}
        }
    }
    let Some(zip) = zip.filter(|z| !z.is_empty()) else {
        return json_error(StatusCode::BAD_REQUEST, "Choose a pack (.zip) first.");
    };
    if !key_text.trim().is_empty() && !fingerprint.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Give a fingerprint or a public key file, not both.",
        );
    }
    let key = if key_text.trim().is_empty() {
        None
    } else {
        match PublicKey::parse(&key_text) {
            Ok(k) => Some(k),
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("That isn't a public key file: {e:#}."),
                )
            }
        }
    };
    let expected = pack::Expected {
        fingerprint: (key.is_none() && !fingerprint.is_empty()).then_some(fingerprint),
        key,
    };
    match tokio::task::spawn_blocking(move || pack::verify_zip(&zip, &expected)).await {
        Ok(v) => Json(verification_json(&v)).into_response(),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't check the pack. Try again.",
        ),
    }
}
