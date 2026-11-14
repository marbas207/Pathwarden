//! Retesting from the run page: a Retest button on each open finding's row
//! in the embedded report, the dialog it opens, and the retest API.
//!
//! **The channel from the report.** The report runs in a sandboxed frame with
//! an opaque origin and shows names straight from the directory, so the app
//! trusts nothing it says. When the app embeds a report
//! ([`embed_report`]) it adds a `<meta>` ([`report_meta`]) with the app's
//! origin and, per open finding, whether a targeted retest is possible and
//! the latest result, and the script that adds the buttons
//! (`assets/report-retest.js`), allowed by its hash. Stored and downloaded
//! reports never contain any of it. A click sends the app one message, `{type:
//! "pathwarden:retest", fingerprint}`, to the app's origin only. The run page
//! accepts it only from that frame's window, only with a well-formed
//! fingerprint of one of this run's open findings, and only opens the
//! [`dialog`]: nothing runs until the user confirms there. Results go back to
//! the frame as plain values that the report inserts as text.
//!
//! **How a finding is retested.**
//!
//! - *Targeted* (built-in collector only): the run keeps a slice of its graph
//!   (`retest.json.gz`, see [`pathwarden_core::retest::targeted`]). The
//!   finding's objects are re-read from the directory over LDAP, with the
//!   Collect wizard's sign-in rules (the current Windows account by default;
//!   a password only in the request body, as a `Secret`, never stored or
//!   logged), merged into the slice, and the finding's rule runs again.
//! - *A new collection*: upload or collect again; each finding is then
//!   compared with the newest later run of the same environment.
//!
//! Targeted results are kept in the run's `retests.json`.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path as UrlPath, State};
use axum::http::header;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use flate2::write::GzEncoder;
use flate2::Compression;
use pathwarden_collect::{Problem, RefreshTarget, Refresher, Secret};
use pathwarden_core::analyze::{self, Analysis};
use pathwarden_core::retest::targeted::{self, Slice};
use pathwarden_core::retest::{self as core_retest, Verdict};
use serde::{Deserialize, Serialize};

use crate::collect::{self, AuthChoice, CollectForm, Collector, Depth};
use crate::pages::{esc, icon, num};
use crate::run_data::{self, FindingRef};
use crate::secret_json::SecretJson;
use crate::security;
use crate::server::{AppState, Shared};
use crate::workspace::{self, RunSummary, Workspace};

/// The slice of the run's graph that targeted retests use.
pub const SLICE_FILE: &str = "retest.json.gz";
/// Targeted retest results for the run.
pub const RETESTS_FILE: &str = "retests.json";

const RETEST_JS: &str = include_str!("assets/retest.js");
const RETEST_CSS: &str = include_str!("assets/retest.css");
/// The Retest buttons for an embedded report: added by the app when it
/// serves `?embed=1`, never part of a stored or downloaded report.
const REPORT_RETEST_JS: &str = include_str!("assets/report-retest.js");
const REPORT_RETEST_CSS: &str = include_str!("assets/report-retest.css");
/// The run page's side of the report's other actions (Accept risk, Open
/// in Explore) and of its height and scroll requests.
const RUN_JS: &str = include_str!("assets/run.js");

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/runs/{id}/retest", post(retest))
        .route(
            "/static/retest.js",
            get(|| async { asset("text/javascript", RETEST_JS) }),
        )
        .route(
            "/static/run.js",
            get(|| async { asset("text/javascript", RUN_JS) }),
        )
        .route(
            "/static/retest.css",
            get(|| async { asset("text/css", RETEST_CSS) }),
        )
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

// ------------------------------------------------------------ run files

/// The slice to save with a finished run (gzipped JSON); `None` if it can't
/// be built.
pub fn slice_bytes(a: &Analysis) -> Option<Vec<u8>> {
    let slice = Slice::build(&a.graph, &a.stats.trusts, &a.findings);
    let mut enc = GzEncoder::new(Vec::new(), Compression::new(6));
    serde_json::to_writer(&mut enc, &slice).ok()?;
    enc.finish().ok()
}

/// The slices of the newest run and of the one asked about last, let go
/// after a while without a request like the run's graph
/// ([`crate::run_data::release_when_idle`]).
static SLICES: crate::run_data::RunCache<Slice> = crate::run_data::RunCache::new(1, |s| {
    // Its objects as the graph weighs them, and its edges.
    s.nodes.len() * crate::run_data::GRAPH_OBJECT_BYTES
        + s.edges.len() * std::mem::size_of::<targeted::SliceEdge>()
});

/// Lets go of the slices without a request since `idle` before `now`.
pub(crate) fn sweep(idle: std::time::Duration, now: std::time::Instant) {
    SLICES.sweep(idle, now);
}

/// The slices kept, and their estimated bytes.
pub(crate) fn weighs() -> (usize, usize) {
    SLICES.weighs()
}

/// The run's slice (blocking), cached for the newest run and the last run
/// asked about.
pub fn slice(run_dir: &Path) -> Option<Arc<Slice>> {
    SLICES
        .get_or_load(run_dir, || {
            let bytes = crate::run_data::read_gz(&run_dir.join(SLICE_FILE)).map_err(|_| ())?;
            let s: Slice = serde_json::from_slice(&bytes).map_err(|_| ())?;
            // A newer Pathwarden's slice may not mean what this one reads:
            // none.
            if !pathwarden_core::formats::of_u32(
                s.version,
                pathwarden_core::retest::targeted::SLICE_VERSION,
            )
            .is_known()
            {
                return Err(());
            }
            Ok(s)
        })
        .ok()
}

/// One retest result, as kept in `retests.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetestRecord {
    pub fingerprint: String,
    /// Unix time of the retest.
    pub at: i64,
    /// `targeted` (objects re-read).
    pub method: String,
    pub verdict: Verdict,
    #[serde(default)]
    pub details: Vec<String>,
    /// Objects re-read.
    #[serde(default)]
    pub refreshed: usize,
    #[serde(default)]
    pub server: Option<String>,
    /// Computers on its path whose sessions or local groups were read.
    #[serde(default)]
    pub hosts: usize,
    /// Computers on its path whose sessions or local groups it rests on.
    #[serde(default)]
    pub hosts_total: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RetestLog {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub results: Vec<RetestRecord>,
}

/// Results kept per finding.
const KEEP_PER_FINDING: usize = 20;

/// The newest `retests.json` version this one reads (docs/dev/formats.md).
pub const RETESTS_VERSION: u32 = 1;

/// What recording a retest into a newer Pathwarden's log says.
pub const NEWER_RETESTS_WORDS: &str =
    "A newer Pathwarden saved this run's retests. Update Pathwarden to record one here.";

/// The run's `retests.json` as JSON, and whether a newer Pathwarden wrote
/// it (its `version` above [`RETESTS_VERSION`], or not a whole number).
fn log_value(run_dir: &Path) -> Option<(serde_json::Value, bool)> {
    let text = std::fs::read_to_string(run_dir.join(RETESTS_FILE)).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let newer = match v.get("version") {
        None | Some(serde_json::Value::Null) => false,
        Some(n) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .is_none_or(|n| !pathwarden_core::formats::of_u32(n, RETESTS_VERSION).is_known()),
    };
    Some((v, newer))
}

/// The run's retest results; none from a newer Pathwarden's log, which is
/// not read as this one's.
pub fn load_log(run_dir: &Path) -> RetestLog {
    log_value(run_dir)
        .filter(|(_, newer)| !newer)
        .and_then(|(v, _)| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

/// Adds a result to the run's `retests.json` (written atomically). A
/// newer Pathwarden's log is never written over: refused.
pub fn record(run_dir: &Path, rec: RetestRecord) -> std::io::Result<()> {
    static WRITE: Mutex<()> = Mutex::new(());
    let _w = WRITE.lock().unwrap_or_else(|e| e.into_inner());
    if log_value(run_dir).is_some_and(|(_, newer)| newer) {
        return Err(std::io::Error::other(NEWER_RETESTS_WORDS));
    }
    let mut log = load_log(run_dir);
    log.version = RETESTS_VERSION;
    log.results.push(rec);
    let mut seen = std::collections::HashMap::<String, usize>::new();
    let mut kept: Vec<RetestRecord> = log
        .results
        .into_iter()
        .rev()
        .filter(|r| {
            let n = seen.entry(r.fingerprint.clone()).or_default();
            *n += 1;
            *n <= KEEP_PER_FINDING
        })
        .collect();
    kept.reverse();
    log.results = kept;
    let tmp = run_dir.join(format!(".{RETESTS_FILE}.tmp"));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(serde_json::to_string_pretty(&log)?.as_bytes())?;
    drop(f);
    std::fs::rename(&tmp, run_dir.join(RETESTS_FILE))
}

// ------------------------------------------------------------ environments

/// The environment a run belongs to: its sorted domains. Runs of different
/// environments are never compared or charted together.
pub fn env_key(r: &RunSummary) -> String {
    let mut d: Vec<String> = r.domains.iter().map(|d| d.to_ascii_uppercase()).collect();
    d.sort();
    d.dedup();
    if d.is_empty() {
        "-".into()
    } else {
        d.join(",")
    }
}

/// Open (unsuppressed) fingerprints of a run (blocking).
pub fn open_fingerprints(run_dir: &Path) -> Option<HashSet<String>> {
    let f = run_data::findings(run_dir)?;
    Some(
        f.iter()
            .filter(|f| f.suppressed.is_none())
            .map(|f| f.fingerprint.clone())
            .collect(),
    )
}

// ------------------------------------------------- the report's buttons

/// What is known about a finding since this run.
enum Evidence<'a> {
    Targeted(&'a RetestRecord),
    LaterRun { run: &'a RunSummary, present: bool },
}

impl Evidence<'_> {
    fn at(&self) -> i64 {
        match self {
            Evidence::Targeted(r) => r.at,
            Evidence::LaterRun { run, .. } => run.created_at,
        }
    }
}

/// The latest result for a finding, as the report's row shows it.
#[derive(Debug, Serialize)]
struct Latest {
    /// `fixed`, `still_open` or `cant_tell`.
    v: Verdict,
    /// Unix time of the retest or of the later run.
    at: i64,
    /// `targeted` or `run` (compared with a later run).
    src: &'static str,
    /// A short line for the tooltip.
    #[serde(skip_serializing_if = "String::is_empty")]
    d: String,
    /// "Can't tell" from the later run only because it didn't read sessions
    /// or local groups ([`core_retest::held`]).
    #[serde(skip)]
    held: bool,
}

/// What the app knows about one open finding.
struct FindingState {
    finding: FindingRef,
    targetable: bool,
    objects: usize,
    /// Computers on its path whose sessions or local groups a targeted
    /// retest reads.
    hosts: usize,
    /// Why a targeted retest isn't possible.
    reason: String,
    latest: Option<Latest>,
    /// Held by a later run that didn't read what it rests on, and a
    /// targeted retest can read it on the computers on its path: it shows
    /// [`core_retest::HELD_LINE`].
    held: bool,
}

/// Longest tooltip line passed to the report.
const DETAIL_MAX: usize = 200;

/// A targeted result's one-line summary: the objects re-read, the computers
/// read, and the first specific ("1 of 2 affected objects remain").
pub fn short_detail(refreshed: usize, hosts: usize, details: &[String]) -> String {
    let mut s = if refreshed == 1 {
        "Re-read 1 object".to_string()
    } else {
        format!("Re-read {} objects", num(refreshed))
    };
    if hosts > 0 {
        s.push_str(" and ");
        s.push_str(&pathwarden_core::text::count(
            hosts,
            "computer",
            "computers",
        ));
    }
    if let Some(d) = details.first() {
        s.push_str(" · ");
        s.push_str(d);
    }
    if s.chars().count() > DETAIL_MAX {
        s = s.chars().take(DETAIL_MAX - 1).collect::<String>() + "…";
    }
    s
}

/// The run's open findings with what can be done and what is known about
/// each (blocking file reads; small).
fn states(st: &AppState, r: &RunSummary) -> Vec<FindingState> {
    let Some(dir) = st.workspace.run_dir(&r.id) else {
        return Vec::new();
    };
    let Some(findings) = run_data::findings(&dir) else {
        return Vec::new();
    };
    let slice = slice(&dir);
    let log = load_log(&dir);
    // Later runs of the run's own environment.
    let runs = st.workspace.for_run(r).runs();
    let key = env_key(r);
    // The newest later run of the same environment.
    let later = runs
        .iter()
        .filter(|x| env_key(x) == key && x.newer_than(r))
        .max_by(|a, b| a.order_key().cmp(&b.order_key()));
    let later_open = later
        .and_then(|l| st.workspace.run_dir(&l.id))
        .and_then(|d| open_fingerprints(&d));
    // What the later run could check, as `pathwarden retest` judges it: a
    // finding it lacks is fixed only when its domain was collected, the
    // collection looks complete, and it read what the finding may rest on.
    let by_scope = |x: &RunSummary| {
        run_data::completeness(&st.workspace, x)
            .map(|c| c.untargeted_by_scope(&x.domains))
            .unwrap_or_default()
    };
    // And its data sources, as saved with each run: a source this run had
    // and the later one lacks holds what may rest on it. A later run saved
    // before its sources were holds every finding that rests on one.
    let coverage = later.map(|l| {
        let sources = st
            .workspace
            .run_dir(&l.id)
            .and_then(|d| run_data::run_sources(&d))
            .unwrap_or_default();
        let base_sources = run_data::run_sources(&dir);
        let had = base_sources
            .as_ref()
            .map(|s| s.all_keys())
            .unwrap_or_default();
        core_retest::Coverage {
            domains: l.domains.clone(),
            complete: !(r.objects > 0 && l.objects * 2 < r.objects) && l.skipped_objects == 0,
            sources,
            // A run saved before runs recorded their computers.
            legacy_hosts: base_sources.is_none_or(|s| s.host_reads.is_empty()),
            ..core_retest::Coverage::default()
        }
        .compared_with(&had)
        .with_untargeted_scopes(by_scope(l))
    });
    let mine: std::collections::HashMap<String, pathwarden_core::posture::Untargeted> =
        by_scope(r).into_iter().collect();
    // A finding the run history tracks: what it rests on and what its
    // sightings did not read, over every sighting, as the history judges
    // it. Read only when the later run lacks a finding.
    let tracked = std::cell::OnceCell::new();
    let tracked = || {
        tracked.get_or_init(|| {
            let ws = st.workspace.for_run(r);
            crate::history_ui::locate(&ws, st.state_dir_for(&ws).as_deref())
                .ok()
                .and_then(|loc| pathwarden_core::history::findings_state_in(&loc.dir).ok())
                .flatten()
        })
    };
    let view = |f: &FindingRef| {
        use pathwarden_core::posture::Untargeted;
        let scope = f.domain.as_deref().map(pathwarden_core::state::scope_key);
        let here = scope
            .as_ref()
            .and_then(|s| mine.get(s))
            .copied()
            .unwrap_or_default();
        let t = tracked()
            .as_ref()
            .and_then(|s| s.findings.get(&f.fingerprint))
            .filter(|t| t.status != pathwarden_core::state::Status::Resolved);
        let not_targeted = match t {
            Some(t) => Untargeted::from_parts(&t.not_targeted).and(here),
            None => here,
        };
        let rests_on = match (f.rests_on, t.and_then(|t| t.rests_on.as_deref())) {
            (Some(u), Some(p)) => Some(u.or(Untargeted::from_parts(p))),
            (Some(u), None) => Some(u),
            (None, Some(p)) => Some(Untargeted::from_parts(p)),
            (None, None) => None,
        };
        core_retest::FindingView {
            fingerprint: f.fingerprint.clone(),
            rule: f.rule.clone(),
            domain: f.domain.clone(),
            not_targeted: not_targeted.parts(),
            scope,
            category: f.category,
            rests_on: rests_on.map(|u| u.parts()),
            sources: f
                .sources
                .iter()
                .map(|s| pathwarden_core::opengraph::source_key(s))
                .collect(),
            requires: f.requires.clone(),
            ..core_retest::FindingView::default()
        }
    };

    findings
        .iter()
        .filter(|f| f.suppressed.is_none())
        .map(|f| {
            let targeted = log
                .results
                .iter()
                .filter(|x| x.fingerprint == f.fingerprint)
                .max_by_key(|x| x.at)
                .map(Evidence::Targeted);
            let from_run = match (later, &later_open) {
                (Some(run), Some(set)) => Some(Evidence::LaterRun {
                    run,
                    present: set.contains(&f.fingerprint),
                }),
                _ => None,
            };
            let evidence = match (targeted, from_run) {
                (Some(a), Some(b)) => Some(if a.at() >= b.at() { a } else { b }),
                (a, b) => a.or(b),
            };
            let latest = evidence.map(|e| match e {
                Evidence::Targeted(x) => Latest {
                    v: x.verdict,
                    at: x.at,
                    src: "targeted",
                    d: short_detail(x.refreshed, x.hosts, &x.details),
                    held: false,
                },
                Evidence::LaterRun { run, present } => {
                    let (v, why, held) = match &coverage {
                        _ if present => (Verdict::StillOpen, Vec::new(), false),
                        Some(c) => {
                            let b = view(f);
                            let (v, why) = core_retest::absent(&b, c);
                            (v, why, core_retest::held(&b, c))
                        }
                        None => (Verdict::Fixed, Vec::new(), false),
                    };
                    Latest {
                        v,
                        at: run.created_at,
                        src: "run",
                        d: why.into_iter().next().unwrap_or_default(),
                        held,
                    }
                }
            });
            let sf = slice.as_ref().and_then(|s| s.finding(&f.fingerprint));
            let (targetable, reason, objects, hosts) = match (sf, &slice) {
                (Some(sf), Some(s)) if sf.targetable() => {
                    (true, String::new(), sf.refresh.len(), s.hosts_of(sf).len())
                }
                (Some(sf), _) => (false, sf.unsupported.clone().unwrap_or_default(), 0, 0),
                _ => (
                    false,
                    "This run was analyzed before targeted retests existed. Retest it with a new collection.".to_string(),
                    0,
                    0,
                ),
            };
            let targetable = targetable && collect::BUILTIN;
            FindingState {
                finding: f.clone(),
                targetable,
                objects,
                hosts,
                reason,
                held: targetable
                    && hosts > 0
                    && latest.as_ref().is_some_and(|l| l.held),
                latest,
            }
        })
        .collect()
}

/// A report as the app embeds it: the retest `meta` and styles in the head,
/// the buttons' script at the end of the body. Returns the page and its
/// Content Security Policy.
///
/// The policy is [`security::REPORT_CSP`] with `'unsafe-inline'` for scripts
/// replaced by the hashes of exactly two scripts: the report's own and the
/// buttons' script. Nothing else in the page can run.
///
/// The report's script is only trusted if it is one Pathwarden wrote: the
/// current [`REPORT_JS`](pathwarden_core::report::REPORT_JS) or a known
/// earlier version ([`EARLIER_REPORT_SCRIPTS`]). Anything else (a damaged or
/// edited file) is shown as a plain report, without buttons.
///
/// Links that leave the report open in a new tab (`target="_blank"`), so
/// the frame itself never navigates away: the app sends retest results to
/// whatever page the frame holds.
pub fn embed_report(html: &str, meta: &str, embed_style: &str, trusted: bool) -> (String, String) {
    let html = links_in_new_tab(html);
    let Some(own_hash) = own_script_hash(&html).filter(|h| known_report_script(h)) else {
        let out = html.replacen("</head>", embed_style, 1);
        return (out, report_csp_for(&html, trusted));
    };
    let hashes = [own_hash, csp_hash(REPORT_RETEST_JS)];
    let head = format!("<style>{REPORT_RETEST_CSS}</style>{embed_style}");
    let mut out = html.replacen("</head>", &head, 1);
    // The data goes right before the script, which reads the element just
    // before itself: a meta of the report's own (or the first `</head>`
    // hidden in a comment) can't stand in for it.
    let script = format!(
        "{meta}<script>{REPORT_RETEST_JS}</script>
"
    );
    match out.rfind("</body>") {
        Some(i) => out.insert_str(i, &script),
        None => out.push_str(&script),
    }
    let csp = security::REPORT_CSP.replacen(
        "script-src 'unsafe-inline'",
        &format!("script-src {}", hashes.join(" ")),
        1,
    );
    if trusted {
        (out, csp)
    } else {
        (out, security::loaded_report_csp(&csp))
    }
}

/// SHA-256 (base64) of the report script of earlier Pathwarden versions, so
/// their stored reports still get Retest buttons. The current script is
/// always known; add its hash here when `report.js` changes.
pub const EARLIER_REPORT_SCRIPTS: &[&str] = &[
    "pSfi2RYenewxL5bHGWIkuL3Qv7xg1PrYLP8gTG6nCKc=",
    "zMGpceCJwbna9nmL8dgJFROMrIAzGKGfidy9uGKFW2I=",
    "vIUSPAzQmhttzNn2qlxqcOPX8GGaMGTrdQFG2T7vxzU=",
    "uclIPESii2DHFbYKje8zMq7Y97b5lbM/1J7l6/lfUNE=",
    "RV9uzrgokAJu6QB3pnuGSeXUZSOu3kNf8xWD0+wobbI=",
    "0wcPAZQ1KS7fLpNCkZSax8z4iQ1nzfzaWPQPVGMI+5o=",
    "jCPAJryZF3RSbe+6brgq4Ki43cpOa9rS54GZpH5Nr38=",
    "DlsL8kWFAXMrT6f9mvK8Z/GV1YjHXFxxh/LqX9BEHFg=",
    "e7FJsFkegpL8Y8H0Z3n6XZwuKaW/G26vpcY3TYA0a+M=",
    "hmb7FCTg5HZJ2Y6vNP5wq+crNjX+VbXRmkZl0pThrk4=",
    "yjiSpeNGd24/S1PfhhFJv/1b//UuAptm8MQEywmumaw=",
    "Wwsb3M8IW2CrkSoZyVKUCXRyUm3JfZZjBtWiRpTaNaU=",
    "NLS+R/4GGsZN4bBiNtpl6Ms3+ujIkLyYfuNm5H3ATZA=",
    "k18F9o+0i2WyQGLpYUtCBNQ5eX6RTHolOZQCopQ0yHA=",
    "pWnTWC8WEvT3qEfKQLspoEawiM4F3e/fu5cyFBmYkBc=",
    "bMJV7bEB4Kg/aAwMntqYHprcJZvsE2dlbY/fPpgKgp4=",
    "yzUCdcfCGEk/ex1Oqjo0Or8zOuFnbRRE0tD5JZY1LBU=",
    "hE/jjg+6roZ0xxJsTXl+ZD97NtsNvyzTutKokFoB63Q=",
    "gozPuTcLSvJpPDa7JbpIpbarNEm64EDR88G+4b3q4WM=",
    "4+bUCZ61wsYlre5xFZ3ErSIWwtk+poByg8mcTRx1zpA=",
    "eozet0KsewtfI4XMXQD6uSLmQ90V8AgDM9XCUNqyUCc=",
    "KUQ9qAmctZuO6WKtzQLSb5E6ck/b3stgi8XU+RvnNng=",
    "lXJbStW1yOKg02kmMsyEXLKKEq48frcwW0swkENLVTw=",
];

/// The hash of today's `report.js`. A test holds it to the script, so a
/// change to the script can't go in without its old hash in
/// [`EARLIER_REPORT_SCRIPTS`] and this one updated.
#[cfg(test)]
const REPORT_SCRIPT: &str = "BaJqGQMyfGUD4uGLGHtGjUjW1YZCJxRmr9Jk2oW+LaY=";

/// The CSP hash of a report's own script: its last `<script>`.
fn own_script_hash(html: &str) -> Option<String> {
    let i = html.rfind("<script>")?;
    let body = &html[i + "<script>".len()..];
    body.find("</script>").map(|j| csp_hash(&body[..j]))
}

/// The policy a report is served with outside the embed (the full page):
/// [`security::REPORT_CSP`] for a run this computer recorded (`trusted`);
/// for a run loaded from the history, only the report's own script when
/// it is one Pathwarden wrote, and no script at all otherwise, and what it
/// opens stays sandboxed ([`security::loaded_report_csp`]). Repository
/// content never runs a script of its own here.
pub fn report_csp_for(html: &str, trusted: bool) -> String {
    if trusted {
        return security::REPORT_CSP.to_string();
    }
    let script = match own_script_hash(html).filter(|h| known_report_script(h)) {
        Some(hash) => format!("script-src {hash}"),
        None => "script-src 'none'".to_string(),
    };
    security::loaded_report_csp(&security::REPORT_CSP.replacen(
        "script-src 'unsafe-inline'",
        &script,
        1,
    ))
}

/// Whether the app's script goes into this report when it is embedded
/// ([`embed_report`]): its own script is one Pathwarden wrote.
pub fn embeds_script(html: &str) -> bool {
    own_script_hash(html).is_some_and(|h| known_report_script(&h))
}

/// Whether a CSP hash source is that of a report script Pathwarden wrote.
fn known_report_script(hash: &str) -> bool {
    hash == csp_hash(pathwarden_core::report::REPORT_JS)
        || EARLIER_REPORT_SCRIPTS
            .iter()
            .any(|h| hash == format!("'sha256-{h}'"))
}

/// Adds `target="_blank" rel="noopener noreferrer"` to every link in the
/// page that leaves it (any `href` not starting with `#`), outside scripts
/// and styles. Data in the report is escaped, so `<a ` only ever starts a
/// real link.
pub fn links_in_new_tab(html: &str) -> String {
    let mut out = String::with_capacity(html.len() + 1024);
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        // Scripts and styles are copied untouched (their hashes must hold).
        let skip = ["<script", "<style"]
            .iter()
            .find(|t| rest.starts_with(**t))
            .map(|t| {
                if *t == "<script" {
                    "</script>"
                } else {
                    "</style>"
                }
            });
        if let Some(end) = skip {
            let n = rest.find(end).map_or(rest.len(), |j| j + end.len());
            out.push_str(&rest[..n]);
            rest = &rest[n..];
            continue;
        }
        if rest.starts_with("<a ") {
            let tag_end = rest.find('>').map_or(rest.len(), |j| j + 1);
            let tag = &rest[..tag_end];
            let href = tag
                .split_once("href=\"")
                .and_then(|(_, v)| v.split('"').next());
            if !tag.contains(" target=") && href.is_some_and(|h| !h.starts_with('#')) {
                out.push_str(r#"<a target="_blank" rel="noopener noreferrer""#);
                out.push_str(&tag[2..]);
            } else {
                out.push_str(tag);
            }
            rest = &rest[tag_end..];
            continue;
        }
        out.push('<');
        rest = &rest[1..];
    }
    out.push_str(rest);
    out
}

/// A CSP source for one inline script: `'sha256-<base64>'`.
///
/// Of the text as the browser sees it: HTML parsing turns CR LF (and a lone
/// CR) into LF, so a script built from a CRLF checkout (Windows) must hash
/// as the LF one, or the page's own scripts are blocked.
pub fn csp_hash(script: &str) -> String {
    use sha2::{Digest, Sha256};
    let text = script.replace("\r\n", "\n").replace('\r', "\n");
    format!("'sha256-{}'", base64(&Sha256::digest(text.as_bytes())))
}

fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for (k, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if k <= c.len() {
                out.push(A[(n >> shift & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The `<meta>` the app adds to an embedded report so it shows a Retest
/// button on each open finding's row (blocking; small). `origin` is the
/// app's own origin: the only one the report sends its requests to.
///
/// It holds no names: per finding, whether a targeted retest is possible and
/// the latest result. The whole value is escaped as an attribute.
pub fn report_meta(st: &AppState, r: &RunSummary, origin: &str) -> String {
    let mut f = serde_json::Map::new();
    let accepted = Accepted::load(st, r);
    let mut acc = Vec::new();
    for s in states(st, r) {
        let mut v = serde_json::json!({ "t": u8::from(s.targetable) });
        if let Some(l) = &s.latest {
            v["r"] = serde_json::to_value(l).unwrap_or_default();
        }
        if s.held {
            v["h"] = core_retest::HELD_LINE.into();
        }
        if accepted.covers(&s.finding) {
            acc.push(s.finding.fingerprint.clone());
        }
        f.insert(s.finding.fingerprint, v);
    }
    // Whether Open in Explore can work for this run.
    let x = st
        .workspace
        .run_dir(&r.id)
        .is_some_and(|d| crate::explore_ui::available(&d));
    // Every finding of the run an accepted risk covers now (accepted then
    // or since), for "Add a note"; by fingerprint only.
    let notable: Vec<String> = st
        .workspace
        .run_dir(&r.id)
        .and_then(|d| run_data::findings(&d))
        .map(|all| {
            all.iter()
                .filter(|f| accepted.covers(f))
                .map(|f| f.fingerprint.clone())
                .collect()
        })
        .unwrap_or_default();
    let data =
        serde_json::json!({ "origin": origin, "f": f, "acc": acc, "a": notable, "x": u8::from(x) });
    format!(
        r#"<meta name="pathwarden-retest" content="{}">"#,
        crate::pages::json_attr(&data.to_string())
    )
}

/// Accepted risks in the workspace config: they apply from the next
/// analysis, so a finding of this run may already be accepted.
struct Accepted {
    config: pathwarden_core::config::Config,
    now: i64,
}

impl Accepted {
    /// The accepted risks of `r`'s environment (never another's), as of now.
    fn load(st: &AppState, r: &RunSummary) -> Self {
        Self {
            config: st.workspace.for_run(r).config().unwrap_or_default(),
            now: pathwarden_core::analyze::now(),
        }
    }

    /// The entry that accepts `f` now, with its place in `pathwarden.toml`:
    /// the one the next analysis applies ([`Config::active_suppression`]:
    /// the first in the file that hasn't expired).
    ///
    /// [`Config::active_suppression`]: pathwarden_core::config::Config::active_suppression
    fn entry(&self, f: &FindingRef) -> Option<(usize, &pathwarden_core::config::Suppression)> {
        self.config
            .active_suppression(&f.fingerprint, &f.rule, self.now)
            .map(|i| (i, &self.config.suppress[i]))
    }

    fn covers(&self, f: &FindingRef) -> bool {
        self.entry(f).is_some()
    }
}

/// An accepted risk as the run page shows it for Add a note (and Settings
/// answers a new one): which entry, what a save checks, and who accepted
/// it, where and when, field by field (the page builds the line).
pub(crate) fn accepted_entry(
    i: usize,
    s: &pathwarden_core::config::Suppression,
) -> serde_json::Value {
    serde_json::json!({
        "i": i,
        "reason": s.reason,
        "target": s.target(),
        "whole_rule": s.fingerprint.is_none(),
        "expires": s.expires,
        "accepted_by": s.accepted_by,
        "accepted_on": s.accepted_on,
        "accepted_at": s.accepted_at,
        "changed_by": s.changed_by,
        "changed_on": s.changed_on,
        "changed_at": s.changed_at,
        "notes": s.notes.len(),
    })
}

/// What the run page adds around the embedded report.
pub struct PageParts {
    /// The Retest and Accept risk dialogs and their scripts.
    pub dialogs: String,
    /// Open findings with a retest result (targeted or from a later run).
    pub retested: usize,
    /// Of those, the ones whose latest result is a targeted retest (the
    /// others come from a later run of the environment).
    pub targeted: usize,
    /// Of those, fixed.
    pub fixed: usize,
    /// The Download menu: the report, an evidence pack, a findings file
    /// ([`crate::evidence_ui::download_menu`]).
    pub download: String,
}

/// The run page's dialogs, hidden until a finding's button in the report
/// asks for one (blocking file reads; small): Retest, and Accept risk. They
/// carry the run's open findings (title, domain, whether a targeted retest
/// is possible, whether it is already accepted), so a message from the
/// report names nothing but a fingerprint.
pub fn page_parts(st: &AppState, r: &RunSummary) -> PageParts {
    let mut data = serde_json::Map::new();
    let accepted = Accepted::load(st, r);
    let states = states(st, r);
    let retested = states.iter().filter(|s| s.latest.is_some()).count();
    let targeted = states
        .iter()
        .filter(|s| s.latest.as_ref().is_some_and(|l| l.src == "targeted"))
        .count();
    let fixed = states
        .iter()
        .filter(|s| s.latest.as_ref().is_some_and(|l| l.v == Verdict::Fixed))
        .count();
    for s in &states {
        data.insert(
            s.finding.fingerprint.clone(),
            serde_json::json!({
                "title": s.finding.title,
                // Not for a run loaded from the history: where this
                // computer signs in is never picked by repository content.
                "domain": if r.shared.is_some() {
                    String::new()
                } else {
                    s.finding.domain.clone().unwrap_or_default().to_ascii_lowercase()
                },
                "t": u8::from(s.targetable),
                "n": s.objects,
                "c": s.hosts,
                "h": if s.held { core_retest::HELD_LINE } else { "" },
                "why": s.reason,
                "acc": u8::from(accepted.covers(&s.finding)),
            }),
        );
    }
    // The accepted risks that cover findings of this run, for "Add a
    // note": which entry, what the page shows of it, and what a save checks.
    let mut notes = serde_json::Map::new();
    if let Some(all) = st
        .workspace
        .run_dir(&r.id)
        .and_then(|d| run_data::findings(&d))
    {
        for f in all.iter() {
            if let Some((i, s)) = accepted.entry(f) {
                let mut entry = accepted_entry(i, s);
                entry["title"] = serde_json::json!(f.title);
                notes.insert(f.fingerprint.clone(), entry);
            }
        }
    }
    let blocked = crate::evidence_ui::pack_blocked(&st.workspace, r);
    PageParts {
        dialogs: dialogs(r, data, notes) + &crate::evidence_ui::dialogs(r),
        download: crate::evidence_ui::download_menu(r, blocked),
        retested,
        targeted,
        fixed,
    }
}

fn dialogs(
    r: &RunSummary,
    data: serde_json::Map<String, serde_json::Value>,
    notes: serde_json::Map<String, serde_json::Value>,
) -> String {
    // A run loaded from the history: its summary came from whoever can push
    // to the repository, so nothing in it picks where this computer signs
    // in (a domain controller, plain LDAP). The fields start empty.
    let c = r.collection.as_ref().filter(|_| r.shared.is_none());
    let current = cfg!(windows) && c.is_none_or(|c| c.current_user);
    format!(
        r##"<link rel="stylesheet" href="/static/retest.css">{SPRITE}
<dialog id="rt-dialog" class="card rt-dialog" aria-labelledby="rt-d-title" data-run="{id}" data-builtin="{builtin}" data-windows="{windows}" data-findings="{findings}">
  <form method="dialog" class="rt-close-form"><button class="rt-x" value="close" aria-label="Close">{i_x}</button></form>
  <p class="eyebrow">Retest</p>
  <h2 class="sub" id="rt-d-title"></h2>
  <section id="rt-targeted" hidden>
    <p class="muted small" id="rt-objects"></p>
    <form id="rt-form" class="rt-form" autocomplete="off">
      <div class="rt-grid">
        <label>Domain<input name="domain" id="rt-domain" required spellcheck="false" placeholder="scale.local" value="{c_domain}"></label>
        <label>Domain controller <span class="muted">(optional)</span><input name="server" id="rt-server" spellcheck="false" placeholder="dc01.scale.local" value="{c_server}"></label>
      </div>
      <fieldset class="rt-auth"><legend>Sign in as</legend>
        <label class="rt-radio"><input type="radio" name="auth" value="current"{cur_checked}> My Windows account</label>
        <label class="rt-radio"><input type="radio" name="auth" value="password"{pw_checked}> A user and password</label>
      </fieldset>
      <div class="rt-grid" id="rt-cred"{cred_hidden}>
        <label>User<input name="user" id="rt-user" spellcheck="false" placeholder="SCALE\svc-pathwarden"></label>
        <label>Password<input name="password" id="rt-password" type="password" autocomplete="new-password"></label>
      </div>
      <label class="rt-check"><input type="checkbox" name="ldaps" id="rt-ldaps"{ldaps_checked}> Use LDAPS (needed with a password)</label>
      <div class="rt-hosts">
        <label class="rt-check"><input type="checkbox" name="kerberos_only" id="rt-kerberos-only" checked> Kerberos only for computers</label>
        <label class="rt-check"><input type="checkbox" name="smb_signing" id="rt-smb-signing" checked> Require SMB signing</label>
      </div>
      <p class="rt-limit">{i_alert}<span>Only this finding's objects are re-read, and only the computers on its path are contacted. A new path that doesn't go through them isn't detected. The password is used for this check only and never saved.</span></p>
    </form>
  </section>
  <p class="rt-why muted small" id="rt-why" hidden></p>
  <div class="rt-result" id="rt-result" aria-live="polite" hidden></div>
  <div class="rt-foot">
    <p class="rt-auto muted small">The next collection retests every finding<span class="tip"><button type="button" class="tip-btn" aria-label="About: retesting with a new collection" aria-describedby="tip-rt-auto">{i_info}</button><span class="tip-text" role="tooltip" id="tip-rt-auto">Each new analysis of this environment (a collection, a schedule or an uploaded collection) compares every open finding of this run with it and marks the fixed ones, new paths and sessions included. Nothing to retest by hand.</span></span> · <a href="/collect">Collect</a></p>
    <button type="submit" form="rt-form" class="btn primary" id="rt-submit" hidden>{i_retest} Retest now</button>
  </div>
</dialog>
<dialog id="ar-dialog" class="card rt-dialog" aria-labelledby="ar-title">
  <form method="dialog" class="rt-close-form"><button class="rt-x" value="close" aria-label="Close">{i_x}</button></form>
  <p class="eyebrow">Accept risk</p>
  <h2 class="sub" id="ar-title"></h2>
  <p class="muted small ar-id">Finding ID <code id="ar-fp"></code></p>
  <form id="ar-form" class="rt-form" autocomplete="off">
    <label><span>Reason <span class="muted">(required)</span></span><textarea id="ar-reason" rows="3" maxlength="2000" required placeholder="e.g. Break-glass account, reviewed quarterly (CHG0012345)"></textarea></label>
    <label class="ar-date"><span>Review by <span class="muted">(optional)</span></span><input type="date" id="ar-expires"></label>
    <p class="rt-limit">{i_alert}<span>This adds an accepted risk to <code>pathwarden.toml</code>. From the next analysis the finding is shown as accepted, with your reason, instead of open; after the review date it counts as open again. This run's report doesn't change.</span></p>
    <div class="dialog-actions"><a class="btn" href="/settings#risks">Accepted risks in Settings</a><button type="submit" class="btn primary" id="ar-submit">{i_check} Accept risk</button></div>
  </form>
  <div class="rt-result" id="ar-result" aria-live="polite" hidden></div>
</dialog>
<dialog id="an-dialog" class="card rt-dialog" aria-labelledby="an-title" data-accepted="{accepted}">
  <form method="dialog" class="rt-close-form"><button class="rt-x" value="close" aria-label="Close">{i_x}</button></form>
  <p class="eyebrow">Add a note</p>
  <h2 class="sub" id="an-title"></h2>
  <div class="an-risk">
    <p class="an-reason" id="an-reason"></p>
    <p class="muted small" id="an-who"></p>
  </div>
  <form id="an-form" class="rt-form" autocomplete="off">
    <label for="an-text"><span>Note</span></label>
    <textarea id="an-text" rows="3" maxlength="2000" required placeholder="e.g. Checked with the CAB: still needed until the new jump host is in."></textarea>
    <p class="muted small">Kept with this accepted risk in <code>pathwarden.toml</code>, with your name, this computer and the time. A note doesn't change the reason or the review date; the report shows it from the next analysis.</p>
    <div class="dialog-actions"><a class="btn" href="/settings#risks">Accepted risks in Settings</a><button type="submit" class="btn primary" id="an-submit">{i_check} Add note</button></div>
  </form>
  <div class="rt-result" id="an-result" aria-live="polite" hidden></div>
</dialog>
<script src="/static/retest.js" defer></script>
<script src="/static/run.js" defer></script>
"##,
        id = esc(&r.id),
        builtin = u8::from(collect::BUILTIN),
        windows = u8::from(cfg!(windows)),
        findings = crate::pages::json_attr(&serde_json::Value::Object(data).to_string()),
        accepted = crate::pages::json_attr(&serde_json::Value::Object(notes).to_string()),
        c_domain = crate::pages::attr(c.map(|c| c.domain.as_str()).unwrap_or_default()),
        c_server = crate::pages::attr(c.and_then(|c| c.server.as_deref()).unwrap_or_default()),
        cur_checked = if current { " checked" } else { "" },
        pw_checked = if current { "" } else { " checked" },
        cred_hidden = if current { " hidden" } else { "" },
        ldaps_checked = if c.is_some_and(|c| c.ldaps) || !cfg!(windows) {
            " checked"
        } else {
            ""
        },
        i_x = icon("i-x"),
        i_alert = icon("i-alert"),
        i_retest = icon("i-retest"),
        i_info = icon("i-info"),
        i_check = icon("i-check"),
    )
}

const SPRITE: &str = r#"<svg class="sprite" width="0" height="0" aria-hidden="true" focusable="false"><defs>
<symbol id="i-retest" viewBox="0 0 24 24"><path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3"/><path d="M19.5 4.5v4.2h-4.2"/><path d="m9 12.2 2.2 2.2L15.5 10"/></symbol>
</defs></svg>"#;

// -------------------------------------------------------------------- API

/// The retest form: the Collect wizard's sign-in fields and the finding.
/// `Debug` shows the password as `Secret(<redacted>)`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RetestForm {
    pub fingerprint: String,
    pub domain: String,
    pub server: Option<String>,
    pub auth: AuthChoice,
    pub user: String,
    /// Read straight into a [`Secret`]: zeroed when the form is dropped.
    pub password: Option<Secret>,
    pub ldaps: bool,
    pub skip_verify: bool,
    /// "Kerberos only for computers" turned off (`--allow-ntlm`).
    pub allow_ntlm: bool,
    /// "Require SMB signing" turned off (`--allow-unsigned-smb`).
    pub allow_unsigned_smb: bool,
    /// Don't read the computers on the finding's path (`pathwarden retest
    /// targeted --no-hosts`).
    pub no_hosts: bool,
    /// Read the services of the computers that store a password the
    /// finding rests on: `None` (the dialog) follows the
    /// environment's `[collect] service_reads`, as Collect does;
    /// `Some(false)` is `--no-service-reads`.
    pub service_reads: Option<bool>,
    /// Their scheduled tasks, likewise with `[collect] task_reads` and
    /// `--no-task-reads`.
    pub task_reads: Option<bool>,
}

/// One targeted retest at a time (each contacts a domain controller).
static RETESTING: AtomicBool = AtomicBool::new(false);

struct Slot;

impl Slot {
    fn take() -> Option<Self> {
        (!RETESTING.swap(true, Ordering::SeqCst)).then_some(Slot)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        RETESTING.store(false, Ordering::SeqCst);
    }
}

/// A fingerprint as rules make them: `PW-003-0123456789abcdef`.
fn valid_fingerprint(fp: &str) -> bool {
    fp.len() <= 64
        && fp.starts_with("PW-")
        && fp.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

async fn retest(
    State(st): State<Shared>,
    UrlPath(id): UrlPath<String>,
    SecretJson(form): SecretJson<RetestForm>,
) -> Response {
    if !workspace::valid_run_id(&id) || !valid_fingerprint(&form.fingerprint) {
        return json_error(StatusCode::BAD_REQUEST, "Invalid run or finding.");
    }
    let (Some(dir), Some(summary)) = (st.workspace.run_dir(&id), st.workspace.run(&id)) else {
        return json_error(StatusCode::NOT_FOUND, "That run no longer exists.");
    };
    if !collect::BUILTIN {
        return json_error(
            StatusCode::CONFLICT,
            "This build has no built-in collector, so it can't re-read single objects. Upload a \
             new collection or collect again to retest.",
        );
    }
    if st.jobs.running().is_some() {
        return json_error(
            StatusCode::CONFLICT,
            "Pathwarden is collecting or analyzing. Wait for it to finish, then retest.",
        );
    }
    let Some(slot) = Slot::take() else {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "A retest is already running. Wait for it to finish.",
        );
    };
    // The run's own environment: its config and history, whichever is
    // current.
    let ws = st.workspace.for_run(&summary);
    let done = tokio::task::spawn_blocking(move || {
        let r = targeted(&ws, &dir, form, &pathwarden_collect::BuiltinRefresher);
        drop(slot);
        r
    })
    .await;
    match done {
        Ok(Ok(rec)) => Json(result_json(&rec)).into_response(),
        Ok(Err((status, body))) => (status, Json(body)).into_response(),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The retest stopped. Try again.",
        ),
    }
}

/// A targeted result as the dialog (and `pathwarden retest targeted
/// --json`) gets it.
pub fn result_json(rec: &RetestRecord) -> serde_json::Value {
    serde_json::json!({
        "verdict": rec.verdict,
        "label": rec.verdict.label(),
        "details": rec.details,
        "refreshed": rec.refreshed,
        "hosts": rec.hosts,
        "hosts_total": rec.hosts_total,
        "at": rec.at,
        "detail": short_detail(rec.refreshed, rec.hosts, &rec.details),
        "lines": result_lines(rec),
    })
}

/// What a targeted result says besides its details, in sentences: what was
/// read, and for a fixed one what wasn't checked. The dialog and `pathwarden
/// retest targeted` print these after the details.
pub fn result_lines(rec: &RetestRecord) -> Vec<String> {
    let mut out = vec![format!(
        "Re-read {}.",
        pathwarden_core::text::count(rec.refreshed, "object", "objects")
    )];
    match (rec.hosts, rec.hosts_total) {
        (_, 0) => {}
        (1, 1) => out.push("Read the computer on its path.".into()),
        (n, t) if n == t => out.push(format!("Read the {t} computers on its path.")),
        (n, t) => out.push(format!(
            "Read {n} of the {} on its path.",
            pathwarden_core::text::count(t, "computer", "computers")
        )),
    }
    if rec.verdict == Verdict::Fixed {
        out.push(
            "Only these objects were checked: a new path elsewhere wouldn't show here.".into(),
        );
    }
    out
}

/// A failed retest: the status and the JSON body to answer with.
pub type Failure = (StatusCode, serde_json::Value);

fn failure(status: StatusCode, message: impl Into<String>) -> Failure {
    (status, serde_json::json!({ "error": message.into() }))
}

/// Re-reads the finding's objects, and the sessions and local groups of the
/// computers on its path, with `reader` (the built-in collector, or a fake
/// in tests); re-evaluates and records the result (blocking). Shared with
/// `pathwarden retest targeted`.
///
/// The computers are read unless `form.no_hosts`, as the sign-in allows
/// ([`pathwarden_collect::host_reader`]): with a user and password over
/// SMB (NTLM), as the Windows account through Windows' own calls (Windows
/// only). Where they aren't read, a finding that rests on them can't be
/// told fixed from the directory alone, and the result says why.
pub fn targeted(
    ws: &Workspace,
    dir: &Path,
    form: RetestForm,
    reader: &dyn Refresher,
) -> Result<RetestRecord, Failure> {
    let fingerprint = form.fingerprint.clone();
    let slice = slice(dir).ok_or_else(|| {
        failure(
            StatusCode::CONFLICT,
            "This run was analyzed before targeted retests existed. Retest it with a new collection.",
        )
    })?;
    let sf = slice
        .finding(&fingerprint)
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "That finding is not in this run."))?;
    if let Some(why) = &sf.unsupported {
        return Err(failure(StatusCode::CONFLICT, why.clone()));
    }
    // The domain object, so the parser knows the domain.
    let domain_sid = slice
        .nodes
        .iter()
        .find(|n| sf.refresh.contains(&n.id))
        .and_then(|n| n.domain_sid.clone());
    let no_hosts = form.no_hosts;
    // The stored credentials switches, as Collect and the command
    // line read them: the form's, else the run environment's `[collect]`.
    let service_reads = collect::service_reads_of(ws, form.service_reads.unwrap_or(true));
    let task_reads = collect::task_reads_of(ws, form.task_reads.unwrap_or(true));

    let mut rnd = [0u8; 4];
    let _ = getrandom::getrandom(&mut rnd);
    let out = ws.uploads_dir().join(format!(
        "retest-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    let collect_form = CollectForm {
        resume: false,
        domain: form.domain,
        server: form.server,
        auth: form.auth,
        user: form.user,
        password: form.password,
        ldaps: form.ldaps,
        skip_verify: form.skip_verify,
        allow_ntlm: form.allow_ntlm,
        allow_unsigned_smb: form.allow_unsigned_smb,
        service_reads: None,
        task_reads: None,
        depth: Depth::Quick,
        collector: Collector::Builtin,
        sharphound: String::new(),
        keep: false,
        env: None,
        new_env: None,
        env_auto: false,
        label: None,
        trusted: Vec::new(),
        trusted_servers: Default::default(),
        also: None,
    };
    let mut req = collect::build_request(collect_form, out.clone()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": e.message, "field": e.field }),
        )
    })?;
    req.service_reads = service_reads;
    req.task_reads = task_reads;
    // The computers on its path, when they can be read with this sign-in.
    let (hosts, _) = slice.host_targets(sf);
    let skipped = if hosts.is_empty() {
        None
    } else if no_hosts {
        Some(targeted::HOSTS_NOT_READ)
    } else if pathwarden_collect::host_reader(&req.auth).is_none() {
        Some(targeted::HOSTS_NEED_PASSWORD)
    } else {
        None
    };
    let target = RefreshTarget {
        ids: sf.refresh.clone(),
        group_dns: sf.groups.clone(),
        domain_sid,
        hosts: if skipped.is_some() { Vec::new() } else { hosts },
    };
    let refreshed = reader.refresh(&req, &target);
    let server = req.server.clone();
    // Zeroes the password: nothing below needs it.
    drop(req);
    let result = refreshed
        .map_err(|e| {
            // Already in plain words (no Kerberos ticket): as is.
            if let Some(ce) = e.downcast_ref::<pathwarden_collect::ConnectionError>() {
                return failure(StatusCode::UNPROCESSABLE_ENTITY, ce.to_string());
            }
            let text = format!("{e:#}");
            let message = match Problem::classify(&text) {
                Problem::Other | Problem::Settings => format!("The retest failed: {text}"),
                p => format!("{} ({text})", p.explain()),
            };
            failure(StatusCode::UNPROCESSABLE_ENTITY, message)
        })
        .and_then(|r| {
            let mut ing = pathwarden_core::ingest::Ingestor::new();
            for f in &r.files {
                ing.ingest_path(f).map_err(|e| {
                    failure(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Couldn't read what was re-read: {e}"),
                    )
                })?;
            }
            let (fresh, _) = ing.finish();
            let reads = targeted::HostReads {
                reads: r.hosts,
                skipped: skipped.map(str::to_string),
                deleted: r.deleted,
            };
            slice
                .retest_with(&fingerprint, &fresh, &reads, analyze::now())
                .map_err(|e| failure(StatusCode::CONFLICT, e))
                .map(|o| (o, r.server))
        });
    let _ = std::fs::remove_dir_all(&out);
    let (outcome, dc) = result?;
    let rec = RetestRecord {
        fingerprint,
        at: analyze::now(),
        method: "targeted".into(),
        verdict: outcome.verdict,
        details: outcome.details,
        refreshed: outcome.refreshed,
        server: dc.or(server),
        hosts: outcome.hosts_read,
        hosts_total: outcome.hosts,
    };
    record(dir, rec.clone()).map_err(|e| {
        failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Retested, but the result couldn't be saved: {e}"),
        )
    })?;
    Ok(rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_values() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // sha256("") as browsers expect it in a CSP.
        assert_eq!(
            csp_hash(""),
            "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"
        );
        // Line ends as the HTML parser leaves them.
        assert_eq!(csp_hash("a\r\nb\rc"), csp_hash("a\nb\nc"));
    }

    #[test]
    fn only_report_scripts_pathwarden_wrote_are_trusted() {
        assert!(known_report_script(&csp_hash(
            pathwarden_core::report::REPORT_JS
        )));
        assert!(known_report_script(&format!(
            "'sha256-{}'",
            EARLIER_REPORT_SCRIPTS[5]
        )));
        assert!(!known_report_script(&csp_hash("alert(1)")));
        assert!(!known_report_script(&csp_hash(REPORT_RETEST_JS)));
    }

    /// When `report.js` changes, reports stored by the build before it must
    /// keep their Retest buttons: move [`REPORT_SCRIPT`] into
    /// [`EARLIER_REPORT_SCRIPTS`] and set it to the new hash.
    #[test]
    fn the_report_script_change_keeps_earlier_reports_retestable() {
        assert_eq!(
            csp_hash(pathwarden_core::report::REPORT_JS),
            format!("'sha256-{REPORT_SCRIPT}'"),
            "report.js changed: add the old hash to EARLIER_REPORT_SCRIPTS"
        );
        assert!(!EARLIER_REPORT_SCRIPTS.contains(&REPORT_SCRIPT));
    }

    #[test]
    fn links_leaving_the_report_open_a_new_tab() {
        let html = concat!(
            r##"<a href="#plan">Plan</a> <a href="https://x.example/a" rel="noreferrer">x</a>"##,
            r##"<a target="_top" href="https://y.example">y</a><abbr>z</abbr> 1 < 2"##,
            r##"<style>a<b{}</style><script>var s = '<a href="https://z">';</script>"##,
            r##"<a class="m" href="mailto:a@b">m</a>"##
        );
        assert_eq!(
            links_in_new_tab(html),
            concat!(
                r##"<a href="#plan">Plan</a> <a target="_blank" rel="noopener noreferrer" href="https://x.example/a" rel="noreferrer">x</a>"##,
                r##"<a target="_top" href="https://y.example">y</a><abbr>z</abbr> 1 < 2"##,
                r##"<style>a<b{}</style><script>var s = '<a href="https://z">';</script>"##,
                r##"<a target="_blank" rel="noopener noreferrer" class="m" href="mailto:a@b">m</a>"##
            )
        );
    }

    #[test]
    fn fingerprints_are_checked() {
        assert!(valid_fingerprint("PW-003-39f2ede7c479090b"));
        assert!(!valid_fingerprint("PW-003/../x"));
        assert!(!valid_fingerprint("x"));
        assert!(!valid_fingerprint(&format!("PW-{}", "a".repeat(80))));
    }

    #[test]
    fn the_log_keeps_the_latest_per_finding() {
        let dir = std::env::temp_dir().join(format!("pw-retests-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..25 {
            record(
                &dir,
                RetestRecord {
                    fingerprint: "PW-003-a".into(),
                    at: i,
                    method: "targeted".into(),
                    verdict: Verdict::StillOpen,
                    details: vec![],
                    refreshed: 1,
                    server: None,
                    hosts: 0,
                    hosts_total: 0,
                },
            )
            .unwrap();
        }
        let log = load_log(&dir);
        assert_eq!(log.results.len(), KEEP_PER_FINDING);
        assert_eq!(log.results.last().unwrap().at, 24);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_password_never_shows_in_debug() {
        let f: RetestForm = serde_json::from_str(
            r#"{"fingerprint":"PW-003-a","domain":"x.local","auth":"password","user":"u","password":"Retest-Secret-8"}"#,
        )
        .unwrap();
        assert!(!format!("{f:?}").contains("Retest-Secret-8"));
    }

    /// The check that Run details can be seen reads styles only of what is
    /// drawn: reading every element's took a minute in a report of
    /// thousands of findings.
    #[test]
    fn the_run_details_check_skips_what_is_not_drawn() {
        assert!(!REPORT_RETEST_JS.contains(r#"querySelectorAll("*")"#));
        assert!(REPORT_RETEST_JS.contains("createTreeWalker"));
    }
}
