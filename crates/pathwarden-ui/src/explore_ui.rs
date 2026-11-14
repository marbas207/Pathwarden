//! The Explore page: a run's graph in Cytoscape.js, opened on a finding's
//! attack path or on any object, with neighbors, paths, "who can reach
//! this" and zone suggestions.
//!
//! Each run saves its whole graph as [`GRAPH_FILE`]
//! ([`pathwarden_core::explore`]); names, distinguished names and search come
//! from the run's object index ([`crate::run_data`]). A few runs are kept in
//! memory. Every query runs on the server, on a blocking thread, and every
//! answer is capped. The API is read-only, except for zone drafts (a
//! short-lived, in-memory hand-off to the Zone wizard, which writes nothing
//! until the user saves there) and owned marks (the environment's
//! [`pathwarden_core::owned`] file, which `pathwarden owned` also writes).
//!
//! The Query tab runs Cypher on the run ([`pathwarden_core::cypher::RunView`]),
//! as `pathwarden query --run` does.
//!
//! Object names come from the directory and are attacker-controlled: the
//! page renders none of them on the server, the API returns them as JSON,
//! and the script inserts them as text (Cytoscape draws labels on a canvas).

use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pathwarden_core::explore::answers::{EdgeOut, Explorer, NodeOut, SuggestionsAnswer};
use pathwarden_core::explore::{self, flag, Bounds, Dir, Edge, ExploreGraph, PathTree, Reacher};
use pathwarden_core::model::{EdgeKind, NodeKind};
use pathwarden_core::zones::ZoneConfig;
use pathwarden_core::{AdGraph, NodeIndex};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::pages::{self, esc, icon, Nav};
use crate::run_data;
use crate::server::AppState;

type Shared = Arc<AppState>;

/// The run's whole graph, beside its object index.
pub const GRAPH_FILE: &str = "graph.bin.gz";

const EXPLORE_JS: &str = include_str!("assets/explore.js");
const EXPLORE_CSS: &str = include_str!("assets/explore.css");
/// Cytoscape.js 3.34.3 (MIT), see THIRD-PARTY-NOTICES.md.
const CYTOSCAPE_JS: &str = include_str!("assets/vendor/cytoscape.min.js");

/// Caps on what one request returns.
pub const NEIGHBOR_LIMIT: usize = 500;
pub const NEIGHBOR_DEFAULT: usize = 40;
pub const REACH_PAGE: usize = 200;
pub const MAX_PATHS: usize = 5;
pub const FINDING_OBJECTS: usize = 50;
pub const FINDINGS_LISTED: usize = 10_000;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/explore", get(latest))
        .route("/runs/{id}/explore", get(page))
        .route("/api/runs/{id}/explore", get(info))
        .route("/api/runs/{id}/explore/node", get(node))
        .route("/api/runs/{id}/explore/neighbors", get(neighbors))
        .route("/api/runs/{id}/explore/path", get(path))
        .route("/api/runs/{id}/explore/reach", get(reach))
        .route("/api/runs/{id}/explore/search", get(search))
        .route("/api/runs/{id}/explore/finding", get(finding))
        .route("/api/runs/{id}/explore/suggestions", get(suggestions))
        .route("/api/runs/{id}/explore/forest", get(forest))
        .route("/api/runs/{id}/explore/crossing", get(crossing))
        .route("/api/runs/{id}/explore/query", post(query))
        .route("/api/prepared", get(prepared_list))
        .route("/api/runs/{id}/explore/owned", get(owned).post(set_owned))
        .route("/api/zones/draft", post(save_draft))
        .route(
            "/static/explore.js",
            get(|| async { asset("text/javascript", EXPLORE_JS) }),
        )
        .route(
            "/static/explore.css",
            get(|| async { asset("text/css", EXPLORE_CSS) }),
        )
        .route(
            "/static/vendor/cytoscape.min.js",
            get(|| async { asset("text/javascript", CYTOSCAPE_JS) }),
        )
}

/// The page's script (tests check it never inserts HTML).
pub fn script() -> &'static str {
    EXPLORE_JS
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

// ------------------------------------------------------------ the run

/// One run, loaded for exploring.
pub struct Run {
    dir: PathBuf,
    g: Arc<AdGraph>,
    x: ExploreGraph,
    tier_zero: Vec<u32>,
    t0_tree: OnceLock<PathTree>,
    suggestions: OnceLock<Value>,
    /// The last "who can reach" answer, sorted, for paging.
    reach: Mutex<Option<(u32, Arc<Vec<Reacher>>)>>,
    pub load_ms: u128,
    objects_ms: u128,
    edges_ms: u128,
}

impl Run {
    fn t0_tree(&self) -> &PathTree {
        self.t0_tree.get_or_init(|| self.x.tier_zero_tree())
    }

    /// The shared answers ([`pathwarden_core::explore::answers`]).
    fn ex(&self) -> Explorer<'_> {
        Explorer::new(&self.g, &self.x)
    }

    fn out(&self, v: u32) -> NodeOut<'_> {
        self.ex().out(v)
    }

    fn outs(&self, ixs: impl IntoIterator<Item = u32>) -> Vec<NodeOut<'_>> {
        self.ex().outs(ixs)
    }
}

/// Why a run can't be explored.
enum LoadError {
    /// Its graph or object index isn't here ([`Missing`]).
    Missing(Missing),
    Broken(String),
}

/// What a run that can't be explored lacks, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// Analyzed before runs kept their graph.
    Old,
    /// Loaded from the history without its object index: over the file
    /// limit of the computer that recorded it.
    IndexNotShared,
    /// Loaded from the history without its graph.
    GraphNotShared,
}

impl Missing {
    /// The sentence the page and the API say.
    pub fn sentence(self) -> &'static str {
        match self {
            Missing::Old => OLD_GRAPH,
            Missing::IndexNotShared => INDEX_NOT_SHARED,
            Missing::GraphNotShared => GRAPH_NOT_SHARED,
        }
    }

    /// Why, after "can't be explored: ".
    pub fn reason(self) -> &'static str {
        match self {
            Missing::Old => "it has no saved graph",
            Missing::IndexNotShared => "its object index wasn't shared",
            Missing::GraphNotShared => "its graph wasn't shared",
        }
    }
}

/// What a run loaded from the history without its object index says.
pub const INDEX_NOT_SHARED: &str = "This run's object index wasn't shared.";

/// The same, without its graph.
pub const GRAPH_NOT_SHARED: &str = "This run's graph wasn't shared.";

/// Why the run in `dir` can't be explored; `None` when it can.
pub fn missing(dir: &FsPath) -> Option<Missing> {
    let (graph, objects) = (
        dir.join(GRAPH_FILE).is_file(),
        dir.join(run_data::OBJECTS_FILE).is_file(),
    );
    if graph && objects {
        return None;
    }
    // A run loaded from the history: its full run left the file out.
    let loaded = dir.join(crate::shared_runs::LOADED_MARKER).exists()
        || dir.join(crate::workspace::LOADED_SUMMARY_FILE).exists();
    Some(match (loaded, objects) {
        (true, false) => Missing::IndexNotShared,
        (true, true) => Missing::GraphNotShared,
        (false, _) => Missing::Old,
    })
}

/// Runs loaded for exploring: the newest and those used last, fewer when
/// they are large, none after a while without a request (see
/// `run_data::RunCache`). They share their object graphs with
/// [`run_data::graph`]'s.
static RUNS: run_data::RunCache<Run> = run_data::RunCache::new(run_data::RECENT, |r| {
    run_data::graph_weight(&r.g) + r.x.memory()
});

/// Lets go of the runs without a request since `idle` before `now`.
pub(crate) fn sweep(idle: std::time::Duration, now: Instant) {
    RUNS.sweep(idle, now);
}

/// The runs loaded for exploring, and the estimated bytes of their edges
/// (their graphs are [`run_data::graph`]'s).
pub(crate) fn edge_weights() -> (usize, usize) {
    RUNS.weighs_by(|r| r.x.memory())
}

fn read_gz(path: &FsPath) -> std::io::Result<Vec<u8>> {
    crate::run_data::read_gz(path)
}

/// A saved run's objects and whole graph, read.
struct Loaded {
    g: Arc<AdGraph>,
    x: ExploreGraph,
    objects_ms: u128,
    edges_ms: u128,
}

/// How large the graph of the run in `dir` may be: from the objects its
/// summary says it collected ([`Bounds::of_collected`]). A run in the
/// workspace always has a summary; a graph is refused without one.
fn bounds(dir: &FsPath) -> Result<Bounds, LoadError> {
    #[derive(serde::Deserialize)]
    struct Summary {
        objects: usize,
    }
    let path = crate::workspace::summary_file(dir)
        .unwrap_or_else(|| dir.join(crate::workspace::SUMMARY_FILE));
    // No larger than a summary takes: one planted in a loaded run is never
    // read whole.
    let read = || -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let max = pathwarden_core::exposed::MAX_SUMMARY;
        let f = std::fs::File::open(&path)?;
        let mut text = Vec::new();
        f.take(max + 1).read_to_end(&mut text)?;
        if text.len() as u64 > max {
            return Err(std::io::Error::other(format!(
                "it is larger than {} KiB",
                max >> 10
            )));
        }
        Ok(text)
    };
    let text = read().map_err(|e| LoadError::Broken(format!("its summary can't be read: {e}")))?;
    // Saved with a byte order mark or not.
    let text = text.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&text);
    let s: Summary = serde_json::from_slice(text)
        .map_err(|e| LoadError::Broken(format!("its summary can't be read: {e}")))?;
    Ok(Bounds::of_collected(s.objects))
}

/// Reads the run in `dir`: its object index, and on its own thread
/// meanwhile, its graph, within what its summary allows.
fn load(dir: &FsPath) -> Result<Loaded, LoadError> {
    let file = dir.join(GRAPH_FILE);
    if let Some(m) = missing(dir) {
        return Err(LoadError::Missing(m));
    }
    let bounds = bounds(dir)?;
    let edges = std::thread::spawn(move || {
        let t = Instant::now();
        let bytes = read_gz(&file).map_err(|e| LoadError::Broken(e.to_string()))?;
        let x = ExploreGraph::decode_within(&bytes, bounds).map_err(LoadError::Broken)?;
        Ok::<_, LoadError>((x, t.elapsed().as_millis()))
    });
    let t = Instant::now();
    let g = run_data::graph(dir);
    let objects_ms = t.elapsed().as_millis();
    let (x, edges_ms) = edges
        .join()
        .map_err(|_| LoadError::Broken("reading the graph failed".into()))??;
    let g = g.ok_or_else(|| LoadError::Broken("the object index couldn't be read".into()))?;
    if g.node_count() != x.node_count() {
        return Err(LoadError::Broken(
            "the object index and the graph disagree".into(),
        ));
    }
    Ok(Loaded {
        g,
        x,
        objects_ms,
        edges_ms,
    })
}

/// A saved run's objects and whole graph, as the Explore page reads them:
/// what `pathwarden reach` and `search` answer from on a saved run
/// (`--run`, `--env`), with [`pathwarden_core::explore::answers::Explorer`].
pub fn read_run(dir: &FsPath) -> Result<(Arc<AdGraph>, ExploreGraph), String> {
    match load(dir) {
        Ok(l) => Ok((l.g, l.x)),
        Err(LoadError::Missing(Missing::Old)) => Err(
            "the run was analyzed before runs kept their graph; analyze its data again to explore it"
                .into(),
        ),
        Err(LoadError::Missing(m)) => Err(format!(
            "{}, so it can't be explored on this computer",
            match m {
                Missing::GraphNotShared => "this run's graph wasn't shared",
                _ => "this run's object index wasn't shared",
            }
        )),
        Err(LoadError::Broken(e)) => Err(format!("the run's graph can't be read: {e}")),
    }
}

/// The run in `dir`, loading it when needed. Two first requests for a run
/// load it once; a request for another run doesn't wait for it.
fn open(dir: &FsPath) -> Result<Arc<Run>, LoadError> {
    if let Some(m) = missing(dir) {
        return Err(LoadError::Missing(m));
    }
    let mut read = false;
    let run = RUNS.get_or_load(dir, || {
        read = true;
        let started = Instant::now();
        let Loaded {
            g,
            x,
            objects_ms,
            edges_ms,
        } = load(dir)?;
        Ok(Run {
            dir: dir.to_path_buf(),
            tier_zero: x.tier_zero(),
            g,
            x,
            t0_tree: OnceLock::new(),
            suggestions: OnceLock::new(),
            reach: Mutex::new(None),
            load_ms: started.elapsed().as_millis(),
            objects_ms,
            edges_ms,
        })
    });
    if read && run.is_ok() {
        run_data::log_weights("explore read");
    }
    run
}

/// Loads the run in `dir` if it can be explored, for a first Explore that
/// doesn't wait (blocking: the server starts it on a blocking thread).
pub fn warm(dir: &FsPath) {
    let _ = open(dir);
}

/// The rail's Explore entry: the newest run that can be explored; with
/// runs of more than one environment, a choice of environment (each its
/// newest run); or a page saying what to do first.
/// `?view=forest` on Explore's links: the Forest view stays open.
#[derive(Deserialize)]
struct ViewQuery {
    view: Option<String>,
}

/// The query Explore's links carry for `view` (only the Forest view).
fn view_suffix(view: Option<&str>) -> &'static str {
    if view == Some("forest") {
        "?view=forest"
    } else {
        ""
    }
}

async fn latest(State(st): State<Shared>, Query(v): Query<ViewQuery>) -> Response {
    let suffix = view_suffix(v.view.as_deref());
    let runs = st.ws().runs();
    let ctx = pages::Ctx::new(&st, &runs);
    // Newest first, so the first of each environment is its latest.
    let mut seen = std::collections::HashSet::new();
    let newest: Vec<&crate::workspace::RunSummary> = runs
        .iter()
        .filter(|r| st.ws().run_dir(&r.id).is_some_and(|dir| available(&dir)))
        .filter(|r| seen.insert(crate::retest_ui::env_key(r)))
        .collect();
    match newest.as_slice() {
        [] => {}
        [run] => {
            // Not its environment's latest: the page says why.
            let latest = runs
                .iter()
                .find(|r| crate::retest_ui::env_key(r) == crate::retest_ui::env_key(run))
                .is_some_and(|r| r.id == run.id);
            let to = match (latest, suffix.is_empty()) {
                (true, _) => format!("/runs/{}/explore{suffix}", run.id),
                (false, true) => format!("/runs/{}/explore?from=latest", run.id),
                (false, false) => format!("/runs/{}/explore{suffix}&from=latest", run.id),
            };
            return (StatusCode::SEE_OTHER, [(header::LOCATION, to)]).into_response();
        }
        several => {
            let mut b = String::from(
                r#"<div class="page-head"><div><h1 class="panel-title">Explore</h1><p class="lead">Choose an environment to open its latest run.</p></div></div><div class="rows card runlist">"#,
            );
            for r in several {
                pages::run_row_to(&mut b, r, &format!("/explore{suffix}"));
            }
            b.push_str("</div>");
            return Html(pages::shell(&ctx, Some(Nav::Explore), "Explore", "", &b)).into_response();
        }
    }
    let older = if runs.is_empty() {
        String::new()
    } else {
        " Runs analyzed before this version don't have the graph data; analyze their collection again.".to_string()
    };
    // The empty state Home and Progress have.
    let body = format!(
        r#"<div class="page-head"><div><h1 class="panel-title">Explore</h1></div></div>
{}"#,
        pages::welcome_card(
            "Explore",
            "Nothing to explore yet.",
            &format!(
                "Explore shows a run's attack paths as a graph, who can reach any object, and suggested zones. It needs one analysis first.{older}"
            ),
        )
    );
    Html(pages::shell(&ctx, Some(Nav::Explore), "Explore", "", &body)).into_response()
}

/// Whether the run has what the explorer needs.
pub fn available(dir: &FsPath) -> bool {
    dir.join(GRAPH_FILE).is_file() && dir.join(run_data::OBJECTS_FILE).is_file()
}

// ------------------------------------------------------------ JSON

struct ApiError(StatusCode, String);

impl ApiError {
    fn bad(msg: &str) -> Self {
        ApiError(StatusCode::BAD_REQUEST, msg.to_string())
    }
}

type ApiResult = Result<Value, ApiError>;

/// Runs `f` on the run's graph on a blocking thread.
async fn with_run<F>(st: &AppState, id: &str, f: F) -> Response
where
    F: FnOnce(&Run) -> ApiResult + Send + 'static,
{
    with_run_or_old(st, id, move |run| f(run).map_err(Failure::Api)).await
}

const OLD_GRAPH: &str = "This run was analyzed before Pathwarden kept the graph for exploring. Analyze the collection again to explore it.";

/// Why a question about a run has no answer.
enum Failure {
    Api(ApiError),
    /// The run was saved before it kept what the question needs; it says
    /// so, and the run has to be analyzed again.
    Old(&'static str),
}

/// [`with_run`] for questions that older runs can't answer.
async fn with_run_or_old<F>(st: &AppState, id: &str, f: F) -> Response
where
    F: FnOnce(&Run) -> Result<Value, Failure> + Send + 'static,
{
    let Some(dir) = st.ws().run_dir(id) else {
        return error(StatusCode::NOT_FOUND, "That run no longer exists.", false);
    };
    let result = tokio::task::spawn_blocking(move || match open(&dir) {
        Ok(run) => f(&run),
        Err(LoadError::Missing(m)) => Err(Failure::Old(m.sentence())),
        Err(LoadError::Broken(e)) => Err(Failure::Api(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("This run's graph couldn't be read ({e}). Analyze the collection again to explore it."),
        ))),
    })
    .await;
    match result {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(Failure::Api(ApiError(s, m)))) => error(s, &m, false),
        Ok(Err(Failure::Old(message))) => error(StatusCode::NOT_FOUND, message, true),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The explorer stopped. Try again.",
            false,
        ),
    }
}

fn error(status: StatusCode, message: &str, reanalyze: bool) -> Response {
    (
        status,
        Json(json!({ "error": message, "reanalyze": reanalyze })),
    )
        .into_response()
}

fn node_arg(run: &Run, ix: Option<u32>) -> Result<u32, ApiError> {
    ix.filter(|&v| run.x.contains(v))
        .ok_or_else(|| ApiError::bad("No such object in this run."))
}

/// `AdminTo,GenericAll` -> kinds; unknown names are ignored.
fn edge_kinds(s: &str) -> Vec<EdgeKind> {
    s.split(',')
        .take(EdgeKind::ALL.len())
        .filter_map(|k| EdgeKind::from_name_or_external(k.trim()))
        .collect()
}

/// The relationships a finding without a path is about, drawn among its
/// objects. Empty for most rules: their objects are a list, not a graph.
fn link_kinds(rule: &str) -> &'static [EdgeKind] {
    match rule {
        // A Tier Zero account's sessions on ordinary hosts.
        "PW-004" => &[EdgeKind::HasSession],
        _ => &[],
    }
}

// ------------------------------------------------------------ the page

#[derive(Deserialize)]
struct PageQuery {
    finding: Option<String>,
    node: Option<u32>,
    /// `forest` opens the Forest view.
    view: Option<String>,
    /// `latest`: opened from Explore's entry ([`fallback_words`]).
    from: Option<String>,
}

/// The Forest view's legend: swatch, label, and the key of its ⓘ
/// definition ([`pathwarden_core::forest::definitions`]).
const FOREST_LEGEND: &[(&str, &str, &str)] = &[
    ("fm-lg-dom", "Domain", ""),
    ("fm-lg-dim", "Not collected", "not_collected"),
    ("fm-lg-hull", "Forest", "forest"),
    ("fm-lg-in", "Inside a forest", "inside"),
    ("fm-lg-x", "Between forests", "between"),
    (
        "fm-lg-bad",
        "Between forests, SID history abuse",
        "between_abuse",
    ),
    ("fm-lg-arrow", "Way in", "way_in"),
];

/// The definitions as the script reads them (`data-defs`), with the words
/// it says itself.
fn forest_words() -> String {
    use pathwarden_core::forest;
    let mut m: serde_json::Map<String, Value> = forest::definitions()
        .into_iter()
        .map(|(k, d)| (k.to_string(), Value::String(d)))
        .collect();
    m.insert("not_a_path_step".into(), forest::NOT_A_PATH_STEP.into());
    m.insert("not_collected_label".into(), forest::NOT_COLLECTED.into());
    Value::Object(m).to_string()
}

fn forest_legend() -> String {
    let mut s = String::from(
        r#"<ul class="xp-legend fm-legend" id="fm-legend" aria-label="Forest legend" hidden>"#,
    );
    for (class, label, key) in FOREST_LEGEND {
        let def = pathwarden_core::forest::definition(key);
        let swatch = if *class == "fm-lg-arrow" {
            r#"<span class="fm-lg-arrow" aria-hidden="true">&rarr;</span>"#.to_string()
        } else {
            format!(r#"<span class="lg {class}"></span>"#)
        };
        let info = if def.is_empty() {
            String::new()
        } else {
            format!(
                r#"<button type="button" class="fm-i" data-def="{d}" title="{d}" aria-label="About {l}">i</button>"#,
                d = esc(&def),
                l = esc(label)
            )
        };
        s.push_str(&format!("<li>{swatch}{}{info}</li>", esc(label)));
    }
    s.push_str("</ul>");
    s
}

/// A fingerprint as the page carries it: `RULE-hex`, nothing else.
fn clean_fingerprint(s: &str) -> Option<String> {
    (s.len() <= 80 && !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .then(|| s.to_string())
}

async fn page(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<PageQuery>,
) -> Response {
    let Some(summary) = st.ws().run(&id) else {
        return (StatusCode::NOT_FOUND, Html(pages::not_found())).into_response();
    };
    let ctx_runs = st.ws().runs();
    let ctx = pages::Ctx::new(&st, &ctx_runs);
    // The picker lists the run's own environment's runs.
    let runs = st.workspace.for_run(&summary).runs();
    let dir = st.workspace.run_dir(&id).unwrap_or_default();
    let env = summary.environment();
    // Which run this is, and a picker to switch (Explore opens the newest
    // run, which with several environments may not be the one wanted).
    let note = crate::environments::run_note(&st, &st.workspace.for_run(&summary));
    // The environment: a menu of every one when there are several
    // (switching opens that one's latest run here), else a link.
    let env_id = crate::workspace::Workspace::env_of(&st.workspace.registry(), &summary);
    // The menu is of environments, so it reads as the environment's name.
    let env_name = ctx
        .envs
        .iter()
        .find(|e| e.id == env_id)
        .map_or(env.clone(), |e| e.name.clone());
    // Switching run or environment keeps the Forest view (the script
    // keeps these links in step when the view changes).
    let suffix = view_suffix(q.view.as_deref());
    let then = format!("/explore{suffix}");
    let env_part = pages::env_picker(&ctx, &env_id, &env_name, &then).unwrap_or_else(|| {
        // The environment's name, as the run page says it; its domains
        // in the tooltip.
        format!(
            r#"<a href="/runs/{id}" title="{env}">{name}</a>"#,
            id = esc(&id),
            env = esc(&env),
            name = esc(&env_name)
        )
    });
    // Opened from Explore's entry, which skipped a later run that can't be
    // explored: which run this is, and why.
    let fallback = if q.from.as_deref() == Some("latest") {
        fallback_words(&st.workspace.for_run(&summary), &runs, &summary)
            .map(|w| {
                format!(
                    r#"<p class="muted small xp-fallback" role="status">{}</p>"#,
                    esc(&w)
                )
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    let head = format!(
        r#"{note}<div class="eyebrow xp-crumb">{env_part}{picker}</div>{fallback}<div class="page-head xp-headline"><div class="xp-head-main"><h1 class="panel-title">Explore</h1></div>"#,
        picker = pages::run_picker(&runs, &summary, &then),
    );
    let body = match missing(&dir) {
        Some(Missing::Old) => format!(
            r#"{head}</div>
<div class="note">{i_alert}<p><strong>Re-analyze to explore.</strong> This run was analyzed before Pathwarden kept the graph for exploring. <a href="/analyze">Analyze the collection again</a> and open the new run's Explore page. The <a href="/runs/{id}">report</a> is still here.</p></div>"#,
            i_alert = icon("i-alert"),
            id = esc(&id),
        ),
        Some(m) => format!(
            r#"{head}</div>
<div class="note">{i_alert}<p><strong>Can't explore this run here.</strong> {why} It was over the largest file the recording computer shares. The <a href="/runs/{id}">report</a> is still here.</p></div>"#,
            i_alert = icon("i-alert"),
            why = m.sentence(),
            id = esc(&id),
        ),
        None => {
            let finding = q
                .finding
                .as_deref()
                .and_then(clean_fingerprint)
                .unwrap_or_default();
            let node = q.node.map(|n| n.to_string()).unwrap_or_default();
            let view = match q.view.as_deref() {
                Some("forest") => "forest",
                Some("list") => "list",
                _ => "",
            };
            format!(
                r##"<link rel="stylesheet" href="/static/explore.css">
<link rel="stylesheet" href="/static/opengraph.css">
<span id="__________cytoscape_stylesheet" hidden></span>
{head}
<div class="xp-search" role="search">
  {i_search}<label class="sr-only" for="xp-q">Find an object</label>
  <input id="xp-q" type="search" placeholder="Find a user, computer, group, OU or GPO" autocomplete="off" spellcheck="false" aria-controls="xp-results" aria-expanded="false">
  <ul id="xp-results" class="xp-results card" role="listbox" hidden></ul>
</div></div>
<div class="xp" id="xp" data-run="{id}" data-finding="{finding}" data-node="{node}" data-view="{view}" data-defs="{defs}">
  <nav class="xp-pager card" id="xp-pager" aria-label="Findings">
    <button type="button" class="btn small-btn" id="xp-prev" title="Previous finding ( [ )">{i_back}<span class="lbl">Previous</span></button>
    <button type="button" class="xp-current" id="xp-current" aria-haspopup="true"><span class="pill" id="xp-sev"></span><span class="xp-ctitle" id="xp-ctitle">Findings</span><span class="xp-pos muted" id="xp-pos"></span></button>
    <button type="button" class="btn small-btn" id="xp-next" title="Next finding ( ] )"><span class="lbl">Next</span>{i_arrow}</button>
  </nav>
  <div class="fm-strip card" id="fm-strip" aria-label="Domains and trusts" hidden><span class="fm-strip-main"><strong id="fm-lead">Domains and trusts</strong><span class="muted" id="fm-detail"></span></span><span class="fm-strip-tags" id="fm-status"></span></div>
  <div class="xp-body">
    <section class="xp-stage card" aria-label="Graph">
      <div class="xp-tools" role="toolbar" aria-label="Graph tools">
        <span class="segmented xp-mode" role="radiogroup" aria-label="View"><label><input type="radio" name="xp-mode" value="graph" checked>Graph</label><label><input type="radio" name="xp-mode" value="list">List</label><label><input type="radio" name="xp-mode" value="forest">Forest</label></span>
        <span class="xp-tool-group">
          <button type="button" class="xp-tool" data-tool="fit" title="Fit to screen">Fit</button>
          <button type="button" class="xp-tool" data-tool="in" title="Zoom in" aria-label="Zoom in">+</button>
          <button type="button" class="xp-tool" data-tool="out" title="Zoom out" aria-label="Zoom out">&minus;</button>
          <button type="button" class="xp-tool" data-tool="layout" title="Lay out left to right">Tidy</button>
          <button type="button" class="xp-tool" data-tool="between" title="Shortest path between the two selected objects" disabled>Path between</button>
          <button type="button" class="xp-tool" data-tool="copy" title="Copy the names of the selected objects (or all)">Copy names</button>
          <button type="button" class="xp-tool" data-tool="clear" title="Clear the graph">Clear</button>
        </span>
      </div>
      <div class="xp-canvas">
        <div id="xp-cy" class="xp-cy"></div>
        <div id="xp-list" class="xp-list" hidden></div>
        <div id="fm" class="fm-canvas" hidden></div>
        <div id="xp-filter" class="xp-filter" hidden></div>
        <div id="xp-empty" class="xp-empty" hidden><p><strong>Nothing on the graph yet.</strong><br><span class="muted">Search for an object above, or open a finding.</span></p></div>
        <div id="xp-dense" class="xp-dense" hidden></div>
        <div id="xp-note" class="xp-dense" role="status" hidden></div>
        <div id="xp-busy" class="xp-busy" hidden><span class="spinner" aria-hidden="true"></span><span id="xp-busy-text">Loading the graph</span></div>
      </div>
      <ul class="xp-legend" id="xp-legend" aria-label="Legend">
        <li><span class="lg lg-start"></span>Start</li>
        <li><span class="lg lg-target"></span>Tier Zero target</li>
        <li><span class="lg lg-t0"></span>Tier Zero</li>
        <li><span class="lg lg-zone"></span>In a zone</li>
        <li><span class="lg lg-path"></span>Attack path</li>
        <li><span class="lg lg-inh"></span>Inherited right</li>
      </ul>
      {forest_legend}
    </section>
    <aside class="xp-side card">
      <div class="xp-tabs" role="tablist" aria-label="Panels">
        <button type="button" role="tab" id="xt-trust" aria-controls="xp-p-trust" aria-selected="false" hidden>Trust</button>
        <button type="button" role="tab" id="xt-finding" aria-controls="xp-p-finding" aria-selected="true">Finding</button>
        <button type="button" role="tab" id="xt-object" aria-controls="xp-p-object" aria-selected="false">Object</button>
        <button type="button" role="tab" id="xt-reach" aria-controls="xp-p-reach" aria-selected="false">Who can reach</button>
        <button type="button" role="tab" id="xt-zones" aria-controls="xp-p-zones" aria-selected="false">Suggested zones <span class="count" id="xp-basket-count" hidden></span></button>
        <span class="xp-tabmore"><button type="button" class="xp-more-btn" id="xt-more" aria-haspopup="true" aria-expanded="false" aria-controls="xp-more-menu"><span id="xt-more-name">More</span> ▾</button><span class="xp-more-menu" id="xp-more-menu" hidden>
          <button type="button" role="tab" id="xt-findings" aria-controls="xp-p-findings" aria-selected="false">Findings</button>
          <button type="button" role="tab" id="xt-query" aria-controls="xp-p-query" aria-selected="false">Query</button>
        </span></span>
      </div>
      <div class="xp-panel" role="tabpanel" id="xp-p-trust" aria-labelledby="xt-trust" hidden></div>
      <div class="xp-panel" role="tabpanel" id="xp-p-finding" aria-labelledby="xt-finding"></div>
      <div class="xp-panel" role="tabpanel" id="xp-p-object" aria-labelledby="xt-object" hidden></div>
      <div class="xp-panel" role="tabpanel" id="xp-p-reach" aria-labelledby="xt-reach" hidden></div>
      <div class="xp-panel" role="tabpanel" id="xp-p-zones" aria-labelledby="xt-zones" hidden></div>
      <div class="xp-panel" role="tabpanel" id="xp-p-findings" aria-labelledby="xt-findings" hidden></div>
      <div class="xp-panel" role="tabpanel" id="xp-p-query" aria-labelledby="xt-query" hidden></div>
    </aside>
  </div>
</div>
<script src="/static/vendor/cytoscape.min.js" defer></script>
<script src="/static/explore.js" defer></script>"##,
                id = esc(&id),
                finding = esc(&finding),
                node = esc(&node),
                defs = esc(&forest_words()),
                forest_legend = forest_legend(),
                i_search = icon("i-search"),
                i_arrow = icon("i-arrow"),
                i_back =
                    r##"<svg class="ic flip" aria-hidden="true"><use href="#i-arrow"/></svg>"##,
            )
        }
    };
    Html(pages::shell(
        &ctx,
        Some(Nav::Explore),
        // As the rail names it; the shell adds the environment's name when
        // there are several.
        "Explore",
        "wide explore",
        &body,
    ))
    .into_response()
}

/// "Showing the run of Nov 5, 2026, 2:10 PM. The latest run, Nov 7, 2026,
/// 9:00 AM, can't be explored: its object index wasn't shared.": what
/// Explore's entry says when it opened `shown` because a later run of its
/// environment (`runs`, newest first) can't be explored. `None` when
/// `shown` is the latest.
pub fn fallback_words(
    ws: &crate::workspace::Workspace,
    runs: &[crate::workspace::RunSummary],
    shown: &crate::workspace::RunSummary,
) -> Option<String> {
    let latest = runs.first().filter(|r| r.id != shown.id)?;
    let why = ws.run_dir(&latest.id).and_then(|d| missing(&d))?;
    Some(format!(
        "Showing the run of {}. The latest run, {}, can't be explored: {}.",
        pathwarden_core::time::format_local(shown.created_at),
        pathwarden_core::time::format_local(latest.created_at),
        why.reason()
    ))
}

// ------------------------------------------------------------ API

async fn info(State(st): State<Shared>, Path(id): Path<String>) -> Response {
    with_run(&st, &id, |run| {
        let findings: Vec<Value> = run
            .x
            .meta
            .findings
            .iter()
            .take(FINDINGS_LISTED)
            .map(|f| {
                json!({
                    "fp": f.fingerprint,
                    "rule": f.rule,
                    "title": f.title,
                    "severity": f.severity,
                    "path": !f.path.is_empty(),
                    "suppressed": f.suppressed,
                })
            })
            .collect();
        Ok(json!({
            "objects": run.x.node_count(),
            "edges": run.x.edge_count(),
            "tier_zero": run.tier_zero.len(),
            "findings": findings,
            "findings_total": run.x.meta.findings.len(),
            "zones": run.x.meta.zones.iter().map(|z| &z.name).collect::<Vec<_>>(),
            "kinds": external_kinds(&run.x),
            "load_ms": run.load_ms,
            "load": { "objects_ms": run.objects_ms, "edges_ms": run.edges_ms, "edges_bytes": run.x.memory() },
            "limits": {
                "neighbors": NEIGHBOR_LIMIT,
                "reach_page": REACH_PAGE,
                "paths": MAX_PATHS,
            },
        }))
    })
    .await
}

/// What the mapping packs say about the run's external (OpenGraph) kinds,
/// for the explorer's labels, colors, icons and source filter. Native kinds
/// are left out (the page knows them). Colors and icons are checked again
/// here, so a planted graph file can't put anything else on the page.
fn external_kinds(x: &ExploreGraph) -> Value {
    let color_ok = |c: &str| {
        c.strip_prefix('#').is_some_and(|h| {
            (h.len() == 3 || h.len() == 6) && h.bytes().all(|b| b.is_ascii_hexdigit())
        })
    };
    let native_node = |n: &str| NodeKind::ALL.iter().any(|k| k.as_str() == n);
    let native_edge = |n: &str| EdgeKind::ALL.iter().any(|k| k.as_str() == n);
    let nodes: Vec<Value> = x
        .kinds_info
        .nodes
        .iter()
        .filter(|n| !native_node(&n.name))
        .map(|n| {
            json!({
                "name": n.name,
                "label": n.label,
                "icon": n.icon.as_deref().filter(|i| pathwarden_core::opengraph::pack::ICONS.contains(i)),
                "color": n.color.as_deref().filter(|c| color_ok(c)),
            })
        })
        .collect();
    let edges: Vec<Value> = x
        .kinds_info
        .edges
        .iter()
        // Native kinds only when a source added them (SYSVOL's edges).
        .filter(|e| !native_edge(&e.name) || !e.sources.is_empty())
        .map(|e| {
            json!({
                "name": e.name,
                "traversable": e.traversable,
                "pack": e.pack,
                "description": e.description,
                "sources": e.sources,
            })
        })
        .collect();
    json!({ "nodes": nodes, "edges": edges })
}

#[derive(Deserialize)]
struct NodeQuery {
    ix: Option<u32>,
}

fn kind_counts(n: &explore::Neighbors) -> Vec<(&'static str, usize)> {
    n.by_kind.iter().map(|(k, c)| (k.as_str(), *c)).collect()
}

async fn node(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<NodeQuery>,
) -> Response {
    let env_dir = env_dir(&st, &id);
    with_run(&st, &id, move |run| {
        let v = node_arg(run, q.ix)?;
        let owned = env_dir
            .and_then(|d| pathwarden_core::owned::load(&d).ok())
            .is_some_and(|ids| {
                ids.binary_search(&run.g.node(NodeIndex::new(v as usize)).id)
                    .is_ok()
            });
        let n = run.ex().node(v);
        let outn = run.x.neighbors(v, Dir::Out, &[], 0);
        let inn = run.x.neighbors(v, Dir::In, &[], 0);
        let tree = run.t0_tree();
        let next = tree.step(v).map(|e| run.out(e.to));
        Ok(json!({
            "node": run.out(v),
            "dn": n.props.distinguishedname,
            "tier_zero_reason": run.x.tier_zero_reason(v),
            "admin_count": run.x.has(v, flag::ADMIN_COUNT),
            "broad": run.x.has(v, flag::BROAD),
            "zones": run.x.zones_of(v),
            "out": kind_counts(&outn),
            "out_total": outn.total,
            "in": kind_counts(&inn),
            "in_total": inn.total,
            "t0_hops": if run.x.has(v, flag::TIER_ZERO) { None } else { tree.hops(v) },
            "t0_next": next,
            "owned": owned,
        }))
    })
    .await
}

#[derive(Deserialize)]
struct NeighborQuery {
    ix: Option<u32>,
    #[serde(default)]
    dir: String,
    #[serde(default)]
    kinds: String,
    limit: Option<usize>,
}

async fn neighbors(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<NeighborQuery>,
) -> Response {
    with_run(&st, &id, move |run| {
        let v = node_arg(run, q.ix)?;
        let dir = match q.dir.as_str() {
            "in" => Dir::In,
            "both" => Dir::Both,
            _ => Dir::Out,
        };
        let limit = q.limit.unwrap_or(NEIGHBOR_DEFAULT).clamp(1, NEIGHBOR_LIMIT);
        let n = run.x.neighbors(v, dir, &edge_kinds(&q.kinds), limit);
        let nodes = run.outs(std::iter::once(v).chain(n.edges.iter().flat_map(|e| [e.from, e.to])));
        Ok(json!({
            "center": v,
            "nodes": nodes,
            "edges": n.edges.iter().map(|e| run.ex().edge_out(e)).collect::<Vec<_>>(),
            "total": n.total,
            "shown": n.edges.len(),
            "by_kind": kind_counts(&n),
        }))
    })
    .await
}

#[derive(Deserialize)]
struct PathQuery {
    from: Option<u32>,
    #[serde(default)]
    to: String,
    k: Option<usize>,
}

fn paths_json(run: &Run, paths: &[Vec<Edge>]) -> Value {
    let nodes = run.outs(
        paths
            .iter()
            .flat_map(|p| p.iter().flat_map(|e| [e.from, e.to])),
    );
    json!({
        "paths": paths
            .iter()
            .map(|p| p.iter().map(|e| run.ex().edge_out(e)).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "nodes": nodes,
    })
}

async fn path(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
) -> Response {
    with_run(&st, &id, move |run| {
        let from = node_arg(run, q.from)?;
        let k = q.k.unwrap_or(1).clamp(1, MAX_PATHS);
        let to_t0 = q.to.is_empty() || q.to.eq_ignore_ascii_case("t0");
        let mut through = None;
        let paths = if to_t0 {
            if k == 1 {
                run.t0_tree().path(from).into_iter().collect()
            } else {
                run.x.k_shortest_paths(from, &run.tier_zero, k)
            }
        } else {
            let to = node_arg(run, q.to.parse().ok())?;
            let found = if k == 1 {
                run.x.shortest_path(from, &[to]).into_iter().collect()
            } else {
                run.x.k_shortest_paths(from, &[to], k)
            };
            // None that avoids Tier Zero: the path up to the first Tier
            // Zero object, which controls the target.
            if found.is_empty() {
                if let Some(p) = run.x.path_through_tier_zero(from, to) {
                    let name = &run.g.node(NodeIndex::new(to as usize)).name;
                    through = Some(pathwarden_core::analysis::through_tier_zero_line(name));
                    vec![p]
                } else {
                    found
                }
            } else {
                found
            }
        };
        let mut v = paths_json(run, &paths);
        v["from"] = json!(from);
        if let Some(line) = through {
            v["through_tier_zero"] = json!(line);
        }
        if paths.is_empty() {
            v["note"] = json!(if to_t0 {
                "No attack path from this object to Tier Zero."
            } else {
                "No attack path between these objects."
            });
        }
        Ok(v)
    })
    .await
}

#[derive(Deserialize)]
struct ReachQuery {
    ix: Option<u32>,
    offset: Option<usize>,
    limit: Option<usize>,
    class: Option<u8>,
}

async fn reach(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<ReachQuery>,
) -> Response {
    with_run(&st, &id, move |run| {
        let v = node_arg(run, q.ix)?;
        let cached = run
            .reach
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|(t, _)| *t == v)
            .map(|(_, l)| l.clone());
        let list = match cached {
            Some(l) => l,
            None => {
                let l = Arc::new(run.ex().reach_list(v));
                *run.reach.lock().unwrap_or_else(|e| e.into_inner()) = Some((v, l.clone()));
                l
            }
        };
        let limit = q.limit.unwrap_or(100).clamp(1, REACH_PAGE);
        let page = run
            .ex()
            .reach_page(v, &list, q.class, q.offset.unwrap_or(0), limit);
        serde_json::to_value(page).map_err(|e| ApiError::bad(&e.to_string()))
    })
    .await
}

#[derive(Deserialize)]
struct SearchQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    kinds: String,
}

async fn search(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<SearchQuery>,
) -> Response {
    let query: String = q.q.chars().take(200).collect();
    let kinds: Vec<NodeKind> = q
        .kinds
        .split(',')
        .filter(|k| !k.trim().is_empty())
        .take(16)
        .map(|k| NodeKind::from_object_type(k.trim()))
        .collect();
    with_run(&st, &id, move |run| {
        Ok(json!({ "results": run.ex().search(&query, &kinds, run_data::SEARCH_LIMIT) }))
    })
    .await
}

#[derive(Deserialize)]
struct FindingQuery {
    #[serde(default)]
    fp: String,
}

async fn finding(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<FindingQuery>,
) -> Response {
    with_run(&st, &id, move |run| {
        let Some((i, f)) = run.x.finding(&q.fp) else {
            return Err(ApiError(
                StatusCode::NOT_FOUND,
                "That finding is not in this run.".into(),
            ));
        };
        let all = &run.x.meta.findings;
        let take = |l: &[u32]| {
            l.iter()
                .copied()
                .take(FINDING_OBJECTS)
                .collect::<Vec<u32>>()
        };
        let (entry, affected, hits) = (take(&f.entry), take(&f.affected), take(&f.hits));
        let edges: Vec<EdgeOut> = f
            .path
            .windows(2)
            .zip(&f.path_edges)
            .map(|(w, k)| {
                let kind = EdgeKind::from_name_or_external(k).unwrap_or(EdgeKind::MemberOf);
                let e = run.x.edge(w[0], w[1], kind).unwrap_or(Edge {
                    from: w[0],
                    to: w[1],
                    kind,
                    inherited: false,
                });
                run.ex().edge_out(&e)
            })
            .collect();
        let nodes = run.outs(
            f.path
                .iter()
                .chain(&entry)
                .chain(&affected)
                .chain(&hits)
                .copied(),
        );
        // A finding with no path is drawn as its objects. Where the finding
        // is about a relationship among them (a Tier Zero account's
        // sessions, PW-004), those edges come too; any other edge would
        // only cross the grid.
        let link_kinds = link_kinds(&f.rule);
        let links: Vec<EdgeOut> = if f.path.is_empty() && !link_kinds.is_empty() {
            let shown: std::collections::BTreeSet<u32> = entry
                .iter()
                .chain(&affected)
                .chain(&hits)
                .copied()
                .collect();
            shown
                .iter()
                .flat_map(|&v| run.x.out_edges(v))
                .filter(|e| e.from != e.to && shown.contains(&e.to) && link_kinds.contains(&e.kind))
                .map(|e| run.ex().edge_out(&e))
                .collect()
        } else {
            Vec::new()
        };
        Ok(json!({
            "finding": {
                "fp": f.fingerprint,
                "rule": f.rule,
                "title": f.title,
                "severity": f.severity,
                "summary": f.summary,
                "domain": f.domain,
                "suppressed": f.suppressed,
                "attack_path": f.attack_path,
                "exposure": f.exposure,
                "exposed": f.exposed,
                "everyone": f.everyone,
                "entry_total": f.entry_total,
                "affected_total": f.affected_total,
                "hits_total": f.hits_total,
            },
            "position": i,
            "count": all.len(),
            "prev": i.checked_sub(1).map(|p| &all[p].fingerprint),
            "next": all.get(i + 1).map(|n| &n.fingerprint),
            "path": { "nodes": f.path, "edges": edges },
            "links": links,
            "entry": entry,
            "affected": affected,
            "hits": hits,
            "nodes": nodes,
        }))
    })
    .await
}

// ------------------------------------------------------- suggestions

/// [`Explorer::suggestions`], with the headline counts from the run's own
/// posture (its summary), so they are the numbers the report, the dashboard
/// and the CLI show. Without a summary that records them, the explore
/// graph's own counts.
fn build_suggestions(run: &Run) -> Value {
    let saved: Option<crate::workspace::RunSummary> = crate::workspace::summary_file(&run.dir)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok());
    let headline = saved.map(|r| (r.exposed, r.relevant_pop()));
    let answer: SuggestionsAnswer = run.ex().suggestions(run.t0_tree(), headline);
    serde_json::to_value(answer).unwrap_or(Value::Null)
}

async fn suggestions(State(st): State<Shared>, Path(id): Path<String>) -> Response {
    with_run(&st, &id, |run| {
        Ok(run
            .suggestions
            .get_or_init(|| build_suggestions(run))
            .clone())
    })
    .await
}

/// The run's domains and trusts ([`pathwarden_core::forest::ForestMap`])
/// with their headline, as `pathwarden summary --json` gives them under
/// `forest`: what the Forest view draws. Runs saved before the map was
/// kept ask to be analyzed again.
async fn forest(State(st): State<Shared>, Path(id): Path<String>) -> Response {
    with_run_or_old(&st, &id, |run| {
        let map =
            (run.x.meta.forest.as_ref()).ok_or(Failure::Old(pathwarden_core::forest::NOT_KEPT))?;
        serde_json::to_value(map.document()).map_err(|e| {
            Failure::Api(ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("The forest map couldn't be written ({e})."),
            ))
        })
    })
    .await
}

#[derive(Deserialize)]
struct CrossingQuery {
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: String,
}

/// The rights principals of domain `from` hold in domain `to`, as the
/// forest map lists them ([`pathwarden_core::forest::Crossing::rights`]),
/// as objects and relationships to draw: the Forest view's "Show".
/// `pathwarden summary --rights` lists the same.
async fn crossing(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<CrossingQuery>,
) -> Response {
    with_run_or_old(&st, &id, move |run| {
        let map =
            (run.x.meta.forest.as_ref()).ok_or(Failure::Old(pathwarden_core::forest::NOT_KEPT))?;
        let c = map
            .trusts
            .iter()
            .flat_map(|t| &t.crossing)
            .chain(&map.indirect)
            .find(|c| c.from.eq_ignore_ascii_case(&q.from) && c.to.eq_ignore_ascii_case(&q.to))
            .ok_or_else(|| {
                Failure::Api(ApiError(
                    StatusCode::NOT_FOUND,
                    "Nothing in this run crosses between those domains.".into(),
                ))
            })?;
        let mut edges = Vec::new();
        for r in &c.rights {
            let (Some(a), Some(b), Some(kind)) = (
                run.g.lookup(&r.from),
                run.g.lookup(&r.to),
                EdgeKind::from_name_or_external(&r.kind),
            ) else {
                continue;
            };
            let (a, b) = (a.index() as u32, b.index() as u32);
            let e = run.x.edge(a, b, kind).unwrap_or(Edge {
                from: a,
                to: b,
                kind,
                inherited: false,
            });
            edges.push(e);
        }
        let nodes = run.outs(edges.iter().flat_map(|e| [e.from, e.to]));
        Ok(json!({
            "from": c.from,
            "to": c.to,
            "counts": c.counts_text(),
            "counted": c.memberships + c.admin_rights + c.aces + c.sid_history,
            "listed": c.rights.len(),
            "nodes": nodes,
            "edges": edges.iter().map(|e| run.ex().edge_out(e)).collect::<Vec<_>>(),
        }))
    })
    .await
}

// ------------------------------------------------------- zone drafts

/// A zone handed from the explorer to the Zone wizard, kept for
/// [`DRAFT_TTL`]. Nothing is written until the user saves in the wizard.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ZoneDraft {
    pub name: String,
    pub members: Vec<String>,
    pub groups: Vec<String>,
    pub ous: Vec<String>,
}

const DRAFT_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_DRAFTS: usize = 32;
const MAX_DRAFT_ENTRIES: usize = 2_000;

// ------------------------------------------------------------ queries

/// Most rows the Query tab shows (the CLI's `--limit` has no such default).
pub const QUERY_ROWS: usize = 1_000;

/// The longest query the Query tab takes.
pub const MAX_QUERY_BYTES: usize = 64 * 1024;

/// The folder of the environment run `id` belongs to (owned marks are kept
/// there).
fn env_dir(st: &AppState, id: &str) -> Option<PathBuf> {
    let ws = st.ws();
    let summary = ws.run(id)?;
    Some(ws.for_run(&summary).env_dir())
}

/// The Query tab's request: Cypher, or a prepared query by its GUID (the
/// server runs its pinned text, so the page never sends it).
#[derive(Deserialize)]
struct QueryBody {
    #[serde(default)]
    cypher: Option<String>,
    #[serde(default)]
    prepared: Option<String>,
}

/// `GET /api/prepared`: the prepared queries, as `pathwarden query
/// --list-prepared --json` prints them.
async fn prepared_list() -> Response {
    Json(pathwarden_core::prepared::listing()).into_response()
}

/// The Cypher a [`QueryBody`] asks for, or why it can't run.
fn query_text(body: &QueryBody) -> Result<String, String> {
    match (&body.prepared, &body.cypher) {
        (Some(guid), _) => {
            let Some(q) = pathwarden_core::prepared::library().by_guid(guid) else {
                return Err("There is no such prepared query.".into());
            };
            if let Some(why) = &q.reason {
                return Err(why.clone());
            }
            if q.edit_first {
                return Err(
                    "This query has a placeholder to replace first. Open it as Cypher and edit it."
                        .into(),
                );
            }
            Ok(q.query.clone())
        }
        (None, Some(c)) => Ok(c.clone()),
        (None, None) => Err("Write a query first.".into()),
    }
}

/// What the Query tab shows of how many objects are marked as owned (none,
/// with why, when the marks can't be read).
fn owned_json(env_dir: Option<&FsPath>) -> Value {
    match env_dir.map(pathwarden_core::owned::load) {
        Some(Err(e)) => json!({ "count": 0, "text": e.to_string() }),
        Some(Ok(ids)) => {
            json!({ "count": ids.len(), "text": pathwarden_core::owned::summary(ids.len()) })
        }
        None => json!({ "count": 0, "text": pathwarden_core::owned::summary(0) }),
    }
}

/// Queries running at once: more wait their turn.
static QUERIES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// `POST /api/runs/<id>/explore/query`: the Query tab's Cypher, on the
/// run, with the environment's owned marks: the answer `pathwarden query
/// --run --json` prints, and what to draw for each returned path.
async fn query(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Json(body): Json<QueryBody>,
) -> Response {
    let env_dir = env_dir(&st, &id);
    let text = match query_text(&body) {
        Ok(t) => t,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e, false),
    };
    if text.len() > MAX_QUERY_BYTES {
        return error(StatusCode::BAD_REQUEST, "The query is too long.", false);
    }
    let Ok(_turn) = QUERIES.acquire().await else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Queries are stopped.",
            false,
        );
    };
    with_run(&st, &id, move |run| {
        use pathwarden_core::cypher;
        let (ids, owned_note) = env_dir
            .as_deref()
            .map(pathwarden_core::owned::for_query)
            .unwrap_or_default();
        let props = run_data::props(&run.dir);
        let view =
            cypher::RunView::new(&run.g, &run.x, run_data::props_ref(&props)).with_owned(&ids);
        let limits = cypher::EvalLimits {
            max_rows: QUERY_ROWS,
            ..Default::default()
        };
        let mut result =
            cypher::run(&view, &text, &limits).map_err(|e| ApiError::bad(&e.message()))?;
        result.warnings.extend(owned_note);
        // Each path as the graph draws it: from its start, the way it runs.
        let mut draw = Vec::new();
        let mut shown: Vec<u32> = Vec::new();
        for cell in result.paths() {
            let Some(p) = cypher::attack_path(&view, cell) else {
                continue;
            };
            let edges: Vec<Edge> = p
                .edges
                .iter()
                .filter_map(|e| run.x.edge_at(e.index() as u32))
                .collect();
            let nodes: Vec<u32> = match (edges.first(), p.steps.first()) {
                (Some(first), Some(step)) => {
                    let mut v = vec![if step.backward { first.to } else { first.from }];
                    for (e, s) in edges.iter().zip(&p.steps) {
                        v.push(if s.backward { e.from } else { e.to });
                    }
                    v
                }
                _ => match cell {
                    cypher::Cell::Path { nodes, .. } => nodes
                        .iter()
                        .filter_map(|id| run.g.lookup(id).map(|ix| ix.index() as u32))
                        .collect(),
                    _ => Vec::new(),
                },
            };
            shown.extend(&nodes);
            draw.push(json!({
                "nodes": nodes,
                "edges": edges.iter().map(|e| run.ex().edge_out(e)).collect::<Vec<_>>(),
            }));
        }
        // The objects of node columns, once each, in row order.
        let mut objects: Vec<u32> = Vec::new();
        for cell in result.rows.iter().flatten() {
            if let cypher::Cell::Node { id } = cell {
                if let Some(ix) = run.g.lookup(id) {
                    let v = ix.index() as u32;
                    if !objects.contains(&v) && objects.len() < QUERY_ROWS {
                        objects.push(v);
                    }
                }
            }
        }
        shown.extend(&objects);
        shown.sort_unstable();
        shown.dedup();
        let answer = serde_json::to_value(cypher::Answer {
            view: &view,
            result: &result,
        })
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        Ok(json!({
            "answer": answer,
            "draw": draw,
            "objects": objects,
            "nodes": run.outs(shown),
            "owned": owned_json(env_dir.as_deref()),
        }))
    })
    .await
}

/// `GET /api/runs/<id>/explore/owned`: how many objects the run's
/// environment marks as owned.
async fn owned(State(st): State<Shared>, Path(id): Path<String>) -> Response {
    if st.ws().run_dir(&id).is_none() {
        return error(StatusCode::NOT_FOUND, "That run no longer exists.", false);
    }
    Json(owned_json(env_dir(&st, &id).as_deref())).into_response()
}

#[derive(Deserialize)]
struct OwnedBody {
    ix: u32,
    owned: bool,
}

/// `POST /api/runs/<id>/explore/owned`: the Object tab's "Mark as owned"
/// and "Not owned", kept for the run's environment.
async fn set_owned(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Json(body): Json<OwnedBody>,
) -> Response {
    let Some(env_dir) = env_dir(&st, &id) else {
        return error(StatusCode::NOT_FOUND, "That run no longer exists.", false);
    };
    with_run(&st, &id, move |run| {
        let v = node_arg(run, Some(body.ix))?;
        let oid = run.g.node(NodeIndex::new(v as usize)).id.clone();
        let n = pathwarden_core::owned::set(&env_dir, &[oid], body.owned)
            .map_err(|e| ApiError(StatusCode::CONFLICT, e))?;
        Ok(json!({
            "owned": body.owned,
            "count": n,
            "text": pathwarden_core::owned::summary(n),
        }))
    })
    .await
}

static DRAFTS: Mutex<Vec<(String, Instant, ZoneConfig)>> = Mutex::new(Vec::new());

fn draft_id() -> String {
    let mut b = [0u8; 12];
    let _ = getrandom::getrandom(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn cap_list(list: Vec<String>) -> Vec<String> {
    list.into_iter()
        .take(MAX_DRAFT_ENTRIES)
        .map(|s| s.trim().chars().take(2048).collect::<String>())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn save_draft(Json(d): Json<ZoneDraft>) -> Response {
    let zone = ZoneConfig {
        name: d.name.trim().chars().take(100).collect(),
        members: cap_list(d.members),
        groups: cap_list(d.groups),
        ous: cap_list(d.ous),
        ..Default::default()
    };
    if zone.members.is_empty() && zone.groups.is_empty() && zone.ous.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "Pick at least one object for the zone.",
            false,
        );
    }
    let id = draft_id();
    let mut drafts = DRAFTS.lock().unwrap_or_else(|e| e.into_inner());
    drafts.retain(|(_, at, _)| at.elapsed() < DRAFT_TTL);
    if drafts.len() >= MAX_DRAFTS {
        drafts.remove(0);
    }
    drafts.push((id.clone(), Instant::now(), zone));
    Json(json!({ "draft": id, "url": format!("/zones/new?draft={id}") })).into_response()
}

/// The draft `id`, if it is still fresh (the Zone wizard pre-fills from it).
pub fn draft(id: &str) -> Option<ZoneConfig> {
    let drafts = DRAFTS.lock().unwrap_or_else(|e| e.into_inner());
    drafts
        .iter()
        .find(|(d, at, _)| d == id && at.elapsed() < DRAFT_TTL)
        .map(|(_, _, z)| z.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path's end is drawn as a Tier Zero target only when it is Tier
    /// Zero: a query's or Path between's end may be any object.
    #[test]
    fn only_a_tier_zero_end_is_a_tier_zero_target() {
        let marks: Vec<&str> = EXPLORE_JS
            .lines()
            .filter(|l| l.contains(r#"addClass("target")"#) || l.contains(r#"" target""#))
            .collect();
        assert!(marks.len() >= 3, "{marks:?}");
        for l in marks {
            assert!(l.contains("t0"), "an end marked without Tier Zero: {l}");
        }
    }

    /// Edge heads stop clear of the target's border and Tier Zero outline,
    /// so the direction shows; they were drawn under it.
    #[test]
    fn edge_heads_stop_clear_of_the_node() {
        assert!(EXPLORE_JS.contains(r#""target-distance-from-node": 7"#));
        assert!(EXPLORE_JS.contains(r#""target-arrow-fill": "filled", "arrow-scale": 1.35"#));
    }

    /// Bundles are worked out on every change of the graph, not per
    /// view (tests/js/explore.test.mjs tests what they are).
    #[test]
    fn bundles_follow_the_graph() {
        assert!(EXPLORE_JS.contains("var BUNDLE_MAX = 3;"));
        assert!(EXPLORE_JS.contains(r#"cy.on("add remove", "edge", queueBundles);"#));
        assert!(!EXPLORE_JS.contains(r#"links.length > 3 ? "nolabel""#));
        assert!(EXPLORE_JS.contains(r#""arrow-scale": 1.8"#));
    }

    #[test]
    fn fingerprints_are_cleaned() {
        assert_eq!(
            clean_fingerprint("PW-001-0123abcd").as_deref(),
            Some("PW-001-0123abcd")
        );
        assert_eq!(clean_fingerprint("\"><script>"), None);
        assert_eq!(clean_fingerprint(""), None);
        assert_eq!(clean_fingerprint(&"a".repeat(200)), None);
    }

    #[test]
    fn edge_kind_lists() {
        assert_eq!(
            edge_kinds("AdminTo, genericall,nope,"),
            vec![EdgeKind::AdminTo, EdgeKind::GenericAll]
        );
        assert!(edge_kinds("").is_empty());
    }
}
