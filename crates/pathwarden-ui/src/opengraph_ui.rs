//! OpenGraph in the UI (`docs/opengraph.md`): what specialist collectors
//! (TaskHound, MSSQLHound, ...) added to a run, how far each is trusted, and
//! whether its findings can ever be marked fixed.
//!
//! - **Detected sources** on Analyze, before anything is analyzed: the page
//!   sends the ends of each chosen `.json` file (`/api/opengraph/sniff`) and
//!   shows which are OpenGraph, the mapping pack that applies, and whether a
//!   coverage file came with them. For an OpenGraph file without one, a
//!   form declares what the collector scanned; the upload carries it, and
//!   the server writes a `pathwarden.coverage.v1` sidecar asserted by the
//!   user and bound to the file it received by SHA-256
//!   ([`write_declarations`]).
//! - **Other sources** in the run page's Run details ([`details_row`]),
//!   from the ingest statistics saved with the run ([`SOURCES_FILE`]):
//!   nodes and edges kept, caps hit, mapping and coverage.
//! - **Mappings** (Configure): the built-in and `[[mapping]]` packs, their
//!   kinds, and marking a reviewed pack trusted (`[opengraph] trust`), only
//!   after an explicit confirmation.
//!
//! Every name here comes from a hostile file or a pack: all of it is
//! escaped, and colors are used only after validation, as SVG attributes.

use std::fmt::Write;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pathwarden_core::ingest::{self, OpenGraphStats, Sniffed};
use pathwarden_core::opengraph::coverage::{self, CoverageState, Declaration, Sidecar};
use pathwarden_core::opengraph::trust::{
    edge_facts, packs_in_effect, trust_change, PackEntry, TrustChange,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::pages::{self, esc, icon, num, Nav};
use crate::run_details::{Go, Row, OTHER_SOURCES_ROW};
use crate::server::AppState;
use pathwarden_core::text::bidi_safe;

type Shared = Arc<AppState>;

/// The run's OpenGraph statistics (`OpenGraphStats` as JSON), saved with
/// runs that had OpenGraph files.
pub const SOURCES_FILE: &str = "opengraph.json";

const OG_JS: &str = include_str!("assets/opengraph.js");
const OG_CSS: &str = include_str!("assets/opengraph.css");

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/opengraph/sniff", post(sniff))
        .route("/mappings", get(mappings_page))
        .route("/api/mappings/trust", post(set_trust))
        .route(
            "/static/opengraph.js",
            get(|| async { ([(header::CONTENT_TYPE, "text/javascript")], OG_JS) }),
        )
        .route(
            "/static/opengraph.css",
            get(|| async { ([(header::CONTENT_TYPE, "text/css")], OG_CSS) }),
        )
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

/// A label's last part: uploads live at `uploads/<run>/<n>/<name>`, zip
/// entries are `archive.zip!entry.json`.
fn base_name(label: &str) -> &str {
    label.rsplit(['/', '\\']).next().unwrap_or(label)
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", num(n), if n == 1 { one } else { many })
}

// ------------------------------------------------------------ packs

/// The packs in effect for the workspace's config (built-in, then
/// `[[mapping]]`, trust applied), and `[[mapping]]` packs that were refused.
pub(crate) fn packs(st: &AppState) -> (Vec<PackEntry>, Vec<(String, String)>) {
    let loaded = crate::settings::load(st);
    packs_in_effect(&loaded.config, &st.ws().env_dir())
}

/// The pack that applies to a source (the last that claims it, as the
/// reader picks it).
fn pack_for<'a>(packs: &'a [PackEntry], source: &str) -> Option<&'a PackEntry> {
    packs.iter().rev().find(|p| p.pack.claims(source))
}

/// "Trusted mapping" and what it means, as a pill and a sentence.
fn trust_line(pack: Option<(&str, bool)>) -> String {
    match pack {
        Some((title, true)) => format!(
            r#"<span class="og-pill og-trusted">Trusted mapping</span> <span class="og-why">{} pack: its mapped relationships make attack paths and findings.</span>"#,
            esc(title)
        ),
        Some((title, false)) => format!(
            r#"<span class="og-pill og-context">Untrusted mapping: context only</span> <span class="og-why">{} pack labels its kinds; nothing from it is part of a path until the pack is trusted on <a href="/mappings">Mappings</a>.</span>"#,
            esc(title)
        ),
        None => r#"<span class="og-pill og-context">No mapping: context only</span> <span class="og-why">Shown in Explore; never part of a path, finding or plan.</span>"#.to_string(),
    }
}

// ------------------------------------------------------------ Run details

/// The JSON saved with a run, when it had OpenGraph files.
pub fn file_for(stats: &OpenGraphStats) -> Option<Vec<u8>> {
    if stats.is_empty() {
        return None;
    }
    serde_json::to_vec(stats).ok()
}

/// The run's OpenGraph statistics, if it had OpenGraph files (blocking).
pub fn read_stats(run_dir: &FsPath) -> Option<OpenGraphStats> {
    let path = run_dir.join(SOURCES_FILE);
    let f = std::fs::File::open(path).ok()?;
    let mut text = Vec::new();
    // Written by Pathwarden; the cap only stops a planted file.
    f.take(64 << 20).read_to_end(&mut text).ok()?;
    serde_json::from_slice(&text).ok()
}

/// The words of a source's mapping: trusted or not, its pack, and what
/// that means.
fn mapping_words(pack: Option<(&str, bool)>) -> String {
    match pack {
        Some((title, true)) => format!(
            "Trusted, {} pack: its mapped relationships make attack paths and findings.",
            bidi_safe(title)
        ),
        Some((title, false)) => format!(
            "Untrusted, context only: the {} pack labels its kinds; nothing from it is part of a path until the pack is trusted on Mappings.",
            bidi_safe(title)
        ),
        None => "No mapping, context only: shown in Explore; never part of a path, finding or plan."
            .to_string(),
    }
}

/// The "Other sources" row of Run details ([`crate::run_details::rows`]),
/// from a finished run's statistics: each specialist collector's
/// OpenGraph source read with the run's AD data (its files, objects,
/// relationships kept and dropped, whether it was read whole, its mapping
/// and coverage), relationship kinds no pack describes, coverage files not
/// used, and what that means for retests. It needs a look when a source
/// was read only partly or has no usable coverage. None without any.
pub fn details_row(s: &OpenGraphStats) -> Option<Row> {
    if s.is_empty() {
        return None;
    }
    let mut facts = Vec::new();
    let mut warn = false;
    let mut without_coverage = Vec::new();
    for src in &s.sources {
        let name = bidi_safe(&src.name).into_owned();
        let title = s
            .packs
            .iter()
            .find(|p| Some(&p.name) == src.pack.as_ref())
            .map(|p| p.title.as_str());
        let pack = src
            .pack
            .as_ref()
            .map(|n| (title.unwrap_or(n.as_str()), src.trusted));
        let files: Vec<String> = src
            .files
            .iter()
            .map(|f| bidi_safe(base_name(f)).into_owned())
            .collect();
        facts.push((
            "Source",
            if files.is_empty() {
                format!("{name}, OpenGraph")
            } else {
                format!(
                    "{name}, OpenGraph · {}: {}",
                    plural(files.len(), "file", "files"),
                    files.join(", ")
                )
            },
            false,
        ));
        facts.push((
            "Objects",
            format!(
                "{} read: {} matched to AD, {} new, {} unknown",
                num(src.nodes),
                num(src.merged),
                num(src.created),
                num(src.placeholders)
            ),
            false,
        ));
        facts.push((
            "Relationships kept",
            if src.context_edges > 0 {
                format!(
                    "{} ({} context only)",
                    num(src.edges),
                    num(src.context_edges)
                )
            } else {
                num(src.edges)
            },
            false,
        ));
        let mut dropped = Vec::new();
        if src.dropped_native > 0 {
            dropped.push(format!(
                "{} AD relationships (only AD data may say them)",
                num(src.dropped_native)
            ));
        }
        if src.unresolved > 0 {
            dropped.push(format!("{} with an end not found", num(src.unresolved)));
        }
        if src.dropped_secrets > 0 {
            dropped.push(format!(
                "{} secret-looking properties",
                num(src.dropped_secrets)
            ));
        }
        if src.invalid + src.oversized > 0 {
            dropped.push(format!(
                "{} invalid or oversized records",
                num(src.invalid + src.oversized)
            ));
        }
        if !dropped.is_empty() {
            facts.push(("Dropped", dropped.join("; "), false));
        }
        if let Some(words) = src.not_modeled() {
            facts.push(("Not modeled", words, false));
        }
        let read = if src.complete {
            "Read whole".to_string()
        } else {
            warn = true;
            let mut why: Vec<String> = src
                .caps_hit
                .iter()
                .map(|c| format!("limit hit: {c}"))
                .collect();
            why.extend(src.errors.iter().map(|e| base_name(e).to_string()));
            bidi_safe(&format!("Read only partly ({})", why.join("; "))).into_owned()
        };
        facts.push(("Read", read, false));
        facts.push(("Mapping", mapping_words(pack), false));
        let c = &src.coverage;
        let unfinished = if c.complete {
            ""
        } else {
            ", collection not finished"
        };
        let coverage = match c.state {
            CoverageState::Sidecar => {
                let mut what = Vec::new();
                if !c.all_in_domains.is_empty() {
                    what.push(format!(
                        "every enabled computer in {}",
                        c.all_in_domains.join(", ")
                    ));
                }
                if !c.ok.is_empty() {
                    what.push(plural(c.ok.len(), "computer listed", "computers listed"));
                }
                if !c.failed.is_empty() {
                    what.push(format!("{} failed", num(c.failed.len())));
                }
                let by = match c.asserted_by.as_deref() {
                    Some("user") => "declared by a person",
                    Some("plugin") => "written by the collector plugin",
                    _ => "from the collector",
                };
                let what = if what.is_empty() {
                    String::new()
                } else {
                    format!(": {}", what.join(", "))
                };
                format!("Coverage file bound, {by}{unfinished}{what}.")
            }
            CoverageState::Collector => format!(
                "From the collector: {}{unfinished}.",
                plural(c.ok.len(), "tenant", "tenants")
            ),
            CoverageState::Invalid => {
                warn = true;
                let notes = c.notes.join(" ");
                if notes.trim().is_empty() {
                    "Coverage file not usable.".to_string()
                } else {
                    format!("Coverage file not usable. {}", notes.trim())
                }
            }
            CoverageState::None => {
                warn = true;
                without_coverage.push(name.clone());
                "No coverage file. Its findings can open, but are never marked Fixed: a missing finding could be a host the collector didn't reach.".to_string()
            }
        };
        facts.push(("Coverage", bidi_safe(&coverage).into_owned(), false));
    }
    let mut text = Vec::new();
    if !s.unmapped_kinds.is_empty() {
        let kinds: Vec<String> = s
            .unmapped_kinds
            .iter()
            .take(40)
            .map(|(k, n)| format!("{} {}", bidi_safe(k), num(*n)))
            .collect();
        text.push(format!(
            "Relationship kinds no pack describes (context only): {}{}.",
            kinds.join(", "),
            if s.unmapped_kinds.len() > 40 {
                ", …"
            } else {
                ""
            }
        ));
    }
    if !s.unused_sidecars.is_empty() {
        let list: Vec<String> = s
            .unused_sidecars
            .iter()
            .map(|u| bidi_safe(base_name(u)).into_owned())
            .collect();
        text.push(format!("Coverage files not used: {}.", list.join("; ")));
    }
    if !s.sources.is_empty() {
        text.push(if without_coverage.is_empty() {
            "For retests: Findings that rest on these sources are marked Fixed only when this coverage says the affected host was scanned again.".to_string()
        } else {
            format!(
                "For retests: Findings that rest on {} can't be marked Fixed by a later run or retest: without coverage, their absence proves nothing. To declare what was scanned, analyze the files again from Analyze and fill in the coverage form under Detected sources.",
                crate::run_details::and_list(&without_coverage)
            )
        });
    }
    Some(Row {
        title: OTHER_SOURCES_ROW,
        status: details_status(s),
        warn,
        facts,
        text,
        go: (!s.sources.is_empty()).then_some(Go::Mappings),
        ..Row::default()
    })
}

/// The "Other sources" row's status: the sources' names (past three, the
/// first two and how many more) and how their mappings are trusted.
fn details_status(s: &OpenGraphStats) -> String {
    let names: Vec<String> = s
        .sources
        .iter()
        .map(|x| bidi_safe(&x.name).into_owned())
        .collect();
    let shown = match names.len() {
        0 => return "Coverage files not used".to_string(),
        1..=3 => names.join(", "),
        n => format!("{} and {} more", names[..2].join(", "), n - 2),
    };
    let untrusted = s.sources.iter().filter(|x| !x.trusted).count();
    let trust = match (s.sources.as_slice(), untrusted) {
        ([_], 0) => "trusted mapping".to_string(),
        (_, 0) => "trusted mappings".to_string(),
        ([one], _) if one.pack.is_none() => "no mapping".to_string(),
        ([_], _) => "untrusted mapping".to_string(),
        (_, n) => plural(n, "untrusted mapping", "untrusted mappings"),
    };
    format!("{shown} · {trust}")
}

// ------------------------------------------------------------ sniffing

/// Most files the upload panel looks at.
const SNIFF_FILES: usize = 40;

#[derive(Deserialize)]
struct SniffRequest {
    files: Vec<SniffFile>,
}

#[derive(Deserialize)]
struct SniffFile {
    name: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    head: String,
    #[serde(default)]
    tail: String,
}

/// What one chosen file is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Chosen {
    /// Collector data, with its `meta.type` (`users`, `azure`, ...).
    Collector(String),
    Zip,
    /// OpenGraph, with its source name (or `None` when the file's ends
    /// don't say).
    OpenGraph(Option<String>),
    /// A coverage sidecar, with the payload file names it lists (when it
    /// was small enough to read here).
    Sidecar(Vec<String>),
    Other,
}

/// The source an OpenGraph file names: `metadata.source_kind`, else a
/// pack's source kind among its node kinds (as the reader decides).
fn source_of(sk: Option<String>, head: &str, packs: &[PackEntry]) -> Option<String> {
    // The reader takes the first claimed kind of the first node that has
    // one: in the text, the earliest claimed kind name.
    sk.or_else(|| {
        packs
            .iter()
            .flat_map(|p| p.pack.source_kinds())
            .filter_map(|s| head.find(&format!("\"{s}\"")).map(|at| (at, s)))
            .min_by_key(|(at, _)| *at)
            .map(|(_, s)| s.clone())
    })
}

fn classify(f: &SniffFile, packs: &[PackEntry]) -> Chosen {
    let lower = f.name.to_ascii_lowercase();
    if lower.ends_with(".zip") {
        return Chosen::Zip;
    }
    if coverage::is_sidecar_name(&f.name) {
        let whole = f.size > 0 && f.size as usize <= f.head.len();
        let payloads = whole
            .then(|| Sidecar::parse(f.head.as_bytes()).ok())
            .flatten()
            .map(|s| s.payloads.into_iter().map(|p| p.file).collect())
            .unwrap_or_default();
        return Chosen::Sidecar(payloads);
    }
    let cap = |s: &str| -> Vec<u8> {
        let b = s.as_bytes();
        b[..b.len().min(ingest::SNIFF_BYTES)].to_vec()
    };
    let (head, tail) = (cap(&f.head), cap(&f.tail));
    match ingest::sniff(&head, &tail) {
        Sniffed::Collector(kind) => Chosen::Collector(kind),
        Sniffed::OpenGraph { source_kind } => {
            Chosen::OpenGraph(source_of(source_kind, &f.head, packs))
        }
        Sniffed::Unknown => Chosen::Other,
    }
}

/// What a chosen file is, in a few words, for its row in the file list
/// (the Collect page's "Analyze other data with it"): "AzureHound:
/// Entra ID", "OpenGraph: TaskHound", "SharpHound". From the file's ends,
/// as [`classify`] reads them.
fn kind_label(f: &SniffFile, packs: &[PackEntry]) -> String {
    match classify(f, packs) {
        Chosen::Collector(kind) if kind.eq_ignore_ascii_case("azure") => {
            "AzureHound: Entra ID".into()
        }
        Chosen::Collector(_) => "SharpHound".into(),
        Chosen::Zip => "Archive".into(),
        Chosen::OpenGraph(Some(source)) => format!("OpenGraph: {source}"),
        Chosen::OpenGraph(None) => "OpenGraph".into(),
        Chosen::Sidecar(_) => "Coverage file".into(),
        Chosen::Other => "Not recognized".into(),
    }
}

/// `/api/opengraph/sniff`: the Detected sources panel for the files chosen
/// on Analyze (`{files: [{name, size, head, tail}]}`, the first and last
/// 64 KiB of each). Answers `{html, opengraph, kinds}`; `opengraph` is
/// false when there is nothing to say beyond plain AD data; `kinds` says
/// what each file is ([`kind_label`]), in the order sent.
async fn sniff(State(st): State<Shared>, Json(req): Json<SniffRequest>) -> Response {
    let st2 = st.clone();
    let done = tokio::task::spawn_blocking(move || {
        let (packs, _) = packs(&st2);
        let domains = known_domains(&st2);
        let kinds: Vec<String> = req
            .files
            .iter()
            .take(SNIFF_FILES)
            .map(|f| kind_label(f, &packs))
            .collect();
        let (html, any) = render_sniff(&req.files, &packs, &domains);
        (html, any, kinds)
    })
    .await;
    match done {
        Ok((html, any, kinds)) => {
            Json(serde_json::json!({ "html": html, "opengraph": any, "kinds": kinds }))
                .into_response()
        }
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Checking the files failed.",
        ),
    }
}

/// Domains of earlier runs, to offer in the coverage form.
fn known_domains(st: &AppState) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in st.ws().runs().iter().filter(|r| !r.demo) {
        for d in &r.domains {
            if !out.iter().any(|x| x.eq_ignore_ascii_case(d)) && out.len() < 12 {
                out.push(d.clone());
            }
        }
    }
    out
}

fn render_sniff(files: &[SniffFile], packs: &[PackEntry], domains: &[String]) -> (String, bool) {
    let mut collectors = 0;
    let mut zips = 0;
    let mut other = Vec::new();
    // Source -> its files, in order seen.
    let mut sources: Vec<(Option<String>, Vec<&str>)> = Vec::new();
    let mut sidecars: Vec<(&str, Vec<String>)> = Vec::new();
    for f in files.iter().take(SNIFF_FILES) {
        match classify(f, packs) {
            Chosen::Collector(_) => collectors += 1,
            Chosen::Zip => zips += 1,
            Chosen::Other => other.push(f.name.as_str()),
            Chosen::Sidecar(p) => sidecars.push((&f.name, p)),
            Chosen::OpenGraph(src) => {
                let at = sources.iter().position(|(s, _)| match (s, &src) {
                    (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                    (None, None) => true,
                    _ => false,
                });
                match at {
                    Some(i) => sources[i].1.push(&f.name),
                    None => sources.push((src, vec![&f.name])),
                }
            }
        }
    }
    let any = !sources.is_empty() || !sidecars.is_empty();
    if !any {
        return (String::new(), false);
    }
    let mut b = String::from(
        r#"<div class="og-head"><h2 class="sub">Detected sources</h2><p class="muted small">From the start and end of each file; the full count is on the run page after analysis.</p></div><ul class="og-list">"#,
    );
    let mut ad = Vec::new();
    if collectors > 0 {
        ad.push(plural(
            collectors,
            "SharpHound or RustHound-CE file",
            "SharpHound or RustHound-CE files",
        ));
    }
    if zips > 0 {
        ad.push(format!(
            "{} (opened when analyzed: OpenGraph files inside are listed on the run page, without a coverage form)",
            plural(zips, ".zip archive", ".zip archives")
        ));
    }
    if !ad.is_empty() {
        let _ = write!(
            b,
            r#"<li class="og-src og-ad"><div class="og-src-head"><strong class="og-name">AD data</strong><span class="muted small">{}</span></div></li>"#,
            esc(&ad.join("; "))
        );
    }
    let mut fi = 0usize;
    for (src, names) in &sources {
        let entry = src.as_deref().and_then(|s| pack_for(packs, s));
        let name = src.as_deref().unwrap_or("Unknown OpenGraph source");
        let _ = write!(
            b,
            r#"<li class="og-src"><div class="og-src-head"><strong class="og-name">{name}</strong><span class="tag">OpenGraph</span><span class="muted small">{n}</span></div><dl class="og-facts"><div class="og-wide"><dt>Mapping</dt><dd>{trust}</dd></div>"#,
            name = esc(name),
            n = esc(&format!(
                "{}: {}",
                plural(names.len(), "file", "files"),
                names.join(", ")
            )),
            trust = trust_line(entry.map(|e| (e.pack.title(), e.pack.trusted()))),
        );
        for file in names {
            let covered = sidecars.iter().any(|(_, payloads)| {
                payloads
                    .iter()
                    .any(|p| base_name(p).eq_ignore_ascii_case(base_name(file)))
            });
            // A sidecar too large to read here may still cover it.
            let unknown_sidecar = sidecars.iter().any(|(_, p)| p.is_empty());
            let coverage = if covered {
                format!(
                    r#"<span class="og-pill og-ok">Coverage file found</span> <span class="og-why">for {}; checked against the file's SHA-256 when analyzed.</span>"#,
                    esc(file)
                )
            } else if src.is_none() {
                r#"<span class="og-pill og-bad">No coverage file</span> <span class="og-why">This file doesn't say which collector wrote it (<code>metadata.source_kind</code>), so coverage can't be declared for it here.</span>"#.to_string()
            } else {
                let form = declare_form(fi, file, name, domains);
                fi += 1;
                format!(
                    r#"<span class="og-pill og-bad">No coverage file{maybe}</span> <span class="og-why">{file}: its findings can open, but are never marked Fixed in a retest, because a missing finding could be a host {name} didn't reach.</span>{form}"#,
                    maybe = if unknown_sidecar { " matched yet" } else { "" },
                    file = esc(file),
                    name = esc(name),
                )
            };
            let _ = write!(
                b,
                r#"<div class="og-wide"><dt>Coverage</dt><dd>{coverage}</dd></div>"#
            );
        }
        b.push_str("</dl></li>");
    }
    for (name, payloads) in &sidecars {
        let what = if payloads.is_empty() {
            "Coverage file; matched to its OpenGraph file by SHA-256 when analyzed.".to_string()
        } else {
            format!(
                "Coverage file for {}; checked against its SHA-256 when analyzed.",
                payloads
                    .iter()
                    .map(|p| base_name(p))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let _ = write!(
            b,
            r#"<li class="og-src og-side"><div class="og-src-head"><strong class="og-name">{}</strong><span class="muted small">{}</span></div></li>"#,
            esc(name),
            esc(&what)
        );
    }
    b.push_str("</ul>");
    if collectors == 0 && zips == 0 {
        b.push_str(r#"<p class="small og-note og-warn">OpenGraph files add to AD data; they are not a collection on their own. Add the SharpHound or RustHound-CE output too.</p>"#);
    }
    if !other.is_empty() {
        let _ = write!(
            b,
            r#"<p class="small og-note">Not recognized from their ends (read when analyzed): {}.</p>"#,
            esc(&other.join(", "))
        );
    }
    (b, any)
}

/// The coverage declaration form for one uploaded OpenGraph file. Its
/// values travel with the upload (field `coverage`).
fn declare_form(i: usize, file: &str, source: &str, domains: &[String]) -> String {
    let mut doms = String::new();
    for (j, d) in domains.iter().enumerate() {
        let _ = write!(
            doms,
            r#"<label class="og-check"><input type="checkbox" name="og-dom" value="{raw}" id="og-d{i}-{j}"> {v}</label>"#,
            raw = crate::pages::attr(d),
            v = esc(d),
        );
    }
    format!(
        r#"<details class="og-declare" data-file="{file}"><summary>Declare what {source} scanned</summary>
<div class="og-declare-body">
<p class="muted small">Pathwarden writes a coverage file for <strong>{file}</strong>, marked as declared by you and bound to the exact file uploaded (its SHA-256). Declare only what the collector really attempted: a host you list that it didn't reach would let a finding there be marked Fixed.</p>
<fieldset><legend>Every enabled computer in these domains was attempted</legend>{doms}
<label class="og-field"><span>Other domains (comma-separated)</span><input type="text" class="og-dom-other" placeholder="CONTOSO.LOCAL" autocomplete="off" spellcheck="false"></label></fieldset>
<label class="og-field"><span>Or these computers (one per line: host names or SIDs)</span><textarea class="og-ok" rows="3" spellcheck="false"></textarea></label>
<label class="og-file-load"><span class="btn small-btn">Load a list from a file</span><input type="file" class="og-load" accept=".txt,.csv,.lst" data-target="og-ok"></label>
<label class="og-field"><span>Computers it attempted that failed (optional)</span><textarea class="og-failed" rows="2" spellcheck="false"></textarea></label>
<label class="og-check"><input type="checkbox" class="og-complete" checked> The {source} run finished</label>
<label class="og-check og-on"><input type="checkbox" class="og-enable"> Attach this coverage to the upload</label>
</div></details>"#,
        file = esc(file),
        source = esc(source),
    )
}

// ------------------------------------------------------------ declarations

/// A coverage declaration for one uploaded file, as the Analyze page sends
/// it (field `coverage`: a JSON list of these).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredFile {
    /// The file's name as chosen in the browser.
    pub file: String,
    pub declaration: Declaration,
}

/// Most bytes of the `coverage` field.
pub const MAX_DECLARATION_BYTES: usize = 8 << 20;

/// Writes a sidecar beside each uploaded OpenGraph file a declaration names
/// (`<name>.coverage.json`, which the reader finds next to its payload),
/// bound to the bytes the server received. `uploaded` is each saved file.
pub(crate) fn write_declarations(
    decls: &[DeclaredFile],
    uploaded: &[PathBuf],
    packs: &[PackEntry],
    now: i64,
) -> Result<(), String> {
    for d in decls {
        let want = crate::server::safe_file_name(&d.file).ok_or_else(|| {
            format!(
                "Coverage was declared for {}, which isn't uploaded.",
                d.file
            )
        })?;
        let path = uploaded
            .iter()
            .find(|p| p.file_name().is_some_and(|n| n.to_string_lossy() == want))
            .ok_or_else(|| format!("Coverage was declared for {want}, which isn't uploaded."))?;
        let (source, hash) = read_payload(path, packs)?;
        let text = d
            .declaration
            .sidecar(&source, &want, &hash, now)
            .map_err(|e| format!("Coverage for {want}: {e}"))?;
        let out = path.with_file_name(format!("{want}.coverage.json"));
        std::fs::write(&out, text).map_err(|e| format!("Couldn't save the coverage file: {e}"))?;
    }
    Ok(())
}

/// The source an uploaded OpenGraph file names, and its SHA-256.
fn read_payload(path: &FsPath, packs: &[PackEntry]) -> Result<(String, String), String> {
    let name = base_name(&path.to_string_lossy()).to_string();
    let io = |e: std::io::Error| format!("Couldn't read {name}: {e}");
    let mut f = std::fs::File::open(path).map_err(io)?;
    let len = f.metadata().map_err(io)?.len();
    let peek = ingest::SNIFF_BYTES as u64;
    let mut head = Vec::new();
    (&mut f).take(peek).read_to_end(&mut head).map_err(io)?;
    let mut tail = Vec::new();
    f.seek(SeekFrom::Start(len.saturating_sub(peek)))
        .map_err(io)?;
    f.read_to_end(&mut tail).map_err(io)?;
    let source = match ingest::sniff(&head, &tail) {
        Sniffed::OpenGraph { source_kind } => {
            source_of(source_kind, &String::from_utf8_lossy(&head), packs)
                .ok_or_else(|| format!("{name} doesn't say which collector wrote it (metadata.source_kind), so its coverage can't be declared."))?
        }
        _ => return Err(format!("Coverage was declared for {name}, which is not an OpenGraph file.")),
    };
    f.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((source, hash))
}

// ------------------------------------------------------------ Mappings

/// A small square of a pack's (validated) color, as an SVG attribute.
fn swatch(color: Option<&str>) -> String {
    let valid = color.filter(|c| {
        c.strip_prefix('#').is_some_and(|h| {
            (h.len() == 3 || h.len() == 6) && h.bytes().all(|b| b.is_ascii_hexdigit())
        })
    });
    match valid {
        Some(c) => format!(
            r#"<svg class="og-swatch" viewBox="0 0 10 10" aria-hidden="true"><rect width="10" height="10" rx="2" fill="{c}"/></svg>"#
        ),
        None => String::new(),
    }
}

/// A node kind's graph icon. `name` is already a `pack::ICONS` name (the
/// Font Awesome name the explorer draws). When that name has a matching
/// sprite the page embeds, the glyph; otherwise nothing (the swatch shows
/// the kind's color): an icon's name is no help to the reader.
fn kind_icon(name: &str) -> String {
    // pack::ICONS (Font Awesome names) → sprite ids embedded by the shell
    // (`pages::ICONS`). Only names with a matching glyph are mapped.
    let sprite = match name {
        "clock" => Some("i-clock"),
        "gear" | "gears" => Some("i-gear"),
        "folder" => Some("i-folder"),
        "file" => Some("i-file"),
        "lock" => Some("i-lock"),
        _ => None,
    };
    match sprite {
        Some(id) => format!(
            r#" <span class="og-kind-ic" role="img" aria-label="{name} icon" title="Shown with the ‘{name}’ icon in the graph">{glyph}</span>"#,
            name = esc(name),
            glyph = icon(id),
        ),
        None => String::new(),
    }
}

/// A pack's fix text for the page, where no relationship is at hand: its
/// `{from}` and `{to}` as "start" and "end" tags (the page says what they
/// stand for), `{source}` as the pack's title. Escaped.
fn fix_html(template: &str, source: &str) -> String {
    let tag =
        |word: &str, what: &str| format!(r#"<span class="og-ph" title="{what}">{word}</span>"#);
    esc(template)
        .replace(
            "{from}",
            &tag("start", "The object the relationship starts from"),
        )
        .replace("{to}", &tag("end", "The object the relationship goes to"))
        .replace("{source}", &esc(source))
}

async fn mappings_page(State(st): State<Shared>) -> Response {
    let st2 = st.clone();
    let sync = crate::sync_ui::view_for(&st, false).await;
    let body = tokio::task::spawn_blocking(move || mappings_body(&st2, sync.as_ref())).await;
    let runs = st.ws().runs();
    let ctx = pages::Ctx::new(&st, &runs);
    match body {
        Ok(b) => Html(pages::shell(
            &ctx,
            Some(Nav::Mappings),
            "Mappings",
            "config",
            &b,
        ))
        .into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "The page failed."),
    }
}

fn mappings_body(st: &AppState, sync: Option<&crate::sync_ui::View>) -> String {
    let loaded = crate::settings::load(st);
    let (mut packs, refused) = packs_in_effect(&loaded.config, &st.ws().env_dir());
    // Packs from the repository first: they wait for someone here.
    packs.sort_by_key(|e| e.from_repo.is_none());
    let mut b = String::from(
        r#"<link rel="stylesheet" href="/static/opengraph.css"><div class="page-head"><div><p class="eyebrow">Configure</p><h1 class="panel-title">Mappings</h1><p class="lead">What OpenGraph collectors' kinds mean to Pathwarden. A file never decides this: only a mapping pack can make a relationship part of an attack path, and only a trusted one.</p></div></div>"#,
    );
    if let Some(v) = sync {
        b.push_str(&crate::sync_ui::sync_line(v, "mappings"));
    }
    if packs
        .iter()
        .any(|e| e.from_repo.as_ref().is_some_and(|r| r.unreadable))
    {
        let _ = write!(
            b,
            r#"<div class="note warn">{}<p><strong>The record of which packs came from the repository can't be read.</strong> Every pack in the <code>packs</code> folder is untrusted until someone on this computer marks it as trusted again.</p></div>"#,
            icon("i-alert")
        );
    }
    if let Some(e) = &loaded.error {
        let _ = write!(
            b,
            r#"<div class="note cfg-error">{}<p><strong>pathwarden.toml can't be loaded.</strong> {}</p></div>"#,
            icon("i-alert"),
            esc(e)
        );
    }
    for (path, e) in &refused {
        let _ = write!(
            b,
            r#"<div class="note cfg-error">{}<p><strong>Mapping pack {} was refused.</strong> {} Analyses stop until it is fixed or removed from <code>[[mapping]]</code>.</p></div>"#,
            icon("i-alert"),
            esc(path),
            esc(e)
        );
    }
    for (i, e) in packs.iter().enumerate() {
        pack_card(&mut b, i, e);
    }
    if !packs.iter().any(|e| e.path.is_some()) {
        let _ = write!(
            b,
            r#"<p class="muted small og-note">No packs of your own. {} says how to add one.</p>"#,
            pages::repo_link("docs/opengraph.md", "The OpenGraph guide")
        );
    }
    // Kinds the latest run saw that no pack describes.
    if let Some((r, dir)) = crate::run_data::latest_with(&st.ws(), SOURCES_FILE) {
        if let Some(s) = read_stats(&dir).filter(|s| !s.unmapped_kinds.is_empty()) {
            let _ = write!(
                b,
                r#"<section class="card og-pack"><h2 class="sub">Kinds without a mapping</h2><p class="muted small">In the latest run with OpenGraph data ({env}, {when}); shown in Explore as context only.</p><details class="og-more"><summary>{n}</summary><ul class="og-kinds">"#,
                env = esc(&r.environment()),
                when = pages::time(r.created_at),
                n = num(s.unmapped_kinds.len())
                    + if s.unmapped_kinds.len() == 1 {
                        " kind"
                    } else {
                        " kinds"
                    },
            );
            for (k, n) in s.unmapped_kinds.iter().take(200) {
                let _ = write!(
                    b,
                    "<li><code>{}</code> <span class=\"muted\">{}</span></li>",
                    esc(k),
                    num(*n)
                );
            }
            b.push_str("</ul>");
            if s.unmapped_kinds.len() > 200 {
                b.push_str(r#"<p class="muted small">The first 200 shown.</p>"#);
            }
            b.push_str("</details></section>");
        }
    }
    let _ = write!(
        b,
        r#"<dialog id="og-trust" class="card og-dialog" aria-labelledby="og-trust-title">
<form method="dialog">
<h2 class="sub" id="og-trust-title">Trust <span id="og-trust-name"></span>?</h2>
<p>Trusting a pack lets its <strong>traversable</strong> relationships become attack paths: they count in exposure, appear in the remediation path and open PW-030 findings, from the next analysis on. Untrusted, they are only labels.</p>
<p class="muted small">Trust a pack only after checking, for each traversable kind, that it really lets an attacker move (ideally against a lab). The name is added to <code>[opengraph] trust</code> in <code>pathwarden.toml</code>; remove it there or here to undo.</p>
<label class="og-check"><input type="checkbox" id="og-trust-ok"> I reviewed this pack's traversable kinds</label>
<p class="save-status small" id="og-trust-status" role="status"></p>
<div class="dialog-actions"><button class="btn" value="cancel">Cancel</button><button type="button" class="btn primary" id="og-trust-go" disabled>Trust this pack</button></div>
</form>
</dialog>
{after}<script src="/static/opengraph.js" defer></script>"#,
        after = crate::settings::after_save(st),
    );
    b
}

fn pack_card(b: &mut String, i: usize, e: &PackEntry) {
    let p = &e.pack;
    let origin = esc(&e.origin());
    let pill_class = if e.from_repo.is_some() && !p.trusted() {
        "og-repo"
    } else if p.trusted() {
        "og-trusted"
    } else {
        "og-context"
    };
    let mut pill = format!(
        r#"<span class="og-pill {pill_class}">{}</span>"#,
        e.trust_label()
    );
    if let Some(r) = &e.from_repo {
        let by = match (&r.added_by, &r.added_on) {
            (Some(b), Some(o)) => format!("{b} on {o}"),
            (Some(b), None) => b.clone(),
            (None, Some(o)) => format!("on {o}"),
            (None, None) => "Not recorded".into(),
        };
        let day = r
            .added_at
            .as_deref()
            .and_then(pathwarden_core::time::parse_rfc3339)
            .map(|t| format!(", {}", pages::time_as(t, "day")))
            .unwrap_or_default();
        let _ = write!(
            pill,
            r#"<span class="tip"><button type="button" class="tip-btn" aria-label="About: Trust on this computer" aria-describedby="tip-pack-{i}">{info}</button><span class="tip-text wide" role="tooltip" id="tip-pack-{i}"><span class="src-row"><span>Added by</span><span>{by}{day}</span></span><span class="src-row"><span>Trust</span><span>Never travels. Here its relationships are only labels until someone on this computer trusts it.</span></span></span></span>"#,
            info = icon("i-info"),
            by = esc(&by),
        );
    }
    let action = if !p.trusted() {
        format!(
            r#"<button type="button" class="btn small-btn" data-og-trust="{n}" data-title="{t}" data-digest="{d}">Mark as trusted…</button>"#,
            n = esc(p.name()),
            t = esc(p.title()),
            d = esc(e
                .from_repo
                .as_ref()
                .and_then(|r| r.current_sha256.as_deref())
                .unwrap_or_default()),
        )
    } else if e.trusted_by_config || e.from_repo.is_some() {
        format!(
            r#"<button type="button" class="btn small-btn" data-og-untrust="{n}" data-title="{t}">Remove trust</button>"#,
            n = esc(p.name()),
            t = esc(p.title()),
        )
    } else {
        String::new()
    };
    let _ = write!(
        b,
        r#"<section class="card og-pack" id="pack-{i}"><div class="og-pack-head"><div><h2 class="sub">{title} <span class="muted small">{name} v{version}</span></h2><p class="muted small">{origin} · for {sources} · kinds starting <code>{prefix}</code></p></div><div class="og-pack-actions">{pill}{action}</div></div>"#,
        title = esc(p.title()),
        name = esc(p.name()),
        version = p.version(),
        sources = esc(&p.source_kinds().join(", ")),
        prefix = esc(p.kind_prefix()),
    );
    if let Some(d) = p.description() {
        let _ = write!(b, r#"<p class="small">{}</p>"#, esc(d));
    }
    // What the pack maps, collapsed: one line per pack until opened.
    let nodes = p.node_views();
    let edges = p.edge_views();
    if nodes.is_empty() && edges.is_empty() {
        b.push_str("</section>");
        return;
    }
    let _ = write!(
        b,
        r#"<details class="og-more"><summary>{}</summary>"#,
        e.summary()
    );
    if !nodes.is_empty() {
        b.push_str(r#"<h3 class="og-h3">Object kinds</h3><ul class="og-kinds">"#);
        for n in &nodes {
            let _ = write!(
                b,
                r#"<li>{sw}<code>{k}</code> {label}{icon}</li>"#,
                sw = swatch(n.color.as_deref()),
                k = esc(&n.kind),
                label = n.label.as_deref().map(esc).unwrap_or_default(),
                icon = n.icon.as_deref().map(kind_icon).unwrap_or_default(),
            );
        }
        b.push_str("</ul>");
    }
    if !edges.is_empty() {
        b.push_str(r#"<h3 class="og-h3">Relationship kinds</h3>"#);
        if edges.iter().any(|e| e.fix.is_some()) {
            b.push_str(r#"<p class="muted small">In the fixes, <span class="og-ph">start</span> and <span class="og-ph">end</span> stand for the objects a relationship goes from and to.</p>"#);
        }
        b.push_str(r#"<div class="og-edges">"#);
        for ed in &edges {
            let path = format!(
                r#"<span class="og-pill {}">{}</span>"#,
                if ed.traversable && p.trusted() {
                    "og-trusted"
                } else {
                    "og-context"
                },
                e.edge_role(ed)
            );
            let facts = edge_facts(ed);
            let _ = write!(
                b,
                r#"<div class="og-edge"><div class="og-edge-head"><code>{k}</code>{path}<span class="muted small">{facts}</span></div>{desc}{fix}</div>"#,
                k = esc(&ed.kind),
                facts = esc(&facts.join(" · ")),
                desc = ed
                    .description
                    .as_deref()
                    .map(|d| format!(r#"<p class="small">{}</p>"#, esc(d)))
                    .unwrap_or_default(),
                fix = ed
                    .fix
                    .as_deref()
                    .map(|f| format!(
                        r#"<p class="small og-fix"><strong>Fix:</strong> {}</p>"#,
                        fix_html(f, p.title())
                    ))
                    .unwrap_or_default(),
            );
        }
        b.push_str("</div>");
    }
    b.push_str("</details></section>");
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustRequest {
    pack: String,
    trusted: bool,
    /// The user ticked "I reviewed this pack" in the dialog.
    #[serde(default)]
    confirm: bool,
    /// For a pack from the repository: the digest of the text the page
    /// showed, which the review was of.
    #[serde(default)]
    digest: Option<String>,
}

/// `/api/mappings/trust`: adds a pack to `[opengraph] trust` (only with
/// `confirm`), or removes it ([`trust_change`]'s checks).
async fn set_trust(State(st): State<Shared>, Json(req): Json<TrustRequest>) -> Response {
    let st2 = st.clone();
    let config_path = st.ws().config_path();
    let checked = tokio::task::spawn_blocking(move || {
        let (packs, _) = packs(&st2);
        match trust_change(&packs, &req.pack, req.trusted, req.confirm)? {
            // A pack from the repository: trusted on this computer, at
            // the text the page showed; never by name. Untrusting it also
            // takes its name out of [opengraph] trust.
            TrustChange::Reviewed { path, name, .. } => {
                pathwarden_core::pack_origin::mark_reviewed(
                    &config_path,
                    &path,
                    req.trusted,
                    req.digest.as_deref(),
                )?;
                let named = crate::settings::load(&st2).config.opengraph.trusts(&name);
                Ok::<_, String>((!req.trusted && named).then_some((name, false)))
            }
            TrustChange::Name(n) => Ok(Some((n, req.trusted))),
        }
    })
    .await;
    let (name, trusted) = match checked {
        Ok(Ok(Some(t))) => t,
        Ok(Ok(None)) => return Json(serde_json::json!({ "saved": true })).into_response(),
        Ok(Err(e)) => return json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "The page failed."),
    };
    crate::settings::edit(&st, move |d| d.set_pack_trust(&name, trusted)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fix templates read as text: no raw placeholders, nothing unescaped.
    #[test]
    fn fixes_show_start_and_end() {
        let html = fix_html(
            "Remove the stored credentials from {to} on {from} ({source}).",
            "Task<b>Hound",
        );
        assert!(!html.contains('{'), "{html}");
        assert!(
            html.contains(r#">end</span> on <span class="og-ph""#),
            "{html}"
        );
        assert!(html.contains("(Task&lt;b&gt;Hound)."), "{html}");
        assert!(kind_icon("user-gear").is_empty());
        assert!(kind_icon("clock").contains("i-clock"));
    }

    #[test]
    fn swatches_take_only_valid_colors() {
        assert!(swatch(Some("#8B5CF6")).contains("fill=\"#8B5CF6\""));
        assert!(swatch(Some("red\" onload=\"x")).is_empty());
        assert!(swatch(None).is_empty());
    }

    #[test]
    fn files_are_classified_from_their_ends() {
        let packs: Vec<PackEntry> = pathwarden_core::opengraph::pack::embedded()
            .iter()
            .map(|p| PackEntry {
                pack: p.clone(),
                path: None,
                trusted_by_config: false,
                from_repo: None,
            })
            .collect();
        let f = |name: &str, head: &str| SniffFile {
            name: name.into(),
            size: head.len() as u64,
            head: head.into(),
            tail: head.into(),
        };
        let og = r#"{"graph":{"nodes":[{"id":"x","kinds":["TH_ScheduledTask","TaskHound"]}],"edges":[]}}"#;
        assert_eq!(
            classify(&f("t.json", og), &packs),
            Chosen::OpenGraph(Some("TaskHound".into()))
        );
        assert_eq!(classify(&f("a.zip", ""), &packs), Chosen::Zip);
        assert_eq!(
            classify(
                &f(
                    "x.json",
                    r#"{"data":[],"meta":{"type":"users","count":0,"version":6}}"#
                ),
                &packs
            ),
            Chosen::Collector("users".into())
        );
        assert_eq!(classify(&f("x.json", "{}"), &packs), Chosen::Other);

        // What each file's row says it is.
        let azure = r#"{"data":[],"meta":{"type":"azure","version":5,"count":0}}"#;
        let users = r#"{"data":[],"meta":{"type":"users","count":0,"version":6}}"#;
        let untitled = r#"{"graph":{"nodes":[{"id":"x","kinds":["Base"]}],"edges":[]}}"#;
        let files = [
            f("contoso-azurehound.json", azure),
            f("taskhound_opengraph.json", og),
            f("20261105_users.json", users),
            f("collection.zip", ""),
            f("other.json", untitled),
            f("notes.json", "{}"),
        ];
        let kinds: Vec<String> = files.iter().map(|x| kind_label(x, &packs)).collect();
        assert_eq!(
            kinds,
            [
                "AzureHound: Entra ID",
                "OpenGraph: TaskHound",
                "SharpHound",
                "Archive",
                "OpenGraph",
                "Not recognized"
            ]
        );
    }
}
