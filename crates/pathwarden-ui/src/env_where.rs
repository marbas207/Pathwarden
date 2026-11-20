//! Where a run goes, on Collect (step 5) and Analyze: "Saving to Production
//! · change", "Saving to a new environment CONTOSO.COM · change", or, when
//! something's off, the question with its reason and the environments as
//! cards ([`crate::environments::decide`]).
//!
//! The pages know the domains before the run starts: Collect from the
//! domain it collects, Analyze from the collector's domains files. The
//! browser reads those out of the chosen files (from a `.zip` too) and
//! posts them here with any local paths, which are read here
//! ([`pathwarden_core::ingest::peek_domains`]). When they can't be read,
//! the analysis decides from the data and stops to ask if it must
//! ([`crate::jobs::JobStatus::Ask`]). The server renders every piece of
//! HTML; the page's script only moves it into place and reads the choice.

use std::fmt::Write;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use pathwarden_core::ingest::peek::{self, PeekedDomains};
use serde::Serialize;

use crate::environments::{self, clean_domains, Decision, Registry, NO_ENV_YET};
use crate::pages::{esc, icon, num};
use crate::server::AppState;
use crate::workspace::{environment_of, RunSummary};

type Shared = Arc<AppState>;

/// The most domains files one request may carry, the most of one read,
/// their total size, and the most paths read.
const MAX_FILES: usize = 16;
const MAX_FILE_BYTES: usize = 8 << 20;
const MAX_BODY: usize = 96 << 20;
const MAX_PATHS: usize = 8;

/// Reads of domains files at once (they run as a path is typed).
static PEEKS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

pub fn routes() -> Router<Shared> {
    Router::new().route(
        "/api/analyze/where",
        post(where_api).layer(DefaultBodyLimit::max(MAX_BODY)),
    )
}

/// What the pages get: the state (`match`, `new`, `ask`, `unknown` or
/// `current`), the "Found in these files" box (Analyze), the block, and
/// the computed name the label would replace.
#[derive(Debug, Serialize)]
pub struct WhereView {
    pub state: &'static str,
    pub found: String,
    pub html: String,
    pub computed: String,
    pub domains: Vec<String>,
    /// The settings line for where the run goes (Analyze shows it).
    pub applies: String,
}

/// Field `domain`: a domain name (Collect, or a stopped analysis); field
/// `path`: a file or folder on this computer; field `domains`: the text of
/// a collector's domains file the browser read out of a chosen file.
async fn where_api(State(st): State<Shared>, mut form: Multipart) -> Response {
    let mut named = Vec::new();
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut peeked = PeekedDomains::default();
    let mut files = 0;
    let mut found = false;
    loop {
        let field = match form.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => return bad("The request was interrupted."),
        };
        match field.name() {
            Some("domain") => named.push(field.text().await.unwrap_or_default()),
            Some("path") => {
                let text = field.text().await.unwrap_or_default();
                let p = text.trim().trim_matches('"').trim();
                if p.is_empty() || p.len() > crate::server::MAX_PATH_FIELD {
                    continue;
                }
                found = true;
                // A network path signs in to its server when looked at; a
                // mapped drive waits on it (the analysis still reads both).
                if !crate::security::is_network_path(p)
                    && !crate::security::is_network_drive(p)
                    && paths.len() < MAX_PATHS
                {
                    paths.push(PathBuf::from(p));
                }
            }
            Some("domains") => {
                found = true;
                files += 1;
                if files > MAX_FILES {
                    continue;
                }
                // Read up to MAX_FILE_BYTES; a larger one is skipped.
                let mut field = field;
                let mut bytes = Vec::new();
                let mut too_big = false;
                loop {
                    match field.chunk().await {
                        Ok(Some(c)) => {
                            if too_big || bytes.len() + c.len() > MAX_FILE_BYTES {
                                too_big = true;
                                bytes.clear();
                            } else {
                                bytes.extend_from_slice(&c);
                            }
                        }
                        Ok(None) => break,
                        Err(_) => return bad("The request was interrupted."),
                    }
                }
                if let (false, Some(list)) = (too_big, peek::domains_in_json(&bytes)) {
                    peeked.add(&list);
                }
            }
            Some("files") => found = true,
            _ => {}
        }
    }
    let st2 = st.clone();
    let view = peek_with(&PEEKS, move || {
        if !paths.is_empty() {
            let more = pathwarden_core::ingest::peek_domains(&paths);
            let mut all: Vec<(String, bool)> =
                more.collected.into_iter().map(|d| (d, true)).collect();
            all.extend(more.trusted.into_iter().map(|d| (d, false)));
            peeked.add(&all);
        }
        let mut collected = clean_domains(&named);
        collected.extend(peeked.collected.iter().cloned());
        // Sorted, as an analysis lists them.
        let mut collected = clean_domains(&collected);
        collected.sort();
        render(&st2, &collected, &peeked.trusted, found)
    })
    .await;
    match view {
        Some(v) => Json(v).into_response(),
        None => bad(
            "Couldn't read the files. Check they are a collection zip or folder, then try again.",
        ),
    }
}

/// Runs `read` on the blocking pool once `sem` ([`PEEKS`]) gives a permit,
/// and holds the permit until `read` ends, even when the browser drops the
/// request meanwhile (a new path typed): reads at once stay at most the
/// semaphore's count. `None`: the read failed.
async fn peek_with<T: Send + 'static>(
    sem: &'static tokio::sync::Semaphore,
    read: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let permit = sem.acquire().await.ok()?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read()
    })
    .await
    .ok()
}

fn bad(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

/// One environment as a card: what it is, how it relates to the domains.
struct Card {
    id: String,
    name: String,
    current: bool,
    /// The domains it has of the run's, and through its list (else runs).
    has: Vec<String>,
    listed: bool,
    /// Its domains (list and runs) and runs.
    domains: Vec<String>,
    runs: usize,
    latest: Option<i64>,
}

/// The block for a run of `collected` domains (`trusted`: domains the
/// files only trust, shown apart). `found`: Analyze, where the domains come
/// from files (an empty list then means they couldn't be read).
pub fn render(st: &AppState, collected: &[String], trusted: &[String], found: bool) -> WhereView {
    let all = st.workspace.all_runs();
    let reg = st.workspace.registry().with_names(&all);
    let current = st.env_id();
    // Analyze knows the trusted domains from the files; Collect only the
    // domain it collects (the analysis checks again with the data).
    let runs = environments::run_domains_for(&reg, &all, found.then_some((collected, trusted)));
    let decision = if collected.is_empty() {
        None
    } else {
        Some(environments::decide(&reg, collected, &runs))
    };
    let computed = if collected.is_empty() {
        String::new()
    } else {
        environment_of(collected)
    };
    let found_html = if found {
        found_box(collected, trusted)
    } else {
        String::new()
    };
    let cards = cards(st.workspace.root(), &reg, &all, &runs, collected, &current);
    let fresh: Vec<String> = match &decision {
        Some(Decision::Ask(a)) => [a.new.clone(), a.legacy.clone()].concat(),
        Some(Decision::New { .. }) => collected.to_vec(),
        _ => Vec::new(),
    };
    let (state, html) = match &decision {
        None if found => ("unknown", unknown_block(&cards)),
        None | Some(Decision::Current) => ("current", current_block(&reg, &cards, &current)),
        Some(Decision::Match { id, .. }) => (
            "match",
            block(&reg, &cards, collected, &fresh, &decision, Some(id)),
        ),
        Some(Decision::New { .. }) => (
            "new",
            block(&reg, &cards, collected, &fresh, &decision, None),
        ),
        Some(Decision::Ask(_)) => (
            "ask",
            block(&reg, &cards, collected, &fresh, &decision, None),
        ),
    };
    let lead = "Analyses here apply";
    let applies = match &decision {
        Some(Decision::Match { id, .. }) => {
            crate::settings::applies_line_in(&st.workspace.in_env(id), lead)
        }
        Some(Decision::New { .. }) => crate::settings::applies_note(
            "A new environment starts with the default settings (no zones, accepted risks or extra Tier Zero objects)",
        ),
        Some(Decision::Ask(_)) => {
            crate::settings::applies_note("Analyses apply the settings of the environment you pick")
        }
        _ => crate::settings::applies_line(st, lead),
    };
    WhereView {
        state,
        found: found_html,
        html,
        computed,
        domains: collected.to_vec(),
        applies,
    }
}

/// The real environments as cards (the demo's and an unused Default left
/// out).
fn cards(
    root: &std::path::Path,
    reg: &Registry,
    all: &[RunSummary],
    runs: &[environments::RunDomains],
    collected: &[String],
    current: &str,
) -> Vec<Card> {
    let unused_default = reg.default_unused(root, runs);
    reg.environments
        .iter()
        .filter(|e| !e.demo && !(e.is_default() && unused_default))
        .map(|e| {
            let mine: Vec<&RunSummary> = all
                .iter()
                .filter(|r| !r.demo && environments::run_env(reg, r) == e.id)
                .collect();
            let mut domains = e.domains.clone();
            for r in &mine {
                domains.extend(r.domains.iter().cloned());
            }
            let domains = clean_domains(&domains);
            let listed: Vec<String> = collected
                .iter()
                .filter(|d| e.domains.contains(d))
                .cloned()
                .collect();
            let (has, by_list) = if listed.is_empty() {
                (
                    collected
                        .iter()
                        .filter(|d| domains.contains(d))
                        .cloned()
                        .collect(),
                    false,
                )
            } else {
                (listed, true)
            };
            Card {
                id: e.id.clone(),
                name: e.display().to_string(),
                current: e.id == current,
                has,
                listed: by_list,
                domains,
                runs: mine.len(),
                latest: mine.iter().map(|r| r.created_at).max(),
            }
        })
        .collect()
}

/// "Found in these files": the collected domains, and the trusted ones
/// apart (dashed). Nothing read: says so.
fn found_box(collected: &[String], trusted: &[String]) -> String {
    if collected.is_empty() {
        return format!(
            r#"<section class="detected card" aria-live="polite"><p class="d-head">{i}Domains not read yet</p><p class="hint">The domains aren't known yet. Pathwarden picks the environment from the data and asks if it must.</p></section>"#,
            i = icon("i-info"),
        );
    }
    let mut chips = String::new();
    for d in collected {
        let _ = write!(
            chips,
            r#"<li><span class="dom-chip is-collected">{}</span></li>"#,
            esc(d)
        );
    }
    for d in trusted {
        let _ = write!(
            chips,
            r#"<li><span class="dom-chip is-trusted">{} <span class="n">· {}</span></span></li>"#,
            esc(d),
            pathwarden_core::forest::NOT_COLLECTED
        );
    }
    format!(
        r#"<section class="detected card" aria-live="polite"><p class="d-head">{i}Found in these files</p><ul>{chips}</ul></section>"#,
        i = icon("i-check"),
    )
}

/// "FABRIKAM.LOCAL and 2 more · 4 runs, the latest Oct 13".
fn card_meta(c: &Card) -> String {
    let mut parts = Vec::new();
    if !c.domains.is_empty() {
        parts.push(esc(&match c.domains.as_slice() {
            [a] => a.clone(),
            [a, b] => format!("{a}, {b}"),
            [a, b, c] => format!("{a}, {b}, {c}"),
            [a, rest @ ..] => format!("{a} and {} more", rest.len()),
            [] => String::new(),
        }));
    }
    parts.push(match (c.runs, c.latest) {
        (0, _) | (_, None) => "no runs yet".to_string(),
        (1, Some(t)) => format!("1 run, {}", crate::pages::time_as(t, "day")),
        (n, Some(t)) => format!(
            "{} runs, the latest {}",
            num(n),
            crate::pages::time_as(t, "day")
        ),
    });
    parts.join(" · ")
}

/// The block for a known set of domains: the line (or the question), and
/// the cards, hidden until "change" unless asking.
fn block(
    reg: &Registry,
    cards: &[Card],
    collected: &[String],
    fresh: &[String],
    decision: &Option<Decision>,
    matched: Option<&String>,
) -> String {
    let asking = matches!(decision, Some(Decision::Ask(_)));
    let mut b = String::new();
    let new_name = match decision {
        Some(Decision::New { name }) => name.clone(),
        _ => environments::new_name(collected),
    };
    let domain_words = esc(&environments::and_list(collected));
    match decision {
        Some(Decision::Ask(ask)) => {
            let reason = ask.reason_html(reg);
            let _ = write!(
                b,
                r#"<div class="env-ask" role="alert">{i}<div><p class="ea-q">Where should this run go?</p><p class="ea-why">{reason}</p></div></div>"#,
                i = icon("i-alert"),
            );
        }
        Some(Decision::Match { id, how }) => {
            let why = match how {
                environments::Assigned::ByRuns => {
                    format!("earlier runs of {domain_words} are there")
                }
                environments::Assigned::Joined => {
                    "it has the other domains; the new ones join it".to_string()
                }
                _ => format!("it lists {domain_words}"),
            };
            let _ = write!(
                b,
                r#"<p class="env-save" id="ew-line">{i}<span>Saving to <strong>{name}</strong></span><span class="sep">·</span><span class="sv-why">{why}</span><span class="sep">·</span><button type="button" class="linkish" data-ew-change>Change</button></p>"#,
                i = icon("i-layers"),
                name = esc(&reg.name_of(id)),
            );
        }
        _ => {
            // An unused Default that takes the name has no settings either
            // (`Registry::default_unused`), so it starts empty too.
            let _ = write!(
                b,
                r#"<p class="env-save" id="ew-line">{i}<span>Saving to a new environment <strong>{name}</strong></span><span class="sep">·</span><button type="button" class="linkish" data-ew-change>Change</button></p><p class="hint sv-hint" id="ew-hint">No environment has {domain_words} yet, so a new one is made, with the default settings. Rename it any time.</p>"#,
                i = icon("i-layers"),
                name = esc(&new_name),
            );
        }
    }
    let intro = match decision {
        Some(Decision::Match { id, how }) if *how == environments::Assigned::Joined => format!(
            "{} has some of {domain_words}; the others join it.",
            esc(&reg.name_of(id)),
        ),
        Some(Decision::Match { id, how }) => format!(
            "{} {} {domain_words}.",
            esc(&reg.name_of(id)),
            if *how == environments::Assigned::ByRuns {
                "has earlier runs of"
            } else {
                "lists"
            }
        ),
        Some(Decision::Ask(_)) => "Nothing is chosen for you. The run is saved in the one you pick, with its settings, and compared with its earlier runs.".to_string(),
        _ => format!("No environment has {domain_words} yet. Pick one to compare this run with its runs, or keep the new one."),
    };
    // The match first, then the ones that have some of the domains, the
    // current one, the rest; New environment last.
    let mut order: Vec<&Card> = cards.iter().collect();
    order.sort_by_key(|c| (Some(&c.id) != matched, c.has.is_empty(), !c.current));
    let mut items = String::new();
    for c in order {
        let checked = Some(&c.id) == matched;
        let missing: Vec<String> = collected
            .iter()
            .filter(|d| !c.has.contains(d))
            .cloned()
            .collect();
        let line = if c.has.is_empty() {
            String::new()
        } else if missing.is_empty() {
            format!(
                r#"<span class="c-match">{i}{verb} {d}</span>"#,
                i = icon("i-check"),
                verb = if c.listed { "Lists" } else { "Has runs of" },
                d = esc(&environments::and_list(&c.has)),
            )
        } else {
            format!(
                r#"<span class="c-match warn">{i}{verb} {d}, not {m}</span>"#,
                i = icon("i-alert"),
                verb = if c.listed { "Lists" } else { "Has runs of" },
                d = esc(&environments::and_list(&c.has)),
                m = esc(&environments::and_list(&missing)),
            )
        };
        let goes = if fresh.is_empty() {
            String::new()
        } else {
            format!(
                " · {} {} on its list",
                esc(&environments::and_list(fresh)),
                if fresh.len() == 1 { "goes" } else { "go" }
            )
        };
        let _ = write!(
            items,
            r#"<label class="choice"><input type="radio" name="ew-pick" value="env:{id}"{checked}><span class="c-mark" aria-hidden="true"></span><span class="c-body"><strong>{name}{cur}</strong>{line}<span class="c-meta">{meta}{goes}</span></span></label>"#,
            id = esc(&c.id),
            checked = if checked { " checked" } else { "" },
            name = esc(&c.name),
            cur = if c.current {
                r#" <span class="tag">Current</span>"#
            } else {
                ""
            },
            meta = card_meta(c),
        );
    }
    let new_checked = matches!(decision, Some(Decision::New { .. }));
    let _ = write!(
        items,
        r#"<label class="choice ew-new"><input type="radio" name="ew-pick" value="new"{checked}><span class="c-mark" aria-hidden="true"></span><span class="c-body"><strong>New environment</strong><span class="c-meta">Its own settings, history and schedule, starting empty. Rename it any time.</span><span class="new-name"><input type="text" name="ew-name" value="{name}" maxlength="{max}" autocomplete="off" spellcheck="false" aria-label="Name of the new environment"></span></span></label>"#,
        checked = if new_checked { " checked" } else { "" },
        name = crate::pages::attr(&new_name),
        max = environments::MAX_NAME,
    );
    format!(
        r#"{b}<fieldset class="env-pick" id="ew-cards"{hidden}><legend>Environment</legend><p class="hint">{intro}</p><div class="choices">{items}</div></fieldset>"#,
        hidden = if asking { "" } else { " hidden" },
    )
}

/// Analyze before the domains are known.
fn unknown_block(cards: &[Card]) -> String {
    format!(
        r#"<p class="env-save" id="ew-line">{i}<span>Saving to the environment that matches the domains</span><span class="sep">·</span><button type="button" class="linkish" data-ew-change>Choose now</button></p><p class="hint sv-hint" id="ew-hint">Pathwarden asks if the domains match more than one environment.</p>{cards}"#,
        i = icon("i-layers"),
        cards = plain_cards(cards, None),
    )
}

/// No domains at all: the current environment.
fn current_block(reg: &Registry, cards: &[Card], current: &str) -> String {
    let name = reg.name_of(current);
    let name = if name == NO_ENV_YET {
        "a new environment".to_string()
    } else {
        format!("<strong>{}</strong>", esc(&name))
    };
    format!(
        r#"<p class="env-save" id="ew-line">{i}<span>Saving to {name}</span><span class="sep">·</span><button type="button" class="linkish" data-ew-change>Change</button></p>{cards}"#,
        i = icon("i-layers"),
        cards = plain_cards(cards, Some(current)),
    )
}

/// The cards without domain lines (domains unknown).
fn plain_cards(cards: &[Card], checked: Option<&str>) -> String {
    let mut items = String::new();
    for c in cards {
        let _ = write!(
            items,
            r#"<label class="choice"><input type="radio" name="ew-pick" value="env:{id}"{checked}><span class="c-mark" aria-hidden="true"></span><span class="c-body"><strong>{name}{cur}</strong><span class="c-meta">{meta}</span></span></label>"#,
            id = esc(&c.id),
            checked = if Some(c.id.as_str()) == checked {
                " checked"
            } else {
                ""
            },
            name = esc(&c.name),
            cur = if c.current {
                r#" <span class="tag">Current</span>"#
            } else {
                ""
            },
            meta = card_meta(c),
        );
    }
    let _ = write!(
        items,
        r#"<label class="choice ew-new"><input type="radio" name="ew-pick" value="new"><span class="c-mark" aria-hidden="true"></span><span class="c-body"><strong>New environment</strong><span class="c-meta">Its own settings, history and schedule, starting empty. Rename it any time.</span><span class="new-name"><input type="text" name="ew-name" value="" maxlength="{max}" autocomplete="off" spellcheck="false" placeholder="Name, for example Production" aria-label="Name of the new environment"></span></span></label>"#,
        max = environments::MAX_NAME,
    );
    format!(
        r#"<fieldset class="env-pick" id="ew-cards" hidden><legend>Environment</legend><p class="hint">The run is saved in the one you pick, with its settings, and compared with its earlier runs.</p><div class="choices">{items}</div></fieldset>"#
    )
}

/// The label field on Collect and Analyze; the script fills in what the
/// label replaces once the domains are known.
pub fn label_field() -> String {
    format!(
        r#"<div class="run-label"><label for="run-label">Run label <span class="opt">(optional)</span></label><input type="text" id="run-label" name="label" maxlength="{max}" autocomplete="off" placeholder="For example baseline, after GPO fix"><p class="hint">Shown instead of <span id="label-instead">the domain name</span>. You can change it later.</p></div>"#,
        max = crate::workspace::MAX_LABEL,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    /// A domain known only from a trust is labelled as the Forest view
    /// labels it.
    #[test]
    fn a_trusted_domain_is_not_collected_known_from_a_trust() {
        let html = found_box(&["ESSOS.LOCAL".into()], &["CONTOSO.LOCAL".into()]);
        assert!(
            html.contains(&format!(
                r#"CONTOSO.LOCAL <span class="n">· {}</span>"#,
                pathwarden_core::forest::NOT_COLLECTED
            )),
            "{html}"
        );
        assert!(!html.contains("trusted, not collected"), "{html}");
    }

    /// A read keeps its permit after the request that started it is
    /// dropped, and gives it back when it ends.
    #[tokio::test]
    async fn a_peek_holds_its_permit_until_the_read_ends() {
        static SEM: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
        let (started, has_started) = channel();
        let (go, wait) = channel::<()>();
        let mut request = Box::pin(peek_with(&SEM, move || {
            started.send(()).unwrap();
            let _ = wait.recv();
        }));
        tokio::select! {
            _ = &mut request => panic!("the read ended before it was let go"),
            _ = tokio::task::spawn_blocking(move || has_started.recv()) => {}
        }
        // The browser went away.
        drop(request);
        assert_eq!(SEM.available_permits(), 1, "held while the read goes on");
        go.send(()).unwrap();
        for _ in 0..200 {
            if SEM.available_permits() == 2 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the permit was not given back");
    }
}
