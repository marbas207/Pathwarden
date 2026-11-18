//! Privilege Zones: the list, the create/edit wizard with a live preview,
//! and object search.
//!
//! Search and preview run on the latest run's object index
//! ([`crate::run_data`]); the preview is core's own zone resolution
//! ([`pathwarden_core::zones::preview`]) on that index, so it shows exactly
//! what the next analysis of the same data will put in the zone.

use std::fmt::Write;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use pathwarden_core::config_edit::{zone_name_problem, ZoneEdit};
use pathwarden_core::model::NodeKind;
use pathwarden_core::object_index;
use pathwarden_core::zones::{self, ZoneConfig};
use serde::{Deserialize, Serialize};

use crate::pages::{self, esc, icon, num, Nav};
use crate::run_data;
use crate::server::AppState;
use crate::settings::{self, json_error};

type Shared = Arc<AppState>;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/zones", get(list_page))
        .route("/zones/new", get(new_page))
        .route("/zones/{index}/edit", get(edit_page))
        .route("/api/objects", get(search))
        .route("/api/zones/preview", post(preview))
        .route("/api/zones", post(save))
        .route("/api/zones/{index}", delete(remove))
}

// ----------------------------------------------------------------- pages

fn no_run_note() -> String {
    format!(
        r#"<div class="note">{}<p><strong>Zones are built from the objects of an analysis.</strong> Search and the live preview need one analysis first: <a href="/analyze">analyze a collection</a><span class="demo-offer">, or <button type="button" class="linkish" data-demo>try the demo</button></span>.</p></div>"#,
        icon("i-alert")
    )
}

fn latest_line(st: &AppState) -> String {
    match run_data::latest_with(&st.ws(), run_data::OBJECTS_FILE) {
        Some((r, _)) => format!(
            r#"<p class="muted small data-from">Objects from the latest analysis: <strong>{}</strong>, analyzed {}.</p>"#,
            esc(&r.environment()),
            pages::time(r.created_at)
        ),
        None => no_run_note(),
    }
}

async fn list_page(State(st): State<Shared>) -> Html<String> {
    let runs = st.ws().runs();
    let ctx = pages::Ctx::new(&st, &runs);
    let loaded = settings::load(&st);
    let sync = crate::sync_ui::view_for(&st, false).await;
    let mut b = format!(
        r#"<div class="page-head"><div><p class="eyebrow">Configure</p><h1 class="panel-title">Privilege Zones{tag}</h1>
<p class="lead">Sets of objects you protect like Tier Zero. Each report shows a zone's status, exposure and protected objects.</p></div>
<a class="btn primary" href="/zones/new">{} New zone</a></div>
{}{line}"#,
        icon("i-plus"),
        settings::file_line_if_there(&st, &loaded),
        tag = sync
            .as_ref()
            .map(|v| crate::sync_ui::tag(v, "zone"))
            .unwrap_or_default(),
        line = sync
            .as_ref()
            .map(|v| {
                let mut s = crate::sync_ui::sync_line(v, "zones");
                if let Some(block) = crate::sync_ui::conflict(v, "zone") {
                    s.push_str(&format!(
                        r#"<section class="card setting" id="zones-sync"><header><h2 class="sub">Zones<span class="stag both">{}</span></h2></header>{block}</section>"#,
                        crate::sync_ui::BOTH_TAG
                    ));
                }
                let reader = crate::sync_ui::reader_action(v, "zone");
                if !reader.is_empty() {
                    s.push_str(&format!(
                        r#"<div class="card-actions" id="zones-sync">{reader}<span class="save-status muted small" aria-live="polite"></span></div>"#
                    ));
                }
                s
            })
            .unwrap_or_default(),
    );
    let zones = &loaded.config.zones;
    if zones.is_empty() {
        let _ = write!(
            b,
            r#"<div class="empty card">{}<p><strong>No zones yet.</strong><br><span class="muted">Tier Zero is always protected. Add a zone for the next most important systems, for example "Tier 1 servers": the server OUs and the groups that administer them.</span></p></div>"#,
            icon("i-zone")
        );
    } else {
        b.push_str(r#"<div class="rows card zonelist">"#);
        for (i, z) in zones.iter().enumerate() {
            let mut parts = Vec::new();
            let count = |n: usize, one: &str, many: &str| {
                format!("{} {}", num(n), if n == 1 { one } else { many })
            };
            if !z.groups.is_empty() {
                parts.push(count(z.groups.len(), "group", "groups"));
            }
            if !z.ous.is_empty() {
                parts.push(count(z.ous.len(), "OU", "OUs"));
            }
            if !z.members.is_empty() {
                parts.push(count(z.members.len(), "named object", "named objects"));
            }
            let sample: Vec<&str> = z
                .groups
                .iter()
                .chain(&z.ous)
                .chain(&z.members)
                .map(String::as_str)
                .take(3)
                .collect();
            let more = (z.groups.len() + z.ous.len() + z.members.len()).saturating_sub(3);
            let _ = write!(
                b,
                r#"<div class="zonerow"><span class="zr-icon">{ic}</span><div class="zr-main"><a class="zr-name" href="/zones/{i}/edit">{name}</a><span class="zr-rules">{rules}</span><span class="zr-sample muted small">{sample}{more}</span>{problem}</div>
<div class="zr-actions"><a class="btn small-btn" href="/zones/{i}/edit">{i_edit} Edit</a><button type="button" class="btn small-btn danger" data-delete-zone="{i}" data-name="{name}" aria-label="Delete {name}">{i_trash}</button></div></div>"#,
                ic = icon("i-zone"),
                name = esc(&z.name),
                rules = parts.join(" · "),
                sample = esc(&sample.join(", ")),
                more = if more > 0 {
                    format!(" and {} more", num(more))
                } else {
                    String::new()
                },
                problem = zone_name_problem(zones, i)
                    .map(|p| {
                        format!(
                            r#"<span class="zr-problem small">{} {}</span>"#,
                            icon("i-alert"),
                            esc(&p)
                        )
                    })
                    .unwrap_or_default(),
                i_edit = icon("i-edit"),
                i_trash = icon("i-trash"),
            );
        }
        b.push_str("</div>");
    }
    let _ = write!(
        b,
        r#"<div class="note tips">{}<p><strong>How a zone is built.</strong> Pick objects one by one, groups (with everyone nested in them) and OUs (with everything below them, and the GPOs linked to them). Tier Zero is never part of a zone: it already sits above every zone. {}</p></div>
{}<script src="/static/config.js" defer></script>"#,
        icon("i-lock"),
        pages::repo_link("docs/privilege-zones.md", "Read the Privilege Zones guide"),
        settings::after_save(&st),
    );
    Html(pages::shell(&ctx, Some(Nav::Zones), "Zones", "config", &b))
}

#[derive(Deserialize)]
struct NewQuery {
    /// A zone handed over by the explorer ([`crate::explore_ui::draft`]).
    draft: Option<String>,
}

async fn new_page(State(st): State<Shared>, Query(q): Query<NewQuery>) -> Html<String> {
    let zone = q
        .draft
        .as_deref()
        .and_then(crate::explore_ui::draft)
        .unwrap_or_default();
    wizard(&st, None, &zone)
}

async fn edit_page(State(st): State<Shared>, Path(index): Path<usize>) -> Response {
    let loaded = settings::load(&st);
    match loaded.config.zones.get(index) {
        Some(z) => wizard(&st, Some(index), z).into_response(),
        None => (StatusCode::NOT_FOUND, Html(pages::not_found())).into_response(),
    }
}

#[derive(Serialize)]
struct WizardData<'a> {
    index: Option<usize>,
    name: &'a str,
    members: &'a [String],
    groups: &'a [String],
    ous: &'a [String],
}

fn wizard(st: &AppState, index: Option<usize>, z: &ZoneConfig) -> Html<String> {
    let runs = st.ws().runs();
    let ctx = pages::Ctx::new(st, &runs);
    let has_index = run_data::latest_with(&st.ws(), run_data::OBJECTS_FILE).is_some();
    let data = serde_json::to_string(&WizardData {
        index,
        name: &z.name,
        members: &z.members,
        groups: &z.groups,
        ous: &z.ous,
    })
    .unwrap_or_default();
    let title = if index.is_some() {
        format!("Edit {}", z.name)
    } else {
        "New zone".to_string()
    };
    let kinds = [
        ("", "All"),
        ("User", "Users"),
        ("Computer", "Computers"),
        ("Group", "Groups"),
        ("OU,Container", "OUs"),
        ("GPO", "GPOs"),
    ];
    let mut filter = String::new();
    for (i, (k, label)) in kinds.iter().enumerate() {
        let _ = write!(
            filter,
            r#"<label class="kchip"><input type="radio" name="kind" value="{k}"{c}><span>{label}</span></label>"#,
            c = if i == 0 { " checked" } else { "" }
        );
    }
    let body = format!(
        r##"<div class="page-head"><div><p class="eyebrow"><a href="/zones">Privilege Zones</a></p><h1 class="panel-title">{title}</h1>
<p class="lead">Name the zone, add what belongs in it, and check what it resolves to before saving.</p></div></div>
{stepper}
<form id="zone-wizard" class="wizard" data-zone="{data}" novalidate>
<section class="card wiz-panel" data-panel="1">
  <div class="field"><label for="zone-name">Zone name</label><input class="input big" id="zone-name" maxlength="100" placeholder="Tier 1 servers" autocomplete="off" required>
  <p class="hint">Shown in reports and used on the command line.</p></div>
  <div class="examples"><span class="muted small">Common zones:</span> <button type="button" class="kchip-btn" data-example="Tier 1 servers">Tier 1 servers</button><button type="button" class="kchip-btn" data-example="Finance">Finance</button><button type="button" class="kchip-btn" data-example="Workstations">Workstations</button><button type="button" class="kchip-btn" data-example="Hypervisors">Hypervisors</button></div>
  <div class="wiz-nav"><span></span><button type="button" class="btn primary" data-next>Next: members {i_arrow}</button></div>
</section>
<section class="wiz-panel" data-panel="2" hidden>
  <div class="wiz-cols">
    <div class="card wiz-main">
      <h2 class="sub first">Add members</h2>
      {latest}
      <div class="kfilter" role="radiogroup" aria-label="Kind">{filter}</div>
      {picker}
      <h3 class="form-title">In this zone <span class="count" id="pick-count">0</span></h3>
      <ul class="picks" id="picks" data-empty="Nothing added yet. Search above, or type a name, SID or distinguished name and press Add."></ul>
    </div>
    <aside class="card wiz-preview" id="preview" aria-live="polite">
      <h2 class="sub first">Live preview</h2>
      <div class="pv-body"><p class="muted small">Add members to see what the zone resolves to.</p></div>
    </aside>
  </div>
  <div class="wiz-nav"><button type="button" class="btn" data-prev>Back</button><button type="button" class="btn primary" data-next>Next: review {i_arrow}</button></div>
</section>
<section class="card wiz-panel" data-panel="3" hidden>
  <h2 class="sub first">Review</h2>
  <div class="review" id="review"></div>
  <div class="wiz-nav"><button type="button" class="btn" data-prev>Back</button><span class="save-status muted small" aria-live="polite"></span><button type="submit" class="btn primary" id="zone-save">{i_check} Save zone</button></div>
</section>
</form>
{saved}
<script src="/static/config.js" defer></script>"##,
        title = esc(&title),
        stepper = pages::stepper("wiz-steps", &["Name", "Members", "Review and save"], true),
        data = crate::pages::json_attr(&data),
        latest = latest_line(st),
        picker = settings::picker(
            "zp",
            "Search users, computers, groups, OUs and GPOs",
            "",
            has_index
        ),
        i_arrow = icon("i-arrow"),
        i_check = icon("i-check"),
        saved = settings::after_save(st),
    );
    Html(pages::shell(
        &ctx,
        Some(Nav::Zones),
        &title,
        "config",
        &body,
    ))
}

// ------------------------------------------------------------------- API

#[derive(Deserialize)]
struct SearchQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    kinds: String,
}

#[derive(Serialize)]
struct Hit {
    id: String,
    name: String,
    kind: &'static str,
    domain: Option<String>,
    dn: Option<String>,
    tier_zero: bool,
    /// What adding it means: `member`, `group` (with members) or `ou`.
    adds_as: &'static str,
}

/// Objects of the latest run matching `q`: at most [`run_data::SEARCH_LIMIT`].
async fn search(State(st): State<Shared>, Query(q): Query<SearchQuery>) -> Response {
    let query: String = q.q.chars().take(200).collect();
    let kinds: Vec<NodeKind> = q
        .kinds
        .split(',')
        .filter(|k| !k.trim().is_empty())
        .take(16)
        .map(|k| NodeKind::from_object_type(k.trim()))
        .collect();
    let ws = st.ws();
    let result = tokio::task::spawn_blocking(move || {
        let (_, dir) = run_data::latest_with(&ws, run_data::OBJECTS_FILE)?;
        let g = run_data::graph(&dir)?;
        let hits = object_index::search(&g, &query, &kinds, run_data::SEARCH_LIMIT);
        Some(
            hits.into_iter()
                .map(|ix| {
                    let n = g.node(ix);
                    Hit {
                        id: n.id.clone(),
                        name: n.name.clone(),
                        kind: n.kind.as_str(),
                        domain: n.domain.clone(),
                        dn: n.props.distinguishedname.clone(),
                        tier_zero: n.tier_zero,
                        adds_as: match n.kind {
                            NodeKind::Group => "group",
                            NodeKind::Ou | NodeKind::Container => "ou",
                            _ => "member",
                        },
                    }
                })
                .collect::<Vec<_>>(),
        )
    })
    .await
    .ok()
    .flatten();
    match result {
        Some(results) => Json(serde_json::json!({ "results": results })).into_response(),
        None => json_error(
            StatusCode::NOT_FOUND,
            "No analysis to search yet. Analyze a collection or try the demo first.",
        ),
    }
}

/// What a zone definition resolves to in the latest run.
async fn preview(State(st): State<Shared>, Json(z): Json<ZoneEdit>) -> Response {
    let config = ZoneConfig {
        name: z.name.chars().take(100).collect(),
        members: cap(z.members),
        groups: cap(z.groups),
        ous: cap(z.ous),
        ..Default::default()
    };
    let ws = st.ws();
    let result = tokio::task::spawn_blocking(move || {
        let (run, dir) = run_data::latest_with(&ws, run_data::OBJECTS_FILE)?;
        let g = run_data::graph(&dir)?;
        Some((
            run.environment(),
            zones::preview(&g, &config, zones::PREVIEW_SAMPLE),
        ))
    })
    .await
    .ok()
    .flatten();
    match result {
        Some((env, p)) => {
            let warnings = p.warnings("the latest analysis");
            Json(serde_json::json!({ "environment": env, "preview": p, "warnings": warnings }))
                .into_response()
        }
        None => json_error(
            StatusCode::NOT_FOUND,
            "The preview needs one analysis first. Analyze a collection or try the demo.",
        ),
    }
}

fn cap(list: Vec<String>) -> Vec<String> {
    list.into_iter()
        .take(10_000)
        .map(|s| s.chars().take(2048).collect())
        .collect()
}

#[derive(Deserialize)]
struct SaveBody {
    index: Option<usize>,
    expect: Option<String>,
    zone: ZoneEdit,
}

async fn save(
    State(st): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SaveBody>,
) -> Response {
    if let Some(r) = settings::stale_page(&st, &headers, &["zone"]) {
        return r;
    }
    settings::edit(&st, move |d| {
        d.upsert_zone(body.index, body.expect.as_deref(), &body.zone)
    })
    .await
}

#[derive(Deserialize)]
struct RemoveBody {
    expect: String,
}

async fn remove(
    State(st): State<Shared>,
    Path(index): Path<usize>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RemoveBody>,
) -> Response {
    if let Some(r) = settings::stale_page(&st, &headers, &["zone"]) {
        return r;
    }
    let loaded = settings::load(&st);
    if loaded.error.is_none() && index >= loaded.config.zones.len() {
        return json_error(
            StatusCode::NOT_FOUND,
            format!("No zone {index}: reload the page, pathwarden.toml may have changed."),
        );
    }
    settings::edit(&st, move |d| d.remove_zone(index, &body.expect)).await
}
