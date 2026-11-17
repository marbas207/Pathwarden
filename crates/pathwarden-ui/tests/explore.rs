//! The graph explorer through the router: its answers match core's
//! analysis on the test forest, every list is capped, names that look like
//! markup stay data, older runs ask to be re-analyzed, and zone drafts reach
//! the Zone wizard without writing the config.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_core::analysis;
use pathwarden_core::NodeIndex;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const PORT: u16 = 4244;
const HOST: &str = "127.0.0.1:4244";
const MARKUP: &str = "<IMG SRC=X ONERROR=ALERT(1)>@CONTOSO.LOCAL";

struct App {
    router: Router,
    state: Arc<AppState>,
    dir: PathBuf,
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn app(name: &str) -> App {
    let dir = std::env::temp_dir().join(format!("pathwarden-xp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(&dir).unwrap();
    let state = Arc::new(AppState::new(ws, Token::generate().unwrap(), PORT));
    App {
        router: router(state.clone()),
        state,
        dir,
    }
}

fn forest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest")
}

impl App {
    fn request(&self, method: Method, uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    async fn get(&self, uri: &str) -> (StatusCode, String) {
        let (s, _, b) = self
            .send(self.request(Method::GET, uri).body(Body::empty()).unwrap())
            .await;
        (s, b)
    }

    async fn api(&self, uri: &str) -> (StatusCode, Value) {
        let (s, b) = self.get(uri).await;
        (s, serde_json::from_str(&b).unwrap_or(Value::Null))
    }

    async fn post(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        let req = self
            .request(Method::POST, uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        let (s, _, b) = self.send(req).await;
        (s, serde_json::from_str(&b).unwrap_or(Value::Null))
    }

    async fn analyze(&self, path: &Path) -> String {
        let boundary = "xpTestBoundary";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{}\r\n--{boundary}--\r\n",
            path.display()
        );
        let req = self
            .request(Method::POST, "/api/analyze")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body))
            .unwrap();
        let (s, _, b) = self.send(req).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        let job = serde_json::from_str::<Value>(&b).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string();
        for _ in 0..600 {
            let (_, v) = self.api(&format!("/api/jobs/{job}")).await;
            if v["status"] == "done" {
                return v["run"].as_str().unwrap().to_string();
            }
            assert_ne!(v["status"], "failed", "{v}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("analysis did not finish");
    }

    /// The node number of `name` in run `run`, through search.
    async fn ix(&self, run: &str, name: &str) -> u64 {
        let (s, v) = self
            .api(&format!("/api/runs/{run}/explore/search?q={}", enc(name)))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap_or_else(|| panic!("{name} not found: {v}"))["ix"]
            .as_u64()
            .unwrap()
    }
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[tokio::test]
async fn answers_match_the_analysis() {
    let a = app("answers");
    let run = a.analyze(&forest()).await;
    let dir = a.state.ws().run_dir(&run).unwrap();
    assert!(dir.join("graph.bin.gz").is_file());
    let (g, _) = pathwarden_core::load(&[forest()], &Default::default()).unwrap();

    let (s, info) = a.api(&format!("/api/runs/{run}/explore")).await;
    assert_eq!(s, StatusCode::OK, "{info}");
    assert_eq!(info["objects"], g.node_count());
    assert_eq!(info["edges"], g.edge_count());
    assert!(!info["findings"].as_array().unwrap().is_empty());

    // Neighbors: every outbound edge of JDOE, as the graph has them.
    let jdoe = a.ix(&run, "JDOE@CONTOSO.LOCAL").await;
    let (_, v) = a
        .api(&format!(
            "/api/runs/{run}/explore/neighbors?ix={jdoe}&dir=out"
        ))
        .await;
    let want = g.inner().edges(NodeIndex::new(jdoe as usize)).count();
    assert_eq!(v["total"], want, "{v}");
    assert_eq!(v["edges"].as_array().unwrap().len(), want);
    assert!(v["edges"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["s"] == jdoe));
    let (_, v) = a
        .api(&format!(
            "/api/runs/{run}/explore/neighbors?ix={jdoe}&dir=out&kinds=MemberOf"
        ))
        .await;
    assert!(v["edges"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["k"] == "MemberOf"));

    // Path to Tier Zero: the analysis's own shortest path, step for step.
    let (_, v) = a
        .api(&format!("/api/runs/{run}/explore/path?from={jdoe}&to=t0"))
        .await;
    let theirs = analysis::path_to_tier_zero(&g, NodeIndex::new(jdoe as usize)).unwrap();
    let ours = v["paths"][0].as_array().unwrap();
    assert_eq!(ours.len(), theirs.steps.len(), "{v}");
    for (e, step) in ours.iter().zip(&theirs.steps) {
        assert_eq!(e["k"], step.edge.as_str());
        let to = g.node(NodeIndex::new(e["t"].as_u64().unwrap() as usize));
        assert_eq!(to.name, step.to);
    }
    // k-shortest: shortest first, and capped.
    let (_, v) = a
        .api(&format!(
            "/api/runs/{run}/explore/path?from={jdoe}&to=t0&k=50"
        ))
        .await;
    let paths = v["paths"].as_array().unwrap();
    assert!(!paths.is_empty() && paths.len() <= 5);
    assert_eq!(paths[0].as_array().unwrap().len(), theirs.steps.len());
    for w in paths.windows(2) {
        assert!(w[0].as_array().unwrap().len() <= w[1].as_array().unwrap().len());
    }
    // Between two objects.
    let da = a.ix(&run, "DA_ALICE@CONTOSO.LOCAL").await;
    let (_, v) = a
        .api(&format!("/api/runs/{run}/explore/path?from={jdoe}&to={da}"))
        .await;
    let theirs = analysis::shortest_path(
        &g,
        NodeIndex::new(jdoe as usize),
        NodeIndex::new(da as usize),
    )
    .unwrap();
    assert_eq!(v["paths"][0].as_array().unwrap().len(), theirs.steps.len());

    // Who can reach DA_ALICE: unprivileged users and computers first,
    // fewest hops first within each group.
    let (_, v) = a
        .api(&format!("/api/runs/{run}/explore/reach?ix={da}"))
        .await;
    let items = v["items"].as_array().unwrap();
    assert!(!items.is_empty(), "{v}");
    assert_eq!(items[0]["class"], 0, "{v}");
    let keys: Vec<(u64, u64)> = items
        .iter()
        .map(|i| (i["class"].as_u64().unwrap(), i["hops"].as_u64().unwrap()))
        .collect();
    assert!(keys.windows(2).all(|w| w[0] <= w[1]), "{keys:?}");
    assert!(items
        .iter()
        .any(|i| i["node"]["name"] == "JDOE@CONTOSO.LOCAL"));
    for i in items {
        assert_eq!(i["first"]["s"], i["node"]["ix"]);
        assert_eq!(i["first"]["t"], i["via"]["ix"]);
    }
    // The words come with the answer, as `pathwarden reach` prints them.
    assert_eq!(
        v["summary"],
        pathwarden_core::explore::answers::reach_summary(v["total"].as_u64().unwrap() as usize)
    );
    let classes = v["classes"].as_array().unwrap();
    assert_eq!(
        classes.iter().map(|c| c.as_u64().unwrap()).sum::<u64>(),
        v["total"].as_u64().unwrap()
    );
    // One class, paged.
    let (_, page) = a
        .api(&format!(
            "/api/runs/{run}/explore/reach?ix={da}&class=0&limit=1&offset=1"
        ))
        .await;
    assert_eq!(page["filtered"], classes[0]);
    assert!(page["items"].as_array().unwrap().len() <= 1);
    assert!(page["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|i| i["class"] == 0));

    // Object details.
    let (_, v) = a
        .api(&format!("/api/runs/{run}/explore/node?ix={da}"))
        .await;
    assert_eq!(v["node"]["t0"], true);
    assert!(v["tier_zero_reason"].is_string(), "{v}");
    let (_, v) = a
        .api(&format!("/api/runs/{run}/explore/node?ix={jdoe}"))
        .await;
    assert_eq!(v["t0_hops"], theirs_hops(&g, jdoe));

    // Suggestions: outside Tier Zero, explained, and SRV01 (a Tier Zero
    // account logs on to it) among them.
    let (_, v) = a.api(&format!("/api/runs/{run}/explore/suggestions")).await;
    assert!(
        v["intro"]
            .as_str()
            .unwrap()
            .starts_with("Candidates for Tier 1"),
        "{v}"
    );
    let heads: Vec<&str> = v["heuristics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["title"].as_str().unwrap())
        .collect();
    assert_eq!(
        heads,
        [
            "Objects many paths cross",
            "Control over many objects",
            "Privileged logons"
        ]
    );
    let items = v["items"].as_array().unwrap();
    assert!(!items.is_empty(), "{v}");
    for i in items {
        assert!(i["node"]["t0"].is_null(), "{i}");
        assert!(i["reason"].as_str().unwrap().len() > 20);
        assert!(matches!(i["tier"].as_u64(), Some(1 | 2)));
    }
    assert!(items
        .iter()
        .any(|i| i["heuristic"] == "privileged_sessions"
            && i["node"]["name"] == "SRV01.CONTOSO.LOCAL"));

    // A finding with a path opens on it, with paging.
    let findings = info["findings"].as_array().unwrap();
    let with_path = findings.iter().find(|f| f["path"] == true).unwrap();
    let (s, v) = a
        .api(&format!(
            "/api/runs/{run}/explore/finding?fp={}",
            with_path["fp"].as_str().unwrap()
        ))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let nodes = v["path"]["nodes"].as_array().unwrap();
    assert_eq!(
        nodes.len(),
        v["path"]["edges"].as_array().unwrap().len() + 1
    );
    assert_eq!(v["count"], findings.len());
    let i = v["position"].as_u64().unwrap() as usize;
    assert_eq!(findings[i]["fp"], with_path["fp"]);
    if i + 1 < findings.len() {
        assert_eq!(v["next"], findings[i + 1]["fp"]);
    }
    // A finding without a path sends links only for the relationship it is
    // about (PW-004: sessions); any other rule's objects stay a grid.
    let mut sessions = 0;
    for f in findings.iter().filter(|f| f["path"] == false) {
        let (s, v) = a
            .api(&format!(
                "/api/runs/{run}/explore/finding?fp={}",
                f["fp"].as_str().unwrap()
            ))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        for l in v["links"].as_array().unwrap() {
            assert_eq!(v["finding"]["rule"], "PW-004", "{l}");
            assert_eq!(l["k"], "HasSession", "{l}");
            sessions += 1;
        }
    }
    assert!(
        sessions > 0,
        "the forest has a PW-004 finding with sessions"
    );
    let (s, _) = a
        .api(&format!("/api/runs/{run}/explore/finding?fp=PW-000-nope"))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

fn theirs_hops(g: &pathwarden_core::AdGraph, ix: u64) -> Value {
    analysis::path_to_tier_zero(g, NodeIndex::new(ix as usize))
        .map(|p| json!(p.steps.len()))
        .unwrap_or(Value::Null)
}

#[tokio::test]
async fn answers_are_capped_and_checked() {
    let a = app("caps");
    let run = a.analyze(&forest()).await;
    let du = a.ix(&run, "DOMAIN USERS@CONTOSO.LOCAL").await;
    let (_, v) = a
        .api(&format!(
            "/api/runs/{run}/explore/neighbors?ix={du}&dir=both&limit=1"
        ))
        .await;
    assert_eq!(v["edges"].as_array().unwrap().len(), 1);
    assert!(v["total"].as_u64().unwrap() > 1);
    let (_, v) = a
        .api(&format!(
            "/api/runs/{run}/explore/neighbors?ix={du}&dir=both&limit=999999"
        ))
        .await;
    assert!(v["edges"].as_array().unwrap().len() <= 500);
    let (_, v) = a
        .api(&format!(
            "/api/runs/{run}/explore/reach?ix={du}&limit=999999"
        ))
        .await;
    assert!(v["items"].as_array().unwrap().len() <= 200);
    let (_, v) = a
        .api(&format!("/api/runs/{run}/explore/search?q=contoso"))
        .await;
    assert!(v["results"].as_array().unwrap().len() <= 20);

    for uri in [
        "neighbors?ix=99999999",
        "neighbors",
        "node?ix=4294967295",
        "path?from=0&to=99999999",
        "reach?ix=-1",
    ] {
        let (s, v) = a.api(&format!("/api/runs/{run}/explore/{uri}")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri}: {v}");
    }
    let (s, _) = a.api("/api/runs/20000101-000000-000000/explore").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = a.api("/api/runs/..%2f..%2fetc/explore").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Read-only: the API takes no writes.
    let req = a
        .request(Method::POST, &format!("/api/runs/{run}/explore/neighbors"))
        .header(header::ORIGIN, format!("http://{HOST}"))
        .body(Body::empty())
        .unwrap();
    let (s, _, _) = a.send(req).await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn the_page_and_its_assets() {
    let a = app("page");
    let run = a.analyze(&forest()).await;
    let (s, body) = a.get(&format!("/runs/{run}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(&format!("/runs/{run}/explore")));

    let (s, body) = a
        .get(&format!("/runs/{run}/explore?finding=PW-001-abc&node=3"))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(r#"data-finding="PW-001-abc""#));
    assert!(body.contains(r#"data-node="3""#));
    assert!(body.contains("/static/vendor/cytoscape.min.js"));
    assert!(!body.contains("<script>"), "no inline scripts");
    assert!(!body.contains(" style=\""), "no inline styles");
    // Anything but a fingerprint is dropped.
    let (_, body) = a
        .get(&format!(
            "/runs/{run}/explore?finding=%22%3E%3Cscript%3Ealert(1)%3C/script%3E"
        ))
        .await;
    assert!(body.contains(r#"data-finding="""#));
    assert!(!body.contains("<script>alert"));

    for (uri, ty) in [
        ("/static/explore.js", "text/javascript"),
        ("/static/explore.css", "text/css"),
        ("/static/vendor/cytoscape.min.js", "text/javascript"),
    ] {
        let req = a.request(Method::GET, uri).body(Body::empty()).unwrap();
        let (s, h, b) = a.send(req).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        assert_eq!(h[header::CONTENT_TYPE], ty);
        assert!(h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("script-src 'self'"));
        assert!(b.len() > 1000);
    }

    // A run from before the explorer: the page and the API ask for a
    // re-analysis.
    let dir = a.state.ws().run_dir(&run).unwrap();
    std::fs::remove_file(dir.join("graph.bin.gz")).unwrap();
    let (s, body) = a.get(&format!("/runs/{run}/explore")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("Re-analyze to explore"));
    assert!(!body.contains("/static/explore.js"));
    let (s, v) = a.api(&format!("/api/runs/{run}/explore")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(v["reanalyze"], true);
}

/// A Tier Zero account logged on to more hosts than are shown: the finding
/// sends its first objects, the account among those the page draws (24),
/// and every link runs from a host into the account.
#[tokio::test]
async fn many_sessions_link_only_to_the_account() {
    let a = app("sessions");
    let src = a.dir.join("collection");
    std::fs::create_dir_all(&src).unwrap();
    for e in std::fs::read_dir(forest()).unwrap().flatten() {
        std::fs::copy(e.path(), src.join(e.file_name())).unwrap();
    }
    const HOSTS: usize = 30;
    let da = "S-1-5-21-1000-1000-1000-1101";
    let computers: Vec<Value> = (1..=HOSTS)
        .map(|i| {
            let sid = format!("S-1-5-21-1000-1000-1000-{}", 3000 + i);
            json!({
                "ObjectIdentifier": sid,
                "PrimaryGroupSID": "S-1-5-21-1000-1000-1000-515",
                "Properties": {
                    "name": format!("WSX{i:02}.CONTOSO.LOCAL"),
                    "domain": "CONTOSO.LOCAL",
                    "domainsid": "S-1-5-21-1000-1000-1000",
                    "enabled": true
                },
                "Sessions": {
                    "Results": [{ "UserSID": da, "ComputerSID": sid }],
                    "Collected": true
                },
                "Aces": []
            })
        })
        .collect();
    let file = json!({
        "data": computers,
        "meta": { "methods": 0, "type": "computers", "count": HOSTS, "version": 6 }
    });
    std::fs::write(src.join("extra_computers.json"), file.to_string()).unwrap();
    let run = a.analyze(&src).await;

    let (_, info) = a.api(&format!("/api/runs/{run}/explore")).await;
    let da_ix = a.ix(&run, "DA_ALICE@CONTOSO.LOCAL").await;
    let mut seen = false;
    for f in info["findings"].as_array().unwrap() {
        if f["rule"] != "PW-004" {
            continue;
        }
        let (s, v) = a
            .api(&format!(
                "/api/runs/{run}/explore/finding?fp={}",
                f["fp"].as_str().unwrap()
            ))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        if v["hits"][0] != da_ix {
            continue;
        }
        seen = true;
        // SRV01 and the 30 new hosts, plus the account.
        assert_eq!(v["finding"]["affected_total"], HOSTS + 2, "{v}");
        let affected: Vec<u64> = v["affected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap())
            .collect();
        assert!(affected.len() <= pathwarden_ui::explore_ui::FINDING_OBJECTS);
        // The page draws the account's links when it is among what it shows.
        assert!(affected.contains(&da_ix), "{v}");
        let links = v["links"].as_array().unwrap();
        assert_eq!(links.len(), affected.len() - 1, "{v}");
        for l in links {
            assert_eq!(l["t"], da_ix, "{l}");
            assert_eq!(l["k"], "HasSession", "{l}");
            assert!(affected.contains(&l["s"].as_u64().unwrap()), "{l}");
        }
    }
    assert!(seen, "a PW-004 finding for DA_ALICE");
}

#[tokio::test]
async fn names_that_look_like_markup_stay_text() {
    let a = app("markup");
    // The test forest with a user renamed to markup.
    let src = a.dir.join("collection");
    std::fs::create_dir_all(&src).unwrap();
    for e in std::fs::read_dir(forest()).unwrap().flatten() {
        let text = std::fs::read_to_string(e.path()).unwrap();
        let text = text.replace("JDOE@CONTOSO.LOCAL", MARKUP);
        std::fs::write(src.join(e.file_name()), text).unwrap();
    }
    let run = a.analyze(&src).await;
    let req = a
        .request(
            Method::GET,
            &format!("/api/runs/{run}/explore/search?q=onerror"),
        )
        .body(Body::empty())
        .unwrap();
    let (_, h, body) = a.send(req).await;
    assert_eq!(h[header::CONTENT_TYPE], "application/json");
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["results"][0]["name"], MARKUP);
    let ix = v["results"][0]["ix"].as_u64().unwrap();

    // Every answer carries it as JSON data.
    for uri in [
        format!("node?ix={ix}"),
        format!("neighbors?ix={ix}&dir=both"),
        format!("path?from={ix}&to=t0"),
    ] {
        let (s, v) = a.api(&format!("/api/runs/{run}/explore/{uri}")).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        assert!(v.to_string().contains("ONERROR"), "{uri}");
    }
    let (_, info) = a.api(&format!("/api/runs/{run}/explore")).await;
    let marked = info["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["title"].as_str().unwrap().contains("<IMG"));
    if let Some(f) = marked {
        let (_, v) = a
            .api(&format!(
                "/api/runs/{run}/explore/finding?fp={}",
                f["fp"].as_str().unwrap()
            ))
            .await;
        assert!(v["finding"]["title"].as_str().unwrap().contains("<IMG"));
    }

    // The pages render no object names on the server, so nothing to escape
    // wrongly; the script sets them as text.
    for uri in [
        format!("/runs/{run}/explore"),
        format!("/runs/{run}/explore?node={ix}"),
    ] {
        let (s, body) = a.get(&uri).await;
        assert_eq!(s, StatusCode::OK);
        assert!(!body.contains("<IMG"), "{uri}");
    }
    let js = pathwarden_ui::explore_ui::script();
    assert!(
        !js.contains(".innerHTML"),
        "explore.js must not use innerHTML"
    );
    assert!(!js.contains("insertAdjacentHTML"));

    // A zone draft with the name reaches the wizard escaped.
    let (s, v) = a
        .post(
            "/api/zones/draft",
            json!({"name": "Tier 1 candidates", "members": [MARKUP], "groups": ["HELPDESK@CONTOSO.LOCAL"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, body) = a.get(v["url"].as_str().unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!body.contains("<IMG"));
    assert!(body.contains("&lt;IMG SRC=X ONERROR=ALERT(1)&gt;"));
    assert!(body.contains("HELPDESK@CONTOSO.LOCAL"));
    assert!(body.contains("Tier 1 candidates"));
}

/// Prepared queries: the list as `--list-prepared --json` gives it,
/// run by GUID from the pinned text; hidden ones and placeholders refused.
#[tokio::test]
async fn prepared_queries_run_by_guid() {
    let a = app("prepared");
    let run = a.analyze(&forest()).await;
    let (s, v) = a.api("/api/prepared").await;
    assert_eq!(s, StatusCode::OK);
    let list = v["queries"].as_array().unwrap();
    assert_eq!(
        list.len(),
        pathwarden_core::prepared::library().offered().len()
    );
    assert!(list.iter().all(|q| q["supported"] == true));
    assert_eq!(
        v["notice"],
        "BloodHound Query Library \u{a9} 2025 SpecterOps. MIT License."
    );
    let q = "/api/runs/{run}/explore/query".replace("{run}", &run);
    // The examples, picked by what the shipped lists say about them.
    use pathwarden_core::prepared::{Prepared, Unsupported};
    let lib = pathwarden_core::prepared::library();
    let pick = |f: &dyn Fn(&Prepared) -> bool| lib.all.iter().find(|q| f(q)).expect("an example");
    for ok in [
        pick(&|q| q.supported && !q.edit_first && q.returns == "paths"),
        pick(&|q| q.supported && !q.edit_first && q.returns == "objects"),
    ] {
        let (s, v) = a.post(&q, json!({"prepared": ok.guid})).await;
        assert_eq!(s, StatusCode::OK, "{}: {v}", ok.name);
        assert!(v["draw"].is_array());
    }
    // Hidden, for either reason: refused with the reason.
    for hidden in [
        pick(&|q| matches!(q.unsupported, Some(Unsupported::Cypher(_)))),
        pick(&|q| matches!(q.unsupported, Some(Unsupported::Fields(_)))),
    ] {
        let (s, v) = a.post(&q, json!({"prepared": hidden.guid})).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(
            v["error"],
            hidden.reason.clone().unwrap(),
            "{}",
            hidden.name
        );
    }
    // A placeholder to replace first.
    let edit = pick(&|q| q.supported && q.edit_first);
    let (s, v) = a.post(&q, json!({"prepared": edit.guid})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(v["error"].as_str().unwrap().contains("placeholder"), "{v}");
    let (s, _) = a.post(&q, json!({"prepared": "nope"})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

/// The Query tab: Cypher on the saved run gives the analysis's
/// paths, what to draw for each, plain refusals; "Mark as owned" keeps the
/// mark in the environment, where queries and `pathwarden owned` see it.
#[tokio::test]
async fn the_query_tab_answers_from_the_saved_run() {
    let a = app("query");
    let run = a.analyze(&forest()).await;
    let (g, _) = pathwarden_core::load(&[forest()], &Default::default()).unwrap();
    let q = "/api/runs/{run}/explore/query".replace("{run}", &run);

    // Shortest paths to Tier Zero: each the analysis's own, drawn from its
    // start.
    let (s, v) = a
        .post(
            &q,
            json!({"cypher": "MATCH p=shortestPath((s:User)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero)) WHERE s<>t RETURN p"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let draw = v["draw"].as_array().unwrap();
    assert!(!draw.is_empty());
    assert_eq!(draw.len(), v["answer"]["paths"].as_array().unwrap().len());
    for d in draw {
        let nodes: Vec<u64> = d["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap())
            .collect();
        let from = NodeIndex::new(nodes[0] as usize);
        let to = NodeIndex::new(*nodes.last().unwrap() as usize);
        let want = analysis::shortest_path(&g, from, to).unwrap();
        assert_eq!(d["edges"].as_array().unwrap().len(), want.steps.len());
        for (e, step) in d["edges"].as_array().unwrap().iter().zip(&want.steps) {
            assert_eq!(e["k"], step.edge.as_str());
        }
        // Every node it draws comes with the answer.
        for n in &nodes {
            assert!(v["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x["ix"].as_u64() == Some(*n)));
        }
    }

    // What isn't supported says so, as a sentence.
    let (s, v) = a
        .post(&q, json!({"cypher": "MATCH (n) WITH n RETURN n"}))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"], "WITH is not supported yet (position 10).");

    // Owned marks: none, then one, kept in the environment.
    let owned = "/api/runs/{run}/explore/owned".replace("{run}", &run);
    let (_, v) = a.api(&owned).await;
    assert_eq!(v["count"], 0);
    assert_eq!(v["text"], "No object is marked as owned.");
    let jdoe = a.ix(&run, "JDOE@CONTOSO.LOCAL").await;
    let (s, v) = a.post(&owned, json!({"ix": jdoe, "owned": true})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["text"], "1 object is marked as owned.");
    let (_, v) = a
        .api(&format!("/api/runs/{run}/explore/node?ix={jdoe}"))
        .await;
    assert_eq!(v["owned"], true);
    let env_dir = a.state.ws().env_dir();
    assert_eq!(
        pathwarden_core::owned::load(&env_dir).unwrap(),
        [g.node(NodeIndex::new(jdoe as usize)).id.clone()]
    );
    let (_, v) = a
        .post(
            &q,
            json!({"cypher": "MATCH p=shortestPath((s:Tag_Owned)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero)) WHERE s<>t RETURN p"}),
        )
        .await;
    assert_eq!(v["owned"]["count"], 1);
    let draw = v["draw"].as_array().unwrap();
    assert!(!draw.is_empty());
    assert!(draw.iter().all(|d| d["nodes"][0].as_u64() == Some(jdoe)));
    let (_, v) = a.post(&owned, json!({"ix": jdoe, "owned": false})).await;
    assert_eq!(v["count"], 0);
    let (_, v) = a
        .post(&q, json!({"cypher": "MATCH (n:Tag_Owned) RETURN n"}))
        .await;
    assert!(v["answer"]["rows"].as_array().unwrap().is_empty());
    assert_eq!(
        v["answer"]["warnings"][0],
        "No object is marked as owned, so Tag_Owned matches nothing."
    );

    // A newer Pathwarden's marks: queries run without them and say why,
    // marking is refused with the same sentence, and no path is shown.
    std::fs::write(
        env_dir.join(pathwarden_core::owned::FILE),
        r#"{"version": 9, "marks": {}}"#,
    )
    .unwrap();
    let (s, v) = a.api(&owned).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["count"], 0);
    assert_eq!(v["text"], pathwarden_core::owned::NEWER);
    let (s, v) = a
        .post(&q, json!({"cypher": "MATCH (n:Tag_Owned) RETURN n"}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let warnings = v["answer"]["warnings"].as_array().unwrap();
    assert!(
        warnings.iter().any(|w| w == pathwarden_core::owned::NEWER),
        "{v}"
    );
    let (s, v) = a.post(&owned, json!({"ix": jdoe, "owned": true})).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["error"], pathwarden_core::owned::NEWER);
    assert!(!v.to_string().contains(&*env_dir.display().to_string()));
    let (_, v) = a
        .api(&format!("/api/runs/{run}/explore/node?ix={jdoe}"))
        .await;
    assert_eq!(v["owned"], false);

    // A query past the size limit is refused.
    let long = "x".repeat(pathwarden_ui::explore_ui::MAX_QUERY_BYTES + 1);
    let (s, v) = a.post(&q, json!({ "cypher": long })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"], "The query is too long.");
}

#[tokio::test]
async fn zone_drafts_write_nothing() {
    let a = app("drafts");
    let (s, v) = a.post("/api/zones/draft", json!({"name": "x"})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, v) = a
        .post(
            "/api/zones/draft",
            json!({"name": "Tier 2", "members": ["WS01.CONTOSO.LOCAL"], "ous": ["WORKSTATIONS@CONTOSO.LOCAL"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        !a.state.ws().config_path().exists(),
        "a draft writes no config"
    );
    let (_, body) = a.get(v["url"].as_str().unwrap()).await;
    assert!(body.contains("WORKSTATIONS@CONTOSO.LOCAL"));
    // Unknown drafts give an empty wizard.
    let (s, body) = a.get("/zones/new?draft=nope").await;
    assert_eq!(s, StatusCode::OK);
    assert!(!body.contains("WS01"));
    // From another origin: refused.
    let req = a
        .request(Method::POST, "/api/zones/draft")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "http://evil.example")
        .body(Body::from(json!({"members": ["A"]}).to_string()))
        .unwrap();
    let (s, _, _) = a.send(req).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_rail_entry_opens_the_newest_explorable_run() {
    let a = app("rail");
    // Nothing analyzed yet: a page saying what to do first.
    let (s, page) = a.get("/explore").await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("Nothing to explore yet"), "{page}");
    assert!(
        page.contains(r#"href="/explore""#),
        "the rail has an Explore entry"
    );
    // After an analysis: straight to that run's explorer.
    let run = a.analyze(&forest()).await;
    let (s, headers, _) = a
        .send(
            a.request(Method::GET, "/explore")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], format!("/runs/{run}/explore"));
}

/// The Forest view's "Show": the rights one domain's principals hold in
/// another, as the forest map lists them, drawn as objects and
/// relationships; the page offers the Forest mode.
#[tokio::test]
async fn crossing_rights_are_drawn_from_the_map() {
    let a = app("crossing");
    // The test forest with CAROL of the child domain in CONTOSO's HELPDESK.
    let data = a.dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    for e in std::fs::read_dir(forest()).unwrap() {
        let p = e.unwrap().path();
        std::fs::copy(&p, data.join(p.file_name().unwrap())).unwrap();
    }
    let groups = data.join("contoso_groups.json");
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&groups).unwrap()).unwrap();
    v["data"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|g| g["ObjectIdentifier"] == "S-1-5-21-1000-1000-1000-1150")
        .unwrap()["Members"]
        .as_array_mut()
        .unwrap()
        .push(json!({"ObjectIdentifier": "S-1-5-21-2000-2000-2000-1202", "ObjectType": "User"}));
    std::fs::write(&groups, v.to_string()).unwrap();
    let run = a.analyze(&data).await;

    let (s, v) = a
        .api(&format!(
            "/api/runs/{run}/explore/crossing?from=child.contoso.local&to=CONTOSO.LOCAL"
        ))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["counts"], "1 group membership");
    assert_eq!(
        (v["counted"].as_u64(), v["listed"].as_u64()),
        (Some(1), Some(1))
    );
    let edges = v["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0]["k"], "MemberOf");
    let name = |ix: &Value| {
        v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["ix"] == *ix)
            .map(|n| n["name"].as_str().unwrap().to_string())
            .unwrap()
    };
    assert_eq!(name(&edges[0]["s"]), "CAROL@CHILD.CONTOSO.LOCAL");
    assert_eq!(name(&edges[0]["t"]), "HELPDESK@CONTOSO.LOCAL");

    // Nothing the other way.
    let (s, _) = a
        .api(&format!(
            "/api/runs/{run}/explore/crossing?from=CONTOSO.LOCAL&to=FABRIKAM.COM"
        ))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, page) = a.get(&format!("/runs/{run}/explore?view=forest")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains(r#"value="forest""#), "the Forest mode");
    assert!(page.contains(r#"data-view="forest""#));
    // The legend's and the script's words are core's.
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    };
    for key in [
        "not_collected",
        "between",
        "between_abuse",
        "inside",
        "way_in",
    ] {
        let def = pathwarden_core::forest::definition(key);
        assert!(!def.is_empty());
        assert!(
            page.contains(&format!("data-def=\"{}\"", esc(&def))),
            "{key}"
        );
    }
    assert!(page.contains(&esc(&serde_json::to_string(
        pathwarden_core::forest::NOT_A_PATH_STEP
    )
    .unwrap())));
    assert!(!page.contains("never cross"), "no overclaim");
    // Switching runs keeps the Forest view.
    assert!(
        page.contains(&format!("/runs/{run}/explore?view=forest")),
        "the run picker carries the view"
    );
    let (s, headers, _) = a
        .send(
            a.request(Method::GET, "/explore?view=forest")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(
        headers[header::LOCATION],
        format!("/runs/{run}/explore?view=forest")
    );
}

/// The forest map: the run's domains and trusts as the analysis builds
/// them, which `pathwarden summary --json` also gives; a run saved before
/// the map was kept asks to be analyzed again.
#[tokio::test]
async fn the_forest_map_is_the_analysis_one() {
    let a = app("forest");
    let run = a.analyze(&forest()).await;
    let (s, v) = a.api(&format!("/api/runs/{run}/explore/forest")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let names: Vec<&str> = v["domains"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["CONTOSO.LOCAL", "CHILD.CONTOSO.LOCAL", "FABRIKAM.COM"]
    );
    assert_eq!(v["forests"].as_array().unwrap().len(), 2);
    let trusts = v["trusts"].as_array().unwrap();
    assert_eq!(trusts.len(), 2);
    assert_eq!(trusts[0]["enables_forest_takeover"], true);
    assert_eq!(trusts[1]["abusable_sid_history"], true);
    let config = pathwarden_core::config::Config::default();
    let analysis = pathwarden_core::analyze::run(&[forest()], &config, &[], &mut |_| {}).unwrap();
    assert_eq!(
        v,
        serde_json::to_value(analysis.forest_map().document()).unwrap()
    );

    // The same run, saved as before the map was kept.
    let old = app("forest-old");
    let run = old.analyze(&forest()).await;
    let dir = old.state.ws().run_dir(&run).unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    pathwarden_core::explore::encode_to(
        &mut gz,
        &analysis.graph,
        &analysis.findings,
        &analysis.zones,
    )
    .unwrap();
    std::fs::write(dir.join("graph.bin.gz"), gz.finish().unwrap()).unwrap();
    let (s, v) = old.api(&format!("/api/runs/{run}/explore/forest")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    assert_eq!(v["reanalyze"], true);
    assert!(v["error"].as_str().unwrap().contains("trusts"));
    // The rest of the explorer still works on it.
    let (s, _) = old.api(&format!("/api/runs/{run}/explore")).await;
    assert_eq!(s, StatusCode::OK);
}

fn varint(b: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        b.push(v as u8 | 0x80);
        v >>= 7;
    }
    b.push(v as u8);
}

/// A planted graph (`n` objects, the first with `edges` edges from
/// itself, two bytes each), gzipped.
fn planted(n: usize, edges: usize) -> Vec<u8> {
    use std::io::Write;
    let mut b = b"PWEXPL\x01".to_vec();
    varint(&mut b, n as u64);
    b.resize(b.len() + 2 * n, 0);
    varint(&mut b, edges as u64);
    b.resize(b.len() + 2 * edges, 0);
    b.resize(b.len() + n, 0);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&b).unwrap();
    gz.finish().unwrap()
}

/// A planted graph in a saved run (one pulled from a run history):
/// Explore and `pathwarden reach` refuse more edges than its objects may
/// have, and more objects than its summary allows, before making them.
#[tokio::test]
async fn explore_refuses_a_planted_graph() {
    use pathwarden_core::explore::{edge_budget, Bounds};
    let a = app("planted");
    let run = a.analyze(&forest()).await;
    let dir = a.state.ws().run_dir(&run).unwrap();
    let collected = a.state.ws().summary(&run).unwrap().objects;
    let n = collected + 10;
    std::fs::write(dir.join("graph.bin.gz"), planted(n, edge_budget(n) + 1)).unwrap();
    let err = pathwarden_ui::explore_ui::read_run(&dir).err().unwrap();
    assert!(err.contains("more edges"), "{err}");

    let many = Bounds::of_collected(collected).max_objects + 1;
    std::fs::write(dir.join("graph.bin.gz"), planted(many, 0)).unwrap();
    let err = pathwarden_ui::explore_ui::read_run(&dir).err().unwrap();
    assert!(err.contains("more objects"), "{err}");
}

/// Headless Edge or Chrome: `PATHWARDEN_TEST_BROWSER`, else where they
/// are usually installed.
fn browser() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("PATHWARDEN_TEST_BROWSER") {
        return Some(PathBuf::from(p));
    }
    let candidates: &[&str] = if cfg!(windows) {
        &[
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        ]
    } else {
        &[
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/microsoft-edge",
        ]
    };
    candidates.iter().map(PathBuf::from).find(|p| p.is_file())
}

/// What the probe does in the page: the Who can reach tab, opened by its
/// tab right after an object is selected, twice. Its findings go in `#out`.
const REACH_PROBE: &str = r##"(function () {
  var out = document.createElement("pre");
  out.id = "out";
  document.body.appendChild(out);
  var res = {};
  function q(s) { return document.querySelector(s); }
  function head() { var h = q("#xp-p-reach h2"); return h ? h.textContent : ""; }
  // Waits for `test`, then goes on (also when it never comes: the
  // findings say what was there).
  function until(test, then, n) {
    n = n || 0;
    if (test() || n > 100) { if (n > 100) res.waited = (res.waited || 0) + 1; then(); return; }
    setTimeout(function () { until(test, then, n + 1); }, 50);
  }
  function done() { out.textContent = JSON.stringify(res); }
  until(function () { var n = q("#xp-p-object .xp-name"); return n && !q("#xp-p-object").hidden; }, function () {
    q("#xt-reach").click();
    until(function () { return head() && q("#xp-reach-list .xp-obj-main"); }, function () {
      res.first = head();
      var b = q("#xp-reach-list .xp-obj-main");
      if (!b) { done(); return; }
      res.picked = b.title;
      b.click();
      until(function () { var n = q("#xp-p-object .xp-name"); return n && n.textContent === res.picked && !q("#xp-p-object").hidden; }, function () {
        q("#xt-reach").click();
        until(function () { return head() && head() !== res.first; }, function () {
          res.second = head();
          done();
        });
      });
    });
  });
})();
"##;

/// The Who can reach tab, opened by its tab after an object is
/// selected, shows who can reach that object (it stayed empty, or showed
/// the object before). The app is served through a small proxy that adds
/// the session and the probe (`/probe.js`, under the page's CSP).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reach_tab_follows_the_selection_in_a_browser() {
    let Some(exe) = browser() else {
        eprintln!("no Edge or Chrome found: the Who can reach browser test was skipped");
        return;
    };
    let a = app("reach-browser");
    let run = a.analyze(&forest()).await;
    let da = a.ix(&run, "DA_ALICE@CONTOSO.LOCAL").await;
    let origin = serve_with_probe(&a, REACH_PROBE, |p| p.contains("/explore?"));
    let profile = a.dir.join("browser-profile");
    let page = format!("{origin}/runs/{run}/explore?node={da}");
    let got = probe_in_browser(exe, profile, page, (1440, 900)).await;
    assert_eq!(got["first"], "Who can reach DA_ALICE", "{got}");
    let picked = got["picked"].as_str().unwrap();
    // As the page shortens it: the name before its domain.
    let short = match picked.split_once('@') {
        Some((name, _)) => name,
        None => picked.split('.').next().unwrap(),
    };
    assert_eq!(
        got["second"].as_str().unwrap(),
        format!("Who can reach {short}"),
        "{got}"
    );
}

/// Serves the app on a free port through a small proxy that adds the
/// session and `/probe.js` (the page's CSP allows a script from its own
/// origin), loaded at the end of each page `inject` picks. Returns the
/// origin.
fn serve_with_probe(a: &App, probe: &'static str, inject: fn(&str) -> bool) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let (router, cookie) = (a.router.clone(), a.state.session_cookie());
    let rt = tokio::runtime::Handle::current();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let (router, cookie, rt) = (router.clone(), cookie.clone(), rt.clone());
            std::thread::spawn(move || {
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&req).to_string();
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, kind, csp, body) = if path == "/probe.js" {
                    (
                        200,
                        "text/javascript".to_string(),
                        None,
                        probe.as_bytes().to_vec(),
                    )
                } else {
                    let res = rt.block_on(async {
                        let req = Request::builder()
                            .uri(&path)
                            .header(header::HOST, HOST)
                            .header(header::COOKIE, cookie)
                            .body(Body::empty())
                            .unwrap();
                        let res = router.oneshot(req).await.unwrap();
                        let status = res.status().as_u16();
                        let h = res.headers().clone();
                        let body = res.into_body().collect().await.unwrap().to_bytes();
                        (status, h, body.to_vec())
                    });
                    let (status, h, mut body) = res;
                    let kind = h
                        .get(header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("text/plain")
                        .to_string();
                    if inject(&path) {
                        let page = String::from_utf8_lossy(&body).replacen(
                            "</body>",
                            r#"<script src="/probe.js" defer></script></body>"#,
                            1,
                        );
                        body = page.into_bytes();
                    }
                    let csp = h
                        .get(header::CONTENT_SECURITY_POLICY)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    (status, kind, csp, body)
                };
                let csp = csp
                    .map(|c| format!("Content-Security-Policy: {c}\r\n"))
                    .unwrap_or_default();
                let _ = write!(
                    s,
                    "HTTP/1.1 {status} X\r\nContent-Type: {kind}\r\n{csp}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(&body);
            });
        }
    });
    origin
}

/// Opens `page` in headless `exe` with a `size` window (CSS pixels) and
/// returns what the probe wrote to `#out`, as JSON.
async fn probe_in_browser(exe: PathBuf, profile: PathBuf, page: String, size: (u32, u32)) -> Value {
    let out = tokio::task::spawn_blocking(move || {
        pathwarden_core::spawn::quiet(&exe)
            .args([
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--virtual-time-budget=30000",
                "--dump-dom",
            ])
            .arg(format!("--window-size={},{}", size.0, size.1))
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg(page)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let dom = String::from_utf8_lossy(&out.stdout);
    let json = dom
        .split(r#"<pre id="out">"#)
        .nth(1)
        .and_then(|s| s.split("</pre>").next())
        .unwrap_or("")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("{e}: {json:.300}\n{}", String::from_utf8_lossy(&out.stderr)))
}

/// What the layout probe checks in a page, a moment after it loads: the
/// rail's footer (About, the theme, Stop) is in the window, the page
/// doesn't scroll sideways, and no button, link or field in the page
/// sticks out of the box that holds it (unless that box scrolls).
const LAYOUT_PROBE: &str = r##"(function () {
  setTimeout(function () {
    var res = { problems: [] };
    function name(e) { return e.tagName.toLowerCase() + (e.id ? "#" + e.id : "") + (typeof e.className === "string" && e.className ? "." + e.className.trim().split(/\s+/).join(".") : ""); }
    var foot = document.querySelector(".rail-foot");
    if (foot) {
      var r = foot.getBoundingClientRect();
      if (r.bottom > innerHeight + 1 || r.top < 0) res.problems.push("rail footer out of the window: " + Math.round(r.top) + "-" + Math.round(r.bottom) + " of " + innerHeight);
    }
    if (document.documentElement.scrollWidth > innerWidth + 1) res.problems.push("page scrolls sideways: " + document.documentElement.scrollWidth + " > " + innerWidth);
    var main = document.querySelector("main");
    function scrolls(e) {
      for (var a = e.parentElement; a && a !== document.body; a = a.parentElement) {
        var o = getComputedStyle(a).overflowX;
        if (o === "auto" || o === "scroll") return true;
      }
      return false;
    }
    if (main) main.querySelectorAll("a, button, input, select, summary").forEach(function (e) {
      if (e.closest("[hidden], .vh, .menu-list, .tip-text, details:not([open]) > :not(summary)")) return;
      var r = e.getBoundingClientRect();
      if (!r.width || !r.height) return;
      var box = e.parentElement;
      while (box && getComputedStyle(box).display === "contents") box = box.parentElement;
      for (var a = box; a && a !== document.body; a = a.parentElement) {
        var s = getComputedStyle(a);
        if (s.display === "contents") continue;
        var ar = a.getBoundingClientRect();
        if (r.right > ar.right + 2 && !scrolls(e)) {
          res.problems.push(name(e) + " sticks out of " + name(a) + " by " + Math.round(r.right - ar.right) + " px");
          break;
        }
        if (s.overflowX !== "visible") break;
      }
    });
    var out = document.createElement("pre");
    out.id = "out";
    out.textContent = JSON.stringify(res);
    document.body.appendChild(out);
  }, 1500);
})();
"##;

/// High display scaling (a 1080 px screen at 150% to 200%) or zoom gives a
/// short, narrow window in CSS pixels. At those sizes every page keeps the
/// rail's footer in view, never scrolls sideways, and keeps its controls
/// inside their boxes; so does a full HD window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pages_fit_high_display_scaling_in_a_browser() {
    let Some(exe) = browser() else {
        eprintln!("no Edge or Chrome found: the layout browser test was skipped");
        return;
    };
    let a = app("layout-browser");
    let run = a.analyze(&forest()).await;
    let da = a.ix(&run, "DA_ALICE@CONTOSO.LOCAL").await;
    let origin = serve_with_probe(&a, LAYOUT_PROBE, |_| true);
    let pages = [
        "/".to_string(),
        format!("/runs/{run}"),
        format!("/runs/{run}/explore?node={da}"),
        "/progress".to_string(),
        "/settings".to_string(),
    ];
    let mut problems = Vec::new();
    for (i, size) in [(960, 500), (1097, 560), (1280, 640), (1920, 1000)]
        .into_iter()
        .enumerate()
    {
        for (j, path) in pages.iter().enumerate() {
            let profile = a.dir.join(format!("browser-profile-{i}-{j}"));
            let got = probe_in_browser(exe.clone(), profile, format!("{origin}{path}"), size).await;
            for p in got["problems"].as_array().unwrap() {
                problems.push(format!(
                    "{}x{} {path}: {}",
                    size.0,
                    size.1,
                    p.as_str().unwrap()
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
