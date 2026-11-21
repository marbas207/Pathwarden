//! OpenGraph in the UI: the Detected sources panel on Analyze, the run's
//! "Other sources" row in Run details, the coverage declaration form, the Mappings page and its trust toggle,
//! and the explorer's kind table. Hostile names must come out escaped.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const PORT: u16 = 4251;
const HOST: &str = "127.0.0.1:4251";
const BOUNDARY: &str = "ogTestBoundary";
const MARKUP: &str = "<img src=x onerror=alert(1)>";

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
    let dir = std::env::temp_dir().join(format!("pathwarden-ogui-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(&dir).unwrap();
    let state = Arc::new(AppState::new(ws, Token::generate().unwrap(), PORT));
    App {
        router: router(state.clone()),
        state,
        dir,
    }
}

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
}

/// One multipart part.
enum Part<'a> {
    Path(&'a Path),
    File(&'a str, Vec<u8>),
    Coverage(Value),
}

impl App {
    fn request(&self, method: Method, uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, String) {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn get(&self, uri: &str) -> (StatusCode, String) {
        self.send(self.request(Method::GET, uri).body(Body::empty()).unwrap())
            .await
    }

    async fn json(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        let req = self
            .request(Method::POST, uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        let (s, b) = self.send(req).await;
        (s, serde_json::from_str(&b).unwrap_or(Value::Null))
    }

    /// Starts an analysis; the status and body of `/api/analyze`.
    async fn start(&self, parts: &[Part<'_>]) -> (StatusCode, String) {
        let mut body: Vec<u8> = Vec::new();
        for p in parts {
            body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
            match p {
                Part::Path(path) => body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"path\"\r\n\r\n{}\r\n",
                        path.display()
                    )
                    .as_bytes(),
                ),
                Part::File(name, bytes) => {
                    body.extend_from_slice(
                        format!(
                            "Content-Disposition: form-data; name=\"files\"; filename=\"{name}\"\r\nContent-Type: application/json\r\n\r\n"
                        )
                        .as_bytes(),
                    );
                    body.extend_from_slice(bytes);
                    body.extend_from_slice(b"\r\n");
                }
                Part::Coverage(v) => body.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"coverage\"\r\n\r\n{v}\r\n")
                        .as_bytes(),
                ),
            }
        }
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        let req = self
            .request(Method::POST, "/api/analyze")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body))
            .unwrap();
        self.send(req).await
    }

    /// Analyzes and waits for the run.
    async fn analyze(&self, parts: &[Part<'_>]) -> String {
        let (s, b) = self.start(parts).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        let job = serde_json::from_str::<Value>(&b).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string();
        for _ in 0..600 {
            let (_, body) = self.get(&format!("/api/jobs/{job}")).await;
            let v: Value = serde_json::from_str(&body).unwrap();
            if v["status"] == "done" {
                return v["run"].as_str().unwrap().to_string();
            }
            assert_ne!(v["status"], "failed", "{v}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("analysis did not finish");
    }

    /// The run page's Run details: the report's tab, in the embedded report
    /// the page's frame loads with its nonce, or else the page itself (its
    /// own copy below the report). The run page has no Detected sources
    /// panel above the report.
    async fn run_details(&self, run: &str) -> String {
        let (s, page) = self.get(&format!("/runs/{run}")).await;
        assert_eq!(s, StatusCode::OK);
        assert!(!page.contains("Detected sources"), "{page}");
        assert!(!page.contains("og-panel"), "{page}");
        let Some(nonce) = page
            .split(r#"data-rd=""#)
            .nth(1)
            .and_then(|t| t.split('"').next())
        else {
            return page;
        };
        let (s, embed) = self
            .get(&format!("/runs/{run}/report?embed=1&rd={nonce}"))
            .await;
        assert_eq!(s, StatusCode::OK);
        embed
    }

    fn config(&self) -> String {
        std::fs::read_to_string(self.state.ws().config_path()).unwrap_or_default()
    }
}

/// The AD fixture's files as upload parts.
fn ad_files() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(testdata("opengraph/ad")).unwrap() {
        let p = e.unwrap().path();
        out.push((
            p.file_name().unwrap().to_string_lossy().into_owned(),
            std::fs::read(&p).unwrap(),
        ));
    }
    out
}

#[tokio::test]
async fn run_details_lists_the_other_sources() {
    let a = app("run-panel");
    let (ad, th, ms, wh) = (
        testdata("opengraph/ad"),
        testdata("opengraph/taskhound"),
        testdata("opengraph/mssqlhound"),
        testdata("opengraph/widgethound"),
    );
    let run = a
        .analyze(&[
            Part::Path(&ad),
            Part::Path(&th),
            Part::Path(&ms),
            Part::Path(&wh),
        ])
        .await;
    let page = a.run_details(&run).await;
    // One row, right after "Where it came from"; amber and open, as two
    // sources have no coverage file.
    let titles: Vec<&str> = page
        .split(r#"<span class="title">"#)
        .skip(1)
        .filter_map(|t| t.split('<').next())
        .collect();
    let at = titles.iter().position(|t| *t == "Other sources").unwrap();
    assert_eq!(titles[at - 1], "Where it came from", "{titles:?}");
    let row = &page[page
        .find(r#"<span class="title">Other sources</span>"#)
        .unwrap()..];
    let row = &row[..row.find("</details>").unwrap()];
    assert!(
        page.contains(
            r#"<details class="row env" open><summary><span class="title">Other sources</span><span class="aside warn">"#
        ),
        "{row}"
    );
    let status = row.split(r#"<span class="aside warn">"#).nth(1).unwrap();
    let status = &status[..status.find("</span>").unwrap()];
    assert_eq!(
        status,
        "TaskHound, MSSQL_Base, WidgetHound · 2 untrusted mappings"
    );
    // MSSQLHound's pack is named in its mapping.
    assert!(
        row.contains("The MSSQLHound pack labels its kinds"),
        "{row}"
    );
    for want in [
        "<dt>Source</dt><dd>TaskHound, OpenGraph · 1 file: taskhound.json</dd>",
        "<dt>Relationships kept</dt>",
        "<dt>Mapping</dt><dd>Trusted mapping: ",
        "Untrusted mapping: context only. The ",
        "No mapping: context only. Shown in Explore",
        "<dt>Coverage</dt><dd>No coverage file:",
        "can&#39;t be marked Fixed",
        r##"<a href="#" data-pw-run="mappings">Mappings</a> lists what each pack means."##,
    ] {
        assert!(
            page.contains(want) || page.contains(&want.replace("&#39;", "'")),
            "missing {want}"
        );
    }
    // The forged native edges in WidgetHound's file are reported as dropped.
    assert!(page.contains("AD relationships (ignored: only AD data sets these)"));
    // A run without OpenGraph data has no such row.
    let plain = a.analyze(&[Part::Path(&ad)]).await;
    let page = a.run_details(&plain).await;
    assert!(page.contains("Where it came from"), "{page}");
    assert!(!page.contains("Other sources"));
}

#[tokio::test]
async fn hostile_names_are_escaped() {
    let a = app("hostile");
    let dir = a.dir.join("hostile-input");
    std::fs::create_dir_all(&dir).unwrap();
    let og = json!({
        "metadata": { "source_kind": MARKUP },
        "graph": {
            "nodes": [{ "id": "X-1", "kinds": ["EV_Thing", MARKUP], "properties": { "name": MARKUP } }],
            "edges": [
                { "kind": "EV_Owns", "start": { "value": "X-1" }, "end": { "value": "S-1-5-21-3000-3000-3000-1001" } },
                { "kind": MARKUP, "start": { "value": "X-1" }, "end": { "value": "S-1-5-21-3000-3000-3000-1001" } }
            ]
        }
    });
    let name = "evil\"><svg onload=alert(1)>.json";
    std::fs::write(dir.join("evil.json"), og.to_string()).unwrap();
    let ad = testdata("opengraph/ad");
    let run = a.analyze(&[Part::Path(&ad), Part::Path(&dir)]).await;
    let (_, run_page) = a.get(&format!("/runs/{run}")).await;
    assert!(!run_page.contains(MARKUP), "raw markup on the run page");
    let page = a.run_details(&run).await;
    assert!(page.contains("Other sources"));
    assert!(!page.contains(MARKUP), "raw markup in Run details");
    assert!(page.contains("&lt;img src=x onerror=alert(1)&gt;"));

    // The upload panel: hostile file names and source kinds.
    let text = og.to_string();
    let (s, v) = a
        .json(
            "/api/opengraph/sniff",
            json!({ "files": [
                { "name": name, "size": text.len(), "head": text, "tail": text },
                { "name": "users.json", "size": 60, "head": "{\"data\":[],\"meta\":{\"type\":\"users\",\"count\":0,\"version\":6}}", "tail": "" }
            ]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["opengraph"], true);
    let html = v["html"].as_str().unwrap();
    assert!(
        !html.contains(MARKUP) && !html.contains("<svg onload"),
        "{html}"
    );
    assert!(
        html.contains("&lt;img src=x onerror=alert(1)&gt;"),
        "{html}"
    );
    assert!(html.contains("No mapping: context only"));
    assert!(html.contains("og-declare"), "a coverage form is offered");

    // Explore's kind table holds only valid kind names (the markup kind
    // was refused at ingest); the source name is JSON data, which the page
    // only ever sets as text.
    let (s, body) = a.get(&format!("/api/runs/{run}/explore")).await;
    assert_eq!(s, StatusCode::OK);
    let v: Value = serde_json::from_str(&body).unwrap();
    for list in ["nodes", "edges"] {
        for k in v["kinds"][list].as_array().unwrap() {
            let name = k["name"].as_str().unwrap();
            assert!(
                name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "{name}"
            );
        }
    }
    assert_eq!(v["kinds"]["edges"][0]["sources"][0], MARKUP);
}

#[tokio::test]
async fn the_upload_panel_sees_sources_and_sidecars() {
    let a = app("sniff");
    let th = std::fs::read_to_string(testdata("opengraph/taskhound/taskhound.json")).unwrap();
    let ms = std::fs::read_to_string(testdata("opengraph/mssqlhound/mssql-srv01.json")).unwrap();
    let side = json!({
        "schema": "pathwarden.coverage.v1", "source_kind": "TaskHound",
        "payloads": [{ "file": "taskhound.json", "sha256": "00" }],
        "units": { "type": "computer", "ok": ["APP01.CORP.LOCAL"] }, "complete": true
    })
    .to_string();
    let file = |name: &str, t: &str| json!({ "name": name, "size": t.len(), "head": t, "tail": t });
    let (s, v) = a
        .json(
            "/api/opengraph/sniff",
            json!({ "files": [file("taskhound.json", &th), file("mssql.json", &ms), file("taskhound.coverage.json", &side), json!({"name": "c.zip", "size": 9})] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let html = v["html"].as_str().unwrap();
    assert!(html.contains("Coverage file found"), "{html}");
    assert!(html.contains("Untrusted mapping"), "{html}");
    assert!(html.contains(".zip archive"), "{html}");
    // TaskHound's file is covered, so only MSSQLHound's gets a form.
    assert_eq!(html.matches("og-declare\"").count(), 1, "{html}");

    // Plain AD data: nothing to show.
    let (_, v) = a
        .json(
            "/api/opengraph/sniff",
            json!({ "files": [file("users.json", "{\"data\":[],\"meta\":{\"type\":\"users\"}}")] }),
        )
        .await;
    assert_eq!(v["opengraph"], false);
}

#[tokio::test]
async fn a_declared_coverage_is_bound_to_the_upload() {
    let a = app("declare");
    let mut parts_owned = ad_files();
    let th = std::fs::read(testdata("opengraph/taskhound/taskhound.json")).unwrap();
    parts_owned.push(("taskhound.json".into(), th));
    let mut parts: Vec<Part> = parts_owned
        .iter()
        .map(|(n, b)| Part::File(n, b.clone()))
        .collect();
    parts.push(Part::Coverage(json!([{
        "file": "taskhound.json",
        "declaration": { "all_in_domains": ["CORP.LOCAL"], "ok": [], "failed": [], "complete": true }
    }])));
    let run = a.analyze(&parts).await;
    let page = a.run_details(&run).await;
    assert!(page.contains("Coverage file, "), "{page}");
    assert!(page.contains("declared by hand"));
    assert!(page.contains("every enabled computer in CORP.LOCAL"));
    let stats: Value = serde_json::from_str(
        &std::fs::read_to_string(a.state.ws().run_dir(&run).unwrap().join("opengraph.json"))
            .unwrap(),
    )
    .unwrap();
    let cov = &stats["sources"][0]["coverage"];
    assert_eq!(cov["state"], "sidecar", "{cov}");
    assert_eq!(cov["asserted_by"], "user");

    // A declaration for a file that wasn't uploaded, or one that says
    // nothing, is refused before anything is analyzed.
    for decl in [
        json!([{ "file": "other.json", "declaration": { "ok": ["APP01"] } }]),
        json!([{ "file": "taskhound.json", "declaration": { "ok": [] } }]),
        json!([{ "file": "taskhound.json", "declaration": { "ok": ["A"], "surprise": 1 } }]),
    ] {
        let mut parts: Vec<Part> = parts_owned
            .iter()
            .map(|(n, b)| Part::File(n, b.clone()))
            .collect();
        parts.push(Part::Coverage(decl.clone()));
        let (s, b) = a.start(&parts).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{decl}: {b}");
    }
    // Declaring coverage for an AD file is refused too.
    let mut parts: Vec<Part> = parts_owned
        .iter()
        .map(|(n, b)| Part::File(n, b.clone()))
        .collect();
    parts.push(Part::Coverage(
        json!([{ "file": "corp_users.json", "declaration": { "ok": ["APP01"] } }]),
    ));
    let (s, b) = a.start(&parts).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    assert!(b.contains("not an OpenGraph file"), "{b}");
}

#[tokio::test]
async fn mappings_lists_packs_and_trust_needs_a_confirm() {
    let a = app("mappings");
    let (s, page) = a.get("/mappings").await;
    assert_eq!(s, StatusCode::OK);
    for want in [
        "TaskHound",
        "TH_HasTaskWithStoredCreds",
        "MSSQLHound",
        "Untrusted mapping: context only",
        // An untrusted pack's summary doesn't call its relationships
        // attack paths yet.
        "attack paths once trusted</summary>",
        "Trust…",
        "Stop storing a password",
        "/static/opengraph.js",
    ] {
        assert!(page.contains(want), "missing {want}");
    }
    assert!(!page.contains("<script>"), "no inline scripts");

    // Without the confirmation, nothing is written.
    let (s, v) = a
        .json(
            "/api/mappings/trust",
            json!({ "pack": "mssqlhound", "trusted": true }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(a.config().is_empty() || !a.config().contains("mssqlhound"));
    // Unknown packs and a built-in trusted pack are refused.
    let (s, _) = a
        .json(
            "/api/mappings/trust",
            json!({ "pack": "nope", "trusted": true, "confirm": true }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = a
        .json(
            "/api/mappings/trust",
            json!({ "pack": "taskhound", "trusted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, v) = a
        .json(
            "/api/mappings/trust",
            json!({ "pack": "mssqlhound", "trusted": true, "confirm": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let config = pathwarden_core::config::Config::parse(&a.config()).unwrap();
    assert_eq!(config.opengraph.trust, vec!["mssqlhound".to_string()]);
    let (_, page) = a.get("/mappings").await;
    assert!(page.contains("Trusted by you") && page.contains("Remove trust"));

    let (s, _) = a
        .json(
            "/api/mappings/trust",
            json!({ "pack": "mssqlhound", "trusted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let config = pathwarden_core::config::Config::parse(&a.config()).unwrap();
    assert!(config.opengraph.trust.is_empty());
}

#[tokio::test]
async fn user_packs_show_on_mappings() {
    let a = app("user-packs");
    std::fs::create_dir_all(a.state.ws().root().join("packs")).unwrap();
    std::fs::write(
        a.state.ws().root().join("packs/widget.toml"),
        "[pack]\nname = \"widgethound\"\ntitle = \"Widget<b>Hound</b>\"\nversion = 3\nsource_kinds = [\"WidgetHound\"]\nkind_prefix = \"WH_\"\n\n[[node]]\nkind = \"WH_Console\"\nlabel = \"Console\"\nicon = \"terminal\"\ncolor = \"#0EA5E9\"\n\n[[edge]]\nkind = \"WH_Manages\"\ntraversable = true\nfix = \"Remove {from} from {to}.\"\n",
    )
    .unwrap();
    std::fs::write(
        a.state.ws().root().join("packs/bad.toml"),
        "[pack]\nname = \"bad\"\nversion = 1\nsource_kinds = [\"B\"]\nkind_prefix = \"BB_\"\n[[edge]]\nkind = \"MemberOf\"\n",
    )
    .unwrap();
    std::fs::write(
        a.state.ws().config_path(),
        "[[mapping]]\npath = \"packs/widget.toml\"\n\n[[mapping]]\npath = \"packs/bad.toml\"\n",
    )
    .unwrap();
    let (s, page) = a.get("/mappings").await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("Your pack (widget.toml)"), "{page}");
    assert!(page.contains("Widget&lt;b&gt;Hound&lt;/b&gt;"));
    assert!(page.contains("fill=\"#0EA5E9\""));
    assert!(page.contains("packs/bad.toml was refused"));
    assert!(page.contains("Path once trusted"));
}

#[tokio::test]
async fn explore_gets_the_kind_table() {
    let a = app("explore");
    let (ad, th, wh) = (
        testdata("opengraph/ad"),
        testdata("opengraph/taskhound"),
        testdata("opengraph/widgethound"),
    );
    let run = a
        .analyze(&[Part::Path(&ad), Part::Path(&th), Part::Path(&wh)])
        .await;
    let (s, body) = a.get(&format!("/api/runs/{run}/explore")).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let nodes = v["kinds"]["nodes"].as_array().unwrap();
    let task = nodes
        .iter()
        .find(|n| n["name"] == "TH_ScheduledTask")
        .unwrap();
    assert_eq!(task["label"], "Scheduled task");
    assert_eq!(task["icon"], "clock");
    assert_eq!(task["color"], "#8B5CF6");
    assert!(
        nodes.iter().all(|n| n["name"] != "User"),
        "natives left out"
    );
    let edges = v["kinds"]["edges"].as_array().unwrap();
    let th_edge = edges
        .iter()
        .find(|e| e["name"] == "TH_HasTaskWithStoredCreds")
        .unwrap();
    assert_eq!(th_edge["traversable"], true);
    assert_eq!(th_edge["sources"], json!(["TaskHound"]));
    let wh_edge = edges.iter().find(|e| e["name"] == "WH_Manages").unwrap();
    assert_eq!(wh_edge["traversable"], false, "no pack: context only");
    let (_, page) = a.get(&format!("/runs/{run}/explore")).await;
    assert!(page.contains("/static/opengraph.css"));

    // A TaskHound finding's (PW-033) path keeps its OpenGraph kinds (not
    // MemberOf).
    let fp = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule"] == "PW-033")
        .unwrap()["fp"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, body) = a
        .get(&format!("/api/runs/{run}/explore/finding?fp={fp}"))
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let f: Value = serde_json::from_str(&body).unwrap();
    let kinds: Vec<&str> = f["path"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["k"].as_str().unwrap())
        .collect();
    assert!(kinds.iter().all(|k| k.starts_with("TH_")), "{kinds:?}");
}
