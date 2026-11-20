//! Retest buttons (the embedded report's meta and the run page's dialog),
//! retest API and Progress page, through the router.

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
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:4243";

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
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-rt-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let state = Arc::new(AppState::new(ws, Token::generate().unwrap(), 4243));
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

/// The forest fixture with CAROL's GenericAll on CHILD_DA removed and BOB
/// requiring pre-authentication again.
fn fixed_forest(dir: &Path) -> PathBuf {
    let out = dir.join("fixed");
    std::fs::create_dir_all(&out).unwrap();
    for e in std::fs::read_dir(testdata("forest")).unwrap().flatten() {
        let mut text = std::fs::read_to_string(e.path()).unwrap();
        if e.file_name().to_string_lossy() == "contoso_users.json" {
            let mut doc: serde_json::Value = serde_json::from_str(&text).unwrap();
            for o in doc["data"].as_array_mut().unwrap() {
                match o["ObjectIdentifier"].as_str().unwrap() {
                    "S-1-5-21-2000-2000-2000-1201" => o["Aces"] = serde_json::json!([]),
                    "S-1-5-21-1000-1000-1000-1104" => {
                        o["Properties"]["dontreqpreauth"] = false.into()
                    }
                    _ => {}
                }
            }
            text = doc.to_string();
        }
        std::fs::write(out.join(e.file_name()), text).unwrap();
    }
    out
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

    /// A GET and the response's Content Security Policy.
    async fn get_csp(&self, uri: &str) -> (String, String) {
        let req = self.request(Method::GET, uri).body(Body::empty()).unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let csp = res.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_string();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (String::from_utf8_lossy(&body).into_owned(), csp)
    }

    async fn get(&self, uri: &str) -> (StatusCode, String) {
        self.send(self.request(Method::GET, uri).body(Body::empty()).unwrap())
            .await
    }

    async fn post_json(&self, uri: &str, body: serde_json::Value) -> (StatusCode, String) {
        let req = self
            .request(Method::POST, uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        self.send(req).await
    }

    /// Analyzes a folder and returns the new run's ID.
    async fn analyze(&self, path: &Path) -> String {
        let boundary = "rtBoundary";
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
        let (s, body) = self.send(req).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{body}");
        let job = serde_json::from_str::<serde_json::Value>(&body).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string();
        for _ in 0..600 {
            let (_, b) = self.get(&format!("/api/jobs/{job}")).await;
            let v: serde_json::Value = serde_json::from_str(&b).unwrap();
            if v["status"] == "done" {
                return v["run"].as_str().unwrap().to_string();
            }
            assert_ne!(v["status"], "failed", "{b}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("analysis did not finish");
    }
}

/// The JSON in the first attribute named `attr` (`content=` for the
/// report's retest meta), unescaped as a browser would.
fn attr_json(html: &str, attr: &str) -> serde_json::Value {
    let start = if attr == "content=" {
        html.find(r#"<meta name="pathwarden-retest" content=""#)
            .map(|i| i + r#"<meta name="pathwarden-retest" content=""#.len())
    } else {
        html.find(&format!(r#"{attr}=""#))
            .map(|i| i + attr.len() + 2)
    }
    .unwrap_or_else(|| panic!("no {attr}: {html}"));
    let raw = &html[start..start + html[start..].find('"').unwrap()];
    let text = raw
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    serde_json::from_str(&text).unwrap()
}

/// The script tags' contents in a page.
fn scripts(html: &str) -> Vec<&str> {
    html.split("<script>")
        .skip(1)
        .map(|s| &s[..s.find("</script>").unwrap()])
        .collect()
}

/// An embedded report: two scripts (the report's own, then the buttons'),
/// each allowed by its hash and nothing else.
fn check_embed(html: &str, csp: &str) {
    use pathwarden_ui::retest_ui::csp_hash;
    let s = scripts(html);
    assert_eq!(s.len(), 2, "{html}");
    assert!(s[1].contains("pathwarden:retest") && s[1].contains("postMessage"));
    assert!(!s[0].contains("pathwarden:retest"));
    let src = csp
        .split(';')
        .map(str::trim)
        .find(|d| d.starts_with("script-src"))
        .unwrap();
    assert_eq!(
        src,
        format!("script-src {} {}", csp_hash(s[0]), csp_hash(s[1]))
    );
    assert!(!csp.contains("script-src 'unsafe-inline'"), "{csp}");
    assert!(csp.contains("sandbox allow-scripts") && csp.contains("default-src 'none'"));
    // The buttons' styles are in the head; their data right before the
    // script, which reads only the element before itself.
    let head = html.split("</head>").next().unwrap();
    assert!(head.contains(".rt-btn") && !head.contains(r#"<meta name="pathwarden-retest""#));
    let meta_at = html.rfind(r#"<meta name="pathwarden-retest""#).unwrap();
    let after = &html[meta_at..];
    let script_at = after.find("<script>").unwrap();
    assert!(!after[1..script_at].contains('<'), "nothing between them");
    assert!(
        after[..script_at].ends_with("\">"),
        "{}",
        &after[..script_at.min(300)]
    );
}

const PW003: &str = "PW-003-39f2ede7c479090b";
const PW004: &str = "PW-004-13b0863341b2e306";
const PW012: &str = "PW-012-9ef87557182c2d18";

/// The forest fixture as a Quick (DC only) collection writes it: no
/// session list collected (the built-in collector's reason), no local
/// groups.
fn quick_forest(dir: &Path) -> PathBuf {
    let out = dir.join("quick");
    std::fs::create_dir_all(&out).unwrap();
    for e in std::fs::read_dir(testdata("forest")).unwrap().flatten() {
        let text = std::fs::read_to_string(e.path()).unwrap();
        let mut doc: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
        if doc["meta"]["type"] == "computers" {
            for c in doc["data"].as_array_mut().unwrap() {
                for k in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
                    c[k] = serde_json::json!({"Results": [], "Collected": false,
                        "FailureReason": pathwarden_core::ingest::NOT_CONTACTED});
                }
                c["LocalGroups"] = serde_json::json!([]);
                c.as_object_mut().unwrap().remove("LocalAdmins");
            }
        }
        std::fs::write(out.join(e.file_name()), doc.to_string()).unwrap();
    }
    out
}

/// A Full run, then a Quick run: the report's retest column says what
/// `pathwarden retest` says of the Full run's findings against the Quick
/// collection: "can't tell" for those that may rest on sessions or local
/// groups, never "fixed".
#[tokio::test]
async fn a_later_quick_run_tells_what_retest_tells() {
    use pathwarden_core::retest::{self, Baseline, Coverage, FindingView, Selection};
    let a = app("quick");
    let first = a.analyze(&testdata("forest")).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let quick = quick_forest(&a.dir);
    a.analyze(&quick).await;
    let (_, embedded) = a.get(&format!("/runs/{first}/report?embed=1")).await;
    let f = attr_json(&embedded, "content=")["f"].clone();
    let ui: std::collections::BTreeMap<String, String> = f
        .as_object()
        .unwrap()
        .iter()
        .map(|(fp, x)| (fp.clone(), x["r"]["v"].as_str().unwrap().to_string()))
        .collect();
    // The command line's comparison of the same two collections.
    let config = pathwarden_core::config::Config::default();
    let eval =
        |p: &Path| pathwarden_core::analyze::evaluate(&[p], &config, &[], &mut |_| {}).unwrap();
    let (base, fresh) = (eval(&testdata("forest")), eval(&quick));
    let untargeted = |e: &pathwarden_core::analyze::Evaluated| {
        pathwarden_core::posture::untargeted_domains(&pathwarden_core::posture::completeness(
            &e.graph,
            e.settings.now,
        ))
    };
    let mut views: Vec<FindingView> = base.findings.iter().map(FindingView::from).collect();
    FindingView::mark_untargeted(&mut views, &untargeted(&base));
    let coverage = Coverage {
        domains: pathwarden_core::analyze::domain_names(&fresh.graph),
        complete: true,
        ..Coverage::default()
    }
    .with_untargeted(&untargeted(&fresh));
    let current: Vec<FindingView> = fresh.findings.iter().map(FindingView::from).collect();
    let cli = retest::compare(
        &Baseline::from_views(views, "forest"),
        &current,
        &coverage,
        &Selection::default(),
    )
    .unwrap();
    let mut cant_tell = 0;
    for r in &cli.results {
        let want = match r.verdict {
            retest::Verdict::Fixed => "fixed",
            retest::Verdict::StillOpen => "still_open",
            retest::Verdict::CantTell => "cant_tell",
        };
        assert_eq!(ui[&r.fingerprint], want, "{}", r.fingerprint);
        cant_tell += usize::from(want == "cant_tell");
    }
    assert!(cant_tell > 0, "{cli:?}");
    assert_eq!(ui[PW004], "cant_tell", "Tier Zero sessions, not read");
}

/// What `pathwarden retest` says of `base`'s findings against `fresh`,
/// by fingerprint.
fn cli_verdicts(base: &Path, fresh: &Path) -> std::collections::BTreeMap<String, String> {
    use pathwarden_core::opengraph::coverage::RunSources;
    use pathwarden_core::retest::{self, Baseline, Coverage, FindingView, Selection};
    let config = pathwarden_core::config::Config::default();
    let eval =
        |p: &Path| pathwarden_core::analyze::evaluate(&[p], &config, &[], &mut |_| {}).unwrap();
    let (base, fresh) = (eval(base), eval(fresh));
    let untargeted = |e: &pathwarden_core::analyze::Evaluated| {
        pathwarden_core::posture::untargeted_domains(&pathwarden_core::posture::completeness(
            &e.graph,
            e.settings.now,
        ))
    };
    let mut views: Vec<FindingView> = base.findings.iter().map(FindingView::from).collect();
    FindingView::mark_untargeted(&mut views, &untargeted(&base));
    let had = RunSources::from_analysis(&base.graph, &base.stats).all_keys();
    let sources = RunSources::from_analysis(&fresh.graph, &fresh.stats);
    let coverage = Coverage {
        domains: pathwarden_core::analyze::domain_names(&fresh.graph),
        complete: true,
        sources,
        ..Coverage::default()
    }
    .compared_with(&had)
    .with_untargeted(&untargeted(&fresh));
    let current: Vec<FindingView> = fresh.findings.iter().map(FindingView::from).collect();
    let r = retest::compare(
        &Baseline::from_views(views, "base"),
        &current,
        &coverage,
        &Selection::default(),
    )
    .unwrap();
    r.results
        .iter()
        .map(|x| {
            let v = match x.verdict {
                retest::Verdict::Fixed => "fixed",
                retest::Verdict::StillOpen => "still_open",
                retest::Verdict::CantTell => "cant_tell",
            };
            (x.fingerprint.clone(), v.to_string())
        })
        .collect()
}

/// A run with SYSVOL data, then one without: the report's retest column
/// says "can't tell" of what rests on SYSVOL, as `pathwarden retest` does.
#[tokio::test]
async fn a_later_run_without_a_source_tells_what_retest_tells() {
    let a = app("nosysvol");
    let first = a.analyze(&testdata("sysvol")).await;
    let bare = a.dir.join("no-sysvol");
    std::fs::create_dir_all(&bare).unwrap();
    for e in std::fs::read_dir(testdata("sysvol")).unwrap().flatten() {
        // A day later, so it isn't the same collection again.
        let name = e
            .file_name()
            .to_string_lossy()
            .replace("20261001", "20261002");
        if !name.contains("pathwarden-sysvol") {
            std::fs::copy(e.path(), bare.join(name)).unwrap();
        }
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    a.analyze(&bare).await;
    let (_, embedded) = a.get(&format!("/runs/{first}/report?embed=1")).await;
    let f = attr_json(&embedded, "content=")["f"].clone();
    let cli = cli_verdicts(&testdata("sysvol"), &bare);
    let mut cant_tell = 0;
    for (fp, want) in &cli {
        assert_eq!(f[fp]["r"]["v"], want.as_str(), "{fp}: {}", f[fp]);
        cant_tell += usize::from(want == "cant_tell");
    }
    assert!(cant_tell > 0, "{cli:?}");
}

#[tokio::test]
async fn retest_buttons_dialog_progress_and_api() {
    let a = app("all");
    // No runs: Progress says so.
    let (s, body) = a.get("/progress").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("No runs yet"), "{body}");
    assert!(body.contains(r#"href="/progress" aria-current="page""#));
    // Runs too, with the ways in.
    let (_, body) = a.get("/runs").await;
    let empty = body
        .split(r#"<p class="empty-actions">"#)
        .nth(1)
        .expect("the ways in");
    for way in [r#"href="/collect""#, "data-demo"] {
        assert!(empty.contains(way), "{way}: {body}");
    }

    let first = a.analyze(&testdata("forest")).await;
    let dir = a.state.ws().run_dir(&first).unwrap();
    assert!(dir.join("retest.json.gz").is_file(), "the slice is kept");

    // The run page: no separate panel, but the dialog the report's buttons
    // open, with this run's open findings.
    let (s, page) = a.get(&format!("/runs/{first}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!page.contains("Retest findings"), "{page}");
    assert!(!page.contains("rt-row") && !page.contains("data-retest="));
    assert!(page.contains(r#"<dialog id="rt-dialog""#), "{page}");
    assert!(page.contains(r#"<script src="/static/retest.js" defer></script>"#));
    let findings = attr_json(&page, "data-findings");
    let findings = findings.as_object().unwrap();
    assert_eq!(findings.len(), 15);
    let builtin = pathwarden_ui::collect::BUILTIN;
    // Trusts can't be re-read: the dialog says why.
    assert_eq!(findings[PW012]["t"], 0);
    assert!(findings[PW012]["why"]
        .as_str()
        .unwrap()
        .contains("Collect again"));
    assert_eq!(findings[PW003]["t"], u8::from(builtin));
    assert!(findings[PW003]["n"].as_u64().unwrap() > 0);
    // No inline scripts or styles.
    assert!(!page.contains("<script>") && !page.contains(" style=\""));

    // The embedded report carries the app's origin and, per open finding,
    // what a retest can do; nothing else changes.
    let stored = std::fs::read_to_string(dir.join("report.html")).unwrap();
    let (s, embedded) = a.get(&format!("/runs/{first}/report?embed=1")).await;
    assert_eq!(s, StatusCode::OK);
    let meta = attr_json(&embedded, "content=");
    assert_eq!(meta["origin"], format!("http://{HOST}"));
    let f = meta["f"].as_object().unwrap();
    assert_eq!(f.len(), 15);
    assert_eq!(f[PW003]["t"], u8::from(builtin));
    assert_eq!(f[PW012]["t"], 0);
    assert!(f[PW003].get("r").is_none(), "not retested yet");
    // Open in Explore is offered (the run has its graph); nothing accepted.
    assert_eq!(meta["x"], 1);
    assert_eq!(meta["acc"], serde_json::json!([]));
    // The run page shows the numbers once (in the report), and carries the
    // Accept risk dialog and its script.
    assert!(!page.contains(r#"class="kpis""#));
    assert!(page.contains(r#"id="ar-dialog""#) && page.contains("/static/run.js"));
    // The settings the next analysis applies are on the Run details tab
    // the embedded report carries.
    assert!(!page.contains(r#"class="applies""#));

    // Accepting a risk (what the dialog sends) marks it, in the frame and
    // on the page, from then on.
    let (s, body) = a
        .post_json(
            "/api/settings/suppress",
            serde_json::json!({"index": null, "risk": {"fingerprint": PW003, "reason": "Test", "expires": null}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    // The new entry comes back, so Add a note works without a reload.
    let saved: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(saved["index"], 0);
    assert_eq!(saved["entry"]["i"], 0);
    assert_eq!(saved["entry"]["target"], PW003);
    assert_eq!(saved["entry"]["reason"], "Test");
    let (_, embedded) = a.get(&format!("/runs/{first}/report?embed=1")).await;
    assert_eq!(
        attr_json(&embedded, "content=")["acc"],
        serde_json::json!([PW003])
    );
    let (_, page2) = a.get(&format!("/runs/{first}")).await;
    let accepted = attr_json(&page2, "data-findings");
    assert_eq!(accepted[PW003]["acc"], 1);
    assert_eq!(accepted[PW004]["acc"], 0);
    let (_, details) = a.get(&format!("/runs/{first}/report?embed=1")).await;
    assert!(details.contains("1 accepted risk"), "the Run details tab");
    // Add a note: the frame offers it on the accepted finding, and the
    // page's dialog knows which entry it goes to.
    assert_eq!(
        attr_json(&embedded, "content=")["a"],
        serde_json::json!([PW003])
    );
    assert!(page2.contains(r#"id="an-dialog""#));
    let notes = attr_json(&page2, "data-accepted");
    assert_eq!(notes[PW003]["i"], 0);
    assert_eq!(notes[PW003]["target"], PW003);
    assert_eq!(notes[PW003]["reason"], "Test");
    assert!(notes[PW003]["accepted_on"].is_string(), "{notes}");
    assert!(notes.get(PW004).is_none());
    let (s, body) = a
        .post_json(
            "/api/settings/suppress/0/note",
            serde_json::json!({"run": first, "expect": "Test", "expect_target": PW003, "text": "From the run page."}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["note"]["text"], "From the run page.");
    // The entry itself, as the dialog builds its line: fields, no prose.
    assert_eq!(notes[PW003]["reason"], "Test");
    assert!(notes[PW003]["accepted_at"].as_str().unwrap().ends_with('Z'));
    assert!(notes[PW003].get("who").is_none());
    assert!(v["note"]["at"].as_str().unwrap().ends_with('Z'));
    let (_, page3) = a.get(&format!("/runs/{first}")).await;
    assert_eq!(attr_json(&page3, "data-accepted")[PW003]["notes"], 1);
    // Removed again, so the rest of the test sees every finding open.
    let req = a
        .request(Method::DELETE, "/api/settings/suppress/0")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, format!("http://{HOST}"))
        .body(Body::from(
            serde_json::json!({"expect": "Test", "expect_target": PW003}).to_string(),
        ))
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::OK);
    // Add a note names the entry the analysis applies: the first in the
    // file that hasn't expired (a rule before the finding's own; an
    // expired entry not at all).
    let config = a.state.ws().config_path();
    let kept = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!(
            "[[suppress]]\nrule = \"PW-003\"\nreason = \"rule first\"\n\n[[suppress]]\nfingerprint = \"{PW003}\"\nreason = \"the finding\"\n\n[[suppress]]\nfingerprint = \"{PW004}\"\nreason = \"expired\"\nexpires = \"2020-01-01\"\n"
        ),
    )
    .unwrap();
    let (_, page4) = a.get(&format!("/runs/{first}")).await;
    let notes = attr_json(&page4, "data-accepted");
    assert_eq!(notes[PW003]["i"], 0, "{notes}");
    assert_eq!(notes[PW003]["reason"], "rule first");
    assert_eq!(notes[PW003]["whole_rule"], true);
    assert!(
        notes.get(PW004).is_none(),
        "an expired entry offers no note: {notes}"
    );
    let (_, embedded4) = a.get(&format!("/runs/{first}/report?embed=1")).await;
    let a_list = &attr_json(&embedded4, "content=")["a"];
    assert!(a_list.as_array().unwrap().iter().any(|v| v == PW003));
    assert!(
        !a_list.as_array().unwrap().iter().any(|v| v == PW004),
        "{a_list}"
    );
    // Expired is open: Accept risk is offered again.
    assert_eq!(attr_json(&page4, "data-findings")[PW004]["acc"], 0);
    std::fs::write(&config, kept).unwrap();
    assert_eq!(
        embedded
            .matches(r#"<meta name="pathwarden-retest""#)
            .count(),
        1
    );
    // The meta sits right before the app's script, not in the head.
    let head = embedded.split("</head>").next().unwrap();
    assert!(!head.contains(r#"<meta name="pathwarden-retest""#));
    assert!(embedded.contains(r#""><script>"#));
    // Opened as localhost, the origin says so.
    let req = Request::builder()
        .uri(format!("/runs/{first}/report?embed=1"))
        .header(header::HOST, "localhost:4243")
        .header(header::COOKIE, a.state.session_cookie())
        .body(Body::empty())
        .unwrap();
    let (_, local) = a.send(req).await;
    assert_eq!(
        attr_json(&local, "content=")["origin"],
        "http://localhost:4243"
    );
    // Standalone and downloaded: exactly the stored report, with no button
    // code (core never writes it) and the usual policy.
    assert!(!stored.contains("pathwarden:retest"));
    for uri in [
        format!("/runs/{first}/report"),
        format!("/runs/{first}/report?download=1"),
    ] {
        let (s, body) = a.get(&uri).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(body, stored, "{uri}");
        assert!(!body.contains(r#"<meta name="pathwarden-retest""#), "{uri}");
        let (_, csp) = a.get_csp(&uri).await;
        assert_eq!(csp, pathwarden_ui::security::REPORT_CSP, "{uri}");
    }
    // Embedded: the buttons' script is added at the end, and the policy
    // allows exactly the report's own script and that one, by hash.
    let (embedded, csp) = a.get_csp(&format!("/runs/{first}/report?embed=1")).await;
    check_embed(&embedded, &csp);

    // The report's own script is trusted only if Pathwarden wrote it (this
    // version's or a known earlier one). A stored report whose script is
    // anything else gets no buttons and no hash: it is shown as a plain,
    // sandboxed report.
    let edited = stored.replacen("<script>", "<script>/* not a script Pathwarden wrote */", 1);
    assert_ne!(edited, stored);
    std::fs::write(dir.join("report.html"), &edited).unwrap();
    let (embedded, csp) = a.get_csp(&format!("/runs/{first}/report?embed=1")).await;
    assert_eq!(scripts(&embedded).len(), 1);
    assert!(!embedded.contains("pathwarden:retest"));
    assert!(!embedded.contains(r#"<meta name="pathwarden-retest""#));
    assert_eq!(csp, pathwarden_ui::security::REPORT_CSP);
    assert_eq!(a.get(&format!("/runs/{first}/report")).await.1, edited);
    std::fs::write(dir.join("report.html"), &stored).unwrap();

    // Links that leave the embedded report open a new tab, so the frame
    // never navigates away from it; in-page links stay as they are.
    let (embedded, _) = a.get_csp(&format!("/runs/{first}/report?embed=1")).await;
    let external = embedded
        .matches(r#"<a target="_blank" rel="noopener noreferrer" href="http"#)
        .count();
    assert!(
        external > 0,
        "the report links to its project page at least"
    );
    assert!(!embedded.contains(r#"<a href="http"#));
    assert!(embedded.contains(r##"<a role="tab" id="tab-overview" href="#overview""##));

    // The retest API: checks before anything reaches the network.
    let uri = format!("/api/runs/{first}/retest");
    let (s, _) = a
        .post_json(&uri, serde_json::json!({"fingerprint": "../x"}))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = a
        .post_json(
            "/api/runs/20991231-000000-abcdef/retest",
            serde_json::json!({"fingerprint": PW003}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let req = a
        .request(Method::POST, &uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "http://evil.example")
        .body(Body::from(
            serde_json::json!({"fingerprint": PW003}).to_string(),
        ))
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::FORBIDDEN);
    if builtin {
        let (s, body) = a
            .post_json(
                &uri,
                serde_json::json!({"fingerprint": PW012, "domain": "contoso.local"}),
            )
            .await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert!(body.contains("Collect again"), "{body}");
        // The Collect wizard's rules: a password needs LDAPS.
        let (s, body) = a
            .post_json(
                &uri,
                serde_json::json!({"fingerprint": PW003, "domain": "contoso.local",
                    "auth": "password", "user": "svc", "password": "Ui-Retest-Secret-4"}),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body.contains("ldaps") && !body.contains("Ui-Retest-Secret-4"),
            "{body}"
        );
        // Nothing listening: a plain failure, nothing recorded, no password.
        let (s, body) = a
            .post_json(
                &uri,
                serde_json::json!({"fingerprint": PW003, "domain": "contoso.local",
                    "server": "127.0.0.1", "auth": "password", "user": "svc",
                    "password": "Ui-Retest-Secret-4", "ldaps": true}),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(!body.contains("Ui-Retest-Secret-4"), "{body}");
        assert!(!dir.join("retests.json").exists());
        assert!(std::fs::read_dir(a.state.ws().uploads_dir())
            .unwrap()
            .all(|e| !e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("retest-")));
    } else {
        let (s, body) = a
            .post_json(&uri, serde_json::json!({"fingerprint": PW003}))
            .await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert!(body.contains("no built-in collector"), "{body}");
    }

    // A recorded targeted result reaches the report's row, escaped: the
    // details can hold names from the directory.
    let hostile = r#""><img src=x onerror=alert(1)>"#;
    std::fs::write(
        dir.join("retests.json"),
        serde_json::json!({"version": 1, "results": [{"fingerprint": PW003, "at": 1791417600,
            "method": "targeted", "verdict": "still_open", "details": [hostile],
            "refreshed": 3}]})
        .to_string(),
    )
    .unwrap();
    let (_, embedded) = a.get(&format!("/runs/{first}/report?embed=1")).await;
    assert!(!embedded.contains("<img src=x"), "escaped");
    let r = &attr_json(&embedded, "content=")["f"][PW003]["r"];
    assert_eq!(r["v"], "still_open");
    assert_eq!(r["src"], "targeted");
    assert_eq!(r["at"], 1791417600);
    assert_eq!(r["d"], format!("Re-read 3 objects · {hostile}"));
    // The run page's dialog data holds no results and no details.
    let (_, page) = a.get(&format!("/runs/{first}")).await;
    assert!(!page.contains("<img src=x") && !page.contains("onerror"));
    assert!(page.contains("1 retested, <strong>0 fixed"), "{page}");

    // A second, fixed collection of the same environment: the first run's
    // findings are compared with it (the newer evidence wins).
    // Runs are ordered by the second they finished.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = a.analyze(&fixed_forest(&a.dir)).await;
    let (_, embedded) = a.get(&format!("/runs/{first}/report?embed=1")).await;
    let f = attr_json(&embedded, "content=")["f"].clone();
    let verdicts: Vec<&str> = f
        .as_object()
        .unwrap()
        .values()
        .map(|x| x["r"]["v"].as_str().unwrap())
        .collect();
    assert_eq!(verdicts.iter().filter(|v| **v == "fixed").count(), 2);
    assert_eq!(verdicts.iter().filter(|v| **v == "still_open").count(), 13);
    assert_eq!(f[PW003]["r"]["src"], "run");
    // Every result is the later run's: the run page says so rather than
    // "retested".
    let (_, page) = a.get(&format!("/runs/{first}")).await;
    assert!(
        page.contains("15 compared with a later run, <strong>2 fixed"),
        "{page}"
    );
    assert!(!page.contains(" retested, <strong>"), "{page}");

    // Progress: both runs, the charts and the numbers.
    let (s, body) = a.get("/progress").await;
    assert_eq!(s, StatusCode::OK);
    for want in [
        "Accounts with an attack path to each tier",
        "Open findings and attack paths",
        "Remediation path",
        "Objects per tier",
        "Collection completeness",
        "What changed since",
        r#"<link rel="stylesheet" href="/static/progress.css">"#,
        r#"<script src="/static/progress.js" defer></script>"#,
        "Show the numbers",
    ] {
        assert!(body.contains(want), "{want}: {body}");
    }
    // Fixed 2 against the first run, said as `pathwarden history` says it.
    assert!(body.contains("2 findings fixed"), "{body}");
    assert!(body.contains(r#"class="pv-hit""#) && body.contains("tabindex=\"0\""));
    assert!(!body.contains(" style=\""));

    // Other domains are another environment, made for them: this one's
    // Progress stays as it was.
    a.analyze(&testdata("sdprop")).await;
    assert_eq!(a.state.workspace.registry().environments.len(), 2);
    let (_, body) = a
        .get("/progress?env=CHILD.CONTOSO.LOCAL%2CCONTOSO.LOCAL")
        .await;
    assert!(body.contains("2 findings fixed"), "{body}");
    let _ = second;

    for asset in [
        "/static/retest.js",
        "/static/retest.css",
        "/static/progress.js",
        "/static/progress.css",
    ] {
        assert_eq!(a.get(asset).await.0, StatusCode::OK, "{asset}");
    }
}

/// The old-report fixtures: logo blocks from reports written before the
/// Crown W, and one whole report of that time (cut down, its own script
/// byte for byte).
fn old_report(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/old-reports")
            .join(name),
    )
    .unwrap()
}

/// A report saved before the Crown W shows the Crown W instead of the old
/// lighthouse, standalone, downloaded and embedded, while the stored file
/// stays as it was and the embedded report keeps its Retest script.
#[tokio::test]
async fn reports_saved_before_the_crown_w_show_it() {
    let a = app("oldbrand");
    let run = a.analyze(&testdata("forest")).await;
    let file = a.state.ws().run_dir(&run).unwrap().join("report.html");
    let current = std::fs::read_to_string(&file).unwrap();
    let lockup = format!(
        r#"<div class="lockup cw-intro" role="img" aria-label="Pathwarden">{}</div>"#,
        pathwarden_core::report::brand_lockup()
    );
    assert!(current.contains(&lockup));
    // A current report is served as stored.
    assert_eq!(a.get(&format!("/runs/{run}/report")).await.1, current);

    // The report with each earlier logo block in place of the Crown W: the
    // header's horizontal logo (the lighthouse) and the first report's
    // small mark. The rail's stacked logo is in the whole report below.
    for (fixture, old, swapped) in [
        (
            "brand-header.html",
            "M165 30 L172 90",
            r#"<span class="pw-cw" role="img" aria-label="Pathwarden"><svg"#,
        ),
        (
            "brand-mark.html",
            "M32 3 L34 17",
            r#"<span class="pw-cw pw-cw-mark"><svg"#,
        ),
    ] {
        let stored = current.replacen(&lockup, old_report(fixture).trim_end(), 1);
        assert!(
            stored.contains(old) && !stored.contains("pw-cw"),
            "{fixture}"
        );
        std::fs::write(&file, &stored).unwrap();
        for uri in [
            format!("/runs/{run}/report"),
            format!("/runs/{run}/report?download=1"),
            format!("/runs/{run}/report?embed=1"),
        ] {
            let (body, csp) = a.get_csp(&uri).await;
            assert!(!body.contains(old), "{fixture} {uri}");
            assert!(!body.contains("logo-light") && !body.contains("mark-light"));
            assert!(body.contains(swapped), "{fixture} {uri}");
            // One Crown W (its gradient IDs are fixed), styled from the head.
            assert_eq!(body.matches(r#"class="cw""#).count(), 1, "{fixture} {uri}");
            let head = body.split("</head>").next().unwrap();
            assert!(head.contains(".pw-cw{"), "{fixture} {uri}");
            // The report's own script is as stored.
            assert_eq!(scripts(&body)[0], scripts(&stored)[0]);
            if uri.ends_with("embed=1") {
                check_embed(&body, &csp);
            } else {
                assert_eq!(csp, pathwarden_ui::security::REPORT_CSP, "{uri}");
            }
        }
        assert_eq!(std::fs::read_to_string(&file).unwrap(), stored, "untouched");
    }

    // A whole report from before (GOAD, October 9): the rail's stacked logo
    // gives way to the lockup, the tagline stays, and its script (an
    // earlier version's, by hash) still gets the Retest buttons.
    let stored = old_report("report-2026-10-09.html");
    assert!(stored.contains(r#"<span class="logo logo-light">"#));
    std::fs::write(&file, &stored).unwrap();
    let (body, csp) = a.get_csp(&format!("/runs/{run}/report?embed=1")).await;
    check_embed(&body, &csp);
    assert!(csp.contains("'sha256-pSfi2RYenewxL5bHGWIkuL3Qv7xg1PrYLP8gTG6nCKc='"));
    // (Its stylesheet still names .logo-light and .logo-dark: harmless.)
    assert!(!body.contains("translate(103.7 -22.8)"));
    assert!(!body.contains(r#"<span class="logo "#));
    assert!(body.contains(&format!(
        r#"<div class="brand"><span class="pw-cw" role="img" aria-label="Pathwarden">{}</span><p class="tagline">"#,
        pathwarden_core::report::brand_lockup()
    )));
    // After the logo, the page is the stored one.
    let (plain, _) = a.get_csp(&format!("/runs/{run}/report")).await;
    let tail = |html: &str| {
        html.split_once(r#"<p class="tagline">"#)
            .unwrap()
            .1
            .to_string()
    };
    assert_eq!(tail(&plain), tail(&stored));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), stored, "untouched");
}

// ------------------------------------------- the computers on the path

const PW006: &str = "PW-006-8ae0b31a46eacada";
const SRV01: &str = "S-1-5-21-1000-1000-1000-1001";

/// The forest fixture with SRV01 changed by `edit`, as a re-read hands it
/// over.
fn forest_with_srv01(dir: &Path, name: &str, edit: impl Fn(&mut serde_json::Value)) -> PathBuf {
    let out = dir.join(name);
    std::fs::create_dir_all(&out).unwrap();
    for e in std::fs::read_dir(testdata("forest")).unwrap().flatten() {
        let text = std::fs::read_to_string(e.path()).unwrap();
        let mut doc: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
        if doc["meta"]["type"] == "computers" {
            for c in doc["data"].as_array_mut().unwrap() {
                if c["ObjectIdentifier"] == SRV01 {
                    edit(c);
                }
            }
        }
        std::fs::write(out.join(e.file_name()), doc.to_string()).unwrap();
    }
    out
}

/// What the fake collector reports of SRV01.
fn srv01_read(read: bool, unreachable: bool) -> pathwarden_collect::HostRead {
    pathwarden_collect::HostRead {
        id: SRV01.into(),
        name: "SRV01.CONTOSO.LOCAL".into(),
        sessions: Some(read),
        local_groups: Some(read),
        why: (!read).then(|| "it didn't answer on port 445".to_string()),
        unreachable,
        skipped: false,
        ..Default::default()
    }
}

fn form(fp: &str, password: bool) -> pathwarden_ui::retest_ui::RetestForm {
    pathwarden_ui::retest_ui::RetestForm {
        fingerprint: fp.into(),
        domain: "contoso.local".into(),
        auth: if password {
            pathwarden_ui::collect::AuthChoice::Password
        } else {
            pathwarden_ui::collect::AuthChoice::Current
        },
        user: if password {
            "svc".into()
        } else {
            String::new()
        },
        password: password.then(|| pathwarden_collect::Secret::new("Hosts-Secret-1")),
        ldaps: true,
        ..Default::default()
    }
}

/// A finding that rests on a session is retested on the computer on its
/// path, through a fake collector (nothing is contacted): fixed when nobody
/// is logged on there, still open when the session is there, "can't tell"
/// when the computer can't be reached. An ACL finding reads no computer.
#[tokio::test]
async fn a_retest_reads_the_computers_on_the_path() {
    use pathwarden_collect::FixedRefresher;
    use pathwarden_core::retest::Verdict;
    use pathwarden_ui::retest_ui::{self, targeted};
    if !pathwarden_ui::collect::BUILTIN {
        // A build without the collector refuses a targeted retest (and
        // offers none).
        return;
    }
    let a = app("hosts");
    let run = a.analyze(&testdata("forest")).await;
    let ws = &a.state.workspace;
    let dir = ws.run_dir(&run).unwrap();

    let logged_off = forest_with_srv01(&a.dir, "off", |c| {
        c["Sessions"]["Results"] = serde_json::json!([]);
    });
    let fake = FixedRefresher::new(&logged_off, vec![srv01_read(true, false)]);
    let rec = targeted(ws, &dir, form(PW006, true), &fake).unwrap();
    assert_eq!(rec.verdict, Verdict::Fixed, "{rec:?}");
    assert_eq!((rec.hosts, rec.hosts_total), (1, 1));
    {
        let asked = fake.asked.lock().unwrap();
        assert_eq!(asked[0].hosts.len(), 1);
        assert_eq!(asked[0].hosts[0].id, SRV01);
        assert!(asked[0].hosts[0].sessions && asked[0].hosts[0].local_groups);
    }
    assert_eq!(
        retest_ui::result_lines(&rec)[1],
        "Read the computer on its path."
    );

    // The session is still there.
    let fake = FixedRefresher::new(testdata("forest"), vec![srv01_read(true, false)]);
    let rec = targeted(ws, &dir, form(PW006, true), &fake).unwrap();
    assert_eq!(rec.verdict, Verdict::StillOpen);

    // SRV01 doesn't answer.
    let fake = FixedRefresher::new(&logged_off, vec![srv01_read(false, true)]);
    let rec = targeted(ws, &dir, form(PW006, true), &fake).unwrap();
    assert_eq!(rec.verdict, Verdict::CantTell);
    assert_eq!(
        rec.details[0],
        "The computer on its path couldn't be reached, so it can't be checked."
    );
    assert_eq!(rec.hosts, 0);

    // As the current Windows account: on Windows the computer is read as
    // that account (Windows' own calls), with no password sentence;
    // elsewhere the form is refused, as for a collection, and nothing is
    // read.
    let fake = FixedRefresher::new(&logged_off, vec![srv01_read(true, false)]);
    let rec = targeted(ws, &dir, form(PW006, false), &fake);
    if cfg!(windows) {
        let rec = rec.unwrap();
        let asked = fake.asked.lock().unwrap();
        assert_eq!(asked[0].hosts.len(), 1);
        assert_eq!(asked[0].hosts[0].id, SRV01);
        assert_eq!(rec.verdict, Verdict::Fixed, "{rec:?}");
        assert_eq!((rec.hosts, rec.hosts_total), (1, 1));
        assert!(
            !rec.details.iter().any(|d| d.contains("password")),
            "{:?}",
            rec.details
        );
    } else {
        let (code, body) = rec.unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["field"], "auth", "{body}");
        assert!(fake.asked.lock().unwrap().is_empty());
    }
    // As the Windows account, SRV01 denies access: can't tell, with why.
    if cfg!(windows) {
        let denied = pathwarden_collect::HostRead {
            id: SRV01.into(),
            name: "SRV01.CONTOSO.LOCAL".into(),
            sessions: Some(false),
            local_groups: Some(false),
            why: Some("access denied".into()),
            unreachable: false,
            skipped: false,
            ..Default::default()
        };
        let fake = FixedRefresher::new(&logged_off, vec![denied]);
        let rec = targeted(ws, &dir, form(PW006, false), &fake).unwrap();
        assert_eq!(rec.verdict, Verdict::CantTell, "{rec:?}");
        assert_eq!(
            rec.details[0],
            "The computer on its path couldn't be read, so it can't be checked."
        );
        assert!(
            !rec.details.iter().any(|d| d.contains("password")),
            "{:?}",
            rec.details
        );
    }

    // An ACL finding: no computer, with a password too.
    let fake = FixedRefresher::new(fixed_forest(&a.dir), vec![srv01_read(true, false)]);
    let rec = targeted(ws, &dir, form(PW003, true), &fake).unwrap();
    assert!(fake.asked.lock().unwrap()[0].hosts.is_empty());
    assert_eq!(rec.verdict, Verdict::Fixed);
    assert_eq!(rec.hosts_total, 0);

    // The results are the run's, and the report's row shows the latest.
    let (_, embedded) = a.get(&format!("/runs/{run}/report?embed=1")).await;
    let f = attr_json(&embedded, "content=")["f"].clone();
    assert_eq!(f[PW006]["r"]["v"], "cant_tell");
    assert_eq!(f[PW003]["r"]["v"], "fixed");
}

/// A Full run, then a Quick one: the findings the Quick run holds for what
/// it didn't read, and that rest on computers a retest can read, carry the
/// one line; the others don't.
#[tokio::test]
async fn only_held_findings_say_to_check_the_computers_on_their_path() {
    let a = app("held");
    let first = a.analyze(&testdata("forest")).await;
    // Before a later run, nothing is held.
    let (_, embedded) = a.get(&format!("/runs/{first}/report?embed=1")).await;
    let f = attr_json(&embedded, "content=")["f"].clone();
    assert!(f
        .as_object()
        .unwrap()
        .values()
        .all(|x| x.get("h").is_none()));

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let quick = quick_forest(&a.dir);
    a.analyze(&quick).await;
    let (_, embedded) = a.get(&format!("/runs/{first}/report?embed=1")).await;
    let f = attr_json(&embedded, "content=")["f"].clone();
    if !pathwarden_ui::collect::BUILTIN {
        // No targeted retest, so no line.
        assert!(f
            .as_object()
            .unwrap()
            .values()
            .all(|x| x.get("h").is_none()));
        return;
    }
    let line = pathwarden_core::retest::HELD_LINE;
    assert_eq!(f[PW006]["h"], line, "{}", f[PW006]);
    assert_eq!(f[PW004]["h"], line);
    assert!(f[PW003].get("h").is_none(), "an ACL finding isn't held");
    for (fp, x) in f.as_object().unwrap() {
        if x.get("h").is_some() {
            assert_eq!(x["r"]["v"], "cant_tell", "{fp}");
        }
    }
    // The dialog says it too, with the computers it reads.
    let (_, page) = a.get(&format!("/runs/{first}")).await;
    let d = attr_json(&page, "data-findings");
    assert_eq!(d[PW006]["h"], line);
    assert_eq!(d[PW006]["c"], 1);
    assert_eq!(d[PW003]["h"], "");
    assert_eq!(d[PW003]["c"], 0);
}
