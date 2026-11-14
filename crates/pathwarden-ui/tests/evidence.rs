//! Evidence packs and findings files from the run page, and the signing key
//! and pack check in Settings, through the router.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_core::evidence::pack;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
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
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-ev-{name}-{}", std::process::id()));
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
/// requiring pre-authentication again: two findings fixed.
fn fixed_forest(dir: &Path) -> PathBuf {
    let out = dir.join("fixed");
    std::fs::create_dir_all(&out).unwrap();
    for e in std::fs::read_dir(testdata("forest")).unwrap().flatten() {
        let mut text = std::fs::read_to_string(e.path()).unwrap();
        if e.file_name().to_string_lossy() == "contoso_users.json" {
            let mut doc: Value = serde_json::from_str(&text).unwrap();
            for o in doc["data"].as_array_mut().unwrap() {
                match o["ObjectIdentifier"].as_str().unwrap() {
                    "S-1-5-21-2000-2000-2000-1201" => o["Aces"] = json!([]),
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

struct Res {
    status: StatusCode,
    disposition: String,
    body: Vec<u8>,
}

impl Res {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("{}", self.text()))
    }
}

impl App {
    fn request(&self, method: Method, uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
    }

    async fn send(&self, req: Request<Body>) -> Res {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let disposition = res
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        Res {
            status,
            disposition,
            body,
        }
    }

    async fn get(&self, uri: &str) -> Res {
        self.send(self.request(Method::GET, uri).body(Body::empty()).unwrap())
            .await
    }

    async fn post_json(&self, uri: &str, body: Value) -> Res {
        let req = self
            .request(Method::POST, uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        self.send(req).await
    }

    /// Posts a multipart form: (name, file name, bytes) per part.
    async fn post_form(&self, uri: &str, parts: &[(&str, Option<&str>, &[u8])]) -> Res {
        let boundary = "evBoundary";
        let mut body = Vec::new();
        for (name, file, data) in parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            match file {
                Some(f) => body.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
                ),
                None => body.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
                ),
            }
            body.extend_from_slice(data);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let req = self
            .request(Method::POST, uri)
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body))
            .unwrap();
        self.send(req).await
    }

    /// Analyzes a folder and returns the new run's ID.
    async fn analyze(&self, path: &Path) -> String {
        let r = self
            .post_form(
                "/api/analyze",
                &[("path", None, path.display().to_string().as_bytes())],
            )
            .await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.text());
        let job = r.json()["job"].as_str().unwrap().to_string();
        for _ in 0..600 {
            let v = self.get(&format!("/api/jobs/{job}")).await.json();
            if v["status"] == "done" {
                return v["run"].as_str().unwrap().to_string();
            }
            assert_ne!(v["status"], "failed", "{v}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("analysis did not finish");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evidence_packs_findings_files_and_the_signing_key() {
    let a = app("all");
    let first = a.analyze(&testdata("forest")).await;
    // Run IDs are by the second.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let fixed = fixed_forest(&a.dir);
    let second = a.analyze(&fixed).await;

    // The run page's Download menu: the first run has nothing to compare
    // with, so its pack is off and says why.
    let page = a.get(&format!("/runs/{first}")).await.text();
    assert!(page.contains("Download "), "{page}");
    assert!(
        page.contains("Needs an earlier run of this environment to compare with."),
        "{page}"
    );
    assert!(page.contains("data-ff-open") && page.contains("/static/evidence.js"));
    assert!(!page.contains("pathwarden evidence"), "no command hints");
    let page = a.get(&format!("/runs/{second}")).await.text();
    assert!(page.contains("data-ev-open"), "{page}");
    assert!(page.contains(r#"<dialog id="ev-dialog""#));

    // The dialog's choices: the earlier run, and no key yet.
    let form = a.get(&format!("/api/runs/{second}/evidence")).await.json();
    assert_eq!(form["earlier"].as_array().unwrap().len(), 1, "{form}");
    assert_eq!(form["earlier"][0]["id"], first.as_str());
    assert_eq!(form["earlier"][0]["previous"], true);
    assert!(form["key"].is_null(), "{form}");
    let file = form["file"].as_str().unwrap().to_string();
    assert!(
        file.starts_with("pathwarden-evidence-") && file.ends_with(".zip"),
        "{file}"
    );
    assert!(form["file_redacted"]
        .as_str()
        .unwrap()
        .ends_with("-redacted.zip"));

    // No key: no pack.
    let r = a
        .post_json(&format!("/api/runs/{second}/evidence"), json!({}))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.text().contains("No signing key yet."), "{}", r.text());

    // Create the key; a second "create" is refused, "replace" isn't.
    let k = a
        .post_json("/api/evidence/key", json!({"action": "create"}))
        .await;
    assert_eq!(k.status, StatusCode::OK, "{}", k.text());
    let fp = k.json()["fingerprint"].as_str().unwrap().to_string();
    assert!(fp.starts_with("SHA256:"));
    let again = a
        .post_json("/api/evidence/key", json!({"action": "create"}))
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    let key_dir = a.dir.join("ws").join(pathwarden_ui::evidence_ui::KEY_DIR);
    assert!(key_dir.join("evidence.key").is_file());
    assert!(key_dir.join("evidence.pub").is_file());
    // Created private: nobody else can read the folder or the key.
    assert!(pathwarden_core::perms::readable_by_others(&key_dir).is_empty());
    assert!(pathwarden_core::perms::readable_by_others(&key_dir.join("evidence.key")).is_empty());

    // Settings shows it, and gives its public key.
    let settings = a.get("/settings").await.text();
    assert!(settings.contains("Evidence signing key"), "{settings}");
    assert!(settings.contains(&fp));
    assert!(settings.contains("Check an evidence pack"));
    assert!(settings.contains(r##"<a href="#evidence">Evidence packs</a>"##));
    let pubkey = a.get("/evidence/public-key").await;
    assert_eq!(pubkey.status, StatusCode::OK);
    assert!(pubkey.disposition.contains("evidence.pub"));
    assert!(pubkey.text().contains(&fp));

    // The pack: every finding open in the first run, signed and checked.
    let made = a
        .post_json(&format!("/api/runs/{second}/evidence"), json!({}))
        .await;
    assert_eq!(made.status, StatusCode::OK, "{}", made.text());
    let m = made.json();
    assert_eq!(m["file"], file.as_str());
    assert_eq!(m["verified"], true, "{m}");
    assert_eq!(m["files_ok"], 6, "{m}");
    assert_eq!(m["signed_by"], fp.as_str());
    let shows = m["shows"].as_str().unwrap();
    assert!(
        shows.contains(" fixed · ") && shows.contains(" still open · "),
        "{shows}"
    );
    assert!(
        !shows.starts_with("0 fixed"),
        "two findings were fixed: {shows}"
    );
    let dl = a.get(m["download"].as_str().unwrap()).await;
    assert_eq!(dl.status, StatusCode::OK);
    assert!(dl.disposition.contains(&file), "{}", dl.disposition);
    assert_eq!(pack::sha256_hex(&dl.body), m["sha256"].as_str().unwrap());
    // Downloaded once.
    assert_eq!(
        a.get(m["download"].as_str().unwrap()).await.status,
        StatusCode::NOT_FOUND
    );
    let v = pack::verify_zip(
        &dl.body,
        &pack::Expected {
            key: None,
            fingerprint: Some(fp.clone()),
        },
    );
    assert_eq!(v.outcome, pack::Outcome::Verified, "{:?}", v.problems);
    let names: Vec<&str> = v
        .manifest
        .as_ref()
        .unwrap()
        .files
        .iter()
        .map(|f| f.path.as_str())
        .collect();
    assert!(names.contains(&"report.html"), "{names:?}");
    // The run's report as stored, and its collector files' hashes (taken
    // when it was analyzed).
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(dl.body.clone())).unwrap();
    let read = |zip: &mut zip::ZipArchive<std::io::Cursor<Vec<u8>>>, name: &str| {
        use std::io::Read;
        let mut s = String::new();
        zip.by_name(name).unwrap().read_to_string(&mut s).unwrap();
        s
    };
    let meta: Value = serde_json::from_str(&read(&mut zip, "metadata.json")).unwrap();
    assert_eq!(meta["before"]["kind"], "run");
    let files = meta["after"]["collection"]["files"].as_array().unwrap();
    assert!(!files.is_empty(), "{meta}");
    assert!(meta["after"]["collection"]["combined_sha256"].is_string());
    let report = read(&mut zip, "report.html");
    assert!(report.contains("<html"), "a report");

    // Leaving out names: no report, and checked for names.
    let r = a
        .post_json(
            &format!("/api/runs/{second}/evidence"),
            json!({"redact": true}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let rm = r.json();
    assert_eq!(rm["files_ok"], 5, "{rm}");
    assert!(rm["file"].as_str().unwrap().ends_with("-redacted.zip"));
    let rz = a.get(rm["download"].as_str().unwrap()).await.body;
    let text = String::from_utf8_lossy(&rz).to_ascii_lowercase();
    assert!(
        !text.contains("report.html"),
        "no report in a redacted pack"
    );

    // Some findings: one rule of the earlier run.
    let open = a
        .get(&format!(
            "/api/runs/{second}/evidence/findings?against={first}"
        ))
        .await
        .json();
    let list = open["findings"].as_array().unwrap();
    assert!(!list.is_empty(), "{open}");
    let rule = list[0]["rule"].as_str().unwrap().to_string();
    let r = a
        .post_json(
            &format!("/api/runs/{second}/evidence"),
            json!({"against": first, "rules": [rule]}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let one = a.get(r.json()["download"].as_str().unwrap()).await.body;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(one.clone())).unwrap();
    let retest: Value = serde_json::from_str(&read(&mut zip, "retest.json")).unwrap();
    for x in retest["results"].as_array().unwrap() {
        assert_eq!(x["rule"], rule.as_str(), "{retest}");
    }
    // A finding the earlier run hasn't open is refused, with why.
    let r = a
        .post_json(
            &format!("/api/runs/{second}/evidence"),
            json!({"findings": ["PW-999-0000000000000000"]}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.text());
    // And the first run can't make one.
    let r = a
        .post_json(&format!("/api/runs/{first}/evidence"), json!({}))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);

    // Check a pack: with the fingerprint, without it, and changed.
    let v = a
        .post_form(
            "/api/evidence/verify",
            &[
                ("pack", Some("p.zip"), &dl.body),
                ("fingerprint", None, fp.as_bytes()),
            ],
        )
        .await;
    assert_eq!(v.status, StatusCode::OK, "{}", v.text());
    let vj = v.json();
    assert_eq!(vj["outcome"], "verified", "{vj}");
    assert_eq!(vj["files_ok"], 6);
    assert!(vj["shows"]["counts"]
        .as_str()
        .unwrap()
        .contains(" fixed · "));
    assert_eq!(vj["shows"]["baseline_kind"], "run");
    let v = a
        .post_form("/api/evidence/verify", &[("pack", Some("p.zip"), &dl.body)])
        .await
        .json();
    assert_eq!(v["outcome"], "signer_not_checked", "{v}");
    let v = a
        .post_form(
            "/api/evidence/verify",
            &[
                ("pack", Some("p.zip"), &dl.body),
                ("key", Some("evidence.pub"), &pubkey.body),
            ],
        )
        .await
        .json();
    assert_eq!(v["outcome"], "verified", "{v}");
    let mut bad = dl.body.clone();
    let n = bad.len();
    bad[n / 2] ^= 0x55;
    let v = a
        .post_form(
            "/api/evidence/verify",
            &[
                ("pack", Some("p.zip"), &bad),
                ("fingerprint", None, fp.as_bytes()),
            ],
        )
        .await
        .json();
    assert_eq!(v["outcome"], "failed", "{v}");
    assert!(!v["problems"].as_array().unwrap().is_empty());
    let r = a.post_form("/api/evidence/verify", &[]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Findings files: SARIF and DefectDojo, named after the run.
    let info = a
        .get(&format!("/api/runs/{second}/findings-file"))
        .await
        .json();
    assert!(info["open"].as_u64().unwrap() > 0, "{info}");
    assert_eq!(info["held"], 0, "{info}");
    let sarif_name = info["sarif"].as_str().unwrap();
    assert!(
        sarif_name.starts_with("pathwarden-findings-") && sarif_name.ends_with(".sarif"),
        "{sarif_name}"
    );
    assert!(info["defectdojo"].as_str().unwrap().ends_with(".json"));
    let s = a
        .get(&format!("/runs/{second}/findings-file?format=sarif"))
        .await;
    assert_eq!(s.status, StatusCode::OK);
    assert!(s.disposition.contains(sarif_name));
    let sj = s.json();
    assert_eq!(sj["version"], "2.1.0");
    assert!(!sj["runs"][0]["results"].as_array().unwrap().is_empty());
    let d = a
        .get(&format!("/runs/{second}/findings-file?format=defectdojo"))
        .await
        .json();
    assert!(!d["findings"].as_array().unwrap().is_empty(), "{d}");
    // The same file `pathwarden export --run` writes: the shared code.
    let ws = &a.state.workspace;
    let r2 = ws.run(&second).unwrap();
    // The app reads the history `state_dir_for` names; the command line
    // passes `--state`, or nothing for the environment's own, the same.
    let state_dir = a.state.state_dir_for(&ws.for_run(&r2));
    assert_eq!(state_dir, None);
    let doc = pathwarden_ui::evidence_ui::findings_doc(ws, None, &r2).unwrap();
    assert_eq!(
        pathwarden_export::text(&doc, pathwarden_export::Format::Sarif).unwrap(),
        s.text()
    );
    assert_eq!(
        a.get(&format!("/runs/{second}/findings-file?format=xml"))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    // Replace the key, then use the old one again from its file.
    let old = std::fs::read_to_string(key_dir.join("evidence.key")).unwrap();
    let r = a
        .post_json("/api/evidence/key", json!({"action": "replace"}))
        .await
        .json();
    assert_ne!(r["fingerprint"], fp.as_str());
    let r = a
        .post_json(
            "/api/evidence/key",
            json!({"action": "use", "text": "nope"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.text().contains("isn't a signing key"), "{}", r.text());
    let r = a
        .post_json("/api/evidence/key", json!({"action": "use", "text": old}))
        .await
        .json();
    assert_eq!(r["fingerprint"], fp.as_str());
    // Replaced or used, the key stays private, and no temporary file is
    // left beside it.
    let private = |p: &Path| pathwarden_core::perms::readable_by_others(p).is_empty();
    assert!(private(&key_dir), "the key folder is private");
    assert!(private(&key_dir.join("evidence.key")));
    assert!(!key_dir.join(".new").exists());
    assert!(pathwarden_ui::evidence_ui::key_exposure(ws).is_none());

    // A wrong signer gives Not verified: another fingerprint, another key
    // file. Both at once is refused.
    let other = pathwarden_core::evidence::SecretKey::generate()
        .unwrap()
        .public();
    let v = a
        .post_form(
            "/api/evidence/verify",
            &[
                ("pack", Some("p.zip"), &dl.body),
                ("fingerprint", None, other.fingerprint().as_bytes()),
            ],
        )
        .await
        .json();
    assert_eq!(v["outcome"], "failed", "{v}");
    let v = a
        .post_form(
            "/api/evidence/verify",
            &[
                ("pack", Some("p.zip"), &dl.body),
                ("key", Some("other.pub"), other.file_text().as_bytes()),
            ],
        )
        .await
        .json();
    assert_eq!(v["outcome"], "failed", "{v}");
    let r = a
        .post_form(
            "/api/evidence/verify",
            &[
                ("pack", Some("p.zip"), &dl.body),
                ("fingerprint", None, fp.as_bytes()),
                ("key", Some("evidence.pub"), &pubkey.body),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text());

    // A later run: the pack of the run before it holds nothing from after
    // it (its history ends at its analysis; the findings state, which is
    // the history's now, is left out and the pack says so).
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let third = a.analyze(&testdata("forest")).await;
    let r3 = ws.run(&third).unwrap();
    let made = a
        .post_json(&format!("/api/runs/{second}/evidence"), json!({}))
        .await;
    assert_eq!(made.status, StatusCode::OK, "{}", made.text());
    let bytes = a.get(made.json()["download"].as_str().unwrap()).await.body;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let meta: Value = serde_json::from_str(&read(&mut zip, "metadata.json")).unwrap();
    let limits = meta["limits"].to_string();
    assert!(
        limits.contains("its findings state is not this run's"),
        "{limits}"
    );
    let history: Value = serde_json::from_str(&read(&mut zip, "history.json")).unwrap();
    let points = history["points"].as_array().unwrap();
    assert!(!points.is_empty(), "{history}");
    for p in points {
        assert!(p["at"].as_i64().unwrap() <= r2.created_at, "{p}");
        assert!(p["at"].as_i64().unwrap() < r3.created_at);
    }
    let findings: Value = serde_json::from_str(&read(&mut zip, "findings.json")).unwrap();
    for f in findings["retested"].as_array().unwrap() {
        assert!(f["tracked"].is_null(), "{f}");
    }
}

/// A run loaded from the shared history: whoever can write the history
/// made its findings and report, so this computer signs no pack of it, nor
/// compares with one. The run page says why, and `pathwarden evidence
/// --run` (the same `build_pack`) refuses too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_loaded_from_the_history_gets_no_pack() {
    use pathwarden_ui::evidence_ui::{self, PackOptions, LOADED_RUN};
    use pathwarden_ui::shared_runs::{SharedFrom, LOADED_MARKER};
    let a = app("loaded");
    let first = a.analyze(&testdata("forest")).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let fixed = fixed_forest(&a.dir);
    let second = a.analyze(&fixed).await;
    let ws = &a.state.workspace;
    let from = SharedFrom {
        remote: "https://git.example.com/history.git".into(),
        branch: None,
        recorded_by: Some("EXAMPLE\\writer".into()),
        recorded_on: Some("WS01".into()),
        recorded_from: "app".into(),
        pathwarden: "1.0.0".into(),
        mirrored_at: 0,
        manifest_sha256: "0".repeat(64),
        left_out: vec![],
    };
    let opts = PackOptions {
        against: None,
        findings: vec![],
        rules: vec![],
        redact: false,
    };
    // As this computer made it, the second run can have a pack.
    let mut r = ws.run(&second).unwrap();
    assert_eq!(evidence_ui::pack_blocked(ws, &r), None);
    // Loaded from the history: refused, with the reason.
    r.shared = Some(from.clone());
    assert_eq!(evidence_ui::pack_blocked(ws, &r), Some(LOADED_RUN));
    let err = evidence_ui::build_pack(ws, None, &r, &opts, "SHA256:x", 0)
        .err()
        .expect("refused");
    assert_eq!(err, LOADED_RUN);
    // A loaded run is never the one compared with either.
    let mut b = ws.run(&first).unwrap();
    let bdir = ws.run_dir(&first).unwrap();
    std::fs::write(bdir.join(LOADED_MARKER), b"Loaded.\n").unwrap();
    b.shared = Some(from);
    ws.update_summary(&b).unwrap();
    assert!(ws.run(&first).unwrap().shared.is_some());
    let r = ws.run(&second).unwrap();
    assert!(evidence_ui::earlier_runs(ws, &r).is_empty());
    assert_eq!(
        evidence_ui::pack_blocked(ws, &r),
        Some("Needs an earlier run of this environment to compare with.")
    );
    let against = PackOptions {
        against: Some(first.clone()),
        ..opts
    };
    let err = evidence_ui::build_pack(ws, None, &r, &against, "SHA256:x", 0)
        .err()
        .expect("refused");
    assert!(err.contains("was loaded from the shared history"), "{err}");
}
