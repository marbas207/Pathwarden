//! What every page shows, whatever is on it: plain words, no
//! command line ("pathwarden history ..."; commands belong in the docs);
//! and showing a page starts no git, even with a git history whose last
//! push failed (the runs waiting are noted on recordings and syncs, and
//! pages only read them).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:4253";

/// The pages of the app, as the rail and the Automate area link them.
const PAGES: &[&str] = &[
    "/",
    "/analyze",
    "/runs",
    "/explore",
    "/progress",
    "/automate/schedule",
    "/automate/ticketing",
    "/automate/history",
    "/zones",
    "/zones/new",
    "/mappings",
    "/environments",
    "/environments/connect",
    "/settings",
    "/plugins/new?kind=command",
    "/plugins/new?kind=servicenow",
];

/// Subcommands a page must not tell people to run.
const SUBCOMMANDS: &[&str] = &[
    "run", "ui", "history", "diagnose", "plan", "changes", "config", "env", "runs", "save",
    "retest", "collect", "export", "explore", "zones", "mappings", "plugins", "schedule",
    "connect", "demo",
];

fn git() -> Command {
    let mut c = Command::new("git");
    for v in pathwarden_core::store::GIT_LOCAL_ENV {
        c.env_remove(v);
    }
    c
}

fn git_ok() -> bool {
    let ok = git()
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
    }
    ok
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn get(router: &Router, st: &AppState, uri: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::HOST, HOST)
        .header(header::COOKIE, st.session_cookie())
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    let s = res.status();
    let b = res.into_body().collect().await.unwrap().to_bytes();
    (s, String::from_utf8_lossy(&b).into_owned())
}

/// `html` without its `open`...`close` elements.
fn without(html: &str, open: &str, close: &str) -> String {
    let mut kept = String::new();
    let mut rest = html;
    while let Some(i) = rest.find(open) {
        kept.push_str(&rest[..i]);
        match rest[i..].find(close) {
            Some(j) => rest = &rest[i + j + close.len()..],
            None => return kept,
        }
    }
    kept.push_str(rest);
    kept
}

/// The page's words: no scripts, styles or tags, nor the files a page
/// shows as they are (a generated script in `<pre>` or `<textarea>`).
fn words(html: &str) -> String {
    let html = without(html, "<script", "</script>");
    let html = without(&html, "<style", "</style>");
    let html = without(&html, "<pre", "</pre>");
    let html = without(&html, "<textarea", "</textarea>");
    let mut text = String::new();
    let mut tag = false;
    for c in html.chars() {
        match c {
            '<' => tag = true,
            '>' if tag => {
                tag = false;
                text.push(' ');
            }
            _ if !tag => text.push(c),
            _ => {}
        }
    }
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[tokio::test]
async fn pages_name_no_commands_and_start_no_git() {
    if !git_ok() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-words-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _clean = Dir(dir.clone());
    let remote = dir.join("state.git");
    assert!(git()
        .args(["init", "-q", "--bare"])
        .arg(&remote)
        .status()
        .unwrap()
        .success());
    let ws = Workspace::open(dir.join("ws")).unwrap();
    std::fs::write(
        ws.config_path(),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{}\"\n",
            slash(&remote),
            slash(&dir.join("ws").join("state"))
        ),
    )
    .unwrap();
    // A sync, then the mark a failed push leaves: reading it would run
    // git (`merge-base`), which no page may do.
    {
        let ws = ws.clone();
        tokio::task::spawn_blocking(move || pathwarden_ui::auto_pull::pull_env(&ws, None))
            .await
            .unwrap()
            .unwrap();
    }
    let kept = dir
        .join("ws")
        .join("state")
        .join(".git")
        .join("pathwarden-unpushed");
    std::fs::write(&kept, "0123456789abcdef0123456789abcdef01234567\n").unwrap();
    // As the recording whose push failed notes it.
    {
        let ws = ws.clone();
        tokio::task::spawn_blocking(move || {
            let loc = pathwarden_ui::history_ui::locate(&ws, None).unwrap();
            pathwarden_ui::shared_runs::record_waiting(&ws, &loc);
        })
        .await
        .unwrap();
    }

    let st = Arc::new(AppState::new(ws.clone(), Token::generate().unwrap(), 4253));
    let r = router(st.clone());
    let pages: Vec<String> = PAGES.iter().map(|p| p.to_string()).collect();
    let before = pathwarden_core::store::git_runs();
    show(&r, &st, &pages, &[]).await;
    assert_eq!(
        pathwarden_core::store::git_runs(),
        before,
        "showing a page started git"
    );

    // A cold start on an encrypted git history with a run in it: its run
    // page and the report frame too. Git at most once per check while
    // nothing is known, then never.
    std::env::set_var(
        pathwarden_core::keystore::TEST_STORE_ENV,
        dir.join("keystore"),
    );
    std::env::remove_var(pathwarden_core::keystore::ENV_VAR);
    let remote2 = dir.join("enc.git");
    assert!(git()
        .args(["init", "-q", "--bare"])
        .arg(&remote2)
        .status()
        .unwrap()
        .success());
    let ws2 = Workspace::open(dir.join("ws2")).unwrap();
    std::fs::write(
        ws2.config_path(),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{}\"\n",
            slash(&remote2),
            slash(&dir.join("ws2").join("state"))
        ),
    )
    .unwrap();
    let st2 = Arc::new(AppState::new(ws2.clone(), Token::generate().unwrap(), 4253));
    let r2 = router(st2.clone());
    let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    analyze(&r2, &st2, &forest).await;
    let (s, b) = post(
        &r2,
        &st2,
        "/api/history/encryption",
        serde_json::json!({"on": true, "passphrase": "correct horse battery staple"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(pathwarden_core::crypt::is_encrypted(
        &dir.join("ws2").join("state")
    ));
    let run = ws2.runs().into_iter().next().expect("a run").id;
    let mut pages2 = pages.clone();
    pages2.push(format!("/runs/{run}"));
    let report = format!("/runs/{run}/report?embed=1");
    pathwarden_core::store::forget_kept_answers();
    let cold = pathwarden_core::store::git_runs();
    show(&r2, &st2, &pages2, std::slice::from_ref(&report)).await;
    let first = pathwarden_core::store::git_runs() - cold;
    assert!(first <= 3, "{first} git commands on a cold start");
    let warm = pathwarden_core::store::git_runs();
    show(&r2, &st2, &pages2, &[report]).await;
    assert_eq!(
        pathwarden_core::store::git_runs(),
        warm,
        "showing a page started git once its checks were known"
    );
}

/// The user's profile folder, without a trailing separator (`None` when
/// it is unset or a root).
fn profile() -> Option<String> {
    let home = std::env::var(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).ok()?;
    let home = home.trim_end_matches(['\\', '/']);
    (home.len() >= 3).then(|| home.to_string())
}

/// Shows `pages` (and the footer's poll), each without a command named in
/// its words, a lab's names or the profile folder, and `raw` (the report
/// frame) as they are.
async fn show(r: &Router, st: &AppState, pages: &[String], raw: &[String]) {
    for page in pages {
        let (s, html) = get(r, st, page).await;
        // Explore opens the latest run's once there is one.
        if s == StatusCode::SEE_OTHER && page == "/explore" {
            continue;
        }
        assert_eq!(s, StatusCode::OK, "{page}");
        // Case kept: "Stop Pathwarden" then "Runs" is no command.
        let text = words(&html);
        // No lab's names in the help, and no user name in a path
        // (the workspace and the plugin folders here are under the
        // profile when the temp folder is).
        for lab in ["ESSOS", "SEVENKINGDOMS", "GOAD"] {
            assert!(
                !text.contains(lab),
                "{page} names {lab}: {}",
                text.find(lab)
                    .map(|i| &text[text[..i].char_indices().rev().nth(80).map_or(0, |(j, _)| j)..])
                    .unwrap_or("")
                    .chars()
                    .take(200)
                    .collect::<String>()
            );
        }
        if let Some(home) = profile() {
            let (text, home) = (text.to_lowercase(), home.to_lowercase());
            assert!(
                !text.contains(&home),
                "{page} shows the profile folder: {}",
                text.find(&home)
                    .map(|i| &text[i.saturating_sub(80)..(i + 120).min(text.len())])
                    .unwrap_or_default()
            );
        }
        for sub in SUBCOMMANDS {
            let said = format!("pathwarden {sub} ");
            let end = format!("pathwarden {sub}.");
            assert!(
                !text.contains(&said) && !text.contains(&end),
                "{page} names `pathwarden {sub}`: {}",
                text.find(&said)
                    .or_else(|| text.find(&end))
                    .map(|i| &text[i.saturating_sub(120)..(i + 80).min(text.len())])
                    .unwrap_or_default()
            );
        }
    }
    for page in raw {
        let (s, _) = get(r, st, page).await;
        assert_eq!(s, StatusCode::OK, "{page}");
    }
    let (s, _) = get(r, st, "/api/history/pulled?since=0&page=runs").await;
    assert_eq!(s, StatusCode::OK);
}

async fn post(
    r: &Router,
    st: &AppState,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::HOST, HOST)
        .header(header::COOKIE, st.session_cookie())
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, format!("http://{HOST}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let res = r.clone().oneshot(req).await.unwrap();
    let s = res.status();
    let b = res.into_body().collect().await.unwrap().to_bytes();
    (s, String::from_utf8_lossy(&b).into_owned())
}

/// Analyzes `path` as the Analyze page does, and waits for it.
async fn analyze(r: &Router, st: &AppState, path: &Path) {
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let boundary = "wordsBoundary";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"env\"\r\n\r\ndefault\r\n--{boundary}--\r\n",
        path.display()
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/analyze")
        .header(header::HOST, HOST)
        .header(header::COOKIE, st.session_cookie())
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header(header::ORIGIN, format!("http://{HOST}"))
        .body(Body::from(body))
        .unwrap();
    let res = r.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let b = res.into_body().collect().await.unwrap().to_bytes();
    let job = serde_json::from_slice::<serde_json::Value>(&b).unwrap()["job"]
        .as_str()
        .unwrap()
        .to_string();
    for _ in 0..2400 {
        let (_, body) = get(r, st, &format!("/api/jobs/{job}")).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        if !matches!(v["status"].as_str(), Some("running" | "collecting")) {
            assert_eq!(v["status"], "done", "{v}");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("analysis did not finish");
}
