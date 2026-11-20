//! Finding actions in a real browser, with the fake action program in
//! testdata/actions: a click on the finding's action button in the
//! embedded report opens the run page's dialog, Run shows the progress
//! and then the result; the record's chip and the Activity are on the
//! finding at once and after a reload; a follow-up (Check status) updates
//! the chip; and the Records filter and the Overview's count follow.
//! Headless Edge or Chrome (`PATHWARDEN_TEST_BROWSER` names one), skipped
//! with a note when there is none.
//!
//! The app is served on 127.0.0.1 as `pathwarden ui` serves it; a layer
//! around it adds two probes, one in the run page (a script file, which
//! its policy allows) and one in the report's frame (allowed by its hash,
//! as the app allows its own), which click and read as a person would
//! and post what they saw to `/__probe/result`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tower::ServiceExt;

use crate::security::Token;
use crate::server::{router, AppState};
use crate::workspace::Workspace;

/// In the run page: fills in the dialog and runs the action, reads the
/// progress and the result, clicks Done; reloads once the report shows
/// the chip.
const TOP: &str = r##"(function () {
  function post(m) { return fetch("/__probe/result", { method: "POST", body: JSON.stringify(m) }); }
  var lines = 0, closed = false;
  window.addEventListener("message", function (e) {
    var m = e.data;
    if (!m || m.type !== "pw-probe") return;
    post(m);
    if (m.step === "chip") (function reload() { if (closed) location.reload(); else setTimeout(reload, 100); })();
  });
  function $(id) { return document.getElementById(id); }
  function tick() {
    var d = $("ac-dialog");
    if (d && d.open && !d.getAttribute("data-probe") && !$("ac-form").hidden) {
      d.setAttribute("data-probe", "1");
      var note = $("ac-in-note");
      if (note) note.value = "From the browser test";
      post({ step: "dialog", label: $("ac-eyebrow").textContent, sends: $("ac-sends-text").textContent });
      $("ac-go").click();
    }
    if (d && !$("ac-run").hidden) lines = Math.max(lines, d.querySelectorAll("#ac-lines li").length);
    if (d && d.getAttribute("data-probe") === "1" && !$("ac-result").hidden) {
      d.setAttribute("data-probe", "2");
      var r = $("ac-result");
      post({ step: "result", title: (r.querySelector("strong") || {}).textContent, chip: (r.querySelector(".ac-chip") || {}).textContent, said: $("ac-saved").textContent, lines: lines });
      // Closed with the dialog's x: no page comes, so the page's wait
      // bar mustn't start (it stayed, spinning, before).
      setTimeout(function () {
        d.querySelector(".rt-x").click(); d.removeAttribute("data-probe"); lines = 0;
        setTimeout(function () {
          // Reloaded only once this is in.
          post({ step: "closed", open: d.open, bar: !!document.querySelector(".pw-load") })
            .then(function () { closed = true; }, function () { closed = true; });
        }, 700);
      }, 300);
    }
    setTimeout(tick, 100);
  }
  tick();
})();"##;

/// In the report's frame: clicks the action, waits for its chip and
/// Activity; after the reload reads them again, runs Check status and
/// waits for the chip to say Closed; then tries the Records filter.
const FRAME: &str = r##"(function () {
  function say(m) { m.type = "pw-probe"; window.parent.postMessage(m, "*"); }
  function q(s, r) { return (r || document).querySelector(s); }
  function wait(fn, ms, then) {
    var t0 = Date.now();
    (function loop() {
      var v = null;
      try { v = fn(); } catch (e) {}
      if (v) return then(v);
      if (Date.now() - t0 > ms) return say({ step: "timeout", done: true });
      setTimeout(loop, 100);
    })();
  }
  var rows = Array.prototype.slice.call(document.querySelectorAll("details.finding"));
  function btn(d, label) {
    return Array.prototype.filter.call(d.querySelectorAll("button"), function (b) { return b.textContent.trim() === label; })[0];
  }
  var withRecord = rows.filter(function (d) { return +d.getAttribute("data-records") > 0; });
  if (!withRecord.length) {
    var d = rows.filter(function (r) { return btn(r, "Open a ticket"); })[0];
    if (!d) return say({ step: "no-button", done: true });
    say({ step: "clicked", fp: d.id.slice(2), more: !!q(".fa-more", d) });
    btn(d, "Open a ticket").click();
    wait(function () { return q(".ac-rowchips .ac-chip", d); }, 60000, function (c) {
      say({ step: "chip", fp: d.id.slice(2), chip: c.textContent, activity: (q(".ac-box .ac-act li .what", d) || {}).textContent, again: !!btn(d, "Open a ticket") });
    });
    return;
  }
  var f = withRecord[0];
  var chip = q(".ac-rowchips .ac-chip", f);
  var act = q(".ac-box .ac-act li .what", f);
  say({ step: "reloaded", fp: f.id.slice(2), chip: chip && chip.textContent, activity: act && act.textContent, again: !!btn(f, "Open a ticket") });
  var status = btn(f, "Check status");
  if (!status) return say({ step: "no-follow-up", done: true });
  status.click();
  wait(function () { var c = q(".ac-rowchips .ac-chip", f); return c && /Closed/.test(c.textContent) && c; }, 60000, function (c) {
    var radios = document.querySelectorAll('input[name="f-records"]');
    function shown() { return rows.filter(function (r) { return !r.hidden; }).length; }
    function pick(v) {
      Array.prototype.forEach.call(radios, function (x) { x.checked = x.value === v; });
      Array.prototype.forEach.call(radios, function (x) { if (x.checked) x.dispatchEvent(new Event("change")); });
      return shown();
    }
    var all = pick(""), yes = pick("yes"), no = pick("no");
    pick("");
    var ov = q("a.ov-recs");
    say({ step: "filter", chip: c.textContent, shown: !!radios.length && !q(".f-recs").hidden, all: all, yes: yes, no: no, overview: ov && ov.textContent, done: true });
  });
})();"##;

/// What the probes said, in order.
#[derive(Default)]
struct Probe {
    said: Mutex<Vec<Value>>,
}

/// Serves the probes and their results, and puts the probes in the run
/// page and in the report's frame.
async fn probes(State(p): State<Arc<Probe>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or_default().to_string();
    if path == "/__probe/top.js" {
        return ([(header::CONTENT_TYPE, "text/javascript")], TOP).into_response();
    }
    if path == "/__probe/result" && req.method() == Method::POST {
        let body = axum::body::to_bytes(req.into_body(), 1 << 20)
            .await
            .unwrap_or_default();
        if let Ok(v) = serde_json::from_slice::<Value>(&body) {
            p.said.lock().unwrap().push(v);
        }
        return StatusCode::NO_CONTENT.into_response();
    }
    let res = next.run(req).await;
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let frame =
        parts.len() == 3 && parts[0] == "runs" && parts[2] == "report" && query.contains("embed=1");
    let page = parts.len() == 2 && parts[0] == "runs";
    if res.status() != StatusCode::OK || !(frame || page) {
        return res;
    }
    let (mut head, body) = res.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let mut html = String::from_utf8_lossy(&bytes).into_owned();
    let tag = if frame {
        format!("<script>{FRAME}</script>")
    } else {
        r#"<script src="/__probe/top.js"></script>"#.to_string()
    };
    match html.rfind("</body>") {
        Some(i) => html.insert_str(i, &tag),
        None => html.push_str(&tag),
    }
    if frame {
        let csp = head.headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .replacen(
                "script-src ",
                &format!("script-src {} ", crate::retest_ui::csp_hash(FRAME)),
                1,
            );
        head.headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_str(&csp).unwrap(),
        );
    }
    head.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(head, Body::from(html))
}

/// The `[[action]]` block that runs the fake program.
fn fake_block() -> String {
    let ext = if cfg!(windows) { "ps1" } else { "sh" };
    let script = std::path::absolute(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../testdata/actions/fake-action.{ext}")),
    )
    .unwrap()
    .display()
    .to_string();
    let argv: Vec<String> = if cfg!(windows) {
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ]
        .iter()
        .map(|a| a.to_string())
        .chain([script])
        .collect()
    } else {
        vec!["sh".into(), script]
    };
    format!(
        "\n[[action]]\nname = \"fake\"\ncommand = {}\n",
        serde_json::to_string(&argv).unwrap()
    )
}

#[test]
fn an_action_runs_in_a_browser_and_stays_on_the_finding() {
    let Some(exe) = crate::run_details::browser_tests::browser() else {
        eprintln!("no Edge or Chrome found: the finding actions browser test was skipped");
        return;
    };
    let dir = std::env::temp_dir().join(format!("pw-ac-browser-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let token = Token::generate().unwrap();
    let secret = token.expose().to_string();
    let state = Arc::new(AppState::new(ws, token, port));
    let host = format!("127.0.0.1:{port}");

    // One analysis of the forest fixture, then the fake action set up.
    let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let run = rt.block_on(async {
        let app = router(state.clone());
        let boundary = "acBrowser";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{}\r\n--{boundary}--\r\n",
            forest.display()
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/analyze")
            .header(header::HOST, &host)
            .header(header::COOKIE, state.session_cookie())
            .header(header::ORIGIN, format!("http://{host}"))
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let job = serde_json::from_slice::<Value>(&bytes).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string();
        loop {
            let j = state.jobs.get(&job).unwrap();
            match &j.status {
                crate::jobs::JobStatus::Done { run } => break run.clone(),
                crate::jobs::JobStatus::Failed { error } => panic!("{error}"),
                _ => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    });
    let config = state.ws().config_path();
    let mut text = std::fs::read_to_string(&config).unwrap_or_default();
    text.push_str(&fake_block());
    std::fs::write(&config, text).unwrap();

    let probe = Arc::new(Probe::default());
    let app =
        router(state.clone()).layer(axum::middleware::from_fn_with_state(probe.clone(), probes));
    rt.spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let profile = dir.join("profile");
    let mut browser = pathwarden_core::spawn::quiet(&exe)
        .args([
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--window-size=1440,1000",
        ])
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("http://{host}/runs/{run}?token={secret}"))
        .spawn()
        .unwrap();
    let started = Instant::now();
    let said = loop {
        let said = probe.said.lock().unwrap().clone();
        if said.iter().any(|s| s["done"] == true) || started.elapsed() > Duration::from_secs(150) {
            break said;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let _ = browser.kill();
    let _ = browser.wait();
    drop(rt);
    let _ = std::fs::remove_dir_all(&dir);

    let step = |name: &str| -> Value {
        said.iter()
            .find(|s| s["step"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("no {name}: {said:?}"))
    };
    // Click, dialog, progress, result.
    let dialog = step("dialog");
    assert_eq!(dialog["label"], "Open a ticket", "{said:?}");
    assert_eq!(dialog["sends"], "The finding's title and the note.");
    let result = step("result");
    assert_eq!(result["title"], "Opened FAKE0001.", "{said:?}");
    assert_eq!(result["chip"], "FAKE0001 · Open");
    assert_eq!(result["said"], crate::actions_ui::SAVED_PAGE_WORDS);
    // The report's finding at once: its chip and Activity, and no second
    // Open while the ticket is open (once).
    let chip = step("chip");
    assert_eq!(chip["chip"], "FAKE0001 · Open", "{said:?}");
    assert_eq!(chip["activity"], "Opened FAKE0001");
    assert_eq!(chip["again"], false);
    // After a reload, from the run history.
    let again = step("reloaded");
    assert_eq!(again["fp"], chip["fp"], "{said:?}");
    assert_eq!(again["chip"], "FAKE0001 · Open");
    assert_eq!(again["activity"], "Opened FAKE0001");
    // A follow-up updates the chip; the filter and the count follow.
    let f = step("filter");
    assert_eq!(f["chip"], "FAKE0001 · Closed", "{said:?}");
    assert_eq!(f["shown"], true);
    assert_eq!(f["yes"], 1, "{said:?}");
    assert_eq!(
        f["no"].as_u64().unwrap() + 1,
        f["all"].as_u64().unwrap(),
        "{said:?}"
    );
    assert_eq!(f["overview"], "1 finding has a record");
    // Closed with its x, the dialog leaves no wait bar.
    let c = step("closed");
    assert_eq!(c["open"], false, "{said:?}");
    assert_eq!(c["bar"], false, "{said:?}");
}
