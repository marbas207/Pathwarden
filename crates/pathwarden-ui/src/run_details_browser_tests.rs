//! The Run details tab's check in a real browser: a report from a shared
//! history whose own styles hide or cover the tab or its Remove makes the
//! app's script in the frame say so (`shown: false`), and a normal report
//! says `shown: true`. Headless Edge or Chrome (`PATHWARDEN_TEST_BROWSER`
//! names one), skipped with a note when there is none. The pages are
//! served by a small server on 127.0.0.1 so the frame's messages reach
//! the page around it, as in the app.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

use super::*;

/// Headless Edge or Chrome: `PATHWARDEN_TEST_BROWSER`, else where they
/// are usually installed.
pub(crate) fn browser() -> Option<PathBuf> {
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

/// The cases: a name, the report's own extra styles, and whether the
/// frame opens on the Run details tab.
const CASES: &[(&str, &str, bool)] = &[
    ("normal", "", false),
    ("normal-open", "", true),
    (
        "tab-off-screen",
        "#tab-details{position:fixed!important;left:-999px!important}",
        false,
    ),
    ("panel-hidden", "#details{display:none!important}", true),
    ("remove-hidden", "#details .rd-remove{display:none!important}", true),
    (
        "tab-covered",
        "body::after{content:\"\";position:fixed;inset:0;background:var(--bg,#fff);pointer-events:none;z-index:99}",
        false,
    ),
    (
        "remove-covered",
        ".pw-cover{position:fixed;inset:0;background:#fff;pointer-events:none;z-index:99}",
        true,
    ),
    ("tab-see-through", "#tab-details .tl{color:transparent!important}", false),
    ("tab-tiny-text", "#tab-details .tl{font-size:0!important}", false),
];

#[test]
fn a_report_that_hides_run_details_is_caught() {
    let Some(exe) = browser() else {
        eprintln!("no Edge or Chrome found: the Run details browser test was skipped");
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let origin = format!("http://127.0.0.1:{port}");
    let nonce = new_nonce();
    let r = {
        let mut r = point_for_browser();
        r.id = "20261027-120000-abcdef".into();
        r
    };
    let panel = panel_html(
        &r,
        None,
        &Ok(String::new()),
        Remove::FromHistory,
        &nonce,
        None,
    );
    let base = crate::run_list::report_as_now(
        include_str!("../tests/data/old-reports/sample-report-0.1.6.html").to_string(),
        None,
    );
    let meta = format!(
        r#"<meta name="pathwarden-retest" content="{}">"#,
        crate::pages::attr(&serde_json::json!({"origin": origin, "f": {}}).to_string())
    );
    let report = |extra: &str| -> String {
        let style = format!("{CSS}{}<style>{extra}</style>", crate::server::EMBED_STYLE);
        let (page, _) = crate::retest_ui::embed_report(&base, &meta, &style, false);
        let mut out = inject(&page, &panel, false, &nonce);
        if extra.contains("pw-cover") {
            out = out.replacen("</body>", r#"<div class="pw-cover"></div></body>"#, 1);
        }
        out
    };
    let mut frames = String::new();
    for (i, (name, _, open)) in CASES.iter().enumerate() {
        frames.push_str(&format!(
            r#"<iframe data-case="{name}" sandbox="allow-scripts" style="width:1400px;height:1600px;display:block" src="/r/{i}?embed=1&rd={nonce}{hash}"></iframe>"#,
            hash = if *open { "#details" } else { "" }
        ));
    }
    let parent = format!(
        r#"<!doctype html><html><body><pre id="out">{{}}</pre>{frames}<script>
var seen = {{}};
window.addEventListener("message", function (e) {{
  var m = e.data;
  if (!m || m.type !== "pathwarden:run-details") return;
  document.querySelectorAll("iframe").forEach(function (f) {{
    if (f.contentWindow === e.source) {{
      var k = f.getAttribute("data-case");
      // Once false, false (as the run page keeps it).
      seen[k] = seen[k] === false ? false : m.shown === true && m.nonce === "{nonce}";
    }}
  }});
  document.getElementById("out").textContent = JSON.stringify(seen);
}});
</script><link rel="stylesheet" href="/slow"></body></html>"#
    );
    let pages: Vec<String> = CASES.iter().map(|(_, extra, _)| report(extra)).collect();
    // One thread per request: /slow holds the page's load event (and so
    // --dump-dom) until the frames have checked and said.
    let pages = std::sync::Arc::new(pages);
    let parent = std::sync::Arc::new(parent);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let (pages, parent) = (pages.clone(), parent.clone());
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (kind, body) = if path.starts_with("/slow") {
                    std::thread::sleep(std::time::Duration::from_millis(4000));
                    ("text/css", String::new())
                } else if let Some(rest) = path.strip_prefix("/r/") {
                    let i: usize = rest.split('?').next().unwrap().parse().unwrap_or(0);
                    ("text/html; charset=utf-8", pages[i].clone())
                } else {
                    ("text/html; charset=utf-8", parent.to_string())
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    let profile = std::env::temp_dir().join(format!("pw-rd-browser-{}", std::process::id()));
    let out = pathwarden_core::spawn::quiet(&exe)
        .args([
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--window-size=1500,1200",
            "--dump-dom",
        ])
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("{origin}/"))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&profile);
    let dom = String::from_utf8_lossy(&out.stdout);
    let json = dom
        .split(r#"<pre id="out">"#)
        .nth(1)
        .and_then(|s| s.split("</pre>").next())
        .unwrap_or("{}")
        .replace("&quot;", "\"");
    let got: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
    for (name, _, _) in CASES {
        let want = name.starts_with("normal");
        assert_eq!(
            got.get(*name).and_then(|v| v.as_bool()),
            Some(want),
            "{name}: {got}\n{dom:.600}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A run loaded from the history, as a summary.
fn point_for_browser() -> crate::workspace::RunSummary {
    let p: pathwarden_core::state::HistoryPoint = serde_json::from_value(serde_json::json!({
        "version": 1, "run_id": "r1", "at": 1, "collected_at": null,
        "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": 1,
        "tier_zero_population": 100, "tier_zero_objects": 1,
        "protection_score": null,
        "findings": {"attack_path": 0, "hygiene": 0, "suppressed": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "changes": {"new": 0, "open": 0, "regressed": 0, "suppressed": 0,
            "resolved": 0},
        "recorded_by": "cli",
    }))
    .unwrap();
    crate::history_ui::point_summary(&p, &[])
}
