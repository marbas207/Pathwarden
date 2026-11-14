//! End-to-end smoke test of the desktop window (`pathwarden ui --window`):
//! starts the real program with its window hidden, drives the page through
//! WebView2's remote debugging (DevTools protocol), and checks that it
//! loads Home, runs the demo, opens the report and stops from Stop
//! Pathwarden, and that pathwarden.exe never listens on a TCP port.
//!
//! Windows, debug builds with the `desktop` feature only: remote debugging
//! and the hidden window are honored by debug builds alone (see
//! `pathwarden_desktop::TEST_DEBUG_PORT`). It needs the WebView2 Runtime
//! and a signed-in desktop session. It starts WebView2 processes on the
//! desktop of whoever runs it, so a person runs it deliberately; it is
//! skipped unless PATHWARDEN_E2E_DESKTOP=1:
//!
//! ```text
//! $env:PATHWARDEN_E2E_DESKTOP = "1"
//! cargo test -p pathwarden --features desktop --test desktop_smoke -- --ignored --nocapture
//! ```
//!
//! The window stays hidden and no input is sent to the desktop: the page is
//! driven only through DevTools. Set PATHWARDEN_DESKTOP_SMOKE_VISIBLE=1 to
//! watch it.
#![cfg(all(windows, feature = "desktop", debug_assertions))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// The program, killed if the test fails before it stops.
struct App(Child);

impl Drop for App {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        // WebView2's own processes can hold the profile for a moment.
        for _ in 0..20 {
            if std::fs::remove_dir_all(&self.0).is_ok() || !self.0.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

/// A free loopback port for remote debugging (never 8765, which people
/// keep for a running Pathwarden).
fn free_port() -> u16 {
    loop {
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("a free port")
            .port();
        if port != 8765 {
            return port;
        }
    }
}

/// `GET path` on the DevTools HTTP endpoint: the body.
fn http_get(port: u16, path: &str) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    // The endpoint may keep the connection open: read what Content-Length says.
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = s.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&raw);
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let len = head.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())?
            });
            if len.is_some_and(|len| body.len() >= len) {
                return Some(body.to_string());
            }
        }
    }
    let text = String::from_utf8_lossy(&raw);
    text.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
}

/// TCP ports `pid` listens on, from netstat (IPv4 and IPv6).
fn listening(pid: u32) -> Vec<String> {
    let out = Command::new("netstat")
        .args(["-ano"])
        .output()
        .expect("running netstat");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            cols.first() == Some(&"TCP")
                && cols.get(3) == Some(&"LISTENING")
                && cols.get(4) == Some(&pid.to_string().as_str())
        })
        .map(str::to_string)
        .collect()
}

/// A minimal WebSocket client for the DevTools protocol: text frames only,
/// masked as a client must.
struct DevTools {
    s: TcpStream,
    next: u64,
}

impl DevTools {
    fn connect(url: &str) -> DevTools {
        let rest = url.strip_prefix("ws://").expect("a ws:// URL");
        let (host, path) = rest.split_once('/').expect("a path");
        let mut s = TcpStream::connect(host).expect("connecting to DevTools");
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        write!(
            s,
            "GET /{path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).expect("reading the handshake");
            head.push(b[0]);
        }
        let head = String::from_utf8_lossy(&head);
        assert!(head.starts_with("HTTP/1.1 101"), "handshake: {head}");
        DevTools { s, next: 1 }
    }

    fn send(&mut self, text: &str) {
        let data = text.as_bytes();
        let mut frame = vec![0x81u8];
        match data.len() {
            n if n < 126 => frame.push(0x80 | n as u8),
            n if n < 65536 => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        let mask = [0x1f, 0x2e, 0x3d, 0x4c];
        frame.extend_from_slice(&mask);
        frame.extend(data.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.s.write_all(&frame).expect("sending to DevTools");
    }

    /// The next whole text message.
    fn recv(&mut self) -> String {
        let mut message = Vec::new();
        loop {
            let mut h = [0u8; 2];
            self.s.read_exact(&mut h).expect("reading from DevTools");
            let (fin, opcode) = (h[0] & 0x80 != 0, h[0] & 0x0f);
            let len = match h[1] & 0x7f {
                126 => {
                    let mut l = [0u8; 2];
                    self.s.read_exact(&mut l).unwrap();
                    u64::from(u16::from_be_bytes(l))
                }
                127 => {
                    let mut l = [0u8; 8];
                    self.s.read_exact(&mut l).unwrap();
                    u64::from_be_bytes(l)
                }
                n => u64::from(n),
            };
            let mut payload = vec![0u8; len as usize];
            self.s.read_exact(&mut payload).unwrap();
            match opcode {
                0x8 => panic!("DevTools closed the connection"),
                0x9 | 0xA => continue, // ping, pong
                _ => message.extend_from_slice(&payload),
            }
            if fin {
                return String::from_utf8(message).expect("a text message");
            }
        }
    }

    /// One DevTools command and its result (events in between are skipped).
    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.send(&json!({ "id": id, "method": method, "params": params }).to_string());
        loop {
            let v: Value = serde_json::from_str(&self.recv()).expect("JSON from DevTools");
            if v["id"] == id {
                assert!(v.get("error").is_none(), "{method}: {v}");
                return v["result"].clone();
            }
        }
    }

    /// Evaluates `expr` in the page (awaiting a promise) and returns its value.
    fn eval(&mut self, expr: &str) -> Value {
        let r = self.call(
            "Runtime.evaluate",
            json!({ "expression": expr, "returnByValue": true, "awaitPromise": true }),
        );
        r["result"]["value"].clone()
    }

    /// Waits until `expr` is true in the page.
    fn wait_for(&mut self, expr: &str, within: Duration) {
        let start = Instant::now();
        loop {
            if self.eval(&format!(
                "(function () {{ try {{ return !!({expr}); }} catch (e) {{ return false; }} }})()"
            )) == json!(true)
            {
                return;
            }
            let at = self.eval("location.href");
            assert!(
                start.elapsed() < within,
                "timed out waiting for {expr} (at {at})"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

#[test]
#[ignore = "starts WebView2; a person runs it with PATHWARDEN_E2E_DESKTOP=1 and --ignored"]
fn window_runs_the_demo_without_a_port() {
    if std::env::var_os("PATHWARDEN_E2E_DESKTOP").is_none_or(|v| v != "1") {
        eprintln!("skipped: set PATHWARDEN_E2E_DESKTOP=1 to run the desktop smoke test");
        return;
    }
    let workspace =
        Dir(std::env::temp_dir().join(format!("pathwarden-desktop-smoke-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&workspace.0);
    let port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pathwarden"));
    cmd.args(["ui", "--window", "--workspace"])
        .arg(&workspace.0)
        .env(pathwarden_desktop::TEST_DEBUG_PORT, port.to_string())
        .env_remove("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
    if std::env::var_os("PATHWARDEN_DESKTOP_SMOKE_VISIBLE").is_none() {
        cmd.env(pathwarden_desktop::TEST_HIDDEN, "1");
    }
    let mut app = App(cmd.spawn().expect("starting pathwarden ui --window"));
    let pid = app.0.id();

    // The window's page, once WebView2 is up.
    let start = Instant::now();
    let ws_url = loop {
        if let Some(status) = app.0.try_wait().unwrap() {
            panic!("pathwarden exited early ({status})");
        }
        let targets: Value = http_get(port, "/json/list")
            .and_then(|b| serde_json::from_str(&b).ok())
            .unwrap_or(Value::Null);
        let page = targets.as_array().and_then(|t| {
            t.iter().find(|t| {
                t["type"] == "page"
                    && t["url"]
                        .as_str()
                        .is_some_and(|u| u.starts_with("https://pathwarden.localhost/"))
            })
        });
        if let Some(url) = page.and_then(|p| p["webSocketDebuggerUrl"].as_str()) {
            break url.to_string();
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the window's page never came up (is the WebView2 Runtime installed?)"
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    let mut page = DevTools::connect(&ws_url);
    let long = Duration::from_secs(60);

    // Home.
    page.wait_for(
        "document.readyState === 'complete' && document.querySelector('[data-demo]')",
        long,
    );
    assert_eq!(
        page.eval("location.origin"),
        json!("https://pathwarden.localhost")
    );
    assert!(
        listening(pid).is_empty(),
        "pathwarden.exe listens: {:?}",
        listening(pid)
    );

    // The demo, as a click on Try the demo: Analyze, then the run.
    page.eval("document.querySelector('[data-demo]').click()");
    page.wait_for(
        "/^\\/runs\\/[^/]+$/.test(location.pathname) && document.readyState === 'complete'",
        Duration::from_secs(600),
    );
    let run = page.eval("location.pathname");
    let run = run.as_str().unwrap().to_string();

    // The report, opened in the window.
    page.eval(&format!("location.href = '{run}/report'"));
    page.wait_for(
        &format!(
            "location.pathname === '{run}/report' && document.readyState === 'complete' \
             && document.body.innerText.includes('Tier Zero')"
        ),
        long,
    );
    assert!(
        listening(pid).is_empty(),
        "pathwarden.exe listens: {:?}",
        listening(pid)
    );

    // Stop Pathwarden: the form posts with the window's Origin (the
    // same-origin referrer policy), and the program exits.
    page.eval("location.href = '/'");
    page.wait_for(
        "location.pathname === '/' && document.readyState === 'complete' && document.querySelector('form.stop-form')",
        long,
    );
    page.eval("document.querySelector('form.stop-form').submit()");
    let start = Instant::now();
    let status = loop {
        if let Some(status) = app.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "Stop Pathwarden didn't stop the program"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(status.success(), "pathwarden exited with {status}");
}
