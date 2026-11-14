//! Driving an external collector: SharpHound or a `rusthound-ce` executable.
//!
//! Secrets are never put on a command line (any local user can read another
//! process's arguments), so SharpHound runs as the current identity and
//! RustHound-CE with a Kerberos ticket cache.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use crate::output::{self, Snapshot};
use crate::{markers, Auth, Cancelled, CollectRequest, ExternalKind, Outcome, Reporter, Scope};

/// How often SharpHound prints "Status: N objects finished" (ms). Its
/// default, 30 s, is too coarse for a live percentage.
const SHARPHOUND_STATUS_MS: &str = "5000";

/// A command line to run: arguments plus extra environment variables.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Invocation {
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub warnings: Vec<String>,
}

/// Arguments for SharpHound (v2, BloodHound CE).
pub(crate) fn sharphound_invocation(req: &CollectRequest) -> anyhow::Result<Invocation> {
    match &req.auth {
        Auth::CurrentUser => {}
        Auth::Password { .. } => anyhow::bail!(
            "SharpHound takes a password only on its command line, where other users on this \
             host can read it. Run Pathwarden as the collection account instead (scheduled \
             task or gMSA, or `runas /netonly /user:DOMAIN\\user`), or use the built-in collector"
        ),
        Auth::KerberosCache { .. } => anyhow::bail!(
            "SharpHound uses the current Windows logon; a Kerberos ticket cache is for RustHound-CE"
        ),
    }
    let mut inv = Invocation::default();
    let methods = match req.scope {
        Scope::DcOnly => "DCOnly",
        Scope::All | Scope::Default => "All",
    };
    let mut push = |a: &str| inv.args.push(a.into());
    push("--collectionmethods");
    push(methods);
    push("--statusinterval");
    push(SHARPHOUND_STATUS_MS);
    push("--domain");
    push(req.domain.trim());
    if let Some(server) = &req.server {
        push("--domaincontroller");
        push(server);
    }
    if req.ldaps {
        push("--secureldap");
        if req.insecure_skip_tls_verify {
            push("--disablecertverification");
        }
    }
    inv.args.push("--outputdirectory".into());
    inv.args.push(req.output_dir.as_os_str().to_owned());
    if req.insecure_skip_tls_verify {
        inv.warnings.push(
            "LDAPS certificates were not checked, so a machine in the middle could read or \
             change the collection."
                .into(),
        );
    }
    Ok(inv)
}

/// Arguments for a `rusthound-ce` executable.
pub(crate) fn rusthound_invocation(req: &CollectRequest) -> anyhow::Result<Invocation> {
    let mut inv = Invocation::default();
    match &req.auth {
        Auth::KerberosCache { ccache } => {
            if req.server.is_none() {
                anyhow::bail!(
                    "Kerberos needs the domain controller's FQDN: pass --server dc01.contoso.local"
                );
            }
            inv.args.push("-k".into());
            if let Some(path) = ccache {
                inv.env
                    .push(("KRB5CCNAME".into(), path.as_os_str().to_owned()));
            }
        }
        Auth::Password { .. } => anyhow::bail!(
            "rusthound-ce takes a password only on its command line (-p), where other users on \
             this host can read it in the process list. Use the built-in collector (same \
             RustHound-CE code, password kept in memory) or a Kerberos ticket cache (--kerberos)"
        ),
        Auth::CurrentUser => anyhow::bail!(
            "rusthound-ce cannot authenticate as the current Windows user; use the built-in \
             collector, SharpHound, or a Kerberos ticket cache (--kerberos)"
        ),
    }
    let method = match req.scope {
        Scope::DcOnly => "DCOnly",
        Scope::All | Scope::Default => "All",
    };
    let mut push = |a: &str| inv.args.push(a.into());
    push("-d");
    push(req.domain.trim());
    if let Some(server) = &req.server {
        push("-f");
        push(server);
    }
    if req.ldaps {
        push("--ldaps");
    }
    push("-c");
    push(method);
    push("-z");
    inv.args.push("-o".into());
    inv.args.push(req.output_dir.as_os_str().to_owned());
    if req.ldaps {
        inv.warnings.push(
            "RustHound-CE does not check LDAPS certificates; the built-in collector does.".into(),
        );
    }
    Ok(inv)
}

/// Runs the external collector and returns the files it produced.
pub(crate) fn run(
    req: &CollectRequest,
    program: &Path,
    kind: ExternalKind,
    rep: &mut Reporter,
    cancel: &AtomicBool,
) -> anyhow::Result<Outcome> {
    if kind == ExternalKind::SharpHound && !cfg!(windows) {
        anyhow::bail!(
            "SharpHound runs on Windows only; use the built-in collector or rusthound-ce"
        );
    }
    let inv = match kind {
        ExternalKind::SharpHound => sharphound_invocation(req)?,
        ExternalKind::RustHound => rusthound_invocation(req)?,
    };
    let name = match kind {
        ExternalKind::SharpHound => "SharpHound",
        ExternalKind::RustHound => "RustHound-CE",
    };
    let before = Snapshot::take(&req.output_dir);
    rep.log(format!("Running {}", program.display()));
    // SharpHound only says how many objects it has done: count the domain
    // alongside it (cheap LDAP counts) for a percentage and an ETA.
    let estimate = start_estimate(req, kind);
    let mut expected: Option<u64> = req.expected_objects;

    let mut cmd = pathwarden_core::spawn::quiet(program);
    cmd.args(&inv.args)
        .envs(inv.env.iter().map(|(k, v)| (k, v)));
    without_secrets(&mut cmd)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("cannot start {}: {e}", program.display()))?;
    // Its hidden console doesn't get Ctrl+C from Pathwarden's: it is
    // stopped with Pathwarden instead (a Job Object on Windows), never left
    // enumerating the domain on its own.
    let contained = pathwarden_core::spawn::contain(&child);

    let (tx, rx) = mpsc::channel::<String>();
    let mut readers = Vec::new();
    if let Some(out) = child.stdout.take() {
        readers.push(spawn_reader(out, tx.clone()));
    }
    if let Some(err) = child.stderr.take() {
        readers.push(spawn_reader(err, tx.clone()));
    }
    drop(tx);

    let mut tail: Vec<String> = Vec::new();
    let started = std::time::Instant::now();
    let status = loop {
        if cancel.load(Ordering::Relaxed) {
            contained.kill();
            let _ = child.kill();
            let _ = child.wait();
            output::remove_new_outputs(&req.output_dir, &before);
            return Err(Cancelled.into());
        }
        if let Some(est) = estimate.as_ref().and_then(|r| r.try_recv().ok()) {
            expected = est.total.or(expected);
            rep.with(|t| {
                for (k, n) in &est.by_kind {
                    t.expect(k, *n);
                }
            });
        }
        if let (Some(n), "enumerate") = (expected, rep.current()) {
            rep.with(|t| t.expect_units(n));
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                tail.push(line.clone());
                if tail.len() > 20 {
                    tail.remove(0);
                }
                let marker = match kind {
                    ExternalKind::SharpHound => markers::sharphound(&line),
                    ExternalKind::RustHound => markers::rusthound(&line),
                };
                if let Some(m) = marker {
                    rep.marker(m);
                }
                rep.log(line);
                rep.tick();
                continue;
            }
            Err(mpsc::RecvTimeoutError::Timeout) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
        }
        rep.tick();
        if let Some(status) = child.try_wait()? {
            break status;
        }
    };
    for r in readers {
        let _ = r.join();
    }
    while let Ok(line) = rx.try_recv() {
        rep.log(line);
    }
    if !status.success() {
        output::remove_new_outputs(&req.output_dir, &before);
        anyhow::bail!(
            "{name} exited with {status}. Last output:\n{}",
            tail.join("\n")
        );
    }
    let files = output::discover_outputs(&req.output_dir, &before);
    let mut warnings = inv.warnings;
    if req.scope == Scope::DcOnly {
        warnings.push(no_sessions_warning());
    }
    // An external collector says nothing of its steps: its whole run.
    let ms = started.elapsed().as_millis() as u64;
    let timings = pathwarden_core::diagnostics::CollectionTimings {
        version: pathwarden_core::diagnostics::TIMINGS_VERSION,
        collector: name.to_string(),
        total_ms: ms,
        phases: vec![pathwarden_core::diagnostics::PhaseTime {
            name: "collector".into(),
            ms,
        }],
        ..Default::default()
    };
    Ok(Outcome {
        files,
        warnings,
        timings: Some(timings),
        signed_in_as: None,
        read_started: None,
    })
}

/// What a cheap count says the collector will process.
#[derive(Debug, Default)]
pub(crate) struct Estimate {
    /// Objects in all, when every count finished.
    pub total: Option<u64>,
    pub by_kind: Vec<(&'static str, u64)>,
}

/// Counts the domain on a background thread while SharpHound runs (built-in
/// LDAP, current Windows user). `None` when that isn't possible.
fn start_estimate(req: &CollectRequest, kind: ExternalKind) -> Option<mpsc::Receiver<Estimate>> {
    if kind != ExternalKind::SharpHound || !matches!(req.auth, Auth::CurrentUser) {
        return None;
    }
    estimate_thread(req)
}

#[cfg(all(feature = "builtin", windows))]
fn estimate_thread(req: &CollectRequest) -> Option<mpsc::Receiver<Estimate>> {
    let (tx, rx) = mpsc::channel();
    let mut sizing = CollectRequest::new(req.domain.clone(), req.output_dir.clone());
    sizing.server = req.server.clone();
    sizing.ldaps = req.ldaps;
    sizing.insecure_skip_tls_verify = req.insecure_skip_tls_verify;
    std::thread::Builder::new()
        .name("pathwarden-estimate".into())
        .spawn(move || {
            if let Some(est) = crate::builtin::estimate(&sizing) {
                let _ = tx.send(est);
            }
        })
        .ok()?;
    Some(rx)
}

#[cfg(not(all(feature = "builtin", windows)))]
fn estimate_thread(_req: &CollectRequest) -> Option<mpsc::Receiver<Estimate>> {
    None
}

pub(crate) fn no_sessions_warning() -> String {
    crate::NO_SESSIONS_NOTE.into()
}

fn spawn_reader(
    stream: impl Read + Send + 'static,
    tx: mpsc::Sender<String>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line = strip_ansi(String::from_utf8_lossy(&buf).trim_end());
                    // Also kept for error messages: no password material.
                    let line = crate::redact::log_line(&line).into_owned();
                    if !line.trim().is_empty() && tx.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// `cmd` without the variables an external collector never gets, even
/// when Pathwarden has them: the collection password, the history's
/// passphrases and the evidence signing key
/// ([`pathwarden_core::keystore::SECRET_ENV`]).
pub(crate) fn without_secrets(cmd: &mut std::process::Command) -> &mut std::process::Command {
    pathwarden_core::keystore::scrub_env(cmd)
}

/// Removes ANSI escape sequences (colors, cursor moves) from a line.
pub(crate) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                // CSI: parameters, then one final byte in @..~
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            } else {
                chars.next();
            }
            continue;
        }
        if c == '\r' {
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use crate::Progress;
    use crate::{Method, Secret};
    use pathwarden_core::keystore::SECRET_ENV;
    use std::path::PathBuf;

    fn req(auth: Auth) -> CollectRequest {
        let mut r = CollectRequest::new("contoso.local", PathBuf::from("out dir"));
        r.auth = auth;
        r.method = Method::External {
            program: PathBuf::from("x"),
            kind: ExternalKind::SharpHound,
        };
        r
    }

    fn args(inv: &Invocation) -> Vec<String> {
        inv.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn sharphound_args() {
        let mut r = req(Auth::CurrentUser);
        r.server = Some("dc01.contoso.local".into());
        r.ldaps = true;
        let inv = sharphound_invocation(&r).unwrap();
        assert_eq!(
            args(&inv),
            [
                "--collectionmethods",
                "All",
                "--statusinterval",
                "5000",
                "--domain",
                "contoso.local",
                "--domaincontroller",
                "dc01.contoso.local",
                "--secureldap",
                "--outputdirectory",
                "out dir",
            ]
        );
        assert!(inv.env.is_empty());
        r.scope = Scope::DcOnly;
        assert_eq!(args(&sharphound_invocation(&r).unwrap())[1], "DCOnly");
    }

    #[test]
    fn sharphound_never_takes_a_password() {
        let r = req(Auth::Password {
            user: "svc-collect".into(),
            password: Secret::new("Pa55word!xyz"),
        });
        let err = sharphound_invocation(&r).unwrap_err().to_string();
        assert!(!err.contains("Pa55word!xyz"));
        assert!(err.contains("command line"));
    }

    #[test]
    fn rusthound_args_use_a_ticket_cache() {
        let mut r = req(Auth::KerberosCache {
            ccache: Some(PathBuf::from("/tmp/krb5cc_svc")),
        });
        r.server = Some("dc01.contoso.local".into());
        r.ldaps = true;
        let inv = rusthound_invocation(&r).unwrap();
        assert_eq!(
            args(&inv),
            [
                "-k",
                "-d",
                "contoso.local",
                "-f",
                "dc01.contoso.local",
                "--ldaps",
                "-c",
                "All",
                "-z",
                "-o",
                "out dir",
            ]
        );
        assert_eq!(
            inv.env,
            vec![(
                OsString::from("KRB5CCNAME"),
                OsString::from("/tmp/krb5cc_svc")
            )]
        );
        assert!(!inv.warnings.is_empty(), "warns about LDAPS validation");
    }

    #[test]
    fn rusthound_refuses_password_on_argv() {
        let mut r = req(Auth::Password {
            user: "svc-collect".into(),
            password: Secret::new("Pa55word!xyz"),
        });
        r.server = Some("dc01.contoso.local".into());
        let err = rusthound_invocation(&r).unwrap_err().to_string();
        assert!(!err.contains("Pa55word!xyz"));
        assert!(err.contains("process list"));
        assert!(rusthound_invocation(&req(Auth::CurrentUser)).is_err());
    }

    #[test]
    fn no_argument_ever_holds_the_secret() {
        // Every auth/flag combination: whatever is built, the secret is absent.
        for kind in [ExternalKind::SharpHound, ExternalKind::RustHound] {
            for ldaps in [false, true] {
                let mut r = req(Auth::Password {
                    user: "svc".into(),
                    password: Secret::new("NeverOnArgv-42"),
                });
                r.ldaps = ldaps;
                r.server = Some("dc01.contoso.local".into());
                let built = match kind {
                    ExternalKind::SharpHound => sharphound_invocation(&r),
                    ExternalKind::RustHound => rusthound_invocation(&r),
                };
                if let Ok(inv) = built {
                    let all = format!("{:?}", inv);
                    assert!(!all.contains("NeverOnArgv-42"));
                }
            }
        }
    }

    /// An external collector never gets the collection password or the
    /// history's passphrases from Pathwarden's environment; what its
    /// invocation sets (the ticket cache) still reaches it.
    #[test]
    fn collectors_never_get_the_secrets() {
        let probe = SECRET_ENV
            .iter()
            .chain(["KRB5CCNAME"].iter())
            .map(|v| {
                if cfg!(windows) {
                    format!("if defined {v} (echo has {v}) else (echo no {v})")
                } else {
                    format!("if [ -n \"${{{v}+x}}\" ]; then echo has {v}; else echo no {v}; fi")
                }
            })
            .collect::<Vec<_>>()
            .join(if cfg!(windows) { " & " } else { "; " });
        #[cfg(windows)]
        let mut cmd = {
            use std::os::windows::process::CommandExt;
            let mut c = pathwarden_core::spawn::quiet("cmd");
            c.args(["/d", "/c"]).raw_arg(&probe);
            c
        };
        #[cfg(not(windows))]
        let mut cmd = {
            let mut c = pathwarden_core::spawn::quiet("sh");
            c.args(["-c", &probe]);
            c
        };
        for var in SECRET_ENV {
            cmd.env(var, "Leaked-Secret-91");
        }
        cmd.env("KRB5CCNAME", "/tmp/krb5cc_svc");
        let out = without_secrets(&mut cmd).output().unwrap();
        let said = String::from_utf8_lossy(&out.stdout);
        for var in SECRET_ENV {
            assert!(said.contains(&format!("no {var}")), "{var}: {said}");
        }
        assert!(said.contains("has KRB5CCNAME"), "{said}");
        assert!(!said.contains("Leaked-Secret-91"));
    }

    #[test]
    fn strips_colors() {
        assert_eq!(
            strip_ansi("\u{1b}[1;32mCONTOSO\u{1b}[0m done\r"),
            "CONTOSO done"
        );
    }

    #[cfg(windows)]
    #[test]
    fn cancel_kills_the_program() {
        use std::time::{Duration, Instant};
        let dir = std::env::temp_dir().join(format!("pw-ext-cancel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("slow.cmd");
        std::fs::write(
            &script,
            "@echo off\r\necho started\r\nping -n 30 127.0.0.1 >nul\r\n",
        )
        .unwrap();
        let mut r = CollectRequest::new("contoso.local", dir.join("out"));
        r.auth = Auth::KerberosCache { ccache: None };
        r.server = Some("dc01.contoso.local".into());
        std::fs::create_dir_all(&r.output_dir).unwrap();
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let result = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(500));
                cancel.store(true, Ordering::SeqCst);
            });
            let mut sink = |_| {};
            let mut rep = Reporter::new(crate::steps_for(&r), &mut sink);
            run(&r, &script, ExternalKind::RustHound, &mut rep, &cancel)
        });
        assert!(result.unwrap_err().is::<Cancelled>());
        assert!(started.elapsed() < Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stand-in SharpHound printing its progress lines: the collection
    /// goes through SharpHound's steps, counts its objects against the
    /// expected total, and finishes at 100%.
    #[cfg(windows)]
    #[test]
    fn follows_sharphound_progress() {
        let dir = std::env::temp_dir().join(format!("pw-ext-sh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let script = dir.join("SharpHound.cmd");
        let lines = [
            "@echo off",
            // Writes where it is told (Pathwarden may collect into a private
            // folder inside --out when others can open --out).
            ":args",
            r#"if "%~1"=="" goto run"#,
            r#"if "%~1"=="--outputdirectory" set "OUT=%~2""#,
            "shift",
            "goto args",
            ":run",
            "echo 2024-04-10T05:04:34.7-07:00^|INFORMATION^|Initializing SharpHound at 5:04 AM",
            "echo 2024-04-10T05:04:35.2-07:00^|INFORMATION^|Beginning LDAP search for example.invalid",
            "echo 2024-04-10T05:05:05.4-07:00^|INFORMATION^|Status: 1200 objects finished (+1200 240)/s -- Using 41 MB RAM",
            "ping -n 2 127.0.0.1 >nul",
            "echo 2024-04-10T05:05:20.8-07:00^|INFORMATION^|Consumers finished, closing output channel",
            r#"echo {} > "%OUT%\20261009120000_BloodHound.zip""#,
            "echo 2024-04-10T05:05:21.1-07:00^|INFORMATION^|SharpHound Enumeration Completed at 5:05 AM! Happy Graphing!",
        ];
        std::fs::write(&script, lines.join("\r\n") + "\r\n").unwrap();
        let mut r = CollectRequest::new("example.invalid", &out);
        r.method = Method::External {
            program: script.clone(),
            kind: ExternalKind::SharpHound,
        };
        r.expected_objects = Some(2400);
        let mut seen = Vec::new();
        // Users can read the output folder: the files still end up private.
        let granted = pathwarden_core::spawn::quiet("icacls")
            .arg(&out)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)R"])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(granted);
        let cancel = AtomicBool::new(false);
        let outcome = crate::collect(&r, &mut |p| seen.push(p), &cancel).unwrap();
        let zip = out.join("20261009120000_BloodHound.zip");
        assert_eq!(outcome.files, vec![zip.clone()]);
        assert!(pathwarden_core::perms::others_with_access(&zip).is_empty());
        assert!(
            outcome.warnings.iter().any(|w| w.contains("can read")),
            "{:?}",
            outcome.warnings
        );
        // The private folder it collected into is gone.
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);
        let statuses: Vec<&crate::Status> = seen
            .iter()
            .filter_map(|p| match p {
                Progress::Status(s) => Some(&**s),
                _ => None,
            })
            .collect();
        let keys: Vec<&str> = statuses.iter().map(|s| s.key.as_str()).collect();
        assert!(
            keys.contains(&"enumerate") && keys.contains(&"write"),
            "{keys:?}"
        );
        let half = statuses
            .iter()
            .find(|s| s.key == "enumerate" && s.done == 1200)
            .expect("counted SharpHound's objects");
        assert_eq!(half.total, Some(2400));
        assert_eq!(half.step_percent, Some(50.0));
        let last = statuses.last().unwrap();
        assert!(last.finished && last.percent == 100.0);
        assert!(seen.contains(&Progress::Phase("Collecting objects".into())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn runs_a_program_and_finds_its_zip() {
        // A stand-in collector: a batch file that writes a zip-named file.
        let dir = std::env::temp_dir().join(format!("pw-ext-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let script = dir.join("fake-rusthound.cmd");
        std::fs::write(
            &script,
            // args: -k -d contoso.local -f dc -c All -z -o <dir>; the dir is %10.
            "@echo off\r\necho collecting %3\r\nshift\r\necho {} > \"%~f9\\20261009120000_contoso.local_rusthound-ce.zip\"\r\n",
        )
        .unwrap();
        let mut r = CollectRequest::new("contoso.local", &out);
        r.auth = Auth::KerberosCache { ccache: None };
        r.server = Some("dc01.contoso.local".into());
        let mut logs = Vec::new();
        let cancel = AtomicBool::new(false);
        let mut sink = |p| logs.push(p);
        let mut rep = Reporter::new(crate::steps_for(&r), &mut sink);
        let outcome = run(&r, &script, ExternalKind::RustHound, &mut rep, &cancel).unwrap();
        drop(rep);
        assert_eq!(
            outcome.files,
            vec![out.join("20261009120000_contoso.local_rusthound-ce.zip")]
        );
        assert!(logs.contains(&Progress::Log("collecting contoso.local".into())));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
