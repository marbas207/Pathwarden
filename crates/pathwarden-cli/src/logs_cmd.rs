//! `pathwarden logs`: this computer's logs and crash reports, as the app's
//! Settings › Logs shows them ([`pathwarden_core::logs`]): the latest jobs,
//! the latest job's last lines, the latest crash report, and opening them.

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Args;
use pathwarden_core::logs::{self, By, Entry};

use crate::ui;

/// Jobs the list shows without --all (with the session logs and crash
/// reports among them).
const LISTED: usize = 6;
/// Lines of the latest job's log --last prints.
const LAST_LINES: usize = 20;

#[derive(Args)]
#[command(
    after_help = "Logs are kept 30 days, at most 200 MB in all. Passwords, tokens and cookies are never written. \
A hard crash may leave no crash report: look in Event Viewer (Windows Logs > Application) on Windows, \
the system journal elsewhere."
)]
pub(crate) struct LogsArgs {
    /// The latest job's log: its last lines.
    #[arg(long, conflicts_with = "crash")]
    last: bool,
    /// The latest crash report.
    #[arg(long)]
    crash: bool,
    /// Open it in the default app: the logs folder, or with --last or
    /// --crash that file (a text editor).
    #[arg(long)]
    open: bool,
    /// List every log, not only those of the latest 6 jobs.
    #[arg(long, conflicts_with_all = ["last", "crash", "open"])]
    all: bool,
    /// Dismiss the latest crash report (the one --crash shows), as Dismiss
    /// on the app's Settings › Logs: on this computer, the dot by Settings
    /// goes.
    #[arg(long, conflicts_with_all = ["last", "open", "all"])]
    dismiss: bool,
}

pub(crate) fn run(a: LogsArgs) -> Result<ExitCode> {
    let dir = logs::dir().context(
        "this account has no folder for logs (LOCALAPPDATA, or XDG_STATE_HOME and HOME, \
         is not set)",
    )?;
    let shown = dir.display().to_string();
    if a.dismiss {
        let Some(c) = logs::last_crash(&dir) else {
            println!("No crash reports. Logs: {shown}");
            return Ok(ExitCode::SUCCESS);
        };
        logs::dismiss(&dir, Some(&c.name)).with_context(|| format!("dismissing {}", c.name))?;
        println!("Dismissed {}.", c.name);
        return Ok(ExitCode::SUCCESS);
    }
    if a.crash {
        let Some(c) = logs::last_crash(&dir) else {
            println!("No crash reports. Logs: {shown}");
            return Ok(ExitCode::SUCCESS);
        };
        if a.open {
            return open(&c.path, &c.name);
        }
        println!(
            "{}  (Pathwarden {}, {})",
            c.name,
            ui::safe(&c.version),
            ui::safe(&c.system)
        );
        println!("{}", ui::safe(&c.sentence()));
        println!("  Message: {}", ui::safe(&c.message));
        println!("  Where:   {}", ui::safe(&c.location));
        if let Some(j) = &c.job_log {
            println!(
                "  Job log: {j} (its last {} lines are in the report)",
                logs::CRASH_TAIL
            );
        }
        println!("Full report: {}", c.path.display());
        println!("{}", hard_crash_words());
        return Ok(ExitCode::SUCCESS);
    }
    if a.last {
        let Some(e) = logs::last_job(&dir) else {
            println!("No job logs yet. Logs: {shown}");
            return Ok(ExitCode::SUCCESS);
        };
        if a.open {
            return open(&e.path, &e.name);
        }
        let by = By::from_word(&e.by).map_or("", |b| b.started());
        let mut about = vec![ui::safe(&e.title).to_string()];
        if !by.is_empty() {
            about.push(by.to_string());
        }
        if e.result != "-" {
            about.push(e.result.clone());
        }
        println!("{}  ({})", e.name, about.join(", "));
        for l in logs::tail(&e.path, LAST_LINES) {
            println!("{}", ui::safe(&l));
        }
        println!("Full log: {}", e.path.display());
        return Ok(ExitCode::SUCCESS);
    }
    if a.open {
        logs::ensure(&dir).with_context(|| format!("creating {shown}"))?;
        return open(&dir, &shown);
    }
    let all = logs::list(&dir);
    if all.is_empty() {
        println!("No logs yet. Logs: {shown}");
        return Ok(ExitCode::SUCCESS);
    }
    let bytes: u64 = all.iter().map(|e| e.bytes).sum();
    println!(
        "Logs: {shown}  ({} {}, {}; {})",
        all.len(),
        if all.len() == 1 { "file" } else { "files" },
        pathwarden_core::diagnostics::bytes(bytes),
        logs::KEPT_WORDS
    );
    println!();
    // The latest LISTED jobs, with the session logs and crash reports
    // among them.
    let rows: Vec<&Entry> = if a.all {
        all.iter().collect()
    } else {
        let mut jobs = 0;
        all.iter()
            .take_while(|e| {
                let more = jobs < LISTED;
                if !e.crash && e.kind != Some(logs::Kind::Session) {
                    jobs += 1;
                }
                more
            })
            .collect()
    };
    let job_w = rows
        .iter()
        .map(|e| e.title.chars().count())
        .max()
        .unwrap_or(0)
        .clamp(26, 44);
    let cell = |s: &str, w: usize| {
        let s: String = s.chars().take(w).collect();
        let pad = w.saturating_sub(s.chars().count());
        format!("{s}{}", " ".repeat(pad))
    };
    println!(
        "  {}  {}  {}  {}  File",
        cell("When", 16),
        cell("Job", job_w),
        cell("Started by", 14),
        cell("Result", 8)
    );
    for e in &rows {
        println!(
            "  {}  {}  {}  {}  {}",
            cell(&logs::when_words(&e.name), 16),
            cell(&ui::safe(&e.title), job_w),
            cell(&e.by, 14),
            cell(&e.result, 8),
            e.name
        );
    }
    if all.len() > rows.len() {
        println!(
            "  ... {} more. All of them: pathwarden logs --all",
            all.len() - rows.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Where a hard crash is, when no report could be written.
fn hard_crash_words() -> &'static str {
    if cfg!(windows) {
        "No crash report? A hard crash may only be in Event Viewer: Windows Logs > Application."
    } else {
        "No crash report? A hard crash may only be in the system journal (journalctl)."
    }
}

fn open(path: &std::path::Path, shown: &str) -> Result<ExitCode> {
    if pathwarden_ui::logs_ui::open_path(path) {
        println!("Opened {}.", ui::safe(shown));
        Ok(ExitCode::SUCCESS)
    } else {
        anyhow::bail!("couldn't open {}", path.display())
    }
}
