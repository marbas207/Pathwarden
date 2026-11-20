//! The Automate area: the step from a one-off analysis to monitoring.
//!
//! - **Schedule** (`/automate/schedule`): whether a schedule is set up (the
//!   task or timer on this computer, and the scheduled runs in the history),
//!   then the generator for the nightly files, from any run of your own data
//!   ([`crate::collect`]'s `schedule.rs`).
//! - **Plugins and actions** (`/automate/ticketing`): the output plugins
//!   ([`crate::plugins_ui`]).
//! - **History storage** (`/automate/history`): where the run history is
//!   kept ([`crate::history_ui`]).
//!
//! Old addresses (`/collect/schedule`, `/plugins`) redirect here.

use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, RawQuery, State};
use axum::http::header::{self, HeaderValue};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;

use crate::collect::{self, ScheduleParams};
use crate::history_ui::{self, Snapshot, STALE_SCHEDULE_SECS};
use crate::pages::{self, esc, icon, num};
use crate::server::AppState;
use crate::workspace::RunSummary;

type Shared = Arc<AppState>;

const AUTOMATE_JS: &str = include_str!("assets/automate.js");
/// Part of `/static/app.css` (see `server`).
pub const AUTOMATE_CSS: &str = include_str!("assets/automate.css");

pub fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/automate",
            get(|| async { Redirect::to("/automate/schedule") }),
        )
        .route("/automate/schedule", get(schedule_page))
        .route("/automate/schedule/{file}", get(schedule_file))
        .route("/automate/ticketing", get(crate::plugins_ui::list_page))
        // Where these pages used to be.
        .route("/collect/schedule", get(old_schedule))
        .route("/collect/schedule/{file}", get(old_schedule_file))
        .route(
            "/plugins",
            get(|| async { Redirect::permanent("/automate/ticketing") }),
        )
        .route(
            "/static/automate.js",
            get(|| async {
                ([(header::CONTENT_TYPE, "text/javascript")], AUTOMATE_JS).into_response()
            }),
        )
}

fn with_query(path: &str, q: Option<String>) -> String {
    match q.filter(|q| !q.is_empty()) {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    }
}

async fn old_schedule(RawQuery(q): RawQuery) -> Redirect {
    Redirect::permanent(&with_query("/automate/schedule", q))
}

async fn old_schedule_file(Path(file): Path<String>, RawQuery(q): RawQuery) -> Response {
    // Only the generator's own file names (anything else is not found there
    // either), so the redirect never points somewhere odd.
    if !file
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    Redirect::permanent(&with_query(&format!("/automate/schedule/{file}"), q)).into_response()
}

// -------------------------------------------------------------- schedule

/// The run the nightly files follow: the one asked for, unless it is the
/// demo (made-up data can't be collected); else the latest of your own. A
/// run loaded from the history is never followed: its summary is the
/// repository's, and nothing in it picks where this computer signs in.
fn chosen_run<'a>(runs: &'a [RunSummary], asked: Option<&str>) -> (Option<&'a RunSummary>, bool) {
    let own = || runs.iter().find(|r| !r.demo && r.shared.is_none());
    let asked_run = asked.and_then(|id| runs.iter().find(|r| r.id == id));
    match asked_run {
        Some(r) if r.demo => (own(), true),
        Some(r) if r.shared.is_some() => (own(), false),
        Some(r) => (Some(r), false),
        None => (own(), false),
    }
}

async fn schedule_page(
    State(st): State<Shared>,
    Query(mut q): Query<ScheduleParams>,
) -> Html<String> {
    let runs = st.ws().runs();
    let (run, was_demo) = chosen_run(&runs, q.run.as_deref());
    let run = run.cloned();
    q.run = run.as_ref().map(|r| r.id.clone());
    let (target, errors) = collect::schedule_target(&q, run.as_ref(), &st.env_id());
    let ws = st.ws();
    let flag = st.state_dir();
    let linux = target.linux;
    let (task, unit) = (target.task_name(), target.unit());
    let (snap, task) = tokio::task::spawn_blocking(move || {
        (
            history_ui::snapshot(&ws, flag.as_deref()),
            detect_task(linux, &task, &unit),
        )
    })
    .await
    .unwrap_or_else(|_| {
        (
            Snapshot {
                location: Err("The history couldn't be read.".into()),
                history: Default::default(),
            },
            None,
        )
    });
    let status = status(
        &snap,
        task.as_deref(),
        &runs,
        run.as_ref(),
        was_demo,
        &target,
    );
    Html(collect::schedule_page(
        &pages::Ctx::new(&st, &runs),
        run.as_ref(),
        &target,
        &q,
        &errors,
        &status,
    ))
}

async fn schedule_file(
    State(st): State<Shared>,
    Path(file): Path<String>,
    Query(mut q): Query<ScheduleParams>,
) -> Response {
    let runs = st.ws().runs();
    let (run, _) = chosen_run(&runs, q.run.as_deref());
    q.run = run.map(|r| r.id.clone());
    let (target, errors) = collect::schedule_target(&q, run, &st.env_id());
    // Not a file built from the defaults in place of what was asked for.
    if !errors.is_empty() {
        return (StatusCode::BAD_REQUEST, errors.join(" ")).into_response();
    }
    let Some(body) = target.file(&file) else {
        return (StatusCode::NOT_FOUND, "No such file.").into_response();
    };
    let mut r = ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response();
    // `file` is one of a fixed set of names (checked by `target.file`).
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{file}\"")) {
        r.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    r
}

/// The Pathwarden task or timer on this computer, in words, if there is one.
/// The schedule usually runs on a server, so not finding one here proves
/// nothing; the history shows whether scheduled runs arrive.
fn detect_task(linux: bool, task: &str, unit: &str) -> Option<String> {
    let timer = format!("{unit}.timer");
    let (program, args): (&str, Vec<&str>) = if cfg!(windows) && !linux {
        ("schtasks", vec!["/Query", "/TN", task, "/FO", "LIST"])
    } else if cfg!(unix) && linux {
        (
            "systemctl",
            vec![
                "show",
                timer.as_str(),
                "--property=ActiveState,NextElapseUSecRealtime",
            ],
        )
    } else {
        return None;
    };
    let args = args.as_slice();
    let out = run_quietly(program, args, Duration::from_secs(5))?;
    if cfg!(windows) && !linux {
        let field = |name: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(name))
                .map(|v| v.trim().to_string())
        };
        let status = field("Status:").unwrap_or_default();
        let next = field("Next Run Time:").unwrap_or_default();
        Some(format!(
            "The scheduled task <code>{}</code> exists on this computer{}{}.",
            esc(task),
            if status.is_empty() {
                String::new()
            } else {
                format!(" ({})", esc(&status.to_lowercase()))
            },
            if next.is_empty() || next.eq_ignore_ascii_case("N/A") {
                String::new()
            } else {
                format!(", next run {}", esc(&next))
            }
        ))
    } else {
        let active = out.lines().any(|l| l.trim() == "ActiveState=active");
        active.then(|| {
            format!(
                "The systemd timer <code>{}</code> is active on this computer.",
                esc(&timer)
            )
        })
    }
}

/// A program's output, or `None` when it fails, is missing, or takes longer
/// than `limit`.
fn run_quietly(program: &str, args: &[&str], limit: Duration) -> Option<String> {
    use std::process::Stdio;
    let mut cmd = pathwarden_core::spawn::quiet(program);
    pathwarden_core::keystore::scrub_env(&mut cmd);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                use std::io::Read;
                child.stdout.take()?.read_to_string(&mut out).ok()?;
                return status.success().then_some(out);
            }
            Ok(None) if started.elapsed() < limit => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// What is scheduled already, the run picker, and what to do next.
fn status(
    snap: &Snapshot,
    task: Option<&str>,
    runs: &[RunSummary],
    run: Option<&RunSummary>,
    was_demo: bool,
    t: &collect::Target,
) -> String {
    let h = &snap.history;
    let scheduled: Vec<_> = h.scheduled().collect();
    let now = pathwarden_core::analyze::now();
    let mut b =
        String::from(r#"<section class="card setting sched-status" aria-label="Schedule status">"#);
    let mut facts = String::new();
    let local_task = task.unwrap_or("None. Expected when the schedule runs on a server.");
    let _ = write!(
        facts,
        "<div><dt>On this computer</dt><dd>{local_task}</dd></div>"
    );
    let last = scheduled.last();
    let _ = write!(
        facts,
        "<div><dt>Last scheduled run</dt><dd>{}</dd></div>",
        match last {
            Some(p) if now - p.at > STALE_SCHEDULE_SECS => format!(
                r#"<span class="sched-warn">{} {}: over a day and a half ago. Check the task on the server.</span>"#,
                icon("i-alert"),
                pages::time(p.at)
            ),
            Some(p) => format!(
                r#"{}: {} {} with an attack path to Tier Zero, {} open, {} new, {} fixed. <a href="/history/{}/performance">Collection performance</a>"#,
                pages::time(p.at),
                num(p.tier_zero_exposed),
                if p.tier_zero_exposed == 1 {
                    "account"
                } else {
                    "accounts"
                },
                num(pathwarden_core::history::open_findings(p)),
                num(pathwarden_core::history::opened(p)),
                num(p.changes.resolved),
                esc(&p.run_id),
            ),
            None => match &snap.location {
                Ok(loc) => format!(
                    "None recorded in the history in use (<code>{}</code>).",
                    esc(&crate::workspace::shown_path(&loc.dir))
                ),
                Err(_) => r#"Unknown: fix the history settings on <a href="/automate/history">History storage</a>."#.into(),
            },
        }
    );
    if let Some(first) = scheduled.first() {
        let _ = write!(
            facts,
            "<div><dt>Running since</dt><dd>{} ({} scheduled run{} recorded).</dd></div>",
            pages::time(first.at),
            num(scheduled.len()),
            if scheduled.len() == 1 { "" } else { "s" }
        );
    }
    let _ = write!(
        b,
        r#"<header><h2 class="sub">Status</h2></header><dl class="hs-facts">{facts}</dl>"#
    );

    // The run to repeat: one of this computer's own (as [`chosen_run`]).
    let own: Vec<&RunSummary> = runs
        .iter()
        .filter(|r| !r.demo && r.shared.is_none())
        .collect();
    if own.is_empty() {
        b.push_str(r#"<p class="muted small">No run of your own yet, so the files use example values.</p>"#);
    } else {
        let mut options = String::new();
        for r in own.iter().take(50) {
            let _ = write!(
                options,
                r#"<option value="{id}"{sel}>{env} · {when} · {src}</option>"#,
                id = esc(&r.id),
                sel = if run.is_some_and(|x| x.id == r.id) {
                    " selected"
                } else {
                    ""
                },
                env = esc(&r.environment()),
                when = esc(&pathwarden_core::time::format_local(r.created_at)),
                src = esc(&crate::workspace::hide_profile(&r.source)),
            );
        }
        let _ = write!(
            b,
            r#"<form class="sched-pick" method="get" action="/automate/schedule"><input type="hidden" name="os" value="{os}"><div class="field"><label for="sched-run">Based on run</label><select class="input" id="sched-run" name="run">{options}</select><p class="hint">The nightly run collects every domain this run covers.</p></div><button type="submit" class="btn">Use this run</button></form>"#,
            os = if t.linux { "linux" } else { "windows" },
        );
    }
    if was_demo {
        b.push_str(r#"<p class="muted small">The demo is made-up data, so it can't be collected on a schedule. The files below follow your latest run instead.</p>"#);
    }

    // Next steps.
    let mut steps: Vec<String> = Vec::new();
    match (&snap.location, last) {
        (Err(_), _) => steps.push(
            r#"Fix the history settings on <a href="/automate/history">History storage</a>, so scheduled runs can be shown here."#
                .into(),
        ),
        (Ok(loc), None) => {
            steps.push("Copy the files below to the server and register the task, then try it once.".into());
            steps.push(if loc.git.is_some() {
                "Copy <code>pathwarden.toml</code> to the server too, so its runs reach this history.".to_string()
            } else {
                r#"Set a shared folder or git repository on <a href="/automate/history">History storage</a>, so the server's runs reach this computer."#.to_string()
            });
        }
        (Ok(_), Some(p)) if now - p.at > STALE_SCHEDULE_SECS => {
            steps.push(if t.linux {
                format!(
                    "On the server, check the timer's last run and its log ({}).",
                    pages::repo_link("docs/running.md#linux-systemd-timer", "how")
                )
            } else {
                format!(
                    "On the server, check the task's last result and its log in <code>{}</code> ({}).",
                    esc(&t.log_dir()),
                    pages::repo_link("docs/running.md#windows-task-scheduler-with-a-gmsa", "how")
                )
            });
        }
        (Ok(_), Some(_)) => {
            steps.push(r#"Scheduled runs appear in <a href="/runs">Runs</a> and <a href="/progress">Progress</a>, next to the runs you start here."#.into());
        }
    }
    steps.push(r#"Open a ticket per finding in ServiceNow or Jira after each run: <a href="/automate/ticketing">Plugins and actions</a>."#.into());
    b.push_str(r#"<h3 class="form-title">Next steps</h3><ol class="sched-next">"#);
    for s in steps {
        let _ = write!(b, "<li>{s}</li>");
    }
    b.push_str("</ol></section>");
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_keep_the_query() {
        assert_eq!(with_query("/a", None), "/a");
        assert_eq!(with_query("/a", Some(String::new())), "/a");
        assert_eq!(with_query("/a", Some("os=linux".into())), "/a?os=linux");
    }

    #[test]
    fn a_missing_program_is_none() {
        assert!(run_quietly("pathwarden-no-such-program", &[], Duration::from_secs(1)).is_none());
    }
}
