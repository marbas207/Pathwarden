//! `pathwarden-output-jira`: keeps one Jira issue per Pathwarden finding,
//! matched by fingerprint in a `pwfp-<fingerprint>` label.
//!
//! Protocol: the Pathwarden event document (`pathwarden.event.v1`) on stdin;
//! settings as JSON in `PATHWARDEN_OUTPUT_SETTINGS` or a file given with
//! `--settings`. `--dry-run` reads Jira but only prints the changes.
//!
//! Not yet validated against a live Jira (see README.md).

#![forbid(unsafe_code)]

mod api;
mod event;
mod reconcile;
mod settings;

use std::io::Read;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use api::Target;
use reconcile::Action;
use settings::Settings;

const USAGE: &str = "usage: pathwarden-output-jira [--settings FILE] [--dry-run] < event.json\n\
settings come from --settings or the PATHWARDEN_OUTPUT_SETTINGS environment variable";

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("jira: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Default)]
struct Counts {
    created: u32,
    commented: u32,
    reopened: u32,
    closed: u32,
    failed: u32,
}

impl Counts {
    fn add(&mut self, a: &Action) {
        match a {
            Action::Create { .. } => self.created += 1,
            Action::Comment { .. } => self.commented += 1,
            Action::Reopen { .. } => self.reopened += 1,
            Action::Resolve { .. } => self.closed += 1,
            Action::Info { .. } => {}
        }
    }
}

/// Returns false when some actions failed (the rest still ran).
fn run() -> Result<bool> {
    let mut settings_file = None;
    let mut dry_run = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--settings" => settings_file = Some(args.next().context("--settings needs a file")?),
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(true);
            }
            other => bail!("unknown argument {other:?}\n{USAGE}"),
        }
    }
    let raw = match settings_file {
        Some(path) => std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?,
        None => std::env::var("PATHWARDEN_OUTPUT_SETTINGS")
            .context("no settings: set PATHWARDEN_OUTPUT_SETTINGS or pass --settings FILE")?,
    };
    let mut settings = Settings::parse(&raw)?;
    settings.dry_run |= dry_run;
    let on_closed = settings.on_closed()?;

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("reading the event from stdin")?;
    let event = event::Event::parse(&input)?;

    // A dry run without credentials is an offline preview against no issues.
    let (client, issues) = match api::Client::new(&settings) {
        Ok(client) => {
            let mut issues = client.issues()?;
            // created_by defaults to the account the plugin signs in as:
            // issues anyone else created are never closed or reopened.
            if settings.created_by.is_none() {
                match client.myself() {
                    Ok(Some(me)) if settings::valid_account(&me) => {
                        let (mine, warning) = reconcile::own_issues(issues, &me);
                        issues = mine;
                        if let Some(w) = warning {
                            eprintln!("jira: warning: {w}");
                        }
                    }
                    Ok(_) => eprintln!(
                        "jira: warning: Jira didn't say which account this is, so issues are \
                         matched by their labels alone, whoever created them; set created_by \
                         to the integration account"
                    ),
                    Err(e) => eprintln!(
                        "jira: warning: could not tell which account this is ({e:#}), so issues \
                         are matched by their labels alone, whoever created them; set \
                         created_by to the integration account"
                    ),
                }
            }
            (Some(client), issues)
        }
        Err(e) if settings.dry_run => {
            println!(
                "offline preview: existing issues not read; every finding at or above \
                 min_severity would be created ({e:#})"
            );
            (None, Vec::new())
        }
        Err(e) => return Err(e),
    };
    let planned = reconcile::plan(&event, &issues, &settings, on_closed);
    let guarded = reconcile::guard(planned, &issues, &settings);
    for w in &guarded.warnings {
        eprintln!("jira: warning: {w}");
    }
    let mut counts = Counts::default();
    for action in &guarded.actions {
        if let Action::Info {
            key,
            fingerprint,
            message,
        } = action
        {
            println!("info: {key} ({fingerprint}) {message}");
            continue;
        }
        let Some(client) = client.as_ref().filter(|_| !settings.dry_run) else {
            print_dry_run(action);
            counts.add(action);
            continue;
        };
        match perform(client, &settings, action) {
            Ok(line) => {
                println!("{line}");
                counts.add(action);
            }
            Err(e) => {
                counts.failed += 1;
                eprintln!("jira: {e:#}");
            }
        }
    }
    println!(
        "jira ({}): {} created, {} commented, {} reopened, {} closed{}{}",
        settings.project,
        counts.created,
        counts.commented,
        counts.reopened,
        counts.closed,
        if counts.failed > 0 {
            format!(", {} failed", counts.failed)
        } else {
            String::new()
        },
        if settings.dry_run {
            " (dry run, nothing changed)"
        } else {
            ""
        }
    );
    Ok(counts.failed == 0 && !guarded.flagged)
}

fn perform(client: &api::Client, settings: &Settings, action: &Action) -> Result<String> {
    Ok(match action {
        Action::Create { fingerprint, issue } => {
            let key = client.create(issue, settings)?;
            format!("created {key} for {fingerprint}")
        }
        Action::Comment {
            key,
            fingerprint,
            note,
        } => {
            client.comment(key, note)?;
            format!("commented on {key} ({fingerprint})")
        }
        Action::Reopen {
            key,
            fingerprint,
            note,
        } => {
            let t = client.transition(
                key,
                Target::Open,
                settings.reopen_transition.as_deref(),
                None,
            )?;
            client.comment(key, note)?;
            format!("reopened {key} ({fingerprint}) with \"{t}\"")
        }
        Action::Resolve {
            key,
            fingerprint,
            note,
        } => {
            // The note first: a closed issue may not take comments.
            client.comment(key, note)?;
            let t = client.transition(
                key,
                Target::Done,
                settings.close_transition.as_deref(),
                settings.close_resolution.as_deref(),
            )?;
            format!("closed {key} ({fingerprint}) with \"{t}\"")
        }
        Action::Info { .. } => String::new(),
    })
}

fn print_dry_run(a: &Action) {
    match a {
        Action::Create { fingerprint, issue } => {
            println!(
                "[dry-run] would create an issue for {fingerprint}: {}",
                issue.summary
            )
        }
        Action::Comment {
            key, fingerprint, ..
        } => {
            println!("[dry-run] would comment on {key} ({fingerprint})")
        }
        Action::Reopen {
            key, fingerprint, ..
        } => println!("[dry-run] would reopen {key} ({fingerprint})"),
        Action::Resolve {
            key, fingerprint, ..
        } => println!("[dry-run] would close {key} ({fingerprint})"),
        Action::Info { .. } => {}
    }
}
