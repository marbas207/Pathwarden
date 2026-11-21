//! `pathwarden-output-servicenow`: keeps one ServiceNow ticket (incident or
//! requested item) per Pathwarden finding, matched by fingerprint in
//! `correlation_id`.
//!
//! Protocol: the Pathwarden event document (`pathwarden.event.v1`) on stdin;
//! settings as JSON in `PATHWARDEN_OUTPUT_SETTINGS` or a file given with
//! `--settings`. `--dry-run` reads ServiceNow but only prints the changes.

#![forbid(unsafe_code)]

mod api;
mod event;
mod reconcile;
mod settings;

use std::io::Read;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use reconcile::Action;
use settings::Settings;

const USAGE: &str =
    "usage: pathwarden-output-servicenow [--settings FILE] [--dry-run] < event.json\n\
settings come from --settings or the PATHWARDEN_OUTPUT_SETTINGS environment variable";

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("servicenow: error: {e:#}");
            ExitCode::FAILURE
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

    // A dry run without credentials is an offline preview against no tickets.
    let (client, tickets) = match api::Client::new(&settings) {
        Ok(client) => {
            let mut tickets = client.tickets()?;
            // created_by defaults to the account the plugin signs in as:
            // tickets anyone else created are never resolved or reopened.
            if settings.created_by.is_none() {
                match client.me() {
                    Ok(Some(me)) if settings::valid_user_name(&me) => {
                        let (mine, warning) = reconcile::own_tickets(tickets, &me);
                        tickets = mine;
                        if let Some(w) = warning {
                            eprintln!("servicenow: warning: {w}");
                        }
                    }
                    Ok(_) => eprintln!(
                        "servicenow: warning: ServiceNow didn't say which account this is, so \
                         tickets are matched by their correlation fields alone, whoever created \
                         them; set created_by to the integration account's user name"
                    ),
                    Err(e) => eprintln!(
                        "servicenow: warning: could not tell which account this is ({e:#}), so \
                         tickets are matched by their correlation fields alone, whoever created \
                         them; set created_by to the integration account's user name"
                    ),
                }
            }
            (Some(client), tickets)
        }
        Err(e) if settings.dry_run => {
            println!(
                "offline preview: existing tickets not read; every finding at or above \
                 min_severity without an open action ticket would be created ({e:#})"
            );
            (None, Vec::new())
        }
        Err(e) => return Err(e),
    };
    let mut tickets = tickets;
    reconcile::settle(&mut tickets, &settings);
    let planned = reconcile::plan(&event, &tickets, &settings, on_closed);
    let guarded = reconcile::guard(planned, &tickets, &settings);
    for w in &guarded.warnings {
        eprintln!("servicenow: warning: {w}");
    }
    let (mut created, mut commented, mut reopened, mut resolved, mut failed) = (0, 0, 0, 0, 0);
    let mut skipped = 0;
    for action in &guarded.actions {
        if let Action::Info {
            ticket,
            fingerprint,
            message,
        } = action
        {
            println!("info: {ticket} ({fingerprint}) {message}");
            continue;
        }
        if let Action::Skip {
            fingerprint,
            record,
        } = action
        {
            println!("skipped {fingerprint}: {}", reconcile::skip_reason(record));
            skipped += 1;
            continue;
        }
        if settings.dry_run || client.is_none() {
            print_dry_run(action);
            count(
                action,
                &mut created,
                &mut commented,
                &mut reopened,
                &mut resolved,
            );
            continue;
        }
        let client = client.as_ref().expect("live client outside a dry run");
        let result = match action {
            Action::Create {
                fingerprint,
                fields,
            } => client
                .create(fields)
                .map(|n| println!("created {n} for {fingerprint}")),
            Action::Comment {
                ticket,
                sys_id,
                fingerprint,
                note,
            } => {
                let mut fields = serde_json::Map::new();
                fields.insert("work_notes".into(), note.clone().into());
                apply(client, sys_id, &fields, "commented on", ticket, fingerprint)
            }
            Action::Reopen {
                ticket,
                sys_id,
                fingerprint,
                fields,
            } => apply(client, sys_id, fields, "reopened", ticket, fingerprint),
            Action::Resolve {
                ticket,
                sys_id,
                fingerprint,
                fields,
            } => apply(client, sys_id, fields, "resolved", ticket, fingerprint),
            Action::Info { .. } | Action::Skip { .. } => Ok(()),
        };
        match result {
            Err(e) => {
                failed += 1;
                eprintln!("servicenow: {e:#}");
            }
            Ok(()) => count(
                action,
                &mut created,
                &mut commented,
                &mut reopened,
                &mut resolved,
            ),
        }
    }
    println!(
        "servicenow ({}): {created} created, {commented} commented, {reopened} reopened, {resolved} resolved{}{}{}",
        settings.table,
        reconcile::skipped_words(skipped),
        if failed > 0 { format!(", {failed} failed") } else { String::new() },
        if settings.dry_run { " (dry run, nothing changed)" } else { "" }
    );
    Ok(failed == 0 && !guarded.flagged)
}

fn count(
    a: &Action,
    created: &mut u32,
    commented: &mut u32,
    reopened: &mut u32,
    resolved: &mut u32,
) {
    match a {
        Action::Create { .. } => *created += 1,
        Action::Comment { .. } => *commented += 1,
        Action::Reopen { .. } => *reopened += 1,
        Action::Resolve { .. } => *resolved += 1,
        Action::Info { .. } | Action::Skip { .. } => {}
    }
}

fn print_dry_run(a: &Action) {
    match a {
        Action::Create { fingerprint, .. } => {
            println!("[dry-run] would create a ticket for {fingerprint}")
        }
        Action::Comment {
            ticket,
            fingerprint,
            ..
        } => {
            println!("[dry-run] would comment on {ticket} ({fingerprint})")
        }
        Action::Reopen {
            ticket,
            fingerprint,
            ..
        } => println!("[dry-run] would reopen {ticket} ({fingerprint})"),
        Action::Resolve {
            ticket,
            fingerprint,
            ..
        } => println!("[dry-run] would resolve {ticket} ({fingerprint})"),
        Action::Info { .. } | Action::Skip { .. } => {}
    }
}

/// Updates a ticket and prints one line.
fn apply(
    client: &api::Client,
    sys_id: &str,
    fields: &serde_json::Map<String, serde_json::Value>,
    done: &str,
    ticket: &str,
    fingerprint: &str,
) -> Result<()> {
    client.update(sys_id, fields)?;
    println!("{done} {ticket} ({fingerprint})");
    Ok(())
}
