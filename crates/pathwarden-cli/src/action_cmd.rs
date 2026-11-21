//! `pathwarden action`: finding actions from the terminal. A finding
//! action is a program someone runs for one finding, when they ask
//! (`[[action]]` in pathwarden.toml). What applies to a finding, the
//! request and the run are the app's own code
//! ([`pathwarden_ui::actions_ui`], [`pathwarden_core::actions`]), so the
//! terminal and the app offer the same actions and send the same request.
//!
//! As with `pathwarden plugins`, the terminal may add a block or change its
//! program (the file could be edited anyway); the app can't with
//! `--lock-destinations` ([`plugin_form::check_action`]).

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use anstream::{eprint, eprintln, println};
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use pathwarden_core::actions::{self, Ask, Ended, FindingContext, Outcome};
use pathwarden_core::config::ActionConfig;
use pathwarden_core::config_edit::{ActionEdit, Setting};
use pathwarden_core::plugin_form;
use pathwarden_ui::actions_ui;
use serde_json::{json, Value};

use crate::config_cmd::{self, Target, Where};
use crate::{emit_json, exit, ui};

#[derive(Args)]
pub(crate) struct ActionArgs {
    #[command(flatten)]
    at: Where,
    #[command(subcommand)]
    what: ActionWhat,
}

#[derive(Subcommand)]
enum ActionWhat {
    /// The finding actions set up and what each program offers; with
    /// --fingerprint, the actions that apply to that finding.
    List {
        /// Only the actions that apply to this finding (its ID, e.g.
        /// PW-006-8ae0b31a46eacada).
        #[arg(long, value_name = "FINDING_ID")]
        fingerprint: Option<String>,
        /// The run the finding is in, by the ID `pathwarden runs list`
        /// prints (default: the newest run that has it).
        #[arg(long, value_name = "RUN", requires = "fingerprint")]
        run: Option<String>,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Run an action for one finding. It asks first unless --yes, prints
    /// the program's progress lines as they come, then the result, and
    /// saves what it did on the finding in the run history (a dry run
    /// saves nothing).
    Run {
        /// The finding (its ID, e.g. PW-006-8ae0b31a46eacada).
        #[arg(value_name = "FINDING_ID")]
        fingerprint: String,
        #[command(flatten)]
        ask: AskArgs,
        /// Don't ask before running it.
        #[arg(long, short = 'y')]
        yes: bool,
        /// Print the result as JSON (progress lines go to stderr).
        #[arg(long)]
        json: bool,
    },
    /// Add a finding action: a program that runs for one finding when
    /// someone asks.
    Add {
        /// The block's name, how its actions are addressed (NAME/ID):
        /// lowercase letters, digits and dashes (default: the plugin's
        /// name, else action-N).
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Run pathwarden-action-PLUGIN from beside pathwarden or its
        /// plugins folder.
        #[arg(
            long,
            value_name = "PLUGIN",
            conflicts_with = "command",
            required_unless_present = "command"
        )]
        plugin: Option<String>,
        /// The program and its arguments, after `--`: a full path, or
        /// powershell, pwsh, python, node, bash, sh or cmd with the script's
        /// full path.
        #[arg(last = true, value_name = "PROGRAM")]
        command: Vec<String>,
        /// A setting passed to the program, e.g. webhook_env=TEAMS_WEBHOOK
        /// (secrets only by the name of an environment variable);
        /// repeatable.
        #[arg(long = "setting", value_name = "NAME=VALUE", value_parser = key_value)]
        settings: Vec<(String, String)>,
        /// How long one run may take, in seconds (default 300, at most
        /// 1800).
        #[arg(long, value_name = "SECONDS")]
        timeout_seconds: Option<u64>,
        /// Only findings at least this severe (critical, high, medium, low,
        /// info).
        #[arg(long, value_name = "SEVERITY")]
        min_severity: Option<String>,
        /// Only findings of this rule; repeatable.
        #[arg(long = "rule", value_name = "RULE")]
        rules: Vec<String>,
        /// Only findings of this category (attack_path, hygiene);
        /// repeatable.
        #[arg(long = "category", value_name = "CATEGORY")]
        categories: Vec<String>,
    },
    /// Remove a finding action by its name.
    Remove {
        /// The block's name, as `list` shows it.
        name: String,
    },
    /// Run an action as a dry run on the first finding of the latest run it
    /// applies to: the program is asked to change nothing.
    Test {
        /// The block's name, as `list` shows it.
        name: String,
        /// Which of its actions (its ID; default: the first that applies).
        #[arg(long, value_name = "ID")]
        action: Option<String>,
        /// Don't ask before running it.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// For people writing actions: print the request an action would get
    /// for a finding, as JSON.
    Request {
        /// The finding (its ID, e.g. PW-006-8ae0b31a46eacada).
        #[arg(value_name = "FINDING_ID")]
        fingerprint: String,
        #[command(flatten)]
        ask: AskArgs,
    },
    /// For people writing actions: run a program's describe, then a dry run
    /// of each action it offers on a sample finding (or --fingerprint's),
    /// and name every problem with its answers. Exits 2 when there are
    /// problems. A program given by its path is checked on the sample
    /// finding without asking: it only gets describe and dry runs. It asks
    /// first unless --yes when a real finding could be sent: a block that
    /// is set up, or --fingerprint.
    Check {
        /// A block's name, or the program to check: its path (a .ps1, .py,
        /// .sh or .js script runs with its interpreter), or an interpreter
        /// with the script's full path after `--`.
        #[arg(value_name = "PROGRAM_OR_NAME")]
        program: String,
        /// The program's arguments, after `--`.
        #[arg(last = true, value_name = "ARGS")]
        args: Vec<String>,
        /// A setting passed to the program, e.g. group=Identity;
        /// repeatable.
        #[arg(long = "setting", value_name = "NAME=VALUE", value_parser = key_value)]
        settings: Vec<(String, String)>,
        /// Dry-run on this finding of the environment instead of the sample.
        #[arg(long, value_name = "FINDING_ID")]
        fingerprint: Option<String>,
        /// The run the finding is in (default: the newest run that has it).
        #[arg(long, value_name = "RUN", requires = "fingerprint")]
        run: Option<String>,
        /// Don't ask before checking a block that is set up, or a real
        /// finding.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// What finding actions created or look after (a ticket), kept on each
    /// finding in the run history: one finding's, or every finding's.
    /// `--open --fixed` lists the fixed findings whose ticket is still open,
    /// as the report's "Fixed, ticket still open" card does.
    Records {
        #[command(subcommand)]
        what: Option<RecordsWhat>,
        /// Only this finding's records (its ID, e.g.
        /// PW-006-8ae0b31a46eacada).
        #[arg(value_name = "FINDING_ID")]
        fingerprint: Option<String>,
        /// Only open records.
        #[arg(long)]
        open: bool,
        /// Only records of findings the latest run found fixed, newest fix
        /// first.
        #[arg(long)]
        fixed: bool,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Repairs of what finding actions did, kept in the run history.
    Log {
        #[command(subcommand)]
        what: LogWhat,
    },
    /// Every run of a finding action, newest first, kept on each finding in
    /// the run history: one finding's, or every finding's.
    Activity {
        /// Only this finding's activity (its ID).
        #[arg(value_name = "FINDING_ID")]
        fingerprint: Option<String>,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum LogWhat {
    /// Take a plain actions.json in an encrypted history into the history,
    /// encrypted. Pathwarden never reads one by itself: anyone who can push
    /// could have put it there. An older Pathwarden leaves one when it
    /// turns encryption on. It shows what the file holds and asks first.
    Import {
        /// Don't ask before importing it.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum RecordsWhat {
    /// Remove a record from a finding. The removal is saved in its
    /// activity. Nothing is changed in the other system.
    Remove {
        /// The finding (its ID).
        #[arg(value_name = "FINDING_ID")]
        fingerprint: String,
        /// The record's ID, as `records` shows it.
        #[arg(value_name = "RECORD_ID")]
        record: String,
        /// Don't ask before removing it.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// Which action, with what, for `run` and `request`.
#[derive(Args)]
struct AskArgs {
    /// The action, as NAME/ID (`list --fingerprint` shows them); may be left
    /// out when only one applies.
    #[arg(long, value_name = "NAME/ID")]
    action: Option<String>,
    /// An input the action asks for, e.g. note="Please review"; repeatable.
    #[arg(long = "input", value_name = "ID=VALUE", value_parser = key_value)]
    inputs: Vec<(String, String)>,
    /// Ask the program for a dry run: it changes nothing, and nothing is
    /// saved on the finding.
    #[arg(long)]
    dry_run: bool,
    /// Run a follow-up (such as Check status) on this record of the
    /// finding, by its ID (`records` shows them).
    #[arg(long, value_name = "RECORD_ID")]
    record: Option<String>,
    /// The run the finding is in, by the ID `pathwarden runs list` prints
    /// (default: the newest run that has it).
    #[arg(long, value_name = "RUN")]
    run: Option<String>,
}

impl AskArgs {
    fn ask(&self) -> Ask {
        Ask {
            action: self.action.clone(),
            inputs: self
                .inputs
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect(),
            dry_run: self.dry_run,
            record: self.record.clone(),
        }
    }
}

fn key_value(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) => Ok((k.trim().to_string(), v.to_string())),
        None => Err(format!("{s:?} is not NAME=VALUE")),
    }
}

/// A setting's value as TOML writes it: true and false, a whole number
/// that reads back the same, else text.
fn setting(v: &str) -> Setting {
    match v {
        "true" => Setting::Bool(true),
        "false" => Setting::Bool(false),
        _ => match v.parse::<i64>() {
            Ok(n) if n.to_string() == v => Setting::Int(n),
            _ => Setting::Str(v.to_string()),
        },
    }
}

/// The workspace the settings are an environment of: finding actions run
/// on its saved runs.
fn workspace(t: &Target) -> Result<&pathwarden_ui::workspace::Workspace> {
    t.ws.as_ref().context(
        "finding actions run on a saved run: name an environment with --env or --workspace instead of -c",
    )
}

/// What a run of an action logs itself as: the finding, or the test.
pub(crate) fn job_of(a: &ActionArgs) -> Option<String> {
    match &a.what {
        ActionWhat::Run { fingerprint, .. } => Some(fingerprint.clone()),
        ActionWhat::Test { name, .. } => Some(format!("test of {name}")),
        _ => None,
    }
}

pub(crate) fn run(a: ActionArgs) -> Result<ExitCode> {
    // Nobody is there to ask in a scheduled task.
    if pathwarden_core::store::unattended() {
        bail!("{}", actions::ActionError::Unattended);
    }
    match a.what {
        ActionWhat::Check {
            program,
            args,
            settings,
            fingerprint,
            run,
            yes,
        } => check(&a.at, &program, &args, settings, fingerprint, run, yes),
        what => {
            let t = config_cmd::target(&a.at)?;
            let config = config_cmd::load(&t.path)?;
            match what {
                ActionWhat::List {
                    fingerprint,
                    run,
                    json,
                } => list(&t, &config.actions, fingerprint, run, json),
                ActionWhat::Run {
                    fingerprint,
                    ask,
                    yes,
                    json,
                } => run_one(&t, &config.actions, &fingerprint, &ask, yes, json),
                ActionWhat::Add {
                    name,
                    plugin,
                    command,
                    settings,
                    timeout_seconds,
                    min_severity,
                    rules,
                    categories,
                } => {
                    let mut set = Vec::new();
                    for (k, v) in settings {
                        if plugin_form::looks_secret(&k) {
                            bail!("Don't put secrets in the file. Instead of {k}, add {k}_env with the name of an environment variable that holds it.");
                        }
                        if k.ends_with("_env") && !pathwarden_core::plugins::valid_env_name(&v) {
                            bail!("{k} must name an environment variable (letters, digits and _).");
                        }
                        set.push((k, setting(&v)));
                    }
                    let mut edit = ActionEdit {
                        name: name.unwrap_or_default(),
                        plugin,
                        command: (!command.is_empty()).then_some(command),
                        timeout_seconds,
                        min_severity,
                        rules: (!rules.is_empty()).then_some(rules),
                        categories: (!categories.is_empty()).then_some(categories),
                        set,
                        remove: Vec::new(),
                    };
                    plugin_form::check_action(true, &mut edit, None).map_err(anyhow::Error::msg)?;
                    config_cmd::save(&t, |d| d.upsert_action(None, &edit))?;
                    let added = config_cmd::load(&t.path)?;
                    let name = added
                        .actions
                        .last()
                        .map(|a| a.name.clone())
                        .unwrap_or_default();
                    println!(
                        "Saved: finding action {} in {}. `pathwarden action test {}` tries it.",
                        ui::safe(&name),
                        t.label,
                        ui::safe(&name)
                    );
                    Ok(ExitCode::SUCCESS)
                }
                ActionWhat::Remove { name } => {
                    let Some(i) = config
                        .actions
                        .iter()
                        .position(|a| a.name.eq_ignore_ascii_case(name.trim()))
                    else {
                        bail!(
                            "There is no finding action {} in {} (see `pathwarden action list`).",
                            ui::safe(&name),
                            t.label
                        );
                    };
                    let name = config.actions[i].name.clone();
                    config_cmd::save(&t, |d| d.remove_action(i, &name))?;
                    println!(
                        "Removed finding action {} from {}.",
                        ui::safe(&name),
                        t.label
                    );
                    Ok(ExitCode::SUCCESS)
                }
                ActionWhat::Test { name, action, yes } => {
                    test(&t, &config.actions, &name, action, yes)
                }
                ActionWhat::Request { fingerprint, ask } => {
                    request(&t, &config.actions, &fingerprint, &ask)
                }
                ActionWhat::Records {
                    what:
                        Some(RecordsWhat::Remove {
                            fingerprint,
                            record,
                            yes,
                        }),
                    ..
                } => remove_record(&t, &fingerprint, &record, yes),
                ActionWhat::Records {
                    what: None,
                    fingerprint,
                    open,
                    fixed,
                    json,
                } => records(&t, fingerprint.as_deref(), open, fixed, json),
                ActionWhat::Activity { fingerprint, json } => {
                    activity(&t, fingerprint.as_deref(), json)
                }
                ActionWhat::Log {
                    what: LogWhat::Import { yes },
                } => import_log(&t, yes),
                ActionWhat::Check { .. } => unreachable!("handled above"),
            }
        }
    }
}

/// What a block's program runs, as `list` shows it.
fn program_line(a: &ActionConfig) -> String {
    let (program, found) = plugin_form::action_program(a);
    format!(
        "{} {}{}",
        if found { "ok" } else { "!" },
        ui::safe(&program),
        if found { "" } else { " (not found)" }
    )
}

/// The block's filters in words, empty when it has none.
fn filters_line(a: &ActionConfig) -> String {
    let mut parts = Vec::new();
    if let Some(s) = a.min_severity {
        parts.push(format!("{} and above", s.label()));
    }
    if !a.rules.is_empty() {
        parts.push(format!("rules {}", a.rules.join(", ")));
    }
    if !a.categories.is_empty() {
        parts.push(
            a.categories
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    parts.join("; ")
}

/// When an action is offered, in words: "on a record", "when fixed",
/// "when open or fixed", "while it has no open record".
fn when_words(d: &actions::ActionDef) -> String {
    let mut w = Vec::new();
    if d.for_.is_some() {
        w.push("on a record".to_string());
    }
    if let Some(when) = &d.when {
        let names: Vec<&str> = when
            .iter()
            .map(|s| match s {
                actions::FindingStatus::Open => "open",
                actions::FindingStatus::Held => "held",
                actions::FindingStatus::Accepted => "accepted",
                actions::FindingStatus::Fixed => "fixed",
            })
            .collect();
        w.push(format!("when {}", or_list(&names)));
    }
    if d.once {
        w.push("while it has no open record".into());
    }
    w.join(", ")
}

/// "a", "a or b", "a, b or c".
fn or_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    }
}

/// On stderr: the blocks named by their position (`action-N`), which
/// changes when blocks move, and what to do.
fn warn_positional(blocks: &[ActionConfig]) {
    for a in blocks.iter().filter(|a| a.positional_name) {
        eprintln!(
            "Note: an [[action]] block has no name, so it is called {} by its place in the file, and that changes when blocks move. Add name = \"{}\" to it.",
            ui::safe(&a.name),
            ui::safe(&pathwarden_core::config::action_name_for(
                a.plugin.as_deref(),
                a.command.as_deref()
            ))
        );
    }
}

fn list(
    t: &Target,
    blocks: &[ActionConfig],
    fingerprint: Option<String>,
    run: Option<String>,
    json: bool,
) -> Result<ExitCode> {
    warn_positional(blocks);
    if let Some(fp) = fingerprint {
        let ws = workspace(t)?;
        let on =
            actions_ui::offered_on(ws, blocks, run.as_deref(), &fp).map_err(anyhow::Error::msg)?;
        if json {
            emit_json(&json!({
                "fingerprint": on.finding.fingerprint,
                "run": on.run.id,
                "status": on.finding.status,
                "actions": on.offered,
                "failed": on.failed.iter().map(|(n, why)| json!({ "name": n, "error": why })).collect::<Vec<_>>(),
            }))?;
            return Ok(ExitCode::SUCCESS);
        }
        println!(
            "{} ({}), in run {}:",
            ui::safe(&on.finding.fingerprint),
            ui::safe(&on.finding.title),
            ui::safe(&on.run.id)
        );
        if on.offered.is_empty() {
            println!("  No action applies to it.");
        }
        let d = ui::DIM;
        for o in &on.offered {
            println!("  {}  {}", ui::safe(&o.address), ui::safe(&o.def.label));
            if !o.def.description.is_empty() {
                println!("     {d}{}{d:#}", ui::safe(&o.def.description));
            }
        }
        for (name, why) in &on.failed {
            println!("  ! {}: {}", ui::safe(name), ui::safe(why));
        }
        return Ok(ExitCode::SUCCESS);
    }
    if blocks.is_empty() {
        if json {
            emit_json(&Vec::<Value>::new())?;
        } else {
            println!("No finding actions in {}.", t.label);
        }
        return Ok(ExitCode::SUCCESS);
    }
    let all = actions::describe_all(blocks);
    if json {
        let list: Vec<Value> = all
            .iter()
            .map(|(a, d)| {
                let (program, found) = plugin_form::action_program(a);
                let mut v = json!({
                    "name": a.name,
                    "program": program,
                    "found": found,
                    "filters": actions::Filters::of_config(a),
                    "timeout_seconds": a.timeout_seconds,
                });
                match d {
                    Ok(d) => {
                        v["actions"] =
                            serde_json::to_value(&d.describe.actions).unwrap_or_default();
                        v["problems"] = json!(d.problems);
                    }
                    Err(e) => v["error"] = json!(e.to_string()),
                }
                v
            })
            .collect();
        emit_json(&list)?;
        return Ok(ExitCode::SUCCESS);
    }
    let d = ui::DIM;
    println!("Finding actions in {}:", t.label);
    for (a, described) in &all {
        let filters = filters_line(a);
        println!(
            "  {}{}",
            ui::safe(&a.name),
            if filters.is_empty() {
                String::new()
            } else {
                format!("  {d}{}{d:#}", ui::safe(&filters))
            }
        );
        println!("     {}", program_line(a));
        match described {
            Ok(x) => {
                for def in &x.describe.actions {
                    let when = when_words(def);
                    println!(
                        "     {}/{}  {}{}",
                        ui::safe(&a.name),
                        ui::safe(&def.id),
                        ui::safe(&def.label),
                        if when.is_empty() {
                            String::new()
                        } else {
                            format!("  {d}({when}){d:#}")
                        }
                    );
                }
                for p in &x.problems {
                    println!("     ! {}", ui::safe(p));
                }
            }
            Err(e) => println!("     ! {}", ui::safe(&e.to_string())),
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Asks on the terminal whether to run it; without one, --yes is needed.
fn confirm(question: &str) -> Result<()> {
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        bail!("running an action asks first, and nothing can answer here; pass --yes to run it without asking");
    }
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut typed = String::new();
    std::io::stdin().lock().read_line(&mut typed)?;
    if !matches!(typed.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        bail!("nothing was run");
    }
    Ok(())
}

/// Says what is about to run, asks unless `yes`, runs it with its progress
/// lines printed as they come, and prints the result.
fn start(
    ws: &pathwarden_ui::workspace::Workspace,
    ready: &actions_ui::Ready,
    yes: bool,
    json: bool,
) -> Result<ExitCode> {
    let o = &ready.prepared.offered;
    let f = &ready.finding;
    let dry = ready.prepared.request["dry_run"].as_bool().unwrap_or(false);
    let say = |line: String| {
        if json {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };
    say(format!(
        "{} ({}) on {}{}: {}, in run {}.",
        ui::safe(&o.def.label),
        ui::safe(&o.address),
        ui::safe(&f.fingerprint),
        ready
            .prepared
            .record
            .as_ref()
            .map(|r| format!(
                ", record {}",
                ui::safe(&pathwarden_core::action_log::chip(&r.record, false))
            ))
            .unwrap_or_default(),
        ui::safe(&f.title),
        ui::safe(&ready.run.id)
    ));
    if !o.def.sends.is_empty() {
        say(format!("It sends: {}", ui::safe(&o.def.sends)));
    }
    if dry {
        say("A dry run: the program is asked to change nothing.".into());
    }
    if !yes {
        confirm(if dry { "Run the dry run?" } else { "Run it?" })?;
    }
    let tag = ui::VIOLET;
    let name = o.name.clone();
    let mut on_line = |line: &str| {
        pathwarden_core::logs::note(line);
        let l = format!("  {tag}[{}]{tag:#} {}", ui::safe(&name), ui::safe(line));
        if json {
            eprintln!("{l}");
        } else {
            println!("{l}");
        }
    };
    let cancel = crate::interrupt::cancel_on_interrupt();
    let out = actions::run(
        &ready.prepared.config,
        &ready.prepared.request,
        &mut on_line,
        &cancel,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    if out.ended == Ended::Cancelled && crate::interrupt::hit() {
        // Saved as cancelled, in one quick try: Ctrl-C stays quick.
        if !out.dry_run {
            if let Err(why) = actions_ui::save_outcome_quick(ws, ready, &out) {
                eprintln!("Not saved on the finding: {}", ui::safe(&why));
            }
        }
        eprintln!("Cancelled.");
        return Ok(ExitCode::from(crate::interrupt::EXIT_CANCELLED as u8));
    }
    // What it did, on the finding at once (a dry run saves nothing). A
    // run that couldn't be saved still ran: said, not an error.
    let saved = if out.dry_run {
        None
    } else {
        Some(actions_ui::save_outcome(ws, ready, &out))
    };
    // The activity entry's log, for the app's Open log on this computer.
    if let (Some(Ok(s)), Some(log), Some(dir)) = (
        &saved,
        pathwarden_core::logs::current(),
        pathwarden_core::logs::dir(),
    ) {
        if let Some(at) = &s.at {
            pathwarden_core::logs::note_action(&dir, &ready.finding.fingerprint, at, log.name());
        }
    }
    let mut said = Vec::new();
    match &saved {
        Some(Ok(s)) => {
            if s.saved && s.pushed {
                said.push(SAVED_WORDS.to_string());
            } else if s.saved {
                said.push(pathwarden_core::action_log::SAVED_HERE_WORDS.to_string());
            }
            said.extend(s.notes.iter().cloned());
        }
        Some(Err(why)) => said.push(format!("Not saved on the finding: {why}")),
        // (A save kept here but not pushed says so in its notes.)
        None => {}
    }
    if json {
        // What the app's result card reads too.
        let v = actions_ui::outcome_json(ready, &out, saved.as_ref());
        for line in &said {
            eprintln!("{}", ui::safe(line));
        }
        emit_json(&v)?;
        return Ok(ExitCode::from(if out.ok { exit::OK } else { exit::ERROR }));
    }
    print_outcome(&out);
    for line in &said {
        println!("{}", ui::safe(line));
    }
    if !out.ok {
        bail!("{}", out.message);
    }
    Ok(ExitCode::SUCCESS)
}

/// What `action run` says once the outcome is saved.
const SAVED_WORDS: &str = "Saved on this finding in the run history.";

/// The result: the message, records and links, then what was wrong with
/// it, and on a failure the program's error output.
fn print_outcome(out: &Outcome) {
    let d = ui::DIM;
    if out.ok {
        println!(
            "{}Done:{:#} {}",
            ui::GREEN,
            ui::GREEN,
            ui::safe(&out.message)
        );
    }
    for r in &out.records {
        let name = r.number.as_deref().or(r.label.as_deref()).unwrap_or(&r.id);
        let status = r
            .status
            .as_deref()
            .unwrap_or(if r.open { "Open" } else { "Closed" });
        println!(
            "  Record: {} · {}{}",
            ui::safe(name),
            ui::safe(status),
            r.url
                .as_deref()
                .map(|u| format!("  {}", ui::safe(u)))
                .unwrap_or_default()
        );
        for (k, v) in &r.fields {
            println!("    {d}{}: {}{d:#}", ui::safe(k), ui::safe(v));
        }
    }
    for l in &out.links {
        println!("  {}: {}", ui::safe(&l.label), ui::safe(&l.url));
    }
    for p in &out.problems {
        println!("  {d}Note: {}{d:#}", ui::safe(p));
    }
    if !out.ok && !out.details.is_empty() {
        println!("  Details ({}):", ui::safe(&out.status));
        for line in out.details.lines() {
            println!("    {d}{}{d:#}", ui::safe(line));
        }
    }
}

fn run_one(
    t: &Target,
    blocks: &[ActionConfig],
    fingerprint: &str,
    ask: &AskArgs,
    yes: bool,
    json: bool,
) -> Result<ExitCode> {
    let ws = workspace(t)?;
    note_plain(ws);
    let ready = actions_ui::prepare(ws, blocks, ask.run.as_deref(), fingerprint, &ask.ask())
        .map_err(anyhow::Error::msg)?;
    // This action's log goes in the run's diagnostics, as from the app.
    pathwarden_core::logs::note_run_current(&ready.run.id);
    start(ws, &ready, yes, json)
}

fn test(
    t: &Target,
    blocks: &[ActionConfig],
    name: &str,
    action: Option<String>,
    yes: bool,
) -> Result<ExitCode> {
    let Some(block) = blocks
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(name.trim()))
    else {
        bail!(
            "There is no finding action {} in {} (see `pathwarden action list`).",
            ui::safe(name),
            t.label
        );
    };
    let ws = workspace(t)?;
    // The app's Test runs the same ([`actions_ui::test_target`]).
    let ready = actions_ui::test_target(ws, blocks, &block.name, action.as_deref())
        .map_err(anyhow::Error::msg)?;
    start(ws, &ready, yes, false)
}

fn request(
    t: &Target,
    blocks: &[ActionConfig],
    fingerprint: &str,
    ask: &AskArgs,
) -> Result<ExitCode> {
    let ws = workspace(t)?;
    if blocks.is_empty() {
        let (_, f) = actions_ui::find_finding(ws, ask.run.as_deref(), fingerprint)
            .map_err(anyhow::Error::msg)?;
        eprintln!("No finding actions are set up, so action, inputs and settings are empty.");
        let me = pathwarden_core::identity::Actor::current();
        emit_json(&actions::finding_request(&f, ask.dry_run, &me))?;
        return Ok(ExitCode::SUCCESS);
    }
    let ready = actions_ui::prepare(ws, blocks, ask.run.as_deref(), fingerprint, &ask.ask())
        .map_err(anyhow::Error::msg)?;
    emit_json(&ready.prepared.request)?;
    Ok(ExitCode::SUCCESS)
}

/// The command that runs a program given by path: a script with its
/// interpreter, anything else as it is.
fn command_for_path(program: &str, args: &[String]) -> Result<Vec<String>> {
    if pathwarden_core::plugins::is_remote_path(program) {
        bail!("{program} is a network path. Copy the program to this computer and check its local path.");
    }
    let path =
        std::path::absolute(Path::new(program)).with_context(|| format!("reading {program}"))?;
    if !path.is_file() {
        bail!("{} is not a file.", path.display());
    }
    let lower = program.to_ascii_lowercase();
    let full = path.display().to_string();
    let mut argv: Vec<String> = if lower.ends_with(".ps1") {
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ]
        .iter()
        .map(|s| s.to_string())
        .chain([full])
        .collect()
    } else if lower.ends_with(".py") {
        vec!["python".into(), full]
    } else if lower.ends_with(".sh") {
        vec!["sh".into(), full]
    } else if lower.ends_with(".js") || lower.ends_with(".mjs") {
        vec!["node".into(), full]
    } else {
        vec![full]
    };
    argv.extend(args.iter().cloned());
    Ok(argv)
}

fn check(
    at: &Where,
    first: &str,
    args: &[String],
    settings: Vec<(String, String)>,
    fingerprint: Option<String>,
    run: Option<String>,
    yes: bool,
) -> Result<ExitCode> {
    // A block of the settings by name, or a program.
    let by_name = args.is_empty() && pathwarden_core::config::valid_plugin_name(first);
    let target = if by_name || fingerprint.is_some() {
        Some(config_cmd::target(at)?)
    } else {
        None
    };
    let mut block = match (&target, by_name) {
        (Some(t), true) => {
            let config = config_cmd::load(&t.path)?;
            let Some(a) = config
                .actions
                .iter()
                .find(|a| a.name.eq_ignore_ascii_case(first))
            else {
                bail!(
                    "There is no finding action {} in {}. To check a program, give its path.",
                    ui::safe(first),
                    t.label
                );
            };
            warn_positional(&config.actions);
            a.clone()
        }
        _ => {
            let argv = if pathwarden_core::plugins::is_interpreter(first) {
                std::iter::once(first.to_string())
                    .chain(args.iter().cloned())
                    .collect()
            } else {
                command_for_path(first, args)?
            };
            pathwarden_core::plugins::check_program(&argv[0]).map_err(anyhow::Error::msg)?;
            pathwarden_core::plugins::check_args(&argv[1..]).map_err(anyhow::Error::msg)?;
            let stem = Path::new(first)
                .file_stem()
                .map(|s| s.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let name: String = stem
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect();
            ActionConfig {
                name: if pathwarden_core::config::valid_plugin_name(&name) {
                    name
                } else {
                    "action".into()
                },
                command: Some(argv),
                timeout_seconds: pathwarden_core::config::ACTION_TIMEOUT_DEFAULT,
                ..ActionConfig::default()
            }
        }
    };
    for (k, v) in settings {
        block.settings.insert(
            k,
            match setting(&v) {
                Setting::Bool(b) => json!(b),
                Setting::Int(n) => json!(n),
                Setting::Str(s) => json!(s),
            },
        );
    }
    let finding: FindingContext = match (&target, &fingerprint) {
        (Some(t), Some(fp)) => {
            let ws = workspace(t)?;
            actions_ui::find_finding(ws, run.as_deref(), fp)
                .map_err(anyhow::Error::msg)?
                .1
        }
        _ => actions::sample_finding(),
    };
    // A real finding could leave the computer: a block that is set up (its
    // program may send even a dry run's request on), or --fingerprint.
    if !yes && (by_name || fingerprint.is_some()) {
        println!(
            "Checking {} runs its program: describe, then a dry run of each action on {}{}.",
            ui::safe(&block.name),
            ui::safe(&finding.fingerprint),
            if fingerprint.is_some() {
                ", a finding of this environment"
            } else {
                ", a sample finding"
            }
        );
        confirm("Check it?")?;
    }
    println!(
        "Checking {} on {}{}.",
        ui::safe(&block.name),
        ui::safe(&finding.fingerprint),
        if fingerprint.is_some() {
            ""
        } else {
            ", a sample finding"
        }
    );
    let tag = ui::VIOLET;
    let cancel = crate::interrupt::cancel_on_interrupt();
    let problems = actions::check(
        &block,
        &finding,
        &mut |who, line| {
            println!("  {tag}[{}]{tag:#} {}", ui::safe(who), ui::safe(line));
        },
        &cancel,
    );
    if crate::interrupt::hit() {
        eprintln!("Cancelled.");
        return Ok(ExitCode::from(crate::interrupt::EXIT_CANCELLED as u8));
    }
    if problems.is_empty() {
        println!("No problems: its describe and every dry run passed the checks.");
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{}:",
        if problems.len() == 1 {
            "1 problem".to_string()
        } else {
            format!("{} problems", problems.len())
        }
    );
    for p in &problems {
        println!("  - {}", ui::safe(p));
    }
    Ok(ExitCode::from(exit::ERROR))
}

/// A record as `records` prints it: its chip, link, fields, and who first
/// made it, where and when.
fn print_record(r: &actions::ActionRecord, indent: &str) {
    let d = ui::DIM;
    println!(
        "{indent}{}  {}{}",
        ui::safe(&r.record.id),
        ui::safe(&pathwarden_core::action_log::chip(&r.record, false)),
        r.record
            .url
            .as_deref()
            .map(|u| format!("  {}", ui::safe(u)))
            .unwrap_or_default()
    );
    for (k, v) in &r.record.fields {
        println!("{indent}  {d}{}: {}{d:#}", ui::safe(k), ui::safe(v));
    }
    let first = pathwarden_core::action_log::Activity {
        at: r.at.clone(),
        by: r.by.clone(),
        on: r.on.clone(),
        ..Default::default()
    };
    println!(
        "{indent}  {d}by {} — {}{d:#}",
        ui::safe(&r.action),
        ui::safe(&first.who_when())
    );
}

/// The finding `fp` names (any case) among the log's, or `fp` as given.
fn finding_key(log: &pathwarden_core::action_log::ActionsFile, fp: &str) -> String {
    log.findings
        .keys()
        .find(|k| k.eq_ignore_ascii_case(fp.trim()))
        .cloned()
        .unwrap_or_else(|| fp.trim().to_string())
}

/// On stderr: a plain actions.json in the encrypted history wasn't read.
fn note_plain(ws: &pathwarden_ui::workspace::Workspace) {
    if actions_ui::plain_left(ws) {
        eprintln!("Note: {}", pathwarden_core::action_log::PLAIN_LEFT_WORDS);
    }
}

fn import_log(t: &Target, yes: bool) -> Result<ExitCode> {
    let ws = workspace(t)?;
    let Some(s) = actions_ui::plain_summary(ws, 5).map_err(anyhow::Error::msg)? else {
        bail!(
            "There is no plain actions.json in the encrypted history of {}.",
            t.label
        );
    };
    println!(
        "The plain actions.json holds {} on {}, with {}.",
        pathwarden_core::text::count(s.records, "record", "records"),
        pathwarden_core::text::count(s.findings, "finding", "findings"),
        pathwarden_core::text::count(s.activity, "entry of activity", "entries of activity"),
    );
    if !s.record_lines.is_empty() {
        println!("Its records:");
        for (fp, line) in &s.record_lines {
            println!("  {}  {}", ui::safe(fp), ui::safe(line));
        }
        if s.more_records > 0 {
            println!("  and {} more", s.more_records);
        }
    }
    if !s.newest.is_empty() {
        println!("The latest:");
        for (fp, line) in &s.newest {
            println!("  {}  {}", ui::safe(fp), ui::safe(line));
        }
    }
    println!(
        "Import it only if you know where it comes from: anyone who can push to the history could have put it there."
    );
    if !yes {
        confirm("Import it?")?;
    }
    let notes = actions_ui::import_plain(ws, &s.hash).map_err(anyhow::Error::msg)?;
    println!(
        "Imported: what it holds is in the history, encrypted, and the plain copy is removed."
    );
    for n in notes {
        println!("{}", ui::safe(&n));
    }
    Ok(ExitCode::SUCCESS)
}

/// `open`: only open records; `fixed`: only records of the findings the
/// latest run found fixed (both: the report's "Fixed, ticket still open").
fn records(
    t: &Target,
    fingerprint: Option<&str>,
    open: bool,
    fixed: bool,
    json: bool,
) -> Result<ExitCode> {
    let ws = workspace(t)?;
    note_plain(ws);
    let log = actions_ui::log(ws).map_err(anyhow::Error::msg)?;
    if fixed {
        return fixed_records(t, ws, &log, fingerprint, open, json);
    }
    let mut rows: Vec<(String, Vec<actions::ActionRecord>)> = match fingerprint {
        Some(fp) => {
            let key = finding_key(&log, fp);
            let records = log.records(&key);
            vec![(key, records)]
        }
        None => log
            .findings
            .iter()
            .filter(|(_, l)| !l.records.is_empty())
            .map(|(fp, l)| (fp.clone(), l.records.clone()))
            .collect(),
    };
    if open {
        for (_, rs) in rows.iter_mut() {
            rs.retain(|r| r.record.open);
        }
    }
    rows.retain(|(_, r)| fingerprint.is_some() || !r.is_empty());
    if json {
        let list: Vec<Value> = rows
            .iter()
            .flat_map(|(fp, rs)| {
                rs.iter().map(move |r| {
                    let mut v = serde_json::to_value(r).unwrap_or_default();
                    v["fingerprint"] = json!(fp);
                    v
                })
            })
            .collect();
        emit_json(&list)?;
        return Ok(ExitCode::SUCCESS);
    }
    if rows.iter().all(|(_, r)| r.is_empty()) {
        let which = if open { "open records" } else { "records" };
        match fingerprint {
            Some(fp) => println!("{} has no {which}.", ui::safe(fp.trim())),
            None => println!("No finding has {which} in {}.", t.label),
        }
        return Ok(ExitCode::SUCCESS);
    }
    for (fp, rs) in &rows {
        println!("{}:", ui::safe(fp));
        for r in rs {
            print_record(r, "  ");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `records --fixed`: the findings the latest run found fixed that have
/// records (open ones, with `open`), newest fix first
/// ([`actions_ui::fixed_records`]). Its JSON is the records, each with
/// its finding's `fingerprint`, `rule`, `title` and `fixed_at` (Unix
/// time).
fn fixed_records(
    t: &Target,
    ws: &pathwarden_ui::workspace::Workspace,
    log: &pathwarden_core::action_log::ActionsFile,
    fingerprint: Option<&str>,
    open: bool,
    json: bool,
) -> Result<ExitCode> {
    let mut list = actions_ui::fixed_records(ws, log, open).map_err(anyhow::Error::msg)?;
    if let Some(fp) = fingerprint {
        list.retain(|f| f.fingerprint.eq_ignore_ascii_case(fp.trim()));
    }
    if json {
        let rows: Vec<Value> = list
            .iter()
            .flat_map(|f| {
                f.records.iter().map(move |r| {
                    let mut v = serde_json::to_value(r).unwrap_or_default();
                    v["fingerprint"] = json!(f.fingerprint);
                    v["rule"] = json!(f.rule);
                    v["title"] = json!(f.title);
                    v["fixed_at"] = json!(f.fixed_at);
                    v
                })
            })
            .collect();
        emit_json(&rows)?;
        return Ok(ExitCode::SUCCESS);
    }
    if list.is_empty() {
        let which = if open { "an open record" } else { "records" };
        match fingerprint {
            Some(fp) => println!(
                "{} isn't a fixed finding with {which}.",
                ui::safe(fp.trim())
            ),
            None => println!("No fixed finding has {which} in {}.", t.label),
        }
        return Ok(ExitCode::SUCCESS);
    }
    let d = ui::DIM;
    for f in &list {
        println!(
            "{}  {} {}  {d}fixed {}{d:#}",
            ui::safe(&f.fingerprint),
            ui::safe(&f.rule),
            ui::safe(&f.title),
            pathwarden_core::report::short_date(f.fixed_at)
        );
        for r in &f.records {
            print_record(r, "  ");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn activity(t: &Target, fingerprint: Option<&str>, json: bool) -> Result<ExitCode> {
    let ws = workspace(t)?;
    note_plain(ws);
    let log = actions_ui::log(ws).map_err(anyhow::Error::msg)?;
    // Newest first, each with its finding.
    let mut all: Vec<(String, pathwarden_core::action_log::Activity)> = match fingerprint {
        Some(fp) => {
            let key = finding_key(&log, fp);
            log.activity(&key)
                .into_iter()
                .map(|a| (key.clone(), a))
                .collect()
        }
        None => log
            .findings
            .keys()
            .flat_map(|fp| log.activity(fp).into_iter().map(move |a| (fp.clone(), a)))
            .collect(),
    };
    all.sort_by(|a, b| b.1.at.cmp(&a.1.at));
    if json {
        let list: Vec<Value> = all
            .iter()
            .map(|(fp, a)| {
                let mut v = serde_json::to_value(a).unwrap_or_default();
                v["fingerprint"] = json!(fp);
                v
            })
            .collect();
        emit_json(&list)?;
        return Ok(ExitCode::SUCCESS);
    }
    if all.is_empty() {
        match fingerprint {
            Some(fp) => println!("No action ran on {}.", ui::safe(fp.trim())),
            None => println!("No action ran on any finding in {}.", t.label),
        }
        return Ok(ExitCode::SUCCESS);
    }
    let d = ui::DIM;
    for (fp, a) in &all {
        let what = if fingerprint.is_some() {
            String::new()
        } else {
            format!("{}  ", ui::safe(fp))
        };
        println!(
            "  {what}{}{} {d}— {}{d:#}",
            if a.ok { "" } else { "! " },
            ui::safe(&a.summary()),
            ui::safe(&a.who_when())
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn remove_record(t: &Target, fingerprint: &str, record: &str, yes: bool) -> Result<ExitCode> {
    let ws = workspace(t)?;
    if !yes {
        println!(
            "This removes record {} from {} in the run history, for everyone. Nothing changes in the other system.",
            ui::safe(record.trim()),
            ui::safe(fingerprint.trim())
        );
        confirm("Remove it?")?;
    }
    let (r, notes) =
        actions_ui::remove_record(ws, fingerprint, record).map_err(anyhow::Error::msg)?;
    println!(
        "Removed record {} ({}) from {}. The removal is in its activity.",
        ui::safe(&r.record.id),
        ui::safe(&pathwarden_core::action_log::chip(&r.record, false)),
        ui::safe(fingerprint.trim())
    );
    for n in notes {
        println!("{}", ui::safe(&n));
    }
    Ok(ExitCode::SUCCESS)
}
