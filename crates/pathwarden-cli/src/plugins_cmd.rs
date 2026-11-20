//! `pathwarden plugins`: the Plugins and actions page from the terminal.
//! The forms' rules are core's (`pathwarden_core::plugin_form`): a
//! plugin added here is checked, refused and written exactly as the page's
//! Save does (`ConfigDoc::upsert_output`), and `test` is the page's Test, a
//! dry run on the latest analysis.
//!
//! One difference, on purpose: with `pathwarden ui --lock-destinations`
//! the page can't choose the program a plugin runs, so that a browser
//! session can't make Pathwarden run a program. From the terminal
//! you could edit pathwarden.toml anyway, so `add command` may name one
//! (never on a network path).

use std::path::PathBuf;

use anstream::println;
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use pathwarden_core::config::OutputConfig;
use pathwarden_core::plugin_form::{self, PluginForm, SN_PASSWORD, SN_USER};
use serde_json::Value;

use crate::config_cmd::{self, Target, Where};
use crate::{emit_json, ui};

#[derive(Args)]
pub(crate) struct PluginsArgs {
    #[command(flatten)]
    at: Where,
    #[command(subcommand)]
    action: PluginsAction,
}

// Parsed once per command, so Add's size (Jira's many options) doesn't matter.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum PluginsAction {
    /// The plugins, numbered for `remove` and `test`, with whether their
    /// program and environment variables are there.
    List {
        /// Print JSON instead of text.
        #[arg(long, display_order = 903)]
        json: bool,
    },
    /// Add a plugin.
    Add {
        #[command(subcommand)]
        kind: AddKind,
    },
    /// Remove a plugin by its number in `list`.
    Remove {
        /// The plugin's number in `list`.
        number: usize,
    },
    /// Run a plugin as a dry run on the latest analysis: it reports what it
    /// would do and changes nothing.
    Test {
        /// The plugin's number in `list`.
        number: usize,
        /// An event document (`pathwarden run --event`) instead of the
        /// environment's latest analysis.
        #[arg(long, value_name = "FILE")]
        event: Option<PathBuf>,
        /// Run a plugin that isn't shipped with Pathwarden: you checked that
        /// it honors dry_run (the app asks the same).
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum AddKind {
    /// ServiceNow: a ticket per finding; fixed findings resolve theirs.
    #[command(name = "servicenow")]
    ServiceNow {
        /// The instance URL, https://.
        #[arg(long, value_name = "URL")]
        instance: String,
        /// What to create: incident, or sc_req_item (requested items).
        #[arg(long, default_value = "incident")]
        table: String,
        /// Findings below this get no ticket (critical, high, medium, low,
        /// info).
        #[arg(long, value_name = "SEVERITY", default_value = "medium")]
        min_severity: String,
        /// Only when two deployments share one instance; changing it later
        /// orphans existing tickets.
        #[arg(long)]
        scope: Option<String>,
        /// Sign in with a bearer token held in this environment variable
        /// (instead of a user name and password).
        #[arg(long, value_name = "VAR", conflicts_with_all = ["username_env", "password_env"])]
        token_env: Option<String>,
        /// The environment variable holding the user name.
        #[arg(long, value_name = "VAR", default_value = SN_USER)]
        username_env: String,
        /// The environment variable holding the password.
        #[arg(long, value_name = "VAR", default_value = SN_PASSWORD)]
        password_env: String,
        /// A field on new tickets, e.g. assignment_group=Identity; repeatable.
        #[arg(long = "field", value_name = "NAME=VALUE", value_parser = key_value)]
        fields: Vec<(String, String)>,
        #[command(flatten)]
        limits: Limits,
    },
    /// Jira: an issue per finding; fixed findings close theirs.
    Jira {
        /// The instance URL, https://, like https://example.atlassian.net.
        #[arg(long, value_name = "URL")]
        instance: String,
        /// cloud, or data-center (Jira Data Center or Server).
        #[arg(long, value_name = "KIND", default_value = "cloud", value_parser = deployment)]
        deployment: String,
        /// The project key, like SEC.
        #[arg(long, value_name = "KEY")]
        project: String,
        /// The issue type for new issues, as it's named in the project.
        #[arg(long, value_name = "NAME", default_value = "Task")]
        issue_type: String,
        /// Findings below this get no issue (critical, high, medium, low,
        /// info).
        #[arg(long, value_name = "SEVERITY", default_value = "medium")]
        min_severity: String,
        /// Only when two deployments share one project; changing it later
        /// orphans existing issues.
        #[arg(long)]
        scope: Option<String>,
        /// Jira Data Center: sign in with a personal access token held in
        /// this environment variable (instead of a user name and password).
        #[arg(long, value_name = "VAR", conflicts_with_all = ["username_env", "token_env"])]
        pat_env: Option<String>,
        /// The environment variable holding the account's email (Cloud) or
        /// user name (Data Center).
        #[arg(long, value_name = "VAR", default_value = plugin_form::JIRA_USER)]
        username_env: String,
        /// The environment variable holding the API token (Cloud) or
        /// password (Data Center).
        #[arg(long, value_name = "VAR", default_value = plugin_form::JIRA_TOKEN)]
        token_env: String,
        /// Leave the priority to Jira instead of setting it from the
        /// severity (when Priority isn't on the project's create screen).
        #[arg(long)]
        no_priority: bool,
        /// When a closed issue's finding is still there: reopen, comment or
        /// ignore. Issues closed as Won't Do, Won't Fix, Duplicate or Risk
        /// Accepted are never reopened.
        #[arg(long, value_name = "ACTION", default_value = "reopen", value_parser = ["reopen", "comment", "ignore"])]
        on_closed_but_present: String,
        /// The transition that closes an issue (default: the first one to a
        /// Done status).
        #[arg(long, value_name = "NAME")]
        close_transition: Option<String>,
        /// The transition that reopens an issue (default: the first one to a
        /// To Do status).
        #[arg(long, value_name = "NAME")]
        reopen_transition: Option<String>,
        /// The resolution set when closing, for workflows whose close screen
        /// asks for one.
        #[arg(long, value_name = "NAME")]
        close_resolution: Option<String>,
        /// A field on new issues, e.g. components=[{"name": "Active
        /// Directory"}] (JSON or text); repeatable.
        #[arg(long = "field", value_name = "NAME=VALUE", value_parser = key_value)]
        fields: Vec<(String, String)>,
        #[command(flatten)]
        limits: Limits,
    },
    /// A script or program of your own; without a program, the plugin
    /// program pathwarden-output-NAME from the plugins folder.
    Command {
        /// The plugin's name: lowercase letters, digits and dashes.
        name: String,
        /// A setting passed to the plugin, e.g. webhook_env=TEAMS_WEBHOOK
        /// (secrets only by the name of an environment variable); repeatable.
        #[arg(long = "setting", value_name = "NAME=VALUE", value_parser = key_value)]
        settings: Vec<(String, String)>,
        /// The program and its arguments, after `--`: a full path, or
        /// powershell, pwsh, python, node, bash, sh or cmd.
        #[arg(last = true, value_name = "PROGRAM")]
        command: Vec<String>,
    },
}

/// The ticketing plugins' safety limits, as the forms' Safety limits.
#[derive(Args)]
struct Limits {
    /// A run that would open more tickets than this opens none of them and
    /// says why (default: 100).
    #[arg(long, value_name = "N")]
    max_create: Option<u32>,
    /// A run that would close more than this percentage of the open tickets
    /// closes none of them and says why (default: 50; 100 turns it off).
    #[arg(long, value_name = "PERCENT")]
    max_resolve_percent: Option<u32>,
}

/// `--deployment`: cloud, or data-center (data_center, as the settings
/// write it, works too).
fn deployment(s: &str) -> Result<String, String> {
    match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "cloud" => Ok("cloud".into()),
        "data-center" | "datacenter" | "server" => Ok("data_center".into()),
        _ => Err(format!("{s:?}: use cloud or data-center")),
    }
}

fn key_value(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) => Ok((k.trim().to_string(), v.to_string())),
        None => Err(format!("{s:?} is not NAME=VALUE")),
    }
}

/// The plugin numbered `number` in `list`.
fn numbered<'a>(
    t: &Target,
    outputs: &'a [OutputConfig],
    number: usize,
) -> Result<&'a OutputConfig> {
    match number.checked_sub(1).and_then(|i| outputs.get(i)) {
        Some(o) => Ok(o),
        None => bail!(
            "There is no plugin {number} in {} (see `pathwarden plugins list`).",
            t.label
        ),
    }
}

pub(crate) fn run(a: PluginsArgs) -> Result<()> {
    let t = config_cmd::target(&a.at)?;
    let config = config_cmd::load(&t.path)?;
    match a.action {
        PluginsAction::List { json } => {
            let outputs = &config.outputs;
            if json {
                let list: Vec<Value> = outputs
                    .iter()
                    .enumerate()
                    .map(|(i, o)| {
                        let (program, found) = plugin_form::program(o);
                        let env: Vec<Value> = plugin_form::env_names(o)
                            .iter()
                            .map(|n| serde_json::json!({ "name": n, "set": plugin_form::env_is_set(n) }))
                            .collect();
                        serde_json::json!({
                            "number": i + 1,
                            "plugin": o.plugin,
                            "kind": plugin_form::describe(o),
                            "program": program,
                            "found": found,
                            "env": env,
                        })
                    })
                    .collect();
                return emit_json(&list);
            }
            if outputs.is_empty() {
                println!(
                    "No plugins in {}. Scheduled runs keep their history either way; plugins only pass the results on.",
                    t.label
                );
                return Ok(());
            }
            let d = ui::DIM;
            println!("Plugins in {}:", t.label);
            for (i, o) in outputs.iter().enumerate() {
                let (program, found) = plugin_form::program(o);
                println!(
                    "  {}. {}  {d}{}{d:#}",
                    i + 1,
                    ui::safe(&o.plugin),
                    ui::safe(&plugin_form::describe(o))
                );
                println!(
                    "     {} {}{}",
                    if found { "ok" } else { "!" },
                    ui::safe(&program),
                    if found { "" } else { " (not found)" }
                );
                let env: Vec<String> = plugin_form::env_names(o)
                    .iter()
                    .map(|n| {
                        format!(
                            "{} {}",
                            ui::safe(n),
                            if plugin_form::env_is_set(n) {
                                "set"
                            } else {
                                "not set"
                            }
                        )
                    })
                    .collect();
                if !env.is_empty() {
                    println!("     {}", env.join(", "));
                }
            }
            println!(
                "\n{d}Environment variables are checked in this terminal's environment. `pathwarden plugins test N` runs one as a dry run.{d:#}"
            );
            Ok(())
        }
        PluginsAction::Add { kind } => {
            let form = match kind {
                AddKind::ServiceNow {
                    instance,
                    table,
                    min_severity,
                    scope,
                    token_env,
                    username_env,
                    password_env,
                    fields,
                    limits,
                } => PluginForm {
                    kind: "servicenow".into(),
                    instance,
                    table,
                    min_severity,
                    scope: scope.unwrap_or_default(),
                    auth: if token_env.is_some() {
                        "bearer"
                    } else {
                        "basic"
                    }
                    .into(),
                    username_env,
                    password_env,
                    token_env: token_env.unwrap_or_default(),
                    fields,
                    max_create: limits.max_create.map(|n| n.to_string()),
                    max_resolve_percent: limits.max_resolve_percent.map(|n| n.to_string()),
                    ..Default::default()
                },
                AddKind::Jira {
                    instance,
                    deployment,
                    project,
                    issue_type,
                    min_severity,
                    scope,
                    pat_env,
                    username_env,
                    token_env,
                    no_priority,
                    on_closed_but_present,
                    close_transition,
                    reopen_transition,
                    close_resolution,
                    fields,
                    limits,
                } => PluginForm {
                    kind: "jira".into(),
                    instance,
                    deployment,
                    project,
                    issue_type,
                    min_severity,
                    scope: scope.unwrap_or_default(),
                    auth: if pat_env.is_some() { "pat" } else { "basic" }.into(),
                    username_env,
                    token_env,
                    pat_env: pat_env.unwrap_or_default(),
                    set_priority: Some(!no_priority),
                    on_closed_but_present,
                    close_transition: close_transition.unwrap_or_default(),
                    reopen_transition: reopen_transition.unwrap_or_default(),
                    close_resolution: close_resolution.unwrap_or_default(),
                    fields,
                    max_create: limits.max_create.map(|n| n.to_string()),
                    max_resolve_percent: limits.max_resolve_percent.map(|n| n.to_string()),
                    ..Default::default()
                },
                AddKind::Command {
                    name,
                    settings,
                    command,
                } => PluginForm {
                    kind: "command".into(),
                    plugin: name,
                    command: (!command.is_empty()).then_some(command),
                    settings,
                    ..Default::default()
                },
            };
            let mut edit = form.edit(None).map_err(anyhow::Error::msg)?;
            plugin_form::check_command(true, &mut edit, None).map_err(anyhow::Error::msg)?;
            config_cmd::save(&t, |d| d.upsert_output(None, None, &edit))?;
            let number = config_cmd::load(&t.path)?.outputs.len();
            println!(
                "Saved: plugin {number}, {}, in {}. Each run (`pathwarden run`) uses it; `pathwarden plugins test {number}` tries it.",
                ui::safe(&edit.plugin),
                t.label
            );
            Ok(())
        }
        PluginsAction::Remove { number } => {
            let o = numbered(&t, &config.outputs, number)?;
            let name = o.plugin.clone();
            config_cmd::save(&t, |d| d.remove_output(number - 1, &name))?;
            println!(
                "Removed plugin {number}, {}, from {}.",
                ui::safe(&name),
                t.label
            );
            Ok(())
        }
        PluginsAction::Test { number, event, yes } => {
            let o = numbered(&t, &config.outputs, number)?;
            if !yes && plugin_form::test_needs_confirmation(o) {
                bail!(
                    "{} isn't shipped with Pathwarden. {} Add --yes to run it.",
                    ui::safe(&o.plugin),
                    plugin_form::TEST_CUSTOM
                );
            }
            let first_run = event.is_none();
            let (text, on) = match event {
                Some(path) => (
                    std::fs::read_to_string(&path)
                        .with_context(|| format!("reading {}", path.display()))?,
                    path.display().to_string(),
                ),
                None => {
                    // (The latest run's event is checked by event_text.)
                    let latest = t.ws.as_ref().and_then(|ws| {
                        pathwarden_ui::run_data::latest_with(
                            ws,
                            pathwarden_ui::run_data::EVENT_FILE,
                        )
                    });
                    let Some((run, dir)) = latest else {
                        bail!("Testing needs one analysis first. Analyze a collection or try the demo, or give --event FILE (from `pathwarden run --event`).");
                    };
                    let text = pathwarden_ui::run_data::event_text(&dir)
                        .context("The latest run's event could not be read.")?;
                    (
                        text,
                        format!(
                            "{}, analyzed {}",
                            run.environment(),
                            pathwarden_core::time::format_local(run.created_at)
                        ),
                    )
                }
            };
            // A newer Pathwarden's schema isn't sent as v1 (docs/dev/formats.md).
            if !pathwarden_core::event::readable(text.as_bytes()) {
                bail!("This event document was saved by a newer Pathwarden. Update Pathwarden to send it.");
            }
            println!(
                "Testing {} on {}: a dry run, which changes nothing.{}",
                ui::safe(&o.plugin),
                ui::safe(&on),
                if first_run {
                    " Every finding counts as new, as on a first scheduled run."
                } else {
                    ""
                }
            );
            let ran = plugin_form::dry_run(o, &text).map_err(anyhow::Error::msg)?;
            let tag = ui::VIOLET;
            for line in ran.output.lines() {
                println!("  {tag}[{}]{tag:#} {}", ui::safe(&o.plugin), ui::safe(line));
            }
            if !ran.ok {
                bail!("{} stopped with {}.", o.plugin, ran.status);
            }
            println!("Done: {}.", ran.status);
            Ok(())
        }
    }
}
