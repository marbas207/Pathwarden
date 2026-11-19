use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

mod action_cmd;
mod changes_cmd;
mod config_cmd;
mod demo;
mod diagnose_cmd;
mod evidence;
mod explore_cmd;
mod export_cmd;
mod guide_cmd;
mod help;
mod history_cmd;
mod interrupt;
mod logo;
mod logs_cmd;
mod mappings_cmd;
mod outputs;
mod owned_cmd;
mod passphrase;
mod plugins_cmd;
mod progress;
mod retest_cmd;
mod runs_cmd;
mod save_cmd;
mod schedule_cmd;
mod shell;
mod ui;
mod zones_cmd;

use progress::Through;

use anstream::{eprintln, print, println};
use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use pathwarden_core::analysis::{self, AttackPath};
use pathwarden_core::analyze::{self, Evaluated};
use pathwarden_core::config::Config;
use pathwarden_core::findings::{self, Category, Finding, Severity};
use pathwarden_core::graph::AdGraph;
use pathwarden_core::posture::{self, Posture, ZonePosture};
use pathwarden_core::remediation;
use pathwarden_core::store;
use pathwarden_core::text::{count, num};
use pathwarden_core::zones::{self, Zone};
use pathwarden_core::{IngestStats, NodeIndex};
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "pathwarden",
    version,
    // The banner carries the name and tagline; the long help (--help) adds a
    // short description under it, the short help (-h, bare run) nothing.
    // Wrapped by hand to 80 columns (clap doesn't wrap without `wrap_help`).
    long_about = concat!(
        "Pathwarden reads BloodHound collector data (SharpHound, RustHound-CE,\n",
        "AzureHound), finds the attack paths to Tier Zero, ranks the findings, and\n",
        "plans the fewest changes that cut them.\n\n",
        "https://github.com/marbas207/Pathwarden"
    )
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Args)]
struct Input {
    /// Collector output: .json files, .zip archives, or folders containing
    /// them; `demo:` for the built-in demo collection; `run:ID` for the raw
    /// collection a saved run kept.
    #[arg(short, long = "input", required = true, num_args = 1..)]
    input: Vec<PathBuf>,
    /// An extra object (ID or name) to treat as Tier Zero; repeatable.
    #[arg(long = "tier-zero", value_name = "ID_OR_NAME")]
    tier_zero: Vec<String>,
    /// The settings (pathwarden.toml): Tier Zero additions, rule settings
    /// and accepted risks.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
    #[command(flatten)]
    env: EnvArgs,
    /// Print JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Show progress as plain lines on stderr even when it isn't a terminal
    /// (on a terminal it is always shown, live).
    #[arg(short, long)]
    verbose: bool,
}

/// `--env NAME`: an environment of the UI workspace (docs/running.md,
/// "Environments"). Its `pathwarden.toml` stands in for `--config`, and its
/// run history for `--state` (run, retest, evidence, history; `report`
/// reads it for the Overview's trend).
#[derive(Args, Default, Clone)]
pub(crate) struct EnvArgs {
    /// Use an environment of the app's workspace (its name or ID): its
    /// settings (pathwarden.toml) and its run history.
    #[arg(long, value_name = "NAME", conflicts_with = "config")]
    env: Option<String>,
    /// The app's workspace (default: the one `pathwarden ui` uses); alone,
    /// its current environment, as with --env.
    #[arg(long = "workspace", value_name = "DIR")]
    env_workspace: Option<PathBuf>,
}

impl EnvArgs {
    /// `--workspace` alone picks that workspace's current environment (as
    /// `history` and `runs list` do), so it can't go with `-c`, which
    /// names the settings itself.
    fn check(&self, config: Option<&std::path::Path>) -> Result<()> {
        if self.env_workspace.is_some() && self.env.is_none() && config.is_some() {
            bail!("--workspace goes with --env, not with -c: -c names the settings itself.");
        }
        Ok(())
    }

    /// The environment's config and history folder, when `--env` (or
    /// `--workspace` alone, for its current environment) is given.
    fn resolve(&self) -> Result<Option<pathwarden_ui::environments::EnvPaths>> {
        match (&self.env, &self.env_workspace) {
            (Some(name), ws) => Ok(Some(pathwarden_ui::environments::cli_paths(
                ws.as_deref(),
                name,
            )?)),
            (None, Some(ws)) => Ok(Some(pathwarden_ui::environments::cli_paths_current(ws)?)),
            (None, None) => Ok(None),
        }
    }
}

/// `pathwarden ui`: the UI's own options, and `--window` / `--no-window` in
/// builds with the `desktop` feature.
#[derive(Args)]
struct UiCommand {
    #[command(flatten)]
    args: pathwarden_ui::UiArgs,
    /// Open Pathwarden in its own window with no network port (the default
    /// on Windows desktops; needs the WebView2 Runtime, else the browser).
    #[cfg(feature = "desktop")]
    #[arg(long, conflicts_with_all = ["port", "no_browser", "browser", "no_window"])]
    window: bool,
    /// Use the browser instead of the window (as on servers and over SSH).
    #[cfg(feature = "desktop")]
    #[arg(long)]
    no_window: bool,
    /// This build has no window: Pathwarden opens in the browser (taken,
    /// so a script written for the full build works).
    #[cfg(not(feature = "desktop"))]
    #[arg(long, hide = true, conflicts_with = "no_window")]
    window: bool,
    /// Use the browser (this build always does).
    #[cfg(not(feature = "desktop"))]
    #[arg(long, hide = true)]
    no_window: bool,
}

impl UiCommand {
    /// Whether to open the desktop window: asked for, or the default on
    /// this computer when nothing asks for the browser (`--no-window`,
    /// `--browser`, `--no-browser` or `--port`).
    #[cfg(feature = "desktop")]
    fn wants_window(&self) -> bool {
        let browser_asked = self.no_window
            || self.args.browser.is_some()
            || self.args.no_browser
            || self.args.port.is_some();
        self.window || (!browser_asked && pathwarden_desktop::window_by_default())
    }
}

/// Exit codes, the same in every command (docs/running.md).
pub(crate) mod exit {
    /// Done; nothing at or above the threshold, everything retested is fixed.
    pub const OK: u8 = 0;
    /// Findings at or above `--fail-on`, or findings still open after a retest.
    pub const FINDINGS: u8 = 1;
    /// A usage error (clap's own) or a runtime error.
    pub const ERROR: u8 = 2;
    /// Nothing open, but some findings can't be told (domain not collected).
    pub const CANT_TELL: u8 = 3;
    /// `collect`: some domains of the run weren't collected; the others
    /// were (and with `--save`, analyzed and saved).
    pub const SOME_NOT_COLLECTED: u8 = 3;
}

#[derive(Subcommand)]
enum Command {
    /// Try Pathwarden on a built-in sample domain: write a report and see what
    /// to run next.
    Demo {
        /// Where to write the report (default: a new folder in the temp folder).
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Show progress as plain lines on stderr even when it isn't a terminal.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Show what was read: objects, relationships, domains and trusts.
    #[command(
        mut_arg("input", |a| a.required(false)),
        after_help = "Without -i it shows the domains and trusts of a run saved in the app's workspace, \
as the app's API returns them (/api/runs/<id>/explore/forest): --run ID, or the latest run of --env NAME \
(--workspace DIR for another workspace)."
    )]
    Summary {
        #[command(flatten)]
        input: Input,
        /// A run saved in the workspace (its ID as the run list or `pathwarden
        /// run` shows it) instead of -i: its domains and trusts.
        #[arg(long, value_name = "RUN", conflicts_with_all = ["input", "config", "tier_zero"])]
        run: Option<String>,
        /// List each right that crosses a trust (up to 100 of each pair of
        /// domains, shared out between the kinds), as the app's Forest
        /// view shows them.
        #[arg(long)]
        rights: bool,
    },
    /// List Tier Zero objects and why each one is Tier Zero.
    TierZero(Input),
    /// How many accounts in each domain have an attack path to Tier Zero (or
    /// a zone).
    #[command(
        after_help = "For a run saved in the app's workspace, `pathwarden runs show ID` shows its exposure, findings and plan steps, as its page does."
    )]
    Exposure {
        #[command(flatten)]
        input: Input,
        /// How many example attack paths to show.
        #[arg(long, value_name = "N", default_value_t = 10)]
        samples: usize,
        /// A Privilege Zone of the settings, instead of Tier Zero.
        #[arg(long, value_name = "NAME")]
        zone: Option<String>,
    },
    /// Run a Cypher query over the graph (preview: a subset of BloodHound
    /// CE's).
    #[command(
        mut_arg("input", |a| a.required(false)),
        after_help = "Without -i it queries a run saved in the app's workspace, as its Explore page \
does: --run ID, or the latest run of --env NAME (--workspace DIR for another workspace). \
A saved run answers from the fields the analysis keeps, not every collector property, and \
Tag_Owned is what `pathwarden owned` marks in its environment.

Prepared queries are the BloodHound Query Library's (a pinned copy, © 2025 SpecterOps, \
MIT License), the same list as the Explore page's: --list-prepared lists them, --prepared \
runs one by its name or GUID, --show-prepared prints its Cypher to edit."
    )]
    Query {
        #[command(flatten)]
        input: Input,
        /// The Cypher query, before -i: one MATCH of nodes and typed
        /// relationships (variable-length, shortestPath(), allShortestPaths(),
        /// p = paths, AD_ATTACK_PATHS), optional WHERE, RETURN nodes and paths
        /// (DISTINCT, LIMIT). Property returns, WITH and ORDER BY aren't
        /// supported yet.
        #[arg(required_unless_present_any = ["prepared", "list_prepared", "show_prepared"])]
        cypher: Option<String>,
        /// Run a prepared query instead: its name (any case), its GUID, or
        /// the GUID's first 8 or more characters.
        #[arg(long, value_name = "NAME_OR_GUID", conflicts_with_all = ["cypher", "list_prepared", "show_prepared"])]
        prepared: Option<String>,
        /// List the prepared queries, by category.
        #[arg(long, conflicts_with_all = ["cypher", "show_prepared", "run", "owned"])]
        list_prepared: bool,
        /// Print a prepared query's Cypher, to copy and edit.
        #[arg(long, value_name = "NAME_OR_GUID", conflicts_with_all = ["cypher", "run", "owned"])]
        show_prepared: Option<String>,
        /// A run saved in the workspace (its ID as the run list or `pathwarden
        /// run` shows it) instead of -i.
        #[arg(long, value_name = "RUN", conflicts_with_all = ["input", "config", "tier_zero"])]
        run: Option<String>,
        /// Stop after this many result rows.
        #[arg(long, value_name = "N", default_value_t = 100_000)]
        limit: usize,
        /// How long the query may run, in seconds.
        #[arg(long = "timeout", value_name = "SECONDS", default_value_t = 10)]
        timeout_secs: u64,
        /// Also treat this object as owned (name, short name, or object ID),
        /// for Tag_Owned; repeatable. `pathwarden owned` keeps marks.
        #[arg(long, value_name = "OBJECT")]
        owned: Vec<String>,
    },
    /// Objects marked as owned in an environment (Tag_Owned in queries), as
    /// the Object tab's "Mark as owned" on the app's Explore page.
    Owned {
        #[command(subcommand)]
        action: owned_cmd::OwnedAction,
    },
    /// The shortest attack path from one object to another, or to Tier Zero.
    #[command(
        mut_arg("input", |a| a.required(false)),
        after_help = "Without -i it answers from a run saved in the app's workspace, as its Explore \
page's Path between does: --run ID, or the latest run of --env NAME (--workspace DIR for another \
workspace)."
    )]
    Path {
        #[command(flatten)]
        input: Input,
        /// A run saved in the workspace (its ID as the run list or `pathwarden
        /// run` shows it) instead of -i.
        #[arg(long, value_name = "RUN", conflicts_with_all = ["input", "config", "tier_zero"])]
        run: Option<String>,
        /// The starting object (name, short name, or object ID).
        #[arg(long, value_name = "OBJECT")]
        from: String,
        /// The target object (default: any Tier Zero object).
        #[arg(long, value_name = "OBJECT")]
        to: Option<String>,
    },
    /// Who can reach an object: everything with an attack path to it,
    /// unprivileged users and computers first.
    #[command(
        mut_arg("input", |a| a.required(false)),
        after_help = "Without -i it answers from a run saved in the app's workspace, as its Explore \
page does: --run ID, or the latest run of --env NAME (--workspace DIR for another workspace)."
    )]
    Reach {
        #[command(flatten)]
        input: Input,
        /// The object (name, short name, or object ID), before -i.
        object: String,
        /// A run saved in the workspace (its ID as the run list or `pathwarden
        /// run` shows it) instead of -i.
        #[arg(long, value_name = "RUN", conflicts_with_all = ["input", "config", "tier_zero"])]
        run: Option<String>,
        /// Only one group of them.
        #[arg(long, value_enum)]
        class: Option<explore_cmd::ReachClass>,
        /// How many to list
        #[arg(long, value_name = "N", default_value_t = 25, value_parser = clap::builder::TypedValueParser::map(clap::value_parser!(u64).range(1..), |v| v as usize))]
        top: usize,
    },
    /// Find objects by name, distinguished name or ID (the Explore page's
    /// search).
    #[command(
        mut_arg("input", |a| a.required(false)),
        after_help = "Without -i it searches a run saved in the app's workspace, as its Explore page \
does: --run ID, or the latest run of --env NAME (--workspace DIR for another workspace)."
    )]
    Search {
        #[command(flatten)]
        input: Input,
        /// What to look for, before -i.
        text: String,
        /// A run saved in the workspace (its ID as the run list or `pathwarden
        /// run` shows it) instead of -i.
        #[arg(long, value_name = "RUN", conflicts_with_all = ["input", "config", "tier_zero"])]
        run: Option<String>,
        /// Only objects of this kind, e.g. User, Computer, Group; repeatable.
        #[arg(long, value_name = "KIND")]
        kind: Vec<String>,
        /// How many to list
        #[arg(long, value_name = "N", default_value_t = 20, value_parser = clap::builder::TypedValueParser::map(clap::value_parser!(u64).range(1..), |v| v as usize))]
        top: usize,
    },
    /// Privilege Zones: list, add, change and preview them (the app's
    /// Privilege Zones page), or get suggestions from the data.
    Zones {
        #[command(subcommand)]
        action: zones_cmd::ZonesAction,
    },
    /// The relationships that, removed, cut the most accounts off from Tier
    /// Zero.
    ChokePoints {
        #[command(flatten)]
        input: Input,
        /// How many to list.
        #[arg(long, value_name = "N", default_value_t = 10, value_parser = clap::builder::TypedValueParser::map(clap::value_parser!(u64).range(1..), |v| v as usize))]
        top: usize,
    },
    /// Run every rule and list the findings, each with its fix.
    #[command(group = clap::ArgGroup::new("period").args(["introduced", "since"]))]
    Findings {
        #[command(flatten)]
        input: Input,
        /// Hide findings below this severity (info, low, medium, high,
        /// critical).
        #[arg(long, value_name = "SEVERITY", default_value = "info")]
        min_severity: Severity,
        /// Only show one category (attack-path, hygiene).
        #[arg(long)]
        category: Option<Category>,
        /// Only show findings of this rule, e.g. PW-003; repeatable.
        #[arg(long = "rule", value_name = "RULE")]
        rules: Vec<String>,
        /// Also list accepted risks.
        #[arg(long = "show-accepted", alias = "show-suppressed")]
        show_suppressed: bool,
        /// Exit with status 1 if a selected finding (not an accepted risk) is
        /// at least this severe.
        #[arg(long, value_name = "SEVERITY")]
        fail_on: Option<Severity>,
        /// Group the findings by the plan step that closes them or cuts their
        /// attack path, then those no step reaches.
        #[arg(long, conflicts_with_all = ["introduced", "since"])]
        by_fix: bool,
        /// Only the findings introduced in a period (first seen by
        /// Pathwarden), from the run history: last (the last run), 7d, 2w,
        /// 1m, 3m, all, a day (YYYY-MM-DD, from then on) or two
        /// (YYYY-MM-DD..YYYY-MM-DD). Each gets its badge
        /// (New, Back, +N objects); the objects it gained come first.
        #[arg(long, value_name = "PERIOD", value_parser = changes_cmd::parse_period, conflicts_with = "since")]
        introduced: Option<pathwarden_core::introduced::Period>,
        /// Only the findings introduced since a day (YYYY-MM-DD), as
        /// --introduced.
        #[arg(long, value_name = "YYYY-MM-DD", value_parser = changes_cmd::parse_day)]
        since: Option<pathwarden_core::introduced::Period>,
        /// The run history folder --introduced reads (overrides [state] path
        /// in the settings).
        #[arg(long, value_name = "DIR", requires = "period")]
        state: Option<PathBuf>,
    },
    /// The remediation path: the fewest plan steps that cut every account off
    /// from Tier Zero.
    #[command(
        after_help = "For a run saved in the app's workspace, `pathwarden runs show ID` shows its exposure, findings and plan steps, as its page does."
    )]
    Plan {
        #[command(flatten)]
        input: Input,
        /// A Privilege Zone of the settings, instead of Tier Zero (the plan
        /// protects Tier Zero too).
        #[arg(long, value_name = "NAME")]
        zone: Option<String>,
        /// Don't run the rules to list the findings the plan leaves (faster
        /// on very large data).
        #[arg(long)]
        no_findings: bool,
        /// Show only the first N plan steps (the summary still counts them
        /// all; --json always has every one).
        #[arg(long, value_name = "N", value_parser = clap::builder::TypedValueParser::map(clap::value_parser!(u64).range(1..), |v| v as usize))]
        top: Option<usize>,
    },
    /// Tier Zero status, exposure, the share of Tier Zero protected, findings
    /// by category, and collection completeness.
    #[command(
        after_help = "For a run saved in the app's workspace, `pathwarden runs show ID` shows its exposure, findings and plan steps, as its page does."
    )]
    Posture(Input),
    /// Open the app: collect or upload data, analyze, and browse reports.
    Ui(UiCommand),
    /// Collect Active Directory data (BloodHound-compatible JSON) to analyze.
    Collect(CollectCommand),
    /// Where a saved run's collection time went, compared with the last run;
    /// --bundle writes a zip that is safe to share.
    Diagnose(diagnose_cmd::DiagnoseArgs),
    /// This computer's logs and crash reports: the latest jobs, the latest
    /// job's last lines, the latest crash report.
    Logs(logs_cmd::LogsArgs),
    /// Analyze a collection and record it in the run history: sync, analyze,
    /// record what changed, run the output plugins, push.
    Run {
        #[command(flatten)]
        input: Input,
        /// Save the run in the app's workspace as the app does: its report on the
        /// Runs page, in the environment its domains match (or --env /
        /// --new-env); stops with status 2 when that needs a choice.
        #[arg(long, conflicts_with_all = ["state", "event", "no_push", "accept_shrink", "no_outputs", "config"])]
        save: bool,
        /// With --save: a new environment for this run, named NAME.
        #[arg(long, value_name = "NAME", requires = "save", conflicts_with = "env")]
        new_env: Option<String>,
        /// What this run was ("after GPO fix"), up to 60 characters: shown in
        /// the run list, history and report title.
        #[arg(long, value_name = "TEXT")]
        label: Option<String>,
        /// The run history folder (overrides [state] path in the settings).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
        /// Write the event document (all findings with their changes) for
        /// plugins.
        #[arg(long, value_name = "FILE")]
        event: Option<PathBuf>,
        /// Also write the HTML report.
        #[arg(long, value_name = "FILE")]
        report: Option<PathBuf>,
        /// Record the run here, but don't push it.
        #[arg(long)]
        no_push: bool,
        /// Don't run the output plugins ([[output]] in the settings).
        #[arg(long)]
        no_outputs: bool,
        /// Mark findings fixed even if this collection is much smaller than
        /// the last.
        #[arg(long)]
        accept_shrink: bool,
        /// Exit with status 1 if an open finding (not an accepted risk) is at
        /// least this severe (the run is recorded first).
        #[arg(long, value_name = "SEVERITY")]
        fail_on: Option<Severity>,
    },
    /// Retest findings after remediation: compare a new collection with the
    /// last run or an earlier one.
    #[command(
        after_help = "Exit status: 0 every retested finding is fixed, 1 some are still open, 2 error, 3 none open, but Pathwarden can't tell for some (domain not collected).",
        subcommand_negates_reqs = true,
        args_conflicts_with_subcommands = true
    )]
    Retest {
        #[command(subcommand)]
        action: Option<retest_cmd::RetestAction>,
        #[command(flatten)]
        input: Input,
        /// Compare with this earlier collection (.zip, .json, folder) or
        /// event document (`run --event`) instead of the run history.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["state", "record"])]
        baseline: Option<PathBuf>,
        /// The run history folder to compare with (overrides [state] path in
        /// the settings).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
        /// Only retest this finding (its ID, e.g. PW-003-39f2ede7c479090b);
        /// repeatable.
        #[arg(long = "finding", value_name = "FINDING_ID")]
        findings: Vec<String>,
        /// Only retest findings of this rule, e.g. PW-003; repeatable.
        #[arg(long = "rule", value_name = "RULE")]
        rules: Vec<String>,
        /// Also record this collection as a run in the run history, as
        /// `pathwarden run` does (no event, report or plugins).
        #[arg(long)]
        record: bool,
        /// With --record: record the run here, but don't push it.
        #[arg(long, requires = "record")]
        no_push: bool,
        /// With --record: what this run was, up to 60 characters.
        #[arg(long, value_name = "TEXT", requires = "record")]
        label: Option<String>,
    },
    /// Write a signed evidence pack for auditors: retest verdicts, history
    /// and hashes.
    #[command(mut_arg("input", |a| a.required(false).required_unless_present("run")))]
    Evidence(evidence::EvidenceArgs),
    /// The run history: what changed since the last run, progress run by
    /// run, where the history is kept, and importing the app's runs.
    #[command(args_conflicts_with_subcommands = true)]
    History {
        #[command(subcommand)]
        action: Option<history_cmd::HistoryAction>,
        /// The run history folder (overrides [state] path in the settings).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
        /// The settings (pathwarden.toml) with the [state] section.
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
        #[command(flatten)]
        env: EnvArgs,
        /// Only the most recent N runs.
        #[arg(long, value_name = "N")]
        last: Option<usize>,
        /// Only the runs of the last week, month or three months up to the
        /// latest run (1w, 1m, 3m or all, the periods of `changes --since`
        /// the app's Progress switch has).
        #[arg(long, value_name = "RANGE", value_parser = parse_range)]
        range: Option<pathwarden_core::history::Range>,
        /// Only what changed since the last run (with --json: the comparison
        /// and its lines, as the app's /api/history/since returns them).
        /// `--since` is the same (its name before 1.0).
        #[arg(long = "changes", alias = "since", conflicts_with_all = ["last", "range"])]
        since: bool,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
        /// With --json: an object of the runs ("runs", the list --json prints
        /// alone) and what changed since the last run ("since", as
        /// --changes --json prints it; null with one run).
        #[arg(long, requires = "json", conflicts_with = "since")]
        with_since: bool,
        /// Remove a run (its ID as this command prints it) from the run
        /// history, so trends stop showing it, and with --env its saved
        /// report too, as Delete does in the app. What the run recorded
        /// about each finding stays.
        #[arg(long, value_name = "RUN", conflicts_with_all = ["last", "range", "json", "since"])]
        forget: Option<String>,
    },
    /// The app's Runs list and run pages: every run of an environment, one
    /// run's numbers and findings, and its report.
    Runs {
        #[command(subcommand)]
        action: runs_cmd::RunsAction,
    },
    /// What is net new over a period: new findings, findings back after a
    /// fix, findings that gained objects, new paths into Tier Zero and the
    /// zones, and what was fixed (the app's Introduced filter).
    #[command(
        mut_arg("input", |a| a.required(false)),
        after_help = "\"Introduced\" means first seen by Pathwarden: each change carries the date of the run \
that found it, not when it was made in the directory. Read from the run history (--state, --env, \
or the [state] in -c). With -i (the collection the latest run read) the objects and paths are \
named, and each path gets the remediation step that cuts it; --paths lists every new member and \
path, not only the first three. A path or member back within a year of leaving is listed as back, \
not new, and does not fail --fail-on new."
    )]
    Changes {
        #[command(flatten)]
        input: Input,
        /// The period: last (the last run), 7d, 2w, 1m, 3m, all, a day
        /// (YYYY-MM-DD, from then on) or two (YYYY-MM-DD..YYYY-MM-DD).
        #[arg(long, value_name = "PERIOD", default_value = "last", value_parser = changes_cmd::parse_period)]
        since: pathwarden_core::introduced::Period,
        /// The run history folder (overrides [state] path in the settings).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
        /// Exit with status 1 when the period has something new: `new`
        /// (a new or returning finding, objects gained, a new path or a new
        /// member of Tier Zero or a zone), or a severity (a new, returning
        /// or grown finding at least that severe).
        #[arg(long, value_name = "new|SEVERITY", value_parser = changes_cmd::parse_fail_on)]
        fail_on: Option<changes_cmd::FailOn>,
        /// After the lines, every new member of Tier Zero and the zones and
        /// every new path into them, one a line, each path with the plan
        /// step that cuts it (the report's "New in Tier Zero and the
        /// zones"); needs -i to name them.
        #[arg(long, requires = "input")]
        paths: bool,
    },
    /// Settings from the terminal: Tier Zero additions, rule settings and
    /// accepted risks (the app's Settings page).
    Config(config_cmd::ConfigArgs),
    /// OpenGraph mapping packs: list them, mark a reviewed one trusted (the
    /// app's Mappings page).
    Mappings(mappings_cmd::MappingsArgs),
    /// Output plugins that run after each run: ServiceNow, Jira, your own script;
    /// add, remove, test (the app's Plugins and actions page).
    Plugins(plugins_cmd::PluginsArgs),
    /// Finding actions: your own program for one finding, run when you ask
    /// (open a ticket, alert a team); list, run, add, remove, test, and
    /// request and check for writing one.
    Action(action_cmd::ActionArgs),
    /// The environments of the app's workspace: list, create, set domains,
    /// use, rename or remove them.
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },
    /// Set or remove a run's label, by the ID the run list or history shows.
    Label {
        /// The run: its ID as `pathwarden history` prints it, or its folder
        /// ID.
        #[arg(value_name = "RUN")]
        run: String,
        /// The label, up to 60 characters.
        #[arg(required_unless_present = "clear")]
        text: Option<String>,
        /// Remove the label.
        #[arg(long, conflicts_with = "text")]
        clear: bool,
        /// Only look in this environment of the app's workspace (its name or
        /// ID).
        #[arg(long, value_name = "NAME")]
        env: Option<String>,
        /// The app's workspace (default: the one `pathwarden ui` uses).
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },
    /// Write a self-contained HTML report: posture, plan, findings and
    /// guides.
    Report {
        #[command(flatten)]
        input: Input,
        /// Where to write the report.
        #[arg(
            short,
            long,
            value_name = "FILE",
            default_value = "pathwarden-report.html"
        )]
        output: PathBuf,
        /// The run history folder that gives the Overview its trend and what
        /// changed since the last run (default: the --env environment's; none
        /// without either).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
    },
    /// Export findings as SARIF 2.1.0 or DefectDojo Generic Findings Import
    /// JSON.
    Export(export_cmd::ExportArgs),
    /// Write the scripts to collect and analyze every night (Task Scheduler
    /// or systemd).
    Schedule(schedule_cmd::ScheduleArgs),
    /// List the rules: on or off, and each one's severity (set in Settings, or
    /// its default by how attack paths are rated).
    Rules {
        #[command(flatten)]
        at: config_cmd::WhereLocal,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Show the step-by-step remediation guide for a rule, e.g. PW-015.
    Guide {
        /// The rule's ID.
        rule: String,
        /// Print the guide's Markdown source instead of plain text.
        #[arg(long, conflicts_with = "json")]
        markdown: bool,
        /// Print JSON (the Markdown and the plain text) instead.
        #[arg(long)]
        json: bool,
    },
}

/// `pathwarden env`: what the app's Environments page shows, renames and removes.
#[derive(Subcommand)]
enum EnvAction {
    /// List the environments: name, ID, domains, runs and folder.
    List {
        /// The app's workspace (default: the one `pathwarden ui` uses).
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Create an environment, as "New environment" in the app does; with
    /// --from-git or --from-folder, for a shared history teammates or a
    /// server already record (the app's Connect to a run history).
    Create {
        /// Its name, up to 60 characters (with --from-git or --from-folder,
        /// default: the shared history's own).
        #[arg(required_unless_present_any = ["from_git", "from_folder", "name_flag"])]
        name: Option<String>,
        /// The same as the name above (kept for scripts; not in --help).
        #[arg(
            long = "name",
            value_name = "NAME",
            conflicts_with = "name",
            hide = true
        )]
        name_flag: Option<String>,
        /// Its domains, e.g. "scale.local, emea.scale.local" (commas, spaces
        /// or new lines between them).
        #[arg(long, value_name = "DOMAINS", default_value = "", hide_default_value = true, conflicts_with_all = ["from_git", "from_folder"])]
        domains: String,
        /// Copy the settings (pathwarden.toml) of this environment.
        #[arg(long, value_name = "ENV", conflicts_with_all = ["from_git", "from_folder"])]
        copy_from: Option<String>,
        /// Connect it to the shared history in this git repository: it
        /// adopts what the history keeps and its encryption, then syncs (an
        /// encrypted one needs its passphrase: typed at a terminal, or
        /// PATHWARDEN_HISTORY_PASSPHRASE).
        #[arg(long, value_name = "URL", conflicts_with = "from_folder")]
        from_git: Option<String>,
        /// Connect it to the shared history in this folder.
        #[arg(long, value_name = "DIR")]
        from_folder: Option<PathBuf>,
        /// With --from-git: the branch (default: the repository's default
        /// branch).
        #[arg(long, value_name = "BRANCH", requires = "from_git")]
        branch: Option<String>,
        #[command(flatten)]
        how: history_cmd::ConnectHow,
        /// Make it the environment the app opens in.
        #[arg(long = "use")]
        make_current: bool,
        /// The app's workspace (default: the one `pathwarden ui` uses).
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },
    /// Set an environment's domains (they replace the current list).
    Domains {
        /// The environment (its name, the name it shows as, or its ID).
        env: String,
        /// The domains, e.g. "scale.local, emea.scale.local".
        domains: String,
        /// The app's workspace (default: the one `pathwarden ui` uses).
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },
    /// Make an environment the one the app opens in, and the default for
    /// `pathwarden config` and `history`.
    Use {
        /// The environment (its name, the name it shows as, or its ID).
        env: String,
        /// The app's workspace (default: the one `pathwarden ui` uses).
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },
    /// Rename an environment.
    Rename {
        /// The environment to rename (its name, the name it shows as, or its
        /// ID).
        env: String,
        /// Its new name, up to 60 characters.
        name: String,
        /// The app's workspace (default: the one `pathwarden ui` uses).
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },
    /// Remove an environment with its runs, settings and history (moved to
    /// environments/removed in the workspace, not deleted).
    Remove {
        /// The environment to remove (its name, the name it shows as, or its
        /// ID).
        env: String,
        /// Don't ask first (needed when not run on a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// The first environment's run history folder, as `pathwarden ui
        /// --state DIR` gives it (pass the same folder so this plans as the
        /// app would).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
        /// The app's workspace (default: the one `pathwarden ui` uses).
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },
}

/// `pathwarden collect`, and with `--save` the rest of what the app does:
/// analyze and save the run to an environment.
#[derive(Args)]
struct CollectCommand {
    #[command(flatten)]
    args: pathwarden_collect::CollectArgs,
    /// Also analyze and save the run in the app's workspace, as the app
    /// does: in the environment the domain matches (or --env / --new-env);
    /// stops before collecting when that needs a choice.
    #[arg(long)]
    save: bool,
    /// With --save: what this run was, up to 60 characters.
    #[arg(long, value_name = "TEXT", requires = "save")]
    label: Option<String>,
    /// With --save: save to this environment (its name or ID).
    #[arg(long, value_name = "NAME", requires = "save")]
    env: Option<String>,
    /// With --save: a new environment for this run, named NAME.
    #[arg(long, value_name = "NAME", requires = "save", conflicts_with = "env")]
    new_env: Option<String>,
    /// With --save or --trusted: the app's workspace (default: the one
    /// `pathwarden ui` uses).
    #[arg(long = "workspace", value_name = "DIR")]
    workspace: Option<PathBuf>,
    /// Also collect the trusted domains the domain's last run in the app's
    /// workspace says this account can read (the ones the app's Collect
    /// page ticks), in the same run.
    #[arg(long)]
    trusted: bool,
    /// Collect several domains without asking first.
    #[arg(long, short = 'y')]
    yes: bool,
    /// The settings (pathwarden.toml) whose `[collect]` section applies
    /// (default: with --save, the environment's).
    #[arg(long, short = 'c', value_name = "FILE")]
    config: Option<PathBuf>,
}

/// `[collect] service_reads` and `task_reads` from `--config`, else (with
/// `--save`) the environment's pathwarden.toml, applied to
/// `--no-service-reads` and `--no-task-reads`.
fn apply_collect_config(
    c: &mut CollectCommand,
    env_ws: Option<&pathwarden_ui::workspace::Workspace>,
) -> Result<()> {
    // `--service-reads` and `--task-reads` win over the file, as the app's
    // options do.
    if c.args.service_reads && c.args.task_reads {
        return Ok(());
    }
    let config = match &c.config {
        Some(path) => {
            let config = Config::from_file(path)?;
            warn_config(&config);
            Some(config)
        }
        None => None,
    };
    if !c.args.service_reads {
        c.args.no_service_reads = match &config {
            Some(config) => !config.collect.service_reads(c.args.no_service_reads),
            None => !pathwarden_ui::collect::service_reads_in(env_ws, !c.args.no_service_reads),
        };
    }
    if !c.args.task_reads {
        c.args.no_task_reads = match &config {
            Some(config) => !config.collect.task_reads(c.args.no_task_reads),
            None => !pathwarden_ui::collect::task_reads_in(env_ws, !c.args.no_task_reads),
        };
    }
    Ok(())
}

/// The command line, with the grouped top-level help.
fn cli_command() -> clap::Command {
    help::apply(help::polish(Cli::command()))
        .bin_name("pathwarden")
        .styles(ui::help_styles())
}

/// `--range`: 1w, 1m, 3m or all ([`pathwarden_core::history::Range`]).
fn parse_range(s: &str) -> std::result::Result<pathwarden_core::history::Range, String> {
    pathwarden_core::history::Range::parse(s)
        .ok_or_else(|| format!("{s:?} is not a range: use 1w, 1m, 3m or all"))
}

fn main() -> ExitCode {
    // First, before any thread: the history passphrase variables leave the
    // environment, so nothing started from here inherits them.
    pathwarden_core::keystore::take_env();
    // A panic writes a crash report to the logs folder.
    pathwarden_core::logs::install_crash_hook(pathwarden_ui::diagnose::system_info().os);
    let mut command = cli_command().before_help(ui::banner());
    // clap exits with 2 on a usage error, 0 for --help and --version.
    let matches = command.clone().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    // Double-clicked in Explorer (desktop builds): open the UI, as
    // `pathwarden ui` would, instead of help in a console that closes.
    #[cfg(feature = "desktop")]
    let cli = match cli.command {
        None if pathwarden_desktop::started_from_explorer() => {
            Cli::try_parse_from(["pathwarden", "ui"]).unwrap_or_else(|e| e.exit())
        }
        _ => cli,
    };
    let Some(cmd) = cli.command else {
        // Bare `pathwarden`: banner and command list, not an error.
        let help = command.render_help();
        print!("{}", help.ansi());
        return ExitCode::SUCCESS;
    };
    match run(cmd) {
        Ok(code) => code,
        Err(e) => {
            let red = ui::severity(Severity::Critical);
            // Errors can quote names and file contents.
            eprintln!(
                "{red}error:{red:#} {}",
                ui::safe_text(&as_sentence(&error_text(&e)))
            );
            ExitCode::from(exit::ERROR)
        }
    }
}

/// An error's text as a sentence: a capital first letter (unless it opens
/// with a flag, a quote or a path) and a closing period on its first line
/// when it has none (later lines are hints, already sentences).
pub(crate) fn as_sentence(text: &str) -> String {
    let (first, rest) = match text.find('\n') {
        Some(i) => text.split_at(i),
        None => (text, ""),
    };
    let mut out = String::with_capacity(text.len() + 1);
    let mut chars = first.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() && opens_with_a_word(first) => {
            out.push(c.to_ascii_uppercase());
            out.push_str(chars.as_str());
        }
        _ => out.push_str(first),
    }
    // Windows ends its own sentence before the code: "... specified.
    // (os error 2)". The code goes inside the sentence instead.
    if let Some(at) = out.rfind(". (os error ") {
        let code = out[at + ". (os error ".len()..].trim_end();
        if code
            .strip_suffix(')')
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        {
            out.remove(at);
        }
    }
    let trimmed = out.trim_end();
    if !trimmed.is_empty() && !trimmed.ends_with(['.', '!', '?', ':']) {
        out.truncate(trimmed.len());
        out.push('.');
    }
    out.push_str(rest);
    out
}

/// Whether `text` opens with an English word Pathwarden starts an error
/// with ("no", "unknown", "reading" ...), not a name the error quotes (a
/// file, a pack, a run ID), which keeps its own case.
fn opens_with_a_word(text: &str) -> bool {
    const WORDS: &[&str] = &[
        "a",
        "accepted",
        "an",
        "another",
        "at",
        "both",
        "can't",
        "cannot",
        "choose",
        "could",
        "couldn't",
        "either",
        "every",
        "failed",
        "give",
        "in",
        "invalid",
        "missing",
        "name",
        "no",
        "not",
        "nothing",
        "only",
        "pass",
        "say",
        "set",
        "that",
        "the",
        "there",
        "these",
        "this",
        "unknown",
        "unsupported",
        "use",
        "with",
    ];
    let word = text.split([' ', ',', ';']).next().unwrap_or_default();
    word.chars().all(|c| c.is_ascii_lowercase() || c == '\'')
        && (WORDS.contains(&word) || (word.len() > 4 && word.ends_with("ing")))
}

/// The error and its causes on one line, like `{:#}`, without repeating a
/// cause that the message before it already ends with ("failed to read x:
/// os error 2: os error 2").
fn error_text(e: &anyhow::Error) -> String {
    // A failure a person can act on (DNS, refused, certificate, password):
    // what to do first, then the technical detail on its own line, lined
    // up under the text after "error: ".
    if let Some(ce) = e.downcast_ref::<pathwarden_collect::ConnectionError>() {
        // No Kerberos ticket for the computers: the way out on the
        // command line, and that nothing was read.
        if ce.problem == pathwarden_collect::Problem::NoTicket {
            return format!(
                "{} Or pass --allow-ntlm to read computers with NTLM.\n       {}\n       \
                 Nothing was collected.",
                ce.message(),
                ce.detail
            );
        }
        if ce.problem != pathwarden_collect::Problem::Settings {
            return format!("{}\n       {}", ce.message(), ce.detail);
        }
    }
    let mut out = String::new();
    for cause in e.chain() {
        let text = cause.to_string();
        if text.is_empty() || out.ends_with(&text) {
            continue;
        }
        if !out.is_empty() {
            out.push_str(": ");
        }
        out.push_str(&text);
    }
    // A history file refused by its binding: what to do, on its own line.
    if let Some(hint) = e
        .chain()
        .find_map(|c| c.downcast_ref::<pathwarden_core::binding::BindingError>())
        .and_then(|b| b.hint())
    {
        out.push_str("\n       ");
        out.push_str(&hint);
    }
    out
}

impl Command {
    /// The collector data this command reads, if any.
    fn input_mut(&mut self) -> Option<&mut Input> {
        match self {
            Command::Summary { input, .. } | Command::TierZero(input) | Command::Posture(input) => {
                Some(input)
            }
            Command::Exposure { input, .. }
            | Command::Query { input, .. }
            | Command::Path { input, .. }
            | Command::Reach { input, .. }
            | Command::Search { input, .. }
            | Command::Zones {
                action:
                    zones_cmd::ZonesAction::Suggest { input, .. }
                    | zones_cmd::ZonesAction::Preview { input, .. },
            }
            | Command::ChokePoints { input, .. }
            | Command::Findings { input, .. }
            | Command::Changes { input, .. }
            | Command::Plan { input, .. }
            | Command::Run { input, .. }
            | Command::Retest { input, .. }
            | Command::Report { input, .. } => Some(input),
            Command::Evidence(args) => args.input_mut(),
            Command::Demo { .. }
            | Command::Ui(_)
            | Command::Collect(_)
            | Command::Diagnose(_)
            | Command::Logs(_)
            | Command::History { .. }
            | Command::Runs { .. }
            | Command::Label { .. }
            | Command::Env { .. }
            | Command::Config(_)
            | Command::Zones { .. }
            | Command::Mappings(_)
            | Command::Plugins(_)
            | Command::Action(_)
            | Command::Export(_)
            | Command::Schedule(_)
            | Command::Rules { .. }
            | Command::Guide { .. }
            | Command::Owned { .. } => None,
        }
    }
}

/// Runs `command`; a job (a collection, `run`, a retest, a history sync, a
/// finding action) with its log ([`pathwarden_core::logs`]): what it was,
/// its lines, and how it ended.
fn run(command: Command) -> Result<ExitCode> {
    use pathwarden_core::logs::{By, JobLog, Outcome};
    let log = job_of(&command)
        .and_then(|(kind, subject)| JobLog::open(kind, By::command_line(), &subject));
    let Some(log) = log else {
        return run_command(command);
    };
    let _in = log.enter();
    let args: Vec<String> = std::env::args().skip(1).collect();
    log.line(&format!("pathwarden {}", args.join(" ")));
    let collecting = log.kind() == pathwarden_core::logs::Kind::Collect;
    let result = run_command(command);
    match &result {
        Ok(code) => {
            let (outcome, why) = outcome_of(*code, collecting);
            log.end(outcome, why);
        }
        Err(e) => log.end(Outcome::Failed, &error_text(e)),
    }
    result
}

/// How a job that returned `code` ended, for its log: findings at or
/// above `--fail-on`, or still open or not told after a retest, are
/// results (ok); an error is a failure, Ctrl-C a stop, and a collection
/// with domains not collected a failure.
fn outcome_of(code: ExitCode, collecting: bool) -> (pathwarden_core::logs::Outcome, &'static str) {
    use pathwarden_core::logs::Outcome;
    let is = |n: u8| code == ExitCode::from(n);
    if code == ExitCode::SUCCESS {
        (Outcome::Ok, "")
    } else if is(exit::ERROR) {
        (Outcome::Failed, "exit status 2")
    } else if is(interrupt::EXIT_CANCELLED as u8) {
        (Outcome::Stopped, "")
    } else if collecting && is(exit::SOME_NOT_COLLECTED) {
        (Outcome::Failed, "some domains not collected")
    } else if is(exit::FINDINGS) {
        (Outcome::Ok, "exit status 1: findings")
    } else if is(exit::CANT_TELL) {
        (Outcome::Ok, "exit status 3: can't tell")
    } else {
        (Outcome::Failed, "exit status not 0")
    }
}

/// The log `command` gets, if it is a job: its kind and subject.
fn job_of(command: &Command) -> Option<(pathwarden_core::logs::Kind, String)> {
    use pathwarden_core::logs::Kind;
    match command {
        Command::Collect(c) => Some((Kind::Collect, c.args.first_domain().to_ascii_uppercase())),
        Command::Run { label, .. } => Some((Kind::Run, label.clone().unwrap_or_default())),
        Command::Retest { findings, .. } => Some((Kind::Retest, findings.join(", "))),
        Command::History {
            action:
                Some(history_cmd::HistoryAction::Storage {
                    action: history_cmd::StorageAction::Sync { .. },
                }),
            ..
        } => Some((Kind::Sync, String::new())),
        Command::Action(a) => action_cmd::job_of(a).map(|s| (Kind::Action, s)),
        _ => None,
    }
}

fn run_command(mut command: Command) -> Result<ExitCode> {
    // `retest targeted` reads a saved run, not collector data.
    if let Command::Retest { action, .. } = &mut command {
        if let Some(retest_cmd::RetestAction::Targeted(args)) = action.take() {
            return retest_cmd::targeted_cmd(args);
        }
    }
    // `-i demo:` reads the built-in demo collection, unpacked for as long as
    // the command runs.
    let _demo = match command.input_mut() {
        Some(input) => demo::resolve(&mut input.input)?,
        None => None,
    };
    // `-i run:ID` reads the raw collection a run kept, as the app's
    // "Add files and analyze again" does: found in --env's runs, else in
    // every environment of the workspace.
    let mut from_runs = pathwarden_ui::add_data::Resolved::default();
    if let Some(input) = command.input_mut() {
        if pathwarden_ui::add_data::names_a_run(&input.input) {
            let ws = pathwarden_ui::environments::cli_workspace_or_current(
                input.env.env_workspace.as_deref(),
                input.env.env.as_deref(),
            )?;
            from_runs = pathwarden_ui::add_data::resolve_inputs(
                &mut input.input,
                &ws,
                input.env.env.is_none(),
            )
            .map_err(anyhow::Error::msg)?;
        }
    }
    // `--env NAME`: the environment's config, and its history for the
    // commands that keep one (an explicit --state still wins). `run --save`
    // picks its environment itself.
    let saving = matches!(command, Command::Run { save: true, .. });
    // `reach` and `search` without -i read a saved run: --env and
    // --workspace pick it, not settings for collector data. So does
    // `query --run` (`--run ID --env NAME --workspace DIR`).
    let saved_run = matches!(
        &command,
        Command::Reach { input, .. }
            | Command::Search { input, .. }
            | Command::Summary { input, .. }
            | Command::Path { input, .. }
            | Command::Zones {
                action: zones_cmd::ZonesAction::Suggest { input, .. }
                    | zones_cmd::ZonesAction::Preview { input, .. }
            }
            if input.input.is_empty()
    ) || matches!(
        &command,
        Command::Query { input, run: Some(_), .. } if input.input.is_empty()
    );
    let mut env_state = None;
    let mut env_dir = None;
    if let Some(input) = command.input_mut().filter(|_| !saved_run) {
        if !saving {
            // `--workspace DIR` alone: that workspace's current environment,
            // as `history`, `runs list` and the `zones` commands take it.
            input.env.check(input.config.as_deref())?;
            if let Some(env) = input.env.resolve()? {
                input.config = env.config;
                env_state = Some(env.state);
            }
        }
    }
    if let Command::History { config, env, .. } = &mut command {
        // `--workspace` alone: that workspace's current environment.
        let resolved = match (&env.env, &env.env_workspace) {
            (None, Some(ws)) => Some(pathwarden_ui::environments::cli_paths_current(ws)?),
            _ => env.resolve()?,
        };
        if let Some(env) = resolved {
            *config = env.config;
            env_state = Some(env.state);
            env_dir = Some(env.dir);
        }
    }
    if let (Command::Evidence(args), Some(dir)) = (&mut command, &env_state) {
        args.default_state(dir);
    }
    match command {
        Command::Demo { output, verbose } => demo_cmd(output, verbose),
        Command::Summary { input, run, rights } if input.input.is_empty() => {
            summary_saved(&input, run.as_deref(), rights)
        }
        Command::Summary { input, rights, .. } => summary(&input, rights),
        Command::TierZero(input) => tier_zero(&input),
        Command::Exposure {
            input,
            samples,
            zone,
        } => exposure(&input, samples, zone.as_deref()),
        Command::Query {
            input,
            cypher,
            prepared,
            list_prepared,
            show_prepared,
            run,
            limit,
            timeout_secs,
            owned,
        } => {
            let limits = (limit, timeout_secs);
            if list_prepared {
                list_prepared_cmd(input.json)
            } else if let Some(key) = show_prepared {
                show_prepared_cmd(&key, input.json)
            } else if let Some(key) = prepared {
                let q = pick_prepared(&key)?;
                query_cmd(&input, run.as_deref(), &q.query, limits, &owned, Some(q))
            } else {
                let cypher = cypher.unwrap_or_default();
                query_cmd(&input, run.as_deref(), &cypher, limits, &owned, None)
            }
        }
        Command::Owned { action } => owned_cmd::run(action),
        Command::Path {
            input,
            run,
            from,
            to,
        } => path(&input, run.as_deref(), &from, to.as_deref()),
        Command::Reach {
            input,
            object,
            run,
            class,
            top,
        } => explore_cmd::reach(&input, run.as_deref(), &object, class, top),
        Command::Search {
            input,
            text,
            run,
            kind,
            top,
        } => explore_cmd::search(&input, run.as_deref(), &text, &kind, top),
        Command::Zones { action } => zones_cmd::run(action),
        Command::ChokePoints { input, top } => choke_points(&input, top),
        Command::Findings {
            input,
            min_severity,
            category,
            rules,
            show_suppressed,
            fail_on,
            by_fix,
            introduced,
            since,
            state,
        } => {
            return findings_cmd(
                &input,
                &FindingsFilter {
                    min_severity,
                    category,
                    rules,
                    show_suppressed,
                },
                fail_on,
                by_fix,
                introduced
                    .or(since)
                    .map(|p| (p, state.clone().or(env_state.clone()))),
                state.or(env_state).as_deref(),
            )
        }
        Command::Changes {
            input,
            since,
            state,
            fail_on,
            paths,
        } => {
            return changes_cmd::changes(
                &input,
                since,
                state.or(env_state).as_deref(),
                fail_on,
                paths,
            )
        }
        Command::Plan {
            input,
            zone,
            top,
            no_findings,
        } => plan(&input, zone.as_deref(), top, no_findings),
        Command::Posture(input) => posture_cmd(&input),
        Command::Report {
            input,
            output,
            state,
        } => {
            let given = state.is_some();
            let history = match state.or(env_state) {
                Some(dir) => HistoryFrom::State { dir, given },
                None => HistoryFrom::None,
            };
            report_cmd(&input, &output, history)
        }
        #[cfg(feature = "desktop")]
        Command::Ui(ui) if ui.wants_window() => pathwarden_desktop::run(ui.args),
        #[cfg(not(feature = "desktop"))]
        Command::Ui(UiCommand {
            window: true, args, ..
        }) => {
            println!("This build has no window; using the browser.");
            pathwarden_ui::run(args)
        }
        Command::Ui(UiCommand { args, .. }) => {
            if let Some(header) = logo::header() {
                println!(
                    "{header}
"
                );
            }
            pathwarden_ui::run(args)
        }
        Command::Collect(c) => return collect_cmd(c),
        // 0 the same, 1 they differ, 2 an error (as `diff`).
        Command::Diagnose(args) if args.compares() => return diagnose_cmd::compare_cmd(args),
        Command::Run {
            input,
            save,
            new_env,
            label,
            report,
            fail_on,
            ..
        } if save => {
            let label = clean_label(label.as_deref())?;
            let ws = save_cmd::workspace(input.env.env_workspace.as_deref())?;
            let choice = save_cmd::check_choice(&ws, input.env.env.as_deref(), new_env.as_deref())?;
            let known = pathwarden_core::ingest::peek_domains(&input.input).collected;
            // A run's kept collection with other files: saved as
            // the app saves it, with how it was collected.
            let (source, collection) = from_runs
                .saved_as()
                .unwrap_or_else(|| (source_words(&input.input), None));
            return save_cmd::save(save_cmd::SaveArgs {
                source,
                inputs: input.input.clone(),
                workspace: input.env.env_workspace.as_deref(),
                choice,
                label,
                known,
                collection,
                timings: None,
                report: report.as_deref(),
                fail_on,
                verbose: input.verbose,
                collected_into: None,
            });
        }
        Command::Run {
            input,
            state,
            event,
            report,
            no_push,
            no_outputs,
            accept_shrink,
            fail_on,
            label,
            ..
        } => {
            let state = state.or(env_state);
            let label = clean_label(label.as_deref())?;
            return run_cmd(
                &input,
                state.as_deref(),
                event.as_deref(),
                report.as_deref(),
                &RunFlags {
                    no_push,
                    no_outputs,
                    accept_shrink,
                    fail_on,
                    label: label.as_deref(),
                },
            );
        }
        Command::Retest {
            action: _,
            input,
            baseline,
            state,
            findings,
            rules,
            record,
            no_push,
            label,
        } => {
            let label = clean_label(label.as_deref())?;
            // A baseline file replaces the history (they conflict).
            let state = if baseline.is_none() {
                state.or(env_state)
            } else {
                state
            };
            return retest_cmd::retest_cmd(retest_cmd::RetestArgs {
                input: &input,
                baseline: baseline.as_deref(),
                state: state.as_deref(),
                selection: pathwarden_core::retest::Selection {
                    fingerprints: findings,
                    rules,
                },
                record,
                no_push,
                label: label.as_deref(),
            });
        }
        Command::Evidence(args) => return evidence::run(args),
        Command::History {
            action: Some(action),
            ..
        } => history_cmd::run(action),
        Command::Runs { action } => runs_cmd::run(action),
        Command::History {
            state,
            config,
            forget: Some(run),
            env,
            ..
        } => retest_cmd::history_forget(
            state.or(env_state).as_deref(),
            config.as_ref(),
            &run,
            env.env
                .as_deref()
                .map(|name| (env.env_workspace.as_deref(), name)),
        ),
        Command::History {
            state,
            config,
            last,
            range,
            since,
            json,
            with_since,
            env,
            forget: None,
            action: None,
        } => {
            let state = state.or(env_state);
            // In an environment of the UI workspace, labels set there later.
            let labels = env_dir
                .map(|d| pathwarden_ui::workspace::labels_in(&d))
                .unwrap_or_default();
            // The settings the commands "since the last run" points at take:
            // the ones given here.
            let context: Vec<String> = match (&env.env, &config) {
                (Some(name), _) => {
                    let mut c = vec!["--env".to_string(), name.clone()];
                    if let Some(ws) = &env.env_workspace {
                        c.extend(["--workspace".to_string(), ws.display().to_string()]);
                    }
                    c
                }
                (None, Some(path)) => vec!["-c".to_string(), path.display().to_string()],
                (None, None) => Vec::new(),
            };
            retest_cmd::history_cmd(
                state.as_deref(),
                config.as_ref(),
                retest_cmd::HistoryView {
                    last,
                    range,
                    since,
                    json,
                    with_since,
                    context: &context,
                },
                &labels,
            )
        }
        Command::Config(args) => config_cmd::run(args),
        Command::Mappings(args) => mappings_cmd::run(args),
        Command::Plugins(args) => plugins_cmd::run(args),
        Command::Action(args) => return action_cmd::run(args),
        Command::Logs(args) => return logs_cmd::run(args),
        Command::Env { action } => match action {
            EnvAction::List { workspace, json } => save_cmd::env_list(workspace.as_deref(), json),
            EnvAction::Rename {
                env,
                name,
                workspace,
            } => save_cmd::env_rename(workspace.as_deref(), &env, &name),
            EnvAction::Remove {
                env,
                yes,
                state,
                workspace,
            } => save_cmd::env_remove(workspace.as_deref(), &env, yes, state.as_deref()),
            EnvAction::Create {
                name,
                name_flag,
                domains,
                copy_from,
                from_git,
                from_folder,
                branch,
                how,
                make_current,
                workspace,
            } => {
                let name = name.or(name_flag);
                if from_git.is_some() || from_folder.is_some() {
                    let place = history_cmd::Place {
                        git: from_git,
                        shared_folder: from_folder,
                        branch,
                    };
                    history_cmd::connect(
                        workspace.as_deref(),
                        None,
                        &place,
                        &how,
                        name.as_deref(),
                        make_current,
                    )
                } else if how.push || how.read_only || how.refresh.is_some() {
                    Err(anyhow::anyhow!(
                        "--push, --read-only and --refresh go with --from-git or --from-folder."
                    ))
                } else {
                    save_cmd::env_create(
                        workspace.as_deref(),
                        name.as_deref().unwrap_or_default(),
                        &domains,
                        copy_from.as_deref(),
                        make_current,
                    )
                }
            }
            EnvAction::Domains {
                env,
                domains,
                workspace,
            } => save_cmd::env_domains(workspace.as_deref(), &env, &domains),
            EnvAction::Use { env, workspace } => save_cmd::env_use(workspace.as_deref(), &env),
        },
        Command::Label {
            run,
            text,
            clear,
            env,
            workspace,
        } => save_cmd::label_cmd(
            workspace.as_deref(),
            env.as_deref(),
            &run,
            if clear { None } else { text.as_deref() },
        ),
        Command::Export(args) => export_cmd::export_cmd(args),
        Command::Diagnose(args) => diagnose_cmd::diagnose_cmd(args),
        Command::Schedule(args) => schedule_cmd::schedule_cmd(args),
        Command::Guide {
            rule,
            markdown,
            json,
        } => guide_cmd::guide(&rule, markdown, json),
        Command::Rules { at, json } => config_cmd::list_rules(at, json),
    }
    .map(|()| ExitCode::SUCCESS)
}

fn open(input: &Input) -> Result<(AdGraph, IngestStats, Config)> {
    open_with(input, false)
}

/// [`open`], keeping every collector property when `all_properties` (for
/// Cypher queries, which can filter on any of them).
fn open_with(input: &Input, all_properties: bool) -> Result<(AdGraph, IngestStats, Config)> {
    let config = read_config(input)?;
    let opts = pathwarden_core::LoadOptions {
        all_properties,
        ..analyze::load_options(&config, &input.tier_zero)
    };
    let mut p = progress::Analysis::new(Through::Load, input.verbose);
    let (g, stats) = pathwarden_core::load_with_progress(&input.input, &opts, &mut p)
        .context("loading collector data")?;
    if let Some(w) = skipped_objects_warning(&stats) {
        p.note(w);
    }
    for w in settings_folder_warnings(&stats) {
        p.note(w);
    }
    for w in opengraph_warnings(&stats) {
        p.note(w);
    }
    for w in tier_zero_warnings(&g, &opts.extra_tier_zero) {
        p.note(w);
    }
    p.done();
    Ok((g, stats, config))
}

/// Configured Tier Zero entries (`--tier-zero` or the config file) that match
/// nothing: a typo would otherwise leave Tier Zero silently unchanged.
fn tier_zero_warnings(g: &AdGraph, extra: &[String]) -> Vec<String> {
    let warn = ui::severity(Severity::Medium);
    pathwarden_core::tierzero::unmatched(g, extra)
        .iter()
        .map(|e| {
            format!(
                "{warn}Warning:{warn:#} The Tier Zero entry '{}' matched no object. Use an object ID or its full name, e.g. NAME@DOMAIN.",
                ui::safe(e)
            )
        })
        .collect()
}

fn read_config(input: &Input) -> Result<Config> {
    let config = match &input.config {
        Some(path) => Config::from_file(path)?,
        None => Config::default(),
    };
    warn_config(&config);
    Ok(config)
}

/// Prints what loading the settings ignored (keys a newer Pathwarden wrote
/// in accepted risks), one warning each, on stderr.
pub(crate) fn warn_config(config: &Config) {
    for w in &config.warnings {
        eprintln!(
            "Warning: pathwarden.toml: {}",
            ui::safe_text(&w.to_string())
        );
    }
}

pub(crate) fn emit_json<T: Serialize>(value: &T) -> Result<()> {
    // The status keys' 1.0 names beside the old ones (status_keys).
    let v = pathwarden_core::status_keys::to_value(value)?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

fn summary(input: &Input, rights: bool) -> Result<()> {
    let (g, stats, config) = open(input)?;
    let forest = pathwarden_core::forest::forest_map(&g, &stats, &relevance(&g, &stats, &config));
    let mut nodes: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, n) in g.nodes() {
        *nodes.entry(n.kind.as_str()).or_default() += 1;
    }
    let mut edges: BTreeMap<&str, usize> = BTreeMap::new();
    for e in g.inner().edge_weights() {
        *edges.entry(e.as_str()).or_default() += 1;
    }
    let placeholders = g.nodes().filter(|(_, n)| n.placeholder).count();
    let tier_zero = analysis::tier_zero(&g).len();

    if input.json {
        /// A trust once, as the text and the report count it, with the
        /// other domain's record of it when both were collected.
        #[derive(Serialize)]
        struct Trust<'a> {
            #[serde(flatten)]
            trust: &'a pathwarden_core::ingest::TrustInfo,
            other_side: Option<&'a pathwarden_core::ingest::TrustInfo>,
        }
        #[derive(Serialize)]
        struct Summary<'a> {
            /// `ingest.trusts` lists each side's record; `trusts` each
            /// trust once.
            ingest: &'a IngestStats,
            nodes: &'a BTreeMap<&'a str, usize>,
            edges: &'a BTreeMap<&'a str, usize>,
            placeholders: usize,
            tier_zero: usize,
            trusts: Vec<Trust<'a>>,
            /// The domains by forest and the trusts with their risk flags,
            /// as the app's API returns them for a saved run.
            forest: pathwarden_core::forest::Document,
            /// OpenGraph and AzureHound sources not read whole.
            #[serde(skip_serializing_if = "Vec::is_empty")]
            incomplete_sources: Vec<IncompleteSource>,
        }
        #[derive(Serialize)]
        struct IncompleteSource {
            #[serde(flatten)]
            source: pathwarden_core::ingest::OgIncomplete,
            /// What `run` and `analyze` warn, in plain text.
            warning: String,
        }
        return emit_json(&Summary {
            ingest: &stats,
            nodes: &nodes,
            edges: &edges,
            placeholders,
            tier_zero,
            trusts: pathwarden_core::ingest::distinct_trusts(&stats.trusts)
                .into_iter()
                .map(|(trust, other_side)| Trust { trust, other_side })
                .collect(),
            forest: forest.document(),
            incomplete_sources: pathwarden_core::ingest::OgIncomplete::all(&stats.opengraph)
                .into_iter()
                .map(|s| IncompleteSource {
                    warning: s.sentences(&s.source, true).join(" "),
                    source: s,
                })
                .collect(),
        });
    }

    println!(
        "Read {}.",
        pathwarden_core::text::count(stats.files.len(), "file", "files")
    );
    if let Some(t) = stats.collected_at {
        // The collector's own clock, read from file names: no zone to give.
        println!(
            "Collected {} (from file names; ages are measured from this time).",
            pathwarden_core::time::format_us(t)
        );
    }
    for f in &stats.skipped_files {
        println!("  Skipped: {}", ui::safe(f));
    }
    for o in &stats.skipped_objects {
        println!("  Skipped object: {}", ui::safe(o));
    }
    println!(
        "\nObjects ({} in all; {} referenced but not collected)",
        num(g.node_count()),
        num(placeholders)
    );
    for (k, v) in &nodes {
        println!("  {k:<16} {:>9}", num(*v));
    }
    println!("\nRelationships ({})", num(g.edge_count()));
    for (k, v) in &edges {
        println!("  {k:<26} {:>9}", num(*v));
    }
    if forest.is_multi_domain() || !forest.trusts.is_empty() {
        print_forest(&forest, rights);
    }
    if !stats.unmapped_rights.is_empty() {
        println!("\nACE rights not modeled yet");
        for (k, v) in &stats.unmapped_rights {
            println!("  {:<26} {:>9}", ui::safe(k), num(*v));
        }
    }
    println!("\nTier Zero objects: {}", num(tier_zero));
    Ok(())
}

/// `summary` without -i: the forest map of a saved run, as the app's API
/// returns it.
fn summary_saved(input: &Input, run: Option<&str>, rights: bool) -> Result<()> {
    let (_, x, saved) = explore_cmd::saved_run(input, run)?;
    let Some(forest) = &x.meta.forest else {
        bail!(
            "{} (run {}; --run ID picks another).",
            pathwarden_core::forest::NOT_KEPT,
            saved.label()
        );
    };
    if input.json {
        return emit_json(&saved.json(serde_json::json!({ "forest": forest.document() })));
    }
    saved.say();
    print_forest(forest, rights);
    Ok(())
}

/// `summary`'s domains by forest and its trusts, each once (both of a
/// trust's domains record it when both were collected), with what makes
/// each one a risk.
fn print_forest(m: &pathwarden_core::forest::ForestMap, rights: bool) {
    use pathwarden_core::forest::Crossing;
    let warn = ui::severity(Severity::High);
    let d = ui::DIM;
    // Every word comes from the map's document, as the Forest view shows it.
    let doc = m.document();
    let (m, h) = (&doc.map, &doc.headline);
    println!("\n{} · {}", h.lead, h.detail);
    for s in &h.status {
        match s.kind {
            "none" => println!("  {d}{}{d:#}", s.text),
            _ => println!("  {warn}{}{warn:#}", s.text),
        }
    }
    println!(
        "\nForests ({}, {})",
        m.forests.len(),
        count(m.domains.len(), "domain", "domains")
    );
    for (i, f) in m.forests.iter().enumerate() {
        println!("  {}", ui::safe(&f.name));
        for dom in m.domains.iter().filter(|x| x.forest == i) {
            if !dom.collected {
                println!(
                    "    {:<32} {}, {}",
                    ui::safe(&dom.name),
                    dom.role_text,
                    dom.note.as_deref().unwrap_or_default().to_lowercase()
                );
                continue;
            }
            println!(
                "    {:<32} {}, {}, {}, {}",
                ui::safe(&dom.name),
                dom.role_text,
                count(dom.users, "user", "users"),
                count(dom.computers, "computer", "computers"),
                count(dom.tier_zero, "Tier Zero object", "Tier Zero objects"),
            );
            match (&dom.paths, &dom.note) {
                (Some(p), _) => println!("      {} {} {d}({}){d:#}", p.count, p.tail, p.percent),
                (None, Some(n)) => println!("      {d}{n}{d:#}"),
                (None, None) => {}
            }
        }
    }
    // A crossing, and with --rights each right it lists.
    let held = |c: &Crossing, indent: &str| {
        println!(
            "{indent}Objects of {} hold in {}: {}",
            ui::safe(&c.from),
            ui::safe(&c.to),
            c.counts
        );
        if !rights {
            return;
        }
        for r in &c.rights {
            println!(
                "{indent}  {} {d}{}{d:#} {}",
                ui::safe(&r.from_name),
                ui::safe(&r.kind),
                ui::safe(&r.to_name)
            );
        }
        if c.rights.is_empty() {
            println!(
                "{indent}  {d}Not listed: this run was analyzed before Pathwarden listed them. Analyze it again.{d:#}"
            );
        } else if c.counted() > c.rights.len() {
            println!(
                "{indent}  {d}{} of {} listed{d:#}",
                c.rights.len(),
                num(c.counted())
            );
        }
    };
    if !m.trusts.is_empty() {
        println!("\nTrusts ({})", m.trusts.len());
    }
    for t in &m.trusts {
        let (s, tg) = (ui::safe(&t.source), ui::safe(&t.target));
        let ends = match t.direction.as_str() {
            "Bidirectional" => format!("{s} <-> {tg}"),
            "Outbound" => format!("{s} trusts {tg}"),
            "Inbound" => format!("{tg} trusts {s}"),
            _ => format!("{s} - {tg} (disabled)"),
        };
        println!(
            "  {ends}  {d}{}, {}{}{d:#}",
            ui::safe(&t.trust_type),
            if t.transitive {
                "transitive"
            } else {
                "not transitive"
            },
            match t.records.as_slice() {
                [_, _, ..] => ", recorded by both domains".to_string(),
                [r] => format!(", recorded by {} only", ui::safe(&r.source)),
                [] => String::new(),
            }
        );
        if t.records_disagree {
            let said: Vec<String> = t
                .records
                .iter()
                .map(|r| format!("{} says {}", ui::safe(&r.source), ui::safe(&r.direction)))
                .collect();
            println!("    {warn}Records disagree:{warn:#} {}.", said.join(", "));
        }
        if t.enables_forest_takeover {
            // Shown though a side was not collected: the trust says so.
            let missing = t
                .flags
                .iter()
                .find(|f| f.kind == "not_collected")
                .map(|f| format!(" ({})", ui::safe(&f.text)))
                .unwrap_or_default();
            println!(
                "    {warn}Forest takeover:{warn:#} Inside one forest, so whoever controls either domain controls the forest{missing}."
            );
        }
        if !t.intra_forest {
            for w in &t.ways {
                let filtering = match &w.filtering_note {
                    Some(n) => format!("{} ({})", w.filtering, ui::safe(n)),
                    None => w.filtering.clone(),
                };
                println!(
                    "    {} into {}: {filtering}, {}",
                    ui::safe(&w.from),
                    ui::safe(&w.to),
                    w.selective
                );
                if let Some(a) = &w.abuse_text {
                    println!(
                        "      {warn}SID history abuse (PW-012):{warn:#} {}",
                        ui::safe(a)
                    );
                }
            }
            if let Some(n) = &t.pw012_note {
                println!("    {d}{n}{d:#}");
            }
            if t.abusable_sid_history || t.pw012_note.is_some() {
                println!("    {d}{}{d:#}", pathwarden_core::forest::NOT_A_PATH_STEP);
            }
        }
        for c in &t.crossing {
            held(c, "    ");
        }
        // As the Forest view's panel says it.
        if t.crossing.is_empty() {
            println!(
                "    {d}{}{d:#}",
                if t.intra_forest {
                    "Nothing else crosses it."
                } else {
                    "Nothing in the data crosses it."
                }
            );
        }
        if let Some(n) = &t.crossing_note {
            println!("    {d}{n}{d:#}");
        }
    }
    if !m.indirect.is_empty() {
        println!("\nRights between domains no trust joins directly");
        for c in &m.indirect {
            held(c, "  ");
        }
    }
}

fn tier_zero(input: &Input) -> Result<()> {
    let (g, _, _) = open(input)?;
    let mut t0: Vec<_> = analysis::tier_zero(&g)
        .into_iter()
        .map(|ix| g.node(ix))
        .collect();
    t0.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
    if input.json {
        return emit_json(&t0);
    }
    for n in &t0 {
        println!(
            "{:<12} {:<45} {}",
            n.kind.as_str(),
            ui::safe(&n.name),
            ui::safe(n.tier_zero_reason.as_deref().unwrap_or_default())
        );
    }
    println!(
        "\n{}",
        count(t0.len(), "Tier Zero object", "Tier Zero objects")
    );
    Ok(())
}

fn exposure(input: &Input, samples: usize, zone: Option<&str>) -> Result<()> {
    let (g, stats, config) = open(input)?;
    let (_, targets, description) = targets_for(&g, &config, zone)?;
    let rel = relevance(&g, &stats, &config);
    let report = analysis::exposure_to(&g, &targets, samples, &rel);
    if input.json {
        return emit_json(&report);
    }
    println!("Protecting {}.\n", ui::safe(&description));
    println!(
        "{:<30} {:>26} {:>26}",
        "Domain", "Users with a path", "Computers with a path"
    );
    let row = |name: &str, e: &analysis::Exposure| {
        println!(
            "{:<30} {:>26} {:>26}",
            ui::safe(name),
            format!(
                "{}/{} ({})",
                e.users_exposed,
                e.users_total,
                pct(e.users_pct())
            ),
            format!(
                "{}/{} ({})",
                e.computers_exposed,
                e.computers_total,
                pct(e.computers_pct())
            ),
        );
    };
    for (domain, e) in &report.per_domain {
        row(domain, e);
    }
    row("TOTAL", &report.total);
    let t = &report.total;
    println!(
        "\nTier Zero exposure {}: {} of {} active users and computers (logged on in the last {} days).",
        pct(t.percent()),
        num(t.exposed()),
        num(t.relevant()),
        report.stale_days
    );
    if !report.activity_unknown_domains.is_empty() {
        println!(
            "Logon times weren't collected for {}: every enabled account is counted.",
            ui::safe(&report.activity_unknown_domains.join(", "))
        );
    }
    if !report.sample_paths.is_empty() {
        println!("\nShortest attack paths:");
        for p in &report.sample_paths {
            println!();
            print_path(p);
        }
    }
    Ok(())
}

fn path(input: &Input, run: Option<&str>, from: &str, to: Option<&str>) -> Result<()> {
    // Without -i: a saved run, as Explore's Path between answers on it.
    let (g, saved) = if input.input.is_empty() {
        let (g, x, s) = explore_cmd::saved_run(input, run)?;
        (g, Some((x, s)))
    } else {
        (std::sync::Arc::new(open(input)?.0), None)
    };
    // A path runs between principals: a certificate template or a GPO of
    // the same name is not what was meant, at either end.
    let src = resolve(&g, from, g.find_principal(from))?;
    let dst = match to {
        Some(to) => Some(resolve(&g, to, g.find_principal(to))?),
        None => None,
    };
    // Paths end at the first Tier Zero object. To an object reached only
    // through Tier Zero: the path up to it, said as Explore says it.
    let mut through = None;
    let found = match (&saved, dst) {
        (Some((x, _)), _) => {
            let (p, t) = explore_cmd::saved_path(&g, x, src, dst);
            through = t;
            p
        }
        (None, Some(dst)) => analysis::shortest_path(&g, src, dst).or_else(|| {
            let p = analysis::path_through_tier_zero(&g, src, dst)?;
            through = Some(analysis::through_tier_zero_line(&g.node(dst).name));
            Some(p)
        }),
        (None, None) => analysis::path_to_tier_zero(&g, src),
    };
    if let Some((_, s)) = &saved {
        if !input.json {
            s.say();
        }
    }
    let n = g.node(src);
    let reason = n.tier_zero_reason.as_deref().unwrap_or("Tier Zero");
    if input.json {
        // A saved run's answer names the run, as `reach` does.
        let emit_json = |v: &serde_json::Value| match &saved {
            Some((_, s)) => emit_json(&s.json(v.clone())),
            None => emit_json(v),
        };
        // A Tier Zero start says so, as the text does: its zero-step path
        // to itself is not a finding.
        if n.tier_zero {
            let mut v = serde_json::to_value(&found)?;
            if let Some(o) = v.as_object_mut() {
                o.insert("tier_zero".into(), true.into());
                o.insert("tier_zero_reason".into(), reason.into());
                if let Some(line) = &through {
                    o.insert("through_tier_zero".into(), line.as_str().into());
                }
            } else {
                v = serde_json::json!({
                    "source": n.name,
                    "path": null,
                    "tier_zero": true,
                    "tier_zero_reason": reason,
                });
            }
            return emit_json(&v);
        }
        if let Some(line) = &through {
            let mut v = serde_json::to_value(&found)?;
            if let Some(o) = v.as_object_mut() {
                o.insert("through_tier_zero".into(), line.as_str().into());
            }
            return emit_json(&v);
        }
        return emit_json(&serde_json::to_value(&found)?);
    }
    if to.is_none() && n.tier_zero {
        println!(
            "{} ({}) is Tier Zero itself ({}): it has no path to Tier Zero to show. \
             Give --to for a path from it to another object.",
            ui::safe(&n.name),
            n.kind.as_str(),
            ui::safe(reason)
        );
        return Ok(());
    }
    if let Some(line) = &through {
        println!(
            "{}
",
            ui::safe(line)
        );
    }
    match found {
        Some(p) => print_path(&p),
        None if n.tier_zero => println!(
            "No attack path found from {} ({}), which is Tier Zero itself ({}).",
            ui::safe(&n.name),
            n.kind.as_str(),
            ui::safe(reason)
        ),
        None => println!("No attack path found."),
    }
    Ok(())
}

/// `pathwarden query`: run a Cypher query over the collector data (`-i`,
/// every collector property kept) or a saved run (as the Explore page
/// does), and print the node id-set, the paths hop by hop, and any matched
/// relationships.
fn query_cmd(
    input: &Input,
    run: Option<&str>,
    cypher: &str,
    (max_rows, timeout_secs): (usize, u64),
    owned: &[String],
    prepared: Option<&pathwarden_core::prepared::Prepared>,
) -> Result<()> {
    use pathwarden_core::cypher;
    let limits = cypher::EvalLimits {
        max_rows: max_rows.max(1),
        timeout: Duration::from_secs(timeout_secs.max(1)),
        ..Default::default()
    };
    if input.input.is_empty() {
        let (g, x, saved) = explore_cmd::saved_run(input, run)?;
        let props = pathwarden_ui::run_data::props(&saved.dir);
        let (mut ids, note) = pathwarden_core::owned::for_query(&saved.env_dir);
        for o in owned {
            let ix = resolve(&g, o, g.find_principal(o))?;
            ids.push(g.node(ix).id.clone());
        }
        let view = cypher::RunView::new(&g, &x, pathwarden_ui::run_data::props_ref(&props))
            .with_owned(&ids);
        saved.say();
        return answer_query(input, &view, cypher, &limits, Some(&saved), note, prepared);
    }
    let (g, _, _) = open_with(input, true)?;
    let mut owned_ix = Vec::new();
    let mut note = None;
    // With --env, the environment's kept marks too.
    if let Some(env) = input.env.resolve()? {
        let (kept, why) = pathwarden_core::owned::for_query(&env.dir);
        owned_ix.extend(pathwarden_core::owned::in_graph(&g, &kept));
        note = why;
    }
    for o in owned {
        owned_ix.push(resolve(&g, o, g.find_principal(o))?);
    }
    let view = cypher::AdGraphView::new(&g).with_owned(owned_ix);
    answer_query(input, &view, cypher, &limits, None, note, prepared)
}

/// "No prepared query is named ..."
fn no_prepared(key: &str) -> anyhow::Error {
    anyhow::anyhow!("No prepared query is named {key:?}. --list-prepared lists them.")
}

/// "... matches 3 prepared queries", and which.
fn several_prepared(key: &str, hits: &[&pathwarden_core::prepared::Prepared]) -> anyhow::Error {
    let mut msg = format!(
        "{key:?} matches {}. Name one by its full name or GUID:",
        pathwarden_core::text::count(hits.len(), "prepared query", "prepared queries")
    );
    for q in hits.iter().take(20) {
        msg.push_str(&format!("\n  {}  {}", &q.guid[..8], q.name));
    }
    if hits.len() > 20 {
        msg.push_str(&format!("\n  and {} more", hits.len() - 20));
    }
    anyhow::anyhow!(msg)
}

/// The prepared query `key` names, if it can run as it is.
fn pick_prepared(key: &str) -> Result<&'static pathwarden_core::prepared::Prepared> {
    use pathwarden_core::prepared::{self, Lookup};
    match prepared::library().find(key) {
        Ok(q) if !q.supported => bail!(
            "The prepared query {:?} isn't offered. {}",
            q.name,
            q.reason.as_deref().unwrap_or_default()
        ),
        Ok(q) if q.edit_first => bail!(
            "The prepared query {:?} has a placeholder to replace first. Print it with \
             --show-prepared, edit it, and run it as a Cypher query.",
            q.name
        ),
        Ok(q) => Ok(q),
        Err(Lookup::None) => Err(no_prepared(key)),
        Err(Lookup::Several(hits)) => Err(several_prepared(key, &hits)),
    }
}

/// `pathwarden query --list-prepared`: the prepared queries, by category,
/// as the Explore page lists them.
fn list_prepared_cmd(json: bool) -> Result<()> {
    let list = pathwarden_core::prepared::listing();
    if json {
        return emit_json(&list);
    }
    println!("{} Release {}.", list.notice, list.library.tag);
    println!(
        "{}.",
        pathwarden_core::text::count(list.queries.len(), "prepared query", "prepared queries")
    );
    let mut category = "";
    for q in &list.queries {
        if q.category != category {
            category = &q.category;
            let n = list
                .queries
                .iter()
                .filter(|x| x.category == category)
                .count();
            println!("\n{} ({n})", ui::safe(category));
        }
        println!(
            "  {}  {:<7}  {:<6}  {}{}",
            &q.guid[..8],
            q.returns,
            q.finding.as_ref().map_or("", |f| f.rule.as_str()),
            ui::safe(&q.name),
            if q.edit_first { " (edit first)" } else { "" }
        );
    }
    Ok(())
}

/// `pathwarden query --show-prepared`: a prepared query's Cypher, to copy
/// and edit; offered or not.
fn show_prepared_cmd(key: &str, json: bool) -> Result<()> {
    use pathwarden_core::prepared::{self, Lookup};
    let q = match prepared::library().find(key) {
        Ok(q) => q,
        Err(Lookup::None) => return Err(no_prepared(key)),
        Err(Lookup::Several(hits)) => return Err(several_prepared(key, &hits)),
    };
    if json {
        return emit_json(q);
    }
    println!("{}", ui::safe_text(&q.query));
    Ok(())
}

/// Runs the query on `view` and prints the answer: as text, or the
/// document the app's Explore page gets.
fn answer_query(
    input: &Input,
    view: &dyn pathwarden_core::cypher::GraphView,
    cypher: &str,
    limits: &pathwarden_core::cypher::EvalLimits,
    saved: Option<&explore_cmd::Saved>,
    owned_note: Option<String>,
    prepared: Option<&pathwarden_core::prepared::Prepared>,
) -> Result<()> {
    use pathwarden_core::cypher;
    // The query text and error messages can quote user input; object IDs
    // (SIDs/GUIDs) are not attacker-controlled text, and names are printed
    // made safe.
    let mut result = cypher::run(view, cypher, limits).map_err(|e| anyhow::anyhow!("{e}"))?;
    // The marks a query couldn't use, as the app says it.
    result.warnings.extend(owned_note);
    // Labels and types are the query's own text: print them made safe.
    for w in &result.warnings {
        eprintln!("Note: {}", ui::safe(w));
    }
    if input.json {
        use std::io::Write as _;
        #[derive(Serialize)]
        struct Out<'a> {
            #[serde(flatten)]
            answer: cypher::Answer<'a>,
            #[serde(skip_serializing_if = "Option::is_none")]
            run: Option<serde_json::Value>,
            #[serde(skip_serializing_if = "Option::is_none")]
            prepared: Option<&'a pathwarden_core::prepared::Prepared>,
        }
        let out = Out {
            prepared,
            answer: cypher::Answer {
                view,
                result: &result,
            },
            run: saved.map(explore_cmd::Saved::run_value),
        };
        // Written as it is made: no second copy of every path in memory.
        let mut w = std::io::BufWriter::new(std::io::stdout().lock());
        serde_json::to_writer_pretty(&mut w, &out)?;
        writeln!(w)?;
        w.flush()?;
        return Ok(());
    }
    if let Some(q) = prepared {
        println!("{}", ui::safe(&q.name));
        let finding = q
            .finding
            .as_ref()
            .map(|f| format!(" Finding: {} {}.", f.rule, f.title))
            .unwrap_or_default();
        println!(
            "{}, revision {}.{finding}\n",
            pathwarden_core::prepared::library().source.library,
            q.revision
        );
    }
    let node_column = result
        .rows
        .iter()
        .flatten()
        .any(|c| matches!(c, cypher::Cell::Node { .. }));
    if result.returns_paths {
        println!(
            "{}",
            pathwarden_core::text::count(result.paths().count(), "path", "paths")
        );
        for p in result.paths().filter_map(|c| cypher::attack_path(view, c)) {
            println!();
            print_path(&p);
        }
    }
    if node_column || !result.returns_paths {
        let ids = result.node_ids();
        if result.returns_paths {
            println!();
        }
        println!(
            "{}",
            pathwarden_core::text::count(ids.len(), "node", "nodes")
        );
        for id in &ids {
            println!("  {id}");
        }
    }
    if !result.returns_paths && !result.relationships.is_empty() {
        println!(
            "\n{}",
            pathwarden_core::text::count(
                result.relationships.len(),
                "relationship",
                "relationships"
            )
        );
        for (src, kind, tgt) in &result.relationships {
            println!("  {src} -[{kind}]-> {tgt}");
        }
    }
    if !result.stopped.is_empty() {
        println!();
    }
    for note in &result.stopped {
        println!("{note}");
    }
    if result.timed_out {
        println!("Raise --timeout for more.");
    } else if (result.truncated && !result.path_steps_capped) || result.relationships_truncated {
        println!("Raise --limit for more.");
    }
    Ok(())
}

/// Who counts toward the exposure denominators, as the Posture page counts
/// them: activity at the collection time, with the config's stale window.
fn relevance(g: &AdGraph, stats: &IngestStats, config: &Config) -> analysis::Relevance {
    analysis::Relevance::from_settings(g, &analyze::settings_for(config, stats))
}

fn choke_points(input: &Input, top: usize) -> Result<()> {
    let (g, stats, config) = open(input)?;
    let points = analysis::choke_points(&g, top, &relevance(&g, &stats, &config));
    if input.json {
        return emit_json(&points);
    }
    if points.is_empty() {
        println!("No account outside Tier Zero has an attack path to Tier Zero.");
        return Ok(());
    }
    println!(
        "{:>3}  {:>9}  {:>9}  {:>17}  Relationship",
        "#", "Cut off", "Via path", "Exposure"
    );
    for (i, c) in points.iter().enumerate() {
        let exposure = format!("{} → {}", pct(c.exposure_before), pct(c.exposure_after));
        println!(
            "{:>3}  {:>9}  {:>9}  {:>17}  {} ({}) -[{}]-> {} ({})",
            i + 1,
            num(c.principals_cut_off),
            num(c.shortest_paths_through),
            exposure,
            ui::safe(&c.from),
            c.from_kind.as_str(),
            c.edge.as_str(),
            ui::safe(&c.to),
            c.to_kind.as_str()
        );
    }
    println!(
        "\nCut off: accounts that lose every attack path to Tier Zero when this relationship is removed.\n\
         Via path: accounts whose shortest attack path goes through it.\n\
         Exposure: Tier Zero exposure before → after removing only this relationship, as a new \
         run would count it (before: of the run's {} active users and computers).",
        num(points[0].relevant_population)
    );
    Ok(())
}

/// The one object of `matches` (what `query` found), or an error that lists
/// them.
fn resolve(g: &AdGraph, query: &str, matches: Vec<NodeIndex>) -> Result<NodeIndex> {
    match matches.as_slice() {
        [] => bail!("No object matches '{query}'."),
        [one] => Ok(*one),
        many => {
            let list: Vec<String> = many
                .iter()
                .map(|&ix| {
                    let n = g.node(ix);
                    format!("  {} {} ({})", n.kind.as_str(), n.name, n.id)
                })
                .collect();
            // When they all have the same full name, only the ID tells
            // them apart.
            let first = &g.node(many[0]).name;
            let advice = if many.iter().all(|&ix| &g.node(ix).name == first) {
                "Use the object ID"
            } else {
                "Use the full name or object ID"
            };
            bail!("'{query}' is ambiguous. {advice}:\n{}", list.join("\n"))
        }
    }
}

fn print_path(p: &AttackPath) {
    match p.steps.first() {
        Some(first) => println!("{} ({})", ui::safe(&first.from), first.from_kind.as_str()),
        None => println!("{} (already the target)", ui::safe(&p.source)),
    }
    for s in &p.steps {
        let v = ui::VIOLET;
        // A Cypher path can walk an edge against its direction.
        let (l, r) = if s.backward { ("<-", "-") } else { ("-", "->") };
        println!(
            "  {v}{l}[{}]{r}{v:#} {} ({})",
            s.edge.as_str(),
            ui::safe(&s.to),
            s.to_kind.as_str()
        );
    }
}

/// Which findings `pathwarden findings` lists.
struct FindingsFilter {
    min_severity: Severity,
    category: Option<Category>,
    rules: Vec<String>,
    show_suppressed: bool,
}

impl FindingsFilter {
    /// The category and rules asked for (which `--fail-on` also looks at).
    fn selects(&self, f: &Finding) -> bool {
        self.category.is_none_or(|c| f.category == c)
            && (self.rules.is_empty() || self.rules.iter().any(|r| r.eq_ignore_ascii_case(f.rule)))
    }

    /// Selected and not hidden by `--min-severity` or as an accepted risk.
    fn shows(&self, f: &Finding) -> bool {
        self.selects(f)
            && f.severity >= self.min_severity
            && (self.show_suppressed || f.suppressed.is_none())
    }
}

/// A `--label` as given: checked as the UI checks it.
fn clean_label(label: Option<&str>) -> Result<Option<String>> {
    match label {
        Some(l) => {
            pathwarden_ui::workspace::clean_label(l).map_err(|e| anyhow::anyhow!("--label: {e}"))
        }
        None => Ok(None),
    }
}

/// What was analyzed, in words, for a saved run: the first input, "and N
/// more".
fn source_words(inputs: &[PathBuf]) -> String {
    match inputs {
        [] => String::new(),
        [one] => one.display().to_string(),
        [first, rest @ ..] => format!("{} and {} more", first.display(), rest.len()),
    }
}

/// The trusted domains `collect --trusted` adds: the ones the
/// newest run of `domain` in the workspace says this account can read.
fn readable_trusted(workspace: Option<&std::path::Path>, domain: &str) -> Result<Vec<String>> {
    let ws = save_cmd::workspace(workspace)?;
    let Some(from) = pathwarden_ui::collect::trusted_for(&ws, &ws.all_runs(), domain) else {
        bail!(
            "No run of {domain} in {} lists its trusted domains. Collect it once first, or name \
             them with --domain.",
            ws.root().display()
        );
    };
    let readable = pathwarden_core::forest::readable(&from.domains);
    // Offered but not ticked (lab item 53): selective authentication is
    // on, or unknown because the trusting side wasn't collected.
    for d in from
        .domains
        .iter()
        .filter(|d| d.pick == pathwarden_core::forest::Pick::Maybe)
    {
        eprintln!(
            "{} left out: {} Name it with --domain to try.",
            ui::safe(&d.name),
            d.why.as_deref().unwrap_or_default()
        );
    }
    if readable.is_empty() {
        let warn = ui::severity(Severity::Medium);
        anstream::eprintln!(
            "{warn}Warning:{warn:#} The last run of {} lists no trusted domain this account can \
             read.",
            ui::safe(&from.domain)
        );
    }
    Ok(readable)
}

/// Before collecting several domains: which, and the authorization
/// line, then a y/N question on the terminal. Without one, `--yes` is
/// needed.
fn confirm_domains(domains: &[String]) -> Result<bool> {
    eprintln!(
        "Collect {} domains, one after another with the same sign-in, then analyze them together \
         as one run:",
        domains.len()
    );
    for d in domains {
        eprintln!("  {}", ui::safe(&d.to_ascii_uppercase()));
    }
    eprintln!("Only collect from domains you are authorized to assess.");
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!(
            "Collecting {} domains asks first, and nothing can answer here. Pass --yes.",
            domains.len()
        );
    }
    eprint!("Collect {} domains? [y/N] ", domains.len());
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// `pathwarden collect`, and with `--save` the run saved to an environment.
fn collect_cmd(mut c: CollectCommand) -> Result<ExitCode> {
    // Several domains: the trusted ones from the last run, then a
    // question unless --yes.
    let trusted = if c.trusted {
        readable_trusted(c.workspace.as_deref(), c.args.first_domain())?
    } else {
        Vec::new()
    };
    let all = pathwarden_ui::environments::clean_domains(
        &c.args
            .domain
            .iter()
            .chain(&trusted)
            .cloned()
            .collect::<Vec<_>>(),
    );
    if all.len() > 1 && !c.yes && !confirm_domains(&all)? {
        eprintln!("Nothing was collected.");
        return Ok(ExitCode::from(exit::ERROR));
    }
    let partly = |failed: usize, code: ExitCode| {
        if failed > 0 && code == ExitCode::SUCCESS {
            ExitCode::from(exit::SOME_NOT_COLLECTED)
        } else {
            code
        }
    };
    if !c.save {
        apply_collect_config(&mut c, None)?;
        let out = c.args.out.clone();
        let collected = progress::collect(c.args, trusted, false, None)?;
        // For the `pathwarden run -i` that reads the folder (a schedule's),
        // which records the timings with the run.
        if let Some(t) = &collected.timings {
            if let Err(e) = pathwarden_core::diagnostics::write_sidecar(&out, t, &collected.files) {
                let warn = ui::severity(Severity::Medium);
                anstream::eprintln!(
                    "{warn}Warning:{warn:#} The collection's timings couldn't be kept in {}: {e}.",
                    out.display()
                );
            }
        }
        return Ok(partly(collected.failed, ExitCode::SUCCESS));
    }
    // Everything that can stop it is checked before collecting.
    let label = clean_label(c.label.as_deref())?;
    let ws = save_cmd::workspace(c.workspace.as_deref())?;
    let mut choice = save_cmd::check_choice(&ws, c.env.as_deref(), c.new_env.as_deref())?;
    let home = pathwarden_ui::environments::clean_domains(&[c.args.first_domain().to_string()]);
    // Several domains go where the first one does, as in the app: the
    // trusted ones go on its list.
    let known = if all.len() > 1 {
        home.clone()
    } else {
        all.clone()
    };
    match save_cmd::precheck(&ws, choice.as_ref(), &known) {
        Err(code) => return Ok(code),
        Ok(Some(id)) if all.len() > 1 && choice.is_none() => {
            choice = Some(pathwarden_ui::environments::Choice::Env(id))
        }
        Ok(_) => {}
    }
    let verbose = c.args.verbose;
    let out = c.args.out.clone();
    // The read is kept in the environment the run goes to.
    let env_ws = match &choice {
        Some(pathwarden_ui::environments::Choice::Env(id)) => ws.in_env(id),
        _ => ws.clone(),
    };
    apply_collect_config(&mut c, Some(&env_ws))?;
    let collected = progress::collect(c.args, trusted, true, Some(&env_ws))?;
    let memory = |phase: &str| {
        if let Some(line) = pathwarden_collect::memory::line(phase).filter(|_| verbose) {
            anstream::eprintln!("{line}");
        }
    };
    memory("before analysis");
    let source = match all.len() {
        1 => format!("Collected from {}", collected.info.domain),
        2 => format!(
            "Collected from {} and 1 trusted domain",
            collected.info.domain
        ),
        n => format!(
            "Collected from {} and {} trusted domains",
            collected.info.domain,
            n - 1
        ),
    };
    let failed = collected.failed;
    let code = save_cmd::save(save_cmd::SaveArgs {
        inputs: collected.files,
        source,
        workspace: c.workspace.as_deref(),
        choice,
        label,
        known,
        collection: Some(collected.info),
        timings: collected.timings,
        report: None,
        fail_on: None,
        verbose,
        collected_into: Some(&out),
    })
    .inspect(|_| memory("after analysis"))?;
    Ok(partly(failed, code))
}

/// Exit status 1 when a finding other than an accepted risk is at least
/// `level`, else 0.
pub(crate) fn fail_on_code<'a>(
    level: Option<Severity>,
    findings: impl IntoIterator<Item = &'a Finding>,
) -> ExitCode {
    let failing = level.is_some_and(|level| {
        findings
            .into_iter()
            .any(|f| f.suppressed.is_none() && f.severity >= level)
    });
    ExitCode::from(if failing { exit::FINDINGS } else { exit::OK })
}

/// What finding actions did on each finding (`actions`), from the run
/// history the settings (or `state`) name, as it is here: nothing is
/// fetched, and a history that can't be read leaves them without.
fn with_actions(input: &Input, state: Option<&Path>, findings: &mut [Finding]) {
    let config = match &input.config {
        Some(path) => match Config::from_file(path) {
            Ok(c) => c,
            Err(_) => return,
        },
        None => Config::default(),
    };
    let Ok(store) = store::Store::new(&config.state, state) else {
        return;
    };
    if !store.dir.is_dir() || store.check_expected().is_err() {
        return;
    }
    if let Ok(file) = pathwarden_core::action_log::load(&store) {
        pathwarden_core::action_log::annotate(&file, findings, &mut []);
    }
}

/// `introduced`: `--introduced` (or `--since`) and the state folder to
/// read it from.
fn findings_cmd(
    input: &Input,
    filter: &FindingsFilter,
    fail_on: Option<Severity>,
    by_fix: bool,
    introduced: Option<(pathwarden_core::introduced::Period, Option<PathBuf>)>,
    state: Option<&Path>,
) -> Result<ExitCode> {
    if let Some(unknown) = filter.rules.iter().find(|r| {
        !findings::rules()
            .iter()
            .any(|k| k.id.eq_ignore_ascii_case(r))
            && !r
                .to_ascii_uppercase()
                .starts_with(pathwarden_core::pingcastle::RULE_PREFIX)
    }) {
        bail!("Unknown rule '{unknown}'. See `pathwarden rules`.");
    }
    let mut p = progress::Analysis::new(Through::Rules, input.verbose);
    let mut ev = run_rules(input, &mut p)?;
    p.done();
    if input.json {
        with_actions(input, state, &mut ev.findings);
    }
    let all = &ev.findings;
    let mut shown: Vec<&Finding> = all.iter().filter(|f| filter.shows(f)).collect();
    // `--introduced`: only the period's findings, each with its badge.
    let intro = match &introduced {
        Some((period, state)) => {
            let config = read_config(input)?;
            let domains = analyze::domain_names(&ev.graph);
            Some(changes_cmd::introduced_findings(
                &config,
                state.as_deref(),
                *period,
                &ev,
                &domains,
            )?)
        }
        None => None,
    };
    let badges: std::collections::HashMap<&str, &pathwarden_core::introduced::IntroFinding> = intro
        .as_ref()
        .map(|(i, _)| {
            i.findings
                .iter()
                .map(|f| (f.fingerprint.as_str(), f))
                .collect()
        })
        .unwrap_or_default();
    if intro.is_some() {
        shown.retain(|f| badges.contains_key(f.fingerprint.as_str()));
    }
    let selected = all
        .iter()
        .filter(|f| filter.selects(f))
        .filter(|f| intro.is_none() || badges.contains_key(f.fingerprint.as_str()));
    let code = fail_on_code(fail_on, selected);

    if by_fix {
        findings_by_fix(input, &ev, filter)?;
        return Ok(code);
    }
    if input.json {
        if intro.is_some() {
            #[derive(Serialize)]
            struct WithIntro<'a> {
                #[serde(flatten)]
                finding: &'a Finding,
                introduced: &'a pathwarden_core::introduced::IntroFinding,
            }
            let rows: Vec<WithIntro> = shown
                .iter()
                .map(|f| WithIntro {
                    finding: f,
                    introduced: badges[f.fingerprint.as_str()],
                })
                .collect();
            emit_json(&rows)?;
        } else {
            emit_json(&shown)?;
        }
        return Ok(code);
    }
    print_posture_header(&ev.posture());
    if let (Some((i, h)), Some((period, _))) = (&intro, &introduced) {
        let heading = pathwarden_core::introduced::Introduced::heading(*period, h.latest);
        println!(
            "
{}{heading}: {}{:#}",
            ui::BOLD,
            count(shown.len(), "finding", "findings"),
            ui::BOLD
        );
        if changes_cmd::no_earlier(h, *period) {
            println!("{}", pathwarden_core::introduced::NO_EARLIER);
        } else if let Some(note) = i.note(&h.runs, h.latest) {
            println!("{}", ui::safe(&note));
        }
    }
    for f in shown {
        println!();
        let sev = ui::severity(f.severity);
        let bold = ui::BOLD;
        println!(
            "{sev}[{}]{sev:#} {}  {bold}{}{bold:#}",
            f.severity.as_str().to_uppercase(),
            f.rule,
            ui::safe(&f.title)
        );
        println!("  id:   {}  ({})", f.fingerprint, f.category.as_str());
        let found = badges.get(f.fingerprint.as_str()).copied();
        if let (Some(i), Some((_, h))) = (found, &intro) {
            println!("  introduced: {}", changes_cmd::badge_words(i, h));
        }
        if pathwarden_core::guides::guide(f.rule).is_some() {
            println!("  guide: pathwarden guide {}", f.rule);
        }
        if let Some(e) = &f.exposure {
            let scope = e
                .scope
                .as_ref()
                .map(|d| format!(" in {}", ui::safe(d)))
                .unwrap_or_default();
            println!(
                "  exposure: {} of {} active users and computers{scope} can abuse this ({}).",
                num(e.principals),
                num(e.population),
                pathwarden_core::posture::share_percent(e.percent)
            );
        }
        if let Some(reason) = &f.suppressed {
            println!("  ACCEPTED RISK: {}", ui::safe(reason));
            if let Some(a) = &f.accepted {
                let mut who = a.accepted_line();
                if let Some(c) = a.changed_line() {
                    who = format!("{who}; {c}");
                }
                if !a.notes.is_empty() {
                    let n = a.notes.len();
                    who = format!("{who}; {n} note{}", if n == 1 { "" } else { "s" });
                }
                println!("    {}", ui::safe(&who));
            }
        }
        println!("  why:  {}", ui::safe_text(&f.summary));
        println!(
            "  fix:  {}",
            ui::safe_text(&pathwarden_core::findings::for_terminal(&f.remediation))
        );
        if let Some(p) = f.path.as_ref().filter(|p| !p.steps.is_empty()) {
            let hops: Vec<String> = p
                .steps
                .iter()
                .map(|s| format!("-[{}]-> {}", s.edge.as_str(), ui::safe(&s.to)))
                .collect();
            println!("  path: {} {}", ui::safe(&p.source), hops.join(" "));
        }
        if !f.affected.is_empty() {
            // Name them (the report and the UI do): the fix says "these
            // accounts", so the reader needs to know which. `--json` has all.
            // With --introduced, the objects gained in the period first.
            const SHOWN: usize = 10;
            let n = f.affected.len();
            println!("  affected ({n}):");
            for (name, seen, detail) in changes_cmd::affected_first(f, found).iter().take(SHOWN) {
                let seen = seen.map(|s| format!("  {s}")).unwrap_or_default();
                match detail {
                    Some(d) => println!("    {}{seen}  ({})", ui::safe(name), ui::safe(d)),
                    None => println!("    {}{seen}", ui::safe(name)),
                }
            }
            if n > SHOWN {
                println!("    … and {} more (--json lists every one).", n - SHOWN);
            }
        }
    }
    Ok(code)
}

/// `findings --by-fix`: the findings under the change of Tier Zero's
/// remediation path that closes them or cuts their path, as the report's
/// "Group by: change that fixes it"; then those on no path.
fn findings_by_fix(input: &Input, ev: &Evaluated, filter: &FindingsFilter) -> Result<()> {
    let config = read_config(input)?;
    let (_, targets, _) = targets_for(&ev.graph, &config, None)?;
    let plan = remediation::plan_to(
        &ev.graph,
        &targets,
        &relevance(&ev.graph, &ev.stats, &config),
    );
    let groups = pathwarden_core::report::fix_groups(&plan, &ev.findings);
    let shown = |fs: &[&'_ Finding]| -> usize { fs.iter().filter(|f| filter.shows(f)).count() };

    if input.json {
        #[derive(Serialize)]
        struct Item<'a> {
            fingerprint: &'a str,
            rule: &'a str,
            severity: Severity,
            title: &'a str,
        }
        #[derive(Serialize)]
        struct Group<'a> {
            step: usize,
            from: &'a str,
            to: &'a str,
            edges: Vec<&'static str>,
            action: &'a str,
            principals_through: usize,
            closes: Vec<Item<'a>>,
            cuts: Vec<Item<'a>>,
        }
        #[derive(Serialize)]
        struct Out<'a> {
            changes: usize,
            groups: Vec<Group<'a>>,
            changes_without_findings: usize,
            not_on_a_path: Vec<Item<'a>>,
        }
        fn items<'a>(fs: &[&'a Finding], filter: &FindingsFilter) -> Vec<Item<'a>> {
            fs.iter()
                .filter(|f| filter.shows(f))
                .map(|f| Item {
                    fingerprint: &f.fingerprint,
                    rule: f.rule,
                    severity: f.severity,
                    title: &f.title,
                })
                .collect()
        }
        return emit_json(&Out {
            changes: plan.fixes.len(),
            groups: groups
                .groups
                .iter()
                .map(|g| Group {
                    step: g.step,
                    from: &g.fix.from,
                    to: &g.fix.to,
                    edges: g.fix.edges.iter().map(|k| k.as_str()).collect(),
                    action: &g.fix.action,
                    principals_through: g.fix.principals_through,
                    closes: items(&g.closes, filter),
                    cuts: items(&g.cuts, filter),
                })
                .filter(|g| !g.closes.is_empty() || !g.cuts.is_empty())
                .collect(),
            changes_without_findings: groups.without_findings,
            not_on_a_path: items(&groups.alone, filter),
        });
    }

    print_posture_header(&ev.posture());
    println!();
    if plan.fixes.is_empty() {
        println!(
            "No account outside Tier Zero has an attack path to it, so no plan step is needed."
        );
    } else {
        print!(
            "{} every attack path to Tier Zero.",
            count(plan.fixes.len(), "plan step cuts", "plan steps cut")
        );
        let (closed, cut) = (groups.closed(), groups.cut_only());
        if closed + cut > 0 {
            print!(" They close {}", count(closed, "finding", "findings"));
            if cut > 0 {
                print!(" and cut the attack path of {} more", num(cut));
            }
            print!(".");
        }
        println!(
            " The plan steps that take care of the most findings come first; step numbers are those of `pathwarden plan`."
        );
    }
    // Up to this many findings under each change.
    const SHOWN: usize = 10;
    let list = |fs: &[&Finding]| {
        let fs: Vec<&&Finding> = fs.iter().filter(|f| filter.shows(f)).collect();
        for f in fs.iter().take(SHOWN) {
            let sev = ui::severity(f.severity);
            println!(
                "      {sev}[{}]{sev:#} {}  {}",
                f.severity.as_str().to_uppercase(),
                f.rule,
                ui::safe(&f.title)
            );
        }
        if fs.len() > SHOWN {
            println!("      … and {} more.", fs.len() - SHOWN);
        }
    };
    let width = plan.fixes.len().to_string().len().max(2);
    for g in &groups.groups {
        let (closes, cuts) = (shown(&g.closes), shown(&g.cuts));
        if closes + cuts == 0 {
            continue;
        }
        let green = ui::GREEN;
        println!();
        println!(
            "{green}{:>width$}.{green:#} {} ({}) -[{}]-> {} ({})",
            g.step,
            ui::safe(&g.fix.from),
            g.fix.from_kind.as_str(),
            g.fix
                .edges
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            ui::safe(&g.fix.to),
            g.fix.to_kind.as_str()
        );
        let pad = " ".repeat(width + 2);
        println!("{pad}{}", ui::safe_text(&g.fix.action));
        if closes > 0 {
            println!("{pad}Closes {closes}:");
            list(&g.closes);
        }
        if cuts > 0 {
            println!("{pad}Cuts the attack path of {cuts}:");
            list(&g.cuts);
        }
    }
    if groups.without_findings > 0 {
        println!();
        println!(
            "{} without a finding of their own; see `pathwarden plan`.",
            count(
                groups.without_findings,
                "other plan step cuts paths",
                "other plan steps cut paths"
            )
        );
    }
    let alone = shown(&groups.alone);
    if alone > 0 {
        println!();
        println!("Not closed by this plan ({alone}). Each needs its own fix:");
        list(&groups.alone);
    }
    println!();
    println!(
        "`pathwarden findings` lists each finding with its fix. A weak account whose path a plan step cuts is still roastable: it needs its own fix too."
    );
    Ok(())
}

fn plan(input: &Input, zone: Option<&str>, top: Option<usize>, no_findings: bool) -> Result<()> {
    // The findings it leaves, as the report's "Not closed by this plan"
    // (Tier Zero's plan, in text): one load runs the rules too.
    let with_findings = zone.is_none() && !no_findings && !input.json;
    let (g, stats, config, findings) = if with_findings {
        let mut p = progress::Analysis::new(Through::Rules, input.verbose);
        let ev = run_rules(input, &mut p)?;
        p.done();
        (ev.graph, ev.stats, read_config(input)?, Some(ev.findings))
    } else {
        let (g, stats, config) = open(input)?;
        (g, stats, config, None)
    };
    let (label, targets, _) = targets_for(&g, &config, zone)?;
    let plan = remediation::plan_to(&g, &targets, &relevance(&g, &stats, &config));
    if input.json {
        return emit_json(&plan);
    }
    let label = ui::safe(&label);
    if plan.exposed_before == 0 {
        println!("No account outside {label} has an attack path to it. Nothing to cut.");
        return Ok(());
    }
    println!(
        "{} outside {label} {} an attack path to it. These {} cut them all off:",
        count(plan.exposed_before, "account", "accounts"),
        if plan.exposed_before == 1 {
            "has"
        } else {
            "have"
        },
        count(plan.fixes.len(), "plan step", "plan steps")
    );
    println!(
        "Exposure to {label}: {} → {} ({:.2} points), as a new run after the plan steps would count it (of {} → {} active users and computers).",
        pct(plan.exposure_before),
        pct(plan.exposure_after),
        plan.exposure_delta,
        num(plan.relevant_population),
        num(plan.relevant_population_after)
    );
    let shown = top.unwrap_or(plan.fixes.len()).min(plan.fixes.len());
    // Numbers right-aligned to the widest one shown ("   9." … "1230.").
    let width = shown.to_string().len().max(3);
    for (i, f) in plan.fixes.iter().take(shown).enumerate() {
        let green = ui::GREEN;
        println!();
        println!(
            "{green}{:>width$}.{green:#} {} ({}) -[{}]-> {} ({})",
            i + 1,
            ui::safe(&f.from),
            f.from_kind.as_str(),
            f.edges
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            ui::safe(&f.to),
            f.to_kind.as_str()
        );
        let pad = " ".repeat(width + 2);
        println!("{pad}{}", ui::safe_text(&f.action));
        println!(
            "{pad}{} an attack path through this.",
            count(
                f.principals_through,
                "exposed account has",
                "exposed accounts have"
            )
        );
    }
    if shown < plan.fixes.len() {
        println!();
        println!(
            "… and {} more. Run without --top for all of them, or with --json.",
            count(plan.fixes.len() - shown, "plan step", "plan steps")
        );
    }
    if plan.exposed_after > 0 {
        println!();
        println!(
            "{} {label} through relationships that can't be removed \
             (for example forest trusts). Treat those accounts as part of {label}.",
            count(
                plan.exposed_after,
                "account still reaches",
                "accounts still reach"
            )
        );
    }
    if let Some(findings) = &findings {
        let left = pathwarden_core::report::findings_left(&plan, findings);
        println!();
        if left.is_empty() {
            println!(
                "Every open finding is closed by a step above, or has its attack path cut by one."
            );
        } else {
            println!(
                "Not closed by this plan ({}). Each needs its own fix:",
                left.len()
            );
            println!(
                "  {d}Weak accounts (even where a step cuts their path), hygiene findings, and \
                 paths that start inside Tier Zero. Most severe first.{d:#}",
                d = ui::DIM
            );
            const SHOWN: usize = 25;
            for f in left.iter().take(SHOWN) {
                let sev = ui::severity(f.severity);
                println!(
                    "  {sev}[{}]{sev:#} {}  {}",
                    f.severity.as_str().to_uppercase(),
                    f.rule,
                    ui::safe(&f.title)
                );
            }
            if left.len() > SHOWN {
                println!(
                    "  … and {} more (`pathwarden findings` lists each finding with its fix).",
                    left.len() - SHOWN
                );
            }
        }
    }
    Ok(())
}

/// Loads the data and runs every enabled rule, with suppressions applied.
fn run_rules(input: &Input, p: &mut progress::Analysis) -> Result<Evaluated> {
    let config = read_config(input)?;
    let ev = analyze::evaluate(&input.input, &config, &input.tier_zero, p)
        .context("loading collector data")?;
    for w in zone_warnings(&ev.zones) {
        p.note(w);
    }
    for w in tier_zero_warnings(
        &ev.graph,
        &analyze::load_options(&config, &input.tier_zero).extra_tier_zero,
    ) {
        p.note(w);
    }
    if let Some(w) = skipped_objects_warning(&ev.stats) {
        p.note(w);
    }
    for w in settings_folder_warnings(&ev.stats) {
        p.note(w);
    }
    for w in opengraph_warnings(&ev.stats) {
        p.note(w);
    }
    Ok(ev)
}

/// OpenGraph and AzureHound sources not read whole, one warning
/// each, in the words Run details uses, with the `[opengraph]` key that
/// raises the limit.
pub(crate) fn opengraph_warnings(stats: &IngestStats) -> Vec<String> {
    let warn = ui::severity(Severity::Medium);
    pathwarden_core::ingest::OgIncomplete::all(&stats.opengraph)
        .iter()
        .map(|s| {
            format!(
                "{warn}Warning:{warn:#} {}",
                s.sentences(&ui::safe(&s.source), true).join(" ")
            )
        })
        .collect()
}

/// Objects left out because they were too large to load safely.
fn skipped_objects_warning(stats: &IngestStats) -> Option<String> {
    let n = stats.skipped_objects.len();
    (n > 0).then(|| {
        let warn = ui::severity(Severity::Medium);
        let first = ui::safe(&stats.skipped_objects[0]);
        format!(
            "{warn}Warning:{warn:#} {} too large to load and {} not analyzed (the first: {first}). Results may be incomplete.",
            pathwarden_core::text::count(n, "object was", "objects were"),
            if n == 1 { "is" } else { "are" }
        )
    })
}

/// Zone entries that matched nothing.
fn zone_warnings(zones: &[Zone]) -> Vec<String> {
    let mut out = Vec::new();
    for z in zones {
        for u in &z.unresolved {
            out.push(format!(
                "Warning: Zone '{}': no object in the data matches {u}.",
                z.name
            ));
        }
        if z.members.is_empty() {
            out.push(format!("Warning: Zone '{}' has no members.", z.name));
        }
    }
    out
}

/// Resolves the config's Privilege Zones, warning about entries that matched nothing.
fn resolve_zones(g: &AdGraph, config: &Config) -> Vec<Zone> {
    let zones = zones::resolve(g, &config.zones);
    for w in zone_warnings(&zones) {
        eprintln!("{w}");
    }
    zones
}

/// Tier Zero, or a named zone plus Tier Zero: (label, targets, description).
fn targets_for(
    g: &AdGraph,
    config: &Config,
    zone: Option<&str>,
) -> Result<(String, Vec<NodeIndex>, String)> {
    let t0 = analysis::tier_zero(g);
    let Some(name) = zone else {
        let description = format!(
            "Tier Zero: {}",
            pathwarden_core::text::count(t0.len(), "object", "objects")
        );
        return Ok(("Tier Zero".to_string(), t0, description));
    };
    let zones = resolve_zones(g, config);
    let Some(z) = zones
        .iter()
        .find(|z| pathwarden_core::zones::same_name(&z.name, name))
    else {
        let known: Vec<&str> = zones.iter().map(|z| z.name.as_str()).collect();
        bail!(
            "No zone named '{name}' in the settings (there is: {}).",
            if known.is_empty() {
                "none".to_string()
            } else {
                known.join(", ")
            }
        );
    };
    let description = format!(
        "zone {}: {}, plus {}, which control every zone",
        z.name,
        pathwarden_core::text::count(z.members.len(), "object", "objects"),
        pathwarden_core::text::count(t0.len(), "Tier Zero object", "Tier Zero objects")
    );
    Ok((format!("zone {}", z.name), z.targets(g), description))
}

fn posture_cmd(input: &Input) -> Result<()> {
    // Through the plan: the headline says how many changes close every path.
    let mut p = progress::Analysis::new(Through::Plan, input.verbose);
    let posture = run_rules(input, &mut p)?.finish(&mut p).posture;
    p.done();
    if input.json {
        return emit_json(&posture);
    }
    print_headline(&posture);
    println!();
    for (i, zone) in std::iter::once(&posture.tier_zero)
        .chain(&posture.zones)
        .enumerate()
    {
        if i > 0 {
            println!();
        }
        // Tier Zero's status is the headline's first line.
        print_zone(zone, posture.activity_days, i > 0);
    }
    if let Some(note) = pathwarden_core::report::activity_note(&posture) {
        println!("\n{}", ui::safe(&note));
    }
    let c = &posture.findings;
    println!(
        "\nFindings: {} attack path, {} hygiene{}",
        num(c.attack_path),
        num(c.hygiene),
        if c.suppressed > 0 {
            format!(
                " ({})",
                count(c.suppressed, "accepted risk", "accepted risks")
            )
        } else {
            String::new()
        }
    );
    println!(
        "  {} critical · {} high · {} medium · {} low",
        num(c.critical),
        num(c.high),
        num(c.medium),
        num(c.low)
    );
    print_completeness(&posture);
    Ok(())
}

/// Tier Zero's status and headline: the status and why (the report's reason
/// line), once, then the accounts with an attack path to it, what the plan
/// does, and the share.
fn print_headline(p: &Posture) {
    let t0 = &p.tier_zero;
    let hl = p.headline();
    // The severity colours, so Critical reads as a critical finding does.
    let style = match t0.exposure_grade {
        posture::ExposureGrade::Critical => ui::severity(Severity::Critical),
        posture::ExposureGrade::High => ui::severity(Severity::High).bold(),
        posture::ExposureGrade::Moderate => ui::severity(Severity::Medium).bold(),
        posture::ExposureGrade::Low => ui::GREEN.bold(),
    };
    println!(
        "Status: {style}{}{style:#}. {}",
        t0.exposure_grade.as_str(),
        ui::safe(&t0.reason.text)
    );
    match &hl.fixes {
        Some(f) => println!("{}. {f}.", hl.title),
        None => println!("{}.", hl.title),
    }
    println!("({})", hl.share);
}

/// One zone's block; `status` for a Privilege Zone (Tier Zero's is the
/// headline).
fn print_zone(z: &ZonePosture, days: i64, status: bool) {
    let h = ui::VIOLET.bold();
    println!("{h}{}{h:#}", z.zone);
    println!("  Objects:          {}", num(z.objects));
    if status {
        println!(
            "  Status:           {}. {}",
            z.exposure_grade.as_str(),
            ui::safe(&z.reason.text)
        );
    }
    println!(
        "  With an attack path: {} {} ({} of {} active users and computers: logged on in the last {days} days).",
        num(z.exposed),
        if z.exposed == 1 { "account" } else { "accounts" },
        posture::share_percent(z.exposure_percent),
        num(z.relevant_population),
    );
    if z.population != z.relevant_population {
        println!(
            "                    ({} enabled users and computers in all; {} haven't logged on in {days} days, have no attack path, and don't count.)",
            num(z.population),
            num(z.population - z.relevant_population)
        );
    }
    println!(
        "  Protected:        {}",
        posture::protected_words(z.objects, z.objects_with_findings)
    );
}

fn print_completeness(p: &Posture) {
    print_sysvol_completeness(p);
    print_adcs_completeness(p);
    print_dc_settings_completeness(p);
    if p.completeness.is_empty() {
        return;
    }
    let active = p.completeness.iter().all(|c| c.active_only);
    println!(
        "\nCollection completeness ({})",
        if active {
            format!("computers active in the last {} days", posture::ACTIVE_DAYS)
        } else {
            "all enabled computers; logon times unavailable".to_string()
        }
    );
    for c in &p.completeness {
        let sessions = if c.sessions_targeted {
            format!(
                "sessions {}/{} ({})",
                c.sessions_collected,
                c.computers,
                pct(c.sessions_percent)
            )
        } else {
            "sessions not targeted".to_string()
        };
        let mut services = match c.services_words() {
            Some(w) => format!("   services read {w}"),
            None => String::new(),
        };
        if let Some(w) = c.tasks_words() {
            services.push_str(&format!("   tasks read {w}"));
        }
        println!(
            "  {:<30} {sessions}   local groups {}   GPO local groups {}{services}",
            ui::safe(&c.domain),
            local_groups_cell(c),
            match c.gpo_local_groups {
                Some(true) => "collected",
                Some(false) => "NOT collected",
                None => "not recorded",
            }
        );
    }
    if let Some(line) = posture::untargeted(&p.completeness).posture_line() {
        println!("  {line}");
    }
    if p.completeness
        .iter()
        .any(|c| c.stored_credentials_collected.is_some())
    {
        println!("  {}", posture::STORED_CREDENTIALS_DEF);
    }
    if p.completeness.iter().any(|c| c.stored_credentials_off) {
        println!("  {}", posture::STORED_CREDENTIALS_OFF_DEF);
    }
    if p.completeness
        .iter()
        .any(|c| c.task_credentials_collected.is_some())
    {
        println!("  {}", posture::TASK_CREDENTIALS_DEF);
    }
    if p.completeness.iter().any(|c| c.task_credentials_off) {
        println!("  {}", posture::TASK_CREDENTIALS_OFF_DEF);
    }
    if p.completeness
        .iter()
        .any(|c| c.gpo_local_groups == Some(false))
    {
        println!(
            "  GPO local groups not collected: admin rights granted by Group Policy are missing. Collect with a user and password (built-in --user), or SharpHound with GPOLocalGroup."
        );
    }
    if p.completeness
        .iter()
        .any(|c| c.member_computers < c.computers)
    {
        println!(
            "  Local groups count member computers only: a domain controller's local groups are \
             the domain's BUILTIN groups, already in the directory."
        );
    }
    if p.completeness.iter().any(|c| c.is_low()) {
        println!(
            "  Below 80%: paths through logged-on sessions and local admin rights may be missing. \
             Run the collector with privileged session collection and from a computer that can \
             reach all computers."
        );
    }
}

/// A share as every page and report words it: two decimals, never
/// rounded to all or none ("39.91%", "100%", "<0.01%").
fn pct(p: f64) -> String {
    posture::share_percent(p)
}

/// "3/4 (75%)" of member computers, or "n/a" with the reason when there are
/// none.
fn local_groups_cell(c: &posture::Completeness) -> String {
    match c.local_groups_na() {
        None if !c.local_groups_targeted => "not targeted".to_string(),
        None => format!(
            "{}/{} ({})",
            c.local_groups_collected,
            c.member_computers,
            pct(c.local_groups_percent)
        ),
        Some(why) => format!("n/a ({why})"),
    }
}

/// AD CS checks the collection could not support, per Enterprise CA.
fn print_adcs_completeness(p: &Posture) {
    use pathwarden_core::dcsettings::FileAge;
    let stale = |f: Option<FileAge>| f == Some(FileAge::Stale);
    let gaps: Vec<_> = p
        .adcs
        .iter()
        .filter(|c| {
            !(c.published_templates && c.esc6 && c.esc11 && c.esc13)
                || stale(c.esc6_file)
                || stale(c.esc11_file)
        })
        .collect();
    if gaps.is_empty() {
        return;
    }
    println!(
        "
AD CS checks not made (data not collected)"
    );
    for c in gaps {
        let mut missing = Vec::new();
        if !c.published_templates {
            missing.push("published templates unknown (all counted as published)");
        }
        // A value from a settings file over 90 days old can confirm a
        // weakness but not show it fixed.
        if stale(c.esc6_file) {
            missing.push("ESC6 from a settings file over 90 days old");
        } else if !c.esc6 {
            missing.push("ESC6 not checked (CA registry not read)");
        }
        if stale(c.esc11_file) {
            missing.push("ESC11 from a settings file over 90 days old");
        } else if !c.esc11 {
            missing.push("ESC11 not checked (CA registry not read)");
        }
        if !c.esc13 {
            missing.push("ESC13 not checked (template issuance policies not collected)");
        }
        println!("  {:<30} {}", ui::safe(&c.ca_name), missing.join("; "));
    }
}

/// The completeness row of the Tier Zero host probe: "Management
/// agents read on Tier Zero hosts: 3 of 4", then each host, in the words
/// the app uses.
fn print_host_agents(p: &Posture) {
    let a = &p.host_agents;
    if a.is_empty() {
        return;
    }
    println!("\n{}", a.line());
    println!("  {}", pathwarden_core::hostprobe::INTRO);
    let (shown, left) = a.shown();
    for h in shown {
        let found = h.found_words();
        println!(
            "  {:<30} {}{}",
            ui::safe(&h.host),
            ui::safe(&h.read_words()),
            if found.is_empty() {
                String::new()
            } else {
                format!(" Agents found: {}", ui::safe(&found))
            }
        );
    }
    if let Some(more) = pathwarden_core::hostprobe::more_words(left) {
        println!("  {more}");
    }
}

/// The report's Tier Zero settings row: per domain, its domain
/// controllers with current settings (ESC9, ESC10); per Enterprise CA, its
/// settings file (ESC6, ESC11). The same words as the report.
fn print_dc_settings_completeness(p: &Posture) {
    print_host_agents(p);
    if p.dc_settings.is_empty() && p.ca_settings.is_empty() {
        return;
    }
    let (n, words) = pathwarden_core::dcsettings::needing_words(&p.dc_settings, &p.ca_settings);
    println!("\nTier Zero settings: {words}");
    if !p.dc_settings.is_empty() {
        println!("  Domain controllers (ESC9, ESC10)");
        for d in &p.dc_settings {
            println!(
                "    {:<30} {} of {} with current settings. Still needed: {}",
                ui::safe(&d.domain),
                d.current(),
                d.domain_controllers,
                ui::safe(&d.still_needed())
            );
        }
    }
    if !p.ca_settings.is_empty() {
        println!("  Certification authorities (ESC6, ESC11)");
        for c in &p.ca_settings {
            println!(
                "    {:<30} {} Still needed: {}",
                ui::safe(&c.ca),
                ui::safe(&c.settings_words()),
                ui::safe(&c.still_needed())
            );
        }
    }
    if n > 0 {
        println!(
            "  ESC6, ESC9, ESC10 and ESC11 need registry settings that only a settings file provides. \
             Run scripts\\Get-PathwardenTierZeroSettings.ps1 (in the release) on each server, or add \
             a settings folder (`pathwarden config settings-folders add`). A file older than {} days \
             can confirm a weakness but can't show that one was fixed.",
            pathwarden_core::dcsettings::STALE_DAYS
        );
    }
}

/// What the built-in collector read from SYSVOL, when it did.
fn print_sysvol_completeness(p: &Posture) {
    if p.sysvol.is_empty() {
        return;
    }
    println!("\nSYSVOL and NETLOGON (read from one domain controller)");
    for d in &p.sysvol {
        let c = &d.checks;
        let part = |x: &pathwarden_core::sysvol::Check| {
            let mut s = x.status.label().to_string();
            if x.failed > 0 {
                s.push_str(&format!(", {} failed", x.failed));
            }
            s
        };
        println!(
            "  {:<30} GPO folder permissions: {}   logon scripts: {}   GPP passwords: {}",
            ui::safe(&d.domain),
            part(&c.gpo_acl),
            part(&c.logon_script_acl),
            part(&c.gpp)
        );
        for x in [&c.gpo_acl, &c.logon_script_acl, &c.gpp] {
            if let Some(r) = &x.reason {
                println!("    {}", ui::safe(r));
            }
        }
    }
}

/// The few posture numbers worth seeing above a findings list.
fn print_posture_header(p: &Posture) {
    let t0 = &p.tier_zero;
    let c = &p.findings;
    println!(
        "Tier Zero {} · {} with an attack path ({} of {} active accounts) · Tier Zero protected: {} · {}, {}{}",
        t0.exposure_grade.as_str(),
        pathwarden_core::text::count(t0.exposed, "account", "accounts"),
        posture::share_percent(t0.exposure_percent),
        num(t0.relevant_population),
        posture::protected_words(t0.objects, t0.objects_with_findings),
        pathwarden_core::text::count(c.attack_path, "attack path", "attack paths"),
        pathwarden_core::text::count(c.hygiene, "hygiene finding", "hygiene findings"),
        if c.suppressed > 0 {
            format!(", {}", count(c.suppressed, "accepted risk", "accepted risks"))
        } else {
            String::new()
        }
    );
    let weak: Vec<String> = p
        .completeness
        .iter()
        .filter(|d| d.is_low())
        .map(|d| {
            if !d.sessions_targeted && d.local_groups_apply() {
                format!(
                    "{} (local groups {} of member computers)",
                    ui::safe(&d.domain),
                    pct(d.local_groups_percent)
                )
            } else if d.local_groups_untargeted() || !d.local_groups_apply() {
                format!(
                    "{} (sessions {})",
                    ui::safe(&d.domain),
                    pct(d.sessions_percent)
                )
            } else if d.local_groups_apply() {
                format!(
                    "{} (sessions {}, local groups {} of member computers)",
                    ui::safe(&d.domain),
                    pct(d.sessions_percent),
                    pct(d.local_groups_percent)
                )
            } else {
                format!(
                    "{} (sessions {})",
                    ui::safe(&d.domain),
                    pct(d.sessions_percent)
                )
            }
        })
        .collect();
    if !weak.is_empty() {
        println!(
            "Warning: Incomplete collection in {}; see `pathwarden posture`.",
            weak.join(", ")
        );
    }
    if let Some(note) = posture::untargeted(&p.completeness).summary_note() {
        println!("{note}");
    }
    if let Some(note) = pathwarden_core::report::activity_note(p) {
        println!("{}", ui::safe(&note));
    }
}

/// The run history a report compares with.
enum HistoryFrom {
    None,
    /// A state folder's: `--state` (`given`), or `--env`'s.
    State {
        dir: PathBuf,
        given: bool,
    },
}

/// `pathwarden report`. With `--state` or `--env`, the run history gives
/// the Overview its trend and what changed since the last run.
fn report_cmd(input: &Input, output: &std::path::Path, history: HistoryFrom) -> Result<()> {
    let mut p = progress::Analysis::new(Through::Report, input.verbose);
    let a = run_rules(input, &mut p)?.finish(&mut p);
    let now = analyze::now();
    let history = match history {
        HistoryFrom::None => Default::default(),
        HistoryFrom::State { dir, given } => {
            // The run that recorded this data, if one did, is what the
            // report stands for: a nightly run and then a report of its
            // data compare with the run before.
            let digest = a.data_digest();
            let this = pathwarden_core::history::This::Data {
                digest: &digest,
                collected_at: a.stats.collected_at,
            };
            let mut h = pathwarden_core::history::for_report_in(&dir, &a.domains, this);
            // A mistyped --state reads as no history at all; a history of
            // other domains, as none of these.
            if given && h.earlier.is_empty() && h.this_run.is_none() {
                let warn = ui::severity(Severity::Medium);
                let any = pathwarden_core::history::load(&dir)
                    .is_ok_and(|(points, _)| !points.is_empty());
                if any {
                    let names: Vec<String> =
                        a.domains.iter().map(|d| ui::safe(d).into_owned()).collect();
                    anstream::eprintln!(
                        "{warn}Warning:{warn:#} {} has no runs of these domains ({}): the report shows this run alone.",
                        dir.display(),
                        names.join(", ")
                    );
                } else {
                    anstream::eprintln!(
                        "{warn}Warning:{warn:#} No run history in {}: the report shows this run alone.",
                        dir.display()
                    );
                }
            }
            h.context = settings_args(input);
            h
        }
    };
    let html = a.report_html_with(now, &history, &mut p);
    p.done();
    std::fs::write(output, html).with_context(|| format!("writing {}", output.display()))?;
    // `--json`: what was written, for scripts (the report itself is HTML).
    if input.json {
        let t0 = &a.posture.tier_zero;
        return emit_json(&serde_json::json!({
            "report": output,
            "findings": a.findings.len(),
            "plan_steps": a.plan.fixes.len(),
            "tier_zero_exposed": t0.exposed,
            "tier_zero_exposure_percent": t0.exposure_percent,
            "exposure_grade": t0.exposure_grade.as_str(),
            "grade_reason": t0.grade_reason,
            "status_reason": t0.reason.text,
            "protection_score": t0.protection_score,
        }));
    }
    let g = ui::GREEN;
    println!(
        "{g}Wrote{g:#} {} ({}, {}).",
        output.display(),
        count(a.findings.len(), "finding", "findings"),
        count(a.plan.fixes.len(), "plan step", "plan steps")
    );
    Ok(())
}

/// After a run's pull: the shared settings in `config_path` and the
/// repository's, as on every pull, when the history shares them
/// ([`pathwarden_core::settings_sync::after_pull`]). A note, and whether
/// the settings here changed.
fn sync_settings(
    store: &store::Store,
    config_path: Option<&std::path::Path>,
    config: &Config,
    push: bool,
) -> (Option<String>, bool) {
    use pathwarden_core::settings_sync;
    let Some(path) = config_path else {
        return (None, false);
    };
    if settings_sync::inactive(&config.state).is_some() {
        return (None, false);
    }
    let (note, applied) = settings_sync::after_pull(&settings_sync::Place {
        store,
        config_path: path,
        pushes: push && config.state.pushes(),
        env_name: None,
    });
    (note.map(|n| n.text), applied)
}

/// The switches of `pathwarden run`.
struct RunFlags<'a> {
    no_push: bool,
    no_outputs: bool,
    accept_shrink: bool,
    fail_on: Option<Severity>,
    label: Option<&'a str>,
}

fn run_cmd(
    input: &Input,
    state_dir: Option<&std::path::Path>,
    event_path: Option<&std::path::Path>,
    report_path: Option<&std::path::Path>,
    flags: &RunFlags,
) -> Result<ExitCode> {
    let RunFlags {
        no_push,
        no_outputs,
        accept_shrink,
        fail_on,
        label,
    } = *flags;
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();
    let config = read_config(input)?;
    let mut store = store::Store::new(&config.state, state_dir)?;
    if let Some(file) = &input.config {
        store = store.with_config_file(file.clone());
    }
    let warn = ui::severity(Severity::Medium);
    for w in &store.warnings {
        anstream::eprintln!("{warn}Warning:{warn:#} {}", as_sentence(&w.to_string()));
    }
    // Where programs run from: this executable's folder and plugins.
    for w in pathwarden_core::plugins::folder_warnings() {
        anstream::eprintln!("{warn}Warning:{warn:#} {}", as_sentence(&w.to_string()));
    }
    // And the programs and scripts a plugin's `command` names.
    for w in pathwarden_core::plugins::command_warnings(&config.outputs) {
        anstream::eprintln!("{warn}Warning:{warn:#} {}", as_sentence(&w.to_string()));
    }
    if let Some(path) = input
        .config
        .as_deref()
        .filter(|p| store.in_git_working_copy(p))
    {
        anstream::eprintln!(
            "{warn}Warning:{warn:#} The settings {} are inside the run history's git working \
             copy, so anyone who can push to the history's repository controls them, including \
             the programs [[output]] runs. Keep pathwarden.toml outside the history folder (see \
             running.md).",
            path.display()
        );
    }
    let _lock = store.lock_waiting(pathwarden_core::settings_sync::lock_wait())?;
    // A sign-in git couldn't make says how to sign in.
    let pulled = store.pull().map_err(|e| {
        let said = format!("{e:#}");
        match crate::history_cmd::sign_in_words(&said, Some(&store.dir)) {
            Some(w) => anyhow::anyhow!("syncing the run history: {w}"),
            None => e.context("syncing the run history"),
        }
    })?;
    if let Some(note) = pulled {
        anstream::eprintln!("{warn}Warning:{warn:#} {}", as_sentence(&note.to_string()));
    }
    // Shared settings the repository changed are this run's settings too.
    let config = match sync_settings(&store, input.config.as_deref(), &config, !no_push) {
        (Some(note), applied) => {
            anstream::eprintln!("{warn}Note:{warn:#} {}", ui::safe(&as_sentence(&note)));
            if applied {
                read_config(input)?
            } else {
                config
            }
        }
        (None, _) => config,
    };
    let (previous, damaged) = store.load_for_run()?;
    if let Some(note) = damaged {
        anstream::eprintln!("{warn}Warning:{warn:#} {}", ui::safe(&as_sentence(&note)));
    }

    let through = if report_path.is_some() {
        Through::Report
    } else {
        Through::Plan
    };
    let mut p = progress::Analysis::new(through, input.verbose);
    let ev = run_rules(input, &mut p)?;
    let code = fail_on_code(fail_on, &ev.findings);
    let run_outputs = !no_outputs && !config.outputs.is_empty();
    let collected = pathwarden_core::diagnostics::collected_timings(&input.input);
    let rec = record(
        &store,
        &previous,
        ev,
        &config,
        &Record {
            started_ms,
            event_path,
            report_path,
            no_push,
            accept_shrink,
            want_event: run_outputs,
            label,
            timings: collected.as_ref().map(|c| &c.timings),
            context: &settings_args(input),
            config_path: input.config.as_deref(),
            source: &source_words(&input.input),
        },
        &mut p,
    )?;
    if let Some(c) = &collected {
        c.mark_recorded();
    }

    let c = rec.counts;
    let (gr, bold) = (ui::GREEN, ui::BOLD);
    match label {
        Some(l) => println!(
            "{bold}Run {}{bold:#} · label \"{}\"",
            rec.run_id,
            ui::safe(l)
        ),
        None => println!("{bold}Run {}{bold:#}", rec.run_id),
    }
    println!(
        "  {} new, {} back, {} fixed, {} still open, {}{}{}.",
        num(c.new),
        num(c.regressed),
        num(c.resolved),
        num(c.open),
        count(c.suppressed, "accepted risk", "accepted risks"),
        if c.held > 0 && rec.not_targeted.is_some() {
            format!(
                ", {} can't tell (not collected, not read or not targeted this run)",
                c.held
            )
        } else if c.held > 0 {
            format!(
                ", {} can't tell (not collected or not read this run)",
                c.held
            )
        } else {
            String::new()
        },
        if c.unchecked > 0 {
            format!(", {} no longer checked (rule turned off)", c.unchecked)
        } else {
            String::new()
        }
    );
    println!(
        "  Tier Zero {} · Tier Zero protected: {}",
        rec.status, rec.protected
    );
    println!("  {}", ui::safe(&rec.reason));
    if let Some(note) = &rec.not_targeted {
        println!("  {note}");
    }
    if let Some((line, notes)) = &rec.settings {
        println!("  {}", ui::safe(line));
        for n in notes {
            println!("  {}", ui::safe(n));
        }
    }
    println!(
        "  {gr}Run history{gr:#} {}{}.",
        store.describe(),
        if rec.pushed {
            ", pushed"
        } else if rec.unpushed.is_some() {
            ", committed here, not pushed (see below)"
        } else if no_push {
            ", not pushed (--no-push)"
        } else if !config.state.pushes() && store.is_git() {
            ", not pushed ([state] push = false)"
        } else {
            ""
        }
    );
    print_full_run(
        rec.full_run.as_ref().map(|f| &f.0),
        rec.full_run.as_ref().map(|f| f.1),
    );
    if let Some(p) = event_path {
        println!("  {gr}Event{gr:#} {}", p.display());
    }
    if let Some(p) = report_path {
        println!("  {gr}Report{gr:#} {}", p.display());
    }
    // What changed, as `pathwarden history` prints it; its commands take
    // the settings this run was given.
    if let Some(since) = &rec.since {
        println!();
        print!("{}", since.render(&settings_args(input)));
    }
    if let Some(k) = &rec.unpushed {
        let warn = ui::severity(Severity::Medium);
        let words = match crate::history_cmd::sign_in_words(&k.detail, Some(&store.dir)) {
            Some(w) => format!("This run is recorded here, but not pushed: {w}"),
            None => k.sentence("This run is recorded"),
        };
        anstream::eprintln!("{warn}Warning:{warn:#} {}", ui::safe_text(&words));
        if input.verbose {
            anstream::eprintln!("  git: {}", ui::safe_text(&k.detail));
        }
    }

    // Plugins run last, once the state is saved: a failing plugin never loses
    // state, and plugins reconcile against their own systems, so the next run
    // catches up with anything this one missed.
    let mut failed = Vec::new();
    if run_outputs && rec.inserted {
        // Its findings are older than the history's: a ticket the newer run
        // left open must not be closed by this one.
        let warn = ui::severity(Severity::Medium);
        anstream::eprintln!(
            "{warn}Warning:{warn:#} The output plugins weren't run: a newer run was recorded in \
             the run history first, so this run's event is older than the history."
        );
    } else if let (true, Some(text)) = (run_outputs, &rec.event_json) {
        for output in &config.outputs {
            if let Err(e) = outputs::run(output, text) {
                let red = ui::severity(Severity::Critical);
                eprintln!(
                    "  {red}Plugin {} failed:{red:#} {}",
                    ui::safe(&output.plugin),
                    ui::safe_text(&format!("{e:#}"))
                );
                failed.push(output.plugin.clone());
            }
        }
    }
    // Recorded, but not pushed: the run fails too (exit code 2, whatever
    // --fail-on says), so a schedule notices. The warning above said why.
    let full_unpushed = rec
        .full_run
        .as_ref()
        .is_some_and(|(l, _)| l.state == pathwarden_ui::shared_runs::FullRunState::Unpushed);
    let unpushed = if rec.unpushed.is_some() {
        Some(UNPUSHED)
    } else {
        full_unpushed.then_some(FULL_UNPUSHED)
    };
    if !failed.is_empty() {
        bail!(
            "{} failed: {}{}",
            pathwarden_core::text::count(failed.len(), "output plugin", "output plugins"),
            failed.join(", "),
            unpushed.map(|u| format!("; and {u}")).unwrap_or_default()
        );
    }
    if let Some(u) = unpushed {
        bail!("{u}");
    }
    Ok(code)
}

/// The error a command ends with when its run was recorded but not pushed
/// (after a warning that says why).
pub(crate) const UNPUSHED: &str = "the run was recorded here, but not pushed";

/// The error a command ends with when its run was pushed but its full run
/// is committed here only (it goes with the next push).
pub(crate) const FULL_UNPUSHED: &str =
    "the run was recorded, but its full run is committed here, not pushed";

/// "  Full run  in the history (2.1 MB)", or a warning saying why not.
pub(crate) fn print_full_run(
    link: Option<&pathwarden_ui::shared_runs::FullRunLink>,
    bytes: Option<u64>,
) {
    let Some(link) = link else {
        return;
    };
    let (text, warn) = pathwarden_ui::shared_runs::words(link, bytes);
    if warn {
        let w = ui::severity(Severity::Medium);
        anstream::eprintln!("{w}Warning:{w:#} {}", ui::safe_text(&text));
    } else {
        let gr = ui::GREEN;
        let rest = text.strip_prefix("Full run ").unwrap_or(&text);
        println!("  {gr}Full run{gr:#} {}", ui::safe_text(rest));
    }
}

/// The settings a command was given, as the commands "since the last run"
/// points at take them: `--env NAME` (and `--workspace`), or `-c PATH`.
pub(crate) fn settings_args(input: &Input) -> Vec<String> {
    match (&input.env.env, &input.config) {
        (Some(name), _) => {
            let mut c = vec!["--env".to_string(), name.clone()];
            if let Some(ws) = &input.env.env_workspace {
                c.extend(["--workspace".to_string(), ws.display().to_string()]);
            }
            c
        }
        (None, Some(path)) => vec!["-c".to_string(), path.display().to_string()],
        (None, None) => Vec::new(),
    }
}

/// `pathwarden demo`: the report for the built-in demo collection, and what
/// to try next.
fn demo_cmd(output: Option<PathBuf>, verbose: bool) -> Result<()> {
    let header = logo::header();
    if let Some(header) = &header {
        println!(
            "{header}
"
        );
    }
    let output = match output {
        Some(path) => {
            // A folder that isn't there yet is made, as `collect -o` does,
            // before the analysis rather than after it.
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
            path
        }
        None => demo::fresh_temp_dir("pathwarden-demo-report")?.join("pathwarden-demo-report.html"),
    };
    let data = demo::unpack()?;
    // The demo's earlier runs recorded first, as the app's Try the demo does
    // ([`pathwarden_ui::demo_runs`]), so the report has a real history: its
    // trend, what changed and the Introduced filter. In a folder of its own,
    // removed at the end.
    let work = demo::fresh_temp_dir("pathwarden-demo-history")?;
    let recorded = demo_history(&work, &data.zip, &output, verbose);
    let _ = std::fs::remove_dir_all(&work);
    recorded?;
    let (h, lit) = (ui::VIOLET.bold(), ui::GREEN.bold());
    // On a terminal, a line between the progress and this; piped, none.
    println!(
        "{}The demo is SCALE.LOCAL, a made-up company of 15,000 users. Next:\n",
        if header.is_some() { "\n" } else { "" }
    );
    let steps = [
        ("Read the report", output.display().to_string()),
        (
            "Explore it in the app",
            "pathwarden ui   (then Try the demo)".into(),
        ),
        (
            "Same data, any command",
            "pathwarden findings -i demo: --min-severity high".into(),
        ),
        ("", "pathwarden plan -i demo:".into()),
        ("Your own domain", "pathwarden collect --help".into()),
        ("", "pathwarden report -i <the collection zip>".into()),
    ];
    for (label, what) in steps {
        println!("  {h}{label:<24}{h:#}{lit}{}{lit:#}", ui::safe(&what));
    }
    Ok(())
}

/// [`demo_cmd`]'s runs: the demo's earlier collections, then its own,
/// recorded in a state folder in `work` with the demo's zone, the last one
/// writing the report to `output`.
fn demo_history(
    work: &std::path::Path,
    latest: &std::path::Path,
    output: &std::path::Path,
    verbose: bool,
) -> Result<()> {
    use pathwarden_ui::demo_runs::{EARLIER, GAP, ZONE_CONFIG};
    let config_path = work.join("pathwarden.toml");
    std::fs::write(&config_path, ZONE_CONFIG)?;
    let state_dir = work.join("state");
    let config = Config::from_file(&config_path)?;
    let store = store::Store::new(&config.state, Some(&state_dir))?;
    let now = analyze::now();
    let n = EARLIER.len() as i64;
    let mut files = Vec::new();
    for (name, zip) in EARLIER {
        let file = work.join(name);
        std::fs::write(&file, zip)?;
        files.push(file);
    }
    files.push(latest.to_path_buf());
    let context = ["-i".to_string(), demo::INPUT.to_string()];
    for (i, file) in files.iter().enumerate() {
        let last = i == files.len() - 1;
        let input = Input {
            input: vec![file.clone()],
            tier_zero: Vec::new(),
            config: Some(config_path.clone()),
            env: EnvArgs::default(),
            json: false,
            verbose,
        };
        let through = if last { Through::Report } else { Through::Plan };
        // The earlier runs say so, and how many are in.
        let mut p = if last {
            progress::Analysis::new(through, verbose)
        } else {
            progress::Analysis::titled(through, verbose, &progress::demo_earlier_title(i))
        };
        let ev = run_rules(&input, &mut p)?;
        let previous = store.load()?;
        let at = now - (n - i as i64) * GAP;
        record(
            &store,
            &previous,
            ev,
            &config,
            &Record {
                started_ms: at * 1000,
                event_path: None,
                report_path: last.then_some(output),
                no_push: true,
                accept_shrink: false,
                want_event: false,
                label: None,
                timings: None,
                context: &context,
                config_path: None,
                source: "",
            },
            &mut p,
        )?;
    }
    Ok(())
}

/// How [`record`] records a run.
pub(crate) struct Record<'a> {
    pub started_ms: i64,
    pub event_path: Option<&'a std::path::Path>,
    pub report_path: Option<&'a std::path::Path>,
    pub no_push: bool,
    pub accept_shrink: bool,
    /// Build the event document even without `event_path` (for plugins).
    pub want_event: bool,
    /// The run's label, for the history point and the report title.
    pub label: Option<&'a str>,
    /// The timings `pathwarden collect` left with the data (a schedule's),
    /// kept in the state with the run.
    pub timings: Option<&'a pathwarden_core::diagnostics::CollectionTimings>,
    /// The settings the run was given ([`settings_args`]), for the
    /// report's What changed commands.
    pub context: &'a [String],
    /// The `pathwarden.toml` the run was given (`-c`), whose shared
    /// sections a full run keeps ([`pathwarden_ui::shared_runs`]).
    pub config_path: Option<&'a std::path::Path>,
    /// What was analysed, in words ([`source_words`]), for a full run.
    pub source: &'a str,
}

/// A recorded run.
pub(crate) struct Recorded {
    pub run_id: String,
    pub counts: pathwarden_core::state::ChangeCounts,
    /// "Critical: 509 accounts have an attack path to Tier Zero" for the summary.
    pub status: String,
    /// Why Tier Zero has that status, as the report says it.
    pub reason: String,
    /// Tier Zero's protected share in words ([`posture::protected_words`]).
    pub protected: String,
    /// What the run did not target (a Quick run), as one note.
    pub not_targeted: Option<String>,
    pub pushed: bool,
    /// Added before a newer run another machine pushed first
    /// ([`pathwarden_core::record::Saved::inserted`]): output plugins don't
    /// get its event.
    pub inserted: bool,
    /// The push failed, but the run is recorded in the working copy and the
    /// next run pushes it: why. The run still exits with an error.
    pub unpushed: Option<pathwarden_core::store::KeptUnpushed>,
    pub event_json: Option<String>,
    /// What changed since the run before it, as `pathwarden history` says.
    pub since: Option<pathwarden_core::since::SinceLast>,
    /// With "Full runs and settings": how the run went into the history in
    /// full, and its size.
    pub full_run: Option<(pathwarden_ui::shared_runs::FullRunLink, u64)>,
    /// The Tier Zero settings files the run used, and what the run
    /// says about them: one line, then sentences (fewer than the last run,
    /// folders that couldn't be opened). `None` when there is nothing to say.
    pub settings: Option<(String, Vec<String>)>,
}

/// The Tier Zero settings files line of `run` and `retest`: "Tier
/// Zero settings files: 6 files, 2 over 90 days old", and the sentences
/// that follow it, as Run details says them.
pub(crate) fn settings_lines(
    files: &[pathwarden_core::dcsettings::SettingsFileUse],
    fewer: &[String],
    unread: usize,
) -> Option<(String, Vec<String>)> {
    use pathwarden_core::dcsettings;
    if files.is_empty() && fewer.is_empty() && unread == 0 {
        return None;
    }
    let line = format!(
        "Tier Zero settings files: {}",
        dcsettings::files_status(files, fewer.len())
    );
    let notes = dcsettings::fewer_sentence(fewer)
        .into_iter()
        .chain(dcsettings::unread_sentence(unread))
        .collect();
    Some((line, notes))
}

/// The Tier Zero settings folders that couldn't be opened, one warning
/// each, with the folder: the terminal of the computer that runs it may
/// name it (runs record file names only).
pub(crate) fn settings_folder_warnings(stats: &IngestStats) -> Vec<String> {
    let warn = ui::severity(Severity::Medium);
    stats
        .settings_folders_unread
        .iter()
        .map(|(dir, why)| {
            format!(
                "{warn}Warning:{warn:#} The Tier Zero settings folder {} couldn't be opened, so its files weren't read: {}.",
                ui::safe(dir),
                ui::safe(why)
            )
        })
        .chain(stats.settings_folder_warnings.iter().map(|w| {
            format!(
                "{warn}Warning:{warn:#} Tier Zero settings folder {}",
                ui::safe(w)
            )
        }))
        .collect()
}

/// Terminal warnings for [`pathwarden_core::record::prepare`].
impl pathwarden_core::record::RecordProgress for progress::Analysis {
    fn warn(&mut self, message: String) {
        let warn = ui::severity(Severity::Medium);
        self.note(format!(
            "{warn}Warning:{warn:#} {}",
            ui::safe_text(&message)
        ));
    }
}

/// What recorded this run: the generated nightly scripts set
/// `PATHWARDEN_SCHEDULED=1`, so the UI can tell scheduled runs apart.
pub(crate) fn recorded_by() -> &'static str {
    use pathwarden_core::record::by;
    match std::env::var_os("PATHWARDEN_SCHEDULED") {
        Some(v) if !v.is_empty() && v != "0" => by::SCHEDULE,
        _ => by::CLI,
    }
}

/// Records an analysis as a run in the state (already locked and pulled):
/// compares it with `previous` ([`pathwarden_core::record::prepare`], shared
/// with the UI), saves the state and history point, commits and pushes
/// (git; [`pathwarden_core::record::save_and_publish`]), and writes the
/// event and report when asked.
pub(crate) fn record(
    store: &store::Store,
    previous: &pathwarden_core::state::FindingsState,
    ev: Evaluated,
    config: &Config,
    opts: &Record,
    p: &mut progress::Analysis,
) -> Result<Recorded> {
    use pathwarden_core::{event, record};

    let prev_run = store::last_run(store);
    let record_opts = record::Options {
        started_ms: opts.started_ms,
        accept_shrink: opts.accept_shrink,
        recorded_by: recorded_by(),
        finished_at: None,
    };
    let mut prep = record::prepare(prev_run.as_ref(), previous, ev, config, &record_opts, p);
    prep.point.label = opts.label.map(str::to_string);
    if opts.report_path.is_none() {
        p.done();
    }
    // Saved, and committed and pushed (git) before the event and report:
    // if another run pushed first, this one is compared again with what it
    // left, and they tell what was recorded. `[state] push = false` works
    // like --no-push.
    let (prep, saved) = record::save_and_publish(
        store,
        prep,
        config,
        &record_opts,
        opts.timings,
        !opts.no_push && config.state.pushes(),
        p,
    );
    // Not recorded (a failed save, another run's state it could not be
    // applied on): nothing more is written. A failed push with the run
    // recorded here is told at the end ([`Recorded::unpushed`]).
    let saved = saved?;
    let (a, r, last) = (&prep.analysis, &prep.reconciled, &prep.last);

    let event_json = if opts.event_path.is_some() || opts.want_event {
        let doc = event::build(
            last,
            &a.posture,
            &a.findings,
            &r.changes,
            &r.state.findings,
            &r.resolved,
            &a.plan,
        );
        // Serialized from the struct, not through a `Value`: without
        // serde_json's `preserve_order` (the lean build) a `Value` sorts its
        // keys, and `schema` must come first for `retest --baseline`.
        let doc = event::Event {
            superseded: saved.inserted,
            ..doc
        };
        let mut text = serde_json::to_string_pretty(&doc)?;
        text.push('\n');
        Some(text)
    } else {
        None
    };
    if let (Some(path), Some(text)) = (opts.event_path, &event_json) {
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    }
    // The history the run is in now, read once for the report and since.
    let points = store
        .check_expected()
        .ok()
        .and_then(|_| pathwarden_core::history::load(&store.dir).ok())
        .map(|(p, _)| p);
    if let Some(path) = opts.report_path {
        // The run is in the history now: the report compares with the ones
        // before it.
        let mut history = match &points {
            Some(points) => pathwarden_core::history::for_report_with(
                &store.dir,
                points,
                &a.domains,
                pathwarden_core::history::This::Run(&last.run_id),
                &r.state,
            ),
            None => Default::default(),
        };
        history.context = opts.context.to_vec();
        let html = a.report_html_labeled(prep.finished, opts.label, &history, &mut *p);
        p.done();
        std::fs::write(path, html).with_context(|| format!("writing {}", path.display()))?;
    }
    let full_run = full_run(store, &prep, points.as_deref(), config, opts, &mut *p);

    Ok(Recorded {
        run_id: last.run_id.clone(),
        counts: r.counts,
        status: format!(
            "{}: {}",
            a.posture.tier_zero.exposure_grade.as_str(),
            a.posture.headline().title
        ),
        reason: a.posture.tier_zero.reason.text.clone(),
        protected: posture::protected_words(
            a.posture.tier_zero.objects,
            a.posture.tier_zero.objects_with_findings,
        ),
        not_targeted: posture::untargeted(&a.posture.completeness).summary_note(),
        pushed: saved.pushed,
        inserted: saved.inserted,
        unpushed: saved.unpushed,
        event_json,
        since: points
            .as_deref()
            .and_then(|p| pathwarden_core::history::since_run_with(p, &last.run_id, &r.state)),
        full_run,
        settings: settings_lines(
            &last.settings_files,
            &prep.settings_fewer,
            a.stats.settings_folders_unread.len(),
        ),
    })
}

/// With "Full runs and settings": the recorded run in full, built here (a
/// schedule's `pathwarden run` keeps no run folder) and committed after its
/// point, under the lock the caller holds
/// ([`pathwarden_ui::shared_runs::publish`]). `None` when the history
/// doesn't keep full runs, or this run isn't pushed.
fn full_run(
    store: &store::Store,
    prep: &pathwarden_core::record::Prepared,
    points: Option<&[pathwarden_core::state::HistoryPoint]>,
    config: &Config,
    opts: &Record,
    p: &mut progress::Analysis,
) -> Option<(pathwarden_ui::shared_runs::FullRunLink, u64)> {
    use pathwarden_ui::shared_runs::{self, Bundle, LeftOut, Parts};
    use pathwarden_ui::workspace::{HistoryLink, RunSummary};
    let push = !opts.no_push && config.state.pushes();
    if !shared_runs::wanted(config) || (store.is_git() && !push) {
        return None;
    }
    let (a, r, last) = (&prep.analysis, &prep.reconciled, &prep.last);
    // As the app's run folder keeps it: no label (the summary has it), no
    // command hints with this computer's paths.
    let history = match points {
        Some(points) => pathwarden_core::history::for_report_with(
            &store.dir,
            points,
            &a.domains,
            pathwarden_core::history::This::Run(&last.run_id),
            &r.state,
        ),
        None => Default::default(),
    };
    // The account lists, made once for the report and the run's files.
    let lists = a.exposure_lists(&history);
    let html = a.report_html_lists(prep.finished, &history, &lists, &mut *p);
    p.done();
    let folder = pathwarden_ui::workspace::new_run_id(prep.finished);
    let mut summary = RunSummary::new(&folder, prep.finished, opts.source.to_string(), false, a);
    summary.label = opts.label.map(str::to_string);
    summary.history = Some(HistoryLink {
        run_id: Some(last.run_id.clone()),
        settings_fewer: prep.settings_fewer.clone(),
        ..HistoryLink::default()
    });
    let config_text = opts
        .config_path
        .and_then(|path| std::fs::read_to_string(path).ok());
    // A full run in the history only: no run folder, so no query fields.
    let extra = pathwarden_ui::run_data::bundle_files(&last.run_id, a, prep.finished, &lists);
    drop(lists);
    summary.tier_zero_lists = extra
        .iter()
        .any(|(n, _)| *n == pathwarden_ui::run_data::EXPOSED_FILE);
    summary.tier_zero_change = pathwarden_core::report::opens_change(&html);
    let bundle = Bundle::build(
        Parts {
            run_id: &last.run_id,
            summary: &summary,
            report_html: &html,
            extra,
            config_text: config_text.as_deref(),
            recorded_from: recorded_by(),
            folder: None,
        },
        shared_runs::file_limit(&config.state, store),
    );
    drop(html);
    let left_out: Vec<String> = bundle
        .manifest
        .left_out
        .iter()
        .map(LeftOut::words)
        .collect();
    let bytes = bundle.bytes();
    let published = shared_runs::publish(store, &[bundle], config.state.full_runs_kept(), push);
    let mut link = shared_runs::link_for(&last.run_id, &published);
    link.left_out = left_out;
    if link.state == shared_runs::FullRunState::Unpushed {
        // Kept here for the next push, even past another machine's; but
        // this run keeps no folder to make it again from.
        if let Some(why) = link.why.as_mut() {
            why.push(' ');
            why.push_str(shared_runs::NO_FOLDER_WORDS);
        }
    }
    Some((link, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `pathwarden retest targeted` and the run page's Retest now are one
    /// piece of code: the same finding, re-read through the same fake
    /// collector (nothing is contacted), gets the same verdict and the
    /// same words, and both keep it with the run.
    #[test]
    fn retest_targeted_is_the_dialogs_retest() {
        use pathwarden_collect::{FixedRefresher, HostRead};
        if !pathwarden_ui::collect::BUILTIN {
            return;
        }
        let dir = std::env::temp_dir().join(format!("pw-cli-targeted-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ws_dir = dir.join("ws");
        let forest =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        let save = Cli::try_parse_from([
            "pathwarden",
            "run",
            "-i",
            forest.to_str().unwrap(),
            "--save",
            "--new-env",
            "Lab",
            "--workspace",
            ws_dir.to_str().unwrap(),
        ])
        .unwrap();
        run(save.command.unwrap()).unwrap();
        let fp = "PW-006-8ae0b31a46eacada";
        let srv01 = "S-1-5-21-1000-1000-1000-1001";
        let unreachable = || {
            FixedRefresher::new(
                &forest,
                vec![HostRead {
                    id: srv01.into(),
                    name: "SRV01.CONTOSO.LOCAL".into(),
                    sessions: Some(false),
                    local_groups: Some(false),
                    why: Some("it didn't answer on port 445".into()),
                    unreachable: true,
                    skipped: false,
                    ..Default::default()
                }],
            )
        };
        let parsed = Cli::try_parse_from([
            "pathwarden",
            "retest",
            "targeted",
            "--finding",
            fp,
            "--env",
            "Lab",
            "--workspace",
            ws_dir.to_str().unwrap(),
            "--json",
        ])
        .unwrap();
        let Some(Command::Retest {
            action: Some(retest_cmd::RetestAction::Targeted(args)),
            ..
        }) = parsed.command
        else {
            panic!("not retest targeted");
        };
        // As the current Windows account (Windows only): the computers on
        // the path are read as that account, SRV01 doesn't answer, and both
        // say so in the same words, with no password sentence.
        if !cfg!(windows) {
            return;
        }
        let cli_reader = unreachable();
        let code = retest_cmd::targeted_with(args, &cli_reader).unwrap();
        assert_eq!(code, ExitCode::from(exit::CANT_TELL));
        assert_eq!(cli_reader.asked.lock().unwrap()[0].hosts.len(), 1);
        assert_eq!(cli_reader.asked.lock().unwrap()[0].hosts[0].id, srv01);

        let ws = pathwarden_ui::environments::cli_workspace(Some(&ws_dir), "Lab").unwrap();
        let run = ws.runs().into_iter().next().unwrap();
        let run_dir = ws.run_dir(&run.id).unwrap();
        let cli = pathwarden_ui::retest_ui::load_log(&run_dir).results;
        assert_eq!(cli.len(), 1);
        // The dialog, signed in as the same (current) account.
        let form = pathwarden_ui::retest_ui::RetestForm {
            fingerprint: fp.into(),
            domain: "contoso.local".into(),
            ..Default::default()
        };
        let ui = pathwarden_ui::retest_ui::targeted(&ws, &run_dir, form, &unreachable()).unwrap();
        assert_eq!(cli[0].verdict, ui.verdict);
        assert_eq!(cli[0].details, ui.details);
        assert_eq!(
            ui.details[0],
            "The computer on its path couldn't be reached, so it can't be checked."
        );
        assert!(
            !ui.details.iter().any(|d| d.contains("password")),
            "{:?}",
            ui.details
        );
        assert_eq!(
            pathwarden_ui::retest_ui::result_lines(&cli[0]),
            pathwarden_ui::retest_ui::result_lines(&ui)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The service and task reads each follow their own flag and
    /// `[collect]` key; `--service-reads` / `--task-reads` win over the
    /// file, as the app's options do.
    #[test]
    fn service_and_task_reads_follow_their_own_switches() {
        let dir = std::env::temp_dir().join(format!("pw-cli-reads-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("pathwarden.toml");
        let reads = |toml: &str, extra: &[&str]| {
            std::fs::write(&file, toml).unwrap();
            let mut argv = vec!["pathwarden", "collect", "-d", "contoso.local", "-o", "out"];
            argv.extend(["-c", file.to_str().unwrap()]);
            argv.extend(extra.iter().copied());
            let Some(Command::Collect(mut c)) = Cli::try_parse_from(&argv).unwrap().command else {
                panic!("not collect");
            };
            apply_collect_config(&mut c, None).unwrap();
            let r = c.args.into_request().unwrap();
            (r.service_reads, r.task_reads)
        };
        assert_eq!(reads("", &[]), (true, true));
        assert_eq!(reads("", &["--no-task-reads"]), (true, false));
        assert_eq!(reads("", &["--no-service-reads"]), (false, true));
        assert_eq!(reads("[collect]\ntask_reads = false\n", &[]), (true, false));
        assert_eq!(
            reads("[collect]\nservice_reads = false\n", &[]),
            (false, true)
        );
        let both = "[collect]\nservice_reads = false\ntask_reads = false\n";
        assert_eq!(reads(both, &[]), (false, false));
        assert_eq!(reads(both, &["--task-reads"]), (false, true));
        assert_eq!(reads(both, &["--service-reads"]), (true, false));
        assert_eq!(
            reads(both, &["--service-reads", "--task-reads"]),
            (true, true)
        );
        assert_eq!(
            reads("[collect]\ntask_reads = true\n", &["--no-task-reads"]),
            (true, false),
            "the command wins when it turns them off"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--no-cache` reads into memory; a full disk says what the
    /// command line can do about it, after the app's words.
    #[test]
    fn no_cache_and_a_full_disk() {
        let parse = |extra: &[&str]| {
            let mut argv = vec!["pathwarden", "collect", "-d", "contoso.local", "-o", "out"];
            argv.extend(extra.iter().copied());
            let Some(Command::Collect(c)) = Cli::try_parse_from(&argv).unwrap().command else {
                panic!("not collect");
            };
            c.args
        };
        assert!(parse(&["--no-cache"]).no_cache);
        assert!(!parse(&[]).no_cache);
        // Set by the caller from the workspace, as the app does.
        assert_eq!(parse(&[]).into_request().unwrap().cache, None);
        // The attributes RustHound-CE reads, unless every one is asked for.
        assert!(!parse(&[]).into_request().unwrap().all_attributes);
        assert!(
            parse(&["--all-attributes"])
                .into_request()
                .unwrap()
                .all_attributes
        );
        // `--read-streams N`, 1 to 8; not given, the settings'
        // or the collector's default decides.
        assert_eq!(parse(&[]).into_request().unwrap().read_streams, None);
        assert_eq!(
            parse(&["--read-streams", "2"])
                .into_request()
                .unwrap()
                .read_streams,
            Some(2)
        );
        for bad in ["0", "9", "four"] {
            let argv = [
                "pathwarden",
                "collect",
                "-d",
                "contoso.local",
                "-o",
                "out",
                "--read-streams",
                bad,
            ];
            assert!(Cli::try_parse_from(argv).is_err(), "{bad}");
        }
        let full = pathwarden_collect::NoSpace {
            place: "C:".into(),
            needed: 13 << 30,
            free: 6 << 30,
        };
        assert_eq!(
            progress::no_space_hint(anyhow::Error::new(full)).to_string(),
            "Not enough free space on C: for this read: about 13 GB needed, 6 GB free. Free some \
             space, or pass --no-cache to read into memory."
        );
        let other = progress::no_space_hint(anyhow::anyhow!("refused"));
        assert_eq!(other.to_string(), "refused");
    }

    /// `--resume` continues a stopped read; without it, the
    /// run says it starts over. The app's offer finds the same reads.
    #[test]
    fn resume_and_starting_over() {
        let parse = |extra: &[&str]| {
            let mut argv = vec!["pathwarden", "collect", "-d", "contoso.local", "-o", "out"];
            argv.extend(extra.iter().copied());
            let Some(Command::Collect(c)) = Cli::try_parse_from(&argv).unwrap().command else {
                panic!("not collect");
            };
            c.args
        };
        assert!(parse(&["--resume"]).resume);
        assert!(!parse(&[]).resume);
        let both = [
            "pathwarden",
            "collect",
            "-d",
            "contoso.local",
            "--resume",
            "--no-cache",
        ];
        assert!(Cli::try_parse_from(both).is_err());
        let stopped = pathwarden_collect::ReadStopped {
            domain: "contoso.local".into(),
            dc: Some("dc01.contoso.local".into()),
            reason: "LDAP search of DC=contoso,DC=local failed: connection reset".into(),
        };
        assert_eq!(
            progress::no_space_hint(anyhow::Error::new(stopped)).to_string(),
            "The read stopped: the connection to dc01.contoso.local was lost. It can be resumed \
             for 24 hours. Run the same command with --resume to continue it."
        );
        if !pathwarden_ui::collect::BUILTIN {
            return;
        }
        let dir = std::env::temp_dir().join(format!("pw-cli-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = pathwarden_collect::ReadCache {
            root: dir.clone(),
            ..pathwarden_collect::ReadCache::default()
        };
        let mut req = parse(&[]).into_request().unwrap();
        req.cache = Some(cache.clone());
        let now = pathwarden_core::analyze::now();
        let notes = |resume| progress::resume_notes(&req, &[], resume, now);
        // Nothing to resume.
        assert!(notes(false).is_empty());
        assert_eq!(
            notes(true),
            ["No stopped read of contoso.local to resume; starting from the beginning."]
        );
        // A read that stopped two hours ago.
        let me = pathwarden_collect::Auth::CurrentUser;
        pathwarden_collect::fake_stopped_read(&cache, "contoso.local", &me, 61, now - 7300)
            .unwrap();
        assert_eq!(
            notes(false),
            [
                "An earlier read of contoso.local stopped at 61% (2 h ago); starting over. Pass \
              --resume to continue it."
            ]
        );
        assert_eq!(
            notes(true),
            ["Resuming the read of contoso.local that stopped at 61% (2 h ago)."]
        );
        // Each domain of the run, once.
        let trusted = ["fabrikam.local".to_string(), "CONTOSO.LOCAL".to_string()];
        assert_eq!(progress::resume_notes(&req, &trusted, false, now).len(), 1);
        // Over 24 hours: nothing to say, it starts over.
        pathwarden_collect::fake_stopped_read(&cache, "contoso.local", &me, 61, now - 90_000)
            .unwrap();
        assert!(notes(false).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `collect`'s `--allow-ntlm` and `--allow-unsigned-smb` and the
    /// wizard's "Kerberos only" and "Require SMB signing" build the same
    /// request (one code path), recorded the same way, both on by default.
    #[test]
    fn computer_sign_in_flags_are_the_wizards_toggles() {
        use pathwarden_ui::collect::{build_request, collection_info, CollectForm};
        // The wizard signs in as the current account on Windows only.
        if !cfg!(windows) || !pathwarden_ui::collect::BUILTIN {
            return;
        }
        for (flags, ntlm, unsigned) in [
            (vec![], false, false),
            (vec!["--allow-ntlm"], true, false),
            (vec!["--allow-unsigned-smb"], false, true),
            (vec!["--allow-ntlm", "--allow-unsigned-smb"], true, true),
        ] {
            let mut argv = vec!["pathwarden", "collect", "-d", "contoso.local", "-o", "out"];
            argv.extend(flags.iter().copied());
            let Some(Command::Collect(c)) = Cli::try_parse_from(&argv).unwrap().command else {
                panic!("not collect");
            };
            let cli = c.args.into_request().unwrap();
            let app = build_request(
                CollectForm {
                    domain: "contoso.local".into(),
                    allow_ntlm: ntlm,
                    allow_unsigned_smb: unsigned,
                    ..CollectForm::default()
                },
                "out".into(),
            )
            .unwrap();
            for req in [&cli, &app] {
                assert_eq!(
                    (req.allow_ntlm, req.allow_unsigned_smb),
                    (ntlm, unsigned),
                    "{flags:?}"
                );
            }
            assert_eq!(collection_info(&cli), collection_info(&app), "{flags:?}");
            assert_eq!(
                pathwarden_collect::computers_words(&cli),
                pathwarden_collect::computers_words(&app)
            );
            assert_eq!(collection_info(&cli).kerberos_only, Some(!ntlm));
            // As the Windows account, signing is Windows' own: not recorded,
            // and --allow-unsigned-smb is said to have no effect.
            assert_eq!(collection_info(&cli).smb_signing, None);
            assert_eq!(
                pathwarden_collect::computers_words(&cli).contains("has no effect"),
                unsigned
            );
        }
        // A form that says nothing about them (an older page) is Kerberos
        // only with signing required.
        let form: CollectForm =
            serde_json::from_str(r#"{"domain":"contoso.local","auth":"current"}"#).unwrap();
        assert!(!form.allow_ntlm && !form.allow_unsigned_smb);
    }

    /// `retest targeted`'s flags reach the re-read as the dialog's
    /// checkboxes do.
    #[test]
    fn retest_stored_reads_switches_are_the_dialogs() {
        use std::sync::Mutex;
        // (services, tasks) each retest asked the collector for.
        struct Seen(Mutex<Vec<(bool, bool)>>);
        impl pathwarden_collect::Refresher for Seen {
            fn refresh(
                &self,
                req: &pathwarden_collect::CollectRequest,
                _: &pathwarden_collect::RefreshTarget,
            ) -> anyhow::Result<pathwarden_collect::Refreshed> {
                self.0
                    .lock()
                    .unwrap()
                    .push((req.service_reads, req.task_reads));
                anyhow::bail!("not contacted in tests")
            }
        }
        if !pathwarden_ui::collect::BUILTIN || !cfg!(windows) {
            return;
        }
        let dir = std::env::temp_dir().join(format!("pw-cli-stored-flags-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ws_dir = dir.join("ws");
        let forest =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        let save = Cli::try_parse_from([
            "pathwarden",
            "run",
            "-i",
            forest.to_str().unwrap(),
            "--save",
            "--new-env",
            "Lab",
            "--workspace",
            ws_dir.to_str().unwrap(),
        ])
        .unwrap();
        run(save.command.unwrap()).unwrap();
        let fp = "PW-006-8ae0b31a46eacada";
        let ws = pathwarden_ui::environments::cli_workspace(Some(&ws_dir), "Lab").unwrap();
        let run_id = ws.runs().into_iter().next().unwrap();
        let run_dir = ws.run_dir(&run_id.id).unwrap();
        let config = ws.for_run(&run_id).config_path();
        // (environment's [collect], flags, the form's switches, what is read)
        let cases = [
            ("", vec![], (None, None), (true, true)),
            (
                "",
                vec!["--no-task-reads"],
                (None, Some(false)),
                (true, false),
            ),
            (
                "",
                vec!["--no-service-reads", "--no-task-reads"],
                (Some(false), Some(false)),
                (false, false),
            ),
            (
                "[collect]\nservice_reads = false\n",
                vec![],
                (None, None),
                (false, true),
            ),
        ];
        for (toml, flags, (services, tasks), want) in cases {
            std::fs::write(&config, toml).unwrap();
            let mut argv = vec![
                "pathwarden",
                "retest",
                "targeted",
                "--finding",
                fp,
                "--env",
                "Lab",
                "--workspace",
                ws_dir.to_str().unwrap(),
            ];
            argv.extend(flags.iter().copied());
            let Some(Command::Retest {
                action: Some(retest_cmd::RetestAction::Targeted(args)),
                ..
            }) = Cli::try_parse_from(&argv).unwrap().command
            else {
                panic!("not retest targeted");
            };
            let cli = Seen(Mutex::new(Vec::new()));
            assert!(retest_cmd::targeted_with(args, &cli).is_err());
            let app = Seen(Mutex::new(Vec::new()));
            let form = pathwarden_ui::retest_ui::RetestForm {
                fingerprint: fp.into(),
                domain: "contoso.local".into(),
                service_reads: services,
                task_reads: tasks,
                ..Default::default()
            };
            assert!(pathwarden_ui::retest_ui::targeted(&ws, &run_dir, form, &app).is_err());
            assert_eq!(*cli.0.lock().unwrap(), vec![want], "{toml} {flags:?}");
            assert_eq!(*cli.0.lock().unwrap(), *app.0.lock().unwrap());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retest_sign_in_flags_are_the_dialogs() {
        use std::sync::Mutex;
        struct Seen(Mutex<Vec<(bool, bool)>>);
        impl pathwarden_collect::Refresher for Seen {
            fn refresh(
                &self,
                req: &pathwarden_collect::CollectRequest,
                _: &pathwarden_collect::RefreshTarget,
            ) -> anyhow::Result<pathwarden_collect::Refreshed> {
                self.0
                    .lock()
                    .unwrap()
                    .push((req.allow_ntlm, req.allow_unsigned_smb));
                anyhow::bail!("not contacted in tests")
            }
        }
        if !pathwarden_ui::collect::BUILTIN || !cfg!(windows) {
            return;
        }
        let dir = std::env::temp_dir().join(format!("pw-cli-krb-flags-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ws_dir = dir.join("ws");
        let forest =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        let save = Cli::try_parse_from([
            "pathwarden",
            "run",
            "-i",
            forest.to_str().unwrap(),
            "--save",
            "--new-env",
            "Lab",
            "--workspace",
            ws_dir.to_str().unwrap(),
        ])
        .unwrap();
        run(save.command.unwrap()).unwrap();
        let fp = "PW-006-8ae0b31a46eacada";
        let ws = pathwarden_ui::environments::cli_workspace(Some(&ws_dir), "Lab").unwrap();
        let run_id = ws.runs().into_iter().next().unwrap();
        let run_dir = ws.run_dir(&run_id.id).unwrap();
        for (flags, ntlm, unsigned) in [
            (vec![], false, false),
            (vec!["--allow-ntlm", "--allow-unsigned-smb"], true, true),
        ] {
            let mut argv = vec![
                "pathwarden",
                "retest",
                "targeted",
                "--finding",
                fp,
                "--env",
                "Lab",
                "--workspace",
                ws_dir.to_str().unwrap(),
            ];
            argv.extend(flags.iter().copied());
            let Some(Command::Retest {
                action: Some(retest_cmd::RetestAction::Targeted(args)),
                ..
            }) = Cli::try_parse_from(&argv).unwrap().command
            else {
                panic!("not retest targeted");
            };
            let cli = Seen(Mutex::new(Vec::new()));
            assert!(retest_cmd::targeted_with(args, &cli).is_err());
            let app = Seen(Mutex::new(Vec::new()));
            let form = pathwarden_ui::retest_ui::RetestForm {
                fingerprint: fp.into(),
                domain: "contoso.local".into(),
                allow_ntlm: ntlm,
                allow_unsigned_smb: unsigned,
                ..Default::default()
            };
            assert!(pathwarden_ui::retest_ui::targeted(&ws, &run_dir, form, &app).is_err());
            assert_eq!(*cli.0.lock().unwrap(), vec![(ntlm, unsigned)], "{flags:?}");
            assert_eq!(*cli.0.lock().unwrap(), *app.0.lock().unwrap());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_command_is_in_exactly_one_help_group() {
        let cmd = Cli::command();
        let grouped: Vec<&str> = help::GROUPS
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
            let n = grouped.iter().filter(|g| **g == sub.get_name()).count();
            assert_eq!(
                n,
                1,
                "{} is listed {n} times in help::GROUPS",
                sub.get_name()
            );
        }
        for name in &grouped {
            assert!(cmd.find_subcommand(name).is_some(), "no command {name}");
        }
    }

    #[test]
    fn top_level_help_fits_80_columns_and_shows_the_groups() {
        let help = cli_command().render_help().to_string();
        for line in help.lines() {
            assert!(line.chars().count() <= help::WIDTH, "too wide: {line:?}");
        }
        for (group, _) in help::GROUPS {
            assert!(help.contains(&format!("{group}:")), "{help}");
        }
        assert!(help.contains("New here?"), "{help}");
        assert!(help.contains("Exit status"), "{help}");
        assert!(help.contains("-h, --help"), "{help}");
    }

    /// `pathwarden ui`: what asks for the browser, whatever the default is.
    #[cfg(feature = "desktop")]
    #[test]
    fn ui_browser_and_window_flags() {
        let ui = |args: &[&str]| -> Result<UiCommand, clap::Error> {
            let mut argv = vec!["pathwarden", "ui"];
            argv.extend_from_slice(args);
            let matches = cli_command().try_get_matches_from(argv)?;
            match Cli::from_arg_matches(&matches)?.command {
                Some(Command::Ui(ui)) => Ok(ui),
                _ => unreachable!(),
            }
        };
        assert!(ui(&["--window"]).unwrap().wants_window());
        for browser in [
            &["--no-window"][..],
            &["--browser"],
            &["--browser", "default"],
            &["--no-browser"],
            &["--port", "40123"],
        ] {
            assert!(!ui(browser).unwrap().wants_window(), "{browser:?}");
        }
        assert_eq!(
            ui(&["--browser"]).unwrap().args.browser,
            Some(pathwarden_ui::launch::BrowserMode::App)
        );
        for clash in [&["--window", "--no-window"][..], &["--window", "--browser"]] {
            assert!(ui(clash).is_err(), "{clash:?}");
        }
    }

    #[test]
    fn error_text_drops_a_repeated_cause() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let e = anyhow::Error::new(io).context("failed to read x: not found");
        assert_eq!(error_text(&e), "failed to read x: not found");
        let e = anyhow::anyhow!("inner").context("outer");
        assert_eq!(error_text(&e), "outer: inner");
    }

    /// A renamed flag keeps its old name as a hidden alias, so no
    /// script breaks; the help shows only the new name.
    #[test]
    fn old_flag_names_still_parse() {
        let parses = |args: &[&str]| {
            let mut all = vec!["pathwarden"];
            all.extend_from_slice(args);
            Cli::try_parse_from(all)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        for (old, new) in [
            (
                &["collect", "-d", "scale.local", "--out", "o"][..],
                &["collect", "-d", "scale.local", "--output", "o"][..],
            ),
            (
                &["schedule", "--domain", "scale.local", "--out", "o"],
                &["schedule", "--domain", "scale.local", "--output", "o"],
            ),
            (
                &["diagnose", "--bundle", "--out", "d.zip"],
                &["diagnose", "--bundle", "--output", "d.zip"],
            ),
            (
                &["evidence", "keygen", "--out", "key"],
                &["evidence", "keygen", "--output", "key"],
            ),
            (
                &["findings", "-i", "demo:", "--show-suppressed"],
                &["findings", "-i", "demo:", "--show-accepted"],
            ),
        ] {
            parses(old).unwrap_or_else(|e| panic!("{old:?}: {e}"));
            parses(new).unwrap_or_else(|e| panic!("{new:?}: {e}"));
        }
        // `-y` skips a confirmation wherever `--yes` does.
        for args in [
            &["env", "remove", "Lab", "-y"][..],
            &["history", "storage", "accept", "-y"],
            &["history", "storage", "set", "--encrypt", "-y"],
            &["plugins", "test", "1", "-y"],
            &["collect", "-d", "scale.local", "-o", "o", "-y"],
        ] {
            parses(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
        // The old names stay out of the help.
        let mut cmd = cli_command();
        for (sub, old) in [
            (&["collect"][..], "--out "),
            (&["schedule"], "--out "),
            (&["diagnose"], "--out "),
            (&["evidence", "keygen"], "--out "),
            (&["findings"], "--show-suppressed"),
        ] {
            let mut c = &mut cmd;
            for s in sub {
                c = c.find_subcommand_mut(s).unwrap();
            }
            let help = c.render_long_help().to_string();
            assert!(!help.contains(old), "{sub:?} shows {old}: {help}");
        }
    }

    #[test]
    fn errors_print_as_sentences() {
        assert_eq!(as_sentence("no such run"), "No such run.");
        assert_eq!(as_sentence("Done."), "Done.");
        assert_eq!(
            as_sentence("--workspace goes with --env"),
            "--workspace goes with --env."
        );
        assert_eq!(as_sentence("no such run (see x)"), "No such run (see x).");
        assert_eq!(as_sentence("a\n       hint."), "A.\n       hint.");
        assert_eq!(as_sentence(""), "");
        assert_eq!(
            as_sentence("reading x: The system cannot find the file specified. (os error 2)"),
            "Reading x: The system cannot find the file specified (os error 2)."
        );
        // A quoted name keeps its case.
        assert_eq!(
            as_sentence("findings.json was replaced."),
            "findings.json was replaced."
        );
        assert_eq!(
            as_sentence("mssqlhound isn't trusted"),
            "mssqlhound isn't trusted."
        );
        assert_eq!(as_sentence("reading x: gone"), "Reading x: gone.");
    }
}
