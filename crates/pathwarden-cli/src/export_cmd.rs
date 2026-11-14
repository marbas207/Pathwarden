//! `pathwarden export`: findings as SARIF 2.1.0 or DefectDojo Generic
//! Findings Import JSON (crate `pathwarden-export`), from an event document
//! (`run --event`, with each finding's change and first-seen time), from a
//! run of the app's workspace (`--run`, as the run page's "Findings file"
//! gives it), or from a fresh analysis of collector data.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use pathwarden_core::findings;
use pathwarden_export::Doc;

use crate::progress::{self, Through};
use crate::Input;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    /// SARIF 2.1.0 (OASIS).
    #[value(help = "SARIF 2.1.0 (OASIS).")]
    Sarif,
    /// DefectDojo "Generic Findings Import" JSON.
    #[value(help = "DefectDojo \"Generic Findings Import\" JSON.")]
    Defectdojo,
}

impl From<Format> for pathwarden_export::Format {
    fn from(f: Format) -> Self {
        match f {
            Format::Sarif => pathwarden_export::Format::Sarif,
            Format::Defectdojo => pathwarden_export::Format::Defectdojo,
        }
    }
}

#[derive(Args)]
pub struct ExportArgs {
    /// The format to write.
    #[arg(value_enum)]
    format: Format,
    /// An event document written by `pathwarden run --event` (keeps each
    /// finding's change and first-seen time).
    #[arg(long, value_name = "FILE", conflicts_with_all = ["input", "tier_zero", "config", "run"])]
    event: Option<PathBuf>,
    /// A run of the app's workspace, by the ID `pathwarden runs list`
    /// prints: its findings as the run page's "Findings file" gives them.
    #[arg(long, value_name = "RUN", conflicts_with_all = ["input", "tier_zero", "config"])]
    run: Option<String>,
    #[command(flatten)]
    env: crate::history_cmd::Env,
    /// With --run: the run history to read, as `pathwarden ui --state`
    /// (default: the environment's own, as the app reads it).
    #[arg(long, value_name = "DIR", requires = "run")]
    state: Option<PathBuf>,
    /// Collector output to analyze instead (as for `findings`); `demo:` for
    /// the built-in demo collection.
    #[arg(short, long = "input", num_args = 1..)]
    input: Vec<PathBuf>,
    /// An extra object (ID or name) to treat as Tier Zero; repeatable.
    #[arg(long = "tier-zero", value_name = "ID_OR_NAME")]
    tier_zero: Vec<String>,
    /// The settings (pathwarden.toml): Tier Zero additions, rule settings
    /// and accepted risks.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Where to write it (default: standard output).
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Show progress as plain lines on stderr even when it isn't a terminal.
    #[arg(short, long)]
    verbose: bool,
}

pub fn export_cmd(args: ExportArgs) -> Result<()> {
    if args.run.is_none() && args.env.given() {
        bail!("--env and --workspace go with --run.");
    }
    let doc = match (&args.event, &args.run) {
        (Some(path), _) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            Doc::from_event(&text).with_context(|| format!("reading {}", path.display()))?
        }
        (None, Some(id)) => {
            let ws = args.env.workspace()?;
            let r = pathwarden_ui::evidence_ui::find_run(&ws, id)?;
            pathwarden_ui::evidence_ui::findings_doc(&ws, args.state.as_deref(), &r)
                .map_err(anyhow::Error::msg)?
        }
        (None, None) => analyze(&args)?,
    };
    if !doc.held.is_empty() {
        anstream::eprintln!(
            "Warning: Pathwarden can't tell whether {} fixed in this run (domain or source not collected), so {} not in the export. A DefectDojo reimport with close_old_findings would close {} (see docs/integrations.md).",
            pathwarden_core::text::count(doc.held.len(), "finding is", "findings are"),
            if doc.held.len() == 1 { "is" } else { "are" },
            if doc.held.len() == 1 { "it" } else { "them" }
        );
    }
    let text = pathwarden_export::text(&doc, args.format.into())?;
    match &args.output {
        Some(path) => write(path, &text),
        None => {
            anstream::print!("{text}");
            Ok(())
        }
    }
}

fn write(path: &Path, text: &str) -> Result<()> {
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    anstream::eprintln!("Wrote {}.", path.display());
    Ok(())
}

/// The findings of a fresh analysis, as the exporters read them.
fn analyze(args: &ExportArgs) -> Result<Doc> {
    if args.input.is_empty() {
        bail!("Give an event document (--event), a run (--run) or a collection (-i).");
    }
    let mut input = Input {
        input: args.input.clone(),
        tier_zero: args.tier_zero.clone(),
        config: args.config.clone(),
        env: Default::default(),
        json: false,
        verbose: args.verbose,
    };
    let _demo = crate::demo::resolve(&mut input.input)?;
    let mut p = progress::Analysis::new(Through::Rules, input.verbose);
    let ev = crate::run_rules(&input, &mut p)?;
    p.done();
    let findings = ev
        .findings
        .iter()
        .map(|f| serde_json::to_value(f).and_then(serde_json::from_value))
        .collect::<Result<Vec<pathwarden_export::Finding>, _>>()
        .context("converting findings")?;
    let mut guides = BTreeMap::new();
    for f in &ev.findings {
        if let Some(g) = pathwarden_core::guides::guide(f.rule) {
            guides.insert(f.rule.to_string(), g.to_string());
        }
    }
    let doc = Doc {
        run_id: String::new(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        when: ev.stats.collected_at,
        findings,
        guides,
        rule_titles: findings::rules()
            .iter()
            .map(|r| (r.id.to_string(), r.title.to_string()))
            .collect(),
        held: Vec::new(),
    };
    doc.check()?;
    Ok(doc)
}
