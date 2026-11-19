//! `pathwarden retest` and `pathwarden history`.
//!
//! `retest` compares a fresh collection with a baseline and says, per
//! finding, Fixed / Still open / Can't tell, plus what is new. It reads the
//! state and writes nothing unless `--record` is given, so it is safe to run
//! at any time. `history` prints the trend from the state's history points.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anstream::{eprintln, println};
use anyhow::{bail, Context, Result};
use pathwarden_core::analyze;
use pathwarden_core::config::Config;
use pathwarden_core::opengraph::coverage::RunSources;
use pathwarden_core::retest::{
    self, Baseline, Coverage, FindingView, RetestReport, Selection, Verdict,
};

use crate::{emit_json, exit, read_config, run_rules, store, ui, Input};

pub struct RetestArgs<'a> {
    pub input: &'a Input,
    pub baseline: Option<&'a Path>,
    pub state: Option<&'a Path>,
    pub selection: Selection,
    pub record: bool,
    pub no_push: bool,
    /// With `record`: the run's label.
    pub label: Option<&'a str>,
}

/// What the baseline is and how much it held.
pub(crate) struct LoadedBaseline {
    pub baseline: Baseline,
    /// Collected objects in the baseline (0 when unknown), to notice a much
    /// smaller fresh collection.
    pub objects: usize,
    /// Keys of the sources the baseline run recorded (OpenGraph, SYSVOL
    /// parts), and of its hosts (`LastRun::hosts`).
    pub sources: Vec<String>,
    /// `Some` when `sources` was recorded before it listed only sources with
    /// data: the source keys the baseline's findings cite
    /// ([`RunSources::baseline_keys`]).
    pub legacy_cited: Option<HashSet<String>>,
    /// When the baseline's data was collected, if known.
    pub collected_at: Option<i64>,
    /// The baseline's run ID (state or event document), if it has one.
    pub run_id: Option<String>,
    /// The Tier Zero settings files the baseline used, to say when
    /// this run has fewer.
    pub settings_files: Vec<pathwarden_core::dcsettings::SettingsFileUse>,
    /// The baseline didn't record its computers (a run of 0.2 or earlier):
    /// [`Coverage::legacy_hosts`].
    pub legacy_hosts: bool,
}

pub(crate) fn baseline_from_path(
    path: &Path,
    config: &Config,
    input: &Input,
) -> Result<LoadedBaseline> {
    let label = path.display().to_string();
    let is_json = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"));
    if is_json && path.is_file() {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if retest::looks_like_event(&text) {
            let ev = retest::parse_event(&text).map_err(anyhow::Error::msg)?;
            let legacy_cited = (!ev.sources_exact).then(|| {
                ev.findings
                    .iter()
                    .flat_map(|f| f.sources.iter().cloned())
                    .collect()
            });
            let run = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .map(|v| v["run"].clone());
            let run_id = run
                .as_ref()
                .and_then(|r| r["run_id"].as_str().map(str::to_string));
            let settings_files = run
                .and_then(|r| serde_json::from_value(r["settings_files"].clone()).ok())
                .unwrap_or_default();
            return Ok(LoadedBaseline {
                baseline: Baseline::from_views(ev.findings, format!("event {label}")),
                objects: ev.objects,
                sources: ev.sources,
                legacy_cited,
                collected_at: ev.collected_at,
                run_id,
                settings_files,
                legacy_hosts: ev.legacy_hosts,
            });
        }
    }
    // An earlier collection: analyze it with the same config.
    let ev = analyze::evaluate(&[path], config, &input.tier_zero, &mut |_| {})
        .with_context(|| format!("analyzing the baseline {label}"))?;
    let objects = ev.graph.nodes().filter(|(_, n)| !n.placeholder).count();
    let sources = RunSources::from_analysis_at(
        &ev.graph,
        &ev.stats,
        Some((ev.settings.now, ev.settings.stale_days)),
    )
    .all_keys();
    let mut views: Vec<FindingView> = ev.findings.iter().map(FindingView::from).collect();
    FindingView::mark_untargeted(&mut views, &untargeted_domains(&ev));
    Ok(LoadedBaseline {
        baseline: Baseline::from_views(views, format!("collection {label}")),
        objects,
        sources,
        legacy_cited: None,
        collected_at: ev.stats.collected_at,
        run_id: None,
        settings_files: ev.stats.settings_files(analyze::now()),
        legacy_hosts: false,
    })
}

/// The run state as a baseline, with what its last run recorded.
pub(crate) fn baseline_from_state(
    store: &store::Store,
    previous: &pathwarden_core::state::FindingsState,
    last: Option<pathwarden_core::state::LastRun>,
) -> LoadedBaseline {
    LoadedBaseline {
        baseline: Baseline::from_state(previous, format!("state {}", store.describe())),
        objects: last.as_ref().map_or(0, |l| l.objects),
        collected_at: last.as_ref().and_then(|l| l.collected_at),
        run_id: last.as_ref().map(|l| l.run_id.clone()),
        legacy_hosts: last.as_ref().is_some_and(|l| l.hosts.is_none()),
        legacy_cited: last
            .as_ref()
            .filter(|l| !l.sources_exact)
            .map(|_| previous.cited_sources()),
        settings_files: last
            .as_ref()
            .map(|l| l.settings_files.clone())
            .unwrap_or_default(),
        sources: last
            .map(|l| {
                l.sources
                    .into_iter()
                    .chain(l.hosts.into_iter().flatten())
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// The settings files this retest used, and the servers the baseline had a
/// file for and this run has not.
fn settings_of(
    base: &LoadedBaseline,
    ev: &analyze::Evaluated,
) -> (
    Vec<pathwarden_core::dcsettings::SettingsFileUse>,
    Vec<String>,
) {
    let files = ev.stats.settings_files(analyze::now());
    let fewer = pathwarden_core::dcsettings::fewer(&base.settings_files, &files);
    (files, fewer)
}

pub fn retest_cmd(args: RetestArgs) -> Result<ExitCode> {
    let input = args.input;
    let config = read_config(input)?;
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();

    let mut p = crate::progress::Analysis::new(crate::progress::Through::Plan, input.verbose);
    let (report, recorded, settings) = match args.baseline {
        Some(path) => {
            let base = baseline_from_path(path, &config, input)?;
            let ev = run_rules(input, &mut p)?;
            let report = compare(&base, &ev, &args.selection)?;
            let settings = (
                settings_of(&base, &ev),
                ev.stats.settings_folders_unread.len(),
            );
            (report, None, settings)
        }
        None => {
            let store = store::Store::new(&config.state, args.state)?;
            // Read-only unless recording: no lock, no pull, nothing written.
            let _lock = if args.record {
                let lock = store.lock_waiting(pathwarden_core::settings_sync::lock_wait())?;
                if let Some(note) = store.pull().context("syncing the run history")? {
                    eprintln!("Warning: {note}");
                }
                Some(lock)
            } else {
                None
            };
            if !args.record && !store.has_state_file("findings.json") {
                bail!(
                    "No run history at {}. Run `pathwarden run` first, point --state at the history \
                     folder, or compare with an earlier collection (--baseline).",
                    store.dir.display()
                );
            }
            let previous = store.load()?;
            let last = store::last_run(&store);
            let base = baseline_from_state(&store, &previous, last);
            let ev = run_rules(input, &mut p)?;
            let report = compare(&base, &ev, &args.selection)?;
            let settings = (
                settings_of(&base, &ev),
                ev.stats.settings_folders_unread.len(),
            );
            let recorded = if args.record {
                let rec = crate::record(
                    &store,
                    &previous,
                    ev,
                    &config,
                    &crate::Record {
                        started_ms,
                        event_path: None,
                        report_path: None,
                        no_push: args.no_push,
                        accept_shrink: false,
                        want_event: false,
                        label: args.label,
                        timings: None,
                        context: &[],
                        config_path: input.config.as_deref(),
                        source: &crate::source_words(&input.input),
                    },
                    &mut p,
                )?;
                Some((rec, store.describe()))
            } else {
                None
            };
            (report, recorded, settings)
        }
    };
    let ((settings_files, settings_fewer), unread) = settings;

    if input.json {
        #[derive(serde::Serialize)]
        struct Out<'a> {
            #[serde(flatten)]
            report: &'a RetestReport,
            #[serde(skip_serializing_if = "Option::is_none")]
            recorded: Option<String>,
            /// The Tier Zero settings files this retest used, and the
            /// servers the baseline had a file for and it has not.
            #[serde(skip_serializing_if = "Vec::is_empty")]
            settings_files: Vec<pathwarden_core::dcsettings::SettingsFileUse>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            settings_fewer: Vec<String>,
        }
        emit_json(&Out {
            report: &report,
            recorded: recorded.as_ref().map(|(r, _)| r.run_id.clone()),
            settings_files: settings_files.clone(),
            settings_fewer: settings_fewer.clone(),
        })?;
    } else {
        print_report(&report);
        if let Some((line, notes)) = crate::settings_lines(&settings_files, &settings_fewer, unread)
        {
            println!("\n{}", ui::safe(&line));
            for n in notes {
                println!("{}", ui::safe(&n));
            }
        }
        if let Some((rec, where_)) = &recorded {
            let g = ui::GREEN;
            println!(
                "\n{g}Recorded{g:#} run {} in {where_}{}",
                rec.run_id,
                if rec.pushed {
                    ", pushed"
                } else if rec.unpushed.is_some() {
                    ", committed here, not pushed (see below)"
                } else {
                    ""
                }
            );
            crate::print_full_run(
                rec.full_run.as_ref().map(|f| &f.0),
                rec.full_run.as_ref().map(|f| f.1),
            );
        }
    }
    // Recorded, but not pushed: the command fails, so a schedule notices.
    let full_unpushed = recorded
        .as_ref()
        .and_then(|(r, _)| r.full_run.as_ref())
        .is_some_and(|(l, _)| l.state == pathwarden_ui::shared_runs::FullRunState::Unpushed);
    if let Some(k) = recorded.and_then(|(r, _)| r.unpushed) {
        let warn = ui::severity(pathwarden_core::findings::Severity::Medium);
        eprintln!(
            "{warn}Warning:{warn:#} {}",
            ui::safe_text(&k.sentence("This run is recorded"))
        );
        if input.verbose {
            eprintln!("  git: {}", ui::safe_text(&k.detail));
        }
        bail!("{}", crate::UNPUSHED);
    }
    if full_unpushed {
        bail!("{}", crate::FULL_UNPUSHED);
    }
    // The report's codes are the CLI's own (crate::exit).
    let code = report.exit_code();
    debug_assert!([exit::OK, exit::FINDINGS, exit::CANT_TELL].contains(&code));
    Ok(ExitCode::from(code))
}

pub(crate) fn compare(
    base: &LoadedBaseline,
    ev: &analyze::Evaluated,
    selection: &Selection,
) -> Result<RetestReport> {
    let objects = ev.graph.nodes().filter(|(_, n)| !n.placeholder).count();
    let shrunk = base.objects > 0 && objects * 2 < base.objects;
    let skipped = ev.stats.skipped_objects.len();
    let sources = RunSources::from_analysis_at(
        &ev.graph,
        &ev.stats,
        Some((ev.settings.now, ev.settings.stale_days)),
    );
    let had = sources.baseline_keys(&base.sources, base.legacy_cited.as_ref());
    let coverage = Coverage {
        domains: analyze::domain_names(&ev.graph),
        complete: !shrunk && skipped == 0,
        sources,
        legacy_hosts: base.legacy_hosts,
        ..Coverage::default()
    }
    .compared_with(&had)
    .with_untargeted(&untargeted_domains(ev));
    if skipped > 0 {
        let warn = ui::severity(pathwarden_core::findings::Severity::Medium);
        eprintln!(
            "{warn}Warning:{warn:#} {} too large to load, so findings missing \
             from this collection are reported as \"can't tell\".",
            pathwarden_core::text::count(skipped, "object was", "objects were")
        );
    }
    if shrunk {
        let warn = ui::severity(pathwarden_core::findings::Severity::Medium);
        eprintln!(
            "{warn}Warning:{warn:#} This collection has {} objects, less than half of the \
             baseline's {}, so findings missing from it are reported as \"can't tell\".",
            pathwarden_core::text::num(objects),
            pathwarden_core::text::num(base.objects)
        );
    }
    let current: Vec<FindingView> = ev.findings.iter().map(FindingView::from).collect();
    retest::compare(&base.baseline, &current, &coverage, selection).map_err(anyhow::Error::msg)
}

/// What an analyzed collection did not target, per domain.
fn untargeted_domains(
    ev: &analyze::Evaluated,
) -> Vec<(String, pathwarden_core::posture::Untargeted)> {
    pathwarden_core::posture::untargeted_domains(&pathwarden_core::posture::completeness(
        &ev.graph,
        ev.settings.now,
    ))
}

fn print_report(r: &RetestReport) {
    let bold = ui::BOLD;
    let dim = ui::DIM;
    println!("{bold}Retest against {}{bold:#}", ui::safe(&r.baseline));
    if r.results.is_empty() {
        println!("  Nothing to retest: the baseline has no open findings that match.");
    }
    for x in &r.results {
        print_verdict(x.verdict, &x.fingerprint, &x.title);
        for d in &x.details {
            println!("  {:<10}  {dim}{}{dim:#}", "", ui::safe(d));
        }
        // Held for sessions or local groups this collection didn't read:
        // the run page's line, and the command that does it.
        if x.held {
            println!(
                "  {:<10}  {} `pathwarden retest targeted --finding {}`",
                "",
                retest::HELD_LINE,
                ui::safe(&x.fingerprint)
            );
        }
    }
    if !r.new.is_empty() {
        println!("\n{bold}New since the baseline{bold:#}");
        for n in &r.new {
            let sev = n.severity.map(ui::severity).unwrap_or(ui::BOLD);
            let label = if n.regressed { "BACK" } else { "NEW" };
            println!(
                "  {sev}{label:<10}{sev:#}  {}  {}",
                ui::safe(&n.fingerprint),
                ui::safe(&n.title)
            );
        }
    }
    let c = r.counts;
    println!(
        "\n{} fixed, {} still open, {} can't tell, {} new.",
        c.fixed, c.still_open, c.cant_tell, c.new
    );
}

/// `pathwarden retest` subcommands.
#[derive(clap::Subcommand)]
pub enum RetestAction {
    /// Retest one finding of a saved run, as the run page's Retest button
    /// does: read its objects and the computers on its path again.
    #[command(
        after_help = "Exit status: 0 fixed, 1 still open, 2 error, 3 can't tell.\n\nComputers on the finding's path are read over SMB (port 445) and RPC: as the current Windows account (Windows only, local administrator there), or with --user, whose password comes from PATHWARDEN_COLLECT_PASSWORD or a prompt."
    )]
    Targeted(TargetedArgs),
}

/// `pathwarden retest targeted`: the run page's Retest now. Re-reads one
/// finding's objects from the directory and, when it rests on sessions or
/// local groups, those of just the computers on its path, then runs its
/// rule again ([`pathwarden_ui::retest_ui::targeted`], the dialog's code).
/// The result is kept with the run, as the dialog keeps it.
#[derive(clap::Args)]
pub struct TargetedArgs {
    /// The finding to retest (its ID, e.g. PW-006-8ae0b31a46eacada).
    #[arg(long = "finding", value_name = "FINDING_ID")]
    pub finding: String,
    /// The run whose finding it is, by the ID `pathwarden runs list` prints
    /// (default: the newest run of the environment with it open).
    #[arg(long, value_name = "RUN")]
    pub run: Option<String>,
    #[command(flatten)]
    pub env: crate::history_cmd::Env,
    /// The domain to read from (default: the finding's).
    #[arg(long, short, value_name = "DOMAIN")]
    pub domain: Option<String>,
    /// The domain controller to query, preferably its FQDN.
    #[arg(long, short = 's', value_name = "HOST")]
    pub server: Option<String>,
    /// The account to sign in as; the password comes from
    /// PATHWARDEN_COLLECT_PASSWORD, else it is prompted for, as with
    /// collect. Without it, the current Windows account, which reads the
    /// computers on the path too.
    #[arg(long, short = 'u', value_name = "USER")]
    pub user: Option<String>,
    /// Use LDAPS (port 636; needed with --user).
    #[arg(long)]
    pub ldaps: bool,
    /// Don't validate the LDAPS certificate (insecure; labs only).
    #[arg(long, requires = "ldaps")]
    pub insecure_skip_tls_verify: bool,
    /// As for collect: sign in to computers with NTLM when Kerberos can't be
    /// used (default: Kerberos only).
    #[arg(long)]
    pub allow_ntlm: bool,
    /// As for collect: read computers whose SMB replies aren't signed
    /// (default: every reply must be signed).
    #[arg(long)]
    pub allow_unsigned_smb: bool,
    /// Don't read the computers on the finding's path (sessions, local
    /// groups, services and scheduled tasks): Pathwarden then can't tell
    /// whether a finding that rests on them is fixed.
    #[arg(long)]
    pub no_hosts: bool,
    /// As for collect: don't read the accounts services run as on the
    /// computers that store a password the finding rests on (default: the
    /// environment's `[collect] service_reads`, on when not set).
    #[arg(long)]
    pub no_service_reads: bool,
    /// As for collect: don't read their scheduled tasks over C$ (default:
    /// the environment's `[collect] task_reads`, on when not set).
    #[arg(long)]
    pub no_task_reads: bool,
    /// Print JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

/// `pathwarden retest targeted`.
pub fn targeted_cmd(args: TargetedArgs) -> Result<ExitCode> {
    targeted_with(args, &pathwarden_collect::BuiltinRefresher)
}

/// [`targeted_cmd`] with the reader of the directory and the computers
/// (a fake in tests).
pub fn targeted_with(
    args: TargetedArgs,
    reader: &dyn pathwarden_collect::Refresher,
) -> Result<ExitCode> {
    use pathwarden_ui::retest_ui;
    if !pathwarden_ui::collect::BUILTIN {
        bail!(
            "this build has no built-in collector, so it can't re-read single objects; collect \
             again or analyze a new collection to retest"
        );
    }
    let fp = args.finding.trim().to_string();
    let ws = args.env.workspace()?;
    let mut runs = ws.runs();
    runs.sort_by(|a, b| b.order_key().cmp(&a.order_key()));
    let open_in = |r: &pathwarden_ui::workspace::RunSummary| {
        ws.run_dir(&r.id)
            .and_then(|d| pathwarden_ui::run_data::findings(&d))
            .and_then(|all| {
                all.iter()
                    .find(|f| f.suppressed.is_none() && f.fingerprint.eq_ignore_ascii_case(&fp))
                    .cloned()
            })
    };
    let (run, finding) = match &args.run {
        Some(id) => {
            let Some(r) = runs.iter().find(|r| {
                r.id == *id || pathwarden_ui::history_ui::recorded_id(r) == Some(id.as_str())
            }) else {
                bail!(
                    "no run {id} in environment {} with a saved report; `pathwarden runs list` \
                     lists its runs",
                    ws.env_name()
                );
            };
            let Some(f) = open_in(r) else {
                bail!("{fp} is not an open finding of run {id}");
            };
            (r.clone(), f)
        }
        None => {
            let Some((r, f)) = runs.iter().find_map(|r| open_in(r).map(|f| (r.clone(), f))) else {
                bail!(
                    "no run of environment {} has {fp} open; `pathwarden runs list` lists its runs",
                    ws.env_name()
                );
            };
            (r, f)
        }
    };
    let dir = ws.run_dir(&run.id).context("the run's folder is missing")?;
    // This retest's log goes in the run's diagnostics, as from the app.
    pathwarden_core::logs::note_run_current(&run.id);
    // As the dialog: a run from the history never picks where this computer
    // signs in, so its domain is given.
    let domain = match (&args.domain, run.shared.is_some()) {
        (Some(d), _) => d.clone(),
        (None, false) => finding
            .domain
            .clone()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        (None, true) => bail!("this run is from the repository: give the domain (--domain)"),
    };
    let password = match &args.user {
        // As `collect -u`: the environment variable, else a prompt at a
        // terminal; never the command line.
        Some(user) => match pathwarden_collect::Secret::from_env() {
            Some(p) => Some(p),
            None if std::io::IsTerminal::is_terminal(&std::io::stdin()) => Some(
                pathwarden_collect::Secret::prompt(&format!("Password for {user}: "))?,
            ),
            None => bail!(
                "no password: set {} or run interactively to be prompted (passwords are                  never taken from the command line)",
                pathwarden_collect::PASSWORD_ENV
            ),
        },
        None => None,
    };
    let form = retest_ui::RetestForm {
        fingerprint: finding.fingerprint.clone(),
        domain,
        server: args.server.clone(),
        auth: if args.user.is_some() {
            pathwarden_ui::collect::AuthChoice::Password
        } else {
            pathwarden_ui::collect::AuthChoice::Current
        },
        user: args.user.clone().unwrap_or_default(),
        password,
        ldaps: args.ldaps,
        skip_verify: args.insecure_skip_tls_verify,
        allow_ntlm: args.allow_ntlm,
        allow_unsigned_smb: args.allow_unsigned_smb,
        no_hosts: args.no_hosts,
        service_reads: args.no_service_reads.then_some(false),
        task_reads: args.no_task_reads.then_some(false),
    };
    let rec = retest_ui::targeted(&ws.for_run(&run), &dir, form, reader).map_err(|(_, body)| {
        anyhow::anyhow!("{}", body["error"].as_str().unwrap_or("the retest failed"))
    })?;
    if args.json {
        let mut v = retest_ui::result_json(&rec);
        v["fingerprint"] = rec.fingerprint.clone().into();
        v["run"] = run.id.clone().into();
        emit_json(&v)?;
    } else {
        let bold = ui::BOLD;
        println!("{bold}Targeted retest of run {}{bold:#}", ui::safe(&run.id));
        print_verdict(rec.verdict, &rec.fingerprint, &finding.title);
        let dim = ui::DIM;
        for d in rec.details.iter().chain(&retest_ui::result_lines(&rec)) {
            println!("  {:<10}  {dim}{}{dim:#}", "", ui::safe(d));
        }
    }
    Ok(ExitCode::from(match rec.verdict {
        Verdict::Fixed => exit::OK,
        Verdict::StillOpen => exit::FINDINGS,
        Verdict::CantTell => exit::CANT_TELL,
    }))
}

/// One verdict line: `FIXED  PW-...  title`.
fn print_verdict(verdict: Verdict, fingerprint: &str, title: &str) {
    let (style, label) = match verdict {
        Verdict::Fixed => (ui::GREEN, "FIXED"),
        Verdict::StillOpen => (
            ui::severity(pathwarden_core::findings::Severity::High),
            "STILL OPEN",
        ),
        Verdict::CantTell => (
            ui::severity(pathwarden_core::findings::Severity::Medium),
            "CAN'T TELL",
        ),
    };
    println!(
        "  {style}{label:<10}{style:#}  {}  {}",
        ui::safe(fingerprint),
        ui::safe(title)
    );
}

/// `pathwarden history --forget RUN`. With an environment (`--env`), the
/// app's Delete ([`pathwarden_ui::history_ui::delete_run`]): the history
/// point, then the saved run. Without, the point in the state folder only.
pub fn history_forget(
    state: Option<&Path>,
    config: Option<&PathBuf>,
    run: &str,
    env: Option<(Option<&Path>, &str)>,
) -> Result<()> {
    if let Some((workspace, name)) = env {
        let ws = pathwarden_ui::environments::cli_workspace(workspace, name)?;
        // An explicit --state wins; else the environment's own history.
        let d =
            pathwarden_ui::history_ui::delete_run(&ws, state, run).map_err(anyhow::Error::msg)?;
        // A run loaded from a history this computer only reads: hidden.
        if d.notes
            .iter()
            .any(|n| n == pathwarden_ui::history_ui::HIDDEN_WORDS)
        {
            println!("Run {run}: {}", pathwarden_ui::history_ui::HIDDEN_WORDS);
            return Ok(());
        }
        for note in &d.notes {
            eprintln!("Warning: {note}");
        }
        match (d.history_point, d.folder) {
            (false, false) => bail!("no run {run} in environment {name} or its history"),
            (p, f) => println!(
                "Removed run {run}: {}{}{}.",
                if p {
                    "its point in the run history"
                } else {
                    ""
                },
                if p && f { " and " } else { "" },
                if f { "its saved report" } else { "" }
            ),
        }
        return Ok(());
    }
    let config = match config {
        Some(p) => Config::from_file(p)?,
        None => Config::default(),
    };
    crate::warn_config(&config);
    let store = store::Store::new(&config.state, state)?;
    if !store.dir.is_dir() {
        bail!("No run history at {}.", store.dir.display());
    }
    let _lock = store.lock_waiting(pathwarden_core::settings_sync::lock_wait())?;
    if let Some(note) = store.pull()? {
        eprintln!("Warning: {note}");
    }
    let (removed, notes) = store.forget_and_publish(run, config.state.pushes())?;
    for note in &notes {
        eprintln!("Warning: {note}");
    }
    if !removed {
        bail!(
            "No run {run} in the run history at {}.",
            store.dir.display()
        );
    }
    println!(
        "Removed run {run} from the run history at {}.",
        store.dir.display()
    );
    Ok(())
}

/// What `pathwarden history` shows.
pub struct HistoryView<'a> {
    /// Only the most recent N runs.
    pub last: Option<usize>,
    /// Only the runs of this range up to the latest one.
    pub range: Option<pathwarden_core::history::Range>,
    /// Only what changed since the last run.
    pub since: bool,
    pub json: bool,
    /// With `json`: the runs and, beside them, what changed since the last
    /// run (`--with-since`).
    pub with_since: bool,
    /// The settings given (`-c`, `--env`), which the commands "since the
    /// last run" points at take too.
    pub context: &'a [String],
}

/// `labels`: labels set later in the UI workspace's environment, by run ID
/// ([`pathwarden_ui::workspace::later_labels`]), over the recorded ones.
pub fn history_cmd(
    state: Option<&Path>,
    config: Option<&PathBuf>,
    view: HistoryView,
    labels: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    let HistoryView {
        last,
        range,
        since,
        json,
        with_since,
        context,
    } = view;
    let config_file = config;
    let config = match config_file {
        Some(p) => Config::from_file(p)?,
        None => Config::default(),
    };
    crate::warn_config(&config);
    let mut store = store::Store::new(&config.state, state)?;
    if let Some(p) = config_file {
        store = store.with_config_file(p.clone());
    }
    if !store.dir.is_dir() {
        bail!(
            "No run history at {}. Run `pathwarden run` first, or point --state at the history folder.",
            store.dir.display()
        );
    }
    // What a run refuses, the history refuses too ([state] encrypted).
    store.check_expected()?;
    let (mut points, skipped) =
        pathwarden_core::history::load(&store.dir).map_err(anyhow::Error::msg)?;
    for p in &mut points {
        p.label = pathwarden_ui::workspace::point_label(labels, &p.run_id, p.label.as_deref());
    }
    for s in &skipped {
        eprintln!("Warning: Skipped {s} (not a history point).");
    }
    // A range is the runs since a time: as many of the latest runs.
    let total = points.len();
    let in_range = range.map(|r| total - r.start(&points, |p| p.at));
    let last = match in_range {
        Some(n) => Some(last.map_or(n, |l| l.min(n))),
        None => last,
    };
    if json && !since && !with_since {
        let start = last.map_or(0, |n| points.len().saturating_sub(n));
        return emit_json(&&points[start..]);
    }
    // The findings state names what changed since the last run; without it
    // (or unreadable) the changes are counted only.
    let findings = match store.load() {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!(
                "Warning: {} Findings that changed are counted, not named.",
                crate::as_sentence(&format!("{e:#}"))
            );
            None
        }
    };
    // Points from before trusted domains were left out join the
    // environment of the points recorded since, so the latest run finds
    // the one before it.
    if json && with_since {
        // The runs as written, and the comparison `--changes --json` prints.
        let start = last.map_or(0, |n| points.len().saturating_sub(n));
        let mut migrated = points.clone();
        pathwarden_core::state::migrate_points(&mut migrated);
        let view = pathwarden_core::since::view(&migrated, findings.as_ref());
        return emit_json(&serde_json::json!({
            "runs": &points[start..],
            "since": view,
        }));
    }
    pathwarden_core::state::migrate_points(&mut points);
    if since {
        // The same comparison the app's /api/history/since returns.
        let view = pathwarden_core::since::view(&points, findings.as_ref());
        if json {
            return emit_json(&view);
        }
        match view {
            Some(v) => anstream::print!("{}", v.since.render(context)),
            None => println!("No earlier run of this environment to compare with."),
        }
        return Ok(());
    }
    anstream::print!(
        "{}",
        pathwarden_core::history::render(&points, last, findings.as_ref(), context)
    );
    // What the range left out of the rows printed, and what the app's
    // Progress page charts of the same runs, so the two agree on what they
    // show.
    let shown = last.map_or(total, |n| n.min(total));
    let cap = pathwarden_core::history::MAX_CHARTED;
    let ranged = range.filter(|r| *r != pathwarden_core::history::Range::All);
    if let (Some(r), Some(n)) = (ranged, in_range) {
        let runs = |n| pathwarden_core::text::count(n, "run", "runs");
        if shown < n {
            println!(
                "
The latest {shown} of the {} in the {} up to the latest run ({total} in all). `--range all` shows every run.",
                runs(n),
                r.span(),
            );
        } else {
            println!(
                "
The {} up to the latest run: {} of {}. `--range all` shows every run.",
                r.span(),
                n,
                runs(total)
            );
        }
    }
    if shown > cap {
        println!(
            "{}, the app's Progress page charts the latest {cap} of these {shown} runs.",
            if ranged.is_some() {
                "On the same range"
            } else {
                "With All"
            }
        );
    }
    Ok(())
}
