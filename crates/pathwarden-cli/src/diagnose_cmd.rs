//! `pathwarden diagnose [RUN]`: a run's collection performance, compared
//! with its environment's previous run collected the same way, as the run
//! page's "Collection performance" panel shows it; `--bundle` writes the
//! zip the panel's "Download diagnostics" gives (both from
//! [`pathwarden_ui::diagnose`]). RUN is a run saved in the workspace, or
//! one a schedule or `pathwarden run` recorded in the history (its page is
//! `/history/<run>/performance`).

use std::path::{Path, PathBuf};

use anstream::println;
use anyhow::{bail, Context, Result};
use clap::Args;
use pathwarden_ui::diagnose::{self, Performance};
use pathwarden_ui::environments;
use pathwarden_ui::workspace::{self, RunSummary, Workspace};

use crate::ui;

/// `pathwarden diagnose`.
#[derive(Args)]
#[command(
    after_help = "The timings are saved with runs Pathwarden collected itself (the app's Collect, \
`collect --save`, a schedule, or `collect` then `run -i`); uploaded data has none. The bundle holds \
counts and durations only, every name replaced by a placeholder, and isn't written if a name of the \
run is found in it.

Exit status with --compare-output: 0 the same, 1 different, 2 error."
)]
pub(crate) struct DiagnoseArgs {
    /// The run: its ID as the run list, `pathwarden run` or `pathwarden
    /// history` shows it, or its folder ID (default: the environment's
    /// latest run).
    #[arg(value_name = "RUN")]
    run: Option<String>,
    /// The environment (its name or ID) whose latest run to show, or that
    /// RUN must be in (default: the environment the app opens in).
    #[arg(long, value_name = "NAME")]
    env: Option<String>,
    /// The app's workspace (default: the one `pathwarden ui` uses).
    #[arg(long, value_name = "DIR")]
    workspace: Option<PathBuf>,
    /// The run history a recorded RUN is in, as `pathwarden ui --state`
    /// (default: the environment's run history).
    #[arg(long, value_name = "DIR")]
    state: Option<PathBuf>,
    /// Also print the collection log's timing lines (the `Timing:` summary
    /// and the `[timing]` block).
    #[arg(long)]
    details: bool,
    /// Write a diagnostics zip that is safe to share: version, OS, cores
    /// and memory, timings, completeness, error counts, collection settings
    /// without credentials, posture and plan size, names replaced.
    #[arg(long, conflicts_with = "json")]
    bundle: bool,
    /// With --bundle: where to write the zip (default:
    /// pathwarden-diagnostics-<run>.zip in the current folder).
    #[arg(
        long = "output",
        short = 'o',
        alias = "out",
        value_name = "FILE",
        requires = "bundle"
    )]
    out: Option<PathBuf>,
    /// Print JSON instead of text (as the app's /api/runs/<run>/performance).
    #[arg(long)]
    json: bool,
    /// Compare two collections (zips, or `collect --output` folders):
    /// whether their BloodHound JSON is the same, every array sorted, and
    /// where not.
    #[arg(
        long,
        num_args = 2,
        value_names = ["A", "B"],
        conflicts_with_all = ["run", "env", "state", "details", "bundle", "json"]
    )]
    compare_output: Option<Vec<PathBuf>>,
}

impl DiagnoseArgs {
    /// `--compare-output` ([`compare_cmd`]).
    pub(crate) fn compares(&self) -> bool {
        self.compare_output.is_some()
    }
}

/// `diagnose --compare-output A B`: exit status 0 when the two are
/// the same, 1 when they differ, 2 on an error, as `diff`. Within the
/// `[ingest]` limits of the workspace's settings (`--workspace`, else the
/// default one), or the defaults.
pub(crate) fn compare_cmd(a: DiagnoseArgs) -> Result<std::process::ExitCode> {
    let [x, y] = a.compare_output.as_deref().unwrap_or_default() else {
        bail!("--compare-output takes two collections.");
    };
    let limits = a
        .workspace
        .clone()
        .map(Ok)
        .unwrap_or_else(workspace::default_dir)
        .and_then(|root| Workspace::existing(&root)?.config())
        .map(|c| c.ingest.limits_with(&c.opengraph))
        .unwrap_or_default();
    let d =
        pathwarden_collect::compare::compare_within(x, y, &limits).map_err(anyhow::Error::msg)?;
    if d.same() {
        println!(
            "Same output: {} files, {} objects.",
            d.files,
            pathwarden_collect::progress::thousands(d.objects as u64)
        );
        return Ok(std::process::ExitCode::SUCCESS);
    }
    let n = d.differences.len();
    println!(
        "Different output: {n}{} difference{}.",
        if d.more { "+" } else { "" },
        if n == 1 && !d.more { "" } else { "s" }
    );
    for line in &d.differences {
        println!("  {}", ui::safe(line));
    }
    Ok(std::process::ExitCode::from(crate::exit::FINDINGS))
}

pub(crate) fn diagnose_cmd(a: DiagnoseArgs) -> Result<()> {
    let root = match &a.workspace {
        Some(d) => d.clone(),
        None => workspace::default_dir()?,
    };
    let ws = Workspace::existing(&root)?;
    let picked = pick_run(&ws, a.env.as_deref(), a.run.as_deref(), a.state.as_deref())?;
    let run = match &picked {
        Picked::Saved(run) => (**run).clone(),
        Picked::Recorded(p, _) => p.run.clone(),
    };
    if a.bundle {
        let out = a
            .out
            .clone()
            .unwrap_or_else(|| PathBuf::from(diagnose::bundle_name(&run)));
        return write_bundle(&ws, &picked, &out);
    }
    let p = match picked {
        Picked::Saved(run) => Performance::of(&ws, &run),
        Picked::Recorded(p, _) => *p,
    };
    if a.json {
        println!("{}", serde_json::to_string_pretty(&p.to_json())?);
        return Ok(());
    }
    for line in p.text(a.details) {
        println!("{}", ui::safe(&line));
    }
    if p.timings.is_some() && !a.details {
        println!();
        println!(
            "The collection log's timing lines: `pathwarden diagnose {} --details`.",
            run.run_id()
        );
    }
    println!(
        "A zip of these numbers that is safe to share: `pathwarden diagnose {} --bundle`.",
        run.run_id()
    );
    Ok(())
}

/// A run saved in the workspace, or one recorded in the history (with the
/// environment's workspace, for its bundle).
enum Picked {
    Saved(Box<RunSummary>),
    Recorded(Box<Performance>, Workspace),
}

/// The run `run` names, or the environment's latest saved run.
fn pick_run(
    ws: &Workspace,
    env: Option<&str>,
    run: Option<&str>,
    state: Option<&Path>,
) -> Result<Picked> {
    let reg = ws.named_registry();
    let only = match env {
        Some(name) => Some(
            reg.find(name)
                .with_context(|| {
                    format!(
                        "no environment named {name:?} (there is: {})",
                        environments::names_list(&reg, ws.root(), &ws.all_runs())
                    )
                })?
                .id
                .clone(),
        ),
        None => None,
    };
    match run {
        Some(id) => {
            let folder = ws
                .run_dir(id)
                .map(|_| id.to_string())
                .or_else(|| ws.find_run(id));
            let Some(folder) = folder else {
                // A run the schedule or `pathwarden run` recorded.
                let env = only
                    .or_else(|| reg.current.clone())
                    .unwrap_or_else(|| environments::DEFAULT_ENV.to_string());
                let env_ws = ws.in_env(&env);
                let p = diagnose::point_performance(&env_ws, state, id).with_context(|| {
                    format!(
                        "no run {id}: use the ID the run list, `pathwarden run` or `pathwarden \
                         history` shows (for a recorded run, --env or --state names its history)"
                    )
                })?;
                return Ok(Picked::Recorded(Box::new(p), env_ws));
            };
            let s = ws.run(&folder).context("that run can't be read")?;
            if only
                .as_deref()
                .is_some_and(|e| e != ws.for_run(&s).env_id())
            {
                bail!("Run {id} isn't in that environment.");
            }
            Ok(Picked::Saved(Box::new(s)))
        }
        None => {
            let env = only
                .or_else(|| reg.current.clone())
                .unwrap_or_else(|| environments::DEFAULT_ENV.to_string());
            ws.in_env(&env)
                .runs()
                .into_iter()
                .next()
                .map(|r| Picked::Saved(Box::new(r)))
                .with_context(|| {
                    format!(
                        "{} has no saved runs yet (pass a run ID, or --env NAME)",
                        ui::safe(&reg.name_of(&env))
                    )
                })
        }
    }
}

fn write_bundle(ws: &Workspace, picked: &Picked, out: &Path) -> Result<()> {
    let exists = || {
        anyhow::anyhow!(
            "{} already exists. Pass --output with another name.",
            out.display()
        )
    };
    // Said before the bundle is made; the write below still never replaces
    // a file made meanwhile.
    if out.exists() {
        return Err(exists());
    }
    // With this computer's logs and crash reports, names replaced.
    let logs = pathwarden_core::logs::dir();
    let (zip, run) = match picked {
        Picked::Saved(run) => (diagnose::bundle(ws, run, logs.as_deref()), &**run),
        Picked::Recorded(p, env_ws) => (diagnose::bundle_point(env_ws, p, logs.as_deref()), &p.run),
    };
    let zip = zip.map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(exists()),
        Err(e) => return Err(e).with_context(|| format!("writing {}", out.display())),
    };
    if let Err(e) = std::io::Write::write_all(&mut file, &zip) {
        // Made above: no half-written bundle left.
        drop(file);
        let _ = std::fs::remove_file(out);
        return Err(e).with_context(|| format!("writing {}", out.display()));
    }
    let gr = ui::GREEN;
    println!(
        "{gr}Wrote{gr:#} {} ({}), diagnostics of run {}.",
        out.display(),
        pathwarden_core::diagnostics::bytes(zip.len() as u64),
        run.run_id()
    );
    println!(
        "  Counts and durations, and this computer's logs of the last 7 days and crash reports; \
         every name replaced by a placeholder, and none of the run's names found in it. Look \
         through it before you send it."
    );
    Ok(())
}
