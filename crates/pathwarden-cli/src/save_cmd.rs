//! `pathwarden collect --save` and `pathwarden run --save`: save a run to
//! an environment of the UI workspace, as an analysis started in the app
//! does (its report on the Runs page, recorded in the environment's
//! history), by the same rules ([`environments::place`]):
//!
//! - `--env NAME` puts it in that environment, `--new-env NAME` in a new
//!   one; picking one lists the run's domains no environment has yet.
//! - Otherwise its collected domains decide: the one environment they
//!   match, or a new one named after them. When something's off (two
//!   environments match, or a known domain plus a new one), the command
//!   stops with exit status 2, says why and what to pass, and saves
//!   nothing: a scheduled run never lands in the wrong environment.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anstream::{eprintln, print, println};
use anyhow::{bail, Context, Result};
use pathwarden_core::analyze;
use pathwarden_core::config::Config;
use pathwarden_core::findings::Severity;
use pathwarden_ui::env_remove;
use pathwarden_ui::environments::{
    self, Ask, Assigned, Choice, Decision, Placement, Registry, Settling,
};
use pathwarden_ui::workspace::{self, CollectionInfo, Workspace};

use crate::progress::{self, Through};
use crate::shell::{quoted, quoted_path};
use crate::{exit, fail_on_code, ui};

/// What to save, and where.
pub(crate) struct SaveArgs<'a> {
    pub inputs: Vec<PathBuf>,
    /// What was analyzed, in words (the run list's second line).
    pub source: String,
    /// `--workspace DIR` (default: the one `pathwarden ui` uses).
    pub workspace: Option<&'a Path>,
    /// The choice made, if any: [`Where::check`].
    pub choice: Option<Choice>,
    pub label: Option<String>,
    /// Domains known before the data is read (the domain `collect`
    /// collects, or the domains files of `run`'s input).
    pub known: Vec<String>,
    pub collection: Option<CollectionInfo>,
    /// `collect --save`: where the collection's time went.
    pub timings: Option<pathwarden_core::diagnostics::CollectionTimings>,
    /// `run --report FILE`: also write the report there.
    pub report: Option<&'a Path>,
    pub fail_on: Option<Severity>,
    pub verbose: bool,
    /// `collect --save`: where the collection is (kept when it stops).
    pub collected_into: Option<&'a Path>,
}

/// The workspace, made if there is none yet (a first `collect --save` on a
/// computer where the app never ran).
pub(crate) fn workspace(dir: Option<&Path>) -> Result<Workspace> {
    let root = match dir {
        Some(d) => d.to_path_buf(),
        None => workspace::default_dir()?,
    };
    if root.join("runs").is_dir() {
        Workspace::existing(&root)
    } else {
        Workspace::open(&root)
    }
}

/// `--env NAME` / `--new-env NAME`, checked before anything is collected
/// or read: an existing environment by its name (as shown) or ID; a new
/// name that is valid and not taken (a typo in `--env` never makes one).
pub(crate) fn check_choice(
    ws: &Workspace,
    env: Option<&str>,
    new_env: Option<&str>,
) -> Result<Option<Choice>> {
    let reg = ws.named_registry();
    match (env, new_env) {
        (Some(name), _) => match reg.find(name) {
            Some(e) if !e.demo => Ok(Some(Choice::Env(e.id.clone()))),
            Some(_) => bail!("Only the demo goes in the demo's environment."),
            None => bail!(
                "no environment named {name:?} in {} (there is: {}). To make one, use --new-env",
                ws.root().display(),
                environments::names_list(&reg, ws.root(), &ws.all_runs())
            ),
        },
        (None, Some(name)) => {
            let name = environments::clean_name(name).map_err(anyhow::Error::msg)?;
            if let Some(e) = reg.find(&name) {
                bail!(
                    "there is already an environment named {}; use --env {}",
                    e.display(),
                    quoted(e.display())
                );
            }
            Ok(Some(Choice::New(name)))
        }
        (None, None) => Ok(None),
    }
}

/// How to save the run once the user picks ([`ask_stop`]).
#[derive(Default)]
pub(crate) struct Again<'a> {
    /// `collect --save`: where the collection is.
    pub collected: Option<&'a Path>,
    /// `--workspace` and `--label` as given, repeated in the `run` command
    /// that saves the collection.
    pub workspace: Option<&'a Path>,
    pub label: Option<&'a str>,
}

/// The "something's off" stop: why, and the values to run again with.
/// Exit status 2; no run was saved. After `collect --save`, it says to save
/// the collection with `run` (with the same `--workspace` and `--label`)
/// instead of collecting again.
pub(crate) fn ask_stop(reg: &Registry, ask: &Ask, domains: &[String], again: &Again) -> ExitCode {
    let red = ui::severity(Severity::Critical);
    eprintln!("{red}error:{red:#} which environment should this run go to?");
    eprintln!("  {}", ui::safe(&ask.reason(reg)));
    match again.collected {
        Some(dir) => {
            let mut run = format!("pathwarden run -i {} --save", quoted_path(dir));
            if let Some(w) = again.workspace {
                run.push_str(&format!(" --workspace {}", quoted_path(w)));
            }
            if let Some(l) = again.label {
                run.push_str(&format!(" --label {}", quoted(l)));
            }
            eprintln!(
                "  The collection stays in {}. Save it with `{}` and one of:",
                ui::safe(&dir.display().to_string()),
                ui::safe(&run)
            )
        }
        None => eprintln!("  Run it again with one of:"),
    }
    let mut rows: Vec<(String, String)> = Vec::new();
    // As the app's where block says it: the new domains, and those known
    // only through old runs, go on the list of the environment picked.
    let listed: Vec<String> = ask.new.iter().chain(&ask.legacy).cloned().collect();
    for (id, _) in &ask.matches {
        let what = if listed.is_empty() {
            "save it there".to_string()
        } else {
            format!(
                "save it there; {} {} on its list",
                environments::and_list(&listed),
                if listed.len() == 1 { "goes" } else { "go" }
            )
        };
        rows.push((format!("--env {}", quoted(&reg.name_of(id))), what));
    }
    rows.push((
        format!("--new-env {}", quoted(&environments::new_name(domains))),
        "a new environment (any name)".into(),
    ));
    let width = rows
        .iter()
        .map(|(f, _)| f.chars().count())
        .max()
        .unwrap_or(0);
    let lit = ui::GREEN.bold();
    for (flag, what) in rows {
        let pad = width - flag.chars().count();
        eprintln!(
            "    {lit}{}{lit:#}{}  {}",
            ui::safe(&flag),
            " ".repeat(pad),
            ui::safe(&what)
        );
    }
    if again.collected.is_some() {
        eprintln!("  No run was saved.");
    } else {
        eprintln!("  Nothing was saved.");
    }
    ExitCode::from(exit::ERROR)
}

/// The decision before the data is read, from the domains known then: a
/// stop when something's off (nothing collected or read yet), else the
/// environment whose settings to analyze with.
pub(crate) fn precheck(
    ws: &Workspace,
    choice: Option<&Choice>,
    known: &[String],
) -> Result<Option<String>, ExitCode> {
    if let Some(c) = choice {
        return Ok(match c {
            Choice::Env(id) => Some(id.clone()),
            Choice::New(_) => None,
        });
    }
    if known.is_empty() {
        return Ok(None);
    }
    let all = ws.all_runs();
    let reg = ws.registry().with_names(&all);
    // Old runs ask, if they must, after the analysis (trusted domains known).
    let runs = environments::run_domains_for(&reg, &all, None);
    match environments::decide(&reg, known, &runs) {
        Decision::Ask(ask) => Err(ask_stop(&reg, &ask, known, &Again::default())),
        Decision::Match { id, .. } => Ok(Some(id)),
        Decision::New { .. } | Decision::Current => Ok(None),
    }
}

/// The environment's config and its bytes (to tell two apart).
fn config_of(ws: &Workspace) -> Result<(Config, Option<Vec<u8>>)> {
    Ok((ws.config()?, std::fs::read(ws.config_path()).ok()))
}

/// Analyzes and saves the run (see the module docs).
pub(crate) fn save(args: SaveArgs) -> Result<ExitCode> {
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();
    let ws = workspace(args.workspace)?;
    let likely = match precheck(&ws, args.choice.as_ref(), &args.known) {
        Ok(l) => l,
        Err(code) => return Ok(code),
    };
    let (mut config, used) = match &likely {
        Some(id) => config_of(&ws.in_env(id))?,
        None => (Config::default(), None),
    };
    let mut p = progress::Analysis::new(Through::Report, args.verbose);
    let mut ev =
        analyze::evaluate(&args.inputs, &config, &[], &mut p).context("loading collector data")?;
    let domains = analyze::domain_names(&ev.graph);
    let trusted = analyze::trusted_domain_names(&ev.graph);
    let all = ws.all_runs();
    let reg = ws.registry().with_names(&all);
    let runs = environments::run_domains_for(&reg, &all, Some((&domains, &trusted)));
    let again = Again {
        collected: args.collected_into,
        workspace: args.workspace,
        label: args.label.as_deref(),
    };
    let (target, how, created) =
        match environments::place(&reg, &domains, &runs, args.choice.as_ref(), false) {
            Placement::Ask(ask) => {
                p.done();
                return Ok(ask_stop(&reg, &ask, &domains, &again));
            }
            Placement::Current | Placement::Demo(_) => (
                reg.current
                    .clone()
                    .filter(|c| reg.get(c).is_some_and(|e| !e.demo))
                    .unwrap_or_else(|| environments::DEFAULT_ENV.into()),
                Assigned::Current,
                false,
            ),
            Placement::Settle(c, how, automatic) => {
                match environments::settle(ws.root(), &c, how, &domains, &runs, automatic)
                    .map_err(anyhow::Error::msg)?
                {
                    Settling::Settled(s) => (s.id, s.how, s.created),
                    // The environments changed meanwhile: the same stop.
                    Settling::Ask(ask) => {
                        p.done();
                        let all = ws.all_runs();
                        let reg = ws.registry().with_names(&all);
                        return Ok(ask_stop(&reg, &ask, &domains, &again));
                    }
                }
            }
        };
    let ws = ws.in_env(&target);
    let (own, own_bytes) = config_of(&ws)?;
    if own_bytes != used {
        config = own;
        ev = analyze::evaluate(&args.inputs, &config, &[], &mut p)
            .context("loading collector data")?;
    }
    // Once, for the settings the run was analyzed with.
    crate::warn_config(&config);
    for w in crate::settings_folder_warnings(&ev.stats) {
        p.note(w);
    }
    for w in crate::opengraph_warnings(&ev.stats) {
        p.note(w);
    }
    let code = fail_on_code(args.fail_on, &ev.findings);
    let id = workspace::new_run_id(analyze::now());
    // Data `pathwarden collect` wrote has its timings with it.
    let collected = args
        .timings
        .is_none()
        .then(|| pathwarden_core::diagnostics::collected_timings(&args.inputs))
        .flatten();
    // What the run did not target (a Quick run), as `pathwarden run` says.
    let not_targeted = pathwarden_core::posture::untargeted(
        &pathwarden_core::posture::completeness(&ev.graph, ev.settings.now),
    )
    .summary_note();
    let summary = pathwarden_ui::jobs::save_analysis(
        &ws,
        &config,
        ev,
        pathwarden_ui::jobs::SaveRun {
            id: &id,
            source: args.source,
            demo: false,
            label: args.label,
            collection: args.collection,
            timings: args
                .timings
                .or_else(|| collected.as_ref().map(|c| c.timings.clone())),
            how,
            state_dir: None,
            started_ms,
            recorded_by: crate::recorded_by(),
            finished_at: None,
            inputs: &args.inputs,
        },
        &mut p,
    )
    .map_err(anyhow::Error::msg)?;
    if let Some(c) = &collected {
        c.mark_recorded();
    }
    p.done();

    // Where it went, and why, as the UI says it.
    let names = ws.named_registry();
    let name = names.name_of(&target);
    let words = environments::and_list(&domains);
    let (gr, bold) = (ui::GREEN, ui::BOLD);
    let why = match how {
        Assigned::ByDomains => format!("it lists {words}"),
        Assigned::ByRuns => format!("earlier runs of {words} are there"),
        Assigned::Joined => "it has the other domains; the new ones join it".into(),
        Assigned::New => format!("no environment lists {words} yet"),
        Assigned::Chosen if created => "made for this run".into(),
        Assigned::Chosen => "chosen".into(),
        Assigned::Current => "the data names no domain".into(),
    };
    let label = summary
        .label
        .as_deref()
        .map(|l| format!(" · label \"{}\"", ui::safe(l)))
        .unwrap_or_default();
    if created && matches!(how, Assigned::New) {
        // The name can hold parentheses of its own ("X.LOCAL (2 domains)
        // and Y.LOCAL"), so why it is new is a sentence of its own.
        println!(
            "{gr}Saving to a new environment{gr:#} {bold}{}{bold:#}{label}",
            ui::safe(&name)
        );
        println!("  No environment lists {} yet.", ui::safe(&words));
        println!(
            "  Later runs can use --env {}; `pathwarden env rename {} NAME` gives it a shorter name.",
            ui::safe(&quoted(&name)),
            ui::safe(&quoted(&name))
        );
    } else if created {
        println!(
            "{gr}Saving to a new environment{gr:#} {bold}{}{bold:#} ({}){label}",
            ui::safe(&name),
            ui::safe(&why)
        );
        println!(
            "  Later runs can use --env {}; `pathwarden env rename {} NAME` gives it a shorter name.",
            ui::safe(&quoted(&name)),
            ui::safe(&quoted(&name))
        );
    } else {
        println!(
            "{gr}Saving to{gr:#} {bold}{}{bold:#} ({}){label}",
            ui::safe(&name),
            ui::safe(&why)
        );
    }
    println!(
        "  Tier Zero {}: {} · {} critical, {} high",
        summary.grade().as_str(),
        summary.headline().title,
        summary.critical,
        summary.high
    );
    if let Some(reason) = &summary.status_reason {
        println!("  {}", ui::safe(reason));
    }
    if let Some(note) = &not_targeted {
        println!("  {note}");
    }
    // The Tier Zero settings files it used, as Run details says.
    if let Some((line, notes)) = crate::settings_lines(
        &summary.settings_files,
        summary
            .history
            .as_ref()
            .map(|h| h.settings_fewer.as_slice())
            .unwrap_or_default(),
        summary.settings_folders_unread,
    ) {
        println!("  {}", ui::safe(&line));
        for n in notes {
            println!("  {}", ui::safe(&n));
        }
    }
    match summary.history.as_ref() {
        Some(h) if h.run_id.is_some() => {
            println!("  Run {}", summary.run_id());
            crate::print_full_run(h.full_run.as_ref(), None);
        }
        Some(h) => {
            let warn = ui::severity(Severity::Medium);
            let why = h.not_recorded.as_deref().unwrap_or_default();
            let why = match h.sign_in {
                true => {
                    // As sorted when it was recorded, with the working copy's
                    // own helper seen then.
                    crate::history_cmd::sign_in_words_for(h.no_helper, h.refused, why)
                }
                false => why.to_string(),
            };
            eprintln!(
                "{warn}Warning:{warn:#} Not in the run history: {}",
                ui::safe_text(&why)
            );
        }
        None => {}
    }
    // The history's warnings were printed as they came (the shared save
    // keeps them for the UI and passes each one on to this terminal too).
    let saved = ws
        .run_dir(&summary.id)
        .context("the run was saved but can't be found")?;
    let report = saved.join(workspace::REPORT_FILE);
    println!("  {gr}Report{gr:#} {}", report.display());
    if let Some(path) = args.report {
        let html = std::fs::read_to_string(&report)?;
        let html = match summary.label.as_deref() {
            Some(l) => pathwarden_core::report::with_label(&html, l),
            None => html,
        };
        std::fs::write(path, html).with_context(|| format!("writing {}", path.display()))?;
        println!("  {gr}Report{gr:#} {}", path.display());
    }
    // What changed, as `pathwarden history --env` prints it.
    let since = summary
        .history
        .as_ref()
        .and_then(|h| h.run_id.as_deref())
        .zip(pathwarden_ui::history_ui::locate_with(&ws, None, &config).ok())
        .and_then(|(run, loc)| pathwarden_core::history::since_run_in(&loc.store.dir, run));
    if let Some(since) = since {
        let mut context = vec!["--env".to_string(), name.clone()];
        if let Some(w) = args.workspace {
            context.extend(["--workspace".to_string(), w.display().to_string()]);
        }
        println!();
        print!("{}", since.render(&context));
    }
    // Saved and recorded here, but not pushed: the command fails (exit
    // code 2), as `pathwarden run` does, so a schedule notices.
    if let Some(h) = summary.history.as_ref().filter(|h| h.unpushed.is_some()) {
        let warn = ui::severity(Severity::Medium);
        let why = h.unpushed.as_deref().unwrap_or_default();
        eprintln!(
            "{warn}Warning:{warn:#} {}",
            ui::safe_text(&crate::as_sentence(why))
        );
        if let Some(detail) = h.unpushed_detail.as_deref().filter(|_| args.verbose) {
            eprintln!("  git: {}", ui::safe_text(detail));
        }
        bail!("{}", crate::UNPUSHED);
    }
    // Its point pushed, its full run only committed here: the same.
    if summary
        .history
        .as_ref()
        .and_then(|h| h.full_run.as_ref())
        .is_some_and(|f| f.state == pathwarden_ui::shared_runs::FullRunState::Unpushed)
    {
        bail!("{}", crate::FULL_UNPUSHED);
    }
    Ok(code)
}

/// The workspace at `dir` (default: the app's), which must exist.
fn existing_workspace(dir: Option<&Path>) -> Result<Workspace> {
    let root = match dir {
        Some(d) => d.to_path_buf(),
        None => workspace::default_dir()?,
    };
    Workspace::existing(&root)
}

/// `pathwarden env list`: the environments as the app's Environments page
/// lists them (an unused starting environment left out).
pub(crate) fn env_list(dir: Option<&Path>, json: bool) -> Result<()> {
    let ws = existing_workspace(dir)?;
    // A registry that can't be read is an error here, as in the app.
    Registry::try_load(ws.root()).map_err(anyhow::Error::msg)?;
    let all = ws.all_runs();
    let reg = ws.registry().with_names(&all);
    let unused = reg.default_unused(ws.root(), &environments::run_domains(&reg, &all));
    // As the Environments page says it.
    if let Some(note) = env_remove::reserved_note(ws.root()) {
        let warn = ui::severity(Severity::Medium);
        eprintln!(
            "{warn}Warning:{warn:#} {}",
            ui::safe(&crate::as_sentence(&note.to_string()))
        );
    }
    let mut rows = Vec::new();
    for e in reg
        .environments
        .iter()
        .filter(|e| !(e.is_default() && unused))
    {
        let runs: Vec<_> = all
            .iter()
            .filter(|r| environments::run_env(&reg, r) == e.id)
            .collect();
        let mut domains = e.domains.clone();
        for r in &runs {
            domains.extend(r.domains.iter().cloned());
        }
        rows.push(serde_json::json!({
            "id": e.id,
            "name": e.display(),
            "demo": e.demo,
            "current": reg.current.as_deref().unwrap_or(environments::DEFAULT_ENV) == e.id,
            "listed_domains": e.domains,
            "domains": environments::clean_domains(&domains),
            "runs": runs.len(),
            "folder": environments::env_dir(ws.root(), &e.id),
        }));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if rows.is_empty() {
        println!("No environment yet: the first collection saved (collect --save, run --save or the app) makes one, named after its domain.");
        return Ok(());
    }
    let bold = ui::BOLD;
    for r in &rows {
        let mut tags = String::new();
        if r["current"] == true {
            tags.push_str(" (current)");
        }
        if r["demo"] == true {
            tags.push_str(" (demo)");
        }
        println!(
            "{bold}{}{bold:#}{tags}  ID {}",
            ui::safe(r["name"].as_str().unwrap_or_default()),
            ui::safe(r["id"].as_str().unwrap_or_default())
        );
        let domains: Vec<&str> = r["domains"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str())
            .collect();
        println!(
            "  {} · domains: {}",
            pathwarden_core::text::count(r["runs"].as_u64().unwrap_or(0) as usize, "run", "runs"),
            if domains.is_empty() {
                "none".to_string()
            } else {
                ui::safe(&domains.join(", ")).to_string()
            }
        );
        println!("  {}", ui::safe(r["folder"].as_str().unwrap_or_default()));
    }
    Ok(())
}

/// `pathwarden env rename`: as the Environments page renames, with the
/// same checks (1 to 60 characters, no control characters, not taken).
pub(crate) fn env_rename(dir: Option<&Path>, env: &str, name: &str) -> Result<()> {
    let ws = existing_workspace(dir)?;
    let reg = ws.named_registry();
    let e = reg.find(env).with_context(|| {
        format!(
            "no environment named {env:?} (there is: {})",
            environments::names_list(&reg, ws.root(), &ws.all_runs())
        )
    })?;
    let shown = e.display().to_string();
    let changed =
        environments::rename_env(ws.root(), &e.id, name, &shown).map_err(anyhow::Error::msg)?;
    if changed {
        println!("Renamed {} to {}.", ui::safe(&shown), ui::safe(name.trim()));
    } else {
        println!("{} keeps its name.", ui::safe(&shown));
    }
    Ok(())
}

/// An environment of the workspace by name, shown name or ID.
fn find_env(ws: &pathwarden_ui::workspace::Workspace, env: &str) -> Result<(String, String)> {
    let reg = ws.named_registry();
    let e = reg.find(env).with_context(|| {
        format!(
            "no environment named {env:?} (there is: {})",
            environments::names_list(&reg, ws.root(), &ws.all_runs())
        )
    })?;
    Ok((e.id.clone(), e.display().to_string()))
}

/// `pathwarden env create`: as "New environment" does (shared
/// [`environments::create_environment`]).
pub(crate) fn env_create(
    dir: Option<&Path>,
    name: &str,
    domains: &str,
    copy_from: Option<&str>,
    make_current: bool,
) -> Result<()> {
    let ws = existing_workspace(dir)?;
    let copy = match copy_from {
        Some(c) => find_env(&ws, c)?.0,
        None => String::new(),
    };
    let id =
        environments::create_environment(&ws, name, domains, &copy).map_err(anyhow::Error::msg)?;
    if make_current {
        environments::make_current(ws.root(), &id).map_err(anyhow::Error::msg)?;
    }
    let created = ws.in_env(&id);
    println!(
        "Created environment {} (ID {id}){}{}",
        ui::safe(name.trim()),
        if copy.is_empty() {
            String::new()
        } else {
            format!(
                ", with the settings of {}",
                ui::safe(copy_from.unwrap_or_default())
            )
        },
        if make_current {
            "; the app now opens in it"
        } else {
            ""
        }
    );
    println!("  Settings: {}", created.config_path().display());
    Ok(())
}

/// `pathwarden env domains`: as "Change domains" does.
pub(crate) fn env_domains(dir: Option<&Path>, env: &str, domains: &str) -> Result<()> {
    let ws = existing_workspace(dir)?;
    let (id, shown) = find_env(&ws, env)?;
    environments::set_domains(ws.root(), &id, domains).map_err(anyhow::Error::msg)?;
    let now = environments::split_domains(domains);
    if now.is_empty() {
        println!("{} lists no domains now.", ui::safe(&shown));
    } else {
        println!("{} lists {}.", ui::safe(&shown), now.join(", "));
    }
    Ok(())
}

/// `pathwarden env use`: as switching environments in the app does.
pub(crate) fn env_use(dir: Option<&Path>, env: &str) -> Result<()> {
    let ws = existing_workspace(dir)?;
    let (id, shown) = find_env(&ws, env)?;
    environments::make_current(ws.root(), &id).map_err(anyhow::Error::msg)?;
    println!("The app now opens in {}.", ui::safe(&shown));
    Ok(())
}

/// `pathwarden env remove`: as the Environments page removes one, from the
/// same code ([`env_remove`]): the same summary of what goes, the same
/// confirmation (its name typed, on a terminal; `--yes` otherwise), the same
/// rules and messages.
pub(crate) fn env_remove(
    dir: Option<&Path>,
    env: &str,
    yes: bool,
    state: Option<&Path>,
) -> Result<()> {
    use std::io::{BufRead, IsTerminal, Write};
    let ws = existing_workspace(dir)?;
    // As the app with the same --state sees the first environment.
    environments::set_default_state(ws.root(), state);
    Registry::try_load(ws.root()).map_err(anyhow::Error::msg)?;
    let reg = ws.named_registry();
    let e = reg.find(env).with_context(|| {
        format!(
            "no environment named {env:?} (there is: {})",
            environments::names_list(&reg, ws.root(), &ws.all_runs())
        )
    })?;
    let plan = env_remove::plan(ws.root(), &e.id, state).map_err(anyhow::Error::msg)?;
    let bold = ui::BOLD;
    println!("{bold}{}{bold:#}", ui::safe(&plan.title()));
    for line in plan.lines() {
        println!("  - {}", ui::safe(&line));
    }
    if !yes {
        let terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
        if !terminal {
            bail!("Not removed: confirm on a terminal, or pass --yes to remove it without asking.");
        }
        eprint!("{}: ", ui::safe(&plan.confirm_prompt()));
        let _ = std::io::stderr().flush();
        let mut typed = String::new();
        std::io::stdin().lock().read_line(&mut typed)?;
        if !plan.confirms(&typed) {
            bail!("{}", env_remove::NOT_CONFIRMED);
        }
    }
    let done = env_remove::remove(ws.root(), &e.id, state, Some(&plan.runs_key))
        .map_err(anyhow::Error::msg)?;
    let gr = ui::GREEN;
    let mut lines = done.lines().into_iter();
    if let Some(first) = lines.next() {
        println!("{gr}{}{gr:#}", ui::safe(&first));
    }
    for line in lines {
        println!("  {}", ui::safe(&line));
    }
    Ok(())
}

/// `pathwarden label`: sets or clears a run's label, by the ID the run list,
/// `pathwarden run` or `pathwarden history` shows: a run saved in the app
/// (or with `--save`), else a run recorded in an environment's history
/// (searched in `env`, else in every environment).
pub(crate) fn label_cmd(
    workspace_dir: Option<&Path>,
    env: Option<&str>,
    run: &str,
    label: Option<&str>,
) -> Result<()> {
    let label = match label {
        Some(l) => workspace::clean_label(l).map_err(anyhow::Error::msg)?,
        None => None,
    };
    let root = match workspace_dir {
        Some(d) => d.to_path_buf(),
        None => workspace::default_dir()?,
    };
    let ws = Workspace::existing(&root)?;
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
    let said = |what: &str| match &label {
        Some(l) => println!("Label of {what}: \"{}\".", ui::safe(l)),
        None => println!("Label of {what} removed."),
    };
    // A run saved in the app: by its folder or history ID.
    let folder = ws
        .run_dir(run)
        .map(|_| run.to_string())
        .or_else(|| ws.find_run(run));
    if let Some(id) = folder {
        let s = ws.summary(&id).context("that run can't be read")?;
        let run_ws = ws.for_run(&s);
        if only.as_deref().is_some_and(|e| e != run_ws.env_id()) {
            bail!("Run {run} isn't in that environment.");
        }
        let s =
            workspace::set_run_label(&run_ws, &id, label.as_deref()).map_err(anyhow::Error::msg)?;
        said(&format!(
            "run {} ({})",
            s.run_id(),
            ui::safe(&s.environment())
        ));
        return Ok(());
    }
    // A run recorded in an environment's history.
    if !workspace::looks_like_history_id(run) {
        bail!(
            "no run {run}: use the ID the run list, `pathwarden run` or `pathwarden history` shows"
        );
    }
    for e in reg.environments.iter().filter(|e| !e.demo) {
        if only.as_deref().is_some_and(|o| o != e.id) {
            continue;
        }
        let env_ws = ws.in_env(&e.id);
        let Ok(loc) = pathwarden_ui::history_ui::locate(&env_ws, None) else {
            continue;
        };
        let has = pathwarden_core::history::load(&loc.dir)
            .map(|(points, _)| points.iter().any(|p| p.run_id == run))
            .unwrap_or(false);
        if has {
            workspace::set_later_label(&env_ws, run, label.as_deref())
                .map_err(anyhow::Error::msg)?;
            said(&format!("run {run} ({})", ui::safe(e.display())));
            return Ok(());
        }
    }
    bail!("no run {run} in the workspace's runs or environments' histories")
}
