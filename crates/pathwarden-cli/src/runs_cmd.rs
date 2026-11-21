//! `pathwarden runs list|show|report`: the app's Runs page and run
//! pages from the terminal. The rows, their tags and words come from the
//! page's own code ([`pathwarden_ui::run_list`]), so both list the same runs
//! in the same words. A run the history has with no full run ("numbers
//! only") shows what its small run page shows.

use std::path::PathBuf;

use anstream::println;
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use pathwarden_core::exposed::{self, Account, ExposureLists, Hop};
use pathwarden_core::model::NodeKind;
use pathwarden_core::point_findings::PointChange;
use pathwarden_ui::history_ui::{self, Snapshot};
use pathwarden_ui::run_list::{self, RunRow, Source};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};

use crate::history_cmd::Env;
use crate::ui;

#[derive(Subcommand)]
pub(crate) enum RunsAction {
    /// Every run of the environment, newest first: the runs on this computer
    /// and the runs in the run history (the app's Runs page).
    List {
        #[command(flatten)]
        env: Env,
        /// The history folder (overrides [state] path in the settings).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// One run, as its page opens it: when and how it was recorded, its
    /// exposure and findings. A run with no full run lists its findings
    /// from the run history.
    Show {
        /// The run, by the ID `runs list` prints (a run folder's ID or the
        /// history's run ID).
        #[arg(value_name = "RUN")]
        run: String,
        #[command(flatten)]
        env: Env,
        /// The history folder (overrides [state] path in the settings).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
        /// List the accounts plan step N of the remediation path cuts off (1
        /// for the first), new ones first.
        #[arg(long, value_name = "N")]
        step: Option<usize>,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Write a run's report, as the run page's "Download report" gives it.
    Report {
        /// The run, by the ID `runs list` prints.
        #[arg(value_name = "RUN")]
        run: String,
        /// Where to write the HTML report.
        #[arg(
            short,
            long,
            value_name = "FILE",
            default_value = "pathwarden-report.html"
        )]
        output: PathBuf,
        #[command(flatten)]
        env: Env,
        /// The history folder (overrides [state] path in the settings).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
    },
}

pub(crate) fn run(action: RunsAction) -> Result<()> {
    match action {
        RunsAction::List { env, state, json } => list(&env, state, json),
        RunsAction::Show {
            run,
            env,
            state,
            step,
            json,
        } => show(&env, state, &run, step, json),
        RunsAction::Report {
            run,
            output,
            env,
            state,
        } => report(&env, state, &run, &output),
    }
}

/// The environment's runs and its history, read as the Runs page reads
/// them.
struct Loaded {
    ws: Workspace,
    runs: Vec<pathwarden_ui::workspace::RunSummary>,
    snap: Snapshot,
    keep: pathwarden_core::config::Keep,
}

fn load(env: &Env, state: Option<PathBuf>) -> Result<Loaded> {
    let ws = env.workspace()?;
    let runs = ws.runs();
    let snap = history_ui::snapshot(&ws, state.as_deref());
    let keep = pathwarden_ui::settings::load_ws(&ws).config.state.keep();
    Ok(Loaded {
        ws,
        runs,
        snap,
        keep,
    })
}

impl Loaded {
    fn rows(&self) -> Vec<RunRow> {
        run_list::run_list_with(&self.ws, &self.runs, &self.snap, self.keep)
    }

    /// What keeps the history's runs from the list, as the Runs page says
    /// it: the history can't be used, or is encrypted and this computer
    /// can't open it.
    fn problem(&self) -> Option<String> {
        let loc = match &self.snap.location {
            Err(e) => return Some(format!("The run history can't be used: {e}")),
            Ok(loc) => loc,
        };
        if let Some(why) = pathwarden_ui::encryption_ui::lock_reason(loc) {
            // The terminal's lead (or the gate's words for a wrong
            // passphrase), then how to give the passphrase here.
            let lead = match why {
                Some(wrong) => format!("{}. {wrong}", pathwarden_ui::encryption_ui::GATE_TITLE),
                None => pathwarden_ui::encryption_ui::CLI_LOCKED.to_string(),
            };
            return Some(format!(
                "{lead} Only the runs analysed here are listed. Store the passphrase with \
                 `pathwarden history storage passphrase set`, or set PATHWARDEN_HISTORY_PASSPHRASE."
            ));
        }
        self.snap.history.problem.clone()
    }
}

/// The ID `runs list`, `run`, `history` and `label` print for a run: the
/// history's, else its folder's. The commands it names take either.
fn shown_id(row: &RunRow) -> &str {
    row.history_id.as_deref().unwrap_or(&row.id)
}

impl Loaded {
    fn find(&self, id: &str) -> Result<RunRow> {
        let rows = self.rows();
        if let Some(r) = rows
            .into_iter()
            .find(|r| r.id == id || r.history_id.as_deref() == Some(id))
        {
            return Ok(r);
        }
        let mut msg = format!(
            "no run {id} in environment {}; `pathwarden runs list` lists its runs",
            self.ws.env_name()
        );
        if let Some(p) = self.problem() {
            msg = format!("{msg}. {p}");
        }
        bail!(msg)
    }
}

/// A run's time as people read it: US style, this computer's time.
fn when(t: i64) -> String {
    pathwarden_core::time::format_local(t)
}

/// "  [Scheduled] [Numbers with names]", or nothing.
fn tags(r: &RunRow) -> String {
    r.tags
        .iter()
        .map(|t| format!("  [{}]", t.words()))
        .collect()
}

/// The list's columns, in the page's words.
const EXPOSURE: &str = "With an attack path to Tier Zero";
const VS: &str = "Vs previous";
const URGENT: &str = "Critical and high";

fn list(env: &Env, state: Option<PathBuf>, json: bool) -> Result<()> {
    let l = load(env, state)?;
    let rows = l.rows();
    let problem = l.problem();
    // Run folders a newer Pathwarden saved: never listed (docs/dev/formats.md).
    let newer = l.ws.newer_run_folders();
    let newer_words = pathwarden_ui::workspace::newer_runs_words(newer);
    if json {
        return crate::emit_json(&json!({
            "environment": l.ws.env_name(),
            "problem": problem,
            "newer_runs": newer,
            "newer_runs_words": newer_words,
            "runs": rows.iter().map(run_list::row_json).collect::<Vec<_>>(),
        }));
    }
    let (b, d) = (ui::BOLD, ui::DIM);
    if rows.is_empty() {
        // No environment to name yet either: one line.
        println!("No runs yet.");
    } else {
        println!(
            "{b}Runs{b:#} of environment {}, newest first: {}",
            ui::safe(&l.ws.env_name()),
            match rows.len() {
                1 => "1 run".to_string(),
                n => format!("{} runs", pathwarden_core::text::num(n)),
            }
        );
    }
    if let Some(p) = &problem {
        println!("{}", ui::safe(p));
    }
    if let Some(w) = &newer_words {
        println!("{w}");
    }
    for r in &rows {
        let s = &r.summary;
        println!();
        // The ID `run`, `history` and `label` print (the folder's only
        // when the history doesn't have the run); --json has both.
        println!(
            "{b}{}{b:#}  {}{}",
            ui::safe(r.history_id.as_deref().unwrap_or(&r.id)),
            ui::safe(&s.title()),
            tags(r)
        );
        println!("  {d}{}{d:#}", ui::safe(&r.sub(when)));
        println!(
            "  {d}{EXPOSURE}:{d:#} {} · {}",
            ui::safe(&run_list::exposure_words(s)),
            s.grade().as_str()
        );
        println!(
            "  {d}{VS}:{d:#} {} · {d}{URGENT}:{d:#} {}",
            r.vs.map(|v| v.text()).unwrap_or_else(|| "-".into()),
            run_list::urgent_words(s)
        );
    }
    if !rows.is_empty() {
        println!("\n`pathwarden runs show RUN` shows one.");
    }
    Ok(())
}

fn findings_json(f: &pathwarden_core::point_findings::PointFindings) -> Value {
    json!({
        "complete": f.complete,
        "new": f.new,
        "back": f.back,
        "fixed": f.fixed,
        "items": f.items.iter().map(|x| json!({
            "fingerprint": x.fingerprint,
            "rule": x.rule,
            "severity": x.severity,
            "title": run_list::finding_title(x),
            "change": x.change,
        })).collect::<Vec<_>>(),
    })
}

/// "Sam@CONTOSO.LOCAL" as a hop of a path: "Sam"; a computer
/// "WS1.CONTOSO.LOCAL": "WS1". Domains keep their name.
fn short_name(name: &str, kind: NodeKind) -> &str {
    let cut = match kind {
        NodeKind::Domain => None,
        NodeKind::Computer => name.find('.'),
        _ => name.find('@'),
    };
    match cut {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    }
}

/// A path in words: "MemberOf ADMINS AdminTo SRV1 HasSession DA"; past
/// three hops, the first two, "…" and the last.
fn path_words(path: &[Hop]) -> String {
    let hop = |h: &Hop| format!("{} {}", h.edge, short_name(h.name, h.kind));
    match path {
        [a, b, .., last] if path.len() > 3 => {
            format!("{} {} … {}", hop(a), hop(b), hop(last))
        }
        _ => path.iter().map(hop).collect::<Vec<_>>().join(" "),
    }
}

fn hops_words(n: usize) -> String {
    pathwarden_core::text::count(n, "hop", "hops")
}

/// "and 12 more (--json lists every one)", past [`run_list::MAX_LISTED`].
fn more(n: usize) {
    if n > run_list::MAX_LISTED {
        println!(
            "  and {} more (--json lists every one)",
            pathwarden_core::text::num(n - run_list::MAX_LISTED)
        );
    }
}

fn hops_json(path: &[Hop]) -> Value {
    json!(path
        .iter()
        .map(|h| json!({ "edge": h.edge, "name": h.name, "kind": h.kind.as_str() }))
        .collect::<Vec<_>>())
}

fn account_json(a: &Account) -> Value {
    json!({
        "name": a.name,
        "kind": a.kind.as_str(),
        "new": a.new,
        "hops": a.hops(),
        "path": hops_json(&a.path),
    })
}

/// `tier_zero_change` of `runs show --json`: every account.
fn change_json(lists: &ExposureLists) -> Value {
    let Some(c) = &lists.change else {
        return Value::Null;
    };
    json!({
        "available": c.unavailable.is_none(),
        "reason": c.unavailable.map(|w| w.key()),
        "words": c.unavailable.and_then(|w| w.sentence()),
        "previous_run": c.previous_run,
        "previous_at": c.previous_at,
        "sentence": lists.same_total_sentence(),
        "now_reach": lists.now_reach().iter().map(|(a, step)| {
            let mut v = account_json(a);
            v["step"] = json!(step);
            v
        }).collect::<Vec<_>>(),
        "from_full_run": c.from_full_run,
        "no_longer": lists.no_longer().iter().map(|g| {
            let mut v = json!({
                "name": g.name,
                "kind": g.kind.as_str(),
                "why": g.why.key(),
                "words": g.why.words(),
            });
            // Its path in the previous run, when its graph was read.
            if !g.path.is_empty() {
                v["hops_then"] = json!(g.path.len());
                v["path_then"] = hops_json(&g.path);
            }
            v
        }).collect::<Vec<_>>(),
        "no_longer_unnamed": c.gone_unnamed,
        "no_longer_unnamed_words": (c.gone_unnamed > 0).then(|| exposed::unnamed_sentence(c.gone_unnamed)),
    })
}

/// What changed since the previous run, account by account (text).
fn print_change(lists: &ExposureLists) {
    let b = ui::BOLD;
    let Some(c) = &lists.change else {
        return;
    };
    if let Some(why) = c.unavailable {
        if let Some(s) = why.sentence() {
            println!("\n{s}");
        }
        return;
    }
    if let Some(s) = lists.same_total_sentence() {
        println!("\n{s}");
    }
    let now = lists.now_reach();
    if !now.is_empty() {
        println!(
            "\n{b}Now reach Tier Zero{b:#} ({})",
            pathwarden_core::text::num(now.len())
        );
        for (a, step) in now.iter().take(run_list::MAX_LISTED) {
            println!(
                "  {} · {} · {} · {}",
                ui::safe(a.name),
                hops_words(a.hops()),
                ui::safe(&path_words(&a.path)),
                match step {
                    Some(n) => format!("step {n} cuts it off"),
                    None => exposed::NO_STEP.to_string(),
                }
            );
        }
        more(now.len());
    }
    let gone = lists.no_longer();
    if !gone.is_empty() || c.gone_unnamed > 0 {
        println!(
            "\n{b}No longer reach Tier Zero{b:#} ({})",
            pathwarden_core::text::num(gone.len() + c.gone_unnamed)
        );
        // "path on Oct 19", as the report and the app say it.
        let on = pathwarden_core::report::short_date(c.previous_at);
        for g in gone.iter().take(run_list::MAX_LISTED) {
            if g.path.is_empty() {
                println!("  {} · {}", ui::safe(g.name), g.why.words());
            } else {
                // Its path in the previous run, read from its full run.
                println!(
                    "  {} · {} · path on {on}: {} · {}",
                    ui::safe(g.name),
                    g.why.words(),
                    hops_words(g.path.len()),
                    ui::safe(&path_words(&g.path)),
                );
            }
        }
        more(gone.len());
        if c.gone_unnamed > 0 {
            println!("  {}", exposed::unnamed_sentence(c.gone_unnamed));
        }
    }
}

/// Step `n`'s accounts (text).
fn print_step(lists: &ExposureLists, n: usize, accounts: &[Account]) {
    let b = ui::BOLD;
    println!(
        "\n{b}Plan step {n}{b:#} cuts off {}.",
        pathwarden_core::text::count(accounts.len(), "account", "accounts")
    );
    // Against the previous run: how many are new, or why that isn't known.
    if let Some(c) = &lists.change {
        match c.unavailable.map(|why| why.sentence()) {
            Some(Some(s)) => println!("{s}"),
            Some(None) => {}
            None => {
                let new = accounts.iter().filter(|a| a.new).count();
                if new > 0 {
                    println!(
                        "{} new since the last run.",
                        pathwarden_core::text::num(new)
                    );
                }
            }
        }
    }
    for a in accounts.iter().take(run_list::MAX_LISTED) {
        println!(
            "  {}{} · {} · {}",
            if a.new { "[New] " } else { "" },
            ui::safe(a.name),
            hops_words(a.hops()),
            ui::safe(&path_words(&a.path)),
        );
    }
    more(accounts.len());
}

fn show(
    env: &Env,
    state: Option<PathBuf>,
    id: &str,
    step: Option<usize>,
    json: bool,
) -> Result<()> {
    let l = load(env, state)?;
    let row = l.find(id)?;
    let page = (row.source == Source::NumbersOnly)
        .then(|| run_list::point_page(&l.ws, &l.runs, &l.snap, &row.id))
        .flatten();
    // Run details' "Other sources" row reads the OpenGraph statistics saved
    // in the run's folder.
    let mut summary = row.summary.clone();
    if matches!(row.source, Source::Local | Source::Shared) {
        pathwarden_ui::run_details::with_sources(&l.ws, &mut summary);
    }
    let s = &summary;
    // The run's account lists, kept with a run that has a folder here.
    let lists = matches!(row.source, Source::Local | Source::Shared)
        .then(|| l.ws.run_dir(&row.id))
        .flatten()
        .and_then(|dir| pathwarden_ui::run_data::exposure_lists(&dir));
    let step_accounts = match (step, &lists) {
        (None, _) => None,
        (Some(_), None) => bail!("Run {} has no account lists.", row.id),
        (Some(_), Some(Err(e))) => bail!("{e}"),
        (Some(n), Some(Ok(lists))) => match lists.step_accounts(n) {
            Some(a) => Some((n, a)),
            None => bail!(
                "The remediation path of run {} has {}.",
                row.id,
                pathwarden_core::text::count(lists.steps.len(), "step", "steps")
            ),
        },
    };
    // What the run page's Run details says besides where the run came
    // from: its collection performance and the settings line.
    let details = (row.source != Source::NumbersOnly && row.source != Source::ScheduleReport)
        .then(|| pathwarden_ui::run_details::perf_and_applies(&l.ws, s));
    if json {
        let mut v = run_list::row_json(&row);
        if let Some((perf, applies)) = &details {
            if let Some(slower) = perf {
                v["performance"] = json!({
                    "slower": slower,
                    "words": pathwarden_ui::run_details::perf_words(*slower),
                });
            }
            v["settings"] = match applies {
                Ok(t) => json!({ "applies": t, "loaded": true }),
                Err(t) => json!({ "applies": t, "loaded": false }),
            };
        }
        v["environment_name"] = json!(l.ws.env_name());
        // The Tier Zero settings files it used, as Run details lists
        // them.
        if !s.settings_files.is_empty() {
            v["settings_files"] = json!(s.settings_files);
        }
        if let Some(h) = s.history.as_ref().filter(|h| !h.settings_fewer.is_empty()) {
            v["settings_fewer"] = json!(h.settings_fewer);
        }
        if s.settings_folders_unread > 0 {
            v["settings_folders_unread"] = json!(s.settings_folders_unread);
        }
        // OpenGraph and AzureHound sources not read whole.
        if !s.incomplete_sources.is_empty() {
            v["incomplete_sources"] = json!(s.incomplete_sources);
        }
        // Other collectors' OpenGraph sources, as Run details' "Other
        // sources" row says them.
        if let Some(og) = &s.other_sources {
            v["other_sources"] = json!(og);
        }
        // Add other data: whether its kept collection is there, and
        // the input that names it.
        if let Some(k) = pathwarden_ui::add_data::kept_collection(s) {
            let here = matches!(k, pathwarden_ui::add_data::Kept::Here(_));
            v["add_data"] = json!({
                "possible": here,
                "words": k.line(),
                "input": here.then(|| format!("{}{}", pathwarden_ui::add_data::INPUT_PREFIX, row.id)),
            });
        }
        // Account by account: what changed, and each step's count (its
        // accounts with --step).
        match &lists {
            Some(Ok(lists)) => {
                v["tier_zero_change"] = change_json(lists);
                v["steps"] = json!(lists
                    .steps
                    .iter()
                    .map(|st| json!({ "step": st.step, "exposed": st.exposed, "new": st.new }))
                    .collect::<Vec<_>>());
                if let Some((n, accounts)) = &step_accounts {
                    let st = &lists.steps[n - 1];
                    v["step"] = json!({
                        "step": n,
                        "exposed": st.exposed,
                        "new": st.new,
                        "accounts": accounts.iter().map(account_json).collect::<Vec<_>>(),
                    });
                }
            }
            Some(Err(e)) => v["tier_zero_lists_error"] = json!(e),
            None => {}
        }
        if let Some(pg) = &page {
            v["line"] = json!(pg.line);
            v["findings"] = match &pg.findings {
                Ok(f) => findings_json(f),
                Err(e) => json!({ "error": e }),
            };
        }
        if let Some(h) = &s.history {
            v["history"] = json!({
                "not_recorded": h.not_recorded,
                "unpushed": h.unpushed,
                "warnings": h.warnings,
                "sign_in": h.sign_in,
                "full_run": h.full_run,
            });
        }
        if let Some(sh) = &s.shared {
            v["shared"] = json!({
                "recorded_by": sh.recorded_by,
                "recorded_on": sh.recorded_on,
                "recorded_from": sh.recorded_from,
                "words": sh.recorded_words(),
                "pathwarden": sh.pathwarden,
                "repository": sh.remote,
                "branch": sh.branch,
                "loaded_at": sh.mirrored_at,
                "left_out": sh.left_out,
            });
        }
        return crate::emit_json(&v);
    }
    let (b, d) = (ui::BOLD, ui::DIM);
    println!("{b}{}{b:#}{}", ui::safe(&s.title()), tags(&row));
    println!(
        "{d}Environment{d:#} {} · {d}Run{d:#} {}",
        ui::safe(&l.ws.env_name()),
        ui::safe(row.history_id.as_deref().unwrap_or(&s.run_id())),
    );
    let collected = s
        .collected_at
        .map(|t| {
            format!(
                " · Data collected {}",
                pathwarden_core::time::format_collected(t)
            )
        })
        .unwrap_or_default();
    println!("{}{collected}", ui::safe(&row.sub(when)));
    println!();
    println!(
        "  {d}{EXPOSURE:<34}{d:#}{} · {}",
        ui::safe(&run_list::exposure_words(s)),
        s.grade().as_str()
    );
    println!(
        "  {d}{VS:<34}{d:#}{}",
        row.vs.map(|v| v.text()).unwrap_or_else(|| "-".into())
    );
    println!("  {d}{URGENT:<34}{d:#}{}", run_list::urgent_words(s));
    match &lists {
        Some(Ok(lists)) => {
            if let Some((n, accounts)) = &step_accounts {
                print_step(lists, *n, accounts);
                return Ok(());
            }
            print_change(lists);
            if !lists.steps.is_empty() {
                println!(
                    "\n`pathwarden runs show {} --step N` lists the accounts step N of the remediation path cuts off.",
                    ui::safe(shown_id(&row))
                );
            }
        }
        Some(Err(e)) => println!("\n{}", ui::safe(e)),
        None => {}
    }
    // Run details, as the run page's tab says it: its rows (where the run
    // came from, the other sources read with it, how it was collected,
    // objects skipped, its place in the run history, the comparison with
    // the previous run, collection performance and the settings line),
    // each a title, a short status (`!` when it needs a look) and what the
    // row says.
    if let Some((perf, applies)) = &details {
        use pathwarden_ui::run_details::{self, Go};
        if run_details::attention(s) {
            println!("\n{}", run_details::ATTENTION);
        }
        println!("\n{b}{}{b:#}", run_details::TAB);
        for r in run_details::rows(s, *perf, applies) {
            println!(
                "  {b}{}{b:#} · {}{}",
                r.title,
                ui::safe(&r.status),
                if r.warn { " !" } else { "" }
            );
            // Labels in a column at least 12 wide, past the longest.
            let width = r
                .facts
                .iter()
                .map(|(k, _, _)| k.len() + 1)
                .max()
                .unwrap_or(0)
                .max(12);
            for (k, v, _) in &r.facts {
                println!("    {d}{k:<width$}{d:#}{}", ui::safe(v));
            }
            // The run's domains: each and how it went.
            let width = r
                .domains
                .iter()
                .map(|l| l.name.chars().count())
                .max()
                .unwrap_or(0);
            for l in &r.domains {
                let pad = " ".repeat(width - l.name.chars().count());
                println!(
                    "    {}{pad}  {}{}",
                    ui::safe(&l.name),
                    if l.collected { "" } else { "! " },
                    ui::safe(&l.text)
                );
            }
            // The Tier Zero settings files: each, and its file name.
            let width = r
                .settings
                .iter()
                .map(|l| l.name.chars().count())
                .max()
                .unwrap_or(0);
            for l in &r.settings {
                let pad = " ".repeat(width - l.name.chars().count());
                println!(
                    "    {}{pad}  {}{} ({})",
                    ui::safe(&l.name),
                    if l.stale { "! " } else { "" },
                    ui::safe(&l.text.text()),
                    ui::safe(&l.detail)
                );
            }
            for (d, _) in &r.dated {
                println!("    {}", ui::safe(&d.text()));
            }
            for t in &r.text {
                println!("    {}", ui::safe(t));
            }
            if let Some(t) = r.resumed {
                println!(
                    "    {}",
                    run_details::resumed_sentence(&run_details::resumed_at_local(t))
                );
            }
            for i in &r.items {
                println!("    - {}", ui::safe(i));
            }
            if let Some(k) = &r.kept {
                let (lead, tail) = run_details::KEPT_WORDS;
                println!("    {lead} {}. {tail}", ui::safe(k));
            }
            match r.go {
                Some(Go::Performance { slower }) => println!(
                    "    {} · `pathwarden diagnose {}` shows it.",
                    run_details::perf_words(slower),
                    ui::safe(shown_id(&row))
                ),
                Some(Go::History) if r.sign_in => {
                    println!("    `pathwarden history storage sign-in` signs in, then syncs.")
                }
                Some(Go::History) => {
                    println!("    `pathwarden history storage show` shows the history.")
                }
                Some(Go::Collect) => {
                    if let Some(c) = collect_again(s) {
                        println!("    `{}` collects them.", ui::safe(&c));
                    }
                }
                Some(Go::SettingsFolders) => {
                    println!(
                        "    `pathwarden config settings-folders` changes the settings folders."
                    )
                }
                Some(Go::Mappings) => println!(
                    "    Mappings {} `pathwarden mappings list` shows them.",
                    run_details::MAPPINGS_TAIL
                ),
                _ => {}
            }
        }
        // Add other data, as the tab has it above Remove this run.
        if let Some(line) = add_data_line(s, &row.id) {
            println!("  {b}{}{b:#}", pathwarden_ui::add_data::TITLE);
            println!("    {line}");
        }
    }
    match (&row.source, &page) {
        (Source::NumbersOnly, Some(pg)) => {
            println!("\n{}", pg.line);
            print_findings(pg);
        }
        (Source::Local | Source::Shared, _) => {
            println!(
                "\n`pathwarden runs report {}` writes its report.",
                ui::safe(shown_id(&row))
            );
        }
        (Source::ScheduleReport, _) => {
            println!(
                "\nIts report is the schedule's latest; `pathwarden runs report {}` writes it.",
                ui::safe(shown_id(&row))
            );
        }
        _ => {}
    }
    Ok(())
}

fn print_findings(pg: &run_list::PointPage) {
    let (b, d) = (ui::BOLD, ui::DIM);
    let f = match &pg.findings {
        Err(e) => {
            println!("\n{b}Findings{b:#}\n{}", ui::safe(e));
            return;
        }
        Ok(f) => f,
    };
    let counts = run_list::findings_counts_words(f);
    if counts.is_empty() {
        println!("\n{b}Findings{b:#}");
    } else {
        println!("\n{b}Findings{b:#}: {counts}");
    }
    // What the page's ⓘ say, as lines.
    println!("{d}{}{d:#}", run_list::FINDINGS_TIP);
    if !f.complete {
        println!(
            "{} {d}{}{d:#}",
            run_list::PARTIAL_WORDS,
            run_list::PARTIAL_TIP
        );
    }
    if let Some(w) = run_list::empty_words(f) {
        println!("{w}");
    }
    for x in f.items.iter().take(run_list::MAX_LISTED) {
        let sev = ui::severity(x.severity);
        let change = match x.change {
            PointChange::Open => String::new(),
            c => format!("[{}] ", c.words()),
        };
        println!(
            "  {sev}{:<10}{sev:#}{change}{}  {d}{}{d:#}",
            run_list::severity_words(x.severity),
            ui::safe(&run_list::finding_title(x)),
            ui::safe(&x.rule)
        );
    }
    if f.items.len() > run_list::MAX_LISTED {
        println!(
            "  and {} more (--json lists every one)",
            pathwarden_core::text::num(f.items.len() - run_list::MAX_LISTED)
        );
    }
}

fn report(env: &Env, state: Option<PathBuf>, id: &str, output: &std::path::Path) -> Result<()> {
    let l = load(env, state)?;
    let row = l.find(id)?;
    let html = match run_list::report_for(&l.ws, &l.snap, &row) {
        Ok(h) => h,
        Err(why) => bail!("{why}"),
    };
    std::fs::write(output, html).with_context(|| format!("writing {}", output.display()))?;
    println!("Wrote {}.", output.display());
    Ok(())
}

/// Run details' "Add other data" for the terminal: the command
/// that analyzes the run's kept collection again with other files, or why
/// it can't. `None` for a run that wasn't collected on this computer.
fn add_data_line(s: &pathwarden_ui::workspace::RunSummary, id: &str) -> Option<String> {
    use pathwarden_ui::add_data::{self, Kept};
    Some(match add_data::kept_collection(s)? {
        Kept::Here(_) => format!(
            "`pathwarden run -i {}{id} -i FILE --save` analyzes this run's collection again \
             with AzureHound, OpenGraph or SharpHound files, as a new run.",
            add_data::INPUT_PREFIX
        ),
        other => other.line().to_string(),
    })
}

/// The command that collects what a run left out: its domain again,
/// with the domains that failed, or with `--trusted` (the trusted domains
/// this account can read).
fn collect_again(r: &pathwarden_ui::workspace::RunSummary) -> Option<String> {
    pathwarden_ui::collect::collect_again_href(r)?;
    let c = r.collection.as_ref()?;
    let mut cmd = format!("pathwarden collect -d {}", c.domain.to_ascii_lowercase());
    let failed = c.failed_domains();
    if failed.is_empty() {
        cmd.push_str(" --trusted");
    }
    for d in failed {
        cmd.push_str(&format!(" -d {}", d.to_ascii_lowercase()));
    }
    cmd.push_str(" -o DIR");
    Some(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathwarden_ui::workspace::{CollectionInfo, DomainOutcome};

    fn run(
        domains: Vec<DomainOutcome>,
        not_collected: Vec<&str>,
    ) -> pathwarden_ui::workspace::RunSummary {
        let p: pathwarden_core::state::HistoryPoint = serde_json::from_value(serde_json::json!({
            "version": 1, "run_id": "r1", "at": 1, "collected_at": null,
            "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": 1,
            "tier_zero_population": 100, "tier_zero_objects": 1,
            "protection_score": null,
            "findings": {"attack_path": 0, "hygiene": 0, "suppressed": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "changes": {"new": 0, "open": 0, "regressed": 0, "suppressed": 0,
                "resolved": 0},
            "recorded_by": "cli",
        }))
        .unwrap();
        let mut r = pathwarden_ui::history_ui::point_summary(&p, &["CONTOSO.LOCAL".to_string()]);
        r.collection = Some(CollectionInfo {
            read_started: None,
            plain_allowed: false,
            plain_fallback: false,
            method: "builtin".into(),
            scope: "dc-only".into(),
            domain: "contoso.local".into(),
            server: None,
            ldaps: true,
            current_user: false,
            warnings: Vec::new(),
            kept: None,
            kerberos_only: Some(true),
            smb_signing: Some(true),
            domains,
        });
        r.not_collected = Some(not_collected.into_iter().map(str::to_string).collect());
        r
    }

    /// `runs show` says how to collect what a run left out: the
    /// domains that failed, else `--trusted`.
    #[test]
    fn the_command_that_collects_what_was_left_out() {
        let failed = DomainOutcome {
            domain: "TAILSPIN.COM".into(),
            collected: false,
            objects: None,
            seconds: None,
            reason: Some("Couldn't reach a domain controller.".into()),
            detail: None,
        };
        assert_eq!(
            collect_again(&run(vec![failed], vec![])).as_deref(),
            Some("pathwarden collect -d contoso.local -d tailspin.com -o DIR")
        );
        assert_eq!(
            collect_again(&run(Vec::new(), vec!["FABRIKAM.COM"])).as_deref(),
            Some("pathwarden collect -d contoso.local --trusted -o DIR")
        );
        assert_eq!(collect_again(&run(Vec::new(), vec![])), None);
    }
}
