//! Explore from the terminal: `pathwarden reach` (who can reach an
//! object), `pathwarden search` and `pathwarden zones suggest`. The answers
//! are the Explore page's own ([`pathwarden_core::explore::answers`]), on the
//! same graph a saved run keeps ([`pathwarden_core::explore::build`]; search
//! needs only names and flags, so it reads them from the data's graph), so
//! the objects, their order and the words match the app; `--json` prints the
//! document the app's API returns. Without `-i`, `reach` and `search` read
//! a run saved in the app's workspace (`--run`, or `--env`'s latest), as its
//! Explore page does ([`pathwarden_ui::explore_ui::read_run`]).

use std::sync::Arc;

use anstream::println;
use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use pathwarden_core::explore::answers::{self, Explorer, NodeOut, REACH_CLASSES};
use pathwarden_core::explore::{self, ExploreGraph};
use pathwarden_core::model::NodeKind;
use pathwarden_core::text::{count, num};
use pathwarden_core::AdGraph;

use crate::progress::{self, Through};
use crate::{emit_json, ui, Input};

/// [`REACH_CLASSES`], for `--class`.
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum ReachClass {
    /// Unprivileged users and computers: where an attacker starts
    Unprivileged,
    /// Groups and other objects
    Other,
    /// Disabled or not collected
    Disabled,
    /// Tier Zero
    TierZero,
}

impl ReachClass {
    fn index(self) -> u8 {
        match self {
            ReachClass::Unprivileged => 0,
            ReachClass::Other => 1,
            ReachClass::Disabled => 2,
            ReachClass::TierZero => 3,
        }
    }
}

/// The data's explore graph, as a saved run's.
fn graph(
    g: &pathwarden_core::AdGraph,
    zones: &[pathwarden_core::zones::Zone],
) -> Result<ExploreGraph> {
    explore::build(g, &[], zones).map_err(anyhow::Error::msg)
}

/// An object as lists show it: `NAME (Kind)`, with its tags.
fn object(n: &NodeOut) -> String {
    let mut s = format!("{} ({})", ui::safe(n.name), n.kind);
    for (on, tag) in [
        (n.t0, "Tier Zero"),
        (n.dc, "DC"),
        (n.disabled, "disabled"),
        (n.ph, "not collected"),
        (n.zone, "in a zone"),
    ] {
        if on {
            s.push_str(&format!(" [{tag}]"));
        }
    }
    s
}

/// Which saved run answered.
pub(crate) struct Saved {
    /// The run's history ID, as the run list and `run --save` show it.
    run: String,
    /// Unix time the run was analyzed.
    at: i64,
    /// `--env` chose the run (no `--run`): the answer says which one.
    chosen: bool,
    /// The run's folder.
    pub(crate) dir: std::path::PathBuf,
    /// Its environment's folder (owned marks are kept there).
    pub(crate) env_dir: std::path::PathBuf,
}

impl Saved {
    /// `ID (Oct 9, 2026, 9:29 PM)`, in this computer's time.
    pub(crate) fn label(&self) -> String {
        format!(
            "{} ({})",
            ui::safe(&self.run),
            pathwarden_core::time::format_local(self.at)
        )
    }

    /// The run `--env` chose, in a line on stderr, so text output stays
    /// the answer alone.
    pub(crate) fn say(&self) {
        if self.chosen {
            let d = ui::DIM;
            anstream::eprintln!("{d}From run {}.{d:#}", self.label());
        }
    }

    /// `{id, at}`: the run, for `--json`.
    pub(crate) fn run_value(&self) -> serde_json::Value {
        serde_json::json!({ "id": self.run, "at": self.at })
    }

    /// `--json`: the answer with a `run` field ({id, at}) beside it.
    pub(crate) fn json(&self, answer: serde_json::Value) -> serde_json::Value {
        let mut v = answer;
        if let Some(o) = v.as_object_mut() {
            o.insert(
                "run".into(),
                serde_json::json!({ "id": self.run, "at": self.at }),
            );
        }
        v
    }
}

/// The run saved in the app's workspace that `reach` and `search` read
/// without `-i`: `run` (its history ID or folder ID), or the latest run of
/// `--env` that can be explored. When the latest can't be (saved before
/// runs kept their graph, the graph is gone, or loaded from the history
/// without its object index), an older run answers and a warning says
/// which and why. Its object index and graph, as the Explore page
/// reads them.
pub(crate) fn saved_run(
    input: &Input,
    run: Option<&str>,
) -> Result<(Arc<AdGraph>, ExploreGraph, Saved)> {
    use pathwarden_ui::environments;
    use pathwarden_ui::explore_ui;
    use pathwarden_ui::workspace::{self, Workspace};

    if run.is_none() && input.env.env.is_none() {
        bail!("Give a collection (-i), or a saved run: --run ID or --env NAME.");
    }
    // A saved run answers with the settings it was analyzed with.
    if input.config.is_some() || !input.tier_zero.is_empty() {
        bail!(
            "-c and --tier-zero go with -i: a saved run keeps the settings it was analyzed with."
        );
    }
    let root = match &input.env.env_workspace {
        Some(d) => d.clone(),
        None => workspace::default_dir()?,
    };
    let ws = Workspace::existing(&root)?;
    let reg = ws.named_registry();
    let env = match &input.env.env {
        Some(name) => Some(
            reg.find(name)
                .with_context(|| {
                    format!(
                        "no environment named {:?} (there is: {})",
                        ui::safe(name),
                        environments::names_list(&reg, ws.root(), &ws.all_runs())
                    )
                })?
                .id
                .clone(),
        ),
        None => None,
    };
    let (summary, dir, env_dir) = match run {
        Some(id) => {
            let folder = ws
                .run_dir(id)
                .map(|_| id.to_string())
                .or_else(|| ws.find_run(id))
                .with_context(|| {
                    format!(
                        "no saved run {}: use the ID the run list or `pathwarden run --save` shows",
                        ui::safe(id)
                    )
                })?;
            let summary = ws.run(&folder).context("that run can't be read")?;
            if env
                .as_deref()
                .is_some_and(|e| e != ws.for_run(&summary).env_id())
            {
                bail!("Run {} isn't in that environment.", ui::safe(id));
            }
            let dir = ws.run_dir(&folder).context("that run can't be read")?;
            let env_dir = ws.for_run(&summary).env_dir();
            (summary, dir, env_dir)
        }
        None => {
            // Checked above: --env was given.
            let env = env.unwrap_or_else(|| environments::DEFAULT_ENV.to_string());
            let in_env = ws.in_env(&env);
            let runs = in_env.runs();
            let found = runs.iter().enumerate().find_map(|(i, r)| {
                let d = in_env.run_dir(&r.id)?;
                explore_ui::available(&d).then_some((i, d))
            });
            let Some((i, dir)) = found else {
                bail!(
                    "{} has no saved run that can be explored (save one with `pathwarden run --save`)",
                    ui::safe(&reg.name_of(&env))
                );
            };
            if i > 0 {
                let warn = ui::severity(pathwarden_core::findings::Severity::Medium);
                // As the Explore page's line says it.
                let why = in_env
                    .run_dir(&runs[0].id)
                    .and_then(|d| explore_ui::missing(&d))
                    .map_or(explore_ui::Missing::Old.reason(), |m| m.reason());
                anstream::eprintln!(
                    "{warn}Warning:{warn:#} The latest run of {}, {}, can't be explored ({why}): \
                     an older run answers. --run ID picks a run.",
                    ui::safe(&reg.name_of(&env)),
                    ui::safe(&runs[0].run_id())
                );
            }
            (runs[i].clone(), dir, in_env.env_dir())
        }
    };
    let (g, x) = explore_ui::read_run(&dir).map_err(anyhow::Error::msg)?;
    let saved = Saved {
        run: summary.run_id(),
        at: summary.created_at,
        chosen: run.is_none(),
        dir,
        env_dir,
    };
    Ok((g, x, saved))
}

/// `pathwarden path` on a saved run: the shortest attack path from `src`
/// to `dst` (or to Tier Zero) on its explore graph, as the Explore page's
/// Path between finds it, and the line said when the only path goes
/// through Tier Zero.
pub(crate) fn saved_path(
    g: &AdGraph,
    x: &ExploreGraph,
    src: pathwarden_core::NodeIndex,
    dst: Option<pathwarden_core::NodeIndex>,
) -> (
    Option<pathwarden_core::analysis::AttackPath>,
    Option<String>,
) {
    use pathwarden_core::analysis::{self, AttackPath, PathStep};
    use pathwarden_core::NodeIndex;
    let from = src.index() as u32;
    let mut through = None;
    let edges = match dst {
        None => x.tier_zero_tree().path(from),
        Some(dst) => {
            let to = dst.index() as u32;
            x.shortest_path(from, &[to]).or_else(|| {
                let p = x.path_through_tier_zero(from, to)?;
                through = Some(analysis::through_tier_zero_line(&g.node(dst).name));
                Some(p)
            })
        }
    };
    let node = |v: u32| g.node(NodeIndex::new(v as usize));
    let path = edges.map(|edges| {
        let steps: Vec<PathStep> = edges
            .iter()
            .map(|e| PathStep {
                from: node(e.from).name.clone(),
                from_kind: node(e.from).kind,
                edge: e.kind,
                to: node(e.to).name.clone(),
                to_kind: node(e.to).kind,
                source: None,
                backward: false,
            })
            .collect();
        AttackPath {
            source: g.node(src).name.clone(),
            target: steps
                .last()
                .map_or_else(|| g.node(src).name.clone(), |s| s.to.clone()),
            steps,
            edges: Vec::new(),
        }
    });
    (path, through)
}

/// `pathwarden reach OBJECT`: who can reach it, earliest in the chain first.
pub(crate) fn reach(
    input: &Input,
    run: Option<&str>,
    query: &str,
    class: Option<ReachClass>,
    top: usize,
) -> Result<()> {
    let (g, x, saved) = if input.input.is_empty() {
        let (g, x, s) = saved_run(input, run)?;
        (g, x, Some(s))
    } else {
        let (g, _, config) = crate::open(input)?;
        let zones = crate::resolve_zones(&g, &config);
        let x = graph(&g, &zones)?;
        (Arc::new(g), x, None)
    };
    let target = crate::resolve(&g, query, g.find(query))?;
    let ex = Explorer::new(&g, &x);
    let v = target.index() as u32;
    let list = ex.reach_list(v);
    let page = ex.reach_page(v, &list, class.map(ReachClass::index), 0, top);
    if input.json {
        return match &saved {
            Some(s) => emit_json(&s.json(serde_json::to_value(&page)?)),
            None => emit_json(&page),
        };
    }
    if let Some(s) = &saved {
        s.say();
    }
    let (b, d) = (ui::BOLD, ui::DIM);
    println!("{b}Who can reach {}{b:#}", object(&page.target));
    println!("{}", page.summary);
    let mut last = None;
    for r in &page.items {
        if last != Some(r.class) {
            last = Some(r.class);
            println!(
                "\n{b}{} · {}{b:#}",
                REACH_CLASSES[r.class as usize],
                num(page.classes[r.class as usize])
            );
        }
        println!(
            "  {}  {d}{} · first {}{} → {}{d:#}",
            object(&r.node),
            count(r.hops as usize, "hop", "hops"),
            r.first.k,
            if r.first.inh { " (inherited)" } else { "" },
            ui::safe(r.via.name),
        );
    }
    if page.items.len() < page.filtered {
        println!(
            "\nShowing {} of {}. --top N shows more; --class picks one group.",
            num(page.items.len()),
            num(page.filtered)
        );
    }
    if page.total > 0 {
        println!(
            "`pathwarden path --from NAME --to \"{}\"` shows one attack path in full.",
            ui::safe(&g.node(target).name)
        );
    }
    Ok(())
}

/// `pathwarden search TEXT`: objects by name, distinguished name or ID.
pub(crate) fn search(
    input: &Input,
    run: Option<&str>,
    text: &str,
    kinds: &[String],
    top: usize,
) -> Result<()> {
    let kinds: Vec<NodeKind> = kinds
        .iter()
        .map(|k| match NodeKind::from_object_type(k.trim()) {
            NodeKind::Base if !k.trim().eq_ignore_ascii_case("Base") => {
                bail!(
                    "Unknown object kind '{}' (e.g. User, Computer, Group, OU, GPO).",
                    ui::safe(k)
                )
            }
            kind => Ok(kind),
        })
        .collect::<Result<_>>()?;
    let query: String = text.chars().take(200).collect();
    // A saved run: the page's own search. The data: names and flags only,
    // no explore graph to build.
    let loaded;
    let mut saved = None;
    let data;
    let hits = if input.input.is_empty() {
        loaded = saved_run(input, run)?;
        saved = Some(&loaded.2);
        Explorer::new(&loaded.0, &loaded.1).search(&query, &kinds, top)
    } else {
        let (g, _, config) = crate::open(input)?;
        data = g;
        let zones = crate::resolve_zones(&data, &config);
        answers::search_graph(&data, &zones, &query, &kinds, top)
    };
    if input.json {
        let answer = serde_json::json!({ "results": hits });
        return match &saved {
            Some(s) => emit_json(&s.json(answer)),
            None => emit_json(&answer),
        };
    }
    if let Some(s) = &saved {
        s.say();
    }
    if hits.is_empty() {
        println!("No object matches '{}'.", ui::safe(text));
        return Ok(());
    }
    for n in &hits {
        let d = ui::DIM;
        println!("{}  {d}{}{d:#}", object(n), ui::safe(n.id));
    }
    if hits.len() == top {
        println!("\nThe first {}: --top N shows more.", num(top));
    }
    Ok(())
}

/// `pathwarden zones suggest`: the Explore page's Suggested zones tab, on
/// the data (`-i`) or a saved run (`--run`, `--env`).
pub(crate) fn zones_suggest(input: Input, run: Option<&str>) -> Result<()> {
    let (g, x, headline, saved) = if input.input.is_empty() {
        let (g, x, s) = saved_run(&input, run)?;
        // The headline counts the run's summary records, as the page does.
        let headline = pathwarden_ui::workspace::summary_file(&s.dir)
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| {
                serde_json::from_str::<pathwarden_ui::workspace::RunSummary>(
                    t.trim_start_matches('\u{feff}'),
                )
                .ok()
            })
            .map(|r| (r.exposed, r.relevant_pop()));
        (g, x, headline, Some(s))
    } else {
        let mut p = progress::Analysis::new(Through::Rules, input.verbose);
        let ev = crate::run_rules(&input, &mut p)?;
        let posture = ev.posture();
        p.done();
        let x = explore::build(&ev.graph, &ev.findings, &ev.zones).map_err(anyhow::Error::msg)?;
        let t0 = &posture.tier_zero;
        let headline = Some((t0.exposed, t0.relevant_population));
        (Arc::new(ev.graph), x, headline, None)
    };
    let answer = Explorer::new(&g, &x).suggestions(&x.tier_zero_tree(), headline);
    if input.json {
        return match &saved {
            Some(s) => emit_json(&s.json(serde_json::to_value(&answer)?)),
            None => emit_json(&answer),
        };
    }
    if let Some(s) = &saved {
        s.say();
    }
    let (b, d) = (ui::BOLD, ui::DIM);
    println!("{b}Suggested zones{b:#}");
    for l in crate::help::wrap(&answer.intro, crate::help::WIDTH) {
        println!("{l}");
    }
    for h in &answer.heuristics {
        let items: Vec<_> = answer
            .items
            .iter()
            .filter(|s| s.heuristic == h.key)
            .collect();
        println!("\n{b}{} · {}{b:#}", h.title, num(items.len()));
        for l in crate::help::wrap(h.about, crate::help::WIDTH) {
            println!("{d}{l}{d:#}");
        }
        if items.is_empty() {
            println!("None.");
        }
        for s in items {
            let mut tags = format!("Tier {}", s.tier);
            for z in &s.zones {
                tags.push_str(&format!(", zone {}", ui::safe(z)));
            }
            println!("  {}  [{tags}]", object(&s.node));
            for l in crate::help::wrap(&s.reason, crate::help::WIDTH - 4) {
                println!("    {}", ui::safe(&l));
            }
        }
    }
    println!(
        "\nTo make one, add them to a [[zone]] in pathwarden.toml (docs/privilege-zones.md), or tick them in the app (Explore, Suggested zones)."
    );
    Ok(())
}
