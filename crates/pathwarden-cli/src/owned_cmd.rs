//! `pathwarden owned`: the objects marked as owned in an environment,
//! which Cypher queries on its runs see as `Tag_Owned`. The same
//! marks, in the same file, as the app's Explore page sets with "Mark as
//! owned" on the Object tab ([`pathwarden_core::owned`]).

use std::path::PathBuf;

use anstream::println;
use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use pathwarden_core::owned;
use pathwarden_core::AdGraph;

use crate::ui;

/// The environment whose marks to use.
#[derive(Args)]
pub(crate) struct At {
    /// The environment (its name or ID) (default: the environment the app
    /// opens in).
    #[arg(long, value_name = "NAME")]
    env: Option<String>,
    /// The app's workspace (default: the one `pathwarden ui` uses).
    #[arg(long, value_name = "DIR")]
    workspace: Option<PathBuf>,
}

#[derive(Subcommand)]
pub(crate) enum OwnedAction {
    /// List the objects marked as owned.
    List {
        #[command(flatten)]
        at: At,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Mark objects as owned.
    Add {
        #[command(flatten)]
        at: At,
        /// The objects to mark (name, short name, or object ID).
        #[arg(required = true, value_name = "OBJECT")]
        objects: Vec<String>,
    },
    /// Mark objects as not owned.
    Remove {
        #[command(flatten)]
        at: At,
        /// The objects to unmark (name, short name, or object ID).
        #[arg(required = true, value_name = "OBJECT")]
        objects: Vec<String>,
    },
}

struct Env {
    dir: PathBuf,
    name: String,
    /// The environment's latest run's objects, for names.
    graph: Option<std::sync::Arc<AdGraph>>,
}

fn env(at: &At) -> Result<Env> {
    let ws = pathwarden_ui::environments::cli_workspace_or_current(
        at.workspace.as_deref(),
        at.env.as_deref(),
    )?;
    let graph = pathwarden_ui::run_data::latest_with(&ws, pathwarden_ui::run_data::OBJECTS_FILE)
        .and_then(|(_, dir)| pathwarden_ui::run_data::graph(&dir));
    Ok(Env {
        dir: ws.env_dir(),
        name: ws.env_name(),
        graph,
    })
}

/// `NAME (Kind)` from the latest run, or the ID when it has no such object.
fn label(e: &Env, id: &str) -> String {
    match e
        .graph
        .as_ref()
        .and_then(|g| g.lookup(id).map(|ix| g.node(ix)))
    {
        Some(n) => format!("{} ({})", ui::safe(&n.name), n.kind.as_str()),
        None => ui::safe(id).into_owned(),
    }
}

/// The object IDs `objects` name, by the latest run's objects (an ID is
/// taken as given when there is no run to check it against).
fn ids(e: &Env, objects: &[String]) -> Result<Vec<String>> {
    let Some(g) = &e.graph else {
        anstream::eprintln!(
            "Note: {} has no analysis to check the names against, so they are kept as given.",
            ui::safe(&e.name)
        );
        return Ok(objects
            .iter()
            .map(|o| o.trim().to_ascii_uppercase())
            .collect());
    };
    objects
        .iter()
        .map(|o| {
            let ix = crate::resolve(g, o, g.find_principal(o))?;
            Ok(g.node(ix).id.clone())
        })
        .collect()
}

pub(crate) fn run(action: OwnedAction) -> Result<()> {
    match action {
        OwnedAction::List { at, json } => {
            let e = env(&at)?;
            let kept = owned::load(&e.dir).map_err(anyhow::Error::msg)?;
            if json {
                return crate::emit_json(&kept);
            }
            println!("{}", owned::summary(kept.len()));
            for id in &kept {
                println!("  {}  {}", label(&e, id), ui::safe(id));
            }
            Ok(())
        }
        OwnedAction::Add { at, objects } => {
            let e = env(&at)?;
            let ids = ids(&e, &objects)?;
            let n = owned::set(&e.dir, &ids, true).map_err(anyhow::Error::msg)?;
            for id in &ids {
                println!("Marked as owned: {}.", label(&e, id));
            }
            println!("{}", owned::summary(n));
            Ok(())
        }
        OwnedAction::Remove { at, objects } => {
            let e = env(&at)?;
            let kept = owned::load(&e.dir).map_err(anyhow::Error::msg)?;
            // An ID kept from an older run may name nothing now.
            let ids: Vec<String> = match ids(&e, &objects) {
                Ok(ids) => ids,
                Err(_)
                    if objects
                        .iter()
                        .all(|o| kept.iter().any(|k| k.eq_ignore_ascii_case(o.trim()))) =>
                {
                    objects
                        .iter()
                        .map(|o| o.trim().to_ascii_uppercase())
                        .collect()
                }
                Err(err) => return Err(err),
            };
            if let Some(id) = ids.iter().find(|id| !kept.contains(id)) {
                bail!("{} isn't marked as owned.", label(&e, id));
            }
            let n = owned::set(&e.dir, &ids, false).map_err(anyhow::Error::msg)?;
            for id in &ids {
                println!("Not owned: {}.", label(&e, id));
            }
            println!("{}", owned::summary(n));
            Ok(())
        }
    }
}
