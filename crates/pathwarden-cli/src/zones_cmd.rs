//! `pathwarden zones`: the Privilege Zones page from the terminal.
//! Edits go through the app's own code (`ConfigDoc::upsert_zone` and
//! `remove_zone`, saved by `pathwarden_ui::settings::apply`), so a zone is
//! checked, refused and written exactly as the wizard saves it; `preview`
//! is the wizard's live preview (`pathwarden_core::zones::preview`, with
//! its warnings), on the data given with `-i`. `suggest` is Explore's
//! (`explore_cmd`).

use anstream::println;
use anyhow::{bail, Result};
use clap::Subcommand;
use pathwarden_core::config_edit::{zone_name_problem, ZoneEdit};
use pathwarden_core::text::{count, num};
use pathwarden_core::zones::{self, ZoneConfig, ZonePreview};

use crate::config_cmd::{self, Target, WhereLocal};
use crate::{emit_json, ui, Input};

#[derive(Subcommand)]
pub(crate) enum ZonesAction {
    /// List the zones.
    List {
        #[command(flatten)]
        at: WhereLocal,
        /// Print JSON instead of text.
        #[arg(long, display_order = 903)]
        json: bool,
    },
    /// What a zone is made of: its groups, OUs and objects.
    Show {
        /// The zone's name.
        name: String,
        #[command(flatten)]
        at: WhereLocal,
        /// Print JSON instead of text.
        #[arg(long, display_order = 903)]
        json: bool,
    },
    /// Add a zone: objects one by one, groups (with everyone nested in them)
    /// and OUs (with everything below them).
    Add {
        /// The zone's name, as reports and `--zone` show it.
        name: String,
        /// An object (ID, NAME@DOMAIN or distinguished name); repeatable.
        #[arg(long = "member", value_name = "OBJECT")]
        members: Vec<String>,
        /// A group, with everyone nested in it; repeatable.
        #[arg(long = "group", value_name = "GROUP")]
        groups: Vec<String>,
        /// An OU, with everything below it and the GPOs linked to it;
        /// repeatable.
        #[arg(long = "ou", value_name = "OU")]
        ous: Vec<String>,
        #[command(flatten)]
        at: WhereLocal,
    },
    /// Change a zone: rename it, add or remove entries.
    Edit {
        /// The zone's name.
        name: String,
        /// A new name.
        #[arg(long, value_name = "NAME")]
        rename: Option<String>,
        /// Add an object; repeatable.
        #[arg(long, value_name = "OBJECT")]
        add_member: Vec<String>,
        /// Remove an object; repeatable.
        #[arg(long, value_name = "OBJECT")]
        remove_member: Vec<String>,
        /// Add a group; repeatable.
        #[arg(long, value_name = "GROUP")]
        add_group: Vec<String>,
        /// Remove a group; repeatable.
        #[arg(long, value_name = "GROUP")]
        remove_group: Vec<String>,
        /// Add an OU; repeatable.
        #[arg(long, value_name = "OU")]
        add_ou: Vec<String>,
        /// Remove an OU; repeatable.
        #[arg(long, value_name = "OU")]
        remove_ou: Vec<String>,
        #[command(flatten)]
        at: WhereLocal,
    },
    /// Remove a zone.
    Remove {
        /// The zone's name.
        name: String,
        #[command(flatten)]
        at: WhereLocal,
    },
    /// What a zone resolves to in the data: objects per kind, a sample, and
    /// entries that match nothing (the wizard's live preview). The zone
    /// comes from -c or --env, else the environment the app opens in (of
    /// --workspace, or the app's own). Without -i, a saved run's objects:
    /// --run ID, or the latest run of --env NAME, with that environment's
    /// zone.
    #[command(mut_arg("input", |a| a.required(false)))]
    Preview {
        /// The zone's name, before -i (which takes every value after it),
        /// or as --zone NAME.
        name: Option<String>,
        /// The zone's name, anywhere on the line.
        #[arg(long = "zone", value_name = "NAME", conflicts_with = "name")]
        zone: Option<String>,
        #[command(flatten)]
        input: Input,
        /// A run saved in the workspace (its ID as the run list or `pathwarden
        /// run` shows it) instead of -i.
        #[arg(long, value_name = "RUN", conflicts_with_all = ["input", "config", "tier_zero"])]
        run: Option<String>,
    },
    /// Objects outside Tier Zero worth putting in a Tier 1 or Tier 2 zone:
    /// objects many attack paths go through, control over many objects,
    /// privileged logons.
    #[command(
        mut_arg("input", |a| a.required(false)),
        after_help = "Without -i it answers from a run saved in the app's workspace, as its Explore \
page's Suggested zones does: --run ID, or the latest run of --env NAME (--workspace DIR for \
another workspace)."
    )]
    Suggest {
        #[command(flatten)]
        input: Input,
        /// A run saved in the workspace (its ID as the run list or `pathwarden
        /// run` shows it) instead of -i.
        #[arg(long, value_name = "RUN", conflicts_with_all = ["input", "config", "tier_zero"])]
        run: Option<String>,
    },
}

/// The zone named `name` (any case) and its place in the file.
fn find<'a>(zones: &'a [ZoneConfig], name: &str, t: &Target) -> Result<(usize, &'a ZoneConfig)> {
    match matching(zones, name)? {
        Some(found) => Ok(found),
        None => bail!(
            "No zone named '{}' in {} (there is: {}; see `pathwarden zones list`).",
            ui::safe(name),
            t.label,
            if zones.is_empty() {
                "none".to_string()
            } else {
                zones
                    .iter()
                    .map(|z| ui::safe(&z.name).into_owned())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ),
    }
}

/// The one zone named `name`. A file that loads can't hold two (config
/// validation uses the same `zones::same_name`), but a command never
/// guesses between them.
fn matching<'a>(zones: &'a [ZoneConfig], name: &str) -> Result<Option<(usize, &'a ZoneConfig)>> {
    let mut found = zones
        .iter()
        .enumerate()
        .filter(|(_, z)| zones::same_name(&z.name, name));
    let first = found.next();
    let others = found.count();
    if others > 0 {
        bail!(
            "{} zones are named '{}'. Rename one in the file first.",
            others + 1,
            ui::safe(name.trim())
        );
    }
    Ok(first)
}

/// Entries as a save keeps them: trimmed, without empties or duplicates
/// (any case), in order.
fn entries(list: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in list {
        let e = e.trim().to_ascii_uppercase();
        if !e.is_empty() && !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

/// "2 groups · 1 OU · 3 objects", as the Privilege Zones list says it.
fn made_of(z: &ZoneConfig) -> String {
    let mut parts = Vec::new();
    if !z.groups.is_empty() {
        parts.push(count(z.groups.len(), "group", "groups"));
    }
    if !z.ous.is_empty() {
        parts.push(count(z.ous.len(), "OU", "OUs"));
    }
    if !z.members.is_empty() {
        parts.push(count(z.members.len(), "named object", "named objects"));
    }
    parts.join(" · ")
}

fn zone_json(z: &ZoneConfig) -> serde_json::Value {
    serde_json::json!({
        "name": z.name,
        "members": z.members,
        "groups": z.groups,
        "ous": z.ous,
    })
}

pub(crate) fn run(action: ZonesAction) -> Result<()> {
    match action {
        ZonesAction::Suggest { input, run } => {
            crate::explore_cmd::zones_suggest(input, run.as_deref())
        }
        ZonesAction::Preview {
            name,
            zone,
            input,
            run,
        } => {
            let Some(name) = name.or(zone) else {
                bail!("Name the zone: `pathwarden zones preview NAME -i DATA` (or --run ID), or --zone NAME. A name given after -i is read as another input.");
            };
            preview(&name, input, run.as_deref())
        }
        ZonesAction::List { at, json } => {
            let t = config_cmd::target(&at.into())?;
            let config = config_cmd::load(&t.path)?;
            if json {
                let list: Vec<serde_json::Value> = (0..config.zones.len())
                    .map(|i| {
                        let mut j = zone_json(&config.zones[i]);
                        j["name_problem"] = zone_name_problem(&config.zones, i).into();
                        j
                    })
                    .collect();
                return emit_json(&list);
            }
            if config.zones.is_empty() {
                println!(
                    "No zones in {}. Tier Zero is always protected; `pathwarden zones add` adds the next most important systems.",
                    t.label
                );
                return Ok(());
            }
            println!("Privilege Zones in {}:", t.label);
            for (i, z) in config.zones.iter().enumerate() {
                println!("  {}  {}", ui::safe(&z.name), made_of(z));
                if let Some(problem) = zone_name_problem(&config.zones, i) {
                    println!("    ! {}", ui::safe(&problem));
                }
            }
            Ok(())
        }
        ZonesAction::Show { name, at, json } => {
            let t = config_cmd::target(&at.into())?;
            let config = config_cmd::load(&t.path)?;
            let (index, z) = find(&config.zones, &name, &t)?;
            if json {
                let mut j = zone_json(z);
                j["name_problem"] = zone_name_problem(&config.zones, index).into();
                return emit_json(&j);
            }
            let b = ui::BOLD;
            println!("{b}{}{b:#}  {}", ui::safe(&z.name), made_of(z));
            for (title, list) in [
                ("Groups, with everyone in them", &z.groups),
                ("OUs, with everything below them", &z.ous),
                ("Objects", &z.members),
            ] {
                if list.is_empty() {
                    continue;
                }
                println!("\n{title}:");
                for e in list {
                    println!("  {}", ui::safe(e));
                }
            }
            Ok(())
        }
        ZonesAction::Add {
            name,
            members,
            groups,
            ous,
            at,
        } => {
            let t = config_cmd::target(&at.into())?;
            let edit = ZoneEdit {
                name,
                members,
                groups,
                ous,
            };
            config_cmd::save(&t, |d| d.upsert_zone(None, None, &edit))?;
            println!(
                "Saved: zone {} in {}. The next analysis uses it.",
                ui::safe(edit.name.trim()),
                t.label
            );
            check_latest(&t, &edit);
            Ok(())
        }
        ZonesAction::Edit {
            name,
            rename,
            add_member,
            remove_member,
            add_group,
            remove_group,
            add_ou,
            remove_ou,
            at,
        } => {
            if rename.is_none()
                && [
                    &add_member,
                    &remove_member,
                    &add_group,
                    &remove_group,
                    &add_ou,
                    &remove_ou,
                ]
                .iter()
                .all(|l| l.is_empty())
            {
                bail!("Nothing to change: give --rename, --add-* or --remove-*.");
            }
            let t = config_cmd::target(&at.into())?;
            let config = config_cmd::load(&t.path)?;
            let (index, z) = find(&config.zones, &name, &t)?;
            let change = |list: &[String], add: &[String], remove: &[String], what: &str| {
                let missing: Vec<&String> = remove
                    .iter()
                    .filter(|r| !list.iter().any(|e| e.trim().eq_ignore_ascii_case(r.trim())))
                    .collect();
                if !missing.is_empty() {
                    bail!(
                        "Not {what} of zone {}: {} (see `pathwarden zones show`).",
                        ui::safe(&z.name),
                        missing
                            .iter()
                            .map(|s| ui::safe(s))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                let mut out: Vec<String> = list
                    .iter()
                    .filter(|e| {
                        !remove
                            .iter()
                            .any(|r| e.trim().eq_ignore_ascii_case(r.trim()))
                    })
                    .cloned()
                    .collect();
                out.extend(add.iter().cloned());
                Ok(out)
            };
            let edit = ZoneEdit {
                name: rename.unwrap_or_else(|| z.name.clone()),
                members: change(&z.members, &add_member, &remove_member, "an object")?,
                groups: change(&z.groups, &add_group, &remove_group, "a group")?,
                ous: change(&z.ous, &add_ou, &remove_ou, "an OU")?,
            };
            if edit.name.trim() == z.name.trim()
                && entries(&edit.members) == entries(&z.members)
                && entries(&edit.groups) == entries(&z.groups)
                && entries(&edit.ous) == entries(&z.ous)
            {
                println!(
                    "Nothing to change: zone {} already reads that way.",
                    ui::safe(z.name.trim())
                );
                return Ok(());
            }
            let expect = z.name.clone();
            // The same change applied to the zone as it is when the save
            // holds the lock, so members added meanwhile stay.
            let (add, rem) = (
                [&add_member, &add_group, &add_ou],
                [&remove_member, &remove_group, &remove_ou],
            );
            let rename = edit.name.clone();
            config_cmd::save(&t, |d| {
                let current = d.validate()?;
                let z = current
                    .zones
                    .get(index)
                    .filter(|z| z.name.trim().eq_ignore_ascii_case(expect.trim()))
                    .ok_or(pathwarden_core::config_edit::CHANGED)?;
                let apply = |list: &[String], add: &[String], remove: &[String]| {
                    let mut out: Vec<String> = list
                        .iter()
                        .filter(|e| {
                            !remove
                                .iter()
                                .any(|r| e.trim().eq_ignore_ascii_case(r.trim()))
                        })
                        .cloned()
                        .collect();
                    for a in add {
                        if !out.iter().any(|e| e.trim().eq_ignore_ascii_case(a.trim())) {
                            out.push(a.clone());
                        }
                    }
                    out
                };
                let now = ZoneEdit {
                    name: rename,
                    members: apply(&z.members, add[0], rem[0]),
                    groups: apply(&z.groups, add[1], rem[1]),
                    ous: apply(&z.ous, add[2], rem[2]),
                };
                d.upsert_zone(Some(index), Some(&expect), &now)
            })?;
            println!(
                "Saved: zone {} in {}. The next analysis uses it.",
                ui::safe(edit.name.trim()),
                t.label
            );
            check_latest(&t, &edit);
            Ok(())
        }
        ZonesAction::Remove { name, at } => {
            let t = config_cmd::target(&at.into())?;
            let config = config_cmd::load(&t.path)?;
            let (index, z) = find(&config.zones, &name, &t)?;
            let expect = z.name.clone();
            config_cmd::save(&t, |d| d.remove_zone(index, &expect))?;
            println!(
                "Removed zone {} from {}. Earlier reports keep it.",
                ui::safe(&expect),
                t.label
            );
            Ok(())
        }
    }
}

/// After a save, what the zone resolves to in the environment's latest
/// analysis, when there is one, as the wizard's preview would say it.
fn check_latest(t: &Target, edit: &ZoneEdit) {
    let Some(ws) = &t.ws else { return };
    let Some((run, dir)) =
        pathwarden_ui::run_data::latest_with(ws, pathwarden_ui::run_data::OBJECTS_FILE)
    else {
        return;
    };
    let Some(g) = pathwarden_ui::run_data::graph(&dir) else {
        return;
    };
    let config = ZoneConfig {
        name: edit.name.trim().to_string(),
        members: edit.members.clone(),
        groups: edit.groups.clone(),
        ous: edit.ous.clone(),
        ..Default::default()
    };
    let p = zones::preview(&g, &config, zones::PREVIEW_SAMPLE);
    println!(
        "In {}, the latest analysis: {}.",
        ui::safe(&run.environment()),
        count(p.total, "object in the zone", "objects in the zone")
    );
    for w in p.warnings("the latest analysis") {
        eprintln!("Note: {}", ui::safe(&w));
    }
}

/// `zones preview NAME -i DATA`.
fn preview(name: &str, mut input: Input, run: Option<&str>) -> Result<()> {
    // Without -i: a saved run's objects, as the zone wizard's live preview
    // reads the latest run's, and the zone from that run's environment.
    if input.input.is_empty() {
        let (g, _, saved) = crate::explore_cmd::saved_run(&input, run)?;
        let path = saved.env_dir.join(pathwarden_ui::workspace::CONFIG_FILE);
        let config = if path.is_file() {
            pathwarden_core::config::Config::from_file(&path).map_err(anyhow::Error::msg)?
        } else {
            pathwarden_core::config::Config::default()
        };
        let Some((_, z)) = matching(&config.zones, name)? else {
            bail!(
                "No zone named '{}' in the settings of that run's environment (there is: {}).",
                ui::safe(name),
                zone_names(&config.zones)
            );
        };
        let p = zones::preview(&g, z, zones::PREVIEW_SAMPLE);
        if input.json {
            return emit_json(&saved.json(serde_json::json!({
                "zone": z.name,
                "preview": p,
                "warnings": p.warnings("the run"),
            })));
        }
        saved.say();
        print_preview(&z.name, &p);
        return Ok(());
    }
    // -c / --env as for every analysis command (already applied); with
    // neither, the zone comes from the current environment of --workspace
    // (else of the app's workspace), as the other `zones` commands' do.
    if input.config.is_none() {
        let ws = pathwarden_ui::environments::cli_workspace_or_current(
            input.env.env_workspace.as_deref(),
            None,
        )
        .map_err(|e| {
            anyhow::anyhow!("{e:#}. Give the zone's settings with -c FILE or --env NAME")
        })?;
        if !ws.config_path().is_file() {
            bail!(
                "No zone named '{}': environment {} (the one the app opens in) has no settings yet. Give the zone's settings with -c FILE or --env NAME.",
                ui::safe(name),
                ui::safe(&ws.env_name())
            );
        }
        input.config = Some(ws.config_path());
    }
    let (g, _, config) = crate::open(&input)?;
    let Some((_, z)) = matching(&config.zones, name)? else {
        bail!(
            "No zone named '{}' in the settings (there is: {}).",
            ui::safe(name),
            zone_names(&config.zones)
        );
    };
    let p = zones::preview(&g, z, zones::PREVIEW_SAMPLE);
    if input.json {
        return emit_json(&serde_json::json!({
            "zone": z.name,
            "preview": p,
            "warnings": p.warnings("the data"),
        }));
    }
    print_preview(&z.name, &p);
    Ok(())
}

/// The zones' names for a "there is: …" list, or "none".
fn zone_names(zones: &[ZoneConfig]) -> String {
    if zones.is_empty() {
        return "none".to_string();
    }
    zones
        .iter()
        .map(|z| ui::safe(&z.name).into_owned())
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_preview(name: &str, p: &ZonePreview) {
    let (b, d) = (ui::BOLD, ui::DIM);
    println!(
        "{b}{}{b:#}: {}",
        ui::safe(name),
        count(p.total, "object in the zone", "objects in the zone")
    );
    println!("{d}Tier Zero objects are never counted.{d:#}");
    if !p.kinds.is_empty() {
        let width = p.kinds.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        println!();
        for (k, n) in &p.kinds {
            println!("  {k:<width$}  {:>8}", num(*n));
        }
    }
    let warnings = p.warnings("the data");
    if !warnings.is_empty() {
        println!();
        for w in &warnings {
            println!("! {}", ui::safe(w));
        }
    }
    if !p.sample.is_empty() {
        println!("\nSample:");
        for s in &p.sample {
            println!("  {}", ui::safe(s));
        }
        if p.total > p.sample.len() {
            println!("  {d}and {} more{d:#}", num(p.total - p.sample.len()));
        }
    }
}
