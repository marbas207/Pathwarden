//! `pathwarden mappings`: the Mappings page from the terminal. The
//! packs and their labels are core's (`opengraph::trust`), as the page
//! lists them; trusting goes through the page's checks (`trust_target`)
//! and `ConfigDoc::set_pack_trust`.

use anstream::println;
use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use pathwarden_core::opengraph::trust::{
    self, edge_facts, fix_text, packs_in_effect, trust_target, PackEntry,
};
use pathwarden_core::text::num;

use crate::config_cmd::{self, Where};
use crate::{emit_json, ui};

#[derive(Args)]
pub(crate) struct MappingsArgs {
    #[command(flatten)]
    at: Where,
    #[command(subcommand)]
    action: MappingsAction,
}

#[derive(Subcommand)]
enum MappingsAction {
    /// The built-in and your own ([[mapping]]) packs, and how far each is
    /// trusted.
    List {
        /// Print JSON instead of text.
        #[arg(long, display_order = 903)]
        json: bool,
    },
    /// One pack in full, as its card on the Mappings page opens: its
    /// description, object kinds and relationship kinds, and which of them
    /// are attack paths. Review this before `trust`.
    Show {
        /// The pack's name, as `list` prints it.
        pack: String,
        /// Print JSON instead of text.
        #[arg(long, display_order = 903)]
        json: bool,
    },
    /// Mark a pack you reviewed as trusted: its traversable relationships
    /// then make attack paths and findings, from the next analysis on.
    Trust {
        /// The pack's name, as `list` prints it.
        pack: String,
        /// You checked, for each traversable kind, that it lets an attacker
        /// move (the app's "I reviewed this pack" box).
        #[arg(long)]
        reviewed: bool,
        /// For a pack from the repository: the digest of the text you
        /// reviewed, as `mappings show` prints it (trust holds for that
        /// text only).
        #[arg(long, value_name = "SHA256")]
        digest: Option<String>,
    },
    /// Remove the trust you gave a pack: its kinds are context only again.
    Untrust {
        /// The pack's name.
        pack: String,
    },
}

pub(crate) fn run(a: MappingsArgs) -> Result<()> {
    let t = config_cmd::target(&a.at)?;
    let config = config_cmd::load(&t.path)?;
    let (packs, refused) = packs_in_effect(&config, &t.base());
    match a.action {
        MappingsAction::List { json } => {
            if json {
                let list: Vec<serde_json::Value> = packs
                    .iter()
                    .map(|e| {
                        let p = &e.pack;
                        serde_json::json!({
                            "name": p.name(),
                            "title": p.title(),
                            "version": p.version(),
                            "path": e.path,
                            "trusted": p.trusted(),
                            "trusted_by_config": e.trusted_by_config,
                            "from_repository": e.from_repo.as_ref().map(|r| serde_json::json!({"added_by": r.added_by, "added_on": r.added_on, "added_at": r.added_at, "trusted_here": e.pack.trusted(), "digest": r.current_sha256, "record_unreadable": r.unreadable})),
                            "sources": p.source_kinds(),
                            "kind_prefix": p.kind_prefix(),
                            "object_kinds": p.node_views().len(),
                            "relationship_kinds": p.edge_views().len(),
                            "attack_path_kinds": p.edge_views().iter().filter(|e| e.traversable).count(),
                        })
                    })
                    .collect();
                let refused: Vec<serde_json::Value> = refused
                    .iter()
                    .map(|(path, e)| serde_json::json!({ "path": path, "error": e }))
                    .collect();
                return emit_json(&serde_json::json!({ "packs": list, "refused": refused }));
            }
            let (b, d) = (ui::BOLD, ui::DIM);
            println!("Mapping packs in {}:", t.label);
            for e in &packs {
                let p = &e.pack;
                println!(
                    "\n{b}{}{b:#} {d}{} v{}{d:#}  [{}]",
                    ui::safe(p.title()),
                    ui::safe(p.name()),
                    p.version(),
                    e.trust_label()
                );
                println!(
                    "  {} · for {} · kinds starting {}",
                    ui::safe(&e.origin()),
                    ui::safe(&p.source_kinds().join(", ")),
                    ui::safe(p.kind_prefix())
                );
                let summary = e.summary();
                if !summary.is_empty() {
                    println!("  {summary}");
                }
            }
            for (path, e) in &refused {
                println!(
                    "\n! Mapping pack {} was refused. {} Analyses stop until it is fixed or removed from [[mapping]].",
                    ui::safe(path),
                    ui::safe(e)
                );
            }
            if !packs.iter().any(|e| e.path.is_some()) {
                println!(
                    "\n{d}No packs of your own. Add one with [[mapping]] path = \"packs/name.toml\" in pathwarden.toml (docs/opengraph.md).{d:#}"
                );
            }
            // Kinds the latest run saw that no pack describes.
            if let Some((r, dir)) = t.ws.as_ref().and_then(|ws| {
                pathwarden_ui::run_data::latest_with(ws, pathwarden_ui::opengraph_ui::SOURCES_FILE)
            }) {
                if let Some(s) = pathwarden_ui::opengraph_ui::read_stats(&dir)
                    .filter(|s| !s.unmapped_kinds.is_empty())
                {
                    println!(
                        "\n{b}Kinds without a mapping{b:#} {d}(in the latest run with OpenGraph data, {}; context only){d:#}",
                        ui::safe(&r.environment())
                    );
                    for (k, n) in s.unmapped_kinds.iter().take(200) {
                        println!("  {}  {}", ui::safe(k), num(*n));
                    }
                }
            }
            Ok(())
        }
        MappingsAction::Show { pack, json } => {
            let name = pack.trim();
            let Some(e) = packs
                .iter()
                .find(|e| e.pack.name().eq_ignore_ascii_case(name))
            else {
                bail!(
                    "There is no mapping pack by that name. `pathwarden mappings list` names them."
                );
            };
            if json {
                return emit_json(&show_json(e));
            }
            show(e, &t.label);
            Ok(())
        }
        MappingsAction::Trust {
            pack,
            reviewed,
            digest,
        } => {
            let name = match trust::trust_change(&packs, &pack, true, reviewed) {
                Ok(trust::TrustChange::Reviewed { path, name, .. }) => {
                    let Some(digest) = digest else {
                        bail!(
                            "{} came from the repository: trust holds for the text you reviewed. Give --digest with the text digest `pathwarden mappings show {}` prints.",
                            ui::safe(&name),
                            ui::safe(&name)
                        );
                    };
                    pathwarden_core::pack_origin::mark_reviewed(
                        &t.path,
                        &path,
                        true,
                        Some(&digest),
                    )
                    .map_err(anyhow::Error::msg)?;
                    println!(
                        "Saved: {} (from the repository) is trusted on this computer, at the text it has now. Its traversable relationships make attack paths and findings from the next analysis on; if the repository changes it, it is untrusted again until you review it.",
                        ui::safe(&name)
                    );
                    return Ok(());
                }
                Ok(trust::TrustChange::Name(n)) => n,
                Err(e) if e == trust::CONFIRM => bail!(
                    "{e} Check, for each traversable kind (`pathwarden mappings show {}`), that it lets an attacker move, then add --reviewed.",
                    ui::safe(pack.trim())
                ),
                Err(e) => bail!("{e} (see `pathwarden mappings list`)."),
            };
            config_cmd::save(&t, |d| d.set_pack_trust(&name, true))?;
            println!(
                "Saved: {} is trusted in {}. Its traversable relationships make attack paths and findings from the next analysis on.",
                ui::safe(&name),
                t.label
            );
            Ok(())
        }
        MappingsAction::Untrust { pack } => {
            if let Ok(trust::TrustChange::Reviewed { path, name, .. }) =
                trust::trust_change(&packs, &pack, false, false)
            {
                pathwarden_core::pack_origin::mark_reviewed(&t.path, &path, false, None)
                    .map_err(anyhow::Error::msg)?;
                // Trust by name, from before, goes too: it would come back
                // if the record of packs from the repository were lost.
                if config.opengraph.trusts(&name) {
                    config_cmd::save(&t, |d| d.set_pack_trust(&name, false))?;
                }
                println!(
                    "Saved: {} (from the repository) is no longer trusted on this computer.",
                    ui::safe(&name)
                );
                return Ok(());
            }
            let name = trust_target(&packs, &pack, false, false).map_err(anyhow::Error::msg)?;
            if !packs
                .iter()
                .any(|e| e.pack.name() == name && e.trusted_by_config)
            {
                bail!(
                    "{} isn't trusted in {}: nothing to remove.",
                    ui::safe(&name),
                    t.label
                );
            }
            config_cmd::save(&t, |d| d.set_pack_trust(&name, false))?;
            println!(
                "Saved: {} is no longer trusted in {}. Its kinds are context only from the next analysis on.",
                ui::safe(&name),
                t.label
            );
            Ok(())
        }
    }
}

/// `show`'s text: the pack card, opened.
fn show(e: &PackEntry, label: &str) {
    let p = &e.pack;
    let (b, d) = (ui::BOLD, ui::DIM);
    println!(
        "{b}{}{b:#} {d}{} v{} in {}{d:#}  [{}]",
        ui::safe(p.title()),
        ui::safe(p.name()),
        p.version(),
        label,
        e.trust_label()
    );
    println!(
        "{} · for {} · kinds starting {}",
        ui::safe(&e.origin()),
        ui::safe(&p.source_kinds().join(", ")),
        ui::safe(p.kind_prefix())
    );
    if let Some(r) = &e.from_repo {
        if let Some(sha) = &r.current_sha256 {
            println!(
                "Text digest {sha}: `pathwarden mappings trust {} --reviewed --digest {sha}` trusts this text, on this computer.",
                ui::safe(p.name())
            );
        }
        if r.unreadable {
            println!("The record of packs from the repository can't be read, so this pack is untrusted until it is reviewed again.");
        }
    }
    if let Some(desc) = p.description() {
        println!("\n{}", ui::safe(desc));
    }
    let summary = e.summary();
    if summary.is_empty() {
        println!("\n{d}It maps no kinds.{d:#}");
        return;
    }
    println!("\n{summary}");
    let nodes = p.node_views();
    if !nodes.is_empty() {
        println!("\n{b}Object kinds{b:#}");
        for n in &nodes {
            match &n.label {
                Some(l) => println!("  {}  {}", ui::safe(&n.kind), ui::safe(l)),
                None => println!("  {}", ui::safe(&n.kind)),
            }
        }
    }
    let edges = p.edge_views();
    if !edges.is_empty() {
        println!("\n{b}Relationship kinds{b:#}");
        if edges.iter().any(|e| e.fix.is_some()) {
            println!("{d}In the fixes, start and end stand for the objects a relationship goes from and to.{d:#}");
        }
        for ed in &edges {
            println!(
                "\n  {b}{}{b:#}  [{}]  {d}{}{d:#}",
                ui::safe(&ed.kind),
                e.edge_role(ed),
                ui::safe(&edge_facts(ed).join(" · "))
            );
            if let Some(desc) = &ed.description {
                println!("    {}", ui::safe(desc));
            }
            if let Some(f) = &ed.fix {
                println!("    Fix: {}", ui::safe(&fix_text(f, p.title())));
            }
        }
    }
}

/// `show --json`: the pack and every kind it maps.
fn show_json(e: &PackEntry) -> serde_json::Value {
    let p = &e.pack;
    let edges: Vec<serde_json::Value> = p
        .edge_views()
        .iter()
        .map(|ed| {
            serde_json::json!({
                "kind": ed.kind,
                "role": e.edge_role(ed),
                "traversable": ed.traversable,
                "attack_path": ed.traversable && p.trusted(),
                "facts": edge_facts(ed),
                "description": ed.description,
                "fix": ed.fix.as_deref().map(|f| fix_text(f, p.title())),
                "cost": ed.cost,
                "cuttable": ed.cuttable,
                "rule": ed.rule,
                "unit": ed.unit,
                "unless": ed.unless,
                "when": ed.when,
            })
        })
        .collect();
    serde_json::json!({
        "name": p.name(),
        "title": p.title(),
        "version": p.version(),
        "description": p.description(),
        "path": e.path,
        "trusted": p.trusted(),
        "trusted_by_config": e.trusted_by_config,
        "from_repository": e.from_repo.as_ref().map(|r| serde_json::json!({"added_by": r.added_by, "added_on": r.added_on, "added_at": r.added_at, "trusted_here": e.pack.trusted(), "digest": r.current_sha256, "record_unreadable": r.unreadable})),
        "trust": e.trust_label(),
        "sources": p.source_kinds(),
        "kind_prefix": p.kind_prefix(),
        "summary": e.summary(),
        "object_kinds": p.node_views(),
        "relationship_kinds": edges,
    })
}
