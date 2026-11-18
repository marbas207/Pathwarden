//! `pathwarden config`: the Settings page from the terminal. Every
//! edit goes through the app's own code (`pathwarden_ui::settings::apply`
//! over `pathwarden_core::config_edit::ConfigDoc`), so it is validated,
//! written and refused exactly as a save in the app is.

use std::path::{Path, PathBuf};

use anstream::println;
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use pathwarden_core::config::{stamp_words, Suppression};
use pathwarden_core::config::{Config, SeverityMode};
use pathwarden_core::config_edit::{RulesEdit, Stamp, SuppressionEdit};
use pathwarden_core::settings_sync::{self, Changed, Resolve};
use pathwarden_ui::workspace::Workspace;

use crate::ui;

#[derive(Args)]
pub(crate) struct ConfigArgs {
    #[command(flatten)]
    at: Where,
    #[command(subcommand)]
    what: ConfigWhat,
}

/// Which pathwarden.toml a settings command changes: shared by `config`,
/// `zones`, `mappings` and `plugins`.
#[derive(Args, Clone, Default)]
pub(crate) struct Where {
    /// Which settings (pathwarden.toml): an environment of the app's
    /// workspace, its name or ID (default: the environment the app opens
    /// in).
    #[arg(
        long,
        value_name = "NAME",
        global = true,
        conflicts_with = "file",
        display_order = 900
    )]
    env: Option<String>,
    /// The app's workspace (default: the one `pathwarden ui` uses).
    #[arg(
        long,
        value_name = "DIR",
        global = true,
        conflicts_with = "file",
        display_order = 901
    )]
    workspace: Option<PathBuf>,
    /// A pathwarden.toml outside the app's workspace (as `-c` elsewhere).
    #[arg(
        short = 'c',
        long = "config",
        value_name = "FILE",
        global = true,
        display_order = 902
    )]
    file: Option<PathBuf>,
}

/// [`Where`] for a command whose subcommands also read data (`zones`):
/// the same options, given after the subcommand.
#[derive(Args, Clone, Default)]
pub(crate) struct WhereLocal {
    /// Which settings (pathwarden.toml): an environment of the app's
    /// workspace, its name or ID (default: the environment the app opens
    /// in).
    #[arg(
        long,
        value_name = "NAME",
        conflicts_with = "file",
        display_order = 900
    )]
    env: Option<String>,
    /// The app's workspace (default: the one `pathwarden ui` uses).
    #[arg(long, value_name = "DIR", conflicts_with = "file", display_order = 901)]
    workspace: Option<PathBuf>,
    /// A pathwarden.toml outside the app's workspace (as `-c` elsewhere).
    #[arg(short = 'c', long = "config", value_name = "FILE", display_order = 902)]
    file: Option<PathBuf>,
}

impl From<WhereLocal> for Where {
    fn from(w: WhereLocal) -> Self {
        Where {
            env: w.env,
            workspace: w.workspace,
            file: w.file,
        }
    }
}

#[derive(Subcommand)]
enum ConfigWhat {
    /// Objects treated as Tier Zero besides the built-in ones.
    TierZero {
        #[command(subcommand)]
        action: TierZeroAction,
    },
    /// Tier Zero settings folders: shared folders whose Tier Zero settings
    /// files every analysis, scheduled run and retest reads.
    SettingsFolders {
        #[command(subcommand)]
        action: SettingsFoldersAction,
    },
    /// Rule settings: stale and password-age thresholds, how attack paths
    /// are rated, which rules run, and their severities.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Accepted risks: findings you keep, with a reason and a review date.
    Risk {
        #[command(subcommand)]
        action: RiskAction,
    },
    /// The shared settings in the history's git repository (with `[state]
    /// keep = "full"`): bring this computer's settings and the shared ones
    /// up to date, or show where they differ. A computer's first sync
    /// takes the history's settings and saves its own pathwarden.toml
    /// beside it first.
    Sync {
        /// Use the shared settings: for sections that differ from them, and
        /// on a computer that only reads those only on this computer too
        /// (replaces this computer's); or the ones --section names.
        #[arg(long, conflicts_with_all = ["keep_local", "status"])]
        use_repo: bool,
        /// Keep this computer's sections and share them (a computer that
        /// pushes): those that differ from the shared settings, or the ones
        /// --section names.
        #[arg(long, conflicts_with = "status")]
        keep_local: bool,
        /// With --use-repo or --keep-local: only this section: tier_zero,
        /// settings_folders, rules, suppress, zone, management_planes,
        /// mapping; repeatable.
        #[arg(long, value_name = "KEY")]
        section: Vec<String>,
        /// Only show where the shared settings changed, section by section
        /// (gets the latest from the repository first; changes nothing).
        #[arg(long)]
        status: bool,
        /// With --status: print JSON instead of text.
        #[arg(long, requires = "status")]
        json: bool,
        /// The history folder (overrides [state] path in the settings).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SettingsFoldersAction {
    /// List the folders.
    List {
        /// Print JSON instead of text.
        #[arg(long, display_order = 903)]
        json: bool,
    },
    /// Add folders.
    Add {
        /// The folders: a share (\\fs01\pathwarden-t0) or a full path.
        #[arg(required = true, value_name = "FOLDER")]
        folders: Vec<String>,
    },
    /// Remove folders, as `list` prints them.
    Remove {
        /// The folders, as `list` prints them.
        #[arg(required = true, value_name = "FOLDER")]
        folders: Vec<String>,
    },
    /// Use folders the shared history brought on this computer, once you
    /// have checked them (until then they are listed but not read).
    Use {
        /// The folders, as `list` prints them.
        #[arg(required = true, value_name = "FOLDER")]
        folders: Vec<String>,
    },
}

#[derive(Subcommand)]
enum TierZeroAction {
    /// List the additions.
    List {
        /// Print JSON instead of text.
        #[arg(long, display_order = 903)]
        json: bool,
    },
    /// Add objects.
    Add {
        /// The objects: an object ID, or its full name such as NAME@DOMAIN.
        #[arg(required = true, value_name = "OBJECT")]
        items: Vec<String>,
        /// Keep entries that match nothing in the environment's latest
        /// analysis (they are refused otherwise; a typo would change
        /// nothing).
        #[arg(long)]
        force: bool,
    },
    /// Remove additions, as `list` prints them.
    Remove {
        /// The additions, as `list` prints them.
        #[arg(required = true, value_name = "OBJECT")]
        items: Vec<String>,
    },
}

#[derive(Subcommand)]
enum RulesAction {
    /// Show the rule settings.
    Show {
        /// Print JSON instead of text.
        #[arg(long, display_order = 903)]
        json: bool,
        /// Also list every rule: on or off, and its severity (set, or what
        /// rates it by default), as the Settings page lists them.
        #[arg(long)]
        rules: bool,
    },
    /// Change some of them; the rest stay as they are.
    // A negative number is a value to refuse in the settings' own words
    // ("must be 1 or more"), not an unknown flag.
    #[command(allow_negative_numbers = true)]
    Set {
        /// Tier Zero accounts with no logon for this many days are stale
        /// (PW-009).
        #[arg(long, value_name = "DAYS")]
        stale_days: Option<i64>,
        /// Tier Zero passwords older than this many days are reported
        /// (PW-010).
        #[arg(long, value_name = "DAYS")]
        password_age_days: Option<i64>,
        /// The krbtgt password older than this many days is reported
        /// (PW-014).
        #[arg(long, value_name = "DAYS")]
        krbtgt_age_days: Option<i64>,
        /// The Seamless SSO key older than this many days is reported
        /// (PW-037).
        #[arg(long, value_name = "DAYS")]
        sso_key_age_days: Option<i64>,
        /// How attack paths are rated.
        #[arg(long, value_enum)]
        rating: Option<Rating>,
        /// Turn a rule off, e.g. PW-011; repeatable.
        #[arg(long, value_name = "RULE")]
        disable: Vec<String>,
        /// Turn a rule back on; repeatable.
        #[arg(long, value_name = "RULE")]
        enable: Vec<String>,
        /// Set a rule's severity, whatever its exposure: PW-002=critical,
        /// high, medium or low; PW-002=default takes it off; repeatable.
        #[arg(long, value_name = "RULE=LEVEL")]
        severity: Vec<String>,
        /// Take every rule back to its default severity (as Settings' reset).
        #[arg(long)]
        reset_severities: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Rating {
    /// A path many users and computers can use is critical; one only a few
    /// can reach is lower (the default; like BloodHound Enterprise).
    #[value(
        help = "A path many users and computers can use is critical; one only a few can reach is lower (the default; like BloodHound Enterprise)."
    )]
    Exposure,
    /// Each rule keeps its own severity, however many accounts can use the
    /// path.
    #[value(help = "Each rule keeps its own severity, however many accounts can use the path.")]
    Rule,
}

#[derive(Subcommand)]
enum RiskAction {
    /// List accepted risks, numbered for `edit`, `note` and `remove`.
    List {
        /// Print JSON instead of text.
        #[arg(long, display_order = 903)]
        json: bool,
    },
    /// Accept one finding (by its ID) or a whole rule.
    Accept {
        /// The finding's ID, e.g. PW-004-13b0863341b2e306.
        #[arg(
            long,
            value_name = "FINDING_ID",
            required_unless_present = "rule",
            conflicts_with = "rule"
        )]
        finding: Option<String>,
        /// A whole rule, e.g. PW-011.
        #[arg(long, value_name = "RULE")]
        rule: Option<String>,
        /// Why it is accepted, and who decided.
        #[arg(long, required = true)]
        reason: String,
        /// The review date: the day it comes back for review (YYYY-MM-DD).
        #[arg(long, value_name = "DATE")]
        review_by: Option<String>,
    },
    /// Change an accepted risk, as the Settings page's Edit does; what you
    /// don't give stays as it is.
    Edit {
        #[command(flatten)]
        which: Which,
        /// Accept this finding instead (its ID): accepted again, by you.
        #[arg(long, value_name = "FINDING_ID", conflicts_with = "new_rule")]
        new_finding: Option<String>,
        /// Accept every finding of this rule instead: accepted again, by
        /// you.
        #[arg(long, value_name = "RULE")]
        new_rule: Option<String>,
        /// A new reason.
        #[arg(long)]
        reason: Option<String>,
        /// A new review date (YYYY-MM-DD).
        #[arg(long, value_name = "DATE", conflicts_with = "no_review_by")]
        review_by: Option<String>,
        /// No review date: accepted until it is removed.
        #[arg(long)]
        no_review_by: bool,
    },
    /// Add a note to an accepted risk (what was decided, checked or
    /// changed); it is kept with who wrote it and when.
    Note {
        #[command(flatten)]
        which: Which,
        /// The note.
        #[arg(long, required = true)]
        text: String,
    },
    /// Remove an accepted risk.
    Remove {
        #[command(flatten)]
        which: Which,
    },
}

/// Which accepted risk: its number in `list`, or what it covers. Both
/// together are checked against each other, so a number from an older
/// `list` never changes another risk.
#[derive(Args)]
struct Which {
    /// Its number in `list`.
    number: Option<usize>,
    /// The one that accepts this finding (its ID).
    #[arg(long, value_name = "FINDING_ID", conflicts_with = "rule")]
    finding: Option<String>,
    /// The one that accepts every finding of this rule.
    #[arg(long, value_name = "RULE")]
    rule: Option<String>,
}

/// Where the settings live, and the environment when they are one's.
pub(crate) struct Target {
    pub path: PathBuf,
    pub ws: Option<Workspace>,
    pub label: String,
    /// The options that make `pathwarden run` read these settings.
    pub run_flags: String,
}

impl Target {
    /// The folder `[[mapping]]` paths are relative to.
    pub fn base(&self) -> PathBuf {
        match &self.ws {
            Some(ws) => ws.env_dir(),
            None => self
                .path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
        }
    }
}

pub(crate) fn target(a: &Where) -> Result<Target> {
    if let Some(file) = &a.file {
        return Ok(Target {
            path: file.clone(),
            ws: None,
            label: file.display().to_string(),
            run_flags: format!("-c {}", arg(&file.display().to_string())),
        });
    }
    let ws = pathwarden_ui::environments::cli_workspace_or_current(
        a.workspace.as_deref(),
        a.env.as_deref(),
    )?;
    // The Default environment has no name to pass to --env.
    let run_flags = if ws.is_default_env() {
        format!("-c {}", arg(&ws.config_path().display().to_string()))
    } else {
        let mut f = format!("--env {}", arg(&ws.env_name()));
        if let Some(dir) = &a.workspace {
            f += &format!(" --workspace {}", arg(&dir.display().to_string()));
        }
        f
    };
    Ok(Target {
        run_flags,
        path: ws.config_path(),
        label: format!(
            "environment {} ({})",
            ws.env_name(),
            ws.config_path().display()
        ),
        ws: Some(ws),
    })
}

/// A command-line argument, quoted when it has a space.
fn arg(s: &str) -> String {
    if s.contains(char::is_whitespace) {
        format!("\"{s}\"")
    } else {
        s.to_string()
    }
}

/// The settings as they are now (the defaults when the file doesn't exist).
pub(crate) fn load(path: &Path) -> Result<Config> {
    if !path.is_file() {
        return Ok(Config::default());
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let config = pathwarden_core::config_edit::check(&text).map_err(anyhow::Error::msg)?;
    crate::warn_config(&config);
    Ok(config)
}

/// Saves a change as the app does, and with a history that shares
/// settings, shares it (a computer that pushes pushes it at once); what
/// became of that is said on stderr.
pub(crate) fn save(
    t: &Target,
    change: impl FnOnce(&mut pathwarden_core::config_edit::ConfigDoc) -> Result<(), String>,
) -> Result<()> {
    let share = pathwarden_ui::settings::Share {
        // `-c FILE` takes a relative [state] path from here, as `run -c`.
        base: match &t.ws {
            Some(_) => None,
            None => std::env::current_dir().ok(),
        },
        env_name: t.ws.as_ref().map(Workspace::env_name),
    };
    let ((), note) = pathwarden_ui::settings::apply_sharing(t.path.clone(), &share, change)
        .map_err(anyhow::Error::msg)?;
    if let Some(n) = note {
        for (i, line) in n.lines().enumerate() {
            eprintln!("{}{}", if i == 0 { "Note: " } else { "  " }, ui::safe(line));
        }
    }
    Ok(())
}

pub(crate) fn run(a: ConfigArgs) -> Result<()> {
    let t = target(&a.at)?;
    match a.what {
        ConfigWhat::TierZero { action } => tier_zero(&t, action),
        ConfigWhat::SettingsFolders { action } => settings_folders(&t, action),
        ConfigWhat::Rules { action } => rules(&t, action),
        ConfigWhat::Risk { action } => risk(&t, action),
        ConfigWhat::Sync {
            use_repo,
            keep_local,
            section,
            status,
            json,
            state,
        } => {
            if !section.is_empty() && !use_repo && !keep_local {
                bail!("--section goes with --use-repo or --keep-local.");
            }
            let resolve = if use_repo {
                Some(Resolve::UseRepo(section))
            } else if keep_local {
                Some(Resolve::KeepLocal(section))
            } else if status {
                None
            } else {
                Some(Resolve::Auto)
            };
            sync(&t, resolve, json, state)
        }
    }
}

// --------------------------------------------------------------- sync

/// `config sync`: `resolve` `None` only shows the status.
fn sync(t: &Target, resolve: Option<Resolve>, json: bool, state: Option<PathBuf>) -> Result<()> {
    let config = load(&t.path)?;
    if let Some(why) = settings_sync::inactive(&config.state) {
        if json {
            return crate::emit_json(&serde_json::json!({ "active": false, "why": why }));
        }
        println!("{}", ui::safe(why));
        return Ok(());
    }
    let (store, pushes, remote) = match &t.ws {
        Some(ws) => {
            let loc = pathwarden_ui::history_ui::locate(ws, state.as_deref())
                .map_err(anyhow::Error::msg)?;
            (loc.store, loc.push, loc.git)
        }
        None => {
            let store = pathwarden_core::store::Store::new(&config.state, state.as_deref())?;
            let remote = store.remote();
            (store, config.state.pushes(), remote)
        }
    };
    let _lock = store.lock_waiting(settings_sync::lock_wait())?;
    if let Some(note) = store
        .pull()
        .context("getting the latest from the repository")?
    {
        eprintln!("Warning: {}", ui::safe(&note));
    }
    let name = t.ws.as_ref().map(Workspace::env_name);
    let place = settings_sync::Place {
        store: &store,
        config_path: &t.path,
        pushes,
        env_name: name.as_deref(),
    };
    let Some(resolve) = resolve else {
        let s = settings_sync::status(&place)?;
        if json {
            let mut v = serde_json::to_value(&s)?;
            v["active"] = true.into();
            // Not "up to date": nothing here says what the repository holds.
            if s.unreadable.is_some() {
                v["state"] = "unreadable".into();
                if let Some(sections) = v["sections"].as_array_mut() {
                    for x in sections {
                        x["state"] = "unreadable".into();
                    }
                }
            }
            v["remote"] = remote.as_ref().map(|r| r.0.clone()).into();
            v["branch"] = remote.as_ref().map(|r| r.1.clone()).into();
            return crate::emit_json(&v);
        }
        print_status(t, &s, remote.as_ref());
        return Ok(());
    };
    let o = settings_sync::sync(&place, resolve)?;
    let kept = settings_sync::push_kept(&store, pushes);
    if o.done.nothing_shared {
        println!(
            "The repository has no shared settings yet, and this computer doesn't push, so it \
             can't share these."
        );
    } else if o.sentence().is_none() && o.status.state == Changed::InStep {
        println!("The shared settings are up to date on this computer.");
    }
    if let Some(s) = o.sentence() {
        if o.done.unreadable.is_some() {
            bail!("{s}");
        }
        if o.conflict() {
            print_status(t, &o.status, remote.as_ref());
            bail!("{s}");
        }
        print_lines(&s);
    }
    for n in kept.iter().chain(&o.status.notes) {
        print_lines(n);
    }
    Ok(())
}

/// A note that may hold git's own lines, each on a line of its own.
fn print_lines(text: &str) {
    for line in text.lines() {
        println!("{}", ui::safe(line));
    }
}

/// The status as text: the repository, the last change and each section.
fn print_status(t: &Target, s: &settings_sync::Status, remote: Option<&(String, String)>) {
    let (b, d) = (ui::BOLD, ui::DIM);
    println!(
        "{b}Shared settings{b:#} of {}{}",
        ui::safe(&t.label),
        if s.encrypted {
            ""
        } else {
            " · in plain text (not encrypted)"
        }
    );
    let fact = |label: &str, text: &str| {
        println!("  {d}{label:<14}{d:#}{}", ui::safe(text));
    };
    if let Some((r, branch)) = remote {
        fact("Repository", &format!("{r}, branch {branch}"));
    }
    fact(
        "This computer",
        if s.pushes {
            "pushes its changes"
        } else {
            "only reads the repository ([state] push = false)"
        },
    );
    if let Some(c) = &s.last_change {
        fact("Last change", &c.summary);
        let who = pathwarden_core::config::stamp_words(&c.by, &c.on, &None)
            .unwrap_or_else(|| "by someone Pathwarden didn't record".into());
        // Git's ISO time, shown as every other time is: local, US style.
        let at = pathwarden_core::time::parse_rfc3339(&c.at)
            .map(pathwarden_core::time::format_local)
            .unwrap_or_else(|| c.at.clone());
        fact("", &format!("{who} (git: {}), {at}", c.git_author));
    }
    if let Some(v) = &s.written_by_version {
        fact("Written by", &format!("Pathwarden {v}"));
    }
    println!();
    // Not "up to date": nothing here says what the repository holds.
    if let Some(words) = s.unreadable_words(false) {
        print_lines(&words);
        for n in &s.notes {
            print_lines(n);
        }
        return;
    }
    let width = s.sections.iter().map(|x| x.name.len()).max().unwrap_or(0) + 2;
    for x in &s.sections {
        let words = if x.state == Changed::Here && !s.pushes {
            "only on this computer"
        } else {
            x.state.words()
        };
        let words = if x.state == Changed::InStep {
            format!("{d}{words}{d:#}")
        } else {
            format!("{b}{words}{b:#}")
        };
        println!("  {:<width$}{words}", x.name);
    }
    println!();
    let line = if !s.in_repository {
        if s.pushes {
            "The repository has no shared settings yet; `pathwarden config sync` shares these."
        } else {
            "The repository has no shared settings yet."
        }
    } else {
        match s.state {
            Changed::InStep => "Up to date.",
            Changed::Here if s.pushes => "Not shared yet: `pathwarden config sync` shares them.",
            Changed::Here => {
                "Only on this computer: it only reads the history. `pathwarden config sync \
                 --use-repo` replaces them with the shared settings."
            }
            Changed::Repository => {
                "Shared updates: `pathwarden config sync` applies them here (so does every run \
                 and pull)."
            }
            Changed::Both if !s.pushes => {
                "This computer's settings differ from the shared ones: both changed since this \
                 computer last synced. `pathwarden config sync --use-repo` takes the shared \
                 settings; the other sections follow them on every pull. Until then, runs here \
                 use this computer's."
            }
            Changed::Both => {
                "This computer's settings differ from the shared ones: both changed since this \
                 computer last synced. Choose which to keep for each: `pathwarden config sync \
                 --use-repo` takes the shared settings, `--keep-local` keeps this computer's \
                 and shares them (`--section KEY` for one). Until then, runs here use this \
                 computer's."
            }
        }
    };
    println!("{line}");
    for n in &s.notes {
        println!("{}", ui::safe(n));
    }
}

/// `config settings-folders`: the Settings page's Tier Zero settings
/// folders card, through the same edit
/// ([`pathwarden_core::config_edit::ConfigDoc::set_settings_folders`]).
fn settings_folders(t: &Target, action: SettingsFoldersAction) -> Result<()> {
    use pathwarden_core::folder_origin;
    let config = load(&t.path)?;
    let same = |a: &str, b: &str| folder_origin::key(a) == folder_origin::key(b);
    // Folders the shared history brought that no one here reviewed: listed,
    // not read, as on the Settings page.
    let waiting = folder_origin::waiting(&config, &t.path);
    let is_waiting = |f: &str| waiting.iter().any(|w| same(w, f));
    match action {
        SettingsFoldersAction::List { json } => {
            if json {
                let rows: Vec<serde_json::Value> = config
                    .settings_folders
                    .iter()
                    .map(|f| serde_json::json!({ "path": f, "used": !is_waiting(f) }))
                    .collect();
                return crate::emit_json(&rows);
            }
            if config.settings_folders.is_empty() {
                println!(
                    "No Tier Zero settings folders in {}: only settings files in the collection are read.",
                    t.label
                );
            } else {
                println!("Tier Zero settings folders in {}:", t.label);
                let repo = folder_origin::from_repo(&config, &t.path);
                for f in &config.settings_folders {
                    if is_waiting(f) {
                        println!(
                            "  {}  ({}not used here until you review it; `pathwarden config settings-folders use` uses it)",
                            ui::safe(f),
                            if repo.contains(f) {
                                "from the repository: "
                            } else {
                                ""
                            }
                        );
                    } else {
                        println!("  {}", ui::safe(f));
                    }
                }
            }
            Ok(())
        }
        SettingsFoldersAction::Use { folders } => {
            let missing: Vec<&String> = folders
                .iter()
                .filter(|f| !config.settings_folders.iter().any(|e| same(e, f)))
                .collect();
            if !missing.is_empty() {
                bail!(
                    "not a Tier Zero settings folder: {} (see `pathwarden config settings-folders list`)",
                    missing
                        .iter()
                        .map(|s| ui::safe(s))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            folder_origin::mark(&t.path, &folders, true).map_err(anyhow::Error::msg)?;
            println!(
                "Saved: {} used on this computer. The next analysis reads {}.",
                pathwarden_core::text::count(
                    folders.len(),
                    "Tier Zero settings folder",
                    "Tier Zero settings folders"
                ),
                if folders.len() == 1 { "it" } else { "them" }
            );
            Ok(())
        }
        SettingsFoldersAction::Add { folders } => {
            for f in &folders {
                pathwarden_core::config_edit::check_settings_folder(f)
                    .map_err(anyhow::Error::msg)?;
            }
            let mut total = 0;
            save(t, |d| {
                let mut all = d.validate()?.settings_folders;
                for f in &folders {
                    if !all.iter().any(|e| same(e, f)) {
                        all.push(f.trim().to_string());
                    }
                }
                total = all.len();
                d.set_settings_folders(&all)
            })?;
            // Added on this computer: used here at once.
            folder_origin::mark(&t.path, &folders, true).map_err(anyhow::Error::msg)?;
            println!(
                "Saved: {} in {}. The app's next analysis reads them, and `pathwarden run` reads them with {}.",
                pathwarden_core::text::count(
                    total,
                    "Tier Zero settings folder",
                    "Tier Zero settings folders"
                ),
                t.label,
                t.run_flags
            );
            Ok(())
        }
        SettingsFoldersAction::Remove { folders } => {
            let missing: Vec<&String> = folders
                .iter()
                .filter(|f| !config.settings_folders.iter().any(|e| same(e, f)))
                .collect();
            if !missing.is_empty() {
                bail!(
                    "not a Tier Zero settings folder: {} (see `pathwarden config settings-folders list`)",
                    missing
                        .iter()
                        .map(|s| ui::safe(s))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            let mut total = 0;
            save(t, |d| {
                let left: Vec<String> = d
                    .validate()?
                    .settings_folders
                    .into_iter()
                    .filter(|e| !folders.iter().any(|f| same(e, f)))
                    .collect();
                total = left.len();
                d.set_settings_folders(&left)
            })?;
            folder_origin::mark(&t.path, &folders, false).map_err(anyhow::Error::msg)?;
            println!(
                "Saved: {} left in {}.",
                pathwarden_core::text::count(
                    total,
                    "Tier Zero settings folder",
                    "Tier Zero settings folders"
                ),
                t.label
            );
            Ok(())
        }
    }
}

fn tier_zero(t: &Target, action: TierZeroAction) -> Result<()> {
    let config = load(&t.path)?;
    match action {
        TierZeroAction::List { json } => {
            if json {
                return crate::emit_json(&config.tier_zero);
            }
            if config.tier_zero.is_empty() {
                println!(
                    "No additions in {}: only the built-in Tier Zero objects are used.",
                    t.label
                );
            } else {
                println!("Tier Zero additions in {}:", t.label);
                for item in &config.tier_zero {
                    println!("  {}", ui::safe(item));
                }
            }
            Ok(())
        }
        TierZeroAction::Add { items, force } => {
            // Checked against the environment's latest analysis, as the
            // Settings page's picker is.
            let latest = t.ws.as_ref().and_then(|ws| {
                pathwarden_ui::run_data::latest_with(ws, pathwarden_ui::run_data::OBJECTS_FILE)
            });
            match latest
                .as_ref()
                .and_then(|(_, dir)| pathwarden_ui::run_data::graph(dir))
            {
                Some(g) => {
                    let unmatched = pathwarden_core::tierzero::unmatched(&g, &items);
                    if !unmatched.is_empty() && !force {
                        bail!(
                            "These match no object in the latest analysis: {}. Use an object ID or its full name (NAME@DOMAIN), or --force to keep them anyway.",
                            unmatched.iter().map(|s| ui::safe(s)).collect::<Vec<_>>().join(", ")
                        );
                    }
                }
                None => eprintln!(
                    "Note: There is no analysis to check the names against, so they are saved as given."
                ),
            }
            // Added to the list as it is when the save holds the lock, so
            // two adds at once both stay.
            let mut total = 0;
            save(t, |d| {
                let mut all = d.validate()?.tier_zero;
                for i in &items {
                    if !all.iter().any(|e| e.eq_ignore_ascii_case(i.trim())) {
                        all.push(i.trim().to_string());
                    }
                }
                total = all.len();
                d.set_tier_zero(&all)
            })?;
            println!(
                "Saved: {} in {}. The next analysis uses them.",
                pathwarden_core::text::count(total, "Tier Zero addition", "Tier Zero additions"),
                t.label
            );
            Ok(())
        }
        TierZeroAction::Remove { items } => {
            let missing: Vec<&String> = items
                .iter()
                .filter(|i| {
                    !config
                        .tier_zero
                        .iter()
                        .any(|e| e.eq_ignore_ascii_case(i.trim()))
                })
                .collect();
            if !missing.is_empty() {
                bail!(
                    "not a Tier Zero addition: {} (see `pathwarden config tier-zero list`)",
                    missing
                        .iter()
                        .map(|s| ui::safe(s))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            let mut total = 0;
            save(t, |d| {
                let left: Vec<String> = d
                    .validate()?
                    .tier_zero
                    .into_iter()
                    .filter(|e| !items.iter().any(|i| e.eq_ignore_ascii_case(i.trim())))
                    .collect();
                total = left.len();
                d.set_tier_zero(&left)
            })?;
            println!(
                "Saved: {} left in {}.",
                pathwarden_core::text::count(total, "Tier Zero addition", "Tier Zero additions"),
                t.label
            );
            Ok(())
        }
    }
}

/// Today, UTC, as YYYY-MM-DD (dates in the settings compare as text).
fn today() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    pathwarden_core::time::format_unix(now)
        .chars()
        .take(10)
        .collect()
}

fn rating_name(m: SeverityMode) -> &'static str {
    match m {
        SeverityMode::Exposure => "exposure",
        _ => "rule",
    }
}

/// `pathwarden rules`: every rule with its severity, as the Settings page
/// lists them: the one set, or its default by how attack paths are rated.
/// The settings are the app's current environment's (or `--env`, `-c`);
/// without a workspace, the defaults.
pub(crate) fn list_rules(at: WhereLocal, json: bool) -> Result<()> {
    let given = at.env.is_some() || at.workspace.is_some() || at.file.is_some();
    let config = match target(&at.into()) {
        Ok(t) => load(&t.path)?,
        Err(e) if given => return Err(e),
        Err(_) => Config::default(),
    };
    let rows = config.rules.rows();
    if json {
        return crate::emit_json(&rows);
    }
    println!("{:<6}  {:<3}  {:<26}  Rule", "ID", "On", "Severity");
    print_rule_rows(&rows);
    println!("(PW-024 is not used.)");
    Ok(())
}

/// One line per rule: ID, on or off, severity (set or default), title.
fn print_rule_rows(rows: &[pathwarden_core::config::RuleRow]) {
    for row in rows {
        let severity = match &row.set {
            Some(s) => format!("{} (set)", s.severity.label()),
            None => row.default_words(),
        };
        println!(
            "{}  {:<3}  {:<26}  {}",
            row.id,
            if row.on { "on" } else { "off" },
            severity,
            row.title
        );
    }
}

/// " · set by NORTH\ned on Oct 24, 2026", with what was recorded.
fn set_by(s: &pathwarden_core::findings::SetSeverity) -> String {
    match (&s.by, &s.at) {
        (Some(b), Some(a)) => format!(" · set by {b} on {}", pathwarden_core::time::day_of(a)),
        (Some(b), None) => format!(" · set by {b}"),
        (None, Some(a)) => format!(" · set on {}", pathwarden_core::time::day_of(a)),
        (None, None) => String::new(),
    }
}

fn rules(t: &Target, action: RulesAction) -> Result<()> {
    let config = load(&t.path)?;
    let r = &config.rules;
    match action {
        RulesAction::Show { json, rules } => {
            let set = r.set_severities();
            if json {
                let mut v = serde_json::json!({
                    "stale_days": r.stale_days,
                    "password_age_days": r.password_age_days,
                    "krbtgt_age_days": r.krbtgt_age_days,
                    "sso_key_age_days": r.sso_key_age_days,
                    "rating": rating_name(r.severity),
                    "disabled": r.disabled,
                    "severities": set,
                });
                if rules {
                    v["rules"] = serde_json::json!(r.rows());
                }
                return crate::emit_json(&v);
            }
            println!("Rule settings in {}:", t.label);
            println!(
                "  Stale Tier Zero account:   {} days without a logon",
                r.stale_days
            );
            println!("  Old Tier Zero password:    {} days", r.password_age_days);
            println!("  Old krbtgt password:       {} days", r.krbtgt_age_days);
            println!("  Old Seamless SSO key:      {} days", r.sso_key_age_days);
            println!(
                "  Attack paths rated:        by {}",
                rating_name(r.severity)
            );
            let total = pathwarden_core::findings::rules().len();
            if r.disabled.is_empty() {
                println!("  Rules:                     all {total} on");
            } else {
                println!(
                    "  Rules:                     {} of {total} on; off: {}",
                    total - r.disabled.len(),
                    r.disabled.join(", ")
                );
            }
            if set.is_empty() {
                println!("  Severities set:            none (each rule's default)");
            } else {
                println!("  Severities set:            {}", set.len());
                let rows = r.rows();
                for (rule, s) in &set {
                    let default = rows
                        .iter()
                        .find(|x| x.id == rule)
                        .map(|x| match x.default.as_str() {
                            "exposure" => "by exposure".to_string(),
                            d => d.to_string(),
                        })
                        .unwrap_or_default();
                    println!(
                        "    {rule}  {:<8}  default {default}{}",
                        s.severity.label(),
                        set_by(s)
                    );
                }
            }
            if rules {
                println!();
                print_rule_rows(&r.rows());
            }
            Ok(())
        }
        RulesAction::Set {
            stale_days,
            password_age_days,
            krbtgt_age_days,
            sso_key_age_days,
            rating,
            disable,
            enable,
            severity: severity_args,
            reset_severities,
        } => {
            let mut severities = std::collections::BTreeMap::new();
            for a in &severity_args {
                let Some((rule, level)) = a.split_once('=') else {
                    bail!("--severity {a}: give a rule and a level, such as PW-011=low or PW-011=default.");
                };
                severities.insert(rule.trim().to_ascii_uppercase(), level.trim().to_string());
            }
            // What isn't given stays as it is when the save holds the lock.
            save(t, |doc| {
                let r = doc.validate()?.rules;
                let mut disabled: Vec<String> = r.disabled.clone();
                for d in &disable {
                    if !disabled.iter().any(|x| x.eq_ignore_ascii_case(d)) {
                        disabled.push(d.clone());
                    }
                }
                disabled.retain(|x| !enable.iter().any(|e| e.eq_ignore_ascii_case(x)));
                let edit = RulesEdit {
                    stale_days: stale_days.unwrap_or(r.stale_days),
                    password_age_days: password_age_days.unwrap_or(r.password_age_days),
                    krbtgt_age_days: krbtgt_age_days.unwrap_or(r.krbtgt_age_days),
                    sso_key_age_days,
                    severity: match rating {
                        Some(Rating::Exposure) => "exposure".into(),
                        Some(Rating::Rule) => "static".into(),
                        None => match r.severity {
                            SeverityMode::Exposure => "exposure".into(),
                            _ => "static".into(),
                        },
                    },
                    disabled,
                    severities: {
                        // --reset-severities: every rule back to its default,
                        // then what --severity gives.
                        let mut s = severities.clone();
                        if reset_severities {
                            for rule in r.set_severities().into_keys() {
                                s.entry(rule).or_insert_with(|| "default".into());
                            }
                        }
                        s
                    },
                };
                doc.set_rules(&edit, &Stamp::now())
            })?;
            println!(
                "Saved the rule settings in {}. The next analysis uses them.",
                t.label
            );
            Ok(())
        }
    }
}

/// The accepted risk `which` names: its index (from 0) and the entry.
fn select<'a>(t: &Target, config: &'a Config, which: &Which) -> Result<(usize, &'a Suppression)> {
    let covers = |s: &Suppression| match (&which.finding, &which.rule) {
        (Some(f), _) => s
            .fingerprint
            .as_deref()
            .is_some_and(|x| x.eq_ignore_ascii_case(f.trim())),
        (None, Some(r)) => {
            s.fingerprint.is_none()
                && s.rule
                    .as_deref()
                    .is_some_and(|x| x.eq_ignore_ascii_case(r.trim()))
        }
        (None, None) => true,
    };
    let what = match (&which.finding, &which.rule) {
        (Some(f), _) => format!("finding {}", f.trim()),
        (None, Some(r)) => format!("every {} finding", r.trim()),
        (None, None) => String::new(),
    };
    if let Some(number) = which.number {
        let Some(s) = number.checked_sub(1).and_then(|i| config.suppress.get(i)) else {
            bail!(
                "there is no accepted risk {number} in {} (see `pathwarden config risk list`)",
                t.label
            );
        };
        if !covers(s) {
            bail!(
                "accepted risk {number} in {} accepts {}, not {what}: the list has changed (see `pathwarden config risk list`)",
                t.label,
                s.target_words()
            );
        }
        return Ok((number - 1, s));
    }
    if what.is_empty() {
        bail!("Say which accepted risk: its number in `pathwarden config risk list`, --finding ID or --rule RULE.");
    }
    let found: Vec<usize> = (0..config.suppress.len())
        .filter(|&i| covers(&config.suppress[i]))
        .collect();
    match found[..] {
        [i] => Ok((i, &config.suppress[i])),
        [] => bail!("no accepted risk in {} accepts {what}", t.label),
        _ => bail!(
            "accepted risks {} in {} all accept {what}: give the number too",
            found
                .iter()
                .map(|i| (i + 1).to_string())
                .collect::<Vec<_>>()
                .join(", "),
            t.label
        ),
    }
}

/// Who accepted it, the last change and the notes, a line each, as `list`
/// prints them under the reason.
pub(crate) fn attribution_lines(s: &Suppression) -> Vec<String> {
    let a = s.acceptance();
    let mut out = vec![a.accepted_line()];
    out.extend(a.changed_line());
    for n in &s.notes {
        out.push(match stamp_words(&n.by, &n.on, &n.at) {
            Some(w) => format!("note {w}: {}", n.text),
            None => format!("note: {}", n.text),
        });
    }
    out
}

fn risk(t: &Target, action: RiskAction) -> Result<()> {
    let config = load(&t.path)?;
    match action {
        RiskAction::List { json } => {
            if json {
                let list: Vec<serde_json::Value> = config
                    .suppress
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        serde_json::json!({
                            "number": i + 1,
                            "finding": s.fingerprint,
                            "rule": s.rule,
                            "reason": s.reason,
                            "review_by": s.expires,
                            "accepted_by": s.accepted_by,
                            "accepted_on": s.accepted_on,
                            "accepted_at": s.accepted_at,
                            "changed_by": s.changed_by,
                            "changed_on": s.changed_on,
                            "changed_at": s.changed_at,
                            // Every key, null when not recorded, as above.
                            "notes": s.notes.iter().map(|n| serde_json::json!({
                                "by": n.by,
                                "on": n.on,
                                "at": n.at,
                                "text": n.text,
                            })).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                return crate::emit_json(&list);
            }
            if config.suppress.is_empty() {
                println!(
                    "No accepted risks in {}: every finding is shown as open.",
                    t.label
                );
                return Ok(());
            }
            println!("Accepted risks in {}:", t.label);
            let today = Some(today());
            for (i, s) in config.suppress.iter().enumerate() {
                let what = s
                    .fingerprint
                    .as_deref()
                    .map(|f| format!("finding {f}"))
                    .or_else(|| s.rule.as_deref().map(|r| format!("every {r} finding")))
                    .unwrap_or_default();
                let when = match s.expires.as_deref() {
                    Some(d) if today.as_deref().is_some_and(|t| d < t) => {
                        format!(
                            ", review was due {} (no longer applied)",
                            pathwarden_core::time::day_of(d)
                        )
                    }
                    Some(d) => format!(", review by {}", pathwarden_core::time::day_of(d)),
                    None => String::new(),
                };
                println!("  {}. {}{}", i + 1, ui::safe(&what), when);
                println!("     {}", ui::safe_text(s.reason.trim_end()));
                for line in attribution_lines(s) {
                    // A note of several lines: the rest indented under its first.
                    let mut parts = line.split('\n');
                    println!("     {}", ui::safe(parts.next().unwrap_or_default()));
                    for rest in parts {
                        if rest.is_empty() {
                            println!();
                        } else {
                            println!("       {}", ui::safe(rest));
                        }
                    }
                }
            }
            Ok(())
        }
        RiskAction::Accept {
            finding,
            rule,
            reason,
            review_by,
        } => {
            // The date is checked where the app's is
            // (`upsert_suppression`): a date, and not already past.
            let edit = SuppressionEdit {
                fingerprint: finding,
                rule,
                reason,
                expires: review_by,
            };
            let by = Stamp::now();
            save(t, |d| d.upsert_suppression(None, None, None, &edit, &by))?;
            println!(
                "Saved: the risk is accepted in {}. It shows as accepted from the next analysis.",
                t.label
            );
            Ok(())
        }
        RiskAction::Edit {
            which,
            new_finding,
            new_rule,
            reason,
            review_by,
            no_review_by,
        } => {
            let (i, s) = select(t, &config, &which)?;
            if new_finding.is_none()
                && new_rule.is_none()
                && reason.is_none()
                && review_by.is_none()
                && !no_review_by
            {
                bail!("Say what to change: --reason, --review-by, --no-review-by, --new-finding or --new-rule.");
            }
            let (target, by) = (s.target().to_string(), Stamp::now());
            let mut words = String::new();
            // What isn't given is taken from the entry as it is when the save
            // holds the lock, so a change made meanwhile isn't undone; the
            // target check refuses it if the entry now covers something else.
            save(t, |d| {
                let current = d.validate()?;
                let s = current
                    .suppress
                    .get(i)
                    .ok_or(pathwarden_core::config_edit::CHANGED)?;
                let (fingerprint, rule) = match (new_finding, new_rule) {
                    (Some(f), _) => (Some(f), None),
                    (None, Some(r)) => (None, Some(r)),
                    (None, None) => (s.fingerprint.clone(), s.rule.clone()),
                };
                let edit = SuppressionEdit {
                    fingerprint,
                    rule,
                    reason: reason.unwrap_or_else(|| s.reason.clone()),
                    expires: if no_review_by {
                        None
                    } else {
                        review_by.or_else(|| s.expires.clone())
                    },
                };
                words = match (&edit.fingerprint, &edit.rule) {
                    (Some(f), _) => format!("finding {}", f.trim()),
                    (None, Some(r)) => format!("every {} finding", r.trim().to_ascii_uppercase()),
                    (None, None) => s.target_words(),
                };
                let expect = s.reason.clone();
                d.upsert_suppression(Some(i), Some(&expect), Some(&target), &edit, &by)
            })?;
            println!(
                "Saved accepted risk {} ({}) in {}. The next analysis uses it.",
                i + 1,
                ui::safe(&words),
                t.label
            );
            Ok(())
        }
        RiskAction::Note { which, text } => {
            let (i, s) = select(t, &config, &which)?;
            let (expect, target, by) = (s.reason.clone(), s.target().to_string(), Stamp::now());
            save(t, |d| {
                d.add_suppression_note(i, &expect, Some(&target), &text, &by)
            })?;
            println!(
                "Added the note to accepted risk {} ({}) in {}.",
                i + 1,
                ui::safe(&s.target_words()),
                t.label
            );
            Ok(())
        }
        RiskAction::Remove { which } => {
            let (i, s) = select(t, &config, &which)?;
            let (reason, target) = (s.reason.clone(), s.target().to_string());
            save(t, |d| d.remove_suppression(i, &reason, Some(&target)))?;
            println!(
                "Removed accepted risk {} ({}) from {}.",
                i + 1,
                ui::safe(&s.target_words()),
                t.label
            );
            Ok(())
        }
    }
}
