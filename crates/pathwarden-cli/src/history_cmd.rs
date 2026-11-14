//! `pathwarden history storage|import|keep-local`: the app's History storage
//! page from the terminal. Where the history is, and the words for it,
//! come from the page's own code (`pathwarden_ui::history_ui`); a change of
//! place is saved through `pathwarden_ui::settings::apply`, so it is
//! validated and refused as a save on the page is; importing earlier
//! analyses is `pathwarden_core::record::import`, as the page's button.

use std::path::PathBuf;

use anstream::println;
use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use pathwarden_core::config::StateBackend;
use pathwarden_core::config_edit::StateEdit;
use pathwarden_ui::history_ui::{self, label, Location, Origin};
use pathwarden_ui::workspace::Workspace;
use serde_json::json;

use crate::ui;

/// Which environment's history: as `pathwarden config` picks one.
#[derive(Args, Clone, Default)]
pub(crate) struct Env {
    /// The environment of the app's workspace (its name or ID) (default:
    /// the environment the app opens in).
    #[arg(long, value_name = "NAME")]
    env: Option<String>,
    /// The app's workspace (default: the one `pathwarden ui` uses).
    #[arg(long, value_name = "DIR")]
    workspace: Option<PathBuf>,
}

impl Env {
    pub(crate) fn workspace(&self) -> Result<Workspace> {
        pathwarden_ui::environments::cli_workspace_or_current(
            self.workspace.as_deref(),
            self.env.as_deref(),
        )
    }

    /// Whether `--env` or `--workspace` was given.
    pub(crate) fn given(&self) -> bool {
        self.env.is_some() || self.workspace.is_some()
    }
}

#[derive(Subcommand)]
pub(crate) enum HistoryAction {
    /// Where the run history is kept, and changing it (the app's History
    /// storage page).
    Storage {
        #[command(subcommand)]
        action: StorageAction,
    },
    /// Add the runs kept on this computer only to the run history, oldest
    /// first, as if each had been recorded when it was analyzed.
    Import {
        #[command(flatten)]
        env: Env,
        /// The history folder (overrides [state] path in the settings).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
    },
    /// Leave the runs kept on this computer only out of the run history, so
    /// they stop being offered for import.
    KeepLocal {
        /// The runs, by folder ID (default: every one `import` would add).
        #[arg(value_name = "RUN")]
        runs: Vec<String>,
        #[command(flatten)]
        env: Env,
        /// The history folder (overrides [state] path in the settings).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum StorageAction {
    /// Where the run history is, how many runs it has, and the runs kept on
    /// this computer only.
    Show {
        #[command(flatten)]
        env: Env,
        /// The history folder (overrides [state] path in the settings).
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Keep the run history in a folder (--folder DIR) or a git repository
    /// (--git URL), or change only its options; what isn't given stays as
    /// it is.
    Set {
        /// A git repository, synced before each run and pushed after (use a
        /// private one; sign in through git's credential helper).
        #[arg(long, value_name = "URL")]
        git: Option<String>,
        /// With --git, or a history already in git: the branch (default:
        /// main).
        #[arg(long, value_name = "BRANCH")]
        branch: Option<String>,
        /// The folder: the history itself, or with --git where the
        /// repository is checked out. A relative folder is taken from the
        /// environment's folder.
        #[arg(long, value_name = "DIR")]
        folder: Option<String>,
        /// With --git, or a history already in git: push recorded runs to
        /// the repository (the default).
        #[arg(long, overrides_with = "no_push")]
        push: bool,
        /// With --git, or a history already in git: only read the shared
        /// history from this computer (as `pathwarden run --no-push`).
        #[arg(long, overrides_with = "push")]
        no_push: bool,
        /// What the history keeps: `names`, numbers with names (IDs, rules,
        /// severities and dates, plus each finding's title, which names the
        /// accounts, groups and computers it is about, and its domain; the
        /// default), or `full`, full runs and settings (also the shared
        /// settings and accepted risks, through a git history; needs --yes,
        /// and for a history that isn't encrypted, --encrypt, which
        /// encrypts it before anything is shared, or --no-encrypt).
        #[arg(long, value_name = "LEVEL", value_parser = ["names", "full"])]
        keep: Option<String>,
        /// With "Full runs and settings": how many full runs the history
        /// keeps, the latest (default: 50); older runs keep their numbers.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=1000))]
        full_runs_kept: Option<u32>,
        /// With "Full runs and settings": the largest file a full run keeps,
        /// in MB, 1 to 2048 (default: 75); a larger one is left out and
        /// named on the run's page. On a GitHub remote, more than 95 is held
        /// to 95.
        #[arg(long, value_name = "MB", value_parser = clap::value_parser!(u64).range(1..=2048))]
        full_run_file_mb: Option<u64>,
        /// With --git, or a history already in git: how often the app syncs
        /// while it is open, and when it opens, in minutes, 1 to 1440
        /// (default: 5). Each computer sets its own, including readers.
        #[arg(long, value_name = "MINUTES", value_parser = clap::value_parser!(u32).range(1..=1440))]
        refresh: Option<u32>,
        /// The same as `--keep names` (finding titles and domain names are
        /// kept at every level now).
        #[arg(long, hide = true, overrides_with = "no_names")]
        names: bool,
        /// No longer available: the history keeps names at every level.
        #[arg(long, hide = true, overrides_with = "names")]
        no_names: bool,
        /// Encrypt every file of the history with a passphrase (age), in one
        /// commit: the passphrase stored on this computer, or
        /// PATHWARDEN_HISTORY_PASSPHRASE, else typed twice (and stored).
        /// Needs --yes.
        #[arg(long, conflicts_with = "no_encrypt")]
        encrypt: bool,
        /// Write every file of the history in plain text again, in one
        /// commit. Needs --yes. With --keep full on a history that isn't
        /// encrypted: keep it in plain text on purpose.
        #[arg(long)]
        no_encrypt: bool,
        /// With --keep full, --encrypt or --no-encrypt: go ahead after the
        /// warning.
        #[arg(long, short = 'y')]
        yes: bool,
        /// With --encrypt: the passphrase from PATHWARDEN_HISTORY_PASSPHRASE
        /// (not stored on this computer).
        #[arg(long, requires = "encrypt")]
        from_env: bool,
        /// With --encrypt or --no-encrypt alone: the history folder.
        #[arg(long, value_name = "DIR", conflicts_with_all = SETTINGS_ARGS)]
        state: Option<PathBuf>,
        /// With --encrypt or --no-encrypt alone: the settings
        /// (pathwarden.toml) with the [state] section, instead of the app's
        /// workspace's (a server's scheduled runs).
        #[arg(short, long, value_name = "FILE", conflicts_with_all = SETTINGS_ARGS)]
        config: Option<PathBuf>,
        #[command(flatten)]
        env: Env,
    },
    /// The passphrase of an encrypted history on this computer: set, change,
    /// check or forget it.
    Passphrase {
        #[command(subcommand)]
        action: PassphraseAction,
    },
    /// Accept an encrypted history as it is now, after restoring it on
    /// purpose (a backup, a force push): this computer stops refusing its
    /// files as older copies, as "Accept the history as it is" in the app.
    /// Resets this computer's records for that history only.
    Accept {
        /// Go ahead without asking.
        #[arg(long, short = 'y')]
        yes: bool,
        #[command(flatten)]
        target: Target,
    },
    /// Sync the history's git repository now, as Sync now in the app: push
    /// the runs recorded here that are waiting, then get the latest.
    #[command(alias = "pull")]
    Sync {
        #[command(flatten)]
        target: Target,
    },
    /// Sign in to the history's git repository, as Sign in in the app: git
    /// opens the Git Credential Manager window (Pathwarden never sees the
    /// password), then the history is synced. Run it as the account that
    /// runs Pathwarden (for a scheduled task, the task's account).
    SignIn {
        #[command(flatten)]
        target: Target,
    },
    /// Look at a shared history before connecting to it: whether it is a
    /// Pathwarden history, encrypted, what it keeps, its runs, and whether
    /// this account can push to it. Nothing is saved or pushed.
    Probe {
        #[command(flatten)]
        place: Place,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
        /// The app's workspace (default: the one `pathwarden ui` uses).
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },
    /// Connect an environment that has no runs of its own to a shared
    /// history, as the app's Connect to a run history: it adopts what the
    /// history keeps and its encryption, then syncs. For a new environment,
    /// use `pathwarden env create --from-git URL`.
    Connect {
        #[command(flatten)]
        place: Place,
        #[command(flatten)]
        how: ConnectHow,
        #[command(flatten)]
        env: Env,
    },
}

/// Where a shared history is: a git repository or a shared folder.
#[derive(Args, Clone, Default)]
pub(crate) struct Place {
    /// A git repository (sign-in comes from git's credential helper).
    #[arg(long, value_name = "URL", required_unless_present = "shared_folder")]
    pub(crate) git: Option<String>,
    /// A shared folder that holds the history.
    #[arg(long = "folder", value_name = "DIR", conflicts_with = "git")]
    pub(crate) shared_folder: Option<PathBuf>,
    /// With --git: the branch (default: the repository's default branch).
    #[arg(long, value_name = "BRANCH", requires = "git")]
    pub(crate) branch: Option<String>,
}

/// How this computer uses the shared history once connected.
#[derive(Args, Clone, Default)]
pub(crate) struct ConnectHow {
    /// Push runs from this computer (the default when this account can
    /// push).
    #[arg(long, overrides_with = "read_only")]
    pub(crate) push: bool,
    /// Only read the shared history from this computer.
    #[arg(long, overrides_with = "push")]
    pub(crate) read_only: bool,
    /// How often the app syncs while it is open, in minutes, 1 to 1440
    /// (default: 5).
    #[arg(long, value_name = "MINUTES", value_parser = clap::value_parser!(u32).range(1..=1440))]
    pub(crate) refresh: Option<u32>,
}

impl Place {
    fn place(&self) -> pathwarden_core::connect::Where {
        match (&self.git, &self.shared_folder) {
            (Some(url), _) => pathwarden_core::connect::Where::Git {
                url: url.clone(),
                branch: self.branch.clone(),
            },
            (None, Some(dir)) => pathwarden_core::connect::Where::Folder(
                std::path::absolute(dir).unwrap_or_else(|_| dir.clone()),
            ),
            (None, None) => unreachable!("clap requires one"),
        }
    }
}

/// `set`'s options that change `[state]` in the workspace's pathwarden.toml.
const SETTINGS_ARGS: [&str; 11] = [
    "git",
    "branch",
    "folder",
    "push",
    "no_push",
    "keep",
    "full_runs_kept",
    "full_run_file_mb",
    "refresh",
    "names",
    "no_names",
];

#[derive(Subcommand)]
pub(crate) enum PassphraseAction {
    /// Store the passphrase on this computer, for this account (Windows
    /// Credential Manager, or the Secret Service on Linux): typed twice, the
    /// first line of stdin, or PATHWARDEN_HISTORY_PASSPHRASE with --from-env.
    /// An encrypted history must open with it.
    Set {
        /// Take it from PATHWARDEN_HISTORY_PASSPHRASE.
        #[arg(long)]
        from_env: bool,
        /// Windows: store it for another account instead (a scheduled task's
        /// gMSA, DOMAIN\name$), in a file beside the history folder only that
        /// account can open (DPAPI-NG), owned by Administrators: run it from
        /// an elevated prompt.
        #[arg(long, value_name = "ACCOUNT")]
        for_account: Option<String>,
        #[command(flatten)]
        target: Target,
    },
    /// Change the passphrase: every file of the history encrypted again with
    /// a new key, in one commit. Older git history still opens with the old
    /// passphrase.
    Change {
        /// Take the new passphrase from PATHWARDEN_HISTORY_NEW_PASSPHRASE.
        #[arg(long)]
        from_env: bool,
        #[command(flatten)]
        target: Target,
    },
    /// Whether the passphrase this computer has opens the history.
    Check {
        #[command(flatten)]
        target: Target,
    },
    /// Remove the passphrase from this computer's store (and this account's
    /// protected file).
    Forget {
        /// Windows: remove the file stored for this account instead.
        #[arg(long, value_name = "ACCOUNT")]
        for_account: Option<String>,
        #[command(flatten)]
        target: Target,
    },
}

/// Which history: an environment of the UI workspace, as the rest of
/// `history storage`, or a server's `pathwarden.toml` (`-c`), as
/// `pathwarden run -c` uses it.
#[derive(Args, Clone, Default)]
pub(crate) struct Target {
    #[command(flatten)]
    env: Env,
    /// The history folder (overrides [state] path in the settings).
    #[arg(long, value_name = "DIR")]
    state: Option<PathBuf>,
    /// The settings (pathwarden.toml) with the [state] section, instead of
    /// the app's workspace's (a server's scheduled runs).
    #[arg(short, long, value_name = "FILE", conflicts_with_all = ["env", "workspace"])]
    config: Option<PathBuf>,
}

impl Target {
    fn locate(&self) -> Result<Location> {
        let Some(file) = &self.config else {
            let ws = self.env.workspace()?;
            return locate(&ws, self.state.as_deref());
        };
        let config = pathwarden_core::config::Config::from_file(file)?;
        crate::warn_config(&config);
        let store = pathwarden_core::store::Store::new(&config.state, self.state.as_deref())?
            .with_config_file(file.clone());
        Ok(Location {
            git: store.remote(),
            push: config.state.pushes(),
            dir: store.dir.clone(),
            origin: if self.state.is_some() {
                Origin::Flag
            } else {
                Origin::Config
            },
            store,
        })
    }
}

use pathwarden_core::keystore::NEW_ENV_VAR;

pub(crate) fn run(action: HistoryAction) -> Result<()> {
    match action {
        HistoryAction::Storage { action } => match action {
            StorageAction::Show { env, state, json } => show(&env, state, json),
            StorageAction::Set {
                git,
                branch,
                folder,
                push,
                no_push,
                keep,
                full_runs_kept,
                full_run_file_mb,
                refresh,
                names,
                no_names,
                encrypt,
                no_encrypt,
                yes,
                from_env,
                state,
                config,
                env,
            } => {
                if no_names {
                    bail!(
                        "--no-names is no longer available: the history keeps finding titles and \
                         domain names at every level (`--keep names`, the default)."
                    );
                }
                if full_runs_kept.is_some() || full_run_file_mb.is_some() {
                    let ws = env.workspace()?;
                    if let Some(n) = full_runs_kept {
                        pathwarden_ui::settings::save_full_runs_kept(&ws, n as usize)
                            .map_err(anyhow::Error::msg)?;
                        println!(
                            "Saved in {}. {}",
                            ws.config_path().display(),
                            pathwarden_ui::settings::full_runs_kept_words(n as usize)
                        );
                    }
                    if let Some(mb) = full_run_file_mb {
                        pathwarden_ui::settings::save_full_run_file_mb(&ws, mb)
                            .map_err(anyhow::Error::msg)?;
                        let s = pathwarden_ui::settings::load_ws(&ws).config.state;
                        let remote = (s.backend == pathwarden_core::config::StateBackend::Git)
                            .then_some(s.remote)
                            .flatten();
                        println!(
                            "Saved in {}. {}",
                            ws.config_path().display(),
                            pathwarden_ui::settings::full_run_file_mb_words(mb, remote.as_deref())
                        );
                    }
                    let others = [
                        git.is_some(),
                        branch.is_some(),
                        folder.is_some(),
                        refresh.is_some(),
                    ]
                    .into_iter()
                    .chain([push, no_push, keep.is_some(), names, encrypt, no_encrypt])
                    .any(|b| b);
                    if !others {
                        return Ok(());
                    }
                }
                let keep = keep.or(names.then(|| "names".to_string()));
                if keep.as_deref() == Some("full") && !yes {
                    bail!("{} Give --yes to confirm.", FULL_WARNING);
                }
                set(
                    &env,
                    SetArgs {
                        git,
                        branch,
                        folder,
                        push: flag(push, no_push),
                        keep,
                        refresh,
                        encrypt: flag(encrypt, no_encrypt),
                        yes,
                        from_env,
                        state,
                        config,
                    },
                )
            }
            StorageAction::Accept { yes, target } => accept(&target, yes),
            StorageAction::Sync { target } => sync(&target),
            StorageAction::SignIn { target } => sign_in(&target),
            StorageAction::Probe {
                place,
                json,
                workspace,
            } => probe(&place, json, workspace.as_deref()),
            StorageAction::Connect { place, how, env } => {
                let ws = env.workspace()?;
                connect(
                    Some(ws.root()),
                    Some(ws.env_id().to_string()),
                    &place,
                    &how,
                    None,
                    false,
                )
            }
            StorageAction::Passphrase { action } => match action {
                PassphraseAction::Set {
                    from_env,
                    for_account,
                    target,
                } => passphrase_set(&target, from_env, for_account),
                PassphraseAction::Change { from_env, target } => {
                    passphrase_change(&target, from_env)
                }
                PassphraseAction::Check { target } => passphrase_check(&target),
                PassphraseAction::Forget {
                    for_account,
                    target,
                } => passphrase_forget(&target, for_account),
            },
        },
        HistoryAction::Import { env, state } => import(&env, state),
        HistoryAction::KeepLocal { runs, env, state } => keep_local(&env, state, runs),
    }
}

/// `--x` / `--no-x`: `Some` when one was given.
fn flag(on: bool, off: bool) -> Option<bool> {
    match (on, off) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

fn locate(ws: &Workspace, state: Option<&std::path::Path>) -> Result<Location> {
    history_ui::locate(ws, state).map_err(|e| {
        anyhow::anyhow!(
            "the history settings of environment {} can't be used: {e}",
            ws.env_name()
        )
    })
}

/// A run's time as people read it: US style, this computer's time.
fn when(t: i64) -> String {
    pathwarden_core::time::format_local(t)
}

fn origin_key(o: Origin) -> &'static str {
    match o {
        Origin::Flag => "flag",
        Origin::Config => "config",
        Origin::Default => "default",
    }
}

fn show(env: &Env, state: Option<PathBuf>, json: bool) -> Result<()> {
    let ws = env.workspace()?;
    let loc = locate(&ws, state.as_deref())?;
    let h = history_ui::read(&loc);
    let snap = history_ui::Snapshot {
        history: h,
        location: Err(String::new()),
    };
    let runs = ws.runs();
    let lo = history_ui::local_only(&ws, &runs, &snap);
    let full = pathwarden_ui::run_list::full_runs(&runs, &snap.history, Some(&loc));
    let h = &snap.history;
    let state = pathwarden_ui::settings::load_ws(&ws).config.state;
    let (names, keep) = (state.keeps_names(), state.keep());
    let encryption = history_ui::Encryption::of(&loc);
    let pull = loc.git.is_some().then(|| {
        pathwarden_ui::last_pull::status(
            pathwarden_ui::last_pull::read(&loc.store),
            state.refresh_minutes(),
            pathwarden_core::analyze::now(),
        )
        .with_waiting(pathwarden_ui::shared_runs::waiting_runs(&ws, &loc))
    });
    if json {
        return crate::emit_json(&json!({
            "environment": ws.env_name(),
            "kind": if loc.git.is_some() { "git" } else { "folder" },
            "dir": loc.dir,
            "remote": loc.git.as_ref().map(|g| &g.0),
            "branch": loc.git.as_ref().map(|g| &g.1),
            "origin": origin_key(loc.origin),
            "push": loc.push,
            "records": loc.records(),
            "include_names": names,
            "encryption": {
                "state": encryption.key(),
                "passphrase": match &encryption {
                    history_ui::Encryption::On(Some(pathwarden_core::keystore::Source::Env)) => {
                        Some("environment")
                    }
                    history_ui::Encryption::On(Some(_)) => Some("stored"),
                    history_ui::Encryption::On(None) => Some("not stored"),
                    _ => None,
                },
            },
            "keep": keep.as_str(),
            // The app's pulls: a git history only.
            "refresh_minutes": loc.git.is_some().then(|| state.refresh_minutes()),
            "last_pull": pull.as_ref().map(|s| json!({
                "status": s.kind,
                // Runs recorded here still waiting to be pushed.
                "waiting": s.waiting.len(),
                // The repository wanted a sign-in git couldn't make.
                "sign_in": s.signed_out(),
                "record": s.last,
            })),
            "full_runs": (keep == pathwarden_core::config::Keep::Full).then(|| json!({
                "kept": state.full_runs_kept(),
                // What a full run recorded here keeps: the setting, held
                // to 95 MB on GitHub.
                "max_file_bytes": pathwarden_ui::shared_runs::file_limit(&state, &loc.store),
                "file_mb_set": state.full_run_file_mb(),
                "held_by_github": pathwarden_ui::shared_runs::file_limit_mb(&state, &loc.store).1,
            })),
            "runs": h.points.len(),
            // As the fact: only at "Full runs and settings", else null.
            "open_in_full": pathwarden_ui::run_list::shows_full_runs(keep, &loc.store).then_some(full),
            "latest": h.latest().map(|p| json!({
                "run_id": p.run_id,
                "at": p.at,
                "recorded_by": p.recorded_by,
            })),
            "problem": h.problem,
            "not_in_history": {
                "importable": lo.importable.iter().map(|r| json!({
                    "id": r.id,
                    "environment": r.environment(),
                    "created_at": r.created_at,
                    "source": r.source,
                })).collect::<Vec<_>>(),
                "too_old": lo.too_old.iter().map(|r| json!({
                    "id": r.id,
                    "environment": r.environment(),
                    "created_at": r.created_at,
                    "source": r.source,
                })).collect::<Vec<_>>(),
                "kept_local": lo.kept,
            },
        }));
    }
    let (b, d) = (ui::BOLD, ui::DIM);
    println!(
        "{b}History storage{b:#} of environment {}",
        ui::safe(&ws.env_name())
    );
    let fact = |label: &str, text: &str| {
        let width = 29;
        // The page's words mark code with backticks; plain text here.
        let text = text.replace('`', "");
        let mut lines = crate::help::wrap(&text, crate::help::WIDTH - width - 2).into_iter();
        println!(
            "  {d}{label:<w$}{d:#}{}",
            ui::safe(&lines.next().unwrap_or_default()),
            w = width
        );
        for l in lines {
            println!("  {:w$}{}", "", ui::safe(&l), w = width);
        }
    };
    fact(label::WHERE, &history_ui::where_words(&loc));
    fact(label::SET_BY, history_ui::origin_words(loc.origin, true));
    fact(label::RECORDED, &history_ui::recorded_words(h, when));
    fact(label::RECORDS, history_ui::records_words(&loc));
    fact(label::KEEPS, history_ui::keep_words(keep));
    if keep == pathwarden_core::config::Keep::Full {
        fact(
            label::KEEP_LATEST,
            &pathwarden_ui::settings::full_runs_kept_words(state.full_runs_kept()),
        );
        let (mb, held) = pathwarden_ui::shared_runs::file_limit_mb(&state, &loc.store);
        fact(
            label::FILE_LIMIT,
            &pathwarden_ui::shared_runs::file_limit_words(mb, held),
        );
    }
    if pathwarden_ui::run_list::shows_full_runs(keep, &loc.store) {
        fact(
            label::FULL_RUNS,
            &pathwarden_ui::run_list::full_runs_words(
                &full,
                pathwarden_ui::encryption_ui::locked(&loc, h),
            ),
        );
    }
    fact(
        label::ENCRYPTION,
        &history_ui::encryption_words(&encryption),
    );
    if let Some(s) = &pull {
        fact(
            label::SYNCS,
            &pathwarden_ui::last_pull::every_words(s.minutes),
        );
        fact(label::LAST_SYNC, &s.text());
    }
    if let Some(p) = &h.problem {
        println!("\n{}", ui::safe(p));
    }
    if !lo.importable.is_empty() || !lo.too_old.is_empty() {
        println!("\n{b}Runs kept on this computer only{b:#}");
        if !lo.importable.is_empty() {
            println!(
                "{} can be added in order, oldest first, as if each had been recorded when it was analyzed:",
                pathwarden_core::text::num(lo.importable.len())
            );
            for r in &lo.importable {
                println!(
                    "  {}  {}  {d}{} · {}{d:#}",
                    r.id,
                    ui::safe(&r.environment()),
                    when(r.created_at),
                    ui::safe(&r.source)
                );
            }
            println!(
                "Add them with `pathwarden history import`, or keep them out with `pathwarden history keep-local`."
            );
        }
        if !lo.too_old.is_empty() {
            println!("{}", history_ui::too_old_words(lo.too_old.len()));
            for r in &lo.too_old {
                println!(
                    "  {}  {}  {d}{} · {}{d:#}",
                    r.id,
                    ui::safe(&r.environment()),
                    when(r.created_at),
                    ui::safe(&r.source)
                );
            }
        }
    }
    if loc.git.is_some() {
        println!("\n`pathwarden history storage sync` gets the latest from the repository.");
    }
    Ok(())
}

struct SetArgs {
    git: Option<String>,
    branch: Option<String>,
    folder: Option<String>,
    push: Option<bool>,
    /// `names` or `full`.
    keep: Option<String>,
    /// Sync every N minutes (git).
    refresh: Option<u32>,
    encrypt: Option<bool>,
    yes: bool,
    from_env: bool,
    state: Option<PathBuf>,
    config: Option<PathBuf>,
}

/// What turning encryption on means, said before it is done.
const ENCRYPT_WARNING: &str =
    "Encrypting the history: the contents of every file Pathwarden writes to this folder \
or repository are encrypted with the passphrase (age). Anyone who reads the history then needs the \
passphrase as well as access. File names, run times, sizes and commit times stay visible. The \
workspace on this computer is never encrypted. A lost passphrase can't be recovered: keep a copy \
somewhere safe. Give each history its own passphrase. \
Encrypted files don't diff or compress across versions, so a git repository grows faster. With \
git, older commits keep the files as they were (plain).";

/// What turning it off means.
const DECRYPT_WARNING: &str = "Decrypting the history: every file is written in plain text again, \
readable by anyone who can read this folder or repository. With git, older commits stay \
encrypted. The passphrase is then removed from this computer, which would otherwise refuse the \
plain history; other computers remove theirs with `pathwarden history storage passphrase forget`.";

/// What `--keep full` stores, said before it is confirmed.
const FULL_WARNING: &str =
    "With \"Full runs and settings\", this folder or repository also keeps each run in full \
     (the report, every account, group and computer the collection found, and the attack paths \
     between them, with the user and computer that recorded it) and the environment's shared \
     settings: Tier Zero additions, zones, and accepted risks with the names of the people and \
     computers that accepted them. Anyone who can read it sees them, and anyone who can push to it can change them for every machine \
     that uses it. Encrypting the history (--encrypt) keeps them from anyone without the \
     passphrase; it is encrypted before anything is shared. A history that isn't encrypted \
     needs --encrypt or --no-encrypt (plain text, on purpose).";

fn set(env: &Env, a: SetArgs) -> Result<()> {
    if a.config.is_some() || a.state.is_some() {
        // A server's pathwarden.toml, or a folder: only encryption.
        let Some(on) = a.encrypt else {
            bail!("--config and --state go with --encrypt or --no-encrypt");
        };
        confirmed(on, a.yes)?;
        let target = Target {
            env: env.clone(),
            state: a.state.clone(),
            config: a.config.clone(),
        };
        return set_encryption(&target.locate()?, on, a.from_env);
    }
    let ws = env.workspace()?;
    let loaded = pathwarden_ui::settings::load_ws(&ws);
    if let Some(e) = loaded.error {
        bail!("{} can't be read: {e}", ws.config_path().display());
    }
    let cur = loaded.config.state;
    let other = a.git.is_some()
        || a.branch.is_some()
        || a.folder.is_some()
        || a.push.is_some()
        || a.keep.is_some()
        || a.refresh.is_some();
    if !other && a.encrypt.is_none() {
        bail!("nothing to change: give --git URL, --folder DIR, or an option such as --keep full (see --help)");
    }
    if let Some(on) = a.encrypt {
        confirmed(on, a.yes)?;
    }
    if !other {
        let loc = locate(&ws, None)?;
        return set_encryption(&loc, a.encrypt == Some(true), a.from_env);
    }
    // --folder alone moves the history to a folder; options alone keep it
    // where it is.
    let wants_git = |cur: &pathwarden_core::config::StateConfig| {
        a.git.is_some() || (a.folder.is_none() && cur.backend == StateBackend::Git)
    };
    if !wants_git(&cur) && (a.push.is_some() || a.branch.is_some() || a.refresh.is_some()) {
        bail!("--push, --no-push, --branch and --refresh go with --git, or with a history already in a git repository");
    }
    let mut new_checkout = false;
    // Made from [state] as it is when the save holds the lock.
    let make = |cur: &pathwarden_core::config::StateConfig| -> Result<StateEdit, String> {
        let git = wants_git(cur);
        let was_git = cur.backend == StateBackend::Git;
        if !git && (a.push.is_some() || a.branch.is_some() || a.refresh.is_some()) {
            return Err("--push, --no-push, --branch and --refresh go with --git, or with a history already in a git repository".into());
        }
        new_checkout = git && !was_git && a.folder.is_none();
        Ok(StateEdit {
            backend: if git { "git" } else { "local" }.into(),
            path: a.folder.clone().or(cur.path.clone()),
            remote: a.git.clone().or(cur.remote.clone()),
            branch: a.branch.clone().or(cur.branch.clone()),
            include_names: cur.include_names,
            push: a.push,
            keep: a.keep.clone(),
            refresh: a.refresh,
        })
    };
    let saved = |loc: &Location| {
        println!(
            "Saved in {}. {}.",
            ws.config_path().display(),
            ui::safe(&history_ui::where_words(loc))
        );
        println!("{}", history_ui::records_words(loc));
        if let Some(n) = a.refresh {
            println!(
                "The app pulls every {} while it is open, and when it opens.",
                pathwarden_ui::last_pull::minutes_words(n)
            );
        }
    };
    // Start a new shared history where one is already: refused, with how
    // to connect to it instead. Nothing is saved or encrypted.
    if let Ok(preview) = make_preview(&cur, &a) {
        if let Err(r) =
            pathwarden_ui::settings::check_new_place(&ws, &preview, a.encrypt == Some(true))
        {
            if r.found {
                let how = match &preview.remote {
                    Some(url) if preview.backend == "git" => format!(
                        "pathwarden history storage connect --git {}{}",
                        ui::safe(url),
                        preview
                            .branch
                            .as_deref()
                            .map(|b| format!(" --branch {}", ui::safe(b)))
                            .unwrap_or_default()
                    ),
                    _ => "pathwarden history storage connect --folder DIR".into(),
                };
                bail!(
                    "{}\nConnect to it with `{how}` (or `pathwarden env create --from-git` for a new environment).",
                    r.sentence()
                );
            }
            bail!("{}", r.sentence());
        }
    }
    if a.encrypt == Some(true) {
        // Encrypted before anything is shared: [state] is saved, the
        // history encrypted, and only then are the settings shared.
        let ((), shared) = pathwarden_ui::settings::update_state_encrypting(&ws, make, || {
            let loc = locate(&ws, None).map_err(|e| format!("{e:#}"))?;
            saved(&loc);
            if loc.store.is_encrypted() {
                println!("The history is encrypted already.");
                return Ok(());
            }
            set_encryption(&loc, true, a.from_env).map_err(|e| format!("{e:#}"))
        })
        .map_err(|e| checkout_error(new_checkout, e))?;
        if let Some(n) = shared {
            println!("{}", ui::safe(&n.text));
        }
        return Ok(());
    }
    // --no-encrypt: kept in plain text on purpose, shared settings too.
    let shared = pathwarden_ui::settings::update_state_in(&ws, a.encrypt == Some(false), make)
        .map_err(|e| checkout_error(new_checkout, e))?;
    let loc = locate(&ws, None)?;
    saved(&loc);
    if let Some(s) = shared {
        println!("{}", ui::safe(&s));
    }
    if a.encrypt == Some(false) {
        if loc.store.is_encrypted() {
            set_encryption(&loc, false, a.from_env)?;
        } else {
            // Plain already: what --no-encrypt asks for. (Alone, it also
            // accepts a history decrypted elsewhere, above.)
            println!("The history stays in plain text.");
        }
    }
    Ok(())
}

/// The [state] `set` would save, made from [state] as it is now: for
/// checking the place before anything is saved.
fn make_preview(
    cur: &pathwarden_core::config::StateConfig,
    a: &SetArgs,
) -> Result<StateEdit, String> {
    let git = a.git.is_some() || (a.folder.is_none() && cur.backend == StateBackend::Git);
    Ok(StateEdit {
        backend: if git { "git" } else { "local" }.into(),
        path: a.folder.clone().or(cur.path.clone()),
        remote: a.git.clone().or(cur.remote.clone()),
        branch: a.branch.clone().or(cur.branch.clone()),
        include_names: cur.include_names,
        push: a.push,
        keep: a.keep.clone(),
        refresh: a.refresh,
    })
}

/// A save's error, with the hint for a new checkout in a folder that isn't
/// a git working copy.
fn checkout_error(new_checkout: bool, e: String) -> anyhow::Error {
    if new_checkout && e.contains("not a git working copy") {
        anyhow::anyhow!("{e} Give it with --folder DIR.")
    } else {
        anyhow::Error::msg(e)
    }
}

/// Prints what turning encryption on (`on`) or off means and stops, unless
/// `--yes`.
fn confirmed(on: bool, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    eprintln!("{}", if on { ENCRYPT_WARNING } else { DECRYPT_WARNING });
    bail!(
        "nothing was changed: run again with --yes to {} the history",
        if on { "encrypt" } else { "decrypt" }
    )
}

/// `set --encrypt` / `--no-encrypt`, after the warning was accepted.
/// `config`: the pathwarden.toml whose `[state] encrypted` records it (none
/// with `--state`, a folder the config doesn't name).
fn set_encryption(loc: &Location, on: bool, from_env: bool) -> Result<()> {
    use pathwarden_core::{crypt, keystore};
    // `[state] encrypted` in the pathwarden.toml that names this history
    // (none for a `--state` folder it doesn't name).
    let record = |on: bool| -> Result<()> {
        if let Some(path) = loc.store.flag_config() {
            pathwarden_core::config_edit::set_state_encrypted_in(path, on)
                .map_err(anyhow::Error::msg)?;
        }
        Ok(())
    };
    if !on {
        let done = loc.store.decrypt(loc.push)?;
        record(false)?;
        for n in &done.notes {
            eprintln!("Warning: {}", ui::safe_text(n));
        }
        match &done.accepted {
            Some(by) => println!(
                "Accepted the history as no longer encrypted ({}). Nothing was written.",
                ui::safe_text(by)
            ),
            None => println!(
                "Decrypted {} of the history{}: they are plain text from now on.",
                pathwarden_core::text::count(done.files, "file", "files"),
                committed_words(loc, &done)
            ),
        }
        return Ok(());
    }
    // The passphrase: --from-env, else the one this computer has, else
    // typed (or piped) and then stored here.
    let (pass, store_after) = if from_env {
        (crate::passphrase::from_env(keystore::ENV_VAR)?, false)
    } else if let Some((p, source)) = crypt::passphrase_for(&loc.dir)? {
        eprintln!("Using the passphrase {}.", source.words());
        (p, false)
    } else {
        (
            crate::passphrase::new(None, "A passphrase for the history")?,
            true,
        )
    };
    let done = loc.store.encrypt(&pass, loc.push).map_err(|e| {
        // The core says it without a command; the terminal adds one.
        if format!("{e:#}").contains(pathwarden_core::store::ENCRYPTED_ALREADY) {
            anyhow::anyhow!(
                "{} `pathwarden history storage passphrase change` changes its passphrase.",
                pathwarden_core::store::ENCRYPTED_ALREADY
            )
        } else {
            e
        }
    })?;
    record(true)?;
    for n in &done.notes {
        eprintln!("Warning: {}", ui::safe_text(n));
    }
    println!(
        "Encrypted {} of the history{}.",
        pathwarden_core::text::count(done.files, "file", "files"),
        committed_words(loc, &done)
    );
    if store_after {
        let place = keystore::store(&loc.dir, &pass)?;
        println!(
            "The passphrase is stored on this computer, {}.",
            place.place()
        );
    }
    println!(
        "Every computer and account that reads or records this history needs the passphrase: \
         `pathwarden history storage passphrase set` there (`--for-account` for a scheduled \
         task's account). A lost passphrase can't be recovered."
    );
    Ok(())
}

/// ", in one commit, pushed" and the like.
fn committed_words(loc: &Location, done: &pathwarden_core::store::Converted) -> &'static str {
    match (loc.git.is_some(), done.pushed) {
        (false, _) => "",
        (true, true) => " in one commit, pushed",
        (true, false) => " in one commit",
    }
}

fn passphrase_set(target: &Target, from_env: bool, for_account: Option<String>) -> Result<()> {
    use pathwarden_core::{crypt, keystore};
    let loc = target.locate()?;
    // A passphrase for a plain history would make this computer refuse it.
    if loc.store.encryption()?.is_none() {
        bail!(
            "the history in {} isn't encrypted, so there is no passphrase to store{}; \
             `pathwarden history storage set --encrypt --yes` encrypts it and stores the \
             passphrase it asks for",
            loc.dir.display(),
            if loc.git.is_some() {
                " (if another computer encrypted it, get the latest first: `pathwarden history \
                 storage sync`)"
            } else {
                ""
            }
        );
    }
    let pass = crate::passphrase::new(
        from_env.then_some(keystore::ENV_VAR),
        "The history's passphrase",
    )?;
    if !crypt::opens(&loc.dir, &pass)? {
        return Err(crypt::CryptError::WrongPassphrase(keystore::Source::Given).into());
    }
    match for_account {
        Some(account) => {
            let file = keystore::store_for_account(&loc.dir, &account, &pass)?;
            println!(
                "Stored for {} in {}: only that account can open it (DPAPI-NG).",
                ui::safe(&account),
                file.display()
            );
        }
        None => {
            let place = keystore::store(&loc.dir, &pass)?;
            println!(
                "Stored on this computer for this account, {}.",
                place.place()
            );
        }
    }
    Ok(())
}

fn passphrase_change(target: &Target, from_env: bool) -> Result<()> {
    use pathwarden_core::{crypt, keystore};
    let loc = target.locate()?;
    if loc.store.encryption()?.is_none() {
        bail!(
            "the history isn't encrypted; `pathwarden history storage set --encrypt --yes` turns \
             encryption on"
        );
    }
    // The current passphrase: the one this computer has, else typed.
    if crypt::passphrase_for(&loc.dir)?.is_none() {
        let Some(current) = crate::passphrase::ask("The current passphrase")? else {
            return Err(crypt::CryptError::NeedPassphrase.into());
        };
        crypt::give_passphrase(&loc.dir, current);
    }
    pathwarden_core::store::check_readable(&loc.dir)?;
    let new = crate::passphrase::new(from_env.then_some(NEW_ENV_VAR), "The new passphrase")?;
    let stored = keystore::stored_here(&loc.dir)?;
    let done = loc.store.change_passphrase(&new, loc.push)?;
    for n in &done.notes {
        eprintln!("Warning: {}", ui::safe_text(n));
    }
    println!(
        "Encrypted {} again with the new passphrase{}.",
        pathwarden_core::text::count(done.files, "file", "files"),
        committed_words(&loc, &done)
    );
    match stored {
        Some(keystore::Source::Store) | Some(keystore::Source::File(_)) => {
            let place = keystore::store(&loc.dir, &new)?;
            println!(
                "The new passphrase is stored on this computer, {}.",
                place.place()
            );
        }
        _ => {}
    }
    if loc.git.is_some() {
        println!("Older git history still opens with the old passphrase.");
    }
    println!(
        "Other computers and accounts (a scheduled task's) need the new passphrase: \
         `pathwarden history storage passphrase set` there."
    );
    Ok(())
}

fn passphrase_check(target: &Target) -> Result<()> {
    use pathwarden_core::crypt;
    let loc = target.locate()?;
    if loc.store.encryption()?.is_none() {
        println!("The history isn't encrypted: no passphrase is needed.");
        return Ok(());
    }
    let (pass, source) = match crypt::passphrase_for(&loc.dir)? {
        Some(p) => p,
        None => match crate::passphrase::ask("The history's passphrase")? {
            Some(p) => (p, pathwarden_core::keystore::Source::Given),
            None => return Err(crypt::CryptError::NeedPassphrase.into()),
        },
    };
    if crypt::opens(&loc.dir, &pass)? {
        println!("The passphrase ({}) opens this history.", source.words());
        Ok(())
    } else {
        Err(crypt::CryptError::WrongPassphrase(source).into())
    }
}

/// `history storage accept`: [`pathwarden_core::store::accept_history`]
/// after saying what it does, and asking on a terminal unless `--yes`.
fn accept(target: &Target, yes: bool) -> Result<()> {
    use pathwarden_core::store;
    use std::io::{BufRead, IsTerminal, Write};
    let loc = target.locate()?;
    // Only past a refusal reading the history actually meets: never
    // resets the records of a history nothing is wrong with.
    let Some(refused) = store::find_refusal(&loc.dir)? else {
        println!("{}", store::NOTHING_REFUSED);
        return Ok(());
    };
    println!("{refused}");
    println!("{}", store::ACCEPT_WORDS);
    if !yes {
        let terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
        if !terminal {
            bail!("nothing was changed: confirm on a terminal, or pass --yes to accept it without asking");
        }
        eprint!("Accept the history as it is? [y/N]: ");
        let _ = std::io::stderr().flush();
        let mut typed = String::new();
        std::io::stdin().lock().read_line(&mut typed)?;
        if !matches!(typed.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            bail!("nothing was changed");
        }
    }
    let reset = store::accept_history(&loc.dir)?;
    println!(
        "Accepted the history in {} as it is. Reset this computer's {}:",
        loc.dir.display(),
        if reset.len() == 1 {
            "record"
        } else {
            "records"
        }
    );
    for r in reset {
        println!("  {}", r.display());
    }
    Ok(())
}

fn passphrase_forget(target: &Target, for_account: Option<String>) -> Result<()> {
    use pathwarden_core::keystore;
    let loc = target.locate()?;
    if let Some(account) = for_account {
        match keystore::forget_for_account(&loc.dir, &account)? {
            Some(file) => println!("Removed {}.", file.display()),
            None => println!(
                "Nothing was stored for {} for this history.",
                ui::safe(&account)
            ),
        }
        return Ok(());
    }
    let removed = keystore::forget(&loc.dir)?;
    if removed.is_empty() {
        println!("Nothing was stored on this computer for this history.");
    } else {
        println!("Removed {}.", removed.join(" and "));
    }
    if keystore::from_env()?.is_some() {
        println!("{} is still set in this environment.", keystore::ENV_VAR);
    }
    Ok(())
}

/// The git history of `target`, and the environment whose settings are
/// shared (none when -c names a file).
fn git_target(target: &Target, what: &str) -> Result<(Location, Option<Workspace>)> {
    let loc = target.locate()?;
    if loc.git.is_none() {
        bail!(
            "the history in {} is a folder, not a git repository: there is nothing to {what}",
            loc.dir.display()
        );
    }
    let ws = match &target.config {
        None => Some(target.env.workspace()?),
        Some(_) => None,
    };
    Ok((loc, ws))
}

/// What the sync brought besides its line: the notes as warnings, and
/// what loading full runs said.
fn print_pulled(p: &history_ui::Pulled) {
    if let Some(note) = &p.notes {
        eprintln!("Warning: {}", ui::safe_text(note));
    }
    if let Some(loaded) = &p.loaded {
        println!("{}", ui::safe_text(loaded));
    }
}

/// A sync that failed, in words: a sign-in git couldn't make says how to
/// sign in, or that git here has no credential helper.
pub(crate) fn sync_failed(message: &str, dir: Option<&std::path::Path>) -> anyhow::Error {
    match sign_in_words(message, dir) {
        Some(w) => anyhow::anyhow!("{w}"),
        None => anyhow::anyhow!("{message}"),
    }
}

/// When git's `message` says the repository wanted a sign-in git couldn't
/// make: what to do, and what git said (the working copy `dir`, when
/// there is one, may name its own credential helper).
pub(crate) fn sign_in_words(message: &str, dir: Option<&std::path::Path>) -> Option<String> {
    use pathwarden_core::connect;
    if !connect::is_sign_in(message) {
        return None;
    }
    Some(sign_in_words_for(
        connect::no_helper(message, dir),
        connect::refused(message),
        message,
    ))
}

/// [`sign_in_words`] for a sign-in already sorted: `no_helper` (git here
/// has no credential helper), `refused` (the repository refused the
/// account git gave), with what git said.
pub(crate) fn sign_in_words_for(no_helper: bool, refused: bool, message: &str) -> String {
    let said = pathwarden_core::store::redact_url(message);
    if no_helper {
        format!(
            "this computer isn't signed in to the repository, and git on this computer has no credential helper (`git config --get credential.helper` is empty). Install Git for Windows with Git Credential Manager, or run `git config --global credential.helper manager`, then `pathwarden history storage sign-in`. Git said: {said}"
        )
    } else if refused {
        format!(
            "the repository refused this computer's sign-in. Run `pathwarden history storage sign-in` as the account that runs Pathwarden (for a scheduled task, the task's account) to sign in with an account that can read it. Git said: {said}"
        )
    } else {
        format!(
            "this computer isn't signed in to the repository. Run `pathwarden history storage sign-in` as the account that runs Pathwarden (for a scheduled task, the task's account). Git said: {said}"
        )
    }
}

fn sync(target: &Target) -> Result<()> {
    let (loc, ws) = git_target(target, "sync")?;
    let p = history_ui::refresh_detail(
        ws.as_ref(),
        &loc,
        false,
        pathwarden_core::settings_sync::lock_wait(),
        "command line",
        &mut |_| {},
    )
    .map_err(|e| match e {
        history_ui::PullError::Failed(m) => sync_failed(&m, Some(&loc.dir)),
        history_ui::PullError::Busy(m) => anyhow::anyhow!("{m}"),
    })?;
    print_pulled(&p);
    println!("Synced: {}.", p.synced_words());
    // What the history holds now.
    println!(
        "{}.",
        history_ui::recorded_words(&history_ui::read(&loc), when).trim_end_matches('.')
    );
    Ok(())
}

fn sign_in(target: &Target) -> Result<()> {
    use pathwarden_ui::sign_in::{NotSignedIn, Outcome};
    let (loc, ws) = git_target(target, "sign in to")?;
    let remote = loc.git.as_ref().map(|g| g.0.clone()).unwrap_or_default();
    match pathwarden_ui::sign_in::sign_in(ws.as_ref(), &loc, false) {
        Ok(p) => {
            print_pulled(&p);
            println!("Signed in to {} and synced.", ui::safe(&remote));
            Ok(())
        }
        Err(NotSignedIn::Busy(m)) => bail!("{m}"),
        Err(NotSignedIn::Failed(Outcome::Cancelled, m)) => bail!(
            "Sign-in was canceled. Run `pathwarden history storage sign-in` again to sign in. Git said: {}",
            pathwarden_core::store::redact_url(&m)
        ),
        Err(NotSignedIn::Failed(Outcome::Failed, m))
            if pathwarden_core::connect::no_helper(&m, Some(&loc.dir)) =>
        {
            Err(sync_failed(&m, Some(&loc.dir)))
        }
        Err(NotSignedIn::Failed(Outcome::Failed, m)) => bail!(
            "Sign-in didn't work. Check that the account can read the repository, then run `pathwarden history storage sign-in` again. Git said: {}",
            pathwarden_core::store::redact_url(&m)
        ),
        Err(NotSignedIn::Failed(_, m)) => bail!(
            "Couldn't sync with the repository. Git said: {}",
            pathwarden_core::store::redact_url(&m)
        ),
    }
}

fn import(env: &Env, state: Option<PathBuf>) -> Result<()> {
    let ws = env.workspace()?;
    let (n, notes) = history_ui::import(&ws, state.as_deref()).map_err(anyhow::Error::msg)?;
    for note in &notes {
        eprintln!("Warning: {}", ui::safe_text(note));
    }
    if n == 0 {
        println!(
            "Nothing to import: every run in the app that can be added is in the run history."
        );
    } else {
        let loc = locate(&ws, state.as_deref())?;
        println!(
            "Imported {} into the run history ({}).",
            pathwarden_core::text::count(n, "run", "runs"),
            ui::safe(&history_ui::where_words(&loc))
        );
    }
    Ok(())
}

fn keep_local(env: &Env, state: Option<PathBuf>, runs: Vec<String>) -> Result<()> {
    let ws = env.workspace()?;
    let loc = locate(&ws, state.as_deref())?;
    let snap = history_ui::Snapshot {
        history: history_ui::read(&loc),
        location: Err(String::new()),
    };
    let all = ws.runs();
    let lo = history_ui::local_only(&ws, &all, &snap);
    let offered: Vec<&str> = lo
        .importable
        .iter()
        .chain(&lo.too_old)
        .map(|r| r.id.as_str())
        .collect();
    let ids: Vec<String> = if runs.is_empty() {
        lo.importable.iter().map(|r| r.id.clone()).collect()
    } else {
        for r in &runs {
            if !offered.contains(&r.as_str()) {
                bail!(
                    "{} isn't a run of environment {} kept on this computer only (see `pathwarden history storage show`).",
                    ui::safe(r),
                    ws.env_name()
                );
            }
        }
        runs
    };
    if ids.is_empty() {
        if lo.too_old.is_empty() {
            println!("Nothing to keep local: every run in the app is in the run history or kept local already.");
        } else {
            println!(
                "Nothing that could be imported is left to keep local. {} Give their IDs (`pathwarden history storage show`) to keep them out of the list.",
                history_ui::too_old_words(lo.too_old.len())
            );
        }
        return Ok(());
    }
    history_ui::keep_local(&ws, &ids).map_err(anyhow::Error::msg)?;
    println!(
        "Kept {} local only: {} in the app and out of the run history.",
        pathwarden_core::text::count(ids.len(), "run", "runs"),
        if ids.len() == 1 {
            "it stays"
        } else {
            "they stay"
        }
    );
    Ok(())
}

// ------------------------------------------------- a shared history

/// Removes a probe's clone unless it was connected (or kept on purpose).
struct Discard<'a> {
    root: &'a std::path::Path,
    token: Option<String>,
}

impl Drop for Discard<'_> {
    fn drop(&mut self) {
        if let Some(t) = self.token.take() {
            pathwarden_ui::connect::discard(self.root, &t);
        }
    }
}

fn workspace_root(dir: Option<&std::path::Path>) -> Result<PathBuf> {
    let root = match dir {
        Some(d) => d.to_path_buf(),
        None => pathwarden_ui::workspace::default_dir()?,
    };
    // A new computer may have no workspace yet: it is made as the app makes it.
    Workspace::open(&root)?;
    Ok(root)
}

/// A refusal at the first step, for the terminal: the sentence, then what
/// git said.
fn refused(r: &pathwarden_ui::connect::Refused) -> anyhow::Error {
    match r.detail() {
        Some(d) => anyhow::anyhow!("{}\nGit said: {}", r.sentence(), ui::safe_text(d)),
        None => anyhow::anyhow!("{}", r.sentence()),
    }
}

/// The facts a probe found, as the page's What it holds.
fn print_found(found: &pathwarden_core::connect::Found) {
    let d = ui::DIM;
    println!("This is a Pathwarden history.");
    for (label, text, sub) in found.facts(when) {
        println!("  {d}{label:<16}{d:#}{}", ui::safe(&text));
        if let Some(sub) = sub {
            println!("  {:16}{d}{sub}{d:#}", "");
        }
    }
}

/// `pathwarden history storage probe`.
fn probe(place: &Place, json: bool, workspace: Option<&std::path::Path>) -> Result<()> {
    use pathwarden_ui::connect as shared;
    let root = workspace_root(workspace)?;
    let w = place.place();
    let session = match shared::start(&root, &w, None) {
        Ok(s) => s,
        Err(r) => {
            if json {
                crate::emit_json(&json!({
                    "history": false,
                    "problem": r.key(),
                    "message": r.sentence(),
                    "detail": r.detail(),
                }))?;
            }
            return Err(refused(&r));
        }
    };
    let _discard = Discard {
        root: &root,
        token: Some(session.token.clone()),
    };
    let found = session
        .found()
        .map_err(|p| anyhow::anyhow!("{}", p.sentence()))?;
    let access = session.meta.access();
    if json {
        return crate::emit_json(&json!({
            "history": true,
            "kind": session.meta.kind,
            "remote": session.meta.url.as_deref().map(pathwarden_core::store::redact_url),
            "branch": session.meta.branch,
            "folder": session.meta.folder,
            "encrypted": found.encrypted,
            "keep": found.keep.as_str(),
            "runs": found.runs,
            "latest": found.latest,
            "push_access": access.as_ref().map(|a| a.key()),
        }));
    }
    if let (Some(u), Some(b)) = (&session.meta.url, &session.meta.branch) {
        println!(
            "A git repository: {}, branch {}.",
            ui::safe(&pathwarden_core::store::redact_url(u)),
            ui::safe(b)
        );
    } else if let Some(f) = &session.meta.folder {
        println!("A shared folder: {}.", ui::safe(f));
    }
    print_found(&found);
    if let Some(a) = &access {
        println!("{}", a.sentence());
    }
    println!("Nothing was saved or pushed. `pathwarden env create --from-git URL` connects a new environment to it.");
    Ok(())
}

/// `pathwarden history storage connect` (`env`: the environment, which
/// must have no runs of its own) and `pathwarden env create --from-git`
/// (`env` none: a new environment, named `name` or after the history).
pub(crate) fn connect(
    workspace: Option<&std::path::Path>,
    env: Option<String>,
    place: &Place,
    how: &ConnectHow,
    name: Option<&str>,
    make_current: bool,
) -> Result<()> {
    use pathwarden_core::connect as core;
    use pathwarden_core::keystore;
    use pathwarden_ui::connect as shared;
    let root = workspace_root(workspace)?;
    let w = place.place();
    // An environment with runs of its own keeps them: a new one is made
    // for the shared history.
    if let Some(id) = &env {
        let ws = Workspace::open(&root)?.in_env(id);
        let n = shared::own_runs(&ws, None);
        if n > 0 {
            let (lead, rest) = core::own_runs(&ws.env_name(), n);
            bail!(
                "{lead} {rest}\nConnect the shared history to a new environment: `pathwarden env create --from-git URL` (or --from-folder DIR)."
            );
        }
    }
    let mut session = shared::start(&root, &w, env.as_deref()).map_err(|r| refused(&r))?;
    let mut discard = Discard {
        root: &root,
        token: Some(session.token.clone()),
    };
    let found = session
        .found()
        .map_err(|p| anyhow::anyhow!("{}", p.sentence()))?;
    print_found(&found);
    // The passphrase: PATHWARDEN_HISTORY_PASSPHRASE, else one this
    // computer keeps (a history used here before, as the app finds it),
    // else typed (and then remembered here); never asked without a
    // terminal.
    let pass = if found.encrypted {
        let ask = || -> Result<(pathwarden_core::crypt::SecretString, bool)> {
            match crate::passphrase::ask("The history's passphrase")? {
                Some(p) => Ok((p, true)),
                None => bail!(
                    "This history is encrypted. Give its passphrase in {}, or run this at a terminal to type it.",
                    keystore::ENV_VAR
                ),
            }
        };
        use pathwarden_core::crypt::{known_passphrase, Known};
        let (p, remember) = match known_passphrase(&found.dir)? {
            // Kept here for another history: said, as the app says it,
            // and remembered for this one too (the app's box starts ticked).
            Known::Opens(p, keystore::Source::Another) => {
                println!("{}", core::ANOTHER_PASSPHRASE);
                (p, true)
            }
            Known::Opens(p, source) => {
                if source != keystore::Source::Env {
                    println!("The history opens with {}.", source.words());
                }
                (p, source == keystore::Source::Store)
            }
            Known::Wrong(keystore::Source::Env) => {
                bail!(
                    "{} ({})",
                    core::WRONG_PASSPHRASE,
                    keystore::Source::Env.words()
                )
            }
            Known::Wrong(source) => {
                eprintln!("{} ({})", core::WRONG_PASSPHRASE, source.words());
                ask()?
            }
            Known::Missing => {
                // Kept before 0.2, so not tried here: said once.
                if keystore::kept_without_key_file() {
                    eprintln!("{}", core::OLD_PASSPHRASES);
                }
                ask()?
            }
        };
        shared::open(&mut session, p.clone(), remember).map_err(anyhow::Error::msg)?;
        Some(p)
    } else {
        None
    };
    let access = session.meta.access();
    let push = match (how.push, how.read_only, &access) {
        (_, true, _) => false,
        (true, _, Some(core::Access::No { .. })) => bail!(
            "{} Leave out --push to connect read only.",
            core::CANNOT_PUSH
        ),
        (true, _, _) => true,
        _ => access.as_ref().is_some_and(core::Access::can_push),
    };
    if let Some(a) = &access {
        println!("{}", a.sentence());
    }
    let contents = core::contents(&found.dir);
    let name = match name {
        Some(n) => n.to_string(),
        None => shared::suggested_name(&root, &contents, env.as_deref()),
    };
    let choices = shared::Choices {
        name,
        push,
        refresh: how
            .refresh
            .unwrap_or(pathwarden_core::config::DEFAULT_REFRESH_MINUTES),
        remember: None,
    };
    let done =
        shared::connect(&root, &session, &choices, pass, false).map_err(anyhow::Error::msg)?;
    discard.token = None;
    if make_current {
        pathwarden_ui::environments::make_current(&root, &done.env_id)
            .map_err(anyhow::Error::msg)?;
    }
    for n in &done.notes {
        eprintln!("Warning: {}", ui::safe_text(n));
    }
    println!(
        "Connected environment {} (ID {}){}.",
        ui::safe(&done.env_name),
        done.env_id,
        if make_current {
            "; the app now opens in it"
        } else {
            ""
        }
    );
    if done.git && !done.push {
        println!("{}", core::READ_ONLY_WORDS);
    }
    println!("{}", done.words());
    Ok(())
}
