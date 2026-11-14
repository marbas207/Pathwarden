//! `pathwarden schedule`: writes the files to collect and analyze every
//! night, the same ones the UI's Automate > Schedule page shows, from the
//! same code (`pathwarden_ui::collect::Target`). It only writes files: an
//! administrator copies them to the server and runs them. Nothing is
//! registered and no permission is changed here.

use std::path::{Path, PathBuf};

use anstream::println;
use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use pathwarden_ui::collect::{plain_text, ScheduleParams, ScheduleSpec, Target};

use crate::help;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Os {
    /// A PowerShell script and a scheduled task that runs as a gMSA.
    #[value(help = "A PowerShell script and a scheduled task that runs as a gMSA.")]
    Windows,
    /// A shell script, a systemd service and a timer.
    #[value(help = "A shell script, a systemd service and a timer.")]
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Scope {
    /// Quick (directory only): users, groups, computers, ACLs, GPOs and
    /// trusts from a domain controller.
    #[value(
        help = "Quick (directory only): users, groups, computers, ACLs, GPOs and trusts from a domain controller."
    )]
    DcOnly,
    /// Full: also sessions and local groups from every computer.
    #[value(help = "Full: also sessions and local groups from every computer.")]
    All,
}

#[derive(Args)]
#[command(after_help = "\
Writes the files into --output and prints what to do with them, in order. It
never registers a task or timer and never changes permissions: an
administrator copies the files to the server and runs them.

Windows: run.ps1, check-gmsa.ps1, setup-folder.ps1, register-task.ps1 and
test-task.ps1. Linux: run.sh, pathwarden.service, pathwarden.timer, setup.sh
and test.sh; with --env the units are pathwarden-<id>.service and .timer.

Only --os defaults to this computer; nothing else is detected, so the files
are the same from any computer.

Examples:
  pathwarden schedule --domain scale.local --server dc01.scale.local \\
      --folder C:\\Pathwarden --account 'SCALE\\svc-pathwarden$' --at 02:00 --output .\\schedule
  pathwarden schedule --os linux --domain scale.local --user svc-pathwarden --output ./schedule")]
pub struct ScheduleArgs {
    /// The server's system (default: this computer's).
    #[arg(long, value_enum)]
    os: Option<Os>,
    /// The domain to collect; repeat it or separate with commas for more
    /// domains of a forest (the first is the one --server serves).
    #[arg(
        long = "domain",
        value_name = "DOMAIN",
        required = true,
        value_delimiter = ','
    )]
    domains: Vec<String>,
    /// A domain controller of the first domain (default: one DNS finds).
    #[arg(long, value_name = "HOST")]
    server: Option<String>,
    /// Windows: connect with LDAPS (Linux always does, so it is an error
    /// there).
    #[arg(long)]
    ldaps: bool,
    /// What to collect.
    #[arg(long, value_enum, default_value = "dc-only")]
    scope: Scope,
    /// Windows: collect with SharpHound (SharpHound.exe next to pathwarden.exe);
    /// --scope all always does.
    #[arg(long)]
    sharphound: bool,
    /// Where Pathwarden lives on the server (default: C:\Pathwarden or
    /// /opt/pathwarden).
    #[arg(long, value_name = "DIR")]
    folder: Option<String>,
    /// Windows: the gMSA the task runs as, DOMAIN\name$ (default: the first
    /// label of the first domain in upper case, so scale.local gives
    /// SCALE\svc-pathwarden$; pass it when the NetBIOS name differs).
    #[arg(long, value_name = "ACCOUNT")]
    account: Option<String>,
    /// Linux: the account the job signs in to the domain as (default:
    /// svc-pathwarden).
    #[arg(long, value_name = "USER")]
    user: Option<String>,
    /// The time of day to run, HH:MM.
    #[arg(long, value_name = "HH:MM", default_value = "02:00")]
    at: String,
    /// For an environment of the app's workspace (its name or ID): its own
    /// task or timer name and folders.
    #[arg(long, value_name = "NAME")]
    env: Option<String>,
    /// The app's workspace --env is in (default: the one `pathwarden ui`
    /// uses).
    #[arg(long = "workspace", value_name = "DIR", requires = "env")]
    env_workspace: Option<PathBuf>,
    /// The folder to write the files into (created if missing).
    #[arg(long = "output", short = 'o', alias = "out", value_name = "DIR")]
    out: PathBuf,
    /// Replace files that are already in --output.
    #[arg(long)]
    force: bool,
}

impl ScheduleArgs {
    /// The page's form values and the collection to repeat.
    fn target(&self, env: Option<String>) -> (Target, Vec<String>) {
        let p = ScheduleParams {
            run: None,
            os: self.os.map(|os| match os {
                Os::Windows => "windows".to_string(),
                Os::Linux => "linux".to_string(),
            }),
            folder: self.folder.clone(),
            account: self.account.clone(),
            at: Some(self.at.clone()),
            user: self.user.clone(),
        };
        let spec = ScheduleSpec {
            domains: self.domains.clone(),
            server: self.server.clone(),
            ldaps: self.ldaps,
            sharphound: self.sharphound,
            full: self.scope == Scope::All,
            env,
        };
        Target::for_command_line(&p, &spec)
    }
}

pub fn schedule_cmd(args: ScheduleArgs) -> Result<()> {
    let env = match &args.env {
        Some(name) => {
            Some(pathwarden_ui::environments::cli_paths(args.env_workspace.as_deref(), name)?.id)
        }
        None => None,
    };
    let (target, errors) = args.target(env);
    if !errors.is_empty() {
        bail!("{}", errors.join("\n       "));
    }
    let files = target.files();
    write_files(&args.out, &files, args.force)?;

    println!(
        "Wrote {} files to {} for a {} server.",
        files.len(),
        args.out.display(),
        if target.linux { "Linux" } else { "Windows" }
    );
    for note in &target.notes {
        println!();
        print_wrapped("Note: ", &plain_text(note));
    }
    for (n, step) in target.steps().iter().enumerate() {
        println!();
        println!("{}. {}", n + 1, step.title);
        print_wrapped("   ", &plain_text(&step.text));
        for b in &step.blocks {
            // The commands are written without a shebang, as the page
            // shows them to paste: say how to run them.
            match b.file.as_str() {
                "setup.sh" => println!("   → setup.sh (run it with `sudo sh setup.sh`)"),
                "test.sh" => println!("   → test.sh (run it with `sh test.sh`)"),
                file => println!("   → {file}"),
            }
        }
    }
    Ok(())
}

/// Writes every file, or none: an existing file stops it unless `force`.
fn write_files(out: &Path, files: &[(String, String)], force: bool) -> Result<()> {
    if !force {
        let there: Vec<&str> = files
            .iter()
            .filter(|(name, _)| out.join(name).exists())
            .map(|(name, _)| name.as_str())
            .collect();
        if !there.is_empty() {
            bail!(
                "{} already has {}. Use --force to replace them.",
                out.display(),
                there.join(", ")
            );
        }
    }
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    for (name, text) in files {
        let path = out.join(name);
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

/// `text` wrapped to the help's width, the first line after `first` and
/// the rest indented as far.
fn print_wrapped(first: &str, text: &str) {
    let indent = " ".repeat(first.len());
    for (i, line) in help::wrap(text, help::WIDTH - first.len())
        .into_iter()
        .enumerate()
    {
        println!("{}{line}", if i == 0 { first } else { &indent });
    }
}
