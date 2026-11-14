//! `pathwarden evidence`: a signed, self-contained evidence pack for
//! auditors, insurers and customers: "finding X was fixed, shown by the
//! collection of date Y", which anyone can check without trusting the
//! person who hands it over.
//!
//! - `pathwarden evidence -i <collection>` retests (like `pathwarden
//!   retest`, without recording) and writes the verdicts, history, finding
//!   details, report, hashes and a signed manifest;
//! - `pathwarden evidence --run <ID>` makes the pack of a run of the UI
//!   workspace against an earlier one, as the run page's "Evidence pack"
//!   makes it ([`pathwarden_ui::evidence_ui::build_pack`]);
//! - `pathwarden evidence keygen` creates a signing key in a new folder;
//!   `pathwarden evidence key` shows, creates or replaces the key the app
//!   signs with (Settings' "Evidence signing key");
//! - `pathwarden evidence verify <pack>` checks the signature and every
//!   file, as Settings' "Check an evidence pack" does.
//!
//! The pack's content, format and signatures are
//! [`pathwarden_core::evidence`]'s, shared with the app; docs/evidence.md
//! describes the format for third-party verification.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anstream::{eprintln, println};
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use pathwarden_core::evidence::content::{self, After, Fresh};
use pathwarden_core::evidence::pack::{self, Outcome};
use pathwarden_core::evidence::{self as core_evidence, PublicKey, SecretKey, KEY_ENV};
use pathwarden_core::retest::{RetestCounts, Selection};
use pathwarden_core::time::format_local;
use pathwarden_ui::evidence_ui;
use zeroize::Zeroizing;

use crate::progress::{self, Through};
use crate::{emit_json, exit, read_config, retest_cmd, run_rules, store, ui, Input};

#[derive(Args)]
#[command(
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    after_help = "Retests like `pathwarden retest` (nothing is recorded) and writes a signed pack; with \
--run, compares a run of the app's workspace with an earlier one, as the app's run page does. \
See docs/evidence.md.

Exit status: 0 every retested finding is fixed, 1 some are still open, 2 error, 3 none open, but \
Pathwarden can't tell for some (domain not collected)."
)]
pub struct EvidenceArgs {
    #[command(subcommand)]
    action: Option<Action>,
    #[command(flatten)]
    build: BuildArgs,
}

impl EvidenceArgs {
    /// The collector data the command reads (building a pack from it only).
    pub fn input_mut(&mut self) -> Option<&mut Input> {
        (self.action.is_none() && self.build.run.is_none()).then_some(&mut self.build.input)
    }

    /// `--env`: the environment's history, unless `--state` or `--baseline`
    /// says otherwise.
    pub fn default_state(&mut self, dir: &std::path::Path) {
        if self.action.is_none() && self.build.state.is_none() && self.build.baseline.is_none() {
            self.build.state = Some(dir.to_path_buf());
        }
    }
}

#[derive(Args)]
struct BuildArgs {
    #[command(flatten)]
    input: Input,
    /// A run of the app's workspace instead of collector data (the ID
    /// `pathwarden runs list` prints), compared with an earlier run of its
    /// environment, as the run page's "Evidence pack" makes it; --env picks
    /// the environment.
    #[arg(long, value_name = "RUN", conflicts_with_all = ["input", "baseline", "tier_zero", "config"])]
    run: Option<String>,
    /// With --run: the earlier run to compare with (default: the run before
    /// it).
    #[arg(long, value_name = "RUN", requires = "run")]
    against: Option<String>,
    /// Compare with this earlier collection (.zip, .json, folder) or event
    /// document instead of the run history.
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
    /// The run history folder: the baseline, and the history and tracking
    /// included (overrides [state] path; with --run, the history the app
    /// reads, as `pathwarden ui --state`).
    #[arg(long, value_name = "DIR")]
    state: Option<PathBuf>,
    /// Only this finding (its ID); repeatable.
    #[arg(long = "finding", value_name = "FINDING_ID")]
    findings: Vec<String>,
    /// Only findings of this rule, e.g. PW-003; repeatable.
    #[arg(long = "rule", value_name = "RULE")]
    rules: Vec<String>,
    /// Where to write the pack: a .zip, or a new folder (default:
    /// pathwarden-evidence-<run>.zip).
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// The signing key file, from `evidence keygen` (default: the
    /// PATHWARDEN_EVIDENCE_KEY variable, and with --run then the app's key,
    /// `evidence key`).
    #[arg(long, value_name = "FILE")]
    key: Option<PathBuf>,
    /// Leave out the HTML report and every object and domain name.
    #[arg(long)]
    redact: bool,
}

#[derive(Subcommand)]
enum Action {
    /// Create a signing key in a new folder only this account can read.
    Keygen {
        /// The folder to create.
        #[arg(
            short,
            long = "output",
            alias = "out",
            value_name = "DIR",
            default_value = "pathwarden-evidence-key"
        )]
        out: PathBuf,
    },
    /// This computer's signing key, the one the app signs packs with (the
    /// app's Settings, "Evidence signing key"): show it, or create, replace
    /// or export it.
    Key {
        #[command(subcommand)]
        action: Option<KeyAction>,
        /// The app's workspace (default: the one `pathwarden ui` uses).
        #[arg(long, value_name = "DIR", global = true)]
        workspace: Option<PathBuf>,
        /// Print JSON instead of text.
        #[arg(long, global = true)]
        json: bool,
    },
    /// Check a pack: the signature, the signer, and every file's SHA-256.
    #[command(
        after_help = "Exit status: 0 verified, 1 not verified (changed, damaged or signed by another key), \
2 error, 3 intact and validly signed, but the signer wasn't checked (give --key or --fingerprint)."
    )]
    Verify {
        /// The pack: a .zip or a folder.
        pack: PathBuf,
        /// The organization's public key file (evidence.pub).
        #[arg(long, value_name = "FILE", conflicts_with = "fingerprint")]
        key: Option<PathBuf>,
        /// The organization's published key fingerprint (SHA256:...).
        #[arg(long, value_name = "FINGERPRINT")]
        fingerprint: Option<String>,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Create the key ("Create a key"); with --replace, in place of the one
    /// there is ("Replace with a new key").
    New {
        /// Replace the key there is: packs from now on are signed with the
        /// new one.
        #[arg(long)]
        replace: bool,
    },
    /// Sign with this secret key file (evidence.key) from now on ("Use
    /// another key file").
    Use {
        /// The secret key file.
        file: PathBuf,
    },
    /// Write the public key file, evidence.pub ("Public key").
    Public {
        /// Where to write it.
        #[arg(short, long, value_name = "FILE", default_value = "evidence.pub")]
        output: PathBuf,
    },
}

pub fn run(args: EvidenceArgs) -> Result<ExitCode> {
    match args.action {
        Some(Action::Keygen { out }) => keygen(&out).map(|()| ExitCode::SUCCESS),
        Some(Action::Key {
            action,
            workspace,
            json,
        }) => key_cmd(action, workspace.as_deref(), json).map(|()| ExitCode::SUCCESS),
        Some(Action::Verify {
            pack,
            key,
            fingerprint,
            json,
        }) => verify_cmd(&pack, key.as_deref(), fingerprint, json),
        None if args.build.run.is_some() => build_from_run(&args.build),
        None => build(&args.build),
    }
}

fn keygen(out: &Path) -> Result<()> {
    let key = core_evidence::create_key_dir(out)?;
    let secret = out.join(core_evidence::KEY_FILE);
    let public = out.join(core_evidence::PUB_FILE);
    let pk = key.public();

    let (g, bold) = (ui::GREEN, ui::BOLD);
    println!(
        "{g}Signing key created{g:#} in {} (only this account can read the folder).\n",
        out.display()
    );
    println!("  Secret key   {}", secret.display());
    println!("  Public key   {}", public.display());
    println!("  {bold}Fingerprint  {}{bold:#}\n", pk.fingerprint());
    println!(
        "Publish the fingerprint (or evidence.pub) where auditors can find it without the\n\
         packs: your website, the contract, or a signed email. They check each pack against it.\n\
         Keep the secret key private and backed up: anyone with it can sign packs as you.\n\n\
         Sign:    pathwarden evidence -i <collection> --key {}\n\
         Or put the last line of {} in the {KEY_ENV} variable (a pipeline secret).",
        crate::shell::quoted_path(&secret),
        core_evidence::KEY_FILE
    );
    Ok(())
}

/// The UI workspace for `evidence key`.
fn key_workspace(dir: Option<&Path>, create: bool) -> Result<pathwarden_ui::workspace::Workspace> {
    let root = match dir {
        Some(d) => d.to_path_buf(),
        None => pathwarden_ui::workspace::default_dir()?,
    };
    if create && !root.exists() {
        std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
    }
    pathwarden_ui::workspace::Workspace::existing(root)
}

fn key_cmd(action: Option<KeyAction>, workspace: Option<&Path>, json: bool) -> Result<()> {
    let (info, done) = match action {
        None => {
            let ws = key_workspace(workspace, false)?;
            (
                evidence_ui::key_info(&ws).map_err(anyhow::Error::msg)?,
                None,
            )
        }
        Some(KeyAction::New { replace }) => {
            let ws = key_workspace(workspace, true)?;
            let k = evidence_ui::create_key(&ws, replace).map_err(anyhow::Error::msg)?;
            (
                Some(k),
                Some(if replace {
                    "Signing key replaced"
                } else {
                    "Signing key created"
                }),
            )
        }
        Some(KeyAction::Use { file }) => {
            let ws = key_workspace(workspace, true)?;
            let text = Zeroizing::new(
                std::fs::read_to_string(&file)
                    .with_context(|| format!("reading {}", file.display()))?,
            );
            let k = evidence_ui::use_key(&ws, &text).map_err(anyhow::Error::msg)?;
            (Some(k), Some("Signing key replaced"))
        }
        Some(KeyAction::Public { output }) => {
            let ws = key_workspace(workspace, false)?;
            let Some(k) = evidence_ui::key_info(&ws).map_err(anyhow::Error::msg)? else {
                bail!("No signing key yet. Create one with `pathwarden evidence key new`.");
            };
            if output.exists() {
                bail!("{} already exists.", output.display());
            }
            std::fs::write(&output, &k.public_text)
                .with_context(|| format!("writing {}", output.display()))?;
            if json {
                return emit_json(&serde_json::json!({
                    "public_key": output.display().to_string(),
                    "fingerprint": k.fingerprint,
                }));
            }
            println!("Wrote {}.", output.display());
            println!("  Fingerprint  {}", k.fingerprint);
            return Ok(());
        }
    };
    if json {
        // An object either way, `exists` saying which.
        let v = match &info {
            Some(k) => {
                let mut v = k.json();
                if let Some(o) = v.as_object_mut() {
                    o.insert("exists".into(), true.into());
                }
                v
            }
            None => serde_json::json!({ "exists": false }),
        };
        return emit_json(&v);
    }
    let Some(k) = info else {
        println!("No signing key yet. Create one with `pathwarden evidence key new`.");
        return Ok(());
    };
    let (g, bold) = (ui::GREEN, ui::BOLD);
    if let Some(done) = done {
        println!("{g}{done}{g:#}\n");
    }
    println!("Evidence signing key: signs the evidence packs made on this computer.");
    println!("  {bold}Fingerprint  {}{bold:#}", k.fingerprint);
    if let Some(t) = k.created {
        println!("  Created      {}", format_local(t));
    }
    println!("  Kept in      {}", k.dir.display());
    println!(
        "\nPublish the fingerprint where auditors find it without the packs: your website,\n\
         the contract, or a signed email."
    );
    Ok(())
}

/// The signing key: `--key`, else [`KEY_ENV`].
fn signing_key(path: Option<&Path>) -> Result<Option<SecretKey>> {
    if let Some(path) = path {
        let file = core_evidence::key_file(path);
        let others = pathwarden_core::perms::readable_by_others(&file);
        if !others.is_empty() {
            let warn = ui::severity(pathwarden_core::findings::Severity::Medium);
            eprintln!(
                "{warn}Warning:{warn:#} The signing key {} can be read by {}. Anyone who can read \
                 it can sign packs as you.",
                file.display(),
                others.join(", ")
            );
        }
        return core_evidence::read_secret_key(path).map(Some);
    }
    // Taken from the environment at start-up (`keystore::take_env`): no
    // program Pathwarden starts inherits it.
    match pathwarden_core::keystore::secret_env(KEY_ENV)? {
        Some(v) => SecretKey::parse(&v)
            .with_context(|| format!("reading the signing key in {KEY_ENV}"))
            .map(Some),
        None => Ok(None),
    }
}

/// What a written pack says, in the terminal or as JSON.
struct Written<'a> {
    output: &'a Path,
    manifest: &'a pack::Manifest,
    fingerprint: &'a str,
    counts: RetestCounts,
    /// "state (run 2026...)" and the like: what it was compared with.
    against: String,
    redact: bool,
    run_id: &'a str,
}

fn say_written(w: &Written, json: bool) -> Result<()> {
    let pack_sha256 = if pack::is_zip(w.output) {
        Some(pack::hash_file(w.output)?.0)
    } else {
        None
    };
    if json {
        return emit_json(&serde_json::json!({
            "pack": w.output.display().to_string(),
            "pack_sha256": pack_sha256,
            "signed_by": w.fingerprint,
            "redacted": w.redact,
            "files": w.manifest.files,
            "counts": w.counts,
            "run_id": w.run_id,
        }));
    }
    let (g, dim) = (ui::GREEN, ui::DIM);
    let c = w.counts;
    println!("{g}Wrote{g:#} {}.", w.output.display());
    println!(
        "  {} fixed, {} still open, {} can't tell, {} new, against the {}.",
        c.fixed, c.still_open, c.cant_tell, c.new, w.against
    );
    println!(
        "  {} files, signed with key {}.",
        w.manifest.files.len() + 2,
        w.fingerprint
    );
    println!(
        "  {}",
        if w.redact {
            "Redacted: no object or domain names, no report."
        } else {
            "Holds names and the full report: share it like the report. --redact leaves them out."
        }
    );
    if let Some(h) = &pack_sha256 {
        println!("  {dim}Pack SHA-256 {h}{dim:#}");
    }
    println!(
        "  Check it with `pathwarden evidence verify {} --fingerprint {}`.",
        ui::safe(&crate::shell::quoted_path(w.output)),
        w.fingerprint
    );
    Ok(())
}

fn exit_code(code: u8) -> ExitCode {
    debug_assert!([exit::OK, exit::FINDINGS, exit::CANT_TELL].contains(&code));
    ExitCode::from(code)
}

/// `evidence --run`: the pack of a run of the UI workspace, as the run page
/// makes it.
fn build_from_run(b: &BuildArgs) -> Result<ExitCode> {
    let id = b.run.as_deref().unwrap_or_default();
    let ws = pathwarden_ui::environments::cli_workspace_or_current(
        b.input.env.env_workspace.as_deref(),
        b.input.env.env.as_deref(),
    )?;
    let key = match signing_key(b.key.as_deref())? {
        Some(k) => k,
        None => evidence_ui::signing_key(&ws)
            .map_err(anyhow::Error::msg)?
            .context(
                "No signing key. Give --key <file>, set PATHWARDEN_EVIDENCE_KEY, or create this \
                 computer's key with `pathwarden evidence key new`.",
            )?,
    };
    let r = evidence_ui::find_run(&ws, id)?;
    let fingerprint = key.public().fingerprint();
    let opts = evidence_ui::PackOptions {
        against: b.against.clone(),
        findings: b.findings.clone(),
        rules: b.rules.clone(),
        redact: b.redact,
    };
    let built = evidence_ui::build_pack(
        &ws,
        b.state.as_deref(),
        &r,
        &opts,
        &fingerprint,
        pathwarden_core::analyze::now(),
    )
    .map_err(anyhow::Error::msg)?;
    let output = b
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(&built.file_name));
    if output.exists() {
        bail!(
            "{} already exists. Evidence packs are never overwritten.",
            output.display()
        );
    }
    let manifest = pack::write(&output, &built.contents.files, built.contents.header, &key)?;
    say_written(
        &Written {
            output: &output,
            manifest: &manifest,
            fingerprint: &fingerprint,
            counts: built.report.counts,
            against: format!("run {}", built.baseline.run_id()),
            redact: b.redact,
            run_id: &r.run_id(),
        },
        b.input.json,
    )?;
    Ok(exit_code(built.report.exit_code()))
}

fn build(b: &BuildArgs) -> Result<ExitCode> {
    // The key first: no point analyzing for minutes and then failing.
    let key = signing_key(b.key.as_deref())?.with_context(|| {
        format!(
            "No signing key. Give --key <file> or set {KEY_ENV}; create one with \
             `pathwarden evidence keygen`."
        )
    })?;
    let input = &b.input;
    if input.input.is_empty() {
        bail!("Give a collection (-i) or a run of the app (--run).");
    }
    let config = read_config(input)?;
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();
    let created_at = started_ms / 1000;
    let run_id = pathwarden_core::state::run_id_millis(started_ms);
    let output = match &b.output {
        Some(p) => p.clone(),
        None => PathBuf::from(format!(
            "pathwarden-evidence-{}{}.zip",
            run_id.replace('.', "-"),
            if b.redact { "-redacted" } else { "" }
        )),
    };
    if output.exists() {
        bail!(
            "{} already exists. Evidence packs are never overwritten.",
            output.display()
        );
    }
    let selection = Selection {
        fingerprints: b.findings.clone(),
        rules: b.rules.clone(),
    };

    // The state: the baseline (without --baseline), and history and tracking.
    let store = store::Store::new(&config.state, b.state.as_deref())?;
    let has_state = store.has_state_file("findings.json");
    let use_state = has_state && (b.baseline.is_none() || b.state.is_some());
    let state = if use_state { Some(store.load()?) } else { None };
    let last = if use_state {
        store::last_run(&store)
    } else {
        None
    };

    let mut p = progress::Analysis::new(
        if b.redact {
            Through::Rules
        } else {
            Through::Report
        },
        input.verbose,
    );
    let (base, baseline_inputs) = match &b.baseline {
        Some(path) => (
            retest_cmd::baseline_from_path(path, &config, input)?,
            Some(content::hash_inputs(std::slice::from_ref(path))?),
        ),
        None => {
            let Some(state) = &state else {
                bail!(
                    "No run history at {}. Run `pathwarden run` first, point --state at the history \
                     folder, or compare with an earlier collection (--baseline).",
                    store.dir.display()
                );
            };
            (
                retest_cmd::baseline_from_state(&store, state, last.clone()),
                None,
            )
        }
    };
    let baseline_kind = base
        .baseline
        .label
        .split(' ')
        .next()
        .unwrap_or("state")
        .to_string();
    let inputs = content::hash_inputs(&input.input)?;
    let ev = run_rules(input, &mut p)?;
    let report = retest_cmd::compare(&base, &ev, &selection)?;
    let domains = pathwarden_core::analyze::domain_names(&ev.graph);
    let trusted = pathwarden_core::analyze::trusted_domain_names(&ev.graph);
    let objects = ev.graph.nodes().filter(|(_, n)| !n.placeholder).count();
    let collected_at = ev.stats.collected_at;

    // The findings the pack covers: retested and new.
    let covered: std::collections::HashSet<&str> = report
        .results
        .iter()
        .map(|r| r.fingerprint.as_str())
        .chain(report.new.iter().map(|n| n.fingerprint.as_str()))
        .collect();
    let (html, all) = if b.redact {
        (None, ev.findings)
    } else {
        let a = ev.finish(&mut p);
        // With a run history, the report's Overview has its trend and what
        // changed since the last run, as `run --report` and the app's do.
        let earlier = if use_state {
            let digest = a.data_digest();
            let this = pathwarden_core::history::This::Data {
                digest: &digest,
                collected_at: a.stats.collected_at,
            };
            let mut h = pathwarden_core::history::for_report_in(&store.dir, &a.domains, this);
            h.context = crate::settings_args(input);
            h
        } else {
            Default::default()
        };
        let html = a.report_html_with(created_at, &earlier, &mut p);
        (Some(html), a.findings)
    };
    p.done();
    let fresh: Vec<Fresh> = all
        .iter()
        .filter(|f| covered.contains(f.fingerprint.as_str()))
        .map(Fresh::from_finding)
        .collect();
    drop(all);
    let history = if use_state {
        store.check_expected()?;
        let (points, _) = pathwarden_core::history::load(&store.dir).map_err(anyhow::Error::msg)?;
        points
    } else {
        Vec::new()
    };
    let config_sha256 = match &input.config {
        Some(path) => Some(pack::hash_file(path)?.0),
        None => None,
    };

    let src = content::Sources {
        created_at,
        redact: b.redact,
        report: &report,
        baseline_kind: &baseline_kind,
        baseline_label: &base.baseline.label,
        baseline_run_id: base.run_id.as_deref(),
        baseline_collected_at: base.collected_at,
        baseline_views: &base.baseline.open,
        baseline_inputs: baseline_inputs.as_ref(),
        after: After::Fresh,
        after_run_id: &run_id,
        after_collected_at: collected_at,
        inputs: Some(&inputs),
        domains: &domains,
        objects,
        fresh: &fresh,
        state: state.as_ref(),
        state_left_out: false,
        history: &history,
        config_sha256,
        config_name: input
            .config
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned()),
        config_note: None,
        binary_sha256: content::binary_hash(),
        selection_findings: &b.findings,
        selection_rules: &b.rules,
    };
    let fingerprint = key.public().fingerprint();
    let withhold = b.redact.then(|| {
        // Trusted domains are named too (in trust findings, for one).
        let mut extra = trusted.clone();
        if let Some(l) = &last {
            extra.extend(l.domains.iter().cloned());
            extra.extend(l.trusted_domains.iter().flatten().cloned());
        }
        content::names_to_withhold(&domains, &base.baseline.open, &fresh, &extra)
    });
    let contents = core_evidence::contents(&src, &fingerprint, html, withhold.as_ref())?;
    let manifest = pack::write(&output, &contents.files, contents.header, &key)?;
    say_written(
        &Written {
            output: &output,
            manifest: &manifest,
            fingerprint: &fingerprint,
            counts: report.counts,
            against: format!(
                "{baseline_kind}{}",
                base.run_id
                    .as_deref()
                    .map(|r| format!(" (run {r})"))
                    .unwrap_or_default()
            ),
            redact: b.redact,
            run_id: &run_id,
        },
        input.json,
    )?;
    Ok(exit_code(report.exit_code()))
}

fn verify_cmd(
    pack_path: &Path,
    key: Option<&Path>,
    fingerprint: Option<String>,
    json: bool,
) -> Result<ExitCode> {
    let key = match key {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading the public key {}", path.display()))?;
            Some(
                PublicKey::parse(&text)
                    .with_context(|| format!("reading the public key {}", path.display()))?,
            )
        }
        None => None,
    };
    let v = pack::verify(pack_path, &pack::Expected { key, fingerprint })?;
    let code = match v.outcome {
        Outcome::Verified => exit::OK,
        Outcome::SignerNotChecked => exit::CANT_TELL,
        Outcome::Failed => exit::FINDINGS,
    };
    if json {
        emit_json(&v)?;
        return Ok(ExitCode::from(code));
    }
    let bold = ui::BOLD;
    let good = ui::GREEN;
    let bad = ui::severity(pathwarden_core::findings::Severity::High);
    let warn = ui::severity(pathwarden_core::findings::Severity::Medium);
    println!(
        "{bold}Evidence pack {}{bold:#}",
        ui::safe(&pack_path.display().to_string())
    );
    match &v.signed_by {
        Some(fp) => println!("  Signature  valid, made with key {fp}"),
        None => println!("  Signature  {bad}not valid{bad:#}"),
    }
    println!(
        "  Files      {} of {} match the manifest.",
        v.files_ok, v.files_checked
    );
    // What the pack says about itself, only once its signature holds.
    if let (Some(m), Some(_)) = (&v.manifest, &v.signed_by) {
        println!(
            "  Created    {} with Pathwarden {}{}",
            format_local(m.created_at),
            ui::safe(&m.pathwarden),
            if m.redacted {
                " (redacted: no names, no report)"
            } else {
                ""
            }
        );
        let s = &m.summary;
        let n = |k: &str| s["counts"][k].as_u64().unwrap_or(0);
        println!(
            "  Shows      {} fixed, {} still open, {} can't tell, {} new, against the {}{}",
            n("fixed"),
            n("still_open"),
            n("cant_tell"),
            n("new"),
            ui::safe(s["baseline"]["kind"].as_str().unwrap_or("baseline")),
            s["baseline"]["run_id"]
                .as_str()
                .map(|r| format!(" (run {})", ui::safe(r)))
                .unwrap_or_default()
        );
    }
    println!();
    match v.outcome {
        Outcome::Verified => println!(
            "{good}VERIFIED{good:#}: every file is exactly as signed, by key {}.",
            v.signed_by.as_deref().unwrap_or_default()
        ),
        Outcome::SignerNotChecked => println!(
            "{warn}INTACT, SIGNER NOT CHECKED{warn:#}: every file is exactly as signed by key\n\
             {}, but nothing says whose key that is.\n\
             Run again with --fingerprint (the one the organization published) or\n\
             --key <their evidence.pub>.",
            v.signed_by.as_deref().unwrap_or_default()
        ),
        Outcome::Failed => {
            println!("{bad}NOT VERIFIED{bad:#}: don't rely on this pack.");
            for p in &v.problems {
                println!("  - {}", ui::safe(p));
            }
        }
    }
    Ok(ExitCode::from(code))
}
