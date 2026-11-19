//! The Collect wizard: collect from Active Directory, then analyze, without
//! the command line.
//!
//! The wizard is one page (`/collect`); its steps (where, who, how deep,
//! check, collect) are shown one at a time by `assets/collect.js`. The
//! password never leaves the browser except in the body of the two POSTs
//! that need it (`/api/collect/test` and `/api/collect/start`), where it is
//! read straight into a [`Secret`] and dropped (zeroed) as soon as the check
//! or the collection ends. It is never stored, logged, echoed back or put in
//! job state or a URL.
//!
//! A collection is a job like an analysis (one at a time, across both): it
//! collects into a fresh `uploads/<id>/`, then analyzes with the same phases
//! as `/analyze` and saves the run. The raw collection is then deleted,
//! unless the user asked to keep it (moved to `collections/<id>/`).
//!
//! `schedule.rs` writes the files to run the same collection every night (a
//! Task Scheduler script and command, or a systemd unit and timer); the
//! Automate area's Schedule page ([`crate::automate`]) shows them. The UI
//! never creates a task or runs anything elevated.

mod detect;
mod schedule;
mod view;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::{Path as UrlPath, Query, State};
use axum::http::header;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pathwarden_collect::{
    Auth, Cancelled, CollectRequest, ConnectionCheck, ConnectionError, ExternalKind, Method,
    NoSpace, Problem, Progress, ReadCache, ReadStopped, Scope, Secret, StoppedRead,
};
use pathwarden_core::analyze;
use serde::Deserialize;

use crate::jobs::{self, CollectProgress, DomainRun, JobSpec, JobStatus, Jobs, LOG_LINES};
use crate::pages;
use crate::secret_json::SecretJson;
use crate::server::Shared;
use crate::workspace::{self, CollectionInfo, RunSummary, Workspace};

pub use schedule::{
    plain_text, Block as ScheduleBlock, Params as ScheduleParams, Spec as ScheduleSpec,
    Step as ScheduleStep, Target,
};

/// Whether this build offers the built-in collector (Cargo feature `builtin`).
pub const BUILTIN: bool = pathwarden_collect::builtin_available();

const COLLECT_JS: &str = include_str!("../assets/collect.js");
const COLLECT_CSS: &str = include_str!("../assets/collect.css");

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/collect", get(page))
        .route("/api/collect/test", post(test))
        .route("/api/collect/trusted", get(trusted))
        .route("/api/collect/start", post(start))
        .route(
            "/api/collect/also",
            post(stage_also).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/api/collect/stopped", post(stopped))
        .route("/runs/{id}/collect", get(collect_again))
        .route("/api/collect/{id}/cancel", post(cancel))
        .route(
            "/static/collect.js",
            get(|| async { asset("text/javascript", COLLECT_JS) }),
        )
        .route(
            "/static/collect.css",
            get(|| async { asset("text/css", COLLECT_CSS) }),
        )
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

// ------------------------------------------------------------- detection

pub use detect::Detected;

/// Letters, digits, `.`, `-` and `_`: what a DNS name or host may hold (and
/// nothing an external program could read as an option).
fn host_like(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.starts_with(['-', '.'])
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

// ------------------------------------------------------------------ form

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthChoice {
    #[default]
    Current,
    Password,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Depth {
    #[default]
    Quick,
    Full,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Collector {
    #[default]
    Builtin,
    Sharphound,
}

/// The wizard's answers, as the browser posts them (JSON). `Debug` shows
/// the password as `Secret(<redacted>)`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct CollectForm {
    pub domain: String,
    pub server: Option<String>,
    pub auth: AuthChoice,
    pub user: String,
    /// Read straight into a [`Secret`]: zeroed when the form is dropped.
    pub password: Option<Secret>,
    pub ldaps: bool,
    pub skip_verify: bool,
    /// "Kerberos only" turned off. Named for the opt-out so a form
    /// that doesn't say gets Kerberos only.
    pub allow_ntlm: bool,
    /// "Require SMB signing" turned off, likewise.
    pub allow_unsigned_smb: bool,
    /// "Read service accounts": `None` when the page didn't say, and
    /// the environment's `[collect] service_reads` decides.
    pub service_reads: Option<bool>,
    /// "Read scheduled tasks", likewise with `[collect]
    /// task_reads`.
    pub task_reads: Option<bool>,
    pub depth: Depth,
    pub collector: Collector,
    pub sharphound: String,
    /// Keep the raw collection after the analysis.
    pub keep: bool,
    /// The environment to analyze into (an ID), or a new one by name;
    /// neither lets the collected domains decide
    /// ([`crate::environments::decide`]).
    pub env: Option<String>,
    pub new_env: Option<String>,
    /// The page made the choice by itself, from the domain it collects
    /// ([`crate::jobs::JobSpec::env_auto`]).
    pub env_auto: bool,
    /// The run's label.
    pub label: Option<String>,
    /// Trusted domains to collect in the same run, after `domain`.
    pub trusted: Vec<String>,
    /// A ticked trusted domain's domain controller, when one is typed:
    /// trusted domain to host, as `--server DOMAIN=HOST`. Blank, or
    /// for a domain not ticked: found through DNS.
    pub trusted_servers: std::collections::BTreeMap<String, String>,
    /// Go on with a read of the domain that stopped, when it can be;
    /// otherwise it starts over.
    pub resume: bool,
    /// Other collectors' files to analyze with the collection: what
    /// `/api/collect/also` named them when they were uploaded.
    pub also: Option<String>,
}

/// Most trusted domains one run collects.
pub const MAX_TRUSTED: usize = 50;

/// The form's trusted domains: DNS names, each once, not the domain
/// itself, lower case.
pub fn trusted_names(form: &CollectForm) -> Result<Vec<String>, FieldError> {
    let domain = form
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let mut out: Vec<String> = Vec::new();
    for t in &form.trusted {
        let t = t.trim().trim_end_matches('.').to_ascii_lowercase();
        if t.is_empty() || t == domain || out.contains(&t) {
            continue;
        }
        if !host_like(&t) || !t.contains('.') {
            return Err(FieldError::new(
                1,
                "trusted",
                format!("{t} isn't a domain name Pathwarden can connect to."),
            ));
        }
        out.push(t);
    }
    if out.len() > MAX_TRUSTED {
        return Err(FieldError::new(
            1,
            "trusted",
            format!("Pick at most {MAX_TRUSTED} trusted domains for one run."),
        ));
    }
    Ok(out)
}

/// The domain controllers typed for the form's ticked trusted domains,
/// checked as `--server DOMAIN=HOST` is
/// ([`pathwarden_collect::named_servers`]). A blank one, or one for a
/// domain not ticked, is left out: that domain's is found through DNS.
pub fn trusted_servers(
    form: &CollectForm,
) -> Result<pathwarden_collect::DomainServers, FieldError> {
    use pathwarden_collect::ServerError;
    let ticked = trusted_names(form).unwrap_or_default();
    let mut pairs: Vec<(Option<String>, String)> = Vec::new();
    for (d, h) in &form.trusted_servers {
        let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.trim().is_empty() || !ticked.contains(&d) {
            continue;
        }
        pairs.push((Some(d), h.clone()));
    }
    let field = |message: String| FieldError::new(1, "trusted", message);
    let domain_of = |i: usize| pairs[i].0.clone().unwrap_or_default();
    match pathwarden_collect::named_servers(&form.domain, &pairs) {
        Ok((_, servers)) => Ok(servers),
        Err(ServerError::BadHost(i)) => {
            let d = domain_of(i);
            Err(field(format!(
                "{}'s domain controller doesn't look like a computer name. Use its full name, \
                 like dc01.{d}, without a port, path or user.",
                d.to_ascii_uppercase()
            )))
        }
        Err(ServerError::Twice(d) | ServerError::FirstTwice(d)) => Err(field(format!(
            "Give {}'s domain controller once.",
            d.to_ascii_uppercase()
        ))),
        Err(ServerError::Empty(i)) => Err(field(format!(
            "Give {}'s domain controller by its full name, or leave it empty.",
            domain_of(i).to_ascii_uppercase()
        ))),
    }
}

/// The form's ticked trusted domains, kept only where the trusts of the
/// domain's last run list them and they can be collected: what the
/// page offers ([`trusted_for`], as `/api/collect/trusted` answers), so a
/// request can't add a domain the page never showed. `known` is that
/// answer; `None` (no run lists the domain's trusts) keeps none.
pub fn keep_known_trusted(form: &mut CollectForm, known: Option<&TrustedFrom>) {
    let offered: Vec<&str> = known
        .map(|k| {
            k.domains
                .iter()
                .filter(|t| t.pick != pathwarden_core::forest::Pick::Off)
                .map(|t| t.name.as_str())
                .collect()
        })
        .unwrap_or_default();
    form.trusted.retain(|t| {
        let t = t.trim().trim_end_matches('.');
        offered.iter().any(|o| o.eq_ignore_ascii_case(t))
    });
}

/// The trusts the page lists for `domain`: [`trusted_for`] over the
/// current environment's runs, then every other's, as
/// `/api/collect/trusted` reads them.
fn known_trusted(st: &Shared, domain: &str) -> Option<TrustedFrom> {
    let env_ws = st.ws();
    let mut runs = env_ws.runs();
    runs.extend(st.workspace.all_runs());
    trusted_for(&env_ws, &runs, domain)
}

/// [`known_trusted`], read off the server thread.
async fn known_trusted_off_thread(st: &Shared, domain: &str) -> Option<TrustedFrom> {
    let (st, domain) = (st.clone(), domain.to_string());
    tokio::task::spawn_blocking(move || known_trusted(&st, &domain))
        .await
        .ok()
        .flatten()
}

/// Where a domain's trusted domains come from: the newest run that
/// collected it, its environment, and what each trusted domain is.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrustedFrom {
    pub run: String,
    /// The domain, as the run names it.
    pub domain: String,
    pub env: String,
    pub domains: Vec<pathwarden_core::forest::TrustedDomain>,
}

/// The trusted domains a collection of `domain` can also collect, from the
/// newest of `runs` (newest first) that collected it: the run's forest map
/// ([`pathwarden_core::forest::trusted_domains`]). `None` when no run did,
/// or the run keeps no forest map (saved before 0.1.7).
pub fn trusted_for(ws: &Workspace, runs: &[RunSummary], domain: &str) -> Option<TrustedFrom> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return None;
    }
    let run = runs.iter().find(|r| {
        !r.demo && r.shared.is_none() && r.domains.iter().any(|d| d.eq_ignore_ascii_case(domain))
    })?;
    let dir = ws.run_dir(&run.id)?;
    let bytes = crate::run_data::read_gz(&dir.join(crate::explore_ui::GRAPH_FILE)).ok()?;
    let map = pathwarden_core::explore::read_forest(&bytes).ok()??;
    let name = run
        .domains
        .iter()
        .find(|d| d.eq_ignore_ascii_case(domain))
        .cloned()
        .unwrap_or_else(|| domain.to_ascii_uppercase());
    Some(TrustedFrom {
        run: run.id.clone(),
        domains: pathwarden_core::forest::trusted_domains(&map, &name),
        domain: name,
        env: run.environment(),
    })
}

/// A problem with one answer: which step and field to send the user back to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    pub step: u8,
    pub field: &'static str,
    pub message: String,
}

impl FieldError {
    fn new(step: u8, field: &'static str, message: impl Into<String>) -> Self {
        Self {
            step,
            field,
            message: message.into(),
        }
    }

    fn response(&self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": self.message,
                "step": self.step,
                "field": self.field,
            })),
        )
            .into_response()
    }
}

impl Depth {
    fn label(self) -> &'static str {
        match self {
            Depth::Quick => "Quick",
            Depth::Full => "Full",
        }
    }
}

impl Collector {
    fn label(self) -> &'static str {
        match self {
            Collector::Builtin => "Built-in collector",
            Collector::Sharphound => "SharpHound",
        }
    }
}

/// A path typed or pasted by the user: quotes ("Copy as path") and spaces
/// removed.
fn clean_path(raw: &str) -> &str {
    raw.trim().trim_matches('"').trim()
}

/// Checks the answers and builds the request, with the wizard's plain
/// messages. Takes the form so the password moves into the request without
/// a copy.
pub fn build_request(form: CollectForm, output_dir: PathBuf) -> Result<CollectRequest, FieldError> {
    let domain = form
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if domain.is_empty() {
        return Err(FieldError::new(
            1,
            "domain",
            "Enter your domain's name, like scale.local.",
        ));
    }
    if !host_like(&domain) || !domain.contains('.') {
        return Err(FieldError::new(
            1,
            "domain",
            "That doesn't look like a domain name. Use its full DNS name, like scale.local \
             (not the short name, like SCALE).",
        ));
    }
    let servers = trusted_servers(&form)?;
    let server = form
        .server
        .as_deref()
        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    if let Some(s) = &server {
        if !host_like(s) {
            return Err(FieldError::new(
                1,
                "server",
                "That doesn't look like a computer name. Use the domain controller's full \
                 name, like dc01.scale.local.",
            ));
        }
    }

    let auth = match form.auth {
        AuthChoice::Current => Auth::CurrentUser,
        AuthChoice::Password => {
            let user = form.user.trim().to_string();
            if user.is_empty() {
                return Err(FieldError::new(2, "user", "Enter the user name."));
            }
            if user.len() > 256 || user.chars().any(|c| c.is_control() || c == '"') {
                return Err(FieldError::new(
                    2,
                    "user",
                    "Enter the user name like svc-pathwarden, SCALE\\svc-pathwarden or \
                     svc-pathwarden@scale.local.",
                ));
            }
            let password = match form.password {
                Some(p) if !p.is_empty() => p,
                _ => return Err(FieldError::new(2, "password", "Enter the password.")),
            };
            Auth::Password { user, password }
        }
    };
    let password = matches!(auth, Auth::Password { .. });

    let method = match form.collector {
        Collector::Builtin => {
            if !BUILTIN {
                return Err(FieldError::new(
                    3,
                    "collector",
                    Problem::NoBuiltin.explain(),
                ));
            }
            if !password && !cfg!(windows) {
                return Err(FieldError::new(
                    2,
                    "auth",
                    "Signing in as your own account works on Windows only. Enter a user and \
                     password.",
                ));
            }
            if password && !form.ldaps {
                return Err(FieldError::new(
                    2,
                    "ldaps",
                    "Turn on LDAPS: with a password, it keeps the password and your data \
                     encrypted on the way.",
                ));
            }
            if form.depth == Depth::Full && !password {
                return Err(FieldError::new(
                    3,
                    "collector",
                    "For a Full collection the built-in collector needs a user and password \
                     (it signs in to every computer with them). Use SharpHound, or go back and \
                     enter a user and password.",
                ));
            }
            Method::Builtin
        }
        Collector::Sharphound => {
            if !cfg!(windows) {
                return Err(FieldError::new(
                    3,
                    "collector",
                    "SharpHound runs on Windows only.",
                ));
            }
            if password {
                return Err(FieldError::new(
                    3,
                    "collector",
                    "SharpHound always runs as your Windows account: it could only take a \
                     password on its command line, where other people on this computer could \
                     read it. Choose \"Use my Windows account\" in step 2, or the built-in \
                     collector.",
                ));
            }
            let raw = clean_path(&form.sharphound);
            if raw.is_empty() {
                return Err(FieldError::new(
                    3,
                    "sharphound",
                    "Enter where SharpHound.exe is, like C:\\Tools\\SharpHound.exe.",
                ));
            }
            // Refused before the file system is touched: even checking
            // that `\\server\share\x.exe` exists signs in to that server
            // (and on a mapped network drive the program comes from it).
            if crate::security::is_remote_path(raw) {
                return Err(FieldError::new(
                    3,
                    "sharphound",
                    "That is a network path. Copy SharpHound.exe to this computer and enter \
                     its local path, like C:\\Tools\\SharpHound.exe: even checking a network \
                     path makes Windows sign in to that server as you.",
                ));
            }
            let program = PathBuf::from(raw);
            if !program.is_absolute() {
                return Err(FieldError::new(
                    3,
                    "sharphound",
                    "Enter the full path, starting with the drive, like \
                     C:\\Tools\\SharpHound.exe.",
                ));
            }
            match std::fs::metadata(&program) {
                Ok(m) if m.is_file() => {}
                Ok(_) => {
                    return Err(FieldError::new(
                        3,
                        "sharphound",
                        format!("{raw} is a folder. Enter the path of SharpHound.exe itself."),
                    ))
                }
                Err(_) => {
                    return Err(FieldError::new(
                        3,
                        "sharphound",
                        format!("Nothing found at {raw}. Check the path."),
                    ))
                }
            }
            Method::External {
                program,
                kind: ExternalKind::SharpHound,
            }
        }
    };

    Ok(CollectRequest {
        domain,
        server,
        // The trusted domains' domain controllers: as typed, else found
        // through DNS.
        servers,
        locate_dc: false,
        auth,
        ldaps: form.ldaps,
        insecure_skip_tls_verify: form.ldaps && form.skip_verify,
        allow_unencrypted_ldap: false,
        allow_ntlm: form.allow_ntlm,
        allow_unsigned_smb: form.allow_unsigned_smb,
        // Set by the caller: the page's answer, else the environment's.
        service_reads: true,
        task_reads: true,
        output_dir,
        method,
        scope: match form.depth {
            Depth::Quick => Scope::DcOnly,
            Depth::Full => Scope::All,
        },
        expected_objects: None,
        cache: None,
        // From the environment's settings ([`all_attributes`]).
        all_attributes: false,
        // From the environment's settings ([`read_streams`]).
        read_streams: None,
    })
}

/// Objects in the latest collected run of `domain`: about what collecting it
/// again will process, for the progress bar.
fn last_size(runs: &[RunSummary], domain: &str) -> Option<u64> {
    runs.iter()
        .filter(|r| {
            r.collection
                .as_ref()
                .is_some_and(|c| c.domain.eq_ignore_ascii_case(domain))
        })
        .max_by(|a, b| a.order_key().cmp(&b.order_key()))
        .map(|r| r.objects as u64)
        .filter(|&n| n > 0)
}

/// Where the built-in collector keeps its read of `domain` while it reads
/// it: `<environment folder>\collect-cache`, with the size of the last read
/// of the domain in that environment for the free-space check. The
/// app and `pathwarden collect` both use it.
/// Whether a Full collection into `ws` reads the accounts services run as:
/// `asked` (the page's choice) unless the environment's pathwarden.toml
/// turns them off with `[collect] service_reads = false`. A file that can't
/// be read leaves the choice as it is.
pub fn service_reads_of(ws: &Workspace, asked: bool) -> bool {
    collect_switch_of(ws, asked, |c, off| c.service_reads(off))
}

/// [`service_reads_of`] for the environment `ws`, or with none the
/// current environment of the default workspace, as [`all_attributes`]
/// finds its setting (`pathwarden collect` without `--save`).
pub fn service_reads_in(ws: Option<&Workspace>, asked: bool) -> bool {
    collect_switch_in(ws, asked, service_reads_of)
}

/// Whether a Full collection into `ws` reads the scheduled tasks:
/// `asked` unless the environment's pathwarden.toml turns them
/// off with `[collect] task_reads = false`, as [`service_reads_of`].
pub fn task_reads_of(ws: &Workspace, asked: bool) -> bool {
    collect_switch_of(ws, asked, |c, off| c.task_reads(off))
}

/// [`task_reads_of`] as [`service_reads_in`] finds it.
pub fn task_reads_in(ws: Option<&Workspace>, asked: bool) -> bool {
    collect_switch_in(ws, asked, task_reads_of)
}

/// A `[collect]` switch that is on by default: `asked` unless the
/// environment's pathwarden.toml turns it off (`read`: the setting, given
/// whether the command turned it off). A file that can't be read leaves
/// the choice as it is.
fn collect_switch_of(
    ws: &Workspace,
    asked: bool,
    read: impl Fn(&pathwarden_core::config::CollectConfig, bool) -> bool,
) -> bool {
    let path = ws.config_path();
    if !path.is_file() {
        return asked;
    }
    match pathwarden_core::config::Config::from_file(&path) {
        Ok(c) => read(&c.collect, !asked),
        Err(_) => asked,
    }
}

/// A switch of [`collect_switch_of`] for `ws`, or with none the current
/// environment of the default workspace.
fn collect_switch_in(
    ws: Option<&Workspace>,
    asked: bool,
    of: fn(&Workspace, bool) -> bool,
) -> bool {
    match ws {
        Some(ws) => of(ws, asked),
        None => match workspace::default_dir().and_then(|root| Workspace::existing(&root)) {
            Ok(ws) => of(&ws, asked),
            Err(_) => asked,
        },
    }
}

pub fn read_cache(ws: &Workspace, domain: &str) -> ReadCache {
    let last = ws
        .runs()
        .into_iter()
        .filter(|r| {
            r.collection
                .as_ref()
                .is_some_and(|c| c.domain.eq_ignore_ascii_case(domain))
        })
        .max_by(|a, b| a.order_key().cmp(&b.order_key()));
    let timings = last
        .as_ref()
        .and_then(|r| ws.run_dir(&r.id))
        .and_then(|d| crate::diagnose::timings_of(&d))
        .filter(|t| t.entries > 0);
    // The entries and bytes the read took on disk; a read into memory gives
    // its entries only. The run's object count is no estimate of entries:
    // unknown then, and the sizing count decides.
    ReadCache {
        resume: false,
        root: ws.env_dir().join(pathwarden_collect::CACHE_DIR),
        last_entries: timings
            .as_ref()
            .map(|t| t.cache_entries.unwrap_or(t.entries)),
        last_bytes: timings
            .as_ref()
            .and_then(|t| t.cache_bytes)
            .filter(|&b| b > 0),
        // By type, for the progress's "of ~".
        last_counts: timings.map(|t| t.read_counts).unwrap_or_default(),
        last_when: last.as_ref().map(|r| r.created_at),
    }
}

/// Removes the reads on disk that can't be resumed any more, in every
/// environment of `ws`: the app does it when it starts. Returns how many
/// went.
pub fn sweep_stopped_reads(ws: &Workspace) -> usize {
    let mut envs: Vec<String> = ws
        .registry()
        .environments
        .iter()
        .map(|e| e.id.clone())
        .collect();
    envs.push(crate::environments::DEFAULT_ENV.into());
    envs.sort();
    envs.dedup();
    envs.iter()
        .map(|id| {
            pathwarden_collect::sweep_stopped_reads(
                &ws.in_env(id).env_dir().join(pathwarden_collect::CACHE_DIR),
            )
        })
        .sum()
}

/// The stopped read the Collect page offers to resume, as
/// `pathwarden collect` finds it ([`pathwarden_collect::stopped_read`]): of
/// the form's domains, the first whose read in `ws`'s environment the
/// form's sign-in can resume; with whether it is the first domain's. `None`
/// for SharpHound, or when there is none.
pub fn stopped_offer(ws: &Workspace, form: &CollectForm) -> Option<(StoppedRead, bool)> {
    if form.collector != Collector::Builtin || !BUILTIN {
        return None;
    }
    let auth = match form.auth {
        AuthChoice::Current => Auth::CurrentUser,
        AuthChoice::Password => Auth::Password {
            user: form.user.clone(),
            password: Secret::new(""),
        },
    };
    let domain = form
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if domain.is_empty() {
        return None;
    }
    let trusted = trusted_names(form).unwrap_or_default();
    std::iter::once(domain)
        .chain(trusted)
        .enumerate()
        .find_map(|(i, d)| {
            pathwarden_collect::stopped_read(&read_cache(ws, &d), &d, &auth).map(|s| (s, i == 0))
        })
}

/// Whether a read of one of the run's domains is kept on disk to resume.
fn kept_reads(req: &CollectRequest, trusted: &[String]) -> bool {
    let Some(cache) = &req.cache else {
        return false;
    };
    std::iter::once(&req.domain)
        .chain(trusted)
        .any(|d| pathwarden_collect::stopped_read(cache, d, &req.auth).is_some())
}

/// "An earlier read stopped at 61%, 2 h ago.", naming the domain when it
/// isn't the first of the run.
pub fn offer_words(s: &StoppedRead, first: bool, now: i64) -> String {
    let of = if first {
        String::new()
    } else {
        format!(" of {}", s.domain.to_ascii_uppercase())
    };
    format!(
        "An earlier read{of} stopped at {}%, {}.",
        s.percent,
        s.ago(now)
    )
}

/// `POST /api/collect/stopped`: the read the Ready step offers to resume,
/// for the answers and the environment chosen: `{"stopped": null}` or
/// `{"stopped": {"text": ...}}`.
async fn stopped(State(st): State<Shared>, SecretJson(form): SecretJson<CollectForm>) -> Response {
    let ws = match crate::server::check_choice(
        &st,
        form.env.as_deref(),
        form.new_env.as_deref(),
        form.env_auto,
    ) {
        Ok(Some((Some(id), _))) => st.ws().in_env(&id),
        // A new environment has no reads yet.
        Ok(Some((None, _))) => {
            return Json(serde_json::json!({ "stopped": null })).into_response();
        }
        Ok(None) => st.ws(),
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let offer = stopped_offer(&ws, &form).map(|(s, first)| {
        serde_json::json!({
            "text": offer_words(&s, first, analyze::now()),
            "percent": s.percent,
        })
    });
    Json(serde_json::json!({ "stopped": offer })).into_response()
}

/// [`read_cache`] in the default workspace's Default environment, for a
/// `pathwarden collect` that saves no run. `None` when there is no folder
/// for a workspace.
pub fn default_read_cache(domain: &str) -> Option<ReadCache> {
    let root = workspace::default_dir().ok()?;
    match Workspace::existing(&root) {
        Ok(ws) if root.join("runs").is_dir() => Some(read_cache(&ws, domain)),
        _ => Some(ReadCache {
            root: root.join(pathwarden_collect::CACHE_DIR),
            ..ReadCache::default()
        }),
    }
}

/// Whether the environment's `pathwarden.toml` asks the built-in collector
/// for every attribute (`[collect] all_attributes`): in `ws`, or the
/// default workspace's Default environment for a `pathwarden collect`
/// that saves no run. The app and `pathwarden collect` both ask here. Off
/// when the settings can't be read.
pub fn all_attributes(ws: Option<&Workspace>) -> bool {
    let config = match ws {
        Some(ws) => ws.config(),
        None => workspace::default_dir().and_then(|root| Workspace::existing(&root)?.config()),
    };
    config.is_ok_and(|c| c.collect.all_attributes)
}

/// How many connections the environment's `pathwarden.toml` has the
/// built-in collector read with (`[collect] read_streams`), as
/// [`all_attributes`] finds it. `None`: not set, or the settings can't be
/// read (the collector's default).
pub fn read_streams(ws: Option<&Workspace>) -> Option<usize> {
    let config = match ws {
        Some(ws) => ws.config(),
        None => workspace::default_dir().and_then(|root| Workspace::existing(&root)?.config()),
    };
    config.ok().and_then(|c| c.collect.read_streams())
}

/// How a request was collected, for the run summary (no credentials).
pub fn collection_info(req: &CollectRequest) -> CollectionInfo {
    CollectionInfo {
        read_started: None,
        method: match req.method {
            Method::Builtin => "builtin",
            Method::External { .. } => "sharphound",
        }
        .into(),
        scope: match req.scope {
            Scope::All => "all",
            _ => "dc-only",
        }
        .into(),
        domain: req.domain.clone(),
        server: req.server.clone(),
        ldaps: req.ldaps,
        current_user: matches!(req.auth, Auth::CurrentUser),
        warnings: Vec::new(),
        kept: None,
        // SharpHound signs in to computers its own way: not enforced.
        kerberos_only: Some(req.method == Method::Builtin && !req.allow_ntlm),
        // As the Windows account, Windows' own SMB client signs as its
        // policy says: not Pathwarden's to require or check.
        smb_signing: match (&req.method, &req.auth) {
            (Method::Builtin, Auth::CurrentUser) => None,
            (Method::Builtin, _) => Some(!req.allow_unsigned_smb),
            _ => Some(false),
        },
        domains: Vec::new(),
    }
}

/// The account names a collection's messages may carry: the user
/// name as typed and its bare name. The run never records them.
pub fn account_names(req: &CollectRequest) -> Vec<String> {
    match &req.auth {
        Auth::Password { user, .. } => vec![user.trim().to_string()],
        _ => Vec::new(),
    }
}

/// A failed domain's detail as the run keeps it: local paths cut to
/// their last part, and any account name (`names`, those the directories
/// reported, any `DOMAIN\user`, a `user@domain` of a known user) said as
/// "the account". The run summary never holds the user name.
pub fn scrub_detail(text: &str, names: &[String]) -> String {
    let text = crate::shared_runs::scrub_path_words(text);
    // Bare names: `svc` of `CONTOSO\svc` or `svc@contoso.local`.
    let mut bare: Vec<String> = Vec::new();
    for n in names {
        let n = n.trim();
        let b = n
            .rsplit_once('\\')
            .map(|(_, u)| u)
            .unwrap_or(n)
            .split('@')
            .next()
            .unwrap_or_default();
        for x in [n, b] {
            if !x.is_empty() && !bare.iter().any(|y| y.eq_ignore_ascii_case(x)) {
                bare.push(x.to_string());
            }
        }
    }
    let is_account = |core: &str| {
        if core.is_empty() {
            return false;
        }
        if bare.iter().any(|b| b.eq_ignore_ascii_case(core)) {
            return true;
        }
        if let Some((d, u)) = core.split_once('\\') {
            return !d.is_empty() && !u.is_empty();
        }
        if let Some((u, _)) = core.split_once('@') {
            return bare.iter().any(|b| b.eq_ignore_ascii_case(u));
        }
        false
    };
    text.split(' ')
        .map(|tok| {
            let core = tok.trim_matches(|c: char| {
                matches!(
                    c,
                    '"' | '\'' | '(' | ')' | ',' | '.' | ':' | ';' | '[' | ']'
                )
            });
            if is_account(core) {
                tok.replacen(core, "the account", 1)
            } else {
                tok.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .replace("the account the account", "the account")
}

/// Records how each domain of a run went, from
/// [`pathwarden_collect::collect_domains`]: `info.domains`, each failure
/// as the app shows it ([`pathwarden_collect::DomainResult::saved_failure`]),
/// its detail without account names or local paths ([`scrub_detail`];
/// `names`: [`account_names`]).
pub fn record_domains(
    info: &mut CollectionInfo,
    results: &[pathwarden_collect::DomainResult],
    names: &[String],
) {
    let mut names = names.to_vec();
    names.extend(
        results
            .iter()
            .filter_map(|r| r.outcome.as_ref().ok()?.signed_in_as.clone()),
    );
    info.domains = results
        .iter()
        .map(|r| {
            let failure = r.saved_failure();
            crate::workspace::DomainOutcome {
                domain: r.domain.to_ascii_uppercase(),
                collected: failure.is_none(),
                objects: failure.is_none().then(|| r.objects()),
                seconds: Some(r.elapsed.as_secs()),
                detail: failure
                    .as_ref()
                    .map(|(_, d)| scrub_detail(d, &names))
                    .filter(|d| !d.is_empty()),
                reason: failure.map(|(s, _)| scrub_detail(&s, &names)),
            }
        })
        .collect();
}

/// The domains a run's trust records name that it didn't collect:
/// as saved, or for a run saved before, its trusted domains.
pub fn not_collected(r: &RunSummary) -> Vec<String> {
    r.not_collected
        .clone()
        .or_else(|| r.trusted_domains.clone())
        .unwrap_or_default()
}

/// The Collect page for what a run left out: its domain, with the
/// domains that failed ticked, or else the trusted domains it didn't
/// collect. `None` when nothing was left out.
pub fn collect_again_href(r: &RunSummary) -> Option<String> {
    // A run loaded from the history never picks where this computer signs
    // in: whoever can write the history chose its domains.
    if r.shared.is_some() {
        return None;
    }
    let domain = match &r.collection {
        Some(c) => c.domain.clone(),
        // A run from a file: its first domain.
        None => r.domains.first()?.clone(),
    };
    let failed = r
        .collection
        .as_ref()
        .map(|c| c.failed_domains())
        .unwrap_or_default();
    let pick: Vec<String> = if failed.is_empty() {
        not_collected(r)
    } else {
        failed
    };
    if pick.is_empty() {
        return None;
    }
    let enc = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    Some(format!(
        "/collect?domain={}&pick={}",
        enc(&domain.to_ascii_lowercase()),
        pick.iter().map(|d| enc(d)).collect::<Vec<_>>().join(",")
    ))
}

// ----------------------------------------------------------------- pages

#[derive(Deserialize)]
struct PageQuery {
    job: Option<String>,
    /// From a run's "Collect them": the domain, and the trusted
    /// domains to tick (comma-separated).
    domain: Option<String>,
    pick: Option<String>,
}

/// What the Collect page starts with besides what it detects: the
/// domain from a link or the environment's last run, and the trusted
/// domains to tick.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prefill {
    pub domain: Option<String>,
    /// The environment whose last run it comes from, for the hint.
    pub from_env: Option<String>,
    pub pick: Vec<String>,
    /// "Read service accounts" ticked: the environment's `[collect]
    /// service_reads`, on when not set.
    pub service_reads: bool,
    /// "Read scheduled tasks" ticked: the environment's `[collect]
    /// task_reads`, on when not set.
    pub task_reads: bool,
}

/// The page's prefill: a link's domain and picks, else (when this computer
/// gives no domain) the domain of the environment's last collected run.
fn prefill(runs: &[RunSummary], env: &str, detected: &Detected, q: &PageQuery) -> Prefill {
    let clean = |s: &str| {
        let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
        (host_like(&s) && s.contains('.')).then_some(s)
    };
    let pick: Vec<String> = q
        .pick
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .filter_map(clean)
        .take(MAX_TRUSTED)
        .collect();
    if let Some(d) = q.domain.as_deref().and_then(clean) {
        return Prefill {
            domain: Some(d),
            from_env: Some(env.to_string()),
            pick,
            ..Prefill::default()
        };
    }
    if detected.domain.is_some() {
        return Prefill {
            pick,
            ..Prefill::default()
        };
    }
    // This computer's own runs only: a run loaded from the history never
    // picks where it signs in.
    let last = runs
        .iter()
        .find(|r| !r.demo && r.shared.is_none())
        .and_then(|r| {
            r.collection
                .as_ref()
                .map(|c| c.domain.clone())
                .or_else(|| r.domains.first().cloned())
        });
    Prefill {
        domain: last.map(|d| d.to_ascii_lowercase()),
        from_env: Some(env.to_string()),
        pick,
        ..Prefill::default()
    }
}

async fn page(State(st): State<Shared>, Query(q): Query<PageQuery>) -> Html<String> {
    let runs = st.ws().runs();
    // Resume a collection's progress: the one named, or the one running.
    let job = q
        .job
        .clone()
        .filter(|id| workspace::valid_run_id(id))
        .and_then(|id| st.jobs.get(&id))
        .or_else(|| st.jobs.running())
        .filter(|j| j.collect.is_some());
    let ctx = pages::Ctx::new(&st, &runs);
    let detected = Detected::from_env();
    let mut pre = prefill(&runs, &ctx.env_name, &detected, &q);
    pre.service_reads = service_reads_of(&st.ws(), true);
    pre.task_reads = task_reads_of(&st.ws(), true);
    Html(view::wizard(&ctx, &detected, st.keep_uploads, job, &pre))
}

#[derive(Deserialize)]
struct TrustedQuery {
    #[serde(default)]
    domain: String,
}

/// The trusted domains the Collect page lists for a domain, from the
/// newest run that collected it, in any environment.
async fn trusted(State(st): State<Shared>, Query(q): Query<TrustedQuery>) -> Response {
    let found = tokio::task::spawn_blocking(move || {
        // The current environment's runs first, then every other's.
        known_trusted(&st, &q.domain)
    })
    .await
    .ok()
    .flatten();
    match found {
        Some(f) => Json(serde_json::json!({
            "from": f.domain,
            "env": f.env,
            "domains": f.domains,
        }))
        .into_response(),
        None => Json(serde_json::json!({ "domains": [] })).into_response(),
    }
}

/// A run's "Collect them": the Collect page with its domain, and the
/// domains it left out ticked.
async fn collect_again(State(st): State<Shared>, UrlPath(id): UrlPath<String>) -> Response {
    let to = st
        .workspace
        .run(&id)
        .and_then(|r| collect_again_href(&r))
        .unwrap_or_else(|| "/collect".into());
    (StatusCode::SEE_OTHER, [(header::LOCATION, to)]).into_response()
}

/// The nightly files for `q`, based on `run` (the Automate area's Schedule
/// page, [`crate::automate`]).
pub(crate) fn schedule_target(
    q: &ScheduleParams,
    run: Option<&RunSummary>,
    env: &str,
) -> (Target, Vec<String>) {
    Target::resolve_in(q, run, &Detected::from_env(), Some(env))
}

/// The Schedule page, with `status` (what is already scheduled, and the run
/// picker) above the files. `typed` is what the form sent: with `errors`,
/// the form shows it again to be corrected.
pub(crate) fn schedule_page(
    ctx: &pages::Ctx,
    run: Option<&RunSummary>,
    t: &Target,
    typed: &ScheduleParams,
    errors: &[String],
    status: &str,
) -> String {
    view::schedule(ctx, run, t, typed, errors, status)
}

pub use view::{collected_words, computers_sentence};

// ------------------------------------------------------------------- API

/// One connection check at a time per server (each can take up to a minute
/// and contacts the domain controller). Held until the check ends.
struct CheckSlot(Arc<Jobs>);

impl CheckSlot {
    fn take(jobs: &Arc<Jobs>) -> Option<Self> {
        (!jobs.checking.swap(true, Ordering::SeqCst)).then(|| CheckSlot(jobs.clone()))
    }
}

impl Drop for CheckSlot {
    fn drop(&mut self) {
        self.0.checking.store(false, Ordering::SeqCst);
    }
}

/// Which step to send the user back to for a connection problem.
fn problem_step(p: Problem) -> u8 {
    match p {
        Problem::Dns
        | Problem::Refused
        | Problem::Unreachable
        | Problem::Timeout
        | Problem::Stalled => 1,
        Problem::CertificateName | Problem::WrongDomain | Problem::NotLocated => 1,
        Problem::Credentials
        | Problem::Kerberos
        | Problem::SigningRequired
        | Problem::CertificateUntrusted
        | Problem::CertificateExpired
        | Problem::NoTicket
        | Problem::Tls => 2,
        Problem::NoBuiltin | Problem::Settings | Problem::Other => 3,
    }
}

fn about(c: pathwarden_collect::Count, what: &str) -> String {
    if c.at_least {
        format!("more than {} {what}", pages::num(c.n))
    } else {
        format!("{} {what}", pages::num(c.n))
    }
}

/// The check's findings as sentences for the page.
fn check_lines(check: &ConnectionCheck, detected: &Detected) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(program) = &check.program {
        lines.push(format!(
            "Found SharpHound at {}.",
            workspace::shown_path(program)
        ));
        lines.push(match &detected.account {
            Some(a) => format!("It will run as {a}, the account you're signed in with."),
            None => "It will run as the account you're signed in with.".into(),
        });
        return lines;
    }
    match (&check.server, &check.bound_as) {
        (Some(s), Some(who)) => lines.push(format!("Connected to {s} and signed in as {who}.")),
        (Some(s), None) => lines.push(format!("Connected to {s} and signed in.")),
        _ => lines.push("Connected and signed in.".into()),
    }
    if let Some(k) = &check.kerberos {
        lines.push(k.clone());
    }
    match (check.users, check.computers) {
        (Some(u), Some(c)) => lines.push(format!(
            "The domain has {} and {}.",
            about(u, "user accounts"),
            about(c, "computers")
        )),
        (Some(u), None) => lines.push(format!("The domain has {}.", about(u, "user accounts"))),
        _ => {}
    }
    lines
}

/// What the check did not cover, so the page doesn't suggest more was
/// checked than was.
fn unchecked_lines(check: &ConnectionCheck, full: bool, kerberos_only: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if check.program.is_some() {
        lines.push(
            "Finding the domain controller, connecting and signing in: SharpHound does that \
             itself when it runs."
                .into(),
        );
        lines.push(
            "Whether the file is SharpHound v2: Pathwarden only checked that it is there.".into(),
        );
    } else if check.users.is_none() {
        lines.push("How big the domain is: counting users took too long or wasn't allowed.".into());
    }
    if full && kerberos_only && check.program.is_none() {
        lines.push(
            "Signing in to each computer for sessions and local groups: that happens during the \
             collection. Computers that are off, refuse, or have no Kerberos name show as not \
             collected in the report."
                .into(),
        );
    } else if full {
        lines.push(
            "Signing in to each computer for sessions and local groups: that happens during the \
             collection. Computers that are off or refuse show as not collected in the report."
                .into(),
        );
    }
    lines
}

async fn test(State(st): State<Shared>, SecretJson(mut form): SecretJson<CollectForm>) -> Response {
    if !form.trusted.is_empty() {
        let known = known_trusted_off_thread(&st, &form.domain).await;
        keep_known_trusted(&mut form, known.as_ref());
    }
    let full = form.depth == Depth::Full;
    let trusted = match trusted_names(&form) {
        Ok(t) => t,
        Err(e) => return e.response(),
    };
    let req = match build_request(form, PathBuf::from("connection-check")) {
        Ok(r) => r,
        Err(e) => return e.response(),
    };
    let kerberos_only = !req.allow_ntlm;
    let Some(slot) = CheckSlot::take(&st.jobs) else {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "A connection check is already running. Wait for it to finish.",
        );
    };
    // The check blocks (up to a minute): off the server thread. The slot and
    // the request (with the password) are dropped as soon as it ends, even
    // if the browser has gone.
    let done = tokio::task::spawn_blocking(move || {
        // Each trusted domain too, after the domain itself.
        let mut results = pathwarden_collect::test_domains(&req, &trusted);
        // SharpHound that isn't SpecterOps': said once, for the run.
        let unsigned = pathwarden_collect::signature::request_warning(&req);
        drop(req);
        drop(slot);
        let first = results.remove(0).1;
        first.map(|check| (check, results, unsigned))
    })
    .await;
    match done {
        Ok(Ok((check, others, unsigned))) => {
            let mut lines = check_lines(&check, &Detected::from_env());
            let mut warnings: Vec<String> = unsigned.into_iter().collect();
            warnings.extend(check.warnings.iter().cloned());
            let (more_lines, more_warnings) = trusted_lines(&others);
            lines.extend(more_lines);
            warnings.extend(more_warnings);
            Json(serde_json::json!({
                "ok": true,
                "lines": lines,
                "not_checked": unchecked_lines(&check, full, kerberos_only),
                "server": check.server,
                "bound_as": check.bound_as,
                "warnings": warnings,
            }))
            .into_response()
        }
        Ok(Err(e)) => {
            let (problem, detail, headline) = match e.downcast_ref::<ConnectionError>() {
                Some(ce) => (ce.problem, ce.detail.clone(), ce.headline.clone()),
                None => (Problem::Other, format!("{e:#}"), None),
            };
            let error = match (headline, problem) {
                (Some(h), _) => h,
                (None, Problem::Settings) => capitalize(&detail),
                (None, p) => p.explain().to_string(),
            };
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": error,
                    "detail": if problem == Problem::Settings { String::new() } else { detail },
                    "step": problem_step(problem),
                    "dns": problem == Problem::Dns,
                })),
            )
                .into_response()
        }
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The check stopped. Try again.",
        ),
    }
}

/// The check's lines and warnings for the trusted domains of a run:
/// a domain that answered, in one line; one that didn't, a warning that it
/// will be skipped.
fn trusted_lines(
    results: &[(String, anyhow::Result<ConnectionCheck>)],
) -> (Vec<String>, Vec<String>) {
    let (mut lines, mut warnings) = (Vec::new(), Vec::new());
    for (domain, r) in results {
        let name = domain.to_ascii_uppercase();
        match r {
            // SharpHound signs in to each domain itself when it runs: the
            // check only found the program.
            Ok(c) if c.program.is_some() => {}
            Ok(c) => {
                lines.push(match (&c.server, &c.bound_as) {
                    (Some(s), Some(who)) => {
                        format!("{name}: connected to {s} and signed in as {who}.")
                    }
                    (Some(s), None) => format!("{name}: connected to {s} and signed in."),
                    _ => format!("{name}: connected and signed in."),
                });
                if let Some(k) = &c.kerberos {
                    lines.push(format!("{name}: {k}"));
                }
                warnings.extend(c.warnings.iter().map(|w| format!("{name}: {w}")));
            }
            Err(e) => {
                let (short, _) = pathwarden_collect::short_reason(e);
                warnings.push(format!("{name}: {short} It will be skipped."));
            }
        }
    }
    (lines, warnings)
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

fn busy() -> Response {
    json_error(
        StatusCode::CONFLICT,
        "Pathwarden is already collecting or analyzing. Wait for it to finish, then try again.",
    )
}

async fn start(
    State(st): State<Shared>,
    SecretJson(mut form): SecretJson<CollectForm>,
) -> Response {
    if st.jobs.running().is_some() {
        return busy();
    }
    if !form.trusted.is_empty() {
        let known = known_trusted_off_thread(&st, &form.domain).await;
        keep_known_trusted(&mut form, known.as_ref());
    }
    let id = workspace::new_run_id(analyze::now());
    let out = st.ws().uploads_dir().join(&id);
    let keep = form.keep;
    let env_auto = form.env_auto;
    let (env, new_env) = match crate::server::check_choice(
        &st,
        form.env.as_deref(),
        form.new_env.as_deref(),
        env_auto,
    ) {
        Ok(c) => c.unwrap_or_default(),
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let label = match crate::workspace::clean_label(form.label.as_deref().unwrap_or_default()) {
        Ok(l) => l,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let (depth, collector) = (form.depth, form.collector);
    let asked_service_reads = form.service_reads;
    let asked_task_reads = form.task_reads;
    let resume = form.resume;
    let also_id = form.also.take().filter(|a| !a.is_empty());
    let trusted = match trusted_names(&form) {
        Ok(t) => t,
        Err(e) => return e.response(),
    };
    // The password typed for it never reaches the log, while it runs.
    let masked = form
        .password
        .as_ref()
        .map(|p| pathwarden_core::redact::mask_while(p.expose()));
    let mut req = match build_request(form, out) {
        Ok(r) => r,
        Err(e) => return e.response(),
    };
    // The trusted domains come from the environment the page placed the
    // domain in: the run goes there, with them.
    let env_auto = env_auto && trusted.is_empty();
    req.expected_objects = last_size(&st.ws().runs(), &req.domain);
    if req.method == Method::Builtin {
        // In the environment picked for the run, else the current one.
        let ws = match &env {
            Some(id) => st.ws().in_env(id),
            None => st.ws(),
        };
        req.cache = Some(ReadCache {
            resume,
            ..read_cache(&ws, &req.domain)
        });
        req.all_attributes = all_attributes(Some(&ws));
        req.read_streams = read_streams(Some(&ws));
        // "Read service accounts", else the environment's
        // `[collect] service_reads`, as the command line reads it.
        req.service_reads = asked_service_reads.unwrap_or_else(|| service_reads_of(&ws, true));
        // "Read scheduled tasks", likewise with `[collect] task_reads`.
        req.task_reads = asked_task_reads.unwrap_or_else(|| task_reads_of(&ws, true));
    }
    let info = collection_info(&req);
    // Other collectors' files, uploaded a moment ago.
    let also = match also_id {
        Some(id) => match st.jobs.take_also(&id) {
            Some(a) => Some(a),
            None => return json_error(
                StatusCode::CONFLICT,
                "The files to analyze with the collection are no longer waiting. Add them again.",
            ),
        },
        None => None,
    };
    let also_names = also.as_ref().map(|a| a.names.clone()).unwrap_or_default();
    let source = format!(
        "Collected from {}{} ({}, {})",
        req.domain,
        match trusted.len() {
            0 => String::new(),
            1 => " and 1 trusted domain".into(),
            n => format!(" and {n} trusted domains"),
        },
        depth.label(),
        match collector {
            Collector::Builtin => "built-in",
            Collector::Sharphound => "SharpHound",
        }
    );
    let source = crate::add_data::source_with(&source, &also_names);
    let progress = CollectProgress {
        method: collector.label().into(),
        depth: depth.label().into(),
        domain: req.domain.to_ascii_uppercase(),
        phase: "Starting".into(),
        domains: if trusted.is_empty() {
            Vec::new()
        } else {
            std::iter::once(req.domain.clone())
                .chain(trusted.iter().cloned())
                .map(|d| DomainRun {
                    name: d.to_ascii_uppercase(),
                    state: "waiting",
                    text: "Waiting".into(),
                })
                .collect()
        },
        also: also_names,
        ..CollectProgress::default()
    };
    let cancel = Arc::new(AtomicBool::new(false));
    if !st
        .jobs
        .try_begin_collect(&id, source.clone(), progress, cancel.clone())
    {
        if let Some(a) = &also {
            a.discard(st.keep_uploads);
        }
        return busy();
    }
    if let Some(log) = st.jobs.open_log(
        &id,
        pathwarden_core::logs::Kind::Collect,
        &req.domain.to_ascii_uppercase(),
    ) {
        log.line(&source);
        if let Some(server) = &info.server {
            log.line(&format!("domain controller {server} (chosen)"));
        }
        for t in &trusted {
            log.line(&format!(
                "trusted domain {} after it",
                t.to_ascii_uppercase()
            ));
        }
    }
    let job = CollectJob {
        _masked: masked,
        jobs: st.jobs.clone(),
        ws: st.ws(),
        id: id.clone(),
        source,
        info,
        keep,
        keep_uploads: st.keep_uploads,
        cancel,
        env,
        new_env,
        env_auto,
        label,
        trusted,
        also,
    };
    std::thread::spawn(move || job.run(req));
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "job": id }))).into_response()
}

/// `/api/collect/also`: other collectors' files to analyze with the
/// collection, uploaded from step 5 just before Start collecting, as
/// Analyze uploads them ([`crate::server::receive`]: the same limits, one
/// folder each under `uploads/`). They wait for Start collecting, which
/// names them by the `also` this answers; files uploaded again replace
/// them. Answers `{also, names}`.
async fn stage_also(State(st): State<Shared>, mut form: axum::extract::Multipart) -> Response {
    if st.jobs.running().is_some() {
        return busy();
    }
    let id = workspace::new_run_id(analyze::now());
    let scratch = st.ws().uploads_dir().join(&id);
    match crate::server::receive(&st, &scratch, &mut form).await {
        Ok(r) => {
            let names: Vec<String> = r
                .inputs
                .iter()
                .map(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| p.display().to_string())
                })
                .collect();
            st.jobs.stage_also(
                jobs::AlsoFiles {
                    id: id.clone(),
                    dir: scratch.exists().then_some(scratch),
                    inputs: r.inputs,
                    names: names.clone(),
                },
                st.keep_uploads,
            );
            Json(serde_json::json!({ "also": id, "names": names })).into_response()
        }
        Err(message) => {
            let _ = tokio::fs::remove_dir_all(&scratch).await;
            json_error(StatusCode::BAD_REQUEST, message)
        }
    }
}

async fn cancel(State(st): State<Shared>, UrlPath(id): UrlPath<String>) -> Response {
    if !workspace::valid_run_id(&id) {
        return json_error(StatusCode::BAD_REQUEST, "Invalid job.");
    }
    if st.jobs.cancel(&id) {
        StatusCode::ACCEPTED.into_response()
    } else {
        json_error(
            StatusCode::CONFLICT,
            "This collection can't be stopped now: it has finished, or the analysis has started.",
        )
    }
}

// ------------------------------------------------------------------- job

/// A collection followed by its analysis, on its own thread.
struct CollectJob {
    /// The typed password, masked in logs until the job ends.
    _masked: Option<pathwarden_core::redact::Masked>,
    jobs: Arc<Jobs>,
    ws: Workspace,
    id: String,
    source: String,
    info: CollectionInfo,
    keep: bool,
    keep_uploads: bool,
    cancel: Arc<AtomicBool>,
    env: Option<String>,
    new_env: Option<String>,
    env_auto: bool,
    label: Option<String>,
    /// Trusted domains collected after the domain.
    trusted: Vec<String>,
    /// Other collectors' files analyzed with the collection.
    also: Option<jobs::AlsoFiles>,
}

/// A domain of a collection started, ended or failed, as its log says it.
fn domain_line(e: &pathwarden_collect::DomainEvent) -> String {
    use pathwarden_collect::DomainState;
    let d = e.domain.to_ascii_uppercase();
    match &e.state {
        DomainState::Started => format!("domain {d} ({} of {}) started", e.index + 1, e.total),
        DomainState::Done { seconds, .. } => format!("domain {d} done in {seconds} s"),
        DomainState::Failed { reason, .. } => format!("domain {d} failed: {reason}"),
    }
}

/// A domain of a collection of several started, ended or failed:
/// its line on the Collect page.
fn domain_event(c: &mut CollectProgress, e: &pathwarden_collect::DomainEvent) {
    use pathwarden_collect::DomainState;
    if let DomainState::Started = e.state {
        // This domain's own counts from here.
        c.objects.clear();
        c.status = None;
    }
    let Some(row) = c.domains.get_mut(e.index) else {
        return;
    };
    match &e.state {
        DomainState::Started => {
            row.state = "active";
            row.text = "Collecting".into();
        }
        DomainState::Done { seconds, .. } => {
            row.state = "done";
            row.text = format!(
                "Done · {}",
                if *seconds < 60 {
                    format!("{seconds} s")
                } else {
                    format!("{} min", (seconds + 30) / 60)
                }
            );
        }
        DomainState::Failed { reason, .. } => {
            row.state = "failed";
            row.text = reason.clone();
        }
    }
}

impl CollectJob {
    fn run(mut self, req: CollectRequest) {
        let out = req.output_dir.clone();
        let names = account_names(&req);
        let log = self.jobs.log(&self.id);
        let _in = log.as_ref().map(|l| l.enter());
        let collected = {
            let jobs = &self.jobs;
            let id = &self.id;
            let mut on_progress = |p: Progress| {
                if let Some(l) = &log {
                    match &p {
                        Progress::Phase(s) => l.line(&format!("step: {s}")),
                        Progress::Log(line) => l.line(line),
                        Progress::Domain(e) => l.line(&domain_line(e)),
                        Progress::Objects { .. } | Progress::Status(_) => {}
                    }
                }
                jobs.update_collect(id, |c| match p {
                    Progress::Phase(s) => c.phase = s,
                    Progress::Objects { kind, count } => {
                        c.objects.insert(kind, count);
                    }
                    Progress::Status(s) => {
                        c.phase = s.phase.clone();
                        c.status = Some(*s);
                    }
                    Progress::Domain(e) => domain_event(c, &e),
                    Progress::Log(line) => {
                        c.log_total += 1;
                        c.log.push(line);
                        if c.log.len() > LOG_LINES {
                            c.log.remove(0);
                        }
                    }
                })
            };
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pathwarden_collect::collect_domains(
                    &req,
                    &self.trusted,
                    &mut on_progress,
                    &self.cancel,
                )
            }))
            .unwrap_or_else(|_| Err(anyhow::anyhow!("the collector stopped unexpectedly")))
        };
        // Stopped: whether a read was kept to resume. A domain that
        // finished is not saved; one that hadn't keeps its read.
        let stopped = self.cancel.load(Ordering::SeqCst)
            || matches!(&collected, Err(e) if e.is::<Cancelled>());
        let kept = stopped && kept_reads(&req, &self.trusted);
        // Zeroes the password: nothing below needs it.
        drop(req);

        let results = match collected {
            _ if stopped => {
                let _ = std::fs::remove_dir_all(&out);
                self.discard_also();
                self.jobs.update_collect(&self.id, |c| c.resumable = kept);
                return self.jobs.set(&self.id, JobStatus::Stopped);
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&out);
                return self.failed(&e);
            }
            Ok(r) => r,
        };
        // Nothing collected: the first domain's reason. Otherwise the
        // domains that failed are left out, and say so in Run details.
        if let Some(Err(e)) = results
            .iter()
            .all(|r| r.outcome.is_err())
            .then(|| results.first().map(|r| &r.outcome))
            .flatten()
        {
            let _ = std::fs::remove_dir_all(&out);
            return self.failed(e);
        }
        record_domains(&mut self.info, &results, &names);
        let outcome = pathwarden_collect::merged(&results);
        self.info.read_started = outcome.read_started;

        let warnings: Vec<String> = outcome.warnings.iter().map(|w| capitalize(w)).collect();
        if let Some(l) = &log {
            let counts: Vec<String> = pathwarden_collect::summarize_outputs(&outcome.files)
                .into_iter()
                .map(|(k, n)| format!("{k} {n}"))
                .collect();
            l.line(&format!("collected: {}", counts.join(", ")));
            for w in &warnings {
                l.line(&format!("warning: {w}"));
            }
        }
        self.info.warnings = warnings.clone();
        // Keep: move the collection out of uploads/ (emptied at start-up)
        // before analyzing, so the run records where it really is.
        let (dir, inputs) = match self.keep.then(|| self.keep_dir(&out)).flatten() {
            Some(kept) => {
                let inputs = relocate(&outcome.files, &out, &kept);
                self.info.kept = Some(kept.display().to_string());
                (kept, inputs)
            }
            None => (out.clone(), outcome.files.clone()),
        };
        // Other collectors' files: read with the collection, in the same
        // analysis. Never moved into a kept collection.
        let mut inputs = inputs;
        let also_dir = self.also.take().and_then(|a| {
            inputs.extend(a.inputs);
            a.dir
        });
        let kept = self.info.kept.clone();
        self.jobs.update_collect(&self.id, |c| {
            c.warnings = warnings;
            c.collected_at = Some(analyze::now());
            c.kept = kept;
            c.phase = "Collected".into();
        });
        self.jobs.set(
            &self.id,
            JobStatus::Running {
                phase: analyze::Phase::Reading,
            },
        );
        let mut spec = JobSpec {
            id: self.id.clone(),
            inputs,
            scratch: Some(dir.clone()),
            also_scratch: also_dir.clone(),
            source: self.source.clone(),
            demo: false,
            env: self.env.clone(),
            new_env: self.new_env.clone(),
            env_auto: self.env_auto,
            label: self.label.clone(),
            collection: Some(self.info.clone()),
            timings: outcome.timings.clone(),
            // A collection just made: never "already analyzed".
            force: true,
        };
        self.log_memory("before analysis");
        let analyzed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            jobs::analyze_with(&self.jobs, &self.ws, &spec)
        }))
        .unwrap_or_else(|_| Err("The analysis stopped. Try again.".into()));
        self.log_memory("after analysis");
        if let Ok(Some(stopped)) = analyzed {
            // Something's off with the environment: the collection waits
            // (a kept one is never deleted afterwards) until the user picks.
            if self.info.kept.is_some() {
                spec.scratch = None;
            }
            self.jobs.keep_pending(&self.id, spec);
            return self.jobs.set(&self.id, stopped);
        }
        if self.info.kept.is_none() && !self.keep_uploads {
            let _ = std::fs::remove_dir_all(&dir);
        }
        if let (Some(also), false) = (&also_dir, self.keep_uploads) {
            let _ = std::fs::remove_dir_all(also);
        }
        self.jobs.set(
            &self.id,
            match analyzed {
                Ok(_) => JobStatus::Done {
                    run: self.id.clone(),
                },
                Err(error) => JobStatus::Failed { error },
            },
        );
    }

    /// The collection failed: why, and whether its read can be resumed,
    /// for the page's Resume button.
    fn failed(&mut self, e: &anyhow::Error) {
        self.discard_also();
        if e.is::<ReadStopped>() {
            self.jobs.update_collect(&self.id, |c| c.resumable = true);
        }
        let error = collect_error(e);
        self.jobs.set(&self.id, JobStatus::Failed { error });
    }

    /// Nothing to analyze: the files uploaded to go with the collection
    ///  are deleted, unless uploads are kept.
    fn discard_also(&mut self) {
        if let Some(a) = self.also.take() {
            a.discard(self.keep_uploads);
        }
    }

    /// The `[memory]` line for `phase`, in the collection's log.
    fn log_memory(&self, phase: &str) {
        if let Some(line) = pathwarden_collect::memory::line(phase) {
            self.jobs.log_line(&self.id, &line);
            self.jobs.update_collect(&self.id, |c| {
                c.log_total += 1;
                c.log.push(line);
                if c.log.len() > LOG_LINES {
                    c.log.remove(0);
                }
            });
        }
    }

    /// Moves the collection to `collections/<id>/`; `None` if that fails
    /// (then it is treated like any upload).
    fn keep_dir(&self, out: &Path) -> Option<PathBuf> {
        let dest = self.ws.collections_dir().join(&self.id);
        std::fs::create_dir_all(self.ws.collections_dir()).ok()?;
        std::fs::rename(out, &dest).ok()?;
        Some(dest)
    }
}

/// `files` under `from`, re-rooted under `to`.
fn relocate(files: &[PathBuf], from: &Path, to: &Path) -> Vec<PathBuf> {
    files
        .iter()
        .map(|f| match f.strip_prefix(from) {
            Ok(rel) => to.join(rel),
            Err(_) => f.clone(),
        })
        .collect()
}

/// A failed collection in plain words, with the collector's own message.
fn collect_error(e: &anyhow::Error) -> String {
    // Already explained by the collector: the plain words, then the detail.
    if let Some(ce) = e.downcast_ref::<ConnectionError>() {
        return ce.to_string();
    }
    if let Some(no_space) = e.downcast_ref::<NoSpace>() {
        return no_space.to_string();
    }
    if let Some(stopped) = e.downcast_ref::<ReadStopped>() {
        return stopped.to_string();
    }
    let text = format!("{e:#}");
    match Problem::classify(&text) {
        Problem::Other | Problem::Settings => format!("The collection failed: {text}"),
        p => format!("{} ({text})", p.explain()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[collect] all_attributes` in the environment's settings asks
    /// for every attribute; off otherwise, and when they can't be read.
    #[test]
    fn all_attributes_comes_from_the_environment_settings() {
        let dir = std::env::temp_dir().join(format!("pw-all-attrs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ws = Workspace::open(&dir).unwrap();
        assert!(!all_attributes(Some(&ws)));
        std::fs::write(ws.config_path(), "[collect]\nall_attributes = true\n").unwrap();
        assert!(all_attributes(Some(&ws)));
        std::fs::write(ws.config_path(), "[collect]\nall_attributes = \"yes\"\n").unwrap();
        assert!(!all_attributes(Some(&ws)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `[collect] read_streams` in the environment's settings: how many
    /// connections the read uses (the collector's default when not set).
    #[test]
    fn read_streams_come_from_the_environment_settings() {
        let dir = std::env::temp_dir().join(format!("pw-read-streams-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ws = Workspace::open(&dir).unwrap();
        assert_eq!(read_streams(Some(&ws)), None);
        std::fs::write(ws.config_path(), "[collect]\nread_streams = 2\n").unwrap();
        assert_eq!(read_streams(Some(&ws)), Some(2));
        std::fs::write(ws.config_path(), "[collect]\nread_streams = 12\n").unwrap();
        assert_eq!(read_streams(Some(&ws)), Some(8));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The read goes in the environment's folder, sized by the last
    /// read of the domain there (`pathwarden collect` uses the same).
    #[test]
    fn the_read_cache_is_in_the_environment_folder() {
        use pathwarden_core::diagnostics::{CollectionTimings, TIMINGS_FILE};
        let dir = std::env::temp_dir().join(format!("pw-read-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ws = Workspace::open(&dir).unwrap();
        let c = read_cache(&ws, "contoso.local");
        assert_eq!(c.root, ws.env_dir().join("collect-cache"));
        assert_eq!((c.last_entries, c.last_bytes), (None, None));

        let info = collection_info(&CollectRequest::new("contoso.local", "o"));
        let run: RunSummary = serde_json::from_value(serde_json::json!({
            "id": "20261009-020000-abcdef", "created_at": 1, "collected_at": null,
            "source": "x", "demo": false, "domains": ["CONTOSO.LOCAL"], "objects": 900,
            "files": 1, "exposure_percent": 0.0, "exposed": 0, "population": 0,
            "protection_score": null, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "info": 0, "suppressed": 0, "plan_steps": 0, "pathwarden": "0.2.0",
            "collection": info,
        }))
        .unwrap();
        let t = CollectionTimings {
            entries: 1000,
            bytes: 16_000_000,
            ..CollectionTimings::default()
        };
        let save = |t: &CollectionTimings| {
            let _ = std::fs::remove_dir_all(ws.runs_dir().join(&run.id));
            ws.save_run_with(&run, "", &[(TIMINGS_FILE, serde_json::to_vec(t).unwrap())])
                .unwrap();
        };
        // A read into memory: its entries, at the default size.
        save(&t);
        let c = read_cache(&ws, "CONTOSO.local");
        assert_eq!((c.last_entries, c.last_bytes), (Some(1000), None));
        // A read on disk: what it took there.
        let t = CollectionTimings {
            cache_entries: Some(1001),
            cache_bytes: Some(20_000_000),
            ..t
        };
        save(&t);
        let c = read_cache(&ws, "CONTOSO.local");
        assert_eq!(
            (c.last_entries, c.last_bytes),
            (Some(1001), Some(20_000_000))
        );
        assert_eq!(read_cache(&ws, "fabrikam.local").last_entries, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn form(domain: &str) -> CollectForm {
        CollectForm {
            domain: domain.into(),
            ..CollectForm::default()
        }
    }

    /// The Collect page offers to resume only a read that
    /// can be: in the run's environment, under 24 hours old, by the same
    /// sign-in, with the built-in collector. `pathwarden collect` finds it
    /// the same way.
    #[test]
    fn the_offer_appears_only_with_a_valid_cache() {
        let dir = std::env::temp_dir().join(format!("pw-resume-offer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ws = Workspace::open(&dir).unwrap();
        let now = analyze::now();
        let mut f = form("Contoso.Local");
        assert!(stopped_offer(&ws, &f).is_none());
        if !BUILTIN {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let cache = read_cache(&ws, "contoso.local");
        let current = Auth::CurrentUser;
        pathwarden_collect::fake_stopped_read(&cache, "contoso.local", &current, 61, now - 7300)
            .unwrap();
        let (s, first) = stopped_offer(&ws, &f).expect("offered");
        assert!(first);
        assert_eq!(
            offer_words(&s, first, now),
            "An earlier read stopped at 61%, 2 h ago."
        );
        // Another sign-in, or SharpHound: no offer.
        f.auth = AuthChoice::Password;
        f.user = "svc".into();
        assert!(stopped_offer(&ws, &f).is_none());
        f.auth = AuthChoice::Current;
        f.collector = Collector::Sharphound;
        assert!(stopped_offer(&ws, &f).is_none());
        f.collector = Collector::Builtin;
        // Another environment's folder: not this one's read.
        let other = ws.in_env("other");
        assert!(stopped_offer(&other, &f).is_none());
        // More than 24 hours old: none.
        pathwarden_collect::fake_stopped_read(&cache, "contoso.local", &current, 61, now - 90_000)
            .unwrap();
        assert!(stopped_offer(&ws, &f).is_none());
        // A trusted domain's read of the run: named.
        pathwarden_collect::fake_stopped_read(&cache, "fabrikam.local", &current, 12, now - 600)
            .unwrap();
        f.trusted = vec!["fabrikam.local".into()];
        let (s, first) = stopped_offer(&ws, &f).expect("offered");
        assert_eq!(
            offer_words(&s, first, now),
            "An earlier read of FABRIKAM.LOCAL stopped at 12%, 10 min ago."
        );
        // Stopped: the box says a read was kept only when one was.
        let mut req = CollectRequest::new("contoso.local", "o");
        req.cache = Some(cache.clone());
        assert!(kept_reads(&req, &["fabrikam.local".into()]));
        assert!(!kept_reads(&req, &[]), "contoso's is too old");
        req.cache = None;
        assert!(!kept_reads(&req, &["fabrikam.local".into()]));
        // The app's sweep at start removes the old one, keeps the other.
        assert_eq!(sweep_stopped_reads(&ws), 1);
        assert!(stopped_offer(&ws, &f).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn domain_and_server_are_checked() {
        let e = build_request(form(""), "o".into()).unwrap_err();
        assert_eq!((e.step, e.field), (1, "domain"));
        let e = build_request(form("CONTOSO"), "o".into()).unwrap_err();
        assert_eq!(e.field, "domain");
        let e = build_request(form("contoso.local; calc"), "o".into()).unwrap_err();
        assert_eq!(e.field, "domain");
        let mut f = form("contoso.local");
        f.server = Some("--evil".into());
        assert_eq!(build_request(f, "o".into()).unwrap_err().field, "server");
    }

    /// A ticked trusted domain's domain controller, typed on step 1,
    /// goes to that domain as `--server DOMAIN=HOST` does; blank, or for a
    /// domain not ticked, it's found through DNS; a bad name is refused.
    #[test]
    fn a_trusted_domains_controller_as_typed() {
        let mut f = form("contoso.local");
        f.trusted = vec!["FABRIKAM.COM".into(), "child.contoso.local".into()];
        f.trusted_servers = [
            ("FABRIKAM.COM", " DC01.Fabrikam.com. "),
            ("child.contoso.local", " "),
            ("tailspin.com", "dc01.tailspin.com"),
        ]
        .into_iter()
        .map(|(d, h)| (d.to_string(), h.to_string()))
        .collect();
        // The same as the CLI's `--server`, messy input on both sides.
        let cli = pathwarden_collect::parse_servers(
            &[" Fabrikam.COM. = dc01.FABRIKAM.com. ".to_string()],
            "Contoso.Local.",
        )
        .unwrap()
        .1;
        assert_eq!(trusted_servers(&f).unwrap(), cli);
        if BUILTIN {
            // As this account on Windows; elsewhere that is refused, so with
            // a user and password.
            if !cfg!(windows) {
                f.auth = AuthChoice::Password;
                f.user = "svc".into();
                f.password = Some(Secret::new("x"));
                f.ldaps = true;
            }
            let req = build_request(f, "o".into()).unwrap();
            assert_eq!(req.server, None);
            assert_eq!(req.servers, cli);
        }

        let mut f = form("contoso.local");
        f.trusted = vec!["fabrikam.com".into()];
        f.trusted_servers = [("fabrikam.com".to_string(), "dc01 --evil".to_string())].into();
        let e = build_request(f, "o".into()).unwrap_err();
        assert_eq!((e.step, e.field), (1, "trusted"));
        assert_eq!(
            e.message,
            "FABRIKAM.COM's domain controller doesn't look like a computer name. Use its full \
             name, like dc01.fabrikam.com, without a port, path or user."
        );
        // The same forms are refused on both sides.
        for bad in ["dc01:636", "dc01/x", "svc@dc01", "[dc01]", "dc01?x"] {
            let mut f = form("contoso.local");
            f.trusted = vec!["fabrikam.com".into()];
            f.trusted_servers = [("fabrikam.com".to_string(), bad.to_string())].into();
            assert_eq!(trusted_servers(&f).unwrap_err().field, "trusted", "{bad}");
            assert!(pathwarden_collect::parse_servers(
                &[format!("fabrikam.com={bad}")],
                "contoso.local"
            )
            .is_err());
        }
    }

    /// A request keeps only the trusted domains the page offers for
    /// the domain (the trusts of its last run, not greyed); none without a
    /// run.
    #[test]
    fn only_offered_trusted_domains_are_kept() {
        use pathwarden_core::forest::{Pick, TrustedDomain};
        let td = |name: &str, pick: Pick| TrustedDomain {
            name: name.into(),
            chip: String::new(),
            pick,
            why: None,
        };
        let known = TrustedFrom {
            run: "r".into(),
            domain: "CONTOSO.LOCAL".into(),
            env: "Contoso".into(),
            domains: vec![
                td("CHILD.CONTOSO.LOCAL", Pick::On),
                td("FABRIKAM.COM", Pick::Maybe),
                td("NORTHWIND.COM", Pick::Off),
            ],
        };
        let mut f = form("contoso.local");
        f.trusted = vec![
            "child.contoso.local.".into(),
            "fabrikam.com".into(),
            "northwind.com".into(),
            "evil.example".into(),
        ];
        keep_known_trusted(&mut f, Some(&known));
        assert_eq!(f.trusted, ["child.contoso.local.", "fabrikam.com"]);
        keep_known_trusted(&mut f, None);
        assert!(f.trusted.is_empty());
    }

    #[test]
    fn password_rules() {
        let mut f = form("Contoso.Local.");
        f.auth = AuthChoice::Password;
        f.user = "svc".into();
        assert_eq!(build_request(f, "o".into()).unwrap_err().field, "password");
        let mut f = form("contoso.local");
        f.auth = AuthChoice::Password;
        f.user = "svc".into();
        f.password = Some(Secret::new("Form-Secret-5"));
        f.collector = Collector::Sharphound;
        f.sharphound = "C:\\x\\SharpHound.exe".into();
        let e = build_request(f, "o".into()).unwrap_err();
        let shown = format!("{e:?}");
        assert!(!shown.contains("Form-Secret-5"));
        if cfg!(windows) {
            assert!(e.message.contains("Windows account"), "{}", e.message);
        }
        if BUILTIN {
            let mut f = form("contoso.local");
            f.auth = AuthChoice::Password;
            f.user = "svc".into();
            f.password = Some(Secret::new("x"));
            assert_eq!(build_request(f, "o".into()).unwrap_err().field, "ldaps");
            let mut f = form("contoso.local");
            f.auth = AuthChoice::Password;
            f.user = "svc".into();
            f.password = Some(Secret::new("x"));
            f.ldaps = true;
            f.depth = Depth::Full;
            let r = build_request(f, "o".into()).unwrap();
            assert_eq!(r.scope, Scope::All);
            assert_eq!(r.domain, "contoso.local");
        }
    }

    #[test]
    fn builtin_matches_the_build() {
        let mut f = form("contoso.local");
        f.auth = AuthChoice::Current;
        let r = build_request(f, "o".into());
        if !BUILTIN {
            assert_eq!(r.unwrap_err().field, "collector");
        } else if cfg!(windows) {
            let r = r.unwrap();
            assert_eq!(r.scope, Scope::DcOnly);
            assert!(matches!(r.auth, Auth::CurrentUser));
        } else {
            assert_eq!(r.unwrap_err().field, "auth");
        }
    }

    #[test]
    fn sharphound_path_is_checked() {
        if !cfg!(windows) {
            return;
        }
        let mut f = form("contoso.local");
        f.collector = Collector::Sharphound;
        f.sharphound = "SharpHound.exe".into();
        assert!(build_request(f, "o".into())
            .unwrap_err()
            .message
            .contains("full path"));
        let dir = std::env::temp_dir();
        let mut f = form("contoso.local");
        f.collector = Collector::Sharphound;
        f.sharphound = format!("\"{}\"", dir.display());
        assert!(build_request(f, "o".into())
            .unwrap_err()
            .message
            .contains("is a folder"));
        let mut f = form("contoso.local");
        f.collector = Collector::Sharphound;
        f.sharphound = dir.join("no-such-SharpHound.exe").display().to_string();
        assert!(build_request(f, "o".into())
            .unwrap_err()
            .message
            .starts_with("Nothing found"));
    }

    #[test]
    fn one_check_at_a_time() {
        let jobs = Arc::new(Jobs::default());
        let first = CheckSlot::take(&jobs).expect("free");
        assert!(CheckSlot::take(&jobs).is_none(), "a second check waits");
        assert!(CheckSlot::take(&Arc::new(Jobs::default())).is_some());
        drop(first);
        assert!(CheckSlot::take(&jobs).is_some());
    }

    #[test]
    fn check_says_what_it_did_not_check() {
        let sharphound = ConnectionCheck {
            program: Some(PathBuf::from("C:\\Tools\\SharpHound.exe")),
            ..ConnectionCheck::default()
        };
        let lines = check_lines(&sharphound, &Detected::default());
        assert!(lines.iter().all(|l| !l.contains("Connected")), "{lines:?}");
        let not = unchecked_lines(&sharphound, false, true);
        assert!(not[0].contains("SharpHound does that"), "{not:?}");
        assert!(not.iter().all(|l| !l.contains("each computer")));

        let builtin = ConnectionCheck {
            server: Some("dc01.contoso.local".into()),
            bound_as: Some("CONTOSO\\alice".into()),
            users: Some(pathwarden_collect::Count {
                n: 1200,
                at_least: false,
            }),
            ..ConnectionCheck::default()
        };
        let lines = check_lines(&builtin, &Detected::default());
        assert_eq!(
            lines[0],
            "Connected to dc01.contoso.local and signed in as CONTOSO\\alice."
        );
        assert!(unchecked_lines(&builtin, false, true).is_empty());
        let not = unchecked_lines(&builtin, true, false);
        assert_eq!(not.len(), 1);
        assert!(not[0].contains("each computer"));
        assert!(!not[0].contains("Kerberos"));
        // Kerberos only: a computer without a Kerberos name is one
        // that isn't collected.
        let not = unchecked_lines(&builtin, true, true);
        assert!(not[0].contains("have no Kerberos name"), "{not:?}");

        let uncounted = ConnectionCheck {
            server: Some("dc01.contoso.local".into()),
            ..ConnectionCheck::default()
        };
        assert!(unchecked_lines(&uncounted, false, true)[0].contains("How big"));

        // The ticket the check got is a line of its own, after the sign-in.
        let with_ticket = ConnectionCheck {
            kerberos: Some(
                "Got a Kerberos ticket for CONTOSO\\alice from dc01.contoso.local.".into(),
            ),
            ..builtin
        };
        let lines = check_lines(&with_ticket, &Detected::default());
        assert_eq!(
            lines[1],
            "Got a Kerberos ticket for CONTOSO\\alice from dc01.contoso.local."
        );
    }

    /// Trusted domains are DNS names, each once, never the domain
    /// itself; a name an external program could read as an option is
    /// refused, on step 1.
    #[test]
    fn trusted_domains_are_checked() {
        let mut f = form("Contoso.Local");
        f.trusted = vec![
            "child.contoso.local".into(),
            "CONTOSO.LOCAL.".into(),
            "Fabrikam.com".into(),
            "fabrikam.com".into(),
            " ".into(),
        ];
        assert_eq!(
            trusted_names(&f).unwrap(),
            ["child.contoso.local", "fabrikam.com"]
        );
        for bad in ["--domain", "fabrikam", "a b.com", "S-1-5-21-1-2-3"] {
            let mut f = form("contoso.local");
            f.trusted = vec![bad.into()];
            let e = trusted_names(&f).unwrap_err();
            assert_eq!((e.step, e.field), (1, "trusted"), "{bad}");
        }
        let mut f = form("contoso.local");
        f.trusted = (0..=MAX_TRUSTED).map(|i| format!("d{i}.com")).collect();
        assert!(trusted_names(&f).unwrap_err().message.contains("at most"));
    }

    /// The check of a run of several domains: each trusted domain that
    /// answered in a line, one that didn't as a warning that it will be
    /// skipped.
    #[test]
    fn the_check_names_each_trusted_domain() {
        let ok = ConnectionCheck {
            server: Some("dc01.fabrikam.com".into()),
            bound_as: Some(r"CONTOSO\svc".into()),
            kerberos: Some(
                "Got a Kerberos ticket for dc01.fabrikam.com through the trust from contoso.local."
                    .into(),
            ),
            warnings: vec!["The trust to fabrikam.com allows only RC4, so its computers will be skipped. Set the trust to use AES.".into()],
            ..ConnectionCheck::default()
        };
        let refused: anyhow::Error = ConnectionError::new(
            "cannot connect to ldaps://tailspin.com:636: connection refused (os error 10061)",
        )
        .into();
        let (lines, warnings) = trusted_lines(&[
            ("fabrikam.com".into(), Ok(ok)),
            ("tailspin.com".into(), Err(refused)),
        ]);
        assert_eq!(
            lines,
            [
                r"FABRIKAM.COM: connected to dc01.fabrikam.com and signed in as CONTOSO\svc.",
                "FABRIKAM.COM: Got a Kerberos ticket for dc01.fabrikam.com through the trust from \
                 contoso.local."
            ]
        );
        assert_eq!(
            warnings,
            [
                "FABRIKAM.COM: The trust to fabrikam.com allows only RC4, so its computers will be \
                 skipped. Set the trust to use AES.",
                "TAILSPIN.COM: Couldn't reach a domain controller. It will be skipped."
            ]
        );
    }

    /// The page starts from a run's link (its domain, the domains to tick),
    /// else from what this computer says, else from the environment's last
    /// run.
    #[test]
    fn the_page_starts_from_a_link_or_the_last_run() {
        let q = |domain: Option<&str>, pick: Option<&str>| PageQuery {
            job: None,
            domain: domain.map(str::to_string),
            pick: pick.map(str::to_string),
        };
        let p: pathwarden_core::state::HistoryPoint = serde_json::from_value(serde_json::json!({
            "version": 1, "run_id": "r1", "at": 1, "collected_at": null,
            "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": 1,
            "tier_zero_population": 100, "tier_zero_objects": 1,
            "protection_score": null,
            "findings": {"attack_path": 0, "hygiene": 0, "suppressed": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "changes": {"new": 0, "open": 0, "regressed": 0, "suppressed": 0,
                "resolved": 0},
            "recorded_by": "app",
        }))
        .unwrap();
        let mut run = crate::history_ui::point_summary(&p, &["CONTOSO.LOCAL".to_string()]);
        let none = Detected::default();
        let p = prefill(
            std::slice::from_ref(&run),
            "Lab",
            &none,
            &q(
                Some("Contoso.Local"),
                Some("CHILD.CONTOSO.LOCAL,--x,fabrikam.com"),
            ),
        );
        assert_eq!(p.domain.as_deref(), Some("contoso.local"));
        assert_eq!(p.from_env.as_deref(), Some("Lab"));
        assert_eq!(p.pick, ["child.contoso.local", "fabrikam.com"]);
        let p = prefill(std::slice::from_ref(&run), "Lab", &none, &q(None, None));
        assert_eq!(p.domain.as_deref(), Some("contoso.local"));
        let joined = Detected {
            domain: Some("fabrikam.com".into()),
            ..Detected::default()
        };
        assert_eq!(
            prefill(std::slice::from_ref(&run), "Lab", &joined, &q(None, None)),
            Prefill::default()
        );
        // A run loaded from the history never picks the domain, nor
        // links to collect what it left out.
        let mut loaded = run.clone();
        loaded.shared = Some(crate::shared_runs::SharedFrom {
            remote: "https://git.example.com/h.git".into(),
            branch: None,
            recorded_by: None,
            recorded_on: None,
            recorded_from: "app".into(),
            pathwarden: "1.0.0".into(),
            mirrored_at: 0,
            manifest_sha256: "0".repeat(64),
            left_out: vec![],
        });
        loaded.not_collected = Some(vec!["EVIL.EXAMPLE".into()]);
        assert_eq!(
            prefill(std::slice::from_ref(&loaded), "Lab", &none, &q(None, None)).domain,
            None
        );
        assert_eq!(collect_again_href(&loaded), None);
        loaded.shared = None;
        assert!(collect_again_href(&loaded).is_some());
        run.demo = true;
        assert_eq!(prefill(&[run], "Lab", &none, &q(None, None)).domain, None);
    }

    /// Each domain's outcome is recorded for Run details: objects and time
    /// when collected, the short reason and its detail when not.
    #[test]
    fn each_domains_outcome_is_recorded() {
        let mut info = collection_info(&CollectRequest::new("contoso.local", "o"));
        let results = vec![
            pathwarden_collect::DomainResult {
                domain: "contoso.local".into(),
                outcome: Ok(pathwarden_collect::Outcome::default()),
                elapsed: std::time::Duration::from_secs(61),
            },
            pathwarden_collect::DomainResult {
                domain: "tailspin.com".into(),
                outcome: Err(ConnectionError::new("timed out").into()),
                elapsed: std::time::Duration::from_secs(30),
            },
        ];
        record_domains(&mut info, &results, &[]);
        assert_eq!(info.domains.len(), 2);
        assert_eq!(info.domains[0].domain, "CONTOSO.LOCAL");
        assert!(info.domains[0].collected);
        assert_eq!(
            (info.domains[0].objects, info.domains[0].seconds),
            (Some(0), Some(61))
        );
        assert!(!info.domains[1].collected);
        assert_eq!(
            info.domains[1].reason.as_deref(),
            Some("Couldn't reach a domain controller.")
        );
        assert!(info.domains[1]
            .detail
            .as_deref()
            .unwrap()
            .contains("timed out"));
        assert_eq!(info.failed_domains(), ["TAILSPIN.COM"]);
        // As saved, and read back.
        let text = serde_json::to_string(&info).unwrap();
        let back: CollectionInfo = serde_json::from_str(&text).unwrap();
        assert_eq!(back, info);
        // A one-domain run saved before reads as its domain.
        let older: CollectionInfo = serde_json::from_str(
            r#"{"method":"builtin","scope":"dc-only","domain":"contoso.local"}"#,
        )
        .unwrap();
        assert_eq!(older.domain_outcomes().len(), 1);
        assert!(older.domain_outcomes()[0].collected);
        assert!(!serde_json::to_string(&older).unwrap().contains("domains"));
    }

    /// A failed domain's detail is saved without the account
    /// name or a local path.
    #[test]
    fn saved_details_name_no_account_and_no_path() {
        let names = vec!["svc-pw".to_string(), r"CONTOSO\svc-pw".to_string()];
        assert_eq!(
            scrub_detail(
                r"The user name or password is wrong. (NTLM bind as CONTOSO\svc-pw failed: rc=49)",
                &names
            ),
            "The user name or password is wrong. (NTLM bind as the account failed: rc=49)"
        );
        assert_eq!(
            scrub_detail(
                "Kerberos didn't work: dc01 doesn't know the account svc-pw in X.",
                &names
            ),
            "Kerberos didn't work: dc01 doesn't know the account in X."
        );
        assert_eq!(
            scrub_detail("bind as svc-pw@contoso.local refused", &names),
            "bind as the account refused"
        );
        // Any DOMAIN\user, a name the directory reported.
        assert_eq!(
            scrub_detail(r"signed in as NORTH\ann, then refused", &[]),
            "signed in as the account, then refused"
        );
        assert_eq!(
            scrub_detail(r"cannot write C:\Users\Ann Smith\out\x.zip: denied", &names),
            "cannot write x.zip: denied"
        );
        assert_eq!(
            scrub_detail("Couldn't reach a domain controller.", &names),
            "Couldn't reach a domain controller."
        );
        // Recorded so, from the request and what the directories said.
        let mut req = CollectRequest::new("contoso.local", "o");
        req.auth = Auth::Password {
            user: r"CONTOSO\svc-pw".into(),
            password: Secret::new("x"),
        };
        let mut info = collection_info(&req);
        let results = vec![pathwarden_collect::DomainResult {
            domain: "fabrikam.com".into(),
            outcome: Err(anyhow::anyhow!(
                r"NTLM bind as CONTOSO\svc-pw failed: rc=49 (invalidCredentials)"
            )),
            elapsed: std::time::Duration::from_secs(1),
        }];
        record_domains(&mut info, &results, &account_names(&req));
        let saved = serde_json::to_string(&info).unwrap();
        assert!(!saved.to_ascii_lowercase().contains("svc-pw"), "{saved}");
    }

    #[test]
    fn hosts() {
        assert!(host_like("dc01.contoso.local"));
        assert!(!host_like("-x"));
        assert!(!host_like("a b"));
        assert!(!host_like("a\\b"));
    }
}
