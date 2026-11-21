//! The run page's "Run details" tab: what the run page's
//! header no longer carries, as rows in the report's Environment style
//! ([`rows`]). Where the run came from (its run ID, who recorded it where,
//! the repository it was loaded from), the other collectors' OpenGraph
//! sources read with it ([`crate::opengraph_ui::details_row`]), how it was
//! collected, objects skipped as too large, sources read part way, its place in the run
//! history, the comparison with the previous run, its collection
//! performance, the settings the next
//! analysis applies, adding other data to its kept collection ([`crate::add_data`]),
//! and removing the run. A row that needs a look is
//! amber and open, and the tab's label gets an amber dot; when findings
//! may be missing, the run page says so in one line ([`ATTENTION`]).
//!
//! The report's tabs live inside the report's frame, so the app adds this
//! tab and its panel to the report only when it embeds it in the run page
//! (`/runs/<id>/report?embed=1`); the downloaded report and the full page
//! never have it. The frame is sandboxed (another origin): its buttons and
//! links don't act there, they ask the page around it (`report-retest.js`
//! sends `pathwarden:run-action`, `run.js` checks it), which opens the
//! confirm dialog of the page's own Delete or goes to the page asked for.
//! The page puts a fresh nonce in the frame's address; the panel carries
//! it, and the page takes a request only with it, from the frame.
//!
//! When the tab can't go into the report (a report left out of a full run,
//! a report whose script isn't one Pathwarden wrote, one without the
//! Environment tab), the run page shows the same facts and Remove below
//! the report instead ([`below_html`]).

use crate::pages::esc;
use crate::workspace::{RunSummary, Workspace};

/// The tab's name.
pub const TAB: &str = "Run details";

/// How the run can be removed from this page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remove {
    /// A run analysed here: deleted here, with its point in the history
    /// when it has one (`recorded`).
    Delete { recorded: bool },
    /// A run loaded from the history, on a computer that pushes.
    FromHistory,
    /// A run loaded from the history, on a computer that only reads it.
    Hide,
}

impl Remove {
    /// The button's words and the line beside it (empty: none).
    pub fn words(self) -> (&'static str, &'static str) {
        match self {
            Remove::Delete { recorded: true } => (
                "Delete run",
                "It is also removed from the run history and Progress.",
            ),
            Remove::Delete { recorded: false } => ("Delete run", ""),
            Remove::FromHistory => (
                "Remove from the run history",
                "This removes it on every computer.",
            ),
            Remove::Hide => (
                "Hide on this computer",
                "It stays in the run history for everyone else.",
            ),
        }
    }

    pub fn of(r: &RunSummary, reads_only: bool) -> Remove {
        match (&r.shared, reads_only) {
            (None, _) => Remove::Delete {
                recorded: crate::history_ui::recorded_id(r).is_some(),
            },
            (Some(_), false) => Remove::FromHistory,
            (Some(_), true) => Remove::Hide,
        }
    }
}

/// What the run page needs of Run details: how the run is removed, the
/// nonce it gives the report frame (only when its report `carries` the
/// tab), and its own Run details below the report ([`below_html`]).
#[derive(Debug, Clone)]
pub struct PageDetails {
    pub remove: Remove,
    pub nonce: String,
    pub carries: bool,
    pub below: Option<String>,
    /// How Sign in went, after the page loaded again from it: the frame is
    /// told too.
    pub said: Option<crate::sign_in::Outcome>,
    /// Its token ([`crate::sign_in::remember`]), for the frame.
    pub signin: Option<String>,
}

/// The facts of "Where it came from", as (label, text, code): the run ID,
/// who recorded it, and for a run loaded from the history the Pathwarden
/// that recorded it, the repository, when it was loaded and what was left
/// out. `runs show` prints the same.
pub fn facts(r: &RunSummary) -> Vec<(&'static str, String, bool)> {
    let mut out = vec![("Run ID", r.run_id(), true)];
    match &r.shared {
        Some(s) => {
            out.push(("Recorded", recorded_value(&s.recorded_words()), false));
            out.push(("Version", format!("Pathwarden {}", s.pathwarden), false));
            out.push((
                REPOSITORY,
                match &s.branch {
                    Some(b) => format!("{}, {}", s.remote, branch_words(b)),
                    None => s.remote.clone(),
                },
                false,
            ));
            out.push((
                "Loaded here",
                pathwarden_core::time::format_local(s.mirrored_at),
                false,
            ));
            if !s.left_out.is_empty() {
                out.push((
                    "Left out",
                    crate::history_ui::shared_left_out_words(&s.left_out),
                    false,
                ));
            }
        }
        None => {
            out.push(("Recorded", "On this computer".to_string(), false));
            if !r.pathwarden.is_empty() {
                out.push(("Version", format!("Pathwarden {}", r.pathwarden), false));
            }
        }
    }
    out
}

/// The "Repository" row's label.
const REPOSITORY: &str = "Repository";

/// "branch main": the branch a run was loaded from.
fn branch_words(b: &str) -> String {
    format!("branch {b}")
}

/// The facts ([`facts`]) as the rows of a `<dl>`. The Repository row's
/// branch goes on its own line (`rd-branch`), so a narrow screen never
/// starts a line with its comma.
fn facts_html(r: &RunSummary, facts: &[(&'static str, String, bool)]) -> String {
    let branch = r
        .shared
        .as_ref()
        .and_then(|s| s.branch.as_ref().map(|b| (&s.remote, b)));
    facts
        .iter()
        .map(|&(k, ref v, code)| {
            let v = match (k, branch) {
                (REPOSITORY, Some((remote, b))) => format!(
                    r#"<span class="rd-remote">{}</span> <span class="rd-branch">{}</span>"#,
                    esc(remote),
                    esc(&branch_words(b))
                ),
                _ if code => format!("<code>{}</code>", esc(v)),
                _ => esc(v),
            };
            format!("<div><dt>{k}</dt><dd>{v}</dd></div>")
        })
        .collect()
}

/// Collection performance as Run details says it: the words of its link,
/// "Collection slower" when the collection got slower than the one before.
pub fn perf_words(slower: bool) -> &'static str {
    if slower {
        "Collection slower"
    } else {
        "Collection performance"
    }
}

/// The run page's one line above the report when something in Run details
/// could change what the report concludes ([`attention`]).
pub const ATTENTION: &str = "Some findings may be missing. See Run details.";

/// Whether findings may be missing from `r`: objects skipped as too large,
/// or the comparison with the previous run in the history warned. The run
/// page then says [`ATTENTION`]; the rows that say why are amber.
pub fn attention(r: &RunSummary) -> bool {
    r.skipped_objects > 0
        || !r.incomplete_sources.is_empty()
        || compared(r).is_some()
        || upgrade(r).is_some()
}

/// The "Sources not read in full" row: each OpenGraph or AzureHound
/// source not read whole, in the words `run` warns with, less the setting's
/// key.
fn sources_row(r: &RunSummary) -> Option<Row> {
    let s = &r.incomplete_sources;
    let status = match s.as_slice() {
        [] => return None,
        [one] => format!(
            "{} not read in full",
            pathwarden_core::text::bidi_safe(&one.source)
        ),
        many => format!("{} sources not read in full", many.len()),
    };
    Some(Row {
        title: "Sources not read in full",
        status,
        warn: true,
        text: s
            .iter()
            .map(|i| {
                i.sentences(&pathwarden_core::text::bidi_safe(&i.source), false)
                    .join(" ")
            })
            .collect(),
        ..Row::default()
    })
}

/// The run's warnings, but the demo's: what the comparison with the
/// previous run in the history warned about (`upgrade` false), or what
/// the history's upgrade couldn't finish (true,
/// [`pathwarden_core::store::is_upgrade_note`]).
fn run_warnings(r: &RunSummary, upgrade: bool) -> Option<Vec<&String>> {
    let out: Vec<&String> = r
        .history
        .as_ref()
        .filter(|_| !r.demo)
        .map(|h| {
            h.warnings
                .iter()
                .filter(|w| pathwarden_core::store::is_upgrade_note(w) == upgrade)
                .collect()
        })
        .unwrap_or_default();
    (!out.is_empty()).then_some(out)
}

/// What the comparison with the previous run in the history warned about
/// (none for the demo, or with nothing to say).
fn compared(r: &RunSummary) -> Option<Vec<&String>> {
    run_warnings(r, false)
}

/// The history's files this run couldn't upgrade.
fn upgrade(r: &RunSummary) -> Option<Vec<&String>> {
    run_warnings(r, true)
}

/// Where a row's link goes in the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Go {
    /// Automate › Schedule, for this run's collection.
    Schedule,
    /// Automate › History storage.
    History,
    /// The run's collection performance.
    Performance { slower: bool },
    /// Settings.
    Settings,
    /// Settings, at the Tier Zero settings folders.
    SettingsFolders,
    /// The Collect page for the domains the run left out.
    Collect,
    /// Configure › Mappings, what each OpenGraph pack means.
    Mappings,
}

impl Go {
    /// The link's words.
    pub fn words(self) -> &'static str {
        match self {
            Go::Schedule => "Schedule this collection",
            Go::History => "History storage",
            Go::Performance { slower } => perf_words(slower),
            Go::Settings => "Settings",
            Go::SettingsFolders => "Change the settings folders",
            Go::Collect => "Collect the missing domains",
            Go::Mappings => "Mappings",
        }
    }

    /// What the tab asks the run page for (`data-pw-run`; `report-retest.js`
    /// and `run.js` know these).
    fn action(self) -> &'static str {
        match self {
            Go::Schedule => "schedule",
            Go::History => "history",
            Go::Performance { .. } => "performance",
            Go::Settings => "settings",
            Go::SettingsFolders => "settings-folders",
            Go::Collect => "collect",
            Go::Mappings => "mappings",
        }
    }

    /// The page it opens, for the run page's own Run details.
    fn href(self, r: &RunSummary) -> String {
        match self {
            Go::Schedule => format!("/automate/schedule?run={}", esc(&r.id)),
            Go::History => "/automate/history".into(),
            Go::Performance { .. } => format!("/runs/{}/performance", esc(&r.id)),
            Go::Settings => "/settings".into(),
            Go::SettingsFolders => "/settings#settings-folders".into(),
            Go::Collect => format!("/runs/{}/collect", esc(&r.id)),
            Go::Mappings => "/mappings".into(),
        }
    }
}

/// One domain of a run, in the Domains row: its name, whether it was
/// collected, what to say ("Collected · 1,204 objects · 1 min", or why
/// not) and the detail behind it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainLine {
    pub name: String,
    pub collected: bool,
    pub text: String,
    pub detail: Option<String>,
}

/// One row of Run details, in the report's Environment style: a title, a
/// short status on the right, and what opens below it. `warn`: it needs a
/// look (amber, and open). The tab, the run page's own Run details and
/// `runs show` all print these ([`rows`]). Text is plain; renderers escape.
#[derive(Debug, Clone, Default)]
pub struct Row {
    pub title: &'static str,
    pub status: String,
    pub warn: bool,
    /// Labelled facts, as (label, text, code) ([`facts`]).
    pub facts: Vec<(&'static str, String, bool)>,
    /// Sentences, one paragraph each.
    pub text: Vec<String>,
    /// A list (collector warnings, the comparison's findings).
    pub items: Vec<String>,
    /// Where the raw collection was kept.
    pub kept: Option<String>,
    pub go: Option<Go>,
    /// The Sign in button goes before the link: the repository wanted a
    /// sign-in git couldn't make ([`crate::sign_in`]).
    pub sign_in: bool,
    /// How a Sign in just now went ([`with_sign_in`]).
    pub said: Option<crate::sign_in::Outcome>,
    /// The run's domains, before the sentences.
    pub domains: Vec<DomainLine>,
    /// The link's words, when not [`Go::words`].
    pub go_words: Option<String>,
    /// A read that stopped and was resumed: when it started (Unix
    /// time), said after the sentences ([`resumed_sentence`]).
    pub resumed: Option<i64>,
    /// The Tier Zero settings files row: one line per file, before
    /// the sentences.
    pub settings: Vec<SettingsLine>,
    /// Sentences with a date in them, after the plain ones, each with the
    /// words of its ⓘ if it has one.
    pub dated: Vec<(Dated, Option<&'static str>)>,
}

/// A sentence with a date in it: `pre`, the day of `at` (US style; local
/// time on a page, UTC in a terminal), then `post`. Without `at`, `pre`
/// and `post` alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dated {
    pub pre: String,
    pub at: Option<i64>,
    pub post: String,
}

impl Dated {
    fn plain(text: String) -> Dated {
        Dated {
            pre: text,
            ..Dated::default()
        }
    }

    /// For a terminal: "Oct 29, 2026" in UTC.
    pub fn text(&self) -> String {
        match self.at {
            Some(t) => format!(
                "{}{}{}",
                self.pre,
                pathwarden_core::time::format_day(t),
                self.post
            ),
            None => format!("{}{}", self.pre, self.post),
        }
    }

    /// For a page: the day in a `<time>` the page shows in local time
    /// (`app.js`, `report-retest.js`), US style until then.
    fn html(&self) -> String {
        match self.at {
            Some(t) => format!(
                "{}{}{}",
                esc(&self.pre),
                crate::pages::time_as(t, "date"),
                esc(&self.post)
            ),
            None => esc(&format!("{}{}", self.pre, self.post)),
        }
    }
}

/// One settings file of a run, in the Tier Zero settings files row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsLine {
    /// The server it describes.
    pub name: String,
    /// Over 90 days old, or undated.
    pub stale: bool,
    pub text: Dated,
    /// Behind its ⓘ: "File name: pathwarden-tierzero-DC01.contoso.local.json".
    pub detail: String,
}

/// The Tier Zero settings files row's title.
pub const SETTINGS_FILES_ROW: &str = "Tier Zero settings files";

/// The ⓘ of the row's first sentence.
pub const SETTINGS_FILES_TIP: &str = "Read from the collection and from the settings folders in Settings. Runs keep each file's name, not its folder.";

/// "Over 90 days old, so it can confirm a weakness but can't show that one
/// was fixed."
fn stale_words() -> String {
    format!(
        "Over {} days old, so it can confirm a weakness but can't show that one was fixed.",
        pathwarden_core::dcsettings::STALE_DAYS
    )
}

/// The Tier Zero settings files row: each file the run used, the
/// oldest, which servers the last run had files for and this one has not,
/// and folders that couldn't be opened. None when there is nothing to say.
fn settings_row(r: &RunSummary) -> Option<Row> {
    use pathwarden_core::dcsettings::ServerKind;
    let files = &r.settings_files;
    let fewer: &[String] = r
        .history
        .as_ref()
        .map(|h| h.settings_fewer.as_slice())
        .unwrap_or_default();
    if files.is_empty() && fewer.is_empty() && r.settings_folders_unread == 0 {
        return None;
    }
    let stale = files.iter().filter(|f| f.stale).count();
    let status = pathwarden_core::dcsettings::files_status(files, fewer.len());
    let settings = files
        .iter()
        .map(|f| {
            let what = match f.kind {
                ServerKind::Dc => "Domain controller",
                ServerKind::Ca => "Certification authority",
            };
            let text = match (f.read_at, f.stale) {
                (Some(t), false) => Dated {
                    pre: format!("{what} · settings read "),
                    at: Some(t),
                    post: ".".into(),
                },
                (Some(t), true) => Dated {
                    pre: format!("{what} · settings read "),
                    at: Some(t),
                    post: format!(". {}", stale_words()),
                },
                (None, _) => Dated::plain(format!(
                    "{what} · its file has no read date, so it can confirm a weakness but can't show that one was fixed."
                )),
            };
            SettingsLine {
                name: f.server.clone(),
                stale: f.stale,
                text,
                detail: format!("File name: {}", f.file_name),
            }
        })
        .collect();
    let mut dated = Vec::new();
    let n = files.len();
    let oldest = files.iter().filter_map(|f| f.read_at).min();
    let used = match n {
        0 => "This run used no settings files.".to_string(),
        1 => "This run used 1 settings file.".to_string(),
        n => format!("This run used {n} settings files."),
    };
    dated.push((
        match oldest {
            Some(t) if n > 1 => Dated {
                pre: format!("{used} The oldest is from "),
                at: Some(t),
                post: ".".into(),
            },
            Some(t) => Dated {
                pre: format!("{used} It is from "),
                at: Some(t),
                post: ".".into(),
            },
            None => Dated::plain(used),
        },
        Some(SETTINGS_FILES_TIP),
    ));
    let text: Vec<String> = pathwarden_core::dcsettings::fewer_sentence(fewer)
        .into_iter()
        .chain(pathwarden_core::dcsettings::unread_sentence(
            r.settings_folders_unread,
        ))
        .collect();
    Some(Row {
        title: SETTINGS_FILES_ROW,
        status,
        warn: stale > 0 || !fewer.is_empty() || r.settings_folders_unread > 0,
        settings,
        dated,
        text,
        go: Some(Go::SettingsFolders),
        ..Row::default()
    })
}

/// "The read was resumed. It started Oct 29, 2026, 4:07 PM.", `when` being
/// the time as the page or the terminal writes it.
pub fn resumed_sentence(when: &str) -> String {
    format!("The read was resumed. It started {when}.")
}

/// The time a resumed read started, for a terminal: US style, in this
/// computer's time ("Oct 29, 2026, 4:07 PM").
pub fn resumed_at_local(t: i64) -> String {
    pathwarden_core::time::format_local(t)
}

/// Run details' rows `rows` after a Sign in that went as `o`: the Run
/// history row says so, under what it says.
pub fn with_sign_in(rows: &mut [Row], o: crate::sign_in::Outcome) {
    if let Some(r) = rows.iter_mut().find(|r| r.title == HISTORY_ROW) {
        r.said = Some(o);
    }
}

/// The Run history row's title.
pub const HISTORY_ROW: &str = "Run history";

/// "This computer isn't signed in to the repository.", with what to install
/// when git here has no credential helper.
fn not_signed_in(h: &crate::workspace::HistoryLink) -> String {
    use pathwarden_core::connect::{NOT_SIGNED_IN, NO_HELPER, REFUSED};
    if h.no_helper {
        format!("{NOT_SIGNED_IN} {NO_HELPER} then sync again.")
    } else if h.refused {
        REFUSED.to_string()
    } else {
        NOT_SIGNED_IN.to_string()
    }
}

/// How [`Row::kept`] reads, around the path.
pub const KEPT_WORDS: (&str, &str) = (
    "The raw collection was kept in",
    "Delete it when done: it maps your whole domain.",
);

/// `s` as a sentence: capitalised, with a full stop. Warnings kept with
/// older runs were written as clauses. A first word that is a name (a
/// host, a domain, a tool: anything but plain lower-case letters) keeps
/// its case.
fn sentence(s: &str) -> String {
    let s = s.trim();
    let first = s.split_whitespace().next().unwrap_or_default();
    let plain = first.chars().all(|c| c.is_ascii_lowercase() || c == '\'');
    let s = if plain {
        crate::shared_runs::capitalized(s)
    } else {
        s.to_string()
    };
    if s.ends_with(['.', '!', '?']) {
        s
    } else {
        format!("{s}.")
    }
}

/// "2 objects", "1 object".
fn objects(n: usize) -> String {
    format!(
        "{} {}",
        crate::pages::num(n),
        if n == 1 { "object" } else { "objects" }
    )
}

/// The rows of Run details for `r`: where it came from; the other sources
/// read with it (when [`with_sources`] read them); how it was
/// collected (runs from the Collect wizard); objects skipped as too large;
/// OpenGraph and AzureHound sources read part way; its place in the run
/// history (runs analysed here); the comparison with
/// the previous run; collection performance (`perf`, as
/// [`perf_and_applies`]); and the settings line (`applies`).
pub fn rows(r: &RunSummary, perf: Option<bool>, applies: &Result<String, String>) -> Vec<Row> {
    let mut out = Vec::new();
    // Where it came from.
    let left_out = r.shared.as_ref().is_some_and(|s| !s.left_out.is_empty());
    out.push(Row {
        title: "Where it came from",
        status: match &r.shared {
            Some(s) if left_out => format!(
                "From the run history · {}",
                crate::shared_runs::left_out_status(s.left_out.iter().map(|l| l.name.as_str()))
            ),
            Some(s) => format!(
                "From the run history · loaded {}",
                pathwarden_core::time::format_local_date(s.mirrored_at)
            ),
            None if r.pathwarden.is_empty() => "On this computer".into(),
            None => format!("On this computer · Pathwarden {}", r.pathwarden),
        },
        warn: left_out,
        facts: facts(r),
        ..Row::default()
    });
    // Specialist collectors' OpenGraph files read with it, as
    // [`with_sources`] read them.
    out.extend(
        r.other_sources
            .as_deref()
            .and_then(crate::opengraph_ui::details_row),
    );
    // How it was collected: the Collect wizard's runs.
    if let Some(c) = &r.collection {
        let (said, short) = crate::collect::collected_words(c);
        // What the chosen depth or sign-in leaves out is information about
        // an intended collection; only the rest are warnings.
        let (notes, warnings): (Vec<&String>, Vec<&String>) = c
            .warnings
            .iter()
            .partition(|w| pathwarden_collect::is_scope_note(w));
        let n = warnings.len();
        let mut text = vec![said];
        // Kerberos only and SMB signing for the computers.
        text.extend(crate::collect::computers_sentence(c));
        text.extend(notes.iter().map(|w| sentence(w)));
        out.push(Row {
            title: "How it was collected",
            status: match n {
                0 => short,
                1 => "1 collector warning".into(),
                n => format!("{n} collector warnings"),
            },
            warn: n > 0,
            text,
            items: warnings.iter().map(|w| sentence(w)).collect(),
            kept: c.kept.clone(),
            go: Some(Go::Schedule),
            // A read that stopped and was resumed: the run is dated
            // by when it finished.
            resumed: c.read_started,
            ..Row::default()
        });
    }
    // The domains it collected, and the ones it didn't.
    out.extend(domains_row(r));
    // Objects skipped as too large.
    if r.skipped_objects > 0 {
        let n = r.skipped_objects;
        out.push(Row {
            title: "Objects skipped",
            status: format!("{} skipped", objects(n)),
            warn: true,
            text: vec![format!(
                "{} {} too large to read safely. Findings that depend on {} may be missing from this run.",
                objects(n),
                if n == 1 { "was" } else { "were" },
                if n == 1 { "it" } else { "them" }
            )],
            ..Row::default()
        });
    }
    // OpenGraph and AzureHound sources not read whole.
    out.extend(sources_row(r));
    // The Tier Zero settings files it used.
    out.extend(settings_row(r));
    // Its place in the run history: runs analysed here (a run loaded from
    // the repository is in it).
    if let (Some(h), None, false) = (&r.history, &r.shared, r.demo) {
        use crate::shared_runs::FullRunState;
        let mut text = Vec::new();
        let mut status = None;
        if let Some(why) = &h.not_recorded {
            let why = if h.sign_in {
                not_signed_in(h)
            } else {
                sentence(why)
            };
            text.push(format!("This run is not in the run history. {why}"));
            status = Some("Not recorded");
        }
        // The run's point and its full run waiting for the same push: one
        // pair of sentences says both.
        let together = h.unpushed.is_some()
            && h.full_run
                .as_ref()
                .is_some_and(|f| f.state == FullRunState::Unpushed && f.left_out.is_empty());
        if let Some(why) = &h.unpushed {
            let mut line = if h.sign_in {
                let n = not_signed_in(h);
                format!(
                    "This run is saved here, but not shared yet: {}{}",
                    n[..1].to_lowercase(),
                    &n[1..]
                )
            } else {
                sentence(why)
            };
            if together {
                line.push_str(" The report and graph go with it.");
            }
            text.push(line);
            status = status.or(Some("Saved here, not shared yet"));
        }
        let mut full_warn = false;
        if let Some(f) = h.full_run.as_ref().filter(|_| !together) {
            let (line, short, warn) = match f.state {
                FullRunState::Shared if f.left_out.is_empty() => (
                    "The report and graph are in the run history.".to_string(),
                    "Recorded · report shared",
                    false,
                ),
                FullRunState::Shared => {
                    let mut line = format!(
                        "Not all of the report and graph is in the run history. Left out, over the file limit: {}.",
                        f.left_out.join(", ")
                    );
                    if f.left_out.iter().any(|w| {
                        crate::shared_runs::explore_needs(crate::shared_runs::left_out_name(w))
                    }) {
                        line.push(' ');
                        line.push_str(crate::shared_runs::EXPLORE_ELSEWHERE_WORDS);
                    }
                    (line, "Recorded · report shared in part", true)
                }
                FullRunState::Pending => (
                    "The report and graph aren't in the run history yet. The next run on this computer adds them."
                        .to_string(),
                    "Recorded · report not shared yet",
                    true,
                ),
                FullRunState::Unpushed => {
                    let mut line = match f.why.as_deref().filter(|w| !w.trim().is_empty()) {
                        Some(why) => sentence(why),
                        None => "The report and graph aren't shared yet. They go with the next run that syncs.".to_string(),
                    };
                    if !f.left_out.is_empty() {
                        line.push_str(&format!(" Left out: {}.", f.left_out.join(", ")));
                    }
                    (line, "Recorded · report not shared yet", true)
                }
                FullRunState::NotShared => {
                    let mut line = "The report and graph aren't shared.".to_string();
                    if let Some(why) = f.why.as_deref().filter(|w| !w.trim().is_empty()) {
                        line.push(' ');
                        line.push_str(&sentence(why));
                    }
                    if !f.left_out.is_empty() {
                        line.push_str(&format!(" Left out: {}.", f.left_out.join(", ")));
                    }
                    (line, "Recorded · report not shared", true)
                }
            };
            text.push(line);
            full_warn = warn;
            if warn {
                status = status.or(Some(short));
            } else if status.is_none() {
                status = Some(short);
            }
        }
        if text.is_empty() {
            text.push("This run is recorded in the run history.".into());
        }
        let warn = h.not_recorded.is_some() || h.unpushed.is_some() || full_warn || together;
        out.push(Row {
            title: HISTORY_ROW,
            status: status.unwrap_or("Recorded").into(),
            warn,
            text,
            go: Some(Go::History),
            sign_in: h.sign_in
                && !h.no_helper
                && (h.not_recorded.is_some() || h.unpushed.is_some()),
            ..Row::default()
        });
    }
    // The comparison with the previous run in the history.
    if let Some(warnings) = compared(r) {
        let n = warnings.len();
        out.push(Row {
            title: "Compared with the previous run",
            status: format!(
                "{n} {} to check",
                if n == 1 { "difference" } else { "differences" }
            ),
            warn: true,
            items: warnings.iter().map(|w| sentence(w)).collect(),
            ..Row::default()
        });
    }
    // The history's upgrade, when some files couldn't be rewritten.
    if let Some(notes) = upgrade(r) {
        out.push(Row {
            title: "History upgrade",
            status: "Not finished".into(),
            warn: true,
            text: notes.iter().map(|n| n.to_string()).collect(),
            ..Row::default()
        });
    }
    // Collection performance.
    if let Some(slower) = perf {
        out.push(Row {
            title: "Collection performance",
            status: if slower {
                "Slower than the previous collection"
            } else {
                "Timings and diagnostics"
            }
            .into(),
            warn: slower,
            text: vec![
                "Collection timings against the previous run, and a diagnostics download.".into(),
            ],
            go: Some(Go::Performance { slower }),
            ..Row::default()
        });
    }
    // The settings the next analysis applies.
    let (line, loaded) = match applies {
        Ok(t) => (t.clone(), true),
        Err(t) => (t.clone(), false),
    };
    out.push(Row {
        title: "Settings",
        status: if loaded {
            "Applies to the next analysis"
        } else {
            "Couldn't be read"
        }
        .into(),
        warn: !loaded,
        text: vec![line],
        go: Some(Go::Settings),
        ..Row::default()
    });
    out
}

/// The Domains row title.
pub const DOMAINS_ROW: &str = "Domains";

/// The title of the row of other collectors' OpenGraph sources
/// ([`crate::opengraph_ui::details_row`]).
pub const OTHER_SOURCES_ROW: &str = "Other sources";

/// What follows the Mappings link: "Mappings lists what each pack means."
pub const MAPPINGS_TAIL: &str = "lists what each pack means.";

/// `r` with the OpenGraph statistics saved in its folder in `ws`
/// ([`crate::opengraph_ui::read_stats`]), for the "Other sources" row
/// (blocking). The run page, its Run details tab and `runs show` read them
/// so; without them, [`rows`] has no such row.
pub fn with_sources(ws: &Workspace, r: &mut RunSummary) {
    r.other_sources = ws
        .run_dir(&r.id)
        .and_then(|d| crate::opengraph_ui::read_stats(&d))
        .map(Box::new);
}

/// "A, B and C".
pub(crate) fn and_list(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// "1 min", "12 s".
fn took(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds} s")
    } else {
        format!("{} min", (seconds + 30) / 60)
    }
}

/// The Domains row of a run from the Collect wizard: each domain it
/// tried and how that went, the attack paths missing through the ones that
/// failed, and a link to collect those; after a one-domain run, only when
/// trusted domains weren't collected.
fn domains_row(r: &RunSummary) -> Option<Row> {
    let c = r.collection.as_ref()?;
    let outcomes = c.domain_outcomes();
    let collected: Vec<&crate::workspace::DomainOutcome> =
        outcomes.iter().filter(|d| d.collected).collect();
    let failed: Vec<String> = outcomes
        .iter()
        .filter(|d| !d.collected)
        .map(|d| d.domain.clone())
        .collect();
    let tried = |name: &str| outcomes.iter().any(|d| d.domain.eq_ignore_ascii_case(name));
    let missing = crate::collect::not_collected(r)
        .iter()
        .filter(|d| !tried(d))
        .count();
    if outcomes.len() <= 1 && missing == 0 {
        return None;
    }
    let lines = outcomes
        .iter()
        .map(|d| {
            let text = if d.collected {
                let mut t = String::from("Collected");
                // An older run's one domain: the run's own count.
                let n = d.objects.or((outcomes.len() == 1).then_some(r.objects));
                if let Some(n) = n.filter(|n| *n > 0) {
                    t.push_str(&format!(" · {}", objects(n)));
                }
                if let Some(s) = d.seconds {
                    t.push_str(&format!(" · {}", took(s)));
                }
                t
            } else {
                d.reason
                    .clone()
                    .unwrap_or_else(|| "It wasn't collected.".into())
            };
            DomainLine {
                name: d.domain.clone(),
                collected: d.collected,
                text,
                detail: d.detail.clone(),
            }
        })
        .collect();
    let mut text = Vec::new();
    let mut go_words = None;
    if !failed.is_empty() {
        let others = match collected.len() {
            0 => String::new(),
            1 => format!(" {} was analyzed on its own.", collected[0].domain),
            n => format!(" The other {n} domains were analyzed together."),
        };
        text.push(format!(
            "Attack paths through {} are missing.{others}",
            and_list(&failed)
        ));
        go_words = Some(format!("Collect {}", and_list(&failed)));
    } else if missing > 0 {
        text.push(if missing == 1 {
            "1 trusted domain wasn't collected.".to_string()
        } else {
            format!("{missing} trusted domains weren't collected.")
        });
    }
    let status = if outcomes.len() > 1 {
        format!("{} of {} collected", collected.len(), outcomes.len())
    } else {
        format!("1 collected · {missing} trusted not collected")
    };
    Some(Row {
        title: DOMAINS_ROW,
        status,
        warn: !failed.is_empty(),
        text,
        domains: lines,
        go: Some(Go::Collect),
        go_words,
        ..Row::default()
    })
}

/// Whether any row needs a look: the tab's label gets an amber dot.
pub fn needs_a_look(rows: &[Row]) -> bool {
    rows.iter().any(|r| r.warn)
}

/// A row's body as HTML: the facts (`dl`, of class `dl_class`), the
/// sentences, the list, the kept path and the link (`link`, made from
/// the row's [`Go`]).
fn body_html(
    r: &RunSummary,
    row: &Row,
    dl_class: &str,
    list_class: &str,
    link: &dyn Fn(Go, &str) -> String,
    sign_in: &str,
) -> String {
    let mut b = String::new();
    if !row.facts.is_empty() {
        b.push_str(&format!(
            r#"<dl class="{dl_class}">{}</dl>"#,
            facts_html(r, &row.facts)
        ));
    }
    if !row.domains.is_empty() {
        b.push_str(r#"<ul class="rd-doms">"#);
        for (i, d) in row.domains.iter().enumerate() {
            let tip = d
                .detail
                .as_deref()
                .map(|t| crate::pages::tip(&format!("rd-dom-{i}"), &d.name, t))
                .unwrap_or_default();
            b.push_str(&format!(
                r#"<li><span class="n">{}</span><span class="{}">{}{tip}</span></li>"#,
                esc(&d.name),
                if d.collected { "ok" } else { "bad" },
                esc(&d.text),
            ));
        }
        b.push_str("</ul>");
    }
    // The Tier Zero settings files, each with its file name behind
    // its ⓘ.
    if !row.settings.is_empty() {
        b.push_str(r#"<ul class="rd-doms">"#);
        for (i, s) in row.settings.iter().enumerate() {
            b.push_str(&format!(
                r#"<li><span class="n">{}</span><span class="{}">{}{}</span></li>"#,
                esc(&s.name),
                if s.stale { "bad" } else { "ok" },
                s.text.html(),
                crate::pages::tip(&format!("rd-sf-{i}"), &s.name, &s.detail),
            ));
        }
        b.push_str("</ul>");
    }
    for (i, (d, tip)) in row.dated.iter().enumerate() {
        let tip = tip
            .map(|t| crate::pages::tip(&format!("rd-sf-text-{i}"), row.title, t))
            .unwrap_or_default();
        b.push_str(&format!("<p>{}{tip}</p>", d.html()));
    }
    for t in &row.text {
        b.push_str(&format!("<p>{}</p>", esc(t)));
    }
    // In local time, as every time on the page (`app.js`).
    if let Some(t) = row.resumed {
        b.push_str(&format!(
            "<p>{}</p>",
            resumed_sentence(&crate::pages::time(t))
        ));
    }
    if !row.items.is_empty() {
        b.push_str(&format!(r#"<ul class="{list_class}">"#));
        for i in &row.items {
            b.push_str(&format!("<li>{}</li>", esc(i)));
        }
        b.push_str("</ul>");
    }
    if let Some(k) = &row.kept {
        b.push_str(&format!(
            "<p>{} <code>{}</code>. {}</p>",
            KEPT_WORDS.0,
            esc(k),
            KEPT_WORDS.1
        ));
    }
    let words = |go: Go| {
        row.go_words
            .clone()
            .unwrap_or_else(|| go.words().to_string())
    };
    match row.go {
        // Sign in, then the link, in one row.
        Some(go) if row.sign_in => {
            b.push_str(&format!(
                r#"<div class="rd-row">{sign_in}{}</div>"#,
                link(go, &words(go))
            ));
        }
        // Signed in just now: what it says is enough.
        Some(_) if row.said.is_some_and(|o| o.good()) => {}
        // Nothing left out to collect again.
        Some(Go::Collect) if crate::collect::collect_again_href(r).is_none() => {}
        // The link, after the last sentence of a Domains row.
        Some(go @ Go::Collect) if !row.text.is_empty() && row.go_words.is_none() => {
            let last = b.rfind("</p>").unwrap_or(b.len());
            b.insert_str(last, &format!(" {}", link(go, &words(go))));
        }
        // "Mappings lists what each pack means."
        Some(go @ Go::Mappings) => {
            b.push_str(&format!("<p>{} {MAPPINGS_TAIL}</p>", link(go, &words(go))))
        }
        Some(go) => b.push_str(&format!("<p>{}</p>", link(go, &words(go)))),
        None => {}
    }
    if let Some(o) = row.said {
        let tone = if o.good() { "good" } else { "bad" };
        b.push_str(&format!(
            r#"<p class="rd-said {tone}" role="status">{}</p>"#,
            esc(o.words())
        ));
    }
    b
}

/// The Sign in button in the report's Run details tab: it asks the run
/// page (`data-pw-run`), which signs in.
const SIGN_IN_FRAME: &str = r##"<button type="button" class="rd-btn" data-pw-run="sign-in"><svg class="ic" aria-hidden="true"><use href="#i-external"/></svg><span>Sign in</span></button>"##;

/// The external-window icon, for a report whose sprite has none.
const EXTERNAL_SYMBOL: &str = r##"<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false"><defs><symbol id="i-external" viewBox="0 0 24 24"><g fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4"/></g></symbol></defs></svg>"##;

/// How the settings line starts.
const APPLIES_LEAD: &str = "The next analysis applies";

/// What Run details shows besides the facts, for `r` in its own
/// environment of `ws` (blocking): its collection performance (`Some`, and
/// `Some(true)` when slower; none for the demo) and the settings line the
/// next analysis applies ([`crate::settings::applies_words_in`]; `Err`
/// with what to say when the settings can't be loaded). The run page and
/// `runs show` both take it from here.
pub fn perf_and_applies(ws: &Workspace, r: &RunSummary) -> (Option<bool>, Result<String, String>) {
    let perf = (!r.demo).then(|| crate::diagnose::Performance::of(ws, r).slower());
    let applies = crate::settings::applies_words_in(&ws.for_run(r), APPLIES_LEAD);
    (perf, applies)
}

/// The value of the "Recorded" row: [`crate::shared_runs::recorded_words`]
/// without its leading word, which the row's label says ("From the command
/// line by ...", "By the schedule as ...", "In the app by ...").
fn recorded_value(words: &str) -> String {
    let rest = words
        .strip_prefix("recorded ")
        .or_else(|| words.strip_prefix("imported "))
        .unwrap_or(words);
    let rest = if words.starts_with("imported ") {
        format!("imported {rest}")
    } else {
        rest.to_string()
    };
    crate::shared_runs::capitalized(&rest)
}

/// The trash icon, for a report that predates it in its icon set.
const TRASH_SYMBOL: &str = r##"<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false"><defs><symbol id="i-trash" viewBox="0 0 64 64"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M16 20L19 57H45L48 20" stroke="currentColor"/><path d="M27 30V47" stroke="currentColor" opacity="0.42"/><path d="M37 30V47" stroke="currentColor" opacity="0.42"/></g><g stroke="none"><rect x="10" y="10" width="44" height="6" fill="currentColor"/></g></symbol></defs></svg>"##;

/// The tab's style, inside the embedded report: its rows as the
/// Environment tab's (the report's own `details.row`), its buttons as the
/// app's (the same padding, gap and icon size), the facts as History
/// storage's, and the amber dot on the tab's label.
pub const CSS: &str = "<style>\
.rd{display:grid;gap:16px}\
.rd .rows.card{padding:0}\
.rd .rows .body p{margin:0 0 8px;font-size:0.92rem;color:var(--ink)}\
.rd .rows .body p:last-child{margin-bottom:0}\
.rd .rows .body code{font-size:0.82rem;overflow-wrap:anywhere}\
.rd .rd-list{margin:0 0 8px;padding-left:20px;font-size:0.92rem}\
.rd .rd-list li{margin:2px 0}\
.rd .rd-facts+p{margin-top:12px}\
.rd-dot{width:8px;height:8px;border-radius:50%;background:var(--warn);flex:none}\
.rd h3{margin:0 0 10px;font-size:1rem}\
.rd .rd-facts{display:grid;gap:8px;margin:0 0 8px}\
.rd .rd-facts>div{display:grid;grid-template-columns:8rem minmax(0,1fr);gap:4px 16px;align-items:baseline}\
.rd .rd-facts dt{color:var(--muted);font-size:0.84rem;font-weight:600;text-transform:none;letter-spacing:0}\
.rd .rd-facts dd{margin:0;font-size:0.92rem;overflow-wrap:anywhere}\
.rd .rd-facts code{font-size:0.82rem;overflow-wrap:anywhere}\
.rd .rd-facts .rd-branch{display:block}\
.rd p{margin:0;font-size:0.92rem;color:var(--muted)}\
.rd p a{font-weight:600}\
.rd .rd-remove,.rd .rd-add{margin-top:12px;padding:18px 20px;border-top:1px solid var(--line)}\
.rd .rd-remove h3,.rd .rd-add h3{color:var(--muted);font-size:0.86rem;text-transform:uppercase;letter-spacing:0.06em}\
.rd-btn:disabled{opacity:0.5;cursor:default}\
.rd-btn:disabled:hover{border-color:var(--line)}\
.rd .rd-row{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px}\
.rd .rd-row .why{color:var(--muted);font-size:0.86rem}\
.rd-btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:9px 16px;border-radius:10px;\
font:inherit;font-size:0.92rem;font-weight:600;line-height:1.2;color:var(--ink);background:var(--card);\
border:1px solid var(--line);cursor:pointer;white-space:nowrap}\
.rd-btn:hover{border-color:var(--accent)}\
.rd-btn .ic{width:17px;height:17px;flex:none}\
.rd-btn.danger{color:var(--critical)}\
.rd-btn.danger:hover{border-color:var(--critical)}\
.rd .rd-row+p.rd-said,.rd p+p.rd-said{margin-top:10px}\
.rd p.rd-said{font-size:0.86rem;font-weight:600}\
.rd p.rd-said.good{color:var(--good)}\
.rd p.rd-said.bad{color:var(--critical)}\
.rd .body>p+.rd-row{margin-top:10px}\
.rd .rd-doms{list-style:none;padding:0;margin:0 0 10px;display:grid}\
.rd .rd-doms li{display:grid;grid-template-columns:18rem minmax(0,1fr);gap:4px 16px;padding:7px 0;border-top:1px solid var(--line);font-size:0.92rem;align-items:baseline}\
.rd .rd-doms li:first-child{border-top:0}\
.rd .rd-doms .n{font-weight:600;overflow-wrap:anywhere}\
.rd .rd-doms .ok{color:var(--muted)}\
.rd .rd-doms .bad{color:var(--ink)}\
.rd .rd-doms .bad::before{content:\"\";display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--warn);margin-right:8px;vertical-align:1px}\
@media (max-width:640px){.rd .rd-facts>div{grid-template-columns:minmax(0,1fr)}}\
</style>";

/// The tab after Environment, with an amber dot when a row needs a look,
/// carrying the run page's `nonce` (the app's script checks that this tab,
/// not one the report made, can be seen).
fn tab_html(dot: bool, nonce: &str) -> String {
    let dot = if dot {
        r#"<span class="rd-dot" role="img" aria-label="Needs a look" title="Needs a look"></span>"#
    } else {
        ""
    };
    format!(
        r##"<a role="tab" id="tab-details" href="#details" aria-controls="details" data-pw-tab="{nonce}"><svg class="ic" aria-hidden="true"><use href="#i-info"/></svg><span class="tl">{TAB}</span>{dot}</a>"##
    )
}

/// The rows ([`rows`]) as one card of the report's foldable rows, a row
/// that needs a look amber and open; links ask the run page
/// (`data-pw-run`).
fn rows_card(r: &RunSummary, rows: &[Row]) -> String {
    let link = |go: Go, words: &str| {
        format!(
            r##"<a href="#" data-pw-run="{}">{}</a>"##,
            go.action(),
            esc(words)
        )
    };
    let mut b = String::from(r#"<div class="rows card">"#);
    for row in rows {
        b.push_str(&format!(
            r#"<details class="row env"{open}><summary><span class="title">{title}</span><span class="aside{w}">{status}</span></summary><div class="body">{body}</div></details>"#,
            open = if row.warn || row.said.is_some() {
                " open"
            } else {
                ""
            },
            w = if row.warn { " warn" } else { "" },
            title = row.title,
            status = esc(&row.status),
            body = body_html(r, row, "rd-facts", "rd-list", &link, SIGN_IN_FRAME),
        ));
    }
    b.push_str("</div>");
    b
}

/// The tab's panel: the rows ([`rows`] of `r`, `perf` and `applies`) and
/// Remove this run.
pub fn panel_html(
    r: &RunSummary,
    perf: Option<bool>,
    applies: &Result<String, String>,
    remove: Remove,
    nonce: &str,
    said: Option<crate::sign_in::Outcome>,
) -> String {
    let mut all = rows(r, perf, applies);
    if let Some(o) = said {
        with_sign_in(&mut all, o);
    }
    let rows = rows_card(r, &all);
    let (label, why) = remove.words();
    let why = if why.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="why">{why}</span>"#)
    };
    let (class, icon) = match remove {
        Remove::Hide => ("rd-btn", ""),
        _ => (
            "rd-btn danger",
            r##"<svg class="ic" aria-hidden="true"><use href="#i-trash"/></svg>"##,
        ),
    };
    let add = add_frame_html(r);
    format!(
        r##"<section id="details" class="panel" role="tabpanel" aria-labelledby="tab-details" tabindex="-1" data-pw-nonce="{nonce}"><h2 class="panel-title">{TAB}</h2><div class="rd">{rows}{add}<div class="rd-remove"><h3>Remove this run</h3><div class="rd-row"><button type="button" class="{class}" data-pw-run="remove">{icon}<span>{label}</span></button>{why}</div></div></div></section>"##
    )
}

/// "Add other data" in the tab: analyze the run's kept collection
/// again with other collectors' files. The button asks the run page
/// (`data-pw-run="add-data"`), which opens Analyze with the collection;
/// greyed out, with why, when the collection wasn't kept or is gone; not
/// there for a run that wasn't collected on this computer.
fn add_frame_html(r: &RunSummary) -> String {
    use crate::add_data::{self, Kept};
    let Some(kept) = add_data::kept_collection(r) else {
        return String::new();
    };
    let button = match kept {
        Kept::Here(_) => format!(
            r#"<button type="button" class="rd-btn" data-pw-run="add-data"><span>{}</span></button>"#,
            add_data::BUTTON
        ),
        _ => format!(
            r#"<button type="button" class="rd-btn" disabled><span>{}</span></button>"#,
            add_data::BUTTON
        ),
    };
    format!(
        r#"<div class="rd-add"><h3>{}</h3><div class="rd-row">{button}<span class="why">{}</span></div></div>"#,
        add_data::TITLE,
        esc(kept.line())
    )
}

/// "Add other data" in the run page's own Run details
/// ([`below_html`]): a link to Analyze with the run's kept collection, or
/// the greyed-out button and why.
fn add_app_html(r: &RunSummary) -> String {
    use crate::add_data::{self, Kept};
    let Some(kept) = add_data::kept_collection(r) else {
        return String::new();
    };
    let action = match kept {
        Kept::Here(_) => format!(
            r#"<a class="btn" href="/analyze?from={}">{}</a>"#,
            esc(&r.id),
            add_data::BUTTON
        ),
        _ => format!(
            r#"<button type="button" class="btn" disabled>{}</button>"#,
            add_data::BUTTON
        ),
    };
    format!(
        r#"<div class="rd-remove-app rd-add-app" role="group" aria-labelledby="rd-add-h"><h3 class="rd-h" id="rd-add-h">{}</h3><div class="rd-row-app">{action}<span class="muted small">{}</span></div></div>"#,
        add_data::TITLE,
        esc(kept.line())
    )
}

/// Whether the tab goes into this report when the run page embeds it
/// ([`inject`]): the app's script goes in with it
/// ([`crate::retest_ui::embeds_script`]) and the report has the
/// Environment tab, with `</main>` after it. The server and the run page
/// both decide by this, on the report as the frame gets it.
pub fn can_inject(html: &str) -> bool {
    let tab = env_tab_end(html);
    let main = html.rfind("</main>");
    matches!((tab, main), (Some(t), Some(m)) if t <= m) && crate::retest_ui::embeds_script(html)
}

/// A per-page nonce for the run page and its frame: 32 hex digits. `None`
/// when the system has no randomness to give: then there is no nonce, and
/// nothing that needs one (never a guessable one).
pub fn try_nonce() -> Option<String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).ok()?;
    Some(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// [`try_nonce`], for tests.
#[cfg(test)]
pub fn new_nonce() -> String {
    try_nonce().expect("randomness")
}

/// Whether `s` is a nonce [`try_nonce`] made.
pub fn valid_nonce(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The run page's own Run details, below the report frame and as wide as
/// it: a collapsed "Run details" row (`<details>`, so it opens without
/// script) with the same rows as the tab ([`rows`]), and under it "Remove
/// this run", always shown (the page's Delete button, with its confirm
/// dialog). For a report that can't carry the tab; for a run loaded from
/// the history whose report carries it, hidden as [`fallback_html`].
pub fn below_html(
    r: &RunSummary,
    perf: Option<bool>,
    applies: &Result<String, String>,
    remove: Remove,
    said: Option<crate::sign_in::Outcome>,
) -> String {
    use crate::pages::icon;
    let mut all = rows(r, perf, applies);
    if let Some(o) = said {
        with_sign_in(&mut all, o);
    }
    let link = |go: Go, words: &str| format!(r#"<a href="{}">{}</a>"#, go.href(r), esc(words));
    let sign_in = crate::last_pull::sign_in_button("data-sign-in");
    let mut list = String::new();
    for row in &all {
        list.push_str(&format!(
            r#"<details class="rd-r{w}"{open}><summary><span class="rd-t">{title}</span><span class="rd-s">{status}</span></summary><div class="rd-b">{body}</div></details>"#,
            open = if row.warn || row.said.is_some() {
                " open"
            } else {
                ""
            },
            w = if row.warn { " warn" } else { "" },
            title = row.title,
            status = esc(&row.status),
            body = body_html(r, row, "rd-dl", "rd-list", &link, &sign_in),
        ));
    }
    let dot = if needs_a_look(&all) {
        r#"<span class="rd-dot" role="img" aria-label="Needs a look" title="Needs a look"></span>"#
    } else {
        ""
    };
    let (label, why) = remove.words();
    let why = if why.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="muted small">{why}</span>"#)
    };
    let (class, trash) = match remove {
        Remove::Hide => ("btn", String::new()),
        _ => ("btn danger", icon("i-trash")),
    };
    let add = add_app_html(r);
    format!(
        r#"<section class="card rd-below" id="run-details" aria-label="{TAB}"><details class="rd-more"{more_open}><summary><span class="rd-sum">{TAB}{dot}</span><svg class="ic chev" aria-hidden="true" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg></summary><div class="rd-body">{list}</div></details>{add}<div class="rd-remove-app" role="group" aria-labelledby="rd-remove-h"><h3 class="rd-h" id="rd-remove-h">Remove this run</h3><div class="rd-row-app"><button type="button" class="{class}" data-delete="{id}">{trash}<span>{label}</span></button>{why}</div></div></section>"#,
        id = esc(&r.id),
        more_open = if said.is_some() { " open" } else { "" },
    )
}

/// [`below_html`], hidden, for a run loaded from the history whose report
/// carries the tab: its report is the repository's file, and could hide
/// the tab with its own styles. The app's script in the frame says whether
/// the tab it added can be seen; the run page shows this copy when it
/// can't, or when the frame says nothing, and removes it when it can.
pub fn fallback_html(
    r: &RunSummary,
    perf: Option<bool>,
    applies: &Result<String, String>,
    remove: Remove,
    said: Option<crate::sign_in::Outcome>,
) -> String {
    below_html(r, perf, applies, remove, said).replacen(
        r#"<section class="card rd-below" id="run-details""#,
        r#"<section class="card rd-below" id="run-details" data-rd-fallback hidden"#,
        1,
    )
}

/// The Collection tab's end, after which the tab goes.
const ENV_TAB: &str = r#"<span class="tl">Collection</span></a>"#;
/// The same tab in reports made before the language pass, when it was "Environment".
const OLD_ENV_TAB: &str = r#"<span class="tl">Environment</span></a>"#;

/// Where the report's Collection (formerly Environment) tab ends.
fn env_tab_end(html: &str) -> Option<usize> {
    [ENV_TAB, OLD_ENV_TAB]
        .iter()
        .find_map(|t| html.find(t).map(|i| i + t.len()))
}

/// The embedded report `html` with the tab after Environment (with an
/// amber dot when `dot`, [`needs_a_look`], and the page's `nonce`) and
/// `panel` after its last panel; the trash icon added when the report
/// predates it. A report without the Environment tab or a `</main>` is
/// left as it is.
pub fn inject(html: &str, panel: &str, dot: bool, nonce: &str) -> String {
    let (Some(t), Some(m)) = (env_tab_end(html), html.rfind("</main>")) else {
        return html.to_string();
    };
    if t > m {
        return html.to_string();
    }
    // After the last panel: before the report's footer, which ends `main`.
    let m = match html[t..m].rfind("<footer>") {
        Some(f) => t + f,
        None => m,
    };
    let icon = if html.contains(r#"id="i-trash""#) {
        ""
    } else {
        TRASH_SYMBOL
    };
    let mut out = String::with_capacity(html.len() + panel.len() + 2048);
    out.push_str(&html[..t]);
    out.push_str(&tab_html(dot, nonce));
    out.push_str(&html[t..m]);
    out.push_str(panel);
    out.push_str(icon);
    if panel.contains("#i-external") && !html.contains(r#"id="i-external""#) {
        out.push_str(EXTERNAL_SYMBOL);
    }
    out.push_str(&html[m..]);
    out
}

#[cfg(test)]
#[path = "run_details_browser_tests.rs"]
pub(crate) mod browser_tests;

#[cfg(test)]
#[path = "run_details_tests.rs"]
mod tests;
