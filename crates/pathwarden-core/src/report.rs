//! The HTML report: one self-contained file (no scripts, fonts or images
//! loaded from anywhere) that can be emailed, attached to a change ticket or
//! archived.
//!
//! It is organized for progressive disclosure: an Overview tab with one
//! sentence, the headline numbers (with what they mean), the first plan steps
//! and the findings no step closes; then the full Remediation path, the
//! Findings grouped by rule (each group holding its findings and the rule's
//! step-by-step guide), and the Environment details. Everything is collapsed
//! until the reader asks for it. Without JavaScript, and in print, all tabs
//! are shown one after another.
//!
//! A report of the run that left the findings state also has the Introduced
//! filter on its Findings tab ([`crate::introduced`]): a period to look back
//! over, a badge on each finding new in it (New, Back, +N objects), the
//! objects each finding gained first with when they were first seen, and
//! the new paths into Tier Zero and the zones.

mod accounts;
mod diagram;

use std::collections::BTreeMap;
use std::fmt::Write;

use crate::findings::{Category, Finding, Severity};
use crate::guides;
use crate::ingest::IngestStats;
use crate::model::{EdgeKind, NodeKind};
use crate::opengraph::KindTable;
use crate::posture::{Posture, ZonePosture, LOW_PERCENT};
use crate::remediation::{PlannedFix, RemediationPlan};
use crate::since::{Delta, Share, SinceLast, Tone};
use crate::state::{CompletenessPoint, HistoryPoint};

const CSS: &str = include_str!("report/report.css");
/// The report's stylesheet, for pages that share its look (the local UI).
pub const REPORT_CSS: &str = CSS;
/// The account lists' script ([`ACCOUNTS_JS`]), the report's and Home's.
const ACCOUNTS: &str = include_str!("report/accounts.js");
/// The script that draws the account lists from their data (the steps'
/// accounts, and those that now reach Tier Zero or no longer do): in the
/// report's own script, and served to the app's Home, which shows the
/// report's What changed.
pub const ACCOUNTS_JS: &str = ACCOUNTS;
const JS: &str = concat!(
    include_str!("report/report.js"),
    include_str!("report/accounts.js")
);
/// The report's one inline script, exactly as written into every report
/// (the local UI pins its Content Security Policy to its hash): its own
/// and the account lists' ([`ACCOUNTS_JS`]).
pub const REPORT_JS: &str = JS;
// The Crown W mark and the outlined wordmark, for inlining: colored by the
// stylesheet's --cw-* tokens (one copy serves both themes) and animated by
// it (`.cw-intro`). Built by scripts/brand/build_repo.py.
const MARK: &str = include_str!("../../../assets/brand/inline/mark.svg");
const WORDMARK: &str = include_str!("../../../assets/brand/inline/wordmark.svg");

/// What changed's accounts that now reach Tier Zero and those that no
/// longer do: their anchor, which the hero's change and the app's Runs
/// list link to.
pub const CHANGE_ANCHOR: &str = accounts::CHANGE_ID;

/// Whether a report's What changed opens to the accounts that now reach
/// Tier Zero and those that no longer do (it has [`CHANGE_ANCHOR`]): the
/// app's Runs list links there only then. Names in a report are escaped,
/// so only the report's own markup has the anchor.
pub fn opens_change(html: &str) -> bool {
    html.contains(&format!(r#"id="{CHANGE_ANCHOR}""#))
}

/// Runs on the Overview's trend, this one included.
const TREND_RUNS: usize = 6;
/// Affected objects shown per kind before "Show N more".
const AFFECTED_VISIBLE: usize = 12;
/// Affected objects written into the report per finding at most; the full
/// list is in `pathwarden findings --json` and the event document.
const AFFECTED_MAX: usize = 1000;

/// The Crown W mark alone (inline SVG, `class="cw"`), as the app's bare
/// pages and its phone bar show it. Its gradients and clip path have fixed
/// IDs, so a page holds one copy.
pub fn brand_mark() -> &'static str {
    MARK.trim_end()
}

/// The Crown W lockup: the mark and the wordmark side by side (two inline
/// SVGs, laid out by `.lockup`). Decorative: the element holding it carries
/// the name.
pub fn brand_lockup() -> String {
    format!("{}{}", MARK.trim_end(), WORDMARK.trim_end())
}

pub struct ReportInput<'a> {
    pub posture: &'a Posture,
    pub findings: &'a [Finding],
    pub plan: &'a RemediationPlan,
    pub stats: &'a IngestStats,
    /// Domains present in the collected data.
    pub domains: &'a [String],
    /// Unix time the report was generated.
    pub generated_at: i64,
    /// The run history ([`crate::history::for_report`]): the earlier runs
    /// of this environment give the Overview its trend, and what changed
    /// since the last run is [`crate::history::ReportHistory::since`], the
    /// comparison `pathwarden history` prints. Empty without a run
    /// history; the Overview then shows this run alone.
    pub history: &'a crate::history::ReportHistory<'a>,
    /// When findings, objects and paths were first seen, for the Findings
    /// tab's Introduced filter; `None` without the findings state this run
    /// left.
    pub introduced: Option<&'a crate::introduced::ForReport<'a>>,
    /// The domains and trusts ([`crate::forest::forest_map`]): the Trusts
    /// table's SID filtering (each way, as the trusting side records it)
    /// and Risk columns, as the app's Forest view and `pathwarden summary`
    /// show them. `None`: the records' own flags, and no Risk column.
    pub forest: Option<&'a crate::forest::ForestMap>,
    /// Which accounts each step cuts off, and which reach Tier Zero now or
    /// no longer ([`crate::exposed::ExposureLists`]): the Remediation
    /// path's account lists and What changed's. `None`: neither.
    pub lists: Option<&'a crate::exposed::ExposureLists>,
    /// What the mapping packs say about the run's external (OpenGraph)
    /// kinds ([`crate::graph::AdGraph::kind_table`]): their labels ("Entra
    /// role") and icons, as Explore shows them. `None`: external objects
    /// keep their kind name and the generic icon.
    pub kinds: Option<&'a KindTable>,
}

/// What the top of the Overview is made from ([`overview_fragment`]): the
/// report's own ([`ReportInput::overview_input`]), or Home's for a run
/// loaded from the history, read from its event document.
pub struct OverviewInput<'a> {
    pub posture: &'a Posture,
    /// Changes in the remediation plan (the choke points).
    pub plan_steps: usize,
    /// Accounts with a path to Tier Zero the plan starts from.
    pub exposed_before: usize,
    /// The plan's first step, which the Choke points card names.
    pub first_step: Option<&'a crate::remediation::PlannedFix>,
    /// When the data was collected.
    pub collected_at: Option<i64>,
    /// Unix time the report was generated.
    pub generated_at: i64,
    pub history: &'a crate::history::ReportHistory<'a>,
    pub introduced: Option<&'a crate::introduced::ForReport<'a>>,
    /// The run's account lists, for What changed's accounts that now reach
    /// Tier Zero or no longer do.
    pub lists: Option<&'a crate::exposed::ExposureLists>,
}

impl<'a> ReportInput<'a> {
    /// What the top of this report's Overview is made from.
    pub fn overview_input(&self) -> OverviewInput<'a> {
        OverviewInput {
            posture: self.posture,
            plan_steps: self.plan.fixes.len(),
            exposed_before: self.plan.exposed_before,
            first_step: self.plan.fixes.first(),
            collected_at: self.stats.collected_at,
            generated_at: self.generated_at,
            history: self.history,
            introduced: self.introduced,
            lists: self.lists,
        }
    }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            // Bidi controls would reorder a name as shown; show them instead.
            c if crate::text::is_bidi_control(c) => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Inline code spans in finding text (`certutil ...`) become <code>.
fn text_with_code(s: &str) -> String {
    let mut out = String::new();
    for (i, part) in s.split('`').enumerate() {
        if i % 2 == 1 {
            let _ = write!(out, "<code>{}</code>", esc(part));
        } else {
            out.push_str(&esc(part));
        }
    }
    out
}

fn pct(v: f64) -> String {
    crate::posture::share_percent(v)
}

/// "1 finding", "3 findings", "1,169,537 principals".
fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", num(n), if n == 1 { one } else { many })
}

/// A count with thousands separators: 1169537 -> "1,169,537".
pub fn num(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn sev_class(s: Severity) -> &'static str {
    s.as_str()
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

const SEVERITIES: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

/// A bar filled to `percent`, in the colour of `class` (a grade's
/// [`crate::posture::ExposureGrade::css_class`]).
fn meter(percent: f64, class: &str, label: &str) -> String {
    let p = percent.clamp(0.0, 100.0);
    format!(
        r#"<div class="meter {class}" role="img" aria-label="{}"><span style="width:{p:.1}%"></span></div>"#,
        esc(label)
    )
}

fn badge(s: Severity) -> String {
    format!(
        r#"<span class="badge {}"><span class="dot" aria-hidden="true"></span>{}</span>"#,
        sev_class(s),
        sev_label(s)
    )
}

/// "Your team set the severity of 2 rules: PW-002 and PW-011." under the
/// Overview's severity cards, linking to the Environment tab's Rule
/// settings.
fn severities_set_line(set: &[crate::posture::SeveritySetting]) -> Option<String> {
    let rules: Vec<String> = set.iter().map(|s| esc(&s.rule)).collect();
    let (last, rest) = rules.split_last()?;
    let list = if rest.is_empty() {
        last.clone()
    } else {
        format!("{} and {last}", rest.join(", "))
    };
    let of = if rest.is_empty() {
        String::new()
    } else {
        format!("{} rules: ", rules.len())
    };
    Some(format!(
        r##"<p class="ov-note muted small sev-note">Your team set the severity of {of}<a href="#env-severities">{list}</a>.</p>"##
    ))
}

/// The small "SET" beside a severity the team set, with its default.
fn set_chip(default: Severity) -> String {
    format!(
        r#"<span class="sevset" title="Severity set by your team. The default is {d}." aria-label="Severity set by your team, default {d}">Set</span>"#,
        d = sev_label(default)
    )
}

fn category_label(c: Category) -> &'static str {
    match c {
        Category::AttackPath => "Attack path",
        Category::Hygiene => "Hygiene",
    }
}

fn category_key(c: Category) -> &'static str {
    match c {
        Category::AttackPath => "attack_path",
        Category::Hygiene => "hygiene",
    }
}

pub fn render_html(r: &ReportInput) -> String {
    let _kinds = ExtKindsScope::enter(r.kinds);
    let mut h = String::with_capacity(256 * 1024);
    let domains = if r.domains.is_empty() {
        "Active Directory".to_string()
    } else {
        r.domains.join(", ")
    };
    let collected = r.stats.collected_at.map_or_else(
        || "unknown".into(),
        |t| {
            format!(
                r#"{} <span class="muted">(collector's time)</span>"#,
                collected_html(t)
            )
        },
    );
    // In UTC until the script moves it to the reader's zone and says so.
    let generated = format!(
        r#"{}<span class="muted" data-local-note hidden> (your time)</span>"#,
        time_html(r.generated_at)
    );
    let domain_list: String = if r.domains.is_empty() {
        "<li>Active Directory</li>".to_string()
    } else {
        // Long domain names wrap only at the dots.
        r.domains
            .iter()
            .map(|d| format!("<li>{}</li>", esc(d).replace('.', ".<wbr>")))
            .collect()
    };
    let open = num(r.findings.iter().filter(|f| f.suppressed.is_none()).count());
    let urgent = r.posture.findings.critical + r.posture.findings.high;

    let _ = write!(
        h,
        r##"<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="Pathwarden {version}">
<title>Pathwarden report: {title}</title>
<style>{CSS}</style>
</head>
<body>
{icons}
<div class="shell">
<aside class="rail">
  <div class="brand"><div class="lockup cw-intro" role="img" aria-label="Pathwarden">{lockup}</div><p class="tagline">Defend every path to privilege.</p></div>
  <nav class="tabs" aria-label="Report sections">
    <div class="tablist" role="tablist" aria-orientation="vertical">
      <a role="tab" id="tab-overview" href="#overview" aria-controls="overview">{i_overview}<span class="tl">Overview</span></a>
      <a role="tab" id="tab-plan" href="#plan" aria-controls="plan">{i_plan}<span class="tl">Remediation path</span><span class="count">{fixes}</span></a>
      <a role="tab" id="tab-findings" href="#findings" aria-controls="findings">{i_findings}<span class="tl">Findings</span><span class="count{hot}">{open}</span></a>
      <a role="tab" id="tab-environment" href="#environment" aria-controls="environment">{i_env}<span class="tl">Collection</span></a>
    </div>
  </nav>
  <dl class="meta">
    <div><dt>Domains</dt><dd><ul class="domains">{domain_list}</ul></dd></div>
    <div><dt>Data collected</dt><dd>{collected}</dd></div>
    <div><dt>Report generated</dt><dd>{generated}</dd></div>
  </dl>
  <div class="rail-foot">
    <button type="button" class="theme-toggle" id="theme-toggle">{i_theme}<span class="tt-label">Light mode</span></button>
    <p class="confidential">Confidential: this report shows how an attacker could move through the directory.</p>
  </div>
</aside>
<main>
"##,
        version = env!("CARGO_PKG_VERSION"),
        icons = sprite(),
        title = esc(&domains),
        lockup = brand_lockup(),
        i_overview = icon("i-gauge"),
        i_plan = icon("i-plan"),
        i_findings = icon("i-alert"),
        i_env = icon("i-server"),
        i_theme = icon("i-theme"),
        fixes = num(r.plan.fixes.len()),
        hot = if urgent > 0 { " hot" } else { "" },
    );

    let links = PlanLinks::new(r.plan, r.findings);
    overview_section(&mut h, r);
    plan_section(&mut h, r, &links);
    findings_section(&mut h, r, &links);
    environment_section(&mut h, r);

    let _ = write!(
        h,
        r#"<footer>Generated by Pathwarden {} &middot; <a href="https://pathwarden.org">pathwarden.org</a></footer>
</main>
</div>
<script>{JS}</script>
</body>
</html>
"#,
        env!("CARGO_PKG_VERSION")
    );
    h
}

/// The open findings a remediation plan doesn't close: those no step
/// closes or cuts, and weak accounts whose path a step only cuts. Most
/// severe first. The report's "Not closed by this plan"; shared with
/// `pathwarden plan`.
pub fn findings_left<'a>(plan: &RemediationPlan, findings: &'a [Finding]) -> Vec<&'a Finding> {
    PlanLinks::new(plan, findings).uncovered(findings)
}

/// One change of a remediation plan with the open findings it takes care
/// of.
pub struct FixGroup<'a> {
    /// The change's number in the plan (1-based).
    pub step: usize,
    pub fix: &'a PlannedFix,
    /// Findings the change itself fixes.
    pub closes: Vec<&'a Finding>,
    /// Findings whose attack path the change cuts. A weak account stays
    /// roastable, so it still needs its own fix.
    pub cuts: Vec<&'a Finding>,
}

impl FixGroup<'_> {
    pub fn len(&self) -> usize {
        self.closes.len() + self.cuts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Open findings grouped by the change that takes care of them: the
/// report's "Group by: change that fixes it" and `pathwarden findings
/// --by-fix`.
pub struct FixGroups<'a> {
    /// Changes with at least one finding, those taking care of the most
    /// first; ties in plan order. A finding two changes cut is under both.
    pub groups: Vec<FixGroup<'a>>,
    /// Changes that cut paths but have no finding of their own.
    pub without_findings: usize,
    /// Open findings no change closes or cuts, most severe first.
    pub alone: Vec<&'a Finding>,
}

impl FixGroups<'_> {
    /// Distinct findings some change closes.
    pub fn closed(&self) -> usize {
        let mut fps: Vec<&str> = self
            .groups
            .iter()
            .flat_map(|g| &g.closes)
            .map(|f| f.fingerprint.as_str())
            .collect();
        fps.sort_unstable();
        fps.dedup();
        fps.len()
    }

    /// Distinct findings some change takes off every path without closing.
    pub fn cut_only(&self) -> usize {
        let closed: std::collections::BTreeSet<&str> = self
            .groups
            .iter()
            .flat_map(|g| &g.closes)
            .map(|f| f.fingerprint.as_str())
            .collect();
        let mut fps: Vec<&str> = self
            .groups
            .iter()
            .flat_map(|g| &g.cuts)
            .map(|f| f.fingerprint.as_str())
            .filter(|fp| !closed.contains(fp))
            .collect();
        fps.sort_unstable();
        fps.dedup();
        fps.len()
    }
}

pub fn fix_groups<'a>(plan: &'a RemediationPlan, findings: &'a [Finding]) -> FixGroups<'a> {
    let links = PlanLinks::new(plan, findings);
    let mut alone: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.suppressed.is_none() && links.coverage(f).is_none())
        .collect();
    alone.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.rule.cmp(b.rule)));
    let mut groups: Vec<FixGroup> = plan
        .fixes
        .iter()
        .zip(links.steps)
        .enumerate()
        .map(|(i, (fix, rel))| FixGroup {
            step: i + 1,
            fix,
            closes: rel.fixes,
            cuts: rel.cuts,
        })
        .collect();
    let without_findings = groups.iter().filter(|g| g.is_empty()).count();
    groups.retain(|g| !g.is_empty());
    groups.sort_by(|a, b| b.len().cmp(&a.len()).then(a.step.cmp(&b.step)));
    FixGroups {
        groups,
        without_findings,
        alone,
    }
}

/// A saved report with this build's stylesheet in place of the one it was
/// written with, so reports analyzed earlier get layout fixes made since
/// (their markup is unchanged; the stored file isn't touched). A page with
/// no report `<style>` block is returned as it is.
pub fn with_current_style(html: &str) -> String {
    const OPEN: &str = "<style>";
    const CLOSE: &str = "</style>";
    let Some(s) = html.find(OPEN).map(|i| i + OPEN.len()) else {
        return html.to_string();
    };
    let Some(e) = html[s..].find(CLOSE).map(|i| s + i) else {
        return html.to_string();
    };
    if html[s..e] == *CSS {
        return html.to_string();
    }
    let mut out = String::with_capacity(html.len() - (e - s) + CSS.len());
    out.push_str(&html[..s]);
    out.push_str(CSS);
    out.push_str(&html[e..]);
    out
}

/// A rendered report with a run label ("after GPO fix"): in the title
/// ("Pathwarden report: after GPO fix (FABRIKAM.LOCAL)") and as a "Run" line
/// in the rail above Domains. The label is escaped here. A report that
/// already has one keeps it; a page that isn't a report is returned as it
/// is. The UI stores reports without a label and adds the current one when
/// it serves them, so a label edited later shows everywhere.
pub fn with_label(html: &str, label: &str) -> String {
    const TITLE: &str = "<title>Pathwarden report: ";
    // "Domains" since the language pass; reports saved before it say "Environment".
    const META: [&str; 2] = [
        "<dl class=\"meta\">\n    <div><dt>Domains</dt>",
        "<dl class=\"meta\">\n    <div><dt>Environment</dt>",
    ];
    let label = label.trim();
    if label.is_empty() || html.contains("<dt>Run</dt>") {
        return html.to_string();
    }
    let meta = META.iter().find_map(|m| html.find(m));
    let (Some(t), Some(m)) = (html.find(TITLE), meta) else {
        return html.to_string();
    };
    let t_end = t + TITLE.len();
    let Some(close) = html[t_end..].find("</title>").map(|i| t_end + i) else {
        return html.to_string();
    };
    if m < close {
        return html.to_string();
    }
    let at = m + "<dl class=\"meta\">\n".len();
    let mut out = String::with_capacity(html.len() + 2 * label.len() + 64);
    out.push_str(&html[..t_end]);
    let _ = write!(out, "{} ({})", esc(label), &html[t_end..close]);
    out.push_str(&html[close..at]);
    let _ = writeln!(out, "    <div><dt>Run</dt><dd>{}</dd></div>", esc(label));
    out.push_str(&html[at..]);
    out
}

/// Line icons, defined once and referenced with `<use>`.
const ICONS: &str = r##"<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false"><defs>
<symbol id="i-user" viewBox="0 0 64 64"><defs><mask id="mr-user" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="12" cy="56" r="7.25" fill="#000"/><circle cx="52" cy="56" r="7.25" fill="#000"/><circle cx="32" cy="19" r="11" fill="#000"/></mask></defs><g mask="url(#mr-user)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M12 56C12 44 21 38 32 38C43 38 52 44 52 56" stroke="currentColor"/></g></g><g stroke="none"><circle cx="12" cy="56" r="5.25" fill="currentColor"/><circle cx="52" cy="56" r="5.25" fill="currentColor"/><circle cx="32" cy="19" r="9" fill="currentColor"/></g></symbol>
<symbol id="i-group" viewBox="0 0 64 64"><defs><mask id="mr-group" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="8" cy="56" r="7.25" fill="#000"/><circle cx="44" cy="56" r="7.25" fill="#000"/><circle cx="44" cy="16" r="8.5" fill="#000"/><circle cx="26" cy="21" r="10.5" fill="#000"/></mask></defs><g mask="url(#mr-group)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M8 56C8 45 16 39 26 39C36 39 44 45 44 56" stroke="currentColor"/><path d="M47 34C53 35.5 57 41 57 49" stroke="currentColor"/></g></g><g stroke="none"><circle cx="8" cy="56" r="5.25" fill="currentColor"/><circle cx="44" cy="56" r="5.25" fill="currentColor"/><circle cx="44" cy="16" r="6.5" fill="currentColor"/><circle cx="26" cy="21" r="8.5" fill="currentColor"/></g></symbol>
<symbol id="i-computer" viewBox="0 0 64 64"><defs><mask id="mr-computer" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="20.5" cy="18.5" r="6" fill="#000"/><circle cx="20.5" cy="45.5" r="6.5" fill="#000"/></mask></defs><g mask="url(#mr-computer)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M14 9H50A4 4 0 0 1 54 13V24A4 4 0 0 1 50 28H14A4 4 0 0 1 10 24V13A4 4 0 0 1 14 9Z" stroke="currentColor"/><path d="M14 36H50A4 4 0 0 1 54 40V51A4 4 0 0 1 50 55H14A4 4 0 0 1 10 51V40A4 4 0 0 1 14 36Z" stroke="currentColor"/><path d="M30 18.5H44" stroke="currentColor" opacity="0.42"/><path d="M30 45.5H44" stroke="currentColor" opacity="0.42"/></g></g><g stroke="none"><circle cx="20.5" cy="18.5" r="4" fill="currentColor"/><circle cx="20.5" cy="45.5" r="4.5" fill="currentColor"/></g></symbol>
<symbol id="i-domain" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/></symbol>
<symbol id="i-folder" viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></symbol>
<symbol id="i-policy" viewBox="0 0 64 64"><defs><mask id="mr-policy" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="32" cy="38" r="8.5" fill="#000"/></mask></defs><g mask="url(#mr-policy)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M8 15H26L32 22H56V53H8Z" stroke="currentColor"/></g></g><g stroke="none"><circle cx="32" cy="38" r="6.5" fill="currentColor"/></g></symbol>
<symbol id="i-cert" viewBox="0 0 64 64"><defs><mask id="mr-cert" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="46" cy="42" r="10" fill="#000"/></mask></defs><g mask="url(#mr-cert)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M8 10H56V42H8Z" stroke="currentColor"/><path d="M17 21H43" stroke="currentColor" opacity="0.42"/><path d="M17 31H33" stroke="currentColor" opacity="0.42"/><path d="M41 49L37 59" stroke="currentColor"/><path d="M51 49L55 59" stroke="currentColor"/></g></g><g stroke="none"><circle cx="46" cy="42" r="8" fill="currentColor"/></g></symbol>
<symbol id="i-object" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3"/></symbol>
<symbol id="i-gauge" viewBox="0 0 64 64"><defs><mask id="mr-gauge" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="10" cy="46" r="7.25" fill="#000"/><circle cx="54" cy="46" r="7.25" fill="#000"/><circle cx="32" cy="46" r="8.75" fill="#000"/></mask></defs><g mask="url(#mr-gauge)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M10 46A22 22 0 0 1 54 46" stroke="currentColor"/><path d="M32 46L43 31" stroke="currentColor"/></g></g><g stroke="none"><circle cx="10" cy="46" r="5.25" fill="currentColor"/><circle cx="54" cy="46" r="5.25" fill="currentColor"/><circle cx="32" cy="46" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-plan" viewBox="0 0 64 64"><defs><mask id="mr-plan" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="37.8" cy="32" r="7.5" fill="#000"/></mask></defs><g mask="url(#mr-plan)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M6.5 17A8.5 8.5 0 1 1 23.5 17A8.5 8.5 0 1 1 6.5 17Z" stroke="currentColor"/><path d="M6.5 47A8.5 8.5 0 1 1 23.5 47A8.5 8.5 0 1 1 6.5 47Z" stroke="currentColor"/><path d="M22.1 21.7L56 44" stroke="currentColor"/><path d="M22.1 42.3L56 20" stroke="currentColor"/></g></g><g stroke="none"><circle cx="37.8" cy="32" r="5.5" fill="currentColor"/></g></symbol>
<symbol id="i-alert" viewBox="0 0 64 64"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M32 7L58 53H6Z" stroke="currentColor"/><path d="M32 24V36" stroke="currentColor"/></g><g stroke="none"><circle cx="32" cy="45" r="4" fill="currentColor"/></g></symbol>
<symbol id="i-server" viewBox="0 0 64 64"><defs><mask id="mr-server" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="20.5" cy="18.5" r="6" fill="#000"/><circle cx="20.5" cy="45.5" r="6.5" fill="#000"/></mask></defs><g mask="url(#mr-server)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M14 9H50A4 4 0 0 1 54 13V24A4 4 0 0 1 50 28H14A4 4 0 0 1 10 24V13A4 4 0 0 1 14 9Z" stroke="currentColor"/><path d="M14 36H50A4 4 0 0 1 54 40V51A4 4 0 0 1 50 55H14A4 4 0 0 1 10 51V40A4 4 0 0 1 14 36Z" stroke="currentColor"/><path d="M30 18.5H44" stroke="currentColor" opacity="0.42"/><path d="M30 45.5H44" stroke="currentColor" opacity="0.42"/></g></g><g stroke="none"><circle cx="20.5" cy="18.5" r="4" fill="currentColor"/><circle cx="20.5" cy="45.5" r="4.5" fill="currentColor"/></g></symbol>
<symbol id="i-theme" viewBox="0 0 24 24"><path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/></symbol>
<symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></symbol>
<symbol id="i-arrow" viewBox="0 0 24 24"><path d="M4 12h15M14 7l5 5-5 5"/></symbol>
<symbol id="i-info" viewBox="0 0 64 64"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M8 32A24 24 0 1 1 56 32A24 24 0 1 1 8 32Z" stroke="currentColor"/><path d="M32 30V45" stroke="currentColor"/></g><g stroke="none"><circle cx="32" cy="20" r="4.25" fill="currentColor"/></g></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></symbol>
<symbol id="i-trash" viewBox="0 0 64 64"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M16 20L19 57H45L48 20" stroke="currentColor"/><path d="M27 30V47" stroke="currentColor" opacity="0.42"/><path d="M37 30V47" stroke="currentColor" opacity="0.42"/></g><g stroke="none"><rect x="10" y="10" width="44" height="6" fill="currentColor"/></g></symbol>
</defs></svg>"##;

fn icon(id: &str) -> String {
    format!(r##"<svg class="ic" aria-hidden="true"><use href="#{id}"/></svg>"##)
}

/// The report's icon sprite: [`ICONS`] and the external kinds' icons
/// (`i-x-NAME`, [`crate::opengraph::pack::icon_symbols`]).
fn sprite() -> &'static str {
    static SPRITE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SPRITE.get_or_init(|| {
        let end = "</defs></svg>";
        let base = ICONS.strip_suffix(end).unwrap_or(ICONS);
        format!("{base}\n{}{end}", crate::opengraph::pack::icon_symbols())
    })
}

thread_local! {
    /// The kind table of the report being rendered ([`ExtKindsScope`]).
    static EXT_KINDS: std::cell::RefCell<Option<KindTable>> = const { std::cell::RefCell::new(None) };
}

/// The run's external kinds, for [`kind_label`] and [`kind_icon_id`] while
/// [`render_html`] runs (the rendering is on one thread). Outside it (Home's
/// overview from an event document), external kinds keep their kind name
/// and the generic icon.
struct ExtKindsScope(Option<KindTable>);

impl ExtKindsScope {
    fn enter(table: Option<&KindTable>) -> Self {
        ExtKindsScope(EXT_KINDS.with(|t| t.replace(table.cloned())))
    }
}

impl Drop for ExtKindsScope {
    fn drop(&mut self) {
        let previous = self.0.take();
        EXT_KINDS.with(|t| *t.borrow_mut() = previous);
    }
}

fn ext_node<R>(
    k: crate::kinds::ExtKind,
    f: impl FnOnce(&crate::opengraph::pack::NodeSem) -> Option<R>,
) -> Option<R> {
    EXT_KINDS.with(|t| t.borrow().as_ref().and_then(|t| t.node(k)).and_then(f))
}

/// A kind's name for readers: an external kind's label from its mapping
/// pack ("Entra role"), else the kind's own name. Not escaped.
fn kind_label(kind: NodeKind) -> std::borrow::Cow<'static, str> {
    let label = match kind {
        NodeKind::External(k) => ext_node(k, |n| {
            n.label
                .as_deref()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                // A pack's label is shown like an object name: no
                // direction overrides that reorder the text around it.
                .map(|l| crate::text::bidi_safe(l).into_owned())
        }),
        _ => None,
    };
    label.map_or(std::borrow::Cow::Borrowed(kind.as_str()), Into::into)
}

/// The plural of a pack's kind label: its last word's ("Entra service
/// principals", "SCCM security roles", "Entra policies").
fn plural_label(label: &str) -> String {
    let lower = label.to_ascii_lowercase();
    let vowel_y = ["ay", "ey", "iy", "oy", "uy"]
        .iter()
        .any(|v| lower.ends_with(v));
    if lower.ends_with('y') && !vowel_y {
        format!("{}ies", &label[..label.len() - 1])
    } else if ["s", "x", "z", "ch", "sh"]
        .iter()
        .any(|e| lower.ends_with(e))
    {
        format!("{label}es")
    } else {
        format!("{label}s")
    }
}

fn kind_icon(kind: NodeKind) -> String {
    icon(&kind_icon_id(kind))
}

/// The icon symbol for each kind of object (also used by the diagrams): an
/// external kind's pack icon when it names one of
/// [`crate::opengraph::pack::ICONS`], else the generic square.
fn kind_icon_id(kind: NodeKind) -> std::borrow::Cow<'static, str> {
    if let NodeKind::External(k) = kind {
        if let Some(id) = ext_node(k, |n| {
            n.icon
                .as_deref()
                .and_then(crate::opengraph::pack::icon_symbol_id)
        }) {
            return id.into();
        }
    }
    let id = match kind {
        NodeKind::User => "i-user",
        NodeKind::Group => "i-group",
        NodeKind::Computer => "i-computer",
        NodeKind::Domain => "i-domain",
        NodeKind::Ou | NodeKind::Container => "i-folder",
        NodeKind::Gpo => "i-policy",
        NodeKind::CertTemplate
        | NodeKind::EnterpriseCa
        | NodeKind::RootCa
        | NodeKind::AiaCa
        | NodeKind::NtAuthStore
        | NodeKind::IssuancePolicy => "i-cert",
        NodeKind::Base | NodeKind::External(_) => "i-object",
    };
    id.into()
}

/// `JDOE@CONTOSO.LOCAL` as the account name with its domain
/// muted (and a computer's FQDN after its host name); the full name stays in
/// the tooltip.
fn name_html_kind(full: &str, kind: Option<NodeKind>) -> String {
    let split = full
        .split_once('@')
        .map(|(n, d)| (n, format!("@{d}")))
        .or_else(|| {
            (kind == Some(NodeKind::Computer))
                .then(|| full.split_once('.'))
                .flatten()
                .map(|(n, d)| (n, format!(".{d}")))
        });
    match split {
        Some((name, rest)) if !name.is_empty() => format!(
            r#"<span class="nm" title="{}">{}<span class="dom">{}</span></span>"#,
            esc(full),
            esc(name),
            esc(&rest)
        ),
        _ => format!(r#"<span class="nm" title="{0}">{0}</span>"#, esc(full)),
    }
}

/// An object with its kind icon, as used in plan steps.
fn object_chip(name: &str, kind: NodeKind) -> String {
    format!(
        r#"<span class="objchip" data-kind="{}">{}{}</span>"#,
        esc(kind.as_str()),
        kind_icon(kind),
        name_html_kind(name, Some(kind))
    )
}

/// A small (i) beside a number or a label, with its definition on hover,
/// on focus and on a tap (`report.js` keeps it open on a tap). `id` names
/// the definition, so a screen reader reads it with the button.
fn tip(id: &str, term: &str, text: &str) -> String {
    format!(
        r#"<span class="tip"><button type="button" class="tip-btn" aria-label="About: {term}" aria-describedby="tip-{id}">{icon}</button><span class="tip-text" role="tooltip" id="tip-{id}">{text}</span></span>"#,
        term = esc(term),
        text = esc(text),
        icon = icon("i-info"),
    )
}

/// The ⓘ of the Environment tab's Tier Zero settings row.
pub const TIER_ZERO_SETTINGS_TIP: &str = "Settings files come from a script each server's admins run (see the docs at pathwarden.org). A file older than 90 days can confirm a weakness but can't show that one was fixed. On a domain controller, a setting that isn't set counts only when a current file gives the Windows build.";

/// The Environment tab's "Tier Zero settings" row: per domain, its
/// domain controllers with current settings (ESC9, ESC10), and per
/// Enterprise CA, its settings file (ESC6, ESC11). Empty when there is
/// neither.
fn tier_zero_settings_row(
    dcs: &[crate::dcsettings::Completeness],
    cas: &[crate::dcsettings::CaCompleteness],
) -> String {
    if dcs.is_empty() && cas.is_empty() {
        return String::new();
    }
    let (n, words) = crate::dcsettings::needing_words(dcs, cas);
    let mut h = format!(
        r#"<details class="row env" id="env-t0-settings"{open}><summary><span class="title">Tier Zero settings</span><span class="aside{warn}">{words}</span></summary><div class="body"><p class="muted">ESC6, ESC9, ESC10 and ESC11 need registry settings that only a settings file provides.{tip}</p>"#,
        open = if n > 0 { " open" } else { "" },
        warn = if n > 0 { " warn" } else { "" },
        words = esc(&words),
        tip = tip("t0-settings", "Tier Zero settings", TIER_ZERO_SETTINGS_TIP),
    );
    if !dcs.is_empty() {
        h.push_str("<h4>Domain controllers (ESC9, ESC10)</h4><table><thead><tr><th>Domain</th><th>Domain controllers with current settings</th><th>Still needed</th></tr></thead><tbody>");
        for d in dcs {
            let _ = write!(
                h,
                "<tr><td>{}</td><td{}>{} of {}</td><td>{}</td></tr>",
                esc(&d.domain),
                if d.needing() > 0 {
                    r#" class="warn""#
                } else {
                    ""
                },
                d.current(),
                d.domain_controllers,
                esc(&d.still_needed()),
            );
        }
        h.push_str("</tbody></table>");
    }
    if !cas.is_empty() {
        h.push_str("<h4>Certification authorities (ESC6, ESC11)</h4><table><thead><tr><th>Enterprise CA</th><th>Settings</th><th>Still needed</th></tr></thead><tbody>");
        for c in cas {
            let _ = write!(
                h,
                "<tr><td>{}</td><td{}>{}</td><td>{}</td></tr>",
                esc(&c.ca),
                if c.needs_file() {
                    r#" class="warn""#
                } else {
                    ""
                },
                esc(&c.settings_words()),
                esc(&c.still_needed()),
            );
        }
        h.push_str("</tbody></table>");
    }
    h.push_str("</div></details>");
    h
}

/// The Environment tab's "Management agents read on Tier Zero hosts" row:
/// per Tier Zero host, its settings file and the agents it shows,
/// in the words `pathwarden posture` prints. Empty when the run read no
/// Tier Zero settings file.
fn host_agents_row(c: &crate::hostprobe::Completeness) -> String {
    use crate::hostprobe::{self, Status};
    if c.is_empty() {
        return String::new();
    }
    let short = c.short();
    let mut h = format!(
        r#"<details class="row env" id="env-t0-agents"{open}><summary><span class="title">{title}</span><span class="aside{warn}">{count}</span></summary><div class="body"><p class="muted">{intro}{tip}</p><table><thead><tr><th>Tier Zero computer</th><th>Settings file</th><th>Agents found</th></tr></thead><tbody>"#,
        open = if short { " open" } else { "" },
        warn = if short { " warn" } else { "" },
        title = esc(hostprobe::TITLE),
        count = esc(&c.count_words()),
        intro = esc(hostprobe::INTRO),
        tip = tip("t0-agents", "Management agents", hostprobe::TIP),
    );
    let (shown, left) = c.shown();
    for a in shown {
        let _ = write!(
            h,
            "<tr><td>{}</td><td{}>{}</td><td>{}</td></tr>",
            esc(&a.host),
            if a.status == Status::Read {
                ""
            } else {
                r#" class="warn""#
            },
            esc(&a.read_words()),
            esc(&a.found_words()),
        );
    }
    if let Some(more) = hostprobe::more_words(left) {
        let _ = write!(
            h,
            r#"<tr><td colspan="3" class="muted">{}</td></tr>"#,
            esc(&more)
        );
    }
    h.push_str("</tbody></table></div></details>");
    h
}

/// How a count moved since the last run ([`crate::since`]'s comparison),
/// where lower is better: "▼ 120" in green, "▲ 2" in red, "no change"
/// muted. The arrow is decoration; the words say which way.
fn delta_count(d: Delta) -> String {
    match d.after.cmp(&d.before) {
        std::cmp::Ordering::Equal => r#"<span class="delta same">no change</span>"#.to_string(),
        std::cmp::Ordering::Less => format!(
            r#"<span class="delta good"><span aria-hidden="true">&#9660;</span><span class="vh">down</span> {}</span>"#,
            num(d.before - d.after)
        ),
        std::cmp::Ordering::Greater => format!(
            r#"<span class="delta bad"><span aria-hidden="true">&#9650;</span><span class="vh">up</span> {}</span>"#,
            num(d.after - d.before)
        ),
    }
}

/// [`delta_count`] for a share where higher is better, in points.
fn delta_points(s: Share) -> String {
    let d = s.after - s.before;
    if d.abs() < 0.005 {
        r#"<span class="delta same">no change</span>"#.to_string()
    } else if d > 0.0 {
        format!(
            r#"<span class="delta good"><span aria-hidden="true">&#9650;</span><span class="vh">up</span> {}</span>"#,
            crate::posture::points(d)
        )
    } else {
        format!(
            r#"<span class="delta bad"><span aria-hidden="true">&#9660;</span><span class="vh">down</span> {}</span>"#,
            crate::posture::points(-d)
        )
    }
}

/// A status that changed since the last run, beside its badge: "▲ was
/// High" in red when it got worse, "▼ was Critical" in green when better.
fn grade_was(g: crate::since::GradeChange) -> String {
    let (class, mark, word) = if g.after > g.before {
        ("bad", "&#9650;", "worse")
    } else {
        ("good", "&#9660;", "better")
    };
    format!(
        r#" <span class="delta {class} was"><span aria-hidden="true">{mark}</span><span class="vh">{word},</span> was {}</span>"#,
        g.before.as_str()
    )
}

/// [`grade_was`] after the severities set in Settings changed: the status
/// may have moved with them, so neither red nor green.
fn grade_was_neutral(g: crate::since::GradeChange) -> String {
    format!(
        r#" <span class="delta was" title="Rule severities changed in Settings since the last run.">was {}</span>"#,
        g.before.as_str()
    )
}

/// A delta followed by "since the last run".
fn since_last(delta: String) -> String {
    format!(r#"<span class="since">{delta} <span class="muted">since the last run</span></span>"#)
}

/// A time in the report: US style in UTC, labeled ("Oct 9, 2026, 9:29 PM
/// UTC"), which `report.js` shows in the reader's local time, the UTC
/// value as its tooltip.
fn time_html(t: i64) -> String {
    let utc = crate::time::format_utc(t);
    format!(
        r#"<time data-unix="{t}" datetime="{}" title="{utc}">{utc}</time>"#,
        crate::time::format_rfc3339(t)
    )
}

/// A collection time, as its file names say it
/// ([`crate::time::format_collected`]): not moved to the reader's zone.
fn collected_html(t: i64) -> String {
    format!(
        r#"<span title="{}">{}</span>"#,
        crate::time::COLLECTED_CLOCK,
        crate::time::format_collected(t)
    )
}

/// "Oct 19" from Unix time (UTC), for the trend's axis and "path on Oct
/// 19" (`runs show` says it the same).
pub fn short_date(t: i64) -> String {
    crate::time::format_month_day(t)
}

/// "Oct 22, 2026": the local day of an accepted risk's RFC 3339 time, a
/// review date as typed ([`crate::time::day_of`]).
fn stamp_date(at: &str) -> String {
    crate::time::day_of(at)
}

/// "<b>NORTH\ned</b> on <b>WS02</b>, Oct 22, 2026" (escaped): who, where
/// and when, with the parts that are known; "an unknown user" when the
/// computer is known but the user isn't. `None` when nothing is.
fn stamp_html(by: &Option<String>, on: &Option<String>, at: &Option<String>) -> Option<String> {
    let mut out = String::new();
    match (by, on) {
        (Some(b), _) => {
            let _ = write!(out, "by <b>{}</b>", esc(b));
        }
        (None, Some(_)) => out.push_str("by an unknown user"),
        (None, None) => {}
    }
    if let Some(o) = on {
        let _ = write!(out, " on <b>{}</b>", esc(o));
    }
    if let Some(a) = at {
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str(&esc(&stamp_date(a)));
    }
    (!out.is_empty()).then_some(out)
}

/// An accepted finding's fact, across the whole fact list: the reason, who
/// accepted it, where and when, the last change, what it covers and its
/// review date, then the notes added since.
fn accepted_fact(reason: &str, a: Option<&crate::config::Acceptance>) -> String {
    let mut h = format!(
        r#"<div class="ar-wide"><dt>Accepted risk</dt><dd><p class="ar-reason">{}</p>"#,
        esc(reason)
    );
    if let Some(a) = a {
        let sep = r#"<span class="sep">·</span>"#;
        let mut parts = Vec::new();
        match stamp_html(&a.accepted_by, &a.accepted_on, &a.accepted_at) {
            Some(w) => parts.push(format!("Accepted {w}")),
            None => parts.push(
                r#"<span class="ar-unknown">Who accepted it and when wasn't recorded</span>"#
                    .to_string(),
            ),
        }
        if let Some(w) = stamp_html(&a.changed_by, &a.changed_on, &a.changed_at) {
            parts.push(format!("changed {w}"));
        }
        if a.whole_rule {
            parts.push("for every finding of its rule".to_string());
        }
        if let Some(d) = &a.expires {
            parts.push(format!("review by {}", esc(&stamp_date(d))));
        }
        let _ = write!(h, r#"<p class="ar-who">{}</p>"#, parts.join(sep));
        if !a.notes.is_empty() {
            h.push_str(r#"<ol class="ar-notes">"#);
            for n in &a.notes {
                let meta: Vec<String> = [
                    n.at.as_deref().map(|t| esc(&stamp_date(t))),
                    stamp_html(&n.by, &n.on, &None)
                        .map(|w| w.trim_start_matches("by ").to_string()),
                ]
                .into_iter()
                .flatten()
                .collect();
                let _ = write!(
                    h,
                    r#"<li>{}<span class="ar-text">{}</span></li>"#,
                    if meta.is_empty() {
                        String::new()
                    } else {
                        format!(r#"<span class="ar-meta">{}</span>"#, meta.join(" · "))
                    },
                    esc(&n.text)
                );
            }
            h.push_str("</ol>");
        }
    }
    h.push_str("</dd></div>");
    h
}

/// "Accepted · NORTH\ned" on an accepted finding's row ("Accepted" when
/// who accepted it isn't known).
fn accepted_tag(f: &Finding) -> String {
    if f.suppressed.is_none() {
        return String::new();
    }
    let who = f.accepted.as_ref().and_then(|a| a.accepted_by.as_deref());
    format!(
        r#"<span class="ar-tag">Accepted{}</span>"#,
        who.map(|w| format!(" · {}", esc(w))).unwrap_or_default()
    )
}

/// The chips of a finding's records on its row ("RITM0001234 · Open"),
/// as text ([`crate::action_log::chip`]).
fn action_chips(f: &Finding) -> String {
    let chips: String = f
        .actions
        .iter()
        .flat_map(|a| &a.records)
        .map(|r| {
            format!(
                r#"<span class="ac-chip{}">{}</span>"#,
                if r.record.open { "" } else { " closed" },
                esc(&crate::action_log::chip(&r.record, false))
            )
        })
        .collect();
    if chips.is_empty() {
        chips
    } else {
        format!(r#"<span class="ac-rowchips">{chips}</span>"#)
    }
}

/// The "Fixed, ticket still open" card: each fixed finding that still
/// has an open record, with its records' chips and the day it was fixed
/// (in the reader's time zone, as the page's other dates), newest fix
/// first ([`crate::action_log::fixed_open`]). Nothing when there are none.
fn fixed_open_card(h: &mut String, list: &[crate::action_log::FixedFinding]) {
    if list.is_empty() {
        return;
    }
    h.push_str(
        r#"<section class="card fixed-open" aria-labelledby="fo-h"><h3 id="fo-h">Fixed, ticket still open</h3><p class="muted small">These findings are fixed, but their tickets are still open, so they can be closed.</p><ul>"#,
    );
    for f in list {
        let chips: String = f
            .records
            .iter()
            .map(|r| {
                format!(
                    r#"<span class="ac-chip">{}</span>"#,
                    esc(&crate::action_log::chip(&r.record, false))
                )
            })
            .collect();
        let _ = write!(
            h,
            r#"<li><span class="t"><span class="rule">{}</span>{}</span><span class="fo-chips">{chips}</span><span class="when">Fixed <time data-unix="{}" data-fmt="day">{}</time></span></li>"#,
            esc(&f.rule),
            esc(&f.title),
            f.fixed_at,
            esc(&short_date(f.fixed_at))
        );
    }
    h.push_str("</ul></section>");
}

/// A finding's Activity list, newest first, as text: "Opened RITM0001234
/// · NORTH\a.admin, SECOPS-WS02, Nov 18, 2026, 2:02 PM". Empty when
/// no action ran on it.
fn action_activity(f: &Finding) -> String {
    let Some(a) = f.actions.as_ref().filter(|a| !a.activity.is_empty()) else {
        return String::new();
    };
    let mut h = String::from(r#"<div class="ac-static"><h4>Activity</h4><ul class="ac-activity">"#);
    for e in &a.activity {
        let _ = write!(
            h,
            r#"<li{}>{} <span class="ac-who">&middot; {}</span></li>"#,
            if e.ok { "" } else { r#" class="ac-failed""# },
            esc(&e.summary()),
            esc(&e.who_when())
        );
    }
    if a.activity_count > a.activity.len() {
        let _ = write!(
            h,
            r#"<li class="ac-who">and {} earlier</li>"#,
            num(a.activity_count - a.activity.len())
        );
    }
    h.push_str("</ul></div>");
    h
}

/// [`short_date`] of `t`, with the time ("Oct 19, 9:12 AM") when `other`
/// is on the same day (UTC), and its seconds ("Oct 19, 9:12:05 AM") when in
/// the same minute, so two runs of one day read apart.
fn date_beside(t: i64, other: i64) -> String {
    use crate::time::{format_clock, format_clock_seconds, format_iso_date};
    if t.div_euclid(60) == other.div_euclid(60) {
        format!("{}, {}", short_date(t), format_clock_seconds(t))
    } else if format_iso_date(t) == format_iso_date(other) {
        format!("{}, {}", short_date(t), format_clock(t))
    } else {
        short_date(t)
    }
}

/// The form `report.js` and `app.js` show [`date_beside`]'s time in, in
/// the reader's zone; `year` adds the year ([`with_year`]).
fn date_beside_form(t: i64, other: i64, year: bool) -> &'static str {
    use crate::time::format_iso_date;
    match (
        t.div_euclid(60) == other.div_euclid(60),
        format_iso_date(t) == format_iso_date(other),
        year,
    ) {
        (true, _, false) => "dayclocksec",
        (true, _, true) => "fullsec",
        (false, true, false) => "dayclock",
        (false, true, true) => "full",
        (false, false, false) => "day",
        (false, false, true) => "date",
    }
}

/// [`date_beside`] as HTML (in SVG text, `svg`: a `tspan`) that the page's
/// script shows in the reader's time zone, labeled UTC until it does.
fn date_beside_html(t: i64, other: i64, year: bool, svg: bool) -> String {
    let text = date_beside(t, other);
    let text = if year { with_year(&text, t) } else { text };
    let form = date_beside_form(t, other, year);
    // A day alone needs no zone.
    let zone = if matches!(form, "day" | "date") {
        ""
    } else {
        " UTC"
    };
    let tag = if svg { "tspan" } else { "time" };
    format!(
        r#"<{tag} data-unix="{t}" data-fmt="{form}">{}{zone}</{tag}>"#,
        esc(&text)
    )
}

/// "Oct 13" as "Oct 13, 2026" (the year of `t`), and "Oct 13, 9:12 AM" as
/// "Oct 13, 2026, 9:12 AM".
fn with_year(date: &str, t: i64) -> String {
    let iso = crate::time::format_iso_date(t);
    let year = &iso[..4];
    match date.split_once(", ") {
        Some((day, time)) => format!("{day}, {year}, {time}"),
        None => format!("{date}, {year}"),
    }
}

/// A tick label: 500, 5k, 2.5k, 1.2M.
fn compact(v: f64) -> String {
    if v >= 1_000_000.0 {
        let m = v / 1_000_000.0;
        if m.fract() == 0.0 {
            format!("{m:.0}M")
        } else {
            format!("{m:.1}M")
        }
    } else if v >= 1_000.0 {
        let k = v / 1_000.0;
        if k.fract() == 0.0 {
            format!("{k:.0}k")
        } else {
            format!("{k:.1}k")
        }
    } else {
        format!("{v:.0}")
    }
}

/// The smallest 1, 2 or 5 times a power of ten that is at least `x` (1 at
/// least): the trend's tick step for half its highest value, so the top
/// tick (two steps) is at or above every value.
fn nice_step(x: f64) -> f64 {
    if x <= 1.0 {
        return 1.0;
    }
    let p = 10f64.powf(x.log10().floor());
    [1.0, 2.0, 5.0, 10.0]
        .into_iter()
        .map(|m| m * p)
        .find(|s| *s >= x)
        .unwrap_or(10.0 * p)
}

/// The hero's right side: accounts with an attack path to Tier Zero over the
/// last runs (`points`, oldest first, this run last), on a 0 / step / 2
/// step scale whose top tick is at or above the highest value, with the
/// first and last values written out. The accent colour, not a status
/// colour: the line is context, the badge is the status.
fn trend_svg(points: &[(i64, usize)]) -> String {
    let (Some(first), Some(last)) = (points.first(), points.last()) else {
        return String::new();
    };
    let max = points.iter().map(|p| p.1).max().unwrap_or(0) as f64;
    let step = nice_step(max / 2.0);
    let top = max.max(2.0 * step) * 1.1;
    let (x0, x1, base, height) = (52.0, 552.0, 146.0, 124.0);
    let x = |i: usize| {
        if points.len() == 1 {
            x1
        } else {
            x0 + (x1 - x0) * i as f64 / (points.len() - 1) as f64
        }
    };
    let y = |v: f64| base - height * v / top;
    let mut s = String::new();
    for k in 0..3 {
        let v = step * k as f64;
        let _ = write!(
            s,
            r#"<line class="grid" x1="{x0}" x2="{x1}" y1="{yy:.1}" y2="{yy:.1}"/><text class="tick" x="44" y="{ty:.1}">{label}</text>"#,
            yy = y(v),
            ty = y(v) + 5.0,
            label = compact(v),
        );
    }
    let line: Vec<String> = points
        .iter()
        .enumerate()
        .map(|(i, p)| format!("{:.1},{:.1}", x(i), y(p.1 as f64)))
        .collect();
    let _ = write!(
        s,
        r#"<polygon class="area" points="{x0:.1},{base:.1} {} {:.1},{base:.1}"/><polyline class="line" points="{}"/>"#,
        line.join(" "),
        x(points.len() - 1),
        line.join(" "),
    );
    for (i, p) in points.iter().enumerate() {
        let _ = write!(
            s,
            r#"<circle class="dot" cx="{:.1}" cy="{:.1}" r="4"/>"#,
            x(i),
            y(p.1 as f64)
        );
    }
    let n = points.len() - 1;
    if n > 0 {
        let _ = write!(
            s,
            r#"<text class="val" x="{:.1}" y="{:.1}">{}</text>"#,
            x(0),
            y(first.1 as f64) - 9.0,
            num(first.1)
        );
    }
    let _ = write!(
        s,
        r#"<text class="val end" x="{:.1}" y="{:.1}">{}</text><text class="date" x="{x0:.1}" y="166">{}</text><text class="date end" x="{x1:.1}" y="166">{}</text>"#,
        x(n),
        y(last.1 as f64) - 9.0,
        num(last.1),
        date_beside_html(first.0, last.0, false, true),
        date_beside_html(last.0, first.0, false, true),
    );
    let label = format!(
        "From {} on {} to {} on {}, over {} runs",
        num(first.1),
        date_beside(first.0, last.0),
        num(last.1),
        date_beside(last.0, first.0),
        points.len()
    );
    format!(
        r#"<div class="hero-trend"><p class="trend-title">Accounts with an attack path to Tier Zero</p><p class="trend-sub">last {} runs &middot; lower is better</p><svg class="trend" viewBox="0 0 560 172" role="img" aria-label="{}">{s}</svg></div>"#,
        points.len(),
        esc(&label)
    )
}

/// The Overview's hero: the accounts with an attack path to Tier Zero and
/// how that moved since the last run; under them its status badge (why, on
/// the badge) with the critical findings, their share of active accounts
/// and the change since the first run in the trend; beside them, with a
/// history, the count over the last runs.
fn hero(r: &OverviewInput, earlier: &[&HistoryPoint], since: Option<&SinceLast>) -> String {
    let t0 = &r.posture.tier_zero;
    let class = t0.exposure_grade.css_class();
    let hl = r.posture.headline();
    // The last word keeps the (i) beside it when the line wraps.
    let label = if t0.exposed == 1 {
        "account has an attack path to Tier"
    } else {
        "accounts have an attack path to Tier"
    };
    let definition = format!(
        "Enabled users and computers outside Tier Zero with a full path to it. {TAKEOVER_WORDS}"
    );
    // Counts measured another way (an older exposure basis) aren't
    // compared; the trend leaves those runs out too.
    // The change opens What changed at the accounts behind it, when it
    // lists them.
    let opens = since.is_some_and(|s| change_anchored(r, s));
    let change = match since.map(|s| s.tier_zero) {
        None => String::new(),
        Some(Some(d)) if opens => format!(
            r##"<p class="hero-change"><a class="delta-link" href="#{}" title="Show which accounts changed">{}</a></p>"##,
            accounts::CHANGE_ID,
            since_last(delta_count(d))
        ),
        Some(Some(d)) => format!(
            r#"<p class="hero-change">{}</p>"#,
            since_last(delta_count(d))
        ),
        Some(None) => r#"<p class="hero-change muted">Not compared: the last run counted these with an older method.</p>"#.to_string(),
    };
    let mut points: Vec<(i64, usize)> = earlier
        .iter()
        .rev()
        .take(TREND_RUNS - 1)
        .rev()
        .map(|p| (p.at, p.tier_zero_exposed))
        .collect();
    let trend = if points.is_empty() {
        String::new()
    } else {
        points.push((this_at(r), t0.exposed));
        trend_svg(&points)
    };
    // Under the count, three facts side by side: the status and its
    // critical findings, the share of active accounts, and how the count
    // moved since the first run in the trend.
    let criticals = match r.posture.findings.critical {
        0 => r#"<span class="hf-label">no Critical findings</span>"#.to_string(),
        n => format!(
            r##"<a class="hf-label hero-crit" href="#findings" data-only="critical" title="Show the Critical findings">{} Critical finding{}</a>"##,
            num(n),
            if n == 1 { "" } else { "s" }
        ),
    };
    let mut facts = format!(
        r#"<div class="hero-facts"><div><span class="hf-num"><span class="grade-badge" title="{reason}">{grade}</span>{why}</span>{criticals}</div>"#,
        // Why it has that status, on the badge and in its (i), which a
        // keyboard reaches: the hero itself is counts.
        reason = esc(&t0.reason.text),
        why = tip("t0status", "Why this status", &t0.reason.text),
        grade = t0.exposure_grade.as_str(),
    );
    // "39.9% of 22,489 active accounts": the share set large.
    if let Some((share, of)) = hl.share.split_once(' ') {
        let _ = write!(
            facts,
            r#"<div><span class="hf-num">{}{}</span><span class="hf-label">{}</span></div>"#,
            esc(share),
            tip(
                "t0share",
                "Share of active accounts",
                &format!("{} Lower is better.", share_words(r.posture.activity_days))
            ),
            esc(of)
        );
    }
    // With two runs the first is the last run, which the line under the
    // count already compares with.
    if let Some(&(at, first)) = points.first().filter(|_| points.len() > 2) {
        if first != t0.exposed {
            let fewer = t0.exposed < first;
            let _ = write!(
                facts,
                r#"<div><span class="hf-num"><span class="hf-arrow {class}" aria-hidden="true">{arrow}</span><span class="vh">{word} </span>{n}{tip}</span><span class="hf-label">since {date} (from {was})</span></div>"#,
                class = if fewer { "good" } else { "bad" },
                arrow = if fewer { "&#9660;" } else { "&#9650;" },
                word = if fewer { "down" } else { "up" },
                n = num(first.abs_diff(t0.exposed)),
                tip = tip(
                    "t0since",
                    "Change since the first run",
                    &format!(
                        "{} {} accounts with an attack path to Tier Zero than on {}, the first run in the chart: {} then, {} now.",
                        num(first.abs_diff(t0.exposed)),
                        if fewer { "fewer" } else { "more" },
                        short_date(at),
                        num(first),
                        num(t0.exposed)
                    )
                ),
                date = short_date(at),
                was = num(first),
            );
        }
    }
    facts.push_str("</div>");
    format!(
        r#"<div class="hero card{solo}"><div class="hero-status {class}" role="group" aria-label="Tier Zero status: {grade}"><p class="hero-line"><span class="hero-count">{count}</span><span class="hero-count-label">{label} <span class="nowrap">Zero{tip}</span></span></p>{change}{facts}</div>{trend}</div>"#,
        solo = if trend.is_empty() { " solo" } else { "" },
        grade = t0.exposure_grade.as_str(),
        count = num(t0.exposed),
        tip = tip(
            "takeover",
            "Accounts with an attack path to Tier Zero",
            &definition
        ),
    )
}

/// Whether What changed opens to the accounts that now reach Tier Zero and
/// those that no longer do (its [`CHANGE_ANCHOR`]), as [`what_changed`]
/// draws it: the last run is in the history, the accounts were compared,
/// and the Tier Zero line or the same-total row is there to open. The
/// hero's change links there only then.
fn change_anchored(r: &OverviewInput, s: &SinceLast) -> bool {
    if !r.history.earlier.iter().any(|p| p.run_id == s.previous_run) {
        return false;
    }
    if !matches!(
        accounts::change_row(r.lists, s),
        Some(accounts::ChangeRow::Lists { .. })
    ) {
        return false;
    }
    s.full_lines().iter().any(|l| l.tier_zero) || accounts::same_total(r.lists, s).is_some()
}

/// When the report's data is from: the run it stands for, or the time it
/// was made.
fn this_at(r: &OverviewInput) -> i64 {
    r.history.this_run.as_ref().map_or(r.generated_at, |p| p.at)
}

/// "What changed since Oct 12": the lines `pathwarden history` prints
/// ([`SinceLast::full_lines`], names whole), in its order, each with what
/// it names: one per line, a severity dot for the word, the same name
/// twice as "×2". The commands `history` adds are for the terminal, so
/// they are left out. Text from settings and the state is escaped.
fn what_changed(r: &OverviewInput, s: &SinceLast, previous_at: i64) -> String {
    let mut b = format!(
        r#"<div class="ov-since" role="region" aria-labelledby="ov-since-h"><h3 class="sub" id="ov-since-h">What changed since {}{}</h3>"#,
        date_beside_html(previous_at, this_at(r), true, false),
        tip(
            "since",
            "What changed",
            "Compared with the last run of this environment that collected sessions and local groups the same way."
        ),
    );
    // One table, a row per change, what went the wrong way first: the
    // count, what changed, and before -> now lined up. A line that names
    // findings opens to list them.
    let mut lines = s.full_lines();
    lines.sort_by_key(|l| match l.tone {
        Tone::Worse => 0,
        Tone::Better => 1,
        Tone::Same => 2,
    });
    b.push_str(r#"<table class="wc-table"><thead class="vh"><tr><th>Change</th><th>What</th><th>Before → now</th></tr></thead><tbody>"#);
    // The Tier Zero line opens to the accounts that now reach it and those
    // that no longer do (or says why they weren't compared). As many came
    // as went: a row of its own says so, under "No change".
    let has_t0 = lines.iter().any(|l| l.tier_zero);
    let t0_row = accounts::change_row(r.lists, s);
    let mut lists_shown = false;
    let mut same_total = if !has_t0 {
        accounts::same_total(r.lists, s).and_then(|sentence| match &t0_row {
            Some(accounts::ChangeRow::Lists { body, .. }) => Some(format!(
                r#"<tr class="same"><td class="wc-chg"><span class="mark" aria-hidden="true">&#8226;</span></td><td class="wc-what"><details class="wc-more wc-accts" id="{}"><summary><span class="wc-text">{}</span></summary>{body}</details></td><td class="wc-ba"></td></tr>"#,
                accounts::CHANGE_ID,
                esc(&sentence),
            )),
            _ => None,
        })
    } else {
        None
    };
    for (i, l) in lines.iter().enumerate() {
        let (class, mark, word) = tone_mark(l.tone);
        let (count, what, before_after) = split_change(&l.text);
        // What is new since the last run opens the Findings tab filtered
        // to it, when the report has the Introduced filter.
        let text = if l.introduced && r.introduced.is_some_and(|i| i.has_earlier) {
            format!(
                r##"<a class="intro-link" href="#introduced-last" title="Show only what is new since the last run">{}</a>"##,
                esc(&what)
            )
        } else {
            esc(&what)
        };
        // A row that names things opens to list them; closed, it shows the
        // first in brief and how many more. New paths and members are named
        // in full (who gained what, and the step that cuts it).
        let total: usize = count.replace(',', "").parse().unwrap_or(0);
        let named = r
            .introduced
            .map(|i| new_in_zone(i, &what))
            .filter(|(_, list)| !list.is_empty());
        let detail = match named {
            Some((first, list)) => Some((first, list)),
            None if !l.items.is_empty() => {
                let mut list = String::new();
                let mut i = 0;
                while i < l.items.len() {
                    let same = l.items[i..]
                        .iter()
                        .take_while(|x| **x == l.items[i])
                        .count();
                    let times = if same > 1 {
                        format!(r#" <span class="times">&times;{same}</span>"#)
                    } else {
                        String::new()
                    };
                    let _ = write!(list, "<li>{}{times}</li>", since_item(&l.items[i]));
                    i += same;
                }
                Some((since_item(&l.items[0]), list))
            }
            None => None,
        };
        let is_t0 = l.tier_zero;
        let what = match (&t0_row, detail) {
            (Some(accounts::ChangeRow::Lists { brief, body }), _) if is_t0 => {
                lists_shown = true;
                format!(
                    r#"<details class="wc-more wc-accts" id="{}"><summary><span class="wc-text">{text}</span><span class="wc-brief">{brief}</span></summary>{body}</details>"#,
                    accounts::CHANGE_ID
                )
            }
            (Some(accounts::ChangeRow::Why(why)), _) if is_t0 => {
                format!(r#"{text}<p class="muted small acc-why">{}</p>"#, esc(why))
            }
            (_, Some((first, list))) => {
                let more = if total > 1 {
                    format!(
                        r#" <span class="wc-more-n">+{} more</span>"#,
                        num(total - 1)
                    )
                } else {
                    String::new()
                };
                format!(
                    r#"<details class="wc-more"><summary><span class="wc-text">{text}</span><span class="wc-brief">{first}{more}</span></summary><ul class="items">{list}</ul></details>"#
                )
            }
            (_, None) => text,
        };
        let _ = write!(
            b,
            r#"<tr class="{class}"><td class="wc-chg"><span class="mark" aria-hidden="true">{mark}</span><span class="vh">{word}</span>{}</td><td class="wc-what">{what}</td><td class="wc-ba">{}</td></tr>"#,
            esc(count),
            esc(before_after),
        );
        // Right under "No change".
        if i == 0 && l.tone == Tone::Same {
            if let Some(row) = same_total.take() {
                b.push_str(&row);
                lists_shown = true;
            }
        }
    }
    if let Some(row) = same_total.take() {
        b.push_str(&row);
        lists_shown = true;
    }
    b.push_str("</tbody></table>");
    if lists_shown {
        if let Some(data) = accounts::change_data(r.lists, s) {
            b.push_str(&data);
        }
    }
    // Data no run recorded: the counts compare, the findings can't.
    if s.findings_unknown {
        b.push_str(r#"<p class="muted small since-note">The last run didn't keep its findings, so only the counts are compared.</p>"#);
    }
    b.push_str("</div>");
    b
}

/// A What changed line's class, its mark and the word the mark stands for
/// (read out, not shown).
fn tone_mark(t: Tone) -> (&'static str, &'static str, &'static str) {
    match t {
        Tone::Worse => ("worse", "&#9650;", "Worse: "),
        Tone::Better => ("better", "&#9660;", "Better: "),
        Tone::Same => ("same", "&#8226;", ""),
    }
}

/// A What changed count line in its table's three columns: the leading
/// count ("47"), what changed ("fewer accounts with an attack path to Tier Zero")
/// and the before and after ("9,022 → 8,975"), when the line has them.
fn split_change(text: &str) -> (&str, String, &str) {
    let n = text
        .find(|c: char| !(c.is_ascii_digit() || c == ','))
        .unwrap_or(text.len());
    let (count, rest) = if n > 0 && text[n..].starts_with(' ') {
        (&text[..n], &text[n + 1..])
    } else {
        ("", text)
    };
    if let Some(open) = rest.find(" (") {
        if let Some(close) = rest[open..].find(')').map(|c| open + c) {
            let inner = &rest[open + 2..close];
            if inner.contains('→') {
                return (
                    count,
                    format!("{}{}", &rest[..open], &rest[close + 1..]),
                    inner,
                );
            }
        }
    }
    (count, rest.to_string(), "")
}

/// The new paths or members a What changed line counts ("new path into
/// Tier Zero", "new members of R01 servers, 1 back"), named in full, the
/// last run's only: the first in brief, and the list. Empty when the line
/// is about something else or nothing was named.
fn new_in_zone(i: &crate::introduced::ForReport, what: &str) -> (String, String) {
    let at_last = |at: i64| i.has_earlier && at == i.latest;
    // The longest zone name that ends the words, so "Tier Zero servers"
    // isn't taken for Tier Zero.
    let zone_of = |zones: &mut dyn Iterator<Item = &String>, link: &[&str]| {
        zones
            .filter(|z| {
                link.iter().any(|w| {
                    what.contains(&format!("{w} {z},")) || what.ends_with(&format!("{w} {z}"))
                })
            })
            .max_by_key(|z| z.len())
            .cloned()
    };
    let (mut first, mut list) = (String::new(), String::new());
    let back = |b: bool, label: &str| {
        if b {
            format!(r#" <span class="muted">{}</span>"#, esc(label))
        } else {
            String::new()
        }
    };
    if what.contains(" path") {
        let Some(zone) = zone_of(&mut i.paths.iter().map(|(z, _)| z), &["into"]) else {
            return (first, list);
        };
        for (_, p) in i.paths.iter().filter(|(z, p)| *z == zone && at_last(p.at)) {
            let Some(n) = &p.named else { continue };
            let path = format!(
                r#"{} <span class="edge">{}</span> {}"#,
                object_chip(&n.from, n.from_kind),
                esc(&n.edge),
                object_chip(&n.to, n.to_kind)
            );
            if first.is_empty() {
                first = format!(
                    r#"{} <span class="edge">{}</span> {}"#,
                    short_name(&n.from, n.from_kind),
                    esc(&n.edge),
                    short_name(&n.to, n.to_kind)
                );
            }
            let step = match n.cut {
                Some(c) => format!(
                    r##" <a class="steplink" href="#{}">{}</a>"##,
                    c.step().map_or("plan".to_string(), |n| format!("step-{n}")),
                    esc(&c.words())
                ),
                None => r#" <span class="muted">No step cuts it</span>"#.to_string(),
            };
            let _ = write!(
                list,
                r#"<li class="wc-path">{path}{}{step}</li>"#,
                back(p.back, &p.label)
            );
        }
    } else if what.contains(" member") {
        let Some(zone) = zone_of(&mut i.members.iter().map(|(z, _)| z), &["of", "in"]) else {
            return (first, list);
        };
        for (_, m) in i
            .members
            .iter()
            .filter(|(z, m)| *z == zone && at_last(m.at))
        {
            let Some(n) = &m.named else { continue };
            if first.is_empty() {
                first = short_name(&n.name, n.kind);
            }
            let via = n
                .via
                .as_ref()
                .map(|g| {
                    format!(
                        r#" <span class="muted">as a member of</span> {}"#,
                        object_chip(g, NodeKind::Group)
                    )
                })
                .unwrap_or_default();
            let _ = write!(
                list,
                r#"<li class="wc-path">{} <span class="edge">joined</span>{via}{}</li>"#,
                object_chip(&n.name, n.kind),
                back(m.back, &m.label)
            );
        }
    }
    (first, list)
}

/// A finding What changed names, "High PW-004 Tier Zero account …": the
/// severity as its dot, the rule ID set apart. Anything else as it is.
fn since_item(item: &str) -> String {
    let sevs = ["critical", "high", "medium", "low", "info"];
    let mut parts = item.splitn(3, ' ');
    if let (Some(word), Some(rule), rest) = (parts.next(), parts.next(), parts.next()) {
        let sev = word.to_ascii_lowercase();
        if sevs.contains(&sev.as_str()) && rule.starts_with("PW-") {
            return format!(
                r#"<span class="dot {sev}" role="img" aria-label="{word}" title="{word}"></span><span class="rid">{}</span>{}"#,
                esc(rule),
                rest.map(|t| format!(" {}", esc(t))).unwrap_or_default()
            );
        }
    }
    esc(item)
}

fn panel_open(h: &mut String, id: &str, title: &str) {
    let _ = write!(
        h,
        r#"<section id="{id}" class="panel" role="tabpanel" aria-labelledby="tab-{id}" tabindex="-1"><h2 class="panel-title">{title}</h2>"#
    );
}

// ---------------------------------------------------------------- Overview

/// The note that some domains had no logon times, so every enabled account
/// there counted ("logon times not collected for X: all enabled accounts
/// counted"), when any did.
pub fn activity_note(p: &Posture) -> Option<String> {
    (!p.activity_unknown_domains.is_empty()).then(|| {
        format!(
            "Sign-in times not collected for {}: all enabled accounts counted.",
            p.activity_unknown_domains.join(", ")
        )
    })
}

/// One of the Overview's four cards: a label with its definition, one
/// number, and a line or two under it.
fn ov_card(h: &mut String, id: &str, label: &str, definition: &str, value: &str, sub: &str) {
    let _ = write!(
        h,
        r#"<div class="card ov-card"><span class="ov-label">{}{}</span><span class="ov-num">{value}</span><span class="ov-sub">{sub}</span></div>"#,
        esc(label),
        tip(id, label, definition),
    );
}

/// The run asked for neither sessions nor local groups (or for no
/// sessions, where local groups don't apply): a Quick collection.
fn nothing_targeted(cp: &CompletenessPoint) -> bool {
    let u = cp.untargeted();
    u.sessions && (u.local_groups || cp.local_groups_percent.is_none())
}

/// Sessions and local groups collected, over every domain: what the
/// Collection card and the note under the tiers say.
fn collection_words(p: &Posture) -> Option<(CompletenessPoint, &'static str)> {
    let c = CompletenessPoint::new(&p.completeness)?;
    // Each domain counts its active computers, or all enabled ones when it
    // has no logon times.
    let which = if p.completeness.iter().all(|d| d.active_only) {
        "active computers"
    } else {
        "computers"
    };
    Some((c, which))
}

/// What changed since the last run, as `pathwarden history` compares it,
/// and the runs on the trend: the earlier ones whose counts were measured
/// the way this run's are, and that targeted what this run did (a Quick
/// run's trend is of Quick runs).
fn since_and_earlier<'r>(r: &OverviewInput<'r>) -> (Option<SinceLast>, Vec<&'r HistoryPoint>) {
    let since = r.history.since(r.posture, r.generated_at, r.collected_at);
    let this_point = collection_words(r.posture).map(|(cp, _)| cp);
    let targeting = crate::since::targeting(this_point.as_ref());
    let earlier = r
        .history
        .earlier
        .iter()
        .filter(|p| p.basis() == r.posture.exposure_basis)
        .filter(|p| crate::since::targeting(p.completeness.as_ref()) == targeting)
        .collect();
    (since, earlier)
}

/// The top of the Overview as Home shows it: the hero, the four cards and
/// What changed (when there is one), from the same code as the report's
/// Overview, so every name in it is escaped here. Its in-page links
/// (`href="#..."`) and IDs are the report's.
pub fn overview_fragment(r: &OverviewInput) -> String {
    let (since, earlier) = since_and_earlier(r);
    let since = since.as_ref();
    let mut h = hero(r, &earlier, since.filter(|s| s.comparable()));
    ov_cards(&mut h, r, since);
    if let Some(w) = what_changed_block(r, since) {
        h.push_str(&w);
    }
    h
}

/// What changed since the last run, when the history has that run.
fn what_changed_block(r: &OverviewInput, since: Option<&SinceLast>) -> Option<String> {
    let s = since?;
    let previous = r
        .history
        .earlier
        .iter()
        .find(|p| p.run_id == s.previous_run)?;
    Some(what_changed(r, s, previous.at))
}

/// What an account with an attack path to Tier Zero means, in the hero's
/// (i) and All definitions.
const TAKEOVER_WORDS: &str = "An attacker who takes over any one of them can take over the domain.";

/// The remediation path, in its card's (i) and All definitions.
const PATH_WORDS: &str = "The fewest steps that cut every attack path to Tier Zero, biggest cut first. Weak accounts and hygiene findings need their own fix.";

/// Open findings, in their card's (i) and All definitions.
const OPEN_WORDS: &str = "Findings not fixed or accepted as a risk. Attack path findings are on a path to Tier Zero and are rated by how many users and computers can use them; hygiene findings are weaknesses not on an attack path.";

/// The share of active accounts, in the hero's (i) and All definitions.
fn share_words(days: i64) -> String {
    format!("Accounts with an attack path, as a share of active users and computers outside Tier Zero (enabled, signed in within {days} days of collection).")
}

/// The Overview's four cards: the work, the findings, Tier Zero's
/// protection, the data.
fn ov_cards(h: &mut String, r: &OverviewInput, since: Option<&SinceLast>) {
    // The counts' changes, when the last run targeted what this one did
    // (a Quick run is not compared with a Full one); What changed says why
    // they aren't.
    let deltas = since.filter(|s| s.comparable());
    let untargeted = collection_words(r.posture)
        .map(|(cp, _)| cp.lacking())
        .unwrap_or_default();
    let t0 = &r.posture.tier_zero;
    let c = &r.posture.findings;
    let open = open_findings(c);
    h.push_str(r#"<div class="ov-cards">"#);
    let zero_sub = match r.first_step {
        _ if r.exposed_before == 0 => "No account outside Tier Zero can reach it.".to_string(),
        None => "No step can cut these paths.".to_string(),
        Some(first) => {
            // Markup already: names are escaped, in <b>.
            let headline = step_headline(first);
            let mut words = headline.chars();
            let headline = words
                .next()
                .map(|c| c.to_lowercase().collect::<String>() + words.as_str())
                .unwrap_or_default();
            format!(
                r##"Start: {headline} (cuts off {}) <a class="ov-start" href="#step-1" aria-label="Step 1 of the remediation path">{}</a>"##,
                plural(first.principals_through, "account", "accounts"),
                icon("i-arrow")
            )
        }
    };
    let zero_change = match deltas.and_then(|s| s.changes_to_zero) {
        Some(c) => format!("<br>{}", since_last(delta_count(c.steps))),
        None => String::new(),
    };
    ov_card(
        h,
        "zero",
        "Remediation path",
        PATH_WORDS,
        &num(r.plan_steps),
        &format!("{zero_sub}{zero_change}"),
    );
    let open_change = deltas
        .map(|s| format!("<br>{}", since_last(delta_count(s.open.total))))
        .unwrap_or_default();
    ov_card(
        h,
        "open",
        "Open findings",
        OPEN_WORDS,
        &num(open),
        &format!(
            "{} on attack paths &middot; {} hygiene{open_change}",
            num(c.attack_path),
            num(c.hygiene)
        ),
    );
    let protected = match (t0.protection_score, t0.objects) {
        (Some(score), n) if n > 0 => {
            let change = match deltas.and_then(|s| s.protection_score) {
                Some(s) => format!("<br>{}", since_last(delta_points(s))),
                None => String::new(),
            };
            (
                pct(score),
                format!(
                    "{}{change}",
                    crate::posture::protected_count(
                        t0.objects.saturating_sub(t0.objects_with_findings),
                        t0.objects
                    )
                ),
            )
        }
        _ => ("n/a".to_string(), "No Tier Zero objects found.".to_string()),
    };
    ov_card(
        h,
        "protected",
        "Tier Zero protected",
        crate::posture::PROTECTED_DEFINITION,
        &protected.0,
        &protected.1,
    );
    // The card's number is the lower of the two figures, so it never reads
    // full while the note under the tiers warns; a domain below the line
    // is named in the warning colour.
    let collection = match collection_words(r.posture) {
        Some((cp, _)) if nothing_targeted(&cp) => (
            "Not collected".to_string(),
            "This run read the directory only.".to_string(),
        ),
        Some((cp, which)) => {
            let sessions = crate::since::whole_percent(cp.sessions_percent);
            let u = cp.untargeted();
            let (value, sub) = match cp.local_groups_percent {
                // One of the two targeted: its share, and the other named.
                Some(g) if u.sessions => (
                    crate::since::whole_percent(g),
                    "of member computers with local groups &middot; sessions not collected"
                        .to_string(),
                ),
                Some(_) if u.local_groups => (
                    sessions.clone(),
                    format!("of {which} with sessions &middot; local groups not collected"),
                ),
                Some(g) if g < cp.sessions_percent => (
                    crate::since::whole_percent(g),
                    format!(
                        "of member computers with local groups &middot; sessions from {sessions}%"
                    ),
                ),
                Some(g) => (
                    sessions.clone(),
                    format!(
                        "of {which} with sessions &middot; local groups from {}%",
                        crate::since::whole_percent(g)
                    ),
                ),
                None => (sessions.clone(), format!("of {which} with sessions")),
            };
            let low = match cp.low_domains {
                0 => String::new(),
                n => format!(
                    r#"<br><span class="low">{} below {LOW_PERCENT:.0}%</span>"#,
                    plural(n, "domain", "domains")
                ),
            };
            (format!("{value}%"), format!("{sub}{low}"))
        }
        None => ("n/a".to_string(), "No computers in the data.".to_string()),
    };
    ov_card(
        h,
        "collection",
        "Collection",
        &format!(
            "The share of active computers (signed in within 14 days of collection) whose sessions and local groups were collected. When it is low, paths can be missing and the counts read low.{}",
            if untargeted.any() {
                format!(" {}", crate::posture::NOT_TARGETED_DEF)
            } else {
                String::new()
            }
        ),
        &collection.0,
        &collection.1,
    );
    h.push_str("</div>");
}

/// Open findings, every severity: saturating, as the counts can come from
/// a run loaded from the history.
fn open_findings(c: &crate::posture::FindingCounts) -> usize {
    [c.high, c.medium, c.low, c.info]
        .into_iter()
        .fold(c.critical, usize::saturating_add)
}

fn overview_section(h: &mut String, r: &ReportInput) {
    let t0 = &r.posture.tier_zero;
    let c = &r.posture.findings;
    let open = open_findings(c);
    let o = r.overview_input();
    let (since, earlier) = since_and_earlier(&o);
    let since = since.as_ref();
    let deltas = since.filter(|s| s.comparable());
    panel_open(h, "overview", "Overview");
    h.push_str(&hero(&o, &earlier, deltas));
    ov_cards(h, &o, since);
    // Findings by severity: labeled cards, so color never carries the
    // meaning alone. Each opens the Findings tab showing that severity.
    let counts = [c.critical, c.high, c.medium, c.low, c.info];
    // Not compared when the runs read different things, or when the
    // earlier run can't be re-rated with this one's severities (What
    // changed says so).
    let before = deltas
        .filter(|s| !s.rating_changed)
        .map(|s| s.open.by_severity());
    let total = open.max(1) as f64;
    h.push_str(
        r#"<div class="ov-sev"><h3 class="sub">Findings by severity</h3><div class="sevcards">"#,
    );
    for (i, (s, n)) in SEVERITIES
        .iter()
        .zip(counts)
        .enumerate()
        .filter(|(_, (s, n))| *n > 0 || **s != Severity::Info)
    {
        // A severity with no findings has nothing to open: a plain card.
        let (open_tag, close_tag) = if n > 0 {
            (
                format!(
                    r##"<a class="sevcard {cls}" href="#findings" data-only="{cls}" title="Show the {label} findings">"##,
                    cls = sev_class(*s),
                    label = sev_label(*s)
                ),
                "</a>",
            )
        } else {
            (
                format!(r#"<div class="sevcard {}">"#, sev_class(*s)),
                "</div>",
            )
        };
        let _ = write!(
            h,
            r##"{open_tag}<span class="sevname"><span class="dot" aria-hidden="true"></span>{label}</span><span class="sevnum">{count}{change}</span><span class="sevtrack" aria-hidden="true"><span style="width:{w:.1}%"></span></span>{close_tag}"##,
            label = sev_label(*s),
            w = 100.0 * n as f64 / total,
            count = num(n),
            change = before
                .map(|b| format!(" {}", since_last(delta_count(b[i].1))))
                .unwrap_or_default(),
        );
    }
    h.push_str("</div>");
    if c.suppressed > 0 {
        let _ = write!(
            h,
            r#"<p class="muted small">{} not counted.</p>"#,
            plural(c.suppressed, "accepted risk", "accepted risks")
        );
    }
    if let Some(line) = severities_set_line(&r.posture.severities_set) {
        h.push_str(&line);
    }
    h.push_str("</div>");
    // What changed since the last run, under the severities: its own section.
    if let Some(w) = what_changed_block(&o, since) {
        h.push_str(&w);
    }

    // Tiers: Tier Zero, then each Privilege Zone.
    let _ = write!(
        h,
        r#"<h3 class="sub">Tier Zero and Privilege Zones</h3><div class="card tiers"><table><thead><tr><th>Name</th><th>Status</th><th>Accounts with an attack path</th><th class="num">Protected</th></tr></thead><tbody>"#
    );
    for z in std::iter::once(t0).chain(&r.posture.zones) {
        // A zone with no change of its own was compared and is the same,
        // or wasn't compared (new, or not counted the last run).
        let change = deltas.and_then(|s| {
            if std::ptr::eq(z, t0) {
                s.tier_zero
            } else if s.zones_unchanged.contains(&z.zone) {
                Some(Delta {
                    before: z.exposed,
                    after: z.exposed,
                })
            } else {
                s.zones.iter().find(|c| c.zone == z.zone)?.exposed
            }
        });
        let grade_change = deltas.and_then(|s| {
            if std::ptr::eq(z, t0) {
                s.tier_zero_grade
            } else {
                s.zones.iter().find(|c| c.zone == z.zone)?.grade
            }
        });
        let _ = write!(
            h,
            // The cell labels show only on a phone, where each tier is a
            // stacked row without the table's headers.
            r#"<tr><th scope="row">{name}</th><td><span class="grade-badge {class}">{grade}</span>{was}</td><td class="take"><strong>{count}</strong><span class="cell-label"> accounts with an attack path</span>{change}</td><td class="num prot">{score}<span class="cell-label"> protected</span></td></tr>"#,
            name = if std::ptr::eq(z, t0) {
                "Tier Zero".to_string()
            } else {
                format!(
                    r#"{} <span class="muted">&middot; Privilege Zone</span>"#,
                    esc(&z.zone)
                )
            },
            class = z.exposure_grade.css_class(),
            grade = z.exposure_grade.as_str(),
            was = grade_change
                .map(|g| match since {
                    Some(s) if s.severity_settings_changed => grade_was_neutral(g),
                    _ => grade_was(g),
                })
                .unwrap_or_default(),
            count = num(z.exposed),
            change = change
                .map(|d| format!(" {}", delta_count(d)))
                .unwrap_or_default(),
            score = crate::posture::protected_words(z.objects, z.objects_with_findings),
        );
    }
    h.push_str("</tbody></table></div>");

    // One line on the collection; a warning when some of it is missing, a
    // plain note when the run did not ask for it.
    if let Some((cp, which)) = collection_words(r.posture).filter(|(cp, _)| cp.untargeted().any()) {
        let u = cp.untargeted();
        let date = r
            .stats
            .collected_at
            .map(|t| format!("Collected {}", short_date(t)));
        let figures = if nothing_targeted(&cp) {
            format!(
                "{} from the directory only: {} weren't collected.",
                date.unwrap_or_else(|| "Read".to_string()),
                if cp.local_groups_percent.is_some() {
                    "sessions and local groups"
                } else {
                    "sessions"
                }
            )
        } else {
            let prefix = date.map(|d| format!("{d}: ")).unwrap_or_default();
            let groups = cp.local_groups_percent.unwrap_or(0.0);
            let mut s = if u.sessions {
                format!(
                    "{prefix}local groups from {}% of member computers; sessions not collected.",
                    crate::since::whole_percent(groups)
                )
            } else {
                format!(
                    "{prefix}sessions from {}% of {which}; local groups not collected.",
                    crate::since::whole_percent(cp.sessions_percent)
                )
            };
            if let Some(c) = s.get(..1) {
                s = c.to_uppercase() + &s[1..];
            }
            s
        };
        let paths = if nothing_targeted(&cp) && cp.local_groups_percent.is_some() {
            crate::posture::Untargeted {
                sessions: true,
                local_groups: true,
            }
        } else {
            u
        };
        let low = match cp.low_domains {
            0 => String::new(),
            1 => format!(" 1 domain is below {LOW_PERCENT:.0}%, so these counts can read low."),
            n => format!(
                " {} domains are below {LOW_PERCENT:.0}%, so these counts can read low.",
                num(n)
            ),
        };
        let _ = write!(
            h,
            r#"<p class="ov-note {}"{}>{} {}{}</p>"#,
            if low.is_empty() { "muted" } else { "warn" },
            if low.is_empty() {
                ""
            } else {
                r#" role="note""#
            },
            esc(&figures),
            esc(&paths.paths_sentence().unwrap_or_default()),
            esc(&low),
        );
    } else if let Some((cp, which)) = collection_words(r.posture) {
        let when = r
            .stats
            .collected_at
            .map(|t| format!("Collected {}: sessions", short_date(t)))
            .unwrap_or_else(|| "Sessions".to_string());
        let groups = cp
            .local_groups_percent
            .map(|g| format!(", local groups from {}%", crate::since::whole_percent(g)))
            .unwrap_or_default();
        let figures = format!(
            "{when} from {}% of {which}{groups}.",
            crate::since::whole_percent(cp.sessions_percent)
        );
        if cp.low_domains > 0 {
            let _ = write!(
                h,
                r##"<p class="ov-note warn" role="note"><strong>Incomplete collection.</strong> {} {} below {LOW_PERCENT:.0}%: paths through sessions and local administrator rights can be missing, so these counts can read low. See <a href="#environment">Collection</a>.</p>"##,
                esc(&figures),
                if cp.low_domains == 1 {
                    "1 domain is".to_string()
                } else {
                    format!("{} domains are", num(cp.low_domains))
                },
            );
        } else {
            let _ = write!(
                h,
                r#"<p class="ov-note muted">{} {}</p>"#,
                esc(&figures),
                if r.posture.completeness.len() == 1 {
                    format!("Above {LOW_PERCENT:.0}%.")
                } else {
                    format!("Every domain is above {LOW_PERCENT:.0}%.")
                }
            );
        }
    }

    let _ = write!(
        h,
        r##"<details class="explain"><summary>{info} All definitions</summary><dl>
<div><dt>Tier Zero</dt><dd>The accounts, groups and servers that control the whole domain: domain controllers, Domain Admins and similar groups, the AD CS servers, and the GPOs and containers above them. Whoever controls one of them controls everything.</dd></div>
<div><dt>Status</dt><dd><strong>Critical</strong>: a group that holds nearly every account (Domain Users, Authenticated Users, Everyone) can reach Tier Zero, or a Critical finding is open. <strong>High</strong>: at least one account outside Tier Zero can reach it. <strong>Moderate</strong>: no account can, but Medium or higher findings are open. <strong>Low</strong>: no account can, and no Medium or higher finding is open. Any open path into Tier Zero keeps the status above Low. The (i) beside the badge says why.</dd></div>
<div><dt>Accounts with an attack path to Tier Zero</dt><dd>Enabled users and computers outside Tier Zero with a full path to it. {takeover}</dd></div>
<div><dt>Share of active accounts</dt><dd>{share}{activity} It doesn't set the status.</dd></div>
<div><dt>Remediation path</dt><dd>{path}</dd></div>
<div><dt>Open findings</dt><dd>{open}</dd></div>
<div><dt>Tier Zero protected</dt><dd>The share of Tier Zero objects that no open attack path finding leads to. A Privilege Zone has its own.</dd></div>
<div><dt>Collection</dt><dd>The share of active computers (signed in within 14 days of collection) whose sessions and local groups were collected. Below {low:.0}% for a domain, paths through sessions and local administrator rights can be missing and the counts read low. {not_targeted} A Quick collection reads the directory only, so it is compared only with other Quick collections.</dd></div>
<div><dt>Tier Zero and Privilege Zones</dt><dd>Tier Zero and each Privilege Zone in the settings: its status, the accounts outside it (and outside Tier Zero) with an attack path to it, and how many of its objects are protected. With a run history, a status that changed says what it was the run before. The remediation path is worked out for Tier Zero only; a zone shows only its count.</dd></div>
<div><dt>What changed</dt><dd>The change from the last comparable run of this environment, line by line. More in the <a href="https://pathwarden.org/kb/glossary.html">glossary</a>.</dd></div>
<div><dt>Introduced</dt><dd>New in a period: a finding first seen in it (New), a finding fixed before and back in it (Back), an older finding that gained objects in it (+N objects), a new member of Tier Zero or a zone, or a new path into one. The Findings tab filters by it.</dd></div>
<div><dt>First seen</dt><dd>When Pathwarden first found a finding, an object in it, a member or a path: the date of that run ("first seen Oct 18 (run 3)"), not when the change was made in the directory. Objects, members and paths have first-seen dates only from the run where tracking started; one that left and returned is "back".</dd></div>
<div><dt>New paths and members</dt><dd>A new member: an object that joined Tier Zero or a Privilege Zone, such as a user added to Domain Admins. A new path: a relationship into Tier Zero or a zone from outside it (a permission, an admin right, a session) that wasn't there at the run before. A zone with more than {zone_max} of either is counted, not dated.</dd></div>
</dl><p class="muted small">More terms in the <a href="https://pathwarden.org/kb/glossary.html">glossary</a>.</p></details>
"##,
        info = icon("i-info"),
        takeover = TAKEOVER_WORDS,
        share = esc(&share_words(r.posture.activity_days)),
        path = PATH_WORDS,
        open = OPEN_WORDS,
        low = LOW_PERCENT,
        not_targeted = crate::posture::NOT_TARGETED_DEF,
        zone_max = num(crate::introduced::ZONE_MAX),
        activity = activity_note(r.posture)
            .map(|n| format!(" {}", esc(&n)))
            .unwrap_or_default(),
    );
    h.push_str("</section>\n");
}

/// What the remediation path covers, and what it leaves.
fn scope_sentence(r: &ReportInput, links: &PlanLinks, uncovered: usize) -> String {
    let p = r.plan;
    let weak = r
        .findings
        .iter()
        .filter(|f| {
            is_weak_account(f)
                && f.suppressed.is_none()
                && links.coverage(f).is_some_and(|c| c.closed_by.is_empty())
        })
        .count();
    let mut s = format!(
        "{} every attack path to Tier Zero{}, biggest cut first.",
        if p.fixes.len() == 1 {
            "This step cuts".to_string()
        } else {
            format!("These {} steps cut", num(p.fixes.len()))
        },
        if p.exposed_after > 0 {
            " that can be cut"
        } else {
            ""
        }
    );
    // `uncovered` includes the weak accounts (Kerberoastable or AS-REP
    // roastable); the rest are on no cut path.
    let other = uncovered.saturating_sub(weak);
    let mut left = Vec::new();
    if weak > 0 {
        left.push(plural(weak, "weak account", "weak accounts"));
    }
    if other > 0 {
        left.push(plural(other, "other finding", "other findings"));
    }
    if !left.is_empty() {
        let _ = write!(
            s,
            " {} {} own fix (below).",
            left.join(" and "),
            if weak + other == 1 {
                "still needs its"
            } else {
                "still need their"
            }
        );
    }
    s
}

// -------------------------------------------------------- Remediation path

/// Findings tied to a remediation step: those about the step's two objects
/// (the step fixes them), and those whose example path takes the step's edge
/// (the step cuts that path). Most severe first.
struct Related<'a> {
    fixes: Vec<&'a Finding>,
    cuts: Vec<&'a Finding>,
}

/// How a finding relates to the remediation path.
#[derive(Default)]
struct Coverage {
    /// Steps (1-based) whose change is the finding's own fix.
    closed_by: Vec<usize>,
    /// Steps that cut the finding's example path to the target.
    cut_by: Vec<usize>,
}

impl Coverage {
    fn covered(&self) -> bool {
        !self.closed_by.is_empty() || !self.cut_by.is_empty()
    }
}

/// The links between the remediation path and the findings, both ways,
/// worked out once for the whole report.
struct PlanLinks<'a> {
    /// Per step, in plan order.
    steps: Vec<Related<'a>>,
    /// Per finding fingerprint.
    findings: BTreeMap<&'a str, Coverage>,
}

impl<'a> PlanLinks<'a> {
    fn new(plan: &RemediationPlan, findings: &'a [Finding]) -> Self {
        let steps: Vec<Related<'a>> = plan.fixes.iter().map(|f| related(f, findings)).collect();
        let mut by: BTreeMap<&'a str, Coverage> = BTreeMap::new();
        for (i, rel) in steps.iter().enumerate() {
            for f in &rel.fixes {
                by.entry(f.fingerprint.as_str())
                    .or_default()
                    .closed_by
                    .push(i + 1);
            }
            for f in &rel.cuts {
                by.entry(f.fingerprint.as_str())
                    .or_default()
                    .cut_by
                    .push(i + 1);
            }
        }
        PlanLinks {
            steps,
            findings: by,
        }
    }

    fn coverage(&self, f: &Finding) -> Option<&Coverage> {
        self.findings
            .get(f.fingerprint.as_str())
            .filter(|c| c.covered())
    }

    /// Whether no step closes `f`: nothing covers it, or (a weak account) a
    /// step only cuts its path.
    fn needs_own_fix(&self, f: &Finding) -> bool {
        match self.coverage(f) {
            None => true,
            Some(c) => is_weak_account(f) && c.closed_by.is_empty(),
        }
    }

    /// Open findings that need their own fixes: those no step closes or cuts,
    /// and weak accounts whose path a step only cuts (the account is still
    /// roastable, so the finding stays open). Most severe first.
    fn uncovered(&self, findings: &'a [Finding]) -> Vec<&'a Finding> {
        let mut v: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.suppressed.is_none() && self.needs_own_fix(f))
            .collect();
        v.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.rule.cmp(b.rule)));
        v
    }
}

fn related<'a>(f: &PlannedFix, findings: &'a [Finding]) -> Related<'a> {
    let mut fixes = Vec::new();
    let mut cuts = Vec::new();
    // A step that removes a right where it is defined (a container above, or
    // AdminSDHolder for SDProp copies) also cuts paths through its copies:
    // those name the same holder and right, but another object.
    let copies = f.sdprop_copies > 0 || f.inherited_by > 0;
    for x in findings.iter().filter(|x| x.suppressed.is_none()) {
        let names = |n: &str| x.affected.iter().any(|a| a.name == n);
        if names(&f.from) && names(&f.to) {
            fixes.push(x);
        } else if x.path.as_ref().is_some_and(|p| {
            p.steps.iter().any(|s| {
                s.from == f.from && (s.to == f.to || (copies && f.edges.contains(&s.edge)))
            })
        }) {
            cuts.push(x);
        }
    }
    for v in [&mut fixes, &mut cuts] {
        v.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.rule.cmp(b.rule)));
    }
    Related { fixes, cuts }
}

/// Up to this many findings are listed under each plan step.
const RELATED_VISIBLE: usize = 6;

/// "step 3", "steps 1 and 4", "steps 1, 2 and 5", each linked to its step.
fn step_links(steps: &[usize]) -> String {
    if let [n] = steps {
        // One step: the whole "step 3" is the link, a bigger target.
        return format!(r##"<a class="steplink" href="#step-{n}">step {n}</a>"##);
    }
    let links: Vec<String> = steps
        .iter()
        .map(|n| format!(r##"<a class="steplink" href="#step-{n}">{n}</a>"##))
        .collect();
    let word = if steps.len() == 1 { "step" } else { "steps" };
    let list = match links.as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    format!("{word} {list}")
}

/// The Remediation tab's steps, in plan order, with the steps on one object
/// of one kind (at least [`GROUP_MIN`]) gathered into one row where the first
/// of them falls. Each step keeps its number and `#step-N` anchor inside.
fn plan_rows_grouped(
    h: &mut String,
    fixes: &[PlannedFix],
    steps: &[Related],
    lists: Option<&crate::exposed::ExposureLists>,
) {
    let key = |f: &PlannedFix| (f.to.clone(), lead_edge(f));
    let mut members: BTreeMap<(String, Option<EdgeKind>), Vec<usize>> = BTreeMap::new();
    for (i, f) in fixes.iter().enumerate() {
        members.entry(key(f)).or_default().push(i);
    }
    let mut done = vec![false; fixes.len()];
    for (i, (f, rel)) in fixes.iter().zip(steps).enumerate() {
        if done[i] {
            continue;
        }
        let group = &members[&key(f)];
        if group.len() < GROUP_MIN {
            plan_row(h, i + 1, f, rel, lists);
            continue;
        }
        let exposed = group
            .iter()
            .map(|&j| fixes[j].principals_through)
            .max()
            .unwrap_or(0);
        let _ = write!(
            h,
            r#"<details class="row step stepgroup"><summary><span class="stepnum">{}</span><span class="steptext"><span class="action">{}</span><span class="rel">{} <span class="muted small">steps {}</span></span></span><span class="aside"><strong>{}</strong> accounts</span></summary><div class="body"><p>{}</p><div class="rows">"#,
            num(group.len()),
            group_headline(f, lead_edge(f), group.len()),
            object_chip(&f.to, f.to_kind),
            step_list(group),
            num(exposed),
            if lead_edge(f)
                .is_some_and(|k| is_permission(k) || edge_meaning(k, f.to_managed).is_none())
            {
                "Each row is a step of the remediation path. One review of the object's permissions (resetting them to the default, then granting back only what is needed) covers them all."
            } else {
                "Each row is a step of the remediation path."
            },
        );
        for &j in group {
            plan_row(h, j + 1, &fixes[j], &steps[j], lists);
            done[j] = true;
        }
        h.push_str("</div></div></details>");
    }
}

/// "6, 9–14, 20 and 2 more": a group's step numbers, short.
fn step_list(group: &[usize]) -> String {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for &i in group {
        let n = i + 1;
        match runs.last_mut() {
            Some((_, end)) if *end + 1 == n => *end = n,
            _ => runs.push((n, n)),
        }
    }
    let shown: Vec<String> = runs
        .iter()
        .take(4)
        .map(|&(a, b)| {
            if a == b {
                num(a)
            } else {
                format!("{}–{}", num(a), num(b))
            }
        })
        .collect();
    let rest: usize = runs.iter().skip(4).map(|&(a, b)| b - a + 1).sum();
    if rest > 0 {
        format!("{} and {} more", shown.join(", "), num(rest))
    } else {
        shown.join(", ")
    }
}

/// One remediation step as a collapsed row (`#step-N`), linking to the
/// findings it fixes.
fn plan_row(
    h: &mut String,
    n: usize,
    f: &PlannedFix,
    related: &Related,
    lists: Option<&crate::exposed::ExposureLists>,
) {
    let edges: String = f
        .edges
        .iter()
        .map(|e| edge_chip(*e, f.to_managed))
        .collect();
    let source = f
        .source
        .as_deref()
        .map(|s| {
            format!(
                r#"<p class="muted small">Reported by {}, not read from the directory.</p>"#,
                esc(s)
            )
        })
        .unwrap_or_default();
    let _ = write!(
        h,
        r#"<details class="row step" id="step-{n}"><summary><span class="stepnum">{n}</span><span class="steptext"><span class="action">{}</span><span class="rel">{} <span class="via">{}{}</span> {}</span></span><span class="aside"><strong>{}</strong> accounts{}</span></summary><div class="body"><p>{}</p>{source}{}{}</div></details>"#,
        step_headline(f),
        object_chip(&f.from, f.from_kind),
        edges,
        icon("i-arrow"),
        object_chip(&f.to, f.to_kind),
        num(f.principals_through),
        accounts::step_new(lists, n),
        text_with_code(&f.action),
        accounts::step_block(lists, n),
        related_links(related),
    );
}

/// An edge name as a chip, with what it means on hover. `to_managed` marks a
/// target whose password the domain rotates (gMSA/sMSA), which changes what
/// some edges (WriteSPN) can actually achieve.
fn edge_chip(e: EdgeKind, to_managed: bool) -> String {
    match edge_meaning(e, to_managed) {
        Some(m) => format!(
            r#"<span class="edge" title="{}">{}</span>"#,
            esc(m),
            esc(e.as_str())
        ),
        None => format!(r#"<span class="edge">{}</span>"#, esc(e.as_str())),
    }
}

/// One line on what a relationship lets the holder do (the full list is in
/// docs/rules.md).
fn edge_meaning(e: EdgeKind, to_managed: bool) -> Option<&'static str> {
    use EdgeKind::*;
    Some(match e {
        MemberOf => "Member of the group, so it has the group's rights.",
        HasSession => "The account is signed in to this computer; whoever controls the computer can take its credentials.",
        AdminTo => "Local administrator on the computer.",
        CanRdp => "Can sign in to the computer over Remote Desktop.",
        CanPsRemote => "Can run commands on the computer with PowerShell remoting.",
        ExecuteDcom => "Can run code on the computer through DCOM.",
        AllowedToDelegate => "Constrained delegation: can act as any user toward the target service.",
        AllowedToAct => "Resource-based delegation: can act as any user on the target computer.",
        HasSidHistory => "Carries the target's SID in its SID history, so it has the target's rights.",
        Contains => "The container holds the object, and rights on the container are inherited by it.",
        GpLink => "The GPO applies to the object, so whoever edits the GPO controls it.",
        SameForestTrust => "Trust within one forest; a domain's admins can take over the forest.",
        DcSync => "Can replicate password hashes from the domain (DCSync).",
        CoerceToTgt => "Unconstrained delegation: can capture a domain controller's Kerberos ticket.",
        GenericAll => "Full control of the object.",
        GenericWrite => "Can write the object's attributes.",
        WriteOwner => "Can make itself the owner, and then grant itself full control.",
        WriteDacl => "Can change the object's permissions, and then grant itself full control.",
        Owns => "Owns the object, so it can grant itself full control.",
        AddMember => "Can add members to the group.",
        AddSelf => "Can add itself to the group.",
        ForceChangePassword => "Can reset the account's password.",
        AllExtendedRights => "Has every extended right, including password reset.",
        AddKeyCredentialLink => "Can add a key credential and sign in as the account (shadow credentials).",
        AddAllowedToAct => "Can set up resource-based delegation on the computer.",
        ReadLapsPassword | SyncLapsPassword => "Can read the computer's local administrator password (LAPS).",
        ReadGmsaPassword => "Can read the managed service account's password.",
        WriteSpn if to_managed => "Can set a service principal name, but the domain rotates this account's password, so it can't be Kerberoasted.",
        WriteSpn => "Can set a service principal name and Kerberoast the account.",
        WriteAccountRestrictions => "Can set up resource-based delegation on the computer.",
        WriteGpLink => "Can link a GPO to the object.",
        WriteGpoFiles => "Can write the GPO's files in SYSVOL, so it decides what the GPO applies.",
        WriteLogonScript => "Can change the user's logon script, which runs as the user at the next logon.",
        ManageCa => "Can reconfigure the certification authority (ESC7).",
        HostsCaService => "The computer runs a certification authority.",
        GoldenCert => "Controls a CA key, so it can forge certificates for any account.",
        ManagesHost => "Manages the computer (SCCM, SCOM and others), so it can run code on it.",
        HasStoredCredential => {
            "Stores the account's password for a service or scheduled task, where any administrator of the computer can read it."
        }
        k if k.is_adcs_abuse() => "A certificate weakness (AD CS) lets it get a certificate for a privileged account.",
        _ => return None,
    })
}

/// The part of a name before its domain ("EVERYONE", "WS-114"), or the
/// whole name.
fn short_plain(full: &str, kind: NodeKind) -> &str {
    full.split_once('@')
        .map(|(n, _)| n)
        .or_else(|| {
            (kind == NodeKind::Computer)
                .then(|| full.split_once('.').map(|(n, _)| n))
                .flatten()
        })
        .filter(|n| !n.is_empty())
        .unwrap_or(full)
}

/// A name without its domain, for one-line steps; the full name stays in
/// the tooltip.
fn short_name(full: &str, kind: NodeKind) -> String {
    format!(
        r#"<b title="{}">{}</b>"#,
        esc(full),
        esc(short_plain(full, kind))
    )
}

/// What a step's headline is made of: a plan step ([`PlannedFix`]), or the
/// relationship a finding is about ([`crate::findings::Finding::headline`]).
pub struct StepWords<'a> {
    pub from: &'a str,
    pub from_kind: NodeKind,
    /// Rights or relationships from `from` to `to`.
    pub edges: &'a [EdgeKind],
    pub to: &'a str,
    pub to_kind: NodeKind,
    /// The target is a group or standalone managed service account.
    pub to_managed: bool,
}

impl<'a> StepWords<'a> {
    pub fn of(f: &'a PlannedFix) -> Self {
        StepWords {
            from: &f.from,
            from_kind: f.from_kind,
            edges: &f.edges,
            to: &f.to,
            to_kind: f.to_kind,
            to_managed: f.to_managed,
        }
    }
}

/// The edge a step's headline is about: plain permissions read the same, so
/// anything else wins.
fn lead_of(edges: &[EdgeKind], to_managed: bool) -> Option<EdgeKind> {
    edges
        .iter()
        .copied()
        .find(|e| edge_meaning(*e, to_managed).is_some() && !is_permission(*e))
        .or_else(|| edges.first().copied())
}

fn lead_edge(f: &PlannedFix) -> Option<EdgeKind> {
    lead_of(&f.edges, f.to_managed)
}

/// Steps on one object of one kind ("remove the permissions 412 principals
/// hold on DOMAIN ADMINS"), when there are enough of them to group.
const GROUP_MIN: usize = 5;

/// What kind of permission a right on `to_kind` is, in words: GPO
/// permissions are set in Group Policy Management, the rest in Active
/// Directory. "the group CERT USERS" names the kind with the object.
fn permission_words(to_kind: NodeKind, b: &str, rights: usize) -> (&'static str, String) {
    (
        crate::remediation::permission_kind(to_kind, rights),
        crate::remediation::the_kind(to_kind, b),
    )
}

/// Headline of a group of `n` steps on the same target, all led by `lead`.
fn group_headline(first: &PlannedFix, lead: Option<EdgeKind>, n: usize) -> String {
    use EdgeKind::*;
    let b = short_name(&first.to, first.to_kind);
    let n = num(n);
    match lead {
        Some(HasSession) => format!("Sign {b} out of {n} computers and stop using it there"),
        Some(MemberOf) => format!("Take {n} members out of the group {b}"),
        Some(AdminTo) => format!("Take {n} accounts out of local Administrators on {b}"),
        Some(CanRdp) => format!("Stop {n} accounts signing in to {b} over Remote Desktop"),
        Some(CoerceToTgt) => format!("Turn off unconstrained delegation on {n} computers"),
        Some(DcSync) => {
            format!(
                "Remove the replication permissions (DCSync) {n} accounts hold on the domain {b}"
            )
        }
        Some(ReadLapsPassword | SyncLapsPassword) => {
            format!("Stop {n} accounts reading the LAPS password of {b}")
        }
        Some(k) if is_permission(k) && !first.to_kind.is_external() => {
            let (words, on) = permission_words(first.to_kind, &b, 2);
            format!("Remove the {words} {n} accounts hold on {on}")
        }
        Some(k) if is_permission(k) || edge_meaning(k, first.to_managed).is_none() => {
            format!("Remove the permissions {n} accounts hold on {b}")
        }
        _ => format!("{n} changes on {b}"),
    }
}

/// A plan step as one plain-English action ("Sign DA-ADMIN21 out of WS-114
/// and stop using it there"), led by its most specific relationship. The
/// full instructions and the edge names stay in the row.
pub fn step_headline(f: &PlannedFix) -> String {
    headline_with(&StepWords::of(f), short_name)
}

/// [`step_headline`] as plain text, for a ticket or the terminal: names
/// without their domain, nothing escaped.
pub fn step_headline_text(w: &StepWords) -> String {
    headline_with(w, |full, kind| short_plain(full, kind).to_string())
}

fn headline_with(f: &StepWords, name: impl Fn(&str, NodeKind) -> String) -> String {
    use EdgeKind::*;
    let a = name(f.from, f.from_kind);
    let b = name(f.to, f.to_kind);
    match lead_of(f.edges, f.to_managed) {
        Some(HasSession) => format!("Sign {b} out of {a} and stop using it there"),
        Some(MemberOf) => format!("Take {a} out of the group {b}"),
        Some(AdminTo) => format!("Take {a} out of local Administrators on {b}"),
        Some(CanRdp) => format!("Stop {a} from signing in to {b} over Remote Desktop"),
        Some(CanPsRemote) => format!("Stop {a} from using PowerShell remoting on {b}"),
        Some(ExecuteDcom) => format!("Stop {a} from running code on {b} through DCOM"),
        Some(AllowedToDelegate) => format!("Remove {b} from the delegation list of {a}"),
        Some(AllowedToAct) => format!("Stop {a} from delegating to {b}"),
        Some(HasSidHistory) => format!("Clear the SID history of {a}"),
        Some(Contains) => format!(
            "Lock down {}",
            crate::remediation::the_kind(f.from_kind, &a)
        ),
        Some(GpLink) => format!("Restrict who can edit the GPO {a}"),
        Some(SameForestTrust) => format!("Manage {a} as Tier Zero"),
        Some(DcSync) => {
            format!("Remove the replication permissions (DCSync) {a} holds on the domain {b}")
        }
        Some(CoerceToTgt) => format!("Turn off unconstrained delegation on {a}"),
        Some(Owns) => format!(
            "Change the owner of {}",
            crate::remediation::the_kind(f.to_kind, &b)
        ),
        Some(ManageCa) => format!("Remove the Manage CA permission of {a} on {b}"),
        Some(HostsCaService | GoldenCert) => format!("Manage {a} as Tier Zero"),
        Some(ManagesHost) => {
            format!("Take {b} out of {a}'s management, or manage {a} as Tier Zero")
        }
        Some(HasStoredCredential) => format!("Stop storing the password of {b} on {a}"),
        Some(ReadLapsPassword | SyncLapsPassword) => {
            format!("Stop {a} from reading the LAPS password of {b}")
        }
        Some(ReadGmsaPassword) => format!("Stop {a} from reading the password of {b}"),
        Some(WriteGpoFiles) => {
            format!("Remove {a}'s write access to the SYSVOL folder of GPO {b}")
        }
        Some(WriteLogonScript) => {
            format!("Remove {a}'s write access to the logon script of {b}")
        }
        Some(k) if k.is_adcs_abuse() => {
            format!("Close the certificate weakness that lets {a} take over {b}")
        }
        // Directory permissions say which kind they are, in words.
        _ if !f.edges.is_empty()
            && f.edges.iter().all(|&e| is_permission(e))
            && !f.to_kind.is_external() =>
        {
            let mut rights = f.edges.to_vec();
            rights.sort_unstable();
            rights.dedup();
            let (words, on) = permission_words(f.to_kind, &b, rights.len());
            format!("Remove the {words} {a} holds on {on}")
        }
        _ => format!("Remove the permissions {a} holds on {b}"),
    }
}

/// Rights that are permissions on an object (an ACE): one headline covers them.
fn is_permission(e: EdgeKind) -> bool {
    use EdgeKind::*;
    matches!(
        e,
        GenericAll
            | GenericWrite
            | WriteOwner
            | WriteDacl
            | AddMember
            | AddSelf
            | ForceChangePassword
            | AllExtendedRights
            | AddKeyCredentialLink
            | AddAllowedToAct
            | WriteSpn
            | WriteAccountRestrictions
            | WriteGpLink
    )
}

fn related_links(related: &Related) -> String {
    let list = |title: &str, fs: &[&Finding]| {
        if fs.is_empty() {
            return String::new();
        }
        let items: String = fs
            .iter()
            .take(RELATED_VISIBLE)
            .map(|f| related_item(f))
            .collect();
        let more = if fs.len() > RELATED_VISIBLE {
            let rest: String = fs
                .iter()
                .skip(RELATED_VISIBLE)
                .map(|f| related_item(f))
                .collect();
            format!(
                r#"<details class="amore"><summary>Show {} more</summary><ul class="related">{rest}</ul></details>"#,
                num(fs.len() - RELATED_VISIBLE)
            )
        } else {
            String::new()
        };
        format!(r#"<h4>{title}</h4><ul class="related">{items}</ul>{more}"#)
    };
    list("Findings this step closes", &related.fixes)
        + &list("Findings whose attack path this step cuts", &related.cuts)
}

/// A finding as a link row (severity, rule, title).
fn related_item(f: &Finding) -> String {
    format!(
        r##"<li><a href="#f-{fp}">{badge}<span class="rule">{rule}</span><span class="rt">{title}</span>{arrow}</a></li>"##,
        fp = esc(&f.fingerprint),
        badge = badge(f.severity),
        rule = esc(f.rule),
        title = esc(&f.title),
        arrow = icon("i-arrow"),
    )
}

fn plan_section(h: &mut String, r: &ReportInput, links: &PlanLinks) {
    let p = r.plan;
    let uncovered = links.uncovered(r.findings);
    panel_open(h, "plan", "Remediation path");
    if p.exposed_before == 0 {
        h.push_str(r#"<p class="lead">No user or computer outside Tier Zero can reach Tier Zero. There is nothing to cut.</p>"#);
    } else {
        let _ = write!(
            h,
            r#"<div class="beforeafter card"><div><span class="ba-num bad">{}</span><span class="ba-label">can reach Tier Zero</span></div><span class="ba-arrow">{}</span><div><span class="ba-num">{}</span><span class="ba-label">{}</span></div><span class="ba-arrow">{}</span><div><span class="ba-num good">{}</span><span class="ba-label">left afterwards</span></div></div>"#,
            num(p.exposed_before),
            icon("i-arrow"),
            num(p.fixes.len()),
            if p.fixes.len() == 1 { "step" } else { "steps" },
            icon("i-arrow"),
            num(p.exposed_after),
        );
        let exposure_line = if p.exposed_after == p.exposed_before {
            format!(
                "The share of active accounts with a path stays at {}: the remaining paths can't be cut. ",
                pct(p.exposure_before),
            )
        } else {
            format!(
                "The share of active accounts with a path drops from {} to {}. ",
                pct(p.exposure_before),
                pct(p.exposure_after),
            )
        };
        let _ = write!(
            h,
            r#"<p class="lead">{}{}{}</p><div class="rows card">"#,
            esc(&exposure_line),
            esc(&scope_sentence(r, links, uncovered.len())),
            if p.exposed_after > 0 {
                format!(
                    " {} a path no step can cut (for example through a forest trust). Treat them as Tier Zero.",
                    plural(p.exposed_after, "account keeps", "accounts keep")
                )
            } else {
                String::new()
            }
        );
        plan_rows_grouped(h, &p.fixes, &links.steps, r.lists);
        h.push_str("</div>");
        // The steps' account lists, which the script draws.
        if let Some(data) = accounts::steps_data(r.lists) {
            h.push_str(&data);
        }
    }
    if !uncovered.is_empty() {
        let _ = write!(
            h,
            r#"<h3 class="sub" id="not-covered">Fix directly{}</h3><p class="scope">{}</p>"#,
            tip(
                "fixdirect",
                "Fix directly",
                "Weak accounts (even where a step cuts their path), hygiene findings, and paths that start inside Tier Zero."
            ),
            if p.fixes.is_empty() {
                "These findings need their own fixes. Most severe first."
            } else {
                "No step closes these; each needs its own fix. Most severe first."
            }
        );
        h.push_str(r#"<ul class="related">"#);
        for f in &uncovered {
            h.push_str(&related_item(f));
        }
        h.push_str("</ul>");
    } else if !r.findings.is_empty() && !p.fixes.is_empty() {
        h.push_str(r#"<p class="scope" id="not-covered">Every open finding is closed by a step above, or has its attack path cut by one.</p>"#);
    }
    h.push_str("</section>\n");
}

// ---------------------------------------------------------------- Findings

fn findings_section(h: &mut String, r: &ReportInput, links: &PlanLinks) {
    panel_open(h, "findings", "Findings");
    if r.findings.is_empty() {
        h.push_str(r#"<p class="lead">No findings.</p>"#);
        fixed_open_card(h, &r.history.fixed_open);
        h.push_str("</section>");
        return;
    }
    let _ = write!(
        h,
        r#"<div class="filters card" role="group" aria-label="Filter findings">
  <span class="chips" role="group" aria-label="Severity">{}</span>
  <span class="segmented" role="radiogroup" aria-label="Category"><label><input type="radio" name="f-category" value="" checked>All</label><label><input type="radio" name="f-category" value="attack_path">Attack path</label><label><input type="radio" name="f-category" value="hygiene">Hygiene</label></span>
  {intro}<input id="f-search" type="search" placeholder="Search findings" aria-label="Search findings">
  <label class="check"><input id="f-suppressed" type="checkbox"> Show accepted risks</label>
  <span class="f-recs"{recs_hidden}><span class="muted">Records{recs_tip}</span><span class="segmented" role="radiogroup" aria-label="Records"><label><input type="radio" name="f-records" value="" checked>Any</label><label><input type="radio" name="f-records" value="yes">Has a record</label><label><input type="radio" name="f-records" value="no">No record</label></span></span>
  <button id="f-expand" type="button">Expand all</button>
  {group_by}<span id="f-count" class="muted" aria-live="polite"></span>
</div>
{intro_more}"#,
        SEVERITIES
            .iter()
            .map(|s| format!(
                r#"<label class="chip {c}"><input type="checkbox" data-sev="{c}" checked>{}</label>"#,
                sev_label(*s),
                c = sev_class(*s)
            ))
            .collect::<String>(),
        group_by = if r.plan.fixes.is_empty() {
            ""
        } else {
            r#"<span class="group-by" hidden><span class="muted">Group by</span><span class="segmented" role="radiogroup" aria-label="Group by"><label><input type="radio" name="f-group" value="rule" checked>Rule</label><label><input type="radio" name="f-group" value="fix">Step</label></span></span>
  "#
        },
        recs_tip = tip("records", "Records", "A ticket or change opened from a finding."),
        intro = r.introduced.map(intro_picker).unwrap_or_default(),
        intro_more = r.introduced.map(intro_panel).unwrap_or_default(),
        // Only when a finding has a record (the app shows it whenever
        // actions are set up).
        recs_hidden = if r
            .findings
            .iter()
            .any(|f| f.actions.as_ref().is_some_and(|a| !a.records.is_empty()))
        {
            ""
        } else {
            " hidden"
        },
    );

    // Group by rule, most severe groups first.
    let titles: BTreeMap<&str, &str> = crate::findings::rules()
        .iter()
        .map(|r| (r.id, r.title))
        .collect();
    let mut groups: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in r.findings {
        groups.entry(f.rule).or_default().push(f);
    }
    let mut groups: Vec<(&str, Vec<&Finding>)> = groups.into_iter().collect();
    // Anyone can attack a crackable password, so these findings all show
    // the same exposure: rank them by severity, then by how old the
    // password is (the oldest has had the longest to leak or be cracked).
    for (_, fs) in groups.iter_mut() {
        if fs.first().is_some_and(|f| is_weak_account(f)) {
            fs.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then(
                        b.password_age_days
                            .unwrap_or(-1)
                            .cmp(&a.password_age_days.unwrap_or(-1)),
                    )
                    .then(a.title.cmp(&b.title))
            });
        }
    }
    let worst = |fs: &[&Finding]| {
        fs.iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info)
    };
    groups.sort_by(|a, b| {
        worst(&b.1)
            .cmp(&worst(&a.1))
            .then(b.1.len().cmp(&a.1.len()))
            .then(a.0.cmp(b.0))
    });

    fixed_open_card(h, &r.history.fixed_open);
    h.push_str(r#"<div class="rows groups card">"#);
    for (rule, fs) in &groups {
        let title = titles.get(rule).copied().unwrap_or(fs[0].title.as_str());
        let cats: String = {
            let mut c: Vec<Category> = fs.iter().map(|f| f.category).collect();
            c.sort_by_key(|c| category_key(*c));
            c.dedup();
            c.iter()
                .map(|c| {
                    format!(
                        r#"<button type="button" class="cat" data-cat="{}" title="Show only {} findings">{}</button>"#,
                        category_key(*c),
                        category_label(*c).to_lowercase(),
                        category_label(*c)
                    )
                })
                .collect()
        };
        let _ = write!(
            h,
            r#"<details class="row group" id="rule-{rule}" data-rule="{rule}"><summary>{badge}<span class="rule">{rule}</span><span class="title">{title}{set_tag}</span><span class="aside">{cats}<span class="gcount" data-total="{n}">{count}</span>{objects}</span></summary><div class="body">"#,
            rule = esc(rule),
            badge = badge(worst(fs)),
            title = esc(title),
            set_tag = fs
                .iter()
                .filter_map(|f| f.severity_default)
                .max()
                .map(set_chip)
                .unwrap_or_default(),
            n = fs.len(),
            count = plural(fs.len(), "finding", "findings"),
            cats = cats,
            objects = group_objects(fs),
        );
        if let Some(md) = guides::guide(rule) {
            let _ = write!(
                h,
                r#"<details class="row guide" id="guide-{rule}"><summary><span class="guide-label">How to fix this kind of finding</span><span class="aside">step-by-step guide</span></summary><div class="body md">{}</div></details>"#,
                guide_html(md),
                rule = esc(rule)
            );
        }
        for f in fs {
            finding_row(
                h,
                f,
                links.coverage(f),
                !r.plan.fixes.is_empty(),
                r.introduced,
            );
        }
        h.push_str("</div></details>\n");
    }
    h.push_str("</div>");
    if !r.plan.fixes.is_empty() {
        by_fix_view(h, r);
    }
    h.push_str("</section>\n");
}

/// "· 538 computers" on a rule's row, when its findings list more objects
/// than there are findings (one "no LAPS" finding can cover every
/// computer), so the count of findings doesn't understate the scope.
fn group_objects(fs: &[&Finding]) -> String {
    let total: usize = fs.iter().map(|f| f.affected.len()).sum();
    if total <= fs.len() {
        return String::new();
    }
    let Some(kind) = fs.iter().flat_map(|f| &f.affected).map(|a| a.kind).next() else {
        return String::new();
    };
    let same = fs.iter().all(|f| f.affected.iter().all(|a| a.kind == kind));
    let (one, many): (String, String) = match kind {
        _ if !same => ("object".into(), "objects".into()),
        NodeKind::User => ("user".into(), "users".into()),
        NodeKind::Computer => ("computer".into(), "computers".into()),
        NodeKind::Group => ("group".into(), "groups".into()),
        NodeKind::Gpo => ("GPO".into(), "GPOs".into()),
        NodeKind::Ou => ("OU".into(), "OUs".into()),
        // A pack's label ("Entra roles"); a kind without one stays "objects".
        NodeKind::External(_) if kind_label(kind) != kind.as_str() => {
            let label = kind_label(kind);
            (label.to_string(), plural_label(&label))
        }
        _ => ("object".into(), "objects".into()),
    };
    let (one, many) = (esc(&one), esc(&many));
    // The words go along for the findings filter, which recounts the
    // findings it shows (report.js).
    format!(
        r#"<span class="gobjects" title="Affected objects across these findings" data-one="{one}" data-many="{many}"> · {}</span>"#,
        plural(total, &one, &many)
    )
}

/// The Introduced picker in the findings filter bar: a period, with the
/// words for each ([`crate::introduced::Period::describe`]) and what the
/// script needs to work them out (the latest run, when tracking began,
/// when findings were fixed, when paths and members left each zone). For
/// the periods it offers, the summary's lines come from the core as
/// `pathwarden changes` prints them; for a date range the script counts
/// the same things in the same words.
fn intro_picker(i: &crate::introduced::ForReport) -> String {
    use crate::introduced::{Period, TIER_ZERO};
    let fixed: Vec<String> = i.fixed.iter().map(|t| t.to_string()).collect();
    let texts = |p: Period| -> Vec<String> { i.lines(p).into_iter().map(|l| l.text).collect() };
    let mut lines = serde_json::Map::new();
    if i.has_earlier {
        lines.insert("last".into(), texts(Period::LastRun).into());
    }
    lines.insert("7".into(), texts(Period::Days(7)).into());
    lines.insert("30".into(), texts(Period::Days(30)).into());
    // The zones in the order the lines name them, and when edges into each
    // were resolved and members left: [time, zone, how many].
    let mut zones: Vec<&String> = i.zones().map(|(n, _)| n).collect();
    zones.sort_by_key(|n| (n.as_str() != TIER_ZERO, n.to_lowercase()));
    let mut gone: Vec<(i64, &str, usize)> = Vec::new();
    let mut left: Vec<(i64, &str, usize)> = Vec::new();
    for (zone, z) in i.zones() {
        gone.extend(
            z.resolved
                .iter()
                .map(|(t, ks)| (*t, zone.as_str(), ks.len())),
        );
        if let Some(m) = &z.members {
            left.extend(
                m.resolved
                    .iter()
                    .map(|(t, ks)| (*t, zone.as_str(), ks.len())),
            );
        }
    }
    // JSON read back by report.js: valid even with a bidi control in a
    // zone's name (esc shows one as text, which isn't JSON).
    let json = |v: serde_json::Value| crate::text::json_attr(&v.to_string());
    format!(
        r#"<span class="intro-pick" data-at="{at}" data-since="{since}" data-earlier="{earlier}" data-fixed="{fixed}" data-last="{last}" data-d7="{d7}" data-d30="{d30}" data-note="{note}" data-lines="{lines}" data-zones="{zones}" data-gone="{gone}" data-left="{left}"><label for="f-intro">Introduced</label>{tip}<select id="f-intro"><option value="" selected>Any time</option>{last_opt}<option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="range">Date range</option></select><span class="intro-range" hidden><input type="date" id="f-intro-from" aria-label="From"><span aria-hidden="true">&ndash;</span><input type="date" id="f-intro-to" aria-label="To"></span></span>
  "#,
        at = i.latest,
        since = i
            .state
            .tracked_since
            .map(|t| t.to_string())
            .unwrap_or_default(),
        earlier = i.has_earlier,
        fixed = fixed.join(" "),
        last = esc(&i.describe(Period::LastRun)),
        d7 = esc(&i.describe(Period::Days(7))),
        d30 = esc(&i.describe(Period::Days(30))),
        note = esc(&i.note()),
        lines = json(lines.into()),
        zones = json(serde_json::json!(zones)),
        gone = json(serde_json::json!(gone)),
        left = json(serde_json::json!(left)),
        tip = tip(
            "introduced",
            "Introduced",
            "When Pathwarden first saw it, not when it changed in AD. New: first seen in the period. Back: fixed before, back in it. +N objects: an older finding that gained objects in it."
        ),
        last_opt = if i.has_earlier {
            r#"<option value="last">Since the last run</option>"#
        } else {
            ""
        },
    )
}

/// Under the filter bar: what the period holds (the script fills it in),
/// the note when it reaches back before objects were dated, and, once a
/// period is picked, the new members of Tier Zero and the zones and the
/// new paths into them, each path with the step that cuts it and, in the
/// app, a link to Explore.
fn intro_panel(i: &crate::introduced::ForReport) -> String {
    let mut b = String::from(
        r#"<p class="intro-sum" id="f-intro-sum" aria-live="polite" hidden></p><p class="intro-note muted small" id="f-intro-note" hidden></p>"#,
    );
    if i.paths.is_empty() && i.members.is_empty() {
        return b;
    }
    let shown_last = |at: i64| i.has_earlier && at == i.latest;
    // Shown only for a period picked under Introduced (the script): with
    // Any time the findings list stands alone.
    let _ = write!(
        b,
        r#"<section class="card intro-paths" id="intro-paths" aria-labelledby="ip-h" hidden><h3 class="sub" id="ip-h">New in Tier Zero and the zones <span class="ip-when muted" id="ip-when">{when}</span>{tip}</h3>"#,
        when = esc(&i.describe(crate::introduced::Period::LastRun)),
        tip = tip(
            "newpaths",
            "New paths and members",
            "New member: joined Tier Zero or a Privilege Zone. New path: a relationship into one that wasn't there before. Each shows when it was first seen (one that came back is marked back) and the step that cuts it."
        ),
    );
    let explore = |name: &str, node: u32| {
        format!(
            r#"<button type="button" class="ip-xp" data-node="{node}" aria-label="Open {} in Explore" hidden>Open in Explore</button>"#,
            esc(name)
        )
    };
    // Members and paths each in a list of their own, so a group added to
    // Tier Zero with many members does not hide the new paths.
    let back = |b: bool| if b { r#" data-back="1""# } else { "" };
    if i.members.iter().any(|(_, m)| m.named.is_some()) {
        b.push_str(r#"<h4 class="ip-sub">Members</h4><ul class="ip-list ip-mems">"#);
    }
    for (zone, m) in &i.members {
        let Some(n) = &m.named else { continue };
        let via = n
            .via
            .as_ref()
            .map(|g| {
                format!(
                    r#" <span class="muted">as a member of</span> {}"#,
                    object_chip(g, NodeKind::Group)
                )
            })
            .unwrap_or_default();
        let _ = write!(
            b,
            r#"<li class="ip-mem" data-seen="{at}" data-zone="{zone}"{back}{hidden}><span class="ip-zone">{zone}</span><span class="ip-path">{who} <span class="edge">joined</span>{via}</span><span class="ip-meta"><span class="muted">{label}</span>{xp}</span></li>"#,
            at = m.at,
            back = back(m.back),
            hidden = if shown_last(m.at) { "" } else { " hidden" },
            zone = esc(zone),
            who = object_chip(&n.name, n.kind),
            label = esc(&m.label),
            xp = explore(&n.name, n.node),
        );
    }
    if i.members.iter().any(|(_, m)| m.named.is_some()) {
        b.push_str("</ul>");
    }
    if i.paths.iter().any(|(_, p)| p.named.is_some()) {
        b.push_str(r#"<h4 class="ip-sub">Paths</h4><ul class="ip-list ip-paths">"#);
    }
    for (zone, p) in &i.paths {
        let Some(n) = &p.named else { continue };
        let step = match n.cut {
            Some(c) => format!(
                r##"<a class="steplink" href="#{}">{}</a>"##,
                c.step().map_or("plan".to_string(), |n| format!("step-{n}")),
                esc(&c.words())
            ),
            None => r#"<span class="muted">No step cuts it</span>"#.to_string(),
        };
        let _ = write!(
            b,
            r#"<li data-seen="{at}" data-zone="{zone}"{back}{hidden}><span class="ip-zone">{zone}</span><span class="ip-path">{from} <span class="edge">{edge}</span> {to}</span><span class="ip-meta"><span class="muted">{label}</span>{step}{xp}</span></li>"#,
            at = p.at,
            back = back(p.back),
            hidden = if shown_last(p.at) { "" } else { " hidden" },
            zone = esc(zone),
            from = object_chip(&n.from, n.from_kind),
            edge = esc(&n.edge),
            to = object_chip(&n.to, n.to_kind),
            label = esc(&p.label),
            xp = explore(&n.from, n.from_node),
        );
    }
    if i.paths.iter().any(|(_, p)| p.named.is_some()) {
        b.push_str("</ul>");
    }
    b.push_str(r#"<button type="button" class="ip-all" hidden></button>"#);
    if i.paths_more > 0 {
        let _ = write!(
            b,
            r#"<p class="muted small">{} more new paths from earlier runs aren't listed.</p>"#,
            num(i.paths_more)
        );
    }
    b.push_str(r#"<p class="muted small ip-none" hidden>No new members of Tier Zero or the zones, and no new paths into them, in this period.</p></section>"#);
    b
}

/// A finding's dates for the filter (attributes) and its badge for the
/// last run, when it is new in it.
/// A finding's dates: the row's data for the Introduced filter, its badge,
/// and when it was first seen (or came back), in words.
fn intro_row(
    i: &crate::introduced::ForReport,
    t: &crate::state::TrackedFinding,
) -> (String, String, String) {
    use crate::introduced::Badge;
    let gained: Vec<(i64, usize)> = t
        .objects
        .as_ref()
        .map(|o| o.gained_counts())
        .unwrap_or_default();
    let mut data = format!(r#" data-seen="{}""#, t.first_seen);
    if let Some(b) = t.regressed_at {
        let _ = write!(data, r#" data-back="{b}""#);
    }
    if !gained.is_empty() {
        let g: Vec<String> = gained.iter().map(|(t, n)| format!("{t}:{n}")).collect();
        let _ = write!(data, r#" data-gained="{}""#, g.join(" "));
    }
    // Objects that left, by when: "N findings lost objects".
    if let Some(o) = t.objects.as_ref().filter(|o| !o.gone.is_empty()) {
        let l: Vec<String> = o
            .gone
            .iter()
            .map(|(t, ks)| format!("{t}:{}", ks.len()))
            .collect();
        let _ = write!(data, r#" data-lost="{}""#, l.join(" "));
    }
    let badge = i
        .has_earlier
        .then(|| Badge::of(t.first_seen, t.regressed_at, &gained, i.latest, i.latest))
        .flatten();
    // When it was first seen, or came back after a fix, in words on every
    // row: "first seen Oct 18 (run 3)".
    let seen = match t.regressed_at {
        Some(b) => crate::introduced::seen_label(b, true, &i.runs, i.latest),
        None => crate::introduced::seen_label(t.first_seen, false, &i.runs, i.latest),
    };
    let html = format!(
        r#"<span class="ibadge{}" data-ibadge{}>{}</span>"#,
        match badge {
            Some(Badge::New) => " new",
            Some(Badge::Back) => " back",
            Some(Badge::Gained(_)) => " gained",
            None => "",
        },
        if badge.is_none() { " hidden" } else { "" },
        badge.map(|b| esc(&b.label())).unwrap_or_default()
    );
    (data, html, seen)
}

/// One finding; `coverage` is how the remediation path closes it (`None`:
/// it doesn't), and `planned` whether there is a remediation path at all.
/// What the findings search matches, escaped for an attribute. Searchable by
/// the objects too ("where does this user show up?"): affected names and
/// IDs, capped like the lists, and the path's ends.
fn search_text(f: &Finding) -> String {
    let mut search = format!(
        "{} {} {} {}",
        f.rule,
        f.title,
        f.domain.as_deref().unwrap_or(""),
        f.fingerprint
    );
    for a in f.affected.iter().take(1000) {
        let _ = write!(search, " {} {}", a.name, a.id);
    }
    if let Some(p) = &f.path {
        let _ = write!(search, " {}", p.source);
        for s in &p.steps {
            let _ = write!(search, " {}", s.to);
        }
    }
    esc(&search.to_lowercase())
}

/// "Group by: Step": the findings under the remediation path's
/// steps, then those on no path. Hidden until the script shows it; the
/// filters apply to its rows too.
fn by_fix_view(h: &mut String, r: &ReportInput) {
    let g = fix_groups(r.plan, r.findings);
    let changes = r.plan.fixes.len();
    let mut lead = format!(
        "{} every attack path to Tier Zero.",
        plural(changes, "step closes", "steps close")
    );
    let closed = g.closed();
    let cut = g.cut_only();
    if closed + cut > 0 {
        let _ = write!(
            lead,
            " They close {}{}.",
            plural(closed, "finding", "findings"),
            if cut > 0 {
                format!(" and take {} more off every path", num(cut))
            } else {
                String::new()
            }
        );
    }
    if !g.alone.is_empty() {
        let _ = write!(
            lead,
            " {} on no path a step cuts; each needs its own fix.",
            if g.alone.len() == 1 {
                "1 finding is".to_string()
            } else {
                format!("{} findings are", num(g.alone.len()))
            }
        );
    }
    lead.push_str(" Changes that take care of the most findings come first.");
    let _ = write!(
        h,
        r#"<div class="byfix" hidden><p class="lead">{}</p><div class="rows card">"#,
        esc(&lead)
    );
    for grp in &g.groups {
        let all: Vec<&Finding> = grp.closes.iter().chain(&grp.cuts).copied().collect();
        let cuts_note = if grp.cuts.iter().any(|f| is_weak_account(f)) {
            r#"<p class="scope">The step cuts their attack path. A weak account (Kerberoastable or AS-REP roastable) stays weak, so it still needs its own fix.</p>"#
        } else {
            ""
        };
        let _ = write!(
            h,
            r##"<details class="row step fixgroup"><summary><span class="stepnum">{n}</span><span class="steptext"><span class="action">{action}</span><span class="rel muted small">Step {n} · {exposed} a path through it</span></span><span class="aside">{sevs}<span class="gcount" data-total="{total}">{count}</span></span></summary><div class="body">{closes}{cuts}<p class="small"><a href="#step-{n}">See step {n} in the remediation path</a></p></div></details>"##,
            n = grp.step,
            action = step_headline(grp.fix),
            exposed = plural(grp.fix.principals_through, "account has", "accounts have"),
            sevs = sev_counts(&all),
            total = all.len(),
            count = plural(all.len(), "finding", "findings"),
            closes = fix_list("Closes", "", &grp.closes),
            cuts = fix_list("Cuts the attack path", cuts_note, &grp.cuts),
        );
    }
    if !g.alone.is_empty() {
        let _ = write!(
            h,
            r#"<details class="row step fixgroup alone"><summary><span class="stepnum"><span aria-hidden="true">–</span><span class="vh">No step</span></span><span class="steptext"><span class="action">Fix directly</span><span class="rel muted small">Each needs its own fix. See "How to fix it" in the finding.</span></span><span class="aside">{}<span class="gcount" data-total="{}">{}</span></span></summary><div class="body">{}</div></details>"#,
            sev_counts(&g.alone),
            g.alone.len(),
            plural(g.alone.len(), "finding", "findings"),
            fix_list("", "", &g.alone),
        );
    }
    h.push_str("</div>");
    if g.without_findings > 0 {
        let _ = write!(
            h,
            r##"<p class="scope">{}; see the <a href="#plan">remediation path</a>.</p>"##,
            if g.without_findings == 1 {
                "1 other step cuts paths but has no finding of its own".to_string()
            } else {
                format!(
                    "{} other steps cut paths but have no finding of their own",
                    num(g.without_findings)
                )
            }
        );
    }
    h.push_str("</div>");
}

/// "9 Critical 1 High": how many findings of each severity, most severe
/// first.
fn sev_counts(fs: &[&Finding]) -> String {
    SEVERITIES
        .iter()
        .filter_map(|s| {
            let n = fs.iter().filter(|f| f.severity == *s).count();
            (n > 0).then(|| {
                format!(
                    r#"<span class="badge {c}"><span class="dot" aria-hidden="true"></span>{n} {}</span>"#,
                    sev_label(*s),
                    c = sev_class(*s),
                    n = num(n)
                )
            })
        })
        .collect()
}

/// A titled list of findings as links, each carrying what the filters match.
fn fix_list(title: &str, note: &str, fs: &[&Finding]) -> String {
    if fs.is_empty() {
        return String::new();
    }
    let items: String = fs
        .iter()
        .map(|f| {
            format!(
                r##"<li data-sev="{sev}" data-cat="{cat}" data-suppressed="false" data-text="{text}"><a href="#f-{fp}">{badge}<span class="rule">{rule}</span><span class="rt">{title}</span>{arrow}</a></li>"##,
                sev = sev_class(f.severity),
                cat = category_key(f.category),
                text = search_text(f),
                fp = esc(&f.fingerprint),
                badge = badge(f.severity),
                rule = esc(f.rule),
                title = esc(&f.title),
                arrow = icon("i-arrow"),
            )
        })
        .collect();
    let head = if title.is_empty() {
        String::new()
    } else {
        format!("<h4>{title}</h4>")
    };
    format!(r#"{head}{note}<ul class="related">{items}</ul>"#)
}

/// With `intro`, the finding's dates for the Introduced filter: when it was
/// first seen and came back, how many objects it gained when, a badge for
/// the last run, and its objects dated.
fn finding_row(
    h: &mut String,
    f: &Finding,
    coverage: Option<&Coverage>,
    planned: bool,
    intro: Option<&crate::introduced::ForReport>,
) {
    // Short form for the row, full sentence for the details. A crackable
    // password is exposed to everyone alike, so its row shows the
    // password's age instead (what the group is sorted by).
    let exposure = if is_weak_account(f) {
        Some(match f.password_age_days {
            Some(d) => format!(
                r#"<span class="expo" title="Days since the password was last set">password <strong>{}</strong> old</span>"#,
                plural(d.max(0) as usize, "day", "days")
            ),
            None => r#"<span class="expo">password age unknown</span>"#.to_string(),
        })
    } else {
        f.exposure.as_ref().map(|e| {
            format!(
                r#"<span class="expo"><strong>{}</strong> exposed</span>"#,
                pct(e.percent)
            )
        })
    };
    let exposure_full = f.exposure.as_ref().map(|e| {
        format!(
            "{} ({} of {} active users and computers{})",
            pct(e.percent),
            num(e.principals),
            num(e.population),
            e.scope
                .as_ref()
                .map(|d| format!(" in {d}"))
                .unwrap_or_default()
        )
    });
    // How the remediation path deals with it: a short tag on the row, a
    // sentence with links to the steps in the details.
    let (tag, note) = plan_note(f, coverage, planned);
    let aside = match (tag.is_empty(), exposure.as_deref()) {
        (true, None) => String::new(),
        (_, e) => format!(
            r#"<span class="aside">{tag}{}</span>"#,
            e.unwrap_or_default()
        ),
    };
    // A finding that is a list of objects (no path to draw) shows the list
    // as its main content; others keep it collapsed under the path.
    let list_style = f.path.as_ref().is_none_or(|p| p.steps.is_empty()) && !f.affected.is_empty();
    let search = search_text(f);
    let dated = intro.and_then(|i| Some((i, i.finding(&f.fingerprint)?)));
    let (intro_data, intro_badge, seen) = match dated {
        Some((i, t)) => intro_row(i, t),
        None => (String::new(), String::new(), String::new()),
    };
    let (seen_line, seen_fact) = if seen.is_empty() {
        (String::new(), String::new())
    } else {
        let (term, when) = match seen.strip_prefix("back ") {
            Some(w) => ("Back after a fix", w),
            None => (
                "First seen",
                seen.strip_prefix("first seen ").unwrap_or(&seen),
            ),
        };
        (
            format!(r#"<span class="seen">{}</span>"#, esc(&seen)),
            format!("<div><dt>{term}</dt><dd>{}</dd></div>", esc(when)),
        )
    };
    // The objects' dates, by object ID: those it gained after its baseline.
    let stamps: Option<std::collections::HashMap<&str, (i64, String)>> =
        dated.and_then(|(i, t)| {
            let by_key = t.objects.as_ref()?.stamps();
            Some(
                f.affected
                    .iter()
                    .filter_map(|a| {
                        let (at, back) =
                            by_key.get(crate::introduced::object_key(&a.id).as_str())?;
                        Some((a.id.as_str(), (*at, i.label(*at, *back))))
                    })
                    .collect(),
            )
        });
    let stamps = stamps.as_ref();
    let _ = write!(
        h,
        r#"<details class="row finding" id="f-{fp}" data-sev="{sev}" data-cat="{category}" data-suppressed="{sup}" data-objects="{objects}" data-records="{records}" data-text="{search}"{intro_data}>
<summary>{badge}<span class="title">{intro_badge}{title}{ar_tag}{set_tag}{seen_line}{ac_chips}</span>{exp}</summary>
<div class="body">
<dl class="facts">{sevfact}<div><dt>Category</dt><dd>{cat}</dd></div>{expfact}<div><dt>Domain</dt><dd>{domain}</dd></div>{seen_fact}<div><dt>Finding ID</dt><dd><code>{id}</code></dd></div>{supfact}</dl>
{note}{activity}<h4>Why it matters</h4><p>{summary}</p>
{listed}<h4 id="fix-{fp}">How to fix it</h4><p>{fix}</p>
"#,
        fp = esc(&f.fingerprint),
        sev = sev_class(f.severity),
        category = category_key(f.category),
        sup = f.suppressed.is_some(),
        objects = f.affected.len(),
        // search_text escapes it already.
        search = search,
        badge = badge(f.severity),
        title = esc(&f.title),
        ar_tag = accepted_tag(f),
        ac_chips = action_chips(f),
        records = f.actions.as_ref().map_or(0, |a| a.records.len()),
        activity = action_activity(f),
        set_tag = f.severity_default.map(set_chip).unwrap_or_default(),
        sevfact = f
            .severity_default
            .map(|d| format!(
                "<div><dt>Severity</dt><dd>{} &middot; set by your team &middot; default {}</dd></div>",
                sev_label(f.severity),
                sev_label(d)
            ))
            .unwrap_or_default(),
        exp = aside,
        cat = category_label(f.category),
        expfact = exposure_full
            .as_deref()
            .map(|e| format!("<div><dt>Exposure</dt><dd>{}</dd></div>", esc(e)))
            .unwrap_or_default(),
        domain = esc(f.domain.as_deref().unwrap_or("-")),
        id = esc(&f.fingerprint),
        supfact = f
            .suppressed
            .as_deref()
            .map(|s| accepted_fact(s, f.accepted.as_ref()))
            .unwrap_or_default()
            + &sources_fact(&f.sources),
        summary = text_with_code(&f.summary),
        listed = if list_style {
            affected_html(&f.affected, f.domain.as_deref(), stamps)
        } else {
            String::new()
        },
        fix = text_with_code(&f.remediation),
    );
    if let Some(p) = f.path.as_ref().filter(|p| !p.steps.is_empty()) {
        h.push_str("<h4>Attack path</h4>");
        h.push_str(&diagram::path_svg(p));
        h.push_str(
            r#"<p class="pathkey muted small"><span class="k start"></span>start <span class="k target"></span>target</p><details class="more"><summary>Path as text</summary><ol class="path">"#,
        );
        if let Some(first) = p.steps.first() {
            let _ = write!(
                h,
                r#"<li><span class="obj">{}</span> <span class="muted">({})</span></li>"#,
                esc(&first.from),
                esc(&kind_label(first.from_kind))
            );
        }
        for s in &p.steps {
            let via = s
                .source
                .as_deref()
                .map(|src| format!(r#" <span class="muted">via {}</span>"#, esc(src)))
                .unwrap_or_default();
            let _ = write!(
                h,
                r#"<li><span class="edge">{}</span> <span class="obj">{}</span> <span class="muted">({})</span>{via}</li>"#,
                esc(s.edge.as_str()),
                esc(&s.to),
                esc(&kind_label(s.to_kind))
            );
        }
        h.push_str("</ol></details>");
    }
    if !list_style && !f.affected.is_empty() {
        let _ = write!(
            h,
            r#"<details class="more"><summary>Affected objects ({})</summary>{}</details>"#,
            num(f.affected.len()),
            affected_html(&f.affected, f.domain.as_deref(), stamps)
        );
    }
    let _ = write!(
        h,
        r##"<p class="links"><a href="#guide-{rule}">Step-by-step guide for {rule}</a>"##,
        rule = esc(f.rule)
    );
    for link in &f.references {
        let _ = write!(
            h,
            r#" &middot; <a href="{0}" rel="noreferrer">{0}</a>"#,
            esc(link)
        );
    }
    h.push_str("</p></div></details>\n");
}

/// Findings about an account that is weak in itself (a crackable
/// password): cutting its path lowers the risk but leaves the weakness.
fn is_weak_account(f: &Finding) -> bool {
    matches!(f.rule, "PW-006" | "PW-007")
}

/// The remediation path's part in a finding: a tag for its row ("Step 3",
/// "Fix directly") and a sentence for its details, with links to the steps.
/// Accepted risks get neither.
fn plan_note(f: &Finding, coverage: Option<&Coverage>, planned: bool) -> (String, String) {
    if f.suppressed.is_some() {
        return (String::new(), String::new());
    }
    match coverage {
        Some(c) => {
            let steps = if c.closed_by.is_empty() {
                &c.cut_by
            } else {
                &c.closed_by
            };
            let tag = format!(
                r#"<span class="ptag ok" title="{}">{}: {} {}</span>"#,
                if c.closed_by.is_empty() {
                    "The remediation path cuts this finding's attack path"
                } else {
                    "The remediation path closes this finding"
                },
                if c.closed_by.is_empty() {
                    "Path cut"
                } else {
                    "Closed"
                },
                if steps.len() == 1 { "step" } else { "steps" },
                steps
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let note = if c.closed_by.is_empty() {
                format!(
                    r#"<p class="plannote ok">Its attack path is cut by {}.{}</p>"#,
                    step_links(&c.cut_by),
                    if is_weak_account(f) {
                        " The account itself stays weak until it is fixed (see How to fix it), and could become a path again."
                    } else {
                        ""
                    }
                )
            } else {
                format!(
                    r#"<p class="plannote ok">Closed by {}.</p>"#,
                    step_links(&c.closed_by)
                )
            };
            (tag, note)
        }
        None => (
            r#"<span class="ptag" title="No remediation path step closes this finding">Fix directly</span>"#.to_string(),
            format!(
                r##"<p class="plannote direct">{} Fix it directly: see <a href="#fix-{}">How to fix it</a>.</p>"##,
                if planned {
                    "No step closes it."
                } else {
                    "No account outside Tier Zero reaches Tier Zero, so there is no remediation path."
                },
                esc(&f.fingerprint)
            ),
        ),
    }
}

/// A guide rendered from Markdown, without its title (the group row says
/// what it is) and with headings demoted under the group.
fn guide_html(md: &str) -> String {
    let body_md = md.split_once('\n').map_or("", |(_, rest)| rest);
    let mut body = String::new();
    let events = pulldown_cmark::Parser::new_ext(body_md, pulldown_cmark::Options::ENABLE_TABLES)
        .map(|e| match e {
            pulldown_cmark::Event::Start(pulldown_cmark::Tag::Heading {
                level,
                id,
                classes,
                attrs,
            }) => pulldown_cmark::Event::Start(pulldown_cmark::Tag::Heading {
                level: demote(level),
                id,
                classes,
                attrs,
            }),
            pulldown_cmark::Event::End(pulldown_cmark::TagEnd::Heading(level)) => {
                pulldown_cmark::Event::End(pulldown_cmark::TagEnd::Heading(demote(level)))
            }
            // Guides are our own content, but never pass raw HTML through.
            pulldown_cmark::Event::Html(t) | pulldown_cmark::Event::InlineHtml(t) => {
                pulldown_cmark::Event::Text(t)
            }
            other => other,
        });
    pulldown_cmark::html::push_html(&mut body, events);
    body
}

fn demote(level: pulldown_cmark::HeadingLevel) -> pulldown_cmark::HeadingLevel {
    use pulldown_cmark::HeadingLevel::*;
    match level {
        H1 | H2 => H4,
        H3 => H5,
        _ => H6,
    }
}

/// Affected objects grouped by kind ("Users · 43"), names sorted, the first
/// few shown and the rest behind "Show N more", each with its detail (last
/// logon, password age) when the rule gives one. A copy button (when
/// JavaScript runs) copies every listed name, one per line.
/// `stamps`: when objects appeared, by ID, with how to say it ("first seen
/// Oct 18 (run 3)"): those come first, the newest first, labeled.
fn affected_html(
    affected: &[crate::findings::Affected],
    domain: Option<&str>,
    stamps: Option<&std::collections::HashMap<&str, (i64, String)>>,
) -> String {
    const ORDER: [(NodeKind, &str, &str); 9] = [
        (NodeKind::User, "user", "users"),
        (NodeKind::Computer, "computer", "computers"),
        (NodeKind::Group, "group", "groups"),
        (NodeKind::Domain, "domain", "domains"),
        (NodeKind::Ou, "OU", "OUs"),
        (NodeKind::Gpo, "GPO", "GPOs"),
        (NodeKind::Container, "container", "containers"),
        (
            NodeKind::CertTemplate,
            "certificate template",
            "certificate templates",
        ),
        (
            NodeKind::EnterpriseCa,
            "certification authority",
            "certification authorities",
        ),
    ];
    let stamp = |a: &crate::findings::Affected| stamps.and_then(|s| s.get(a.id.as_str()));
    // Objects that appeared after the baseline first, so the cap below
    // never hides them.
    let mut ordered: Vec<&crate::findings::Affected> = affected.iter().collect();
    if stamps.is_some_and(|s| !s.is_empty()) {
        ordered.sort_by_key(|a| std::cmp::Reverse(stamp(a).map(|s| s.0)));
    }
    let shown = &ordered[..affected.len().min(AFFECTED_MAX)];
    // Native kinds in ORDER, then each external kind on its own (by name),
    // then any other object.
    let mut groups: BTreeMap<(usize, &'static str), Vec<&crate::findings::Affected>> =
        BTreeMap::new();
    for &a in shown {
        let slot = match a.kind {
            NodeKind::External(_) => (ORDER.len(), a.kind.as_str()),
            k => (
                ORDER
                    .iter()
                    .position(|(o, _, _)| *o == k)
                    .unwrap_or(ORDER.len() + 1),
                "",
            ),
        };
        groups.entry(slot).or_default().push(a);
    }
    // Names in the finding's own domain drop the suffix (it's in the
    // finding); the full name stays in the tooltip and in "Copy names".
    let short = |a: &crate::findings::Affected| -> String {
        let name = &a.name;
        domain
            .and_then(|d| {
                name.strip_suffix(&format!("@{d}"))
                    .or_else(|| name.strip_suffix(&format!(".{d}")))
            })
            .filter(|s| !s.is_empty())
            .map(|s| {
                format!(
                    r#"<span class="nm" title="{}">{}</span>"#,
                    esc(name),
                    esc(s)
                )
            })
            .unwrap_or_else(|| name_html_kind(name, Some(a.kind)))
    };
    let item = |a: &crate::findings::Affected| {
        let (seen, when) = match stamp(a) {
            Some((at, label)) => (
                format!(r#" data-seen="{at}""#),
                format!(r#"<span class="aseen">{}</span>"#, esc(label)),
            ),
            None => (String::new(), String::new()),
        };
        format!(
            r#"<li data-name="{}"{seen}>{}{when}{}</li>"#,
            esc(&a.name),
            short(a),
            a.detail
                .as_deref()
                .map(|d| format!(r#"<span class="adetail">{}</span>"#, esc(d)))
                .unwrap_or_default()
        )
    };
    // A group holding objects new to the finding comes first (the newest
    // first), so a new computer isn't listed after every older user.
    let mut groups: Vec<((usize, &str), Vec<&crate::findings::Affected>)> =
        groups.into_iter().collect();
    groups.sort_by_key(|(slot, list)| {
        (
            std::cmp::Reverse(list.iter().filter_map(|a| stamp(a).map(|s| s.0)).max()),
            *slot,
        )
    });
    let mut h = String::from(r#"<div class="affected">"#);
    for ((slot, _), mut list) in groups {
        list.sort_by(|a, b| {
            stamp(b)
                .map(|s| s.0)
                .cmp(&stamp(a).map(|s| s.0))
                .then(a.name.cmp(&b.name))
        });
        let n = list.len();
        let (kind, label) = match (ORDER.get(slot), list[0].kind) {
            (Some(&(kind, one, many)), _) => (kind, if n == 1 { one } else { many }.to_string()),
            // An external kind: its pack's label ("Entra roles"); a kind
            // without one keeps its name.
            (None, kind @ NodeKind::External(_)) => {
                let label = kind_label(kind);
                if n == 1 || label == kind.as_str() {
                    (kind, label.into_owned())
                } else {
                    (kind, plural_label(&label))
                }
            }
            (None, _) => (
                NodeKind::Base,
                if n == 1 { "object" } else { "objects" }.to_string(),
            ),
        };
        let mut label = label;
        if let Some(first) = label.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        let _ = write!(
            h,
            r#"<div class="agroup"><h5>{}{} <span class="acount">{}</span></h5><ul class="alist">"#,
            kind_icon(kind),
            esc(&label),
            num(n)
        );
        for a in list.iter().take(AFFECTED_VISIBLE) {
            h.push_str(&item(a));
        }
        h.push_str("</ul>");
        if list.len() > AFFECTED_VISIBLE {
            let _ = write!(
                h,
                r#"<details class="amore"><summary>Show {} more</summary><ul class="alist">"#,
                num(list.len() - AFFECTED_VISIBLE)
            );
            for a in list.iter().skip(AFFECTED_VISIBLE) {
                h.push_str(&item(a));
            }
            h.push_str("</ul></details>");
        }
        h.push_str("</div>");
    }
    if affected.len() > AFFECTED_MAX {
        let _ = write!(
            h,
            r#"<p class="muted small">{} more aren't listed in this report.</p>"#,
            num(affected.len() - AFFECTED_MAX)
        );
    }
    let _ = write!(
        h,
        r#"<button type="button" class="copy-names">{}<span>Copy {}</span></button></div>"#,
        icon("i-copy"),
        if shown.len() == 1 { "name" } else { "names" }
    );
    h
}

// ------------------------------------------------------------- Environment

/// The Environment tab's Rule settings: the rules whose severity the team
/// set for this run, with their default and who set them. Nothing when
/// none was set.
fn rule_settings_row(h: &mut String, p: &Posture) {
    let set = &p.severities_set;
    if set.is_empty() {
        return;
    }
    let levels: BTreeMap<String, Severity> =
        set.iter().map(|s| (s.rule.clone(), s.severity)).collect();
    let by_exposure = crate::findings::severity_settings_key(true, &levels) == p.severity_settings;
    let _ = write!(
        h,
        r#"<details class="row env" id="env-severities" open><summary><span class="title">Rule settings</span><span class="aside">{} set by your team</span></summary><div class="body"><table class="sev-set"><thead><tr><th>Rule</th><th>Severity</th><th>Default</th><th>Set by</th></tr></thead><tbody>"#,
        plural(set.len(), "severity", "severities")
    );
    for s in set {
        let default = match s.default.as_str() {
            "exposure" => "By exposure".to_string(),
            "" => "-".to_string(),
            d => esc(d),
        };
        let who = match (&s.by, &s.at) {
            (Some(b), Some(a)) => format!("{} on {}", esc(b), esc(&stamp_date(a))),
            (Some(b), None) => esc(b),
            (None, Some(a)) => format!("on {}", esc(&stamp_date(a))),
            (None, None) => r#"<span class="muted">Not recorded</span>"#.to_string(),
        };
        let _ = write!(
            h,
            r#"<tr><td><span class="rid">{}</span> {}</td><td>{}</td><td>{default}</td><td>{who}</td></tr>"#,
            esc(&s.rule),
            esc(&s.title),
            badge(s.severity),
        );
    }
    let _ = write!(
        h,
        r#"</tbody></table><p class="muted small">A set severity applies to every finding of the rule. Other attack path rules are rated {}.</p></div></details>"#,
        if by_exposure {
            "by exposure"
        } else {
            "by rule"
        }
    );
}

fn environment_section(h: &mut String, r: &ReportInput) {
    panel_open(h, "environment", "Collection");
    h.push_str(r#"<div class="rows card">"#);
    rule_settings_row(h, r.posture);

    // Protected zones.
    let t0 = &r.posture.tier_zero;
    let zones = r.posture.zones.len();
    let _ = write!(
        h,
        r#"<details class="row env"><summary><span class="title">Tier Zero and Privilege Zones</span><span class="aside">{}Tier Zero protected: {}</span></summary><div class="body"><table class="zones"><thead><tr><th>Zone</th><th class="num">Objects</th><th>Accounts with an attack path</th><th class="num">Protected</th></tr></thead><tbody>"#,
        if zones > 0 {
            format!("{} &middot; ", plural(zones, "zone", "zones"))
        } else {
            String::new()
        },
        crate::posture::protected_words(t0.objects, t0.objects_with_findings),
    );
    for z in std::iter::once(t0).chain(&r.posture.zones) {
        zone_row(h, z);
    }
    h.push_str(r#"</tbody></table><p class="muted small">Protected: the share of a zone's objects that no open attack path finding leads to.</p></div></details>"#);

    // Collection completeness.
    if !r.posture.completeness.is_empty() {
        let low = r
            .posture
            .completeness
            .iter()
            .filter(|d| d.is_low() || d.gpo_local_groups == Some(false))
            .count();
        let active = r.posture.completeness.iter().all(|c| c.active_only);
        let untargeted = crate::posture::untargeted(&r.posture.completeness);
        // The services column, when any domain has service data or
        // had the reads turned off.
        let services = r
            .posture
            .completeness
            .iter()
            .any(|c| c.stored_credentials_collected.is_some() || c.stored_credentials_off);
        let any_off = r
            .posture
            .completeness
            .iter()
            .any(|c| c.stored_credentials_off);
        // The tasks column, likewise.
        let tasks = r
            .posture
            .completeness
            .iter()
            .any(|c| c.task_credentials_collected.is_some() || c.task_credentials_off);
        let tasks_off = r
            .posture
            .completeness
            .iter()
            .any(|c| c.task_credentials_off);
        let mut aside = Vec::new();
        if low > 0 {
            aside.push(format!("{} below 80%", plural(low, "domain", "domains")));
        }
        if let Some(chip) = untargeted.chip() {
            aside.push(chip);
        }
        if aside.is_empty() {
            aside.push("every domain at 80% or more".to_string());
        }
        let _ = write!(
            h,
            r#"<details class="row env" open><summary><span class="title">Collection completeness</span><span class="aside{}">{}</span></summary><div class="body"><p class="muted">{}.{}{}{}{}</p><table><thead><tr><th>Domain</th><th class="num">Computers</th><th>Sessions collected</th><th>Local groups collected (member computers)</th><th>GPO local groups</th>{}{}</tr></thead><tbody>"#,
            if low > 0 { " warn" } else { "" },
            aside.join(" &middot; "),
            if active {
                "Computers active in the 14 days before collection"
            } else {
                "All enabled computers (sign-in times were unavailable)"
            },
            tip(
                "completeness",
                "Collection completeness",
                "Paths through sessions and local administrator rights are only as complete as these numbers; without GPO local groups, admin rights granted by Group Policy are missing. Local groups count member computers only: a domain controller's local groups are already in the directory."
            ),
            if untargeted.any() {
                format!(" {}", crate::posture::NOT_TARGETED_DEF)
            } else {
                String::new()
            },
            match (services, any_off) {
                (false, _) => String::new(),
                (true, false) => format!(" {}", crate::posture::STORED_CREDENTIALS_DEF),
                (true, true) => format!(
                    " {} {}",
                    crate::posture::STORED_CREDENTIALS_DEF,
                    crate::posture::STORED_CREDENTIALS_OFF_DEF
                ),
            },
            match (tasks, tasks_off) {
                (false, _) => String::new(),
                (true, false) => format!(" {}", crate::posture::TASK_CREDENTIALS_DEF),
                (true, true) => format!(
                    " {} {}",
                    crate::posture::TASK_CREDENTIALS_DEF,
                    crate::posture::TASK_CREDENTIALS_OFF_DEF
                ),
            },
            if services {
                "<th>Services read</th>"
            } else {
                ""
            },
            if tasks { "<th>Tasks read</th>" } else { "" }
        );
        for d in &r.posture.completeness {
            let cell = |n: usize, of: usize, p: f64| {
                format!(
                    r#"<td><div class="cmeter{}"><span style="width:{:.1}%"></span></div> {n}/{of} ({})</td>"#,
                    if p < LOW_PERCENT { " low" } else { "" },
                    p,
                    crate::posture::share_percent(p)
                )
            };
            const NOT_TARGETED: &str = r#"<td class="muted">Not collected</td>"#;
            let groups = match d.local_groups_na() {
                None if !d.local_groups_targeted => NOT_TARGETED.to_string(),
                None => cell(
                    d.local_groups_collected,
                    d.member_computers,
                    d.local_groups_percent,
                ),
                Some(why) => format!(r#"<td class="muted">n/a ({why})</td>"#),
            };
            let gpo = match d.gpo_local_groups {
                Some(true) => "<td>collected</td>",
                Some(false) => r#"<td class="warn">not collected</td>"#,
                None => r#"<td class="muted">not recorded</td>"#,
            };
            // The services and tasks cells: a share, "off", or not recorded.
            let read_cell = |shown: bool, off: bool, read: Option<usize>| match (shown, off, read) {
                (false, _, _) => String::new(),
                (true, true, _) => format!(
                    r#"<td class="muted">{}</td>"#,
                    crate::posture::STORED_CREDENTIALS_OFF
                ),
                (true, false, Some(n)) => cell(
                    n,
                    d.computers,
                    if d.computers == 0 {
                        0.0
                    } else {
                        100.0 * n as f64 / d.computers as f64
                    },
                ),
                (true, false, None) => r#"<td class="muted">not recorded</td>"#.to_string(),
            };
            let stored = read_cell(
                services,
                d.stored_credentials_off,
                d.stored_credentials_collected,
            );
            let task_cell = read_cell(tasks, d.task_credentials_off, d.task_credentials_collected);
            let _ = write!(
                h,
                "<tr><td>{}</td><td class=\"num\">{}</td>{}{}{gpo}{stored}{task_cell}</tr>",
                esc(&d.domain),
                d.computers,
                if d.sessions_targeted {
                    cell(d.sessions_collected, d.computers, d.sessions_percent)
                } else {
                    NOT_TARGETED.to_string()
                },
                groups
            );
        }
        h.push_str("</tbody></table>");
        // Computers the collector skipped (Kerberos only, required SMB
        // signing): one line per domain that has any.
        let several = r.posture.completeness.len() > 1;
        for d in &r.posture.completeness {
            if let Some(words) = d.skipped_words() {
                let _ = write!(
                    h,
                    r#"<p class="muted small">{}{}</p>"#,
                    if several {
                        format!("{}: ", esc(&d.domain))
                    } else {
                        String::new()
                    },
                    esc(&words)
                );
            }
        }
        h.push_str("</div></details>");
    }

    // SYSVOL (built-in collector only).
    if !r.posture.sysvol.is_empty() {
        use crate::sysvol::CheckStatus;
        let short = r
            .posture
            .sysvol
            .iter()
            .filter(|d| {
                [&d.checks.gpo_acl, &d.checks.logon_script_acl, &d.checks.gpp]
                    .iter()
                    .any(|c| c.status != CheckStatus::Complete)
            })
            .count();
        let _ = write!(
            h,
            r#"<details class="row env" open><summary><span class="title">SYSVOL and NETLOGON</span><span class="aside{}">{}</span></summary><div class="body"><p class="muted">Read from one domain controller. Parts not read can't show problems; their findings stay open.</p><table><thead><tr><th>Domain</th><th>GPO folder permissions</th><th>Logon script permissions</th><th>GPP passwords</th></tr></thead><tbody>"#,
            if short > 0 { " warn" } else { "" },
            if short > 0 {
                format!("{} not fully read", plural(short, "domain", "domains"))
            } else {
                "fully read".to_string()
            }
        );
        for d in &r.posture.sysvol {
            let cell = |c: &crate::sysvol::Check, what: &str| {
                let mut t = format!("{} ({} {what}", c.status.label(), c.read);
                if c.failed > 0 {
                    let _ = write!(t, ", {} failed", c.failed);
                }
                if c.skipped > 0 {
                    let _ = write!(t, ", {} skipped", c.skipped);
                }
                t.push(')');
                if let Some(reason) = &c.reason {
                    let _ = write!(t, ": {reason}");
                }
                format!(
                    "<td{}>{}</td>",
                    if c.status == CheckStatus::Complete {
                        ""
                    } else {
                        r#" class="warn""#
                    },
                    esc(&t)
                )
            };
            let _ = write!(
                h,
                "<tr><td>{}</td>{}{}{}</tr>",
                esc(&d.domain),
                cell(&d.checks.gpo_acl, "folders"),
                cell(&d.checks.logon_script_acl, "scripts"),
                cell(&d.checks.gpp, "files"),
            );
        }
        h.push_str("</tbody></table></div></details>");
    }

    // AD CS checks the collection could not support. A value from a
    // settings file over 90 days old is a gap too: it can't show a fix.
    use crate::dcsettings::FileAge;
    let stale_file = |c: &crate::posture::AdcsCompleteness| {
        c.esc6_file == Some(FileAge::Stale) || c.esc11_file == Some(FileAge::Stale)
    };
    let adcs_gaps = r
        .posture
        .adcs
        .iter()
        .filter(|c| !(c.published_templates && c.esc6 && c.esc11 && c.esc13) || stale_file(c))
        .count();
    if adcs_gaps > 0 {
        let _ = write!(
            h,
            r#"<details class="row env" open><summary><span class="title">AD CS data</span><span class="aside warn">{} not fully checked</span></summary><div class="body"><p class="muted">Checks this collection couldn't run. "Not checked" means unknown, not safe.</p><table><thead><tr><th>Enterprise CA</th><th>Published templates</th><th>ESC6 (CA registry)</th><th>ESC11 (CA registry)</th><th>ESC13 (issuance policies)</th></tr></thead><tbody>"#,
            plural(adcs_gaps, "CA", "CAs")
        );
        let cell = |ok: bool, missing: &str| {
            if ok {
                "<td>collected</td>".to_string()
            } else {
                format!(r#"<td class="warn">{}</td>"#, esc(missing))
            }
        };
        // ESC6 and ESC11 may come from a Tier Zero settings file.
        let reg = |ok: bool, file: Option<FileAge>| match file {
            Some(FileAge::Current) => "<td>from its settings file</td>".to_string(),
            Some(FileAge::Stale) => {
                r#"<td class="warn">settings file over 90 days old</td>"#.to_string()
            }
            None => cell(ok, "not checked"),
        };
        for c in &r.posture.adcs {
            let _ = write!(
                h,
                "<tr><td>{}</td>{}{}{}{}</tr>",
                esc(&c.ca_name),
                cell(
                    c.published_templates,
                    "not collected: all templates counted as published"
                ),
                reg(c.esc6, c.esc6_file),
                reg(c.esc11, c.esc11_file),
                cell(c.esc13, "not checked"),
            );
        }
        h.push_str("</tbody></table></div></details>");
    }

    // Tier Zero settings: the registry values only a settings file gives,
    // for the domain controllers (ESC9, ESC10) and the Enterprise CAs
    // (ESC6, ESC11).
    h.push_str(&tier_zero_settings_row(
        &r.posture.dc_settings,
        &r.posture.ca_settings,
    ));
    // The management agents on the Tier Zero hosts.
    h.push_str(&host_agents_row(&r.posture.host_agents));

    // Trusts.
    let s = r.stats;
    if !s.trusts.is_empty() {
        // Each trust once: with both of its domains collected, both list it.
        let trusts = crate::ingest::distinct_trusts(&s.trusts);
        let unfiltered = trusts
            .iter()
            .filter(|(t, other)| {
                !(t.sid_filtering && other.is_none_or(|o| o.sid_filtering))
                    && matches!(
                        t.trust_type.to_ascii_lowercase().as_str(),
                        "forest" | "external"
                    )
            })
            .count();
        // With the forest map (its words filled in), what stands out is its
        // headline's: SID history abuse, or PW-012 where the data can't tell.
        let map = r.forest.map(|m| m.document());
        let (warn, aside) = match &map {
            Some(d) => {
                let said: Vec<String> = d
                    .headline
                    .status
                    .iter()
                    .filter(|s| s.kind != "none")
                    .map(|s| format!(" &middot; {}", esc(&s.text)))
                    .collect();
                (!said.is_empty(), said.concat())
            }
            None if unfiltered > 0 => (
                true,
                format!(" &middot; {unfiltered} to other forests without SID filtering"),
            ),
            None => (false, String::new()),
        };
        let _ = write!(
            h,
            r#"<details class="row env"><summary><span class="title">Trusts</span><span class="aside{}">{}{}</span></summary><div class="body"><table><thead><tr><th>From</th><th>To</th><th>Type</th><th>Direction</th><th>SID filtering</th>{}</tr></thead><tbody>"#,
            if warn { " warn" } else { "" },
            plural(trusts.len(), "trust", "trusts"),
            aside,
            if map.is_some() { "<th>Risk</th>" } else { "" },
        );
        for (t, other) in &trusts {
            let mapped = map
                .as_ref()
                .and_then(|d| map_trust(&d.map, &t.source, &t.target));
            let inside = matches!(
                t.trust_type.to_ascii_lowercase().as_str(),
                "parentchild" | "crosslink" | "treeroot" | "shortcut"
            );
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>{}</tr>",
                esc(&t.source),
                esc(&t.target),
                esc(&t.trust_type),
                match other {
                    Some(_) => format!("{}, recorded by both domains", esc(&t.direction)),
                    None => esc(&t.direction),
                },
                match other {
                    _ if inside => "n/a (same forest)".to_string(),
                    _ if mapped.is_some() => mapped.map(way_filtering).unwrap_or_default(),
                    // Each side sets it for the SIDs coming in from the other.
                    Some(o) if o.sid_filtering != t.sid_filtering => format!(
                        "{}: {}, {}: {}",
                        esc(&t.source),
                        on_off(t.sid_filtering),
                        esc(&o.source),
                        on_off(o.sid_filtering)
                    ),
                    _ => on_off(t.sid_filtering).to_string(),
                },
                match (&map, mapped) {
                    (Some(_), Some(m)) => format!("<td>{}</td>", trust_risk(m)),
                    (Some(_), None) => "<td>&ndash;</td>".to_string(),
                    _ => String::new(),
                }
            );
        }
        h.push_str("</tbody></table></div></details>");
    }

    /// The map's trust between `a` and `b`.
    fn map_trust<'m>(
        m: &'m crate::forest::ForestMap,
        a: &str,
        b: &str,
    ) -> Option<&'m crate::forest::TrustEdge> {
        let is = |x: &str, y: &str| x.eq_ignore_ascii_case(y);
        m.trusts.iter().find(|t| {
            (is(&t.source, a) && is(&t.target, b)) || (is(&t.source, b) && is(&t.target, a))
        })
    }

    /// Each way's SID filtering, as the trusting side records it: on, off
    /// (the collector's flag when there are no trust attributes) or unknown
    /// and why, as `summary` gives it.
    fn way_filtering(t: &crate::forest::TrustEdge) -> String {
        if t.ways.is_empty() {
            return "n/a (trust disabled)".into();
        }
        t.ways
            .iter()
            .map(|w| {
                let word = w.filtering.trim_start_matches("SID filtering ");
                let note = match (w.sid_filtering, &w.filtering_note) {
                    (Some(_), Some(_)) => " (from the collector)".to_string(),
                    (None, Some(_)) if w.sid_filtering_unknown.is_some() => {
                        " (the collected data doesn't say)".to_string()
                    }
                    (None, Some(n)) => format!(" ({})", esc(n)),
                    _ => String::new(),
                };
                format!("{} into {}: {}{note}", esc(&w.from), esc(&w.to), esc(word))
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// What the map flags on the trust.
    fn trust_risk(t: &crate::forest::TrustEdge) -> String {
        let mut flags = Vec::new();
        for f in &t.flags {
            match f.kind.as_str() {
                "takeover" => flags.push(format!(r#"<span class="ttag">{}</span>"#, esc(&f.text))),
                "not_collected" => flags.push(format!("({})", esc(&f.text))),
                "abuse" => flags.push(format!(r#"<span class="ttag bad">{}</span>"#, esc(&f.text))),
                "unknown" => flags.push(esc(&f.text)),
                _ => {}
            }
        }
        if flags.is_empty() {
            "&ndash;".into()
        } else {
            flags.join(" ")
        }
    }

    fn on_off(on: bool) -> &'static str {
        if on {
            "on"
        } else {
            "off"
        }
    }

    // Data sources.
    let objects: usize = s.objects.values().sum();
    let _ = write!(
        h,
        r#"<details class="row env"><summary><span class="title">Data sources</span><span class="aside">{} &middot; {}</span></summary><div class="body"><dl class="facts"><div><dt>Collector files</dt><dd>{}</dd></div><div><dt>Objects in them (counted per file)</dt><dd>{}</dd></div><div><dt>Domains</dt><dd>{}</dd></div></dl><h4>Files</h4><ul class="files">"#,
        plural(s.files.len(), "collector file", "collector files"),
        // What the files hold, one object in several files counted in
        // each: more than the run's objects (`pathwarden summary`).
        plural(objects, "entry", "entries"),
        num(s.files.len()),
        num(objects),
        esc(&r.domains.join(", "))
    );
    for f in &s.files {
        // Only the file names: local paths say nothing useful to the reader.
        let name = f.rsplit(['/', '\\', '!']).next().unwrap_or(f);
        let _ = write!(h, "<li><code>{}</code></li>", esc(name));
    }
    h.push_str("</ul>");
    opengraph_sources(h, &s.opengraph);
    h.push_str("</div></details>");

    h.push_str("</div></section>\n");
}

/// "Source" in a finding's facts, for findings that rest on OpenGraph data.
fn sources_fact(sources: &[String]) -> String {
    if sources.is_empty() {
        return String::new();
    }
    if sources.iter().all(|s| s == crate::pingcastle::SOURCE) {
        return "<div><dt>Source</dt><dd>PingCastle report (imported; not checked by Pathwarden)</dd></div>".into();
    }
    let names: Vec<String> = sources.iter().map(|s| esc(s)).collect();
    if sources.iter().all(|s| s == crate::entra::SOURCE) {
        return format!(
            "<div><dt>Source</dt><dd>{} (Entra ID), besides the directory</dd></div>",
            names.join(", ")
        );
    }
    format!(
        "<div><dt>Source</dt><dd>{} (OpenGraph), besides the directory</dd></div>",
        names.join(", ")
    )
}

/// The OpenGraph sources read, in the data sources section. Nothing when
/// there were none.
fn opengraph_sources(h: &mut String, og: &crate::ingest::OpenGraphStats) {
    use crate::opengraph::coverage::CoverageState;
    if og.is_empty() {
        return;
    }
    h.push_str(
        r#"<h4>Other sources (OpenGraph)</h4><table><thead><tr><th>Source</th><th>Mapping</th><th class="num">Files</th><th class="num">Objects</th><th class="num">Relationships</th><th>Coverage</th><th>Read</th></tr></thead><tbody>"#,
    );
    for src in &og.sources {
        let mapping = match (&src.pack, src.trusted) {
            (Some(p), true) => format!("{}: used for paths", esc(p)),
            (Some(p), false) => format!("{}: shown only, pack not trusted yet", esc(p)),
            (None, _) => "no mapping: shown only".to_string(),
        };
        let coverage = match src.coverage.state {
            CoverageState::Sidecar if src.coverage.complete => {
                let by = src.coverage.asserted_by.as_deref().unwrap_or("collector");
                format!(
                    "coverage file: {}, complete per the {}",
                    plural(src.coverage.ok.len(), "part", "parts"),
                    esc(by)
                )
            }
            CoverageState::Sidecar => "coverage file, collection not complete".to_string(),
            CoverageState::Invalid => {
                "coverage file not usable: findings can't be marked fixed".to_string()
            }
            CoverageState::None => "no coverage file: findings can't be marked fixed".to_string(),
            CoverageState::Collector if src.coverage.ok.is_empty() => {
                "no tenant fully collected: findings can't be marked fixed".to_string()
            }
            CoverageState::Collector => {
                let mut s = format!(
                    "{} collected",
                    plural(src.coverage.ok.len(), "tenant", "tenants")
                );
                if !src.coverage.failed.is_empty() {
                    let _ = write!(
                        s,
                        "; {} only referenced, their findings stay open",
                        plural(src.coverage.failed.len(), "tenant", "tenants")
                    );
                }
                s
            }
        };
        let read = if src.complete {
            "complete".to_string()
        } else {
            let mut why: Vec<String> = src
                .caps_hit
                .iter()
                .map(|c| format!("limit on {}", esc(c)))
                .collect();
            if !src.errors.is_empty() {
                why.push(plural(src.errors.len(), "error", "errors"));
            }
            if src.oversized > 0 {
                why.push(format!(
                    "{} too large",
                    plural(src.oversized, "record", "records")
                ));
            }
            format!("incomplete ({})", why.join(", "))
        };
        let _ = write!(
            h,
            r#"<tr><td>{}</td><td>{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td>{}</td><td>{}</td></tr>"#,
            esc(&src.name),
            mapping,
            src.files.len(),
            num(src.nodes),
            num(src.edges),
            coverage,
            read
        );
    }
    h.push_str("</tbody></table>");
    let mut notes: Vec<String> = Vec::new();
    for src in &og.sources {
        if src.dropped_native > 0 {
            notes.push(format!(
                "{}: {} dropped (AD relationships such as MemberOf come from the directory only)",
                esc(&src.name),
                plural(
                    src.dropped_native,
                    "native AD relationship",
                    "native AD relationships"
                )
            ));
        }
        if src.unresolved > 0 {
            notes.push(format!(
                "{}: {} whose ends matched no object, or more than one",
                esc(&src.name),
                plural(src.unresolved, "relationship", "relationships")
            ));
        }
        if src.dropped_secrets > 0 {
            notes.push(format!(
                "{}: {} that looked like secrets (passwords) not kept",
                esc(&src.name),
                plural(src.dropped_secrets, "property", "properties")
            ));
        }
        if let Some(words) = src.not_modeled() {
            notes.push(format!("{}: {} not analyzed", esc(&src.name), esc(&words)));
        }
    }
    if !og.unmapped_kinds.is_empty() {
        let kinds: Vec<String> = og
            .unmapped_kinds
            .iter()
            .take(20)
            .map(|(k, n)| format!("<code>{}</code> ({})", esc(k), num(*n)))
            .collect();
        notes.push(format!(
            "Relationship kinds no mapping pack describes, shown in Explore as context only: {}{}",
            kinds.join(", "),
            if og.unmapped_kinds.len() > 20 {
                ", …"
            } else {
                ""
            }
        ));
    }
    for s in &og.unused_sidecars {
        let name = s.rsplit(['/', '\\', '!']).next().unwrap_or(s);
        notes.push(format!("Coverage file not used: {}", esc(name)));
    }
    if !notes.is_empty() {
        h.push_str(r#"<ul class="muted small">"#);
        for n in notes {
            let _ = write!(h, "<li>{n}</li>");
        }
        h.push_str("</ul>");
    }
}

fn zone_row(h: &mut String, z: &ZonePosture) {
    let _ = write!(
        h,
        r#"<tr><td>{}</td><td class="num">{}</td><td class="meter-cell">{} <span>{} of {} ({})</span></td><td class="num">{}</td></tr>"#,
        esc(&z.zone),
        num(z.objects),
        meter(
            z.exposure_percent,
            z.exposure_grade.css_class(),
            &format!("{} with an attack path", pct(z.exposure_percent))
        ),
        num(z.exposed),
        num(z.relevant_population),
        pct(z.exposure_percent),
        z.protection_score.map(pct).unwrap_or_else(|| "n/a".into())
    );
}

#[cfg(test)]
mod tests {
    /// Permission steps say which kind of permission, and the kind of
    /// object in words.
    #[test]
    fn permission_headlines_say_the_kind_in_words() {
        use super::{step_headline_text, StepWords};
        use crate::model::{EdgeKind, NodeKind};
        let words = |edges: &'static [EdgeKind], to: &'static str, to_kind| StepWords {
            from: "EVERYONE@SCALE.LOCAL",
            from_kind: NodeKind::Group,
            edges,
            to,
            to_kind,
            to_managed: false,
        };
        assert_eq!(
            step_headline_text(&words(
                &[EdgeKind::GenericWrite],
                "DEFAULT DOMAIN POLICY@SCALE.LOCAL",
                NodeKind::Gpo
            )),
            "Remove the Group Policy security permission EVERYONE holds on the GPO DEFAULT DOMAIN POLICY"
        );
        assert_eq!(
            step_headline_text(&words(
                &[EdgeKind::AddMember],
                "CERT USERS@SCALE.LOCAL",
                NodeKind::Group
            )),
            "Remove the Active Directory security permission EVERYONE holds on the group CERT USERS"
        );
        assert_eq!(
            step_headline_text(&words(
                &[EdgeKind::GenericWrite, EdgeKind::WriteDacl],
                "J.DOE@SCALE.LOCAL",
                NodeKind::User
            )),
            "Remove the Active Directory security permissions EVERYONE holds on the user J.DOE"
        );
        assert_eq!(
            step_headline_text(&words(
                &[EdgeKind::CoerceToTgt],
                "DC01.SCALE.LOCAL",
                NodeKind::Computer
            )),
            "Turn off unconstrained delegation on EVERYONE"
        );
    }

    /// Every icon a mapping pack may name is in the report's sprite once,
    /// as `i-x-NAME` with the pack's drawing, and the sprite still closes.
    #[test]
    fn the_sprite_has_every_pack_icon() {
        use crate::opengraph::pack::ICON_GLYPHS;
        let sprite = super::sprite();
        assert!(sprite.starts_with("<svg ") && sprite.ends_with("</defs></svg>"));
        assert_eq!(sprite.matches("</defs></svg>").count(), 1);
        for (name, drawing) in ICON_GLYPHS {
            let symbol =
                format!(r#"<symbol id="i-x-{name}" viewBox="0 0 24 24">{drawing}</symbol>"#);
            assert_eq!(sprite.matches(&symbol).count(), 1, "{name}");
        }
    }

    /// External objects read as their pack says, grouped by kind; a pack's
    /// label is escaped, and a kind the pack says nothing about keeps its
    /// name and the generic icon. Outside a render, every external kind
    /// does.
    #[test]
    fn external_kinds_read_as_their_pack_says() {
        use super::{KindTable, NodeKind};
        use crate::findings::Affected;
        use crate::opengraph::pack::Pack;
        let pack = Pack::parse(
            r##"
[pack]
name = "test"
version = 1
source_kinds = ["TestHound"]
kind_prefix = "TT_"
trusted = true

[[node]]
kind = "TT_Box"
label = "<b>Crate</b> & co"
icon = "box"
"##,
        )
        .unwrap();
        let table = KindTable::from_packs(&[pack]);
        let boxed = NodeKind::External(crate::kinds::intern("TT_Box"));
        let plain = NodeKind::External(crate::kinds::intern("TT_Plain"));
        let affected: Vec<Affected> = [("A", boxed), ("B", boxed), ("C", plain)]
            .into_iter()
            .map(|(n, kind)| Affected {
                id: n.into(),
                name: n.into(),
                kind,
                detail: None,
            })
            .collect();
        {
            let _scope = super::ExtKindsScope::enter(Some(&table));
            assert_eq!(super::kind_label(boxed), "<b>Crate</b> & co");
            assert_eq!(super::kind_icon_id(boxed), "i-x-box");
            assert_eq!(super::kind_label(plain), "TT_Plain");
            assert_eq!(super::kind_icon_id(plain), "i-object");
            let h = super::affected_html(&affected, None, None);
            assert!(h.contains(
                r##"<use href="#i-x-box"/></svg>&lt;b&gt;Crate&lt;/b&gt; &amp; cos <span class="acount">2</span>"##
            ));
            assert!(h.contains(
                r##"<use href="#i-object"/></svg>TT_Plain <span class="acount">1</span>"##
            ));
            assert!(!h.contains("<b>Crate"));
        }
        assert_eq!(super::kind_label(boxed), "TT_Box");
        assert_eq!(super::kind_icon_id(boxed), "i-object");
    }

    #[test]
    fn plural_labels() {
        for (one, many) in [
            ("Entra role", "Entra roles"),
            ("Entra service principal", "Entra service principals"),
            ("Entra policy", "Entra policies"),
            ("SQL Server instance", "SQL Server instances"),
            ("Entra key", "Entra keys"),
            ("Mailbox", "Mailboxes"),
            ("Access", "Accesses"),
        ] {
            assert_eq!(super::plural_label(one), many);
        }
    }

    /// An accepted finding says who accepted it, where, when, the last
    /// change, what it covers, the review date and its notes; its row says
    /// "Accepted · user". Names from the file are escaped.
    #[test]
    fn accepted_findings_say_who_accepted_them() {
        let c = crate::config::Config::parse(
            r#"[[suppress]]
rule = "PW-011"
reason = "LAPS <rollout>"
expires = "2026-11-15"
accepted_by = 'NORTH\eddard.stark'
accepted_on = "PW-SCHED01"
accepted_at = "2026-10-22T14:03:11Z"
changed_on = "WS03"
changed_at = "2026-10-29T10:00:00Z"

[[suppress.notes]]
by = 'NORTH\<robb>'
on = "WS03"
at = "2026-10-29T10:11:02Z"
text = "Checked & kept."
"#,
        )
        .unwrap();
        let mut f = vec![crate::findings::Finding::new(
            "PW-011",
            crate::findings::Severity::Medium,
            &["a"],
            "x",
        )];
        c.apply_suppressions(&mut f, 0);
        let fact =
            super::accepted_fact(f[0].suppressed.as_deref().unwrap(), f[0].accepted.as_ref());
        assert!(
            fact.contains(r#"<p class="ar-reason">LAPS &lt;rollout&gt;</p>"#),
            "{fact}"
        );
        assert!(
            fact.contains(
                r"Accepted by <b>NORTH\eddard.stark</b> on <b>PW-SCHED01</b>, Oct 22, 2026"
            ),
            "{fact}"
        );
        assert!(
            fact.contains("changed by an unknown user on <b>WS03</b>, Oct 29, 2026"),
            "{fact}"
        );
        assert!(
            fact.contains("for every finding of its rule")
                && fact.contains("review by Nov 15, 2026"),
            "{fact}"
        );
        assert!(fact.contains(r#"<span class="ar-meta">Oct 29, 2026 · <b>NORTH\&lt;robb&gt;</b> on <b>WS03</b></span><span class="ar-text">Checked &amp; kept.</span>"#), "{fact}");
        assert_eq!(
            super::accepted_tag(&f[0]),
            r#"<span class="ar-tag">Accepted · NORTH\eddard.stark</span>"#
        );
        // An entry from before attribution says so; an open finding has no tag.
        let c = crate::config::Config::parse("[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\n")
            .unwrap();
        c.apply_suppressions(&mut f, 0);
        let fact = super::accepted_fact("r", f[0].accepted.as_ref());
        assert!(
            fact.contains("Who accepted it and when wasn't recorded"),
            "{fact}"
        );
        assert_eq!(
            super::accepted_tag(&f[0]),
            r#"<span class="ar-tag">Accepted</span>"#
        );
        let c = crate::config::Config::default();
        c.apply_suppressions(&mut f, 0);
        assert_eq!(super::accepted_tag(&f[0]), "");
        // A time that isn't RFC 3339 (written by hand) is shown as written;
        // a note of several lines keeps them (the page shows them so).
        let c = crate::config::Config::parse(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\naccepted_on = \"WS\"\naccepted_at = \"last Tuesday\"\n[[suppress.notes]]\ntext = \"one\\ntwo\"\n",
        )
        .unwrap();
        c.apply_suppressions(&mut f, 0);
        let fact = super::accepted_fact("r", f[0].accepted.as_ref());
        assert!(
            fact.contains("Accepted by an unknown user on <b>WS</b>, last Tuesday"),
            "{fact}"
        );
        assert!(
            fact.contains("<span class=\"ar-text\">one\ntwo</span>"),
            "{fact}"
        );
    }

    /// The trend's step: two of them reach the highest value.
    #[test]
    fn the_top_tick_is_at_or_above_the_peak() {
        for (max, step) in [
            (0.0, 1.0),
            (2.0, 1.0),
            (3.0, 2.0),
            (9_900.0, 5_000.0),
            (12_745.0, 10_000.0),
            (20_000.0, 10_000.0),
            (20_001.0, 20_000.0),
            (420.0, 500.0),
        ] {
            let s = super::nice_step(max / 2.0);
            assert_eq!(s, step, "{max}");
            assert!(2.0 * s >= max, "{max}");
        }
    }

    /// Two times on one day read apart; on different days, the dates do.
    #[test]
    fn dates_of_one_day_carry_the_time() {
        let oct19 = 1_792_368_000; // 2026-10-19 00:00 UTC
        let a = oct19 + 9 * 3_600 + 12 * 60;
        assert_eq!(super::date_beside(a, oct19 + 60), "Oct 19, 9:12 AM");
        assert_eq!(super::date_beside(a, a + 5), "Oct 19, 9:12:00 AM");
        assert_eq!(
            super::with_year(&super::date_beside(a, oct19 + 60), a),
            "Oct 19, 2026, 9:12 AM"
        );
        assert_eq!(super::with_year("Oct 19", a), "Oct 19, 2026");
        assert_eq!(super::date_beside(a, oct19 - 60), "Oct 19");
    }

    #[test]
    fn saved_reports_get_the_current_stylesheet() {
        let old = "<html><head><style>.lead { max-width: 72ch; }</style></head><body><p class=\"lead\">x</p></body></html>";
        let new = super::with_current_style(old);
        assert!(new.contains(super::CSS));
        assert!(!new.contains("max-width: 72ch"));
        assert!(new.ends_with("</style></head><body><p class=\"lead\">x</p></body></html>"));
        // Already current: unchanged. Not a report: unchanged.
        assert_eq!(super::with_current_style(&new), new);
        assert_eq!(
            super::with_current_style("<p>no style</p>"),
            "<p>no style</p>"
        );
    }

    #[test]
    fn counts_get_thousands_separators() {
        assert_eq!(super::num(0), "0");
        assert_eq!(super::num(999), "999");
        assert_eq!(super::num(1000), "1,000");
        assert_eq!(super::num(1_169_537), "1,169,537");
        assert_eq!(super::plural(1, "step", "steps"), "1 step");
        assert_eq!(super::plural(12_000, "step", "steps"), "12,000 steps");
    }

    #[test]
    fn writespn_onto_managed_account_does_not_advise_kerberoasting() {
        use crate::model::EdgeKind;
        // Ordinary target: setting an SPN lets you Kerberoast it.
        let ordinary = super::edge_meaning(EdgeKind::WriteSpn, false).unwrap();
        assert_eq!(
            ordinary,
            "Can set a service principal name and Kerberoast the account."
        );
        // gMSA/sMSA target (managedpassword == Some(true)): the domain rotates
        // the password, so the ticket can't be cracked. The guidance must not
        // promise a crack, and must say the step is a Kerberoasting dead end.
        let managed = super::edge_meaning(EdgeKind::WriteSpn, true).unwrap();
        assert!(
            !managed.contains("Kerberoast the account"),
            "managed target must not advise Kerberoasting; got: {managed}"
        );
        assert!(managed.contains("can't be Kerberoasted"), "got: {managed}");
    }
}
