//! Server-rendered pages, in the report's visual language: the same rail,
//! logo, colors, cards and rows (the stylesheet is the report's, plus
//! `assets/ui.css`).

use std::fmt::Write;
use std::path::Path;
use std::sync::OnceLock;

use pathwarden_core::findings::Severity;

use crate::jobs::Job;
use crate::server::AppState;
use crate::workspace::RunSummary;

/// Rail entries. The next screens (Settings, Zones, Plugins) get a variant
/// here, a page function below and a route in `server`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Home,
    Analyze,
    Runs,
    Explore,
    Progress,
    Collect,
    // Automate (`automate`, `plugins_ui`, `history_ui`).
    Schedule,
    /// Plugins and actions: the output plugins and finding actions.
    Plugins,
    History,
    // Configuration (`settings`, `zones_ui`, `environments`).
    Zones,
    /// OpenGraph mapping packs (`opengraph_ui`).
    Mappings,
    Environments,
    Settings,
}

/// What every page's rail needs.
pub struct Ctx<'a> {
    pub workspace: &'a Path,
    /// The sidebar's count: the runs the Runs list shows
    /// ([`crate::run_list::row_count`]).
    pub runs: usize,
    pub keep_uploads: bool,
    pub max_file: u64,
    /// Shown in the desktop window (`pathwarden ui --window`), where files
    /// are analyzed where they are rather than uploaded.
    pub window: bool,
    /// The current environment's ID and name (as it shows:
    /// [`crate::environments::Registry::with_names`]).
    pub env_id: String,
    pub env_name: String,
    /// The environments the switcher lists (an unused Default left out
    /// unless current), in registry order.
    pub envs: Vec<EnvItem>,
    /// The current environment's pull counter ([`crate::auto_pull`]),
    /// stamped on the page.
    pub pulled: u64,
    /// The sidebar footer's pull status (empty unless the history is a git
    /// repository).
    pub pull_foot: String,
    /// Some shared section differs from the shared settings: an amber dot
    /// on Settings in the rail, on every page.
    pub settings_differ: bool,
    /// Pathwarden stopped unexpectedly and it isn't dismissed
    /// ([`crate::logs_ui`]): the same dot.
    pub crash: bool,
}

/// One environment in the switcher.
pub struct EnvItem {
    pub id: String,
    pub name: String,
    pub demo: bool,
    /// "FABRIKAM.LOCAL and 2 more · 4 runs".
    pub sub: String,
}

impl<'a> Ctx<'a> {
    pub fn new(st: &'a AppState, runs: &[RunSummary]) -> Self {
        let all = st.workspace.all_runs();
        let reg = st.workspace.registry().with_names(&all);
        let env_id = st.env_id();
        let unused = reg.default_unused(
            st.workspace.root(),
            &crate::environments::run_domains(&reg, &all),
        );
        let envs = reg
            .environments
            .iter()
            .filter(|e| !(e.is_default() && unused) || e.id == env_id)
            .map(|e| {
                let mine: Vec<&RunSummary> = all
                    .iter()
                    .filter(|r| crate::environments::run_env(&reg, r) == e.id)
                    .collect();
                let mut domains = e.domains.clone();
                for r in &mine {
                    domains.extend(r.domains.iter().cloned());
                }
                let domains = crate::environments::clean_domains(&domains);
                let mut parts = Vec::new();
                match domains.as_slice() {
                    [] => {}
                    [one] => parts.push(one.clone()),
                    [first, rest @ ..] => parts.push(format!("{first} and {} more", rest.len())),
                }
                if e.demo {
                    parts.push("the built-in sample".into());
                } else if !mine.is_empty() {
                    parts.push(if mine.len() == 1 {
                        "1 run".to_string()
                    } else {
                        format!("{} runs", num(mine.len()))
                    });
                }
                EnvItem {
                    id: e.id.clone(),
                    name: e.display().to_string(),
                    demo: e.demo,
                    sub: parts.join(if e.demo { ", " } else { " · " }),
                }
            })
            .collect();
        let ws = st.ws();
        let flag = st.state_dir_for(&ws);
        let (pull_foot, settings_differ) = crate::auto_pull::foot_and_dot(&ws, flag.as_deref());
        // The runs the Runs list shows: these, and the history's others.
        let points = crate::history_ui::point_ids(&ws, flag.as_deref());
        Self {
            pulled: st.auto_pull.counter(&env_id),
            pull_foot,
            settings_differ,
            crash: crate::logs_ui::pending(st).is_some(),
            workspace: st.workspace.root(),
            runs: crate::run_list::row_count(runs, points.iter().map(String::as_str)),
            keep_uploads: st.keep_uploads,
            max_file: st.limits.per_file,
            window: st.transport.embedded_origin().is_some(),
            env_name: reg.name_of(&env_id),
            env_id,
            envs,
        }
    }

    /// Whether the workspace shows more than one environment.
    pub fn several_envs(&self) -> bool {
        self.envs.len() > 1
    }

    /// There is a demo environment: Try the demo is not offered.
    pub fn has_demo(&self) -> bool {
        self.envs.iter().any(|e| e.demo)
    }

    /// Nothing collected yet: the current environment is the unused
    /// Default ("No environment yet").
    pub fn no_env_yet(&self) -> bool {
        self.env_name == crate::environments::NO_ENV_YET
    }
}

/// The rail's environment switcher, always there so the layout never
/// shifts: the current environment, a menu of the others (each a small
/// form, so switching needs no script) and a link to manage them. The
/// server sends the browser back to the page it was on. Before the first
/// collection it says "No environment yet"; the demo has its own, which
/// never mixes with real runs.
fn env_switcher(ctx: &Ctx) -> String {
    let real = ctx
        .envs
        .iter()
        .any(|e| !e.demo && e.name != crate::environments::NO_ENV_YET);
    let mut list: Vec<&EnvItem> = ctx
        .envs
        .iter()
        .filter(|e| e.name != crate::environments::NO_ENV_YET)
        .collect();
    // The current one first, the demo last.
    list.sort_by_key(|e| (e.id != ctx.env_id, e.demo));
    let mut items = String::new();
    for e in &list {
        let current = e.id == ctx.env_id;
        let _ = write!(
            items,
            r#"<li><button type="submit" class="menu-item es-item" formaction="/environments/switch?to={id}"{cur}>{ic}<span><strong>{name}{tag}</strong>{sub}</span></button></li>"#,
            id = esc(&e.id),
            cur = if current {
                r#" aria-current="true""#
            } else {
                ""
            },
            ic = if current {
                icon("i-check")
            } else {
                icon("i-layers")
            },
            name = esc(&e.name),
            tag = if e.demo {
                r#" <span class="tag demo">Demo</span>"#
            } else {
                ""
            },
            sub = if e.sub.is_empty() {
                String::new()
            } else {
                format!(r#"<span class="es-sub">{}</span>"#, esc(&e.sub))
            },
        );
    }
    let (head, note, manage) = if list.is_empty() {
        (
            String::new(),
            r#"<p class="es-empty">Your first collection creates one, named after its domain.</p>"#,
            "Manage environments",
        )
    } else if !real {
        (
            r#"<p class="pm-head">Environments</p>"#.to_string(),
            r#"<p class="es-empty">Your first collection gets its own environment; it never mixes with the demo.</p>"#,
            "Manage environments",
        )
    } else {
        (
            r#"<p class="pm-head">Switch to</p>"#.to_string(),
            "",
            "New or manage environments",
        )
    };
    let list_html = if list.is_empty() {
        String::new()
    } else {
        format!(
            r#"{head}<form method="post" class="es-form"><ul class="es-list">{items}</ul></form>"#
        )
    };
    format!(
        r#"<details class="menu env-switch" id="env-switch"><summary aria-label="Environment: {name}. Switch environment">{i_layers}<span class="es-text"><span class="es-k">Environment</span><span class="es-name{none}">{name}</span></span><svg class="ic chev" aria-hidden="true" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg></summary><div class="menu-list card es-menu">{list_html}{note}<a href="/environments" class="es-manage">{i_manage}<span>{manage}</span></a></div></details>"#,
        name = esc(&ctx.env_name),
        none = if ctx.no_env_yet() { " es-none" } else { "" },
        i_layers = icon("i-layers"),
        i_manage = icon("i-plus"),
    )
}

/// JSON for an HTML attribute (`data-…="…"`), read back with JSON.parse:
/// bidi controls are written as JSON escapes (`\u202e`), not shown as
/// `\u{202e}` the way [`esc`] shows them in text (that isn't JSON, and one
/// name holding one would leave the page's script without its data). The
/// script shows them when it puts the text on the page.
pub fn json_attr(text: &str) -> String {
    pathwarden_core::text::json_attr(text)
}

/// A value the page sends back as it is (an input's `value`, a chip's
/// `data-value`): only `& < > " '` escaped, so a bidi control in a name
/// survives the round trip. Text shown on the page uses [`esc`].
pub fn attr(text: &str) -> String {
    pathwarden_core::text::html_attr(text)
}

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            // Bidi controls would reorder a name as shown; show them instead.
            c if pathwarden_core::text::is_bidi_control(c) => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Plain text with code in backticks, as HTML: escaped, each `span` in
/// `<code>`.
pub(crate) fn code_html(s: &str) -> String {
    let mut out = String::new();
    for (i, part) in esc(s).split('`').enumerate() {
        if i % 2 == 1 {
            out.push_str("<code>");
            out.push_str(part);
            out.push_str("</code>");
        } else {
            out.push_str(part);
        }
    }
    out
}

/// Text and code (`true`) parts as HTML: escaped, code in `<code>`.
pub(crate) fn parts_html(parts: &[(String, bool)]) -> String {
    parts
        .iter()
        .map(|(s, code)| {
            if *code {
                format!("<code>{}</code>", esc(s))
            } else {
                esc(s)
            }
        })
        .collect()
}

/// A count with thousands separators.
pub(crate) fn num(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A run's colour class: its Tier Zero grade's, as the report colours it.
pub(crate) fn grade_class(r: &RunSummary) -> &'static str {
    r.grade().css_class()
}

/// "account" or "accounts".
fn accounts(n: usize) -> &'static str {
    if n == 1 {
        "account"
    } else {
        "accounts"
    }
}

/// A marker after an exposure figure computed on an older basis than this
/// build's (another denominator): empty for the current basis.
pub fn older_basis_mark(basis: u8) -> &'static str {
    if basis == pathwarden_core::analysis::EXPOSURE_BASIS {
        ""
    } else {
        r#" <abbr class="old-basis muted" title="Older exposure basis (another denominator): not comparable with runs since">*</abbr>"#
    }
}

/// A time, in the one form every page uses: US style, which the browser
/// shows in local time with the UTC value as its tooltip (`app.js`); until
/// then it reads in UTC, labeled ("Oct 9, 2026, 9:29 PM UTC").
pub(crate) fn time(unix: i64) -> String {
    time_as(unix, "full")
}

/// [`time`] in another form: `"day"` (Oct 9) or `"time"` (9:29 PM).
pub(crate) fn time_as(unix: i64, form: &str) -> String {
    use pathwarden_core::time;
    let utc = time::format_utc(unix);
    let text = match form {
        "date" => time::format_day(unix),
        "day" => time::format_month_day(unix),
        "time" => format!("{} UTC", time::format_clock(unix)),
        _ => utc.clone(),
    };
    let iso = time::format_rfc3339(unix);
    format!(
        r#"<time data-unix="{unix}" data-fmt="{form}" datetime="{iso}" title="{utc}">{text}</time>"#
    )
}

/// A collection time as its file names say it, never moved to another zone
/// ([`pathwarden_core::time::format_collected`]).
pub(crate) fn collected_time(unix: i64) -> String {
    format!(
        r#"<span title="{}">{}</span>"#,
        pathwarden_core::time::COLLECTED_CLOCK,
        pathwarden_core::time::format_collected(unix)
    )
}

/// A thin bar, drawn in SVG so it needs no inline style.
const ICONS: &str = r##"<svg class="sprite" width="0" height="0" aria-hidden="true" focusable="false"><defs>
<symbol id="i-user" viewBox="0 0 64 64"><defs><mask id="ma-user" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="12" cy="56" r="7.25" fill="#000"/><circle cx="52" cy="56" r="7.25" fill="#000"/><circle cx="32" cy="19" r="11" fill="#000"/></mask></defs><g mask="url(#ma-user)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M12 56C12 44 21 38 32 38C43 38 52 44 52 56" stroke="currentColor"/></g></g><g stroke="none"><circle cx="12" cy="56" r="5.25" fill="currentColor"/><circle cx="52" cy="56" r="5.25" fill="currentColor"/><circle cx="32" cy="19" r="9" fill="currentColor"/></g></symbol>
<symbol id="i-group" viewBox="0 0 64 64"><defs><mask id="ma-group" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="8" cy="56" r="7.25" fill="#000"/><circle cx="44" cy="56" r="7.25" fill="#000"/><circle cx="44" cy="16" r="8.5" fill="#000"/><circle cx="26" cy="21" r="10.5" fill="#000"/></mask></defs><g mask="url(#ma-group)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M8 56C8 45 16 39 26 39C36 39 44 45 44 56" stroke="currentColor"/><path d="M47 34C53 35.5 57 41 57 49" stroke="currentColor"/></g></g><g stroke="none"><circle cx="8" cy="56" r="5.25" fill="currentColor"/><circle cx="44" cy="56" r="5.25" fill="currentColor"/><circle cx="44" cy="16" r="6.5" fill="currentColor"/><circle cx="26" cy="21" r="8.5" fill="currentColor"/></g></symbol>
<symbol id="i-computer" viewBox="0 0 64 64"><defs><mask id="ma-computer" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="20.5" cy="18.5" r="6" fill="#000"/><circle cx="20.5" cy="45.5" r="6.5" fill="#000"/></mask></defs><g mask="url(#ma-computer)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M14 9H50A4 4 0 0 1 54 13V24A4 4 0 0 1 50 28H14A4 4 0 0 1 10 24V13A4 4 0 0 1 14 9Z" stroke="currentColor"/><path d="M14 36H50A4 4 0 0 1 54 40V51A4 4 0 0 1 50 55H14A4 4 0 0 1 10 51V40A4 4 0 0 1 14 36Z" stroke="currentColor"/><path d="M30 18.5H44" stroke="currentColor" opacity="0.42"/><path d="M30 45.5H44" stroke="currentColor" opacity="0.42"/></g></g><g stroke="none"><circle cx="20.5" cy="18.5" r="4" fill="currentColor"/><circle cx="20.5" cy="45.5" r="4.5" fill="currentColor"/></g></symbol>
<symbol id="i-domain" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/></symbol>
<symbol id="i-policy" viewBox="0 0 64 64"><defs><mask id="ma-policy" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="32" cy="38" r="8.5" fill="#000"/></mask></defs><g mask="url(#ma-policy)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M8 15H26L32 22H56V53H8Z" stroke="currentColor"/></g></g><g stroke="none"><circle cx="32" cy="38" r="6.5" fill="currentColor"/></g></symbol>
<symbol id="i-cert" viewBox="0 0 64 64"><defs><mask id="ma-cert" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="46" cy="42" r="10" fill="#000"/></mask></defs><g mask="url(#ma-cert)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M8 10H56V42H8Z" stroke="currentColor"/><path d="M17 21H43" stroke="currentColor" opacity="0.42"/><path d="M17 31H33" stroke="currentColor" opacity="0.42"/><path d="M41 49L37 59" stroke="currentColor"/><path d="M51 49L55 59" stroke="currentColor"/></g></g><g stroke="none"><circle cx="46" cy="42" r="8" fill="currentColor"/></g></symbol>
<symbol id="i-object" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3"/></symbol>
<symbol id="i-home" viewBox="0 0 64 64"><defs><mask id="ma-home" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="10" cy="32" r="7.25" fill="#000"/><circle cx="54" cy="32" r="7.25" fill="#000"/><circle cx="32" cy="13" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-home)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M10 32L32 13L54 32" stroke="currentColor"/><path d="M16 28V54H48V28" stroke="currentColor"/></g></g><g stroke="none"><circle cx="10" cy="32" r="5.25" fill="currentColor"/><circle cx="54" cy="32" r="5.25" fill="currentColor"/><circle cx="32" cy="13" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-upload" viewBox="0 0 64 64"><defs><mask id="ma-upload" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="32" cy="16" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-upload)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M32 50V18" stroke="currentColor"/><path d="M18 32L32 16L46 32" stroke="currentColor"/></g></g><g stroke="none"><rect x="10" y="52" width="44" height="6" fill="currentColor"/><circle cx="32" cy="16" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-runs" viewBox="0 0 64 64"><defs><mask id="ma-runs" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="11" cy="16" r="7.25" fill="#000"/><circle cx="11" cy="32" r="7.25" fill="#000"/><circle cx="11" cy="48" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-runs)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M24 16H54" stroke="currentColor"/><path d="M24 32H54" stroke="currentColor"/><path d="M24 48H46" stroke="currentColor"/></g></g><g stroke="none"><circle cx="11" cy="16" r="5.25" fill="currentColor"/><circle cx="11" cy="32" r="5.25" fill="currentColor"/><circle cx="11" cy="48" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-play" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m10 8.5 5.5 3.5-5.5 3.5z"/></symbol>
<symbol id="i-radar" viewBox="0 0 64 64"><defs><mask id="ma-radar" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="49" cy="19" r="7.25" fill="#000"/><circle cx="32" cy="32" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-radar)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M12 32A20 20 0 1 1 52 32A20 20 0 1 1 12 32Z" stroke="currentColor"/><path d="M32 32L49 19" stroke="currentColor"/></g></g><g stroke="none"><circle cx="49" cy="19" r="5.25" fill="currentColor"/><circle cx="32" cy="32" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-download" viewBox="0 0 64 64"><defs><mask id="ma-download" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="32" cy="8" r="7.25" fill="#000"/><circle cx="32" cy="42" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-download)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M32 8V40" stroke="currentColor"/><path d="M17 27L32 42L47 27" stroke="currentColor"/></g></g><g stroke="none"><rect x="10" y="51" width="44" height="6" fill="currentColor"/><circle cx="32" cy="8" r="5.25" fill="currentColor"/><circle cx="32" cy="42" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-trash" viewBox="0 0 64 64"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M16 20L19 57H45L48 20" stroke="currentColor"/><path d="M27 30V47" stroke="currentColor" opacity="0.42"/><path d="M37 30V47" stroke="currentColor" opacity="0.42"/></g><g stroke="none"><rect x="10" y="10" width="44" height="6" fill="currentColor"/></g></symbol>
<symbol id="i-external" viewBox="0 0 24 24"><path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4"/></symbol>
<symbol id="i-sync" viewBox="0 0 24 24"><path d="M4.5 11a7.5 7.5 0 0 1 13.2-4.3"/><path d="M18.2 3.2v3.9h-3.9"/><path d="M19.5 13a7.5 7.5 0 0 1-13.2 4.3"/><path d="M5.8 20.8v-3.9h3.9"/></symbol>
<symbol id="i-check" viewBox="0 0 64 64"><defs><mask id="ma-check" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="10" cy="34" r="7.25" fill="#000"/><circle cx="54" cy="18" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-check)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M10 34L25 49L54 18" stroke="currentColor"/></g></g><g stroke="none"><circle cx="10" cy="34" r="5.25" fill="currentColor"/><circle cx="54" cy="18" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-x" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></symbol>
<symbol id="i-lock" viewBox="0 0 64 64"><defs><mask id="ma-lock" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="32" cy="42" r="8.5" fill="#000"/></mask></defs><g mask="url(#ma-lock)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M20 28V21A12 12 0 0 1 44 21V28" stroke="currentColor"/><path d="M12 28H52V56H12Z" stroke="currentColor"/></g></g><g stroke="none"><circle cx="32" cy="42" r="6.5" fill="currentColor"/></g></symbol>
<symbol id="i-folder" viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></symbol>
<symbol id="i-file" viewBox="0 0 24 24"><path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5"/></symbol>
<symbol id="i-arrow" viewBox="0 0 24 24"><path d="M4 12h15M14 7l5 5-5 5"/></symbol>
<symbol id="i-theme" viewBox="0 0 24 24"><path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/></symbol>
<symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></symbol>
<symbol id="i-alert" viewBox="0 0 64 64"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M32 7L58 53H6Z" stroke="currentColor"/><path d="M32 24V36" stroke="currentColor"/></g><g stroke="none"><circle cx="32" cy="45" r="4" fill="currentColor"/></g></symbol>
<symbol id="i-zone" viewBox="0 0 64 64"><defs><mask id="ma-zone" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="20.5" cy="32" r="7.25" fill="#000"/><circle cx="43.5" cy="32" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-zone)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M20 9H44A11 11 0 0 1 55 20V44A11 11 0 0 1 44 55H20A11 11 0 0 1 9 44V20A11 11 0 0 1 20 9Z" stroke="currentColor"/><path d="M32 16V48" stroke="currentColor" opacity="0.42"/></g></g><g stroke="none"><circle cx="20.5" cy="32" r="5.25" fill="currentColor"/><circle cx="43.5" cy="32" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-plug" viewBox="0 0 64 64"><defs><mask id="ma-plug" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="22" cy="10" r="7.25" fill="#000"/><circle cx="42" cy="10" r="7.25" fill="#000"/><circle cx="32" cy="48" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-plug)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M22 10V27" stroke="currentColor"/><path d="M42 10V27" stroke="currentColor"/><path d="M15 27H49V31A17 17 0 0 1 15 31Z" stroke="currentColor"/><path d="M32 48V58" stroke="currentColor"/></g></g><g stroke="none"><circle cx="22" cy="10" r="5.25" fill="currentColor"/><circle cx="42" cy="10" r="5.25" fill="currentColor"/><circle cx="32" cy="48" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-gear" viewBox="0 0 64 64"><defs><mask id="ma-gear" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="40" cy="17" r="7.25" fill="#000"/><circle cx="18" cy="32" r="7.25" fill="#000"/><circle cx="34" cy="47" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-gear)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M10 17H54" stroke="currentColor"/><path d="M10 32H54" stroke="currentColor"/><path d="M10 47H54" stroke="currentColor"/></g></g><g stroke="none"><circle cx="40" cy="17" r="5.25" fill="currentColor"/><circle cx="18" cy="32" r="5.25" fill="currentColor"/><circle cx="34" cy="47" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-search" viewBox="0 0 64 64"><defs><mask id="ma-search" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="54" cy="54" r="7.25" fill="#000"/><circle cx="27" cy="27" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-search)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M11 27A16 16 0 1 1 43 27A16 16 0 1 1 11 27Z" stroke="currentColor"/><path d="M39 39L54 54" stroke="currentColor"/></g></g><g stroke="none"><circle cx="54" cy="54" r="5.25" fill="currentColor"/><circle cx="27" cy="27" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
<symbol id="i-trend" viewBox="0 0 64 64"><defs><mask id="ma-trend" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="9" cy="14" r="7.25" fill="#000"/><circle cx="55" cy="48" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-trend)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M9 14L23 31L35 23L55 48" stroke="currentColor"/></g></g><g stroke="none"><circle cx="9" cy="14" r="5.25" fill="currentColor"/><circle cx="55" cy="48" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-edit" viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/></symbol>
<symbol id="i-power" viewBox="0 0 24 24"><path d="M12 3.5v8"/><path d="M7 6.5a7.5 7.5 0 1 0 10 0"/></symbol>
<symbol id="i-clock" viewBox="0 0 64 64"><defs><mask id="ma-clock" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="50.19" cy="22.5" r="7.25" fill="#000"/><circle cx="32" cy="12" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-clock)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M50.19 22.5A21 21 0 1 1 32 12" stroke="currentColor"/><path d="M32 23V33H41" stroke="currentColor"/></g></g><g stroke="none"><circle cx="50.19" cy="22.5" r="5.25" fill="currentColor"/><circle cx="32" cy="12" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-history" viewBox="0 0 64 64"><defs><mask id="ma-history" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="32" cy="15" r="8" fill="#000"/></mask></defs><g mask="url(#ma-history)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M11 15A21 6 0 0 1 53 15" stroke="currentColor"/><path d="M11 15V49A21 6 0 0 0 53 49V15" stroke="currentColor"/><path d="M11 32A21 6 0 0 0 53 32" stroke="currentColor" opacity="0.42"/></g></g><g stroke="none"><circle cx="32" cy="15" r="6" fill="currentColor"/></g></symbol>
<symbol id="i-graph" viewBox="0 0 64 64"><defs><mask id="ma-graph" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="12" cy="12" r="7.25" fill="#000"/><circle cx="52" cy="12" r="7.25" fill="#000"/><circle cx="12" cy="52" r="7.25" fill="#000"/><circle cx="52" cy="52" r="7.25" fill="#000"/><circle cx="32" cy="32" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-graph)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M12 12L52 52" stroke="currentColor"/><path d="M52 12L12 52" stroke="currentColor"/></g></g><g stroke="none"><circle cx="12" cy="12" r="5.25" fill="currentColor"/><circle cx="52" cy="12" r="5.25" fill="currentColor"/><circle cx="12" cy="52" r="5.25" fill="currentColor"/><circle cx="52" cy="52" r="5.25" fill="currentColor"/><circle cx="32" cy="32" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-layers" viewBox="0 0 64 64"><defs><mask id="ma-layers" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="32" cy="21" r="7" fill="#000"/></mask></defs><g mask="url(#ma-layers)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M32 9L56 21L32 33L8 21Z" stroke="currentColor"/><path d="M8 33L32 45L56 33" stroke="currentColor"/><path d="M8 44L32 56L56 44" stroke="currentColor"/></g></g><g stroke="none"><circle cx="32" cy="21" r="5" fill="currentColor"/></g></symbol>
<symbol id="i-info" viewBox="0 0 64 64"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M8 32A24 24 0 1 1 56 32A24 24 0 1 1 8 32Z" stroke="currentColor"/><path d="M32 30V45" stroke="currentColor"/></g><g stroke="none"><circle cx="32" cy="20" r="4.25" fill="currentColor"/></g></symbol>
<symbol id="i-mapping" viewBox="0 0 64 64"><defs><mask id="ma-mapping" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="18" cy="23" r="7.25" fill="#000"/><circle cx="46" cy="41" r="8.75" fill="#000"/></mask></defs><g mask="url(#ma-mapping)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M10 16H26V30H10Z" stroke="currentColor"/><path d="M38 34H54V48H38Z" stroke="currentColor"/><path d="M18 30V37A5 5 0 0 0 23 42H38" stroke="currentColor"/></g></g><g stroke="none"><circle cx="18" cy="23" r="5.25" fill="currentColor"/><circle cx="46" cy="41" r="6.75" fill="currentColor"/></g></symbol>
</defs></svg>"##;

/// The app's icon sprite: [`ICONS`] and the external kinds' icons
/// (`i-x-NAME`, as the report's sprite has them, for its finding cards).
fn sprite() -> &'static str {
    static SPRITE: OnceLock<String> = OnceLock::new();
    SPRITE.get_or_init(|| {
        let end = "</defs></svg>";
        let base = ICONS.strip_suffix(end).unwrap_or(ICONS);
        format!(
            "{base}\n{}{end}",
            pathwarden_core::opengraph::pack::icon_symbols()
        )
    })
}

pub(crate) fn icon(id: &str) -> String {
    format!(r##"<svg class="ic" aria-hidden="true"><use href="#{id}"/></svg>"##)
}

/// Pathwarden's GitHub repository, for links to its docs (the binary ships
/// without them).
pub(crate) const REPO_URL: &str = "https://github.com/marbas207/Pathwarden";

/// Pathwarden's website, linked from About Pathwarden in the rail.
pub(crate) const SITE_URL: &str = "https://pathwarden.org";

/// The author's Buy Me a Coffee page, linked from About Pathwarden.
pub(crate) const COFFEE_URL: &str = "https://buymeacoffee.com/marbasec";

/// A link to a file in the repository (`docs/privilege-zones.md`), opening
/// in a new tab, with `text` (HTML) as its text. A page of `docs/` opens on
/// pathwarden.org, which builds its docs from the repository; anything
/// else (a plugin's README) on GitHub.
pub(crate) fn repo_link(path: &str, text: &str) -> String {
    format!(
        r#"<a href="{}" target="_blank" rel="noopener noreferrer">{text}</a>"#,
        esc(&doc_url(path))
    )
}

/// Where `path` (`docs/ui.md#safety-locks`) is read: `docs/x.md` is
/// `https://pathwarden.org/docs/x.html`, the glossary is in the site's
/// knowledge base, and the rest is on GitHub.
pub(crate) fn doc_url(path: &str) -> String {
    let (file, frag) = match path.split_once('#') {
        Some((f, a)) => (f, format!("#{a}")),
        None => (path, String::new()),
    };
    if file == "docs/glossary.md" {
        return format!("{SITE_URL}/kb/glossary.html{frag}");
    }
    if let Some(name) = file
        .strip_prefix("docs/")
        .and_then(|f| f.strip_suffix(".md"))
    {
        if !name.is_empty() && !name.contains('/') {
            return format!("{SITE_URL}/docs/{name}.html{frag}");
        }
    }
    format!("{REPO_URL}/blob/main/{path}")
}

/// The wizards' step indicator (the Collect and Zone wizards): numbered
/// dots joined by a line, done steps ticked, the current one marked with
/// `aria-current="step"`, and "Step 2 of 6 · Who" in place of the labels on
/// a phone. With `clickable`, each step is a button (`data-goto`). The
/// pages' scripts move it with `Pathwarden.step` (`app.js`).
pub(crate) fn stepper(id: &str, labels: &[&str], clickable: bool) -> String {
    let mut b = format!(r#"<ol class="stepper" id="{id}" aria-label="Steps">"#);
    for (i, label) in labels.iter().enumerate() {
        let n = i + 1;
        let inner = format!(
            r#"<span class="sp-n" aria-hidden="true"><span>{n}</span>{check}</span><span class="sp-l">{label}</span>"#,
            check = icon("i-check"),
            label = esc(label),
        );
        let _ = write!(
            b,
            r#"<li data-step="{n}"{cur}>{inner}</li>"#,
            cur = if n == 1 {
                r#" aria-current="step""#
            } else {
                ""
            },
            inner = if clickable {
                format!(
                    r#"<button type="button" class="sp-btn" data-goto="{n}" aria-label="Step {n}: {}">{inner}</button>"#,
                    esc(label)
                )
            } else {
                inner
            },
        );
    }
    let _ = write!(
        b,
        r#"</ol><p class="stepper-mobile" id="{id}-mobile" aria-hidden="true">Step 1 of {} · {}</p>"#,
        labels.len(),
        esc(labels.first().copied().unwrap_or_default()),
    );
    b
}

/// What a page is to the history's news (`app.js`): the pages whose note
/// shows new runs, and the configuration pages whose sections it names.
/// A run's page is told apart by its address.
fn page_kind(active: Option<Nav>) -> &'static str {
    match active {
        Some(Nav::Home) => "home",
        Some(Nav::Runs) => "runs",
        Some(Nav::Progress) => "progress",
        Some(Nav::Settings) => "settings",
        Some(Nav::Zones) => "zones",
        Some(Nav::Mappings) => "mappings",
        _ => "",
    }
}

fn lockup() -> &'static str {
    static LOCKUP: OnceLock<String> = OnceLock::new();
    LOCKUP.get_or_init(pathwarden_core::report::brand_lockup)
}

pub(crate) fn shell(
    ctx: &Ctx,
    active: Option<Nav>,
    title: &str,
    main_class: &str,
    body: &str,
) -> String {
    let item = |nav: Nav, href: &str, ic: &str, label: &str, count: Option<usize>| {
        format!(
            r#"<a href="{href}"{current}>{ic}<span class="tl">{label}</span>{count}</a>"#,
            // The Collect wizard is one of Analyze's two sources.
            current =
                if active == Some(nav) || (nav == Nav::Analyze && active == Some(Nav::Collect)) {
                    r#" aria-current="page""#
                } else {
                    ""
                },
            ic = icon(ic),
            count = count
                .filter(|n| *n > 0)
                .map(|n| format!(r#"<span class="count">{}</span>"#, num(n)))
                .unwrap_or_default(),
        )
    };
    format!(
        r##"<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>{title}{env_title} · Pathwarden</title>
{brand_links}
<link rel="stylesheet" href="/static/app.css">
<script src="/static/theme.js"></script>
<script src="/static/app.js" defer></script>
</head>
<body class="app{has_demo}" data-pulled="{pulled}" data-env="{env_id}" data-page="{page}">
{icons}
<div class="shell">
<aside class="rail">
  <div class="brand"><a href="/" class="lockup home-link" aria-label="Pathwarden home">{lockup}</a><p class="tagline">Defend every path to privilege.</p></div>
  {switcher}
  <nav class="tabs" aria-label="Pathwarden">
    <div class="tablist">
      {home}
      {analyze}
      {runs}
      {explore}
      {progress}
    </div>

    <div class="tablist tablist-config"><span class="tl-group" aria-hidden="true">Automate</span>{schedule}{plugins}{history}</div>
    <div class="tablist tablist-config"><span class="tl-group" aria-hidden="true">Configure</span>{zones}{mappings}{environments}{settings}</div>
  </nav>
  <div class="rail-foot">
    {pull_foot}
    <details class="menu where">
      <summary class="icon-btn" aria-label="About Pathwarden" title="About Pathwarden">{i_info}</summary>
      <div class="menu-list card where-pop">
        <p class="where-head">Pathwarden {version}</p>
        <p class="about-links"><a href="{SITE_URL}" target="_blank" rel="noopener noreferrer">pathwarden.org</a><a href="{COFFEE_URL}" target="_blank" rel="noopener noreferrer">Buy me a coffee</a><a href="{REPO_URL}/issues/new" target="_blank" rel="noopener noreferrer">Report a problem</a><a href="{REPO_URL}/releases" target="_blank" rel="noopener noreferrer">Check for updates</a></p>
      </div>
    </details>
    <button type="button" class="theme-toggle icon-btn" id="theme-toggle" title="Light mode">{i_theme}<span class="tt-label sr-only">Light mode</span></button>
    <form method="post" action="/stop" class="stop-form" data-confirm="Stop Pathwarden? You are signed out and any collection or analysis still running stops."><button type="submit" class="theme-toggle icon-btn stop-btn" title="Stop Pathwarden and sign out">{i_stop}<span class="tt-label sr-only">Stop Pathwarden</span></button></form>
  </div>
</aside>
<main class="{main_class}">
{body}
</main>
</div>
<div class="toast" id="toast" role="alert" hidden></div>
</body>
</html>
"##,
        title = esc(title),
        icons = sprite(),
        pulled = ctx.pulled,
        env_id = esc(&ctx.env_id),
        page = page_kind(active),
        pull_foot = ctx.pull_foot,
        brand_links = crate::brand::HEAD_LINKS,
        // Once there is a demo environment, Try the demo is hidden (it is
        // one switch away); removing that environment brings it back.
        has_demo = if ctx.has_demo() { " has-demo" } else { "" },
        switcher = env_switcher(ctx),
        env_title = if ctx.several_envs() {
            format!(" · {}", esc(&ctx.env_name))
        } else {
            String::new()
        },
        home = item(Nav::Home, "/", "i-home", "Home", None),
        // Analyze opens on its first choice, Collect from Active Directory.
        analyze = item(Nav::Analyze, "/collect", "i-upload", "Analyze", None),
        runs = item(Nav::Runs, "/runs", "i-runs", "Runs", Some(ctx.runs)),
        explore = item(Nav::Explore, "/explore", "i-graph", "Explore", None),
        progress = item(Nav::Progress, "/progress", "i-trend", "Progress", None),
        lockup = lockup(),
        i_theme = icon("i-theme"),
        i_stop = icon("i-power"),
        i_info = icon("i-info"),
        version = env!("CARGO_PKG_VERSION"),
        zones = item(Nav::Zones, "/zones", "i-zone", "Zones", None),
        mappings = item(Nav::Mappings, "/mappings", "i-mapping", "Mappings", None),
        environments = item(
            Nav::Environments,
            "/environments",
            "i-layers",
            "Environments",
            None
        ),
        schedule = item(
            Nav::Schedule,
            "/automate/schedule",
            "i-clock",
            "Schedule",
            None
        ),
        plugins = item(
            Nav::Plugins,
            "/automate/ticketing",
            "i-plug",
            "Plugins and actions",
            None
        ),
        history = item(
            Nav::History,
            "/automate/history",
            "i-history",
            "History storage",
            None
        ),
        settings = settings_item(
            item(Nav::Settings, "/settings", "i-gear", "Settings", None),
            ctx.settings_differ,
            ctx.crash
        ),
    )
}

/// What a Settings section's dot says (Settings' jump links).
pub const SETTINGS_DIFFER: &str = "A setting has two values";

/// What the rail's dot on Settings says; `app.js` says the same.
pub const RAIL_DIFFER: &str = "Settings differ from the shared settings";

/// The rail's Settings link `link`, with one amber dot when some shared
/// section differs from the shared settings, or Pathwarden stopped
/// unexpectedly ([`crate::logs_ui::CRASH_DOT`]), or both: no text on the
/// page, the words in the link's name for screen readers and as its
/// tooltip. `data-differ` tells the page's script which it is.
fn settings_item(link: String, differ: bool, crash: bool) -> String {
    let words = match (differ, crash) {
        (false, false) => return link,
        (true, false) => RAIL_DIFFER.to_string(),
        (false, true) => crate::logs_ui::CRASH_DOT.to_string(),
        (true, true) => format!(
            "{RAIL_DIFFER}; {}",
            crate::logs_ui::CRASH_DOT.to_lowercase()
        ),
    };
    let marks = format!(
        "{}{}",
        if differ { " data-differ" } else { "" },
        if crash { " data-crash" } else { "" }
    );
    link.replacen(
        r#"<a href="/settings""#,
        &format!(r#"<a href="/settings" title="{words}"{marks}"#),
        1,
    )
    .replacen(
        "</a>",
        &format!(
            r#"<span class="sr-only">: {}</span><span class="nav-dot" aria-hidden="true" title="{words}"></span></a>"#,
            words.to_lowercase()
        ),
        1,
    )
}

// ------------------------------------------------------------------- Home

/// Home: the welcome and the three ways in on first launch; once there are
/// runs, a dashboard (the latest run's summary, then the latest runs).
/// Home. `overviews` are the latest run's report Overview, by run ([`crate::home_overview`]); a card without one is the
/// short card.
pub fn home(
    ctx: &Ctx,
    runs: &[RunSummary],
    running: Option<Job>,
    now: i64,
    overviews: &std::collections::HashMap<String, String>,
) -> String {
    let mut b = String::new();
    if runs.is_empty() {
        if ctx.several_envs() {
            // A new environment: say whose Home this is.
            let _ = write!(
                b,
                r#"<div class="env-note card" role="note">{}<p><strong>{}</strong> has no runs yet. New runs are saved here.</p></div>"#,
                icon("i-layers"),
                esc(&ctx.env_name)
            );
        }
        welcome(&mut b);
    } else {
        let latest = &runs[0];
        // With several (named) environments, the title is this one's name.
        let title = if ctx.several_envs() {
            esc(&ctx.env_name)
        } else {
            "Overview".to_string()
        };
        let _ = write!(
            b,
            r#"<div class="page-head home-head"><div><h1 class="panel-title">{title}</h1><p class="lead">Last run {when}.</p></div>{menu}</div>"#,
            when = time(latest.created_at),
            menu = new_analysis_menu(ctx.has_demo()),
        );
    }
    if let Some(job) = running {
        let (page, what) = if job.collect.is_some() {
            ("collect", "A collection is running")
        } else {
            ("analyze", "An analysis is running")
        };
        let _ = write!(
            b,
            r#"<a class="banner card" href="/{page}?job={id}"><span class="spinner" aria-hidden="true"></span><span><strong>{what}</strong> <span class="muted">{source}</span></span><span class="more-link">Open {arrow}</span></a>"#,
            id = esc(&job.id),
            source = esc(&crate::workspace::hide_profile(&job.source)),
            arrow = icon("i-arrow"),
        );
    }
    if !runs.is_empty() {
        // Only the latest run's summary: runs that collected other domains
        // are in the list below, not cards of their own.
        b.push_str(r#"<div class="env-cards">"#);
        if let Some(env) = environments(runs).into_iter().next() {
            match overviews.get(&env.runs[0].id) {
                Some(ov) => env_overview(&mut b, &env, now, ov),
                None => env_card(&mut b, &env, now),
            }
        }
        b.push_str("</div>");
    }
    // On first run the welcome card is the page: no empty list under it.
    if runs.is_empty() {
        return shell(ctx, Some(Nav::Home), "Home", "", &b);
    }
    let _ = write!(
        b,
        r#"<div class="sub-head"><h2 class="sub">Recent runs</h2>{}</div>"#,
        if runs.len() > 5 {
            format!(
                r#"<a class="more-link" href="/runs">All {} runs {}</a>"#,
                num(runs.len()),
                icon("i-arrow")
            )
        } else {
            String::new()
        }
    );
    run_list(&mut b, &runs[..runs.len().min(5)]);
    // What changed's account lists, which the report's script draws.
    if !overviews.is_empty() {
        b.push_str(r#"<script src="/static/accounts.js" defer></script>"#);
    }
    shell(ctx, Some(Nav::Home), "Home", "", &b)
}

fn welcome(b: &mut String) {
    b.push_str(&welcome_card(
        "Attack path analysis",
        "See every attack path to Tier Zero.",
        "Pathwarden reads what SharpHound or RustHound-CE collects, finds every path to Tier Zero, and the fewest fixes that cut them. Runs stay on this computer unless you share a run history.",
    ));
}

/// The one empty state: Home's welcome card, with the page's own words
/// (`eyebrow`, `title` and `lead`, plain text) above the three ways in.
/// Home, Explore and Progress show it when there is nothing yet.
pub(crate) fn welcome_card(eyebrow: &str, title: &str, lead: &str) -> String {
    format!(
        r##"<section class="welcome card">
  <div class="welcome-text">
    <p class="eyebrow">{eyebrow}</p>
    <h1 class="panel-title">{title}</h1>
    <p class="lead">{lead}</p>
  </div>
  <div class="actions">
    <a class="action primary" href="/collect">{i_upload}<span class="a-text"><strong>{ANALYZE_TITLE}</strong><span>{ANALYZE_SUB}</span></span>{i_arrow}</a>
    <a class="action connect" href="/environments/connect">{i_history}<span class="a-text"><strong>Connect to a run history</strong><span>Open the runs your team records.</span></span>{i_arrow}</a>
    <button class="action" type="button" data-demo>{i_play}<span class="a-text"><strong>Try the demo</strong><span>A made-up company: 15,000 users, 10,000 computers.</span></span>{i_arrow}</button>
  </div>
</section>
"##,
        eyebrow = esc(eyebrow),
        title = esc(title),
        lead = esc(lead),
        i_upload = icon("i-upload"),
        i_history = icon("i-history"),
        i_play = icon("i-play"),
        i_arrow = icon("i-arrow"),
    )
}

/// The way in to Analyze, which asks where the data comes from (Active
/// Directory, or a collection you have), wherever a page offers it: it
/// opens on Collect from Active Directory (`/collect`).
pub(crate) const ANALYZE_TITLE: &str = "Analyze";
pub(crate) const ANALYZE_SUB: &str =
    "Collect from Active Directory, or analyze a previous collection.";

/// The ways in, as buttons, for a page with nothing to show yet.
pub(crate) fn empty_actions() -> String {
    format!(
        r#"<p class="empty-actions"><a class="btn primary" href="/collect">{} {ANALYZE_TITLE}</a><button class="btn" type="button" data-demo>{} Try the demo</button></p>"#,
        icon("i-upload"),
        icon("i-play"),
    )
}

/// "Analyze ▾": Analyze and the demo, as a menu; once there is a demo
/// environment, a plain button to Analyze.
fn new_analysis_menu(has_demo: bool) -> String {
    if has_demo {
        return format!(
            r#"<a class="btn primary" href="/collect">{} Analyze</a>"#,
            icon("i-plus")
        );
    }
    format!(
        r#"<details class="menu new-menu"><summary class="btn primary">{i_plus} Analyze <svg class="ic chev" aria-hidden="true" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg></summary><ul class="menu-list card menu-right">
<li><a href="/collect">{i_upload}<span><strong>{ANALYZE_TITLE}</strong><span class="muted small">{ANALYZE_SUB}</span></span></a></li>
<li><button type="button" class="menu-item" data-demo>{i_play}<span><strong>Try the demo</strong><span class="muted small">A made-up company: 15,000 users, 10,000 computers.</span></span></button></li>
</ul></details>"#,
        i_plus = icon("i-plus"),
        i_upload = icon("i-upload"),
        i_play = icon("i-play"),
    )
}

/// The runs of one environment (its domains), newest first.
struct Env<'a> {
    runs: Vec<&'a RunSummary>,
}

/// Runs grouped by environment, the most recently analyzed first.
fn environments(runs: &[RunSummary]) -> Vec<Env<'_>> {
    let mut out: Vec<(String, Env)> = Vec::new();
    for r in runs {
        let key = crate::retest_ui::env_key(r);
        match out.iter_mut().find(|(k, _)| *k == key) {
            Some((_, e)) => e.runs.push(r),
            None => out.push((key, Env { runs: vec![r] })),
        }
    }
    out.into_iter().map(|(_, e)| e).collect()
}

/// The run Home's summary shows: the latest one.
pub fn latest_runs(runs: &[RunSummary]) -> Vec<String> {
    runs.first().map(|r| r.id.clone()).into_iter().collect()
}

/// One environment on Home with its latest report's Overview (`ov`): its
/// name and runs above, how old the data is and its pages below.
fn env_overview(b: &mut String, env: &Env, now: i64, ov: &str) {
    let r = env.runs[0];
    let _ = write!(
        b,
        r#"<section class="env-ov">
  <header class="ec-head"><h2 class="ec-name"><a href="/runs/{id}">{env}</a>{demo}</h2><span class="muted small">{n_runs} · latest run {when} · collected {ago}</span><span class="ec-links"><a href="/runs/{id}">Report</a><a href="/runs/{id}/explore">Explore</a><a href="/progress?env={key}">Progress</a></span></header>
  {ov}
</section>"#,
        id = esc(&r.id),
        env = esc(&r.environment()),
        demo = if r.demo {
            r#" <span class="tag">Demo</span>"#
        } else {
            ""
        },
        n_runs = if env.runs.len() == 1 {
            "1 run".to_string()
        } else {
            format!("{} runs", num(env.runs.len()))
        },
        when = time(r.created_at),
        ago = days_ago(r.collected_at.unwrap_or(r.created_at), now),
        key = esc(&crate::progress::urlencode(&crate::retest_ui::env_key(r))),
    );
}

/// "today", "yesterday", "12 days ago".
fn days_ago(then: i64, now: i64) -> String {
    match (now - then).max(0) / 86_400 {
        0 => "today".into(),
        1 => "yesterday".into(),
        n => format!("{} days ago", num(n as usize)),
    }
}

/// One environment on Home: its latest exposure and the change since the
/// run before, a trend line, open critical and high findings, the next
/// remediation step and how old the data is.
fn env_card(b: &mut String, env: &Env, now: i64) {
    let r = env.runs[0];
    // Like with like: the last run that targeted what this one did (a
    // Quick run against the last Quick run), as the history compares them.
    // The summaries carry it (Home fills in older ones before this).
    let targeting = |r: &RunSummary| pathwarden_core::since::targeting(r.completeness.as_ref());
    let mine = targeting(r);
    let alike: Vec<&RunSummary> = env
        .runs
        .iter()
        .copied()
        .filter(|x| targeting(x) == mine)
        .collect();
    let prev = alike.get(1).copied();
    let just_before = prev.is_some_and(|p| env.runs.get(1).is_some_and(|q| q.id == p.id));
    // The change in accounts that can reach Tier Zero: a count, so it
    // compares across a change of exposure basis, which only moves the share.
    let change = match prev {
        None if env.runs.len() > 1 => {
            r#"<span class="ec-delta muted">Not compared with the last run</span>"#.to_string()
        }
        None => r#"<span class="ec-delta muted">First run</span>"#.to_string(),
        Some(p) => {
            let d = r.exposed as i64 - p.exposed as i64;
            if d == 0 && just_before {
                r#"<span class="ec-delta muted">No change since the last run</span>"#.to_string()
            } else if d == 0 {
                r#"<span class="ec-delta muted">No change since the last run of the same kind</span>"#
                    .to_string()
            } else {
                format!(
                    r#"<span class="ec-delta {cls}">{arrow} {v} {what} <span class="muted">since {when}</span></span>"#,
                    cls = if d < 0 { "good" } else { "bad" },
                    arrow = if d < 0 { "↓" } else { "↑" },
                    v = num(d.unsigned_abs() as usize),
                    what = accounts(d.unsigned_abs() as usize),
                    when = time_as(p.created_at, "day"),
                )
            }
        }
    };
    let sev = |n: usize, s: Severity, label: &str| {
        format!(
            r#"<span class="pill {}{}"><span class="dot" aria-hidden="true"></span>{} {label}</span>"#,
            s.as_str(),
            if n == 0 { " zero" } else { "" },
            num(n)
        )
    };
    let collected = r.collected_at.unwrap_or(r.created_at);
    // What the fixes buy: the first step's own effect when the summary has
    // it, else the whole plan's drop, said to be the whole plan's. Whether
    // anything drops is a question of the plan cutting someone off
    // (`exposure_delta > 0`), not of the rounding of the figure.
    let pts = |d: f64| {
        if d < 0.005 {
            r#"<span class="good">&minus;&lt;0.01 points</span>"#.to_string()
        } else {
            format!(r#"<span class="good">&minus;{d:.2} points</span>"#)
        }
    };
    let plan_drop = if r.exposure_delta > 0.0 {
        format!(" {}", pts(r.exposure_delta))
    } else {
        String::new()
    };
    let next = match &r.next_step {
        Some(step) => format!(
            r#"<p class="ec-next"><span class="ec-k">First step</span> <span><a href="/runs/{id}">{}</a>{more}</span></p>"#,
            esc(step),
            id = esc(&r.id),
            more = match r.next_step_delta {
                Some(d) if r.plan_steps > 1 => format!(
                    r#" <span class="muted">· 1 of {} steps</span>{}"#,
                    num(r.plan_steps),
                    if d > 0.0 { format!(" {}", pts(d)) } else { String::new() }
                ),
                _ if r.plan_steps > 1 && r.exposure_delta > 0.0 => format!(
                    r#" <span class="muted">· all {} steps</span>{plan_drop}"#,
                    num(r.plan_steps)
                ),
                _ if r.plan_steps > 1 => {
                    format!(r#" <span class="muted">· 1 of {} steps</span>"#, num(r.plan_steps))
                }
                _ => plan_drop.clone(),
            },
        ),
        None if r.plan_steps == 0 => {
            r#"<p class="ec-next"><span class="ec-k">First step</span> <span class="muted">No attack path to cut.</span></p>"#.to_string()
        }
        None => format!(
            r#"<p class="ec-next"><span class="ec-k">First step</span> <a href="/runs/{}">{} steps cut every path.</a>{plan_drop}</p>"#,
            esc(&r.id),
            num(r.plan_steps)
        ),
    };
    let _ = write!(
        b,
        r#"<section class="env-card card">
  <header class="ec-head"><h2 class="ec-name"><a href="/runs/{id}">{env}</a>{demo}</h2><span class="muted small">{n_runs} · latest run {when}</span></header>
  <div class="ec-main">
    <div class="ec-expo {band}"><span class="ec-label">Tier Zero <span class="ec-grade">· {grade}</span>{reason}</span><span class="ec-pct">{count}</span><span class="ec-what">{what}</span>{change}<span class="ec-share muted small">{share}{mark}</span></div>
    {protect}
    <div class="ec-sev"><span class="ec-k">Open</span>{crit}{high}<span class="muted small">of {open}</span></div>
    {spark}
  </div>
  {next}
  <footer class="ec-foot"><span class="muted small">Collected {ago}</span><span class="ec-links"><a href="/runs/{id}">Report</a><a href="/runs/{id}/explore">Explore</a><a href="/progress?env={key}">Progress</a></span></footer>
</section>"#,
        id = esc(&r.id),
        env = esc(&r.environment()),
        demo = if r.demo {
            r#" <span class="tag">Demo</span>"#
        } else {
            ""
        },
        n_runs = if env.runs.len() == 1 {
            "1 run".to_string()
        } else {
            format!("{} runs", num(env.runs.len()))
        },
        when = time(r.created_at),
        band = grade_class(r),
        reason = tip(&format!("ec-why-{}", r.id), "this status", &r.status_reason()),
        count = num(r.exposed),
        what = if r.exposed == 0 {
            "accounts have an attack path to Tier Zero"
        } else if r.exposed == 1 {
            "account has an attack path to Tier Zero"
        } else {
            "accounts have an attack path to Tier Zero"
        },
        share = esc(&r.headline().share),
        mark = older_basis_mark(r.basis()),
        grade = r.grade().as_str(),
        protect = r.protection_score.map(|s| format!(
            r#"<p class="ec-protect"><span class="ec-k">Tier Zero protected</span> <span class="ec-pscore">{}</span></p>"#,
            pathwarden_core::posture::share_percent(s)
        )).unwrap_or_default(),
        spark = sparkline(&alike),
        crit = sev(r.critical, Severity::Critical, "critical"),
        high = sev(r.high, Severity::High, "high"),
        open = pathwarden_core::text::count(r.open_findings(), "finding", "findings"),
        ago = days_ago(collected, now),
        key = esc(&crate::progress::urlencode(&crate::retest_ui::env_key(r))),
    );
}

/// Exposure over the environment's last runs (oldest left), scaled to its
/// own range, with the latest point marked. Nothing for a single run.
fn sparkline(runs: &[&RunSummary]) -> String {
    // Accounts that can reach Tier Zero: a count, so every run compares,
    // whatever its exposure basis.
    let mut pts: Vec<f64> = runs.iter().take(12).map(|r| r.exposed as f64).collect();
    pts.reverse();
    if pts.len() < 2 {
        return String::new();
    }
    let (lo, hi) = pts
        .iter()
        .fold((f64::MAX, f64::MIN), |(a, b), v| (a.min(*v), b.max(*v)));
    let span = (hi - lo).max(1.0);
    let (w, h, pad) = (120.0, 40.0, 4.0);
    let xy: Vec<(f64, f64)> = pts
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = pad + (w - 2.0 * pad) * i as f64 / (pts.len() - 1) as f64;
            let y = pad + (h - 2.0 * pad) * (1.0 - (v - lo) / span);
            (x, y)
        })
        .collect();
    let line: Vec<String> = xy.iter().map(|(x, y)| format!("{x:.1},{y:.1}")).collect();
    let (lx, ly) = xy[xy.len() - 1];
    format!(
        r#"<svg class="ec-spark" viewBox="0 0 {w} {h}" role="img" aria-label="Accounts with an attack path to Tier Zero over the last {n} runs: from {first} to {last}"><polyline points="{line}"/><circle cx="{lx:.1}" cy="{ly:.1}" r="3"/></svg>"#,
        n = pts.len(),
        first = num(pts[0] as usize),
        last = num(pts[pts.len() - 1] as usize),
        line = line.join(" "),
    )
}

fn run_list(b: &mut String, runs: &[RunSummary]) {
    if runs.is_empty() {
        let _ = write!(
            b,
            r#"<div class="empty card">{}<div><p><strong>No runs yet.</strong><br><span class="muted">Analyze a collection or try the demo, and the run shows up here.</span></p>{}</div></div>"#,
            icon("i-runs"),
            empty_actions()
        );
        return;
    }
    b.push_str(r#"<div class="rows card runlist"><div class="runhead" aria-hidden="true"><span>Run</span><span>With an attack path to Tier Zero</span><span>Critical and high</span><span></span></div>"#);
    for r in runs {
        run_row(b, r);
    }
    b.push_str("</div>");
}

fn run_row(b: &mut String, r: &RunSummary) {
    run_row_to(b, r, "");
}

/// The label editor of a run row or the run page: a button that opens a
/// small form posting to `action` (`back`: where to go after).
pub(crate) fn label_editor(
    label: Option<&str>,
    action: &str,
    back: &str,
    hint: &str,
) -> (String, String) {
    let button = match label {
        Some(_) => format!(
            r#"<button type="button" class="rr-edit" data-label-edit aria-label="Edit label" title="Edit label">{}</button>"#,
            icon("i-edit")
        ),
        None => format!(
            r#"<button type="button" class="rr-add" data-label-edit>{} Add label</button>"#,
            icon("i-plus")
        ),
    };
    let form = format!(
        r#"<form class="inline-edit" method="post" action="{action}" data-label-form hidden><input type="hidden" name="back" value="{back}"><input type="text" name="label" value="{value}" maxlength="{max}" autocomplete="off" aria-label="Run label" placeholder="for example baseline, after GPO fix"><button type="submit" class="btn primary icon-only" aria-label="Save label" title="Save label">{i_check}</button><button type="button" class="btn icon-only" data-label-cancel aria-label="Cancel" title="Cancel">{i_x}</button>{hint}</form>"#,
        action = esc(action),
        back = esc(back),
        value = attr(label.unwrap_or_default()),
        max = crate::workspace::MAX_LABEL,
        i_check = icon("i-check"),
        i_x = icon("i-x"),
        hint = if hint.is_empty() {
            String::new()
        } else {
            format!(r#"<span class="ie-hint">{}</span>"#, esc(hint))
        },
    );
    (button, form)
}

/// A run's row, linking to `/runs/<id><page>` (`page`: "" or "/explore").
pub(crate) fn run_row_to(b: &mut String, r: &RunSummary, page: &str) {
    let demo = if r.demo {
        r#" <span class="tag">Demo</span>"#
    } else {
        ""
    };
    run_row_at(b, r, &format!("/runs/{}{page}", esc(&r.id)), demo);
}

/// A run list row linking to `href` (escaped), with `tags` (HTML) after the
/// environment: the Runs page also lists runs the CLI or a schedule recorded
/// ([`crate::history_ui`]).
pub(crate) fn run_row_at(b: &mut String, r: &RunSummary, href: &str, tags: &str) {
    run_row_vs(b, r, href, tags, "");
}

/// [`run_row_at`] with the Runs page's "vs previous" cell (`vs`, HTML;
/// left out when empty).
pub(crate) fn run_row_vs(b: &mut String, r: &RunSummary, href: &str, tags: &str, vs: &str) {
    run_row_full(b, r, href, tags, vs, None);
}

/// A run row. The row is a block with one link stretched over it, so the
/// label editor (`label_action`: where its form posts; Runs page only) can
/// sit inside. A labelled run shows the label, with the computed name
/// first on the line under it.
pub(crate) fn run_row_full(
    b: &mut String,
    r: &RunSummary,
    href: &str,
    tags: &str,
    vs: &str,
    label_action: Option<&str>,
) {
    run_row_with(b, r, href, tags, vs, label_action, "", "");
}

/// "8 critical", "11 high" pills, or "None": a run's critical and high
/// findings, as the run list shows them.
pub(crate) fn severity_pills(r: &RunSummary) -> String {
    let sev = |n: usize, s: Severity, label: &str| {
        if n == 0 {
            String::new()
        } else {
            format!(
                r#"<span class="pill {}"><span class="dot" aria-hidden="true"></span>{} {label}</span>"#,
                s.as_str(),
                num(n)
            )
        }
    };
    if r.critical + r.high == 0 {
        r#"<span class="pill none">None</span>"#.to_string()
    } else {
        format!(
            "{}{}",
            sev(r.critical, Severity::Critical, "critical"),
            sev(r.high, Severity::High, "high")
        )
    }
}

/// A small (i) with the details in a popover, as the other pages have
/// them. `body` is fixed text (escaped here).
pub(crate) fn tip(id: &str, about: &str, body: &str) -> String {
    format!(
        r#"<span class="tip"><button type="button" class="tip-btn" aria-label="About: {about}" aria-describedby="{id}">{i}</button><span class="tip-text" role="tooltip" id="{id}">{body}</span></span>"#,
        id = esc(id),
        about = esc(about),
        body = esc(body),
        i = icon("i-info"),
    )
}

/// What a safety lock is, behind the (i) of each lock note
/// ([`lock_note`]).
pub(crate) const LOCK_ABOUT: &str = "Safety locks keep pages from choosing programs for Pathwarden to run, or where findings and runs are sent.";

/// A lock note: `words` (fixed text: what is turned off in this app and
/// what still works), with an (i) that says it is a safety lock and links
/// to the docs on turning it off. The page names no command.
pub(crate) fn lock_note(id: &str, words: &str) -> String {
    format!(
        r#"<div class="note locked" data-lock="{id}">{lock}<p>{words} <span class="tip"><button type="button" class="tip-btn" aria-label="About: safety locks" aria-describedby="{id}-tip">{i}</button><span class="tip-text" role="tooltip" id="{id}-tip">{about} {docs}</span></span></p></div>"#,
        id = esc(id),
        lock = icon("i-lock"),
        words = esc(words),
        i = icon("i-info"),
        about = esc(LOCK_ABOUT),
        docs = repo_link("docs/ui.md#safety-locks", "How to turn them off"),
    )
}

/// [`run_row_full`] with `extra` (HTML) after the line under the title,
/// and `class` (" numbers-only", or empty) on the row.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_row_with(
    b: &mut String,
    r: &RunSummary,
    href: &str,
    tags: &str,
    vs: &str,
    label_action: Option<&str>,
    extra: &str,
    class: &str,
) {
    let urgent = severity_pills(r);
    let (edit, form) = match label_action {
        Some(action) => label_editor(r.label.as_deref(), action, "/runs", ""),
        None => (String::new(), String::new()),
    };
    let _ = write!(
        b,
        r#"<div class="runrow{class}" title="Run {run_id}">
  <span class="rr-main"><span class="rr-env"><a class="rr-link" href="{href}">{title}</a>{tags}{edit}</span>{form}<span class="rr-sub">{dom}{when} · {source}{extra}</span></span>
  <span class="rr-expo {band}" title="{reason}"><span class="rr-pct">{exposed}</span><span class="rr-grade">{grade}</span><span class="rr-of">{what} · {share}{mark}</span></span>
  {vs}<span class="rr-sev">{urgent}</span>
  {arrow}
</div>"#,
        run_id = esc(&r.run_id()),
        title = esc(&r.title()),
        dom = if r.label.is_some() {
            format!(
                r#"<span class="rr-dom">{}</span> · "#,
                esc(&r.environment())
            )
        } else {
            String::new()
        },
        when = time(r.created_at),
        source = esc(&crate::workspace::hide_profile(&r.source)),
        band = grade_class(r),
        reason = esc(&r.status_reason()),
        grade = r.grade().as_str(),
        mark = older_basis_mark(r.basis()),
        exposed = num(r.exposed),
        what = accounts(r.exposed),
        share = esc(&r.headline().share),
        arrow = icon("i-arrow"),
        vs = if vs.is_empty() {
            String::new()
        } else {
            format!(r#"<span class="rr-vs">{vs}</span>"#)
        },
    );
}

// --------------------------------------------------------------- Analyze

fn size_label(bytes: u64) -> String {
    if bytes >= 1 << 30 {
        format!("{} GB", bytes >> 30)
    } else {
        format!("{} MB", bytes >> 20)
    }
}

/// `applies` says which workspace settings the analysis uses
/// ([`crate::settings::applies_line`]); `where_html` is where the run goes
/// before the files are chosen ([`crate::env_where::render`]).
/// Analyze's question, "Where does the data come from?": Active Directory
/// (the Collect wizard, `collect` true) or a previous collection (this
/// page), as two choices that link to each other's page. The menu has
/// Analyze alone.
pub(crate) fn source_switch(collect: bool) -> String {
    let choice = |on: bool, href: &str, ic: &str, title: &str, what: &str| {
        format!(
            r#"<a class="src-choice{}" href="{href}"{}>{}<span><strong>{title}</strong><span class="muted small">{what}</span></span></a>"#,
            if on { " on" } else { "" },
            if on { r#" aria-current="page""# } else { "" },
            icon(ic),
        )
    };
    format!(
        r#"<nav class="src-switch" aria-label="Where the data comes from">{}{}</nav>"#,
        choice(
            collect,
            "/collect",
            "i-radar",
            "Collect from Active Directory",
            "A few questions, then Pathwarden collects and analyzes",
        ),
        choice(
            !collect,
            "/analyze",
            "i-upload",
            "A previous collection",
            "SharpHound, RustHound-CE, AzureHound or OpenGraph files",
        ),
    )
}

/// `from`: a run whose kept collection the files are analyzed with (Run
/// details' "Add files and analyze again"): listed first, as the
/// collection the files go with.
pub fn analyze(
    ctx: &Ctx,
    job: Option<Job>,
    applies: &str,
    where_html: &str,
    from: Option<&RunSummary>,
) -> String {
    let example = if cfg!(windows) {
        r"C:\Collections\20240410083609_BloodHound.zip"
    } else {
        "/home/me/collections/20240410083609_BloodHound.zip"
    };
    let kept = if ctx.window {
        "Files are read where they are; nothing is copied."
    } else if ctx.keep_uploads {
        "Uploaded copies are kept on this computer. Delete them when you are done."
    } else {
        "Uploaded copies are deleted as soon as the analysis finishes."
    };
    let (job_id, job_json) = match &job {
        Some(j) => (
            esc(&j.id),
            json_attr(&serde_json::to_string(j).unwrap_or_default()),
        ),
        None => (String::new(), String::new()),
    };
    let env_choice = format!(
        r#"<div class="env-where" id="ew" data-state="unknown">{where_html}</div>{label}"#,
        label = crate::env_where::label_field(),
    );
    // A run's kept collection, first: the run by its ID, and its
    // domains for where the new run goes.
    let (lead, from_list) = match from {
        Some(r) => (
            "Add AzureHound, OpenGraph or SharpHound files. They are analyzed with this collection, as a new run.",
            format!(
                r#"<ul class="filelist from-list" id="from-list" data-from="{id}" data-domains="{domains}" data-name="{name}"><li class="card">{i_folder}<span class="fl-name">Collection of {title}</span><span class="muted small">Collected {when}</span></li></ul>"#,
                id = esc(&r.id),
                domains = json_attr(&serde_json::to_string(&r.domains).unwrap_or_default()),
                name = esc(&format!("Collection of {}", r.title())),
                i_folder = icon("i-folder"),
                title = esc(&r.title()),
                when = r.collected_at.map_or_else(|| time(r.created_at), collected_time),
            ),
        ),
        None => (
            "SharpHound or RustHound-CE output (.zip or .json), plus any AzureHound or OpenGraph files.",
            String::new(),
        ),
    };
    let body = format!(
        r##"<div class="page-head glow-head"><div><h1 class="panel-title">Analyze</h1>
<p class="lead">Where does the data come from?</p></div></div>
{sources}

<form id="analyze-form" class="analyze"{hide_form}>
 <div class="an-col an-source">
  <h2 class="an-step"><span>1</span> What to analyze</h2>
  {from_list}
  <div class="source-box">
   <label class="dropzone" id="dropzone">
    <input type="file" id="files" name="files" multiple accept=".zip,.json">
    <span class="dz-icon">{i_upload}</span>
    <span class="dz-title">Drop files here, or <span class="link">browse</span></span>
    <span class="dz-hint">.zip or .json up to {max} each, or drop a folder</span>
   </label>
   <div class="sb-path">
    <span class="or"><span>or paste the path of a file or folder on this computer</span></span>
    <div class="pathfield">
     {i_folder}
     <label class="sr-only" for="path">File or folder path</label>
     <input type="text" id="path" name="path" placeholder="{example}" autocomplete="off" spellcheck="false">
    </div>
   </div>
  </div>
  <ul class="filelist" id="filelist" hidden></ul>
  <div id="ew-found"></div>
  <link rel="stylesheet" href="/static/opengraph.css">
  <section class="og-panel card" id="og-panel" aria-live="polite" hidden></section>
 </div>
 <div class="an-col an-dest">
  <h2 class="an-step"><span>2</span> Where it goes</h2>
  <div class="note">{i_lock}<p><strong>Collector data is a map of your domain.</strong> {kept}</p></div>
  {env_choice}
  <div id="an-applies">{applies}</div>

  <div class="form-actions">
    <button type="submit" class="btn primary" id="start" disabled>Start analysis {i_arrow}</button>
    <span class="muted small" id="start-hint">Choose files or enter a path to begin.</span>
  </div>
 </div>
</form>

<section class="progress card" id="progress" data-job="{job_id}" data-initial="{job_json}"{hide_progress} aria-live="polite">
  <div class="progress-head"><span class="spinner" aria-hidden="true"></span><div><h2 class="sub">Analyzing</h2><p class="muted small" id="progress-source"></p></div><span class="elapsed muted" id="elapsed"></span></div>
  <ol class="steps" id="steps">
    <li data-step="upload" hidden><span class="st"></span><span class="sl">Uploading files <span class="muted" id="upload-pct"></span></span></li>
    <li data-step="reading"><span class="st"></span><span class="sl">Reading the data <span class="muted" id="read-pct"></span></span></li>
    <li data-step="graph"><span class="st"></span><span class="sl">Building the graph</span></li>
    <li data-step="rules"><span class="st"></span><span class="sl">Checking for weaknesses</span></li>
    <li data-step="earlier" hidden><span class="st"></span><span class="sl">{building} <span class="muted" id="earlier-n"></span></span></li>
    <li data-step="remediation"><span class="st"></span><span class="sl">Planning the remediation path</span></li>
    <li data-step="report"><span class="st"></span><span class="sl">Writing the report</span></li>
  </ol>
  <div class="upbar" id="upbar" hidden><span id="upbar-fill"></span></div>
  <p class="muted small">You can leave this page; it keeps going.</p>
</section>

<section class="ask-env card" id="ask-env" hidden>
  <div class="env-where" id="ask-where" data-state="ask"></div>
  <div class="form-actions"><button type="button" class="btn primary" id="ask-go" disabled>Save the run {i_arrow}</button><button type="button" class="btn" id="ask-discard">Discard</button><span class="muted small" id="ask-hint">Nothing is saved yet. Choose an environment, or discard.</span></div>
</section>

<section class="failed card" id="duplicate" hidden role="alert">
  <div class="failed-head">{i_alert}<h2 class="sub">Already analyzed</h2></div>
  <p id="duplicate-message"></p>
  <div class="dialog-actions dup-actions"><a class="btn primary" id="duplicate-open" href="/runs">Open that run</a><button type="button" class="btn" id="duplicate-anyway">Analyze anyway</button></div>
</section>

<section class="failed card" id="failed" hidden role="alert">
  <div class="failed-head">{i_alert}<h2 class="sub">The analysis didn't finish</h2></div>
  <p id="failed-message"></p>
  <p class="muted small failed-source" id="failed-source" hidden></p>
  <div class="failed-actions"><button type="button" class="btn primary" id="retry">Try again</button><a class="btn" href="/collect">{i_radar} Collect from Active Directory</a></div>
</section>
<script src="/static/opengraph.js" defer></script>
"##,
        hide_form = if job.is_some() { " hidden" } else { "" },
        hide_progress = if job.is_some() { "" } else { " hidden" },
        building = crate::demo_runs::BUILDING,
        // While the demo analyzes, no source is chosen: it is the demo.
        sources = if job
            .as_ref()
            .is_some_and(|j| j.source == crate::jobs::DEMO_SOURCE)
        {
            r#"<p class="lead src-lead">Source: the built-in demo.</p>"#.to_string()
        } else {
            format!(
                r#"{}
<p class="lead src-lead">{lead}</p>"#,
                source_switch(false)
            )
        },
        max = size_label(ctx.max_file),
        i_upload = icon("i-upload"),
        i_folder = icon("i-folder"),
        i_lock = icon("i-lock"),
        i_arrow = icon("i-arrow"),
        i_alert = icon("i-alert"),
        i_radar = icon("i-radar"),
    );
    shell(ctx, Some(Nav::Analyze), "Analyze", "", &body)
}

// ------------------------------------------------------------------ Runs

/// `rows` are the rows of the run history ([`crate::history_ui::run_rows`]):
/// every UI run and every run the CLI or a schedule recorded, newest first.
/// `gate`: the "This history is encrypted" card ([`crate::encryption_ui::gate`]), or empty.
pub fn runs(ctx: &Ctx, runs: &[RunSummary], rows: &[String], note: &str, gate: &str) -> String {
    // Which environment this list is, with a way to rename it.
    let env_line = if ctx.no_env_yet() {
        String::new()
    } else {
        format!(
            r#"<p class="env-line">{i}<span>In <strong>{name}</strong></span><span class="sep">·</span><span>{n}</span><span class="sep">·</span><a href="/environments#env-{id}">{i_edit} Rename</a><span class="sep">·</span><a href="/environments">Manage environments</a></p>"#,
            i = icon("i-layers"),
            name = esc(&ctx.env_name),
            n = if rows.len() == 1 {
                "1 run".to_string()
            } else {
                format!("{} runs", num(rows.len()))
            },
            id = esc(&ctx.env_id),
            i_edit = icon("i-edit"),
        )
    };
    let mut b = format!(
        r#"<div class="page-head"><div><h1 class="panel-title">Runs</h1><p class="lead">Every run on this computer and in the run history, newest first.</p>{env_line}</div>{}</div>{note}"#,
        if runs.is_empty() {
            String::new()
        } else {
            format!(
                r#"<a class="btn" href="/collect">{} Analyze</a>"#,
                icon("i-upload")
            )
        }
    );
    b.push_str(gate);
    if rows.is_empty() {
        run_list(&mut b, &[]);
    } else {
        b.push_str(r#"<div class="rows card runlist with-vs"><div class="runhead" aria-hidden="true"><span>Run</span><span>With an attack path to Tier Zero</span><span>Since the previous run</span><span>Critical and high</span><span></span></div>"#);
        for row in rows {
            b.push_str(row);
        }
        b.push_str("</div>");
    }
    shell(ctx, Some(Nav::Runs), "Runs", "", &b)
}

// ------------------------------------------------------------- Run detail

/// The run page: the header (with a run picker, the retest summary and,
/// when findings may be missing, one line that says the reasons are in Run
/// details), and the report at full height. The report's overview carries the headline
/// numbers, so the page doesn't repeat them. `parts` are the dialogs the
/// report's finding actions open ([`crate::retest_ui::page_parts`]).
/// `env` is the run's environment (ID and the name it shows as); `perf`
/// `details`: how the run is removed, the frame's nonce, and the page's own
/// Run details when the report couldn't carry the tab
/// ([`crate::run_details::PageDetails`]).
pub fn run(
    ctx: &Ctx,
    r: &RunSummary,
    runs: &[RunSummary],
    parts: &crate::retest_ui::PageParts,
    env_note: &str,
    env: (&str, &str),
    details: &crate::run_details::PageDetails,
) -> String {
    let collected = r
        .collected_at
        .map(|t| format!(" · Collected {}", collected_time(t)))
        .unwrap_or_default();
    // How the run was collected and recorded, and the other sources read
    // with it, are on Run details; when findings may be missing, one line
    // above the report says why is there.
    let attention = if crate::run_details::attention(r) {
        let (lead, rest) = crate::run_details::ATTENTION
            .split_once(crate::run_details::TAB)
            .unwrap_or((crate::run_details::ATTENTION, ""));
        format!(
            r#"<span class="rh-attn">{i} <span>{lead}<a href="{href}" data-rd-open>{tab}</a>{rest}</span></span>"#,
            i = icon("i-alert"),
            // The report's tab when it carries it, else the page's own Run
            // details below the report.
            href = if details.carries {
                "#details"
            } else {
                "#run-details"
            },
            tab = crate::run_details::TAB,
        )
    } else {
        String::new()
    };
    let retests = if parts.retested == 0 {
        String::new()
    } else {
        // Without a targeted retest, every result is a later run's: nobody
        // retested anything, so don't say so.
        let (what, about) = if parts.targeted == 0 {
            (
                "checked by a later run",
                "Open findings checked against a later run of this environment",
            )
        } else {
            (
                "retested",
                "Open findings with a retest result: a targeted retest, or a later run of this environment",
            )
        };
        format!(
            r#"<span class="rh-retest">{i_retest} {n} {what}, <strong>{f} fixed</strong> {tip}</span>"#,
            tip = tip("rh-retest-tip", "these counts", about),
            i_retest = icon("i-check"),
            n = num(parts.retested),
            f = num(parts.fixed),
        )
    };
    let (edit, form) = label_editor(
        r.label.as_deref(),
        &format!("/runs/{}/label", r.id),
        &format!("/runs/{}", r.id),
        &format!(
            "Up to {} characters. Empty shows {}.",
            crate::workspace::MAX_LABEL,
            r.environment()
        ),
    );
    let body = format!(
        r##"<div class="page-head run-head">
  <div class="rh-top">
    <div class="eyebrow"><a class="rh-env" href="/environments#env-{env_id}" title="Open this environment">{i_layers}{env_name}</a>{demo}</div>
    <div class="rh-title"><h1 class="panel-title">{title}</h1>{edit}{form}</div>
  </div>
  <div class="rh-text">
    <p class="muted small rh-meta">{dom}Analyzed {when}{collected} · {source}{from_repo}</p>
    <div class="rh-status">{retests}{attention}</div>
  </div>
  <div class="rh-side">
    <div class="rh-picker">{picker}</div>
    <div class="rh-actions">
      <a class="btn primary" href="/runs/{id}/explore">{i_explore} Explore</a>
      {download}
      <a class="btn" href="/runs/{id}/report" target="_blank" rel="noopener">{i_external} Open report in a new tab</a>
    </div>
  </div>
  <button type="button" class="rd-delete" data-delete="{id}"{data_rd} hidden aria-hidden="true" tabindex="-1">{delete_words}</button>
</div>
{env_note}<div class="frame card"><iframe class="report-frame" id="report-frame" title="Report: {run_title}" data-src="/runs/{id}/report?embed=1{rd}" sandbox="{sandbox}"></iframe></div>
{below}

{dialogs}<dialog id="confirm-delete" class="card">
  <form method="dialog">
    {delete_dialog}
  </form>
</dialog>
"##,
        id = esc(&r.id),
        // A run loaded from the history: the report is another computer's,
        // so what it opens stays sandboxed. The header's tag says
        // where it came from (the owner chose the tag alone).
        sandbox = if r.shared.is_some() {
            crate::security::LOADED_REPORT_SANDBOX
        } else {
            crate::security::REPORT_SANDBOX
        },
        from_repo = if r.shared.is_some() {
            format!(
                r#" <span class="tag repo">{}From the run history</span>"#,
                icon("i-history")
            )
        } else {
            String::new()
        },
        delete_words = details.remove.words().0,
        delete_dialog = delete_dialog(r, details.remove),
        // The nonce only goes with a report that carries the tab.
        data_rd = if details.carries {
            format!(r#" data-rd="{}""#, esc(&details.nonce))
        } else {
            String::new()
        },
        rd = match (details.carries, &details.signin) {
            (true, Some(t)) => format!("&amp;rd={}&amp;signin={}", esc(&details.nonce), esc(t)),
            (true, None) => format!("&amp;rd={}", esc(&details.nonce)),
            _ => String::new(),
        },
        below = details.below.as_deref().unwrap_or(""),
        picker = run_picker(runs, r, ""),
        env_id = esc(env.0),
        env_name = esc(env.1),
        i_layers = icon("i-layers"),
        title = esc(&r.title()),
        dom = if r.label.is_some() {
            format!(
                r#"<span class="rh-dom">{}</span> · "#,
                esc(&r.environment())
            )
        } else {
            String::new()
        },
        demo = if r.demo { " · Demo data" } else { "" },
        run_title = esc(&r.title()),
        when = time(r.created_at),
        source = esc(&crate::workspace::hide_profile(&r.source)),
        dialogs = parts.dialogs,
        download = parts.download,
        i_external = icon("i-external"),
        i_explore = icon("i-graph"),
    );
    shell(ctx, Some(Nav::Runs), &r.title(), "wide", &body)
}

/// What the Delete dialog asks (Run details' "Remove this run",
/// [`crate::run_details`]).
fn delete_dialog(r: &RunSummary, remove: crate::run_details::Remove) -> String {
    use crate::run_details::Remove;
    let trash = icon("i-trash");
    let (head, text, go) = match remove {
        Remove::Delete { recorded } => (
            "Delete this run?".to_string(),
            format!(
                "The report for <strong>{}</strong> is removed from this computer. This can't be undone.{}",
                esc(&r.title()),
                if recorded {
                    " It is also removed from the run history and Progress. Findings keep their first-seen dates."
                } else {
                    ""
                }
            ),
            "Delete run",
        ),
        Remove::FromHistory => (
            "Remove this run from the run history?".to_string(),
            format!(
                "<strong>{}</strong> is removed from the run history for everyone at their next sync. Findings keep their dates. It can be recovered from the repository's git history.",
                esc(&r.title())
            ),
            "Remove from the run history",
        ),
        Remove::Hide => (
            "Hide this run on this computer?".to_string(),
            format!(
                "<strong>{}</strong> stays in the run history for everyone else. It won't load on this computer again.",
                esc(&r.title())
            ),
            "Hide on this computer",
        ),
    };
    format!(
        r#"<h2 class="sub">{head}</h2>
    <p class="muted">{text}</p>
    <div class="dialog-actions"><button class="btn" value="cancel">Cancel</button><button class="btn danger solid" value="delete" id="confirm-delete-go">{trash} {go}</button></div>"#
    )
}

/// Most runs listed in a run picker.
const PICKER_MAX: usize = 40;

/// "Run of Oct 9, 9:30 PM ▾": the current run, and a menu of the
/// workspace's runs (this environment's first) that opens the same page
/// The environment `env_id` (shown as `label`) as a menu of every
/// environment, for Explore's breadcrumb: picking one switches to it
/// and opens `then` (its latest run's Explore). Form posts in a
/// `<details>`, so it works without script. `None` with one environment
/// or none: there is nothing to pick.
pub(crate) fn env_picker(ctx: &Ctx, env_id: &str, label: &str, then: &str) -> Option<String> {
    let mut list: Vec<&EnvItem> = ctx
        .envs
        .iter()
        .filter(|e| e.name != crate::environments::NO_ENV_YET)
        .collect();
    if list.len() < 2 {
        return None;
    }
    // This one first, the demo last.
    list.sort_by_key(|e| (e.id != env_id, e.demo));
    let items: String = list
        .iter()
        .map(|e| {
            let current = e.id == env_id;
            format!(
                r#"<li><form method="post" action="/environments/switch?to={id}&amp;then={then}"><button type="submit" class="menu-item"{cur}>{ic}<span><strong>{name}{tag}</strong>{sub}</span></button></form></li>"#,
                id = esc(&e.id),
                then = esc(then),
                cur = if current { r#" aria-current="true""# } else { "" },
                ic = icon(if current { "i-check" } else { "i-layers" }),
                name = esc(&e.name),
                tag = if e.demo { r#" <span class="tag demo">Demo</span>"# } else { "" },
                sub = if e.sub.is_empty() {
                    String::new()
                } else {
                    format!(r#"<span class="muted small">{}</span>"#, esc(&e.sub))
                },
            )
        })
        .collect();
    Some(format!(
        r#"<details class="menu env-picker"><summary aria-label="Switch environment" title="{label}">{label} <svg class="ic chev" aria-hidden="true" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg></summary><ul class="menu-list card">{items}</ul></details>"#,
        label = esc(label),
    ))
}

/// (`page`: "" for the run page, "/explore" for Explore) for another run.
/// Plain links in a `<details>`, so it works without script.
pub(crate) fn run_picker(runs: &[RunSummary], current: &RunSummary, page: &str) -> String {
    let key = crate::retest_ui::env_key(current);
    let mut list: Vec<&RunSummary> = runs.iter().collect();
    // This environment first, then the others; newest first within each.
    list.sort_by(|a, b| {
        (crate::retest_ui::env_key(a) != key)
            .cmp(&(crate::retest_ui::env_key(b) != key))
            .then(b.order_key().cmp(&a.order_key()))
    });
    let mut items = String::new();
    let mut last_env = None;
    for r in list.iter().take(PICKER_MAX) {
        let env = crate::retest_ui::env_key(r);
        if last_env.as_ref() != Some(&env) {
            let _ = write!(
                items,
                r#"<li class="pm-head" role="presentation">{}</li>"#,
                esc(&r.environment())
            );
            last_env = Some(env);
        }
        let _ = write!(
            items,
            r#"<li><a href="/runs/{id}{page}"{cur}><span class="pm-when">{label}{when}</span><span class="pm-expo {band}" title="{grade}: {count} {what} with an attack path to Tier Zero">{count}</span>{demo}</a></li>"#,
            id = esc(&r.id),
            // The label is why runs get named: show it above the time.
            label = match r.label.as_deref().filter(|l| !l.is_empty()) {
                Some(l) => format!(r#"<span class="pm-label">{}</span>"#, esc(l)),
                None => String::new(),
            },
            cur = if r.id == current.id {
                r#" aria-current="true""#
            } else {
                ""
            },
            when = time(r.created_at),
            band = grade_class(r),
            grade = r.grade().as_str(),
            count = num(r.exposed),
            what = accounts(r.exposed),
            demo = if r.demo {
                r#"<span class="tag">Demo</span>"#
            } else {
                ""
            },
        );
    }
    let more = if runs.len() > PICKER_MAX {
        format!(
            r#"<li class="pm-all"><a href="/runs">All {} runs</a></li>"#,
            num(runs.len())
        )
    } else {
        String::new()
    };
    format!(
        r#"<details class="menu run-picker"><summary aria-label="Switch run">Run of {when} <svg class="ic chev" aria-hidden="true" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg></summary><ul class="menu-list card">{items}{more}</ul></details>"#,
        when = time(current.created_at),
    )
}

// ----------------------------------------------------------- Bare pages

/// A page shown without the session (so without the stylesheet, which
/// needs it): inline styles only, and the small Crown W inline (its colors
/// are its own attributes; the light scheme swaps them here).
pub fn bare_page(title: &str, text: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="same-origin"><title>{t} · Pathwarden</title>
{links}
<style>body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0e14;color:#f2f4f8;font:16px/1.55 "Segoe UI",system-ui,sans-serif;padding:16px;box-sizing:border-box}}
main{{max-width:30rem;background:#121925;border:1px solid #222c3c;border-radius:14px;padding:28px 30px;border-top:3px solid #9d5cff}}
.cw{{display:block;width:40px;height:auto;margin:0 0 16px;overflow:visible}}
h1{{font:600 1.4rem/1.25 Bahnschrift,"Segoe UI",system-ui,sans-serif;margin:0 0 .6rem}}p{{margin:0;color:#9aa7b8}}
@media (prefers-color-scheme:light){{body{{background:#f4f5f8;color:#0b0e14}}main{{background:#fff;border-color:#e1e4ea;border-top-color:#6b00d6}}p{{color:#556173}}
.cw .cw-a{{stop-color:#6b00d6}}.cw .cw-b{{stop-color:#1f8a3a}}.cw-nl,.cw-nr{{fill:#6b00d6}}.cw-jw{{fill:#1f8a3a}}.cw-bar{{fill:#0b0e14}}.cw .cw-glow{{filter:url(#pwcw-gl)}}.cw .cw-ho{{stop-opacity:.3}}}}</style>
</head><body><main>{mark}<h1>{t}</h1><p>{x}</p></main></body></html>"#,
        mark = pathwarden_core::report::brand_mark(),
        links = crate::brand::HEAD_LINKS,
        t = esc(title),
        x = esc(text),
    )
}

pub fn not_found() -> String {
    format!(
        r#"<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Not found · Pathwarden</title>
{links}
<link rel="stylesheet" href="/static/app.css"><script src="/static/theme.js"></script></head>
<body class="app bare"><main class="card lone"><h1 class="panel-title">Not found</h1><p class="muted">That page or run doesn't exist. It may have been deleted.</p><p><a class="btn primary" href="/">Back to Home</a></p></main></body></html>"#,
        links = crate::brand::HEAD_LINKS,
    )
}

#[cfg(test)]
mod tests {
    use super::{doc_url, esc, json_attr};

    /// Docs pages open on pathwarden.org, with their section; the glossary
    /// in its knowledge base; anything else on GitHub.
    #[test]
    fn docs_links_open_on_the_site() {
        assert_eq!(
            doc_url("docs/ui.md#safety-locks"),
            "https://pathwarden.org/docs/ui.html#safety-locks"
        );
        assert_eq!(
            doc_url("docs/privilege-zones.md"),
            "https://pathwarden.org/docs/privilege-zones.html"
        );
        assert_eq!(
            doc_url("docs/glossary.md"),
            "https://pathwarden.org/kb/glossary.html"
        );
        assert_eq!(
            doc_url("crates/pathwarden-output-jira/README.md"),
            "https://github.com/marbas207/Pathwarden/blob/main/crates/pathwarden-output-jira/README.md"
        );
        assert_eq!(
            doc_url("docs/dev/threat-model.md"),
            "https://github.com/marbas207/Pathwarden/blob/main/docs/dev/threat-model.md"
        );
    }

    /// A run summary of `exposed` accounts, Quick (nothing targeted) or Full.
    fn run(id: &str, at: i64, exposed: usize, quick: bool) -> super::RunSummary {
        serde_json::from_value(serde_json::json!({
            "id": id, "created_at": at, "collected_at": null,
            "source": "x", "demo": false, "domains": ["CONTOSO.LOCAL"], "objects": 0,
            "files": 1, "exposure_percent": 0.0, "exposed": exposed, "population": 0,
            "protection_score": null, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "info": 0, "suppressed": 0, "plan_steps": 0, "pathwarden": "0.1.0",
            "completeness": {"computers": 10, "sessions_collected": 9,
                "sessions_percent": 90.0, "member_computers": 9,
                "local_groups_collected": 9, "local_groups_percent": 100.0,
                "low_domains": 0, "sessions_targeted": !quick,
                "local_groups_targeted": !quick},
        }))
        .unwrap()
    }

    /// The app's sprite has every kind icon the report's object chips use,
    /// so Home's What changed (the report's) shows them; each mask is the
    /// app's own.
    #[test]
    fn the_sprite_has_the_report_s_kind_icons() {
        for id in [
            "i-user",
            "i-group",
            "i-computer",
            "i-domain",
            "i-folder",
            "i-policy",
            "i-cert",
            "i-object",
        ] {
            assert_eq!(
                super::ICONS
                    .matches(&format!(r#"<symbol id="{id}""#))
                    .count(),
                1,
                "{id}"
            );
        }
        assert!(!super::ICONS.contains("mr-"));
    }

    /// Every icon a mapping pack may name is in the sprite as `i-x-NAME`
    /// (the report's finding cards use them), drawn as Explore draws it.
    #[test]
    fn the_sprite_has_every_pack_icon_as_explore_draws_it() {
        use pathwarden_core::opengraph::pack::{ICONS, ICON_GLYPHS};
        let explore = include_str!("assets/explore.js");
        let sprite = super::sprite();
        assert!(sprite.ends_with("</defs></svg>"));
        for name in ICONS {
            let (_, drawing) = ICON_GLYPHS.iter().find(|(n, _)| n == name).unwrap();
            let symbol =
                format!(r#"<symbol id="i-x-{name}" viewBox="0 0 24 24">{drawing}</symbol>"#);
            assert_eq!(sprite.matches(&symbol).count(), 1, "{name}");
            assert_eq!(
                sprite.matches(&format!(r#"id="i-x-{name}""#)).count(),
                1,
                "{name}"
            );
            let key = if name.contains('-') {
                format!("\"{name}\"")
            } else {
                name.to_string()
            };
            assert!(
                explore.contains(&format!("    {key}: '{drawing}'")),
                "explore.js EXT_GLYPHS draws {name} differently"
            );
        }
        let in_explore = explore
            .split("var EXT_GLYPHS = {")
            .nth(1)
            .and_then(|s| s.split("};").next())
            .unwrap()
            .lines()
            .filter(|l| l.contains(": '"))
            .count();
        assert_eq!(in_explore, ICONS.len());
    }

    /// Home summarizes only the latest run, even when earlier runs
    /// collected other domains: those are in the run list.
    #[test]
    fn home_summarizes_only_the_latest_run() {
        let a = run("20261003-020000-aaaaaa", 300, 5, false);
        let mut b = run("20261002-020000-bbbbbb", 200, 5, false);
        b.domains = vec!["FABRIKAM.LOCAL".into()];
        let c = run("20261001-020000-cccccc", 100, 5, false);
        let runs = vec![a, b, c];
        assert_eq!(super::environments(&runs).len(), 2);
        assert_eq!(super::latest_runs(&runs), ["20261003-020000-aaaaaa"]);
        assert!(super::latest_runs(&[]).is_empty());
    }

    /// Home's card compares a Quick run with the last Quick run, never
    /// with a Full one: no "fewer accounts" from not reading sessions.
    #[test]
    fn the_home_card_compares_like_with_like() {
        let card = |runs: Vec<&super::RunSummary>| {
            let mut b = String::new();
            super::env_card(&mut b, &super::Env { runs }, 1_000_000);
            b
        };
        let full = run("20261001-020000-aaaaaa", 100, 9000, false);
        let quick = run("20261002-020000-bbbbbb", 200, 1, true);
        let b = card(vec![&quick, &full]);
        assert!(b.contains("Not compared with the last run"), "{b}");
        assert!(!b.contains("↓"), "{b}");
        // No trend from a Full run to a Quick one.
        assert!(!b.contains("ec-spark"), "{b}");
        let older = run("20260930-020000-cccccc", 50, 3, true);
        let b = card(vec![&quick, &full, &older]);
        // The trend is of the Quick runs: 3 to 1, the Full run left out.
        assert!(b.contains("over the last 2 runs: from 3 to 1"), "{b}");
        assert!(
            b.contains(r#"<span class="ec-delta good">↓ 2 accounts"#),
            "{b}"
        );
    }

    /// Home's card says Tier Zero protected and the percentage alone:
    /// never a score, no "higher is better".
    #[test]
    fn the_home_card_says_tier_zero_protected() {
        let mut r = run("20261001-020000-aaaaaa", 100, 9000, false);
        r.protection_score = Some(100.0 * 53.0 / 59.0);
        let mut b = String::new();
        super::env_card(&mut b, &super::Env { runs: vec![&r] }, 1_000_000);
        assert!(
            b.contains(
                r#"<p class="ec-protect"><span class="ec-k">Tier Zero protected</span> <span class="ec-pscore">89.83%</span></p>"#
            ),
            "{b}"
        );
        assert!(!b.contains("Protection Score"), "{b}");
        assert!(!b.contains("higher is better"), "{b}");
    }

    #[test]
    fn esc_shows_bidi_controls() {
        assert_eq!(esc("<a\u{202e}b>"), r"&lt;a\u{202e}b&gt;");
        assert_eq!(esc("JDOE@CONTOSO.LOCAL"), "JDOE@CONTOSO.LOCAL");
    }

    /// JSON in an attribute stays JSON with a bidi control in it (as a JSON
    /// escape), so the page's script can still read it.
    #[test]
    fn json_attributes_survive_bidi_controls() {
        let v = serde_json::json!({"reason": "Kiosk \u{202e}exe.\"<x>\""});
        let attr = json_attr(&v.to_string());
        assert!(
            !attr.contains('\u{202e}') && attr.contains(r"\u202e"),
            "{attr}"
        );
        let back = attr
            .replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&#39;", "'")
            .replace("&amp;", "&");
        let parsed: serde_json::Value = serde_json::from_str(&back).unwrap();
        assert_eq!(parsed, v);
    }
}
