//! The account lists on a page: which accounts each remediation step
//! cuts off, and which reach Tier Zero now or no longer do since the last
//! run. The page carries them as data (a `<script type="application/json"
//! class="acc-data">` block, at most [`LISTED`] accounts a list) and
//! `accounts.js` draws them: 20 at first, then Show all, a search
//! and Copy names for a step's.
//!
//! The same HTML and data serve the report, the app's run page (the report
//! in its frame) and Home (the report's What changed, lifted with its
//! data, or made from a loaded run's lists). Names go into the data as text
//! the script sets with `textContent`, never as HTML.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

use serde::Serialize;

use super::{esc, icon, kind_icon_id, num, tip};
use crate::exposed::{Account, ExposureLists, Hop, LISTED};
use crate::model::NodeKind;
use crate::since::SinceLast;

/// What a step's (i) says.
const STEP_TIP: &str = "Accounts with an attack path to Tier Zero through this step. Some also have other paths, which other steps cut. New: no path to Tier Zero in the last run that targeted the same.";

/// What the (i) beside "Now reach Tier Zero" says.
const CHANGE_TIP: &str = "Now reach: accounts with an attack path to Tier Zero that had none in the last run that targeted the same. No longer reach: the reverse, with why, and each one's path then when that run is kept in full.";

/// The anchor of What changed's Tier Zero accounts.
pub const CHANGE_ID: &str = "since-tier-zero";

/// The data `accounts.js` draws from: objects named once, by index.
#[derive(Serialize, Default)]
struct Data {
    /// Name and icon.
    nodes: Vec<(String, Cow<'static, str>)>,
    edges: Vec<String>,
    lists: BTreeMap<String, List>,
}

#[derive(Serialize)]
struct List {
    /// Accounts in the list; more than `rows` when cut at [`LISTED`].
    total: usize,
    rows: Vec<Row>,
    /// No longer reach: the day of the previous run the paths are from
    /// ("Oct 19"), when they are.
    #[serde(skip_serializing_if = "Option::is_none")]
    on: Option<String>,
}

/// One account: its node, hops, the hops shown of its path (all of up to
/// three; else the first two and the last), new or not, the step that cuts
/// it off, why it no longer reaches Tier Zero.
#[derive(Serialize)]
struct Row {
    a: u32,
    #[serde(skip_serializing_if = "is_zero")]
    h: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    p: Vec<[u32; 2]>,
    #[serde(skip_serializing_if = "is_false")]
    n: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    s: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    w: Option<&'static str>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Default)]
struct Table {
    data: Data,
    nodes: HashMap<(String, Cow<'static, str>), u32>,
    edges: HashMap<String, u32>,
}

impl Table {
    fn node(&mut self, name: &str, kind: NodeKind) -> u32 {
        // Bidi controls would reorder a name as shown: shown instead.
        let name = crate::text::bidi_safe(name).into_owned();
        let key = (name, kind_icon_id(kind));
        if let Some(&i) = self.nodes.get(&key) {
            return i;
        }
        let i = self.data.nodes.len() as u32;
        self.data.nodes.push(key.clone());
        self.nodes.insert(key, i);
        i
    }

    fn edge(&mut self, e: &str) -> u32 {
        if let Some(&i) = self.edges.get(e) {
            return i;
        }
        let i = self.data.edges.len() as u32;
        self.data.edges.push(e.to_string());
        self.edges.insert(e.to_string(), i);
        i
    }

    /// The hops shown of `path`: all of up to three, else the first two and
    /// the last (the page puts "…" between).
    fn path(&mut self, path: &[Hop]) -> Vec<[u32; 2]> {
        let shown: Vec<&Hop> = match path {
            [a, b, .., last] if path.len() > 3 => vec![a, b, last],
            _ => path.iter().collect(),
        };
        shown
            .into_iter()
            .map(|h| [self.edge(h.edge), self.node(h.name, h.kind)])
            .collect()
    }

    fn account(&mut self, a: &Account) -> Row {
        Row {
            a: self.node(a.name, a.kind),
            h: a.hops(),
            p: self.path(&a.path),
            n: a.new,
            s: None,
            w: None,
        }
    }

    /// The data as a block the page's script reads: JSON, with `<`, `>`
    /// and `&` escaped, so nothing in it ends the block.
    fn script(self) -> String {
        let json = serde_json::to_string(&self.data).expect("the lists serialize");
        format!(
            r#"<script type="application/json" class="acc-data">{}</script>"#,
            json.replace('<', "\\u003c")
                .replace('>', "\\u003e")
                .replace('&', "\\u0026")
        )
    }
}

/// The lists compared with the previous run's accounts, when they were
/// (the run What changed compares with).
fn compared<'a>(lists: Option<&'a ExposureLists>, s: &SinceLast) -> Option<&'a ExposureLists> {
    lists.filter(|l| {
        l.change
            .as_ref()
            .is_some_and(|c| c.unavailable.is_none() && c.previous_run == s.previous_run)
    })
}

/// Why the accounts weren't compared, in one sentence; `None` when they
/// were, or when the last run kept numbers only (which says nothing).
fn why_not(lists: Option<&ExposureLists>, previous_run: Option<&str>) -> Option<&'static str> {
    let c = lists?.change.as_ref()?;
    if previous_run.is_some_and(|p| p != c.previous_run) {
        return None;
    }
    c.unavailable?.sentence()
}

// ------------------------------------------------------------ the steps

/// The data of every step's list (`step-N`), for the Remediation path;
/// `None` without steps.
pub fn steps_data(lists: Option<&ExposureLists>) -> Option<String> {
    let lists = lists?;
    if lists.steps.is_empty() {
        return None;
    }
    let mut t = Table::default();
    for (st, listed) in lists.steps.iter().zip(lists.listed_per_step()) {
        let accounts = lists
            .step_accounts_first(st.step, listed)
            .unwrap_or_default();
        let rows = accounts.iter().map(|a| t.account(a)).collect();
        t.data.lists.insert(
            format!("step-{}", st.step),
            List {
                total: st.exposed,
                rows,
                on: None,
            },
        );
    }
    Some(t.script())
}

/// " 2 new" beside a step's count, when some of its accounts are new.
pub fn step_new(lists: Option<&ExposureLists>, n: usize) -> String {
    let Some(st) = lists
        .filter(|l| l.compared().is_some())
        .and_then(|l| l.steps.get(n - 1))
        .filter(|st| st.new > 0)
    else {
        return String::new();
    };
    format!(
        r#" <span class="ibadge" title="New since the last run">{} new</span>"#,
        num(st.new)
    )
}

/// Step `n`'s "Accounts it cuts off", folded: its count, how many are new
/// (or why that isn't known), and the list with a search and Copy names.
pub fn step_block(lists: Option<&ExposureLists>, n: usize) -> String {
    let Some(l) = lists else {
        return String::new();
    };
    let Some(st) = l.steps.get(n - 1) else {
        return String::new();
    };
    if st.exposed == 0 {
        return String::new();
    }
    let badge = if l.compared().is_some() && st.new > 0 {
        format!(
            r#" <span class="ibadge">{} new since the last run</span>"#,
            num(st.new)
        )
    } else {
        String::new()
    };
    let note = why_not(Some(l), None)
        .map(|s| format!(r#"<p class="muted small acc-note">{}</p>"#, esc(s)))
        .unwrap_or_default();
    // At most 1,000 a step, and 20,000 over the report's steps.
    let listed = l.listed_per_step()[n - 1];
    let placeholder = if listed < st.exposed {
        format!("Search the first {} accounts", num(listed))
    } else {
        format!("Search {} accounts", num(st.exposed))
    };
    // Nothing listed: nothing to search or copy.
    let tools = if listed == 0 {
        String::new()
    } else {
        format!(
            r#"<div class="acc-tools"><input type="search" class="acc-search" placeholder="{placeholder}" aria-label="Search the accounts"><span class="acc-match" aria-live="polite"></span><button type="button" class="acc-copy">{}<span>Copy names</span></button></div>"#,
            icon("i-copy")
        )
    };
    let words = crate::exposed::listed_words(listed);
    format!(
        r#"<details class="acc" id="step-{n}-accounts"><summary>Accounts it cuts off <span class="acount">{count}</span>{badge}{tip}</summary><div class="acc-body">{note}{tools}{list}</div></details>"#,
        count = num(st.exposed),
        tip = tip(&format!("acc{n}"), "Accounts it cuts off", STEP_TIP),
        list = list_html(
            &format!("step-{n}"),
            "step",
            (listed < st.exposed).then_some(words.as_str())
        ),
    )
}

/// What changed's lists when cut at [`LISTED`] (a step's say
/// [`crate::exposed::listed_words`]).
const LISTED_CHANGE: &str = "The first 1,000 are listed.";

/// A list the script fills (`key` in the data), and its foot: what it
/// says when cut at [`LISTED`].
fn list_html(key: &str, kind: &str, capped: Option<&str>) -> String {
    let capped = match capped {
        Some(words) => format!(r#" data-capped="{}""#, esc(words)),
        None => String::new(),
    };
    format!(
        r#"<ul class="acc-list" data-acc="{key}" data-kind="{kind}"{capped}></ul><div class="acc-foot"></div>"#
    )
}

// ------------------------------------------------------- What changed

/// What What changed's Tier Zero row says under its words: the accounts
/// that now reach Tier Zero and those that no longer do, folded (`brief`
/// and the lists), or why they weren't compared. `None`: as before.
pub enum ChangeRow {
    Lists { brief: String, body: String },
    Why(&'static str),
}

/// What changed's Tier Zero row, for `lists` against the run `s` compares
/// with.
pub fn change_row(lists: Option<&ExposureLists>, s: &SinceLast) -> Option<ChangeRow> {
    if let Some(l) = compared(lists, s) {
        let c = l.change.as_ref().expect("compared");
        let now = c.now_total();
        let gone = c.gone_total() + c.gone_unnamed;
        if now == 0 && gone == 0 {
            return None;
        }
        let mut brief = Vec::new();
        if now > 0 {
            brief.push(format!("<b>{}</b> now reach it", num(now)));
        }
        if gone > 0 {
            brief.push(format!("<b>{}</b> no longer do", num(gone)));
        }
        let mut body = String::from(
            r##"<div class="acc-change"><a class="acc-base" href="#plan" hidden tabindex="-1"></a>"##,
        );
        let mut first = true;
        if now > 0 {
            let _ = write!(
                body,
                r#"<h5>Now reach Tier Zero <span class="acount">{}</span>{}</h5>{}"#,
                num(now),
                tip("t0now", "Now reach Tier Zero", CHANGE_TIP),
                list_html("now", "now", (now > LISTED).then_some(LISTED_CHANGE)),
            );
            first = false;
        }
        if gone > 0 {
            let _ = write!(
                body,
                r#"<h5>No longer reach Tier Zero <span class="acount">{}</span>{}</h5>{}"#,
                num(gone),
                if first {
                    tip("t0now", "No longer reach Tier Zero", CHANGE_TIP)
                } else {
                    String::new()
                },
                list_html(
                    "gone",
                    "gone",
                    (c.gone_total() > LISTED).then_some(LISTED_CHANGE)
                ),
            );
            if c.gone_unnamed > 0 {
                let _ = write!(
                    body,
                    r#"<p class="muted small acc-unnamed">{}</p>"#,
                    esc(&crate::exposed::unnamed_sentence(c.gone_unnamed))
                );
            }
        }
        body.push_str("</div>");
        return Some(ChangeRow::Lists {
            brief: brief.join(" · "),
            body,
        });
    }
    why_not(lists, Some(&s.previous_run)).map(ChangeRow::Why)
}

/// The data of What changed's lists (`now`, `gone`), when they are shown.
pub fn change_data(lists: Option<&ExposureLists>, s: &SinceLast) -> Option<String> {
    let l = compared(lists, s)?;
    let c = l.change.as_ref().expect("compared");
    let mut t = Table::default();
    let now = l.now_reach();
    let rows = now
        .iter()
        .take(LISTED)
        .map(|(a, step)| Row {
            s: *step,
            n: false,
            ..t.account(a)
        })
        .collect();
    t.data.lists.insert(
        "now".into(),
        List {
            total: c.now_total(),
            rows,
            on: None,
        },
    );
    // With the previous run's graph, each one's path then.
    let gone = l.no_longer();
    let rows = gone
        .iter()
        .take(LISTED)
        .map(|g| Row {
            a: t.node(g.name, g.kind),
            h: g.path.len(),
            p: t.path(&g.path),
            n: false,
            s: None,
            w: Some(g.why.words()),
        })
        .collect();
    t.data.lists.insert(
        "gone".into(),
        List {
            total: c.gone_total(),
            rows,
            on: l.earlier_paths().then(|| super::short_date(c.previous_at)),
        },
    );
    Some(t.script())
}

/// "5 new accounts reach Tier Zero, and 5 older accounts no longer do.":
/// What changed's row when as many came as went.
pub fn same_total(lists: Option<&ExposureLists>, s: &SinceLast) -> Option<String> {
    compared(lists, s)?.same_total_sentence()
}
