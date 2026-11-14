//! Home's Overview: the top of the latest run's report Overview (the status
//! and count with its trend, What changed and the four cards), from the
//! same code as the report ([`pathwarden_core::report`]), so Home shows
//! what the report does. Its links go to the run page at the same place in
//! the report, and its IDs are made unique on the page.
//!
//! A run analysed on this computer has it lifted from its saved report
//! ([`of_run`]); a report saved before this Overview (no hero) has none, and
//! Home keeps its card. A run loaded from the history's full runs never has
//! its report's HTML lifted ([`crate::shared_runs::trusted_run_dir`]): its
//! Overview is made here from its data ([`of_loaded_run`]: the posture and
//! plan in its event document, and the run history), so everything in it
//! is escaped by Pathwarden. One without that data keeps Home's card.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use pathwarden_core::exposed::ExposureLists;
use pathwarden_core::history::{ReportHistory, This};
use pathwarden_core::model::{EdgeKind, NodeKind};
use pathwarden_core::posture::{
    Completeness, ExposureGrade, FindingCounts, PlanSummary, Posture, SeveritySetting,
    StatusReason, ZonePosture,
};
use pathwarden_core::remediation::PlannedFix;
use pathwarden_core::report::{self, OverviewInput};
use pathwarden_core::state::{FindingsState, HistoryPoint};
use serde::de::{self, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde::Deserialize;

use crate::workspace::{RunSummary, Workspace};

/// The Overview comes first in the report: read no further than this.
const READ_LIMIT: u64 = 16 << 20;

/// The most an event document inflates to before Home gives up on it and
/// keeps its card: 64 MB. The posture and plan come after the findings, so
/// the whole document is read (as it inflates, nothing of the findings
/// held). A directory of 1.27 million objects (282,843 of them with a path
/// to Tier Zero, 151 findings) has one of 4.2 MB.
pub(crate) const EVENT_LIMIT: u64 = 64 << 20;

/// The most Privilege Zones, and domains, an event document's posture may
/// have for Home to show it.
const MAX_ZONES: usize = 256;
pub(crate) const MAX_DOMAINS: usize = 1024;
/// The most rights one remediation step names.
const MAX_EDGES: usize = 256;

type Cache = HashMap<PathBuf, (Option<SystemTime>, u64, Option<String>)>;

/// The Overview of the report in `run_dir`, for the run `id`; `n` keeps
/// its IDs apart from another's on the same page. Read once per report
/// file (its time and size).
pub fn of_run(run_dir: &Path, id: &str, n: usize) -> Option<String> {
    if !crate::shared_runs::trusted_run_dir(run_dir) {
        return None;
    }
    let path = run_dir.join(crate::workspace::REPORT_FILE);
    let meta = std::fs::metadata(&path).ok()?;
    let key = (meta.modified().ok(), meta.len());
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let cached = cache
        .lock()
        .ok()
        .and_then(|c| c.get(&path).filter(|e| (e.0, e.1) == key).cloned());
    let fragment = match cached {
        Some((_, _, f)) => f,
        None => {
            let mut html = String::new();
            std::fs::File::open(&path)
                .ok()?
                .take(READ_LIMIT)
                .read_to_string(&mut html)
                .ok()?;
            let f = extract(&html);
            if let Ok(mut c) = cache.lock() {
                c.insert(path, (key.0, key.1, f.clone()));
            }
            f
        }
    };
    Some(localize(&fragment?, id, n))
}

// ------------------------------------------------- a run from the history

/// What Home reads of a loaded run's event document (`event.json.gz`,
/// [`crate::run_data::EVENT_FILE`]): only what the Overview shows, in types
/// of its own. It is the repository's data, read here and never written
/// anywhere.
#[derive(Deserialize)]
struct EventRead {
    /// [`pathwarden_core::event::schema_ok`]: another schema isn't read.
    #[serde(default)]
    schema: Option<String>,
    run: RunRead,
    posture: PostureRead,
    plan: PlanRead,
}

#[derive(Deserialize)]
struct RunRead {
    #[serde(default)]
    collected_at: Option<i64>,
}

#[derive(Deserialize)]
struct PostureRead {
    tier_zero: ZoneRead,
    #[serde(deserialize_with = "at_most::<_, ZoneRead, MAX_ZONES>")]
    zones: Vec<ZoneRead>,
    findings: FindingCounts,
    #[serde(deserialize_with = "at_most::<_, Completeness, MAX_DOMAINS>")]
    completeness: Vec<Completeness>,
    exposure_basis: u8,
    activity_days: i64,
    #[serde(default)]
    plan: Option<PlanSummary>,
    #[serde(default, deserialize_with = "at_most::<_, SeveritySetting, MAX_ZONES>")]
    severities_set: Vec<SeveritySetting>,
    #[serde(default)]
    severity_settings: String,
}

#[derive(Deserialize)]
struct ZoneRead {
    zone: String,
    objects: usize,
    population: usize,
    relevant_population: usize,
    exposed: usize,
    exposure_percent: f64,
    exposure_grade: ExposureGrade,
    reason: ReasonRead,
    objects_with_findings: usize,
    protection_score: Option<f64>,
}

#[derive(Deserialize)]
struct ReasonRead {
    text: String,
}

/// The plan: its first step and how many there are, nothing of the rest.
#[derive(Deserialize)]
struct PlanRead {
    exposed_before: usize,
    fixes: FirstAndCount,
}

#[derive(Deserialize)]
struct FixRead {
    from: String,
    from_kind: NodeKind,
    #[serde(deserialize_with = "edges")]
    edges: Vec<EdgeKind>,
    to: String,
    to_kind: NodeKind,
    #[serde(default)]
    to_managed: bool,
    principals_through: usize,
}

/// A list's first element and its length; the others are skipped.
struct FirstAndCount(Option<FixRead>, usize);

impl<'de> Deserialize<'de> for FirstAndCount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = FirstAndCount;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a list of steps")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let first: Option<FixRead> = seq.next_element()?;
                let mut n = usize::from(first.is_some());
                while seq.next_element::<IgnoredAny>()?.is_some() {
                    n = n.saturating_add(1);
                }
                Ok(FirstAndCount(first, n))
            }
        }
        d.deserialize_seq(V)
    }
}

/// A list of at most `N`; a longer one isn't read.
pub(crate) fn at_most<'de, D, T, const N: usize>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct V<T, const N: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for V<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a list of at most {N}")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(x) = seq.next_element()? {
                if out.len() == N {
                    return Err(de::Error::custom(format!("more than {N}")));
                }
                out.push(x);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(V::<T, N>(PhantomData))
}

/// A step's rights by name. A kind this process doesn't know reads as
/// [`pathwarden_core::kinds::OTHER`] (a plain permission in the step's
/// words): reading a kind never grows the table.
fn edges<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<EdgeKind>, D::Error> {
    Ok(at_most::<_, String, MAX_EDGES>(d)?
        .iter()
        .map(|s| {
            EdgeKind::from_name_or_external(s)
                .unwrap_or(EdgeKind::External(pathwarden_core::kinds::OTHER))
        })
        .collect())
}

impl ZoneRead {
    fn posture(self) -> ZonePosture {
        ZonePosture {
            zone: self.zone,
            objects: self.objects,
            population: self.population,
            relevant_population: self.relevant_population,
            exposed: self.exposed,
            exposure_percent: self.exposure_percent,
            exposure_grade: self.exposure_grade,
            grade_reason: String::new(),
            reason: StatusReason {
                text: self.reason.text,
                link: None,
            },
            broad_groups: Vec::new(),
            objects_with_findings: self.objects_with_findings,
            protection_score: self.protection_score,
        }
    }
}

/// What a loaded run's Overview is made from.
struct LoadedData {
    posture: Posture,
    plan_steps: usize,
    exposed_before: usize,
    first_step: Option<PlannedFix>,
    collected_at: Option<i64>,
}

impl From<EventRead> for LoadedData {
    fn from(e: EventRead) -> Self {
        let p = e.posture;
        LoadedData {
            posture: Posture {
                tier_zero: p.tier_zero.posture(),
                zones: p.zones.into_iter().map(ZoneRead::posture).collect(),
                findings: p.findings,
                completeness: p.completeness,
                sysvol: Vec::new(),
                adcs: Vec::new(),
                dc_settings: Vec::new(),
                ca_settings: Vec::new(),
                host_agents: Default::default(),
                exposure_basis: p.exposure_basis,
                activity_days: p.activity_days,
                activity_unknown_domains: Vec::new(),
                plan: p.plan,
                severities_set: p.severities_set,
                severity_settings: p.severity_settings,
            },
            plan_steps: e.plan.fixes.1,
            exposed_before: e.plan.exposed_before,
            // What the step's words need; the rest isn't shown.
            first_step: e.plan.fixes.0.map(|f| PlannedFix {
                from: f.from,
                from_kind: f.from_kind,
                edges: f.edges,
                to: f.to,
                to_kind: f.to_kind,
                to_managed: f.to_managed,
                cost: 0,
                principals_through: f.principals_through,
                shortest_paths_through: 0,
                sdprop_copies: 0,
                inherited_by: 0,
                action: String::new(),
                source: None,
            }),
            collected_at: e.run.collected_at,
        }
    }
}

type DataCache = HashMap<PathBuf, (Option<SystemTime>, u64, Option<Arc<LoadedData>>)>;

/// The run history Home's loaded runs are compared with: this workspace's
/// history, read on first use (once per Home request), and its findings
/// state, read only when the latest run needs it.
pub struct History {
    ws: Workspace,
    flag: Option<PathBuf>,
    read: OnceLock<Option<(PathBuf, Vec<HistoryPoint>)>>,
    state: OnceLock<Option<FindingsState>>,
}

impl History {
    /// The history of workspace `ws` (`flag`: `ui --state`).
    pub fn new(ws: &Workspace, flag: Option<PathBuf>) -> Self {
        History {
            ws: ws.clone(),
            flag,
            read: OnceLock::new(),
            state: OnceLock::new(),
        }
    }

    /// The history's folder and points, when it can be read.
    fn points(&self) -> Option<(&Path, &[HistoryPoint])> {
        self.read
            .get_or_init(|| {
                let loc = crate::history_ui::locate(&self.ws, self.flag.as_deref()).ok()?;
                let points = crate::history_ui::read(&loc).points;
                Some((loc.dir, points))
            })
            .as_ref()
            .map(|(dir, points)| (dir.as_path(), points.as_slice()))
    }

    /// The report's history for run `r`, as the report of a run recorded
    /// here gets it ([`pathwarden_core::history::for_report_in`]): the runs
    /// before it, with the findings state when it is the latest. Empty when
    /// the history hasn't the run: no trend and no What changed.
    fn for_run(&self, r: &RunSummary) -> ReportHistory<'_> {
        let Some((dir, points)) = self.points() else {
            return ReportHistory::default();
        };
        let run_id = r.run_id();
        let mut h: ReportHistory<'_> =
            pathwarden_core::history::for_report(points, &r.domains, This::Run(&run_id));
        let Some(this) = &h.this_run else {
            return ReportHistory::default();
        };
        let latest =
            pathwarden_core::since::latest_point(points).is_some_and(|l| l.run_id == this.run_id);
        if latest {
            h.state = self
                .state
                .get_or_init(|| {
                    pathwarden_core::history::findings_state_in(dir)
                        .ok()
                        .flatten()
                })
                .as_ref()
                .map(Cow::Borrowed);
        }
        h
    }
}

/// The Overview of run `r`, loaded from the history into `run_dir`, made
/// from its data with the report's own code; `n` keeps its IDs apart from
/// another's on the same page. `None` when its event document is missing
/// or isn't one Home reads (a file left out of its full run, one too large
/// or not of this form): Home keeps its card. The event is read once per
/// file (its time and size).
pub fn of_loaded_run(
    run_dir: &Path,
    r: &RunSummary,
    history: Option<&History>,
    n: usize,
) -> Option<String> {
    let data = loaded_data(&run_dir.join(crate::run_data::EVENT_FILE))?;
    let earlier = history.map(|h| h.for_run(r)).unwrap_or_default();
    // Its account lists, when its full run has them: What changed's
    // accounts that now reach Tier Zero or no longer do.
    let lists = loaded_lists(&run_dir.join(crate::run_data::EXPOSED_FILE));
    let fragment = report::overview_fragment(&OverviewInput {
        posture: &data.posture,
        plan_steps: data.plan_steps,
        exposed_before: data.exposed_before,
        first_step: data.first_step.as_ref(),
        collected_at: data.collected_at,
        generated_at: r.created_at,
        history: &earlier,
        introduced: None,
        lists: lists.as_deref(),
    });
    Some(localize(&fragment, &r.id, n))
}

/// What the event document at `path` gives the Overview, cached by its
/// time and size, for at most [`LISTS_KEPT`] runs.
fn loaded_data(path: &Path) -> Option<Arc<LoadedData>> {
    let meta = std::fs::metadata(path).ok()?;
    let key = (meta.modified().ok(), meta.len());
    static CACHE: OnceLock<Mutex<DataCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some((_, _, d)) = cache
        .lock()
        .ok()
        .and_then(|c| c.get(path).filter(|e| (e.0, e.1) == key).cloned())
    {
        return d;
    }
    let d = read_event(path, EVENT_LIMIT).map(|e| Arc::new(e.into()));
    if let Ok(mut c) = cache.lock() {
        // As the lists: past that many runs, start over.
        if c.len() >= LISTS_KEPT && !c.contains_key(path) {
            c.clear();
        }
        c.insert(path.to_path_buf(), (key.0, key.1, d.clone()));
    }
    d
}

type ListsCache = HashMap<PathBuf, (Option<SystemTime>, u64, Option<Arc<ExposureLists>>)>;

/// The most loaded runs whose lists (and Overview data) Home keeps read.
const LISTS_KEPT: usize = 16;

/// What changed of the account lists at `path` (a loaded run's
/// `exposed.json.gz`), kept by the file's time and size: Home shows What
/// changed alone, so the steps' lists aren't kept, and at most
/// [`exposed::LISTED`](pathwarden_core::exposed::LISTED) accounts a list
/// ([`ExposureLists::change_only`]). `None` when the run has
/// none, or they can't be read.
fn loaded_lists(path: &Path) -> Option<Arc<ExposureLists>> {
    let meta = std::fs::metadata(path).ok()?;
    let key = (meta.modified().ok(), meta.len());
    static CACHE: OnceLock<Mutex<ListsCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some((_, _, l)) = cache
        .lock()
        .ok()
        .and_then(|c| c.get(path).filter(|e| (e.0, e.1) == key).cloned())
    {
        return l;
    }
    let dir = path.parent()?;
    let l = crate::run_data::exposure_lists(dir)
        .and_then(Result::ok)
        .map(|l| Arc::new(l.change_only()));
    if let Ok(mut c) = cache.lock() {
        // Home shows a few latest runs: past that many, start over.
        if c.len() >= LISTS_KEPT && !c.contains_key(path) {
            c.clear();
        }
        c.insert(path.to_path_buf(), (key.0, key.1, l.clone()));
    }
    l
}

/// The event document at `path`, read as it inflates, up to `limit` bytes.
fn read_event(path: &Path, limit: u64) -> Option<EventRead> {
    let f = std::fs::File::open(path).ok()?;
    let gz = flate2::read::GzDecoder::new(std::io::BufReader::new(f)).take(limit);
    serde_json::from_reader::<_, EventRead>(std::io::BufReader::new(gz))
        .ok()
        .filter(|e| pathwarden_core::event::schema_ok(e.schema.as_deref()))
}

/// The Overview's hero, What changed (when there is one) and the four
/// cards, as the report has them.
fn extract(html: &str) -> Option<String> {
    let section = html.find(r#"<section id="overview""#)?;
    let hero = section + html[section..].find(r#"<div class="hero card"#)?;
    let mut end = block_end(html, hero)?;
    let mut out = html[hero..end].to_string();
    // What changed is under the severities; before the cards, or right
    // under them, in reports saved earlier. The severities stay on the
    // run page.
    for (next, keep) in [
        (r#"<div class="card ov-since""#, true),
        (r#"<div class="ov-cards""#, true),
        (r#"<div class="ov-sev""#, false),
        (r#"<div class="ov-since""#, true),
    ] {
        if html[end..].starts_with(next) {
            let to = block_end(html, end)?;
            if keep {
                out.push_str(&html[end..to]);
            }
            end = to;
        }
    }
    Some(out)
}

/// Where the `<div>` that opens at `start` closes (after its `</div>`).
fn block_end(html: &str, start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut at = start;
    loop {
        let open = html[at..].find("<div").map(|i| at + i);
        let close = html[at..].find("</div>").map(|i| at + i)?;
        match open {
            Some(o) if o < close => {
                depth += 1;
                at = o + 4;
            }
            _ => {
                depth = depth.checked_sub(1)?;
                at = close + 6;
                if depth == 0 {
                    return Some(at);
                }
            }
        }
    }
}

/// The report's in-page links go to the run page (which passes the place on
/// to its report), and its IDs get the prefix `h{n}-`.
fn localize(fragment: &str, id: &str, n: usize) -> String {
    // Icons (`<use href="#i-info">`) stay on the page's sprite.
    const ICON: &str = "<use href=\"#";
    const KEPT: &str = "<use data-pw-icon=\"";
    fragment
        .replace(ICON, KEPT)
        .replace(r##"href="#"##, &format!(r##"href="/runs/{id}#"##))
        .replace(KEPT, ICON)
        .replace(r#"id="tip-"#, &format!(r#"id="h{n}-tip-"#))
        .replace(
            r#"aria-describedby="tip-"#,
            &format!(r#"aria-describedby="h{n}-tip-"#),
        )
        .replace(r#"id="ov-since-h""#, &format!(r#"id="h{n}-ov-since-h""#))
        .replace(
            r#"id="since-tier-zero""#,
            &format!(r#"id="h{n}-since-tier-zero""#),
        )
        .replace(
            r#"aria-labelledby="ov-since-h""#,
            &format!(r#"aria-labelledby="h{n}-ov-since-h""#),
        )
}

#[cfg(test)]
#[path = "accounts_browser_tests.rs"]
mod accounts_browser_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// An event document with `zones` Privilege Zones, `fixes` steps and
    /// `padding` bytes of spaces among its findings, gzipped into a file.
    fn event_file(name: &str, zones: usize, fixes: usize, padding: usize) -> PathBuf {
        let zone = |name: &str| {
            format!(
                r#"{{"zone":"{name}","objects":3,"population":10,"relevant_population":8,"exposed":2,"exposure_percent":25.0,"exposure_grade":"High","grade_reason":"x","reason":{{"text":"2 accounts can take it over."}},"objects_with_findings":1,"protection_score":66.7}}"#
            )
        };
        let fix = r#"{"from":"ANN@CONTOSO.LOCAL","from_kind":"User","edges":["GenericAll","NoSuchKind"],"to":"DOMAIN ADMINS@CONTOSO.LOCAL","to_kind":"Group","cost":1,"principals_through":2,"shortest_paths_through":2,"sdprop_copies":0,"inherited_by":0,"action":"x"}"#;
        let zones: Vec<String> = (0..zones).map(|i| zone(&format!("Z{i}"))).collect();
        let fixes: Vec<&str> = (0..fixes).map(|_| fix).collect();
        let head = format!(
            r#"{{"schema":"pathwarden.event.v1","run":{{"collected_at":1800000000}},"posture":{{"tier_zero":{},"zones":[{}],"findings":{{"attack_path":1,"hygiene":0,"suppressed":0,"critical":0,"high":1,"medium":0,"low":0,"info":0}},"completeness":[],"exposure_basis":2,"activity_days":90}},"findings":["#,
            zone("Tier Zero"),
            zones.join(",")
        );
        let tail = format!(
            r#"],"resolved":[],"held":[],"plan":{{"exposed_before":2,"exposed_after":0,"fixes":[{}]}}}}"#,
            fixes.join(",")
        );
        let path = std::env::temp_dir().join(format!(
            "pathwarden-home-overview-{name}-{}.json.gz",
            std::process::id()
        ));
        let mut gz = flate2::write::GzEncoder::new(
            std::fs::File::create(&path).unwrap(),
            flate2::Compression::fast(),
        );
        gz.write_all(head.as_bytes()).unwrap();
        let spaces = vec![b' '; 1 << 20];
        let mut left = padding;
        while left > 0 {
            let n = left.min(spaces.len());
            gz.write_all(&spaces[..n]).unwrap();
            left -= n;
        }
        gz.write_all(tail.as_bytes()).unwrap();
        gz.finish().unwrap();
        path
    }

    #[test]
    fn reads_the_first_step_and_how_many() {
        let path = event_file("steps", 2, 3, 10);
        let d: LoadedData = read_event(&path, EVENT_LIMIT).unwrap().into();
        assert_eq!(d.plan_steps, 3);
        let first = d.first_step.unwrap();
        assert_eq!(first.from, "ANN@CONTOSO.LOCAL");
        // A kind this computer doesn't know is a plain permission.
        assert_eq!(
            first.edges[1],
            EdgeKind::External(pathwarden_core::kinds::OTHER)
        );
        assert_eq!(d.posture.zones.len(), 2);
        assert_eq!(d.collected_at, Some(1_800_000_000));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_event_too_large_or_with_too_many_zones_isnt_read() {
        // Over the limit: not read, though it is a whole document.
        let path = event_file("large", 0, 1, EVENT_LIMIT as usize);
        assert!(read_event(&path, EVENT_LIMIT).is_none());
        assert!(read_event(&path, 2 * EVENT_LIMIT).is_some());
        let _ = std::fs::remove_file(&path);
        let path = event_file("zones", MAX_ZONES + 1, 1, 0);
        assert!(read_event(&path, EVENT_LIMIT).is_none());
        let _ = std::fs::remove_file(&path);
    }

    const REPORT: &str = r##"<html><section id="overview" class="panel"><h2>Overview</h2><div class="hero card"><div class="hero-status"><p><a href="#rule-PW-006">10</a><span class="tip"><button aria-describedby="tip-takeover"><svg class="ic"><use href="#i-info"/></svg></button><span id="tip-takeover">x</span></span></p></div><div class="hero-trend"><svg></svg></div></div><div class="card ov-since" role="region" aria-labelledby="ov-since-h"><h3 id="ov-since-h">What changed</h3></div><div class="ov-cards"><div class="card ov-card">5 <a href="#step-1">go</a></div><div class="card ov-card">19</div></div><div class="sev-cards"><div>not this</div></div></section>"##;

    #[test]
    fn lifts_the_hero_what_changed_and_the_cards() {
        let f = extract(REPORT).unwrap();
        assert!(f.starts_with(r#"<div class="hero card">"#), "{f}");
        assert!(
            f.ends_with(r#"<div class="card ov-card">19</div></div>"#),
            "{f}"
        );
        assert!(f.contains("What changed"));
        assert!(!f.contains("not this"));
        let l = localize(&f, "20261020-1", 0);
        assert!(
            l.contains(r##"href="/runs/20261020-1#rule-PW-006""##),
            "{l}"
        );
        assert!(l.contains(r##"href="/runs/20261020-1#step-1""##), "{l}");
        // Icons stay on the page's sprite.
        assert!(l.contains(r##"<use href="#i-info"/>"##), "{l}");
        assert!(l.contains(r#"aria-describedby="h0-tip-takeover""#), "{l}");
        assert!(l.contains(r#"id="h0-tip-takeover""#), "{l}");
        assert!(l.contains(r#"aria-labelledby="h0-ov-since-h""#), "{l}");
        assert!(l.contains(r#"id="h0-ov-since-h""#), "{l}");
    }

    /// What changed's accounts keep one anchor per card on Home, and the
    /// hero's link to them goes to the run page.
    #[test]
    fn the_accounts_anchor_is_made_unique() {
        let l = localize(
            r##"<a class="delta-link" href="#since-tier-zero">2</a><details class="wc-more wc-accts" id="since-tier-zero"><a class="acc-base" href="#plan" hidden></a></details>"##,
            "20261020-1",
            3,
        );
        assert!(
            l.contains(r##"href="/runs/20261020-1#since-tier-zero""##),
            "{l}"
        );
        assert!(l.contains(r#"id="h3-since-tier-zero""#), "{l}");
        assert!(l.contains(r##"href="/runs/20261020-1#plan""##), "{l}");
    }

    #[test]
    fn a_report_without_the_hero_has_none() {
        assert_eq!(
            extract(r#"<section id="overview"><div class="cards"></div></section>"#),
            None
        );
        // Cut short: no end found.
        assert_eq!(
            extract(r#"<section id="overview"><div class="hero card"><div>"#),
            None
        );
    }

    #[test]
    fn what_changed_is_optional() {
        let r = REPORT.replace(
            r#"<div class="card ov-since" role="region" aria-labelledby="ov-since-h"><h3 id="ov-since-h">What changed</h3></div>"#,
            "",
        );
        let f = extract(&r).unwrap();
        assert!(!f.contains("What changed"));
        assert!(f.contains("ov-cards"));
    }

    #[test]
    fn skips_the_severities_for_what_changed_under_them() {
        let r = r#"<section id="overview"><div class="hero card">h</div><div class="ov-cards">c</div><div class="ov-sev"><div class="sevcards">s</div></div><div class="ov-since">w</div><p>not this</p></section>"#;
        assert_eq!(
            extract(r).unwrap(),
            r#"<div class="hero card">h</div><div class="ov-cards">c</div><div class="ov-since">w</div>"#
        );
    }
}
