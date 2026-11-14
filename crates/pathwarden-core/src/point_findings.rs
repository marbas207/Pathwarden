//! The findings of a run recorded in the history, from the findings state
//! (`findings.json`): for a run with no full run to open (a "numbers only"
//! point), the small run page and `pathwarden runs show` list them.
//!
//! A history point keeps counts, not findings. The findings state keeps
//! one record per finding with the latest of each date: first and last
//! seen, last fixed, last back. So a past run's findings can only be told
//! from it in part, and every part is checked against the point's own
//! counts before it is named:
//!
//! - **new, back, fixed**: each kind is named only when the findings the
//!   state dates to that run are exactly as many as the point counted
//!   ([`Kind::named`]); a finding fixed, back and fixed again loses its
//!   earlier dates, so its earlier runs fall short and say the count only.
//! - **still open**: named ([`PointFindings::complete`]) for the
//!   environment's latest run, whose findings are exactly those last seen
//!   then; for an earlier run only when nothing could have hidden a
//!   finding's absence (held domains, a rule turned off, a run inserted
//!   later, a finding gone and back since) and the findings the dates place
//!   in it add up to the point's counts, severity by severity.
//!
//! Titles and severities are what the state has now: as the last run that
//! saw each finding had them.

use serde::Serialize;

use crate::findings::Severity;
use crate::state::{FindingsState, HistoryPoint, Status, TrackedFinding};

/// What a finding was in that run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointChange {
    /// First seen in that run.
    New,
    /// Fixed before, and back in that run.
    Back,
    /// Seen before and still there.
    Open,
    /// Gone in that run (fixed).
    Fixed,
}

impl PointChange {
    /// The tag a list shows for it (none for open).
    pub fn words(self) -> &'static str {
        match self {
            PointChange::New => "New",
            PointChange::Back => "Back",
            PointChange::Open => "",
            PointChange::Fixed => "Fixed",
        }
    }
}

/// A finding of the run.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PointFinding {
    pub fingerprint: String,
    pub rule: String,
    /// As the last run that saw it had it.
    pub severity: Severity,
    /// As the history keeps it now: absent when it kept numbers only.
    pub title: Option<String>,
    pub change: PointChange,
}

/// New, back or fixed findings of the run: how many the point counted, and
/// whether they are named ([`PointFindings::items`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Kind {
    /// The point's own count.
    pub count: usize,
    /// The state dates exactly that many to the run: they are listed.
    pub named: bool,
}

/// The findings of one run.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PointFindings {
    /// The findings still open in the run are all listed. False: none of
    /// them is, since the state can't tell them apart.
    pub complete: bool,
    pub new: Kind,
    pub back: Kind,
    pub fixed: Kind,
    /// The named findings: the run's, then those it fixed; most severe
    /// first in each.
    pub items: Vec<PointFinding>,
}

impl PointFindings {
    pub fn kind(&self, change: PointChange) -> Option<Kind> {
        match change {
            PointChange::New => Some(self.new),
            PointChange::Back => Some(self.back),
            PointChange::Fixed => Some(self.fixed),
            PointChange::Open => None,
        }
    }
}

/// The findings of run `p`, one of the history's `points`, by the findings
/// state `state`.
pub fn point_findings(
    points: &[HistoryPoint],
    p: &HistoryPoint,
    state: &FindingsState,
) -> PointFindings {
    let at = p.at;
    let env = |q: &HistoryPoint| q.scopes == p.scopes;
    // Only this environment's findings (a finding without a domain could
    // be anyone's: the dates decide).
    let ours = |t: &TrackedFinding| match &t.scope {
        Some(s) if !p.scopes.is_empty() => p.scopes.iter().any(|k| k == s),
        _ => true,
    };
    // The environment's latest run: its findings are those last seen then.
    let latest = !p.inserted
        && !points
            .iter()
            .any(|q| env(q) && !q.inserted && q.at > at && q.run_id != p.run_id);
    let mut items = Vec::new();
    let mut unknown = 0usize;
    for (fp, t) in state.findings.iter().filter(|(_, t)| ours(t)) {
        let change = if t.resolved_at == Some(at) {
            // Gone in it. Set aside because its rule was turned off isn't a
            // fix (and the point doesn't count it as one).
            if t.rule_off || t.status != Status::Resolved {
                continue;
            }
            PointChange::Fixed
        } else if t.first_seen == at {
            PointChange::New
        } else if t.regressed_at == Some(at) {
            PointChange::Back
        } else if latest {
            if t.last_seen != at || t.status == Status::Resolved {
                continue;
            }
            PointChange::Open
        } else if t.first_seen < at && t.last_seen >= at {
            // Gone and back since it was first seen: whether it was there
            // in that run isn't kept.
            if t.regressed_at.is_some_and(|back| back > at) {
                unknown += 1;
            }
            PointChange::Open
        } else {
            continue;
        };
        items.push(PointFinding {
            fingerprint: fp.clone(),
            rule: t.rule.clone(),
            severity: t.severity,
            title: t.title.clone(),
            change,
        });
    }
    let kind = |change: PointChange, count: usize| Kind {
        count,
        named: items.iter().filter(|f| f.change == change).count() == count,
    };
    let (new, back, fixed) = (
        kind(PointChange::New, p.changes.new),
        kind(PointChange::Back, p.changes.regressed),
        kind(PointChange::Fixed, p.changes.resolved),
    );

    // The open ones: only where nothing could hide a finding's absence.
    let c = &p.findings;
    let present: Vec<&PointFinding> = items
        .iter()
        .filter(|f| f.change != PointChange::Fixed)
        .collect();
    let open_now = |s: Severity| {
        present
            .iter()
            .filter(|f| f.severity == s)
            .filter(|f| state.findings[&f.fingerprint].status != Status::Suppressed)
            .count()
    };
    let rule_was_off = points
        .iter()
        .any(|q| env(q) && q.at <= at && q.changes.unchecked > 0);
    let complete = new.named
        && back.named
        && !p.inserted
        && p.changes.held == 0
        && (latest || (!rule_was_off && unknown == 0))
        && present.len() == c.critical + c.high + c.medium + c.low + c.info + c.suppressed
        && [
            (Severity::Critical, c.critical),
            (Severity::High, c.high),
            (Severity::Medium, c.medium),
            (Severity::Low, c.low),
            (Severity::Info, c.info),
        ]
        .iter()
        .all(|&(s, n)| open_now(s) == n);
    items.retain(|f| match f.change {
        PointChange::Open => complete,
        PointChange::New => new.named,
        PointChange::Back => back.named,
        PointChange::Fixed => fixed.named,
    });
    items.sort_by(|a, b| {
        (a.change == PointChange::Fixed)
            .cmp(&(b.change == PointChange::Fixed))
            .then(b.severity.cmp(&a.severity))
            .then(a.change.cmp(&b.change))
            .then(a.rule.cmp(&b.rule))
            .then(a.title.cmp(&b.title))
            .then(a.fingerprint.cmp(&b.fingerprint))
    });
    PointFindings {
        complete,
        new,
        back,
        fixed,
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(json: &[String]) -> FindingsState {
        serde_json::from_str(&format!(
            r#"{{"version":1,"findings":{{{}}}}}"#,
            json.join(",")
        ))
        .unwrap()
    }

    fn finding(fp: &str, sev: &str, status: &str, extra: &str) -> String {
        format!(
            r#""{fp}":{{"rule":"PW-001","severity":"{sev}","category":"attack_path","status":"{status}","times_seen":1,"title":"{fp} title","scope":"s1",{extra}}}"#
        )
    }

    /// A point at `at` with `high` open high findings and its changes:
    /// new, back, fixed, held, unchecked.
    fn point(at: i64, high: usize, ch: [usize; 5]) -> HistoryPoint {
        let mut p: HistoryPoint = serde_json::from_value(serde_json::json!({
            "version": 1, "run_id": format!("r{at}"), "at": at, "collected_at": null,
            "tier_zero_exposure_percent": 0.0, "tier_zero_exposed": 0,
            "tier_zero_population": 0, "tier_zero_objects": 0,
            "protection_score": null,
            "findings": {"attack_path": 0, "hygiene": 0, "critical": 0, "high": high, "medium": 0, "low": 0, "info": 0, "suppressed": 0},
            "changes": {"new": ch[0], "open": 0, "regressed": ch[1], "suppressed": 0, "resolved": ch[2], "held": ch[3], "unchecked": ch[4]},
        }))
        .unwrap();
        p.scopes = vec!["s1".into()];
        p
    }

    fn changes(f: &PointFindings) -> Vec<(&str, PointChange)> {
        f.items
            .iter()
            .map(|i| (i.fingerprint.as_str(), i.change))
            .collect()
    }

    #[test]
    fn a_past_run_is_told_from_the_dates() {
        let s = state(&[
            finding("a", "high", "open", r#""first_seen":100,"last_seen":300"#),
            finding("b", "high", "open", r#""first_seen":200,"last_seen":300"#),
            finding("c", "critical", "resolved", r#""first_seen":100,"last_seen":100,"resolved_at":200"#),
            // Another environment's.
            r#""z":{"rule":"PW-002","severity":"high","category":"attack_path","status":"open","first_seen":100,"last_seen":300,"times_seen":3,"scope":"other"}"#.to_string(),
        ]);
        let points = [
            point(100, 1, [2, 0, 0, 0, 0]),
            point(200, 2, [1, 0, 1, 0, 0]),
            point(300, 2, [0, 0, 0, 0, 0]),
        ];
        let f = point_findings(&points, &points[1], &s);
        assert!(f.complete, "{f:?}");
        assert!(f.new.named && f.fixed.named && f.back.named);
        assert_eq!(
            changes(&f),
            [
                ("b", PointChange::New),
                ("a", PointChange::Open),
                ("c", PointChange::Fixed)
            ]
        );
        assert_eq!(f.items[0].title.as_deref(), Some("b title"));
        // The latest: exactly what was last seen then.
        let f = point_findings(&points, &points[2], &s);
        assert!(f.complete, "{f:?}");
        assert_eq!(
            changes(&f),
            [("a", PointChange::Open), ("b", PointChange::Open)]
        );
    }

    /// Fixed, back, fixed: the state keeps the latest dates only, so the
    /// earlier runs say their counts without names.
    #[test]
    fn fixed_back_and_fixed_again() {
        let s = state(&[
            finding(
                "a",
                "high",
                "resolved",
                r#""first_seen":100,"last_seen":300,"resolved_at":400,"regressed_at":300"#,
            ),
            finding("k", "high", "open", r#""first_seen":100,"last_seen":400"#),
        ]);
        let points = [
            point(100, 2, [2, 0, 0, 0, 0]),
            point(200, 1, [0, 0, 1, 0, 0]),
            point(300, 2, [0, 1, 0, 0, 0]),
            point(400, 1, [0, 0, 1, 0, 0]),
        ];
        // At 200, a was fixed: that date is gone.
        let f = point_findings(&points, &points[1], &s);
        assert_eq!(
            f.fixed,
            Kind {
                count: 1,
                named: false
            }
        );
        assert!(!f.complete, "a may have been gone: {f:?}");
        assert!(f.items.is_empty(), "{f:?}");
        // At 300 it was back, at 400 fixed again: both named.
        let f = point_findings(&points, &points[2], &s);
        assert_eq!(
            f.back,
            Kind {
                count: 1,
                named: true
            }
        );
        assert!(changes(&f).contains(&("a", PointChange::Back)), "{f:?}");
        let f = point_findings(&points, &points[3], &s);
        assert_eq!(
            f.fixed,
            Kind {
                count: 1,
                named: true
            }
        );
        assert!(f.complete, "{f:?}");
        assert_eq!(
            changes(&f),
            [("k", PointChange::Open), ("a", PointChange::Fixed)]
        );
        // At 100 both were new.
        let f = point_findings(&points, &points[0], &s);
        assert_eq!(
            f.new,
            Kind {
                count: 2,
                named: true
            }
        );
    }

    /// A domain not collected (held) or a rule turned off: a finding's
    /// absence then leaves no trace, so the open ones aren't named.
    #[test]
    fn held_domains_and_rules_turned_off() {
        let s = state(&[
            finding("a", "high", "open", r#""first_seen":100,"last_seen":400"#),
            finding("b", "high", "open", r#""first_seen":100,"last_seen":400"#),
        ]);
        // b's domain wasn't collected at 200; at 300 its rule was off.
        let points = [
            point(100, 2, [2, 0, 0, 0, 0]),
            point(200, 1, [0, 0, 0, 1, 0]),
            point(300, 1, [0, 0, 0, 0, 1]),
            point(350, 2, [0, 0, 0, 0, 0]),
            point(400, 2, [0, 0, 0, 0, 0]),
        ];
        for i in [1, 2, 3] {
            let f = point_findings(&points, &points[i], &s);
            assert!(!f.complete, "{i}: {f:?}");
            assert!(f.items.is_empty(), "{i}: {f:?}");
        }
        // Severity by severity: counts that match in all but not by
        // severity aren't enough.
        let s2 = state(&[
            finding(
                "a",
                "critical",
                "open",
                r#""first_seen":100,"last_seen":400"#,
            ),
            finding("b", "high", "open", r#""first_seen":100,"last_seen":400"#),
        ]);
        let f = point_findings(&points, &points[0], &s2);
        assert!(!f.complete, "{f:?}");
        assert_eq!(
            f.new,
            Kind {
                count: 2,
                named: true
            }
        );
        // The latest is told exactly.
        let f = point_findings(&points, &points[4], &s);
        assert!(f.complete, "{f:?}");
        // A run inserted later never is.
        let mut p = points[3].clone();
        p.inserted = true;
        let f = point_findings(&points, &p, &s);
        assert!(!f.complete);
    }
}
