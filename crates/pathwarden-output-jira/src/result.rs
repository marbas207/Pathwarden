//! The result file Pathwarden names in `PATHWARDEN_OUTPUT_RESULT` on a
//! real run (`pathwarden.output-result.v1`): the issues this plugin keeps
//! for the event's findings, so they show on the findings. Never written
//! on a dry run or the offline preview, nor when Pathwarden names no file.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::event::Event;
use crate::reconcile::{Action, Issue};
use crate::settings::Settings;

pub const ENV: &str = "PATHWARDEN_OUTPUT_RESULT";
pub const SCHEMA: &str = "pathwarden.output-result.v1";

/// One issue on one finding, as the result file has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Record {
    pub fingerprint: String,
    /// The issue key.
    pub id: String,
    pub kind: &'static str,
    pub number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub status: String,
    pub open: bool,
}

/// Where to write the result: the file Pathwarden named (`var`), on a run
/// that changes Jira (`live`, not `dry_run`); else nowhere.
pub fn path_for(dry_run: bool, live: bool, var: Option<OsString>) -> Option<PathBuf> {
    if dry_run || !live {
        return None;
    }
    var.filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Writes `records` to `path`.
pub fn write(path: &Path, records: &[Record]) -> Result<()> {
    let doc = serde_json::json!({ "schema": SCHEMA, "records": records });
    let bytes = serde_json::to_vec(&doc).context("writing the result")?;
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

/// An issue as this run leaves it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Kept {
    open: bool,
    /// Its status name, as last read; `None` once this run moved it.
    status: Option<String>,
}

/// The issues this run leaves on the event's findings: each finding's
/// (and held finding's) issue as found, then as the actions that worked
/// changed it (created, reopened, closed; an issue closed because its
/// finding is gone too). A finding the action skip rule skipped is left
/// out: its record is the action's.
#[derive(Debug, Default)]
pub struct Tracker {
    by: BTreeMap<(String, String), Kept>,
}

impl Tracker {
    pub fn new(event: &Event, issues: &[Issue]) -> Self {
        let mut by_fp: BTreeMap<&str, &Issue> = BTreeMap::new();
        for i in issues {
            match by_fp.get(i.fingerprint.as_str()) {
                Some(existing) if existing.active || !i.active => {}
                _ => {
                    by_fp.insert(i.fingerprint.as_str(), i);
                }
            }
        }
        let mut by = BTreeMap::new();
        let present = event
            .findings
            .iter()
            .map(|f| f.fingerprint.as_str())
            .chain(event.held.iter().map(|h| h.fingerprint.as_str()));
        for fp in present {
            if let Some(i) = by_fp.get(fp) {
                by.insert(
                    (fp.to_string(), i.key.clone()),
                    Kept {
                        open: i.active,
                        status: i.status.clone(),
                    },
                );
            }
        }
        Tracker { by }
    }

    /// `action` was left out by the skip rule, or worked; `created` is the
    /// new issue's key for a create.
    pub fn done(&mut self, action: &Action, created: Option<String>) {
        match action {
            Action::Skip { fingerprint, .. } => self.by.retain(|(fp, _), _| fp != fingerprint),
            Action::Create { fingerprint, .. } => {
                if let Some(key) = created {
                    self.by.insert(
                        (fingerprint.clone(), key),
                        Kept {
                            open: true,
                            status: None,
                        },
                    );
                }
            }
            Action::Reopen {
                key, fingerprint, ..
            } => {
                if let Some(k) = self.by.get_mut(&(fingerprint.clone(), key.clone())) {
                    *k = Kept {
                        open: true,
                        status: None,
                    };
                }
            }
            Action::Resolve {
                key, fingerprint, ..
            } => {
                self.by.insert(
                    (fingerprint.clone(), key.clone()),
                    Kept {
                        open: false,
                        status: None,
                    },
                );
            }
            Action::Comment { .. } | Action::Info { .. } => {}
        }
    }

    /// The records for the result file. Links only for an `https://`
    /// instance.
    pub fn records(&self, settings: &Settings) -> Vec<Record> {
        let instance = settings.instance.trim().trim_end_matches('/');
        let https = instance
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("https://"));
        self.by
            .iter()
            .map(|((fp, key), k)| Record {
                fingerprint: fp.clone(),
                id: key.clone(),
                kind: "ticket",
                number: key.clone(),
                url: https.then(|| format!("{instance}/browse/{key}")),
                status: k
                    .status
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| if k.open { "Open" } else { "Done" }.to_string()),
                open: k.open,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Finding, Held, Run};

    fn settings() -> Settings {
        Settings::parse(r#"{"instance":"https://contoso.atlassian.net","project":"SEC"}"#).unwrap()
    }

    fn issue(fp: &str, key: &str, active: bool, status: &str) -> Issue {
        Issue {
            key: key.into(),
            fingerprint: fp.into(),
            active,
            resolution: None,
            creator: None,
            status: Some(status.into()),
        }
    }

    fn event(fps: &[&str], held: &[&str]) -> Event {
        Event {
            schema: "pathwarden.event.v1".into(),
            run: Run {
                run_id: "R1".into(),
            },
            findings: fps
                .iter()
                .map(|fp| Finding {
                    fingerprint: fp.to_string(),
                    ..Default::default()
                })
                .collect(),
            held: held
                .iter()
                .map(|fp| Held {
                    fingerprint: fp.to_string(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_real_run_writes_where_pathwarden_said_a_dry_run_never() {
        let var = Some(OsString::from("/work/output-result-1.json"));
        assert_eq!(
            path_for(false, true, var.clone()),
            Some(PathBuf::from("/work/output-result-1.json"))
        );
        assert_eq!(path_for(true, true, var.clone()), None, "dry run");
        assert_eq!(path_for(false, false, var), None, "offline preview");
        assert_eq!(path_for(false, true, None), None, "no file asked for");
    }

    #[test]
    fn issues_as_the_run_leaves_them() {
        let e = event(&["A", "B", "C", "H"], &["H"]);
        let issues = [
            issue("A", "SEC-1", true, "In Progress"),
            issue("B", "SEC-2", false, "Done"),
            issue("H", "SEC-4", true, "To Do"),
            issue("GONE", "SEC-5", true, "To Do"),
        ];
        let s = settings();
        let mut t = Tracker::new(&e, &issues);
        t.done(
            &Action::Create {
                fingerprint: "C".into(),
                issue: crate::reconcile::NewIssue {
                    summary: String::new(),
                    description: String::new(),
                    labels: Vec::new(),
                    priority: None,
                },
            },
            Some("SEC-7".into()),
        );
        t.done(
            &Action::Reopen {
                key: "SEC-2".into(),
                fingerprint: "B".into(),
                note: String::new(),
            },
            None,
        );
        t.done(
            &Action::Resolve {
                key: "SEC-5".into(),
                fingerprint: "GONE".into(),
                note: String::new(),
            },
            None,
        );
        let got: Vec<(String, String, String, bool)> = t
            .records(&s)
            .into_iter()
            .map(|r| (r.fingerprint, r.number, r.status, r.open))
            .collect();
        let want = [
            ("A", "SEC-1", "In Progress", true),
            ("B", "SEC-2", "Open", true),
            ("C", "SEC-7", "Open", true),
            ("GONE", "SEC-5", "Done", false),
            ("H", "SEC-4", "To Do", true),
        ];
        assert_eq!(
            got,
            want.map(|(a, b, c, d)| (a.into(), b.into(), c.into(), d))
        );
        assert_eq!(
            t.records(&s)[0].url.as_deref(),
            Some("https://contoso.atlassian.net/browse/SEC-1")
        );
    }

    #[test]
    fn skipped_findings_are_left_out() {
        let e = event(&["A"], &[]);
        let s = settings();
        let mut t = Tracker::new(&e, &[issue("A", "SEC-1", false, "Done")]);
        t.done(
            &Action::Skip {
                fingerprint: "A".into(),
                record: "RITM1".into(),
            },
            None,
        );
        assert!(t.records(&s).is_empty());
    }
}
