//! The result file Pathwarden names in `PATHWARDEN_OUTPUT_RESULT` on a
//! real run (`pathwarden.output-result.v1`): the tickets this plugin keeps
//! for the event's findings, so they show on the findings. Never written
//! on a dry run or the offline preview, nor when Pathwarden names no file.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::event::Event;
use crate::reconcile::{Action, Ticket};
use crate::settings::Settings;

pub const ENV: &str = "PATHWARDEN_OUTPUT_RESULT";
pub const SCHEMA: &str = "pathwarden.output-result.v1";

/// One ticket on one finding, as the result file has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Record {
    pub fingerprint: String,
    /// The ticket's sys_id (its number when ServiceNow didn't say).
    pub id: String,
    pub kind: &'static str,
    pub number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub status: String,
    pub open: bool,
}

/// Where to write the result: the file Pathwarden named (`var`), on a run
/// that changes ServiceNow (`live`, not `dry_run`); else nowhere.
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

/// A ticket as this run leaves it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Kept {
    number: String,
    sys_id: Option<String>,
    open: bool,
    /// Closed by being resolved (the state this plugin resolves to).
    resolved: bool,
}

/// The tickets this run leaves on the event's findings: each finding's
/// (and held finding's) ticket as found, then as the actions that worked
/// changed it (created, reopened, resolved; a ticket resolved because its
/// finding is gone too). A finding the action skip rule skipped is left
/// out: its record is the action's.
#[derive(Debug, Default)]
pub struct Tracker {
    by: BTreeMap<(String, String), Kept>,
}

impl Tracker {
    pub fn new(event: &Event, tickets: &[Ticket], settings: &Settings) -> Self {
        let resolved_state = settings
            .resolve_fields()
            .get("state")
            .and_then(|v| match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            });
        let mut by_fp: BTreeMap<&str, &Ticket> = BTreeMap::new();
        for t in tickets {
            match by_fp.get(t.correlation_id.as_str()) {
                Some(existing) if existing.active || !t.active => {}
                _ => {
                    by_fp.insert(t.correlation_id.as_str(), t);
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
            if let Some(t) = by_fp.get(fp) {
                by.insert(
                    (fp.to_string(), t.sys_id.clone()),
                    Kept {
                        number: t.number.clone(),
                        sys_id: Some(t.sys_id.clone()),
                        open: t.active,
                        resolved: !t.active
                            && resolved_state.is_some()
                            && t.state == resolved_state,
                    },
                );
            }
        }
        Tracker { by }
    }

    /// `action` was left out by the skip rule, or worked; `created` is the
    /// new ticket's number and sys_id for a create.
    pub fn done(&mut self, action: &Action, created: Option<(String, Option<String>)>) {
        match action {
            Action::Skip { fingerprint, .. } => self.by.retain(|(fp, _), _| fp != fingerprint),
            Action::Create { fingerprint, .. } => {
                if let Some((number, sys_id)) = created {
                    let id = sys_id.clone().unwrap_or_else(|| number.clone());
                    self.by.insert(
                        (fingerprint.clone(), id),
                        Kept {
                            number,
                            sys_id,
                            open: true,
                            resolved: false,
                        },
                    );
                }
            }
            Action::Reopen {
                fingerprint,
                sys_id,
                ..
            } => {
                if let Some(k) = self.by.get_mut(&(fingerprint.clone(), sys_id.clone())) {
                    k.open = true;
                    k.resolved = false;
                }
            }
            Action::Resolve {
                ticket,
                sys_id,
                fingerprint,
                ..
            } => {
                let k = self
                    .by
                    .entry((fingerprint.clone(), sys_id.clone()))
                    .or_insert_with(|| Kept {
                        number: ticket.clone(),
                        sys_id: Some(sys_id.clone()),
                        open: true,
                        resolved: false,
                    });
                k.open = false;
                k.resolved = true;
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
        let table = settings.table.trim();
        self.by
            .iter()
            .map(|((fp, id), k)| Record {
                fingerprint: fp.clone(),
                id: id.clone(),
                kind: "ticket",
                number: k.number.clone(),
                url: k
                    .sys_id
                    .as_ref()
                    .filter(|_| https)
                    .map(|s| format!("{instance}/{table}.do?sys_id={s}")),
                status: if k.open {
                    "Open"
                } else if k.resolved {
                    "Resolved"
                } else {
                    "Closed"
                }
                .to_string(),
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
        Settings::parse(r#"{"instance":"https://x.service-now.com"}"#).unwrap()
    }

    fn ticket(fp: &str, number: &str, active: bool) -> Ticket {
        Ticket {
            sys_id: format!("{:0>32}", number.to_ascii_lowercase().replace("inc", "")),
            number: number.into(),
            correlation_id: fp.into(),
            active,
            state: (!active).then(|| "6".to_string()),
            close_code: None,
            created_by: None,
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
        let var = Some(OsString::from("C:\\work\\output-result-1.json"));
        assert_eq!(
            path_for(false, true, var.clone()),
            Some(PathBuf::from("C:\\work\\output-result-1.json"))
        );
        assert_eq!(path_for(true, true, var.clone()), None, "dry run");
        assert_eq!(path_for(false, false, var), None, "offline preview");
        assert_eq!(path_for(false, true, None), None, "no file asked for");
        assert_eq!(path_for(false, true, Some(OsString::new())), None);
    }

    #[test]
    fn tickets_as_the_run_leaves_them() {
        let e = event(&["A", "B", "C", "H"], &["H"]);
        let tickets = [
            ticket("A", "INC1", true),
            ticket("B", "INC2", false),
            ticket("H", "INC4", true),
            ticket("GONE", "INC5", true),
            ticket("OLD", "INC6", false),
        ];
        let s = settings();
        let mut t = Tracker::new(&e, &tickets, &s);
        // C gets a new ticket, B's is reopened, GONE's is resolved.
        t.done(
            &Action::Create {
                fingerprint: "C".into(),
                fields: Default::default(),
            },
            Some(("INC7".into(), Some("c".repeat(32)))),
        );
        t.done(
            &Action::Reopen {
                ticket: "INC2".into(),
                sys_id: tickets[1].sys_id.clone(),
                fingerprint: "B".into(),
                fields: Default::default(),
            },
            None,
        );
        t.done(
            &Action::Resolve {
                ticket: "INC5".into(),
                sys_id: tickets[3].sys_id.clone(),
                fingerprint: "GONE".into(),
                fields: Default::default(),
            },
            None,
        );
        let got: Vec<(String, String, String, bool)> = t
            .records(&s)
            .into_iter()
            .map(|r| (r.fingerprint, r.number, r.status, r.open))
            .collect();
        let want = [
            ("A", "INC1", "Open", true),
            ("B", "INC2", "Open", true),
            ("C", "INC7", "Open", true),
            ("GONE", "INC5", "Resolved", false),
            ("H", "INC4", "Open", true),
        ];
        assert_eq!(
            got,
            want.map(|(a, b, c, d)| (a.into(), b.into(), c.into(), d))
        );
        let r = t.records(&s);
        assert_eq!(
            r[0].url.as_deref(),
            Some(
                format!(
                    "https://x.service-now.com/incident.do?sys_id={}",
                    tickets[0].sys_id
                )
                .as_str()
            )
        );
        assert_eq!(r[2].id, "c".repeat(32));
    }

    #[test]
    fn skipped_findings_and_failed_creates_are_left_out() {
        let e = event(&["A", "B"], &[]);
        let tickets = [ticket("A", "INC1", false)];
        let s = settings();
        let mut t = Tracker::new(&e, &tickets, &s);
        t.done(
            &Action::Skip {
                fingerprint: "A".into(),
                record: "RITM1".into(),
            },
            None,
        );
        // A create that failed reports nothing.
        t.done(
            &Action::Create {
                fingerprint: "B".into(),
                fields: Default::default(),
            },
            None,
        );
        assert!(t.records(&s).is_empty());
    }

    #[test]
    fn no_links_for_a_plain_http_instance() {
        let s =
            Settings::parse(r#"{"instance":"http://localhost:8080","allow_insecure_http":true}"#)
                .unwrap();
        let e = event(&["A"], &[]);
        let t = Tracker::new(&e, &[ticket("A", "INC1", true)], &s);
        assert_eq!(t.records(&s)[0].url, None);
    }

    #[test]
    fn the_file_has_the_schema_and_records() {
        let dir = std::env::temp_dir().join(format!("pw-sn-result-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.json");
        let r = Record {
            fingerprint: "A".into(),
            id: "x".into(),
            kind: "ticket",
            number: "INC1".into(),
            url: None,
            status: "Open".into(),
            open: true,
        };
        write(&path, &[r]).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["records"][0]["number"], "INC1");
        assert_eq!(v["records"][0]["open"], true);
        assert!(v["records"][0].get("url").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
