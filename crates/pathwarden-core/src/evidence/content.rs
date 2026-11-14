//! What goes into an evidence pack: the documents, built from a retest and
//! the state, with names left out when the pack is redacted.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use crate::diagnostics;
use crate::findings::{self, Finding};
use crate::retest::{FindingView, RetestReport};
use crate::state::{FindingsState, HistoryPoint, TrackedFinding};
use crate::time::format_utc;
use anyhow::{bail, Result};
use serde_json::{json, Value};

use super::pack::{hash_file, iso, sha256_hex};

/// One collector (or other input) file, hashed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InputFile {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Inputs {
    pub files: Vec<InputFile>,
}

impl Inputs {
    /// SHA-256 over the sorted file hashes, one lowercase hex hash per line
    /// (each followed by `\n`): one number for the whole collection that
    /// needs no file names, so a redacted pack has it too.
    pub fn combined(&self) -> String {
        let mut hashes: Vec<&str> = self.files.iter().map(|f| f.sha256.as_str()).collect();
        hashes.sort_unstable();
        let text: String = hashes.iter().map(|h| format!("{h}\n")).collect();
        sha256_hex(text.as_bytes())
    }

    fn to_json(&self, redact: bool) -> Value {
        json!({
            "collector": collector_hint(&self.files),
            "files": self.files.iter().map(|f| {
                let mut v = json!({"sha256": f.sha256, "bytes": f.bytes});
                if !redact {
                    v["name"] = json!(f.name);
                }
                v
            }).collect::<Vec<_>>(),
            "combined_sha256": self.combined(),
        })
    }
}

/// Hashes the files the analysis read, exactly as the loader picks them
/// ([`crate::ingest::files_read`]): each given file, and the `.json` and
/// `.zip` files below each given folder, links not followed, each once.
/// A file below a folder is named by its path in that folder.
pub fn hash_inputs(paths: &[PathBuf]) -> Result<Inputs> {
    let mut files = Vec::new();
    for (root, path) in crate::ingest::files_read(paths) {
        let (sha256, bytes) = hash_file(&path)?;
        let name = if root == path {
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            let rel: &Path = path.strip_prefix(&root).unwrap_or(&path);
            rel.to_string_lossy().replace('\\', "/")
        };
        files.push(InputFile {
            name,
            sha256,
            bytes,
        });
    }
    Ok(Inputs { files })
}

/// The collector, as far as the file names tell: SharpHound names its zip
/// `<time>_BloodHound[-<version>].zip`, RustHound-CE (and Pathwarden's
/// built-in collector, which is RustHound-CE) `<time>_<domain>_rusthound-ce.zip`.
pub fn collector_hint(files: &[InputFile]) -> String {
    let mut seen: Vec<String> = Vec::new();
    for f in files {
        let lower = f.name.to_ascii_lowercase();
        let base = lower.rsplit('/').next().unwrap_or(&lower);
        let hint = if let Some(i) = base.find("_bloodhound") {
            let rest = &base[i + "_bloodhound".len()..];
            match rest
                .strip_prefix('-')
                .and_then(|v| v.strip_suffix(".zip"))
                .filter(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
            {
                Some(v) => format!("SharpHound {v}"),
                None => "SharpHound".to_string(),
            }
        } else if base.contains("rusthound") {
            "RustHound-CE".to_string()
        } else {
            continue;
        };
        if !seen.contains(&hint) {
            seen.push(hint);
        }
    }
    if seen.is_empty() {
        "a BloodHound-compatible collector (not named in the files)".to_string()
    } else {
        seen.join(", ")
    }
}

/// One finding of the "after" side, as the pack shows it: the finding as
/// `findings --json` writes it, with the parts the redaction needs.
#[derive(Debug, Clone)]
pub struct Fresh {
    pub fingerprint: String,
    pub category: Value,
    pub domain: Option<String>,
    /// Its affected objects: (ID, name).
    pub affected: Vec<(String, String)>,
    pub json: Value,
}

impl Fresh {
    pub fn from_finding(f: &Finding) -> Self {
        Fresh {
            fingerprint: f.fingerprint.clone(),
            category: json!(f.category),
            domain: f.domain.clone(),
            affected: f
                .affected
                .iter()
                .map(|a| (a.id.clone(), a.name.clone()))
                .collect(),
            json: serde_json::to_value(f).unwrap_or(Value::Null),
        }
    }

    /// One finding of an event document (`pathwarden.event.v1`): the
    /// finding without the run's own fields (its change, when it was first
    /// seen, how often), as `findings --json` writes it.
    pub fn from_event(v: &Value) -> Option<Self> {
        let mut json = v.clone();
        let o = json.as_object_mut()?;
        for k in ["change", "first_seen", "times_seen"] {
            o.remove(k);
        }
        let fingerprint = o.get("fingerprint")?.as_str()?.to_string();
        let affected = o
            .get("affected")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|x| {
                        let s = |k: &str| x[k].as_str().unwrap_or_default().to_string();
                        (s("id"), s("name"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let category = o.get("category").cloned().unwrap_or(Value::Null);
        let domain = o.get("domain").and_then(Value::as_str).map(str::to_string);
        Some(Fresh {
            fingerprint,
            category,
            domain,
            affected,
            json,
        })
    }
}

/// What the "after" side of a pack is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum After {
    /// A collection analyzed when the pack was made (`pathwarden evidence
    /// -i`), not recorded as a run.
    Fresh,
    /// A run saved earlier (`pathwarden evidence --run`, the app's run
    /// page): its findings and report as they were saved.
    Run {
        /// When the run was analyzed.
        analyzed_at: i64,
        /// Whether the run is recorded in the run history.
        recorded: bool,
    },
}

/// SHA-256 of the running executable.
pub fn binary_hash() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    hash_file(&exe).ok().map(|(h, _)| h)
}

fn rule_title(rule: &str) -> String {
    findings::rules()
        .iter()
        .find(|r| r.id.eq_ignore_ascii_case(rule))
        .map(|r| r.title.to_string())
        .unwrap_or_else(|| rule.to_string())
}

fn when(t: Option<i64>) -> Value {
    match t {
        Some(t) => json!({"unix": t, "utc": iso(t)}),
        None => Value::Null,
    }
}

/// Everything a pack is built from.
pub struct Sources<'a> {
    pub created_at: i64,
    pub redact: bool,
    pub report: &'a RetestReport,
    /// "state", "collection" or "event".
    pub baseline_kind: &'a str,
    pub baseline_label: &'a str,
    pub baseline_run_id: Option<&'a str>,
    pub baseline_collected_at: Option<i64>,
    pub baseline_views: &'a [FindingView],
    /// The baseline collection's files (`--baseline` with a collection).
    pub baseline_inputs: Option<&'a Inputs>,
    pub after: After,
    pub after_run_id: &'a str,
    pub after_collected_at: Option<i64>,
    /// The collector files analyzed; `None` for a run saved before they
    /// were hashed.
    pub inputs: Option<&'a Inputs>,
    pub domains: &'a [String],
    pub objects: usize,
    pub fresh: &'a [Fresh],
    pub state: Option<&'a FindingsState>,
    /// The run history has runs after this one, so its findings state is
    /// not this run's: `state` is left out, and the pack says so.
    pub state_left_out: bool,
    pub history: &'a [HistoryPoint],
    pub config_sha256: Option<String>,
    pub config_name: Option<String>,
    /// Without `config_sha256`: why there is none, when it isn't that no
    /// config file was used (the built-in defaults).
    pub config_note: Option<&'a str>,
    pub binary_sha256: Option<String>,
    pub selection_findings: &'a [String],
    pub selection_rules: &'a [String],
}

impl Sources<'_> {
    fn tracked(&self, fp: &str) -> Option<&TrackedFinding> {
        self.state.and_then(|s| s.findings.get(fp))
    }

    fn before(&self) -> Value {
        let mut v = json!({
            "kind": self.baseline_kind,
            "run_id": self.baseline_run_id,
            "collected_at": when(self.baseline_collected_at),
        });
        if !self.redact {
            v["description"] = json!(self.baseline_label);
        }
        if let Some(i) = self.baseline_inputs {
            v["collection"] = i.to_json(self.redact);
        }
        v
    }

    fn analyzed_at(&self) -> i64 {
        match self.after {
            After::Fresh => self.created_at,
            After::Run { analyzed_at, .. } => analyzed_at,
        }
    }

    fn collection_json(&self) -> Value {
        match self.inputs {
            Some(i) => i.to_json(self.redact),
            None => json!({
                "recorded": false,
                "note": "the run's collector files were not hashed when it was analyzed",
            }),
        }
    }

    fn after(&self) -> Value {
        let mut collection = self.collection_json();
        collection["objects"] = json!(self.objects);
        collection["domain_count"] = json!(self.domains.len());
        if !self.redact {
            collection["domains"] = json!(self.domains);
        }
        json!({
            "run_id": self.after_run_id,
            "recorded_in_state": matches!(self.after, After::Run { recorded: true, .. }),
            "analyzed_at": when(Some(self.analyzed_at())),
            "collected_at": when(self.after_collected_at),
            "collection": collection,
        })
    }

    /// The short version, for the manifest (signed) and `verify`'s output.
    pub fn summary(&self) -> Value {
        json!({
            "baseline": {
                "kind": self.baseline_kind,
                "run_id": self.baseline_run_id,
                "collected_at": when(self.baseline_collected_at),
            },
            "after": {
                "run_id": self.after_run_id,
                "collected_at": when(self.after_collected_at),
                "collection_sha256": self.inputs.map(Inputs::combined),
            },
            "counts": self.report.counts,
            "verdicts": self.report.results.iter().map(|r| json!({
                "fingerprint": r.fingerprint,
                "rule": r.rule,
                "verdict": r.verdict,
            })).collect::<Vec<_>>(),
            "selection": self.selection(),
        })
    }

    fn selection(&self) -> Value {
        json!({
            "findings": self.selection_findings,
            "rules": self.selection_rules,
            "whole_run": self.selection_findings.is_empty() && self.selection_rules.is_empty(),
        })
    }

    /// `metadata.json`: the tool, the config, and both sides of the retest.
    pub fn metadata(&self) -> Value {
        let mut config = json!({"sha256": self.config_sha256});
        if self.config_sha256.is_none() {
            config["note"] = json!(self
                .config_note
                .unwrap_or("no config file: the built-in defaults"));
        } else if !self.redact {
            config["file"] = json!(self.config_name);
        }
        json!({
            "created_at": when(Some(self.created_at)),
            "redacted": self.redact,
            "pathwarden": {
                "version": env!("CARGO_PKG_VERSION"),
                "binary_sha256": self.binary_sha256,
            },
            "config": config,
            "before": self.before(),
            "after": self.after(),
            "selection": self.selection(),
            "limits": self.limits(),
        })
    }

    fn limits(&self) -> Vec<String> {
        let first = match self.after {
            After::Fresh => "The \"after\" side is the collection analyzed when the pack was made; it was not recorded as a run in the state.".to_string(),
            After::Run { analyzed_at, .. } => format!(
                "The \"after\" side is run {}, analyzed {}; its findings and report are the ones saved with the run.",
                self.after_run_id,
                format_utc(analyzed_at)
            ),
        };
        let second = match self.inputs {
            Some(_) => "Collector files do not say which domain controller answered, so the pack identifies the collection by its hashes and collection time.",
            None => "The run's collector files were not hashed when it was analyzed, so the pack identifies the collection by its run ID and collection time only.",
        };
        let mut l = vec![first, second.to_string()];
        if let After::Run { .. } = self.after {
            l.push(
                "history.json holds the run history's points up to this run, none after it."
                    .to_string(),
            );
        }
        if self.state_left_out {
            l.push("What the run history tracked about each finding (first seen, last seen, times seen) is left out: the history has runs after this one, so its findings state is not this run's.".to_string());
        }
        l
    }

    /// `retest.json`: the verdicts, with both sides' times and run IDs.
    pub fn retest(&self) -> Result<Value> {
        let mut report = self.report.clone();
        if self.redact {
            report.baseline = self.baseline_kind.to_string();
            for r in &mut report.results {
                r.title = rule_title(&r.rule);
                let domain = r.domain.take();
                r.details = r
                    .details
                    .iter()
                    .map(|d| match &domain {
                        Some(name) if !name.is_empty() => d.replace(name.as_str(), "its domain"),
                        _ => d.clone(),
                    })
                    .collect();
            }
            for n in &mut report.new {
                n.title = rule_title(&n.rule);
                n.domain = None;
            }
        }
        let mut v = serde_json::to_value(&report)?;
        v["before"] = self.before();
        v["after"] = json!({
            "run_id": self.after_run_id,
            "analyzed_at": when(Some(self.analyzed_at())),
            "collected_at": when(self.after_collected_at),
        });
        Ok(v)
    }

    /// `findings.json`: each retested finding before and after, with what
    /// the state tracked about it, and the new findings.
    pub fn findings(&self) -> Value {
        let fresh: HashMap<&str, &Fresh> = self
            .fresh
            .iter()
            .map(|f| (f.fingerprint.as_str(), f))
            .collect();
        let before: HashMap<&str, &FindingView> = self
            .baseline_views
            .iter()
            .map(|f| (f.fingerprint.as_str(), f))
            .collect();
        let retested: Vec<Value> = self
            .report
            .results
            .iter()
            .map(|r| {
                let fp = r.fingerprint.as_str();
                let tracked = self.tracked(fp).map(|t| tracked_json(t, self.redact));
                if self.redact {
                    let b = before.get(fp);
                    json!({
                        "fingerprint": fp,
                        "rule": r.rule,
                        "rule_title": rule_title(&r.rule),
                        "verdict": r.verdict,
                        "severity": r.severity,
                        "category": b.and_then(|b| b.category),
                        "domain_key": b.and_then(|b| b.scope.clone()),
                        "exposure_before": r.exposure_before,
                        "exposure_after": r.exposure_after,
                        "affected_before": r.affected_before,
                        "affected_remaining": r.affected_remaining,
                        "tracked": tracked,
                    })
                } else {
                    json!({
                        "fingerprint": fp,
                        "rule": r.rule,
                        "verdict": r.verdict,
                        "before": before.get(fp),
                        "after": fresh.get(fp).map(|f| &f.json),
                        "tracked": tracked,
                    })
                }
            })
            .collect();
        let new: Vec<Value> = self
            .report
            .new
            .iter()
            .map(|n| {
                let f = fresh.get(n.fingerprint.as_str());
                if self.redact {
                    json!({
                        "fingerprint": n.fingerprint,
                        "rule": n.rule,
                        "rule_title": rule_title(&n.rule),
                        "severity": n.severity,
                        "category": f.map(|f| &f.category),
                        "regressed": n.regressed,
                    })
                } else {
                    json!({"regressed": n.regressed, "finding": f.map(|f| &f.json)})
                }
            })
            .collect();
        json!({"retested": retested, "new": new})
    }

    /// `history.json`: the state's history points since the earliest
    /// retested finding was first seen (all of them when that is unknown).
    pub fn history(&self) -> Value {
        let since = self
            .report
            .results
            .iter()
            .filter_map(|r| self.tracked(&r.fingerprint).map(|t| t.first_seen))
            .min();
        let mut zone_names: BTreeMap<String, String> = BTreeMap::new();
        let points: Vec<Value> = self
            .history
            .iter()
            .filter(|p| since.is_none_or(|s| p.at >= s))
            // A saved run's pack ends at that run: nothing it couldn't
            // have known.
            .filter(|p| match self.after {
                After::Run { analyzed_at, .. } => p.at <= analyzed_at,
                After::Fresh => true,
            })
            .map(|p| {
                let mut p = p.clone();
                if self.redact {
                    // Zone names are the config's; they may name systems.
                    for z in &mut p.zones {
                        let n = zone_names.len() + 1;
                        z.zone = zone_names
                            .entry(z.zone.clone())
                            .or_insert_with(|| format!("zone {n}"))
                            .clone();
                    }
                    // A run label is free text; it may name systems too.
                    p.label = None;
                }
                serde_json::to_value(&p).unwrap_or(Value::Null)
            })
            .collect();
        json!({
            "since": when(since),
            "points": points,
        })
    }

    /// `README.txt`: what the pack is and how to check it, in words.
    pub fn readme(&self, fingerprint: &str) -> String {
        let c = self.report.counts;
        let collected = |t: Option<i64>| {
            t.map_or("collection time unknown".to_string(), |t| {
                format!("collected {}", format_utc(t))
            })
        };
        let mut l: Vec<String> = vec![
            "Pathwarden evidence pack".into(),
            "========================".into(),
            String::new(),
            format!(
                "Made {} by Pathwarden {}.",
                format_utc(self.created_at),
                env!("CARGO_PKG_VERSION")
            ),
            format!(
                "Before: the {} baseline{} ({}).",
                self.baseline_kind,
                self.baseline_run_id
                    .map(|r| format!(", run {r}"))
                    .unwrap_or_default(),
                collected(self.baseline_collected_at)
            ),
            match (self.after, self.inputs) {
                (After::Fresh, Some(i)) => format!(
                    "After:  a collection of {} ({}), SHA-256 {}.",
                    crate::text::count(i.files.len(), "file", "files"),
                    collected(self.after_collected_at),
                    i.combined()
                ),
                (_, Some(i)) => format!(
                    "After:  run {}, a collection of {} ({}), SHA-256 {}.",
                    self.after_run_id,
                    crate::text::count(i.files.len(), "file", "files"),
                    collected(self.after_collected_at),
                    i.combined()
                ),
                (_, None) => format!(
                    "After:  run {} ({}); its collector files were not hashed.",
                    self.after_run_id,
                    collected(self.after_collected_at)
                ),
            },
            String::new(),
            format!(
                "Result: {} fixed, {} still open, {} can't tell, {} new.",
                c.fixed, c.still_open, c.cant_tell, c.new
            ),
            String::new(),
        ];
        for r in &self.report.results {
            let title = if self.redact {
                rule_title(&r.rule)
            } else {
                r.title.clone()
            };
            l.push(format!(
                "  {:<11} {}  {title}",
                r.verdict.label(),
                r.fingerprint
            ));
        }
        if self.report.results.is_empty() {
            l.push("  (no open findings matched)".into());
        }
        l.push(String::new());
        if self.redact {
            l.push("This pack is redacted: it holds no object or domain names and no HTML".into());
            l.push("report. Findings are identified by fingerprint and rule.".into());
            l.push(String::new());
        }
        let mut files = vec![
            ("manifest.json", "every other file's SHA-256 (signed)"),
            (
                "manifest.json.minisig",
                "the Ed25519 signature of manifest.json (minisign format)",
            ),
            (
                "metadata.json",
                "Pathwarden version and binary hash, config hash, collection hashes and times, run IDs",
            ),
            ("retest.json", "the verdicts, before and after"),
            (
                "findings.json",
                "each finding before and after, and what the state tracked about it",
            ),
            ("history.json", "the state's history points over the same period"),
        ];
        if !self.redact {
            files.push((
                "report.html",
                "the full HTML report of the collection (holds names)",
            ));
        }
        l.extend(["Files".into(), "-----".into()]);
        l.extend(files.iter().map(|(f, what)| format!("{f:<22} {what}")));
        l.push(String::new());
        for line in [
            "Checking the pack",
            "-----------------",
            "This pack was signed with the key whose fingerprint is",
            "",
            &format!("  {fingerprint}"),
            "",
            "Check that this is the fingerprint the organization published (on its",
            "website, in the contract, or told to you directly), not just the one",
            "printed here. Then run one of:",
            "",
            &format!("  pathwarden evidence verify <pack> --fingerprint {fingerprint}"),
            &format!("  python3 verify_evidence.py <pack> --fingerprint {fingerprint}"),
            "  (scripts/verify_evidence.py in the Pathwarden repository)",
            "",
            "or check the signature with minisign and the organization's public key,",
            "then each file's SHA-256 against manifest.json:",
            "",
            "  minisign -Vm manifest.json -p evidence.pub",
            "",
            "Any change to any file, to the manifest or to the signature makes the",
            "check fail.",
        ] {
            l.push(line.to_string());
        }
        let mut out = l.join("\n");
        out.push('\n');
        out
    }
}

fn tracked_json(t: &TrackedFinding, redact: bool) -> Value {
    let mut t = t.clone();
    if redact {
        t.title = None;
        t.domain = None;
    }
    serde_json::to_value(&t).unwrap_or(Value::Null)
}

/// The names a redacted pack must not contain: domains (and their labels),
/// and the affected objects of every finding it covers (their names whole,
/// as listed, and their domain SIDs). The search `diagnose --bundle` runs
/// ([`diagnostics::NameScan`]).
pub fn names_to_withhold(
    domains: &[String],
    views: &[FindingView],
    fresh: &[Fresh],
    extra: &[String],
) -> diagnostics::NameScan {
    let mut scan = diagnostics::NameScan::default();
    let listed = views
        .iter()
        .flat_map(|v| v.affected.iter().flatten().map(|a| (&a.id, &a.name)))
        .chain(
            fresh
                .iter()
                .flat_map(|f| f.affected.iter().map(|(id, name)| (id, name))),
        );
    for (id, name) in listed {
        scan.add_listed(name);
        scan.add_sid(id);
    }
    let finding_domains = views
        .iter()
        .filter_map(|v| v.domain.as_ref())
        .chain(fresh.iter().filter_map(|f| f.domain.as_ref()));
    for d in domains.iter().chain(extra).chain(finding_domains) {
        scan.add_domain(d);
    }
    scan
}

/// Fails if any file holds one of the names (case-insensitive): the last
/// check before a redacted pack is written, with the bundle's search
/// ([`diagnostics::check_all`]).
pub fn check_redacted(files: &[(String, Vec<u8>)], names: &diagnostics::NameScan) -> Result<()> {
    if let Err(r) = diagnostics::check_all(files, names) {
        bail!(
            "redaction check failed: {} would contain a name ({} characters); no pack was written. \
             Please report this as a bug.",
            r.file,
            r.chars
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str) -> InputFile {
        InputFile {
            name: name.into(),
            sha256: sha256_hex(name.as_bytes()),
            bytes: 1,
        }
    }

    #[test]
    fn collector_from_file_names() {
        assert_eq!(
            collector_hint(&[file("NORTH_20240410083414_BloodHound-2.3.3.zip")]),
            "SharpHound 2.3.3"
        );
        assert_eq!(
            collector_hint(&[file("20261009120000_BloodHound.zip")]),
            "SharpHound"
        );
        assert_eq!(
            collector_hint(&[file("20261009120000_contoso.local_rusthound-ce.zip")]),
            "RustHound-CE"
        );
        assert!(collector_hint(&[file("contoso_users.json")]).contains("not named"));
    }

    #[test]
    fn combined_hash_ignores_names_and_order() {
        let a = Inputs {
            files: vec![file("a"), file("b")],
        };
        let mut b = Inputs {
            files: vec![file("b"), file("a")],
        };
        assert_eq!(a.combined(), b.combined());
        b.files[0].name = "renamed".into();
        assert_eq!(a.combined(), b.combined());
        b.files[0].sha256 = sha256_hex(b"other");
        assert_ne!(a.combined(), b.combined());
    }

    #[test]
    fn a_finding_from_an_event_drops_the_runs_own_fields() {
        let v = json!({
            "change": "new", "first_seen": 5, "times_seen": 1,
            "rule": "PW-001", "fingerprint": "PW-001-aa", "category": "attack_path",
            "domain": "CONTOSO.LOCAL",
            "affected": [{"id": "S-1-5-21-1-2-3-1104", "name": "BOB@CONTOSO.LOCAL", "kind": "User"}],
        });
        let f = Fresh::from_event(&v).unwrap();
        assert_eq!(f.fingerprint, "PW-001-aa");
        assert_eq!(f.domain.as_deref(), Some("CONTOSO.LOCAL"));
        assert_eq!(
            f.affected,
            vec![("S-1-5-21-1-2-3-1104".into(), "BOB@CONTOSO.LOCAL".into())]
        );
        assert_eq!(f.category, json!("attack_path"));
        for k in ["change", "first_seen", "times_seen"] {
            assert!(f.json.get(k).is_none(), "{k}");
        }
        assert_eq!(f.json["rule"], "PW-001");
        assert!(Fresh::from_event(&json!({"rule": "PW-001"})).is_none());
    }

    fn point(at: i64) -> HistoryPoint {
        HistoryPoint {
            version: 1,
            run_id: crate::state::run_id(at),
            at,
            collected_at: None,
            tier_zero_exposure_percent: 1.0,
            tier_zero_exposed: 1,
            tier_zero_population: 0,
            tier_zero_relevant_population: 0,
            exposure_basis: 0,
            tier_zero_objects: 0,
            protection_score: None,
            tier_zero_grade: None,
            plan: None,
            findings: Default::default(),
            changes: Default::default(),
            zones: Vec::new(),
            completeness: None,
            scopes: Vec::new(),
            trusted_scopes: None,
            recorded_by: None,
            label: None,
            data: None,
            inserted: false,
            exposed_keys: false,
            severity_settings: None,
            rule_severities: Default::default(),
        }
    }

    /// A pack of an older run holds nothing from after it: the history ends
    /// at its analysis, and the findings state (which is the history's now)
    /// is left out, with why.
    #[test]
    fn an_older_runs_pack_ends_at_that_run() {
        let report = RetestReport {
            baseline: "run x".into(),
            results: Vec::new(),
            new: Vec::new(),
            counts: Default::default(),
        };
        let analyzed = 1_791_500_000;
        let history = [
            point(analyzed - 7 * 86_400),
            point(analyzed),
            point(analyzed + 86_400),
        ];
        let src = Sources {
            created_at: analyzed + 2 * 86_400,
            redact: false,
            report: &report,
            baseline_kind: "run",
            baseline_label: "run x",
            baseline_run_id: Some("x"),
            baseline_collected_at: None,
            baseline_views: &[],
            baseline_inputs: None,
            after: After::Run {
                analyzed_at: analyzed,
                recorded: true,
            },
            after_run_id: "y",
            after_collected_at: None,
            inputs: None,
            domains: &[],
            objects: 3,
            fresh: &[],
            state: None,
            state_left_out: true,
            history: &history,
            config_sha256: None,
            config_name: None,
            config_note: None,
            binary_sha256: None,
            selection_findings: &[],
            selection_rules: &[],
        };
        let h = src.history();
        let ats: Vec<i64> = h["points"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["at"].as_i64().unwrap())
            .collect();
        assert_eq!(ats, vec![analyzed - 7 * 86_400, analyzed]);
        let limits = src.metadata()["limits"].to_string();
        assert!(limits.contains("none after it"), "{limits}");
        assert!(
            limits.contains("its findings state is not this run's"),
            "{limits}"
        );
        // A fresh collection's pack keeps every point.
        let src = Sources {
            after: After::Fresh,
            state_left_out: false,
            ..src
        };
        assert_eq!(src.history()["points"].as_array().unwrap().len(), 3);
        assert!(!src.metadata()["limits"]
            .to_string()
            .contains("findings state"));
    }

    /// A pack of a run saved before its collector files were hashed says
    /// so, and that its "after" side is that run.
    #[test]
    fn a_saved_run_without_hashes_says_so() {
        let report = RetestReport {
            baseline: "run 20261019T191300.000Z".into(),
            results: Vec::new(),
            new: Vec::new(),
            counts: Default::default(),
        };
        let src = Sources {
            created_at: 1_791_590_400,
            redact: false,
            report: &report,
            baseline_kind: "run",
            baseline_label: "run 20261019T191300.000Z",
            baseline_run_id: Some("20261019T191300.000Z"),
            baseline_collected_at: None,
            baseline_views: &[],
            baseline_inputs: None,
            after: After::Run {
                analyzed_at: 1_791_500_000,
                recorded: true,
            },
            after_run_id: "20261027T191300.000Z",
            after_collected_at: None,
            inputs: None,
            domains: &[],
            objects: 3,
            fresh: &[],
            state: None,
            state_left_out: false,
            history: &[],
            config_sha256: None,
            config_name: None,
            config_note: Some("the run's settings were not kept with it"),
            binary_sha256: None,
            selection_findings: &[],
            selection_rules: &[],
        };
        let readme = src.readme("SHA256:x");
        assert!(
            readme.contains("After:  run 20261027T191300.000Z (collection time unknown); its collector files were not hashed."),
            "{readme}"
        );
        let m = src.metadata();
        assert_eq!(m["after"]["recorded_in_state"], true);
        assert_eq!(m["after"]["collection"]["recorded"], false);
        assert_eq!(m["after"]["analyzed_at"]["unix"], 1_791_500_000);
        assert_eq!(
            m["config"]["note"],
            "the run's settings were not kept with it"
        );
        assert!(m["limits"][0]
            .as_str()
            .unwrap()
            .starts_with("The \"after\" side is run 20261027T191300.000Z"));
        assert!(src.summary()["after"]["collection_sha256"].is_null());

        // With the hashes, the pack names the collection by them.
        let inputs = Inputs {
            files: vec![file("20261027_BloodHound.zip")],
        };
        let src = Sources {
            inputs: Some(&inputs),
            ..src
        };
        assert_eq!(
            src.summary()["after"]["collection_sha256"],
            json!(inputs.combined())
        );
        assert!(src.readme("SHA256:x").contains(&format!(
            "After:  run 20261027T191300.000Z, a collection of 1 file (collection time unknown), SHA-256 {}.",
            inputs.combined()
        )));
    }

    #[test]
    fn redaction_check_finds_names_in_any_case() {
        let files = |text: &str| vec![("a.json".to_string(), text.as_bytes().to_vec())];
        let names = names_to_withhold(&["CONTOSO.LOCAL".into(), "AD".into()], &[], &[], &[]);
        assert!(check_redacted(&files(r#"{"x":"Contoso.Local"}"#), &names).is_err());
        // A domain's label, and a domain as an object key.
        assert!(check_redacted(&files(r#"{"x":"contoso"}"#), &names).is_err());
        assert!(check_redacted(&files(r#"{"contoso.local":1}"#), &names).is_err());
        let other = names_to_withhold(&["fabrikam.local".into()], &[], &[], &[]);
        assert!(check_redacted(&files(r#"{"x":"Contoso.Local"}"#), &other).is_ok());
    }

    #[test]
    fn redaction_check_finds_affected_objects_and_their_domain_sid() {
        let view = FindingView {
            fingerprint: "f".into(),
            rule: "PW-001".into(),
            affected: Some(vec![crate::retest::AffectedView {
                id: "S-1-5-21-11-22-33-1104".into(),
                name: "SVC BACKUP@CONTOSO.LOCAL".into(),
            }]),
            ..FindingView::default()
        };
        let names = names_to_withhold(&[], &[view], &[], &[]);
        let files = |text: &str| vec![("README.txt".to_string(), text.as_bytes().to_vec())];
        assert!(check_redacted(&files("svc backup@contoso.local"), &names).is_err());
        assert!(check_redacted(&files("S-1-5-21-11-22-33-500"), &names).is_err());
        // Its first part alone is prose.
        assert!(check_redacted(&files("a backup of the domain"), &names).is_ok());
    }
}
