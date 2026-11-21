//! What an output plugin says it did, so its tickets show on the
//! findings: an optional result file (`pathwarden.output-result.v1`) the
//! plugin writes to the path in [`RESULT_ENV`] on a real run (never on a
//! Test or a dry run). Its records have the shape of an action result's
//! ([`crate::actions::Record`]), each with the finding's `fingerprint`:
//!
//! `{"schema":"pathwarden.output-result.v1","records":[{"fingerprint":"…",
//! "id":"…","kind":"ticket","number":"INC0012345","url":"https://…",
//! "status":"Open","open":true}]}`
//!
//! It is read as an action's result is: at most [`MAX_BYTES`] and
//! [`MAX_RECORDS`] records, texts cut to the same caps, links that aren't
//! `https://` left out, nothing read as HTML. The records are kept on the
//! findings in the history's `actions.json` ([`crate::action_log`]) with
//! the plugin as their source: `plugin:<plugin>` in the record's `action`
//! ([`source`]), which no `[[action]]` block can be named.

use std::collections::HashSet;

use serde_json::Value;

use crate::actions::{record_of, text_field, type_of, Problems, Record, MAX_RECORD_TEXT};
use crate::config::OutputConfig;

/// The variable naming the file a plugin may write its result to.
pub const RESULT_ENV: &str = "PATHWARDEN_OUTPUT_RESULT";
/// The result file's schema.
pub const SCHEMA: &str = "pathwarden.output-result.v1";
/// The largest result file read: about 800 bytes a record at
/// [`MAX_RECORDS`].
pub const MAX_BYTES: u64 = 8 << 20;
/// Most records read from one result file; the rest are left out.
pub const MAX_RECORDS: usize = 10_000;
/// Most records one finding takes from one plugin.
pub const MAX_PER_FINDING: usize = crate::actions::MAX_RECORDS;
/// Most problems a result's warning lists; the rest are counted.
pub const MAX_PROBLEMS: usize = 10;
/// The start of a plugin's records' `action` ([`source`]).
pub const SOURCE_PREFIX: &str = "plugin:";

/// One record of a result: the finding it is on, and the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputRecord {
    pub fingerprint: String,
    pub record: Record,
}

/// A result file as read: its records and what was wrong with it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutputResult {
    pub records: Vec<OutputRecord>,
    pub problems: Vec<String>,
}

/// The source the records of `output` are kept under, in a record's
/// `action`: `plugin:<plugin>` (`plugin:servicenow`). Stable while the
/// block names the same plugin, and never the address of a finding action
/// (their names can't hold `:`), so no follow-up or `once` takes a plugin's
/// record for an action's.
pub fn source(output: &OutputConfig) -> String {
    format!("{SOURCE_PREFIX}{}", output.plugin)
}

/// Whether a record's `action` is an output plugin's ([`source`]).
pub fn is_plugin_source(action: &str) -> bool {
    action.starts_with(SOURCE_PREFIX)
}

/// How a record's source reads: "ServiceNow plugin", "Jira plugin",
/// "teams plugin"; `None` for a finding action's address.
pub fn source_label(action: &str) -> Option<String> {
    let name = action.strip_prefix(SOURCE_PREFIX)?;
    Some(match name {
        "servicenow" => "ServiceNow plugin".to_string(),
        "jira" => "Jira plugin".to_string(),
        other => format!("{other} plugin"),
    })
}

/// Whether `output` is set to change nothing (`dry_run = true`, as Test
/// sets it): then no result is asked for or read.
pub fn is_dry_run(output: &OutputConfig) -> bool {
    output
        .settings
        .get("dry_run")
        .is_some_and(|v| v.as_bool() == Some(true))
}

/// Reads a result file. `Err` when it can't be used at all (not JSON,
/// another schema, no `records` list). Otherwise its records as checked
/// and the problems found: a record without a fingerprint or ID, past
/// [`MAX_RECORDS`] or [`MAX_PER_FINDING`], or there twice is left out; a
/// text too long is cut; a link that isn't `https://` is left out.
pub fn parse(bytes: &[u8]) -> Result<OutputResult, String> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    if bytes.len() as u64 > MAX_BYTES {
        return Err(format!(
            "The result file is larger than {} MiB.",
            MAX_BYTES >> 20
        ));
    }
    let v: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("The result isn't JSON: {e}"))?;
    let Some(o) = v.as_object() else {
        return Err(format!(
            "The result must be a JSON object, not {}.",
            type_of(&v)
        ));
    };
    let mut p = Problems(Vec::new());
    match o.get("schema") {
        Some(Value::String(s)) if s == SCHEMA => {}
        None | Some(Value::Null) => p.add("schema", format!("is missing: use \"{SCHEMA}\"")),
        Some(other) => {
            return Err(format!(
                "schema {other} isn't \"{SCHEMA}\", the version this Pathwarden reads."
            ))
        }
    }
    let items = match o.get("records") {
        Some(Value::Array(items)) => items,
        None | Some(Value::Null) => return Err("The result has no records list.".into()),
        Some(other) => return Err(format!("records must be a list, not {}.", type_of(other))),
    };
    if items.len() > MAX_RECORDS {
        p.add(
            "records",
            format!("has more than {MAX_RECORDS} records; the rest were left out"),
        );
    }
    let mut out = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut per_finding: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for (i, item) in items.iter().enumerate().take(MAX_RECORDS) {
        let at = format!("records[{i}]");
        let Some(obj) = item.as_object() else {
            p.add(&at, format!("must be an object, not {}", type_of(item)));
            continue;
        };
        let before = p.0.len();
        let fingerprint = text_field(obj, "fingerprint", &at, MAX_RECORD_TEXT, true, &mut p);
        if p.0.len() > before {
            continue;
        }
        let Some(fingerprint) = fingerprint else {
            continue;
        };
        let Some(record) = record_of(item, &at, &mut p) else {
            continue;
        };
        if !seen.insert((fingerprint.clone(), record.id.clone())) {
            p.add(&at, "is there twice (same fingerprint and id); left out");
            continue;
        }
        let n = per_finding.entry(fingerprint.clone()).or_default();
        if *n >= MAX_PER_FINDING {
            p.add(
                &at,
                format!("is past {MAX_PER_FINDING} records on one finding; left out"),
            );
            continue;
        }
        *n += 1;
        out.push(OutputRecord {
            fingerprint,
            record,
        });
    }
    Ok(OutputResult {
        records: out,
        problems: p.0,
    })
}

/// `problems` on one line for the run log: the first [`MAX_PROBLEMS`] and
/// how many more.
pub fn problems_line(problems: &[String]) -> String {
    let mut line = problems
        .iter()
        .take(MAX_PROBLEMS)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    if problems.len() > MAX_PROBLEMS {
        line.push_str(&format!("; and {} more", problems.len() - MAX_PROBLEMS));
    }
    line
}

/// What one plugin reported, ready to save ([`save_all`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reported {
    /// [`source`].
    pub source: String,
    /// [`source_label`].
    pub label: String,
    pub records: Vec<OutputRecord>,
}

/// What a plugin's result file holds, for `output` ([`read_result`]):
/// `None` when it wrote none; the warning for the run log when it can't
/// be read or something in it was left out.
pub fn read_result(
    output: &OutputConfig,
    file: Option<Result<Vec<u8>, String>>,
) -> (Option<Reported>, Option<String>) {
    let Some(file) = file else {
        return (None, None);
    };
    let source = source(output);
    let label = source_label(&source).unwrap_or_else(|| output.plugin.clone());
    let parsed = file.and_then(|bytes| parse(&bytes));
    match parsed {
        Err(why) => (
            None,
            Some(format!(
                "Its result file wasn't read, so its tickets aren't updated on the findings: {why}"
            )),
        ),
        Ok(r) => {
            let warning = (!r.problems.is_empty()).then(|| {
                format!(
                    "Parts of its result file were left out: {}",
                    problems_line(&r.problems)
                )
            });
            (
                Some(Reported {
                    source,
                    label,
                    records: r.records,
                }),
                warning,
            )
        }
    }
}

/// The fingerprints of an event document's findings, fixed findings and
/// held findings: those a plugin given it may report records on.
pub fn event_fingerprints(event_json: &str) -> HashSet<String> {
    let Ok(v) = serde_json::from_str::<Value>(event_json) else {
        return HashSet::new();
    };
    ["findings", "resolved", "held"]
        .iter()
        .filter_map(|k| v.get(*k).and_then(Value::as_array))
        .flatten()
        .filter_map(|f| f.get("fingerprint").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

/// What [`save_all`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavedRecords {
    /// How many findings' records changed.
    pub findings: usize,
    /// How many records were left out: on findings the history doesn't
    /// have.
    pub unknown: usize,
    pub saved: crate::action_log::Saved,
}

/// Saves what the plugins of a run reported on the findings, in one
/// change of the history's `actions.json` ([`crate::action_log::plugin_changes`],
/// [`crate::action_log::save_plugin_records`]): only records that are new
/// or changed, on fingerprints `known` takes. Hold the history's lock and
/// pull first.
pub fn save_all(
    store: &crate::store::Store,
    reported: &[Reported],
    known: &dyn Fn(&str) -> bool,
    run_id: Option<&str>,
    push: bool,
) -> anyhow::Result<SavedRecords> {
    if reported.iter().all(|r| r.records.is_empty()) {
        return Ok(SavedRecords::default());
    }
    let file = crate::action_log::load(store)?;
    let who = crate::identity::Actor::current();
    let at = crate::action_log::now_at();
    let mut changes = Vec::new();
    let mut unknown = 0;
    for r in reported {
        unknown += r.records.iter().filter(|x| !known(&x.fingerprint)).count();
        changes.extend(crate::action_log::plugin_changes(
            &file, &r.source, &r.label, &r.records, known, &who, &at, run_id,
        ));
    }
    let findings = changes
        .iter()
        .map(|c| c.fingerprint.as_str())
        .collect::<HashSet<_>>()
        .len();
    let saved = crate::action_log::save_plugin_records(store, &changes, push)?;
    Ok(SavedRecords {
        findings,
        unknown,
        saved,
    })
}

#[cfg(test)]
#[path = "output_result_tests.rs"]
mod tests;
