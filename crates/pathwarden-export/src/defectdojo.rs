//! DefectDojo "Generic Findings Import" JSON.
//!
//! Format: <https://docs.defectdojo.com/supported_tools/parsers/file/generic/>
//! (checked 2026-10-10 against the parser in `dojo/tools/generic/json_parser.py`,
//! which refuses any finding key outside its allow-list; [`ALLOWED_KEYS`] is
//! that list, and a test keeps the output inside it).
//!
//! | Pathwarden | DefectDojo |
//! |---|---|
//! | fingerprint | `unique_id_from_tool` |
//! | rule ID | `vuln_id_from_tool` |
//! | title | `title` |
//! | severity | `severity` (`Critical` ... `Info`) |
//! | rule, domain, finding ID (stable text only) | `description` |
//! | why it matters, exposure | `impact` |
//! | how to fix it, plus the guide | `mitigation` |
//! | attack path, affected objects | `steps_to_reproduce` |
//! | accepted risk | `risk_accepted: true`, `active: false` |
//! | finding actions' records | `references`, one line each after the rule's references |
//!
//! DefectDojo shows `description`, `impact`, `mitigation`,
//! `steps_to_reproduce` and `severity_justification` as Markdown. Text
//! from the directory (names, domains) and Pathwarden's own plain
//! sentences go in escaped ([`md`]), so a name can't add a link, an image
//! (which the browser would fetch), a heading or a table; only the rule
//! guides, which are Markdown, go in as they are.
//!
//! `description` holds only text that stays the same while the finding
//! exists. DefectDojo's default deduplication for this format hashes title
//! and description, so anything that changes from run to run (exposure
//! counts, object lists) is kept out of it. Deduplicating on
//! `unique_id_from_tool` is still the recommended setup
//! (docs/integrations.md), since some titles carry counts.

use serde_json::{json, Map, Value};

use crate::doc::{Doc, Finding};

/// The test type name the report sets (`type`), so DefectDojo settings can
/// target Pathwarden imports alone (`DD_DEDUPLICATION_ALGORITHM_PER_PARSER`).
pub const TEST_TYPE: &str = "Pathwarden";
/// Affected objects listed per finding.
const AFFECTED_MAX: usize = 100;

/// The finding keys DefectDojo's generic JSON parser accepts (2026-10).
pub const ALLOWED_KEYS: &[&str] = &[
    "title",
    "severity",
    "description",
    "date",
    "cwe",
    "cve",
    "epss_score",
    "epss_percentile",
    "cvssv3",
    "cvssv3_score",
    "cvssv4",
    "cvssv4_score",
    "mitigation",
    "impact",
    "steps_to_reproduce",
    "severity_justification",
    "references",
    "active",
    "verified",
    "false_p",
    "out_of_scope",
    "risk_accepted",
    "under_review",
    "is_mitigated",
    "thread_id",
    "mitigated",
    "numerical_severity",
    "param",
    "payload",
    "line",
    "file_path",
    "component_name",
    "component_version",
    "static_finding",
    "dynamic_finding",
    "scanner_confidence",
    "unique_id_from_tool",
    "vuln_id_from_tool",
    "sast_source_object",
    "sast_sink_object",
    "sast_source_line",
    "sast_source_file_path",
    "nb_occurences",
    "publish_date",
    "service",
    "planned_remediation_date",
    "planned_remediation_version",
    "effort_for_fixing",
    "tags",
    "kev_date",
    "known_exploited",
    "ransomware_used",
    "fix_available",
    "fix_version",
    // Popped by the parser before the check:
    "endpoints",
    "files",
    "vulnerability_ids",
    "cwes",
];

fn severity(f: &Finding) -> &'static str {
    match f.severity_key() {
        "critical" => "Critical",
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Info",
    }
}

/// Plain text as Markdown that shows exactly that text: every character
/// Markdown gives a meaning within a line is escaped (with a backslash, or
/// as an entity for `<`, `>` and `&`, which may start HTML or a link), and
/// so is one that would start a heading or a list at the start; line
/// breaks and other control characters become spaces, so the text stays
/// on its line. With `[` and `]` escaped no link or image can form, so
/// parentheses and `!` stay as they are.
fn md(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 4);
    let lead = text.len() - text.trim_start().len();
    let digits = text[lead..].bytes().take_while(u8::is_ascii_digit).count();
    for (i, c) in text.char_indices() {
        // `# x`, `- x`, `+ x`, `= x`, `1. x`: a heading or list at the start.
        let starts_block = (i == lead && matches!(c, '#' | '-' | '+' | '='))
            || (digits > 0 && i == lead + digits && c == '.');
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\\' | '`' | '*' | '_' | '[' | ']' | '|' => {
                out.push('\\');
                out.push(c);
            }
            c if starts_block => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// [`md`] for text of several lines: each line escaped on its own.
fn md_lines(text: &str) -> String {
    text.lines().map(md).collect::<Vec<_>>().join("\n")
}

/// DefectDojo limits `title` to 511 characters.
fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max - 3).collect();
    out.push_str("...");
    out
}

/// The report for a run's findings.
pub fn defectdojo(doc: &Doc) -> Value {
    let findings: Vec<Value> = doc.findings.iter().map(|f| finding(doc, f)).collect();
    let mut report = Map::new();
    report.insert("name".into(), "Pathwarden".into());
    report.insert("type".into(), TEST_TYPE.into());
    if !doc.tool_version.is_empty() {
        report.insert("version".into(), doc.tool_version.clone().into());
    }
    if !doc.run_id.is_empty() {
        report.insert(
            "description".into(),
            format!("Pathwarden run {}", doc.run_id).into(),
        );
    }
    report.insert("dynamic_tool".into(), true.into());
    report.insert("static_tool".into(), false.into());
    report.insert("findings".into(), findings.into());
    Value::Object(report)
}

fn finding(doc: &Doc, f: &Finding) -> Value {
    let rule_title = doc.rule_title(&f.rule);
    let mut m = Map::new();
    m.insert("title".into(), clip(&f.title, 511).into());
    m.insert("severity".into(), severity(f).into());

    // Stable text only (see the module comment).
    let mut d = format!("**Rule:** {} {}\n\n", md(&f.rule), md(&rule_title));
    if let Some(domain) = &f.domain {
        d.push_str(&format!("**Domain:** {}\n\n", md(domain)));
    }
    if !f.category.is_empty() {
        d.push_str(&format!(
            "**Category:** {}\n\n",
            f.category.replace('_', " ")
        ));
    }
    d.push_str(&format!("**Finding ID:** {}\n", md(&f.fingerprint)));
    m.insert("description".into(), d.into());

    let mut impact = md_lines(f.summary.trim());
    if let Some(e) = f.exposure_line() {
        impact.push_str(&format!("\n\nExposure: {}.", md(&e)));
    }
    if !impact.is_empty() {
        m.insert("impact".into(), impact.into());
    }

    let mut mitigation = md_lines(f.remediation.trim());
    if let Some(guide) = doc.guides.get(&f.rule) {
        mitigation.push_str("\n\n");
        mitigation.push_str(guide.trim_end());
    }
    if !mitigation.is_empty() {
        m.insert("mitigation".into(), mitigation.into());
    }

    let mut steps = String::new();
    if let Some(p) = f.path_line() {
        steps.push_str(&format!("Attack path: {}\n\n", md(&p)));
    }
    if !f.affected.is_empty() {
        steps.push_str(&format!("Affected objects ({}):\n", f.affected.len()));
        for a in f.affected.iter().take(AFFECTED_MAX) {
            let detail = a
                .detail
                .as_deref()
                .map(|d| format!(", {}", md(d)))
                .unwrap_or_default();
            steps.push_str(&format!("- {} ({}{detail})\n", md(&a.name), md(&a.kind)));
        }
        if f.affected.len() > AFFECTED_MAX {
            steps.push_str(&format!("- and {} more\n", f.affected.len() - AFFECTED_MAX));
        }
    }
    if !steps.is_empty() {
        m.insert("steps_to_reproduce".into(), steps.trim_end().into());
    }
    // Why it has its severity: its exposure, and when the team set it.
    let why = match (f.severity_set_line(), f.exposure_line()) {
        (Some(set), Some(e)) => Some(format!("{set} Exposure: {e}.")),
        (Some(set), None) => Some(set),
        (None, e) => e,
    };
    if let Some(why) = why {
        m.insert("severity_justification".into(), md(&why).into());
    }
    // The references, then the records finding actions keep on it: "Record
    // RITM10816190 · Open: https://...".
    let mut refs = f.references.clone();
    for r in f.actions.iter().flat_map(|a| &a.records) {
        refs.push(format!(
            "Record {}{}",
            md(&r.line()),
            r.url
                .as_deref()
                .map(|u| format!(": {}", md(u)))
                .unwrap_or_default()
        ));
    }
    if !refs.is_empty() {
        m.insert("references".into(), refs.join("\n").into());
    }
    if let Some(when) = f.first_seen.or(doc.when) {
        m.insert("date".into(), crate::date(when).into());
    }
    m.insert("unique_id_from_tool".into(), f.fingerprint.clone().into());
    m.insert("vuln_id_from_tool".into(), f.rule.clone().into());
    if f.is_suppressed() {
        // DefectDojo shows accepted risks as inactive.
        m.insert("active".into(), false.into());
        m.insert("risk_accepted".into(), true.into());
    } else {
        m.insert("active".into(), true.into());
    }
    m.insert("static_finding".into(), false.into());
    m.insert("dynamic_finding".into(), true.into());
    let mut tags = vec!["pathwarden".to_string()];
    if !f.category.is_empty() {
        tags.push(f.category.replace('_', "-"));
    }
    if f.rule.starts_with("PC-") {
        tags.push("pingcastle".into());
    }
    m.insert("tags".into(), json!(tags));
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name can't add Markdown of its own: a link, an image the
    /// browser would fetch, HTML, a heading or a line of its own.
    #[test]
    fn text_is_escaped_for_markdown() {
        let e = md("EVIL![x](https://t.example/p.png)<img src=x>\n# Fixed");
        assert_eq!(
            e,
            r"EVIL!\[x\](https://t.example/p.png)&lt;img src=x&gt; # Fixed"
        );
        assert_eq!(md("a & b *c* `d` x_y |"), r"a &amp; b \*c\* \`d\` x\_y \|");
        assert_eq!(md("  # Fixed"), r"  \# Fixed");
        assert_eq!(
            md_lines("- a\n12. b\nThe default is High."),
            "\\- a\n12\\. b\nThe default is High."
        );
    }

    #[test]
    fn clips_long_titles() {
        assert_eq!(clip("abc", 511), "abc");
        let long = "x".repeat(600);
        let c = clip(&long, 511);
        assert_eq!(c.chars().count(), 511);
        assert!(c.ends_with("..."));
    }
}
