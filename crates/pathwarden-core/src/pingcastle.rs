//! PingCastle health-check reports (`ad_hc_<domain>.xml`) as external
//! hygiene findings.
//!
//! PingCastle runs hundreds of configuration checks Pathwarden can't run
//! from collector data. Importing its report puts those results in the same
//! backlog: each triggered risk rule becomes a hygiene finding with rule ID
//! `PC-<RiskId>` and a fingerprint per (rule, domain), so it is tracked,
//! ticketed, suppressed and retested like any other finding. Fix it, run
//! PingCastle again, give Pathwarden the new report, and the finding
//! resolves.
//!
//! **Format.** The XML is .NET `XmlSerializer` output of PingCastle's
//! `HealthcheckData` class (`PingCastleCommon/Data/HealthcheckData.cs` in
//! <https://github.com/netwrix/pingcastle>): a `HealthcheckData` root with
//! `DomainFQDN`, `GenerationDate`, `EngineVersion` and
//! `RiskRules/HealthcheckRiskRule` elements, each with `Points`, `Category`,
//! `Model`, `RiskId`, `Rationale` and optional `Details/string`. Only those
//! elements are read.
//!
//! **Trust.** The report is whatever file the operator hands over: it is not
//! signed and Pathwarden can't check it against the directory. Its findings
//! say so (`sources = ["PingCastle"]`), take their text from the report
//! verbatim (escaped wherever it is shown), and get their severity from
//! PingCastle's points only. A finding resolves only in a run that read a
//! PingCastle report for the same domain: a run without one holds it as
//! "can't tell" instead of marking it fixed. The parser refuses DTDs (so no
//! entity expansion), files over [`MAX_BYTES`], more than [`MAX_RULES`]
//! rules, and rule IDs outside `[A-Za-z0-9._-]`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::Serialize;

use crate::findings::{Category, Finding, Severity};
use crate::opengraph::unit_key;

/// The source name findings carry, and the coverage source in the state.
pub const SOURCE: &str = "PingCastle";
/// Rule ID prefix: `PC-A-MinPwdLen`.
pub const RULE_PREFIX: &str = "PC-";
/// Largest report read. Real health-check reports are a few MiB.
pub const MAX_BYTES: u64 = 64 << 20;
/// Most risk rules taken from one report (PingCastle has a few hundred).
pub const MAX_RULES: usize = 2000;
/// Most `Details` lines kept per rule.
const DETAILS_MAX: usize = 50;
/// Distinct rule IDs interned for the life of the process.
const MAX_RULE_IDS: usize = 4096;

/// One report, as read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Upper-case FQDN, as Pathwarden names domains.
    pub domain: String,
    pub generated: Option<String>,
    pub engine: Option<String>,
    pub rules: Vec<RiskRule>,
    /// Rules dropped (bad ID, over the limit), for the run's notes.
    pub skipped: usize,
}

/// One triggered PingCastle risk rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RiskRule {
    pub risk_id: String,
    pub category: String,
    pub model: String,
    pub points: i64,
    pub rationale: String,
    pub details: Vec<String>,
}

/// A report read in a run, as the ingest statistics record it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportInfo {
    pub file: String,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    pub rules: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub skipped: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Severity from PingCastle's points, with the bands DefectDojo's
/// PingCastle parser uses (before its own contextual adjustments): 0 info,
/// 1-5 low, 6-10 medium, 11-15 high, above 15 critical.
pub fn severity(points: i64) -> Severity {
    match points {
        i64::MIN..=0 => Severity::Info,
        1..=5 => Severity::Low,
        6..=10 => Severity::Medium,
        11..=15 => Severity::High,
        _ => Severity::Critical,
    }
}

/// `[A-Za-z0-9._-]`, 1-64 characters: safe in a label, a file name, a URL.
pub fn valid_risk_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether a path is a PingCastle report by name (an explicit `.xml` input
/// is read as one whatever its name).
pub fn is_report_name(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    name.starts_with("ad_hc_") && name.ends_with(".xml")
}

fn is_xml(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("xml"))
}

/// Splits analysis inputs into collector inputs and PingCastle reports: an
/// `.xml` file given directly is a report (and not passed to the collector
/// reader); a folder stays a collector input and its `ad_hc_*.xml` files,
/// at any depth (links not followed), are reports too. Archives are not
/// searched.
pub fn split_inputs<P: AsRef<Path>>(inputs: &[P]) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut collector = Vec::new();
    let mut reports = Vec::new();
    for p in inputs {
        let p = p.as_ref();
        if p.is_dir() {
            collector.push(p.to_path_buf());
            find_reports(p, &mut reports, &mut HashSet::new(), 0);
        } else if is_xml(p) {
            reports.push(p.to_path_buf());
        } else {
            collector.push(p.to_path_buf());
        }
    }
    (collector, reports)
}

fn find_reports(dir: &Path, out: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>, depth: usize) {
    if depth > 16 {
        return;
    }
    let key = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if !seen.insert(key) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for e in entries {
        match std::fs::symlink_metadata(&e) {
            Ok(m) if m.file_type().is_symlink() => {}
            Ok(m) if m.is_dir() => find_reports(&e, out, seen, depth + 1),
            Ok(m) if m.is_file() && is_report_name(&e) => out.push(e),
            _ => {}
        }
    }
}

/// Reads a report file.
pub fn read(path: &Path) -> Result<Report, String> {
    let len = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if len > MAX_BYTES {
        return Err(format!(
            "{len} bytes, more than the {} MiB a PingCastle report may have",
            MAX_BYTES >> 20
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    parse(&bytes)
}

/// Parses a report.
pub fn parse(bytes: &[u8]) -> Result<Report, String> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    if bytes.starts_with(b"\xff\xfe") || bytes.starts_with(b"\xfe\xff") {
        return Err("UTF-16 is not supported; PingCastle writes UTF-8".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "not UTF-8 text".to_string())?;
    if text.contains("<!DOCTYPE") || text.contains("<!ENTITY") {
        return Err("a DTD is not allowed in a PingCastle report".into());
    }
    let doc = roxmltree::Document::parse(text).map_err(|e| format!("not valid XML: {e}"))?;
    let root = doc.root_element();
    if root.tag_name().name() != "HealthcheckData" {
        return Err(format!(
            "not a PingCastle health-check report (root element <{}>, expected <HealthcheckData>)",
            root.tag_name().name()
        ));
    }
    let child_text = |node: roxmltree::Node, name: &str| -> Option<String> {
        node.children()
            .find(|c| c.is_element() && c.tag_name().name() == name)
            .map(|c| c.text().unwrap_or_default().trim().to_string())
    };
    let domain = child_text(root, "DomainFQDN")
        .filter(|d| !d.is_empty())
        .ok_or("the report has no DomainFQDN")?;
    if domain.len() > 255
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err("the report's DomainFQDN is not a domain name".into());
    }
    let mut report = Report {
        domain: domain.to_ascii_uppercase(),
        generated: child_text(root, "GenerationDate").filter(|s| !s.is_empty()),
        engine: child_text(root, "EngineVersion").filter(|s| !s.is_empty()),
        ..Report::default()
    };
    let Some(rules) = root
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "RiskRules")
    else {
        // No triggered rules is a clean report, not an error.
        return Ok(report);
    };
    let mut seen = HashSet::new();
    for rule in rules
        .children()
        .filter(|c| c.is_element() && c.tag_name().name() == "HealthcheckRiskRule")
    {
        let risk_id = child_text(rule, "RiskId").unwrap_or_default();
        if !valid_risk_id(&risk_id) || report.rules.len() >= MAX_RULES {
            report.skipped += 1;
            continue;
        }
        let details: Vec<String> = rule
            .children()
            .find(|c| c.is_element() && c.tag_name().name() == "Details")
            .map(|d| {
                d.children()
                    .filter(|c| c.is_element())
                    .filter_map(|c| c.text())
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let parsed = RiskRule {
            points: child_text(rule, "Points")
                .and_then(|p| p.parse().ok())
                .unwrap_or(0),
            category: child_text(rule, "Category").unwrap_or_default(),
            model: child_text(rule, "Model").unwrap_or_default(),
            rationale: child_text(rule, "Rationale").unwrap_or_default(),
            details,
            risk_id,
        };
        // A rule listed twice is one finding: keep the first, add details.
        if !seen.insert(parsed.risk_id.clone()) {
            if let Some(existing) = report
                .rules
                .iter_mut()
                .find(|r| r.risk_id == parsed.risk_id)
            {
                existing.details.extend(parsed.details);
                existing.points = existing.points.max(parsed.points);
            }
            continue;
        }
        report.rules.push(parsed);
    }
    Ok(report)
}

/// A `&'static str` for a rule ID ([`Finding::rule`] is static: core
/// rules are compiled in). Each distinct ID is leaked once; past
/// [`MAX_RULE_IDS`] distinct IDs, `None`.
fn intern(id: String) -> Option<&'static str> {
    static IDS: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let mut ids = IDS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(s) = ids.get(id.as_str()) {
        return Some(s);
    }
    if ids.len() >= MAX_RULE_IDS {
        return None;
    }
    let s: &'static str = Box::leak(id.into_boxed_str());
    ids.insert(s);
    Some(s)
}

fn clip(s: &str, max: usize) -> String {
    let one_line: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if one_line.chars().count() <= max {
        return one_line;
    }
    let mut out: String = one_line.chars().take(max - 3).collect();
    out.push_str("...");
    out
}

/// The report's triggered rules as hygiene findings.
pub fn findings(report: &Report) -> Vec<Finding> {
    let domain = report.domain.as_str();
    let unit = unit_key(SOURCE, domain);
    let mut out = Vec::new();
    for r in &report.rules {
        let Some(rule) = intern(format!("{RULE_PREFIX}{}", r.risk_id)) else {
            continue;
        };
        let sev = severity(r.points);
        let headline = if r.rationale.is_empty() {
            r.risk_id.clone()
        } else {
            r.rationale.clone()
        };
        let mut f = Finding::new(
            rule,
            sev,
            &[domain],
            clip(&format!("PingCastle {}: {headline}", r.risk_id), 200),
        );
        f.category = Category::Hygiene;
        f.domain = Some(domain.to_string());
        let mut summary = format!(
            "PingCastle's health check of {domain} triggered rule {} ({} / {}, {} point{}): {}",
            r.risk_id,
            r.category,
            r.model,
            r.points,
            if r.points == 1 { "" } else { "s" },
            if r.rationale.is_empty() {
                "no rationale given"
            } else {
                r.rationale.as_str()
            }
        );
        if !r.details.is_empty() {
            summary.push_str("\n\nDetails from the report:");
            for d in r.details.iter().take(DETAILS_MAX) {
                summary.push_str("\n- ");
                summary.push_str(&clip(d, 300));
            }
            if r.details.len() > DETAILS_MAX {
                summary.push_str(&format!("\n- and {} more", r.details.len() - DETAILS_MAX));
            }
        }
        summary.push_str(
            "\n\nImported from a PingCastle report; Pathwarden did not check this itself.",
        );
        f.summary = summary;
        f.remediation = format!(
            "Fix it as PingCastle's report explains for rule {} (its HTML report describes the \
             rule and the change to make). Then run PingCastle again and give Pathwarden the new \
             report with the next collection: the finding resolves when the rule no longer \
             triggers for {domain}.",
            r.risk_id
        );
        f.references = vec!["https://github.com/netwrix/pingcastle"];
        f.sources = vec![SOURCE.to_string()];
        f.requires = vec![unit.clone()];
        out.push(f);
    }
    out
}

/// Reads every report among `paths`; the findings, and what was read.
pub fn load(paths: &[PathBuf]) -> Result<(Vec<Finding>, Vec<ReportInfo>), (PathBuf, String)> {
    let mut findings = Vec::new();
    let mut infos = Vec::new();
    let mut domains = HashSet::new();
    for p in paths {
        let report = read(p).map_err(|e| (p.clone(), e))?;
        if !domains.insert(report.domain.clone()) {
            return Err((
                p.clone(),
                format!(
                    "a second PingCastle report for {}; give one report per domain",
                    report.domain
                ),
            ));
        }
        findings.extend(self::findings(&report));
        infos.push(ReportInfo {
            file: p.display().to_string(),
            domain: report.domain.clone(),
            generated: report.generated.clone(),
            engine: report.engine.clone(),
            rules: report.rules.len(),
            skipped: report.skipped,
        });
    }
    Ok((findings, infos))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<HealthcheckData xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <EngineVersion>3.3.0.1</EngineVersion>
  <GenerationDate>2026-10-01T09:00:00+02:00</GenerationDate>
  <DomainFQDN>contoso.local</DomainFQDN>
  <RiskRules>
    <HealthcheckRiskRule>
      <Points>10</Points>
      <Category>Anomalies</Category>
      <Model>WeakPassword</Model>
      <RiskId>A-MinPwdLen</RiskId>
      <Rationale>Password policy allows length less than 8 characters</Rationale>
    </HealthcheckRiskRule>
    <HealthcheckRiskRule>
      <Points>50</Points>
      <Category>PrivilegedAccounts</Category>
      <Model>AccountTakeOver</Model>
      <RiskId>P-Kerberoasting</RiskId>
      <Rationale>Presence of 2 admin accounts which can be kerberoasted</Rationale>
      <Details><string>svc_sql</string><string>svc_backup</string></Details>
    </HealthcheckRiskRule>
  </RiskRules>
</HealthcheckData>"#;

    #[test]
    fn reads_triggered_rules() {
        let r = parse(ONE.as_bytes()).unwrap();
        assert_eq!(r.domain, "CONTOSO.LOCAL");
        assert_eq!(r.engine.as_deref(), Some("3.3.0.1"));
        assert_eq!(r.rules.len(), 2);
        assert_eq!(r.rules[1].details, ["svc_sql", "svc_backup"]);
        let f = findings(&r);
        assert_eq!(f[0].rule, "PC-A-MinPwdLen");
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[1].severity, Severity::Critical);
        assert_eq!(f[0].category, Category::Hygiene);
        assert_eq!(f[0].domain.as_deref(), Some("CONTOSO.LOCAL"));
        assert_eq!(f[0].sources, [SOURCE]);
        assert_eq!(f[0].requires, [unit_key(SOURCE, "CONTOSO.LOCAL")]);
        assert!(f[1].summary.contains("- svc_backup"));
        assert!(f[0]
            .title
            .starts_with("PingCastle A-MinPwdLen: Password policy"));
    }

    #[test]
    fn fingerprints_are_stable_per_rule_and_domain() {
        let a = findings(&parse(ONE.as_bytes()).unwrap());
        // A later report: other points, rationale and details, same rule.
        let later = ONE
            .replace("<Points>50</Points>", "<Points>30</Points>")
            .replace("Presence of 2 admin", "Presence of 1 admin")
            .replace("<string>svc_backup</string>", "");
        let b = findings(&parse(later.as_bytes()).unwrap());
        assert_eq!(a[1].fingerprint, b[1].fingerprint);
        assert!(a[1].fingerprint.starts_with("PC-P-Kerberoasting-"));
        // Another domain: another finding.
        let other =
            findings(&parse(ONE.replace("contoso.local", "fabrikam.local").as_bytes()).unwrap());
        assert_ne!(a[0].fingerprint, other[0].fingerprint);
    }

    #[test]
    fn severity_bands() {
        for (points, want) in [
            (0, Severity::Info),
            (-3, Severity::Info),
            (1, Severity::Low),
            (5, Severity::Low),
            (6, Severity::Medium),
            (10, Severity::Medium),
            (15, Severity::High),
            (16, Severity::Critical),
            (100, Severity::Critical),
        ] {
            assert_eq!(severity(points), want, "{points}");
        }
    }

    #[test]
    fn refuses_what_it_should() {
        for (bad, why) in [
            (
                "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY a \"b\">]><HealthcheckData/>",
                "DTD",
            ),
            ("<Other><DomainFQDN>x</DomainFQDN></Other>", "root element"),
            ("<HealthcheckData></HealthcheckData>", "DomainFQDN"),
            (
                "<HealthcheckData><DomainFQDN>a b\"c</DomainFQDN></HealthcheckData>",
                "domain name",
            ),
            ("not xml", "XML"),
        ] {
            let e = parse(bad.as_bytes()).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        // A bad rule ID is skipped, not fatal.
        let r = parse(ONE.replace("A-MinPwdLen", "A-Min Pwd\"Len").as_bytes()).unwrap();
        assert_eq!((r.rules.len(), r.skipped), (1, 1));
        // No RiskRules: a clean report.
        let clean =
            parse(b"<HealthcheckData><DomainFQDN>c.local</DomainFQDN></HealthcheckData>").unwrap();
        assert!(clean.rules.is_empty());
    }

    #[test]
    fn duplicate_rules_merge() {
        let twice = ONE.replace(
            "</RiskRules>",
            "<HealthcheckRiskRule><Points>60</Points><RiskId>P-Kerberoasting</RiskId>\
             <Details><string>svc_other</string></Details></HealthcheckRiskRule></RiskRules>",
        );
        let r = parse(twice.as_bytes()).unwrap();
        assert_eq!(r.rules.len(), 2);
        assert_eq!(r.rules[1].points, 60);
        assert_eq!(r.rules[1].details.len(), 3);
    }

    #[test]
    fn report_names() {
        assert!(is_report_name(Path::new("x/ad_hc_contoso.local.xml")));
        assert!(is_report_name(Path::new("AD_HC_X.XML")));
        assert!(!is_report_name(Path::new("ad_hc_contoso.local.html")));
        assert!(!is_report_name(Path::new("other.xml")));
    }
}
