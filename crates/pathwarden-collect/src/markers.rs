//! Reading progress out of collector output lines: SharpHound's log, and
//! RustHound-CE's (the external program's output, or the built-in
//! collector's log records).
//!
//! The parsers look for a few stable words rather than exact formats, so a
//! changed timestamp, log level or punctuation in a future version still
//! parses; a line they don't recognise is just a log line.

/// What a collector output line says about progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Marker {
    /// A step started (a key of the collector's steps).
    Step(&'static str),
    /// Objects processed so far (SharpHound's "Status: N objects finished").
    Done(u64),
    /// Objects of one type written (RustHound-CE's "N users parsed!").
    Count(String, u64),
    /// Computers the collector will contact (sessions / local groups).
    Targets(u64),
    /// The collector says it is finished.
    Finished,
}

/// The message part of a SharpHound line, without its
/// `2024-04-10T05:04:35.27-07:00|INFORMATION|` prefix.
fn sharphound_message(line: &str) -> &str {
    let mut rest = line.trim();
    // Up to two `|`-separated fields before the message: time and level.
    for _ in 0..2 {
        match rest.split_once('|') {
            Some((head, tail)) if is_time(head) || is_level(head) => rest = tail,
            _ => break,
        }
    }
    rest.trim()
}

fn is_time(s: &str) -> bool {
    let s = s.trim();
    s.len() <= 40 && s.starts_with(|c: char| c.is_ascii_digit())
}

fn is_level(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_uppercase().as_str(),
        "INFORMATION" | "INFO" | "WARNING" | "WARN" | "ERROR" | "DEBUG" | "TRACE" | "CRITICAL"
    )
}

/// The integer right before `word` in `text` (e.g. `314` in "314 objects").
fn number_before(text: &str, word: &str) -> Option<u64> {
    let at = text.find(word)?;
    let digits: String = text[..at]
        .trim_end()
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit() || *c == ',')
        .filter(|c| c.is_ascii_digit())
        .collect();
    digits.chars().rev().collect::<String>().parse().ok()
}

/// Progress in a SharpHound (v1 or v2) output line.
pub(crate) fn sharphound(line: &str) -> Option<Marker> {
    let msg = sharphound_message(line);
    let lower = msg.to_ascii_lowercase();
    if lower.contains("objects finished") {
        return number_before(&lower, "objects finished").map(Marker::Done);
    }
    if lower.contains("enumeration completed") || lower.contains("enumeration finished") {
        return Some(Marker::Finished);
    }
    if lower.starts_with("beginning ldap search")
        || lower.contains("beginning ldap search for")
        || lower.starts_with("starting computer enumeration")
    {
        return Some(Marker::Step("enumerate"));
    }
    if lower.starts_with("consumers finished")
        || lower.starts_with("output channel closed")
        || lower.starts_with("closing writers")
        || lower.starts_with("writing ")
        || lower.contains("zipping")
    {
        return Some(Marker::Step("write"));
    }
    None
}

/// Progress in a RustHound-CE log line (external program or built-in).
pub(crate) fn rusthound(line: &str) -> Option<Marker> {
    let lower = line.to_ascii_lowercase();
    if lower.contains("enumeration completed") {
        return Some(Marker::Finished);
    }
    if lower.contains("ldap filter") || lower.contains("all data collected for namingcontext") {
        return Some(Marker::Step("read"));
    }
    if lower.contains("starting the ldap objects parsing") {
        return Some(Marker::Step("parse"));
    }
    if lower.contains("starting checker") {
        return Some(Marker::Step("resolve"));
    }
    if lower.contains("active target(s)") {
        return number_before(&lower, "active target").map(Marker::Targets);
    }
    if lower.contains("[sessions]")
        || lower.contains("[localgroups]")
        || lower.contains("[gpo]")
        || lower.contains("[webclient]")
        || lower.contains("esc8 web enrollment probe")
    {
        return Some(Marker::Step("modules"));
    }
    if let Some(at) = lower.find(" parsed!") {
        // "1234 users parsed!"
        let head = lower[..at].trim_end();
        let (count, kind) = head.rsplit_once(' ')?;
        let count = count.rsplit(' ').next()?.trim();
        let n = count.parse().ok()?;
        return Some(Marker::Count(kind.to_string(), n));
    }
    if lower.contains(" created!") {
        return Some(Marker::Step("write"));
    }
    if lower.contains("connected to") && lower.contains("active directory") {
        return Some(Marker::Step("read"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARPHOUND_V2: &str = "\
2024-04-10T05:04:34.5591796-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2024-04-10T05:04:34.7310547-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices
2024-04-10T05:04:34.7466813-07:00|INFORMATION|Initializing SharpHound at 5:04 AM on 4/10/2024
2024-04-10T05:04:35.0122989-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for sevenkingdoms.local : kingslanding.sevenkingdoms.local
2024-04-10T05:04:35.2779322-07:00|INFORMATION|Beginning LDAP search for sevenkingdoms.local
2024-04-10T05:04:35.3091662-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-04-10T05:04:35.3091662-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-04-10T05:05:05.4185379-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2024-04-10T05:05:10.1000000-07:00|INFORMATION|Status: 1,204 objects finished (+1204 240.8)/s -- Using 41 MB RAM
2024-04-10T05:05:20.8873005-07:00|INFORMATION|Consumers finished, closing output channel
2024-04-10T05:05:20.9185458-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-04-10T05:05:21.0278962-07:00|INFORMATION|Status: 2314 objects finished (+314 Infinity)/s -- Using 43 MB RAM
2024-04-10T05:05:21.0278962-07:00|INFORMATION|Enumeration finished in 00:00:45.7547437
2024-04-10T05:05:21.0904077-07:00|INFORMATION|Saving cache with stats: 273 ID to type mappings.
 277 name to SID mappings.
2024-04-10T05:05:21.1060370-07:00|INFORMATION|SharpHound Enumeration Completed at 5:05 AM on 4/10/2024! Happy Graphing!";

    #[test]
    fn sharphound_v2_lines() {
        let got: Vec<Marker> = SHARPHOUND_V2.lines().filter_map(sharphound).collect();
        assert_eq!(
            got,
            vec![
                Marker::Step("enumerate"),
                Marker::Done(0),
                Marker::Done(1204),
                Marker::Step("write"),
                Marker::Step("write"),
                Marker::Step("write"),
                Marker::Done(2314),
                Marker::Finished,
                Marker::Finished,
            ]
        );
    }

    #[test]
    fn sharphound_variants() {
        // v1 style, no timestamp; other levels; future punctuation.
        assert_eq!(
            sharphound("Status: 60 objects finished (+60 2)/s -- Using 19 MB RAM"),
            Some(Marker::Done(60))
        );
        assert_eq!(
            sharphound("2025-01-01 10:00:00|INFO|status: 99 Objects Finished"),
            Some(Marker::Done(99))
        );
        assert_eq!(
            sharphound("12:00:00|WARNING|Status: 7 objects finished"),
            Some(Marker::Done(7))
        );
        assert_eq!(sharphound("[-] Some unrelated line | with a pipe"), None);
        assert_eq!(sharphound("Status: objects finished"), None);
        assert_eq!(sharphound(""), None);
    }

    #[test]
    fn rusthound_lines() {
        let lines = [
            ("[2026-10-09T10:00:00Z INFO  rusthound_ce::transport::ldap] Connected to CONTOSO.LOCAL Active Directory!", Some(Marker::Step("read"))),
            ("Ldap filter : (objectClass=*)", Some(Marker::Step("read"))),
            ("All data collected for NamingContext DC=contoso,DC=local", Some(Marker::Step("read"))),
            ("Starting the LDAP objects parsing...", Some(Marker::Step("parse"))),
            ("Starting checker to replace some values...", Some(Marker::Step("resolve"))),
            ("[sessions] 950 active target(s) after expiry/enabled filter", Some(Marker::Targets(950))),
            ("[gpo] mapping 12 GPO(s) to GPOChanges / UserRights", Some(Marker::Step("modules"))),
            ("1234 users parsed!", Some(Marker::Count("users".into(), 1234))),
            ("[2026-10-09T10:00:00Z INFO  rusthound_ce::json::maker::common] 17 computers parsed!", Some(Marker::Count("computers".into(), 17))),
            ("./out/20261009_contoso-local_users.json created!", Some(Marker::Step("write"))),
            ("RustHound-CE Enumeration Completed at 10:01:02 on 10/09/26! Happy Graphing!", Some(Marker::Finished)),
            ("MachineAccountQuota: 10", None),
        ];
        for (line, want) in lines {
            assert_eq!(rusthound(line), want, "{line}");
        }
    }
}
