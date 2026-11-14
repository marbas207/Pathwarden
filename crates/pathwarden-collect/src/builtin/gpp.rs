//! Group Policy Preferences passwords (`cpassword`, MS14-025) and the
//! `pathwarden-sysvol.json` sidecar the built-in collector adds to its zip.
//!
//! The scan only notes that an element carries a non-empty `cpassword`,
//! with the account it is for. The value is never decrypted, copied, logged
//! or written anywhere. Files go through [`super::sysvol::xml_is_safe`]
//! first (size and attributes per element), like `Groups.xml` for the
//! parser.

use serde::Serialize;

use super::sysvol::xml_is_safe;

/// The GPP files that can hold a password: `Preferences\<dir>\<file>` under
/// a GPO's `Machine` and `User` folders.
pub(crate) const GPP_FILES: [(&str, &str); 6] = [
    ("Groups", "Groups.xml"),
    ("Services", "Services.xml"),
    ("ScheduledTasks", "ScheduledTasks.xml"),
    ("DataSources", "DataSources.xml"),
    ("Drives", "Drives.xml"),
    ("Printers", "Printers.xml"),
];

/// Attributes that name the account a GPP password belongs to, by file.
const ACCOUNT_ATTRS: [&str; 6] = [
    "userName",
    "accountName",
    "runAs",
    "username",
    "newName",
    "name",
];

/// Most accounts kept per file.
const MAX_ACCOUNTS: usize = 64;

/// What one file says: the accounts whose password it stores, or `None`
/// when it holds no `cpassword`. An account the file does not name is
/// "(not named)".
pub(crate) fn scan_cpassword(xml: &[u8]) -> Result<Option<Vec<String>>, String> {
    xml_is_safe(xml)?;
    let text = decode(xml);
    let b = text.as_bytes();
    let mut accounts: Vec<String> = Vec::new();
    let mut found = false;
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        i += 1;
        // Comments and CDATA hold no elements: skipped whole, so an
        // element commented out is not a password the GPO sets.
        let skip = [(&b"!--"[..], &b"-->"[..]), (b"![CDATA[", b"]]>")]
            .into_iter()
            .find(|(open, _)| b[i..].starts_with(open));
        if let Some((open, close)) = skip {
            i += open.len();
            i = b[i..]
                .windows(close.len())
                .position(|w| w == close)
                .map_or(b.len(), |at| i + at + close.len());
            continue;
        }
        if matches!(b.get(i), Some(b'/' | b'?' | b'!')) {
            continue;
        }
        // The element name.
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' && b[i] != b'/' {
            i += 1;
        }
        let mut has_password = false;
        let mut account: Option<(usize, String)> = None;
        // Attributes until the end of the tag.
        loop {
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= b.len() || b[i] == b'>' || b[i] == b'/' || b[i] == b'<' {
                break;
            }
            let name_start = i;
            while i < b.len() && b[i] != b'=' && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                i += 1;
            }
            let name = &text[name_start..i];
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if b.get(i) != Some(&b'=') {
                continue;
            }
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            let Some(&q) = b.get(i).filter(|&&c| c == b'"' || c == b'\'') else {
                continue;
            };
            i += 1;
            let value_start = i;
            while i < b.len() && b[i] != q {
                i += 1;
            }
            let value = &text[value_start..i.min(b.len())];
            i += 1;
            if name == "cpassword" {
                has_password |= !value.trim().is_empty();
            } else if let Some(rank) = ACCOUNT_ATTRS.iter().position(|a| *a == name) {
                let v = unescape(value.trim());
                if !v.is_empty() && account.as_ref().is_none_or(|(r, _)| rank < *r) {
                    account = Some((rank, v));
                }
            }
        }
        if has_password {
            found = true;
            let a = account
                .map(|(_, a)| a)
                .unwrap_or_else(|| "(not named)".to_string());
            if !accounts.contains(&a) && accounts.len() < MAX_ACCOUNTS {
                accounts.push(a);
            }
        }
    }
    Ok(found.then_some(accounts))
}

/// UTF-8 (with or without BOM), or UTF-16 LE with BOM, as text.
fn decode(xml: &[u8]) -> String {
    if let Some(rest) = xml.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let xml = xml.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(xml);
    String::from_utf8_lossy(xml).into_owned()
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// How much of one part was read (`pathwarden.sysvol.v1`).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub(crate) struct CheckOut {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub read: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl CheckOut {
    pub fn not_collected(reason: &str) -> Self {
        CheckOut {
            status: "not_collected",
            reason: Some(reason.to_string()),
            ..CheckOut::default()
        }
    }

    /// Sets the status from the counts: complete when nothing failed and
    /// the step finished, not collected when nothing could be read.
    pub fn finish(&mut self, timed_out: bool, first_error: Option<String>) {
        self.status = if self.failed == 0 && !timed_out {
            "complete"
        } else if self.read == 0 {
            "not_collected"
        } else {
            "partial"
        };
        if timed_out {
            self.reason = Some("the SYSVOL step ran out of time".into());
        } else if let Some(e) = first_error.filter(|_| self.failed > 0) {
            self.reason = Some(format!(
                "{} could not be read, first: {e}",
                pathwarden_core::text::count(self.failed, "item", "items")
            ));
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct ChecksOut {
    pub gpo_acl: CheckOut,
    pub logon_script_acl: CheckOut,
    pub gpp: CheckOut,
    /// Local groups set by GPOs (Restricted Groups, Group Policy
    /// Preferences), which become `GPOChanges` on OUs and domains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpo_local_groups: Option<CheckOut>,
    /// `Machine\Registry.pol` of the GPOs: the WSUS server and the SCCM
    /// client setup they set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_pol: Option<CheckOut>,
    /// SCCM's site objects, from the directory read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sccm_sites: Option<CheckOut>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FolderOut {
    pub path: String,
    pub sd: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GpoOut {
    pub guid: String,
    pub object_id: Option<String>,
    pub folders: Vec<FolderOut>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ScriptOut {
    pub script: String,
    pub users: Vec<String>,
    pub sd: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GppOut {
    pub guid: String,
    pub object_id: Option<String>,
    pub file: String,
    pub accounts: Vec<String>,
}

/// What one GPO, through one setting, puts in one local group.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct GpoLocalOut {
    pub guid: String,
    pub object_id: Option<String>,
    /// `restricted_groups` or `gpp` (Local Users and Groups).
    pub setting: &'static str,
    /// `administrators`, `remote_desktop`, `dcom` or `ps_remote`.
    pub group: &'static str,
    /// Only items with item-level targeting add these members.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub item_level_targeting: bool,
    /// More members than the cap: the list is cut, so ingest names no GPO
    /// where this one is linked.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub members_truncated: bool,
    /// The members' object IDs, as `GPOChanges` writes them.
    pub members: Vec<String>,
}

/// The sidecar.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SidecarOut {
    pub schema: &'static str,
    pub domain: String,
    pub dc: Option<String>,
    pub checks: ChecksOut,
    pub gpos: Vec<GpoOut>,
    pub logon_scripts: Vec<ScriptOut>,
    pub gpp_passwords: Vec<GppOut>,
    /// Which GPO and setting puts each member in the local groups. Empty
    /// when not read (as the current Windows user, or SYSVOL failed).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub gpo_local_groups: Vec<GpoLocalOut>,
    /// The Windows Update and SCCM setup values each GPO's
    /// `Machine\Registry.pol` sets, for the GPOs that set one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub registry_policy: Vec<pathwarden_core::sysvol::GpoPolicy>,
    /// SCCM's site objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sccm: Option<pathwarden_core::sysvol::sccm::SccmSites>,
    /// Disabled GPO links, from the directory read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_gp_links: Option<Vec<pathwarden_core::sysvol::DisabledLink>>,
    /// GPOs whose `Machine\Registry.pol` could not be read; empty
    /// when the read ran out of time.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub registry_pol_failed: Vec<pathwarden_core::sysvol::GpoRef>,
    /// Computers created through the machine account quota.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_quota_computers: Option<Vec<String>>,
}

/// The file name inside the zip.
pub(crate) const SIDECAR_FILE: &str = "pathwarden-sysvol.json";

impl SidecarOut {
    pub fn new(domain: &str, dc: &str) -> Self {
        SidecarOut {
            schema: "pathwarden.sysvol.v1",
            domain: domain.to_string(),
            dc: Some(dc.to_string()),
            checks: ChecksOut::default(),
            gpos: Vec::new(),
            logon_scripts: Vec::new(),
            gpp_passwords: Vec::new(),
            gpo_local_groups: Vec::new(),
            registry_policy: Vec::new(),
            sccm: None,
            disabled_gp_links: None,
            registry_pol_failed: Vec::new(),
            machine_quota_computers: None,
        }
    }

    /// Records what one GPO's `Machine\Registry.pol` read got.
    pub fn add_registry_pol(
        &mut self,
        guid: &str,
        object_id: Option<&String>,
        got: &RegistryPolGot,
        first_error: &mut Option<String>,
        warn: &dyn Fn(String),
    ) {
        let check = self
            .checks
            .registry_pol
            .get_or_insert_with(CheckOut::default);
        match got {
            RegistryPolGot::Missing => {}
            RegistryPolGot::Values(values) => {
                check.read += 1;
                if !values.is_empty() {
                    self.registry_policy
                        .push(pathwarden_core::sysvol::GpoPolicy {
                            guid: guid.to_string(),
                            object_id: object_id.cloned(),
                            values: values.clone(),
                        });
                }
            }
            RegistryPolGot::Unreadable(why) => {
                check.failed += 1;
                self.registry_pol_failed
                    .push(pathwarden_core::sysvol::GpoRef {
                        guid: guid.to_string(),
                        object_id: object_id.cloned(),
                    });
                warn(format!(
                    r"{guid} Machine\Registry.pol not read ({why}): its WSUS and SCCM settings are not collected"
                ));
                first_error.get_or_insert_with(|| why.clone());
            }
        }
    }
}

/// What reading one GPO's `Machine\Registry.pol` got: only the kept
/// values ([`pathwarden_core::sysvol::regpol`]), parsed as soon as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegistryPolGot {
    /// No such file: the GPO sets no Administrative Templates.
    Missing,
    Values(Vec<pathwarden_core::sysvol::regpol::PolicyValue>),
    /// Not read, too large, or not in the format.
    Unreadable(String),
}

impl RegistryPolGot {
    pub fn of(bytes: &[u8]) -> Self {
        match pathwarden_core::sysvol::regpol::parse(bytes) {
            Ok(v) => RegistryPolGot::Values(v),
            Err(e) => RegistryPolGot::Unreadable(e),
        }
    }
}

impl SidecarOut {
    /// Scans one GPP file and records it (never the password). A file
    /// that can't be scanned counts as failed: the part is then partial,
    /// and `first_error` names it when it is the first.
    pub fn scan_gpp(
        &mut self,
        guid: &str,
        object_id: Option<&String>,
        file: &str,
        bytes: &[u8],
        first_error: &mut Option<String>,
        warn: &dyn Fn(String),
    ) {
        match scan_cpassword(bytes) {
            Ok(found) => {
                self.checks.gpp.read += 1;
                if let Some(accounts) = found {
                    warn(format!(
                        "{guid} {file} stores a Group Policy Preferences password (cpassword)"
                    ));
                    self.gpp_passwords.push(GppOut {
                        guid: guid.to_string(),
                        object_id: object_id.cloned(),
                        file: file.to_string(),
                        accounts,
                    });
                }
            }
            Err(why) => {
                self.checks.gpp.failed += 1;
                warn(format!(
                    "{guid} {file} not checked for passwords ({why}). Check who can edit this GPO"
                ));
                first_error.get_or_insert_with(|| format!("{guid} {file}: {why}"));
            }
        }
    }

    /// Adds the sidecar to the collector's zip.
    pub fn append_to(&self, zip_path: &std::path::Path) -> Result<(), String> {
        use std::io::Write;
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(zip_path)
            .map_err(|e| e.to_string())?;
        let mut zip = zip::ZipWriter::new_append(file).map_err(|e| e.to_string())?;
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file(SIDECAR_FILE, options)
            .map_err(|e| e.to_string())?;
        zip.write_all(&json).map_err(|e| e.to_string())?;
        zip.finish().map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Users' logon scripts that resolve to NETLOGON, by script (relative
/// path, case kept from the first user), with the users' SIDs; and how many
/// users name a script outside NETLOGON or a malformed one.
pub(crate) fn logon_scripts(
    users: impl IntoIterator<Item = (String, String)>,
) -> (Vec<(String, Vec<String>)>, usize) {
    let mut by_key: std::collections::BTreeMap<String, (String, Vec<String>)> =
        std::collections::BTreeMap::new();
    let mut skipped = 0;
    for (sid, script) in users {
        let script = script.trim();
        if script.is_empty() {
            continue;
        }
        if !is_safe_relative(script) {
            skipped += 1;
            continue;
        }
        let script = script.replace('/', "\\");
        by_key
            .entry(script.to_ascii_lowercase())
            .or_insert_with(|| (script.clone(), Vec::new()))
            .1
            .push(sid);
    }
    (by_key.into_values().collect(), skipped)
}

/// A path that stays inside its share (the same test ingest applies).
pub(crate) fn is_safe_relative(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 260
        && !p.starts_with(['\\', '/'])
        && !p.contains(':')
        && !p
            .chars()
            .any(|c| c.is_control() || matches!(c, '*' | '?' | '"' | '<' | '>' | '|'))
        && p.split(['\\', '/'])
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// `{8-4-4-4-12}`: a GPO folder name.
pub(crate) fn is_gpo_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Lower-case hex.
#[cfg(any(windows, test))]
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUPS: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)" image="2" changed="2014-01-01 10:00:00" uid="{A1}"><Properties action="U" newName="" fullName="" description="" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="Administrator (built-in)"/></User></Groups>"#;

    #[test]
    fn finds_the_account_never_the_value() {
        let found = scan_cpassword(GROUPS.as_bytes()).unwrap().unwrap();
        assert_eq!(found, ["Administrator (built-in)"]);
        assert!(!format!("{found:?}").contains("j1Uyj3"));
        // With a BOM, and in UTF-16.
        let mut bom = b"\xEF\xBB\xBF".to_vec();
        bom.extend_from_slice(GROUPS.as_bytes());
        assert!(scan_cpassword(&bom).unwrap().is_some());
        let mut utf16 = vec![0xFF, 0xFE];
        for u in GROUPS.encode_utf16() {
            utf16.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(
            scan_cpassword(&utf16).unwrap().unwrap(),
            ["Administrator (built-in)"]
        );
    }

    #[test]
    fn each_file_type_names_its_account() {
        let cases = [
            (
                r#"<NTServices><NTService name="svc"><Properties serviceName="x" accountName="CONTOSO\svc_sql" cpassword="abc"/></NTService></NTServices>"#,
                "CONTOSO\\svc_sql",
            ),
            (
                r#"<ScheduledTasks><Task name="t"><Properties runAs='CONTOSO\task' cpassword='abc' logonType="Password"/></Task></ScheduledTasks>"#,
                "CONTOSO\\task",
            ),
            (
                r#"<DataSources><DataSource name="d"><Properties dsn="x" username="sa&amp;co" cpassword="abc"/></DataSource></DataSources>"#,
                "sa&co",
            ),
            (
                r#"<Drives><Drive name="H:"><Properties path="\\fs\h" userName="CONTOSO\map" cpassword="abc"/></Drive></Drives>"#,
                "CONTOSO\\map",
            ),
            (
                r#"<Printers><SharedPrinter name="p"><Properties path="\\ps\p" username="CONTOSO\prn" cpassword="abc"/></SharedPrinter></Printers>"#,
                "CONTOSO\\prn",
            ),
        ];
        for (xml, account) in cases {
            assert_eq!(
                scan_cpassword(xml.as_bytes()).unwrap().unwrap(),
                [account],
                "{xml}"
            );
        }
        // No account attribute at all.
        assert_eq!(
            scan_cpassword(br#"<a><b cpassword="x"/></a>"#)
                .unwrap()
                .unwrap(),
            ["(not named)"]
        );
    }

    #[test]
    fn empty_or_absent_cpassword_is_not_a_finding() {
        let xml = GROUPS.replace("j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw", "");
        assert_eq!(scan_cpassword(xml.as_bytes()).unwrap(), None);
        assert_eq!(
            scan_cpassword(b"<Groups><User userName='x'/></Groups>").unwrap(),
            None
        );
        // A value that merely contains the word, or a comment, is not one.
        assert_eq!(
            scan_cpassword(br#"<a description="cpassword=&quot;x&quot;"/><!-- cpassword="y" -->"#)
                .unwrap(),
            None
        );
        // An element commented out, or in CDATA, sets nothing.
        assert_eq!(
            scan_cpassword(
                br#"<Groups><!-- <User name="old"><Properties userName="x" cpassword="y"/></User> --><![CDATA[<a cpassword="z"/>]]></Groups>"#
            )
            .unwrap(),
            None
        );
        // The element after one still counts.
        assert_eq!(
            scan_cpassword(
                br#"<Groups><!-- old --><Properties userName="x" cpassword="y"/></Groups>"#
            )
            .unwrap()
            .unwrap(),
            ["x"]
        );
        // Garbage never panics.
        for junk in [
            &b"<!--"[..],
            b"<!-- x",
            b"<![CDATA[",
            b"<!-->",
            b"<",
            b"<a b",
            b"<a b=",
            b"<a b=\"",
            b"<a b='x' c",
            b"\xff\xfe\x00",
        ] {
            let _ = scan_cpassword(junk);
        }
    }

    #[test]
    fn hostile_files_are_refused_before_scanning() {
        let mut x = String::from("<Groups><User ");
        for i in 0..300_000 {
            x.push_str(&format!("a{i}=\"\" "));
        }
        x.push_str("cpassword=\"x\"/></Groups>");
        let started = std::time::Instant::now();
        let err = scan_cpassword(x.as_bytes()).unwrap_err();
        assert!(err.contains("more than 256 attributes"), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        let big = vec![b' '; super::super::sysvol::MAX_GPP_XML + 1];
        assert!(scan_cpassword(&big).unwrap_err().contains("4 MiB"));
    }

    #[test]
    fn logon_scripts_group_by_file_and_skip_other_servers() {
        let (scripts, skipped) = logon_scripts([
            ("S-1".to_string(), "logon.bat".to_string()),
            ("S-2".to_string(), "LOGON.BAT".to_string()),
            ("S-3".to_string(), "it/admin.cmd".to_string()),
            ("S-4".to_string(), r"\\fs01\scripts\x.bat".to_string()),
            ("S-5".to_string(), r"..\..\x.bat".to_string()),
            ("S-6".to_string(), "".to_string()),
        ]);
        assert_eq!(skipped, 2);
        assert_eq!(
            scripts,
            [
                (r"it\admin.cmd".to_string(), vec!["S-3".to_string()]),
                (
                    "logon.bat".to_string(),
                    vec!["S-1".to_string(), "S-2".to_string()]
                ),
            ]
        );
    }

    #[test]
    fn check_status_from_counts() {
        let mut c = CheckOut {
            read: 3,
            ..CheckOut::default()
        };
        c.finish(false, None);
        assert_eq!(c.status, "complete");
        c.failed = 1;
        c.finish(false, Some("access denied".into()));
        assert_eq!(c.status, "partial");
        assert!(c.reason.as_deref().unwrap().contains("access denied"));
        c.read = 0;
        c.finish(false, None);
        assert_eq!(c.status, "not_collected");
        let mut t = CheckOut {
            read: 2,
            ..CheckOut::default()
        };
        t.finish(true, None);
        assert_eq!(t.status, "partial");
    }

    /// A GPP file that can't be scanned leaves the part partial,
    /// with the file named, not complete.
    #[test]
    fn a_file_not_scanned_makes_the_gpp_part_partial() {
        let mut s = SidecarOut::new("contoso.local", "dc01.contoso.local");
        let mut first = None;
        let warned = std::cell::RefCell::new(Vec::new());
        let warn = |m: String| warned.borrow_mut().push(m);
        s.scan_gpp(
            "{A}",
            None,
            r"Machine\Preferences\Groups\Groups.xml",
            GROUPS.as_bytes(),
            &mut first,
            &warn,
        );
        let big = vec![b' '; super::super::sysvol::MAX_GPP_XML + 1];
        s.scan_gpp(
            "{B}",
            None,
            r"Machine\Preferences\Services\Services.xml",
            &big,
            &mut first,
            &warn,
        );
        s.checks.gpp.finish(false, first);
        let gpp = &s.checks.gpp;
        assert_eq!((gpp.read, gpp.failed, gpp.status), (1, 1, "partial"));
        let reason = gpp.reason.as_deref().unwrap();
        assert!(
            reason.contains(r"{B} Machine\Preferences\Services\Services.xml"),
            "{reason}"
        );
        assert!(warned
            .borrow()
            .iter()
            .any(|w| w.contains("not checked for passwords")));
    }

    /// The sidecar the collector writes is what ingest reads.
    #[test]
    fn sidecar_round_trips_through_ingest() {
        use pathwarden_core::sysvol::{sd::build, CheckStatus, Sidecar};
        let mut s = SidecarOut::new("contoso.local", "dc01.contoso.local");
        s.checks.gpo_acl = CheckOut {
            read: 1,
            ..CheckOut::default()
        };
        s.checks.gpo_acl.finish(false, None);
        s.checks.logon_script_acl = CheckOut::not_collected("password authentication");
        s.gpos.push(GpoOut {
            guid: "{31B2F340-016D-11D2-945F-00C04FB984F9}".into(),
            object_id: Some("31B2F340-016D-11D2-945F-00C04FB984F9".into()),
            folders: vec![FolderOut {
                path: String::new(),
                sd: hex(&build::sd(Some("S-1-5-32-544"), Some(&[]))),
            }],
        });
        s.scan_gpp(
            "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            None,
            r"Machine\Preferences\Groups\Groups.xml",
            GROUPS.as_bytes(),
            &mut None,
            &|_| {},
        );
        s.checks.gpp.finish(false, None);
        let json = serde_json::to_vec(&s).unwrap();
        assert!(!String::from_utf8_lossy(&json).contains("j1Uyj3"));
        let mut notes = Vec::new();
        let back = Sidecar::parse(&json, &mut notes).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(back.checks.gpo_acl.status, CheckStatus::Complete);
        assert_eq!(
            back.checks.logon_script_acl.status,
            CheckStatus::NotCollected
        );
        assert_eq!(back.checks.gpp.status, CheckStatus::Complete);
        assert_eq!(back.gpos.len(), 1);
        assert_eq!(back.gpp_passwords[0].accounts, ["Administrator (built-in)"]);
        assert_eq!(pathwarden_core::sysvol::FILE_NAME, SIDECAR_FILE);
    }

    #[test]
    fn sidecar_goes_into_the_zip() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("pw-gpp-zip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.zip");
        {
            let mut z = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
            z.start_file("users.json", zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(b"{}").unwrap();
            z.finish().unwrap();
        }
        SidecarOut::new("contoso.local", "dc01")
            .append_to(&path)
            .unwrap();
        let mut z = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
        let names: Vec<String> = (0..z.len())
            .map(|i| z.by_index(i).unwrap().name().unwrap().into_owned())
            .collect();
        assert_eq!(names, ["users.json", SIDECAR_FILE]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
