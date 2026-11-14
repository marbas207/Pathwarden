//! Targeted re-collection, for retesting one finding: read only the named
//! objects (by `objectSid` or `objectGUID`), the members of the named groups
//! (so member names resolve), and the domain object, through the same bind
//! and the same RustHound-CE search and parsing as a full collection. The
//! result is an ordinary collection (a zip of BloodHound JSON) holding just
//! those objects.
//!
//! For a finding that rests on sessions or local groups, it also reads those
//! on just the computers on the finding's path ([`RefreshTarget::hosts`],
//! at most [`MAX_HOSTS`]) over SMB (port 445) and RPC with the same account,
//! each computer with its own time limit ([`host_reader`]): with a user and
//! password, through the built-in collector's SMB sign-in (NTLM), as a Full
//! collection does; as the current Windows account (Windows only), through
//! Windows' own calls.
//!
//! Built-in collector only (Cargo feature `builtin`); without it,
//! [`refresh_objects`] says so.

use std::path::PathBuf;

pub use pathwarden_core::retest::targeted::{HostRead, SliceHost, MAX_HOSTS};

use crate::CollectRequest;

/// Most objects one targeted re-collection asks for.
pub const MAX_OBJECTS: usize = 600;

/// What to re-read.
#[derive(Debug, Clone, Default)]
pub struct RefreshTarget {
    /// Object IDs: SIDs (`S-1-5-21-...`) or GUIDs.
    pub ids: Vec<String>,
    /// Distinguished names of groups whose members to read as well.
    pub group_dns: Vec<String>,
    /// The domain's SID: the domain object is always read (the parser needs
    /// it).
    pub domain_sid: Option<String>,
    /// Computers (among `ids`) whose sessions or local groups to read too.
    /// Empty: none is contacted.
    pub hosts: Vec<SliceHost>,
}

/// What a targeted re-collection wrote.
#[derive(Debug, Default)]
pub struct Refreshed {
    /// Collector files (a zip) in the request's output directory.
    pub files: Vec<PathBuf>,
    /// The domain controller that answered.
    pub server: Option<String>,
    /// One per computer in [`RefreshTarget::hosts`]: what was read of it.
    pub hosts: Vec<HostRead>,
    /// Of [`RefreshTarget::ids`], those the search didn't return that the
    /// directory says are deleted (noSuchObject, or a tombstone). One the
    /// search didn't return and that isn't here may be hidden from the
    /// account: the retest doesn't take it as deleted.
    pub deleted: Vec<String>,
}

/// Does a targeted re-collection. The built-in collector
/// ([`BuiltinRefresher`]) contacts the domain controller and the computers;
/// tests give one that doesn't touch the network.
pub trait Refresher: Sync {
    fn refresh(&self, req: &CollectRequest, target: &RefreshTarget) -> anyhow::Result<Refreshed>;
}

/// A [`Refresher`] for tests: it contacts nothing, copies the collector
/// files of `source` into the request's output folder as the re-read, and
/// reports `hosts` as what was read of the computers asked for. Each
/// target it was given is kept in `asked`.
#[doc(hidden)]
pub struct FixedRefresher {
    pub source: PathBuf,
    pub hosts: Vec<HostRead>,
    /// Reported as [`Refreshed::deleted`].
    pub deleted: Vec<String>,
    pub asked: std::sync::Mutex<Vec<RefreshTarget>>,
}

impl FixedRefresher {
    pub fn new(source: impl Into<PathBuf>, hosts: Vec<HostRead>) -> Self {
        Self {
            source: source.into(),
            hosts,
            deleted: Vec::new(),
            asked: Default::default(),
        }
    }
}

impl Refresher for FixedRefresher {
    fn refresh(&self, req: &CollectRequest, target: &RefreshTarget) -> anyhow::Result<Refreshed> {
        self.asked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(target.clone());
        std::fs::create_dir_all(&req.output_dir)?;
        let mut files = Vec::new();
        for e in std::fs::read_dir(&self.source)?.flatten() {
            let to = req.output_dir.join(e.file_name());
            std::fs::copy(e.path(), &to)?;
            files.push(to);
        }
        let asked: std::collections::HashSet<&str> =
            target.hosts.iter().map(|h| h.id.as_str()).collect();
        Ok(Refreshed {
            files,
            server: Some("dc01.test".into()),
            hosts: self
                .hosts
                .iter()
                .filter(|h| asked.contains(h.id.as_str()))
                .cloned()
                .collect(),
            deleted: self.deleted.clone(),
        })
    }
}

/// How a targeted re-collection reads the computers on a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostReader {
    /// Over SMB with NTLM as the request's user and password (RustHound-CE's
    /// sessions and local groups modules).
    Ntlm,
    /// As the signed-in Windows account, through Windows' own calls
    /// (NetSessionEnum, NetWkstaUserEnum, Remote Registry,
    /// NetLocalGroupGetMembers). Windows only.
    WindowsAccount,
}

/// How the computers on a path are read with `auth`; `None` when they
/// can't be (the current account outside Windows, a ticket cache).
pub fn host_reader(auth: &crate::Auth) -> Option<HostReader> {
    match auth {
        crate::Auth::Password { .. } => Some(HostReader::Ntlm),
        crate::Auth::CurrentUser if cfg!(windows) => Some(HostReader::WindowsAccount),
        _ => None,
    }
}

/// [`refresh_objects`].
pub struct BuiltinRefresher;

impl Refresher for BuiltinRefresher {
    fn refresh(&self, req: &CollectRequest, target: &RefreshTarget) -> anyhow::Result<Refreshed> {
        refresh_objects(req, target)
    }
}

/// RFC 4515 escaping of every byte, for binary attribute values.
fn hex_escape(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}

/// RFC 4515 escaping for a string value (a DN).
fn escape_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

/// The binary form of `S-1-5-21-...`.
pub(crate) fn sid_bytes(sid: &str) -> Option<Vec<u8>> {
    let mut parts = sid.trim().strip_prefix("S-")?.split('-');
    let revision: u8 = parts.next()?.parse().ok()?;
    let authority: u64 = parts.next()?.parse().ok()?;
    let subs: Vec<u32> = parts.map(|p| p.parse().ok()).collect::<Option<_>>()?;
    if subs.is_empty() || subs.len() > 15 || authority >= 1 << 48 {
        return None;
    }
    let mut b = vec![revision, subs.len() as u8];
    b.extend_from_slice(&authority.to_be_bytes()[2..]);
    for s in subs {
        b.extend_from_slice(&s.to_le_bytes());
    }
    Some(b)
}

/// `S-1-5-21-...` from its binary form (the built-in collector reads SIDs).
#[cfg(any(feature = "builtin", test))]
pub(crate) fn sid_string(b: &[u8]) -> Option<String> {
    let (&revision, rest) = b.split_first()?;
    let (&count, rest) = rest.split_first()?;
    if rest.len() != 6 + 4 * count as usize {
        return None;
    }
    let mut authority = [0u8; 8];
    authority[2..].copy_from_slice(&rest[..6]);
    let mut out = format!("S-{revision}-{}", u64::from_be_bytes(authority));
    for c in rest[6..].as_chunks::<4>().0 {
        out.push_str(&format!(
            "-{}",
            u32::from_le_bytes([c[0], c[1], c[2], c[3]])
        ));
    }
    Some(out)
}

/// A GUID string (upper case) from its binary (little-endian fields) form.
#[cfg(any(feature = "builtin", test))]
pub(crate) fn guid_string(b: &[u8]) -> Option<String> {
    let b: &[u8; 16] = b.try_into().ok()?;
    let hex = |s: &[u8]| s.iter().map(|x| format!("{x:02X}")).collect::<String>();
    let rev = |s: &[u8]| {
        let mut v = s.to_vec();
        v.reverse();
        hex(&v)
    };
    Some(format!(
        "{}-{}-{}-{}-{}",
        rev(&b[0..4]),
        rev(&b[4..6]),
        rev(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    ))
}

/// The binary (little-endian fields) form of a GUID string.
pub(crate) fn guid_bytes(guid: &str) -> Option<Vec<u8>> {
    let hex: String = guid.trim().chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || guid.trim().len() != 36 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let raw: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
        .collect::<Option<_>>()?;
    let mut b = Vec::with_capacity(16);
    b.extend(raw[0..4].iter().rev());
    b.extend(raw[4..6].iter().rev());
    b.extend(raw[6..8].iter().rev());
    b.extend_from_slice(&raw[8..16]);
    Some(b)
}

/// The LDAP filter for a target. Errors for an ID that is neither a SID nor
/// a GUID, or when there is nothing (or too much) to read.
pub fn ldap_filter(target: &RefreshTarget) -> anyhow::Result<String> {
    let mut terms = Vec::new();
    for id in target.ids.iter().chain(target.domain_sid.iter()) {
        if let Some(b) = sid_bytes(id) {
            terms.push(format!("(objectSid={})", hex_escape(&b)));
        } else if let Some(b) = guid_bytes(id) {
            terms.push(format!("(objectGUID={})", hex_escape(&b)));
        } else {
            anyhow::bail!("'{id}' is not an object SID or GUID");
        }
    }
    for dn in &target.group_dns {
        if dn.trim().is_empty() {
            continue;
        }
        terms.push(format!("(memberOf={})", escape_value(dn.trim())));
    }
    terms.sort();
    terms.dedup();
    if terms.is_empty() {
        anyhow::bail!("nothing to re-read");
    }
    if terms.len() > MAX_OBJECTS {
        anyhow::bail!(
            "{} objects is too many for a targeted re-collection (at most {MAX_OBJECTS})",
            terms.len()
        );
    }
    Ok(format!("(|{})", terms.concat()))
}

/// Re-reads the target's objects into `req.output_dir`, and the sessions
/// and local groups of its computers. Blocks (up to two minutes, four with
/// computers); call it from a background thread. Uses the request's domain,
/// server, authentication and LDAPS settings; its method and scope are
/// ignored (LDAP, and SMB for the computers).
pub fn refresh_objects(req: &CollectRequest, target: &RefreshTarget) -> anyhow::Result<Refreshed> {
    let filter = ldap_filter(target)?;
    if req.method != crate::Method::Builtin {
        anyhow::bail!("only the built-in collector can re-read single objects");
    }
    if target.hosts.len() > MAX_HOSTS {
        anyhow::bail!(
            "{} computers is too many for a targeted re-collection (at most {MAX_HOSTS})",
            target.hosts.len()
        );
    }
    if !target.hosts.is_empty() && host_reader(&req.auth).is_none() {
        anyhow::bail!("reading computers needs a user and password");
    }
    crate::validate(req)?;
    let mut ids = target.ids.clone();
    ids.extend(target.domain_sid.iter().cloned());
    run(req, &filter, &ids, &target.hosts)
}

#[cfg(feature = "builtin")]
fn run(
    req: &CollectRequest,
    filter: &str,
    ids: &[String],
    hosts: &[SliceHost],
) -> anyhow::Result<Refreshed> {
    crate::builtin::targeted::run(req, filter, ids, hosts)
}

#[cfg(not(feature = "builtin"))]
fn run(
    _req: &CollectRequest,
    _filter: &str,
    _ids: &[String],
    _hosts: &[SliceHost],
) -> anyhow::Result<Refreshed> {
    anyhow::bail!(
        "this Pathwarden build has no built-in collector, so it can't re-read single objects; \
         collect again or upload a new collection to retest"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sids_and_guids_become_binary_filters() {
        assert_eq!(
            hex_escape(&sid_bytes("S-1-5-21-1-2-3-500").unwrap()),
            "\\01\\05\\00\\00\\00\\00\\00\\05\\15\\00\\00\\00\\01\\00\\00\\00\\02\\00\\00\\00\\03\\00\\00\\00\\f4\\01\\00\\00"
        );
        // {2B9A4F6C-0E2A-4B8D-9E55-1C2D3E4F5A6B} as AD stores it.
        assert_eq!(
            guid_bytes("2B9A4F6C-0E2A-4B8D-9E55-1C2D3E4F5A6B").unwrap(),
            [
                0x6c, 0x4f, 0x9a, 0x2b, 0x2a, 0x0e, 0x8d, 0x4b, 0x9e, 0x55, 0x1c, 0x2d, 0x3e, 0x4f,
                0x5a, 0x6b
            ]
        );
        assert!(sid_bytes("S-1-5").is_none());
        assert!(sid_bytes("S-1-5-21-x").is_none());
        assert!(guid_bytes("not-a-guid").is_none());
    }

    /// What an entry's `objectSid` and `objectGUID` say, to tell
    /// which objects asked for the search didn't return.
    #[test]
    fn binary_sids_and_guids_read_back() {
        for sid in [
            "S-1-5-21-1-2-3-500",
            "S-1-5-32-544",
            "S-1-5-21-4000000000-2-3",
        ] {
            assert_eq!(sid_string(&sid_bytes(sid).unwrap()).as_deref(), Some(sid));
        }
        let guid = "2B9A4F6C-0E2A-4B8D-9E55-1C2D3E4F5A6B";
        assert_eq!(
            guid_string(&guid_bytes(guid).unwrap()).as_deref(),
            Some(guid)
        );
        assert_eq!(
            guid_string(&guid_bytes(&guid.to_ascii_lowercase()).unwrap()).as_deref(),
            Some(guid)
        );
        assert!(sid_string(&[1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]).is_none());
        assert!(sid_string(&[]).is_none());
        assert!(guid_string(&[0; 15]).is_none());
    }

    #[test]
    fn filters_escape_and_refuse_odd_ids() {
        let f = ldap_filter(&RefreshTarget {
            ids: vec!["S-1-5-21-1-2-3-500".into()],
            group_dns: vec!["CN=A*(B)\\,C,DC=X".into()],
            domain_sid: Some("S-1-5-21-1-2-3".into()),
            hosts: vec![],
        })
        .unwrap();
        assert!(
            f.starts_with("(|(memberOf=CN=A\\2a\\28B\\29\\5c,C,DC=X)(objectSid="),
            "{f}"
        );
        assert_eq!(f.matches("(objectSid=").count(), 2);
        assert!(ldap_filter(&RefreshTarget {
            ids: vec!["*)(objectClass=*".into()],
            ..RefreshTarget::default()
        })
        .is_err());
        assert!(ldap_filter(&RefreshTarget::default()).is_err());
    }

    /// A user and password: NTLM over SMB, as a targeted retest. The Windows account:
    /// Windows' own calls, on Windows only; elsewhere the computers aren't
    /// read.
    #[test]
    fn the_sign_in_picks_how_computers_are_read() {
        let password = crate::Auth::Password {
            user: r"CONTOSO\svc".into(),
            password: crate::Secret::new("x"),
        };
        assert_eq!(host_reader(&password), Some(HostReader::Ntlm));
        assert_eq!(
            host_reader(&crate::Auth::CurrentUser),
            cfg!(windows).then_some(HostReader::WindowsAccount)
        );
        assert_eq!(
            host_reader(&crate::Auth::KerberosCache { ccache: None }),
            None
        );
        // Asking for computers as the current account is refused only where
        // it can't read them.
        let mut req = CollectRequest::new("contoso.local", "out");
        req.scope = crate::Scope::DcOnly;
        let target = RefreshTarget {
            ids: vec!["S-1-5-21-1-2-3-1001".into()],
            hosts: vec![SliceHost {
                id: "S-1-5-21-1-2-3-1001".into(),
                sessions: true,
                local_groups: false,
                ..Default::default()
            }],
            ..RefreshTarget::default()
        };
        req.auth = crate::Auth::KerberosCache { ccache: None };
        let err = refresh_objects(&req, &target).unwrap_err().to_string();
        assert!(err.contains("needs a user and password"), "{err}");
    }

    #[test]
    fn without_the_collector_it_says_so() {
        if crate::builtin_available() {
            return;
        }
        let req = CollectRequest::new("contoso.local", "out");
        let err = refresh_objects(
            &req,
            &RefreshTarget {
                ids: vec!["S-1-5-21-1-2-3-500".into()],
                ..RefreshTarget::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("no built-in collector"), "{err}");
    }
}
