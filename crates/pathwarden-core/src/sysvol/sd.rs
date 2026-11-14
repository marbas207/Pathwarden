//! Binary (self-relative) Windows security descriptors of files and folders,
//! and who they let write.
//!
//! The collector hands over the descriptor exactly as the server returned it
//! (`GetNamedSecurityInfoW` on a UNC path), hex-encoded, and all of the
//! interpretation happens here, where it can be tested. The format is
//! `SECURITY_DESCRIPTOR_RELATIVE`, `ACL`, `ACE_HEADER` and `SID` from
//! [MS-DTYP] 2.4.
//!
//! What counts as write, per principal:
//!
//! - allow ACEs minus deny ACEs **for the same SID** (a deny on a group the
//!   principal is in is not applied; that would need everyone's token);
//! - inherit-only ACEs are skipped: they apply to what is created inside,
//!   not to the folder or file itself;
//! - generic rights are expanded the way the file system maps them;
//! - the owner can always change the DACL, unless an OWNER RIGHTS ACE says
//!   otherwise;
//! - no DACL at all means everyone has full control.
//!
//! Conditional (callback) allow ACEs count as allow: their conditions are
//! not evaluated, and reporting a write that a condition limits is safer
//! than missing one.

/// Most ACEs read from one DACL (a 64 KiB ACL holds at most about 3,000).
const MAX_ACES: usize = 4096;

pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
/// FILE_ALL_ACCESS.
pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
/// FILE_GENERIC_WRITE.
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SELF_RELATIVE: u16 = 0x8000;

const INHERIT_ONLY_ACE: u8 = 0x08;
const INHERITED_ACE: u8 = 0x10;

pub const OWNER_RIGHTS: &str = "S-1-3-4";
pub const EVERYONE: &str = "S-1-1-0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceKind {
    Allow,
    Deny,
    /// Object, audit, alarm and other ACE types: not used on files.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub kind: AceKind,
    pub flags: u8,
    pub mask: u32,
    pub sid: String,
}

impl Ace {
    pub fn inherit_only(&self) -> bool {
        self.flags & INHERIT_ONLY_ACE != 0
    }

    pub fn inherited(&self) -> bool {
        self.flags & INHERITED_ACE != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptor {
    pub owner: Option<String>,
    /// `None`: no DACL, which grants everyone full control.
    pub dacl: Option<Vec<Ace>>,
}

/// What the descriptor protects: a folder (where "write" includes creating
/// files and deleting what is inside) or a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Folder,
    File,
}

/// A principal that can write, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writer {
    pub sid: String,
    /// Plain-language rights, most powerful first ("full control",
    /// "change permissions", "create files", ...).
    pub rights: Vec<&'static str>,
    /// It writes only as the owner.
    pub owner: bool,
    /// Every ACE that grants the rights is inherited from a parent folder.
    pub inherited: bool,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| "truncated security descriptor".to_string())
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| "truncated security descriptor".to_string())
}

/// A SID at `at`, as `S-1-...`, and its length in bytes.
pub fn parse_sid(b: &[u8], at: usize) -> Result<(String, usize), String> {
    let rev = *b.get(at).ok_or("truncated SID")?;
    let count = *b.get(at + 1).ok_or("truncated SID")? as usize;
    if rev != 1 || count > 15 {
        return Err("malformed SID".into());
    }
    let auth = b.get(at + 2..at + 8).ok_or("truncated SID")?;
    let authority = auth.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
    let mut s = format!("S-1-{authority}");
    for i in 0..count {
        let sub = u32_at(b, at + 8 + 4 * i).map_err(|_| "truncated SID")?;
        s.push('-');
        s.push_str(&sub.to_string());
    }
    Ok((s, 8 + 4 * count))
}

/// Parses a self-relative security descriptor.
pub fn parse(b: &[u8]) -> Result<SecurityDescriptor, String> {
    if b.len() < 20 || b[0] != 1 {
        return Err("not a security descriptor".into());
    }
    let control = u16_at(b, 2)?;
    if control & SE_SELF_RELATIVE == 0 {
        return Err("not a self-relative security descriptor".into());
    }
    let owner_at = u32_at(b, 4)? as usize;
    let dacl_at = u32_at(b, 16)? as usize;
    let owner = if owner_at == 0 {
        None
    } else {
        Some(parse_sid(b, owner_at)?.0)
    };
    let dacl = if control & SE_DACL_PRESENT == 0 || dacl_at == 0 {
        None
    } else {
        Some(parse_acl(b, dacl_at)?)
    };
    Ok(SecurityDescriptor { owner, dacl })
}

fn parse_acl(b: &[u8], at: usize) -> Result<Vec<Ace>, String> {
    let size = u16_at(b, at + 2)? as usize;
    let count = u16_at(b, at + 4)? as usize;
    if size < 8 || at + size > b.len() {
        return Err("ACL runs past the end of the security descriptor".into());
    }
    if count > MAX_ACES {
        return Err(format!("more than {MAX_ACES} ACEs"));
    }
    let end = at + size;
    let mut pos = at + 8;
    let mut aces = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = *b.get(pos).ok_or("truncated ACE")?;
        let flags = *b.get(pos + 1).ok_or("truncated ACE")?;
        let len = u16_at(b, pos + 2)? as usize;
        if len < 8 || pos + len > end {
            return Err("ACE runs past the end of its ACL".into());
        }
        let kind = match kind {
            // ACCESS_ALLOWED, ACCESS_ALLOWED_CALLBACK.
            0x00 | 0x09 => AceKind::Allow,
            // ACCESS_DENIED (a callback deny is not applied: its
            // condition may not hold).
            0x01 => AceKind::Deny,
            _ => AceKind::Other,
        };
        if kind != AceKind::Other {
            if len < 16 {
                return Err("ACE too short for its SID".into());
            }
            let mask = u32_at(b, pos + 4)?;
            let (sid, sid_len) = parse_sid(&b[..pos + len], pos + 8)?;
            if 8 + sid_len > len {
                return Err("SID runs past the end of its ACE".into());
            }
            aces.push(Ace {
                kind,
                flags,
                mask,
                sid,
            });
        }
        pos += len;
    }
    Ok(aces)
}

/// Generic rights expanded to file rights.
fn expand(mask: u32) -> u32 {
    let mut m = mask;
    if m & GENERIC_ALL != 0 {
        m |= FILE_ALL_ACCESS;
    }
    if m & GENERIC_WRITE != 0 {
        m |= FILE_GENERIC_WRITE;
    }
    m
}

/// Rights that let a principal change what a folder or file holds.
fn write_bits(target: Target) -> u32 {
    let base = FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER;
    match target {
        Target::Folder => base | FILE_DELETE_CHILD,
        Target::File => base,
    }
}

/// Plain-language names of the write rights in `mask`.
pub fn right_names(mask: u32, target: Target) -> Vec<&'static str> {
    let m = expand(mask);
    if m & FILE_ALL_ACCESS == FILE_ALL_ACCESS {
        return vec!["full control"];
    }
    let mut out = Vec::new();
    if m & WRITE_DAC != 0 {
        out.push("change permissions");
    }
    if m & WRITE_OWNER != 0 {
        out.push("take ownership");
    }
    match target {
        Target::Folder => {
            if m & FILE_WRITE_DATA != 0 {
                out.push("create files");
            }
            if m & FILE_APPEND_DATA != 0 {
                out.push("create folders");
            }
            if m & FILE_DELETE_CHILD != 0 {
                out.push("delete files inside");
            }
        }
        Target::File => {
            if m & FILE_WRITE_DATA != 0 {
                out.push("write");
            }
            if m & FILE_APPEND_DATA != 0 {
                out.push("append");
            }
        }
    }
    out
}

/// Every principal that can write to what `sd` protects, by SID, in the
/// order they first appear (the owner last).
pub fn writers(sd: &SecurityDescriptor, target: Target) -> Vec<Writer> {
    let Some(dacl) = &sd.dacl else {
        return vec![Writer {
            sid: EVERYONE.to_string(),
            rights: vec!["full control"],
            owner: false,
            inherited: false,
        }];
    };
    // Per SID: allowed, denied, and whether an explicit ACE allows.
    let mut order: Vec<&str> = Vec::new();
    let mut allow: std::collections::HashMap<&str, (u32, u32, bool)> =
        std::collections::HashMap::new();
    let mut owner_rights = false;
    for ace in dacl {
        if ace.sid == OWNER_RIGHTS {
            owner_rights = true;
        }
        if ace.inherit_only() || ace.kind == AceKind::Other {
            continue;
        }
        let entry = allow.entry(ace.sid.as_str()).or_insert_with(|| {
            order.push(ace.sid.as_str());
            (0, 0, false)
        });
        match ace.kind {
            AceKind::Allow => {
                entry.0 |= expand(ace.mask);
                if !ace.inherited() && expand(ace.mask) & write_bits(target) != 0 {
                    entry.2 = true;
                }
            }
            AceKind::Deny => entry.1 |= expand(ace.mask),
            AceKind::Other => {}
        }
    }
    let mut out = Vec::new();
    for sid in order {
        if sid == OWNER_RIGHTS {
            continue;
        }
        let (a, d, explicit) = allow[sid];
        let effective = a & !d;
        if effective & write_bits(target) == 0 {
            continue;
        }
        out.push(Writer {
            sid: sid.to_string(),
            rights: right_names(effective, target),
            owner: false,
            inherited: !explicit,
        });
    }
    // The owner may always rewrite the DACL (unless OWNER RIGHTS limits it).
    if let Some(owner) = &sd.owner {
        if !owner_rights && !out.iter().any(|w| w.sid == *owner) {
            out.push(Writer {
                sid: owner.clone(),
                rights: vec!["owner"],
                owner: true,
                inherited: false,
            });
        }
    }
    out
}

/// Lower-case hex.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Bytes from hex (either case).
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().as_bytes();
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    let digit = |c: u8| -> Result<u8, String> {
        (c as char)
            .to_digit(16)
            .map(|d| d as u8)
            .ok_or_else(|| "not hex".to_string())
    };
    s.chunks(2)
        .map(|p| Ok(digit(p[0])? << 4 | digit(p[1])?))
        .collect()
}

/// Builds self-relative security descriptors, for tests (here, in the
/// collector and in fixtures).
pub mod build {
    /// A SID's binary form.
    pub fn sid(s: &str) -> Vec<u8> {
        let parts: Vec<u64> = s
            .trim_start_matches("S-")
            .split('-')
            .map(|p| p.parse().expect("numeric SID part"))
            .collect();
        let mut out = vec![parts[0] as u8, (parts.len() - 2) as u8];
        out.extend_from_slice(&parts[1].to_be_bytes()[2..]);
        for sub in &parts[2..] {
            out.extend_from_slice(&(*sub as u32).to_le_bytes());
        }
        out
    }

    /// `(type, flags, mask, sid)`: type 0 allow, 1 deny.
    pub fn sd(owner: Option<&str>, aces: Option<&[(u8, u8, u32, &str)]>) -> Vec<u8> {
        let mut acl = Vec::new();
        if let Some(aces) = aces {
            let mut body = Vec::new();
            for (kind, flags, mask, s) in aces {
                let sid = sid(s);
                let len = (8 + sid.len()) as u16;
                body.push(*kind);
                body.push(*flags);
                body.extend_from_slice(&len.to_le_bytes());
                body.extend_from_slice(&mask.to_le_bytes());
                body.extend_from_slice(&sid);
            }
            acl.extend_from_slice(&[2, 0]);
            acl.extend_from_slice(&((8 + body.len()) as u16).to_le_bytes());
            acl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
            acl.extend_from_slice(&[0, 0]);
            acl.extend_from_slice(&body);
        }
        let owner = owner.map(sid).unwrap_or_default();
        let mut control: u16 = 0x8000;
        if aces.is_some() {
            control |= 0x0004;
        }
        let owner_at = if owner.is_empty() { 0 } else { 20u32 };
        let dacl_at = if aces.is_some() {
            20 + owner.len() as u32
        } else {
            0
        };
        let mut out = vec![1, 0];
        out.extend_from_slice(&control.to_le_bytes());
        out.extend_from_slice(&owner_at.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&dacl_at.to_le_bytes());
        out.extend_from_slice(&owner);
        out.extend_from_slice(&acl);
        out
    }

    /// [`sd`] as hex.
    pub fn sd_hex(owner: Option<&str>, aces: Option<&[(u8, u8, u32, &str)]>) -> String {
        super::to_hex(&sd(owner, aces))
    }
}

#[cfg(test)]
mod tests {
    use super::build::sd;
    use super::*;

    const HELPDESK: &str = "S-1-5-21-1-2-3-1105";
    const DA: &str = "S-1-5-21-1-2-3-512";

    #[test]
    fn parses_owner_and_aces() {
        let b = sd(
            Some("S-1-5-32-544"),
            Some(&[
                (0, 0, FILE_ALL_ACCESS, DA),
                (0, 0x10, 0x1200a9, "S-1-5-11"),
                (1, 0, FILE_WRITE_DATA, HELPDESK),
            ]),
        );
        let parsed = parse(&b).unwrap();
        assert_eq!(parsed.owner.as_deref(), Some("S-1-5-32-544"));
        let dacl = parsed.dacl.unwrap();
        assert_eq!(dacl.len(), 3);
        assert_eq!(dacl[0].sid, DA);
        assert_eq!(dacl[1].sid, "S-1-5-11");
        assert!(dacl[1].inherited());
        assert_eq!(dacl[2].kind, AceKind::Deny);
        // Round trip through hex.
        assert_eq!(from_hex(&to_hex(&b)).unwrap(), b);
        assert_eq!(from_hex("0A0b").unwrap(), vec![10, 11]);
        assert!(from_hex("abc").is_err());
    }

    #[test]
    fn writers_allow_minus_deny_skip_inherit_only_and_read() {
        let b = sd(
            Some(DA),
            Some(&[
                // Read and execute only: not a writer.
                (0, 0, 0x1200a9, "S-1-5-11"),
                // Modify, but write data denied: still creates folders.
                (0, 0, 0x1301bf, HELPDESK),
                (1, 0, FILE_WRITE_DATA, HELPDESK),
                // Inherit-only: applies to children, not the folder.
                (0, 0x0b, GENERIC_ALL, "S-1-3-0"),
                // Generic write, inherited.
                (0, 0x10, GENERIC_WRITE, "S-1-5-21-1-2-3-1106"),
                // Full control.
                (0, 0, FILE_ALL_ACCESS, DA),
            ]),
        );
        let w = writers(&parse(&b).unwrap(), Target::Folder);
        let sids: Vec<&str> = w.iter().map(|w| w.sid.as_str()).collect();
        assert_eq!(sids, [HELPDESK, "S-1-5-21-1-2-3-1106", DA]);
        assert_eq!(w[0].rights, ["create folders"]);
        assert!(!w[0].inherited);
        assert_eq!(w[1].rights, ["create files", "create folders"]);
        assert!(w[1].inherited);
        assert_eq!(w[2].rights, ["full control"]);
        // The owner already writes through an ACE: listed once.
        assert!(!w[2].owner);
    }

    #[test]
    fn owner_null_dacl_and_owner_rights() {
        // An owner with no ACE still writes (it can change the DACL).
        let b = sd(Some(HELPDESK), Some(&[(0, 0, FILE_ALL_ACCESS, DA)]));
        let w = writers(&parse(&b).unwrap(), Target::File);
        assert_eq!(w.len(), 2);
        assert_eq!(w[1].sid, HELPDESK);
        assert!(w[1].owner);
        assert_eq!(w[1].rights, ["owner"]);
        // OWNER RIGHTS with read only takes that away.
        let b = sd(
            Some(HELPDESK),
            Some(&[(0, 0, FILE_ALL_ACCESS, DA), (0, 0, 0x1200a9, OWNER_RIGHTS)]),
        );
        let w = writers(&parse(&b).unwrap(), Target::File);
        assert_eq!(w.len(), 1);
        // No DACL: everyone has full control.
        let w = writers(&parse(&sd(Some(DA), None)).unwrap(), Target::File);
        assert_eq!(w[0].sid, EVERYONE);
        assert_eq!(w[0].rights, ["full control"]);
        // An empty DACL: nobody but the owner.
        let w = writers(&parse(&sd(Some(DA), Some(&[]))).unwrap(), Target::File);
        assert_eq!(w.len(), 1);
        assert!(w[0].owner);
    }

    #[test]
    fn file_rights_and_folder_only_rights() {
        // Delete child means nothing on a file.
        let b = sd(None, Some(&[(0, 0, FILE_DELETE_CHILD, HELPDESK)]));
        assert!(writers(&parse(&b).unwrap(), Target::File).is_empty());
        assert_eq!(
            writers(&parse(&b).unwrap(), Target::Folder)[0].rights,
            ["delete files inside"]
        );
        let b = sd(
            None,
            Some(&[(0, 0, FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER, HELPDESK)]),
        );
        assert_eq!(
            writers(&parse(&b).unwrap(), Target::File)[0].rights,
            ["change permissions", "take ownership", "append"]
        );
    }

    #[test]
    fn rejects_malformed_descriptors() {
        let good = sd(Some(DA), Some(&[(0, 0, FILE_ALL_ACCESS, DA)]));
        assert!(parse(&[]).is_err());
        assert!(parse(&good[..good.len() - 3]).is_err());
        let mut absolute = good.clone();
        absolute[3] = 0;
        assert!(parse(&absolute).is_err());
        // An ACE claiming to be longer than its ACL.
        let mut long = good.clone();
        let ace = 20 + build::sid(DA).len() + 8;
        long[ace + 2] = 0xff;
        assert!(parse(&long).is_err());
        // An ACL claiming more ACEs than it holds.
        let mut many = good;
        let acl = 20 + build::sid(DA).len();
        many[acl + 4] = 9;
        assert!(parse(&many).is_err());
        // Random bytes never panic.
        let mut x: u32 = 7;
        for _ in 0..2000 {
            let len = (x % 120) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    (x >> 16) as u8
                })
                .collect();
            let mut b = bytes;
            if b.len() > 4 {
                b[0] = 1;
                b[3] |= 0x80;
            }
            let _ = parse(&b);
        }
    }
}
