//! A scheduled task's file (`C:\Windows\System32\Tasks\...`), read for the
//! one thing stored-credential detection needs: whether the task stores an account's password, and
//! whose. The file comes off a computer that may be hostile, so:
//!
//! - it is refused over [`MAX_TASK_FILE`] bytes;
//! - it is decoded strictly: UTF-16 (little or big endian, by its byte order
//!   mark, as Windows writes task files) or UTF-8, and refused when it isn't
//!   valid text;
//! - one linear pass refuses it before the parser sees it when it declares
//!   a DTD, or passes a limit beyond which the parser's work grows faster
//!   than the file: nesting ([`MAX_DEPTH`]; the parser recurses), attributes
//!   per element and per file, namespace declarations, CDATA sections,
//!   references and text (see `shape_ok`);
//! - the XML parser refuses any DTD too, so no entity can be declared (no
//!   "billion laughs", no external entity), and stops past [`MAX_NODES`]
//!   nodes;
//! - only `Task/Principals/Principal/{UserId,LogonType}` and
//!   `Task/Settings/Enabled` are looked at. Actions, arguments, the
//!   description and everything else are never read out of the parsed
//!   document, and the text is dropped once parsed. An error names a line
//!   at most, never the file's text.
//!
//! The password itself is never in the file: Windows keeps it in the
//! computer's credential store. The file only says that one is stored:
//! `LogonType` `Password` or `InteractiveTokenOrPassword`
//! ([`crate::storedcreds::STORED_LOGON_TYPES`]).

use crate::storedcreds::STORED_LOGON_TYPES;

/// Largest task file read (real ones: a few kilobytes).
pub const MAX_TASK_FILE: usize = 1 << 20;
/// Most attributes one element may carry (real ones: a handful).
pub const MAX_ATTRIBUTES: usize = 256;
/// Most XML nodes parsed (real files: a few hundred at most).
pub const MAX_NODES: u32 = 20_000;
/// Deepest element nesting (real files: five or six).
pub const MAX_DEPTH: usize = 64;
/// Most attributes in a whole file (real ones: a few).
pub const MAX_ATTRIBUTES_TOTAL: usize = 1024;
/// Most namespace declarations (`xmlns`, `xmlns:p`) on one element (real
/// ones: one, on `Task`).
pub const MAX_NS_PER_ELEMENT: usize = 4;
/// Most namespace declarations in a whole file.
pub const MAX_NS: usize = 16;
/// Most CDATA sections in a file (real ones: none).
pub const MAX_CDATA: usize = 32;
/// Most entity and character references in a file, in text and attribute
/// values alike (real ones: a few).
pub const MAX_REFERENCES: usize = 4096;
/// Most text in a file, outside markup (real ones: a few kilobytes).
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
/// Longest account name kept.
const MAX_ACCOUNT: usize = crate::storedcreds::MAX_TEXT;
/// Most principals looked at (the schema allows one).
const MAX_PRINCIPALS: usize = 16;

/// What a task file says about a stored password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAccount {
    /// The principal's `UserId`: `DOMAIN\user`, `user@domain` or a SID.
    pub account: String,
    /// One of [`STORED_LOGON_TYPES`].
    pub logon_type: &'static str,
    /// `Settings/Enabled`; `None` when not set (enabled by default).
    pub enabled: Option<bool>,
}

/// The text of a task file: UTF-16 by its byte order mark (or, without
/// one, by a NUL next to the first `<`), else UTF-8. Invalid text is an
/// error, never replaced.
pub fn decode(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() > MAX_TASK_FILE {
        return Err(format!(
            "{} bytes, over the {} KiB limit",
            bytes.len(),
            MAX_TASK_FILE / 1024
        ));
    }
    let utf16 = |b: &[u8], le: bool| -> Result<String, String> {
        let (pairs, rest) = b.as_chunks::<2>();
        if !rest.is_empty() {
            return Err("not valid UTF-16 (an odd number of bytes)".into());
        }
        let units = pairs.iter().map(|&c| {
            if le {
                u16::from_le_bytes(c)
            } else {
                u16::from_be_bytes(c)
            }
        });
        char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .map_err(|_| "not valid UTF-16".to_string())
    };
    let utf8 = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| "not valid UTF-8".to_string());
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, true),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, false),
        [0xEF, 0xBB, 0xBF, rest @ ..] => utf8(rest),
        [b'<', 0, ..] => utf16(bytes, true),
        [0, b'<', ..] => utf16(bytes, false),
        _ => utf8(bytes),
    }
}

/// Checks the shape of `xml` before it reaches the parser, in one linear
/// pass. Refused: a DTD; elements nested deeper than [`MAX_DEPTH`] (the
/// parser recurses); an element with more than [`MAX_ATTRIBUTES`]
/// attributes, or a file with more than [`MAX_ATTRIBUTES_TOTAL`] (the parser
/// checks duplicates in quadratic time); namespace declarations past
/// [`MAX_NS_PER_ELEMENT`] on an element or [`MAX_NS`] in the file (the
/// parser's namespace bookkeeping is quadratic too); more than
/// [`MAX_CDATA`] CDATA sections, [`MAX_REFERENCES`] entity or character
/// references, or [`MAX_TEXT_BYTES`] of text (the parser joins adjacent
/// text by copying). Comments, CDATA and processing instructions are
/// skipped whole, and quoted values inside tags, so markup inside them
/// can't make the counts wrong.
fn shape_ok(xml: &str) -> Result<(), String> {
    let b = xml.as_bytes();
    let unclosed = || "not valid XML (a construct is never closed)".to_string();
    let find = |from: usize, end: &str| {
        xml.get(from..)
            .and_then(|r| r.find(end))
            .map(|n| from + n + end.len())
    };
    let over = |what: &str, limit: usize| Err(format!("more than {limit} {what}"));
    let mut depth = 0usize;
    let mut attrs_total = 0usize;
    let mut ns_total = 0usize;
    let mut cdata = 0usize;
    let mut text = 0usize;
    let mut refs = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'<' {
            if b[i] == b'&' {
                refs += 1;
                if refs > MAX_REFERENCES {
                    return over("entity or character references", MAX_REFERENCES);
                }
            }
            if !b[i].is_ascii_whitespace() {
                text += 1;
                if text > MAX_TEXT_BYTES {
                    return over("bytes of text", MAX_TEXT_BYTES);
                }
            }
            i += 1;
            continue;
        }
        let rest = &b[i..];
        if rest.starts_with(b"<!--") {
            i = find(i + 4, "-->").ok_or_else(unclosed)?;
            continue;
        }
        if rest.starts_with(b"<![CDATA[") {
            cdata += 1;
            if cdata > MAX_CDATA {
                return over("CDATA sections", MAX_CDATA);
            }
            let end = find(i + 9, "]]>").ok_or_else(unclosed)?;
            text += end - i - 12;
            if text > MAX_TEXT_BYTES {
                return over("bytes of text", MAX_TEXT_BYTES);
            }
            i = end;
            continue;
        }
        if rest.starts_with(b"<?") {
            i = find(i + 2, "?>").ok_or_else(unclosed)?;
            continue;
        }
        if rest.starts_with(b"<!") {
            return Err("it declares a DTD, which task files never do".into());
        }
        // A start or end tag, to its `>` outside quoted values.
        let closing = rest.get(1) == Some(&b'/');
        let mut quote: Option<u8> = None;
        let mut attrs = 0usize;
        let mut ns = 0usize;
        let mut last = 0u8;
        let mut j = i + 1;
        loop {
            let Some(&c) = b.get(j) else {
                return Err(unclosed());
            };
            // References count in attribute values too.
            if c == b'&' {
                refs += 1;
                if refs > MAX_REFERENCES {
                    return over("entity or character references", MAX_REFERENCES);
                }
            }
            match (quote, c) {
                (Some(q), _) if c == q => quote = None,
                (Some(_), _) => {}
                (None, b'"' | b'\'') => quote = Some(c),
                (None, b'=') => {
                    attrs += 1;
                    attrs_total += 1;
                    if attrs > MAX_ATTRIBUTES {
                        return Err(format!(
                            "an element with more than {MAX_ATTRIBUTES} attributes"
                        ));
                    }
                    if attrs_total > MAX_ATTRIBUTES_TOTAL {
                        return over("attributes", MAX_ATTRIBUTES_TOTAL);
                    }
                    if attribute_name(b, i + 1, j).starts_with(b"xmlns") {
                        ns += 1;
                        ns_total += 1;
                        if ns > MAX_NS_PER_ELEMENT {
                            return Err(format!(
                                "an element with more than {MAX_NS_PER_ELEMENT} namespace \
                                 declarations"
                            ));
                        }
                        if ns_total > MAX_NS {
                            return over("namespace declarations", MAX_NS);
                        }
                    }
                }
                (None, b'>') => break,
                _ => {}
            }
            if !c.is_ascii_whitespace() {
                last = c;
            }
            j += 1;
        }
        if closing {
            depth = depth.saturating_sub(1);
        } else if last != b'/' {
            depth += 1;
            if depth > MAX_DEPTH {
                return Err(format!("elements nested more than {MAX_DEPTH} deep"));
            }
        }
        i = j + 1;
    }
    Ok(())
}

/// The attribute name before the `=` at `eq`, within a tag that starts at
/// `from`: back over spaces, then back to the space, quote or tag name
/// before it.
fn attribute_name(b: &[u8], from: usize, eq: usize) -> &[u8] {
    let mut end = eq;
    while end > from && b[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > from && !matches!(b[start - 1], b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'') {
        start -= 1;
    }
    &b[start..end]
}

/// Whether a task file's bytes match the hash its registration records
/// (`TaskCache\Tasks\{Id}`, value `Hash`), which ties the file to what
/// Task Scheduler registered: a file a user rewrote no longer matches.
///
/// Public descriptions of the value (the winreg-kb notes on the Task
/// Scheduler keys) give a SHA-256 of the task's XML file on Windows 10 and
/// Server 2016 on (a CRC32 before), computed over the file as stored,
/// without its byte order mark. Microsoft doesn't document it, so both the
/// file without its byte order mark and the whole file are accepted; either
/// way a rewritten file fails. A lab confirms the format.
pub fn matches_registration(bytes: &[u8], hash: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    if hash.len() != 32 {
        return false;
    }
    let body = bytes
        .strip_prefix(&[0xFF, 0xFE])
        .or_else(|| bytes.strip_prefix(&[0xFE, 0xFF]))
        .or_else(|| bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]))
        .unwrap_or(bytes);
    Sha256::digest(body).as_slice() == hash || Sha256::digest(bytes).as_slice() == hash
}

/// The first child element of `n` named `name` (any namespace).
fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    n.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

/// The trimmed text of an element, or "".
fn text_of<'a>(n: Option<roxmltree::Node<'a, '_>>) -> &'a str {
    n.and_then(|n| n.text()).map(str::trim).unwrap_or_default()
}

/// The account whose password the task stores, if it stores one: `None`
/// for a task that runs as a service account, with S4U, an interactive
/// token or a group, or has no principal. An error when the file is not a
/// task file Pathwarden can read safely.
pub fn stored_account(bytes: &[u8]) -> Result<Option<TaskAccount>, String> {
    let text = decode(bytes)?;
    shape_ok(&text)?;
    let opts = roxmltree::ParsingOptions {
        allow_dtd: false,
        nodes_limit: MAX_NODES,
    };
    let doc = roxmltree::Document::parse_with_options(&text, opts).map_err(|e| match e {
        roxmltree::Error::DtdDetected => "it declares a DTD, which task files never do".to_string(),
        roxmltree::Error::NodesLimitReached => format!("more than {MAX_NODES} XML nodes"),
        // The error's position only: never the text around it.
        e => format!("not valid XML (line {})", e.pos().row),
    })?;
    let root = doc.root_element();
    if root.tag_name().name() != "Task" {
        return Err("not a task file".into());
    }
    let enabled = child(root, "Settings")
        .and_then(|s| child(s, "Enabled"))
        .and_then(|e| match text_of(Some(e)) {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        });
    let Some(principals) = child(root, "Principals") else {
        return Ok(None);
    };
    for p in principals
        .children()
        .filter(|c| c.is_element() && c.tag_name().name() == "Principal")
        .take(MAX_PRINCIPALS)
    {
        let logon = text_of(child(p, "LogonType"));
        let Some(logon_type) = STORED_LOGON_TYPES.iter().find(|l| **l == logon) else {
            continue;
        };
        let user = text_of(child(p, "UserId"));
        if user.is_empty() || user.chars().any(char::is_control) {
            continue;
        }
        return Ok(Some(TaskAccount {
            account: user.chars().take(MAX_ACCOUNT).collect(),
            logon_type,
            enabled,
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    /// A task file as Task Scheduler writes it, with `principal` and
    /// `extra` inside `<Task>`.
    fn task(principal: &str, extra: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="{NS}">
  <RegistrationInfo><Author>NORTH\admin</Author><Description>Nightly sync</Description></RegistrationInfo>
  <Principals><Principal id="Author">{principal}</Principal></Principals>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>sync.exe</Command><Arguments>/p Hunter2!</Arguments></Exec></Actions>
  {extra}
</Task>"#
        )
    }

    fn utf16le(s: &str) -> Vec<u8> {
        let mut b = vec![0xFF, 0xFE];
        b.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
        b
    }

    fn principal(user: &str, logon: &str) -> String {
        format!("<UserId>{user}</UserId><LogonType>{logon}</LogonType>")
    }

    #[test]
    fn only_logon_types_that_store_a_password() {
        for (logon, stored) in [
            ("Password", true),
            ("InteractiveTokenOrPassword", true),
            ("S4U", false),
            ("InteractiveToken", false),
            ("ServiceAccount", false),
            ("Group", false),
            ("password", false),
            ("", false),
        ] {
            let xml = task(&principal(r"NORTH\svc_sync", logon), "");
            let got = stored_account(&utf16le(&xml)).unwrap();
            assert_eq!(got.is_some(), stored, "{logon}");
            if let Some(t) = got {
                assert_eq!(t.account, r"NORTH\svc_sync");
                assert_eq!(t.logon_type, logon);
                assert_eq!(t.enabled, Some(true));
            }
        }
        // No LogonType at all, or no UserId: nothing stored.
        let xml = task(r"<UserId>NORTH\svc</UserId>", "");
        assert_eq!(stored_account(xml.as_bytes()).unwrap(), None);
        let xml = task("<LogonType>Password</LogonType>", "");
        assert_eq!(stored_account(xml.as_bytes()).unwrap(), None);
        // A group principal.
        let xml = task("<GroupId>S-1-5-32-545</GroupId>", "");
        assert_eq!(stored_account(xml.as_bytes()).unwrap(), None);
    }

    /// A SID, a name or a UPN; disabled tasks still count; the arguments
    /// (with a password in them) never come out.
    #[test]
    fn reads_the_account_and_nothing_else() {
        for user in [
            "S-1-5-21-1-2-3-1201",
            r"NORTH\svc_sync",
            "svc_sync@north.contoso.local",
        ] {
            let xml = task(&principal(user, "Password"), "")
                .replace("<Enabled>true</Enabled>", "<Enabled>false</Enabled>");
            let t = stored_account(&utf16le(&xml)).unwrap().unwrap();
            assert_eq!(t.account, user);
            assert_eq!(t.enabled, Some(false));
            assert!(!format!("{t:?}").contains("Hunter2"));
        }
        // UTF-8, with and without its BOM, and UTF-16 big endian.
        let xml = task(&principal(r"NORTH\a", "Password"), "").replace("UTF-16", "UTF-8");
        assert!(stored_account(xml.as_bytes()).unwrap().is_some());
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(xml.as_bytes());
        assert!(stored_account(&bom).unwrap().is_some());
        let mut be = vec![0xFE, 0xFF];
        be.extend(xml.encode_utf16().flat_map(u16::to_be_bytes));
        assert!(stored_account(&be).unwrap().is_some());
        // UTF-16 without a BOM.
        let le: Vec<u8> = xml.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(stored_account(&le).unwrap().is_some());
        // A very long account name is cut.
        let long = format!(r"NORTH\{}", "a".repeat(5000));
        let xml = task(&principal(&long, "Password"), "");
        let t = stored_account(xml.as_bytes()).unwrap().unwrap();
        assert_eq!(t.account.chars().count(), MAX_ACCOUNT);
        // No Enabled element: not known.
        let xml = task(&principal(r"NORTH\a", "Password"), "")
            .replace("<Settings><Enabled>true</Enabled></Settings>", "");
        let t = stored_account(xml.as_bytes()).unwrap().unwrap();
        assert_eq!(t.enabled, None);
    }

    #[test]
    fn hostile_files_are_refused() {
        // Billion laughs: refused at the DTD, nothing expanded.
        let laughs = r#"<?xml version="1.0"?>
<!DOCTYPE Task [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<Task><Principals><Principal><UserId>&d;</UserId><LogonType>Password</LogonType></Principal></Principals></Task>"#;
        let e = stored_account(laughs.as_bytes()).unwrap_err();
        assert!(e.contains("DTD"), "{e}");
        assert!(stored_account(&utf16le(laughs))
            .unwrap_err()
            .contains("DTD"));
        // An external entity, likewise.
        let xxe =
            r#"<!DOCTYPE Task [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><Task>&x;</Task>"#;
        assert!(stored_account(xxe.as_bytes()).unwrap_err().contains("DTD"));
        // An undeclared entity.
        let xml = task(&principal("&x;", "Password"), "");
        assert!(stored_account(xml.as_bytes()).is_err());
        // Too large.
        let big = vec![b' '; MAX_TASK_FILE + 1];
        assert!(stored_account(&big).unwrap_err().contains("limit"));
        // Deep nesting: refused before the parser, no stack overflow.
        let deep = format!(
            "<Task>{}{}</Task>",
            "<a>".repeat(100_000),
            "</a>".repeat(100_000)
        );
        assert!(stored_account(deep.as_bytes())
            .unwrap_err()
            .contains("nested"));
        // Closing tags hidden in comments, CDATA or quoted values don't
        // undo the count (as many as the CDATA limit, each hiding two: if
        // counted, they would undo the whole nesting).
        for hide in ["<!--</a></a>-->", "<![CDATA[</a></a>]]>", "<b x='</a>'/>"] {
            let deep = format!(
                "<Task>{}{}</Task>",
                format!("<a>{hide}").repeat(MAX_CDATA),
                "<a>".repeat(MAX_DEPTH - MAX_CDATA)
            );
            assert!(
                stored_account(deep.as_bytes())
                    .unwrap_err()
                    .contains("nested"),
                "{hide}"
            );
        }
        // Nesting within the limit, comments and self-closing tags parse.
        let ok = format!(
            "<Task><!-- a <comment> --><x/>{}{}<Principals><Principal>{}</Principal></Principals></Task>",
            "<a>".repeat(MAX_DEPTH - 2),
            "</a>".repeat(MAX_DEPTH - 2),
            principal(r"NORTH\x", "Password")
        );
        assert!(stored_account(ok.as_bytes()).unwrap().is_some());
        // Many nodes, not deep: refused at the node limit.
        let wide = format!("<Task>{}</Task>", "<a/>".repeat(MAX_NODES as usize + 1));
        assert!(stored_account(wide.as_bytes())
            .unwrap_err()
            .contains("nodes"));
        // An element with very many attributes.
        let attrs: String = (0..=MAX_ATTRIBUTES)
            .map(|i| format!(" a{i}=\"\""))
            .collect();
        let xml = format!("<Task{attrs}/>");
        assert!(stored_account(xml.as_bytes())
            .unwrap_err()
            .contains("attributes"));
        // Never closed.
        assert!(stored_account(b"<Task><!-- x").is_err());
        assert!(stored_account(b"<Task a='>").is_err());
        // Bad encodings: odd UTF-16, an unpaired surrogate, bad UTF-8.
        assert!(stored_account(&[0xFF, 0xFE, b'<']).is_err());
        assert!(stored_account(&[0xFF, 0xFE, 0x00, 0xD8, b'<', 0]).is_err());
        assert!(stored_account(&[b'<', b'T', 0xC3, 0x28]).is_err());
        assert!(stored_account(b"").is_err());
        assert!(stored_account(&[0xFF, 0xFE]).is_err());
        // Not a task, not XML.
        assert!(stored_account(b"<Other/>")
            .unwrap_err()
            .contains("not a task"));
        assert!(stored_account(b"MZ\x90\x00").is_err());
        // A control character in the account: never kept (XML 1.0 refuses
        // it as a reference; a raw one is skipped).
        let xml = task(&principal(r"NORTH\a&#7;b", "Password"), "");
        assert!(stored_account(xml.as_bytes()).is_err());
        let xml = task(&principal("NORTH\\a\u{1}b", "Password"), "");
        assert!(!matches!(stored_account(xml.as_bytes()), Ok(Some(_))));
        // The error never quotes the file.
        let xml = task(&principal("Hunter2!", "Password"), "<broken");
        let e = stored_account(xml.as_bytes()).unwrap_err();
        assert!(!e.contains("Hunter2"), "{e}");
    }

    /// A file matches its registration's SHA-256 with or without its byte
    /// order mark; a rewritten one, or another hash size, never does.
    #[test]
    fn registration_hashes() {
        use sha2::{Digest, Sha256};
        let file = utf16le(&task(&principal(r"NORTH\bob", "Password"), ""));
        let without_bom = Sha256::digest(&file[2..]).to_vec();
        let whole = Sha256::digest(&file).to_vec();
        assert!(matches_registration(&file, &without_bom));
        assert!(matches_registration(&file, &whole));
        let forged = utf16le(&task(&principal(r"NORTH\Administrator", "Password"), ""));
        assert!(!matches_registration(&forged, &without_bom));
        assert!(!matches_registration(&file, &without_bom[..4]));
        assert!(!matches_registration(&file, &[]));
    }

    /// Files shaped to make the parser's work grow faster than the file:
    /// refused in the linear pre-check, quickly.
    #[test]
    fn quadratic_shapes_are_refused_fast() {
        let started = std::time::Instant::now();
        // The review's namespace bomb: 63 nested elements with 256
        // `xmlns:pN` each, then ~19,900 leaves declaring one each.
        let decls: String = (0..256)
            .map(|n| format!(" xmlns:p{n}=\"urn:{n}\""))
            .collect();
        let bomb = format!(
            "<Task>{}{}{}</Task>",
            format!("<a{decls}>").repeat(63),
            "<b xmlns:q=\"urn:q\"/>".repeat(19_900),
            "</a>".repeat(63)
        );
        assert!(bomb.len() < MAX_TASK_FILE);
        let e = stored_account(bomb.as_bytes()).unwrap_err();
        assert!(e.contains("namespace"), "{e}");
        // Few per element, many in the file.
        let leaves = format!(
            "<Task>{}</Task>",
            "<b xmlns:q=\"urn:q\"/>".repeat(MAX_NS + 1)
        );
        let e = stored_account(leaves.as_bytes()).unwrap_err();
        assert!(e.contains("namespace declarations"), "{e}");
        // A default namespace counts too; spaces around `=` don't hide one.
        let spaced: String = (0..=MAX_NS_PER_ELEMENT)
            .map(|n| format!(" xmlns:p{n} = 'urn:{n}'"))
            .collect();
        assert!(stored_account(format!("<Task{spaced}/>").as_bytes()).is_err());
        // Attributes: few per element, too many in the file.
        let many = format!(
            "<Task>{}</Task>",
            "<b x='1' y='2' z='3' w='4'/>".repeat(MAX_ATTRIBUTES_TOTAL / 4 + 1)
        );
        let e = stored_account(many.as_bytes()).unwrap_err();
        assert!(e.contains("attributes"), "{e}");
        // CDATA sections, references and text, each past its cap.
        let cdata = format!("<Task>{}</Task>", "<![CDATA[x]]>".repeat(MAX_CDATA + 1));
        assert!(stored_account(cdata.as_bytes())
            .unwrap_err()
            .contains("CDATA"));
        let refs = format!("<Task>{}</Task>", "&amp;".repeat(MAX_REFERENCES + 1));
        assert!(stored_account(refs.as_bytes())
            .unwrap_err()
            .contains("references"));
        let text = format!("<Task>{}</Task>", "x".repeat(MAX_TEXT_BYTES + 1));
        assert!(stored_account(text.as_bytes())
            .unwrap_err()
            .contains("text"));
        let big_cdata = format!(
            "<Task><![CDATA[{}]]></Task>",
            "x".repeat(MAX_TEXT_BYTES + 1)
        );
        assert!(stored_account(big_cdata.as_bytes())
            .unwrap_err()
            .contains("text"));
        // References in attribute values count too.
        let in_attrs = format!(
            "<Task>{}</Task>",
            format!("<b x='{}'/>", "&amp;".repeat(8)).repeat(MAX_REFERENCES / 8 + 1)
        );
        assert!(stored_account(in_attrs.as_bytes())
            .unwrap_err()
            .contains("references"));
        // A real task file is well within every limit (with its one xmlns).
        let ok = task(&principal(r"NORTH\a", "Password"), "");
        assert!(stored_account(ok.as_bytes()).unwrap().is_some());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }
}
