//! Group Policy's `Registry.pol` (the PReg format) under a GPO's `Machine`
//! folder: the registry values its Administrative Templates set on
//! computers.
//!
//! Only two keys are kept, everything else in the file is skipped:
//!
//! - `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` (and its `AU`
//!   subkey): `WUServer`, `WUStatusServer`, `UseWUServer`, which name the
//!   WSUS server a computer takes its updates from.
//! - `SOFTWARE\Policies\Microsoft\CCMSetup`: `SetupParameters`, the SCCM
//!   client's installation settings (client push by Group Policy).
//!
//! The format: the signature `PReg`, version 1, then entries
//! `[key;value;type;size;data]` where the brackets, semicolons and the two
//! names are UTF-16LE (the names end with a NUL), `type` and `size` are
//! 32-bit little-endian, and `data` is `size` bytes. A value named
//! `**del.<name>` deletes `<name>`; `**delvals.` deletes every value of the
//! key. Anything that doesn't follow the format fails the file: a file
//! that can't be read whole isn't half used.

use serde::{Deserialize, Serialize};

/// Largest `Registry.pol` read, as for `Groups.xml`.
pub const MAX_FILE: usize = 4 * 1024 * 1024;
/// Most values kept from one file. Real files set a handful.
pub const MAX_VALUES: usize = 64;
/// Longest text value kept (a URL, the SCCM setup parameters).
pub const MAX_TEXT: usize = 1024;
/// Longest key or value name read, in UTF-16 units (the registry's own
/// limits are 255 for a key name and 16,383 for a value name).
const MAX_NAME: usize = 16_384;
/// Longest value name kept (the reader of a sidecar refuses longer ones).
pub const MAX_VALUE_NAME: usize = 256;

pub const WINDOWS_UPDATE: &str = r"SOFTWARE\POLICIES\MICROSOFT\WINDOWS\WINDOWSUPDATE";
pub const WINDOWS_UPDATE_AU: &str = r"SOFTWARE\POLICIES\MICROSOFT\WINDOWS\WINDOWSUPDATE\AU";
pub const CCM_SETUP: &str = r"SOFTWARE\POLICIES\MICROSOFT\CCMSETUP";

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const REG_DWORD_BIG_ENDIAN: u32 = 5;
const REG_QWORD: u32 = 11;

/// One value a GPO sets (or deletes) under a kept key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyValue {
    /// The key, upper case, without leading or trailing backslashes.
    pub key: String,
    /// The value name, upper case; `*` with `delete` for every value of
    /// the key (`**delvals.`).
    pub name: String,
    /// A string value (`REG_SZ`, `REG_EXPAND_SZ`), as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// A number (`REG_DWORD`, `REG_QWORD`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<u64>,
    /// The GPO deletes the value (a policy set to Disabled writes this).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub delete: bool,
}

impl PolicyValue {
    /// Whether the entry is well formed: a kept key, a name, and exactly
    /// one of a value or a delete. For values read back from a sidecar.
    pub fn is_valid(&self) -> bool {
        is_kept_key(&self.key)
            && !self.name.is_empty()
            && self.name.len() <= MAX_VALUE_NAME
            && self.text.as_ref().is_none_or(|t| t.len() <= MAX_TEXT)
            && (self.delete == (self.text.is_none() && self.number.is_none()))
            && !(self.text.is_some() && self.number.is_some())
    }
}

/// Whether `key` (upper case, trimmed as [`PolicyValue::key`]) is one of
/// the keys kept.
pub fn is_kept_key(key: &str) -> bool {
    matches!(key, WINDOWS_UPDATE | WINDOWS_UPDATE_AU | CCM_SETUP)
}

fn normalize_key(key: &str) -> String {
    key.trim_matches(['\\', ' ']).to_ascii_uppercase()
}

/// A cursor over the file's bytes; every read is bounds-checked.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn u16(&mut self) -> Result<u16, String> {
        let s = self
            .b
            .get(self.at..self.at + 2)
            .ok_or_else(|| truncated(self.at))?;
        self.at += 2;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let s = self
            .b
            .get(self.at..self.at + 4)
            .ok_or_else(|| truncated(self.at))?;
        self.at += 4;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn expect(&mut self, c: char) -> Result<(), String> {
        let at = self.at;
        match self.u16()? {
            u if u == c as u16 => Ok(()),
            _ => Err(format!("expected '{c}' at byte {at}")),
        }
    }

    /// A NUL-terminated UTF-16LE string.
    fn name(&mut self) -> Result<String, String> {
        let mut units = Vec::new();
        loop {
            match self.u16()? {
                0 => break,
                u => units.push(u),
            }
            if units.len() > MAX_NAME {
                return Err(format!("a name over {MAX_NAME} characters"));
            }
        }
        Ok(String::from_utf16_lossy(&units))
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let b: &'a [u8] = self.b;
        let end = self
            .at
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or_else(|| format!("a value of {n} bytes runs past the end of the file"))?;
        let s = &b[self.at..end];
        self.at = end;
        Ok(s)
    }
}

fn truncated(at: usize) -> String {
    format!("the file ends early (at byte {at})")
}

/// UTF-16LE text without its trailing NULs; an odd length is an error.
fn text(data: &[u8]) -> Result<String, String> {
    if !data.len().is_multiple_of(2) {
        return Err("a text value of odd length".into());
    }
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    Ok(String::from_utf16_lossy(&units[..end]))
}

/// The kept values of a `Registry.pol` file, in file order. `Err` with why
/// when the file is over [`MAX_FILE`], isn't a PReg file, or doesn't
/// follow the format to its end.
pub fn parse(bytes: &[u8]) -> Result<Vec<PolicyValue>, String> {
    if bytes.len() > MAX_FILE {
        return Err(format!("over {} MiB", MAX_FILE / (1024 * 1024)));
    }
    if bytes.len() < 8 || &bytes[..4] != b"PReg" {
        return Err("not a Registry.pol file".into());
    }
    if u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != 1 {
        return Err("a Registry.pol version other than 1".into());
    }
    let mut r = Reader { b: bytes, at: 8 };
    let mut out = Vec::new();
    while r.at < bytes.len() {
        r.expect('[')?;
        let key = r.name()?;
        r.expect(';')?;
        let name = r.name()?;
        r.expect(';')?;
        let kind = r.u32()?;
        r.expect(';')?;
        let size = r.u32()? as usize;
        r.expect(';')?;
        let data = r.bytes(size)?;
        r.expect(']')?;
        let key = normalize_key(&key);
        if !is_kept_key(&key) {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        let mut push = |v: PolicyValue| -> Result<(), String> {
            // As [`PolicyValue::is_valid`]: no setting kept has a longer name.
            if v.name.len() > MAX_VALUE_NAME {
                return Ok(());
            }
            if out.len() >= MAX_VALUES {
                return Err(format!(
                    "more than {MAX_VALUES} Windows Update or SCCM setup values"
                ));
            }
            out.push(v);
            Ok(())
        };
        let deleted = |name: &str| PolicyValue {
            key: key.clone(),
            name: name.to_ascii_uppercase(),
            text: None,
            number: None,
            delete: true,
        };
        if lower == "**delvals." {
            push(deleted("*"))?;
            continue;
        }
        if let Some(v) = lower.strip_prefix("**del.") {
            if !v.is_empty() {
                push(deleted(&name[6..]))?;
            }
            continue;
        }
        if lower.starts_with("**deletevalues") {
            for v in text(data)?.split(';').filter(|v| !v.trim().is_empty()) {
                push(deleted(v.trim()))?;
            }
            continue;
        }
        // Other markers (`**DeleteKeys`, `**SecureKey`, ...) and the key's
        // default value: nothing a kept setting reads.
        if lower.starts_with("**") || name.is_empty() {
            continue;
        }
        let (t, n) = match (kind, size) {
            (REG_SZ | REG_EXPAND_SZ, _) => {
                let t = text(data)?;
                if t.len() > MAX_TEXT {
                    continue;
                }
                (Some(t), None)
            }
            (REG_DWORD, 4) => (
                None,
                Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64),
            ),
            (REG_DWORD_BIG_ENDIAN, 4) => (
                None,
                Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64),
            ),
            (REG_QWORD, 8) => {
                let mut b = [0u8; 8];
                b.copy_from_slice(data);
                (None, Some(u64::from_le_bytes(b)))
            }
            // Binary, multi-string, or a number of the wrong size.
            _ => continue,
        };
        push(PolicyValue {
            key: key.clone(),
            name: name.to_ascii_uppercase(),
            text: t,
            number: n,
            delete: false,
        })?;
    }
    Ok(out)
}

/// Builds a `Registry.pol` file from `(key, name, type, data)` entries, for
/// tests (here and in the collector's).
#[doc(hidden)]
pub fn build(entries: &[(&str, &str, u32, &[u8])]) -> Vec<u8> {
    let mut b = b"PReg".to_vec();
    b.extend_from_slice(&1u32.to_le_bytes());
    let utf16 = |s: &str, b: &mut Vec<u8>| {
        for u in s.encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
    };
    for (key, name, kind, data) in entries {
        utf16("[", &mut b);
        utf16(key, &mut b);
        b.extend_from_slice(&[0, 0]);
        utf16(";", &mut b);
        utf16(name, &mut b);
        b.extend_from_slice(&[0, 0]);
        utf16(";", &mut b);
        b.extend_from_slice(&kind.to_le_bytes());
        utf16(";", &mut b);
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        utf16(";", &mut b);
        b.extend_from_slice(data);
        utf16("]", &mut b);
    }
    b
}

/// `s` as NUL-terminated UTF-16LE (a `REG_SZ` value's data), for tests.
#[doc(hidden)]
pub fn sz(s: &str) -> Vec<u8> {
    let mut b: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    b.extend_from_slice(&[0, 0]);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    const WU: &str = r"Software\Policies\Microsoft\Windows\WindowsUpdate";
    const AU: &str = r"Software\Policies\Microsoft\Windows\WindowsUpdate\AU";

    fn wsus_file(url: &str) -> Vec<u8> {
        build(&[
            (
                r"Software\Policies\Microsoft\Windows\System",
                "EnableSmartScreen",
                REG_DWORD,
                &1u32.to_le_bytes(),
            ),
            (WU, "WUServer", REG_SZ, &sz(url)),
            (WU, "WUStatusServer", REG_SZ, &sz(url)),
            (AU, "UseWUServer", REG_DWORD, &1u32.to_le_bytes()),
            (AU, "NoAutoUpdate", REG_BINARY_FOR_TEST, &[1, 2, 3]),
        ])
    }

    const REG_BINARY_FOR_TEST: u32 = 3;

    #[test]
    fn keeps_only_the_windows_update_and_sccm_setup_values() {
        let got = parse(&wsus_file("http://wsus01.example.test:8530")).unwrap();
        let names: Vec<(&str, &str)> = got
            .iter()
            .map(|v| (v.key.as_str(), v.name.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                (WINDOWS_UPDATE, "WUSERVER"),
                (WINDOWS_UPDATE, "WUSTATUSSERVER"),
                (WINDOWS_UPDATE_AU, "USEWUSERVER"),
            ]
        );
        assert_eq!(
            got[0].text.as_deref(),
            Some("http://wsus01.example.test:8530")
        );
        assert_eq!(got[2].number, Some(1));
        assert!(got.iter().all(PolicyValue::is_valid));

        let ccm = build(&[(
            r"\SOFTWARE\Policies\Microsoft\CCMSetup",
            "SetupParameters",
            REG_SZ,
            &sz("SMSSITECODE=P01 SMSMP=mp01.example.test"),
        )]);
        let got = parse(&ccm).unwrap();
        assert_eq!(got[0].key, CCM_SETUP);
        assert_eq!(
            got[0].text.as_deref(),
            Some("SMSSITECODE=P01 SMSMP=mp01.example.test")
        );
    }

    #[test]
    fn deletes_are_kept_as_deletes() {
        let f = build(&[
            (WU, "**del.WUServer", REG_SZ, &sz(" ")),
            (AU, "**delvals.", REG_SZ, &sz(" ")),
            (
                WU,
                "**DeleteValues",
                REG_SZ,
                &sz("WUStatusServer;UseWUServer;"),
            ),
            (WU, "**SecureKey", REG_DWORD, &1u32.to_le_bytes()),
        ]);
        let got = parse(&f).unwrap();
        let names: Vec<(&str, bool)> = got.iter().map(|v| (v.name.as_str(), v.delete)).collect();
        assert_eq!(
            names,
            [
                ("WUSERVER", true),
                ("*", true),
                ("WUSTATUSSERVER", true),
                ("USEWUSERVER", true)
            ]
        );
        assert!(got.iter().all(PolicyValue::is_valid));
    }

    #[test]
    fn names_longer_than_the_sidecar_keeps_are_skipped() {
        let long = "A".repeat(MAX_VALUE_NAME + 1);
        let delete = format!("**del.{long}");
        let list = format!("{long};WUServer;");
        let f = build(&[
            (WU, &long, REG_SZ, &sz("http://x")),
            (WU, &delete, REG_SZ, &sz(" ")),
            (WU, "**DeleteValues", REG_SZ, &sz(&list)),
            (WU, "WUStatusServer", REG_SZ, &sz("http://y")),
        ]);
        let got = parse(&f).unwrap();
        let names: Vec<&str> = got.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["WUSERVER", "WUSTATUSSERVER"]);
        assert!(got.iter().all(PolicyValue::is_valid));
    }

    #[test]
    fn an_empty_file_has_no_values() {
        assert_eq!(parse(&build(&[])).unwrap(), Vec::new());
    }

    #[test]
    fn a_wrong_header_or_version_is_refused() {
        assert!(parse(b"").is_err());
        assert!(parse(b"PReg").is_err());
        assert!(parse(b"GERP\x01\0\0\0").is_err());
        assert!(parse(b"PReg\x02\0\0\0").is_err());
        let mut xml = b"<?xml version=\"1.0\"?>".to_vec();
        xml.resize(64, b' ');
        assert!(parse(&xml).is_err());
    }

    #[test]
    fn every_truncation_is_an_error_and_never_a_panic() {
        let f = wsus_file("https://wsus01.example.test:8531");
        for n in 0..f.len() {
            // Cut at an entry's end is a shorter, valid file.
            let r = parse(&f[..n]);
            if let Ok(v) = &r {
                assert!(v.len() <= 3, "{n}: {v:?}");
            }
        }
        // Cut inside the last entry: an error.
        assert!(parse(&f[..f.len() - 1]).is_err());
        assert!(parse(&f[..f.len() - 3]).is_err());
    }

    #[test]
    fn odd_lengths_are_errors() {
        // A text value of odd length.
        let f = build(&[(WU, "WUServer", REG_SZ, b"h\0t\0t")]);
        assert!(parse(&f).unwrap_err().contains("odd length"));
        // A name cut in the middle of a UTF-16 unit.
        let mut f = build(&[(WU, "WUServer", REG_SZ, &sz("http://x"))]);
        f.truncate(8 + 2 + 3);
        assert!(parse(&f).is_err());
        // One stray byte after a whole entry.
        let mut f = wsus_file("http://x");
        f.push(b'[');
        assert!(parse(&f).is_err());
    }

    #[test]
    fn sizes_that_run_past_the_end_are_errors() {
        let mut f = build(&[(WU, "WUServer", REG_SZ, &sz("http://x"))]);
        // The size field of the only entry: after "[key\0;WUServer\0;type;".
        let at = 8 + 2 * (1 + WU.len() + 1 + 1 + "WUServer".len() + 1 + 1) + 4 + 2;
        f[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&f).unwrap_err().contains("past the end"));
    }

    #[test]
    fn oversized_files_and_lists_are_refused() {
        let mut big = build(&[]);
        big.resize(MAX_FILE + 1, 0);
        assert!(parse(&big).unwrap_err().contains("MiB"));
        let one = (WU, "WUServer", REG_SZ, sz("http://x"));
        let many: Vec<(&str, &str, u32, &[u8])> = (0..=MAX_VALUES)
            .map(|_| (one.0, one.1, one.2, one.3.as_slice()))
            .collect();
        assert!(parse(&build(&many)).unwrap_err().contains("more than"));
        // A URL over the cap is skipped, not kept cut.
        let long = format!("http://{}", "a".repeat(MAX_TEXT));
        assert!(parse(&build(&[(WU, "WUServer", REG_SZ, &sz(&long))]))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn numbers_of_the_wrong_size_are_skipped() {
        let f = build(&[
            (AU, "UseWUServer", REG_DWORD, &[1, 0]),
            (AU, "UseWUServer", REG_DWORD_BIG_ENDIAN, &[0, 0, 0, 1]),
            (AU, "UseWUServer", REG_QWORD, &2u64.to_le_bytes()),
        ]);
        let got = parse(&f).unwrap();
        assert_eq!(
            got.iter().map(|v| v.number).collect::<Vec<_>>(),
            [Some(1), Some(2)]
        );
    }

    #[test]
    fn hostile_bytes_never_panic() {
        // A cheap fuzz: every byte of a valid file flipped in turn.
        let f = wsus_file("http://wsus01");
        for i in 0..f.len() {
            for x in [0x00, 0xFF, 0x5B, 0x3B, 0x5D] {
                let mut g = f.clone();
                g[i] = x;
                let _ = parse(&g);
            }
        }
    }
}
