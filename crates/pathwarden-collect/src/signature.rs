//! Whether the program given as SharpHound is signed by SpecterOps.
//!
//! Pathwarden runs the file it is given as SharpHound whatever it is; this
//! only says so when the file isn't signed by SpecterOps, so the user can
//! stop. On Windows, the file's Authenticode signature is checked with
//! `WinVerifyTrust` (the policy `WINTRUST_ACTION_GENERIC_VERIFY_V2`, as
//! Explorer and `Get-AuthenticodeSignature` use it), from the local
//! certificate cache only: nothing is fetched over the network and
//! revocation isn't checked. A valid signature counts as SpecterOps' when
//! its signing certificate's subject (common name or organization) contains
//! "SpecterOps", ignoring case. SharpHound releases are published by
//! SpecterOps (github.com/SpecterOps/SharpHound); the exact subject of their
//! signing certificate isn't pinned here.

use std::path::Path;

/// What the file's signature says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
    /// Validly signed by SpecterOps.
    SpecterOps,
    /// Validly signed by someone else: the signing certificate's name.
    Other(String),
    /// No signature.
    Unsigned,
    /// A signature that doesn't check out (the file was changed after it
    /// was signed, an untrusted or expired certificate, ...).
    Invalid,
    /// Not known: not Windows, or the file couldn't be checked.
    Unknown,
}

/// The signature of the file at `program`. A path the collector refuses (a
/// network or device path, or not a full path) is [`Signer::Unknown`],
/// never looked at.
pub fn signer(program: &Path) -> Signer {
    if !program.is_absolute()
        || pathwarden_core::plugins::is_network_path(&program.to_string_lossy())
    {
        return Signer::Unknown;
    }
    #[cfg(windows)]
    {
        win::signer(program)
    }
    #[cfg(not(windows))]
    {
        let _ = program;
        Signer::Unknown
    }
}

/// Whether a signing certificate with these names is SpecterOps'.
// Used by the Windows signature check (and tests) only.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn is_specterops(names: &[&str]) -> bool {
    names
        .iter()
        .any(|n| n.to_ascii_lowercase().contains("specterops"))
}

/// The warning for SharpHound at `program` when it isn't validly signed by
/// SpecterOps, as one sentence plus what to do; `None` when it is, or when
/// it can't be told (not Windows).
pub fn sharphound_warning(program: &Path) -> Option<String> {
    warning_for(&program.display().to_string(), &signer(program))
}

/// [`sharphound_warning`] for a request that runs SharpHound; `None` for
/// any other collector. The Collect page's check and `pathwarden collect`
/// both say it.
pub fn request_warning(req: &crate::CollectRequest) -> Option<String> {
    match &req.method {
        crate::Method::External {
            program,
            kind: crate::ExternalKind::SharpHound,
        } => sharphound_warning(program),
        _ => None,
    }
}

fn warning_for(name: &str, signer: &Signer) -> Option<String> {
    let what = match signer {
        Signer::SpecterOps | Signer::Unknown => return None,
        Signer::Unsigned => format!("{name} isn't signed by SpecterOps."),
        Signer::Other(by) => format!("{name} is signed by {}, not SpecterOps.", clean(by)),
        Signer::Invalid => format!("{name} has a signature that isn't valid."),
    };
    Some(format!(
        "{what} Run it only if you trust where it came from."
    ))
}

/// A certificate name as one short line of text.
fn clean(name: &str) -> String {
    let one: String = name.chars().filter(|c| !c.is_control()).take(120).collect();
    let one = one.trim();
    if one.is_empty() {
        "an unnamed certificate".into()
    } else {
        one.to_string()
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod win {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{
        HWND, INVALID_HANDLE_VALUE, TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN,
        TRUST_E_SUBJECT_FORM_UNKNOWN,
    };
    use windows_sys::Win32::Security::Cryptography::{
        szOID_ORGANIZATION_NAME, CertGetNameStringW, CERT_CONTEXT, CERT_NAME_ATTR_TYPE,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
        WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };

    use super::{is_specterops, Signer};

    pub(super) fn signer(program: &Path) -> Signer {
        if !program.is_file() {
            return Signer::Unknown;
        }
        let path: Vec<u16> = program
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path.as_ptr(),
            hFile: std::ptr::null_mut(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        // SAFETY: an all-zero WINTRUST_DATA is valid (null pointers, zero
        // flags); the fields that matter are set below.
        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file };
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        // Nothing from the network: the certificate chain is built from
        // what this computer has.
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let hwnd: HWND = INVALID_HANDLE_VALUE as HWND;
        // SAFETY: `data` points to `file`, which points to `path`; all
        // three outlive both calls. The state the first call keeps is
        // released by the second (WTD_STATEACTION_CLOSE).
        let status =
            unsafe { WinVerifyTrust(hwnd, &mut action, (&mut data as *mut WINTRUST_DATA).cast()) };
        let result = match status {
            0 => {
                // SAFETY: after a successful verify, the state data holds
                // the provider data until it is closed below; each pointer
                // is checked before use.
                let names = unsafe { signer_names(&data) };
                let refs: Vec<&str> = names.iter().map(String::as_str).collect();
                if is_specterops(&refs) {
                    Signer::SpecterOps
                } else {
                    Signer::Other(
                        names
                            .into_iter()
                            .find(|n| !n.is_empty())
                            .unwrap_or_default(),
                    )
                }
            }
            TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
                Signer::Unsigned
            }
            _ => Signer::Invalid,
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: as above; closing releases the state of the verify.
        unsafe { WinVerifyTrust(hwnd, &mut action, (&mut data as *mut WINTRUST_DATA).cast()) };
        result
    }

    /// The signing certificate's common name and organization.
    ///
    /// # Safety
    /// `data` must hold the state of a successful verify, not yet closed.
    unsafe fn signer_names(data: &WINTRUST_DATA) -> Vec<String> {
        let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if prov.is_null() {
            return Vec::new();
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if sgnr.is_null() {
            return Vec::new();
        }
        let cert = WTHelperGetProvCertFromChain(sgnr, 0);
        if cert.is_null() || (*cert).pCert.is_null() {
            return Vec::new();
        }
        let ctx = (*cert).pCert;
        vec![
            name(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, std::ptr::null()),
            name(ctx, CERT_NAME_ATTR_TYPE, szOID_ORGANIZATION_NAME.cast()),
        ]
    }

    /// One name of the certificate (`CertGetNameStringW`), empty if none.
    ///
    /// # Safety
    /// `ctx` must be a valid certificate context; `para` as the name type
    /// wants it.
    unsafe fn name(ctx: *const CERT_CONTEXT, kind: u32, para: *const core::ffi::c_void) -> String {
        let len = CertGetNameStringW(ctx, kind, 0, para, std::ptr::null_mut(), 0);
        if len <= 1 {
            return String::new();
        }
        let mut buf = vec![0u16; len as usize];
        let got = CertGetNameStringW(ctx, kind, 0, para, buf.as_mut_ptr(), len);
        let end = (got as usize).saturating_sub(1).min(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specterops_is_found_in_either_name() {
        assert!(is_specterops(&["SpecterOps, Inc.", ""]));
        assert!(is_specterops(&["Code Signing", "SPECTEROPS INC"]));
        assert!(!is_specterops(&["Fabrikam Tools Ltd", "Fabrikam"]));
        assert!(!is_specterops(&[]));
    }

    #[test]
    fn warnings_are_one_line_each() {
        let p = r"C:\Tools\SharpHound.exe";
        assert_eq!(warning_for(p, &Signer::SpecterOps), None);
        assert_eq!(warning_for(p, &Signer::Unknown), None);
        assert_eq!(
            warning_for(p, &Signer::Unsigned).unwrap(),
            r"C:\Tools\SharpHound.exe isn't signed by SpecterOps. Run it only if you trust where it came from."
        );
        assert_eq!(
            warning_for(p, &Signer::Other("Fabrikam Tools\r\nLtd".into())).unwrap(),
            r"C:\Tools\SharpHound.exe is signed by Fabrikam ToolsLtd, not SpecterOps. Run it only if you trust where it came from."
        );
        assert_eq!(
            warning_for(p, &Signer::Other(String::new())).unwrap(),
            r"C:\Tools\SharpHound.exe is signed by an unnamed certificate, not SpecterOps. Run it only if you trust where it came from."
        );
        assert_eq!(
            warning_for(p, &Signer::Invalid).unwrap(),
            r"C:\Tools\SharpHound.exe has a signature that isn't valid. Run it only if you trust where it came from."
        );
    }

    /// A scratch folder of this test's own.
    #[cfg(windows)]
    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pathwarden-signature-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(windows)]
    #[test]
    fn an_unsigned_file_is_unsigned_and_a_missing_one_unknown() {
        let d = scratch("unsigned");
        let f = d.join("SharpHound.exe");
        std::fs::write(&f, b"MZ not really a program").unwrap();
        assert_eq!(signer(&f), Signer::Unsigned);
        assert!(sharphound_warning(&f)
            .unwrap()
            .ends_with("isn't signed by SpecterOps. Run it only if you trust where it came from."));
        assert_eq!(signer(&d.join("missing.exe")), Signer::Unknown);
        assert_eq!(signer(Path::new("SharpHound.exe")), Signer::Unknown);
        assert_eq!(
            signer(Path::new(
                r"\\pathwarden-unc-test.invalid\share\SharpHound.exe"
            )),
            Signer::Unknown
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A program Windows ships with its own (embedded) signature is
    /// Microsoft's, not SpecterOps'; changed after signing, its signature
    /// isn't valid. Skipped where no such program is found.
    #[cfg(windows)]
    #[test]
    fn a_signed_file_names_its_signer_and_a_changed_one_is_invalid() {
        let Some(root) = std::env::var_os("SystemRoot") else {
            return;
        };
        let system = std::path::PathBuf::from(root).join("System32");
        let Some(signed) = ["MpSigStub.exe", "appverif.exe"]
            .iter()
            .map(|n| system.join(n))
            .find(|p| matches!(signer(p), Signer::Other(_)))
        else {
            eprintln!("skipping: no embedded-signed program found in System32");
            return;
        };
        match signer(&signed) {
            Signer::Other(by) => assert!(by.contains("Microsoft"), "{by}"),
            s => panic!("{s:?}"),
        }
        let d = scratch("changed");
        let copy = d.join("SharpHound.exe");
        let mut bytes = std::fs::read(&signed).unwrap();
        // A byte in the middle of the code, inside what the signature covers.
        let at = bytes.len() / 3;
        bytes[at] ^= 0xff;
        std::fs::write(&copy, &bytes).unwrap();
        assert_eq!(signer(&copy), Signer::Invalid);
        let _ = std::fs::remove_dir_all(&d);
    }
}
