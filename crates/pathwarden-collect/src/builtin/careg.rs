//! The Enterprise CAs' registry flags. RustHound-CE 2.5.27 (MIT,
//! see THIRD-PARTY-NOTICES.md) reads `EditFlags` itself in a Full collection,
//! but only with a password or NT hash, and not `InterfaceFlags`; this module
//! reads both as the collecting account (the current Windows user or a gMSA
//! too), keeps RustHound-CE's ESC6 value when it has one, and always adds
//! ESC11:
//!
//! - `EditFlags` of the default policy module: `EDITF_ATTRIBUTESUBJECTALTNAME2`
//!   (0x40000) lets a requester put any name in the SAN of any template's
//!   certificate (ESC6);
//! - `InterfaceFlags`: without `IF_ENFORCEENCRYPTICERTREQUEST` (0x200), the
//!   CA's RPC interface accepts NTLM-relayed requests (ESC11).
//!
//! On a CA host any authenticated user can read
//! `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc` remotely: installing the
//! AD CS role adds it to the "remotely accessible registry paths" (it is not
//! in Windows' base list). Hardening can remove it, and then the read fails
//! and the CA stays not collected. So a full collection reads
//! both flags from each CA's host as the collecting account, over Remote
//! Registry (`dcerpc::rrp`, the client RustHound-CE uses for registry
//! sessions), and writes them into the collection's Enterprise CA objects in
//! SharpHound's shape (`CARegistryData.IsUserSpecifiesSanEnabled`,
//! `isuserspecifiessanenabledcollected`), so that Pathwarden and BloodHound
//! CE both use them. ESC11 has no field in BloodHound's model; it is
//! recorded as `enforceencryptionforrequests`.
//!
//! A CA that can't be read stays not collected, with the reason.

use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use dcerpc::rrp::{RegValue, RegistryClient};
use rusthound_ce::args::Options;
use rusthound_ce::objects::enterpriseca::EnterpriseCA;
use rusthound_ce::transport::smb::{connect_ipc, smb_identity, SmbAuth};
use serde_json::{json, Value};

use super::hosts::SmbIdentity;
use super::Msg;

const CONFIGURATION: &str = r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration";
const POLICY_MODULE: &str = r"PolicyModules\CertificateAuthority_MicrosoftDefault.Policy";
/// `EDITF_ATTRIBUTESUBJECTALTNAME2`.
const SAN_FLAG: u32 = 0x0004_0000;
/// `IF_ENFORCEENCRYPTICERTREQUEST`.
const ENCRYPT_FLAG: u32 = 0x0000_0200;
/// RPC "pipe not available": Remote Registry was still starting.
const PIPE_NOT_AVAILABLE: &str = "0xc00000ac";
/// How long Remote Registry gets to start before it is asked again.
const REGISTRY_START: Duration = Duration::from_secs(3);
/// Longest wait for one CA, sign-in included.
const PER_CA: Duration = Duration::from_secs(30);

/// The two flags of one CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Flags {
    pub edit_flags: u32,
    /// `None` when the value is not set (the CA has never had it written).
    pub interface_flags: Option<u32>,
}

impl Flags {
    pub(crate) fn san_enabled(self) -> bool {
        self.edit_flags & SAN_FLAG != 0
    }

    /// Not set means the default, which on current Windows enforces
    /// encryption, so only a set value without the flag counts as off.
    pub(crate) fn encryption_enforced(self) -> bool {
        self.interface_flags.is_none_or(|v| v & ENCRYPT_FLAG != 0)
    }
}

/// What was read from one CA.
#[derive(Debug, Clone)]
pub(crate) struct CaRead {
    /// The CA's name, as `caname` in the collection.
    pub ca: String,
    /// Its host, as `dnshostname` in the collection.
    pub host: String,
    pub flags: Result<Flags, String>,
}

/// Reads the flags of every Enterprise CA in `cas` that names its host.
pub(crate) async fn read(
    options: &Options,
    smb: &SmbIdentity,
    cas: &[EnterpriseCA],
    tx: &mpsc::Sender<Msg>,
) -> Vec<CaRead> {
    let log = |m: String| {
        let _ = tx.send(Msg::Log(m));
    };
    // Bare name only; the domain is `smb.domain` (2.5.26 folded smb_user into
    // smb_identity, which returns (domain, user)).
    let user = smb_identity(options.username.as_deref().unwrap_or_default(), &smb.domain).1;
    let password = options.password.clone().unwrap_or_default();
    let mut out = Vec::new();
    for ca in cas {
        let (name, host) = (ca.caname().trim(), ca.dns_host().trim());
        if name.is_empty() || host.is_empty() {
            continue;
        }
        let mut flags = read_one(host, name, smb, &user, &password).await;
        if flags
            .as_ref()
            .is_err_and(|e| e.contains(PIPE_NOT_AVAILABLE))
        {
            log(format!(
                "[adcs] Remote Registry was starting on {host}; asking again in {}s",
                REGISTRY_START.as_secs()
            ));
            tokio::time::sleep(REGISTRY_START).await;
            flags = read_one(host, name, smb, &user, &password).await;
        }
        match &flags {
            Ok(f) => log(format!(
                "[adcs] {name} on {host}: requester-supplied SAN {} (ESC6), request encryption {} (ESC11)",
                if f.san_enabled() { "ON" } else { "off" },
                if f.encryption_enforced() { "enforced" } else { "NOT enforced" },
            )),
            Err(e) => log(format!(
                "warning: [adcs] could not read the registry flags of {name} on {host}, so ESC6 \
                 is not checked for it: {e}"
            )),
        }
        out.push(CaRead {
            ca: name.to_string(),
            host: host.to_string(),
            flags,
        });
    }
    out
}

async fn read_one(
    host: &str,
    ca: &str,
    smb: &SmbIdentity,
    user: &str,
    password: &str,
) -> Result<Flags, String> {
    match tokio::time::timeout(PER_CA, read_flags(host, ca, smb, user, password)).await {
        Ok(r) => r,
        Err(_) => Err(format!("no answer within {}s", PER_CA.as_secs())),
    }
}

/// One registry value read, by either client.
trait ReadValue {
    async fn value(&mut self, subkey: &str, name: &str) -> Result<RegValue, String>;
}

impl ReadValue for RegistryClient<'_> {
    async fn value(&mut self, subkey: &str, name: &str) -> Result<RegValue, String> {
        self.read_value(subkey, name)
            .await
            .map_err(|e| e.to_string())
    }
}

impl ReadValue for super::krbreg::Registry<'_> {
    async fn value(&mut self, subkey: &str, name: &str) -> Result<RegValue, String> {
        self.read_value(subkey, name).await
    }
}

async fn read_flags(
    host: &str,
    ca: &str,
    smb: &SmbIdentity,
    user: &str,
    password: &str,
) -> Result<Flags, String> {
    let domain = smb.domain.as_str();
    match &smb.kerberos {
        // Kerberos only: the CA host's cifs/ ticket, and the
        // registry bound without NTLM over that session.
        Some(k) => {
            let mut client = super::krbreg::connect(host, &k.ccache, &k.kdc, domain, user)
                .await
                .map_err(|e| e.to_string())?;
            let mut reg = super::krbreg::Registry::open(&mut client)
                .await
                .map_err(|e| format!("Remote Registry: {e}"))?;
            flags_of(&mut reg, ca).await
        }
        None => {
            let mut client = connect_ipc(host, domain, user, SmbAuth::Password(password))
                .await
                .map_err(|e| e.to_string())?;
            let mut reg = RegistryClient::connect(&mut client, domain, user, password, host)
                .await
                .map_err(|e| format!("Remote Registry: {e}"))?;
            flags_of(&mut reg, ca).await
        }
    }
}

async fn flags_of(reg: &mut impl ReadValue, ca: &str) -> Result<Flags, String> {
    // The key is the CA's sanitized name, normally its name. If not, the
    // host's active CA names it.
    let mut key = format!(r"{CONFIGURATION}\{ca}");
    let edit = match reg
        .value(&format!(r"{key}\{POLICY_MODULE}"), "EditFlags")
        .await
    {
        Ok(v) => v,
        Err(first) => {
            let active = reg
                .value(CONFIGURATION, "Active")
                .await
                .map(|v| v.as_string())
                .ok()
                .filter(|a| !a.is_empty() && !a.eq_ignore_ascii_case(ca));
            let Some(active) = active else {
                return Err(format!("EditFlags: {first}"));
            };
            key = format!(r"{CONFIGURATION}\{active}");
            reg.value(&format!(r"{key}\{POLICY_MODULE}"), "EditFlags")
                .await
                .map_err(|e| format!("EditFlags: {e}"))?
        }
    };
    let edit_flags = edit
        .as_dword()
        .ok_or_else(|| "EditFlags is not a number".to_string())?;
    let interface_flags = reg
        .value(&key, "InterfaceFlags")
        .await
        .ok()
        .and_then(|v| v.as_dword());
    Ok(Flags {
        edit_flags,
        interface_flags,
    })
}

/// Writes what was read into the collection zip's `*_enterprisecas.json`.
pub(crate) fn apply_to_zip(zip: &Path, reads: &[CaRead]) -> Result<(), String> {
    if reads.is_empty() {
        return Ok(());
    }
    super::fixups::patch_zip(
        zip,
        |name| name.ends_with("_enterprisecas.json"),
        |_, doc| patch(doc, reads),
    )
}

/// Sets each read CA's flags in an Enterprise CA collection document.
pub(crate) fn patch(doc: &mut Value, reads: &[CaRead]) {
    let Some(data) = doc.get_mut("data").and_then(Value::as_array_mut) else {
        return;
    };
    for o in data.iter_mut().filter_map(Value::as_object_mut) {
        let prop = |k: &str| {
            o.get("Properties")
                .and_then(|p| p.get(k))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let (name, host) = (prop("caname"), prop("dnshostname"));
        let Some(read) = reads
            .iter()
            .find(|r| r.ca.eq_ignore_ascii_case(&name) && r.host.eq_ignore_ascii_case(&host))
        else {
            continue;
        };
        // RustHound-CE 2.5.27 reads EditFlags itself in a Full collection
        // (with a password or NT hash; not as the current Windows user or a
        // gMSA). Its value stands when it read one; ours fills the gap.
        let upstream_read = o
            .get("CARegistryData")
            .and_then(|r| r.get("IsUserSpecifiesSanEnabled"))
            .and_then(|s| s.get("Collected"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let san = match &read.flags {
            Ok(f) => json!({ "Value": f.san_enabled(), "Collected": true, "FailureReason": null }),
            Err(e) => json!({ "Value": null, "Collected": false, "FailureReason": e }),
        };
        if !o.get("CARegistryData").is_some_and(Value::is_object) {
            o.insert("CARegistryData".into(), json!({}));
        }
        if !upstream_read {
            if let Some(reg) = o.get_mut("CARegistryData").and_then(Value::as_object_mut) {
                reg.insert("IsUserSpecifiesSanEnabled".into(), san);
            }
        }
        if !o.get("Properties").is_some_and(Value::is_object) {
            o.insert("Properties".into(), json!({}));
        }
        if let Some(p) = o.get_mut("Properties").and_then(Value::as_object_mut) {
            p.insert(
                "isuserspecifiessanenabledcollected".into(),
                (upstream_read || read.flags.is_ok()).into(),
            );
            if let Ok(f) = &read.flags {
                p.insert(
                    "enforceencryptionforrequests".into(),
                    f.encryption_enforced().into(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> Value {
        json!({ "data": [
            { "Properties": { "caname": "ESSOS-CA", "dnshostname": "braavos.essos.local",
                              "isuserspecifiessanenabledcollected": false },
              "CARegistryData": { "IsUserSpecifiesSanEnabled": { "Value": false, "Collected": false,
                                  "FailureReason": "not collected: the MS-RRP bind needs a password or NT hash" } } },
            { "Properties": { "caname": "OTHER-CA", "dnshostname": "other.essos.local" } }
        ], "meta": { "type": "enterprisecas" } })
    }

    fn read(flags: Result<Flags, String>) -> CaRead {
        CaRead {
            ca: "essos-ca".into(),
            host: "BRAAVOS.essos.local".into(),
            flags,
        }
    }

    #[test]
    fn flags_from_goad() {
        // braavos.essos.local on GOAD, read as a plain domain user.
        let f = Flags {
            edit_flags: 0x0015_014e,
            interface_flags: Some(0x441),
        };
        assert!(f.san_enabled());
        assert!(!f.encryption_enforced());
        let default = Flags {
            edit_flags: 0x0011_014e,
            interface_flags: None,
        };
        assert!(!default.san_enabled());
        assert!(default.encryption_enforced());
    }

    #[test]
    fn a_read_ca_is_marked_collected() {
        let mut d = doc();
        let f = Flags {
            edit_flags: 0x0015_014e,
            interface_flags: Some(0x441),
        };
        patch(&mut d, &[read(Ok(f))]);
        let ca = &d["data"][0];
        assert_eq!(
            ca["CARegistryData"]["IsUserSpecifiesSanEnabled"],
            json!({ "Value": true, "Collected": true, "FailureReason": null })
        );
        assert_eq!(ca["Properties"]["isuserspecifiessanenabledcollected"], true);
        assert_eq!(ca["Properties"]["enforceencryptionforrequests"], false);
        // Another CA is left as it was.
        assert_eq!(d["data"][1], doc()["data"][1]);
    }

    #[test]
    fn rusthound_ce_s_own_read_stands_and_esc11_is_added() {
        // 2.5.27 read EditFlags itself (a password run): keep its value.
        let mut d = doc();
        d["data"][0]["CARegistryData"]["IsUserSpecifiesSanEnabled"] =
            json!({ "Value": true, "Collected": true, "FailureReason": null });
        d["data"][0]["Properties"]["isuserspecifiessanenabledcollected"] = json!(true);
        let ours = Flags {
            edit_flags: 0x0011_014e,
            interface_flags: Some(0x441),
        };
        patch(&mut d, &[read(Ok(ours))]);
        let ca = &d["data"][0];
        assert_eq!(
            ca["CARegistryData"]["IsUserSpecifiesSanEnabled"],
            json!({ "Value": true, "Collected": true, "FailureReason": null })
        );
        assert_eq!(ca["Properties"]["isuserspecifiessanenabledcollected"], true);
        assert_eq!(ca["Properties"]["enforceencryptionforrequests"], false);
        // Even when our own read failed, theirs stays collected.
        let mut d2 = d.clone();
        patch(&mut d2, &[read(Err("access denied".into()))]);
        assert_eq!(
            d2["data"][0]["CARegistryData"],
            d["data"][0]["CARegistryData"]
        );
        assert_eq!(
            d2["data"][0]["Properties"]["isuserspecifiessanenabledcollected"],
            true
        );
    }

    #[test]
    fn an_unread_ca_says_why() {
        let mut d = doc();
        patch(
            &mut d,
            &[read(Err("Remote Registry: access denied".into()))],
        );
        let ca = &d["data"][0];
        assert_eq!(
            ca["CARegistryData"]["IsUserSpecifiesSanEnabled"]["Collected"],
            false
        );
        assert_eq!(
            ca["CARegistryData"]["IsUserSpecifiesSanEnabled"]["FailureReason"],
            "Remote Registry: access denied"
        );
        assert_eq!(
            ca["Properties"]["isuserspecifiessanenabledcollected"],
            false
        );
        assert!(ca["Properties"]
            .get("enforceencryptionforrequests")
            .is_none());
    }
}
