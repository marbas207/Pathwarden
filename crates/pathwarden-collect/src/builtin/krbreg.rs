//! Remote Registry over a Kerberos SMB session, without NTLM.
//!
//! dcerpc's `RegistryClient` (the client RustHound-CE's sessions module and
//! Pathwarden's CA registry read use) binds `\winreg` with NTLM sign and
//! seal only, so with Kerberos only it would hand each computer an NTLM
//! response. Over a named pipe the RPC layer needs no sign-in of its own:
//! the call runs as the SMB session's account (impacket's `reg.py` binds
//! the same way), and the SMB session is Kerberos, its replies signed and
//! checked (vendor/smb2-client). This is that client: a plain bind, then
//! `OpenLocalMachine`, `OpenUsers`, `BaseRegOpenKey`, `BaseRegQueryValue`,
//! `BaseRegEnumKey` and `BaseRegCloseKey`. The request encoders follow
//! dcerpc 0.2.11's (`rrp.rs`, MIT), which are private; its public reply
//! decoders are used as they are.
//!
//! Used for the Remote Registry sessions of a Full collection (which
//! RustHound-CE then records as not collected) and for the CAs' flags
//! (`super::careg`).

use dcerpc::ndr::{NdrDecoder, NdrEncoder};
use dcerpc::rrp::{decode_enum_key, decode_query_value, opnum, winreg_syntax, Hkey, RegValue};
use dcerpc::transport::SmbPipe;
use rusthound_ce::transport::smb::{connect_ipc, SmbAuth};
use smb2_client::SmbClient;

use super::krb::{self, NoTicket};

/// REGSAM for reading (KEY_READ).
const KEY_READ: u32 = 0x0002_0019;
/// The buffer offered to `BaseRegQueryValue`.
const QUERY_BUF: u32 = 0x0002_0000;
/// Most HKEY_USERS subkeys read.
const MAX_SUBKEYS: u32 = 10_000;

/// Signs in to `host`'s IPC$ with its `cifs/` ticket from `kdc` and the TGT
/// in `ccache`. A computer without one is never connected to: the error
/// says why ([`NoTicket`]).
pub(crate) async fn connect(
    host: &str,
    ccache: &str,
    kdc: &str,
    domain: &str,
    user: &str,
) -> Result<SmbClient, Failure> {
    let (blob, key) = krb::service_ticket(ccache, host, kdc)
        .await
        .map_err(Failure::NoTicket)?;
    connect_ipc(
        host,
        domain,
        user,
        SmbAuth::Kerberos {
            gss_blob: &blob,
            session_key: &key,
        },
    )
    .await
    .map_err(|e| Failure::Smb(format!("{e:#}")))
}

/// Why a Kerberos registry read failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// No service ticket: the computer was not contacted.
    NoTicket(NoTicket),
    /// The SMB sign-in, the pipe or a call failed.
    Smb(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::NoTicket(why) => f.write_str(&why.words()),
            Failure::Smb(e) => f.write_str(e),
        }
    }
}

/// `\winreg` on a signed-in SMB session, bound without RPC sign-in.
pub(crate) struct Registry<'a> {
    pipe: SmbPipe<'a>,
}

/// An `RRP_UNICODE_STRING` with its NUL, as dcerpc encodes it.
fn ustr(e: &mut NdrEncoder, s: &str) {
    let mut units: Vec<u16> = s.encode_utf16().collect();
    units.push(0);
    let n = units.len() as u32;
    let bytes = (n * 2) as u16;
    e.u16(bytes);
    e.u16(bytes);
    e.referent();
    e.u32(n);
    e.u32(0);
    e.u32(n);
    for u in units {
        e.u16(u);
    }
    e.align(4);
}

/// The handle and Win32 result of an open.
fn opened(resp: &[u8], what: &str) -> Result<Hkey, String> {
    let mut d = NdrDecoder::new(resp);
    let attrs = d.u32().map_err(|e| format!("{what}: {e}"))?;
    let uuid = d.uuid().map_err(|e| format!("{what}: {e}"))?;
    let ret = d.u32().unwrap_or(u32::MAX);
    let mut h = [0u8; 20];
    h[..4].copy_from_slice(&attrs.to_le_bytes());
    h[4..].copy_from_slice(&uuid);
    if ret != 0 || h == [0u8; 20] {
        return Err(format!("{what} failed (rc={ret})"));
    }
    Ok(Hkey(h))
}

impl<'a> Registry<'a> {
    /// Opens `\winreg` on `smb` (IPC$ connected) and binds it.
    pub(crate) async fn open(smb: &'a mut SmbClient) -> Result<Self, String> {
        let fid = smb
            .open_pipe("winreg")
            .await
            .map_err(|e| format!("open \\winreg: {e}"))?;
        let mut pipe = SmbPipe::new(smb, fid);
        pipe.bind(winreg_syntax())
            .await
            .map_err(|e| format!("bind winreg: {e}"))?;
        Ok(Self { pipe })
    }

    async fn call(&mut self, op: u16, stub: Vec<u8>) -> Result<Vec<u8>, String> {
        self.pipe.call(op, &stub).await.map_err(|e| e.to_string())
    }

    async fn root(&mut self, op: u16, what: &str) -> Result<Hkey, String> {
        let mut e = NdrEncoder::new();
        e.null_ptr();
        e.u32(KEY_READ);
        let resp = self.call(op, e.into_bytes()).await?;
        opened(&resp, what)
    }

    pub(crate) async fn hklm(&mut self) -> Result<Hkey, String> {
        self.root(opnum::OPEN_LOCAL_MACHINE, "OpenLocalMachine")
            .await
    }

    pub(crate) async fn hku(&mut self) -> Result<Hkey, String> {
        self.root(opnum::OPEN_USERS, "OpenUsers").await
    }

    pub(crate) async fn open_key(&mut self, parent: &Hkey, subkey: &str) -> Result<Hkey, String> {
        self.open_key_with(parent, subkey, KEY_READ).await
    }

    /// [`Self::open_key`] asking only for `access` (a REGSAM).
    pub(crate) async fn open_key_with(
        &mut self,
        parent: &Hkey,
        subkey: &str,
        access: u32,
    ) -> Result<Hkey, String> {
        let mut e = NdrEncoder::new();
        e.bytes(&parent.0);
        ustr(&mut e, subkey);
        e.u32(0);
        e.u32(access);
        let resp = self.call(opnum::BASE_REG_OPEN_KEY, e.into_bytes()).await?;
        opened(&resp, &format!("BaseRegOpenKey('{subkey}')"))
    }

    pub(crate) async fn query(&mut self, key: &Hkey, value: &str) -> Result<RegValue, String> {
        let mut e = NdrEncoder::new();
        e.bytes(&key.0);
        ustr(&mut e, value);
        e.referent();
        e.u32(0);
        e.referent();
        e.u32(QUERY_BUF);
        e.u32(0);
        e.u32(0);
        e.referent();
        e.u32(QUERY_BUF);
        e.referent();
        e.u32(0);
        let resp = self
            .call(opnum::BASE_REG_QUERY_VALUE, e.into_bytes())
            .await?;
        decode_query_value(&resp).map_err(|e| e.to_string())
    }

    pub(crate) async fn enum_key(
        &mut self,
        key: &Hkey,
        index: u32,
    ) -> Result<Option<String>, String> {
        const CAP_WCHARS: u32 = 512;
        const SPACES: u32 = 64;
        let mut e = NdrEncoder::new();
        e.bytes(&key.0);
        e.u32(index);
        e.u16(0);
        e.u16((CAP_WCHARS * 2) as u16);
        e.referent();
        e.u32(CAP_WCHARS);
        e.u32(0);
        e.u32(0);
        e.referent();
        e.u16((SPACES * 2) as u16);
        e.u16((SPACES * 2 + 2) as u16);
        e.referent();
        e.u32(SPACES + 1);
        e.u32(0);
        e.u32(SPACES);
        for _ in 0..SPACES {
            e.u16(0x20);
        }
        e.null_ptr();
        let resp = self.call(opnum::BASE_REG_ENUM_KEY, e.into_bytes()).await?;
        decode_enum_key(&resp).map_err(|e| e.to_string())
    }

    pub(crate) async fn close(&mut self, key: &Hkey) {
        let mut e = NdrEncoder::new();
        e.bytes(&key.0);
        let _ = self.call(opnum::BASE_REG_CLOSE_KEY, e.into_bytes()).await;
    }

    /// `HKLM\<subkey>`'s `value`.
    pub(crate) async fn read_value(
        &mut self,
        subkey: &str,
        value: &str,
    ) -> Result<RegValue, String> {
        let hklm = self.hklm().await?;
        let key = match self.open_key(&hklm, subkey).await {
            Ok(k) => k,
            Err(e) => {
                self.close(&hklm).await;
                return Err(e);
            }
        };
        let v = self.query(&key, value).await;
        self.close(&key).await;
        self.close(&hklm).await;
        v
    }

    /// The profile keys under HKEY_USERS: the SIDs of the accounts with a
    /// logon on the computer (`_Classes` keys and services left out).
    pub(crate) async fn logged_on_sids(&mut self) -> Result<Vec<String>, String> {
        let hku = self.hku().await?;
        let mut out = Vec::new();
        for i in 0..MAX_SUBKEYS {
            match self.enum_key(&hku, i).await {
                Ok(None) => break,
                Ok(Some(name)) => {
                    if is_profile(&name) {
                        out.push(name);
                    }
                }
                Err(e) => {
                    self.close(&hku).await;
                    return Err(e);
                }
            }
        }
        self.close(&hku).await;
        Ok(out)
    }
}

/// A user's profile key under HKEY_USERS (a domain or local account's SID,
/// not its `_Classes` key or a service's).
pub(crate) fn is_profile(key: &str) -> bool {
    key.starts_with("S-1-5-21-") && !key.to_ascii_lowercase().ends_with("_classes")
}

/// The logged-on SIDs of `host`, read over Kerberos SMB.
pub(crate) async fn registry_sessions(
    host: &str,
    ccache: &str,
    kdc: &str,
    domain: &str,
    user: &str,
) -> Result<Vec<String>, String> {
    let mut smb = connect(host, ccache, kdc, domain, user)
        .await
        .map_err(|e| format!("{host}: {e}"))?;
    let mut reg = Registry::open(&mut smb)
        .await
        .map_err(|e| format!("{host} WINREG: {e}"))?;
    reg.logged_on_sids()
        .await
        .map_err(|e| format!("{host} WINREG: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_keys() {
        assert!(is_profile("S-1-5-21-1-2-3-1104"));
        assert!(!is_profile("S-1-5-21-1-2-3-1104_Classes"));
        assert!(!is_profile("S-1-5-18"));
        assert!(!is_profile(".DEFAULT"));
    }

    /// The open request is the null server name and KEY_READ; a reply's
    /// handle comes back, a failure says its code.
    #[test]
    fn opens_decode() {
        let mut ok = vec![0u8; 4];
        ok.extend_from_slice(&[7u8; 16]);
        ok.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(opened(&ok, "x").unwrap().0[4..], [7u8; 16]);
        let mut denied = vec![0u8; 20];
        denied.extend_from_slice(&5u32.to_le_bytes());
        assert_eq!(
            opened(&denied, "OpenUsers").unwrap_err(),
            "OpenUsers failed (rc=5)"
        );
    }
}
