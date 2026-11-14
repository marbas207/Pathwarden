//! Kerberos only as the current Windows account.
//!
//! As the Windows account, computers are read through Windows' own SMB
//! client (UNC paths, NetAPI, Remote Registry), which can't be told "no
//! NTLM" for one connection: it uses Kerberos when the domain has a
//! Kerberos name (SPN) for the computer, and NTLM when it doesn't. So
//! before a computer is contacted, SSPI's Kerberos package (not Negotiate,
//! which would fall back to NTLM) is asked for its `cifs/<name>` ticket. A
//! name the domain doesn't know, as one someone added to DNS, gets
//! `SEC_E_TARGET_UNKNOWN`: the computer is skipped and Windows never signs
//! in to it.
//!
//! What this doesn't close: a look-alike of a *real* computer's name that
//! answers but turns Kerberos down could still get NTLM from Windows. The
//! Windows policies "Network security: Restrict NTLM: Outgoing NTLM traffic
//! to remote servers", or SMB NTLM blocking (Windows 11 24H2, Server 2025),
//! close that (docs/dev/threat-model.md).

// SSPI calls (secur32), Windows API only.
#![allow(unsafe_code)]

use windows_sys::Win32::Foundation::{SEC_E_OK, SEC_E_TARGET_UNKNOWN, SEC_I_CONTINUE_NEEDED};
use windows_sys::Win32::Security::Authentication::Identity::{
    AcquireCredentialsHandleW, DeleteSecurityContext, FreeContextBuffer, FreeCredentialsHandle,
    InitializeSecurityContextW, SecBuffer, SecBufferDesc, ISC_REQ_ALLOCATE_MEMORY, SECBUFFER_TOKEN,
    SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP,
};
use windows_sys::Win32::Security::Credentials::SecHandle;

use super::krb::NoTicket;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Whether Windows gets a Kerberos ticket for `cifs/<host>` as the current
/// account. The ticket goes into the logon session's cache, where Windows'
/// SMB client finds it.
pub(crate) fn cifs_ticket(host: &str) -> Result<(), NoTicket> {
    let package = wide("Kerberos");
    let target = wide(&format!("cifs/{host}"));
    let mut cred = SecHandle::default();
    let mut expiry = 0i64;
    // SAFETY: valid NUL-terminated strings and out-pointers to locals; the
    // handle is freed below.
    let status = unsafe {
        AcquireCredentialsHandleW(
            std::ptr::null(),
            package.as_ptr(),
            SECPKG_CRED_OUTBOUND,
            std::ptr::null(),
            std::ptr::null(),
            None,
            std::ptr::null(),
            &mut cred,
            &mut expiry,
        )
    };
    if status != SEC_E_OK {
        return Err(NoTicket::Refused(format!(
            "Kerberos: no credentials for this account (0x{:08x})",
            status as u32
        )));
    }
    let mut out_buf = SecBuffer {
        cbBuffer: 0,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: std::ptr::null_mut(),
    };
    let mut out = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut out_buf,
    };
    let mut ctx = SecHandle::default();
    let mut attrs = 0u32;
    // SAFETY: as above; the output token is allocated by SSPI and freed
    // below, as is the context.
    let status = unsafe {
        InitializeSecurityContextW(
            &cred,
            std::ptr::null(),
            target.as_ptr(),
            ISC_REQ_ALLOCATE_MEMORY,
            0,
            SECURITY_NATIVE_DREP,
            std::ptr::null(),
            0,
            &mut ctx,
            &mut out,
            &mut attrs,
            &mut expiry,
        )
    };
    // SAFETY: freeing what SSPI allocated, once.
    unsafe {
        if !out_buf.pvBuffer.is_null() {
            FreeContextBuffer(out_buf.pvBuffer);
        }
        if status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED {
            DeleteSecurityContext(&ctx);
        }
        FreeCredentialsHandle(&cred);
    }
    match status {
        SEC_E_OK | SEC_I_CONTINUE_NEEDED => Ok(()),
        SEC_E_TARGET_UNKNOWN => Err(NoTicket::NoName(format!("no SPN cifs/{host}"))),
        other => Err(NoTicket::Refused(format!(
            "Kerberos refused a ticket for cifs/{host} (0x{:08x})",
            other as u32
        ))),
    }
}
