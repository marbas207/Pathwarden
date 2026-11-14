//! A minimal SMB2 client — from-scratch pure Rust, scoped to what
//! named-pipe DCE/RPC needs: negotiate (dialect 2.1.0), NTLM session setup, tree-connect to
//! IPC$, create a pipe, and FSCTL_PIPE_TRANSCEIVE to carry RPC PDUs.
//!
//! Raw NTLMSSP is placed directly in the session-setup security buffer (Windows accepts it
//! without a SPNEGO wrapper). SMB 2.x message signing (HMAC-SHA256, truncated to 16 bytes)
//! is applied once a session key is established, since DCs require signing on IPC$.

pub mod client;
pub mod header;
pub mod msg;
pub mod server;
pub mod socks;
pub mod spnego;
pub mod transport;

pub use client::{Cred, SmbClient};
pub use msg::DirEntry;

// --- Pathwarden patch: required signing -------------------------------------
// As published, the client signs every request after sign-in but never checks
// the signature on a reply, so a machine in the middle, or a look-alike server
// that accepted the sign-in without knowing the session key, could forge every
// answer. With signing required, the client asks the server to sign
// (SecurityMode SIGNING_REQUIRED in NEGOTIATE and SESSION_SETUP) and refuses
// any reply after sign-in whose signature is missing or wrong
// (`SmbError::BadSignature`). Off by default: nothing changes unless a caller
// turns it on, for one client (`SmbClient::set_require_signing`) or for every
// client created afterwards (`set_require_signing`, for callers that don't
// create the clients themselves, like RustHound-CE's modules).

static REQUIRE_SIGNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether clients created from now on require signed replies (see
/// [`SmbClient::set_require_signing`]).
pub fn set_require_signing(on: bool) {
    REQUIRE_SIGNING.store(on, std::sync::atomic::Ordering::SeqCst);
}

/// What [`set_require_signing`] last set.
pub fn require_signing() -> bool {
    REQUIRE_SIGNING.load(std::sync::atomic::Ordering::SeqCst)
}

/// The name of an SMB2 command, for messages.
pub fn command_name(command: u16) -> &'static str {
    use header::cmd;
    match command {
        cmd::NEGOTIATE => "NEGOTIATE",
        cmd::SESSION_SETUP => "SESSION_SETUP",
        cmd::TREE_CONNECT => "TREE_CONNECT",
        cmd::CREATE => "CREATE",
        cmd::CLOSE => "CLOSE",
        cmd::READ => "READ",
        cmd::WRITE => "WRITE",
        cmd::IOCTL => "IOCTL",
        cmd::QUERY_DIRECTORY => "QUERY_DIRECTORY",
        _ => "command",
    }
}
/// The name of a Kerberos error code (RFC 4120 7.5.9), for messages.
pub fn krb_error_name(code: u32) -> &'static str {
    match code {
        7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        31 => "KRB_AP_ERR_BAD_INTEGRITY",
        32 => "KRB_AP_ERR_TKT_EXPIRED",
        33 => "KRB_AP_ERR_TKT_NYV",
        34 => "KRB_AP_ERR_REPEAT",
        35 => "KRB_AP_ERR_NOT_US",
        36 => "KRB_AP_ERR_BADMATCH",
        37 => "KRB_AP_ERR_SKEW",
        40 => "KRB_AP_ERR_MSG_TYPE",
        41 => "KRB_AP_ERR_MODIFIED",
        44 => "KRB_AP_ERR_BADKEYVER",
        60 => "KRB_ERR_GENERIC",
        68 => "KDC_ERR_WRONG_REALM",
        _ => "Kerberos error",
    }
}
// --- end of patch -------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SmbError {
    #[error("truncated SMB2 message")]
    Truncated,
    #[error("bad protocol id")]
    BadProtocol,
    #[error("SMB2 status {0:#010x} for command {1:#06x}")]
    Status(u32, u16),
    #[error("unexpected security token")]
    BadToken,
    #[error("ntlm: {0}")]
    Ntlm(String),
    /// Pathwarden patch: signing is required and a reply after sign-in had no
    /// signature, or a wrong one. The command is the one answered.
    #[error("SMB2 {} answered without a valid signature", command_name(*.0))]
    BadSignature(u16),
    /// Pathwarden patch: signing is required and a reply answered another
    /// request (MessageId, Command, flags or session not this request's):
    /// replayed or misdirected.
    #[error("SMB2 {} answered with a reply to another request", command_name(*.0))]
    NotAnAnswer(u16),
    /// Pathwarden patch: the server refused the Kerberos ticket, with this
    /// KRB-ERROR code (37 is a clock skew, 41 a ticket it can't decrypt).
    #[error("SMB2 SESSION_SETUP refused the Kerberos ticket: {name} ({0})", name = krb_error_name(*.0))]
    KerberosRefused(u32),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SmbError>;

/// SMB2 status codes we branch on.
pub mod status {
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const PENDING: u32 = 0x0000_0103; // interim async response; the real one follows
    pub const MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
    pub const END_OF_FILE: u32 = 0xC000_0011;
    pub const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    /// STATUS_OBJECT_PATH_NOT_FOUND — a component of the path prefix does
    /// not exist (distinct from `OBJECT_NAME_NOT_FOUND` where the final
    /// leaf is missing). Useful for CREATE against a nested share path.
    /// Adopted from g0h4n's PR smb2-client#1 for 0.2.4.
    pub const OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
    pub const SHARING_VIOLATION: u32 = 0xC000_0043;
    /// STATUS_NO_MORE_FILES — QUERY_DIRECTORY has returned the last entry.
    pub const NO_MORE_FILES: u32 = 0x8000_0006;
}
