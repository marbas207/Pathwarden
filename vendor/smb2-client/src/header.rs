//! SMB2 sync header (MS-SMB2 §2.2.1.2) — fixed 64 bytes, little-endian.

use crate::{Result, SmbError};

pub mod cmd {
    pub const NEGOTIATE: u16 = 0x0000;
    pub const SESSION_SETUP: u16 = 0x0001;
    pub const TREE_CONNECT: u16 = 0x0003;
    pub const CREATE: u16 = 0x0005;
    pub const CLOSE: u16 = 0x0006;
    pub const READ: u16 = 0x0008;
    pub const WRITE: u16 = 0x0009;
    pub const IOCTL: u16 = 0x000B;
    pub const QUERY_DIRECTORY: u16 = 0x000E;
}

pub const FLAGS_SIGNED: u32 = 0x0000_0008;
const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// Build a 64-byte sync header with the signature field zeroed.
#[allow(clippy::too_many_arguments)]
pub fn build(
    command: u16,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    signed: bool,
) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[0..4].copy_from_slice(&PROTOCOL_ID);
    h[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
    h[6..8].copy_from_slice(&1u16.to_le_bytes()); // CreditCharge
                                                  // 8..12 Status/ChannelSequence = 0
    h[12..14].copy_from_slice(&command.to_le_bytes());
    h[14..16].copy_from_slice(&1u16.to_le_bytes()); // CreditRequest
    let flags = if signed { FLAGS_SIGNED } else { 0 };
    h[16..20].copy_from_slice(&flags.to_le_bytes());
    // 20..24 NextCommand = 0
    h[24..32].copy_from_slice(&message_id.to_le_bytes());
    // 32..36 Reserved (ProcessId)
    h[36..40].copy_from_slice(&tree_id.to_le_bytes());
    h[40..48].copy_from_slice(&session_id.to_le_bytes());
    // 48..64 Signature = 0
    h
}

/// Parsed fields we consume from a response header.
#[derive(Clone, Copy, Debug)]
pub struct Parsed {
    pub command: u16,
    pub status: u32,
    pub session_id: u64,
    pub tree_id: u32,
}

pub fn parse(buf: &[u8]) -> Result<Parsed> {
    if buf.len() < 64 {
        return Err(SmbError::Truncated);
    }
    if buf[0..4] != PROTOCOL_ID {
        return Err(SmbError::BadProtocol);
    }
    Ok(Parsed {
        status: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        command: u16::from_le_bytes(buf[12..14].try_into().unwrap()),
        tree_id: u32::from_le_bytes(buf[36..40].try_into().unwrap()),
        session_id: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
    })
}

/// SMB 2.x signing: HMAC-SHA256(session_key, message-with-zeroed-sig-and-SIGNED-flag),
/// truncated to 16 bytes, written back into the Signature field.
pub fn sign(message: &mut [u8], key: &[u8; 16]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    for b in &mut message[48..64] {
        *b = 0;
    }
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("hmac key");
    mac.update(message);
    let sig = mac.finalize().into_bytes();
    message[48..64].copy_from_slice(&sig[..16]);
}

/// SMB 3.0/3.0.2 signing: AES-128-CMAC over the message with the zeroed Signature field and
/// the SIGNED flag set, truncated to 16 bytes.
pub fn sign_v3(message: &mut [u8], signing_key: &[u8; 16]) {
    use aes::Aes128;
    use cmac::{Cmac, Mac};
    for b in &mut message[48..64] {
        *b = 0;
    }
    let mut mac = <Cmac<Aes128>>::new_from_slice(signing_key).expect("cmac key");
    mac.update(message);
    let sig = mac.finalize().into_bytes();
    message[48..64].copy_from_slice(&sig[..16]);
}

/// Pathwarden patch: a message's MessageId.
pub fn message_id(message: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(message.get(24..32)?.try_into().ok()?))
}

/// Pathwarden patch: whether `message` is the server's reply to the
/// request sent with `message_id` and `command`: those two match, the
/// SERVER_TO_REDIR flag is set, and once a session is known (`session_id`
/// not 0) the reply names it.
pub fn answers(message: &[u8], message_id: u64, command: u16, session_id: u64) -> bool {
    let Ok(p) = parse(message) else {
        return false;
    };
    let flags = u32::from_le_bytes(message[16..20].try_into().unwrap());
    self::message_id(message) == Some(message_id)
        && p.command == command
        && flags & 0x0000_0001 != 0
        && (session_id == 0 || p.session_id == session_id)
}

/// Pathwarden patch: whether a reply carries a valid signature under
/// `key` (AES-CMAC with `v3`, else HMAC-SHA256): the SIGNED flag is set, it
/// is a single message (this client never sends compound requests, so a
/// compound reply is refused), and the Signature field is what signing it
/// again gives. Compared in constant time.
pub fn verify(message: &[u8], key: &[u8; 16], v3: bool) -> bool {
    if message.len() < 64 {
        return false;
    }
    let flags = u32::from_le_bytes(message[16..20].try_into().unwrap());
    let next_command = u32::from_le_bytes(message[20..24].try_into().unwrap());
    if flags & FLAGS_SIGNED == 0 || next_command != 0 {
        return false;
    }
    let mut again = message.to_vec();
    if v3 {
        sign_v3(&mut again, key);
    } else {
        sign(&mut again, key);
    }
    again[48..64]
        .iter()
        .zip(&message[48..64])
        .fold(0u8, |d, (a, b)| d | (a ^ b))
        == 0
}

/// SMB 3.0.x signing-key derivation (MS-SMB2 §3.1.4.2): SP800-108 counter-mode KDF with
/// HMAC-SHA256 over the session key, label "SMB2AESCMAC" and context "SmbSign".
pub fn kdf_signing_key(session_key: &[u8; 16]) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut input = Vec::new();
    input.extend_from_slice(&1u32.to_be_bytes()); // counter i
    input.extend_from_slice(b"SMB2AESCMAC\0"); // label
    input.extend_from_slice(b"SmbSign\0"); // context
    input.extend_from_slice(&128u32.to_be_bytes()); // L (bits)
    let mut mac = <Hmac<Sha256>>::new_from_slice(session_key).expect("hmac key");
    mac.update(&input);
    let out = mac.finalize().into_bytes();
    let mut k = [0u8; 16];
    k.copy_from_slice(&out[..16]);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_64_bytes_and_parses() {
        let h = build(cmd::NEGOTIATE, 3, 0xAABB, 0x11, true);
        assert_eq!(h.len(), 64);
        let p = parse(&h).unwrap();
        assert_eq!(p.command, cmd::NEGOTIATE);
        assert_eq!(p.session_id, 0xAABB);
        assert_eq!(p.tree_id, 0x11);
        assert_eq!(
            u32::from_le_bytes(h[16..20].try_into().unwrap()),
            FLAGS_SIGNED
        );
    }

    /// Pathwarden patch.
    #[test]
    fn verify_accepts_signed_and_refuses_unsigned_or_tampered() {
        let key = [7u8; 16];
        for v3 in [false, true] {
            let mut m = build(cmd::TREE_CONNECT, 4, 9, 0, true);
            m.extend_from_slice(&[16, 0, 1, 0, 0, 0, 0, 0]);
            if v3 {
                sign_v3(&mut m, &key);
            } else {
                sign(&mut m, &key);
            }
            assert!(verify(&m, &key, v3));
            assert!(!verify(&m, &[8u8; 16], v3), "another key");
            let mut tampered = m.clone();
            tampered[70] ^= 1;
            assert!(!verify(&tampered, &key, v3), "a changed body");
            let mut unsigned = m.clone();
            unsigned[16] &= !(FLAGS_SIGNED as u8);
            assert!(!verify(&unsigned, &key, v3), "no SIGNED flag");
            let mut blank = m.clone();
            blank[48..64].fill(0);
            assert!(!verify(&blank, &key, v3), "no signature");
        }
        assert!(!verify(&[0u8; 10], &key, false), "too short");
    }

    /// Pathwarden patch: a KRB-ERROR's code from a SPNEGO token.
    #[test]
    fn krb_error_codes_are_read() {
        use crate::client::krb_error_code;
        // negTokenResp [1] { negState [0] reject, responseToken [2] OCTET
        // STRING { krb5 OID, KRB-ERROR { pvno 5, msg-type 30, ..., [6] 37 } } }
        let krb_error = [
            0x7e, 0x0e, 0x30, 0x0c, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x1e,
            0xa6, 0x03, 0x02, 0x01, 0x25,
        ];
        let mut token = vec![0xa1, 0x20, 0x30, 0x1e, 0xa0, 0x03, 0x0a, 0x01, 0x02, 0xa2, 0x17, 0x04, 0x15];
        token.extend_from_slice(&krb_error);
        assert_eq!(krb_error_code(&token), Some(37));
        assert_eq!(krb_error_code(&[0xa1, 0x03, 0x0a, 0x01, 0x00]), None);
        assert_eq!(
            crate::SmbError::KerberosRefused(41).to_string(),
            "SMB2 SESSION_SETUP refused the Kerberos ticket: KRB_AP_ERR_MODIFIED (41)"
        );
    }

    /// Pathwarden patch.
    #[test]
    fn answers_matches_the_request() {
        let mut m = build(cmd::READ, 7, 0x55, 1, true);
        assert!(!answers(&m, 7, cmd::READ, 0x55), "a request, not a reply");
        m[16] |= 0x01;
        assert!(answers(&m, 7, cmd::READ, 0x55));
        assert!(answers(&m, 7, cmd::READ, 0), "no session yet");
        assert!(!answers(&m, 6, cmd::READ, 0x55), "another message");
        assert!(!answers(&m, 7, cmd::CREATE, 0x55), "another command");
        assert!(!answers(&m, 7, cmd::READ, 0x56), "another session");
    }
}
