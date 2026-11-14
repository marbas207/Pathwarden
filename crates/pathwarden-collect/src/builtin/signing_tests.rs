//! The patched SMB client (vendor/smb2-client) against a fake server:
//! with signing required it asks for signing, and after sign-in refuses a
//! reply that is unsigned, signed with another key, or changed after
//! signing; a correctly signed reply goes through. Without it, the
//! published behaviour: replies aren't checked.

use smb2_client::header::{self, cmd};
use smb2_client::{SmbClient, SmbError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The session key the fake Kerberos sign-in agrees on.
const KEY: [u8; 16] = [0x5a; 16];

/// How the fake server answers TREE_CONNECT.
#[derive(Clone, Copy, Debug)]
enum Reply {
    Signed,
    Unsigned,
    OtherKey,
    Tampered,
    /// A validly signed reply to an earlier request (another MessageId
    /// and command), replayed.
    Replayed,
    /// Validly signed, the right MessageId, but another session.
    OtherSession,
}

async fn read_msg(s: &mut TcpStream) -> Vec<u8> {
    let mut prefix = [0u8; 4];
    s.read_exact(&mut prefix).await.unwrap();
    let len = ((prefix[1] as usize) << 16) | ((prefix[2] as usize) << 8) | prefix[3] as usize;
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await.unwrap();
    buf
}

async fn send_msg(s: &mut TcpStream, m: &[u8]) {
    let len = m.len() as u32;
    s.write_all(&[0, (len >> 16) as u8, (len >> 8) as u8, len as u8])
        .await
        .unwrap();
    s.write_all(m).await.unwrap();
}

/// A response to `req` (same command and message id), with `body`.
fn response(req: &[u8], session_id: u64, tree_id: u32, body: &[u8]) -> Vec<u8> {
    let p = header::parse(req).unwrap();
    let message_id = u64::from_le_bytes(req[24..32].try_into().unwrap());
    let mut m = header::build(p.command, message_id, session_id, tree_id, false);
    // SMB2_FLAGS_SERVER_TO_REDIR
    m[16] |= 0x01;
    m.extend_from_slice(body);
    m
}

/// Serves one client: NEGOTIATE (2.1), a Kerberos SESSION_SETUP, then a
/// TREE_CONNECT answered as `reply` says. Returns the NEGOTIATE and
/// SESSION_SETUP requests' SecurityMode.
async fn serve(listener: TcpListener, reply: Reply) -> (u16, u8) {
    let (mut s, _) = listener.accept().await.unwrap();
    let negotiate = read_msg(&mut s).await;
    let neg_mode = u16::from_le_bytes([negotiate[68], negotiate[69]]);
    let mut body = vec![0u8; 64];
    body[0..2].copy_from_slice(&65u16.to_le_bytes());
    body[2..4].copy_from_slice(&1u16.to_le_bytes()); // signing enabled
    body[4..6].copy_from_slice(&0x0210u16.to_le_bytes());
    send_msg(&mut s, &response(&negotiate, 0, 0, &body)).await;

    let setup = read_msg(&mut s).await;
    let setup_mode = setup[67];
    let body = [9u8, 0, 0, 0, 72, 0, 0, 0];
    send_msg(&mut s, &response(&setup, 0x77, 0, &body)).await;

    let tree = read_msg(&mut s).await;
    assert!(header::verify(&tree, &KEY, false), "the request is signed");
    let tree_body = [16, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut m = match reply {
        Reply::Replayed => response(&setup, 0x77, 5, &tree_body),
        Reply::OtherSession => response(&tree, 0x78, 5, &tree_body),
        _ => response(&tree, 0x77, 5, &tree_body),
    };
    if !matches!(reply, Reply::Unsigned) {
        // The signature covers the SIGNED flag: set it first.
        m[16] |= header::FLAGS_SIGNED as u8;
    }
    match reply {
        Reply::Signed | Reply::Replayed | Reply::OtherSession => header::sign(&mut m, &KEY),
        Reply::Unsigned => {}
        Reply::OtherKey => header::sign(&mut m, &[1u8; 16]),
        Reply::Tampered => {
            header::sign(&mut m, &KEY);
            // ShareType, after signing.
            m[66] ^= 0x01;
        }
    }
    send_msg(&mut s, &m).await;
    (neg_mode, setup_mode)
}

/// Signs in with the fake Kerberos material and tree-connects.
async fn client(addr: String, require: bool) -> Result<(), SmbError> {
    let mut c = SmbClient::connect(&addr).await?;
    c.set_require_signing(require);
    c.login_kerberos(b"\x60\x00", &KEY).await?;
    c.tree_connect(r"\\fake\IPC$").await
}

fn run(reply: Reply, require: bool) -> (Result<(), SmbError>, (u16, u8)) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(serve(listener, reply));
        let r = client(addr, require).await;
        (r, server.await.unwrap())
    })
}

#[test]
fn a_signed_reply_is_accepted_and_signing_is_asked_for() {
    let (r, (neg, setup)) = run(Reply::Signed, true);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(neg & 0x0002, 0x0002, "NEGOTIATE asks for SIGNING_REQUIRED");
    assert_eq!(
        setup & 0x02,
        0x02,
        "SESSION_SETUP asks for SIGNING_REQUIRED"
    );
}

#[test]
fn unsigned_wrongly_signed_and_tampered_replies_are_refused() {
    for reply in [Reply::Unsigned, Reply::OtherKey, Reply::Tampered] {
        let (r, _) = run(reply, true);
        match r {
            Err(SmbError::BadSignature(c)) => assert_eq!(c, cmd::TREE_CONNECT, "{reply:?}"),
            other => panic!("{reply:?}: {other:?}"),
        }
        let e = run(reply, true).0.unwrap_err().to_string();
        assert_eq!(e, "SMB2 TREE_CONNECT answered without a valid signature");
        assert!(e.contains(super::hosts::UNSIGNED_REPLY));
    }
    // Validly signed, but a reply to another request (replayed) or for
    // another session: refused, in their own words.
    for reply in [Reply::Replayed, Reply::OtherSession] {
        let e = run(reply, true).0.unwrap_err();
        assert!(
            matches!(e, SmbError::NotAnAnswer(c) if c == cmd::TREE_CONNECT),
            "{reply:?}: {e:?}"
        );
        assert!(e.to_string().contains(super::hosts::OTHER_REPLY));
    }
}

#[test]
fn without_signing_required_replies_are_not_checked() {
    let (r, (neg, _)) = run(Reply::Unsigned, false);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(neg & 0x0002, 0, "only SIGNING_ENABLED, as published");
}

/// The process-wide switch the modules' clients take, and the guard that
/// turns it off again.
#[test]
fn the_switch_follows_the_guard() {
    let _serial = super::SIGNING_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    {
        let _on = super::Signing::require(true);
        assert!(smb2_client::require_signing());
    }
    assert!(!smb2_client::require_signing());
}
