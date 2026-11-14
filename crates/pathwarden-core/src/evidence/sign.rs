//! Ed25519 keys and signatures for evidence packs, in minisign's formats.
//!
//! - Public key: `untrusted comment: ...` then base64(`"Ed"` ‖ key ID (8
//!   bytes) ‖ public key (32 bytes)), the same as a minisign `.pub` file.
//! - Signature: minisign's legacy (`"Ed"`, not prehashed) format:
//!   `untrusted comment: ...`, base64(`"Ed"` ‖ key ID ‖ Ed25519 signature of
//!   the file), `trusted comment: ...`, base64(Ed25519 signature of the
//!   file's signature ‖ the trusted comment).
//! - Secret key: Pathwarden's own: comment lines starting with `#`, then one
//!   line of base64 holding the 32-byte Ed25519 seed. Not minisign's (which
//!   is scrypt-encrypted), so `minisign -S` can't sign with it, but anyone can
//!   verify a pack with `minisign -V` and the public key.
//!
//! The key ID is the first 8 bytes of SHA-256 of the public key, so a key
//! read from the environment has the same ID as its file. The fingerprint
//! people publish out of band is `SHA256:` + base64 (unpadded) of SHA-256
//! of the 32-byte public key, as `ssh-keygen -l` prints SSH keys.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature as EdSig, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The environment variable that may hold the signing key.
pub const KEY_ENV: &str = crate::keystore::EVIDENCE_KEY_ENV;

/// minisign's signature algorithm tag for an Ed25519 signature of the raw
/// file (legacy; `ED` signs a BLAKE2b hash).
const ALG: &[u8; 2] = b"Ed";
const COMMENT: &str = "untrusted comment: ";
const TRUSTED: &str = "trusted comment: ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    pub fn key_id(&self) -> [u8; 8] {
        let h = Sha256::digest(self.0.as_bytes());
        h[..8].try_into().expect("8 bytes")
    }

    /// `SHA256:` and the unpadded base64 of SHA-256 of the public key.
    pub fn fingerprint(&self) -> String {
        format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(Sha256::digest(self.0.as_bytes()))
        )
    }

    /// The key as minisign writes it (`RWQ...`): one line, 56 characters.
    pub fn minisign(&self) -> String {
        let mut raw = Vec::with_capacity(42);
        raw.extend_from_slice(ALG);
        raw.extend_from_slice(&self.key_id());
        raw.extend_from_slice(self.0.as_bytes());
        STANDARD.encode(raw)
    }

    /// The `.pub` file: readable by minisign (`minisign -V -p`).
    pub fn file_text(&self) -> String {
        format!(
            "{COMMENT}Pathwarden evidence public key {}\n{}\n",
            self.fingerprint(),
            self.minisign()
        )
    }

    /// From a `.pub` file's text, or the bare `RWQ...` line.
    pub fn parse(text: &str) -> Result<Self> {
        let line = key_line(text).context("no public key in the text")?;
        let raw = STANDARD
            .decode(line)
            .context("the public key is not valid base64")?;
        if raw.len() == 32 {
            bail!("that looks like a secret key, not a public key; use the .pub file");
        }
        if raw.len() != 42 || &raw[..2] != ALG {
            bail!("not an Ed25519 public key in minisign format");
        }
        let bytes: [u8; 32] = raw[10..].try_into().expect("32 bytes");
        let key = VerifyingKey::from_bytes(&bytes).context("not a valid Ed25519 public key")?;
        let pk = PublicKey(key);
        if raw[2..10] != pk.key_id() {
            // A key made by minisign itself (random ID): Pathwarden can't
            // have signed with it.
            bail!("not a Pathwarden evidence key (its key ID is not derived from the key)");
        }
        Ok(pk)
    }
}

/// The first line that is neither blank nor a comment.
fn key_line(text: &str) -> Option<&str> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(COMMENT))
}

pub struct SecretKey(SigningKey);

impl SecretKey {
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut())
            .map_err(|e| anyhow::anyhow!("no secure random numbers: {e}"))?;
        Ok(SecretKey(SigningKey::from_bytes(&seed)))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// The secret key file. Keep it private.
    pub fn file_text(&self) -> Zeroizing<String> {
        let seed = Zeroizing::new(self.0.to_bytes());
        Zeroizing::new(format!(
            "# Pathwarden evidence signing key (secret: keep it private).\n\
             # Public key fingerprint: {}\n\
             {}\n",
            self.public().fingerprint(),
            Zeroizing::new(STANDARD.encode(&seed[..])).as_str()
        ))
    }

    /// From the key file's text, or the bare base64 line (as
    /// [`KEY_ENV`] may hold it).
    pub fn parse(text: &str) -> Result<Self> {
        let line = key_line(text).context("no key in the text")?;
        let raw = Zeroizing::new(
            STANDARD
                .decode(line)
                .context("the signing key is not valid base64")?,
        );
        if raw.len() == 42 {
            bail!("that is a public key; signing needs the secret key (evidence.key)");
        }
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            raw.as_slice()
                .try_into()
                .context("not a Pathwarden evidence signing key (expected 32 bytes)")?,
        );
        Ok(SecretKey(SigningKey::from_bytes(&seed)))
    }

    /// A minisign signature file for `message`.
    pub fn sign(&self, message: &[u8], trusted_comment: &str) -> String {
        let trusted_comment = one_line(trusted_comment);
        let sig = self.0.sign(message).to_bytes();
        let mut global = sig.to_vec();
        global.extend_from_slice(trusted_comment.as_bytes());
        let global = self.0.sign(&global).to_bytes();
        Signature {
            key_id: self.public().key_id(),
            sig,
            trusted_comment,
            global,
        }
        .file_text(&self.public())
    }
}

fn one_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

/// A parsed minisign signature file.
#[derive(Debug)]
pub struct Signature {
    key_id: [u8; 8],
    sig: [u8; 64],
    pub trusted_comment: String,
    global: [u8; 64],
}

impl Signature {
    /// The signature file exactly as Pathwarden writes it for `key`.
    /// minisign doesn't sign the first ("untrusted") comment line, so
    /// [`Signature::verify`] also requires the file to be byte for byte this:
    /// nothing in a pack can change unnoticed.
    pub fn file_text(&self, key: &PublicKey) -> String {
        let mut line = Vec::with_capacity(74);
        line.extend_from_slice(ALG);
        line.extend_from_slice(&self.key_id);
        line.extend_from_slice(&self.sig);
        format!(
            "{COMMENT}signature from Pathwarden evidence key {}\n{}\n{TRUSTED}{}\n{}\n",
            key.fingerprint(),
            STANDARD.encode(line),
            self.trusted_comment,
            STANDARD.encode(self.global)
        )
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
        let first = lines.next().unwrap_or_default();
        if !first.starts_with(COMMENT) {
            bail!("not a minisign signature (no untrusted comment line)");
        }
        let raw = STANDARD
            .decode(lines.next().unwrap_or_default().trim())
            .context("the signature is not valid base64")?;
        if raw.len() != 74 {
            bail!("the signature has the wrong length");
        }
        if &raw[..2] != ALG {
            bail!("unsupported signature algorithm (Pathwarden writes Ed25519 \"Ed\" signatures)");
        }
        let trusted = lines.next().unwrap_or_default();
        let Some(trusted_comment) = trusted.strip_prefix(TRUSTED) else {
            bail!("the signature has no trusted comment");
        };
        let global = STANDARD
            .decode(lines.next().unwrap_or_default().trim())
            .context("the signature's comment signature is not valid base64")?;
        Ok(Signature {
            key_id: raw[2..10].try_into().expect("8 bytes"),
            sig: raw[10..74].try_into().expect("64 bytes"),
            trusted_comment: trusted_comment.to_string(),
            global: global
                .as_slice()
                .try_into()
                .context("the comment signature has the wrong length")?,
        })
    }

    /// Checks the signature of `message` and of the trusted comment, as
    /// `minisign -V` does. The key ID must match too.
    pub fn verify(&self, key: &PublicKey, message: &[u8]) -> Result<(), String> {
        if self.key_id != key.key_id() {
            return Err("it was signed with a different key".into());
        }
        let sig = EdSig::from_bytes(&self.sig);
        key.0
            .verify_strict(message, &sig)
            .map_err(|_| "the signature does not match the manifest".to_string())?;
        let mut global = self.sig.to_vec();
        global.extend_from_slice(self.trusted_comment.as_bytes());
        key.0
            .verify_strict(&global, &EdSig::from_bytes(&self.global))
            .map_err(|_| "the signature's trusted comment was changed".to_string())?;
        Ok(())
    }
}

/// Normalizes a fingerprint as typed: the `SHA256:` prefix is optional.
pub fn normalize_fingerprint(s: &str) -> String {
    let s = s.trim();
    let body = s
        .strip_prefix("SHA256:")
        .or_else(|| s.strip_prefix("sha256:"))
        .unwrap_or(s);
    format!("SHA256:{}", body.trim_end_matches('='))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_through_their_files() {
        let sk = SecretKey::generate().unwrap();
        let again = SecretKey::parse(&sk.file_text()).unwrap();
        assert_eq!(again.public(), sk.public());
        let pk = PublicKey::parse(&sk.public().file_text()).unwrap();
        assert_eq!(pk, sk.public());
        assert!(pk.minisign().starts_with("RW"), "{}", pk.minisign());
        assert_eq!(pk.minisign().len(), 56);
        assert!(pk.fingerprint().starts_with("SHA256:"));
        assert_eq!(pk.fingerprint().len(), 7 + 43);
        // Mixed up: each says which file it wanted.
        let e = SecretKey::parse(&pk.file_text()).err().unwrap();
        assert!(e.to_string().contains("public key"), "{e}");
        let e = PublicKey::parse(&sk.file_text()).err().unwrap();
        assert!(e.to_string().contains("secret key"), "{e}");
    }

    #[test]
    fn signatures_verify_and_detect_changes() {
        let sk = SecretKey::generate().unwrap();
        let pk = sk.public();
        let text = sk.sign(b"manifest", "pack 1\nwith a newline");
        let sig = Signature::parse(&text).unwrap();
        assert_eq!(sig.trusted_comment, "pack 1 with a newline");
        sig.verify(&pk, b"manifest").unwrap();
        assert!(sig.verify(&pk, b"manifesT").is_err());
        // Another key.
        let other = SecretKey::generate().unwrap().public();
        assert!(sig
            .verify(&other, b"manifest")
            .unwrap_err()
            .contains("different key"));
        // An edited trusted comment.
        let edited = text.replace("pack 1", "pack 2");
        let sig = Signature::parse(&edited).unwrap();
        assert!(sig
            .verify(&pk, b"manifest")
            .unwrap_err()
            .contains("trusted comment"));
    }

    #[test]
    fn fingerprints_normalize() {
        assert_eq!(normalize_fingerprint(" abc= "), "SHA256:abc");
        assert_eq!(normalize_fingerprint("SHA256:abc"), "SHA256:abc");
    }
}
