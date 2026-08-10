//! Ed25519 signature verification.
//!
//! Used for: the license checkout (`.lic`) signature (always Ed25519,
//! independent of the license's own `scheme`), and one of the four machine
//! checkout (`.mach`) signature schemes.
//!
//! ⚠️ **Critical signing gotcha** (see `docs/plans/tamga-rust.plan.md` §E):
//! the `.lic`/`.mach` signature is computed over the **ASCII/UTF-8 bytes of
//! the `enc` base64 STRING itself — NOT the decoded bytes of `enc`**. A
//! verifier that decodes `enc` first and then verifies over the decoded
//! bytes will get a false negative against every real server-produced file.
//! This must be caught by a dedicated negative test once implemented (see
//! plan §E: "negative test proving decoded-bytes verification fails against
//! a known-good fixture").
//!
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verifies an Ed25519 `signature` over `message` using the account's raw
/// 32-byte public key. Uses `ed25519-dalek`'s own constant-time verify
/// primitive — never a hand-rolled byte comparison, which would risk a
/// timing side channel (see plan §E's "Constant-time comparison audit"
/// item).
///
/// Callers verifying a `.lic`/`.mach` checkout file must pass `message` as
/// the **base64 string bytes of `enc`, not `enc`'s decoded bytes** — see the
/// module doc comment's gotcha.
pub fn verify(
    pubkey: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), crate::error::CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(pubkey).map_err(|_| crate::error::CryptoError::InvalidKey)?;
    let sig =
        Signature::try_from(signature).map_err(|_| crate::error::CryptoError::InvalidSignature)?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| crate::error::CryptoError::VerificationFailed)
}

/// Loads a raw 32-byte Ed25519 public key from a base64-encoded string
/// (account config format).
pub fn public_key_from_base64(b64: &str) -> Result<[u8; 32], crate::error::CryptoError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| crate::error::CryptoError::InvalidKey)?;
    bytes
        .try_into()
        .map_err(|_| crate::error::CryptoError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn gen_keypair() -> ([u8; 32], SigningKey) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        (signing_key.verifying_key().to_bytes(), signing_key)
    }

    #[test]
    fn accepts_a_valid_signature() {
        let (pubkey, signing_key) = gen_keypair();
        let message = b"the base64 enc string bytes";
        let sig = signing_key.sign(message);
        assert!(verify(&pubkey, message, &sig.to_bytes()).is_ok());
    }

    #[test]
    fn rejects_tampered_message() {
        let (pubkey, signing_key) = gen_keypair();
        let sig = signing_key.sign(b"original");
        assert!(verify(&pubkey, b"tampered!", &sig.to_bytes()).is_err());
    }

    #[test]
    fn rejects_signature_from_a_different_key() {
        let (pubkey_a, _) = gen_keypair();
        let (_, signing_key_b) = gen_keypair();
        let message = b"data";
        let sig = signing_key_b.sign(message);
        assert!(verify(&pubkey_a, message, &sig.to_bytes()).is_err());
    }

    #[test]
    fn rejects_malformed_signature_bytes() {
        let (pubkey, _) = gen_keypair();
        assert!(verify(&pubkey, b"data", b"too-short").is_err());
    }

    #[test]
    fn public_key_from_base64_round_trips() {
        let (pubkey, _) = gen_keypair();
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(pubkey);
        assert_eq!(public_key_from_base64(&b64).unwrap(), pubkey);
    }

    #[test]
    fn public_key_from_base64_rejects_wrong_length() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"too short");
        assert!(public_key_from_base64(&b64).is_err());
    }
}
