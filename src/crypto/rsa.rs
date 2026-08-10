//! RSA-PKCS1v1.5 and RSA-PSS signature verification, built on `aws-lc-rs`.
//!
//! ⚠️ **Deliberately not the `rsa` crate** — RUSTSEC-2023-0071 (Marvin timing
//! attack) is unpatched there. `aws-lc-rs` is used instead, and the `rsa`
//! crate is banned outright via `deny.toml`'s `bans.deny`. Confirm any new
//! dependency doesn't pull `rsa` in transitively (`cargo deny check`).
//!
//! Used for:
//! - One of the four machine checkout (`.mach`) signature schemes: both
//!   `RSA_2048_PKCS1_SIGN` and `RSA_2048_PKCS1_PSS_SIGN`.
//! - Machine offline proof (`src/proof.rs`) verification, which is
//!   **always** RSA-2048 PKCS#1 v1.5 / SHA-256 regardless of the license's
//!   own `scheme`.
//!
//! ⚠️ **Explicit rejection**: `RSA_2048_JWT_RS256` is not supported for
//! machine files — the server returns `422 SCHEME_NOT_SUPPORTED` for it.
//! This module's dispatcher (invoked from `src/checkout/machine_file.rs`)
//! must reject that scheme up front rather than attempt JWT parsing.
//!
use aws_lc_rs::signature::{
    UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256,
};

/// Verifies an RSA-PKCS1v1.5/SHA-256 `signature` over `message`.
/// `pubkey_spki_der` is the raw SubjectPublicKeyInfo (SPKI) DER bytes.
pub fn verify_pkcs1(
    pubkey_spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), crate::error::CryptoError> {
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pubkey_spki_der)
        .verify(message, signature)
        .map_err(|_| crate::error::CryptoError::VerificationFailed)
}

/// Verifies an RSA-PSS/SHA-256 `signature` over `message`. `pubkey_spki_der`
/// is the raw SubjectPublicKeyInfo (SPKI) DER bytes.
pub fn verify_pss(
    pubkey_spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), crate::error::CryptoError> {
    UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, pubkey_spki_der)
        .verify(message, signature)
        .map_err(|_| crate::error::CryptoError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
    use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256, RSA_PSS_SHA256};

    fn gen_rsa_keypair() -> (Vec<u8>, RsaKeyPair) {
        let kp = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        // `.public_key()` — NOT `.as_der()`, which is the PKCS8 *private*
        // key DER. This is the actual SPKI public key `UnparsedPublicKey`
        // expects, matching `tamga-api`'s own `extract_public_key`.
        let spki = kp.public_key().as_ref().to_vec();
        (spki, kp)
    }

    #[test]
    fn pkcs1_accepts_valid_signature() {
        let (pubkey, kp) = gen_rsa_keypair();
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&RSA_PKCS1_SHA256, &rng, b"data", &mut sig).unwrap();
        assert!(verify_pkcs1(&pubkey, b"data", &sig).is_ok());
    }

    #[test]
    fn pkcs1_rejects_tampered_message() {
        let (pubkey, kp) = gen_rsa_keypair();
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&RSA_PKCS1_SHA256, &rng, b"original", &mut sig)
            .unwrap();
        assert!(verify_pkcs1(&pubkey, b"tampered", &sig).is_err());
    }

    #[test]
    fn pss_accepts_valid_signature() {
        let (pubkey, kp) = gen_rsa_keypair();
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&RSA_PSS_SHA256, &rng, b"data", &mut sig).unwrap();
        assert!(verify_pss(&pubkey, b"data", &sig).is_ok());
    }

    #[test]
    fn pss_rejects_tampered_message() {
        let (pubkey, kp) = gen_rsa_keypair();
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&RSA_PSS_SHA256, &rng, b"original", &mut sig)
            .unwrap();
        assert!(verify_pss(&pubkey, b"tampered", &sig).is_err());
    }

    #[test]
    fn pkcs1_signature_does_not_verify_as_pss() {
        // Cross-scheme confusion check: a valid PKCS1 signature must not
        // also verify under the PSS algorithm identifier.
        let (pubkey, kp) = gen_rsa_keypair();
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&RSA_PKCS1_SHA256, &rng, b"data", &mut sig).unwrap();
        assert!(verify_pss(&pubkey, b"data", &sig).is_err());
    }
}
