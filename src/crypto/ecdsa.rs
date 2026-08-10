//! ECDSA P-256/SHA-256 signature verification.
//!
//! Used for the `ECDSA_P256_SIGN` machine checkout (`.mach`) signature
//! scheme. Built on `aws_lc_rs::signature` — same crate as `crypto/rsa.rs`
//! and `crypto/ed25519.rs`'s ASN.1 verify path, so this module doesn't pull
//! in the separate `p256` dependency for a single primitive.

use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};

/// Verifies an ECDSA P-256/SHA-256 ASN.1 DER `signature` over `message`.
/// `pubkey` is the raw 65-byte uncompressed P-256 point.
pub fn verify(
    pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), crate::error::CryptoError> {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pubkey)
        .verify(message, signature)
        .map_err(|_| crate::error::CryptoError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    fn gen_keypair() -> (Vec<u8>, EcdsaKeyPair) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        let pubkey = kp.public_key().as_ref().to_vec();
        (pubkey, kp)
    }

    #[test]
    fn accepts_a_valid_signature() {
        let (pubkey, kp) = gen_keypair();
        let rng = SystemRandom::new();
        let sig = kp.sign(&rng, b"data").unwrap();
        assert!(verify(&pubkey, b"data", sig.as_ref()).is_ok());
    }

    #[test]
    fn rejects_tampered_signature() {
        let (pubkey, kp) = gen_keypair();
        let rng = SystemRandom::new();
        let mut sig = kp.sign(&rng, b"data").unwrap().as_ref().to_vec();
        let last = sig.len() - 1;
        sig[last] ^= 0xff;
        assert!(verify(&pubkey, b"data", &sig).is_err());
    }

    #[test]
    fn rejects_wrong_key() {
        let (_, kp_a) = gen_keypair();
        let (pubkey_b, _) = gen_keypair();
        let rng = SystemRandom::new();
        let sig = kp_a.sign(&rng, b"data").unwrap();
        assert!(verify(&pubkey_b, b"data", sig.as_ref()).is_err());
    }
}
