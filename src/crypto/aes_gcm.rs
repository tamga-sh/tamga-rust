//! AES-256-GCM decryption, shared by both the license file (`.lic`) and
//! machine file (`.mach`) checkout formats.
//!
//! The two formats differ only in **how the 32-byte key is derived** —
//! license files use the non-KDF transform in `src/crypto/naive_key.rs`,
//! machine files use proper HKDF-SHA256 in `src/crypto/hkdf.rs`. This module
//! only implements the decrypt primitive itself, key-agnostic.
//!
//! Wire format for both: `nonce(12B) ‖ ciphertext ‖ tag(16B)`, random nonce
//! per checkout call.
//!
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

/// Decrypts `ciphertext_and_tag` (ciphertext with the 16-byte AEAD tag
/// appended, as produced by the server's `seal_in_place_append_tag`) with
/// AES-256-GCM. Returns [`crate::error::CryptoError::DecryptionFailed`] for
/// both a wrong key and a tampered ciphertext/tag — AEAD decryption
/// deliberately doesn't distinguish the two failure modes, since doing so
/// would leak information useful to a chosen-ciphertext attacker.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, crate::error::CryptoError> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let nonce = Nonce::from(*nonce);
    cipher
        .decrypt(&nonce, ciphertext_and_tag)
        .map_err(|_| crate::error::CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::rand_core::RngCore;
    use aes_gcm::aead::OsRng;

    fn encrypt_for_test(key: &[u8; 32], plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext_and_tag = cipher.encrypt(&nonce, plaintext).unwrap();
        (nonce_bytes, ciphertext_and_tag)
    }

    #[test]
    fn round_trips_a_known_plaintext() {
        let key = [0x42u8; 32];
        let plaintext = b"license payload json";
        let (nonce, ciphertext_and_tag) = encrypt_for_test(&key, plaintext);
        let decrypted = decrypt(&key, &nonce, &ciphertext_and_tag).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let key = [0x42u8; 32];
        let (nonce, mut ciphertext_and_tag) = encrypt_for_test(&key, b"payload");
        let last = ciphertext_and_tag.len() - 1;
        ciphertext_and_tag[last] ^= 0xff; // flip a byte inside the AEAD tag
        assert!(decrypt(&key, &nonce, &ciphertext_and_tag).is_err());
    }

    #[test]
    fn rejects_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let (nonce, ciphertext_and_tag) = encrypt_for_test(&key, b"payload");
        assert!(decrypt(&wrong_key, &nonce, &ciphertext_and_tag).is_err());
    }
}
