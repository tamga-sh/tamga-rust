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
//! Intended contents (see `docs/plans/tamga-rust.plan.md` §E):
//! - `decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext_and_tag: &[u8]) ->
//!   Result<Vec<u8>, CryptoError>` built on the `aes-gcm` crate.
//! - Test coverage: round-trip against a known nonce/key/plaintext test
//!   vector, plus a tampered-ciphertext (AEAD tag mismatch) rejection test.
