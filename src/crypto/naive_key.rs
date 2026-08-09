//! ⚠️ Non-KDF key derivation for **license file** (`.lic`) encryption.
//!
//! The AES key is `license.key`'s raw UTF-8 bytes, **zero-padded or
//! truncated to exactly 32 bytes** — a literal byte-copy/pad/truncate
//! transform.
//!
//! This function intentionally does **not** use HKDF/PBKDF2/scrypt — it
//! replicates the server's naive transform bit-for-bit. Do not "fix" it to
//! use a real KDF, or decryption will silently fail against real server
//! output. Contrast with `src/crypto/hkdf.rs`, which machine file encryption
//! uses instead and which *is* a proper KDF.
//!
//! Intended contents (see `docs/plans/tamga-rust.plan.md` §E):
//! - `derive_license_file_key(license_key: &str) -> [u8; 32]`.
//! - Test coverage: zero-pad behavior for keys shorter than 32 bytes,
//!   truncate behavior for keys longer than 32 bytes.
