//! HKDF-SHA256 key derivation — used for **machine file** (`.mach`)
//! encryption. This is a proper KDF, unlike license file encryption's naive
//! transform (see `src/crypto/naive_key.rs`).
//!
//! Parameters (see `docs/plans/tamga-rust.plan.md` §F):
//! - `salt = "tamga:machine-file-key-v1"`
//! - `ikm = <license key>`
//! - `info = <machine fingerprint>`
//! - output: 32-byte AES key
//!
//! Unlike license checkout's naive key derivation (key-string only), a
//! verifier needs **both** the license key **and** the target machine's
//! fingerprint to decrypt a machine file.
//!
//! Intended contents:
//! - `derive_machine_file_key(license_key: &str, fingerprint: &str) ->
//!   [u8; 32]` built on the `hkdf` crate with `sha2::Sha256`.
//! - Test coverage: known `salt`/`ikm`/`info` test vector.
