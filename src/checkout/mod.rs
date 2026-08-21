//! PEM-envelope parsing and verification orchestration for offline checkout
//! files. Owns the file format; delegates actual cryptography to
//! `src/crypto/`.
//!
//! Module layout:
//!
//! - [`license_file`] — `.lic` parse + verify (format v2 only). Ed25519-only
//!   signature (independent of the license's own `scheme`), HKDF-SHA256 key
//!   derivation when encrypted, and enforcement of the signed `exp` claim.
//! - [`machine_file`] — `.mach` parse + verify (format v2 only). Signature
//!   scheme taken from the license's `scheme` field
//!   (Ed25519/RSA-PKCS1/RSA-PSS/ECDSA-P256; `RSA_2048_JWT_RS256` explicitly
//!   rejected), HKDF-SHA256 key derivation when encrypted, and enforcement of
//!   the same signed `exp` claim against the same
//!   `CLOCK_SKEW_TOLERANCE_SECS`.
//!
//! Both formats share the same inner JSON shape once the PEM markers are
//! stripped: `{ enc: String, sig: String, alg: String }`, base64-encoded as
//! the PEM body, and both require the `+v2` marker on `alg`.
//!
//! They differ in how `enc` is laid out when encrypted. A `.lic` file's is a
//! single base64 blob of `nonce ‖ ciphertext ‖ tag`; a `.mach` file's is
//! `"<nonce_b64>.<cipher_b64>"`, two separately base64-encoded halves, because
//! the machine path runs through the server's `FieldEncryption` rather than
//! sealing the bytes inline. Do not "unify" the two readers.

pub mod license_file;
pub mod machine_file;
