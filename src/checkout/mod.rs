//! PEM-envelope parsing and verification orchestration for offline checkout
//! files. Owns the file format; delegates actual cryptography to
//! `src/crypto/`.
//!
//! Module layout:
//!
//! - [`license_file`] — `.lic` parse + verify (format v2 only). Ed25519-only
//!   signature (independent of the license's own `scheme`), HKDF-SHA256 key
//!   derivation when encrypted, and enforcement of the signed `exp` claim.
//! - [`machine_file`] — `.mach` parse + verify. Signature scheme taken from
//!   the license's `scheme` field (Ed25519/RSA-PKCS1/RSA-PSS/ECDSA-P256;
//!   `RSA_2048_JWT_RS256` explicitly rejected), HKDF-SHA256 key derivation
//!   when encrypted.
//!
//! Both formats share the same inner JSON shape once the PEM markers are
//! stripped: `{ enc: String, sig: String, alg: String }`, base64-encoded as
//! the PEM body.

pub mod license_file;
pub mod machine_file;
