//! Cryptographic primitives only — no HTTP, no PEM parsing, no protocol
//! knowledge. `src/checkout/` owns the PEM-envelope format and orchestrates
//! calls into this module.
//!
//! This separation (per `docs/plans/tamga-rust.plan.md` §2) is what lets
//! `tamga-c` re-export these primitives independently if a future C consumer
//! wants raw verify functions without the full HTTP client.
//!
//! Module layout:
//!
//! - [`ed25519`] — Ed25519 verify (license checkout signature + one of 4
//!   machine checkout schemes).
//! - [`rsa`] — RSA-PKCS1v1.5 / RSA-PSS verify via `aws-lc-rs` (**not** the
//!   banned `rsa` crate — RUSTSEC-2023-0071, Marvin timing attack).
//! - [`ecdsa`] — ECDSA P-256/SHA-256 verify.
//! - [`aes_gcm`] — AES-256-GCM decrypt, shared by both checkout file formats.
//! - [`hkdf`] — HKDF-SHA256 key derivation (machine file encryption — a
//!   proper KDF).
//! - [`naive_key`] — ⚠️ non-KDF zero-pad/truncate key derivation (license
//!   file encryption). Deliberately not a hash or KDF — see that module's
//!   doc comment before "fixing" it.
//!
//! **Security review gate**: every file in this module is in scope for the
//! mandatory `security-reviewer` passes on plan Sections E, F, and H. Do not
//! implement real logic here without that review before merge.

pub mod aes_gcm;
pub mod ecdsa;
pub mod ed25519;
pub mod hkdf;
pub mod naive_key;
pub mod rsa;
