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
//! - [`hkdf`] — HKDF-SHA256 key derivation for both offline file types.
//!   Licence files used a zero-pad transform before format v2; the module that
//!   implemented it has been removed rather than deprecated, so no caller can
//!   opt back into the weaker derivation.

pub mod aes_gcm;
pub mod ecdsa;
pub mod ed25519;
pub mod hkdf;
pub mod rsa;
