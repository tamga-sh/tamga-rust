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
//! Intended contents (see `docs/plans/tamga-rust.plan.md` §F, §H):
//! - RSA-PKCS1v1.5/SHA-256 verify function.
//! - RSA-PSS/SHA-256 verify function.
//! - Both built on `aws-lc-rs::signature`.
