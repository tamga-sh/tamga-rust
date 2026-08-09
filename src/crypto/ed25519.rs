//! Ed25519 signature verification.
//!
//! Used for: the license checkout (`.lic`) signature (always Ed25519,
//! independent of the license's own `scheme`), and one of the four machine
//! checkout (`.mach`) signature schemes.
//!
//! ⚠️ **Critical signing gotcha** (see `docs/plans/tamga-rust.plan.md` §E):
//! the `.lic`/`.mach` signature is computed over the **ASCII/UTF-8 bytes of
//! the `enc` base64 STRING itself — NOT the decoded bytes of `enc`**. A
//! verifier that decodes `enc` first and then verifies over the decoded
//! bytes will get a false negative against every real server-produced file.
//! This must be caught by a dedicated negative test once implemented (see
//! plan §E: "negative test proving decoded-bytes verification fails against
//! a known-good fixture").
//!
//! Intended contents:
//! - Public key loading helpers from account config (raw 32-byte key,
//!   base64/hex input).
//! - `verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8]) ->
//!   Result<(), CryptoError>` built on `ed25519-dalek`.
//! - Constant-time comparison audit: use `ed25519-dalek`'s own verify
//!   primitive, never a hand-rolled early-return byte comparison (timing
//!   side-channel risk) — see plan §E's "Constant-time comparison audit"
//!   task.
