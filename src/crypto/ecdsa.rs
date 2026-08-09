//! ECDSA P-256/SHA-256 signature verification.
//!
//! Used for the `ECDSA_P256_SIGN` machine checkout (`.mach`) signature
//! scheme (see `docs/plans/tamga-rust.plan.md` §F). Built on the `p256`
//! crate (or `aws-lc-rs`, per Cargo.toml's dependency comment — pick one
//! consistently when implementing; do not depend on both for the same
//! primitive).
