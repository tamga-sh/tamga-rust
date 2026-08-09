//! `.mach` file parsing and verification.
//!
//! Same shape as `.lic` (see `src/checkout/license_file.rs`) with these
//! machine-specific differences (see `docs/plans/tamga-rust.plan.md` §F):
//!
//! - Wrapper: `-----BEGIN MACHINE FILE-----`/`-----END MACHINE FILE-----`,
//!   same inner `{ enc, sig, alg }` JSON structure.
//! - `ttl` is **validated server-side**: must be `> 0` and `<= 31536000`
//!   (365 days) or `422 TTL_INVALID`. The client should pre-check this range
//!   before the round-trip, in addition to handling the server error.
//! - Signing scheme is taken from the **license's** `scheme` field
//!   (Ed25519/RSA-PKCS1/RSA-PSS/ECDSA-P256 — see `src/models/policy.rs`
//!   `LicenseScheme`), not hardcoded to Ed25519 like license checkout.
//!   ⚠️ `RSA_2048_JWT_RS256` is explicitly rejected for machine files (the
//!   server returns `422 SCHEME_NOT_SUPPORTED`) — this SDK's local verifier
//!   must reject that scheme up front rather than attempt JWT parsing.
//! - Encryption key (when encrypted) is **HKDF-SHA256** derived (see
//!   `src/crypto/hkdf.rs`): `salt="tamga:machine-file-key-v1"`,
//!   `ikm=<license key>`, `info=<machine fingerprint>` → 32-byte AES key. A
//!   verifier needs both the license key and the target machine's
//!   fingerprint to decrypt.
//!
//! Intended public API: `verify_machine_file(pem: &str, scheme:
//! crate::models::policy::LicenseScheme, pubkey: &[u8], license_key:
//! Option<&str>, fingerprint: Option<&str>) -> Result<MachineResource,
//! CheckoutError>`, dispatching to the correct verifier in `src/crypto/`
//! based on `scheme`.

/// The JSON:API `machine-files` checkout response. Stub — see module doc
/// comment above.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MachineFile {
    _private: (),
}
