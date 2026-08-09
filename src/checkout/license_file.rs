//! `.lic` file parsing and verification — the core payload format this SDK's
//! verifier must implement exactly right, since `tamga-c` (and transitively
//! `tamga-java`/`tamga-swift`) re-export this crate's implementation instead
//! of re-implementing it.
//!
//! **File format**:
//! ```text
//! -----BEGIN LICENSE FILE-----
//! <base64 of JSON: { "enc": "<base64>", "sig": "<base64 ed25519 sig over enc's UTF-8 bytes>", "alg": "<algorithm string>" }>
//! -----END LICENSE FILE-----
//! ```
//!
//! `alg` is exactly `"base64+ed25519"` (plain) or `"aes-256-gcm+ed25519"`
//! (encrypted) — **Ed25519 only** for the checkout signature, independent of
//! the license's own key `scheme`.
//!
//! **Verification flow** an implementation must follow (see
//! `docs/plans/tamga-rust.plan.md` §E):
//! 1. Strip the `-----BEGIN/END LICENSE FILE-----` PEM markers.
//! 2. Base64-decode the body → parse the inner `{ enc, sig, alg }` JSON.
//! 3. Base64-decode `sig`.
//! 4. Ed25519-verify `sig` against **`enc`'s ASCII/UTF-8 bytes — the base64
//!    STRING itself, not its decoded bytes** (see the gotcha documented in
//!    `src/crypto/ed25519.rs`) using the account's public Ed25519 key.
//! 5. Base64-decode `enc`.
//! 6. If `alg` contains `aes-256-gcm`: split `nonce(12B) ‖ ciphertext ‖
//!    tag(16B)`, AES-256-GCM-open with the key from
//!    `src/crypto/naive_key.rs` (derived from the license key string, zero-
//!    padded/truncated to 32 bytes — not a hash or KDF).
//! 7. Parse the resulting bytes as `{"data": <LicenseResource>}`.
//!
//! Also documented here (doc comments only, not enforced by code yet):
//! - `includes` on the checkout response is **always `[]`** — there is no
//!   working `include[]` param despite the field existing; do not build a
//!   "checkout with embedded relationships" feature around it.
//! - `id` is a fresh UUIDv7 per call, **not idempotent** — calling checkout
//!   twice yields two different certificates (different signature nonce for
//!   the encrypted variant).
//! - `ttl`/`expiry` are **metadata only, not embedded in the signed
//!   payload**, and are **not re-checked by the server on any later
//!   validation** — expiry enforcement for an offline file is entirely this
//!   SDK's/caller's responsibility on the client side.
//!
//! Intended public API: `verify_license_file(pem: &str, ed25519_pubkey:
//! &[u8; 32], license_key: Option<&str>) -> Result<LicenseResource,
//! CheckoutError>` orchestrating the full flow above.

/// `{ certificate, algorithm, includes, ttl, expiry, issued }` — the
/// JSON:API `license-files` checkout response. Stub — see module doc
/// comment above.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LicenseFile {
    _private: (),
}
