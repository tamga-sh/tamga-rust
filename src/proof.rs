//! Machine offline proof — generation call, byte-exact serialization, and
//! RSA-PKCS1v1.5 verification.
//!
//! `POST /machines/{id}/actions/generate-offline-proof`, body
//! `{ "meta": { "dataset": {...} } }` (default `{}`). Always signs with
//! **RSA-2048 PKCS#1 v1.5 / SHA-256** regardless of the license's own
//! `scheme`. Response: machine resource with `meta.proof =
//! "v1x0.<base64 signature>"`.
//!
//! ⚠️ **Byte-exact serialization gotcha** (see
//! `docs/plans/tamga-rust.plan.md` §H): the signature covers
//! `{"account":{"id":...},"machine":{"id":...,"fingerprint":...},
//! "dataset":<client dataset>}` serialized **exactly** as the server
//! produces it — field order matters. A verifying SDK must reproduce the
//! same serialization, not just the same field set, or the signature check
//! fails. Implement with an ordered `serde` struct (fixed field order),
//! never a `HashMap` (whose iteration/serialization order is not
//! guaranteed to match).
//!
//! This is a lighter-weight alternative to full checkout for periodic
//! "prove this machine is still valid" pings in air-gapped environments.
//!
//! Intended public API:
//! - `generate_offline_proof` (in `src/client.rs`, the HTTP call).
//! - `verify_offline_proof(proof: &str, account_id: Uuid, machine_id: Uuid,
//!   fingerprint: &str, dataset: &serde_json::Value, rsa_pubkey: &[u8]) ->
//!   Result<(), ProofError>` — parses the `"v1x0."` prefix and base64
//!   payload, rebuilds the byte-exact payload, and RSA-PKCS1v1.5/SHA-256
//!   verifies it (reusing `src/crypto/rsa.rs`).
//!
//! Test coverage to add once implemented: byte-exact serialization against
//! a known-good server-produced payload fixture, and a field-order
//! sensitivity test proving a reordered-but-equal-content JSON payload
//! fails signature verification (i.e. the byte-exact requirement is
//! actually enforced, not accidentally order-independent).

/// Parsed `meta.proof` value (`"v1x0.<base64 signature>"`). Stub — see
/// module doc comment above.
#[derive(Debug, Clone)]
pub struct OfflineProof {
    _private: (),
}
