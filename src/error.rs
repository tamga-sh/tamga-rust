//! `TamgaError`, `JsonApiError`, and typed per-endpoint error codes.
//!
//! Intended contents (deferred — see `docs/plans/tamga-rust.plan.md` §K):
//!
//! - `JsonApiError`: `{ id, status, code, title, detail, source: { pointer } }`
//!   mirroring the server's JSON:API error envelope.
//! - `TamgaError` top-level enum wrapping: `Http(reqwest::Error)`,
//!   `Json(serde_json::Error)`, `Api(JsonApiError)`, `Crypto(CryptoError)`,
//!   `Checkout(CheckoutError)`, `Proof(ProofError)`.
//! - Consumers should match errors on `code` (stable) rather than `detail`
//!   (human text, may change).
//! - Fixed-status codes: `NOT_FOUND` (404), `UNAUTHORIZED` (401),
//!   `FORBIDDEN` (403), `INTERNAL_SERVER_ERROR` (500, generic — never leaks
//!   DB detail).
//! - Per-endpoint codes: `KEY_TAKEN`, `FINGERPRINT_TAKEN`, `PID_TAKEN` (409
//!   conflicts); `CHECK_IN_NOT_REQUIRED`, `TTL_INVALID`,
//!   `LICENSE_NOT_ENCRYPTED`, `LICENSE_KEY_MISSING`, `SCHEME_NOT_SUPPORTED`,
//!   `DATASET_INVALID` (422 validation failures).
//! - `429 TOO_MANY_REQUESTS` is declared in the server's error enum but has
//!   **no constructor and is never returned by any code path today** — do
//!   not build client-side 429/backoff handling expecting the server to
//!   ever send it under the current deployment.
//! - `CHECK_IN_NOT_REQUIRED` (422) is a **caller error**, not something to
//!   retry — callers should check `require_check_in` on the license's
//!   policy before scheduling periodic check-ins.

/// Top-level SDK error type.
///
/// Consumers should match on the wrapped [`JsonApiError::code`] (stable)
/// rather than `detail` (human text, may change) — see module doc comment.
///
/// Only `Http` is populated so far (Section B — client/transport
/// construction). `Json`/`Api`/`Crypto`/`Checkout`/`Proof` variants land
/// alongside the sections that produce them (C, E/F/H per plan §4).
#[derive(Debug, thiserror::Error)]
pub enum TamgaError {
    /// Underlying HTTP transport error (connection, timeout, TLS, or
    /// malformed request such as an invalid `User-Agent`/timeout value).
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),
}

/// JSON:API error object as returned by the server. Stub.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct JsonApiError {
    /// Server-declared field names (`id`, `status`, `code`, `title`,
    /// `detail`, `source.pointer`) will be added when this is implemented.
    #[serde(skip)]
    _private: (),
}
