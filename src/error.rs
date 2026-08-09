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
/// rather than [`JsonApiError::detail`] (human text, may change) — see
/// module doc comment.
///
/// `Crypto`/`Checkout`/`Proof` variants land alongside the sections that
/// produce them (E, F, H per plan §4).
#[derive(Debug, thiserror::Error)]
pub enum TamgaError {
    /// Underlying HTTP transport error (connection, timeout, TLS, or
    /// malformed request such as an invalid `User-Agent`/timeout value).
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),
    /// Response body could not be parsed as the expected JSON shape.
    #[error("failed to parse response body: {0}")]
    Json(#[from] serde_json::Error),
    /// Server returned a non-2xx status with a JSON:API error body. Boxed —
    /// `JsonApiError` carries several owned `String`s, and clippy's
    /// `result_large_err` flags an unboxed variant here as bloating every
    /// `Result<T, TamgaError>` return slot across the crate.
    #[error("API error {code}: {detail}", code = .0.code, detail = .0.detail)]
    Api(Box<JsonApiError>),
}

/// A single JSON:API error object, matching `tamga-api`'s
/// `crate::error::JsonApiError` field-for-field. The server always wraps
/// these in a top-level `{ "errors": [...] }` array; this SDK surfaces only
/// the first element via [`TamgaError::Api`] — every endpoint this crate
/// calls returns at most one error per response today.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct JsonApiError {
    /// Server-generated UUIDv7, unique per error occurrence — useful to
    /// correlate with server-side logs alongside `X-Request-Id`.
    pub id: String,
    /// HTTP status code, as a string (JSON:API convention), e.g. `"404"`.
    pub status: String,
    /// Stable, machine-matchable code, e.g. `"NOT_FOUND"`,
    /// `"FINGERPRINT_TAKEN"`, `"CHECK_IN_NOT_REQUIRED"`. Match on this, not
    /// `detail`.
    pub code: String,
    /// Short, human-readable summary of the error type.
    pub title: String,
    /// Human-readable, request-specific explanation. May change wording
    /// across server versions — not stable for programmatic matching.
    pub detail: String,
    /// Present for validation errors (`422`) — points at the offending
    /// request body field via a JSON Pointer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<JsonApiErrorSource>,
}

/// `source.pointer` on a [`JsonApiError`] — a JSON Pointer (RFC 6901) into
/// the request body identifying the field that failed validation.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct JsonApiErrorSource {
    /// e.g. `"/data/attributes/key"`.
    pub pointer: Option<String>,
}

/// Top-level JSON:API error document: `{ "errors": [ ... ] }`. Internal —
/// only [`TamgaError::Api`]'s single [`JsonApiError`] is exposed publicly.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct JsonApiErrorDocument {
    pub errors: Vec<JsonApiError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_representative_error_body() {
        let json = serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "404",
                "code": "NOT_FOUND",
                "title": "Not Found",
                "detail": "The requested license was not found",
                "source": null,
            }]
        });
        let doc: JsonApiErrorDocument = serde_json::from_value(json).unwrap();
        assert_eq!(doc.errors.len(), 1);
        assert_eq!(doc.errors[0].code, "NOT_FOUND");
        assert_eq!(doc.errors[0].status, "404");
    }

    #[test]
    fn deserializes_error_with_source_pointer() {
        let json = serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "422",
                "code": "DATASET_INVALID",
                "title": "Unprocessable Entity",
                "detail": "dataset must be an object",
                "source": { "pointer": "/meta/dataset" },
            }]
        });
        let doc: JsonApiErrorDocument = serde_json::from_value(json).unwrap();
        assert_eq!(
            doc.errors[0].source.as_ref().unwrap().pointer.as_deref(),
            Some("/meta/dataset")
        );
    }
}
