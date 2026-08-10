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
    /// Server returned a non-2xx status with a JSON:API error body whose
    /// `code` doesn't have a more specific typed variant below. Boxed —
    /// `JsonApiError` carries several owned `String`s, and clippy's
    /// `result_large_err` flags an unboxed variant here as bloating every
    /// `Result<T, TamgaError>` return slot across the crate.
    #[error("API error {code}: {detail}", code = .0.code, detail = .0.detail)]
    Api(Box<JsonApiError>),
    /// `422 CHECK_IN_NOT_REQUIRED` — a **caller error**, not something to
    /// retry. Callers should check `require_check_in` on the license's
    /// policy before scheduling periodic check-ins, rather than reacting to
    /// this error with retry logic.
    #[error("check-in not required: {detail}", detail = .0.detail)]
    CheckInNotRequired(Box<JsonApiError>),
    /// A `.lic`/`.mach` offline file failed to parse or verify — see
    /// [`CheckoutError`] for the specific stage that failed.
    #[error(transparent)]
    Checkout(#[from] CheckoutError),
    /// `422 LICENSE_NOT_ENCRYPTED` — the server rejected an `encrypt: true`
    /// checkout request because the license has no `key` set. A caller
    /// error: check that the license has a key before requesting an
    /// encrypted checkout.
    #[error("license not encrypted: {detail}", detail = .0.detail)]
    LicenseNotEncrypted(Box<JsonApiError>),
    /// `422 LICENSE_KEY_MISSING` — the server rejected an `encrypt: true`
    /// machine checkout because the machine's license has no `key` set.
    /// Distinct API error code from `LICENSE_NOT_ENCRYPTED` (license file
    /// checkout's equivalent) despite the similar meaning.
    #[error("license key missing: {detail}", detail = .0.detail)]
    LicenseKeyMissingApi(Box<JsonApiError>),
    /// `422 TTL_INVALID` — the server rejected a `ttl` outside `(0,
    /// 31536000]`. The SDK also pre-checks this client-side (see
    /// [`crate::checkout::machine_file::check_ttl`]) so this variant is
    /// normally only reachable if the client-side check was bypassed.
    #[error("ttl invalid: {detail}", detail = .0.detail)]
    TtlInvalidApi(Box<JsonApiError>),
    /// `422 SCHEME_NOT_SUPPORTED` — the server rejected a machine checkout
    /// because the license's scheme is `RSA_2048_JWT_RS256`.
    #[error("scheme not supported: {detail}", detail = .0.detail)]
    SchemeNotSupportedApi(Box<JsonApiError>),
}

/// Cryptographic primitive failures — signature verification, decryption,
/// or malformed key/signature material. Never distinguishes *why* a
/// verification failed beyond this coarse granularity (e.g. "wrong key" vs
/// "tampered ciphertext" both surface as [`CryptoError::DecryptionFailed`])
/// — a more specific error would leak information useful to an attacker
/// probing for valid inputs.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// Public key bytes are malformed or the wrong length for the scheme.
    #[error("invalid public key")]
    InvalidKey,
    /// Signature bytes are malformed or the wrong length for the scheme.
    #[error("invalid signature encoding")]
    InvalidSignature,
    /// Signature verification failed — wrong key, tampered message, or both.
    #[error("signature verification failed")]
    VerificationFailed,
    /// AEAD decryption failed — wrong key, tampered ciphertext, or tampered
    /// tag. AES-GCM inherently cannot distinguish these.
    #[error("decryption failed (wrong key or tampered ciphertext)")]
    DecryptionFailed,
}

/// Failures while parsing or verifying a `.lic`/`.mach` offline checkout
/// file — see `src/checkout/license_file.rs`'s module doc comment for the
/// full verification flow this maps onto.
#[derive(Debug, thiserror::Error)]
pub enum CheckoutError {
    /// Input didn't start/end with the expected `-----BEGIN ... -----`/
    /// `-----END ... -----` PEM markers.
    #[error("malformed PEM envelope: missing BEGIN/END markers")]
    MalformedPem,
    /// The PEM body, or the `enc`/`sig` fields inside it, wasn't valid
    /// base64.
    #[error("invalid base64 in certificate payload")]
    InvalidBase64,
    /// The decoded PEM body wasn't valid `{ enc, sig, alg }` JSON, or the
    /// decrypted/decoded payload wasn't valid `{"data": ...}` JSON.
    #[error("invalid JSON in certificate payload: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// `alg` wasn't one of the two license-file values this SDK
    /// understands (`"base64+ed25519"`, `"aes-256-gcm+ed25519"`).
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The file's `alg` requires decryption but no `license_key` was
    /// supplied to the verify call.
    #[error("license key is required to decrypt an encrypted checkout file")]
    LicenseKeyMissing,
    /// The file's `alg` requires decryption but no `fingerprint` was
    /// supplied to [`crate::checkout::machine_file::verify_machine_file`]
    /// (machine files, unlike license files, need both the license key
    /// *and* the target machine's fingerprint to decrypt).
    #[error("machine fingerprint is required to decrypt an encrypted machine file")]
    FingerprintMissing,
    /// `RSA_2048_JWT_RS256` was passed as the verification scheme for a
    /// `.mach` file — this scheme is not supported for machine file
    /// checkout (the server itself rejects generating one with `422
    /// SCHEME_NOT_SUPPORTED`); rejected up front, before any parsing.
    #[error("scheme not supported for machine file checkout: RSA_2048_JWT_RS256")]
    SchemeNotSupported,
    /// Client-side pre-check failure: `ttl` must be `> 0` and
    /// `<= 31536000` (365 days) — mirrors the server's own validated range
    /// (`422 TTL_INVALID`), checked before the round trip.
    #[error("ttl out of range: {0}")]
    TtlOutOfRange(String),
    /// Signature verification or decryption itself failed — see
    /// [`CryptoError`].
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl TamgaError {
    /// Maps a parsed [`JsonApiError`] to its most specific [`TamgaError`]
    /// variant, falling back to the generic [`TamgaError::Api`] for any
    /// `code` without a dedicated variant. Single dispatch point extended
    /// as later sections (K, and E/F/H's per-endpoint codes) add more typed
    /// variants — new codes only need a match arm here, not a new call site
    /// at every endpoint method.
    pub(crate) fn from_json_api_error(err: JsonApiError) -> Self {
        match err.code.as_str() {
            "CHECK_IN_NOT_REQUIRED" => TamgaError::CheckInNotRequired(Box::new(err)),
            "LICENSE_NOT_ENCRYPTED" => TamgaError::LicenseNotEncrypted(Box::new(err)),
            "LICENSE_KEY_MISSING" => TamgaError::LicenseKeyMissingApi(Box::new(err)),
            "TTL_INVALID" => TamgaError::TtlInvalidApi(Box::new(err)),
            "SCHEME_NOT_SUPPORTED" => TamgaError::SchemeNotSupportedApi(Box::new(err)),
            _ => TamgaError::Api(Box::new(err)),
        }
    }
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
    fn maps_check_in_not_required_code_to_typed_variant() {
        let err = JsonApiError {
            id: "01926b3e-0000-7000-8000-000000000000".to_string(),
            status: "422".to_string(),
            code: "CHECK_IN_NOT_REQUIRED".to_string(),
            title: "Unprocessable Entity".to_string(),
            detail: "this license's policy does not require check-in".to_string(),
            source: None,
        };
        let mapped = TamgaError::from_json_api_error(err);
        assert!(matches!(mapped, TamgaError::CheckInNotRequired(_)));
    }

    #[test]
    fn unrecognized_code_maps_to_generic_api_variant() {
        let err = JsonApiError {
            id: "01926b3e-0000-7000-8000-000000000000".to_string(),
            status: "404".to_string(),
            code: "NOT_FOUND".to_string(),
            title: "Not Found".to_string(),
            detail: "not found".to_string(),
            source: None,
        };
        let mapped = TamgaError::from_json_api_error(err);
        assert!(matches!(mapped, TamgaError::Api(_)));
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
