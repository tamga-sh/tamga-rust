//! `TamgaError`, `JsonApiError`, and typed per-endpoint error codes.
//!
//! - [`JsonApiError`]: `{ id, status, code, title, detail, source: { pointer } }`
//!   mirroring the server's JSON:API error envelope.
//! - [`TamgaError`]: the top-level enum, wrapping transport failures
//!   (`Http`, `Json`), the generic `Api` fallback, one typed variant per
//!   server error code the SDK's endpoints can produce, and the offline
//!   verification errors [`CheckoutError`] and [`ProofError`] (both of which
//!   in turn wrap [`CryptoError`]).
//! - Consumers should match errors on `code` (stable) rather than `detail`
//!   (human text, may change).
//! - Fixed-status codes: `NOT_FOUND` (404), `UNAUTHORIZED` (401),
//!   `FORBIDDEN` (403), `INTERNAL_SERVER_ERROR` (500, generic — never leaks
//!   DB detail).
//! - Per-endpoint codes: `FINGERPRINT_TAKEN`, `PID_TAKEN` (409 conflicts);
//!   `CHECK_IN_NOT_REQUIRED`, `TTL_INVALID`, `LICENSE_NOT_ENCRYPTED`,
//!   `LICENSE_KEY_MISSING`, `SCHEME_NOT_SUPPORTED`, `DATASET_INVALID` (422
//!   validation failures). Any other code falls through to
//!   [`TamgaError::Api`].
//! - Codes without a dedicated variant still arrive intact on
//!   [`TamgaError::Api`], which carries the server's `code` verbatim. Two
//!   families of them matter enough to have first-class classifiers rather
//!   than string comparisons at each call site:
//!   - [`LimitExceededCode`] — the **create-time** `422`s
//!     (`MACHINE_LIMIT_EXCEEDED`, `CORE_LIMIT_EXCEEDED`,
//!     `MEMORY_LIMIT_EXCEEDED`, `DISK_LIMIT_EXCEEDED`,
//!     `TOO_MANY_PROCESSES`). These are the same limits validation reports,
//!     refused earlier; [`LimitExceededCode::as_validation_code`] maps each
//!     one onto its
//!     [`crate::models::validation::ValidationCode`] equivalent.
//!   - [`LicenseAuthCode`] — the `401`s the licence-key auth gate produces
//!     (`LICENSE_SUSPENDED`, `LICENSE_EXPIRED`, `LICENSE_NOT_ALLOWED`).
//!     None of the three is transient; retrying makes none of them pass.
//! - Reach those two via [`TamgaError::limit_exceeded`],
//!   [`TamgaError::license_auth_failure`], or the raw
//!   [`TamgaError::code`]/[`TamgaError::json_api_error`] accessors. No new
//!   `TamgaError` variant is added for them — the enum is exhaustive and
//!   public, so growing it is a breaking change.
//! - `429 TOO_MANY_REQUESTS` is live. Credential-accepting endpoints (session
//!   creation, password reset, licence-key validation, token minting) run on a
//!   tight per-IP budget — 5 requests/second by default — which a heartbeat
//!   timer reaches easily. It maps to [`TamgaError::RateLimited`], which
//!   carries the server's parsed `Retry-After`; safe requests are retried
//!   automatically first (see
//!   [`crate::client::ClientConfigBuilder::max_retries`]).
//! - `CHECK_IN_NOT_REQUIRED` (422) is a **caller error**, not something to
//!   retry — callers should check `require_check_in` on the license's
//!   policy before scheduling periodic check-ins.
//! - **Auth is enforced server-side.** A missing or unrecognized credential
//!   is `401 UNAUTHORIZED`; a valid credential that is not permitted for the
//!   operation is `403 FORBIDDEN`. The two are distinct states — do not
//!   conflate them. Licence-key auth additionally requires the licence's
//!   policy to set `authentication_strategy` to `LICENSE` or `MIXED`; the
//!   column defaults to `'TOKEN'`, under which every licence-key request is
//!   refused with `401 LICENSE_NOT_ALLOWED`. That is a provisioning
//!   precondition, not a transient failure — see [`LicenseAuthCode`].

/// Top-level SDK error type.
///
/// Consumers should match on the wrapped [`JsonApiError::code`] (stable)
/// rather than [`JsonApiError::detail`] (human text, may change) — see
/// module doc comment.
///
/// Offline verification failures arrive as [`TamgaError::Checkout`] or
/// [`TamgaError::Proof`]; neither carries a `CryptoError` directly, since
/// both of those wrap it.
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
    /// The server answered `429 Too Many Requests` and the retry budget was
    /// exhausted (or the request was not safe to repeat).
    ///
    /// `retry_after` is the server's `Retry-After` in seconds when it sent
    /// one. Wait at least that long before trying again.
    ///
    /// `response_info` carries the diagnostic response headers, including the
    /// `x-ratelimit-*` budget the middleware attaches to the throttled
    /// response itself
    /// ([`crate::transport::RateLimitInfo`]). Boxed for the same reason the
    /// [`TamgaError::Api`] payload is: an inline [`crate::transport::ResponseInfo`]
    /// is wide enough to bloat every `Result<T, TamgaError>` slot in the crate.
    #[error("rate limited by the server{}", match retry_after {
        Some(s) => format!("; retry after {s}s"),
        None => String::new(),
    })]
    RateLimited {
        /// Server-supplied `Retry-After`, in seconds.
        retry_after: Option<u64>,
        /// Diagnostic response headers off the `429`, `x-ratelimit-*`
        /// included. All-`None` when the response carried none — which means
        /// no information, not an unlimited budget.
        response_info: Box<crate::transport::ResponseInfo>,
    },
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
    /// `409 FINGERPRINT_TAKEN` — a machine (or component) with this
    /// fingerprint already exists on this license.
    #[error("fingerprint taken: {detail}", detail = .0.detail)]
    FingerprintTaken(Box<JsonApiError>),
    /// `422 DATASET_INVALID` — `meta.dataset` sent to
    /// `generate_offline_proof` wasn't a JSON object (arrays/scalars are
    /// rejected).
    #[error("dataset invalid: {detail}", detail = .0.detail)]
    DatasetInvalid(Box<JsonApiError>),
    /// `409 PID_TAKEN` — a process with this PID already exists on this
    /// machine.
    #[error("pid taken: {detail}", detail = .0.detail)]
    PidTaken(Box<JsonApiError>),
    /// A `"v1x0."` offline proof failed to parse or verify — see
    /// [`ProofError`].
    #[error(transparent)]
    Proof(#[from] ProofError),
    /// `404 NOT_FOUND` — the requested resource doesn't exist (or doesn't
    /// belong to this account).
    #[error("not found: {detail}", detail = .0.detail)]
    NotFound(Box<JsonApiError>),
    /// `401 UNAUTHORIZED` — missing or unrecognized credentials. Reachable
    /// on every endpoint this crate calls: auth **is** enforced
    /// server-side.
    ///
    /// Note that the licence-key auth gate has its own `401` codes
    /// (`LICENSE_SUSPENDED`, `LICENSE_EXPIRED`, `LICENSE_NOT_ALLOWED`)
    /// which arrive on [`TamgaError::Api`], not here — see
    /// [`LicenseAuthCode`] and [`TamgaError::license_auth_failure`].
    #[error("unauthorized: {detail}", detail = .0.detail)]
    Unauthorized(Box<JsonApiError>),
    /// `403 FORBIDDEN` — credentials valid, but not permitted for this
    /// operation. A licence key is scoped to its own licence, so validating
    /// or checking out another licence lands here; so do the two endpoints
    /// a `LicenseToken` role can never call
    /// ([`crate::Client::reset_heartbeat`],
    /// [`crate::Client::generate_offline_proof`]).
    #[error("forbidden: {detail}", detail = .0.detail)]
    Forbidden(Box<JsonApiError>),
    /// `500 INTERNAL_SERVER_ERROR` — generic server-side failure. The
    /// server never leaks DB/internal detail into `detail` for this code —
    /// don't expect this to be more specific than "something went wrong."
    #[error("internal server error: {detail}", detail = .0.detail)]
    InternalServerError(Box<JsonApiError>),
}

/// A server error code meaning "this policy limit is already reached".
///
/// These are **creation-time** `422`s: the server refuses to register the
/// machine or process at all rather than letting it in and reporting the
/// overage on the next validate. Which of the two happens is decided by the
/// policy's overage strategy — under `ALLOW_ACCESS` /
/// `ALLOW_1_25X_OVERAGE` and friends creation still succeeds and the limit
/// surfaces only at validate, so a client has to handle **both** paths.
/// [`crate::Client::activate_machine`] does.
///
/// Each of these has an exactly equivalent
/// [`crate::models::validation::ValidationCode`] — the same limit, reported
/// by the other endpoint — via [`Self::as_validation_code`]. Normalizing to
/// that lets a caller write the over-limit branch once.
///
/// Non-exhaustive: the server may add limits, and matching one here must not
/// become a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LimitExceededCode {
    /// `MACHINE_LIMIT_EXCEEDED` — `policy.max_machines` reached.
    MachineLimitExceeded,
    /// `CORE_LIMIT_EXCEEDED` — `policy.max_cores` reached.
    CoreLimitExceeded,
    /// `MEMORY_LIMIT_EXCEEDED` — `policy.max_memory` reached. The machine's
    /// `memory` is counted in **megabytes** — see
    /// [`crate::client::CreateMachineOptions::memory`].
    MemoryLimitExceeded,
    /// `DISK_LIMIT_EXCEEDED` — `policy.max_disk` reached. Counted in
    /// **megabytes**, like `memory`.
    DiskLimitExceeded,
    /// `TOO_MANY_PROCESSES` — `policy.max_processes` reached. Unlike the
    /// other four this code is spelled identically on both the create-time
    /// and the validation side.
    TooManyProcesses,
}

impl LimitExceededCode {
    /// Parses a server `code` string, returning `None` for anything that is
    /// not one of these limit codes.
    pub fn parse(code: &str) -> Option<Self> {
        match code {
            "MACHINE_LIMIT_EXCEEDED" => Some(LimitExceededCode::MachineLimitExceeded),
            "CORE_LIMIT_EXCEEDED" => Some(LimitExceededCode::CoreLimitExceeded),
            "MEMORY_LIMIT_EXCEEDED" => Some(LimitExceededCode::MemoryLimitExceeded),
            "DISK_LIMIT_EXCEEDED" => Some(LimitExceededCode::DiskLimitExceeded),
            "TOO_MANY_PROCESSES" => Some(LimitExceededCode::TooManyProcesses),
            _ => None,
        }
    }

    /// The wire string this code is spelled as.
    pub fn as_str(self) -> &'static str {
        match self {
            LimitExceededCode::MachineLimitExceeded => "MACHINE_LIMIT_EXCEEDED",
            LimitExceededCode::CoreLimitExceeded => "CORE_LIMIT_EXCEEDED",
            LimitExceededCode::MemoryLimitExceeded => "MEMORY_LIMIT_EXCEEDED",
            LimitExceededCode::DiskLimitExceeded => "DISK_LIMIT_EXCEEDED",
            LimitExceededCode::TooManyProcesses => "TOO_MANY_PROCESSES",
        }
    }

    /// The validation code reporting this same limit on the validate
    /// endpoint. Lets one over-limit branch serve both the create-time
    /// `422` and the validate-time outcome.
    pub fn as_validation_code(self) -> crate::models::validation::ValidationCode {
        use crate::models::validation::ValidationCode;
        match self {
            LimitExceededCode::MachineLimitExceeded => ValidationCode::TooManyMachines,
            LimitExceededCode::CoreLimitExceeded => ValidationCode::TooManyCores,
            LimitExceededCode::MemoryLimitExceeded => ValidationCode::TooMuchMemory,
            LimitExceededCode::DiskLimitExceeded => ValidationCode::TooMuchDisk,
            LimitExceededCode::TooManyProcesses => ValidationCode::TooManyProcesses,
        }
    }
}

/// A `401` from the licence-key auth gate, before any endpoint logic runs.
///
/// All three are **configuration or lifecycle** states, not transient
/// failures: retrying, backing off, or re-sending the same key changes
/// nothing. In particular `LICENSE_NOT_ALLOWED` means the licence's policy
/// has `authentication_strategy` set to `TOKEN` (the column default) or
/// `NONE`, neither of which accepts a licence key as a credential at all —
/// the fix is provisioning the policy as `LICENSE` or `MIXED`, not client-side
/// retry logic. See [`crate::models::policy::AuthenticationStrategy`].
///
/// Non-exhaustive for the same reason as [`LimitExceededCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LicenseAuthCode {
    /// `LICENSE_SUSPENDED` — the licence itself is suspended.
    LicenseSuspended,
    /// `LICENSE_EXPIRED` — the licence has expired **and** its policy's
    /// expiration strategy is `REVOKE_ACCESS`. Under `MAINTAIN_ACCESS`,
    /// `ALLOW_ACCESS` or `RESTRICT_ACCESS` an expired licence still
    /// authenticates and the expiry surfaces at validate instead.
    LicenseExpired,
    /// `LICENSE_NOT_ALLOWED` — the policy does not accept licence-key auth.
    LicenseNotAllowed,
}

impl LicenseAuthCode {
    /// Parses a server `code` string, returning `None` for anything that is
    /// not one of these auth-gate codes.
    pub fn parse(code: &str) -> Option<Self> {
        match code {
            "LICENSE_SUSPENDED" => Some(LicenseAuthCode::LicenseSuspended),
            "LICENSE_EXPIRED" => Some(LicenseAuthCode::LicenseExpired),
            "LICENSE_NOT_ALLOWED" => Some(LicenseAuthCode::LicenseNotAllowed),
            _ => None,
        }
    }

    /// The wire string this code is spelled as.
    pub fn as_str(self) -> &'static str {
        match self {
            LicenseAuthCode::LicenseSuspended => "LICENSE_SUSPENDED",
            LicenseAuthCode::LicenseExpired => "LICENSE_EXPIRED",
            LicenseAuthCode::LicenseNotAllowed => "LICENSE_NOT_ALLOWED",
        }
    }
}

/// Failures while parsing or verifying a machine offline proof string
/// (`"v1x0.<base64 signature>"`) — see `src/proof.rs`'s module doc comment
/// for the full verification flow this maps onto.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// Input didn't start with the expected `"v1x0."` prefix.
    #[error("malformed proof: missing v1x0. prefix")]
    MalformedProof,
    /// The signature portion (after the prefix) wasn't valid base64.
    #[error("invalid base64 in proof signature")]
    InvalidBase64,
    /// Signature verification itself failed — see [`CryptoError`].
    #[error(transparent)]
    Crypto(#[from] CryptoError),
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
    /// understands (`"base64+ed25519+v2"`, `"aes-256-gcm+ed25519+v2"`).
    ///
    /// A v1 file (no `+v2` suffix) lands here too, and that is deliberate:
    /// v1 carried no expiry inside the signature, so accepting one would
    /// hand back the permanent-file problem v2 exists to close.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The file's signed `exp` claim is in the past.
    ///
    /// The signature was valid — this is an authentic file that has simply
    /// run out. Re-check out to get a fresh one.
    #[error("license file expired at unix timestamp {exp}")]
    Expired {
        /// The `exp` claim, seconds since the Unix epoch.
        exp: i64,
    },
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
    /// The file's `kid` claim names a signing key the supplied
    /// [`crate::checkout::key_set::SigningKeySet`] does not hold.
    ///
    /// **This is not a forgery.** It is the outcome a genuine file signed
    /// before a key rotation produces against a key set that has not caught up
    /// — a stale set, an application shipped with one pinned key, or an
    /// account whose public key was never published. A tampered file whose
    /// `kid` *is* known fails as
    /// [`CheckoutError::Crypto`]`(`[`CryptoError::VerificationFailed`]`)`
    /// instead, and separating the two is the entire point of verifying
    /// through a key set: the first calls for refreshing the keys, the second
    /// for refusing the file.
    ///
    /// Nothing about the file has been trusted at this point. Every key the
    /// caller holds has already been tried against the signature and none
    /// verified; the `kid` is then read from those still-unverified bytes
    /// only to label which failure this is — it never selects a key to
    /// verify against, and it can never introduce one.
    #[error("no signing key for kid {kid} in the supplied key set")]
    UnknownSigningKey {
        /// The `kid` the file claims, verbatim. Log it next to
        /// [`crate::checkout::key_set::SigningKeySet::kids`] to see what the
        /// set did hold.
        kid: String,
    },
    /// Signature verification or decryption itself failed — see
    /// [`CryptoError`].
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl TamgaError {
    /// The underlying JSON:API error object, for any variant that carries
    /// one. `None` for the transport (`Http`, `Json`), rate-limit and
    /// offline-verification variants, which never have a server error body.
    ///
    /// This is the single accessor the code-based helpers below are built
    /// on: match on [`JsonApiError::code`] (stable), never `detail` (human
    /// text, may be reworded).
    pub fn json_api_error(&self) -> Option<&JsonApiError> {
        match self {
            TamgaError::Api(err)
            | TamgaError::CheckInNotRequired(err)
            | TamgaError::LicenseNotEncrypted(err)
            | TamgaError::LicenseKeyMissingApi(err)
            | TamgaError::TtlInvalidApi(err)
            | TamgaError::SchemeNotSupportedApi(err)
            | TamgaError::FingerprintTaken(err)
            | TamgaError::DatasetInvalid(err)
            | TamgaError::PidTaken(err)
            | TamgaError::NotFound(err)
            | TamgaError::Unauthorized(err)
            | TamgaError::Forbidden(err)
            | TamgaError::InternalServerError(err) => Some(err),
            TamgaError::Http(_)
            | TamgaError::Json(_)
            | TamgaError::RateLimited { .. }
            | TamgaError::Checkout(_)
            | TamgaError::Proof(_) => None,
        }
    }

    /// The server's stable error `code`, for any variant carrying a
    /// [`JsonApiError`]. Shorthand for
    /// `self.json_api_error().map(|e| e.code.as_str())`.
    ///
    /// Useful for codes without a dedicated variant — `SCOPE_NOT_SUPPORTED`
    /// (the `422` that `scope.version`/`scope.checksum` provoke),
    /// `ENTITLEMENT_ALREADY_INHERITED`, `POLICY_ENTITLEMENT`, and so on.
    pub fn code(&self) -> Option<&str> {
        self.json_api_error().map(|err| err.code.as_str())
    }

    /// Classifies this error as a create-time policy-limit refusal, if it is
    /// one. See [`LimitExceededCode`].
    pub fn limit_exceeded(&self) -> Option<LimitExceededCode> {
        self.code().and_then(LimitExceededCode::parse)
    }

    /// Classifies this error as a licence-key auth-gate `401`, if it is one.
    /// See [`LicenseAuthCode`].
    pub fn license_auth_failure(&self) -> Option<LicenseAuthCode> {
        self.code().and_then(LicenseAuthCode::parse)
    }

    /// Maps a parsed [`JsonApiError`] to its most specific [`TamgaError`]
    /// variant, falling back to the generic [`TamgaError::Api`] for any
    /// `code` without a dedicated variant. Single dispatch point: a newly
    /// typed code needs a match arm here, not a new call site at every
    /// endpoint method.
    ///
    /// The fallback loses nothing — [`TamgaError::Api`] carries the
    /// server's `code` verbatim, and
    /// [`TamgaError::limit_exceeded`]/[`TamgaError::license_auth_failure`]
    /// classify the two families that matter without needing variants of
    /// their own (which this enum, being public and exhaustive, cannot grow
    /// without a breaking release).
    pub(crate) fn from_json_api_error(err: JsonApiError) -> Self {
        match err.code.as_str() {
            "CHECK_IN_NOT_REQUIRED" => TamgaError::CheckInNotRequired(Box::new(err)),
            "LICENSE_NOT_ENCRYPTED" => TamgaError::LicenseNotEncrypted(Box::new(err)),
            "LICENSE_KEY_MISSING" => TamgaError::LicenseKeyMissingApi(Box::new(err)),
            "FINGERPRINT_TAKEN" => TamgaError::FingerprintTaken(Box::new(err)),
            "PID_TAKEN" => TamgaError::PidTaken(Box::new(err)),
            "NOT_FOUND" => TamgaError::NotFound(Box::new(err)),
            "UNAUTHORIZED" => TamgaError::Unauthorized(Box::new(err)),
            "FORBIDDEN" => TamgaError::Forbidden(Box::new(err)),
            "INTERNAL_SERVER_ERROR" => TamgaError::InternalServerError(Box::new(err)),
            "DATASET_INVALID" => TamgaError::DatasetInvalid(Box::new(err)),
            "TTL_INVALID" => TamgaError::TtlInvalidApi(Box::new(err)),
            "SCHEME_NOT_SUPPORTED" => TamgaError::SchemeNotSupportedApi(Box::new(err)),
            _ => TamgaError::Api(Box::new(err)),
        }
    }
}

/// A single JSON:API error object, matching the server's own error type
/// field-for-field. The server always wraps
/// these in a top-level `{ "errors": [...] }` array; this SDK surfaces only
/// the first element via [`TamgaError::Api`] — every endpoint this crate
/// calls returns at most one error per response today.
///
/// Tolerant on the way in, deliberately: `status` may be a JSON string or a
/// JSON number, and `title`/`detail` may be absent. A document that failed
/// to decode used to be replaced wholesale by a synthetic `UNKNOWN` error
/// (`client.rs`, `api_error`), which threw away a perfectly good `code`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct JsonApiError {
    /// Server-generated UUIDv7, unique per error occurrence — useful to
    /// correlate with server-side logs alongside `X-Request-Id`.
    pub id: String,
    /// HTTP status code, as a string (JSON:API convention), e.g. `"404"`.
    ///
    /// A server that sends the number (`422`) — the shape the API patch's
    /// new `422`s are specified with — decodes to the same `"422"`.
    #[serde(deserialize_with = "deserialize_status")]
    pub status: String,
    /// Stable, machine-matchable code, e.g. `"NOT_FOUND"`,
    /// `"FINGERPRINT_TAKEN"`, `"CHECK_IN_NOT_REQUIRED"`. Match on this, not
    /// `detail`.
    pub code: String,
    /// Short, human-readable summary of the error type. Empty when the
    /// server omitted it.
    #[serde(default)]
    pub title: String,
    /// Human-readable, request-specific explanation. May change wording
    /// across server versions — not stable for programmatic matching. Empty
    /// when the server omitted it.
    #[serde(default)]
    pub detail: String,
    /// Present for validation errors (`422`) — points at the offending
    /// request body field via a JSON Pointer.
    pub source: Option<JsonApiErrorSource>,
}

/// `status` as either JSON representation. A plain `String` field refuses
/// the number, and refusing it fails the whole document — the D18 defect.
fn deserialize_status<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;

    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum StatusRepr {
        Text(String),
        Number(u64),
    }

    Ok(match StatusRepr::deserialize(deserializer)? {
        StatusRepr::Text(text) => text,
        StatusRepr::Number(number) => number.to_string(),
    })
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

/// Rejections from [`crate::fingerprint::canonical`] and
/// [`crate::fingerprint::compute`].
///
/// Every variant is a refusal, never a silent repair. Stripping a control
/// character or collapsing a repeated label would map two *different* inputs
/// onto one canonical string, and therefore onto one seat — the exact class
/// of bug the canonicalizer exists to prevent. A caller that would rather
/// coerce than fail must do so itself, visibly, before calling.
///
/// `#[non_exhaustive]`: [`TamgaError`] is not, and adding a variant to it
/// would be a breaking change. This enum is declared closed-to-external-
/// matching from its first release so a future validation rule stays a patch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FingerprintError {
    /// No components were supplied. Hashing the bare domain prefix would give
    /// every caller who passes an empty collection the same fingerprint —
    /// a single shared seat — so it is refused instead.
    #[error("at least one component is required")]
    NoComponents,
    /// A label was the empty string.
    #[error("component label must not be empty")]
    EmptyLabel,
    /// A label held a byte outside ASCII printable `0x21..=0x7E`, or held
    /// `'='`.
    ///
    /// `'='` would make the `label=value` split ambiguous. Non-ASCII is
    /// refused so a label can never itself need Unicode normalisation — see
    /// the module doc comment on [`crate::fingerprint`] for why no port of
    /// this SDK normalises anything.
    ///
    /// The offending label is Debug-formatted, so a control character in it
    /// is escaped rather than written raw into a log line.
    #[error("invalid label {label:?}: labels are ASCII printable 0x21..=0x7E, excluding '='")]
    InvalidLabel {
        /// The label as supplied.
        label: String,
    },
    /// The same label appeared twice.
    ///
    /// Not deduplicated: two values for one label is a caller bug, and
    /// silently picking one of them hides it.
    #[error("duplicate label {label:?}: two values for one label is a caller bug")]
    DuplicateLabel {
        /// The label that repeated.
        label: String,
    },
    /// A value still held an ASCII control character (`0x00..=0x1F` or
    /// `0x7F`) after ASCII whitespace was trimmed from both ends.
    ///
    /// The unit separator `0x1F` lands here too: it is the field separator of
    /// the canonical string, so a value containing one could forge an extra
    /// component.
    #[error("value for label {label:?} contains an ASCII control character")]
    ControlCharacterInValue {
        /// The label whose value was rejected. The value itself is not
        /// echoed — it is caller-chosen machine identity material.
        label: String,
    },
}

/// Failures from [`crate::Client::download_artifact`], which spans two
/// different hosts: the Tamga API, then the storage backend the API
/// presigns a URL on.
///
/// Kept separate from [`TamgaError`] because a storage-side failure is not
/// an API failure — a `403` from S3 means the presigned URL expired between
/// issue and use, which calls for re-requesting the URL, not for
/// re-authenticating with Tamga.
///
/// `#[non_exhaustive]` for the same reason as [`FingerprintError`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArtifactDownloadError {
    /// The Tamga API call that issues the presigned URL failed.
    #[error("failed to obtain a download URL: {0}")]
    Api(#[from] TamgaError),
    /// The API answered `200` but left `redirectUrl` absent.
    ///
    /// The download action is the only route that populates it, so this
    /// means the server changed shape — it is not a condition a caller can
    /// retry into success.
    #[error("the download response carried no redirectUrl")]
    MissingRedirectUrl,
    /// `redirectUrl` did not parse as a URL at all.
    #[error("the download response carried an unparseable redirectUrl")]
    MalformedRedirectUrl,
    /// `redirectUrl` parsed, but its scheme is neither `http` nor `https`.
    ///
    /// This value comes from the server, so it is a URL this crate did not
    /// choose. "It parsed" is not the same as "it is an HTTP URL": a `file:`,
    /// `data:` or `ftp:` URL parses perfectly well. tamga-dotnet found its
    /// absolute-URI check returning `true` for `/relative/path` and
    /// `C:\x\y`, both yielding `file:` URIs, which is the failure this
    /// refuses by naming the two acceptable schemes rather than by rejecting
    /// a blocklist.
    ///
    /// `reqwest` would refuse a non-HTTP scheme itself, but as an opaque
    /// transport failure. Rejecting it here makes the cause legible.
    #[error("redirectUrl has unsupported scheme `{scheme}` (expected http or https)")]
    UnsupportedRedirectScheme {
        /// The scheme as parsed, e.g. `"file"`.
        scheme: String,
    },
    /// The unauthenticated fetch of the presigned URL failed at the
    /// transport level (DNS, TLS, timeout, connection reset).
    #[error("failed to fetch the presigned URL: {0}")]
    Fetch(#[source] reqwest::Error),
    /// The storage host answered a non-success status.
    ///
    /// Most often `403` — a presigned URL is short-lived and this one had
    /// already expired. Request a fresh one rather than retrying this URL.
    #[error("storage host answered HTTP {status}")]
    StorageStatus {
        /// The status code the storage host returned.
        status: u16,
    },
    /// The artifact exceeded the `max_bytes` ceiling the caller passed.
    ///
    /// The server admits uploads up to 1 GiB, so buffering an artifact into
    /// memory unbounded is a real exhaustion risk; the ceiling is required
    /// rather than defaulted so the number is always a caller's decision.
    #[error("artifact exceeds the {limit}-byte ceiling supplied by the caller")]
    TooLarge {
        /// The ceiling that was exceeded, in bytes.
        limit: u64,
    },
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
            status: "422".to_string(),
            // Live server code with no dedicated variant: `scope.version`
            // or `scope.checksum` on validate fails the whole call with
            // this. Deliberately left on the generic `Api` path — see
            // `models::validation::ScopeObject`.
            code: "SCOPE_NOT_SUPPORTED".to_string(),
            title: "Unprocessable Entity".to_string(),
            detail: "scope.version is not supported".to_string(),
            source: None,
        };
        let mapped = TamgaError::from_json_api_error(err);
        assert!(matches!(mapped, TamgaError::Api(_)));
        assert_eq!(mapped.code(), Some("SCOPE_NOT_SUPPORTED"));
    }

    #[test]
    fn a_numeric_status_decodes_to_its_decimal_string() {
        // D18. The wire shape the API plan specifies for the new 422s puts
        // `status` on the wire as a JSON number; pre-patch servers send the
        // JSON:API string "422". Both must decode to the same `String`.
        let json = serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": 422,
                "code": "SIGNING_KEY_MISSING",
                "title": "Unprocessable Entity",
                "detail": "the account has no Ed25519 signing key",
                "source": null,
            }]
        });
        let doc: JsonApiErrorDocument = serde_json::from_value(json).unwrap();
        assert_eq!(doc.errors[0].status, "422");
        assert_eq!(doc.errors[0].code, "SIGNING_KEY_MISSING");
    }

    #[test]
    fn a_missing_title_or_detail_does_not_fail_the_whole_document() {
        // A failed decode collapses a perfectly good `code` into "UNKNOWN"
        // (client.rs `api_error`), which is the D18 defect in a second shape.
        let json = serde_json::json!({
            "errors": [{ "id": "e1", "status": "422", "code": "SECRET_KEY_MISSING" }]
        });
        let doc: JsonApiErrorDocument = serde_json::from_value(json).unwrap();
        assert_eq!(doc.errors[0].code, "SECRET_KEY_MISSING");
        assert_eq!(doc.errors[0].title, "");
        assert_eq!(doc.errors[0].detail, "");
    }

    #[test]
    fn the_two_new_422_codes_land_on_api_with_their_code_intact() {
        // `TamgaError` is public and exhaustive, so neither gets a variant;
        // the contract is that `code()` survives on the generic arm.
        for code in ["SIGNING_KEY_MISSING", "SECRET_KEY_MISSING"] {
            let err = error_with_code("422", code);
            assert!(matches!(err, TamgaError::Api(_)), "{code}: {err:?}");
            assert_eq!(err.code(), Some(code));
        }
    }

    fn error_with_code(status: &str, code: &str) -> TamgaError {
        TamgaError::from_json_api_error(JsonApiError {
            id: "01926b3e-0000-7000-8000-000000000000".to_string(),
            status: status.to_string(),
            code: code.to_string(),
            title: String::new(),
            detail: String::new(),
            source: None,
        })
    }

    #[test]
    fn create_time_limit_codes_classify_and_map_onto_validation_codes() {
        use crate::models::validation::ValidationCode;
        let cases = [
            (
                "MACHINE_LIMIT_EXCEEDED",
                LimitExceededCode::MachineLimitExceeded,
                ValidationCode::TooManyMachines,
            ),
            (
                "CORE_LIMIT_EXCEEDED",
                LimitExceededCode::CoreLimitExceeded,
                ValidationCode::TooManyCores,
            ),
            (
                "MEMORY_LIMIT_EXCEEDED",
                LimitExceededCode::MemoryLimitExceeded,
                ValidationCode::TooMuchMemory,
            ),
            (
                "DISK_LIMIT_EXCEEDED",
                LimitExceededCode::DiskLimitExceeded,
                ValidationCode::TooMuchDisk,
            ),
            (
                "TOO_MANY_PROCESSES",
                LimitExceededCode::TooManyProcesses,
                ValidationCode::TooManyProcesses,
            ),
        ];
        for (wire, expected, validation) in cases {
            // The server sends `status` as a JSON string, not a number.
            let err = error_with_code("422", wire);
            assert_eq!(err.limit_exceeded(), Some(expected), "code {wire}");
            assert_eq!(expected.as_str(), wire);
            assert_eq!(expected.as_validation_code(), validation, "code {wire}");
        }
    }

    #[test]
    fn license_auth_gate_codes_classify() {
        let cases = [
            ("LICENSE_SUSPENDED", LicenseAuthCode::LicenseSuspended),
            ("LICENSE_EXPIRED", LicenseAuthCode::LicenseExpired),
            ("LICENSE_NOT_ALLOWED", LicenseAuthCode::LicenseNotAllowed),
        ];
        for (wire, expected) in cases {
            let err = error_with_code("401", wire);
            assert_eq!(err.license_auth_failure(), Some(expected), "code {wire}");
            assert_eq!(expected.as_str(), wire);
            // These are auth-gate codes, not limit codes.
            assert_eq!(err.limit_exceeded(), None, "code {wire}");
        }
    }

    #[test]
    fn every_code_carrying_variant_still_exposes_its_code() {
        // `from_json_api_error` and `json_api_error` are two hand-written
        // match arms over the same vocabulary: the first maps a wire code
        // onto a typed variant, the second lists every variant that still
        // carries the server body. The compiler forces the second to mention
        // a new variant, but not to put it in the right group — dropping one
        // into the `None` arm would silently break `code()`, and with it
        // `limit_exceeded` and `license_auth_failure`, which are built on it.
        // Round-trip every mapped code to keep the two in step.
        let carries_a_body = [
            "CHECK_IN_NOT_REQUIRED",
            "LICENSE_NOT_ENCRYPTED",
            "LICENSE_KEY_MISSING",
            "FINGERPRINT_TAKEN",
            "PID_TAKEN",
            "NOT_FOUND",
            "UNAUTHORIZED",
            "FORBIDDEN",
            "INTERNAL_SERVER_ERROR",
            "DATASET_INVALID",
            "TTL_INVALID",
            "SCHEME_NOT_SUPPORTED",
            // No dedicated variant — falls back to `Api`, which carries the
            // body just the same. This is the route every un-typed code
            // takes, including `SCOPE_NOT_SUPPORTED`.
            "SCOPE_NOT_SUPPORTED",
        ];
        for wire in carries_a_body {
            let err = error_with_code("422", wire);
            assert!(
                err.json_api_error().is_some(),
                "{wire} lost its server error body"
            );
            assert_eq!(err.code(), Some(wire), "code {wire}");
        }
    }

    #[test]
    fn classifiers_return_none_for_errors_without_a_server_body() {
        let err = TamgaError::RateLimited {
            retry_after: Some(5),
            response_info: Box::default(),
        };
        assert!(err.json_api_error().is_none());
        assert_eq!(err.code(), None);
        assert_eq!(err.limit_exceeded(), None);
        assert_eq!(err.license_auth_failure(), None);
    }

    #[test]
    fn json_api_error_is_readable_through_a_typed_variant_too() {
        let err = error_with_code("404", "NOT_FOUND");
        assert!(matches!(err, TamgaError::NotFound(_)));
        assert_eq!(err.code(), Some("NOT_FOUND"));
        assert_eq!(err.json_api_error().unwrap().status, "404");
    }

    #[test]
    fn fixed_status_codes_map_to_their_typed_variants() {
        let build = |code: &str| JsonApiError {
            id: "01926b3e-0000-7000-8000-000000000000".to_string(),
            status: "0".to_string(),
            code: code.to_string(),
            title: "".to_string(),
            detail: "".to_string(),
            source: None,
        };
        assert!(matches!(
            TamgaError::from_json_api_error(build("NOT_FOUND")),
            TamgaError::NotFound(_)
        ));
        assert!(matches!(
            TamgaError::from_json_api_error(build("UNAUTHORIZED")),
            TamgaError::Unauthorized(_)
        ));
        assert!(matches!(
            TamgaError::from_json_api_error(build("FORBIDDEN")),
            TamgaError::Forbidden(_)
        ));
        assert!(matches!(
            TamgaError::from_json_api_error(build("INTERNAL_SERVER_ERROR")),
            TamgaError::InternalServerError(_)
        ));
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
