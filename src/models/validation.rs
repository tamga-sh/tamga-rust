//! `ScopeObject`, `ValidationMeta`, and `ValidationCode`.
//!
//! Intended contents (see `docs/plans/tamga-rust.plan.md` §C):
//!
//! - `ScopeObject`: 8 optional fields — `product`, `policy`, `user`,
//!   `environment` (`Uuid`), `entitlements` (`Vec<String>`), `fingerprint`,
//!   `version`, `checksum` (`String`). Only `product`/`policy`/`user`/
//!   `environment` are enforced server-side today; the rest are parsed but
//!   silently ignored — keep them in the request builder for
//!   forward-compatibility, but do not advertise them as functioning
//!   constraints yet. Must serialize with `skip_serializing_if =
//!   "Option::is_none"` so unset fields are omitted from the request body.
//! - `ValidationMeta`: `{ ts, valid, detail, code }`.
//! - `ValidationCode`: all **24** variants, with a `#[serde(other)]
//!   Unknown(String)` fallback for lenient deserialization of any future
//!   server-side addition.
//!   - ✅ Reachable today (14): `VALID`, `SUSPENDED`, `EXPIRED`, `OVERDUE`,
//!     `PRODUCT_SCOPE_MISMATCH`, `POLICY_SCOPE_MISMATCH`,
//!     `USER_SCOPE_MISMATCH`, `ENVIRONMENT_SCOPE_MISMATCH`,
//!     `TOO_MANY_MACHINES`, `TOO_MANY_CORES`, `TOO_MUCH_MEMORY`,
//!     `TOO_MUCH_DISK`, `TOO_MANY_PROCESSES`, `TOO_MANY_USES`.
//!   - ⛔ `NOT_FOUND` — never emitted; the handler returns HTTP 404 directly
//!     instead of this code.
//!   - ⛔ Declared but never wired into any validation path (9): `BANNED`,
//!     `ENTITLEMENTS_MISSING`, `TOO_MANY_USERS`, `HEARTBEAT_DEAD`,
//!     `HEARTBEAT_NOT_STARTED`, `FINGERPRINT_SCOPE_MISMATCH`,
//!     `COMPONENTS_SCOPE_MISMATCH`, `CHECKSUM_SCOPE_MISMATCH`,
//!     `VERSION_SCOPE_MISMATCH`.

/// Scope constraints for `validate_by_id`. Stub — see module doc comment.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScopeObject {
    _private: (),
}

/// `{ ts, valid, detail, code }` returned alongside a license resource on
/// the validate-by-key/by-id endpoints. Stub.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ValidationMeta {
    _private: (),
}

/// All 24 server-declared validation codes. Stub — real variants land with
/// the `#[serde(other)]` fallback described in the module doc comment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub enum ValidationCode {
    /// Placeholder — replaced by the real 24-variant enum.
    #[serde(other)]
    Unknown,
}
