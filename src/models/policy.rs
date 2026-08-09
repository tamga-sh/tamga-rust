//! `Policy` and its enums — the policy-derived behavior reference an SDK
//! needs to interpret a license, not just its `ValidationCode`.
//!
//! Intended contents (see `docs/plans/tamga-rust.plan.md` §C, §F, §G, §K):
//!
//! - `LicenseScheme`: `ED25519_SIGN`, `RSA_2048_PKCS1_SIGN`,
//!   `RSA_2048_PKCS1_PSS_SIGN`, `ECDSA_P256_SIGN`, `RSA_2048_JWT_RS256`, plus
//!   `None`/unset (legacy plain key string, unsigned).
//! - `OverageStrategy`: `NO_OVERAGE`, `ALLOW_1_25X_OVERAGE`,
//!   `ALLOW_1_5X_OVERAGE`, `ALLOW_2X_OVERAGE`, `ALWAYS_ALLOW_OVERAGE`.
//!   Multiplies the relevant `max_*` limit before comparing; applies to
//!   machines/cores/memory/disk/processes — **not** to `uses` (always
//!   strict `>=` regardless of strategy).
//! - `HeartbeatCullStrategy`: `DEACTIVATE_DEAD` (row deleted), `KEEP_DEAD`
//!   (row kept).
//! - `HeartbeatResurrectionStrategy`: `NO_REVIVE`, `1_MINUTE_REVIVE`,
//!   `2_MINUTE_REVIVE`, `5_MINUTE_REVIVE`, `10_MINUTE_REVIVE`,
//!   `15_MINUTE_REVIVE`, `ALWAYS_REVIVE`.
//! - `check_in_interval`: lowercase wire values (`"day"`, `"week"`,
//!   `"month"`, `"year"`) — inconsistent casing vs. the `SCREAMING_SNAKE_CASE`
//!   used elsewhere; model with `#[serde(rename_all = "lowercase")]` rather
//!   than assuming the same casing convention as the other enums.
//! - Free-text, branch-on-literal fields — model as open string newtypes
//!   with named associated constants, **not** closed enums (the server
//!   branches on literal string match; treat any unrecognized value as
//!   "deny/default"):
//!   - `expiration_strategy`: `"RESTRICT_ACCESS"` (default),
//!     `"MAINTAIN_ACCESS"`, `"ALLOW_ACCESS"`.
//!   - `renewal_basis`: `"FROM_EXPIRY"` (default), `"FROM_NOW"`.
//!   - `authentication_strategy`: `"TOKEN"` (default), `"LICENSE"`,
//!     `"MIXED"`.
//! - ⚠️ Policy-create defaults reference **non-existent** enum variants:
//!   new policies default `overage_strategy` to `"DENY_ACCESS"` (not a real
//!   `OverageStrategy` variant — silently behaves as `NO_OVERAGE`) and
//!   `heartbeat_resurrection_strategy` to `"NO_RESURRECTION"` (not a real
//!   variant — silently behaves as `NO_REVIVE`). Do not trust a freshly
//!   created policy's declared default string; treat unrecognized values as
//!   the "no restriction" variant to match actual server behavior.
//! - `Policy` full field set: `max_machines`, `max_cores`, `max_memory`,
//!   `max_disk`, `max_processes`, `max_uses`, `overage_strategy`,
//!   `heartbeat_cull_strategy`, `heartbeat_resurrection_strategy`,
//!   `heartbeat_duration`, `require_check_in`, `check_in_interval`,
//!   `expiration_strategy`, `renewal_basis`, `authentication_strategy`,
//!   `scheme`. The `GET` response **omits `max_memory` and `max_disk`** even
//!   though both are enforced during validation — model both as
//!   `Option<i64>` and expect `None` from the server today; the SDK cannot
//!   introspect these two limits client-side, only observe
//!   `TOO_MUCH_MEMORY`/`TOO_MUCH_DISK` on a failed validation.

/// Signing scheme for checkout/license keys. Stub — see module doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum LicenseScheme {
    /// Placeholder — replaced by the real 5-variant-plus-`None` enum.
    #[serde(other)]
    Unknown,
}

/// Overage handling for machine/core/memory/disk/process limits. Stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum OverageStrategy {
    /// Placeholder — replaced by the real 5-variant enum.
    #[serde(other)]
    Unknown,
}

/// Dead-machine culling behavior. Stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum HeartbeatCullStrategy {
    /// Placeholder — replaced by the real 2-variant enum.
    #[serde(other)]
    Unknown,
}

/// Dead-machine resurrection grace window. Stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum HeartbeatResurrectionStrategy {
    /// Placeholder — replaced by the real 7-variant enum.
    #[serde(other)]
    Unknown,
}

/// The full `policies` JSON:API resource. Stub — see module doc comment.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Policy {
    _private: (),
}
