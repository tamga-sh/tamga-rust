//! `ScopeObject`, `ValidationMeta`, and `ValidationCode`.
//!
//! Contents:
//!
//! - `ScopeObject`: 8 optional fields — `product`, `policy`, `user`,
//!   `environment` (`Uuid`), `entitlements` (`Vec<String>`), `fingerprint`,
//!   `version`, `checksum` (`String`). Six are enforced server-side:
//!   `product`, `policy`, `user`, `environment`, `entitlements` and
//!   `fingerprint`. The remaining two, `version` and `checksum`, are
//!   **refused**: setting either fails the entire validate call with
//!   `422 SCOPE_NOT_SUPPORTED` before any check runs, so the caller never
//!   sees a `meta.valid` at all. They are therefore never serialized — see
//!   `ScopeObject`'s own doc comment. Enforced fields serialize with
//!   `skip_serializing_if = "Option::is_none"` so unset ones are omitted
//!   from the request body.
//! - `ValidationMeta`: `{ ts, valid, detail, code }`.
//! - `ValidationCode`: all **24** variants, with a `#[serde(other)]
//!   Unknown(String)` fallback for lenient deserialization of any future
//!   server-side addition.
//!   - ✅ Reachable today (16): `VALID`, `SUSPENDED`, `EXPIRED`, `OVERDUE`,
//!     `PRODUCT_SCOPE_MISMATCH`, `POLICY_SCOPE_MISMATCH`,
//!     `USER_SCOPE_MISMATCH`, `ENVIRONMENT_SCOPE_MISMATCH`,
//!     `FINGERPRINT_SCOPE_MISMATCH`, `ENTITLEMENTS_MISSING`,
//!     `TOO_MANY_MACHINES`, `TOO_MANY_CORES`, `TOO_MUCH_MEMORY`,
//!     `TOO_MUCH_DISK`, `TOO_MANY_PROCESSES`, `TOO_MANY_USES`.
//!   - ⛔ `NOT_FOUND` — never emitted; the handler returns HTTP 404 directly
//!     instead of this code.
//!   - ⛔ Declared but never wired into any validation path (7): `BANNED`,
//!     `TOO_MANY_USERS`, `HEARTBEAT_DEAD`, `HEARTBEAT_NOT_STARTED`,
//!     `COMPONENTS_SCOPE_MISMATCH`, `CHECKSUM_SCOPE_MISMATCH`,
//!     `VERSION_SCOPE_MISMATCH`. The last two are structurally
//!     unreachable — the scope fields that would produce them are rejected
//!     with `422 SCOPE_NOT_SUPPORTED` first.

/// Scope constraints for `validate_by_id`, sent as `meta.scope` in the
/// request body. Every field is optional — `None` means "no constraint,
/// skip this check" (mirrors the server's `ValidationScope`).
///
/// Six of the eight are enforced server-side: `product`, `policy`, `user`,
/// `environment`, `entitlements` and `fingerprint`.
///
/// `version` and `checksum` are **refused**, not ignored. The server has
/// nothing to compare either against, and rather than let a scope silently
/// pass (which then gets relied on) it fails the whole call with
/// `422 SCOPE_NOT_SUPPORTED` before running any validation — so a caller
/// that sets one gets no `meta.valid` back at all. Both fields are
/// consequently **never serialized into the request body**: they are kept
/// as deserializable members so existing code that reads or assigns them
/// still compiles, but assigning one now degrades to a working, unscoped
/// validate instead of a hard failure. They are deprecated; drop them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScopeObject {
    /// Enforced. Must match the license's product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<uuid::Uuid>,
    /// Enforced. Must match the license's policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<uuid::Uuid>,
    /// Enforced. Must match the license's owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<uuid::Uuid>,
    /// Enforced. Must match the license's environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<uuid::Uuid>,
    /// Enforced. Entitlement **codes** (the stable developer-facing
    /// identifier), not the entitlement UUIDs that attach/detach bodies
    /// take. Compared case-insensitively and de-duplicated server-side,
    /// and satisfied by directly-attached *and* policy-inherited
    /// entitlements alike. An empty vec asserts nothing. A license missing
    /// any one of them validates as
    /// [`ValidationCode::EntitlementsMissing`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlements: Option<Vec<String>>,
    /// Enforced. Matches when **any** machine on this license carries this
    /// fingerprint, regardless of that machine's heartbeat status. This is
    /// the anti-key-sharing check: pass the activating machine's own
    /// fingerprint to assert the license is being validated from a machine
    /// it knows about. A mismatch validates as
    /// [`ValidationCode::FingerprintScopeMismatch`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// **Deprecated and never sent.** Setting this used to be a silent
    /// no-op; the server now answers `422 SCOPE_NOT_SUPPORTED` and fails
    /// the whole validate call, so this SDK omits the field from the
    /// request body entirely. See the struct's doc comment.
    #[serde(skip_serializing)]
    pub version: Option<String>,
    /// **Deprecated and never sent.** Same as `version` — the server
    /// answers `422 SCOPE_NOT_SUPPORTED`, so this SDK omits the field. See
    /// the struct's doc comment.
    #[serde(skip_serializing)]
    pub checksum: Option<String>,
}

/// Combined response of `validate_by_key`/`validate_by_id`: the (possibly
/// touched) license resource plus the validation outcome. Quick-validate
/// returns only a bare [`ValidationMeta`] — it has no `data` envelope.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// The license resource as of this validation call (reflects
    /// `last_validated_at` being bumped, unless `skip_touch: true` was
    /// sent).
    pub license: crate::models::license::LicenseResource,
    /// The validation outcome.
    pub meta: ValidationMeta,
}

/// `{ ts, valid, detail, code }` returned alongside a license resource on
/// the validate-by-key/by-id endpoints, and as the entire flat body on
/// quick-validate.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ValidationMeta {
    /// Server timestamp the validation ran at.
    pub ts: chrono::DateTime<chrono::Utc>,
    /// Whether the license passed all checks.
    pub valid: bool,
    /// Human-readable explanation — may change wording; match on `code`
    /// instead for stable programmatic handling.
    pub detail: String,
    /// Stable, machine-matchable outcome code.
    pub code: ValidationCode,
}

/// All 24 server-declared validation codes, evaluated in priority order for
/// the by-ID endpoint. Deserializes any unrecognized wire value into
/// `Unknown(String)` rather than failing, so a future server-side addition
/// doesn't hard-break this SDK.
///
/// - ✅ Reachable today (16): `Valid`, `Suspended`, `Expired`, `Overdue`,
///   `ProductScopeMismatch`, `PolicyScopeMismatch`, `UserScopeMismatch`,
///   `EnvironmentScopeMismatch`, `FingerprintScopeMismatch`,
///   `EntitlementsMissing`, `TooManyMachines`, `TooManyCores`,
///   `TooMuchMemory`, `TooMuchDisk`, `TooManyProcesses`, `TooManyUses`.
/// - ⛔ `NotFound` — never emitted; the handler returns HTTP 404 directly.
/// - ⛔ Declared but never wired into any validation path (7): `Banned`,
///   `TooManyUsers`, `HeartbeatDead`, `HeartbeatNotStarted`,
///   `ComponentsScopeMismatch`, `ChecksumScopeMismatch`,
///   `VersionScopeMismatch`.
///
/// The five over-limit codes (`TooManyMachines`, `TooManyCores`,
/// `TooMuchMemory`, `TooMuchDisk`, `TooManyProcesses`) have create-time
/// twins: under a strict overage strategy the server refuses registration
/// with a `422` instead, which this SDK classifies as a
/// [`crate::error::LimitExceededCode`] and can normalize back onto the
/// matching variant here via
/// [`crate::error::LimitExceededCode::as_validation_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationCode {
    /// ✅ All checks passed.
    Valid,
    /// ⛔ Declared, never emitted — the handler 404s instead.
    NotFound,
    /// ⛔ Declared, not wired into any validation path yet.
    Banned,
    /// ✅ `license.suspended == true`.
    Suspended,
    /// ✅ `expiry < now`.
    Expired,
    /// ✅ Check-in required and the window has elapsed.
    Overdue,
    /// ✅ `scope.entitlements` set and the license (counting both directly
    /// attached and policy-inherited rows) does not hold every listed code.
    EntitlementsMissing,
    /// ✅ Machine count over `policy.max_machines` (per overage strategy).
    /// A strict strategy refuses the machine at creation time instead —
    /// see [`crate::error::LimitExceededCode::MachineLimitExceeded`].
    TooManyMachines,
    /// ✅ Core count over `policy.max_cores`.
    TooManyCores,
    /// ✅ Memory over `policy.max_memory`.
    TooMuchMemory,
    /// ✅ Disk over `policy.max_disk`.
    TooMuchDisk,
    /// ✅ Process count over `policy.max_processes`.
    TooManyProcesses,
    /// ⛔ Declared, not wired into any validation path yet.
    TooManyUsers,
    /// ⛔ Declared, not wired into any validation path yet.
    HeartbeatDead,
    /// ⛔ Declared, not wired into any validation path yet.
    HeartbeatNotStarted,
    /// ✅ `scope.product` set and mismatched.
    ProductScopeMismatch,
    /// ✅ `scope.policy` set and mismatched.
    PolicyScopeMismatch,
    /// ✅ `scope.user` set and mismatched.
    UserScopeMismatch,
    /// ✅ `scope.fingerprint` set and no machine on this license carries
    /// it.
    FingerprintScopeMismatch,
    /// ⛔ Declared, not wired into any validation path yet.
    ComponentsScopeMismatch,
    /// ⛔ Structurally unreachable — `scope.checksum` is refused with
    /// `422 SCOPE_NOT_SUPPORTED` before validation runs.
    ChecksumScopeMismatch,
    /// ⛔ Structurally unreachable — `scope.version` is refused with
    /// `422 SCOPE_NOT_SUPPORTED` before validation runs.
    VersionScopeMismatch,
    /// ✅ `scope.environment` set and mismatched.
    EnvironmentScopeMismatch,
    /// ✅ `uses >= max_uses`, strict `>=` regardless of overage strategy.
    TooManyUses,
    /// Any wire value not matching a known variant above — lenient
    /// deserialization for forward-compatibility with future server codes.
    Unknown(String),
}

impl<'de> serde::Deserialize<'de> for ValidationCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "VALID" => ValidationCode::Valid,
            "NOT_FOUND" => ValidationCode::NotFound,
            "BANNED" => ValidationCode::Banned,
            "SUSPENDED" => ValidationCode::Suspended,
            "EXPIRED" => ValidationCode::Expired,
            "OVERDUE" => ValidationCode::Overdue,
            "ENTITLEMENTS_MISSING" => ValidationCode::EntitlementsMissing,
            "TOO_MANY_MACHINES" => ValidationCode::TooManyMachines,
            "TOO_MANY_CORES" => ValidationCode::TooManyCores,
            "TOO_MUCH_MEMORY" => ValidationCode::TooMuchMemory,
            "TOO_MUCH_DISK" => ValidationCode::TooMuchDisk,
            "TOO_MANY_PROCESSES" => ValidationCode::TooManyProcesses,
            "TOO_MANY_USERS" => ValidationCode::TooManyUsers,
            "HEARTBEAT_DEAD" => ValidationCode::HeartbeatDead,
            "HEARTBEAT_NOT_STARTED" => ValidationCode::HeartbeatNotStarted,
            "PRODUCT_SCOPE_MISMATCH" => ValidationCode::ProductScopeMismatch,
            "POLICY_SCOPE_MISMATCH" => ValidationCode::PolicyScopeMismatch,
            "USER_SCOPE_MISMATCH" => ValidationCode::UserScopeMismatch,
            "FINGERPRINT_SCOPE_MISMATCH" => ValidationCode::FingerprintScopeMismatch,
            "COMPONENTS_SCOPE_MISMATCH" => ValidationCode::ComponentsScopeMismatch,
            "CHECKSUM_SCOPE_MISMATCH" => ValidationCode::ChecksumScopeMismatch,
            "VERSION_SCOPE_MISMATCH" => ValidationCode::VersionScopeMismatch,
            "ENVIRONMENT_SCOPE_MISMATCH" => ValidationCode::EnvironmentScopeMismatch,
            "TOO_MANY_USES" => ValidationCode::TooManyUses,
            other => ValidationCode::Unknown(other.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_known_wire_pairs() -> Vec<(&'static str, ValidationCode)> {
        vec![
            ("VALID", ValidationCode::Valid),
            ("NOT_FOUND", ValidationCode::NotFound),
            ("BANNED", ValidationCode::Banned),
            ("SUSPENDED", ValidationCode::Suspended),
            ("EXPIRED", ValidationCode::Expired),
            ("OVERDUE", ValidationCode::Overdue),
            ("ENTITLEMENTS_MISSING", ValidationCode::EntitlementsMissing),
            ("TOO_MANY_MACHINES", ValidationCode::TooManyMachines),
            ("TOO_MANY_CORES", ValidationCode::TooManyCores),
            ("TOO_MUCH_MEMORY", ValidationCode::TooMuchMemory),
            ("TOO_MUCH_DISK", ValidationCode::TooMuchDisk),
            ("TOO_MANY_PROCESSES", ValidationCode::TooManyProcesses),
            ("TOO_MANY_USERS", ValidationCode::TooManyUsers),
            ("HEARTBEAT_DEAD", ValidationCode::HeartbeatDead),
            ("HEARTBEAT_NOT_STARTED", ValidationCode::HeartbeatNotStarted),
            (
                "PRODUCT_SCOPE_MISMATCH",
                ValidationCode::ProductScopeMismatch,
            ),
            ("POLICY_SCOPE_MISMATCH", ValidationCode::PolicyScopeMismatch),
            ("USER_SCOPE_MISMATCH", ValidationCode::UserScopeMismatch),
            (
                "FINGERPRINT_SCOPE_MISMATCH",
                ValidationCode::FingerprintScopeMismatch,
            ),
            (
                "COMPONENTS_SCOPE_MISMATCH",
                ValidationCode::ComponentsScopeMismatch,
            ),
            (
                "CHECKSUM_SCOPE_MISMATCH",
                ValidationCode::ChecksumScopeMismatch,
            ),
            (
                "VERSION_SCOPE_MISMATCH",
                ValidationCode::VersionScopeMismatch,
            ),
            (
                "ENVIRONMENT_SCOPE_MISMATCH",
                ValidationCode::EnvironmentScopeMismatch,
            ),
            ("TOO_MANY_USES", ValidationCode::TooManyUses),
        ]
    }

    #[test]
    fn deserializes_all_24_known_wire_strings() {
        let pairs = all_known_wire_pairs();
        assert_eq!(pairs.len(), 24, "must cover all 24 server-declared codes");
        for (wire, expected) in pairs {
            let json = format!("\"{wire}\"");
            let parsed: ValidationCode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, expected, "wire value {wire}");
        }
    }

    #[test]
    fn deserializes_unknown_value_to_unknown_variant() {
        let parsed: ValidationCode = serde_json::from_str("\"SOME_FUTURE_CODE\"").unwrap();
        assert_eq!(
            parsed,
            ValidationCode::Unknown("SOME_FUTURE_CODE".to_string())
        );
    }

    #[test]
    fn scope_object_serializes_only_set_fields() {
        let scope = ScopeObject {
            product: Some(uuid::Uuid::nil()),
            ..Default::default()
        };
        let value = serde_json::to_value(&scope).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.len(), 1, "only `product` was set: {obj:?}");
        assert!(obj.contains_key("product"));
    }

    #[test]
    fn scope_object_never_serializes_the_two_refused_fields() {
        // Setting either used to be a harmless no-op. It now fails the
        // whole validate call with 422 SCOPE_NOT_SUPPORTED, so a caller
        // that still sets one must degrade to an unscoped validate rather
        // than to no validate at all.
        let scope = ScopeObject {
            product: Some(uuid::Uuid::nil()),
            version: Some("1.2.3".to_string()),
            checksum: Some("deadbeef".to_string()),
            ..Default::default()
        };
        let value = serde_json::to_value(&scope).unwrap();
        assert_eq!(value, serde_json::json!({ "product": uuid::Uuid::nil() }));
    }

    #[test]
    fn scope_object_still_deserializes_the_two_refused_fields() {
        // Skipped on the way out, not on the way in — round-tripping a
        // stored scope must not silently drop what the caller wrote.
        let scope: ScopeObject =
            serde_json::from_value(serde_json::json!({ "version": "1.2.3" })).unwrap();
        assert_eq!(scope.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn scope_object_serializes_the_enforced_entitlements_and_fingerprint() {
        let scope = ScopeObject {
            entitlements: Some(vec!["pro".to_string()]),
            fingerprint: Some("fp-abc123".to_string()),
            ..Default::default()
        };
        let value = serde_json::to_value(&scope).unwrap();
        assert_eq!(
            value,
            serde_json::json!({ "entitlements": ["pro"], "fingerprint": "fp-abc123" })
        );
    }

    #[test]
    fn scope_object_empty_serializes_to_empty_object() {
        let scope = ScopeObject::default();
        let value = serde_json::to_value(&scope).unwrap();
        assert_eq!(value, serde_json::json!({}));
    }

    #[test]
    fn validation_meta_deserializes_from_representative_response() {
        let json = serde_json::json!({
            "ts": "2026-01-01T00:00:00Z",
            "valid": true,
            "detail": "is valid",
            "code": "VALID",
        });
        let meta: ValidationMeta = serde_json::from_value(json).unwrap();
        assert!(meta.valid);
        assert_eq!(meta.detail, "is valid");
        assert_eq!(meta.code, ValidationCode::Valid);
    }
}
