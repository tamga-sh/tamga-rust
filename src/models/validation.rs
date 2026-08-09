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

/// Scope constraints for `validate_by_id`, sent as `meta.scope` in the
/// request body. Every field is optional — `None` means "no constraint,
/// skip this check" (mirrors the server's `ValidationScope`).
///
/// Only `product`/`policy`/`user`/`environment` are enforced server-side
/// today; `entitlements`/`fingerprint`/`version`/`checksum` are parsed and
/// silently ignored. Kept here for forward-compatibility — do not advertise
/// them as functioning constraints.
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
    /// Not enforced server-side yet — parsed and ignored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlements: Option<Vec<String>>,
    /// Not enforced server-side yet — parsed and ignored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Not enforced server-side yet — parsed and ignored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Not enforced server-side yet — parsed and ignored.
    #[serde(skip_serializing_if = "Option::is_none")]
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
/// - ✅ Reachable today (14): `Valid`, `Suspended`, `Expired`, `Overdue`,
///   `ProductScopeMismatch`, `PolicyScopeMismatch`, `UserScopeMismatch`,
///   `EnvironmentScopeMismatch`, `TooManyMachines`, `TooManyCores`,
///   `TooMuchMemory`, `TooMuchDisk`, `TooManyProcesses`, `TooManyUses`.
/// - ⛔ `NotFound` — never emitted; the handler returns HTTP 404 directly.
/// - ⛔ Declared but never wired into any validation path (9): `Banned`,
///   `EntitlementsMissing`, `TooManyUsers`, `HeartbeatDead`,
///   `HeartbeatNotStarted`, `FingerprintScopeMismatch`,
///   `ComponentsScopeMismatch`, `ChecksumScopeMismatch`,
///   `VersionScopeMismatch`.
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
    /// ⛔ Declared, not wired into any validation path yet.
    EntitlementsMissing,
    /// ✅ Machine count over `policy.max_machines` (per overage strategy).
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
    /// ⛔ Declared, not wired into any validation path yet.
    FingerprintScopeMismatch,
    /// ⛔ Declared, not wired into any validation path yet.
    ComponentsScopeMismatch,
    /// ⛔ Declared, not wired into any validation path yet.
    ChecksumScopeMismatch,
    /// ⛔ Declared, not wired into any validation path yet.
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
