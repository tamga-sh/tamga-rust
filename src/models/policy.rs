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

/// Signing scheme used for license/machine checkout files and (always,
/// regardless of this value) machine offline proofs.
///
/// The wire field (`license.scheme`/`policy.scheme`) is `Option<String>` —
/// `None` or `""` means "legacy plain/unsigned key" and has **no**
/// corresponding variant here. When generating a **machine** file the
/// server defaults an unset scheme to [`LicenseScheme::Ed25519Sign`] (see
/// `tamga-api/src/features/machines/check_out_machine.rs`); callers of
/// [`crate::checkout::machine_file::verify_machine_file`] whose license has
/// no `scheme` set must pass `Ed25519Sign` to match, not skip verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseScheme {
    /// Ed25519 signature. The machine-file default when a license has no
    /// `scheme` set.
    Ed25519Sign,
    /// RSA-2048 PKCS#1 v1.5 / SHA-256.
    Rsa2048Pkcs1Sign,
    /// RSA-2048 PSS / SHA-256.
    Rsa2048Pkcs1PssSign,
    /// ECDSA P-256 / SHA-256 (ASN.1 DER signature).
    EcdsaP256Sign,
    /// RS256-signed JWT. **Not supported for machine file checkout** — the
    /// server returns `422 SCHEME_NOT_SUPPORTED`; a verifier must reject
    /// this scheme up front rather than attempt JWT parsing.
    Rsa2048JwtRs256,
}

impl LicenseScheme {
    /// Parses the wire string (`license.scheme`/`policy.scheme`, when
    /// `Some`). Returns `None` for an unrecognized string, mirroring the
    /// server's own `LicenseScheme::from_str` — this crate has no
    /// `Unknown` fallback variant for a scheme, since an unrecognized
    /// signing algorithm can't be dispatched to any verifier.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ED25519_SIGN" => Some(LicenseScheme::Ed25519Sign),
            "RSA_2048_PKCS1_SIGN" => Some(LicenseScheme::Rsa2048Pkcs1Sign),
            "RSA_2048_PKCS1_PSS_SIGN" => Some(LicenseScheme::Rsa2048Pkcs1PssSign),
            "ECDSA_P256_SIGN" => Some(LicenseScheme::EcdsaP256Sign),
            "RSA_2048_JWT_RS256" => Some(LicenseScheme::Rsa2048JwtRs256),
            _ => None,
        }
    }
}

#[cfg(test)]
mod license_scheme_tests {
    use super::*;

    #[test]
    fn parses_all_5_known_wire_strings() {
        assert_eq!(
            LicenseScheme::parse("ED25519_SIGN"),
            Some(LicenseScheme::Ed25519Sign)
        );
        assert_eq!(
            LicenseScheme::parse("RSA_2048_PKCS1_SIGN"),
            Some(LicenseScheme::Rsa2048Pkcs1Sign)
        );
        assert_eq!(
            LicenseScheme::parse("RSA_2048_PKCS1_PSS_SIGN"),
            Some(LicenseScheme::Rsa2048Pkcs1PssSign)
        );
        assert_eq!(
            LicenseScheme::parse("ECDSA_P256_SIGN"),
            Some(LicenseScheme::EcdsaP256Sign)
        );
        assert_eq!(
            LicenseScheme::parse("RSA_2048_JWT_RS256"),
            Some(LicenseScheme::Rsa2048JwtRs256)
        );
    }

    #[test]
    fn rejects_unrecognized_scheme_string() {
        assert_eq!(LicenseScheme::parse("BOGUS"), None);
        assert_eq!(LicenseScheme::parse(""), None);
    }
}

/// Overage handling for machine/core/memory/disk/process limits — how far
/// over `policy.max_*` a count is still permitted before validation fails
/// with the corresponding `TooMany*`/`TooMuch*`
/// [`crate::models::validation::ValidationCode`].
///
/// Multiplies the relevant limit before comparing; applies to
/// machines/cores/memory/disk/processes — **not** to `uses` (server always
/// enforces strict `count >= max_uses` for uses, regardless of strategy).
///
/// Deserializes any unrecognized wire value to [`OverageStrategy::NoOverage`]
/// rather than erroring — this mirrors the server's own fallback behavior
/// (`Policy::overage_strategy_parsed()`), which matters because
/// policy-create currently defaults new policies to the **non-existent**
/// string `"DENY_ACCESS"`; the server itself silently treats that as
/// `NoOverage`; an SDK that hard-fails on it would be stricter than the
/// server it's talking to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverageStrategy {
    /// Enforce the limit strictly — no activations beyond max (`count <=
    /// max`). Also the fallback for any unrecognized wire value.
    NoOverage,
    /// Allow up to 125% of the limit (`count <= max * 1.25`).
    Allow1_25xOverage,
    /// Allow up to 150% of the limit (`count <= max * 1.5`).
    Allow1_5xOverage,
    /// Allow up to 200% of the limit (`count <= max * 2.0`).
    Allow2xOverage,
    /// Skip limit enforcement entirely — always allowed.
    AlwaysAllowOverage,
}

impl OverageStrategy {
    /// Returns whether `count` is permitted under this strategy given a
    /// `max` limit. Mirrors the server's own `OverageStrategy::allows`
    /// exactly (including its `f64` multiplication), so a caller
    /// client-side pre-check reaches the identical verdict.
    pub fn allows(self, count: i64, max: i64) -> bool {
        match self {
            OverageStrategy::NoOverage => count <= max,
            OverageStrategy::Allow1_25xOverage => (count as f64) <= (max as f64) * 1.25,
            OverageStrategy::Allow1_5xOverage => (count as f64) <= (max as f64) * 1.5,
            OverageStrategy::Allow2xOverage => (count as f64) <= (max as f64) * 2.0,
            OverageStrategy::AlwaysAllowOverage => true,
        }
    }
}

impl<'de> serde::Deserialize<'de> for OverageStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "NO_OVERAGE" => OverageStrategy::NoOverage,
            "ALLOW_1_25X_OVERAGE" => OverageStrategy::Allow1_25xOverage,
            "ALLOW_1_5X_OVERAGE" => OverageStrategy::Allow1_5xOverage,
            "ALLOW_2X_OVERAGE" => OverageStrategy::Allow2xOverage,
            "ALWAYS_ALLOW_OVERAGE" => OverageStrategy::AlwaysAllowOverage,
            _ => OverageStrategy::NoOverage,
        })
    }
}

#[cfg(test)]
mod overage_strategy_tests {
    use super::*;

    #[test]
    fn deserializes_all_5_known_wire_strings() {
        let cases = [
            ("\"NO_OVERAGE\"", OverageStrategy::NoOverage),
            (
                "\"ALLOW_1_25X_OVERAGE\"",
                OverageStrategy::Allow1_25xOverage,
            ),
            ("\"ALLOW_1_5X_OVERAGE\"", OverageStrategy::Allow1_5xOverage),
            ("\"ALLOW_2X_OVERAGE\"", OverageStrategy::Allow2xOverage),
            (
                "\"ALWAYS_ALLOW_OVERAGE\"",
                OverageStrategy::AlwaysAllowOverage,
            ),
        ];
        for (wire, expected) in cases {
            let parsed: OverageStrategy = serde_json::from_str(wire).unwrap();
            assert_eq!(parsed, expected, "wire value {wire}");
        }
    }

    #[test]
    fn falls_back_to_no_overage_for_unrecognized_value() {
        // Reproduces the real "DENY_ACCESS" policy-create-default gotcha.
        let parsed: OverageStrategy = serde_json::from_str("\"DENY_ACCESS\"").unwrap();
        assert_eq!(parsed, OverageStrategy::NoOverage);
    }

    #[test]
    fn no_overage_blocks_at_max_plus_one() {
        assert!(!OverageStrategy::NoOverage.allows(11, 10));
        assert!(OverageStrategy::NoOverage.allows(10, 10));
    }

    #[test]
    fn allow_1_25x_permits_within_allowance_and_blocks_excess() {
        assert!(OverageStrategy::Allow1_25xOverage.allows(12, 10));
        assert!(!OverageStrategy::Allow1_25xOverage.allows(13, 10));
    }

    #[test]
    fn allow_1_5x_permits_within_allowance() {
        assert!(OverageStrategy::Allow1_5xOverage.allows(15, 10));
    }

    #[test]
    fn allow_2x_permits_within_allowance() {
        assert!(OverageStrategy::Allow2xOverage.allows(20, 10));
    }

    #[test]
    fn always_allow_permits_any_count() {
        assert!(OverageStrategy::AlwaysAllowOverage.allows(9999, 1));
    }
}

/// What happens to a machine row once its heartbeat window elapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HeartbeatCullStrategy {
    /// The machine row is deleted once dead.
    DeactivateDead,
    /// The dead machine row is kept — the license owner can still see it.
    KeepDead,
}

/// How long after heartbeat expiry a dead machine may still be revived by a
/// new ping, before [`HeartbeatCullStrategy`] takes effect.
///
/// Deserializes any unrecognized wire value to
/// [`HeartbeatResurrectionStrategy::NoRevive`] rather than erroring — same
/// rationale as [`OverageStrategy`]'s fallback: freshly-created policies
/// currently default this field to the **non-existent** string
/// `"NO_RESURRECTION"`, which the server itself silently treats as
/// `NoRevive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatResurrectionStrategy {
    /// Resurrection never allowed. Also the fallback for any unrecognized
    /// wire value (including the real-world `"NO_RESURRECTION"` default
    /// bug).
    NoRevive,
    /// Revivable within 1 minute of expiry.
    OneMinuteRevive,
    /// Revivable within 2 minutes of expiry.
    TwoMinuteRevive,
    /// Revivable within 5 minutes of expiry.
    FiveMinuteRevive,
    /// Revivable within 10 minutes of expiry.
    TenMinuteRevive,
    /// Revivable within 15 minutes of expiry.
    FifteenMinuteRevive,
    /// Always revivable, regardless of how long dead.
    AlwaysRevive,
}

impl<'de> serde::Deserialize<'de> for HeartbeatResurrectionStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "NO_REVIVE" => HeartbeatResurrectionStrategy::NoRevive,
            "1_MINUTE_REVIVE" => HeartbeatResurrectionStrategy::OneMinuteRevive,
            "2_MINUTE_REVIVE" => HeartbeatResurrectionStrategy::TwoMinuteRevive,
            "5_MINUTE_REVIVE" => HeartbeatResurrectionStrategy::FiveMinuteRevive,
            "10_MINUTE_REVIVE" => HeartbeatResurrectionStrategy::TenMinuteRevive,
            "15_MINUTE_REVIVE" => HeartbeatResurrectionStrategy::FifteenMinuteRevive,
            "ALWAYS_REVIVE" => HeartbeatResurrectionStrategy::AlwaysRevive,
            _ => HeartbeatResurrectionStrategy::NoRevive,
        })
    }
}

#[cfg(test)]
mod heartbeat_strategy_tests {
    use super::*;

    #[test]
    fn cull_strategy_deserializes_both_known_wire_strings() {
        let deactivate: HeartbeatCullStrategy =
            serde_json::from_str("\"DEACTIVATE_DEAD\"").unwrap();
        assert_eq!(deactivate, HeartbeatCullStrategy::DeactivateDead);
        let keep: HeartbeatCullStrategy = serde_json::from_str("\"KEEP_DEAD\"").unwrap();
        assert_eq!(keep, HeartbeatCullStrategy::KeepDead);
    }

    #[test]
    fn resurrection_strategy_deserializes_all_7_known_wire_strings() {
        let cases = [
            ("\"NO_REVIVE\"", HeartbeatResurrectionStrategy::NoRevive),
            (
                "\"1_MINUTE_REVIVE\"",
                HeartbeatResurrectionStrategy::OneMinuteRevive,
            ),
            (
                "\"2_MINUTE_REVIVE\"",
                HeartbeatResurrectionStrategy::TwoMinuteRevive,
            ),
            (
                "\"5_MINUTE_REVIVE\"",
                HeartbeatResurrectionStrategy::FiveMinuteRevive,
            ),
            (
                "\"10_MINUTE_REVIVE\"",
                HeartbeatResurrectionStrategy::TenMinuteRevive,
            ),
            (
                "\"15_MINUTE_REVIVE\"",
                HeartbeatResurrectionStrategy::FifteenMinuteRevive,
            ),
            (
                "\"ALWAYS_REVIVE\"",
                HeartbeatResurrectionStrategy::AlwaysRevive,
            ),
        ];
        for (wire, expected) in cases {
            let parsed: HeartbeatResurrectionStrategy = serde_json::from_str(wire).unwrap();
            assert_eq!(parsed, expected, "wire value {wire}");
        }
    }

    #[test]
    fn resurrection_strategy_falls_back_to_no_revive_for_unrecognized_value() {
        // Reproduces the real "NO_RESURRECTION" policy-create-default gotcha.
        let parsed: HeartbeatResurrectionStrategy =
            serde_json::from_str("\"NO_RESURRECTION\"").unwrap();
        assert_eq!(parsed, HeartbeatResurrectionStrategy::NoRevive);
    }
}

/// The full `policies` JSON:API resource. Stub — see module doc comment.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Policy {
    _private: (),
}
