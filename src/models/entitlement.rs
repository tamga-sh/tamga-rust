//! `EntitlementResource` and the licence-scoped [`LicenseEntitlement`].
//!
//! Fields: `name`, `code`, `kind`, `metadata`, `created`, `updated`.
//!
//! `code` is the stable, developer-facing identifier — `name` is just a
//! display label. [`crate::Client::has_entitlement`] matches on
//! `code`, never `name`. Despite the URL nesting under
//! `/licenses/{id}/entitlements`, these are full `Entitlement` resources,
//! not lightweight junction/relationship records.
//!
//! `kind` ([`EntitlementKind`]) is a required, always-present field: `Flag`
//! is a boolean grant (the only kind that existed before entitlement
//! metering), `Meter` is a named, per-license counter with an independent
//! cap. It is meaningful on every scope an entitlement is read from, so it
//! lives on the shared [`EntitlementAttributes`], not only on the
//! licence-scoped shape below.
//!
//! The licence-scoped **list** route (and the metering actions —
//! [`crate::Client::increment_entitlement_usage`],
//! [`crate::Client::decrement_entitlement_usage`],
//! [`crate::Client::reset_entitlement_usage`] — which return the same shape)
//! carry attributes the others do not: `inherited`, true when the licence
//! holds the entitlement through its policy rather than by a direct
//! attachment; `max_value`, the effective cap for a `kind: "meter"`
//! entitlement (nullable — `None` means unlimited, meaningless for a
//! `flag`); and `current_value`, the running count (`0` if never
//! incremented, which also means "only inherited, never directly attached"
//! — see [`LicenseEntitlementAttributes::current_value`]). `inherited`
//! decides what a caller can do with the row — an inherited entitlement
//! cannot be detached (`403 POLICY_ENTITLEMENT`), re-attaching it fails
//! (`422 ENTITLEMENT_ALREADY_INHERITED`), and, because the item route
//! resolves direct attachments only, `GET .../entitlements/{id}` on it
//! **404s**. Read it via [`crate::Client::list_license_entitlements`], which
//! returns [`LicenseEntitlement`]; [`EntitlementResource`] itself is shared
//! with the account-, policy- and release-scoped routes, where the server
//! emits none of `inherited`/`max_value`/`current_value`.

/// The `entitlements` JSON:API resource: `{ id, type, attributes }`. Field
/// set matches the Tamga API's actual full `EntitlementResource` serializer —
/// confirmed the license-scoped list/get endpoints return this, not the
/// lightweight `LicenseEntitlementResource` junction resource (which only
/// carries `created`/`updated` timestamps).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EntitlementResource {
    /// UUIDv7 entitlement ID.
    pub id: uuid::Uuid,
    /// Always `"entitlements"`.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The resource's attribute bag.
    pub attributes: EntitlementAttributes,
}

/// Attributes of an [`EntitlementResource`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EntitlementAttributes {
    /// Display label — **never** match on this; see `code`.
    pub name: String,
    /// The stable, developer-facing identifier. [`crate::Client::has_entitlement`]
    /// matches on this field, never `name`.
    pub code: String,
    /// Whether this entitlement is a boolean grant or a metered counter —
    /// see [`EntitlementKind`]. Required and always present, unlike this
    /// crate's usual `#[serde(default)]` additive fields: the server never
    /// omits it, on any scope.
    pub kind: EntitlementKind,
    /// Arbitrary caller-set metadata.
    pub metadata: serde_json::Value,
    /// Creation timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// Last-updated timestamp.
    pub updated: chrono::DateTime<chrono::Utc>,
}

/// Whether an [`EntitlementResource`] is a boolean grant or a named,
/// per-license counter with an independent cap.
///
/// Always present on the wire — never optional or defaulted, unlike most of
/// this crate's forward-compatible fields. Deserializes any unrecognized
/// wire value into `Unknown(String)` rather than failing, the same
/// hand-written approach (not `#[serde(other)]`, which only fits unit
/// variants and would drop the string) as
/// [`crate::models::validation::ValidationCode`] — so a future server-side
/// kind cannot hard-break deserialization of every entitlement response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntitlementKind {
    /// A boolean grant — the only kind that existed before entitlement
    /// metering. `max_value`/`current_value` on [`LicenseEntitlementAttributes`]
    /// are present but not enforced for a flag.
    Flag,
    /// A named, per-license counter with an independent cap. See
    /// [`LicenseEntitlementAttributes::max_value`]/
    /// [`LicenseEntitlementAttributes::current_value`] and
    /// [`crate::Client::increment_entitlement_usage`]/
    /// [`crate::Client::decrement_entitlement_usage`]/
    /// [`crate::Client::reset_entitlement_usage`].
    Meter,
    /// Any wire value not matching a known variant above — lenient
    /// deserialization for forward-compatibility with a future server-side
    /// kind.
    Unknown(String),
}

impl<'de> serde::Deserialize<'de> for EntitlementKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "flag" => EntitlementKind::Flag,
            "meter" => EntitlementKind::Meter,
            other => EntitlementKind::Unknown(other.to_string()),
        })
    }
}

#[cfg(test)]
mod entitlement_kind_tests {
    use super::*;

    #[test]
    fn deserializes_both_known_wire_strings() {
        let flag: EntitlementKind = serde_json::from_str("\"flag\"").unwrap();
        assert_eq!(flag, EntitlementKind::Flag);
        let meter: EntitlementKind = serde_json::from_str("\"meter\"").unwrap();
        assert_eq!(meter, EntitlementKind::Meter);
    }

    #[test]
    fn deserializes_unknown_value_to_unknown_variant() {
        let parsed: EntitlementKind = serde_json::from_str("\"future_kind\"").unwrap();
        assert_eq!(parsed, EntitlementKind::Unknown("future_kind".to_string()));
    }
}

/// One row of `GET /licenses/{id}/entitlements` — an
/// [`EntitlementResource`] plus the licence-scoped `inherited` flag the
/// shared resource type has no field for.
///
/// Returned by [`crate::Client::list_license_entitlements`]. The plain
/// [`crate::Client::list_entitlements`] parses the same response into bare
/// [`EntitlementResource`]s and drops the flag; use this variant whenever
/// the caller intends to act on a row (detach it, re-attach it, or fetch it
/// by id), because all three of those behave differently for an inherited
/// entitlement.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LicenseEntitlement {
    /// UUIDv7 entitlement ID.
    pub id: uuid::Uuid,
    /// Always `"entitlements"`.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The resource's attribute bag, including `inherited`.
    pub attributes: LicenseEntitlementAttributes,
}

/// Attributes of a [`LicenseEntitlement`] — [`EntitlementAttributes`] plus
/// `inherited`, `max_value` and `current_value`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LicenseEntitlementAttributes {
    /// Display label — **never** match on this; see `code`.
    pub name: String,
    /// The stable, developer-facing identifier.
    pub code: String,
    /// Whether this entitlement is a boolean grant or a metered counter —
    /// see [`EntitlementKind`]. Required and always present.
    pub kind: EntitlementKind,
    /// Arbitrary caller-set metadata.
    pub metadata: serde_json::Value,
    /// Creation timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// Last-updated timestamp.
    pub updated: chrono::DateTime<chrono::Utc>,
    /// `true` when the licence holds this through its **policy** rather
    /// than through a direct attachment.
    ///
    /// An inherited entitlement grants access exactly like a direct one,
    /// but it is not independently manageable: detaching it fails with
    /// `403 POLICY_ENTITLEMENT`, attaching it again fails with
    /// `422 ENTITLEMENT_ALREADY_INHERITED`, and
    /// [`crate::Client::get_entitlement`] answers `404` for it because the
    /// item route joins only the direct-attachment table. List-then-get-each
    /// is therefore not a valid pattern on this resource.
    ///
    /// Defaults to `false` if a server build omits the attribute — the flag
    /// exists only on this licence-scoped list route.
    #[serde(default)]
    pub inherited: bool,
    /// The *effective* cap for a `kind: "meter"` entitlement: the license's
    /// own override if it has one, else the policy's default, else `None` =
    /// unlimited. Same "nullable = unlimited" convention every other
    /// `max_*` field on `licenses`/`policies` uses. **Meaningless for
    /// `kind: "flag"`** — present but not enforced.
    ///
    /// `#[serde(default)]` so a server build that omits the attribute
    /// (pre-migration, or an account-/policy-scoped variant of this same
    /// struct elsewhere) degrades to `None` rather than failing the whole
    /// resource.
    #[serde(default)]
    pub max_value: Option<i32>,
    /// The running count for a `kind: "meter"` entitlement — always
    /// present, `0` if never incremented.
    ///
    /// **`0` does not necessarily mean "never used"** — it also means "this
    /// entitlement is only inherited from the license's policy and has
    /// never been directly attached to this license", because only a
    /// direct `license_entitlements` row carries a counter at all. Check
    /// [`Self::inherited`] to tell the two apart if that distinction
    /// matters to your caller.
    ///
    /// `#[serde(default)]` for the same forward/backward-compatibility
    /// reason as [`Self::max_value`], even though the server always sends
    /// this field today.
    #[serde(default)]
    pub current_value: i32,
}
