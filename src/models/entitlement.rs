//! `EntitlementResource` and the licence-scoped [`LicenseEntitlement`].
//!
//! Fields: `name`, `code`, `metadata`, `created`, `updated`.
//!
//! `code` is the stable, developer-facing identifier — `name` is just a
//! display label. [`crate::Client::has_entitlement`] matches on
//! `code`, never `name`. Despite the URL nesting under
//! `/licenses/{id}/entitlements`, these are full `Entitlement` resources,
//! not lightweight junction/relationship records.
//!
//! The licence-scoped **list** route carries one attribute the others do
//! not: `inherited`, true when the licence holds the entitlement through
//! its policy rather than by a direct attachment. That flag decides what a
//! caller can do with the row — an inherited entitlement cannot be detached
//! (`403 POLICY_ENTITLEMENT`), re-attaching it fails
//! (`422 ENTITLEMENT_ALREADY_INHERITED`), and, because the item route
//! resolves direct attachments only, `GET .../entitlements/{id}` on it
//! **404s**. Read it via [`crate::Client::list_license_entitlements`], which
//! returns [`LicenseEntitlement`]; [`EntitlementResource`] itself is shared
//! with the account-, policy- and release-scoped routes, where the server
//! emits no such attribute.

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
    /// Arbitrary caller-set metadata.
    pub metadata: serde_json::Value,
    /// Creation timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// Last-updated timestamp.
    pub updated: chrono::DateTime<chrono::Utc>,
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
/// `inherited`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LicenseEntitlementAttributes {
    /// Display label — **never** match on this; see `code`.
    pub name: String,
    /// The stable, developer-facing identifier.
    pub code: String,
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
}
