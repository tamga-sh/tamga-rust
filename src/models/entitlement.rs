//! `EntitlementResource`.
//!
//! Fields: `name`, `code`, `metadata`, `created`, `updated`.
//!
//! `code` is the stable, developer-facing identifier — `name` is just a
//! display label. [`crate::Client::has_entitlement`] matches on
//! `code`, never `name`. Despite the URL nesting under
//! `/licenses/{id}/entitlements`, these are full `Entitlement` resources,
//! not lightweight junction/relationship records.

/// The `entitlements` JSON:API resource: `{ id, type, attributes }`. Field
/// set matches `tamga-api`'s actual full `EntitlementResource` serializer —
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
