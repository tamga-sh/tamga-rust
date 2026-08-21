//! `ReleaseResource` — the `releases` JSON:API resource returned by the
//! auto-update check.
//!
//! ⚠️ **This resource's attributes are camelCase**, unlike every other
//! resource in this crate. The server's `ReleaseAttributes` carries
//! `#[serde(rename_all = "camelCase")]`, so `product_id` goes over the wire as
//! `productId` while `LicenseAttributes`, `MachineAttributes` and
//! `PolicyAttributes` are all snake_case. It is one of exactly two casing
//! exceptions in the protocol — the other being
//! [`crate::models::policy::CheckInInterval`]'s lowercase wire values.
//!
//! `tag` is emitted with `skip_serializing_if = "Option::is_none"`, so it is
//! genuinely absent rather than `null` when unset — modelled with
//! `#[serde(default)]` so an absent key decodes rather than erroring.
//!
//! See [`crate::Client::check_for_upgrade`] for why an *absent* release does
//! not mean "you are up to date".

/// The `releases` JSON:API resource: `{ id, type, attributes }`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ReleaseResource {
    /// UUIDv7 release ID.
    pub id: uuid::Uuid,
    /// Always `"releases"`.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The resource's attribute bag.
    pub attributes: ReleaseAttributes,
}

/// Attributes of a [`ReleaseResource`]. **camelCase on the wire** — see the
/// module doc comment.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseAttributes {
    /// The owning product's ID (wire name `productId`).
    pub product_id: uuid::Uuid,
    /// Optional display name.
    pub name: Option<String>,
    /// Version string, as the product publishes it. Not parsed or compared
    /// client-side — the server decides what "newer" means, including how the
    /// optional `constraint` narrows it.
    pub version: String,
    /// Release channel (e.g. `"stable"`, `"beta"`).
    pub channel: String,
    /// Publication status.
    pub status: String,
    /// Optional tag. **Absent, not `null`**, when unset.
    #[serde(default)]
    pub tag: Option<String>,
    /// Arbitrary caller-set metadata.
    pub metadata: serde_json::Value,
    /// Creation timestamp (wire name `created`).
    #[serde(rename = "created")]
    pub created: chrono::DateTime<chrono::Utc>,
    /// Last-updated timestamp (wire name `updated`).
    #[serde(rename = "updated")]
    pub updated: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_the_camel_case_attribute_names() {
        let json = serde_json::json!({
            "type": "releases",
            "id": "01926b3e-0000-7000-8000-000000000000",
            "attributes": {
                "productId": "01926b3e-1111-7000-8000-000000000000",
                "name": "Acme 2.0",
                "version": "2.0.0",
                "channel": "stable",
                "status": "PUBLISHED",
                "tag": "ga",
                "metadata": {},
                "created": "2026-01-01T00:00:00Z",
                "updated": "2026-01-01T00:00:00Z",
            }
        });
        let release: ReleaseResource = serde_json::from_value(json).unwrap();
        assert_eq!(release.resource_type, "releases");
        assert_eq!(release.attributes.version, "2.0.0");
        assert_eq!(release.attributes.tag.as_deref(), Some("ga"));
    }

    #[test]
    fn an_absent_tag_decodes_rather_than_erroring() {
        // The server skips the key entirely instead of sending null.
        let json = serde_json::json!({
            "type": "releases",
            "id": "01926b3e-0000-7000-8000-000000000000",
            "attributes": {
                "productId": "01926b3e-1111-7000-8000-000000000000",
                "name": null,
                "version": "2.0.0",
                "channel": "stable",
                "status": "PUBLISHED",
                "metadata": {},
                "created": "2026-01-01T00:00:00Z",
                "updated": "2026-01-01T00:00:00Z",
            }
        });
        let release: ReleaseResource = serde_json::from_value(json).unwrap();
        assert_eq!(release.attributes.tag, None);
    }
}
