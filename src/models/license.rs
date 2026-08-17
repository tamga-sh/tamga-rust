//! `LicenseResource` — the JSON:API `licenses` resource.
//!
//! The field set matches the server's own `licenses` serializer exactly.
//! Notably: **no `relationships` object exists on this resource today** — the
//! server's serializer never emits one, so this SDK does not model a
//! `policy`/`product`/`owner` relationships field the server never sends.

/// The `licenses` JSON:API resource: `{ id, type, attributes }`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LicenseResource {
    /// UUIDv7 license ID.
    pub id: uuid::Uuid,
    /// Always `"licenses"`.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The resource's flat attribute bag — see [`LicenseAttributes`].
    pub attributes: LicenseAttributes,
}

/// Attributes of a [`LicenseResource`], matching the Tamga API's
/// `LicenseAttributes` field-for-field.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LicenseAttributes {
    /// Optional display name.
    pub name: Option<String>,
    /// The raw license key string, if one is set (some licenses are
    /// keyless/token-only).
    pub key: Option<String>,
    /// Server-computed status string (not the same enum as
    /// [`crate::models::validation::ValidationCode`] — this is the
    /// license's own state, e.g. `"ACTIVE"`/`"EXPIRED"`/`"SUSPENDED"`).
    pub status: String,
    /// Absolute expiry timestamp, if the license expires.
    pub expiry: Option<chrono::DateTime<chrono::Utc>>,
    /// Manually suspended by an account admin.
    pub suspended: bool,
    /// Whether checkout/download of this license's key is protected.
    pub protected: bool,
    /// Current use count, compared against `max_uses` (strict `>=`,
    /// regardless of overage strategy).
    pub uses: i32,
    /// Signing scheme for checkout files — see
    /// [`crate::models::policy::LicenseScheme`]. `None` means a legacy
    /// plain/unsigned key.
    pub scheme: Option<String>,
    /// Whether checkout files for this license are encrypted by default.
    pub encrypted: bool,
    /// Strict mode flag (server-side semantics not yet SDK-relevant).
    pub strict: bool,
    /// Floating license flag (server-side semantics not yet SDK-relevant).
    pub floating: bool,
    /// Per-license override of `policy.max_machines`, if set.
    pub max_machines: Option<i32>,
    /// Per-license override of `policy.max_uses`, if set.
    pub max_uses: Option<i32>,
    /// Per-license override of `policy.max_users`, if set.
    pub max_users: Option<i32>,
    /// Timestamp of the last successful validation, unless suppressed via
    /// `skip_touch`.
    pub last_validated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Timestamp of the last successful check-in.
    pub last_check_in_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Timestamp of the last license-file checkout.
    pub last_check_out_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Current count of activated machines.
    pub machines_count: i32,
    /// Arbitrary caller-set metadata.
    pub metadata: serde_json::Value,
    /// Creation timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// Last-updated timestamp.
    pub updated: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn representative_license_json() -> serde_json::Value {
        serde_json::json!({
            "type": "licenses",
            "id": "01926b3e-0000-7000-8000-000000000000",
            "attributes": {
                "name": "Acme Corp",
                "key": "lic-abc123",
                "status": "ACTIVE",
                "expiry": null,
                "suspended": false,
                "protected": false,
                "uses": 0,
                "scheme": null,
                "encrypted": false,
                "strict": false,
                "floating": false,
                "max_machines": null,
                "max_uses": null,
                "max_users": null,
                "last_validated_at": null,
                "last_check_in_at": null,
                "last_check_out_at": null,
                "machines_count": 0,
                "metadata": {},
                "created": "2026-01-01T00:00:00Z",
                "updated": "2026-01-01T00:00:00Z",
            }
        })
    }

    #[test]
    fn deserializes_representative_license_resource() {
        let resource: LicenseResource =
            serde_json::from_value(representative_license_json()).unwrap();
        assert_eq!(resource.resource_type, "licenses");
        assert_eq!(resource.attributes.name, Some("Acme Corp".to_string()));
        assert_eq!(resource.attributes.key, Some("lic-abc123".to_string()));
        assert_eq!(resource.attributes.status, "ACTIVE");
        assert!(!resource.attributes.suspended);
        assert_eq!(resource.attributes.uses, 0);
    }

    #[test]
    fn rejects_a_json_object_with_a_relationships_field_gracefully() {
        // The server never sends `relationships` on this resource (see
        // module doc comment), but if it ever did, `serde`'s default
        // behavior (ignore unknown fields) means this SDK wouldn't break —
        // proving we did NOT opt into `deny_unknown_fields`.
        let mut json = representative_license_json();
        json["relationships"] = serde_json::json!({ "policy": { "data": null } });
        let resource: Result<LicenseResource, _> = serde_json::from_value(json);
        assert!(resource.is_ok());
    }
}
