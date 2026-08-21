//! `ArtifactResource` — the `artifacts` JSON:API resource: the uploaded binary
//! a release distributes.
//!
//! ## Casing is mixed, and uniform camelCase gets it wrong
//!
//! The server's `ArtifactAttributes` carries `#[serde(rename_all =
//! "camelCase")]` **and** explicit `#[serde(rename = "created")]` /
//! `#[serde(rename = "updated")]` on its two timestamps
//! (`artifacts/serializer.rs:20,34-37`). So the wire names are `redirectUrl`
//! — camelCased — but `created` and `updated`, *not* `createdAt`/`updatedAt`.
//! An SDK that applies camelCase uniformly to this resource decodes two null
//! timestamps and reports nothing wrong. Both renames are spelled out
//! explicitly below rather than left to `rename_all`.
//!
//! [`crate::models::release::ReleaseResource`] has the same shape for the
//! same reason.
//!
//! ## `redirectUrl` is absent, not null
//!
//! The server emits it with `skip_serializing_if = "Option::is_none"`, and
//! only the download action ever populates it — list and show omit the key
//! entirely. Modelled `#[serde(default)]` so an absent key decodes to `None`
//! rather than erroring.
//!
//! ## Read-only here
//!
//! `Role::LicenseToken` holds `artifact.read` (long-standing) and
//! `artifact.download` (granted more recently) but not
//! `artifact.create`/`update`/`delete` (`authz/mod.rs`), so this crate models
//! artifacts for reading only. There is no create/update/delete/upload path,
//! and adding one would be unreachable with the credential this SDK is built
//! around.

/// The `artifacts` JSON:API resource: `{ id, type, attributes }`.
#[derive(Debug, Clone, serde::Deserialize)]
#[non_exhaustive]
pub struct ArtifactResource {
    /// UUIDv7 artifact ID.
    pub id: uuid::Uuid,
    /// Always `"artifacts"`.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The resource's attribute bag.
    pub attributes: ArtifactAttributes,
}

/// Attributes of an [`ArtifactResource`]. **Mixed casing on the wire** — see
/// the module doc comment.
///
/// `#[non_exhaustive]`: the server can add an attribute at any time, and this
/// crate learned from [`crate::transport::ResponseInfo`] that a public struct
/// with all-public fields cannot grow one without a breaking release.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ArtifactAttributes {
    /// Filename as uploaded, e.g. `"acme-2.0.0-x86_64.tar.gz"`.
    pub filename: String,
    /// MIME type, when the uploader set one.
    pub filetype: Option<String>,
    /// Size in bytes, when known.
    ///
    /// Advisory: it is recorded at upload time, not measured on download.
    /// Size the `max_bytes` ceiling of
    /// [`crate::Client::download_artifact`] from your own policy, not from
    /// this field.
    pub filesize: Option<i64>,
    /// Integrity checksum, when the uploader supplied one.
    ///
    /// Free-form: the algorithm is not declared anywhere on the wire. The
    /// server itself only *infers* it from the string's length and character
    /// set (`artifacts/model.rs::infer_checksum_algorithm`), so this crate
    /// does not verify downloaded bytes against it — guessing an algorithm
    /// and reporting a pass would be worse than not checking. Verify it
    /// against whatever convention your upload side actually uses.
    pub checksum: Option<String>,
    /// Target platform, e.g. `"darwin"`, `"linux"`, `"win32"`.
    pub platform: Option<String>,
    /// Target architecture, e.g. `"x86_64"`, `"arm64"`.
    pub arch: Option<String>,
    /// Detached signature over the artifact, when the uploader supplied one.
    ///
    /// Opaque to this crate — unlike a `.lic`/`.mach` file, no scheme is
    /// declared for it, so [`crate::checkout`] cannot verify it.
    pub signature: Option<String>,
    /// Upload/publication status, e.g. `"UPLOADED"`.
    pub status: String,
    /// The presigned storage URL (wire name `redirectUrl`).
    ///
    /// **Absent — not null — on list and show.** Populated only by
    /// [`crate::Client::artifact_download_url`], which asks the download
    /// action for the URL instead of a redirect.
    ///
    /// Short-lived, and a bearer capability in its own right: anyone holding
    /// it can fetch the bytes until it expires. Never attach Tamga
    /// credentials when fetching it, and do not log it.
    #[serde(default)]
    pub redirect_url: Option<String>,
    /// Arbitrary uploader-set metadata.
    pub metadata: serde_json::Value,
    /// Creation timestamp — wire name `created`, **not** `createdAt`.
    #[serde(rename = "created")]
    pub created: chrono::DateTime<chrono::Utc>,
    /// Last-updated timestamp — wire name `updated`, **not** `updatedAt`.
    #[serde(rename = "updated")]
    pub updated: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_attributes_json() -> serde_json::Value {
        serde_json::json!({
            "type": "artifacts",
            "id": "01926b3e-0000-7000-8000-000000000000",
            "attributes": {
                "filename": "acme-2.0.0-x86_64.tar.gz",
                "filetype": "application/gzip",
                "filesize": 1048576,
                "checksum": "d41d8cd98f00b204e9800998ecf8427e",
                "platform": "linux",
                "arch": "x86_64",
                "signature": "MEUCIQ...",
                "status": "UPLOADED",
                "metadata": {"channel": "stable"},
                "created": "2026-01-01T00:00:00Z",
                "updated": "2026-01-02T00:00:00Z",
            }
        })
    }

    #[test]
    fn decodes_created_and_updated_not_created_at_and_updated_at() {
        // The trap: `rename_all = "camelCase"` is on the server type, but both
        // timestamps carry an explicit rename that overrides it. A port that
        // expects `createdAt`/`updatedAt` gets two nulls — or, with
        // non-Option fields like these, a hard decode error.
        let r: ArtifactResource = serde_json::from_value(full_attributes_json()).unwrap();
        assert_eq!(
            r.attributes.created.to_rfc3339(),
            "2026-01-01T00:00:00+00:00"
        );
        assert_eq!(
            r.attributes.updated.to_rfc3339(),
            "2026-01-02T00:00:00+00:00"
        );
    }

    #[test]
    fn created_at_spelling_does_not_decode() {
        // Pins the direction of the trap: if someone "fixes" the rename to
        // camelCase, this stops failing and the test above starts.
        let mut json = full_attributes_json();
        let attrs = json["attributes"].as_object_mut().unwrap();
        let created = attrs.remove("created").unwrap();
        attrs.insert("createdAt".to_string(), created);
        let r: Result<ArtifactResource, _> = serde_json::from_value(json);
        assert!(
            r.is_err(),
            "`createdAt` must not satisfy the `created` field"
        );
    }

    #[test]
    fn decodes_the_camel_case_redirect_url() {
        let mut json = full_attributes_json();
        json["attributes"]["redirectUrl"] =
            serde_json::json!("https://storage.example.com/a?sig=x");
        let r: ArtifactResource = serde_json::from_value(json).unwrap();
        assert_eq!(
            r.attributes.redirect_url.as_deref(),
            Some("https://storage.example.com/a?sig=x")
        );
    }

    #[test]
    fn an_absent_redirect_url_decodes_to_none() {
        // List and show omit the key entirely rather than sending null, so
        // `#[serde(default)]` is load-bearing, not decoration.
        let json = full_attributes_json();
        assert!(json["attributes"].get("redirectUrl").is_none());
        let r: ArtifactResource = serde_json::from_value(json).unwrap();
        assert!(r.attributes.redirect_url.is_none());
    }

    #[test]
    fn the_optional_attributes_decode_when_null() {
        let mut json = full_attributes_json();
        for key in [
            "filetype",
            "filesize",
            "checksum",
            "platform",
            "arch",
            "signature",
        ] {
            json["attributes"][key] = serde_json::Value::Null;
        }
        let r: ArtifactResource = serde_json::from_value(json).unwrap();
        assert!(r.attributes.filetype.is_none());
        assert!(r.attributes.filesize.is_none());
        assert!(r.attributes.checksum.is_none());
        assert!(r.attributes.platform.is_none());
        assert!(r.attributes.arch.is_none());
        assert!(r.attributes.signature.is_none());
        // Non-optional attributes still land.
        assert_eq!(r.attributes.filename, "acme-2.0.0-x86_64.tar.gz");
        assert_eq!(r.attributes.status, "UPLOADED");
        assert_eq!(r.resource_type, "artifacts");
    }
}
