//! `SigningKeyResource` — the `signing-keys` JSON:API resource published by
//! `GET /v1/accounts/{account_id}/signing-keys`.
//!
//! The account's **whole** key history, retired keys included. That is the
//! point of the route: a client holding a `.lic` or `.mach` file signed before
//! the last rotation needs the key its `kid` claim names, and its only other
//! options are to fail verification or to accept any key, the second of which
//! defeats signing entirely.
//!
//! Two things about this resource are easy to get wrong.
//!
//! **The resource `id` *is* the `kid`.** It is not a UUID like every other
//! resource in this crate — the server sets `id: k.kid`
//! (`accounts/serializer.rs:123`), exactly the value an offline file's
//! `kid` claim carries. So matching a file to its key needs no local hashing at
//! all against this route's output; [`crate::crypto::ed25519::key_id`] exists
//! for the other direction, where a caller has embedded a public key in the
//! binary and never calls the API.
//!
//! **`publicKey` is camelCase inside an otherwise snake_case struct.** The
//! server's `SigningKeyAttributes` carries no `rename_all`; the single field
//! rename on `public_key` (`accounts/serializer.rs:111`) is the only
//! exception, and `algorithm`, `status`, `created` and `retired` are all bare.
//! Applying camelCase to the whole struct is as wrong as applying snake_case to
//! all of it.
//!
//! **Ed25519 only, today.** Rotation is `rotate_ed25519` and inserts a literal
//! `'ed25519'`; nothing writes another algorithm, and the account's RSA and
//! ECDSA signing keys are neither published here nor rotated at all. A `.mach`
//! file signed under an RSA or ECDSA scheme therefore has no entry here — and
//! its `kid` claim names the account's *Ed25519* key regardless, because both
//! checkout handlers compute it from `account.ed25519_public_key` whatever
//! scheme actually signed the bytes (`check_out_machine.rs:125`). Treat `kid`
//! as meaningful for Ed25519-signed files only.

/// The `signing-keys` JSON:API resource: `{ id, type, attributes }`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SigningKeyResource {
    /// **The `kid`, not a UUID** — the same 16-character lowercase hex string
    /// an offline file's `kid` claim carries. See the module doc comment.
    pub id: String,
    /// Always `"signing-keys"`.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The resource's attribute bag.
    pub attributes: SigningKeyAttributes,
}

/// Attributes of a [`SigningKeyResource`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SigningKeyAttributes {
    /// `"ed25519"` for every key the server publishes today — rotation only
    /// ever mints Ed25519 keys. Left an open string rather than an enum so a
    /// future algorithm decodes instead of failing the whole response.
    pub algorithm: String,
    /// The public half, standard base64 of the raw 32 bytes.
    ///
    /// **Wire name `publicKey`** — the one camelCase field in an otherwise
    /// snake_case resource.
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// `"active"` or `"retired"`. An account has at most one active key per
    /// algorithm; everything else it has ever signed with stays here as
    /// `"retired"` so old files keep verifying. Open string for the same
    /// reason as `algorithm`.
    pub status: String,
    /// When the key was created (wire name `created`).
    pub created: chrono::DateTime<chrono::Utc>,
    /// When the key was retired. **Absent, not `null`**, while the key is
    /// still active — the server skips the field entirely
    /// (`skip_serializing_if = "Option::is_none"`).
    #[serde(default)]
    pub retired: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_a_retired_key() {
        let json = serde_json::json!({
            "type": "signing-keys",
            "id": "51643eac9777b63a",
            "attributes": {
                "algorithm": "ed25519",
                "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "status": "retired",
                "created": "2026-01-01T00:00:00Z",
                "retired": "2026-06-01T00:00:00Z",
            }
        });
        let key: SigningKeyResource = serde_json::from_value(json).unwrap();
        assert_eq!(key.resource_type, "signing-keys");
        // Not a UUID: the id is the kid.
        assert_eq!(key.id, "51643eac9777b63a");
        assert_eq!(key.attributes.status, "retired");
        assert!(key.attributes.retired.is_some());
    }

    #[test]
    fn an_active_key_omits_retired_entirely_rather_than_nulling_it() {
        let json = serde_json::json!({
            "type": "signing-keys",
            "id": "51643eac9777b63a",
            "attributes": {
                "algorithm": "ed25519",
                "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "status": "active",
                "created": "2026-01-01T00:00:00Z",
            }
        });
        let key: SigningKeyResource = serde_json::from_value(json).unwrap();
        assert_eq!(key.attributes.retired, None);
    }

    #[test]
    fn the_public_key_field_is_camel_case_on_the_wire() {
        // snake_case here decodes to a missing-field error: the rename is
        // per-field, and the rest of the struct is bare.
        let json = serde_json::json!({
            "type": "signing-keys",
            "id": "51643eac9777b63a",
            "attributes": {
                "algorithm": "ed25519",
                "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "status": "active",
                "created": "2026-01-01T00:00:00Z",
            }
        });
        assert!(serde_json::from_value::<SigningKeyResource>(json).is_err());
    }

    #[test]
    fn an_unknown_algorithm_or_status_still_decodes() {
        // Open strings, not enums: a future algorithm must not fail the whole
        // key set and strand every file the account has already signed.
        let json = serde_json::json!({
            "type": "signing-keys",
            "id": "0011223344556677",
            "attributes": {
                "algorithm": "ml-dsa-44",
                "publicKey": "AAAA",
                "status": "compromised",
                "created": "2026-01-01T00:00:00Z",
            }
        });
        let key: SigningKeyResource = serde_json::from_value(json).unwrap();
        assert_eq!(key.attributes.algorithm, "ml-dsa-44");
        assert_eq!(key.attributes.status, "compromised");
    }
}
