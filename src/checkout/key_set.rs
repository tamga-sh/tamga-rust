//! [`SigningKeySet`] — the trusted Ed25519 keys an offline file is allowed to
//! have been signed by, indexed by the `kid` its claims name.
//!
//! # The problem this closes
//!
//! Verifying against one embedded public key collapses two completely
//! different outcomes into one error. A file signed last month, before the
//! account rotated its signing key, is authentic and its licence may well still
//! be valid — but it fails against the current key with exactly the error a
//! forgery produces, and the caller has no way to tell "my key set is stale"
//! from "this file was tampered with". The first calls for fetching the key
//! set or shipping an update; the second calls for refusing the customer.
//!
//! # How the `kid` is used, and why that is safe
//!
//! The `kid` claim lives *inside* the signed payload but is read *before* the
//! signature is checked, which is only sound under one rule: it selects a key
//! from a set the caller already trusts, and never supplies one. A file naming
//! a `kid` this set does not hold is
//! [`crate::error::CheckoutError::UnknownSigningKey`]; a file naming one it
//! does hold is verified against exactly that key and nothing else. There is
//! deliberately no "try every key" fallback — trying them all would verify the
//! same set of files while destroying the distinction this module exists for.
//!
//! This is the same discipline JWS `kid` handling needs, and it is why
//! [`SigningKeySet`] can only be built from keys the caller supplies: from the
//! account's published key set ([`crate::Client::signing_key_set`]) or from
//! public keys embedded in the application binary
//! ([`SigningKeySet::from_public_keys`]).
//!
//! # Ed25519 only
//!
//! Every key the server publishes is Ed25519 (rotation is `rotate_ed25519`),
//! and `.lic` files are Ed25519-signed regardless of the licence's own
//! `scheme`. A `.mach` file signed under an RSA or ECDSA scheme cannot be
//! verified through this path at all — its key is not published, is never
//! rotated, and its `kid` claim names the account's Ed25519 key anyway. See
//! [`crate::models::signing_key`].

/// A set of trusted Ed25519 public keys, indexed by `kid`.
///
/// Build one from the account's published key set with
/// [`crate::Client::signing_key_set`], from [`SigningKeySet::from_resources`],
/// or from keys embedded in the binary with
/// [`SigningKeySet::from_public_keys`]. Then pass it to
/// [`crate::checkout::license_file::verify_license_file_with_key_set`] or
/// [`crate::checkout::machine_file::verify_machine_file_with_key_set`].
#[derive(Debug, Clone, Default)]
pub struct SigningKeySet {
    entries: Vec<(String, [u8; 32])>,
}

/// The algorithm string the server writes for every key it publishes.
const ED25519_ALGORITHM: &str = "ed25519";

impl SigningKeySet {
    /// Builds a key set from public keys the caller holds, each standard
    /// base64 of the raw 32 bytes — the format the server publishes and stores.
    ///
    /// Strict on purpose: a key that is not valid base64 of exactly 32 bytes is
    /// [`crate::error::CryptoError::InvalidKey`] rather than being skipped. A
    /// typo in a key pinned in an application binary must fail loudly at
    /// startup, not silently produce a set that reports every genuine file as
    /// signed by an unknown key.
    ///
    /// Each key's `kid` is derived with [`crate::crypto::ed25519::key_id`], so
    /// this works with no network access at all.
    pub fn from_public_keys<I, S>(public_keys: I) -> Result<Self, crate::error::CryptoError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut entries = Vec::new();
        for key in public_keys {
            let b64 = key.as_ref();
            let bytes = crate::crypto::ed25519::public_key_from_base64(b64)?;
            entries.push((crate::crypto::ed25519::key_id(b64), bytes));
        }
        Ok(SigningKeySet { entries })
    }

    /// Builds a key set from the account's published key set, as returned by
    /// [`crate::Client::list_signing_keys`].
    ///
    /// Lenient where [`SigningKeySet::from_public_keys`] is strict, and for the
    /// opposite reason: this input is the server's whole key history, and one
    /// unusable row — a future non-Ed25519 algorithm, a legacy key that does
    /// not decode — must not strand every file the account has already signed.
    /// Such entries are skipped, and a file naming one surfaces as
    /// [`crate::error::CheckoutError::UnknownSigningKey`] with the `kid` in
    /// hand. Compare [`SigningKeySet::len`] against the number of resources
    /// fetched if you need to know that something was dropped.
    ///
    /// The `kid` is taken from the resource's `id`, which *is* the `kid` — the
    /// server sets it from the same value it writes into the file's claim, so
    /// no local hashing is involved on this path.
    pub fn from_resources(resources: &[crate::models::signing_key::SigningKeyResource]) -> Self {
        let entries = resources
            .iter()
            .filter(|r| {
                r.attributes
                    .algorithm
                    .eq_ignore_ascii_case(ED25519_ALGORITHM)
            })
            .filter_map(|r| {
                crate::crypto::ed25519::public_key_from_base64(&r.attributes.public_key)
                    .ok()
                    .map(|bytes| (r.id.clone(), bytes))
            })
            .collect();
        SigningKeySet { entries }
    }

    /// The raw 32-byte public key this set holds under `kid`, if any.
    ///
    /// Matching is exact and case-sensitive: the server emits lowercase hex on
    /// both sides, in the resource `id` and in the file's claim alike.
    pub fn find(&self, kid: &str) -> Option<&[u8; 32]> {
        self.entries
            .iter()
            .find(|(candidate, _)| candidate == kid)
            .map(|(_, key)| key)
    }

    /// How many usable keys the set holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set holds no usable key at all.
    ///
    /// An empty set is not an error here — every verification through it
    /// reports [`crate::error::CheckoutError::UnknownSigningKey`], which is the
    /// honest answer — but it is almost always a sign that the fetch or the
    /// embedded key list is wrong.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The `kid`s this set can verify against, in insertion order. Useful in a
    /// log line next to an `UnknownSigningKey` failure.
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(kid, _)| kid.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Base64 of 32 zero bytes — a well-formed key encoding, used here only
    /// for its length and its `kid`.
    const ZERO_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const ZERO_KEY_KID: &str = "51643eac9777b63a";

    fn resource(
        id: &str,
        algorithm: &str,
        public_key: &str,
    ) -> crate::models::signing_key::SigningKeyResource {
        serde_json::from_value(serde_json::json!({
            "type": "signing-keys",
            "id": id,
            "attributes": {
                "algorithm": algorithm,
                "publicKey": public_key,
                "status": "retired",
                "created": "2026-01-01T00:00:00Z",
            }
        }))
        .unwrap()
    }

    #[test]
    fn a_key_embedded_in_the_binary_indexes_itself_by_its_computed_kid() {
        let set = SigningKeySet::from_public_keys([ZERO_KEY_B64]).unwrap();
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
        assert!(set.find(ZERO_KEY_KID).is_some());
        assert_eq!(set.kids().collect::<Vec<_>>(), vec![ZERO_KEY_KID]);
    }

    #[test]
    fn a_mistyped_embedded_key_fails_loudly_rather_than_silently() {
        // The alternative — skipping it — produces a set that reports every
        // genuine file as signed by an unknown key, at runtime, in the field.
        assert!(SigningKeySet::from_public_keys(["not base64 at all"]).is_err());
        assert!(
            SigningKeySet::from_public_keys(["QUJD"]).is_err(),
            "3 bytes is not a key"
        );
    }

    #[test]
    fn a_fetched_key_set_takes_the_kid_from_the_resource_id() {
        // The server's `id` *is* the kid; nothing is hashed on this path.
        let set =
            SigningKeySet::from_resources(&[resource("deadbeefdeadbeef", "ed25519", ZERO_KEY_B64)]);
        assert!(set.find("deadbeefdeadbeef").is_some());
        assert!(set.find(ZERO_KEY_KID).is_none());
    }

    #[test]
    fn one_unusable_published_key_does_not_strand_the_others() {
        // A future algorithm and a key that does not decode are both skipped;
        // the Ed25519 rows around them still verify their files.
        let set = SigningKeySet::from_resources(&[
            resource("0000000000000000", "ml-dsa-44", ZERO_KEY_B64),
            resource("1111111111111111", "ed25519", "!!!not base64!!!"),
            resource("2222222222222222", "ed25519", ZERO_KEY_B64),
        ]);
        assert_eq!(set.len(), 1);
        assert!(set.find("2222222222222222").is_some());
        assert!(set.find("0000000000000000").is_none());
        assert!(set.find("1111111111111111").is_none());
    }

    #[test]
    fn kid_matching_is_exact() {
        let set = SigningKeySet::from_public_keys([ZERO_KEY_B64]).unwrap();
        assert!(set.find(&ZERO_KEY_KID.to_uppercase()).is_none());
        assert!(set.find("51643eac9777b63").is_none());
        assert!(set.find("").is_none());
    }

    #[test]
    fn an_empty_set_is_buildable_and_finds_nothing() {
        let set = SigningKeySet::default();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert!(set.find(ZERO_KEY_KID).is_none());
        assert_eq!(SigningKeySet::from_resources(&[]).len(), 0);
        assert_eq!(
            SigningKeySet::from_public_keys(Vec::<String>::new())
                .unwrap()
                .len(),
            0
        );
    }
}
