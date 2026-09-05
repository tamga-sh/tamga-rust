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
//! Every key the set holds is tried against the signature over `enc`'s
//! base64 string **before a single byte of `enc` is decoded**, so the only
//! bytes that reach a decoder, a cipher or the JSON parser on the success
//! path are bytes a trusted key has already vouched for. The `kid` claim is
//! read only afterwards, and only when no key verified, to label the
//! failure: a `kid` the set holds means a forgery
//! ([`crate::error::CryptoError::VerificationFailed`]); a `kid` it does not
//! hold means a set that has not caught up with a rotation
//! ([`crate::error::CheckoutError::UnknownSigningKey`]). The distinction the
//! set exists for survives because the `kid` still decides the label; what
//! changed is that a file no longer chooses which key its signature is
//! checked against, and no unverified ciphertext is decrypted except to read
//! that one claim. (Until 0.3.3 the `kid` selected the key and the payload
//! was decoded first — an order tamga-swift, -java, -go and -python never
//! had; every SDK now shares this one.)
//!
//! Trying every key is sound because a [`SigningKeySet`] can only be built
//! from keys the caller supplies — the account's published key set
//! ([`crate::Client::signing_key_set`]) or public keys embedded in the
//! application binary ([`SigningKeySet::from_public_keys`]) — never from
//! anything the file carries.
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
    ///
    /// Since the API patch every account publishes a key from creation and
    /// the startup sweep backfills older accounts, so an empty *fetched* set
    /// is no longer the healthy "never rotated" state it once was.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The `kid`s this set can verify against, in insertion order. Useful in a
    /// log line next to an `UnknownSigningKey` failure.
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(kid, _)| kid.as_str())
    }

    /// Every key the set holds, in insertion order. Crate-private: the
    /// verify-first paths in `license_file`/`machine_file` try each one
    /// against the signature, and nothing outside needs the raw bytes.
    pub(crate) fn keys(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.entries.iter().map(|(_, key)| key)
    }

    /// Tries every held key against `signature` over `message`, returning
    /// the first that verifies.
    ///
    /// `Err` only for a signature malformed for *every* key
    /// ([`crate::error::CryptoError::InvalidSignature`]: the wrong length). A
    /// plain mismatch under every key is `Ok(None)`, which the caller then
    /// labels through [`SigningKeySet::label_failure`]. An empty set is
    /// `Ok(None)` too.
    pub(crate) fn find_verifying_key(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<Option<&[u8; 32]>, crate::error::CryptoError> {
        for key in self.keys() {
            match crate::crypto::ed25519::verify(key, message, signature) {
                Ok(()) => return Ok(Some(key)),
                Err(crate::error::CryptoError::InvalidSignature) => {
                    return Err(crate::error::CryptoError::InvalidSignature)
                }
                Err(_) => {}
            }
        }
        Ok(None)
    }

    /// Labels a signature that no held key verified, from the `kid` the
    /// still-unverified payload names.
    ///
    /// `probe` is the outcome of decoding — and, when encrypted, decrypting
    /// — `enc` **only** to read `meta.kid`; nothing else is taken from those
    /// bytes, and nothing they contain is trusted. The rules:
    ///
    /// - the `kid` is held → [`crate::error::CryptoError::VerificationFailed`].
    ///   The file names a key we have and that key did not sign it: a
    ///   forgery, or an altered file.
    /// - the `kid` is not held → [`crate::error::CheckoutError::UnknownSigningKey`].
    ///   A set that has not caught up with a rotation, not a forgery.
    /// - the payload cannot be decoded, decrypted or parsed, or names no
    ///   `kid` → [`crate::error::CryptoError::VerificationFailed`]. With
    ///   nothing to label it by, the signature failure stands as what it is.
    /// - the caller supplied no licence key (or, for a machine file, no
    ///   fingerprint) for an encrypted file →
    ///   [`crate::error::CheckoutError::LicenseKeyMissing`] /
    ///   [`crate::error::CheckoutError::FingerprintMissing`], unchanged. A
    ///   missing argument is the caller's to fix, and hiding it behind a
    ///   signature verdict would send them chasing keys.
    pub(crate) fn label_failure(
        &self,
        probe: Result<Vec<u8>, crate::error::CheckoutError>,
    ) -> crate::error::CheckoutError {
        use crate::error::{CheckoutError, CryptoError};

        let plaintext = match probe {
            Ok(plaintext) => plaintext,
            Err(
                missing @ (CheckoutError::LicenseKeyMissing | CheckoutError::FingerprintMissing),
            ) => return missing,
            Err(_) => return CryptoError::VerificationFailed.into(),
        };
        match crate::checkout::license_file::probe_kid(&plaintext) {
            Ok(kid) if self.find(&kid).is_some() => CryptoError::VerificationFailed.into(),
            Ok(kid) => CheckoutError::UnknownSigningKey { kid },
            Err(_) => CryptoError::VerificationFailed.into(),
        }
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
