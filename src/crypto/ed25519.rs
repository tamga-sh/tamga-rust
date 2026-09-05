//! Ed25519 signature verification.
//!
//! Used for: the license checkout (`.lic`) signature (always Ed25519,
//! independent of the license's own `scheme`), and one of the four machine
//! checkout (`.mach`) signature schemes.
//!
//! ⚠️ **Critical signing gotcha**: the `.lic`/`.mach` signature is computed
//! over the **ASCII/UTF-8 bytes of the `enc` base64 STRING itself — NOT the
//! decoded bytes of `enc`**. A verifier that decodes `enc` first and then
//! verifies over the decoded bytes will get a false negative against every
//! real server-produced file. This replicates the server's own signing
//! behaviour and is pinned by a negative test in
//! `src/checkout/license_file.rs`
//! (`decoded_bytes_signature_verification_fails_proving_the_string_bytes_gotcha`).
//!
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verifies an Ed25519 `signature` over `message` using the account's raw
/// 32-byte public key. Uses `ed25519-dalek`'s own constant-time verify
/// primitive — never a hand-rolled byte comparison, which would risk a
/// timing side channel.
///
/// Callers verifying a `.lic`/`.mach` checkout file must pass `message` as
/// the **base64 string bytes of `enc`, not `enc`'s decoded bytes** — see the
/// module doc comment's gotcha.
pub fn verify(
    pubkey: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), crate::error::CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(pubkey).map_err(|_| crate::error::CryptoError::InvalidKey)?;
    let sig =
        Signature::try_from(signature).map_err(|_| crate::error::CryptoError::InvalidSignature)?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| crate::error::CryptoError::VerificationFailed)
}

/// The `kid` a signed offline file names, computed from an Ed25519 public key.
///
/// The server's rule (`tamga-api/src/shared/crypto/license_file.rs:70-77`) is
/// the first eight bytes of `SHA-256(public key)`, lowercase hex — so a
/// sixteen-character string. Because it is a pure function of the key, a client
/// holding any public key can compute the id the file would name, which is what
/// makes key rotation solvable offline: fetch or embed the key set, compute
/// each id, and try every held key against the signature before trusting
/// any of it — the file's `kid` claim no longer picks which key to verify
/// against, it only labels which key was expected once none of them verify.
/// See [`crate::checkout::key_set::SigningKeySet`].
///
/// ⚠️ **The hash is over the base64 STRING, not the 32 decoded key bytes.**
/// The server stores and publishes the Ed25519 public half as standard base64
/// (`key_material.rs` — "Raw 32-byte Ed25519 public key, base64-encoded") and
/// hands that same `&str` to its `key_id`. Hashing the decoded bytes gives a
/// different, wrong id — the same class of gotcha as the signature covering
/// `enc`'s base64 string rather than its decoded bytes.
///
/// Passing the empty string is not an error and is worth knowing about: a
/// pre-patch server signed every file of an account whose
/// `ed25519_public_key` column was never backfilled with `key_id("")` — the
/// constant `e3b0c44298fc1c14`. The API patch's startup sweep backfills every
/// account and repairs the public half, so only files issued before it carry
/// that `kid`.
pub fn key_id(ed25519_public_key_base64: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(ed25519_public_key_base64.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Loads a raw 32-byte Ed25519 public key from a base64-encoded string
/// (account config format).
pub fn public_key_from_base64(b64: &str) -> Result<[u8; 32], crate::error::CryptoError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| crate::error::CryptoError::InvalidKey)?;
    bytes
        .try_into()
        .map_err(|_| crate::error::CryptoError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn gen_keypair() -> ([u8; 32], SigningKey) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        (signing_key.verifying_key().to_bytes(), signing_key)
    }

    #[test]
    fn accepts_a_valid_signature() {
        let (pubkey, signing_key) = gen_keypair();
        let message = b"the base64 enc string bytes";
        let sig = signing_key.sign(message);
        assert!(verify(&pubkey, message, &sig.to_bytes()).is_ok());
    }

    #[test]
    fn rejects_tampered_message() {
        let (pubkey, signing_key) = gen_keypair();
        let sig = signing_key.sign(b"original");
        assert!(verify(&pubkey, b"tampered!", &sig.to_bytes()).is_err());
    }

    #[test]
    fn rejects_signature_from_a_different_key() {
        let (pubkey_a, _) = gen_keypair();
        let (_, signing_key_b) = gen_keypair();
        let message = b"data";
        let sig = signing_key_b.sign(message);
        assert!(verify(&pubkey_a, message, &sig.to_bytes()).is_err());
    }

    #[test]
    fn rejects_malformed_signature_bytes() {
        let (pubkey, _) = gen_keypair();
        assert!(verify(&pubkey, b"data", b"too-short").is_err());
    }

    #[test]
    fn public_key_from_base64_round_trips() {
        let (pubkey, _) = gen_keypair();
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(pubkey);
        assert_eq!(public_key_from_base64(&b64).unwrap(), pubkey);
    }

    #[test]
    fn public_key_from_base64_rejects_wrong_length() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"too short");
        assert!(public_key_from_base64(&b64).is_err());
    }

    #[test]
    fn key_id_matches_the_servers_own_vectors() {
        // 16 lowercase hex characters = the first 8 bytes of SHA-256.
        let all_zero_key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let kid = key_id(all_zero_key_b64);
        assert_eq!(kid, "51643eac9777b63a");
        assert_eq!(kid.len(), 16);
        assert!(kid
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn key_id_of_the_empty_string_is_the_unbackfilled_account_sentinel() {
        // `check_out_license.rs:92` passes `.unwrap_or_default()`, so an
        // account whose public-key column was never populated signs every file
        // with this one `kid`. Recognising it is the difference between "your
        // key set is stale" and "this server has no published key at all".
        assert_eq!(key_id(""), "e3b0c44298fc1c14");
    }

    #[test]
    fn key_id_hashes_the_base64_string_not_the_decoded_bytes() {
        // The gotcha this function exists to pin: the server hands its
        // `key_id` the stored base64 `&str`, never the 32 decoded bytes.
        use base64::Engine as _;
        let (pubkey, _) = gen_keypair();
        let b64 = base64::engine::general_purpose::STANDARD.encode(pubkey);

        use sha2::Digest as _;
        let over_decoded_bytes: String = sha2::Sha256::digest(pubkey)[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        assert_ne!(key_id(&b64), over_decoded_bytes);
    }
}
