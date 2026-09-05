//! `.lic` file parsing and verification — the core payload format this SDK's
//! verifier must implement exactly right, since `tamga-c` (and transitively
//! `tamga-java`/`tamga-swift`) re-export this crate's implementation instead
//! of re-implementing it.
//!
//! **File format**:
//! ```text
//! -----BEGIN LICENSE FILE-----
//! <base64 of JSON: { "enc": "<base64>", "sig": "<base64 ed25519 sig over enc's UTF-8 bytes>", "alg": "<algorithm string>" }>
//! -----END LICENSE FILE-----
//! ```
//!
//! `alg` is exactly `"base64+ed25519+v2"` (plain) or
//! `"aes-256-gcm+ed25519+v2"` (encrypted) — **Ed25519 only** for the checkout
//! signature, independent of the license's own key `scheme`.
//!
//! **Format v2 and why v1 is refused outright.** In v1 the `ttl`/`expiry` a
//! caller asked for lived only in the JSON:API envelope *around* the
//! certificate, never inside the signed bytes. A 24-hour trial file was
//! therefore cryptographically valid forever: the client is the attacker, so
//! any check built on the envelope is bypassed by keeping — or
//! redistributing — the raw `certificate` string. v2 moves the claims inside
//! the signature. Accepting both formats would give that back, so a file whose
//! `alg` does not end in `+v2` is rejected.
//!
//! **Verification flow** an implementation must follow:
//! 1. Strip the `-----BEGIN/END LICENSE FILE-----` PEM markers.
//! 2. Base64-decode the body → parse the inner `{ enc, sig, alg }` JSON.
//! 3. Base64-decode `sig`.
//! 4. Ed25519-verify `sig` against **`enc`'s ASCII/UTF-8 bytes — the base64
//!    STRING itself, not its decoded bytes** (see the gotcha documented in
//!    `src/crypto/ed25519.rs`) using the account's public Ed25519 key.
//! 5. Base64-decode `enc`.
//! 6. If `alg` contains `aes-256-gcm`: split `nonce(12B) ‖ ciphertext ‖
//!    tag(16B)`, AES-256-GCM-open with
//!    `crypto::hkdf::derive_license_file_key` (HKDF-SHA256, salt
//!    `"tamga:license-file-key-v1"`, info `"license-file"`).
//! 7. Parse the resulting bytes as `{"data": <LicenseResource>, "meta": <claims>}`.
//! 8. **Enforce `meta.exp`.** Steps 1–7 only establish that the file is
//!    authentic; without this step v2 buys nothing over v1.
//!
//! Also documented here (doc comments only, not enforced by code yet):
//! - `includes` on the checkout response is **always `[]`** — there is no
//!   working `include[]` param despite the field existing; do not build a
//!   "checkout with embedded relationships" feature around it.
//! - `id` is a fresh UUIDv7 per call, **not idempotent** — calling checkout
//!   twice yields two different certificates (different signature nonce for
//!   the encrypted variant).
//! - The envelope's `ttl`/`expiry` fields are still metadata and still must
//!   not be trusted; the authoritative expiry is `meta.exp` inside the signed
//!   payload, which this module enforces.
//!
//! **Key rotation.** The three functions above take one public key, which
//! means a file signed before the account rotated its signing key fails with
//! exactly the error a forged file produces. Where that distinction matters —
//! and it usually does, since one calls for refreshing keys and the other for
//! refusing the customer — verify through a
//! [`crate::checkout::key_set::SigningKeySet`] instead: the `kid` claim selects
//! the key, an unknown `kid` is
//! [`crate::error::CheckoutError::UnknownSigningKey`], and a known `kid` with a
//! bad signature stays [`crate::error::CryptoError::VerificationFailed`].
//!
//! Public API: [`verify_license_file`] orchestrates the full flow above,
//! [`verify_license_file_with_claims`] additionally returns the signed claims,
//! and [`verify_license_file_at`] takes the current time from the caller.
//! [`verify_license_file_with_key_set`] and
//! [`verify_license_file_with_key_set_at`] are the rotation-aware equivalents.

const PEM_HEADER: &str = "-----BEGIN LICENSE FILE-----";
const PEM_FOOTER: &str = "-----END LICENSE FILE-----";

/// The `license-files` JSON:API resource returned by
/// `POST .../licenses/{id}/actions/check-out`: `{ id, type, attributes }`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LicenseFileResource {
    /// Fresh UUIDv7 per call — **not idempotent**; checking out twice
    /// yields two different certificates (different signature nonce for
    /// the encrypted variant).
    pub id: uuid::Uuid,
    /// Always `"license-files"`.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The resource's attribute bag — see [`LicenseFile`].
    pub attributes: LicenseFile,
}

/// `{ certificate, algorithm, includes, ttl, expiry, issued }` — the
/// checkout response attributes.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LicenseFile {
    /// The PEM-wrapped `.lic` certificate string — pass to
    /// [`verify_license_file`].
    pub certificate: String,
    /// `"base64+ed25519+v2"` or `"aes-256-gcm+ed25519+v2"`, matching
    /// `certificate`'s inner `alg` field.
    pub algorithm: String,
    /// **Always `[]`** — there is no working `include[]` param despite this
    /// field existing; do not build a "checkout with embedded
    /// relationships" feature around it.
    pub includes: Vec<String>,
    /// TTL in seconds, if requested. **Metadata only** — not embedded in
    /// the signed payload, and not re-checked by the server on any later
    /// validation. Expiry enforcement for an offline file is entirely this
    /// SDK's/caller's responsibility.
    pub ttl: Option<i64>,
    /// Absolute expiry timestamp derived from `issued + ttl`, if `ttl` was
    /// set. Same "metadata only" caveat as `ttl`.
    pub expiry: Option<chrono::DateTime<chrono::Utc>>,
    /// When this checkout call was issued.
    pub issued: chrono::DateTime<chrono::Utc>,
}

/// The inner `{ enc, sig, alg }` JSON payload wrapped by the PEM envelope.
#[derive(Debug, serde::Deserialize)]
struct CertPayload {
    enc: String,
    sig: String,
    alg: String,
}

/// `{"data": <LicenseResource>, "meta": <claims>}` — what `enc`
/// decodes/decrypts to in format v2.
#[derive(Debug, serde::Deserialize)]
struct DataPayload {
    data: crate::models::license::LicenseResource,
    meta: LicenseFileClaims,
}

/// The claims carried *inside* the signed bytes.
///
/// These are the point of format v2. Everything here is covered by the
/// signature, so unlike the response envelope it cannot be edited by whoever
/// holds the file.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LicenseFileClaims {
    /// Issued-at, seconds since the Unix epoch.
    pub iat: i64,
    /// Expiry, seconds since the Unix epoch. Absent means the file never
    /// expires (checkout was made without a `ttl`).
    #[serde(default)]
    pub exp: Option<i64>,
    /// Unique per checkout — usable for replay detection.
    pub jti: String,
    /// Identifies the signing key, so a file survives a key rotation.
    ///
    /// The first eight bytes of `SHA-256` over the signing key's **base64
    /// string**, lowercase hex — see [`crate::crypto::ed25519::key_id`], and
    /// [`verify_license_file_with_key_set`] for verifying through it rather
    /// than merely reading it back.
    pub kid: String,
}

/// A verified licence file: the resource plus the claims that were signed
/// alongside it.
#[derive(Debug, Clone)]
pub struct VerifiedLicenseFile {
    /// The licence the file describes.
    pub license: crate::models::license::LicenseResource,
    /// The claims that were covered by the signature.
    pub claims: LicenseFileClaims,
}

/// How much clock skew to tolerate when checking `exp`.
///
/// Deliberately small. The client's clock is under the attacker's control, so
/// a generous allowance is just a free extension of every expired file; this
/// covers ordinary NTP drift and nothing more.
///
/// Shared with [`crate::checkout::machine_file`], which enforces the same
/// `exp` claim over the same signed `meta` block. Two constants would let the
/// two file formats silently drift into different grace periods.
pub(crate) const CLOCK_SKEW_TOLERANCE_SECS: i64 = 60;

/// Parses and fully verifies a `.lic` file (from either
/// [`crate::Client::check_out_license`]'s raw PEM string or
/// [`LicenseFileResource::attributes`]'s `certificate` field), returning
/// the embedded [`crate::models::license::LicenseResource`] once the
/// signature (and decryption, if encrypted) has checked out. Works fully
/// offline — no network access required — once `ed25519_pubkey` is
/// embedded in the calling application.
///
/// `license_key` is required only for the encrypted
/// (`aes-256-gcm+ed25519+v2`) variant; pass `None` for a plain
/// (`base64+ed25519+v2`) file. A file whose `alg` lacks the `+v2` suffix is
/// rejected as [`crate::error::CheckoutError::UnsupportedAlgorithm`] — there
/// is no v1 fallback.
///
/// The signed `exp` claim is enforced against the system clock with a 60
/// second skew tolerance; use [`verify_license_file_at`] to supply the time
/// yourself.
///
/// See the module doc comment for the full verification flow this
/// implements, [`crate::crypto::ed25519`] for the signature gotcha (the
/// signature covers the base64 **string**, not its decoded bytes), and
/// [`crate::crypto::hkdf::derive_license_file_key`] for the encryption key
/// derivation.
pub fn verify_license_file(
    pem: &str,
    ed25519_pubkey: &[u8; 32],
    license_key: Option<&str>,
) -> Result<crate::models::license::LicenseResource, crate::error::CheckoutError> {
    verify_license_file_with_claims(pem, ed25519_pubkey, license_key).map(|v| v.license)
}

/// As [`verify_license_file`], also returning the signed claims.
///
/// Use this when you want `jti` for replay detection or `kid` for key-rotation
/// bookkeeping. Expiry is enforced either way — it is not opt-in.
pub fn verify_license_file_with_claims(
    pem: &str,
    ed25519_pubkey: &[u8; 32],
    license_key: Option<&str>,
) -> Result<VerifiedLicenseFile, crate::error::CheckoutError> {
    verify_license_file_at(pem, ed25519_pubkey, license_key, unix_now())
}

/// Current wall-clock time as a Unix timestamp.
///
/// `chrono` is built here without its `clock` feature on purpose (the SDK does
/// not want a system-time dependency in its default build), so this reads the
/// clock directly. A clock set before the epoch yields 0.
///
/// Shared with [`crate::checkout::machine_file`] so both offline file formats
/// read the same clock.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// As [`verify_license_file_with_claims`], with the current time supplied by
/// the caller.
///
/// Two uses. Tests get determinism. And an application that keeps a
/// server-supplied timestamp — the recommended defence against a user winding
/// the system clock back to revive an expired file — can pass that instead of
/// trusting the local clock.
pub fn verify_license_file_at(
    pem: &str,
    ed25519_pubkey: &[u8; 32],
    license_key: Option<&str>,
    now_unix: i64,
) -> Result<VerifiedLicenseFile, crate::error::CheckoutError> {
    let cert = parse_envelope(pem)?;
    // The `alg` gate runs before any key or signature work on every entry
    // point, so a v1 file gets the same answer whichever key it meets.
    let encoding = validate_alg(&cert.alg)?;
    // Nothing is decoded or decrypted until the signature over `enc` has
    // passed.
    verify_signature(ed25519_pubkey, &cert)?;
    let plaintext = decode_plaintext(&cert, encoding, license_key)?;
    finish(&plaintext, now_unix)
}

/// As [`verify_license_file`], selecting the public key by the file's own
/// `kid` claim from a set of keys the caller trusts.
///
/// This is what makes a key rotation survivable. Verifying against one embedded
/// key reports a file signed before the rotation with exactly the error a
/// forged file produces; through a key set the two are distinct outcomes:
///
/// - the `kid` is not in the set →
///   [`crate::error::CheckoutError::UnknownSigningKey`] — fetch the account's
///   key set, or ship an application update, and try again;
/// - the `kid` is in the set but the signature fails →
///   [`crate::error::CryptoError::VerificationFailed`] — refuse the file.
///
/// Build the set with [`crate::Client::signing_key_set`] (one call, cacheable
/// for the life of the process) or, with no network at all, from public keys
/// pinned in the binary via
/// [`crate::checkout::key_set::SigningKeySet::from_public_keys`].
///
/// `license_key` is required only for an encrypted file, exactly as in
/// [`verify_license_file`]. The signed `exp` claim is enforced the same way
/// too; use [`verify_license_file_with_key_set_at`] to supply the time.
///
/// One ordering difference from [`verify_license_file`] is worth knowing:
/// selecting a key needs the `kid`, and the `kid` lives inside `enc`, so `enc`
/// is decoded (and, when encrypted, decrypted under the licence key) *before*
/// the signature is checked. A file that is malformed or undecryptable
/// therefore reports that rather than a signature failure. Nothing from those
/// bytes is trusted: the only value taken from them before verification is the
/// `kid`, and it can only ever select from keys the caller already supplied.
pub fn verify_license_file_with_key_set(
    pem: &str,
    keys: &crate::checkout::key_set::SigningKeySet,
    license_key: Option<&str>,
) -> Result<VerifiedLicenseFile, crate::error::CheckoutError> {
    verify_license_file_with_key_set_at(pem, keys, license_key, unix_now())
}

/// As [`verify_license_file_with_key_set`], with the current time supplied by
/// the caller — see [`verify_license_file_at`] for why that matters.
pub fn verify_license_file_with_key_set_at(
    pem: &str,
    keys: &crate::checkout::key_set::SigningKeySet,
    license_key: Option<&str>,
    now_unix: i64,
) -> Result<VerifiedLicenseFile, crate::error::CheckoutError> {
    let cert = parse_envelope(pem)?;
    let encoding = validate_alg(&cert.alg)?;
    let plaintext = decode_plaintext(&cert, encoding, license_key)?;
    let kid = probe_kid(&plaintext)?;
    let pubkey = keys
        .find(&kid)
        .ok_or(crate::error::CheckoutError::UnknownSigningKey { kid })?;
    verify_signature(pubkey, &cert)?;
    finish(&plaintext, now_unix)
}

/// Strips the PEM markers and parses the inner `{ enc, sig, alg }` JSON.
fn parse_envelope(pem: &str) -> Result<CertPayload, crate::error::CheckoutError> {
    use base64::Engine as _;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    let body = pem
        .trim()
        .strip_prefix(PEM_HEADER)
        .and_then(|rest| rest.strip_suffix(PEM_FOOTER))
        .ok_or(crate::error::CheckoutError::MalformedPem)?
        .trim();

    let cert_json = B64
        .decode(body)
        .map_err(|_| crate::error::CheckoutError::InvalidBase64)?;
    Ok(serde_json::from_slice(&cert_json)?)
}

/// Ed25519-verifies `cert.sig` against `cert.enc`.
///
/// ⚠️ The signature covers `enc`'s ASCII/UTF-8 bytes — the base64 STRING
/// itself, never its decoded bytes. See `src/crypto/ed25519.rs`.
fn verify_signature(
    ed25519_pubkey: &[u8; 32],
    cert: &CertPayload,
) -> Result<(), crate::error::CheckoutError> {
    use base64::Engine as _;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    let sig_bytes = B64
        .decode(&cert.sig)
        .map_err(|_| crate::error::CheckoutError::InvalidBase64)?;
    crate::crypto::ed25519::verify(ed25519_pubkey, cert.enc.as_bytes(), &sig_bytes)?;
    Ok(())
}

/// How `enc` is encoded, as declared by `alg`. Private: the two legal
/// strings are matched whole and nothing outside this module needs the
/// distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncEncoding {
    /// `base64+ed25519+v2` — `enc` is base64 of the payload JSON.
    Plain,
    /// `aes-256-gcm+ed25519+v2` — `enc` is base64 of `nonce ‖ ciphertext ‖ tag`.
    Aes256Gcm,
}

/// The `alg` gate. Runs before any key or signature work on every entry
/// point, single-key and key-set alike.
///
/// Exactly two strings are legal, matched whole; a v1 file (no `+v2`) is
/// [`crate::error::CheckoutError::UnsupportedAlgorithm`] and there is no
/// fallback — see the module doc for why. Running it first is what makes
/// the answer entry-point-independent: a v1 file presented with the wrong
/// key used to report a signature failure through [`verify_license_file`]
/// and an unsupported algorithm through
/// [`verify_license_file_with_key_set`] — one file, two diagnoses.
fn validate_alg(alg: &str) -> Result<EncEncoding, crate::error::CheckoutError> {
    match alg {
        "base64+ed25519+v2" => Ok(EncEncoding::Plain),
        "aes-256-gcm+ed25519+v2" => Ok(EncEncoding::Aes256Gcm),
        other => Err(crate::error::CheckoutError::UnsupportedAlgorithm(
            other.to_string(),
        )),
    }
}

/// Base64-decodes `enc`, decrypting it first when `encoding` says so.
///
/// `encoding` comes from [`validate_alg`], which every caller has already
/// run, so no `alg` check happens here.
fn decode_plaintext(
    cert: &CertPayload,
    encoding: EncEncoding,
    license_key: Option<&str>,
) -> Result<Vec<u8>, crate::error::CheckoutError> {
    use base64::Engine as _;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    let enc_bytes = B64
        .decode(&cert.enc)
        .map_err(|_| crate::error::CheckoutError::InvalidBase64)?;

    match encoding {
        EncEncoding::Plain => Ok(enc_bytes),
        EncEncoding::Aes256Gcm => {
            let key_str = license_key.ok_or(crate::error::CheckoutError::LicenseKeyMissing)?;
            let key = crate::crypto::hkdf::derive_license_file_key(key_str);
            // nonce(12B) ‖ ciphertext ‖ tag(16B) — at least 28 bytes even
            // for an empty plaintext.
            if enc_bytes.len() < 12 + 16 {
                return Err(crate::error::CryptoError::DecryptionFailed.into());
            }
            let (nonce_bytes, ciphertext_and_tag) = enc_bytes.split_at(12);
            let nonce: [u8; 12] = nonce_bytes
                .try_into()
                .expect("split_at(12) guarantees a 12-byte slice");
            Ok(crate::crypto::aes_gcm::decrypt(
                &key,
                &nonce,
                ciphertext_and_tag,
            )?)
        }
    }
}

/// Reads **only** the `kid` claim out of not-yet-verified payload bytes.
///
/// Deliberately its own minimal type rather than a full [`DataPayload`] parse:
/// the one value taken from unverified bytes should be the one value needed to
/// pick a key, and everything else waits until the signature has passed.
///
/// Shared with [`crate::checkout::machine_file`], whose payload carries the
/// same `meta` block built from the same server-side struct.
pub(crate) fn probe_kid(plaintext: &[u8]) -> Result<String, crate::error::CheckoutError> {
    #[derive(serde::Deserialize)]
    struct KidProbe {
        meta: KidProbeMeta,
    }
    #[derive(serde::Deserialize)]
    struct KidProbeMeta {
        kid: String,
    }

    let probe: KidProbe = serde_json::from_slice(plaintext)?;
    Ok(probe.meta.kid)
}

/// Parses the verified payload and enforces its signed `exp` claim.
fn finish(
    plaintext: &[u8],
    now_unix: i64,
) -> Result<VerifiedLicenseFile, crate::error::CheckoutError> {
    let payload: DataPayload = serde_json::from_slice(plaintext)?;

    // The signature proves the file is authentic. It does not prove it is
    // still valid — that is this check, and skipping it is what made v1 files
    // permanent.
    if let Some(exp) = payload.meta.exp {
        // `saturating_sub`, not `-`: `now_unix` comes from the caller, and an
        // absurd one must not panic in a debug build or wrap in a release one.
        if now_unix.saturating_sub(CLOCK_SKEW_TOLERANCE_SECS) > exp {
            return Err(crate::error::CheckoutError::Expired { exp });
        }
    }

    Ok(VerifiedLicenseFile {
        license: payload.data,
        claims: payload.meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use rand::RngCore;

    const B64_TEST: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    fn gen_keypair() -> ([u8; 32], SigningKey) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        (signing_key.verifying_key().to_bytes(), signing_key)
    }

    /// Builds a `.lic` PEM exactly the way the server's own encoder does, so
    /// these tests exercise the same wire format a real server produces —
    /// notably signing over the base64 **string**, not decoded bytes.
    fn build_pem(
        payload_json: &str,
        signing_key: &SigningKey,
        encryption_key: Option<&[u8; 32]>,
    ) -> String {
        use base64::Engine as _;
        const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

        let (enc, alg) = match encryption_key {
            None => (B64.encode(payload_json.as_bytes()), "base64+ed25519+v2"),
            Some(key) => {
                use aes_gcm::aead::Aead;
                use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
                use rand::{rngs::OsRng as AeadOsRng, RngCore as _};
                let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
                let mut nonce_bytes = [0u8; 12];
                AeadOsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from(nonce_bytes);
                let ciphertext_and_tag = cipher.encrypt(&nonce, payload_json.as_bytes()).unwrap();
                let mut out = nonce_bytes.to_vec();
                out.extend_from_slice(&ciphertext_and_tag);
                (B64.encode(&out), "aes-256-gcm+ed25519+v2")
            }
        };

        let sig = B64.encode(signing_key.sign(enc.as_bytes()).to_bytes());
        let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": alg });
        let cert_json = serde_json::to_string(&cert).unwrap();
        let pem_body = B64.encode(cert_json.as_bytes());
        format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}")
    }

    /// The same payload with a chosen `kid` claim, so a test can name a key.
    fn payload_json_with_kid(kid: &str) -> String {
        let mut v: serde_json::Value =
            serde_json::from_str(&representative_payload_json()).unwrap();
        v["meta"]["kid"] = serde_json::json!(kid);
        v.to_string()
    }

    /// Base64 of a raw public key, the format the server publishes and the
    /// format [`crate::crypto::ed25519::key_id`] hashes.
    fn pubkey_b64(pubkey: &[u8; 32]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(pubkey)
    }

    /// Re-wraps `pem` with a different `alg`, leaving `enc` and `sig` intact.
    /// `alg` is not covered by the signature, so this is exactly the downgrade
    /// an attacker can attempt.
    fn repack_alg(pem: &str, alg: &str) -> String {
        use base64::Engine as _;
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let cert_json = B64_TEST.decode(body.trim()).unwrap();
        let mut cert: serde_json::Value = serde_json::from_slice(&cert_json).unwrap();
        cert["alg"] = serde_json::json!(alg);
        let repacked = B64_TEST.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        format!("{PEM_HEADER}\n{repacked}\n{PEM_FOOTER}")
    }

    fn representative_payload_json() -> String {
        serde_json::json!({
            "data": {
                "type": "licenses",
                "id": "01926b3e-0000-7000-8000-000000000000",
                "attributes": {
                    "name": "Acme Corp", "key": "lic-abc123", "status": "ACTIVE",
                    "expiry": null, "suspended": false, "protected": false, "uses": 0,
                    "scheme": null, "encrypted": false, "strict": false, "floating": false,
                    "max_machines": null, "max_uses": null, "max_users": null,
                    "last_validated_at": null, "last_check_in_at": null, "last_check_out_at": null,
                    "machines_count": 0, "metadata": {},
                    "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
                }
            },
            "meta": { "iat": 1_767_225_600, "jti": "test-jti", "kid": "test-kid" }
        })
        .to_string()
    }

    /// The same payload with an `exp` claim `offset` seconds from `iat`.
    fn payload_json_expiring_at(exp: i64) -> String {
        let mut v: serde_json::Value =
            serde_json::from_str(&representative_payload_json()).unwrap();
        v["meta"]["exp"] = serde_json::json!(exp);
        v.to_string()
    }

    // ── Format v2: the expiry claim ──────────────────────────────────────

    #[test]
    fn an_expired_file_is_refused_even_though_its_signature_is_valid() {
        // The whole point of v2. In v1 the requested TTL lived only in the
        // JSON:API envelope around the certificate, so a 24-hour trial file
        // stayed cryptographically valid forever and the client — which is the
        // attacker — simply kept the raw PEM.
        let (pubkey, signing_key) = gen_keypair();
        let exp = 1_767_225_600;
        let pem = build_pem(&payload_json_expiring_at(exp), &signing_key, None);

        let err = verify_license_file_at(&pem, &pubkey, None, exp + 3600).unwrap_err();
        assert!(matches!(err, crate::error::CheckoutError::Expired { .. }));
    }

    #[test]
    fn a_file_within_its_ttl_verifies() {
        let (pubkey, signing_key) = gen_keypair();
        let exp = 1_767_225_600;
        let pem = build_pem(&payload_json_expiring_at(exp), &signing_key, None);

        let verified = verify_license_file_at(&pem, &pubkey, None, exp - 3600).unwrap();
        assert_eq!(verified.claims.exp, Some(exp));
    }

    #[test]
    fn a_file_without_an_exp_claim_never_expires() {
        // Checkout without a `ttl` produces no `exp`. That must read as
        // perpetual, not as "expired at the epoch".
        let (pubkey, signing_key) = gen_keypair();
        let pem = build_pem(&representative_payload_json(), &signing_key, None);

        let verified = verify_license_file_at(&pem, &pubkey, None, i64::MAX / 2).unwrap();
        assert!(verified.claims.exp.is_none());
    }

    #[test]
    fn clock_skew_tolerance_is_seconds_not_hours() {
        // A generous allowance would just be a free extension on every expired
        // file, since the clock belongs to the attacker.
        let (pubkey, signing_key) = gen_keypair();
        let exp = 1_767_225_600;
        let pem = build_pem(&payload_json_expiring_at(exp), &signing_key, None);

        // Just inside the tolerance.
        assert!(verify_license_file_at(&pem, &pubkey, None, exp + 30).is_ok());
        // Comfortably outside it.
        assert!(verify_license_file_at(&pem, &pubkey, None, exp + 600).is_err());
    }

    #[test]
    fn a_v1_file_is_refused_outright() {
        use base64::Engine as _;
        // Accepting both formats would hand back the permanent-file problem:
        // an attacker holding any v1 certificate could keep using it forever.
        let (pubkey, signing_key) = gen_keypair();
        let pem = build_pem(&representative_payload_json(), &signing_key, None);
        // Repack the same certificate with a v1 `alg`.
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let cert_json = B64_TEST.decode(body.trim()).unwrap();
        let mut cert: serde_json::Value = serde_json::from_slice(&cert_json).unwrap();
        cert["alg"] = serde_json::json!("base64+ed25519");
        let repacked = B64_TEST.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        let v1_pem = format!("{PEM_HEADER}\n{repacked}\n{PEM_FOOTER}");

        let err = verify_license_file(&v1_pem, &pubkey, None).unwrap_err();
        assert!(matches!(
            err,
            crate::error::CheckoutError::UnsupportedAlgorithm(ref a) if a == "base64+ed25519"
        ));
    }

    #[test]
    fn a_v1_alg_is_refused_before_the_signature_is_even_checked() {
        // D17. The same file must produce the same error from every entry
        // point, and the `alg` gate must not depend on holding the right
        // key: presented with the WRONG key, a v1 file used to report a
        // signature failure here and UnsupportedAlgorithm through a key set.
        let (_pubkey, signing_key) = gen_keypair();
        let (wrong_pubkey, _) = gen_keypair();
        let pem = build_pem(&representative_payload_json(), &signing_key, None);
        let v1_pem = repack_alg(&pem, "base64+ed25519");

        assert!(matches!(
            verify_license_file(&v1_pem, &wrong_pubkey, None).unwrap_err(),
            crate::error::CheckoutError::UnsupportedAlgorithm(ref a) if a == "base64+ed25519"
        ));
    }

    #[test]
    fn the_claims_carry_a_replay_id_and_a_key_id() {
        let (pubkey, signing_key) = gen_keypair();
        let pem = build_pem(&representative_payload_json(), &signing_key, None);

        let verified = verify_license_file_with_claims(&pem, &pubkey, None).unwrap();
        assert!(!verified.claims.jti.is_empty());
        assert!(!verified.claims.kid.is_empty());
    }

    #[test]
    fn verifies_a_known_good_plain_fixture() {
        let (pubkey, signing_key) = gen_keypair();
        let pem = build_pem(&representative_payload_json(), &signing_key, None);
        let license = verify_license_file(&pem, &pubkey, None).unwrap();
        assert_eq!(license.attributes.key, Some("lic-abc123".to_string()));
    }

    #[test]
    fn verifies_a_known_good_encrypted_fixture() {
        let (pubkey, signing_key) = gen_keypair();
        let license_key = "lic-abc123";
        let enc_key = crate::crypto::hkdf::derive_license_file_key(license_key);
        let pem = build_pem(&representative_payload_json(), &signing_key, Some(&enc_key));
        let license = verify_license_file(&pem, &pubkey, Some(license_key)).unwrap();
        assert_eq!(license.attributes.key, Some("lic-abc123".to_string()));
    }

    #[test]
    fn rejects_tampered_signature() {
        let (pubkey, signing_key) = gen_keypair();
        let mut pem = build_pem(&representative_payload_json(), &signing_key, None);
        // Flip a character inside the base64 PEM body — corrupts the
        // encoded `sig` field without breaking base64/JSON parsing.
        let mid = pem.len() / 2;
        let corrupted_char = if pem.as_bytes()[mid] == b'A' {
            'B'
        } else {
            'A'
        };
        pem.replace_range(mid..mid + 1, &corrupted_char.to_string());
        assert!(verify_license_file(&pem, &pubkey, None).is_err());
    }

    #[test]
    fn rejects_tampered_ciphertext_aead_tag_mismatch() {
        let (pubkey, signing_key) = gen_keypair();
        let license_key = "lic-abc123";
        let enc_key = crate::crypto::hkdf::derive_license_file_key(license_key);
        // Re-sign a manually tampered `enc` so signature verification
        // passes but AEAD decryption must fail — proves the AEAD tag
        // check itself, independent of signature verification.
        use base64::Engine as _;
        const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
        let mut enc_bytes = {
            use aes_gcm::aead::Aead;
            use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
            use rand::{rngs::OsRng as AeadOsRng, RngCore as _};
            let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*enc_key));
            let mut nonce_bytes = [0u8; 12];
            AeadOsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from(nonce_bytes);
            let ciphertext_and_tag = cipher
                .encrypt(&nonce, representative_payload_json().as_bytes())
                .unwrap();
            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&ciphertext_and_tag);
            out
        };
        let last = enc_bytes.len() - 1;
        enc_bytes[last] ^= 0xff;
        let enc = B64.encode(&enc_bytes);
        let sig = B64.encode(signing_key.sign(enc.as_bytes()).to_bytes());
        let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": "aes-256-gcm+ed25519+v2" });
        let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        let pem = format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}");

        assert!(verify_license_file(&pem, &pubkey, Some(license_key)).is_err());
    }

    // ── Key rotation: verifying through a key set ────────────────────────

    #[test]
    fn a_file_signed_before_a_rotation_still_verifies_against_the_retired_key() {
        // The scenario the whole key-set path exists for. Two keys, the file
        // signed by the older one, and a set that holds both — the retired key
        // is in the set precisely because the server never deletes it.
        let (old_pubkey, old_signing) = gen_keypair();
        let (new_pubkey, _new_signing) = gen_keypair();
        let old_b64 = pubkey_b64(&old_pubkey);
        let kid = crate::crypto::ed25519::key_id(&old_b64);

        let pem = build_pem(&payload_json_with_kid(&kid), &old_signing, None);
        let keys = crate::checkout::key_set::SigningKeySet::from_public_keys([
            pubkey_b64(&new_pubkey),
            old_b64,
        ])
        .unwrap();

        let verified = verify_license_file_with_key_set(&pem, &keys, None).unwrap();
        assert_eq!(verified.claims.kid, kid);
        assert_eq!(
            verified.license.attributes.key,
            Some("lic-abc123".to_string())
        );

        // …and the single-key call against the *current* key is exactly the
        // false alarm this replaces.
        assert!(verify_license_file(&pem, &new_pubkey, None).is_err());
    }

    #[test]
    fn an_unknown_kid_is_reported_distinctly_from_a_bad_signature() {
        // The distinction M22 exists to create. Same file, two key sets: one
        // that has never heard of the signer, and one that has and rejects the
        // signature. Collapsing these into one error is what left a caller
        // unable to tell a stale key set from a forgery.
        let (_pubkey, signing) = gen_keypair();
        let (other_pubkey, _) = gen_keypair();
        let other_b64 = pubkey_b64(&other_pubkey);

        let pem = build_pem(&payload_json_with_kid("00ff00ff00ff00ff"), &signing, None);

        // 1. The claimed kid is in no key we hold.
        let stale =
            crate::checkout::key_set::SigningKeySet::from_public_keys([&other_b64]).unwrap();
        let err = verify_license_file_with_key_set(&pem, &stale, None).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::CheckoutError::UnknownSigningKey { ref kid }
                    if kid == "00ff00ff00ff00ff"
            ),
            "expected UnknownSigningKey, got {err:?}"
        );

        // 2. The claimed kid resolves — to a key that did not sign this file.
        let wrong_key_under_the_claimed_kid = build_pem(
            &payload_json_with_kid(&crate::crypto::ed25519::key_id(&other_b64)),
            &signing,
            None,
        );
        let err = verify_license_file_with_key_set(&wrong_key_under_the_claimed_kid, &stale, None)
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::CheckoutError::Crypto(crate::error::CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn an_empty_key_set_reports_the_kid_rather_than_a_forgery() {
        // A fetch that returned nothing, or an application shipped with no
        // pinned key: honest as "I hold no key for this", never as "forged".
        let (_pubkey, signing) = gen_keypair();
        let pem = build_pem(&payload_json_with_kid("abcdef0123456789"), &signing, None);
        let empty = crate::checkout::key_set::SigningKeySet::default();

        let err = verify_license_file_with_key_set(&pem, &empty, None).unwrap_err();
        assert!(matches!(
            err,
            crate::error::CheckoutError::UnknownSigningKey { ref kid } if kid == "abcdef0123456789"
        ));
    }

    #[test]
    fn the_key_set_path_decrypts_an_encrypted_file_and_still_enforces_exp() {
        // The kid lives inside the ciphertext, so the encrypted variant has to
        // be decrypted before a key can be chosen — and expiry is enforced
        // afterwards exactly as on the single-key path, not skipped.
        let (pubkey, signing) = gen_keypair();
        let b64 = pubkey_b64(&pubkey);
        let kid = crate::crypto::ed25519::key_id(&b64);
        let keys = crate::checkout::key_set::SigningKeySet::from_public_keys([&b64]).unwrap();

        let license_key = "lic-abc123";
        let enc_key = crate::crypto::hkdf::derive_license_file_key(license_key);
        let exp = 1_767_225_600;
        let mut payload: serde_json::Value =
            serde_json::from_str(&payload_json_with_kid(&kid)).unwrap();
        payload["meta"]["exp"] = serde_json::json!(exp);
        let pem = build_pem(&payload.to_string(), &signing, Some(&enc_key));

        let verified =
            verify_license_file_with_key_set_at(&pem, &keys, Some(license_key), exp - 3600)
                .unwrap();
        assert_eq!(verified.claims.exp, Some(exp));

        let err = verify_license_file_with_key_set_at(&pem, &keys, Some(license_key), exp + 3600)
            .unwrap_err();
        assert!(matches!(err, crate::error::CheckoutError::Expired { .. }));

        // Without the licence key the payload cannot be decoded at all, so no
        // key can be selected — reported as the missing key, not as a forgery.
        assert!(matches!(
            verify_license_file_with_key_set(&pem, &keys, None).unwrap_err(),
            crate::error::CheckoutError::LicenseKeyMissing
        ));
    }

    #[test]
    fn the_key_set_path_refuses_a_v1_file_too() {
        use base64::Engine as _;
        // The alg gate runs first on every entry point; the key-set path is
        // no way round it.
        let (pubkey, signing) = gen_keypair();
        let b64 = pubkey_b64(&pubkey);
        let keys = crate::checkout::key_set::SigningKeySet::from_public_keys([&b64]).unwrap();
        let pem = build_pem(
            &payload_json_with_kid(&crate::crypto::ed25519::key_id(&b64)),
            &signing,
            None,
        );

        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let cert_json = B64_TEST.decode(body.trim()).unwrap();
        let mut cert: serde_json::Value = serde_json::from_slice(&cert_json).unwrap();
        cert["alg"] = serde_json::json!("base64+ed25519");
        let repacked = B64_TEST.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        let v1_pem = format!("{PEM_HEADER}\n{repacked}\n{PEM_FOOTER}");

        assert!(matches!(
            verify_license_file_with_key_set(&v1_pem, &keys, None).unwrap_err(),
            crate::error::CheckoutError::UnsupportedAlgorithm(ref a) if a == "base64+ed25519"
        ));
    }

    #[test]
    fn a_payload_without_a_kid_claim_is_a_parse_failure_not_an_unknown_key() {
        use base64::Engine as _;
        // Every v2 file the server issues carries one. A payload missing it is
        // malformed, and calling that "signed by a key I do not have" would
        // point the caller at the wrong remedy.
        let (pubkey, signing) = gen_keypair();
        let b64 = pubkey_b64(&pubkey);
        let keys = crate::checkout::key_set::SigningKeySet::from_public_keys([&b64]).unwrap();

        let mut payload: serde_json::Value =
            serde_json::from_str(&representative_payload_json()).unwrap();
        payload["meta"].as_object_mut().unwrap().remove("kid");
        let enc = B64_TEST.encode(payload.to_string().as_bytes());
        let sig = B64_TEST.encode(signing.sign(enc.as_bytes()).to_bytes());
        let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": "base64+ed25519+v2" });
        let pem_body = B64_TEST.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        let pem = format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}");

        assert!(matches!(
            verify_license_file_with_key_set(&pem, &keys, None).unwrap_err(),
            crate::error::CheckoutError::InvalidJson(_)
        ));
    }

    #[test]
    fn decoded_bytes_signature_verification_fails_proving_the_string_bytes_gotcha() {
        // Negative test proving the SDK signs/verifies over the base64
        // STRING, not decoded bytes.
        let (pubkey, signing_key) = gen_keypair();
        let payload = representative_payload_json();
        use base64::Engine as _;
        const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
        let enc = B64.encode(payload.as_bytes());
        let decoded_enc_bytes = B64.decode(&enc).unwrap();

        // Sign over the DECODED bytes instead of the string — the wrong
        // way to do it.
        let wrong_sig = signing_key.sign(&decoded_enc_bytes);

        // This SDK's `verify_license_file` always verifies against the
        // base64 STRING bytes (`cert.enc.as_bytes()`), so a signature
        // computed over decoded bytes must NOT verify.
        let verify_result =
            crate::crypto::ed25519::verify(&pubkey, enc.as_bytes(), &wrong_sig.to_bytes());
        assert!(
            verify_result.is_err(),
            "a signature over decoded bytes must not verify against the base64 string bytes"
        );
    }
}
