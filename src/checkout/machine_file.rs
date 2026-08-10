//! `.mach` file parsing and verification.
//!
//! Same shape as `.lic` (see `src/checkout/license_file.rs`) with these
//! machine-specific differences (see `docs/plans/tamga-rust.plan.md` §F):
//!
//! - Wrapper: `-----BEGIN MACHINE FILE-----`/`-----END MACHINE FILE-----`,
//!   same inner `{ enc, sig, alg }` JSON structure.
//! - `ttl` is **validated server-side**: must be `> 0` and `<= 31536000`
//!   (365 days) or `422 TTL_INVALID`. The client should pre-check this range
//!   before the round-trip, in addition to handling the server error.
//! - Signing scheme is taken from the **license's** `scheme` field
//!   (Ed25519/RSA-PKCS1/RSA-PSS/ECDSA-P256 — see `src/models/policy.rs`
//!   `LicenseScheme`), not hardcoded to Ed25519 like license checkout.
//!   ⚠️ `RSA_2048_JWT_RS256` is explicitly rejected for machine files (the
//!   server returns `422 SCHEME_NOT_SUPPORTED`) — this SDK's local verifier
//!   must reject that scheme up front rather than attempt JWT parsing.
//! - Encryption key (when encrypted) is **HKDF-SHA256** derived (see
//!   `src/crypto/hkdf.rs`): `salt="tamga:machine-file-key-v1"`,
//!   `ikm=<license key>`, `info=<machine fingerprint>` → 32-byte AES key. A
//!   verifier needs both the license key and the target machine's
//!   fingerprint to decrypt.
//!
//! Intended public API: `verify_machine_file(pem: &str, scheme:
//! crate::models::policy::LicenseScheme, pubkey: &[u8], license_key:
//! Option<&str>, fingerprint: Option<&str>) -> Result<MachineResource,
//! CheckoutError>`, dispatching to the correct verifier in `src/crypto/`
//! based on `scheme`.

const PEM_HEADER: &str = "-----BEGIN MACHINE FILE-----";
const PEM_FOOTER: &str = "-----END MACHINE FILE-----";

/// The `machine-files` JSON:API resource returned by
/// `POST .../machines/{id}/actions/check-out`: `{ id, type, attributes }`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MachineFileResource {
    /// Fresh UUIDv7 per call — not idempotent, same as license files.
    pub id: uuid::Uuid,
    /// Always `"machine-files"`.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The resource's attribute bag — see [`MachineFile`].
    pub attributes: MachineFile,
}

/// `{ certificate, algorithm, includes, ttl, expiry, issued }` — the
/// checkout response attributes. Same shape as
/// [`crate::checkout::license_file::LicenseFile`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MachineFile {
    /// The PEM-wrapped `.mach` certificate string — pass to
    /// [`verify_machine_file`].
    pub certificate: String,
    /// `"{base64|aes-256-gcm}+{ed25519|rsa-sha256|rsa-pss-sha256|ecdsa-p256}"`.
    pub algorithm: String,
    /// **Always `[]`** — same caveat as license files.
    pub includes: Vec<String>,
    /// TTL in seconds, if requested. Metadata only — same caveat as license
    /// files.
    pub ttl: Option<i64>,
    /// Absolute expiry timestamp, if `ttl` was set.
    pub expiry: Option<chrono::DateTime<chrono::Utc>>,
    /// When this checkout call was issued.
    pub issued: chrono::DateTime<chrono::Utc>,
}

/// Maximum `ttl` seconds the server accepts (365 days) — see
/// [`check_ttl`].
pub const MAX_TTL_SECS: u64 = 365 * 24 * 3600;

/// Client-side pre-check mirroring the server's validated `ttl` range
/// (`> 0 && <= 31536000`), so a caller gets a typed error before the round
/// trip instead of only discovering the problem via a `422 TTL_INVALID` API
/// error.
pub fn check_ttl(ttl: u64) -> Result<(), crate::error::CheckoutError> {
    if ttl == 0 || ttl > MAX_TTL_SECS {
        return Err(crate::error::CheckoutError::TtlOutOfRange(format!(
            "must be > 0 and <= {MAX_TTL_SECS}, got {ttl}"
        )));
    }
    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct CertPayload {
    enc: String,
    sig: String,
    alg: String,
}

#[derive(Debug, serde::Deserialize)]
struct DataPayload {
    data: crate::models::machine::MachineResource,
}

/// Maps a [`crate::models::policy::LicenseScheme`] to its `alg` suffix, per
/// `tamga-api`'s `scheme_to_alg_suffix` — note both `Rsa2048Pkcs1Sign` and
/// `Rsa2048JwtRs256` map to the same `"rsa-sha256"` suffix server-side,
/// which is exactly why algorithm selection in [`verify_machine_file`] is
/// driven by the caller-supplied `scheme` parameter, never by parsing the
/// file's self-declared `alg` string — a self-declared string can't
/// disambiguate those two schemes, and trusting untrusted input to select
/// a crypto primitive is an algorithm-confusion risk regardless.
fn scheme_alg_suffix(scheme: crate::models::policy::LicenseScheme) -> &'static str {
    use crate::models::policy::LicenseScheme;
    match scheme {
        LicenseScheme::Ed25519Sign => "ed25519",
        LicenseScheme::Rsa2048Pkcs1Sign | LicenseScheme::Rsa2048JwtRs256 => "rsa-sha256",
        LicenseScheme::Rsa2048Pkcs1PssSign => "rsa-pss-sha256",
        LicenseScheme::EcdsaP256Sign => "ecdsa-p256",
    }
}

/// Parses and fully verifies a `.mach` file, returning the embedded
/// [`crate::models::machine::MachineResource`] once the signature (and
/// decryption, if encrypted) has checked out.
///
/// `scheme` **must** come from the license's own `scheme` field (via
/// whatever license resource governs this machine) — never from parsing
/// the file's `alg` string, which cannot safely disambiguate
/// `RSA_2048_PKCS1_SIGN` from `RSA_2048_JWT_RS256` (see
/// [`scheme_alg_suffix`]). If the license has no `scheme` set, pass
/// [`crate::models::policy::LicenseScheme::Ed25519Sign`] — the server's own
/// default when generating a machine file for an unset scheme.
///
/// `pubkey` is the raw public key for `scheme`: 32 bytes for Ed25519, a
/// SubjectPublicKeyInfo (SPKI) DER blob for either RSA variant, or a
/// 65-byte uncompressed P-256 point for ECDSA.
///
/// `license_key`/`fingerprint` are required only for an encrypted
/// (`aes-256-gcm+...`) file — both are needed to re-derive the HKDF key
/// (see `src/crypto/hkdf.rs`).
pub fn verify_machine_file(
    pem: &str,
    scheme: crate::models::policy::LicenseScheme,
    pubkey: &[u8],
    license_key: Option<&str>,
    fingerprint: Option<&str>,
) -> Result<crate::models::machine::MachineResource, crate::error::CheckoutError> {
    use crate::models::policy::LicenseScheme;

    // ⚠️ Reject up front — before any parsing — rather than let a
    // JWT-scheme signature attempt fail confusingly downstream.
    if scheme == LicenseScheme::Rsa2048JwtRs256 {
        return Err(crate::error::CheckoutError::SchemeNotSupported);
    }

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
    let cert: CertPayload = serde_json::from_slice(&cert_json)?;

    let (enc_prefix, alg_suffix) = cert
        .alg
        .split_once('+')
        .ok_or_else(|| crate::error::CheckoutError::UnsupportedAlgorithm(cert.alg.clone()))?;
    let expected_suffix = scheme_alg_suffix(scheme);
    if alg_suffix != expected_suffix {
        return Err(crate::error::CheckoutError::UnsupportedAlgorithm(format!(
            "file declares alg suffix {alg_suffix:?}, expected {expected_suffix:?} for the supplied scheme"
        )));
    }

    // ⚠️ Same gotcha as license files: signature covers `enc`'s ASCII/UTF-8
    // STRING bytes, never its decoded bytes.
    let sig_bytes = B64
        .decode(&cert.sig)
        .map_err(|_| crate::error::CheckoutError::InvalidBase64)?;
    match scheme {
        LicenseScheme::Ed25519Sign => {
            let pubkey32: [u8; 32] = pubkey
                .try_into()
                .map_err(|_| crate::error::CryptoError::InvalidKey)?;
            crate::crypto::ed25519::verify(&pubkey32, cert.enc.as_bytes(), &sig_bytes)?;
        }
        LicenseScheme::Rsa2048Pkcs1Sign => {
            crate::crypto::rsa::verify_pkcs1(pubkey, cert.enc.as_bytes(), &sig_bytes)?;
        }
        LicenseScheme::Rsa2048Pkcs1PssSign => {
            crate::crypto::rsa::verify_pss(pubkey, cert.enc.as_bytes(), &sig_bytes)?;
        }
        LicenseScheme::EcdsaP256Sign => {
            crate::crypto::ecdsa::verify(pubkey, cert.enc.as_bytes(), &sig_bytes)?;
        }
        // Provably unreachable given the early return above, but a typed
        // error (not `unreachable!()`) so a future refactor that moves or
        // conditions that early return fails safe — a panic on
        // attacker-controlled input, versus a typed error, is the
        // difference the security review flagged here (LOW, non-blocking).
        LicenseScheme::Rsa2048JwtRs256 => {
            return Err(crate::error::CheckoutError::SchemeNotSupported);
        }
    }

    let enc_bytes = B64
        .decode(&cert.enc)
        .map_err(|_| crate::error::CheckoutError::InvalidBase64)?;

    let plaintext = match enc_prefix {
        "base64" => enc_bytes,
        "aes-256-gcm" => {
            let key_str = license_key.ok_or(crate::error::CheckoutError::LicenseKeyMissing)?;
            let fp = fingerprint.ok_or(crate::error::CheckoutError::FingerprintMissing)?;
            let key = crate::crypto::hkdf::derive_machine_file_key(key_str, fp);
            if enc_bytes.len() < 12 + 16 {
                return Err(crate::error::CryptoError::DecryptionFailed.into());
            }
            let (nonce_bytes, ciphertext_and_tag) = enc_bytes.split_at(12);
            let nonce: [u8; 12] = nonce_bytes
                .try_into()
                .expect("split_at(12) guarantees a 12-byte slice");
            crate::crypto::aes_gcm::decrypt(&key, &nonce, ciphertext_and_tag)?
        }
        other => {
            return Err(crate::error::CheckoutError::UnsupportedAlgorithm(
                other.to_string(),
            ));
        }
    };

    let payload: DataPayload = serde_json::from_slice(&plaintext)?;
    Ok(payload.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::policy::LicenseScheme;
    use base64::Engine as _;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    fn representative_payload_json() -> String {
        serde_json::json!({
            "data": {
                "type": "machines",
                "id": "01926b3e-2222-7000-8000-000000000000",
                "attributes": {
                    "fingerprint": "fp-abc123", "cores": 4, "memory": null, "disk": null,
                    "ip": null, "hostname": "host1", "platform": "linux", "name": null,
                    "heartbeat_status": "NOT_STARTED", "last_heartbeat_at": null,
                    "next_heartbeat_at": null, "last_check_out_at": null, "metadata": {},
                    "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
                }
            }
        })
        .to_string()
    }

    /// Signs `enc` with the scheme-appropriate key, returning the raw
    /// signature bytes — mirrors `tamga-api`'s `sign()` dispatch.
    fn sign_for_scheme(
        scheme: LicenseScheme,
        enc: &str,
    ) -> (Vec<u8> /* pubkey */, Vec<u8> /* sig */) {
        use aws_lc_rs::rand::SystemRandom;
        match scheme {
            LicenseScheme::Ed25519Sign => {
                use ed25519_dalek::{Signer, SigningKey};
                use rand::rngs::OsRng;
                use rand::RngCore;
                let mut secret = [0u8; 32];
                OsRng.fill_bytes(&mut secret);
                let signing_key = SigningKey::from_bytes(&secret);
                let pubkey = signing_key.verifying_key().to_bytes().to_vec();
                let sig = signing_key.sign(enc.as_bytes()).to_bytes().to_vec();
                (pubkey, sig)
            }
            LicenseScheme::Rsa2048Pkcs1Sign | LicenseScheme::Rsa2048JwtRs256 => {
                use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
                use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256};
                let kp = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
                // `.public_key()` — NOT `.as_der()` (that's the PKCS8
                // *private* key DER). See crypto/rsa.rs's test helper for
                // the same fix with more detail.
                let pubkey = kp.public_key().as_ref().to_vec();
                let rng = SystemRandom::new();
                let mut sig = vec![0u8; kp.public_modulus_len()];
                kp.sign(&RSA_PKCS1_SHA256, &rng, enc.as_bytes(), &mut sig)
                    .unwrap();
                (pubkey, sig)
            }
            LicenseScheme::Rsa2048Pkcs1PssSign => {
                use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
                use aws_lc_rs::signature::{KeyPair as _, RSA_PSS_SHA256};
                let kp = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
                let pubkey = kp.public_key().as_ref().to_vec();
                let rng = SystemRandom::new();
                let mut sig = vec![0u8; kp.public_modulus_len()];
                kp.sign(&RSA_PSS_SHA256, &rng, enc.as_bytes(), &mut sig)
                    .unwrap();
                (pubkey, sig)
            }
            LicenseScheme::EcdsaP256Sign => {
                use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
                let rng = SystemRandom::new();
                let pkcs8 =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
                let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
                    .unwrap();
                let pubkey = kp.public_key().as_ref().to_vec();
                let sig = kp.sign(&rng, enc.as_bytes()).unwrap().as_ref().to_vec();
                (pubkey, sig)
            }
        }
    }

    fn build_pem(scheme: LicenseScheme, encrypt_key: Option<[u8; 32]>) -> (Vec<u8>, String) {
        let payload = representative_payload_json();
        let suffix = scheme_alg_suffix(scheme);
        let (enc_prefix, enc) = match encrypt_key {
            None => ("base64", B64.encode(payload.as_bytes())),
            Some(key) => {
                use aes_gcm::aead::{rand_core::RngCore as _, Aead, OsRng as AeadOsRng};
                use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
                let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key));
                let mut nonce_bytes = [0u8; 12];
                AeadOsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from(nonce_bytes);
                let ciphertext_and_tag = cipher.encrypt(&nonce, payload.as_bytes()).unwrap();
                let mut out = nonce_bytes.to_vec();
                out.extend_from_slice(&ciphertext_and_tag);
                ("aes-256-gcm", B64.encode(&out))
            }
        };
        let (pubkey, sig_bytes) = sign_for_scheme(scheme, &enc);
        let sig = B64.encode(&sig_bytes);
        let alg = format!("{enc_prefix}+{suffix}");
        let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": alg });
        let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        (pubkey, format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}"))
    }

    #[test]
    fn ed25519_machine_file_round_trip() {
        let (pubkey, pem) = build_pem(LicenseScheme::Ed25519Sign, None);
        let machine =
            verify_machine_file(&pem, LicenseScheme::Ed25519Sign, &pubkey, None, None).unwrap();
        assert_eq!(machine.attributes.fingerprint, "fp-abc123");
    }

    #[test]
    fn rsa_pkcs1_machine_file_round_trip() {
        let (pubkey, pem) = build_pem(LicenseScheme::Rsa2048Pkcs1Sign, None);
        let machine =
            verify_machine_file(&pem, LicenseScheme::Rsa2048Pkcs1Sign, &pubkey, None, None)
                .unwrap();
        assert_eq!(machine.attributes.fingerprint, "fp-abc123");
    }

    #[test]
    fn rsa_pss_machine_file_round_trip() {
        let (pubkey, pem) = build_pem(LicenseScheme::Rsa2048Pkcs1PssSign, None);
        let machine = verify_machine_file(
            &pem,
            LicenseScheme::Rsa2048Pkcs1PssSign,
            &pubkey,
            None,
            None,
        )
        .unwrap();
        assert_eq!(machine.attributes.fingerprint, "fp-abc123");
    }

    #[test]
    fn ecdsa_p256_machine_file_round_trip() {
        let (pubkey, pem) = build_pem(LicenseScheme::EcdsaP256Sign, None);
        let machine =
            verify_machine_file(&pem, LicenseScheme::EcdsaP256Sign, &pubkey, None, None).unwrap();
        assert_eq!(machine.attributes.fingerprint, "fp-abc123");
    }

    #[test]
    fn encrypted_machine_file_requires_correct_fingerprint() {
        let license_key = "lic-abc123";
        let fingerprint = "fp-abc123";
        let key = crate::crypto::hkdf::derive_machine_file_key(license_key, fingerprint);
        let (pubkey, pem) = build_pem(LicenseScheme::Ed25519Sign, Some(key));

        // Correct fingerprint decrypts fine.
        let machine = verify_machine_file(
            &pem,
            LicenseScheme::Ed25519Sign,
            &pubkey,
            Some(license_key),
            Some(fingerprint),
        )
        .unwrap();
        assert_eq!(machine.attributes.fingerprint, "fp-abc123");

        // Wrong fingerprint fails cleanly (wrong derived key -> AEAD tag
        // mismatch), not a panic or silent corruption.
        let result = verify_machine_file(
            &pem,
            LicenseScheme::Ed25519Sign,
            &pubkey,
            Some(license_key),
            Some("wrong-fingerprint"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn rsa_jwt_rs256_scheme_rejected_before_any_signature_attempt() {
        // Build a file signed with a real (non-JWT) scheme, but ask
        // verify_machine_file to treat it as JWT — proves rejection
        // happens before parsing/verification, not as a side effect of a
        // parse failure.
        let (pubkey, pem) = build_pem(LicenseScheme::Ed25519Sign, None);
        let result = verify_machine_file(&pem, LicenseScheme::Rsa2048JwtRs256, &pubkey, None, None);
        assert!(matches!(
            result,
            Err(crate::error::CheckoutError::SchemeNotSupported)
        ));
    }

    #[test]
    fn check_ttl_accepts_valid_range() {
        assert!(check_ttl(1).is_ok());
        assert!(check_ttl(MAX_TTL_SECS).is_ok());
    }

    #[test]
    fn check_ttl_rejects_zero_and_over_max() {
        assert!(check_ttl(0).is_err());
        assert!(check_ttl(MAX_TTL_SECS + 1).is_err());
    }

    #[test]
    fn alg_suffix_mismatch_is_rejected() {
        // File genuinely signed+verifiable under Ed25519, but caller
        // claims RSA-PKCS1 — the alg-suffix cross-check must catch this
        // before any RSA verification is even attempted (a raw pubkey
        // byte slice from an Ed25519 key isn't valid SPKI DER anyway, but
        // the suffix check should short-circuit first with a clear error).
        let (pubkey, pem) = build_pem(LicenseScheme::Ed25519Sign, None);
        let result =
            verify_machine_file(&pem, LicenseScheme::Rsa2048Pkcs1Sign, &pubkey, None, None);
        assert!(matches!(
            result,
            Err(crate::error::CheckoutError::UnsupportedAlgorithm(_))
        ));
    }
}
