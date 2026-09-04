//! `.mach` file parsing and verification (format v2 only).
//!
//! Same shape as `.lic` (see [`crate::checkout::license_file`]) with these
//! machine-specific differences:
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
//!   [`crate::crypto::hkdf::derive_machine_file_key`]):
//!   `salt="tamga:machine-file-key-v1"`, `ikm=<license key>`,
//!   `info=<machine fingerprint>` → 32-byte AES key. A verifier needs both
//!   the license key and the target machine's fingerprint to decrypt.
//!
//! # The `alg` string
//!
//! `<encoding>+<signing suffix>+v2`, three `+`-separated fields:
//!
//! | field | values |
//! |---|---|
//! | encoding | `base64` (plain) · `aes-256-gcm` (encrypted) |
//! | signing suffix | `ed25519` · `ecdsa-p256` · `rsa-sha256` · `rsa-pss-sha256` |
//! | version | `v2`, mandatory |
//!
//! Two of those values contain hyphens (`aes-256-gcm`, `rsa-pss-sha256`), so
//! the fields must be cut at the **first** and **last** `+` — never by
//! comparing the whole post-`+` remainder against a suffix, and never by a
//! substring test, which would also wave through `base64+ed25519+v3` and
//! `xbase64+ed25519+v2junk`.
//!
//! **A file without the `+v2` marker is rejected outright.** v1 carried no
//! `meta.exp` inside the signed payload and derived its AES key by zero-padding
//! the licence key instead of through HKDF. Accepting one reinstates both
//! weaknesses, and its signature still checks out, because `sig` covers `enc`
//! alone — nothing else in the certificate is authenticated.
//!
//! # The encrypted `enc` field
//!
//! `"<nonce_b64>.<cipher_b64>"` — two **separately** base64-encoded halves, not
//! one base64 blob of `nonce ‖ ciphertext ‖ tag`. The ciphertext half already
//! includes the 16-byte GCM tag. The plain (`base64+…`) variant is a single
//! blob with no dot; branch on the encoding prefix from `alg`, not on whether a
//! dot happens to be present.
//!
//! # Order of operations
//!
//! Verify the signature over `enc`'s **string** bytes first, then split, then
//! decode, then decrypt. Attacker-controlled bytes are never decoded before
//! they are authenticated.
//!
//! # The signed claims
//!
//! The payload is `{"data": <MachineResource>, "meta": <claims>}`, the same
//! [`MachineFileClaims`] the licence-file format carries. `exp` is **optional
//! by design** — a checkout requested without a `ttl` produces a file that
//! genuinely never expires, so its absence is legitimate rather than an error.
//! When present it is enforced against a 60-second clock-skew tolerance, using
//! the same constant as the licence-file path so the two formats cannot drift
//! into different grace periods.
//!
//! Public API: [`verify_machine_file`] dispatches to the correct verifier in
//! [`crate::crypto`] based on the caller-supplied `scheme`,
//! [`verify_machine_file_with_claims`] additionally returns the signed claims,
//! and [`verify_machine_file_at`] takes the current time from the caller.

const PEM_HEADER: &str = "-----BEGIN MACHINE FILE-----";
const PEM_FOOTER: &str = "-----END MACHINE FILE-----";

/// The mandatory trailing field of a machine-file `alg` string.
const ALG_VERSION_MARKER: &str = "v2";

/// AES-256-GCM nonce length, in bytes.
const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length, in bytes. The server appends it to the
/// ciphertext, so a ciphertext half shorter than this cannot be genuine.
const GCM_TAG_LEN: usize = 16;

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
    /// `"{base64|aes-256-gcm}+{ed25519|rsa-sha256|rsa-pss-sha256|ecdsa-p256}+v2"`,
    /// matching `certificate`'s inner `alg` field.
    pub algorithm: String,
    /// **Always `[]`** — same caveat as license files.
    pub includes: Vec<String>,
    /// TTL in seconds, if requested. **Metadata only** — the authoritative
    /// expiry is the signed `meta.exp` claim inside the certificate, which
    /// [`verify_machine_file`] enforces. Same caveat as license files.
    pub ttl: Option<i64>,
    /// Absolute expiry timestamp, if `ttl` was set. Same "metadata only"
    /// caveat as `ttl`.
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

/// The claims carried *inside* a machine file's signed bytes.
///
/// Byte-identical to the licence file's, because the server builds both from
/// the same `LicenseFileClaims` struct (`check_out_machine.rs` serialises it
/// straight into the machine payload's `meta`). Aliased rather than duplicated
/// so the two cannot drift.
///
/// An alias of convenience, not a promise that the two claim sets stay
/// field-identical forever: if the server ever gives machine files a claim of
/// their own this becomes a distinct type, which would break anyone who had
/// relied on the two being the same type (a trait impl, say). Treat it as the
/// name for "a machine file's claims", not as a synonym you can substitute
/// either way.
pub type MachineFileClaims = crate::checkout::license_file::LicenseFileClaims;

/// A verified machine file: the resource plus the claims that were signed
/// alongside it.
#[derive(Debug, Clone)]
pub struct VerifiedMachineFile {
    /// The machine the file describes.
    pub machine: crate::models::machine::MachineResource,
    /// The claims that were covered by the signature.
    pub claims: MachineFileClaims,
}

#[derive(Debug, serde::Deserialize)]
struct CertPayload {
    enc: String,
    sig: String,
    alg: String,
}

/// `{"data": <MachineResource>, "meta": <claims>}` — what `enc`
/// decodes/decrypts to in format v2. `meta` is **not** optional: every v2 file
/// the server issues carries it, so a payload without one is refused rather
/// than treated as a file that never expires.
#[derive(Debug, serde::Deserialize)]
struct DataPayload {
    data: crate::models::machine::MachineResource,
    meta: MachineFileClaims,
}

/// How `enc` is encoded, as declared by the first field of `alg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncEncoding {
    /// `base64` — `enc` is one base64 blob of the payload JSON.
    Plain,
    /// `aes-256-gcm` — `enc` is `"<nonce_b64>.<cipher_b64>"`.
    Aes256Gcm,
}

/// Maps a [`crate::models::policy::LicenseScheme`] to its `alg` suffix,
/// mirroring the server's own mapping — note both `Rsa2048Pkcs1Sign` and
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

/// Splits `alg` into its encoding and signing-suffix fields, rejecting
/// anything that is not exactly `<encoding>+<signing suffix>+v2` for a known
/// encoding.
///
/// The encoding is everything before the **first** `+` and the version marker
/// everything after the **last** one; whatever sits between them is the signing
/// suffix. Neither `aes-256-gcm` nor `rsa-pss-sha256` contains a `+`, only
/// hyphens, so the three fields are unambiguous — but a `split_once('+')` whose
/// remainder is then compared against the bare signing suffix rejects every
/// genuine file (the remainder is `ed25519+v2`, not `ed25519`), and a substring
/// test accepts forgeries.
fn parse_alg(alg: &str) -> Result<(EncEncoding, &str), crate::error::CheckoutError> {
    let unsupported = || crate::error::CheckoutError::UnsupportedAlgorithm(alg.to_string());

    let (encoding, rest) = alg.split_once('+').ok_or_else(unsupported)?;
    let (signing_suffix, version) = rest.rsplit_once('+').ok_or_else(unsupported)?;

    // A v1 file has only two fields and lands on the `rsplit_once` above; this
    // catches a third field that is present but is not the v2 marker.
    if version != ALG_VERSION_MARKER {
        return Err(unsupported());
    }
    // More than three fields: the middle would still hold a `+`.
    if signing_suffix.is_empty() || signing_suffix.contains('+') {
        return Err(unsupported());
    }

    let encoding = match encoding {
        "base64" => EncEncoding::Plain,
        "aes-256-gcm" => EncEncoding::Aes256Gcm,
        _ => return Err(unsupported()),
    };
    Ok((encoding, signing_suffix))
}

/// Parses and fully verifies a `.mach` file, returning the embedded
/// [`crate::models::machine::MachineResource`] once the signature (and
/// decryption, if encrypted) has checked out and the signed `exp` claim has
/// been found to be in the future.
///
/// The embedded resource is a **read** of the machine row taken at checkout
/// time, not the echo of a write, and the server resolves it through a
/// policy-joined query. Two consequences worth knowing: its
/// `heartbeat_status` is a genuine staleness verdict and **can be
/// [`crate::models::machine::HeartbeatStatus::Dead`]** — the ping, reset and
/// create responses never can — and its `next_heartbeat_at` reflects the
/// policy's real window rather than the 600s fallback those responses carry.
///
/// `scheme` **must** come from the license's own `scheme` field (via
/// whatever license resource governs this machine) — never from parsing
/// the file's `alg` string, which cannot safely disambiguate
/// `RSA_2048_PKCS1_SIGN` from `RSA_2048_JWT_RS256` (see this module's
/// private `scheme_alg_suffix` helper). If the license has no `scheme` set, pass
/// [`crate::models::policy::LicenseScheme::Ed25519Sign`] — the server's own
/// default when generating a machine file for an unset scheme.
///
/// `pubkey` is the raw public key for `scheme`, exactly as the server's
/// `extract_public_key` produces it: 32 bytes for Ed25519, a DER `RSAPublicKey`
/// blob for either RSA variant, or a 65-byte uncompressed P-256 point for
/// ECDSA.
///
/// `license_key`/`fingerprint` are required only for an encrypted
/// (`aes-256-gcm+...`) file — both are needed to re-derive the HKDF key
/// (see `src/crypto/hkdf.rs`).
///
/// A file whose `alg` lacks the `+v2` suffix is rejected as
/// [`crate::error::CheckoutError::UnsupportedAlgorithm`] — there is no v1
/// fallback. The signed `exp` claim, when the file carries one, is enforced
/// against the system clock with a 60 second skew tolerance and surfaces as
/// [`crate::error::CheckoutError::Expired`], the same distinct outcome the
/// licence-file path uses; use [`verify_machine_file_at`] to supply the time
/// yourself.
pub fn verify_machine_file(
    pem: &str,
    scheme: crate::models::policy::LicenseScheme,
    pubkey: &[u8],
    license_key: Option<&str>,
    fingerprint: Option<&str>,
) -> Result<crate::models::machine::MachineResource, crate::error::CheckoutError> {
    verify_machine_file_with_claims(pem, scheme, pubkey, license_key, fingerprint)
        .map(|v| v.machine)
}

/// As [`verify_machine_file`], also returning the signed claims.
///
/// Use this when you want `jti` for replay detection or `kid` for key-rotation
/// bookkeeping. Expiry is enforced either way — it is not opt-in.
pub fn verify_machine_file_with_claims(
    pem: &str,
    scheme: crate::models::policy::LicenseScheme,
    pubkey: &[u8],
    license_key: Option<&str>,
    fingerprint: Option<&str>,
) -> Result<VerifiedMachineFile, crate::error::CheckoutError> {
    verify_machine_file_at(
        pem,
        scheme,
        pubkey,
        license_key,
        fingerprint,
        crate::checkout::license_file::unix_now(),
    )
}

/// As [`verify_machine_file_with_claims`], with the current time supplied by
/// the caller.
///
/// Two uses, the same two as
/// [`crate::checkout::license_file::verify_license_file_at`]. Tests get
/// determinism. And an application that keeps a server-supplied timestamp —
/// the recommended defence against a user winding the system clock back to
/// revive an expired file — can pass that instead of trusting the local clock,
/// which on an offline-verification path belongs to the attacker.
pub fn verify_machine_file_at(
    pem: &str,
    scheme: crate::models::policy::LicenseScheme,
    pubkey: &[u8],
    license_key: Option<&str>,
    fingerprint: Option<&str>,
    now_unix: i64,
) -> Result<VerifiedMachineFile, crate::error::CheckoutError> {
    use crate::models::policy::LicenseScheme;

    // ⚠️ Reject up front — before any parsing — rather than let a
    // JWT-scheme signature attempt fail confusingly downstream.
    if scheme == LicenseScheme::Rsa2048JwtRs256 {
        return Err(crate::error::CheckoutError::SchemeNotSupported);
    }

    use base64::Engine as _;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    let cert = parse_envelope(pem)?;

    let (encoding, signing_suffix) = parse_alg(&cert.alg)?;
    // Cross-check only: the file agreeing with the caller rules out a mixed-up
    // key, but it can never *select* the primitive — `rsa-sha256` is emitted
    // for two different schemes.
    let expected_suffix = scheme_alg_suffix(scheme);
    if signing_suffix != expected_suffix {
        return Err(crate::error::CheckoutError::UnsupportedAlgorithm(format!(
            "file declares alg suffix {signing_suffix:?}, expected {expected_suffix:?} for the supplied scheme"
        )));
    }

    // ⚠️ Same gotcha as license files: signature covers `enc`'s ASCII/UTF-8
    // STRING bytes, never its decoded bytes. Nothing below this point runs
    // until it has passed.
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

    let plaintext = decode_plaintext(&cert, encoding, license_key, fingerprint)?;
    finish(&plaintext, now_unix)
}

/// As [`verify_machine_file`], selecting the public key by the file's own
/// `kid` claim from a set of keys the caller trusts.
///
/// Same rotation problem, same two distinct outcomes as
/// [`crate::checkout::license_file::verify_license_file_with_key_set`]: an
/// unknown `kid` is [`crate::error::CheckoutError::UnknownSigningKey`] (a
/// stale key set), a known `kid` with a failing signature stays
/// [`crate::error::CryptoError::VerificationFailed`] (a forgery).
///
/// **Ed25519-signed machine files only, and that is a server-side limit rather
/// than a shortcut here.** There is no `scheme` parameter because a key set
/// cannot serve the other three:
///
/// - the only keys the account publishes are Ed25519 — rotation is
///   `rotate_ed25519` and writes a literal `'ed25519'`, and the account's RSA
///   and ECDSA signing keys are neither published nor rotated at all;
/// - and both checkout handlers compute the `kid` claim from
///   `account.ed25519_public_key` **whatever scheme actually signed the bytes**
///   (`check_out_machine.rs:125`), so on an RSA- or ECDSA-signed file the claim
///   names a key that did not sign it. Matching on it would be worse than
///   useless.
///
/// A file whose `alg` names any other signing suffix is refused as
/// [`crate::error::CheckoutError::UnsupportedAlgorithm`]. Verify those with
/// [`verify_machine_file`] and the licence's own `scheme`, and accept that a
/// rotation is not a distinguishable outcome for them.
pub fn verify_machine_file_with_key_set(
    pem: &str,
    keys: &crate::checkout::key_set::SigningKeySet,
    license_key: Option<&str>,
    fingerprint: Option<&str>,
) -> Result<VerifiedMachineFile, crate::error::CheckoutError> {
    verify_machine_file_with_key_set_at(
        pem,
        keys,
        license_key,
        fingerprint,
        crate::checkout::license_file::unix_now(),
    )
}

/// As [`verify_machine_file_with_key_set`], with the current time supplied by
/// the caller — see [`verify_machine_file_at`] for why that matters.
pub fn verify_machine_file_with_key_set_at(
    pem: &str,
    keys: &crate::checkout::key_set::SigningKeySet,
    license_key: Option<&str>,
    fingerprint: Option<&str>,
    now_unix: i64,
) -> Result<VerifiedMachineFile, crate::error::CheckoutError> {
    use crate::models::policy::LicenseScheme;

    let cert = parse_envelope(pem)?;
    let (encoding, signing_suffix) = parse_alg(&cert.alg)?;

    // Not a cross-check against a caller-supplied scheme, as in
    // `verify_machine_file_at`, but a hard restriction: the key set holds
    // Ed25519 keys and nothing else can be resolved from a `kid`.
    let expected_suffix = scheme_alg_suffix(LicenseScheme::Ed25519Sign);
    if signing_suffix != expected_suffix {
        return Err(crate::error::CheckoutError::UnsupportedAlgorithm(format!(
            "file declares alg suffix {signing_suffix:?}; a signing key set can only verify {expected_suffix:?} machine files"
        )));
    }

    // The `kid` lives inside `enc`, so `enc` is decoded — and, when encrypted,
    // decrypted under the licence key and fingerprint — before the signature
    // is checked. Nothing from those bytes is trusted: the `kid` can only
    // select from keys the caller already supplied, never introduce one.
    let plaintext = decode_plaintext(&cert, encoding, license_key, fingerprint)?;
    let kid = crate::checkout::license_file::probe_kid(&plaintext)?;
    let pubkey = keys
        .find(&kid)
        .ok_or(crate::error::CheckoutError::UnknownSigningKey { kid })?;

    use base64::Engine as _;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&cert.sig)
        .map_err(|_| crate::error::CheckoutError::InvalidBase64)?;
    crate::crypto::ed25519::verify(pubkey, cert.enc.as_bytes(), &sig_bytes)?;

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
    let cert: CertPayload = serde_json::from_slice(&cert_json)?;
    Ok(cert)
}

/// Decodes `enc`, decrypting it first when `encoding` says it is encrypted.
fn decode_plaintext(
    cert: &CertPayload,
    encoding: EncEncoding,
    license_key: Option<&str>,
    fingerprint: Option<&str>,
) -> Result<Vec<u8>, crate::error::CheckoutError> {
    use base64::Engine as _;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    let plaintext = match encoding {
        EncEncoding::Plain => B64
            .decode(&cert.enc)
            .map_err(|_| crate::error::CheckoutError::InvalidBase64)?,
        EncEncoding::Aes256Gcm => {
            let key_str = license_key.ok_or(crate::error::CheckoutError::LicenseKeyMissing)?;
            let fp = fingerprint.ok_or(crate::error::CheckoutError::FingerprintMissing)?;
            let key = crate::crypto::hkdf::derive_machine_file_key(key_str, fp);

            // `"<nonce_b64>.<cipher_b64>"` — two SEPARATELY base64-encoded
            // halves (the server's `FieldEncryption::encrypt` returns
            // `format!("{nonce_b64}.{cipher_b64}")`), not one base64 blob of
            // `nonce ‖ ciphertext ‖ tag`. Decoding the whole string as one
            // fails outright: `.` is not in the base64 alphabet.
            let (nonce_b64, cipher_b64) = cert
                .enc
                .split_once('.')
                .ok_or(crate::error::CryptoError::DecryptionFailed)?;

            let nonce: [u8; NONCE_LEN] = B64
                .decode(nonce_b64)
                .map_err(|_| crate::error::CheckoutError::InvalidBase64)?
                .as_slice()
                .try_into()
                .map_err(|_| crate::error::CryptoError::DecryptionFailed)?;

            // The ciphertext half already carries the 16-byte GCM tag.
            let ciphertext_and_tag = B64
                .decode(cipher_b64)
                .map_err(|_| crate::error::CheckoutError::InvalidBase64)?;
            if ciphertext_and_tag.len() < GCM_TAG_LEN {
                return Err(crate::error::CryptoError::DecryptionFailed.into());
            }

            crate::crypto::aes_gcm::decrypt(&key, &nonce, &ciphertext_and_tag)?
        }
    };
    Ok(plaintext)
}

/// Parses the verified payload and enforces its signed `exp` claim.
fn finish(
    plaintext: &[u8],
    now_unix: i64,
) -> Result<VerifiedMachineFile, crate::error::CheckoutError> {
    let payload: DataPayload = serde_json::from_slice(plaintext)?;

    // The signature proves the file is authentic. It does not prove it is
    // still valid — that is this check. `exp` is absent for a checkout made
    // without a `ttl`, which genuinely never expires, so absence is not an
    // error. Same constant as the licence-file path, deliberately.
    if let Some(exp) = payload.meta.exp {
        // `saturating_sub`, not `-`: `now_unix` comes from the caller, and an
        // absurd one must not panic in a debug build or wrap in a release one.
        if now_unix.saturating_sub(crate::checkout::license_file::CLOCK_SKEW_TOLERANCE_SECS) > exp {
            return Err(crate::error::CheckoutError::Expired { exp });
        }
    }

    Ok(VerifiedMachineFile {
        machine: payload.data,
        claims: payload.meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::policy::LicenseScheme;
    use base64::Engine as _;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    /// Fixed instant used as `iat` throughout, so nothing here reads a clock.
    const ISSUED_AT: i64 = 1_767_225_600;

    /// These build their own certificates, which is only sound for coverage of
    /// branches a captured artefact cannot reach (missing key, malformed PEM,
    /// a payload with no `exp`). Interop with the bytes the server actually
    /// emits is pinned by `tests/machine_file_v2_fixtures.rs`, which iterates
    /// server-produced fixtures — a self-built fixture only ever proves the
    /// verifier agrees with itself.
    fn representative_payload_json(exp: Option<i64>) -> String {
        let mut meta = serde_json::json!({
            "iat": ISSUED_AT, "jti": "test-jti", "kid": "test-kid"
        });
        if let Some(exp) = exp {
            meta["exp"] = serde_json::json!(exp);
        }
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
            },
            "meta": meta
        })
        .to_string()
    }

    /// Signs `enc` with the scheme-appropriate key, returning the raw
    /// signature bytes — mirrors the Tamga API's `sign()` dispatch.
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

    /// Reproduces the server's `encode_machine_file`, including the mandatory
    /// `+v2` marker and the dot-separated encrypted `enc`.
    fn build_pem_with(
        scheme: LicenseScheme,
        encrypt_key: Option<[u8; 32]>,
        exp: Option<i64>,
    ) -> (Vec<u8>, String) {
        let payload = representative_payload_json(exp);
        let suffix = scheme_alg_suffix(scheme);
        let (enc_prefix, enc) = match encrypt_key {
            None => ("base64", B64.encode(payload.as_bytes())),
            Some(key) => {
                use aes_gcm::aead::Aead;
                use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
                use rand::{rngs::OsRng as AeadOsRng, RngCore as _};
                let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key));
                let mut nonce_bytes = [0u8; NONCE_LEN];
                AeadOsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from(nonce_bytes);
                let ciphertext_and_tag = cipher.encrypt(&nonce, payload.as_bytes()).unwrap();
                // `<nonce_b64>.<cipher_b64>` — separately encoded halves.
                (
                    "aes-256-gcm",
                    format!(
                        "{}.{}",
                        B64.encode(nonce_bytes),
                        B64.encode(&ciphertext_and_tag)
                    ),
                )
            }
        };
        let (pubkey, sig_bytes) = sign_for_scheme(scheme, &enc);
        let sig = B64.encode(&sig_bytes);
        let alg = format!("{enc_prefix}+{suffix}+{ALG_VERSION_MARKER}");
        let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": alg });
        let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        (pubkey, format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}"))
    }

    fn build_pem(scheme: LicenseScheme, encrypt_key: Option<[u8; 32]>) -> (Vec<u8>, String) {
        build_pem_with(scheme, encrypt_key, None)
    }

    /// Verifies at a fixed instant, so no test here depends on the wall clock.
    fn verify_at_issue_time(
        pem: &str,
        scheme: LicenseScheme,
        pubkey: &[u8],
        license_key: Option<&str>,
        fingerprint: Option<&str>,
    ) -> Result<VerifiedMachineFile, crate::error::CheckoutError> {
        verify_machine_file_at(pem, scheme, pubkey, license_key, fingerprint, ISSUED_AT)
    }

    /// Builds an Ed25519-signed `.mach` file under a caller-chosen key, and
    /// with a `kid` claim the caller chooses independently of it — the two
    /// have to be separable to tell "unknown key" from "bad signature" apart.
    fn build_ed25519_pem_with_kid(
        signing_key: &ed25519_dalek::SigningKey,
        kid: &str,
        encrypt_key: Option<[u8; 32]>,
    ) -> String {
        use ed25519_dalek::Signer as _;

        let mut payload: serde_json::Value =
            serde_json::from_str(&representative_payload_json(None)).unwrap();
        payload["meta"]["kid"] = serde_json::json!(kid);
        let payload = payload.to_string();

        let (enc_prefix, enc) = match encrypt_key {
            None => ("base64", B64.encode(payload.as_bytes())),
            Some(key) => {
                use aes_gcm::aead::Aead;
                use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
                use rand::{rngs::OsRng as AeadOsRng, RngCore as _};
                let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key));
                let mut nonce_bytes = [0u8; NONCE_LEN];
                AeadOsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from(nonce_bytes);
                let ciphertext_and_tag = cipher.encrypt(&nonce, payload.as_bytes()).unwrap();
                (
                    "aes-256-gcm",
                    format!(
                        "{}.{}",
                        B64.encode(nonce_bytes),
                        B64.encode(&ciphertext_and_tag)
                    ),
                )
            }
        };

        let sig = B64.encode(signing_key.sign(enc.as_bytes()).to_bytes());
        let alg = format!("{enc_prefix}+ed25519+{ALG_VERSION_MARKER}");
        let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": alg });
        let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}")
    }

    fn gen_ed25519() -> (ed25519_dalek::SigningKey, String) {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let b64 = B64.encode(signing_key.verifying_key().to_bytes());
        (signing_key, b64)
    }

    // ── Key rotation: verifying through a key set ────────────────────────

    #[test]
    fn a_machine_file_signed_before_a_rotation_verifies_against_the_retired_key() {
        let (old_signing, old_b64) = gen_ed25519();
        let (_new_signing, new_b64) = gen_ed25519();
        let kid = crate::crypto::ed25519::key_id(&old_b64);
        let pem = build_ed25519_pem_with_kid(&old_signing, &kid, None);

        let keys = crate::checkout::key_set::SigningKeySet::from_public_keys([&new_b64, &old_b64])
            .unwrap();
        let verified =
            verify_machine_file_with_key_set_at(&pem, &keys, None, None, ISSUED_AT).unwrap();
        assert_eq!(verified.claims.kid, kid);
        assert_eq!(verified.machine.attributes.fingerprint, "fp-abc123");
    }

    #[test]
    fn an_unknown_kid_on_a_machine_file_is_distinct_from_a_bad_signature() {
        let (signing, _b64) = gen_ed25519();
        let (_other_signing, other_b64) = gen_ed25519();
        let keys = crate::checkout::key_set::SigningKeySet::from_public_keys([&other_b64]).unwrap();

        // Names a kid nothing in the set holds.
        let unknown = build_ed25519_pem_with_kid(&signing, "0f0f0f0f0f0f0f0f", None);
        assert!(matches!(
            verify_machine_file_with_key_set_at(&unknown, &keys, None, None, ISSUED_AT).unwrap_err(),
            crate::error::CheckoutError::UnknownSigningKey { ref kid } if kid == "0f0f0f0f0f0f0f0f"
        ));

        // Names a kid the set *does* hold — but a different key signed it.
        let forged =
            build_ed25519_pem_with_kid(&signing, &crate::crypto::ed25519::key_id(&other_b64), None);
        assert!(matches!(
            verify_machine_file_with_key_set_at(&forged, &keys, None, None, ISSUED_AT).unwrap_err(),
            crate::error::CheckoutError::Crypto(crate::error::CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn the_key_set_path_handles_the_dot_separated_encrypted_enc() {
        // The kid is inside the ciphertext, so both halves of the machine
        // file's own encrypted layout have to be decoded before a key can be
        // picked — and both the licence key and the fingerprint are needed.
        let (signing, b64) = gen_ed25519();
        let kid = crate::crypto::ed25519::key_id(&b64);
        let keys = crate::checkout::key_set::SigningKeySet::from_public_keys([&b64]).unwrap();

        let license_key = "lic-abc123";
        let fingerprint = "fp-abc123";
        let enc_key = crate::crypto::hkdf::derive_machine_file_key(license_key, fingerprint);
        let pem = build_ed25519_pem_with_kid(&signing, &kid, Some(*enc_key));

        let verified = verify_machine_file_with_key_set_at(
            &pem,
            &keys,
            Some(license_key),
            Some(fingerprint),
            ISSUED_AT,
        )
        .unwrap();
        assert_eq!(verified.claims.kid, kid);

        assert!(matches!(
            verify_machine_file_with_key_set_at(&pem, &keys, None, Some(fingerprint), ISSUED_AT)
                .unwrap_err(),
            crate::error::CheckoutError::LicenseKeyMissing
        ));
        assert!(matches!(
            verify_machine_file_with_key_set_at(&pem, &keys, Some(license_key), None, ISSUED_AT)
                .unwrap_err(),
            crate::error::CheckoutError::FingerprintMissing
        ));
    }

    #[test]
    fn a_non_ed25519_machine_file_is_refused_by_the_key_set_path() {
        // Not a shortcut: the account publishes Ed25519 keys only, never
        // rotates the RSA/ECDSA ones, and stamps the *Ed25519* key's id into
        // the `kid` claim of an ECDSA-signed file regardless. Matching on that
        // claim would be worse than useless, so the path refuses outright.
        for scheme in [
            LicenseScheme::EcdsaP256Sign,
            LicenseScheme::Rsa2048Pkcs1Sign,
            LicenseScheme::Rsa2048Pkcs1PssSign,
        ] {
            let (_pubkey, pem) = build_pem(scheme, None);
            let keys = crate::checkout::key_set::SigningKeySet::default();
            let err = verify_machine_file_with_key_set_at(&pem, &keys, None, None, ISSUED_AT)
                .unwrap_err();
            assert!(
                matches!(err, crate::error::CheckoutError::UnsupportedAlgorithm(ref a) if a.contains("key set")),
                "{scheme:?} produced {err:?}"
            );
        }
    }

    #[test]
    fn the_wall_clock_key_set_entry_point_verifies_a_file_that_never_expires() {
        // The `_at` variants carry the interesting cases; this pins that the
        // convenience wrapper reads the clock and reaches the same verdict for
        // a file with no `exp` claim, which is timeless by construction.
        let (signing, b64) = gen_ed25519();
        let kid = crate::crypto::ed25519::key_id(&b64);
        let keys = crate::checkout::key_set::SigningKeySet::from_public_keys([&b64]).unwrap();
        let pem = build_ed25519_pem_with_kid(&signing, &kid, None);

        let verified = verify_machine_file_with_key_set(&pem, &keys, None, None).unwrap();
        assert_eq!(verified.claims.kid, kid);
        assert!(verified.claims.exp.is_none());
    }

    #[test]
    fn the_key_set_path_still_enforces_the_signed_exp_claim() {
        use ed25519_dalek::Signer as _;
        let (signing, b64) = gen_ed25519();
        let kid = crate::crypto::ed25519::key_id(&b64);
        let keys = crate::checkout::key_set::SigningKeySet::from_public_keys([&b64]).unwrap();

        let exp = ISSUED_AT + 3600;
        let mut payload: serde_json::Value =
            serde_json::from_str(&representative_payload_json(Some(exp))).unwrap();
        payload["meta"]["kid"] = serde_json::json!(kid);
        let enc = B64.encode(payload.to_string().as_bytes());
        let sig = B64.encode(signing.sign(enc.as_bytes()).to_bytes());
        let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": "base64+ed25519+v2" });
        let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        let pem = format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}");

        assert!(verify_machine_file_with_key_set_at(&pem, &keys, None, None, exp - 1).is_ok());
        assert!(matches!(
            verify_machine_file_with_key_set_at(&pem, &keys, None, None, exp + 3600).unwrap_err(),
            crate::error::CheckoutError::Expired { exp: e } if e == exp
        ));
    }

    // ── alg parsing ──────────────────────────────────────────────────────

    #[test]
    fn parse_alg_cuts_at_the_first_and_last_plus() {
        assert_eq!(
            parse_alg("base64+ed25519+v2").unwrap(),
            (EncEncoding::Plain, "ed25519")
        );
        // Both fields carry hyphens; only the `+` positions may be trusted.
        assert_eq!(
            parse_alg("aes-256-gcm+rsa-pss-sha256+v2").unwrap(),
            (EncEncoding::Aes256Gcm, "rsa-pss-sha256")
        );
        assert_eq!(
            parse_alg("aes-256-gcm+ecdsa-p256+v2").unwrap(),
            (EncEncoding::Aes256Gcm, "ecdsa-p256")
        );
    }

    #[test]
    fn parse_alg_refuses_anything_that_is_not_exactly_v2() {
        for bad in [
            "base64+ed25519",          // v1: no version field at all
            "base64+ed25519+v1",       // an explicit older version
            "base64+ed25519+v3",       // a substring test would accept this
            "base64+ed25519+v2junk",   // ...and this
            "xbase64+ed25519+v2",      // ...and this
            "base64+ed25519+extra+v2", // four fields
            "base64++v2",              // empty signing suffix
            "base64",                  // no `+` at all
            "",                        // empty
            "aes-256-cbc+ed25519+v2",  // unknown encoding
        ] {
            assert!(parse_alg(bad).is_err(), "alg {bad:?} must not be accepted");
        }
    }

    // ── round trips, one per supported scheme ────────────────────────────

    #[test]
    fn ed25519_machine_file_round_trip() {
        let (pubkey, pem) = build_pem(LicenseScheme::Ed25519Sign, None);
        let machine =
            verify_at_issue_time(&pem, LicenseScheme::Ed25519Sign, &pubkey, None, None).unwrap();
        assert_eq!(machine.machine.attributes.fingerprint, "fp-abc123");
    }

    #[test]
    fn rsa_pkcs1_machine_file_round_trip() {
        let (pubkey, pem) = build_pem(LicenseScheme::Rsa2048Pkcs1Sign, None);
        let machine =
            verify_at_issue_time(&pem, LicenseScheme::Rsa2048Pkcs1Sign, &pubkey, None, None)
                .unwrap();
        assert_eq!(machine.machine.attributes.fingerprint, "fp-abc123");
    }

    #[test]
    fn rsa_pss_machine_file_round_trip() {
        let (pubkey, pem) = build_pem(LicenseScheme::Rsa2048Pkcs1PssSign, None);
        let machine = verify_at_issue_time(
            &pem,
            LicenseScheme::Rsa2048Pkcs1PssSign,
            &pubkey,
            None,
            None,
        )
        .unwrap();
        assert_eq!(machine.machine.attributes.fingerprint, "fp-abc123");
    }

    #[test]
    fn ecdsa_p256_machine_file_round_trip() {
        let (pubkey, pem) = build_pem(LicenseScheme::EcdsaP256Sign, None);
        let machine =
            verify_at_issue_time(&pem, LicenseScheme::EcdsaP256Sign, &pubkey, None, None).unwrap();
        assert_eq!(machine.machine.attributes.fingerprint, "fp-abc123");
    }

    #[test]
    fn the_plain_entry_point_returns_just_the_machine_resource() {
        let (pubkey, pem) = build_pem(LicenseScheme::Ed25519Sign, None);
        // No `exp`, so the system-clock entry point is safe to call here.
        let machine =
            verify_machine_file(&pem, LicenseScheme::Ed25519Sign, &pubkey, None, None).unwrap();
        assert_eq!(machine.attributes.fingerprint, "fp-abc123");
    }

    // ── encryption ───────────────────────────────────────────────────────

    #[test]
    fn encrypted_machine_file_requires_correct_fingerprint() {
        let license_key = "lic-abc123";
        let fingerprint = "fp-abc123";
        let key = crate::crypto::hkdf::derive_machine_file_key(license_key, fingerprint);
        let (pubkey, pem) = build_pem(LicenseScheme::Ed25519Sign, Some(*key));

        // Correct fingerprint decrypts fine.
        let machine = verify_at_issue_time(
            &pem,
            LicenseScheme::Ed25519Sign,
            &pubkey,
            Some(license_key),
            Some(fingerprint),
        )
        .unwrap();
        assert_eq!(machine.machine.attributes.fingerprint, "fp-abc123");

        // Wrong fingerprint fails cleanly (wrong derived key -> AEAD tag
        // mismatch), not a panic or silent corruption.
        let result = verify_at_issue_time(
            &pem,
            LicenseScheme::Ed25519Sign,
            &pubkey,
            Some(license_key),
            Some("wrong-fingerprint"),
        );
        assert!(matches!(
            result,
            Err(crate::error::CheckoutError::Crypto(
                crate::error::CryptoError::DecryptionFailed
            ))
        ));
    }

    #[test]
    fn an_encrypted_file_needs_both_the_licence_key_and_the_fingerprint() {
        let key = crate::crypto::hkdf::derive_machine_file_key("lic-abc123", "fp-abc123");
        let (pubkey, pem) = build_pem(LicenseScheme::Ed25519Sign, Some(*key));

        assert!(matches!(
            verify_at_issue_time(
                &pem,
                LicenseScheme::Ed25519Sign,
                &pubkey,
                None,
                Some("fp-abc123")
            ),
            Err(crate::error::CheckoutError::LicenseKeyMissing)
        ));
        assert!(matches!(
            verify_at_issue_time(
                &pem,
                LicenseScheme::Ed25519Sign,
                &pubkey,
                Some("lic-abc123"),
                None
            ),
            Err(crate::error::CheckoutError::FingerprintMissing)
        ));
    }

    #[test]
    fn an_encrypted_enc_without_a_dot_separator_is_refused() {
        // A single base64 blob of `nonce ‖ ciphertext ‖ tag` — what the
        // server's stale doc comment describes, and what every SDK
        // implemented. The server does not produce it, so it must not open.
        let license_key = "lic-abc123";
        let fingerprint = "fp-abc123";
        let key = crate::crypto::hkdf::derive_machine_file_key(license_key, fingerprint);
        let payload = representative_payload_json(None);
        let enc = {
            use aes_gcm::aead::Aead;
            use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
            use rand::{rngs::OsRng as AeadOsRng, RngCore as _};
            let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
            let mut nonce_bytes = [0u8; NONCE_LEN];
            AeadOsRng.fill_bytes(&mut nonce_bytes);
            let ciphertext_and_tag = cipher
                .encrypt(&Nonce::from(nonce_bytes), payload.as_bytes())
                .unwrap();
            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&ciphertext_and_tag);
            B64.encode(&out)
        };
        let (pubkey, sig_bytes) = sign_for_scheme(LicenseScheme::Ed25519Sign, &enc);
        let cert = serde_json::json!({
            "enc": enc,
            "sig": B64.encode(&sig_bytes),
            "alg": "aes-256-gcm+ed25519+v2",
        });
        let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        let pem = format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}");

        assert!(matches!(
            verify_at_issue_time(
                &pem,
                LicenseScheme::Ed25519Sign,
                &pubkey,
                Some(license_key),
                Some(fingerprint)
            ),
            Err(crate::error::CheckoutError::Crypto(
                crate::error::CryptoError::DecryptionFailed
            ))
        ));
    }

    // ── the signed exp claim ─────────────────────────────────────────────

    #[test]
    fn an_expired_machine_file_is_refused_even_though_its_signature_is_valid() {
        let exp = ISSUED_AT + 3600;
        let (pubkey, pem) = build_pem_with(LicenseScheme::Ed25519Sign, None, Some(exp));
        let err = verify_machine_file_at(
            &pem,
            LicenseScheme::Ed25519Sign,
            &pubkey,
            None,
            None,
            exp + 3600,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            crate::error::CheckoutError::Expired { exp: e } if e == exp
        ));
    }

    #[test]
    fn a_machine_file_within_its_ttl_verifies() {
        let exp = ISSUED_AT + 3600;
        let (pubkey, pem) = build_pem_with(LicenseScheme::Ed25519Sign, None, Some(exp));
        let verified = verify_machine_file_at(
            &pem,
            LicenseScheme::Ed25519Sign,
            &pubkey,
            None,
            None,
            exp - 60,
        )
        .unwrap();
        assert_eq!(verified.claims.exp, Some(exp));
    }

    #[test]
    fn a_machine_file_without_an_exp_claim_never_expires() {
        // `check_out_machine.rs` sets `exp` to `ttl.map(..)`, so a checkout
        // made without a TTL genuinely produces a file with no expiry.
        // Absence is legitimate — not an error, and not "expired at the epoch".
        let (pubkey, pem) = build_pem(LicenseScheme::Ed25519Sign, None);
        let verified = verify_machine_file_at(
            &pem,
            LicenseScheme::Ed25519Sign,
            &pubkey,
            None,
            None,
            i64::MAX / 2,
        )
        .unwrap();
        assert!(verified.claims.exp.is_none());
    }

    #[test]
    fn machine_file_expiry_uses_the_same_skew_tolerance_as_the_licence_file() {
        let exp = ISSUED_AT + 3600;
        let (pubkey, pem) = build_pem_with(LicenseScheme::Ed25519Sign, None, Some(exp));
        let at = |now| {
            verify_machine_file_at(&pem, LicenseScheme::Ed25519Sign, &pubkey, None, None, now)
        };
        let tolerance = crate::checkout::license_file::CLOCK_SKEW_TOLERANCE_SECS;
        assert_eq!(tolerance, 60, "the tolerance is seconds, not hours");
        assert!(at(exp + tolerance).is_ok());
        assert!(at(exp + tolerance + 1).is_err());
    }

    #[test]
    fn a_payload_without_a_meta_block_is_refused() {
        // Format v2 always carries `meta`. A payload without one is either v1
        // or forged; either way there is no `exp` to enforce, so accepting it
        // would be the permanent-file problem again.
        let payload = serde_json::json!({
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
        .to_string();
        let enc = B64.encode(payload.as_bytes());
        let (pubkey, sig_bytes) = sign_for_scheme(LicenseScheme::Ed25519Sign, &enc);
        let cert = serde_json::json!({
            "enc": enc,
            "sig": B64.encode(&sig_bytes),
            "alg": "base64+ed25519+v2",
        });
        let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        let pem = format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}");

        assert!(matches!(
            verify_at_issue_time(&pem, LicenseScheme::Ed25519Sign, &pubkey, None, None),
            Err(crate::error::CheckoutError::InvalidJson(_))
        ));
    }

    // ── rejections ───────────────────────────────────────────────────────

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
    fn a_malformed_pem_envelope_is_refused() {
        assert!(matches!(
            verify_at_issue_time(
                "not a pem",
                LicenseScheme::Ed25519Sign,
                &[0u8; 32],
                None,
                None
            ),
            Err(crate::error::CheckoutError::MalformedPem)
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
        // byte slice from an Ed25519 key isn't valid DER anyway, but
        // the suffix check should short-circuit first with a clear error).
        let (pubkey, pem) = build_pem(LicenseScheme::Ed25519Sign, None);
        let result =
            verify_at_issue_time(&pem, LicenseScheme::Rsa2048Pkcs1Sign, &pubkey, None, None);
        assert!(matches!(
            result,
            Err(crate::error::CheckoutError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn a_v1_alg_is_refused_outright() {
        // `sig` covers `enc` alone, so stripping `+v2` leaves a file whose
        // signature still verifies. Only the explicit marker check stops it.
        let (pubkey, pem) = build_pem(LicenseScheme::Ed25519Sign, None);
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let mut cert: serde_json::Value =
            serde_json::from_slice(&B64.decode(body.trim()).unwrap()).unwrap();
        cert["alg"] = serde_json::json!("base64+ed25519");
        let repacked = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
        let v1_pem = format!("{PEM_HEADER}\n{repacked}\n{PEM_FOOTER}");

        assert!(matches!(
            verify_at_issue_time(&v1_pem, LicenseScheme::Ed25519Sign, &pubkey, None, None),
            Err(crate::error::CheckoutError::UnsupportedAlgorithm(ref a)) if a == "base64+ed25519"
        ));
    }
}
