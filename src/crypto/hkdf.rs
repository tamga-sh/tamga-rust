//! HKDF-SHA256 key derivation for both offline file types.
//!
//! Machine files always used a proper KDF. License files did not: the AES key
//! was the licence key's raw bytes zero-padded to 32, which meant an attacker
//! holding a stolen `.lic` was not attacking a 256-bit key space but the
//! licence key's own entropy — a dictionary attack against the AEAD tag on a
//! `XXXX-XXXX-XXXX-XXXX`-shaped string. Format v2 fixes that; the old
//! `naive_key` module is gone, not deprecated, because keeping it would let a
//! caller silently opt back into the weaker derivation.
//!
//! Parameters (see `docs/plans/tamga-rust.plan.md` §F):
//! - `salt = "tamga:machine-file-key-v1"`
//! - `ikm = <license key>`
//! - `info = <machine fingerprint>`
//! - output: 32-byte AES key
//!
//! Unlike license checkout's naive key derivation (key-string only), a
//! verifier needs **both** the license key **and** the target machine's
//! fingerprint to decrypt a machine file.
//!
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const MACHINE_SALT: &[u8] = b"tamga:machine-file-key-v1";
const LICENSE_SALT: &[u8] = b"tamga:license-file-key-v1";
const LICENSE_INFO: &[u8] = b"license-file";

/// Derives the 32-byte AES-256-GCM key for an encrypted `.mach` file via
/// HKDF-SHA256 (RFC 5869): `salt = "tamga:machine-file-key-v1"`,
/// `ikm = license_key`, `info = fingerprint`. HKDF (rather than raw
/// `SHA256(license_key || fingerprint)`) avoids prefix-collision — see the
/// module doc comment.
///
/// Returns [`Zeroizing<[u8; 32]>`] rather than a bare array so the derived key
/// material is wiped from memory when it goes out of scope instead of sitting
/// in freed-but-unzeroed memory. `Zeroizing<T>` derefs transparently to `T`, so
/// callers that borrow it need no changes. This does not — and cannot — extend
/// to the caller-supplied `license_key: &str`; the SDK does not own that
/// string's storage, only the key it derives from it.
pub fn derive_machine_file_key(license_key: &str, fingerprint: &str) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(MACHINE_SALT), license_key.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(fingerprint.as_bytes(), &mut key[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length (max is 255*32)");
    key
}

/// Derives the 32-byte AES-256-GCM key for an encrypted `.lic` file
/// (format v2): `salt = "tamga:license-file-key-v1"`, `ikm = license_key`,
/// `info = "license-file"`.
///
/// Unlike the machine file, no fingerprint is involved — a licence file is not
/// bound to a machine.
pub fn derive_license_file_key(license_key: &str) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(LICENSE_SALT), license_key.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(LICENSE_INFO, &mut key[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length (max is 255*32)");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_license_key_is_not_recoverable_from_the_derived_key() {
        // v1 zero-padded the licence key, so the derived key literally
        // contained it in cleartext and everything past its length was zero.
        let key = derive_license_file_key("SHORT-KEY");
        assert_ne!(&key[..9], b"SHORT-KEY");
        assert!(key[9..].iter().any(|b| *b != 0));
    }

    #[test]
    fn license_and_machine_derivations_never_collide() {
        // Different salts, so the same licence key must not produce the same
        // AES key for the two file types.
        assert_ne!(
            *derive_license_file_key("same-key"),
            *derive_machine_file_key("same-key", "license-file")
        );
    }

    #[test]
    fn license_key_derivation_is_deterministic() {
        assert_eq!(
            derive_license_file_key("LK-1"),
            derive_license_file_key("LK-1")
        );
        assert_ne!(
            derive_license_file_key("LK-1"),
            derive_license_file_key("LK-2")
        );
    }

    #[test]
    fn same_inputs_produce_same_key() {
        assert_eq!(
            derive_machine_file_key("lk", "fp"),
            derive_machine_file_key("lk", "fp")
        );
    }

    #[test]
    fn different_license_key_produces_different_key() {
        assert_ne!(
            derive_machine_file_key("key-a", "fp"),
            derive_machine_file_key("key-b", "fp")
        );
    }

    #[test]
    fn different_fingerprint_produces_different_key() {
        assert_ne!(
            derive_machine_file_key("lk", "fp-a"),
            derive_machine_file_key("lk", "fp-b")
        );
    }

    #[test]
    fn returns_a_zeroizing_wrapper_not_a_bare_array() {
        // Type-level proof the zeroize-on-drop guarantee actually applies —
        // see naive_key.rs's identical test for the full rationale.
        let key: zeroize::Zeroizing<[u8; 32]> = derive_machine_file_key("lk", "fp");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn prefix_collision_inputs_produce_different_keys() {
        // "ab"+"cdef" and "abc"+"def" concatenate to the same bytes, but
        // HKDF binds each field independently via the info parameter —
        // matches the server's own test of this exact property.
        assert_ne!(
            derive_machine_file_key("ab", "cdef"),
            derive_machine_file_key("abc", "def"),
            "HKDF must prevent prefix-collision between license_key and fingerprint"
        );
    }
}
