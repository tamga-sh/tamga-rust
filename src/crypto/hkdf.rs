//! HKDF-SHA256 key derivation — used for **machine file** (`.mach`)
//! encryption. This is a proper KDF, unlike license file encryption's naive
//! transform (see `src/crypto/naive_key.rs`).
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

const SALT: &[u8] = b"tamga:machine-file-key-v1";

/// Derives the 32-byte AES-256-GCM key for an encrypted `.mach` file via
/// HKDF-SHA256 (RFC 5869): `salt = "tamga:machine-file-key-v1"`,
/// `ikm = license_key`, `info = fingerprint`. HKDF (rather than raw
/// `SHA256(license_key || fingerprint)`) avoids prefix-collision — see the
/// module doc comment.
pub fn derive_machine_file_key(license_key: &str, fingerprint: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SALT), license_key.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(fingerprint.as_bytes(), &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length (max is 255*32)");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

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
