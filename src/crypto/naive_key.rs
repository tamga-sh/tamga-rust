//! ⚠️ Non-KDF key derivation for **license file** (`.lic`) encryption.
//!
//! The AES key is `license.key`'s raw UTF-8 bytes, **zero-padded or
//! truncated to exactly 32 bytes** — a literal byte-copy/pad/truncate
//! transform.
//!
//! This function intentionally does **not** use HKDF/PBKDF2/scrypt — it
//! replicates the server's naive transform bit-for-bit. Do not "fix" it to
//! use a real KDF, or decryption will silently fail against real server
//! output. Contrast with `src/crypto/hkdf.rs`, which machine file encryption
//! uses instead and which *is* a proper KDF.
//!
//! Ground-truth verified against the server's own derivation in
//! `tamga-api/src/features/licenses/check_out_license.rs`:
//! ```rust,ignore
//! let kb = key_str.as_bytes();
//! let mut key_bytes = vec![0u8; 32];
//! let len = kb.len().min(32);
//! key_bytes[..len].copy_from_slice(&kb[..len]);
//! ```

use zeroize::Zeroizing;

/// Derives the AES-256-GCM key for an encrypted `.lic` file: `license_key`'s
/// raw UTF-8 bytes, zero-padded (if shorter than 32 bytes) or truncated (if
/// longer) to exactly 32 bytes. Deliberately **not** a hash or KDF — see
/// module doc comment.
///
/// Returns [`Zeroizing<[u8; 32]>`] rather than a bare array so the derived
/// key material is wiped from memory when it goes out of scope, instead of
/// sitting in freed-but-unzeroed memory indefinitely. `Zeroizing<T>`
/// transparently derefs to `T` (here `[u8; 32]`), so existing callers that
/// borrow it (e.g. `aes_gcm::decrypt(&key, ...)`) need no changes. This does
/// not, and cannot, extend to the caller-supplied `license_key: &str` itself
/// — the SDK doesn't own that string's lifetime or storage, only the key it
/// derives from it.
pub fn derive_license_file_key(license_key: &str) -> Zeroizing<[u8; 32]> {
    let kb = license_key.as_bytes();
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    let len = kb.len().min(32);
    key_bytes[..len].copy_from_slice(&kb[..len]);
    key_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_pads_keys_shorter_than_32_bytes() {
        let key = derive_license_file_key("short");
        assert_eq!(&key[..5], b"short");
        assert_eq!(&key[5..], [0u8; 27]);
    }

    #[test]
    fn truncates_keys_longer_than_32_bytes() {
        let long_key = "a".repeat(50);
        let key = derive_license_file_key(&long_key);
        assert_eq!(*key, [b'a'; 32]);
    }

    #[test]
    fn exact_32_byte_key_is_unchanged() {
        let exact = "a".repeat(32);
        let key = derive_license_file_key(&exact);
        assert_eq!(*key, [b'a'; 32]);
    }

    #[test]
    fn returns_a_zeroizing_wrapper_not_a_bare_array() {
        // Type-level proof that the zeroize-on-drop guarantee actually
        // applies to this function's return value -- if this function's
        // signature ever regresses back to a bare [u8; 32], this fails to
        // compile rather than silently losing the zeroize guarantee.
        let key: zeroize::Zeroizing<[u8; 32]> = derive_license_file_key("check-the-type");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn is_not_a_hash_same_prefix_different_length_diverges_only_after_prefix() {
        // A real KDF/hash would produce a completely different key for any
        // input change. This transform is a literal byte-copy, so two keys
        // sharing a prefix must share that same prefix in the derived key
        // too — proving this is NOT hashing the input.
        let a = derive_license_file_key("abc");
        let b = derive_license_file_key("abcdef");
        assert_eq!(&a[..3], &b[..3]);
    }
}
