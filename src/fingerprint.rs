//! Canonicalise a machine fingerprint before sending it to the server.
//!
//! ## The defect this closes
//!
//! The server stores `fingerprint TEXT NOT NULL` — no length limit, no
//! `CHECK`, no normalisation — unique per `(license_id, fingerprint)`. Every
//! Tamga SDK sent the caller's string through byte-for-byte, so `"ABC-123"`,
//! `"abc-123"` and `" ABC-123 "` were three machines holding three seats on
//! one licence. Trailing whitespace off a config file or a shelled-out
//! `wmic`/`ioreg` read is the common way in.
//!
//! [`compute`] turns caller-chosen, *labelled* components into one stable
//! 64-character lowercase hex string, so re-ordering the components or
//! picking up stray whitespace cannot change the identity.
//!
//! ## What this deliberately does not do
//!
//! It reads **no hardware identifiers**. What identifies a machine is a
//! product decision, not a library's: a cloned VM template shares its
//! machine-id, a container has none, a replaced motherboard changes one. No
//! default is right for both a desktop app and a Kubernetes sidecar, so the
//! choice of components stays with the caller.
//!
//! ## Algorithm
//!
//! ```text
//! canonical    = "tamga-fingerprint-v1" US join(US, sort_bytewise(["label=" + trimmed_value]))
//! fingerprint  = lowercase_hex(SHA-256(UTF-8(canonical)))
//! ```
//!
//! `US` is U+001F, the ASCII unit separator, emitted as the single byte
//! `0x1F`. The literal prefix is a domain separator, so a future v2 rule
//! cannot collide with a v1 fingerprint.
//!
//! Rules, each enforced by [`canonical`]:
//!
//! | Part | Rule |
//! |---|---|
//! | components | at least one |
//! | label | non-empty; ASCII printable `0x21..=0x7E`; no `'='`; no duplicates |
//! | value | ASCII whitespace trimmed from both ends **first**, then no ASCII control character; `'='` allowed; may be empty |
//! | sort | bytewise ascending over the UTF-8 bytes of the whole `label=value` component |
//! | case | preserved — never folded |
//!
//! ## Why there is no Unicode normalisation
//!
//! Values are **not** NFC-normalised, and that is a constraint rather than an
//! oversight. NFC would need a new dependency here
//! (`unicode-normalization`), and in the C11 port it would mean ICU or
//! hand-rolled Unicode tables inside a library whose selling point is having
//! no dependencies at all. A rule that eight ports cannot implement
//! *identically* is worse than no rule: it would hand back two fingerprints
//! for one machine depending on which SDK the application was written in,
//! silently consuming two seats. Everything above is ASCII-only for that
//! reason. A caller whose values can arrive in more than one normal form
//! must normalise before calling.
//!
//! Case folding is absent for a separate reason: lowercasing a base64 or hex
//! identifier corrupts it.
//!
//! ## Example
//!
//! ```
//! use tamga::fingerprint;
//!
//! // Component order is the caller's convenience, not part of the identity.
//! let a = fingerprint::compute([("machine-id", "abc123"), ("disk", "SN-9")])?;
//! let b = fingerprint::compute([("disk", "SN-9"), ("machine-id", "abc123")])?;
//! assert_eq!(a, b);
//! assert_eq!(a.len(), 64);
//! # Ok::<(), tamga::error::FingerprintError>(())
//! ```

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::error::FingerprintError;

/// Domain-separation prefix. Bump the suffix, never the shape, if the rule
/// ever changes — a v2 canonical string must not be able to equal a v1 one.
const DOMAIN: &str = "tamga-fingerprint-v1";

/// U+001F, the ASCII unit separator: the single byte `0x1F`.
const UNIT_SEPARATOR: char = '\u{1f}';

/// The spec's ASCII whitespace set: space, tab, CR, LF, vertical tab, form
/// feed.
///
/// Deliberately **not** [`str::trim`], which strips every Unicode
/// `White_Space` code point — U+00A0 and U+3000 among them. Trimming those
/// would be a normalisation rule the C11 port cannot reproduce without
/// Unicode tables, which is exactly what the module doc comment rules out.
const ASCII_WHITESPACE: [char; 6] = [' ', '\t', '\r', '\n', '\u{b}', '\u{c}'];

/// Builds the canonical string that [`compute`] hashes.
///
/// Exposed because it is what makes a fingerprint mismatch debuggable: two
/// machines that should agree and do not differ visibly here, where the hex
/// digest shows nothing. Use [`compute`] for the value you actually send.
///
/// The returned string contains raw `0x1F` bytes between components.
///
/// # Errors
///
/// Returns a [`FingerprintError`] for any component that breaks the rules in
/// the module doc comment. Nothing is ever repaired in place — see
/// [`FingerprintError`] for why silent repair would be the more dangerous
/// behaviour.
pub fn canonical<I, L, V>(components: I) -> Result<String, FingerprintError>
where
    I: IntoIterator<Item = (L, V)>,
    L: AsRef<str>,
    V: AsRef<str>,
{
    let mut seen_labels = BTreeSet::new();
    let mut parts: Vec<String> = Vec::new();

    for (label, value) in components {
        let label = label.as_ref();
        validate_label(label)?;

        if !seen_labels.insert(label.to_owned()) {
            return Err(FingerprintError::DuplicateLabel {
                label: label.to_owned(),
            });
        }

        // Trim BEFORE validating: `"  abc\t\n"` is the footgun this helper
        // exists to absorb, so its tab and newline must not be reported as
        // rejected control characters.
        let value = value
            .as_ref()
            .trim_matches(|c| ASCII_WHITESPACE.contains(&c));
        // `char::is_ascii_control` is exactly the spec's set: 0x00..=0x1F and
        // 0x7F. Non-ASCII is untouched by it, which is the intent.
        if value.chars().any(|c| c.is_ascii_control()) {
            return Err(FingerprintError::ControlCharacterInValue {
                label: label.to_owned(),
            });
        }

        let mut part = String::with_capacity(label.len() + 1 + value.len());
        part.push_str(label);
        part.push('=');
        part.push_str(value);
        parts.push(part);
    }

    if parts.is_empty() {
        return Err(FingerprintError::NoComponents);
    }

    // The spec's "bytewise ascending over the UTF-8 bytes of the whole
    // component". `Ord for String` defers to `Ord for str`, which is `[u8]`
    // lexicographic ordering over the UTF-8 encoding — not locale-aware
    // collation, and not code-point order over decoded chars.
    // `sorts_bytewise_not_by_locale_collation` below pins that rather than
    // assuming it. A sort, not a set: collapsing equal parts would be the
    // silent dedup that `DuplicateLabel` exists to refuse.
    parts.sort_unstable();

    let mut out =
        String::with_capacity(DOMAIN.len() + parts.iter().map(|p| p.len() + 1).sum::<usize>());
    out.push_str(DOMAIN);
    for part in &parts {
        out.push(UNIT_SEPARATOR);
        out.push_str(part);
    }
    Ok(out)
}

/// The fingerprint to send: `SHA-256` of [`canonical`], lowercase hex, always
/// 64 characters.
///
/// Pass the result as the `fingerprint` of
/// [`crate::Client::activate_machine`],
/// [`crate::Client::find_machine_by_fingerprint`], or a validation scope.
///
/// Feeding the *same* components in a different order, or with leading and
/// trailing ASCII whitespace, yields the same string; changing the case of a
/// value does not.
///
/// # Errors
///
/// As [`canonical`].
pub fn compute<I, L, V>(components: I) -> Result<String, FingerprintError>
where
    I: IntoIterator<Item = (L, V)>,
    L: AsRef<str>,
    V: AsRef<str>,
{
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let canonical = canonical(components)?;
    let digest = Sha256::digest(canonical.as_bytes());

    // Written out rather than `write!`-formatted so there is no `fmt::Result`
    // to discard: a `let _ =` on a `#[must_use]` return is precisely the
    // silenced-error pattern this crate lints against.
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(HEX[usize::from(byte >> 4)] as char);
        hex.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(hex)
}

/// Non-empty, ASCII printable `0x21..=0x7E`, and no `'='`.
///
/// `0x20` (space) is excluded by the range, as is `0x1F`, so a separator or a
/// space inside a label is caught here rather than needing its own check.
fn validate_label(label: &str) -> Result<(), FingerprintError> {
    if label.is_empty() {
        return Err(FingerprintError::EmptyLabel);
    }
    // `char::is_ascii_graphic` is exactly 0x21..=0x7E, so space (0x20) and the
    // unit separator (0x1F) are both excluded by it without their own checks.
    let valid = label.chars().all(|c| c.is_ascii_graphic() && c != '=');
    if !valid {
        return Err(FingerprintError::InvalidLabel {
            label: label.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one vector every other property is anchored to.
    const SINGLE: &str = "8edf2aef2de1f97d8c49b093cd789342003cc35132411010328db9c65ae47c21";

    #[test]
    fn canonical_uses_the_real_unit_separator_byte() {
        let c = canonical([("machine-id", "abc123")]).unwrap();
        assert_eq!(c, "tamga-fingerprint-v1\u{1f}machine-id=abc123");
        assert!(c.as_bytes().contains(&0x1f));
        // "<US>" in the fixture is a display placeholder, never literal text.
        assert!(!c.contains("<US>"));
    }

    #[test]
    fn compute_is_64_lowercase_hex_characters() {
        let fp = compute([("machine-id", "abc123")]).unwrap();
        assert_eq!(fp.len(), 64);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(fp, SINGLE);
    }

    #[test]
    fn component_order_does_not_change_the_fingerprint() {
        let sorted = compute([("disk", "SN-9"), ("machine-id", "abc123")]).unwrap();
        let unsorted = compute([("machine-id", "abc123"), ("disk", "SN-9")]).unwrap();
        assert_eq!(sorted, unsorted);
    }

    #[test]
    fn surrounding_ascii_whitespace_is_trimmed_not_rejected() {
        // Tab and newline are ASCII control characters; trimming must happen
        // first or this is a ControlCharacterInValue rejection instead.
        let padded = compute([("machine-id", "  abc123\t\n")]).unwrap();
        assert_eq!(padded, SINGLE);
    }

    #[test]
    fn interior_whitespace_is_preserved() {
        // Trimming is ends-only: an interior space is identity material.
        let a = compute([("name", "My Machine")]).unwrap();
        let b = compute([("name", "MyMachine")]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn unicode_whitespace_is_not_trimmed() {
        // `str::trim` would strip U+00A0 and make these equal. `trim_matches`
        // with the explicit ASCII set must not — the C11 port cannot
        // reproduce a Unicode White_Space table.
        let nbsp = compute([("machine-id", "\u{a0}abc123")]).unwrap();
        assert_ne!(nbsp, SINGLE);
    }

    #[test]
    fn case_is_preserved() {
        let upper = compute([("machine-id", "ABC123")]).unwrap();
        assert_ne!(upper, SINGLE);
        assert_eq!(
            upper,
            "d9515717e1662b5e24d33ddbc05839fb9c6a50f4704c537f43127e468cdad82a"
        );
    }

    #[test]
    fn sorts_bytewise_not_by_locale_collation() {
        // Uppercase 'Z' is 0x5A, lowercase 'a' is 0x61, so bytewise puts
        // "Z=..." first. Locale-aware collation puts "a" before "Z" — the
        // ordering this test exists to rule out.
        let c = canonical([("a", "1"), ("Z", "2")]).unwrap();
        assert_eq!(c, "tamga-fingerprint-v1\u{1f}Z=2\u{1f}a=1");
    }

    #[test]
    fn an_empty_value_still_contributes_its_label() {
        // A component that exists but reads empty is not an absent component.
        let empty = canonical([("machine-id", "")]).unwrap();
        assert_eq!(empty, "tamga-fingerprint-v1\u{1f}machine-id=");
        assert_ne!(compute([("machine-id", "")]).unwrap(), SINGLE);
    }

    #[test]
    fn equals_is_legal_in_a_value_and_splits_at_the_first_one() {
        let c = canonical([("path", "a=b=c")]).unwrap();
        assert_eq!(c, "tamga-fingerprint-v1\u{1f}path=a=b=c");
    }

    #[test]
    fn non_ascii_values_pass_through_as_utf8_bytes() {
        let c = canonical([("owner", "café")]).unwrap();
        assert_eq!(c, "tamga-fingerprint-v1\u{1f}owner=café");
        assert_eq!(
            compute([("owner", "café")]).unwrap(),
            "8a729bee74af4aeaf886d4584cc61bc8025d4bad3cce72441693e84e5c450739"
        );
    }

    #[test]
    fn nfc_and_nfd_spellings_are_deliberately_different() {
        // "café" precomposed (U+00E9) vs decomposed (e + U+0301). A port that
        // normalised would collapse these; none of the eight may. Documented
        // in the module doc comment, pinned here.
        let precomposed = compute([("owner", "caf\u{e9}")]).unwrap();
        let decomposed = compute([("owner", "cafe\u{301}")]).unwrap();
        assert_ne!(precomposed, decomposed);
    }

    #[test]
    fn accepts_owned_strings_and_borrowed_str_alike() {
        let owned = compute([(String::from("machine-id"), String::from("abc123"))]).unwrap();
        let borrowed = compute([("machine-id", "abc123")]).unwrap();
        assert_eq!(owned, borrowed);

        // A Vec of tuples is the shape a caller assembling components
        // conditionally ends up with.
        let v: Vec<(&str, String)> = vec![("machine-id", "abc123".to_string())];
        assert_eq!(compute(v).unwrap(), borrowed);
    }

    #[test]
    fn rejects_no_components() {
        let none: [(&str, &str); 0] = [];
        assert_eq!(canonical(none), Err(FingerprintError::NoComponents));
    }

    #[test]
    fn rejects_an_empty_label() {
        assert_eq!(canonical([("", "x")]), Err(FingerprintError::EmptyLabel));
    }

    #[test]
    fn rejects_a_duplicate_label() {
        assert_eq!(
            canonical([("id", "a"), ("id", "b")]),
            Err(FingerprintError::DuplicateLabel {
                label: "id".to_string()
            })
        );
    }

    #[test]
    fn rejects_a_duplicate_label_even_when_the_values_are_equal() {
        // Same value twice is still two components for one label; the set of
        // parts would silently collapse to one without the explicit check.
        assert!(matches!(
            canonical([("id", "a"), ("id", "a")]),
            Err(FingerprintError::DuplicateLabel { .. })
        ));
    }

    #[test]
    fn rejects_equals_in_a_label() {
        assert_eq!(
            canonical([("a=b", "x")]),
            Err(FingerprintError::InvalidLabel {
                label: "a=b".to_string()
            })
        );
    }

    #[test]
    fn rejects_the_separator_in_a_label() {
        assert!(matches!(
            canonical([("a\u{1f}b", "x")]),
            Err(FingerprintError::InvalidLabel { .. })
        ));
    }

    #[test]
    fn rejects_a_non_ascii_label() {
        assert!(matches!(
            canonical([("café", "x")]),
            Err(FingerprintError::InvalidLabel { .. })
        ));
    }

    #[test]
    fn rejects_a_space_in_a_label() {
        // 0x20 sits below the 0x21 floor, so it is caught by the range.
        assert!(matches!(
            canonical([("a b", "x")]),
            Err(FingerprintError::InvalidLabel { .. })
        ));
    }

    #[test]
    fn rejects_the_separator_in_a_value() {
        assert_eq!(
            canonical([("id", "a\u{1f}b")]),
            Err(FingerprintError::ControlCharacterInValue {
                label: "id".to_string()
            })
        );
    }

    #[test]
    fn rejects_a_control_character_in_a_value_rather_than_stripping_it() {
        assert!(matches!(
            canonical([("id", "a\u{7}b")]),
            Err(FingerprintError::ControlCharacterInValue { .. })
        ));
        // Had it been stripped, this would equal the clean spelling — two
        // different inputs on one seat.
        assert!(canonical([("id", "ab")]).is_ok());
    }

    #[test]
    fn rejects_del_in_a_value() {
        // 0x7F is a control character but sits above the 0x1F range.
        assert!(matches!(
            canonical([("id", "a\u{7f}b")]),
            Err(FingerprintError::ControlCharacterInValue { .. })
        ));
    }

    #[test]
    fn a_value_of_only_whitespace_trims_to_empty_and_is_accepted() {
        assert_eq!(
            canonical([("id", " \t\r\n")]).unwrap(),
            "tamga-fingerprint-v1\u{1f}id="
        );
    }

    #[test]
    fn error_display_escapes_a_control_character_in_the_label() {
        // Debug formatting, so a raw byte cannot be injected into a log line.
        let err = canonical([("a\u{1f}b", "x")]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("\\u{1f}"), "{msg}");
        assert!(!msg.contains('\u{1f}'), "{msg}");
    }

    #[test]
    fn control_character_error_does_not_echo_the_value() {
        // The value is machine identity material; only the label is named.
        let err = canonical([("id", "secret\u{7}stuff")]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("id"));
        assert!(!msg.contains("secret"), "{msg}");
    }
}
