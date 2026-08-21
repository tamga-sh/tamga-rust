//! Conformance of [`tamga::fingerprint`] against the cross-SDK test vectors.
//!
//! `tests/fixtures/fingerprint/fingerprint.json` is the shared fixture every
//! Tamga SDK is held to. It was produced by an independent SHA-256
//! implementation, not by any SDK — a fixture an SDK generated could only
//! prove that SDK agrees with itself, which is worth nothing when the
//! property under test is that eight ports agree with *each other*. A machine
//! must fingerprint identically whether the application embedding it is
//! written in Rust, Go, C or Python; a port that quietly disagrees consumes a
//! second seat for a machine that already holds one.
//!
//! These tests **iterate the file** rather than naming vectors inline, so a
//! vector added upstream is exercised here as soon as the file is refreshed
//! instead of being silently ignored.
//!
//! `canonical` in the fixture writes the unit separator as the display
//! placeholder `<US>`; the real canonical string carries the single byte
//! `0x1F`. [`expand_separator`] converts, and
//! `the_fixture_placeholder_is_not_literal_text` proves the placeholder never
//! leaks into a hashed string.

use std::path::PathBuf;

use tamga::error::FingerprintError;
use tamga::fingerprint;

/// The `<US>` placeholder the fixture uses so the JSON stays readable.
const US_PLACEHOLDER: &str = "<US>";

#[derive(serde::Deserialize)]
struct Fixture {
    vectors: Vec<Vector>,
    rejected: Vec<Rejected>,
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    components: Vec<Vec<String>>,
    canonical: String,
    fingerprint: String,
}

#[derive(serde::Deserialize)]
struct Rejected {
    name: String,
    components: Vec<Vec<String>>,
    reason: String,
}

/// Reads the fixture as UTF-8.
///
/// `std::fs::read_to_string` decodes UTF-8 or fails with
/// `ErrorKind::InvalidData` — it never falls back to a platform locale codec.
/// That matters: tamga-python's equivalent used a reader that *did*
/// (`cp1252` on `windows-latest`), so its `non_ascii_value` vector decoded as
/// mojibake and hashed differently on Windows alone. Every other vector is
/// pure ASCII and would have stayed green through it, so the suite would have
/// looked fine while the SDK disagreed with itself across two operating
/// systems. Rust cannot reach that state here, and
/// `the_non_ascii_vector_survived_the_read_intact` proves it rather than
/// asserting it.
fn fixture() -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/fingerprint/fingerprint.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("fixture is valid JSON")
}

/// Turns the fixture's `<US>` placeholder into the real `0x1F` byte.
fn expand_separator(display: &str) -> String {
    display.replace(US_PLACEHOLDER, "\u{1f}")
}

/// `[["label", "value"], ...]` as the pairs the API takes.
fn pairs(components: &[Vec<String>]) -> Vec<(String, String)> {
    components
        .iter()
        .map(|c| {
            assert_eq!(c.len(), 2, "each component is a [label, value] pair");
            (c[0].clone(), c[1].clone())
        })
        .collect()
}

#[test]
fn the_fixture_is_not_empty() {
    // A fixture that failed to parse into zero vectors would make every
    // iterating test below vacuously green.
    let f = fixture();
    assert_eq!(f.vectors.len(), 9, "expected 9 positive vectors");
    assert_eq!(f.rejected.len(), 8, "expected 8 rejected cases");
}

#[test]
fn the_non_ascii_vector_survived_the_read_intact() {
    // Guards the decode step itself, ahead of any hashing. A mis-decoding
    // reader turns "café" into "cafÃ©" and the only symptom downstream is an
    // opaque digest mismatch; this names the actual cause.
    let f = fixture();
    let v = find(&f, "non_ascii_value");
    let components = pairs(&v.components);
    assert_eq!(components[0].1, "caf\u{e9}", "fixture decoded as mojibake");
    assert_eq!(
        components[0].1.chars().count(),
        4,
        "expected 4 scalar values, so the é is one char and not two bytes"
    );
    assert_eq!(
        components[0].1.as_bytes(),
        &[0x63, 0x61, 0x66, 0xc3, 0xa9],
        "é must be the two UTF-8 bytes C3 A9"
    );
    // And the value must not have been silently normalised on the way in.
    assert_ne!(components[0].1, "cafe\u{301}");
}

#[test]
fn every_vector_produces_the_expected_canonical_string() {
    for v in fixture().vectors {
        let got = fingerprint::canonical(pairs(&v.components)).unwrap_or_else(|e| {
            panic!("vector `{}` should canonicalize, got {e}", v.name);
        });
        assert_eq!(
            got,
            expand_separator(&v.canonical),
            "vector `{}` canonical mismatch",
            v.name
        );
    }
}

#[test]
fn every_vector_produces_the_expected_fingerprint() {
    for v in fixture().vectors {
        let got = fingerprint::compute(pairs(&v.components)).unwrap_or_else(|e| {
            panic!("vector `{}` should compute, got {e}", v.name);
        });
        assert_eq!(got, v.fingerprint, "vector `{}` digest mismatch", v.name);
        assert_eq!(got.len(), 64, "vector `{}` is not 64 chars", v.name);
    }
}

#[test]
fn the_fixture_placeholder_is_not_literal_text() {
    // `<US>` is a display convention. Hashing it literally would produce
    // self-consistent but cross-SDK-incompatible digests, which is exactly
    // the failure the shared fixture exists to catch.
    for v in fixture().vectors {
        let got = fingerprint::canonical(pairs(&v.components)).unwrap();
        assert!(!got.contains(US_PLACEHOLDER), "vector `{}`", v.name);
        if v.canonical.contains(US_PLACEHOLDER) {
            assert!(
                got.as_bytes().contains(&0x1f),
                "vector `{}` should carry a real 0x1F byte",
                v.name
            );
        }
    }
}

#[test]
fn every_rejected_case_is_an_error_not_a_repair() {
    for r in fixture().rejected {
        let result = fingerprint::compute(pairs(&r.components));
        assert!(
            result.is_err(),
            "case `{}` must be rejected ({}), got {:?}",
            r.name,
            r.reason,
            result
        );
    }
}

#[test]
fn rejected_cases_map_onto_the_documented_variants() {
    // Pins *which* error each case yields, so a rule cannot drift into being
    // enforced by the wrong check while the suite stays green.
    for r in fixture().rejected {
        let err = fingerprint::compute(pairs(&r.components)).unwrap_err();
        let matched = match r.name.as_str() {
            "empty_label" => matches!(err, FingerprintError::EmptyLabel),
            "duplicate_label" => matches!(err, FingerprintError::DuplicateLabel { .. }),
            "equals_in_label" | "separator_in_label" | "non_ascii_label" => {
                matches!(err, FingerprintError::InvalidLabel { .. })
            }
            "separator_in_value" | "control_in_value" => {
                matches!(err, FingerprintError::ControlCharacterInValue { .. })
            }
            "no_components" => matches!(err, FingerprintError::NoComponents),
            other => panic!("fixture grew an unmapped rejected case `{other}` — map it"),
        };
        assert!(matched, "case `{}` produced {err:?}", r.name);
    }
}

// ── The three invariants that carry the most weight ─────────────────────────
//
// Each is a vector *pair* in the fixture: the property is a relationship
// between two inputs, which no single vector can express.

#[test]
fn order_independence_two_sorted_equals_two_unsorted() {
    let f = fixture();
    let a = find(&f, "two_sorted");
    let b = find(&f, "two_unsorted");
    assert_eq!(
        fingerprint::compute(pairs(&a.components)).unwrap(),
        fingerprint::compute(pairs(&b.components)).unwrap(),
        "component order is the caller's convenience, not part of the identity"
    );
}

#[test]
fn whitespace_equivalence_trimmed_equals_single() {
    let f = fixture();
    let padded = find(&f, "whitespace_trimmed");
    let clean = find(&f, "single");
    assert_eq!(
        fingerprint::compute(pairs(&padded.components)).unwrap(),
        fingerprint::compute(pairs(&clean.components)).unwrap(),
        "leading/trailing ASCII whitespace is the footgun this helper absorbs"
    );
}

#[test]
fn case_preservation_case_preserved_differs_from_single() {
    let f = fixture();
    let upper = find(&f, "case_preserved");
    let lower = find(&f, "single");
    assert_ne!(
        fingerprint::compute(pairs(&upper.components)).unwrap(),
        fingerprint::compute(pairs(&lower.components)).unwrap(),
        "case folding would corrupt a base64 or hex identifier"
    );
}

fn find<'a>(f: &'a Fixture, name: &str) -> &'a Vector {
    f.vectors
        .iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("fixture is missing the `{name}` vector"))
}
