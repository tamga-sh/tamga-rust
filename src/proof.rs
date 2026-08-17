//! Machine offline proof — generation call, byte-exact serialization, and
//! RSA-PKCS1v1.5 verification.
//!
//! `POST /machines/{id}/actions/generate-offline-proof`, body
//! `{ "meta": { "dataset": {...} } }` (default `{}`). Always signs with
//! **RSA-2048 PKCS#1 v1.5 / SHA-256** regardless of the license's own
//! `scheme`. Response: machine resource with `meta.proof =
//! "v1x0.<base64 signature>"`.
//!
//! ⚠️ **Byte-exact serialization gotcha, and why it's implemented with
//! `serde_json::Value`, not a fixed-field-order struct**: the signature
//! covers `{"account":{"id":...},"machine":{"id":...,"fingerprint":...},
//! "dataset":<client dataset>}`, but the server builds that payload via
//! `serde_json::json!(...)` — and `serde_json::Map` is `BTreeMap`-backed
//! (alphabetically sorted output) unless the `preserve_order` crate feature
//! is enabled, which it is **not** in the server's dependency graph. So
//! despite the source code literally
//! writing `{"account": ..., "machine": ..., "dataset": ...}`, the actual
//! bytes on the wire are alphabetically sorted at every nesting level:
//! `{"account":{"id":...},"dataset":...,"machine":{"fingerprint":...,
//! "id":...}}` — note `fingerprint` before `id`, and `dataset` before
//! `machine`, neither of which matches the source's literal order.
//!
//! A fixed-field-order **struct** with fields declared in the server
//! source's literal order would therefore be **wrong** — it would produce
//! `{"account":...,"machine":...,"dataset":...}`, which does not match. The
//! correct fix (used here) is building the payload with
//! `serde_json::Value`/`json!()`, exactly mirroring how the server builds
//! it: this crate's own `Cargo.lock` also has no `indexmap` next to its
//! `serde_json`, so both sides independently normalize to the same
//! canonical alphabetical order regardless of construction order — this is
//! *more* robust than a hand-ordered struct, not less, because it doesn't
//! depend on whoever writes the SDK correctly guessing and hardcoding the
//! server's sort order. What must never appear here is a
//! non-deterministic-iteration-order type (`std::collections::HashMap`);
//! `serde_json::Value`'s `BTreeMap`-backed `Map` is deterministic and is
//! what's actually needed.
//!
//! This is a lighter-weight alternative to full checkout for periodic
//! "prove this machine is still valid" pings in air-gapped environments.

/// Parsed/verified offline proof outcome. `verify_offline_proof` returns
/// `Ok(())` — there is no payload to extract beyond "this proof is valid
/// for this exact (account, machine, fingerprint, dataset) tuple," which
/// the caller already has all the pieces of by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineProofVerified;

const PROOF_PREFIX: &str = "v1x0.";

/// Builds the byte-exact JSON payload the server signs — see the module
/// doc comment for why this uses `serde_json::Value` rather than a
/// fixed-field-order struct.
fn build_payload_json(
    account_id: uuid::Uuid,
    machine_id: uuid::Uuid,
    fingerprint: &str,
    dataset: &serde_json::Value,
) -> String {
    let payload = serde_json::json!({
        "account": { "id": account_id },
        "machine": { "id": machine_id, "fingerprint": fingerprint },
        "dataset": dataset,
    });
    serde_json::to_string(&payload).expect("serde_json::Value serialization is infallible")
}

/// Verifies a `"v1x0.<base64 signature>"` offline proof (from
/// [`crate::Client::generate_offline_proof`]'s returned `proof` string)
/// against the exact `(account_id, machine_id, fingerprint, dataset)`
/// tuple it should have been generated for. Always RSA-2048 PKCS#1 v1.5 /
/// SHA-256, regardless of the license's own `scheme`.
///
/// Works fully offline once `rsa_pubkey` (SubjectPublicKeyInfo DER) is
/// embedded in the calling application.
pub fn verify_offline_proof(
    proof: &str,
    account_id: uuid::Uuid,
    machine_id: uuid::Uuid,
    fingerprint: &str,
    dataset: &serde_json::Value,
    rsa_pubkey: &[u8],
) -> Result<OfflineProofVerified, crate::error::ProofError> {
    let sig_b64 = proof
        .strip_prefix(PROOF_PREFIX)
        .ok_or(crate::error::ProofError::MalformedProof)?;
    use base64::Engine as _;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|_| crate::error::ProofError::InvalidBase64)?;
    let payload_json = build_payload_json(account_id, machine_id, fingerprint, dataset);
    crate::crypto::rsa::verify_pkcs1(rsa_pubkey, payload_json.as_bytes(), &sig_bytes)?;
    Ok(OfflineProofVerified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_json_field_order_is_alphabetical_not_source_order() {
        let account_id = uuid::Uuid::nil();
        let machine_id = uuid::Uuid::nil();
        let json = build_payload_json(
            account_id,
            machine_id,
            "fp-abc",
            &serde_json::json!({ "b": 1, "a": 2 }),
        );
        // Top level: account, dataset, machine (alphabetical) — NOT
        // account, machine, dataset (the literal source-code order in
        // both this function and the server's).
        let account_pos = json.find("\"account\"").unwrap();
        let dataset_pos = json.find("\"dataset\"").unwrap();
        let machine_pos = json.find("\"machine\"").unwrap();
        assert!(account_pos < dataset_pos, "{json}");
        assert!(dataset_pos < machine_pos, "{json}");
        // Nested machine object: fingerprint before id (alphabetical),
        // not id before fingerprint (the literal source-code order).
        let fingerprint_pos = json.find("\"fingerprint\"").unwrap();
        let id_pos_in_machine = json[machine_pos..].find("\"id\"").unwrap() + machine_pos;
        assert!(fingerprint_pos < id_pos_in_machine, "{json}");
        // Nested dataset object's own keys also canonicalize
        // alphabetically, regardless of insertion order in the json!
        // macro call above ("b" before "a").
        let a_pos = json.find("\"a\":2").unwrap();
        let b_pos = json.find("\"b\":1").unwrap();
        assert!(a_pos < b_pos, "{json}");
    }

    #[test]
    fn payload_json_matches_a_known_good_server_produced_fixture() {
        // Hand-verified against the exact structure
        // tamga-api/src/features/machines/generate_offline_proof.rs
        // produces for these inputs (BTreeMap/alphabetical order).
        let account_id: uuid::Uuid = "01926b3e-0000-7000-8000-000000000000".parse().unwrap();
        let machine_id: uuid::Uuid = "01926b3e-1111-7000-8000-000000000000".parse().unwrap();
        let json = build_payload_json(
            account_id,
            machine_id,
            "fp-abc",
            &serde_json::json!({ "cores": 4 }),
        );
        let expected = format!(
            "{{\"account\":{{\"id\":\"{account_id}\"}},\"dataset\":{{\"cores\":4}},\"machine\":{{\"fingerprint\":\"fp-abc\",\"id\":\"{machine_id}\"}}}}"
        );
        assert_eq!(json, expected);
    }

    fn gen_rsa_keypair() -> (Vec<u8>, aws_lc_rs::rsa::KeyPair) {
        use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
        use aws_lc_rs::signature::KeyPair as _;
        let kp = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let pubkey = kp.public_key().as_ref().to_vec();
        (pubkey, kp)
    }

    fn sign_payload(kp: &aws_lc_rs::rsa::KeyPair, payload_json: &str) -> String {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::RSA_PKCS1_SHA256;
        use base64::Engine as _;
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&RSA_PKCS1_SHA256, &rng, payload_json.as_bytes(), &mut sig)
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(&sig)
    }

    #[test]
    fn verify_offline_proof_accepts_a_known_good_fixture() {
        let (pubkey, kp) = gen_rsa_keypair();
        let account_id = uuid::Uuid::nil();
        let machine_id = uuid::Uuid::nil();
        let dataset = serde_json::json!({ "cores": 4 });
        let payload_json = build_payload_json(account_id, machine_id, "fp-abc", &dataset);
        let proof = format!("v1x0.{}", sign_payload(&kp, &payload_json));

        let result =
            verify_offline_proof(&proof, account_id, machine_id, "fp-abc", &dataset, &pubkey);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn verify_offline_proof_rejects_tampered_dataset() {
        let (pubkey, kp) = gen_rsa_keypair();
        let account_id = uuid::Uuid::nil();
        let machine_id = uuid::Uuid::nil();
        let signed_dataset = serde_json::json!({ "cores": 4 });
        let payload_json = build_payload_json(account_id, machine_id, "fp-abc", &signed_dataset);
        let proof = format!("v1x0.{}", sign_payload(&kp, &payload_json));

        let tampered_dataset = serde_json::json!({ "cores": 999 });
        let result = verify_offline_proof(
            &proof,
            account_id,
            machine_id,
            "fp-abc",
            &tampered_dataset,
            &pubkey,
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_offline_proof_rejects_a_signature_computed_over_reordered_json() {
        // Field-order sensitivity: proves the byte-exact requirement is
        // actually enforced, not accidentally order-independent. A
        // signature computed over a manually-reordered (but
        // semantically-identical) JSON string must NOT verify against the
        // canonically-ordered payload this SDK reconstructs.
        let (pubkey, kp) = gen_rsa_keypair();
        let account_id = uuid::Uuid::nil();
        let machine_id = uuid::Uuid::nil();
        let dataset = serde_json::json!({ "cores": 4 });

        let canonical_json = build_payload_json(account_id, machine_id, "fp-abc", &dataset);
        // Hand-reorder to "account, machine, dataset" (the literal
        // source-code order, NOT the canonical alphabetical order) —
        // semantically identical content, different bytes.
        let reordered_json = format!(
            "{{\"account\":{{\"id\":\"{account_id}\"}},\"machine\":{{\"id\":\"{machine_id}\",\"fingerprint\":\"fp-abc\"}},\"dataset\":{{\"cores\":4}}}}"
        );
        assert_ne!(canonical_json, reordered_json);

        let proof = format!("v1x0.{}", sign_payload(&kp, &reordered_json));
        let result =
            verify_offline_proof(&proof, account_id, machine_id, "fp-abc", &dataset, &pubkey);
        assert!(
            result.is_err(),
            "a signature over reordered JSON must not verify against the canonical payload"
        );
    }

    #[test]
    fn malformed_prefix_is_rejected_before_any_crypto() {
        let (pubkey, _) = gen_rsa_keypair();
        let result = verify_offline_proof(
            "not-v1x0-prefixed",
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            "fp",
            &serde_json::json!({}),
            &pubkey,
        );
        assert!(matches!(
            result,
            Err(crate::error::ProofError::MalformedProof)
        ));
    }
}
