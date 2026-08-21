//! `GET /signing-keys`, and the rotation scenario it exists to make survivable.
//!
//! A `.lic` file names its signer with a `kid` claim. Verified against a single
//! embedded public key, a file signed before the account rotated that key fails
//! with exactly the error a forgery produces — the caller cannot tell "my keys
//! are stale, refresh them" from "refuse this customer". The account publishes
//! its whole key history, retired keys included, precisely so a client can tell
//! the two apart.
//!
//! Two wire details this file pins, because both are easy to get wrong:
//! the resource `id` is the `kid` and not a UUID, and `publicKey` is the one
//! camelCase field in an otherwise snake_case resource.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use tamga::checkout::key_set::SigningKeySet;
use tamga::checkout::license_file::verify_license_file_with_key_set_at;
use tamga::crypto::ed25519::key_id;
use tamga::error::CheckoutError;
use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const PEM_HEADER: &str = "-----BEGIN LICENSE FILE-----";
const PEM_FOOTER: &str = "-----END LICENSE FILE-----";
/// Fixed instant, so nothing here reads the wall clock.
const NOW: i64 = 1_767_225_600;

fn client(server: &MockServer) -> Client {
    let config = ClientConfig::builder("acc-123", server.uri())
        .auth(AuthTransport::Bearer("tok-admin".to_string()))
        .build();
    Client::new(config).unwrap()
}

fn gen_key() -> (SigningKey, String) {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let public_b64 = B64.encode(signing_key.verifying_key().to_bytes());
    (signing_key, public_b64)
}

/// A `.lic` PEM built the way the server's encoder builds one: the signature
/// covers the base64 `enc` **string**, and the claims live inside it.
fn build_lic(signing_key: &SigningKey, kid: &str) -> String {
    let payload = serde_json::json!({
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
        "meta": { "iat": NOW, "jti": "jti-1", "kid": kid }
    })
    .to_string();

    let enc = B64.encode(payload.as_bytes());
    let sig = B64.encode(signing_key.sign(enc.as_bytes()).to_bytes());
    let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": "base64+ed25519+v2" });
    let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
    format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}")
}

fn key_resource(kid: &str, public_key: &str, active: bool) -> serde_json::Value {
    let mut attributes = serde_json::json!({
        "algorithm": "ed25519",
        // camelCase — the single renamed field in this resource.
        "publicKey": public_key,
        "status": if active { "active" } else { "retired" },
        "created": "2026-01-01T00:00:00Z",
    });
    if !active {
        // Absent, not null, while the key is still current.
        attributes["retired"] = serde_json::json!("2026-06-01T00:00:00Z");
    }
    serde_json::json!({ "type": "signing-keys", "id": kid, "attributes": attributes })
}

#[tokio::test]
async fn the_route_returns_retired_keys_alongside_the_active_one() {
    let server = MockServer::start().await;
    let (_old, old_b64) = gen_key();
    let (_new, new_b64) = gen_key();

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/signing-keys"))
        .and(header("Tamga-Version", "1.8"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                key_resource("aaaaaaaaaaaaaaaa", &new_b64, true),
                key_resource("bbbbbbbbbbbbbbbb", &old_b64, false),
            ]
        })))
        .mount(&server)
        .await;

    let keys = client(&server).list_signing_keys().await.unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].resource_type, "signing-keys");
    // The id is the kid, not a UUID.
    assert_eq!(keys[0].id, "aaaaaaaaaaaaaaaa");
    assert_eq!(keys[0].attributes.status, "active");
    assert_eq!(keys[0].attributes.retired, None);
    assert_eq!(keys[0].attributes.public_key, new_b64);
    assert_eq!(keys[1].attributes.status, "retired");
    assert!(keys[1].attributes.retired.is_some());
}

#[tokio::test]
async fn a_file_signed_before_the_rotation_still_verifies_through_the_fetched_set() {
    // End to end: fetch the published set, verify a file whose signer has since
    // been retired, and get the licence back rather than a forgery report.
    let server = MockServer::start().await;
    let (old_signing, old_b64) = gen_key();
    let (_new_signing, new_b64) = gen_key();
    let old_kid = key_id(&old_b64);

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/signing-keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                key_resource(&key_id(&new_b64), &new_b64, true),
                key_resource(&old_kid, &old_b64, false),
            ]
        })))
        .mount(&server)
        .await;

    let keys = client(&server).signing_key_set().await.unwrap();
    assert_eq!(keys.len(), 2);

    let pem = build_lic(&old_signing, &old_kid);
    let verified = verify_license_file_with_key_set_at(&pem, &keys, None, NOW).unwrap();
    assert_eq!(verified.claims.kid, old_kid);
    assert_eq!(
        verified.license.attributes.key,
        Some("lic-abc123".to_string())
    );
}

#[tokio::test]
async fn a_key_set_fetched_before_a_rotation_names_the_kid_it_is_missing() {
    // The other half of the distinction. The client's cached set predates the
    // rotation, so a freshly issued file names a key it has never seen — that
    // is a refresh signal, not a tampered file, and the error says so.
    let server = MockServer::start().await;
    let (_stale_signing, stale_b64) = gen_key();
    let (fresh_signing, fresh_b64) = gen_key();
    let fresh_kid = key_id(&fresh_b64);

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/signing-keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [key_resource(&key_id(&stale_b64), &stale_b64, true)]
        })))
        .mount(&server)
        .await;

    let keys = client(&server).signing_key_set().await.unwrap();
    let pem = build_lic(&fresh_signing, &fresh_kid);

    match verify_license_file_with_key_set_at(&pem, &keys, None, NOW).unwrap_err() {
        CheckoutError::UnknownSigningKey { kid } => {
            assert_eq!(kid, fresh_kid);
            assert!(!keys.kids().any(|k| k == kid));
        }
        other => panic!("expected UnknownSigningKey, got {other:?}"),
    }
}

#[tokio::test]
async fn a_licence_key_cannot_read_the_key_set() {
    // `Role::LicenseToken` has no `account.read`, and its permission set is
    // fixed — no account configuration adds it back. The embedded case has to
    // pin the public keys in the binary instead.
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/signing-keys"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "403",
                "code": "FORBIDDEN",
                "title": "Forbidden",
                "detail": "not permitted to read this account",
            }]
        })))
        .mount(&server)
        .await;

    let config = ClientConfig::builder("acc-123", server.uri())
        .auth(AuthTransport::License("lic-abc123".to_string()))
        .build();
    let err = Client::new(config)
        .unwrap()
        .signing_key_set()
        .await
        .expect_err("a licence key has no account.read");

    assert!(matches!(err, TamgaError::Forbidden(_)));
    assert_eq!(err.code(), Some("FORBIDDEN"));
}

#[tokio::test]
async fn keys_pinned_in_the_binary_verify_with_no_network_at_all() {
    // The path an embedded licence-key client is left with. No server, no
    // fetch — the same rotation-aware distinction, from keys shipped with the
    // application.
    let (old_signing, old_b64) = gen_key();
    let (_new_signing, new_b64) = gen_key();
    let old_kid = key_id(&old_b64);

    let keys = SigningKeySet::from_public_keys([&new_b64, &old_b64]).unwrap();
    let pem = build_lic(&old_signing, &old_kid);

    let verified = verify_license_file_with_key_set_at(&pem, &keys, None, NOW).unwrap();
    assert_eq!(verified.claims.kid, old_kid);
}
