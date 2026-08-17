//! Integration tests for machine checkout crypto, exercised through the HTTP
//! client. Per-scheme
//! signature/decryption coverage (all 4 supported schemes, JWT rejection,
//! wrong-fingerprint rejection) lives in
//! `src/checkout/machine_file.rs::tests` — these tests instead cover the
//! `Client` methods themselves: request wiring, response parsing, and the
//! client-side TTL pre-check short-circuiting before any round trip.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use tamga::checkout::machine_file::verify_machine_file;
use tamga::models::policy::LicenseScheme;
use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn gen_keypair() -> ([u8; 32], SigningKey) {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    (signing_key.verifying_key().to_bytes(), signing_key)
}

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

fn build_plain_pem(signing_key: &SigningKey) -> String {
    let enc = B64.encode(representative_payload_json().as_bytes());
    let sig = B64.encode(signing_key.sign(enc.as_bytes()).to_bytes());
    let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": "base64+ed25519" });
    let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
    format!("-----BEGIN MACHINE FILE-----\n{pem_body}\n-----END MACHINE FILE-----")
}

fn test_client(mock_server: &MockServer) -> Client {
    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    Client::new(config).unwrap()
}

#[tokio::test]
async fn check_out_machine_returns_raw_pem_verifiable_offline() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let (pubkey, signing_key) = gen_keypair();
    let pem = build_plain_pem(&signing_key);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/check-out"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_string(pem.clone()))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let returned_pem = client
        .check_out_machine(machine_id, false, None)
        .await
        .unwrap();
    assert_eq!(returned_pem, pem);

    let machine = verify_machine_file(
        &returned_pem,
        LicenseScheme::Ed25519Sign,
        &pubkey,
        None,
        None,
    )
    .unwrap();
    assert_eq!(machine.attributes.fingerprint, "fp-abc123");
}

#[tokio::test]
async fn check_out_machine_json_parses_enveloped_resource() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let (_, signing_key) = gen_keypair();
    let pem = build_plain_pem(&signing_key);

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/check-out"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "machine-files",
                "id": "01926b3e-3333-7000-8000-000000000000",
                "attributes": {
                    "certificate": pem,
                    "algorithm": "base64+ed25519",
                    "includes": [],
                    "ttl": null,
                    "expiry": null,
                    "issued": "2026-01-01T00:00:00Z",
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let file = client
        .check_out_machine_json(machine_id, false, None)
        .await
        .unwrap();
    assert_eq!(file.attributes.algorithm, "base64+ed25519");
}

#[tokio::test]
async fn check_out_machine_rejects_out_of_range_ttl_before_any_request() {
    // No mock registered at all — if the client made a round trip despite
    // the invalid ttl, this would fail with a connection/404 error instead
    // of the expected typed pre-check error, proving the check happens
    // client-side before any request is sent.
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let client = test_client(&mock_server);

    let result = client
        .check_out_machine(machine_id, false, Some(999_999_999))
        .await;
    assert!(matches!(
        result,
        Err(TamgaError::Checkout(
            tamga::error::CheckoutError::TtlOutOfRange(_)
        ))
    ));
}
