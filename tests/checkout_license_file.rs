//! Integration tests for `docs/plans/tamga-rust.plan.md` §E — License
//! Checkout Crypto, exercised through the HTTP client (unit tests for the
//! verification logic itself live in
//! `src/checkout/license_file.rs::tests`).

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use tamga::checkout::license_file::verify_license_file;
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
        }
    })
    .to_string()
}

fn build_plain_pem(signing_key: &SigningKey) -> String {
    let enc = B64.encode(representative_payload_json().as_bytes());
    let sig = B64.encode(signing_key.sign(enc.as_bytes()).to_bytes());
    let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": "base64+ed25519" });
    let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
    format!("-----BEGIN LICENSE FILE-----\n{pem_body}\n-----END LICENSE FILE-----")
}

fn test_client(mock_server: &MockServer) -> Client {
    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    Client::new(config).unwrap()
}

#[tokio::test]
async fn check_out_license_returns_raw_pem_verifiable_offline() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let (pubkey, signing_key) = gen_keypair();
    let pem = build_plain_pem(&signing_key);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/check-out"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_string(pem.clone()))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let returned_pem = client
        .check_out_license(license_id, false, None)
        .await
        .unwrap();
    assert_eq!(returned_pem, pem);

    // The whole point of checkout: verify fully offline once we have it.
    let license = verify_license_file(&returned_pem, &pubkey, None).unwrap();
    assert_eq!(license.attributes.key, Some("lic-abc123".to_string()));
}

#[tokio::test]
async fn check_out_license_json_parses_enveloped_resource() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let (_, signing_key) = gen_keypair();
    let pem = build_plain_pem(&signing_key);

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/check-out"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "license-files",
                "id": "01926b3e-1111-7000-8000-000000000000",
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
        .check_out_license_json(license_id, false, None)
        .await
        .unwrap();
    assert_eq!(file.attributes.algorithm, "base64+ed25519");
    assert!(file.attributes.includes.is_empty());
}

#[tokio::test]
async fn check_out_license_json_maps_license_not_encrypted_error() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/check-out"
        )))
        .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "422",
                "code": "LICENSE_NOT_ENCRYPTED",
                "title": "Unprocessable Entity",
                "detail": "license key is required for encrypted checkout",
                "source": null,
            }]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client.check_out_license_json(license_id, true, None).await;
    assert!(matches!(result, Err(TamgaError::LicenseNotEncrypted(_))));
}
