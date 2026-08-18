//! Integration tests for the machine offline proof, exercised through the
//! HTTP client. The core
//! byte-exact-serialization / field-order-sensitivity / tampered-dataset
//! coverage lives in `src/proof.rs::tests` — these tests instead cover
//! `Client::generate_offline_proof`'s request/response wiring.

use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn machine_resource_json(id: uuid::Uuid) -> serde_json::Value {
    serde_json::json!({
        "type": "machines",
        "id": id.to_string(),
        "attributes": {
            "fingerprint": "fp-abc123",
            "cores": null, "memory": null, "disk": null, "ip": null,
            "hostname": null, "platform": null, "name": null,
            "heartbeat_status": "NOT_STARTED",
            "last_heartbeat_at": null, "next_heartbeat_at": null, "last_check_out_at": null,
            "metadata": {},
            "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
        }
    })
}

fn test_client(mock_server: &MockServer) -> Client {
    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    Client::new(config).unwrap()
}

#[tokio::test]
async fn generate_offline_proof_returns_machine_and_proof_string() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/generate-offline-proof"
        )))
        .and(body_json(serde_json::json!({
            "meta": { "dataset": { "cores": 4 } }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": machine_resource_json(machine_id),
            "meta": { "proof": "v1x0.ZmFrZS1zaWc=" }
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let (machine, proof) = client
        .generate_offline_proof(machine_id, Some(serde_json::json!({ "cores": 4 })))
        .await
        .unwrap();
    assert_eq!(machine.attributes.fingerprint, "fp-abc123");
    assert_eq!(proof, "v1x0.ZmFrZS1zaWc=");
}

#[tokio::test]
async fn generate_offline_proof_defaults_dataset_to_empty_object() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/generate-offline-proof"
        )))
        .and(body_json(serde_json::json!({
            "meta": { "dataset": {} }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": machine_resource_json(machine_id),
            "meta": { "proof": "v1x0.ZmFrZS1zaWc=" }
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    // If the request body didn't have `dataset: {}` exactly, wiremock's
    // body_json matcher would 404 and this would fail.
    let result = client.generate_offline_proof(machine_id, None).await;
    assert!(result.is_ok(), "{result:?}");
}
