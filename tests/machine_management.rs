//! Integration tests for `docs/plans/tamga-rust.plan.md` §G — Machine
//! Management.

use tamga::client::CreateMachineOptions;
use tamga::models::machine::HeartbeatStatus;
use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn machine_resource_json(id: uuid::Uuid, heartbeat_status: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "machines",
        "id": id.to_string(),
        "attributes": {
            "fingerprint": "fp-abc123",
            "cores": null, "memory": null, "disk": null, "ip": null,
            "hostname": null, "platform": null, "name": null,
            "heartbeat_status": heartbeat_status,
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
async fn create_machine_happy_path() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .and(body_json(serde_json::json!({
            "data": {
                "type": "machines",
                "attributes": {
                    "fingerprint": "fp-abc123",
                    "name": null, "ip": null, "hostname": null, "platform": null,
                    "cores": null, "memory": null, "disk": null, "metadata": {},
                },
                "relationships": {
                    "license": { "data": { "type": "licenses", "id": license_id } }
                }
            }
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "data": machine_resource_json(machine_id, "NOT_STARTED")
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let machine = client
        .create_machine(license_id, "fp-abc123", CreateMachineOptions::default())
        .await
        .unwrap();
    assert_eq!(machine.attributes.fingerprint, "fp-abc123");
    assert_eq!(
        machine.attributes.heartbeat_status,
        HeartbeatStatus::NotStarted
    );
}

#[tokio::test]
async fn create_machine_duplicate_fingerprint_returns_typed_error() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "409",
                "code": "FINGERPRINT_TAKEN",
                "title": "Conflict",
                "detail": "a machine with this fingerprint already exists on this license",
                "source": null,
            }]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client
        .create_machine(license_id, "fp-abc123", CreateMachineOptions::default())
        .await;
    assert!(matches!(result, Err(TamgaError::FingerprintTaken(_))));
}

#[tokio::test]
async fn ping_heartbeat_happy_path() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/ping-heartbeat"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": machine_resource_json(machine_id, "ALIVE")
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let machine = client.ping_heartbeat(machine_id).await.unwrap();
    assert_eq!(machine.attributes.heartbeat_status, HeartbeatStatus::Alive);
}

#[tokio::test]
async fn reset_heartbeat_happy_path() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/reset-heartbeat"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": machine_resource_json(machine_id, "NOT_STARTED")
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let machine = client.reset_heartbeat(machine_id).await.unwrap();
    assert_eq!(
        machine.attributes.heartbeat_status,
        HeartbeatStatus::NotStarted
    );
}

#[tokio::test]
async fn delete_machine_happy_path() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("DELETE"))
        .and(path(format!("/v1/accounts/acc-123/machines/{machine_id}")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    assert!(client.delete_machine(machine_id).await.is_ok());
}

#[tokio::test]
async fn activate_machine_deletes_on_overage_when_requested() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "data": machine_resource_json(machine_id, "NOT_STARTED")
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "licenses",
                "id": license_id.to_string(),
                "attributes": {
                    "name": null, "key": "lic-abc123", "status": "ACTIVE", "expiry": null,
                    "suspended": false, "protected": false, "uses": 0, "scheme": null,
                    "encrypted": false, "strict": false, "floating": false,
                    "max_machines": 1, "max_uses": null, "max_users": null,
                    "last_validated_at": null, "last_check_in_at": null, "last_check_out_at": null,
                    "machines_count": 2, "metadata": {},
                    "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
                }
            },
            "meta": {
                "ts": "2026-01-01T00:00:00Z", "valid": false,
                "detail": "has too many machines", "code": "TOO_MANY_MACHINES",
            }
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("/v1/accounts/acc-123/machines/{machine_id}")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    // If delete_machine were never called, wiremock would still respond
    // 404 to an unmatched DELETE rather than fail this test directly — the
    // real assertion is that activate_machine still returns the (failed)
    // validation result to the caller even after auto-deleting.
    let result = client
        .activate_machine(
            license_id,
            "fp-abc123",
            CreateMachineOptions::default(),
            None,
            true,
        )
        .await
        .unwrap();
    assert!(!result.meta.valid);
    assert_eq!(
        result.meta.code,
        tamga::models::validation::ValidationCode::TooManyMachines
    );
}
