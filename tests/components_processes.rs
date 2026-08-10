//! Integration tests for `docs/plans/tamga-rust.plan.md` §I — Components &
//! Processes.

use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn component_resource_json(id: uuid::Uuid, machine_id: uuid::Uuid) -> serde_json::Value {
    serde_json::json!({
        "type": "components",
        "id": id.to_string(),
        "attributes": {
            "fingerprint": "comp-fp-1",
            "name": "GPU",
            "machine_id": machine_id.to_string(),
            "metadata": {},
            "created": "2026-01-01T00:00:00Z",
            "updated": "2026-01-01T00:00:00Z",
        }
    })
}

fn process_resource_json(id: uuid::Uuid, machine_id: uuid::Uuid, pid: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "processes",
        "id": id.to_string(),
        "attributes": {
            "pid": pid,
            "machine_id": machine_id.to_string(),
            "last_heartbeat_at": "2026-01-01T00:00:00Z",
            "metadata": {},
            "created": "2026-01-01T00:00:00Z",
            "updated": "2026-01-01T00:00:00Z",
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
async fn create_component_happy_path() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let component_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/components"))
        .and(body_json(serde_json::json!({
            "machine_id": machine_id,
            "fingerprint": "comp-fp-1",
            "name": "GPU",
            "metadata": {},
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "data": component_resource_json(component_id, machine_id)
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let component = client
        .create_component(machine_id, "comp-fp-1", "GPU", None)
        .await
        .unwrap();
    assert_eq!(component.attributes.fingerprint, "comp-fp-1");
    assert_eq!(component.attributes.name, "GPU");
}

#[tokio::test]
async fn create_component_duplicate_fingerprint_returns_typed_error() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/components"))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000", "status": "409",
                "code": "FINGERPRINT_TAKEN", "title": "Conflict",
                "detail": "a component with this fingerprint already exists on this machine",
                "source": null,
            }]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client
        .create_component(machine_id, "comp-fp-1", "GPU", None)
        .await;
    assert!(matches!(result, Err(TamgaError::FingerprintTaken(_))));
}

#[tokio::test]
async fn create_process_with_numeric_pid_serializes_as_json_string() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let process_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/processes"))
        .and(body_json(serde_json::json!({
            "machine_id": machine_id,
            "pid": "1234",
            "metadata": {},
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "data": process_resource_json(process_id, machine_id, "1234")
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    // `body_json` above requires the wire value to be the JSON *string*
    // "1234", not the number 1234 — matching proves the Pid::From<u32>
    // stringification actually happened on the wire, not just in-memory.
    let process = client
        .create_process(machine_id, 1234u32, None)
        .await
        .unwrap();
    assert_eq!(process.attributes.pid, "1234");
}

#[tokio::test]
async fn create_process_duplicate_pid_returns_typed_error() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/processes"))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000", "status": "409",
                "code": "PID_TAKEN", "title": "Conflict",
                "detail": "a process with this pid already exists on this machine",
                "source": null,
            }]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client.create_process(machine_id, 1234u32, None).await;
    assert!(matches!(result, Err(TamgaError::PidTaken(_))));
}

#[tokio::test]
async fn ping_process_happy_path() {
    let mock_server = MockServer::start().await;
    let process_id = uuid::Uuid::nil();
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/processes/{process_id}/actions/ping"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": process_resource_json(process_id, machine_id, "1234")
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let process = client.ping_process(process_id).await.unwrap();
    assert_eq!(process.attributes.pid, "1234");
}

#[tokio::test]
async fn list_components_sends_limit_and_page_after_query_params() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let component_id = uuid::Uuid::nil();
    let after_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/components"
        )))
        .and(query_param("limit", "10"))
        .and(query_param("page[after]", after_id.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [component_resource_json(component_id, machine_id)]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let components = client
        .list_components(machine_id, Some(10), Some(after_id))
        .await
        .unwrap();
    assert_eq!(components.len(), 1);
}
