//! Integration tests for releasing process slots — the only thing that ever
//! removes a process row, since the server's reaper has no call site.

use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn process_json(id: uuid::Uuid, machine_id: uuid::Uuid, pid: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "processes",
        "id": id.to_string(),
        "attributes": {
            "pid": pid,
            "machine_id": machine_id.to_string(),
            "last_heartbeat_at": "2026-01-01T00:00:00Z",
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
async fn delete_process_accepts_204_no_content() {
    let mock_server = MockServer::start().await;
    let process_id = uuid::Uuid::nil();

    Mock::given(method("DELETE"))
        .and(path(format!("/v1/accounts/acc-123/processes/{process_id}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    test_client(&mock_server)
        .delete_process(process_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_process_surfaces_404_rather_than_succeeding_silently() {
    let mock_server = MockServer::start().await;
    let process_id = uuid::Uuid::nil();

    Mock::given(method("DELETE"))
        .and(path(format!("/v1/accounts/acc-123/processes/{process_id}")))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "errors": [{
                "id": "err-1", "status": "404", "code": "NOT_FOUND",
                "title": "Not Found", "detail": "process not found",
            }]
        })))
        .mount(&mock_server)
        .await;

    let err = test_client(&mock_server)
        .delete_process(process_id)
        .await
        .unwrap_err();
    assert!(matches!(err, TamgaError::NotFound(_)));
}

#[tokio::test]
async fn delete_process_surfaces_403_for_a_credential_without_process_delete() {
    let mock_server = MockServer::start().await;
    let process_id = uuid::Uuid::nil();

    Mock::given(method("DELETE"))
        .and(path(format!("/v1/accounts/acc-123/processes/{process_id}")))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": [{
                "id": "err-1", "status": "403", "code": "FORBIDDEN",
                "title": "Forbidden", "detail": "not permitted to delete this process",
            }]
        })))
        .mount(&mock_server)
        .await;

    let err = test_client(&mock_server)
        .delete_process(process_id)
        .await
        .unwrap_err();
    assert!(matches!(err, TamgaError::Forbidden(_)));
}

#[tokio::test]
async fn delete_machine_processes_releases_every_slot_then_stops() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let first = uuid::Uuid::from_u128(1);
    let second = uuid::Uuid::from_u128(2);

    // The listing is re-read from page one after each batch, because the rows
    // are being deleted underneath it. First read: two rows. Second: none.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/processes"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                process_json(first, machine_id, "1"),
                process_json(second, machine_id, "2"),
            ]
        })))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/processes"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })))
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("/v1/accounts/acc-123/processes/{first}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("/v1/accounts/acc-123/processes/{second}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let deleted = test_client(&mock_server)
        .delete_machine_processes(machine_id)
        .await
        .unwrap();
    assert_eq!(deleted, 2);
}

#[tokio::test]
async fn delete_machine_processes_treats_an_already_gone_row_as_done() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let gone = uuid::Uuid::from_u128(1);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/processes"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "data": [process_json(gone, machine_id, "1")] }),
            ),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/processes"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })))
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("/v1/accounts/acc-123/processes/{gone}")))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "errors": [{
                "id": "err-1", "status": "404", "code": "NOT_FOUND",
                "title": "Not Found", "detail": "process not found",
            }]
        })))
        .mount(&mock_server)
        .await;

    // A concurrent caller getting there first satisfies the goal, so the row
    // is not counted but the sweep continues.
    let deleted = test_client(&mock_server)
        .delete_machine_processes(machine_id)
        .await
        .unwrap();
    assert_eq!(deleted, 0);
}

#[tokio::test]
async fn delete_machine_processes_aborts_on_a_real_failure() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let blocked = uuid::Uuid::from_u128(1);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/processes"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "data": [process_json(blocked, machine_id, "1")] }),
            ),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("/v1/accounts/acc-123/processes/{blocked}")))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": [{
                "id": "err-1", "status": "403", "code": "FORBIDDEN",
                "title": "Forbidden", "detail": "not permitted",
            }]
        })))
        .mount(&mock_server)
        .await;

    let err = test_client(&mock_server)
        .delete_machine_processes(machine_id)
        .await
        .unwrap_err();
    assert!(matches!(err, TamgaError::Forbidden(_)));
}

#[tokio::test]
async fn delete_machine_processes_on_a_machine_with_none_is_a_single_read() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/processes"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let deleted = test_client(&mock_server)
        .delete_machine_processes(machine_id)
        .await
        .unwrap();
    assert_eq!(deleted, 0);
}
