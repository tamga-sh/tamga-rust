//! Integration tests for machine management.

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

fn license_resource_json(license_id: uuid::Uuid, machines_count: u32) -> serde_json::Value {
    serde_json::json!({
        "type": "licenses",
        "id": license_id.to_string(),
        "attributes": {
            "name": null, "key": "lic-abc123", "status": "ACTIVE", "expiry": null,
            "suspended": false, "protected": false, "uses": 0, "scheme": null,
            "encrypted": false, "strict": false, "floating": false,
            "max_machines": 1, "max_uses": null, "max_users": null,
            "last_validated_at": null, "last_check_in_at": null, "last_check_out_at": null,
            "machines_count": machines_count, "metadata": {},
            "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
        }
    })
}

fn validation_error_body(code: &str) -> serde_json::Value {
    serde_json::json!({
        "errors": [{
            "id": "01926b3e-0000-7000-8000-000000000000",
            // JSON:API sends `status` as a string, not a number.
            "status": "422",
            "code": code,
            "title": "Unprocessable Entity",
            "detail": "the license has reached its machine limit",
            "source": { "pointer": "/data/relationships/license" },
        }]
    })
}

#[tokio::test]
async fn activate_machine_normalizes_a_create_time_limit_refusal_without_deleting() {
    // Strict overage strategy: the server refuses `POST /machines` outright,
    // so the create -> validate -> rollback path never starts. The seat that
    // is already taken belongs to some other machine — issuing a DELETE here
    // would evict an innocent activation, so the mock server mounts no
    // DELETE route at all and would 404 if one were sent.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_json(validation_error_body("MACHINE_LIMIT_EXCEEDED")),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    // The licence resource still has to come from somewhere. `skip_touch` is
    // true: no activation happened, so nothing should be recorded as a
    // successful validation.
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .and(body_json(serde_json::json!({
            "meta": { "skip_touch": true }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": license_resource_json(license_id, 1),
            "meta": {
                "ts": "2026-01-01T00:00:00Z", "valid": true,
                "detail": "is valid", "code": "VALID",
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client
        .activate_machine(
            license_id,
            "fp-abc123",
            CreateMachineOptions::default(),
            None,
            true,
        )
        .await
        .expect("a create-time limit refusal is an over-limit outcome, not a transport failure");

    // Same shape the validate-time overage produces, so one caller branch
    // covers both policies — even though the probe validate itself said VALID
    // (it describes the licence *without* the refused machine).
    assert!(!result.meta.valid);
    assert_eq!(
        result.meta.code,
        tamga::models::validation::ValidationCode::TooManyMachines
    );
    assert_eq!(
        result.meta.detail,
        "the license has reached its machine limit"
    );
    assert_eq!(result.license.id, license_id);

    // No DELETE was issued: every mounted expectation is verified on drop,
    // and an unmatched DELETE would have been recorded here.
    let deletes = mock_server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .into_iter()
        .filter(|req| req.method == wiremock::http::Method::DELETE)
        .count();
    assert_eq!(deletes, 0, "nothing was created, so nothing may be deleted");
}

#[tokio::test]
async fn activate_machine_still_rolls_back_when_overage_is_only_reported_at_validate() {
    // Permissive overage strategy (ALLOW_ACCESS / ALLOW_1_25X_OVERAGE ...):
    // the server's create-time limit check runs through it and lets the
    // machine in, so the limit surfaces only at validate. The rollback path
    // must still run.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "data": machine_resource_json(machine_id, "NOT_STARTED")
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // skip_touch is false here: this is a real activation attempt.
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .and(body_json(serde_json::json!({
            "meta": { "skip_touch": false }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": license_resource_json(license_id, 2),
            "meta": {
                "ts": "2026-01-01T00:00:00Z", "valid": false,
                "detail": "has too many machines", "code": "TOO_MANY_MACHINES",
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("/v1/accounts/acc-123/machines/{machine_id}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
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

    // `.expect(1)` on the DELETE mock is the assertion: wiremock verifies
    // every expectation when the server drops, so the rollback is proven to
    // have run rather than merely tolerated.
    let deletes = mock_server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .into_iter()
        .filter(|req| req.method == wiremock::http::Method::DELETE)
        .count();
    assert_eq!(deletes, 1, "the just-created machine must be rolled back");
}

#[tokio::test]
async fn activate_machine_propagates_a_non_limit_create_failure_unchanged() {
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
        .activate_machine(
            license_id,
            "fp-abc123",
            CreateMachineOptions::default(),
            None,
            true,
        )
        .await;
    assert!(matches!(result, Err(TamgaError::FingerprintTaken(_))));
}

#[tokio::test]
async fn ping_heartbeat_against_a_stale_machine_returns_resurrected() {
    // A machine that stopped pinging goes `DEAD` server-side, but a ping
    // still lands (bare `SET last_heartbeat_at = NOW()`, no resurrection
    // check) and revives it. `RESURRECTED` is what the server really answers
    // here, and mocking that is the point: the ping writes the timestamp and
    // then derives the status from it, so its age is ~0 and `DEAD` is not a
    // response this route can produce. `DEAD` does reach this crate, just not
    // here: the machine inside a verified `.mach` file, and the one on a
    // `generate_offline_proof` response, are read from the row rather than
    // echoed from a write, so either can carry it.
    //
    // The property under test is that the client accepts the revival answer
    // and does not treat a status change as a failure. Never stop a ping loop
    // on a status; only the 404 below is terminal.
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/ping-heartbeat"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": machine_resource_json(machine_id, "RESURRECTED")
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let machine = client
        .ping_heartbeat(machine_id)
        .await
        .expect("pinging a stale machine must succeed, not fail");
    assert_eq!(
        machine.attributes.heartbeat_status,
        HeartbeatStatus::Resurrected
    );
}

#[tokio::test]
async fn ping_heartbeat_404_is_the_only_row_is_gone_signal() {
    // Re-activation hangs off this, not off any `heartbeat_status` value —
    // `HeartbeatStatus::Dead` never arrives on this route (see above), so a
    // 404 is the only terminal signal a ping loop can act on.
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/ping-heartbeat"
        )))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "404",
                "code": "NOT_FOUND",
                "title": "Not Found",
                "detail": "machine not found",
                "source": null,
            }]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client.ping_heartbeat(machine_id).await;
    assert!(matches!(result, Err(TamgaError::NotFound(_))));
}
