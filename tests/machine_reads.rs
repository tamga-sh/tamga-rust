//! Integration tests for the machine domain's read/update half:
//! `get_machine`, `list_machines` (offset paginated), `update_machine`,
//! `list_machine_processes`, and the idempotent activation path built on them.

use tamga::client::{CreateMachineOptions, ListMachinesOptions, UpdateMachineOptions};
use tamga::models::machine::HeartbeatStatus;
use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn machine_json(id: uuid::Uuid, fingerprint: &str, heartbeat_status: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "machines",
        "id": id.to_string(),
        "attributes": {
            "fingerprint": fingerprint,
            "cores": null, "memory": null, "disk": null, "ip": null,
            "hostname": null, "platform": null, "name": null,
            "heartbeat_status": heartbeat_status,
            "last_heartbeat_at": null, "next_heartbeat_at": null, "last_check_out_at": null,
            "metadata": {},
            "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
        }
    })
}

fn license_json(id: uuid::Uuid) -> serde_json::Value {
    serde_json::json!({
        "type": "licenses",
        "id": id.to_string(),
        "attributes": {
            "name": null, "key": null, "status": "ACTIVE", "expiry": null,
            "suspended": false, "protected": false, "uses": 0, "scheme": null,
            "encrypted": false, "strict": false, "floating": false,
            "max_machines": null, "max_uses": null, "max_users": null,
            "last_validated_at": null, "last_check_in_at": null, "last_check_out_at": null,
            "machines_count": 1, "metadata": {},
            "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
        }
    })
}

fn page_meta(number: i64, size: i64, total: i64, total_pages: i64) -> serde_json::Value {
    serde_json::json!({
        "page": { "number": number, "size": size, "total": total, "totalPages": total_pages }
    })
}

fn test_client(mock_server: &MockServer) -> Client {
    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    Client::new(config).unwrap()
}

#[tokio::test]
async fn get_machine_returns_the_resource() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!("/v1/accounts/acc-123/machines/{machine_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": machine_json(machine_id, "fp-abc123", "ALIVE")
        })))
        .mount(&mock_server)
        .await;

    let machine = test_client(&mock_server)
        .get_machine(machine_id)
        .await
        .unwrap();
    assert_eq!(machine.attributes.fingerprint, "fp-abc123");
}

#[tokio::test]
async fn get_machine_can_report_dead_unlike_any_write_response() {
    // The whole reason this route is worth having: it is a policy-joined read
    // of a row nobody just wrote, so the staleness verdict is real. A `Dead`
    // branch here is live code; against a ping response it is unreachable.
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    let mut body = machine_json(machine_id, "fp-abc123", "DEAD");
    body["attributes"]["last_heartbeat_at"] = serde_json::json!("2026-01-01T00:00:00Z");
    body["attributes"]["next_heartbeat_at"] = serde_json::json!("2026-01-01T00:01:30Z");

    Mock::given(method("GET"))
        .and(path(format!("/v1/accounts/acc-123/machines/{machine_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": body })))
        .mount(&mock_server)
        .await;

    let machine = test_client(&mock_server)
        .get_machine(machine_id)
        .await
        .unwrap();
    assert_eq!(machine.attributes.heartbeat_status, HeartbeatStatus::Dead);
    // And the policy join means the window is recoverable from this response.
    assert_eq!(
        machine.attributes.observed_heartbeat_window(),
        Some(std::time::Duration::from_secs(90))
    );
}

#[tokio::test]
async fn observed_heartbeat_window_is_none_without_both_timestamps() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!("/v1/accounts/acc-123/machines/{machine_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": machine_json(machine_id, "fp-abc123", "NOT_STARTED")
        })))
        .mount(&mock_server)
        .await;

    let machine = test_client(&mock_server)
        .get_machine(machine_id)
        .await
        .unwrap();
    assert_eq!(machine.attributes.observed_heartbeat_window(), None);
}

#[tokio::test]
async fn list_machines_decodes_offset_page_metadata() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [machine_json(machine_id, "fp-abc123", "ALIVE")],
            "meta": page_meta(1, 25, 142, 6),
        })))
        .mount(&mock_server)
        .await;

    let page = test_client(&mock_server)
        .list_machines(ListMachinesOptions::default())
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.page.total, 142);
    assert_eq!(page.page.total_pages, 6);
    // Offset, not keyset: the next request is a page *number*, not a cursor.
    assert_eq!(page.next_page_number(), Some(2));
}

#[tokio::test]
async fn list_machines_sends_offset_params_never_a_keyset_cursor() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/machines"))
        .and(query_param("page[number]", "3"))
        .and(query_param("page[size]", "100"))
        .and(query_param("filter[license]", license_id.to_string()))
        .and(query_param("filter[platform]", "linux"))
        .and(query_param("filter[q]", "needle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [],
            "meta": page_meta(3, 100, 0, 0),
        })))
        .mount(&mock_server)
        .await;

    let page = test_client(&mock_server)
        .list_machines(ListMachinesOptions {
            license_id: Some(license_id),
            platform: Some("linux".to_string()),
            search: Some("needle".to_string()),
            page_number: Some(3),
            page_size: Some(100),
        })
        .await
        .unwrap();
    assert!(page.items.is_empty());
    assert_eq!(page.next_page_number(), None);

    // The route has no `page[after]`; sending one would be silently ignored,
    // which is exactly how the entitlements listing already misleads callers.
    let requests = mock_server.received_requests().await.unwrap();
    let query = requests[0].url.query().unwrap_or_default();
    assert!(
        !query.contains("page%5Bafter%5D") && !query.contains("page[after]"),
        "list_machines must not send a keyset cursor: {query}"
    );
}

#[tokio::test]
async fn find_machine_by_fingerprint_matches_exactly_not_by_substring() {
    // `filter[q]` is an ILIKE '%term%' across name, hostname AND fingerprint,
    // so the server can legitimately return rows that merely contain the term.
    // The exact match has to happen client-side.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let wanted = uuid::Uuid::from_u128(2);

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/machines"))
        .and(query_param("filter[license]", license_id.to_string()))
        .and(query_param("filter[q]", "fp-abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                machine_json(uuid::Uuid::from_u128(1), "fp-abc123", "ALIVE"),
                machine_json(wanted, "fp-abc", "ALIVE"),
                machine_json(uuid::Uuid::from_u128(3), "FP-ABC", "ALIVE"),
            ],
            "meta": page_meta(1, 100, 3, 1),
        })))
        .mount(&mock_server)
        .await;

    let found = test_client(&mock_server)
        .find_machine_by_fingerprint(license_id, "fp-abc")
        .await
        .unwrap()
        .expect("the exact fingerprint is present");
    assert_eq!(found.id, wanted);
    assert_eq!(found.attributes.fingerprint, "fp-abc");
}

#[tokio::test]
async fn find_machine_by_fingerprint_returns_none_when_only_near_misses_come_back() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [machine_json(uuid::Uuid::from_u128(1), "fp-abc123", "ALIVE")],
            "meta": page_meta(1, 100, 1, 1),
        })))
        .mount(&mock_server)
        .await;

    let found = test_client(&mock_server)
        .find_machine_by_fingerprint(license_id, "fp-abc")
        .await
        .unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn find_machine_by_fingerprint_walks_past_the_first_page() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let wanted = uuid::Uuid::from_u128(9);

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/machines"))
        .and(query_param("page[number]", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [machine_json(uuid::Uuid::from_u128(1), "other", "ALIVE")],
            "meta": page_meta(1, 100, 200, 2),
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/machines"))
        .and(query_param("page[number]", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [machine_json(wanted, "fp-abc", "ALIVE")],
            "meta": page_meta(2, 100, 200, 2),
        })))
        .mount(&mock_server)
        .await;

    let found = test_client(&mock_server)
        .find_machine_by_fingerprint(license_id, "fp-abc")
        .await
        .unwrap()
        .expect("found on the second page");
    assert_eq!(found.id, wanted);
}

#[tokio::test]
async fn find_machine_by_fingerprint_always_scopes_to_the_licence() {
    // Not a convenience: the resource carries no license_id, so filter[license]
    // is the only thing that makes "this machine is yours" checkable. And it
    // costs nothing — all three uniqueness strategies raise FINGERPRINT_TAKEN
    // for the caller's own rows too, so a genuine re-activation is always
    // inside the scoped search.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::from_u128(11);

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [],
            "meta": page_meta(1, 100, 0, 0),
        })))
        .mount(&mock_server)
        .await;

    test_client(&mock_server)
        .find_machine_by_fingerprint(license_id, "fp-abc")
        .await
        .unwrap();

    let requests = mock_server.received_requests().await.unwrap();
    let query = requests[0].url.query().unwrap_or_default();
    assert!(
        query.contains(&format!("filter%5Blicense%5D={license_id}"))
            || query.contains(&format!("filter[license]={license_id}")),
        "the licence filter is mandatory: {query}"
    );
}

#[tokio::test]
async fn update_machine_sends_a_json_api_envelope() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("PATCH"))
        .and(path(format!("/v1/accounts/acc-123/machines/{machine_id}")))
        .and(body_json(serde_json::json!({
            "data": {
                "type": "machines",
                "attributes": {
                    "name": "renamed", "ip": null, "hostname": null, "platform": null,
                    "cores": 8, "memory": null, "disk": null, "metadata": null,
                }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": machine_json(machine_id, "fp-abc123", "ALIVE")
        })))
        .mount(&mock_server)
        .await;

    let machine = test_client(&mock_server)
        .update_machine(
            machine_id,
            UpdateMachineOptions {
                name: Some("renamed".to_string()),
                cores: Some(8),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(machine.attributes.fingerprint, "fp-abc123");
}

#[tokio::test]
async fn update_machine_is_the_write_whose_response_can_still_say_dead() {
    // The counterexample to "a write response can never say DEAD". The UPDATE
    // touches no heartbeat column, so the status is judged against a
    // last_heartbeat_at as old as it was before the call. Its RETURNING list
    // selects no policy column either, so next_heartbeat_at is on the 600s
    // fallback — the two fields split differently on this one route.
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    let mut body = machine_json(machine_id, "fp-abc123", "DEAD");
    body["attributes"]["last_heartbeat_at"] = serde_json::json!("2026-01-01T00:00:00Z");
    body["attributes"]["next_heartbeat_at"] = serde_json::json!("2026-01-01T00:10:00Z");

    Mock::given(method("PATCH"))
        .and(path(format!("/v1/accounts/acc-123/machines/{machine_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": body })))
        .mount(&mock_server)
        .await;

    let machine = test_client(&mock_server)
        .update_machine(
            machine_id,
            UpdateMachineOptions {
                hostname: Some("renamed-host".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(machine.attributes.heartbeat_status, HeartbeatStatus::Dead);
    assert_eq!(
        machine.attributes.observed_heartbeat_window(),
        Some(std::time::Duration::from_secs(600)),
        "the fallback, not the policy value — this route joins no policy"
    );
}

#[tokio::test]
async fn list_machine_processes_sends_the_keyset_cursor_this_route_does_honour() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let after = uuid::Uuid::from_u128(7);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/processes"
        )))
        .and(query_param("limit", "50"))
        .and(query_param("page[after]", after.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "type": "processes",
                "id": uuid::Uuid::from_u128(8).to_string(),
                "attributes": {
                    "pid": "4242",
                    "machine_id": machine_id.to_string(),
                    "last_heartbeat_at": "2026-01-01T00:00:00Z",
                    "metadata": {},
                    "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
                }
            }]
        })))
        .mount(&mock_server)
        .await;

    let processes = test_client(&mock_server)
        .list_machine_processes(machine_id, Some(50), Some(after))
        .await
        .unwrap();
    assert_eq!(processes.len(), 1);
    assert_eq!(processes[0].attributes.pid, "4242");
}

// ── Idempotent activation ────────────────────────────────────────────────

#[tokio::test]
async fn idempotent_activation_creates_when_the_fingerprint_is_free() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let machine_id = uuid::Uuid::from_u128(4);

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "data": machine_json(machine_id, "fp-abc123", "NOT_STARTED")
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": license_json(license_id),
            "meta": { "ts": "2026-01-01T00:00:00Z", "valid": true, "detail": "ok", "code": "VALID" },
        })))
        .mount(&mock_server)
        .await;

    let activation = test_client(&mock_server)
        .activate_machine_idempotent(
            license_id,
            "fp-abc123",
            CreateMachineOptions::default(),
            None,
            true,
        )
        .await
        .unwrap();
    assert!(!activation.reused);
    assert_eq!(activation.machine.unwrap().id, machine_id);
    assert!(activation.validation.meta.valid);
}

#[tokio::test]
async fn idempotent_activation_adopts_the_machine_already_on_this_licence() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let existing_id = uuid::Uuid::from_u128(5);

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "errors": [{
                "id": "err-1", "status": "409", "code": "FINGERPRINT_TAKEN",
                "title": "Conflict",
                "detail": "This fingerprint is already activated within the policy's uniqueness scope",
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/machines"))
        .and(query_param("filter[license]", license_id.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [machine_json(existing_id, "fp-abc123", "ALIVE")],
            "meta": page_meta(1, 100, 1, 1),
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": license_json(license_id),
            "meta": { "ts": "2026-01-01T00:00:00Z", "valid": true, "detail": "ok", "code": "VALID" },
        })))
        .mount(&mock_server)
        .await;

    let activation = test_client(&mock_server)
        .activate_machine_idempotent(
            license_id,
            "fp-abc123",
            CreateMachineOptions::default(),
            None,
            true,
        )
        .await
        .unwrap();
    assert!(activation.reused, "a re-activation, not a fresh create");
    assert_eq!(activation.machine.unwrap().id, existing_id);
}

#[tokio::test]
async fn idempotent_activation_propagates_a_conflict_held_by_another_licence() {
    // Under UNIQUE_PER_POLICY / UNIQUE_PER_ACCOUNT the conflicting machine can
    // belong to a different licence. Handing it back as "yours" would defeat
    // the anti-seat-sharing check the wider scopes exist for.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "errors": [{
                "id": "err-1", "status": "409", "code": "FINGERPRINT_TAKEN",
                "title": "Conflict", "detail": "already activated elsewhere",
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [],
            "meta": page_meta(1, 100, 0, 0),
        })))
        .mount(&mock_server)
        .await;

    let err = test_client(&mock_server)
        .activate_machine_idempotent(
            license_id,
            "fp-abc123",
            CreateMachineOptions::default(),
            None,
            true,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TamgaError::FingerprintTaken(_)));
}

#[tokio::test]
async fn idempotent_activation_never_rolls_back_a_machine_it_adopted() {
    // Deleting a pre-existing machine because the licence is over its limit
    // would destroy a seat this call did not create.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let existing_id = uuid::Uuid::from_u128(5);

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "errors": [{
                "id": "err-1", "status": "409", "code": "FINGERPRINT_TAKEN",
                "title": "Conflict", "detail": "already activated",
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [machine_json(existing_id, "fp-abc123", "ALIVE")],
            "meta": page_meta(1, 100, 1, 1),
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": license_json(license_id),
            "meta": {
                "ts": "2026-01-01T00:00:00Z", "valid": false,
                "detail": "too many machines", "code": "TOO_MANY_MACHINES",
            },
        })))
        .mount(&mock_server)
        .await;

    let activation = test_client(&mock_server)
        .activate_machine_idempotent(
            license_id,
            "fp-abc123",
            CreateMachineOptions::default(),
            None,
            true,
        )
        .await
        .unwrap();
    assert!(activation.reused);
    assert!(activation.machine.is_some(), "the adopted machine survives");

    let deletes = mock_server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method == wiremock::http::Method::DELETE)
        .count();
    assert_eq!(deletes, 0, "an adopted machine must never be rolled back");
}

#[tokio::test]
async fn idempotent_activation_reports_a_strict_policy_refusal_with_no_machine() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
            "errors": [{
                "id": "err-1", "status": "422", "code": "MACHINE_LIMIT_EXCEEDED",
                "title": "Unprocessable", "detail": "This license has reached its machine limit",
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": license_json(license_id),
            "meta": { "ts": "2026-01-01T00:00:00Z", "valid": true, "detail": "ok", "code": "VALID" },
        })))
        .mount(&mock_server)
        .await;

    let activation = test_client(&mock_server)
        .activate_machine_idempotent(
            license_id,
            "fp-abc123",
            CreateMachineOptions::default(),
            None,
            true,
        )
        .await
        .unwrap();
    assert!(activation.machine.is_none(), "no row was created");
    assert!(!activation.reused);
    assert!(!activation.validation.meta.valid);
}

#[tokio::test]
async fn idempotent_activation_reports_no_machine_after_rolling_back_the_one_it_created() {
    // D15. After the rollback DELETE the row is gone; returning it as
    // `machine: Some(..)` names a machine the caller must not act on.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let machine_id = uuid::Uuid::from_u128(6);

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "data": machine_json(machine_id, "fp-abc123", "NOT_STARTED")
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": license_json(license_id),
            "meta": {
                "ts": "2026-01-01T00:00:00Z", "valid": false,
                "detail": "too many machines", "code": "TOO_MANY_MACHINES",
            },
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

    let activation = test_client(&mock_server)
        .activate_machine_idempotent(
            license_id,
            "fp-abc123",
            CreateMachineOptions::default(),
            None,
            true,
        )
        .await
        .unwrap();

    assert!(!activation.reused);
    assert!(!activation.validation.meta.valid);
    assert!(
        activation.machine.is_none(),
        "the rolled-back machine no longer exists and must not be reported"
    );
}
