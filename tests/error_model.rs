//! Integration tests for the error model (`src/error.rs`).
//!
//! End-to-end error-path coverage for codes not already exercised via a
//! mocked server round trip in another section's test file: the fixed
//! HTTP-status codes, and the remaining per-endpoint 409/422 codes
//! (`DATASET_INVALID`, `LICENSE_KEY_MISSING`, and the server-side —
//! as opposed to this SDK's own client-side pre-check — paths for
//! `TTL_INVALID`/`SCHEME_NOT_SUPPORTED`).

use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn error_body(status: &str, code: &str) -> serde_json::Value {
    serde_json::json!({
        "errors": [{
            "id": "01926b3e-0000-7000-8000-000000000000",
            "status": status,
            "code": code,
            "title": "error",
            "detail": "error detail",
            "source": null,
        }]
    })
}

fn test_client(mock_server: &MockServer) -> Client {
    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    Client::new(config).unwrap()
}

async fn mount_quick_validate_error(
    mock_server: &MockServer,
    license_id: uuid::Uuid,
    status: u16,
    code: &str,
) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .respond_with(
            ResponseTemplate::new(status).set_body_json(error_body(&status.to_string(), code)),
        )
        .mount(mock_server)
        .await;
}

#[tokio::test]
async fn not_found_maps_to_typed_variant() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    mount_quick_validate_error(&mock_server, license_id, 404, "NOT_FOUND").await;

    let client = test_client(&mock_server);
    let result = client.quick_validate(license_id, None).await;
    assert!(matches!(result, Err(TamgaError::NotFound(_))));
}

#[tokio::test]
async fn unauthorized_maps_to_typed_variant() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    mount_quick_validate_error(&mock_server, license_id, 401, "UNAUTHORIZED").await;

    let client = test_client(&mock_server);
    let result = client.quick_validate(license_id, None).await;
    assert!(matches!(result, Err(TamgaError::Unauthorized(_))));
}

#[tokio::test]
async fn forbidden_maps_to_typed_variant() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    mount_quick_validate_error(&mock_server, license_id, 403, "FORBIDDEN").await;

    let client = test_client(&mock_server);
    let result = client.quick_validate(license_id, None).await;
    assert!(matches!(result, Err(TamgaError::Forbidden(_))));
}

#[tokio::test]
async fn internal_server_error_maps_to_typed_variant() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    mount_quick_validate_error(&mock_server, license_id, 500, "INTERNAL_SERVER_ERROR").await;

    let client = test_client(&mock_server);
    let result = client.quick_validate(license_id, None).await;
    assert!(matches!(result, Err(TamgaError::InternalServerError(_))));
}

#[tokio::test]
async fn dataset_invalid_maps_to_typed_variant() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/generate-offline-proof"
        )))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(error_body("422", "DATASET_INVALID")),
        )
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client
        .generate_offline_proof(machine_id, Some(serde_json::json!(["not", "an", "object"])))
        .await;
    assert!(matches!(result, Err(TamgaError::DatasetInvalid(_))));
}

#[tokio::test]
async fn license_key_missing_maps_to_typed_variant() {
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/check-out"
        )))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(error_body("422", "LICENSE_KEY_MISSING")),
        )
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client.check_out_machine_json(machine_id, true, None).await;
    assert!(matches!(result, Err(TamgaError::LicenseKeyMissingApi(_))));
}

#[tokio::test]
async fn ttl_invalid_server_side_maps_to_typed_variant() {
    // Distinct from the client-side pre-check in
    // tests/checkout_machine_file.rs — this exercises the SDK's dispatcher
    // actually receiving TTL_INVALID *from the server*, for a ttl this
    // SDK's own client-side check doesn't reject (i.e. bypassing/not
    // covered by check_ttl would still surface correctly).
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/check-out"
        )))
        .respond_with(ResponseTemplate::new(422).set_body_json(error_body("422", "TTL_INVALID")))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client
        .check_out_machine_json(machine_id, false, Some(3600))
        .await;
    assert!(matches!(result, Err(TamgaError::TtlInvalidApi(_))));
}

#[tokio::test]
async fn scheme_not_supported_server_side_maps_to_typed_variant() {
    // Distinct from the client-side JWT rejection in
    // src/checkout/machine_file.rs::tests — exercises the dispatcher
    // receiving this code directly from the server.
    let mock_server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/machines/{machine_id}/actions/check-out"
        )))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(error_body("422", "SCHEME_NOT_SUPPORTED")),
        )
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client.check_out_machine_json(machine_id, false, None).await;
    assert!(matches!(result, Err(TamgaError::SchemeNotSupportedApi(_))));
}

#[tokio::test]
async fn create_time_machine_limit_maps_onto_the_matching_validation_code() {
    // The server refuses the machine outright under a strict overage
    // strategy. `status` is the JSON:API string "422", not the number.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(error_body("422", "MACHINE_LIMIT_EXCEEDED")),
        )
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let err = client
        .create_machine(
            license_id,
            "fp-abc123",
            tamga::client::CreateMachineOptions::default(),
        )
        .await
        .expect_err("creation is refused when the machine limit is already reached");

    // No dedicated TamgaError variant — the code rides on the generic Api
    // variant and is classified from there.
    assert!(matches!(err, TamgaError::Api(_)));
    assert_eq!(err.code(), Some("MACHINE_LIMIT_EXCEEDED"));
    assert_eq!(
        err.limit_exceeded(),
        Some(tamga::error::LimitExceededCode::MachineLimitExceeded)
    );
    assert_eq!(
        err.limit_exceeded().unwrap().as_validation_code(),
        tamga::models::validation::ValidationCode::TooManyMachines
    );
    assert_eq!(err.license_auth_failure(), None);
}

#[tokio::test]
async fn license_not_allowed_401_is_classified_as_an_auth_gate_failure() {
    // The policy's authentication_strategy defaults to 'TOKEN', under which
    // a licence key is never an acceptable credential. Not retryable.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(error_body("401", "LICENSE_NOT_ALLOWED")),
        )
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let err = client
        .validate_by_id(license_id, None, false, None)
        .await
        .expect_err("the policy does not accept licence-key auth");

    // Distinct from the bare `UNAUTHORIZED` code, which has its own variant.
    assert!(matches!(err, TamgaError::Api(_)));
    assert_eq!(err.code(), Some("LICENSE_NOT_ALLOWED"));
    assert_eq!(err.json_api_error().unwrap().status, "401");
    assert_eq!(
        err.license_auth_failure(),
        Some(tamga::error::LicenseAuthCode::LicenseNotAllowed)
    );
    assert_eq!(err.limit_exceeded(), None);
}

#[tokio::test]
async fn scope_not_supported_is_unreachable_because_the_sdk_never_sends_those_fields() {
    // A caller that still sets `version`/`checksum` must degrade to an
    // unscoped validate, not to a 422 that kills the whole call.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "meta": { "skip_touch": false, "scope": { "product": uuid::Uuid::nil() } }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": license_resource_json(license_id),
            "meta": {
                "ts": "2026-01-01T00:00:00Z", "valid": true,
                "detail": "is valid", "code": "VALID",
            }
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let scope = tamga::models::validation::ScopeObject {
        product: Some(uuid::Uuid::nil()),
        version: Some("1.2.3".to_string()),
        checksum: Some("deadbeef".to_string()),
        ..Default::default()
    };
    let result = client
        .validate_by_id(license_id, Some(scope), false, None)
        .await
        .expect("the refused scope fields must never reach the wire");
    assert!(result.meta.valid);
}

fn license_resource_json(license_id: uuid::Uuid) -> serde_json::Value {
    serde_json::json!({
        "type": "licenses",
        "id": license_id.to_string(),
        "attributes": {
            "name": null, "key": "lic-abc123", "status": "ACTIVE", "expiry": null,
            "suspended": false, "protected": false, "uses": 0, "scheme": null,
            "encrypted": false, "strict": false, "floating": false,
            "max_machines": 1, "max_uses": null, "max_users": null,
            "last_validated_at": null, "last_check_in_at": null, "last_check_out_at": null,
            "machines_count": 1, "metadata": {},
            "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
        }
    })
}
