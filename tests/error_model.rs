//! Integration tests for `docs/plans/tamga-rust.plan.md` §K — Error Model.
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
