//! Integration tests for the transport layer's request/response header
//! handling, which needs a real endpoint to exercise. Uses `quick_validate` as
//! the vehicle since it's the simplest endpoint with both a header-sensitive
//! request and a non-enveloped response body.

use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn quick_validate_response(code: &str, valid: bool) -> serde_json::Value {
    serde_json::json!({
        "ts": "2026-01-01T00:00:00Z",
        "valid": valid,
        "detail": "test detail",
        "code": code,
    })
}

#[tokio::test]
async fn sends_tamga_version_and_otp_headers_on_every_request() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .and(header("Tamga-Version", "1.8"))
        .and(header("Tamga-OTP", "123456"))
        .and(header("Authorization", "License lic-abc"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(quick_validate_response("VALID", true)),
        )
        .mount(&mock_server)
        .await;

    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    let client = Client::new(config).unwrap();

    // If any expected header were missing, wiremock wouldn't match this
    // request and the mock server would 404 — so a successful result here
    // is itself the header assertion.
    let result = client.quick_validate(license_id, Some("123456")).await;
    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn quick_validate_parses_flat_body_with_no_data_envelope() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(quick_validate_response("VALID", true)),
        )
        .mount(&mock_server)
        .await;

    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    let client = Client::new(config).unwrap();

    let meta = client.quick_validate(license_id, None).await.unwrap();
    assert!(meta.valid);
    assert_eq!(meta.detail, "test detail");
}
