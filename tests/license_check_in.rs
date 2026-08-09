//! Integration tests for `docs/plans/tamga-rust.plan.md` §D — License
//! Check-In.

use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn license_resource_json(id: uuid::Uuid) -> serde_json::Value {
    serde_json::json!({
        "type": "licenses",
        "id": id.to_string(),
        "attributes": {
            "name": "Acme Corp",
            "key": "lic-abc123",
            "status": "ACTIVE",
            "expiry": null,
            "suspended": false,
            "protected": false,
            "uses": 0,
            "scheme": null,
            "encrypted": false,
            "strict": false,
            "floating": false,
            "max_machines": null,
            "max_uses": null,
            "max_users": null,
            "last_validated_at": null,
            "last_check_in_at": "2026-01-02T00:00:00Z",
            "last_check_out_at": null,
            "machines_count": 0,
            "metadata": {},
            "created": "2026-01-01T00:00:00Z",
            "updated": "2026-01-02T00:00:00Z",
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
async fn check_in_happy_path_updates_last_check_in_at() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/check-in"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "data": license_resource_json(license_id) })),
        )
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let license = client.check_in(license_id).await.unwrap();
    assert_eq!(
        license.attributes.last_check_in_at,
        Some("2026-01-02T00:00:00Z".parse().unwrap())
    );
}

#[tokio::test]
async fn check_in_against_require_check_in_false_policy_returns_typed_error() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/check-in"
        )))
        .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "422",
                "code": "CHECK_IN_NOT_REQUIRED",
                "title": "Unprocessable Entity",
                "detail": "this license's policy does not require check-in",
                "source": null,
            }]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client.check_in(license_id).await;
    assert!(matches!(result, Err(TamgaError::CheckInNotRequired(_))));
}
