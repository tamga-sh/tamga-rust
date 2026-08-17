//! Integration tests for entitlements (`Client::list_entitlements`,
//! `get_entitlement`, `has_entitlement`).

use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn entitlement_json(id: uuid::Uuid, name: &str, code: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "entitlements",
        "id": id.to_string(),
        "attributes": {
            "name": name,
            "code": code,
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
async fn list_entitlements_sends_pagination_params_and_parses_full_resources() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();
    let after_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements"
        )))
        .and(query_param("limit", "10"))
        .and(query_param("page[after]", after_id.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [entitlement_json(entitlement_id, "Pro Features", "pro")]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let entitlements = client
        .list_entitlements(license_id, Some(10), Some(after_id))
        .await
        .unwrap();
    assert_eq!(entitlements.len(), 1);
    assert_eq!(entitlements[0].attributes.code, "pro");
    assert_eq!(entitlements[0].attributes.name, "Pro Features");
}

#[tokio::test]
async fn get_entitlement_by_id() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements/{entitlement_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": entitlement_json(entitlement_id, "Pro Features", "pro")
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let entitlement = client
        .get_entitlement(license_id, entitlement_id)
        .await
        .unwrap();
    assert_eq!(entitlement.attributes.code, "pro");
}

#[tokio::test]
async fn has_entitlement_matches_by_code_not_name() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    // Entitlement's `name` happens to equal the code we'll search for, but
    // its actual `code` is different — has_entitlement("pro") must return
    // false here, proving it matches on `code`, not `name`.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [entitlement_json(entitlement_id, "pro", "pro-features-v2")]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let has_it = client
        .has_entitlement(license_id, "pro", None)
        .await
        .unwrap();
    assert!(
        !has_it,
        "must not match on `name` — the entitlement's `name` is \"pro\" but its `code` is \"pro-features-v2\""
    );

    let has_actual_code = client
        .has_entitlement(license_id, "pro-features-v2", None)
        .await
        .unwrap();
    assert!(has_actual_code);
}
