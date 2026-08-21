//! Integration tests for the licence/policy read routes and the policy-aware
//! heartbeat sizing they exist to make possible.

use tamga::models::policy::CheckInInterval;
use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn policy_json(id: uuid::Uuid, heartbeat_duration: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "type": "policies",
        "id": id.to_string(),
        "attributes": {
            "product_id": uuid::Uuid::from_u128(9).to_string(),
            "name": "Default", "duration": null, "strict": false, "floating": false,
            "scheme": null, "encrypted": false, "use_pool": false, "protected": false,
            "require_check_in": false, "check_in_interval": null,
            "check_in_interval_count": null, "require_heartbeat": true,
            "heartbeat_duration": heartbeat_duration,
            "heartbeat_cull_strategy": "DEACTIVATE_DEAD",
            "heartbeat_resurrection_strategy": "NO_RESURRECTION",
            "machine_uniqueness_strategy": "UNIQUE_PER_LICENSE",
            "expiration_strategy": "RESTRICT_ACCESS", "expiration_basis": "FROM_CREATION",
            "renewal_basis": "FROM_EXPIRY", "authentication_strategy": "LICENSE",
            "overage_strategy": "DENY_ACCESS",
            "max_machines": null, "max_cores": null, "max_uses": null,
            "max_processes": null, "max_users": null, "metadata": {},
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
async fn get_license_returns_the_resource_including_its_plaintext_key() {
    // The key really is plaintext on this route, and the route really is not
    // licence-scoped. Asserted so the SDK's docs cannot drift from it.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!("/v1/accounts/acc-123/licenses/{license_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "licenses",
                "id": license_id.to_string(),
                "attributes": {
                    "name": "Acme", "key": "lic-plaintext", "status": "ACTIVE", "expiry": null,
                    "suspended": false, "protected": false, "uses": 0, "scheme": null,
                    "encrypted": false, "strict": false, "floating": false,
                    "max_machines": null, "max_uses": null, "max_users": null,
                    "last_validated_at": null, "last_check_in_at": null,
                    "last_check_out_at": null, "machines_count": 0, "metadata": {},
                    "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let license = test_client(&mock_server)
        .get_license(license_id)
        .await
        .unwrap();
    assert_eq!(license.attributes.key.as_deref(), Some("lic-plaintext"));
    assert_eq!(license.attributes.status, "ACTIVE");
}

#[tokio::test]
async fn get_license_policy_decodes_a_policy_with_the_real_bogus_defaults() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let policy_id = uuid::Uuid::from_u128(3);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/policy"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": policy_json(policy_id, serde_json::json!(null))
        })))
        .mount(&mock_server)
        .await;

    let policy = test_client(&mock_server)
        .get_license_policy(license_id)
        .await
        .unwrap();
    assert_eq!(policy.id, policy_id);
    assert_eq!(policy.attributes.overage_strategy, "DENY_ACCESS");
    assert!(policy.attributes.require_heartbeat);
}

#[tokio::test]
async fn a_policy_using_the_servers_own_check_in_spelling_decodes() {
    // `policies.check_in_interval` stores only daily/weekly/monthly/yearly.
    // Modelling just the noun forms made every such policy fail to decode as a
    // whole resource — the read routes would have been unusable.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    let mut body = policy_json(uuid::Uuid::from_u128(3), serde_json::json!(null));
    body["attributes"]["require_check_in"] = serde_json::json!(true);
    body["attributes"]["check_in_interval"] = serde_json::json!("monthly");
    body["attributes"]["check_in_interval_count"] = serde_json::json!(3);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/policy"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": body })))
        .mount(&mock_server)
        .await;

    let policy = test_client(&mock_server)
        .get_license_policy(license_id)
        .await
        .unwrap();
    assert_eq!(
        policy.attributes.check_in_interval,
        Some(CheckInInterval::Month)
    );
}

#[tokio::test]
async fn get_policy_by_id_is_the_route_a_licence_key_cannot_use() {
    // The LicenseToken role's permission set has no `policy.read`, and
    // permissions are intersected rather than granted, so this is 403 for
    // every licence-key caller no matter how the token is configured.
    let mock_server = MockServer::start().await;
    let policy_id = uuid::Uuid::from_u128(3);

    Mock::given(method("GET"))
        .and(path(format!("/v1/accounts/acc-123/policies/{policy_id}")))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": [{
                "id": "err-1", "status": "403", "code": "FORBIDDEN",
                "title": "Forbidden", "detail": "You are not allowed to read this policy",
            }]
        })))
        .mount(&mock_server)
        .await;

    let err = test_client(&mock_server)
        .get_policy(policy_id)
        .await
        .unwrap_err();
    assert!(matches!(err, TamgaError::Forbidden(_)));
}

#[tokio::test]
async fn get_policy_by_id_works_for_a_back_office_credential() {
    let mock_server = MockServer::start().await;
    let policy_id = uuid::Uuid::from_u128(3);

    Mock::given(method("GET"))
        .and(path(format!("/v1/accounts/acc-123/policies/{policy_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": policy_json(policy_id, serde_json::json!(45))
        })))
        .mount(&mock_server)
        .await;

    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::Bearer("tok-admin".to_string()))
        .build();
    let policy = Client::new(config)
        .unwrap()
        .get_policy(policy_id)
        .await
        .unwrap();
    assert_eq!(policy.attributes.heartbeat_duration, Some(45));
}

#[tokio::test]
async fn effective_heartbeat_window_reads_the_policy_rather_than_assuming_600s() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/policy"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": policy_json(uuid::Uuid::from_u128(3), serde_json::json!(90))
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    assert_eq!(
        client.effective_heartbeat_window(license_id).await.unwrap(),
        std::time::Duration::from_secs(90)
    );
    assert_eq!(
        client
            .recommended_heartbeat_interval(license_id)
            .await
            .unwrap(),
        std::time::Duration::from_secs(30)
    );
}

#[tokio::test]
async fn effective_heartbeat_window_falls_back_to_600s_on_a_null_duration() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/policy"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": policy_json(uuid::Uuid::from_u128(3), serde_json::json!(null))
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    assert_eq!(
        client.effective_heartbeat_window(license_id).await.unwrap(),
        std::time::Duration::from_secs(600)
    );
    assert_eq!(
        client
            .recommended_heartbeat_interval(license_id)
            .await
            .unwrap(),
        std::time::Duration::from_secs(200)
    );
}
