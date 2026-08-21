//! Integration tests for license validation.

use tamga::models::validation::ScopeObject;
use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig};
use wiremock::matchers::{body_json, method, path};
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
            "last_check_in_at": null,
            "last_check_out_at": null,
            "machines_count": 0,
            "metadata": {},
            "created": "2026-01-01T00:00:00Z",
            "updated": "2026-01-01T00:00:00Z",
        }
    })
}

fn validate_response(id: uuid::Uuid, code: &str, valid: bool) -> serde_json::Value {
    serde_json::json!({
        "data": license_resource_json(id),
        "meta": {
            "ts": "2026-01-01T00:00:00Z",
            "valid": valid,
            "detail": "test detail",
            "code": code,
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
async fn validate_by_key_happy_path() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/licenses/actions/validate-key"))
        .and(body_json(serde_json::json!({ "key": "lic-abc123" })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validate_response(license_id, "VALID", true)),
        )
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client.validate_by_key("lic-abc123", None).await.unwrap();
    assert!(result.meta.valid);
    assert_eq!(
        result.meta.code,
        tamga::models::validation::ValidationCode::Valid
    );
    assert_eq!(
        result.license.attributes.key,
        Some("lic-abc123".to_string())
    );
}

#[tokio::test]
async fn validate_by_id_with_fully_populated_scope() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let scope = ScopeObject {
        product: Some(uuid::Uuid::nil()),
        policy: Some(uuid::Uuid::nil()),
        user: Some(uuid::Uuid::nil()),
        environment: Some(uuid::Uuid::nil()),
        entitlements: Some(vec!["pro".to_string()]),
        fingerprint: Some("fp-123".to_string()),
        version: Some("1.0.0".to_string()),
        checksum: Some("deadbeef".to_string()),
    };

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validate_response(license_id, "VALID", true)),
        )
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let result = client
        .validate_by_id(license_id, Some(scope), false, None)
        .await
        .unwrap();
    assert!(result.meta.valid);
}

#[tokio::test]
async fn skip_touch_true_round_trips_in_request_body() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/actions/validate"
        )))
        .and(body_json(serde_json::json!({
            "meta": { "skip_touch": true }
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validate_response(license_id, "VALID", true)),
        )
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    // `body_json` matcher above fails the match (→ 404 from wiremock) if
    // `skip_touch` isn't `true` in the outgoing body, so success here IS
    // the round-trip assertion.
    let result = client.validate_by_id(license_id, None, true, None).await;
    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn each_reachable_validation_code_deserializes_from_a_mocked_response() {
    use tamga::models::validation::ValidationCode as VC;

    let reachable = [
        ("VALID", VC::Valid),
        ("SUSPENDED", VC::Suspended),
        ("EXPIRED", VC::Expired),
        ("OVERDUE", VC::Overdue),
        ("PRODUCT_SCOPE_MISMATCH", VC::ProductScopeMismatch),
        ("POLICY_SCOPE_MISMATCH", VC::PolicyScopeMismatch),
        ("USER_SCOPE_MISMATCH", VC::UserScopeMismatch),
        ("ENVIRONMENT_SCOPE_MISMATCH", VC::EnvironmentScopeMismatch),
        // Both became reachable when the server started enforcing
        // `scope.entitlements` and `scope.fingerprint`; the list missed them.
        ("ENTITLEMENTS_MISSING", VC::EntitlementsMissing),
        ("FINGERPRINT_SCOPE_MISMATCH", VC::FingerprintScopeMismatch),
        ("TOO_MANY_MACHINES", VC::TooManyMachines),
        ("TOO_MANY_CORES", VC::TooManyCores),
        ("TOO_MUCH_MEMORY", VC::TooMuchMemory),
        ("TOO_MUCH_DISK", VC::TooMuchDisk),
        ("TOO_MANY_PROCESSES", VC::TooManyProcesses),
        ("TOO_MANY_USES", VC::TooManyUses),
    ];
    assert_eq!(reachable.len(), 16, "must cover all 16 reachable codes");

    for (wire, expected) in reachable {
        let mock_server = MockServer::start().await;
        let license_id = uuid::Uuid::nil();
        Mock::given(method("POST"))
            .and(path("/v1/accounts/acc-123/licenses/actions/validate-key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(validate_response(license_id, wire, false)),
            )
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server);
        let result = client.validate_by_key("lic-abc123", None).await.unwrap();
        assert_eq!(result.meta.code, expected, "wire value {wire}");
    }
}
