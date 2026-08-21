//! Integration tests for the auto-update check and the liveness probe — the
//! two routes that break this crate's own conventions.

use tamga::client::{UpgradeCheck, UpgradeQuery};
use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_client(mock_server: &MockServer) -> Client {
    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    Client::new(config).unwrap()
}

fn upgrade_query(product_id: uuid::Uuid) -> UpgradeQuery {
    UpgradeQuery {
        product_id,
        platform: "linux".to_string(),
        filetype: "tar.gz".to_string(),
        version: "1.0.0".to_string(),
        channel: None,
        constraint: None,
    }
}

#[tokio::test]
async fn an_available_upgrade_decodes_the_camel_case_release_resource() {
    let mock_server = MockServer::start().await;
    let product_id = uuid::Uuid::from_u128(1);
    let release_id = uuid::Uuid::from_u128(2);

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/releases/actions/upgrade"))
        .and(query_param("product", product_id.to_string()))
        .and(query_param("platform", "linux"))
        .and(query_param("filetype", "tar.gz"))
        .and(query_param("version", "1.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "releases",
                "id": release_id.to_string(),
                "attributes": {
                    "productId": product_id.to_string(),
                    "name": "Acme 2.0",
                    "version": "2.0.0",
                    "channel": "stable",
                    "status": "PUBLISHED",
                    "metadata": {},
                    "created": "2026-01-01T00:00:00Z",
                    "updated": "2026-01-01T00:00:00Z",
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let outcome = test_client(&mock_server)
        .check_for_upgrade(upgrade_query(product_id))
        .await
        .unwrap();
    match outcome {
        UpgradeCheck::Available(release) => {
            assert_eq!(release.id, release_id);
            assert_eq!(release.attributes.version, "2.0.0");
            assert_eq!(release.attributes.product_id, product_id);
            assert_eq!(release.attributes.tag, None);
        }
        other => panic!("expected an available release, got {other:?}"),
    }
}

#[tokio::test]
async fn a_204_is_reported_as_no_update_offered_not_as_up_to_date() {
    // The server answers 204 both when nothing newer exists and when
    // something newer exists that this licence has expired out of. Nothing on
    // the wire separates them, so neither does this type.
    let mock_server = MockServer::start().await;
    let product_id = uuid::Uuid::from_u128(1);

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/releases/actions/upgrade"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let outcome = test_client(&mock_server)
        .check_for_upgrade(upgrade_query(product_id))
        .await
        .unwrap();
    assert!(matches!(outcome, UpgradeCheck::NoUpdateOffered));
}

#[tokio::test]
async fn optional_channel_and_constraint_are_sent_only_when_set() {
    let mock_server = MockServer::start().await;
    let product_id = uuid::Uuid::from_u128(1);

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/releases/actions/upgrade"))
        .and(query_param("channel", "beta"))
        .and(query_param("constraint", "^2"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let outcome = test_client(&mock_server)
        .check_for_upgrade(UpgradeQuery {
            channel: Some("beta".to_string()),
            constraint: Some("^2".to_string()),
            ..upgrade_query(product_id)
        })
        .await
        .unwrap();
    assert!(matches!(outcome, UpgradeCheck::NoUpdateOffered));
}

#[tokio::test]
async fn a_suspended_licence_is_a_403_not_a_no_update_answer() {
    // The third outcome, and it is deliberately not folded into 204: a
    // suspension is the licence's own state, not information about a release.
    let mock_server = MockServer::start().await;
    let product_id = uuid::Uuid::from_u128(1);

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/releases/actions/upgrade"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": [{
                "id": "err-1", "status": "403", "code": "FORBIDDEN",
                "title": "Forbidden",
                "detail": "The license is suspended and does not have access to this release",
            }]
        })))
        .mount(&mock_server)
        .await;

    let err = test_client(&mock_server)
        .check_for_upgrade(upgrade_query(product_id))
        .await
        .unwrap_err();
    assert!(matches!(err, TamgaError::Forbidden(_)));
}

#[tokio::test]
async fn an_unknown_product_is_a_404_not_a_no_update_answer() {
    let mock_server = MockServer::start().await;
    let product_id = uuid::Uuid::from_u128(1);

    Mock::given(method("GET"))
        .and(path("/v1/accounts/acc-123/releases/actions/upgrade"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "errors": [{
                "id": "err-1", "status": "404", "code": "NOT_FOUND",
                "title": "Not Found", "detail": "product not found",
            }]
        })))
        .mount(&mock_server)
        .await;

    let err = test_client(&mock_server)
        .check_for_upgrade(upgrade_query(product_id))
        .await
        .unwrap_err();
    assert!(matches!(err, TamgaError::NotFound(_)));
}

// ── Health ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_is_not_account_scoped_and_decodes_a_flat_body() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "ok", "version": "1.8.3", "uptime_secs": 4242,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let health = test_client(&mock_server).health().await.unwrap();
    assert_eq!(health.status, "ok");
    assert_eq!(health.version, "1.8.3");
    assert_eq!(health.uptime_secs, 4242);
}

#[tokio::test]
async fn health_sends_no_credential_at_all() {
    // Load-bearing. The server resolves the request's credential *before*
    // consulting its public-route list, and in singleplayer mode a route with
    // no {account_id} segment still resolves against the configured account —
    // so a licence key the policy refuses would 401 the one call whose job is
    // to isolate that failure from a host-header misconfiguration.
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "ok", "version": "1.8.3", "uptime_secs": 1,
        })))
        .mount(&mock_server)
        .await;

    test_client(&mock_server).health().await.unwrap();

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "health must not send an Authorization header"
    );
    assert!(
        requests[0].headers.get("tamga-version").is_some(),
        "the version header is still sent — it has no auth side effect"
    );
}

#[tokio::test]
async fn health_sends_no_query_token_either() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "ok", "version": "1.8.3", "uptime_secs": 1,
        })))
        .mount(&mock_server)
        .await;

    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::Query("tok-abc".to_string()))
        .build();
    Client::new(config).unwrap().health().await.unwrap();

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests[0].url.query(), None);
}

#[tokio::test]
async fn health_surfaces_a_server_failure_rather_than_reporting_ok() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health"))
        .respond_with(ResponseTemplate::new(500).set_body_string("<html>bad gateway</html>"))
        .mount(&mock_server)
        .await;

    let err = test_client(&mock_server).health().await.unwrap_err();
    // A non-JSON:API body must synthesize UNKNOWN, never panic.
    assert_eq!(err.code(), Some("UNKNOWN"));
}

#[tokio::test]
async fn origin_url_drops_the_account_segment_base_url_appends() {
    let config = ClientConfig::builder("acc-123", "api.tamga.sh")
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    assert_eq!(config.origin_url(), "https://api.tamga.sh");
    assert_eq!(
        config.base_url(),
        "https://api.tamga.sh/v1/accounts/acc-123"
    );

    let local = ClientConfig::builder("acc-123", "http://127.0.0.1:8080/")
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    assert_eq!(local.origin_url(), "http://127.0.0.1:8080");
}
