//! Integration tests for entitlements (`Client::list_entitlements`,
//! `get_entitlement`, `has_entitlement`).

use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig};
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn entitlement_json(id: uuid::Uuid, name: &str, code: &str) -> serde_json::Value {
    entitlement_json_with_kind(id, name, code, "flag")
}

fn entitlement_json_with_kind(
    id: uuid::Uuid,
    name: &str,
    code: &str,
    kind: &str,
) -> serde_json::Value {
    serde_json::json!({
        "type": "entitlements",
        "id": id.to_string(),
        "attributes": {
            "name": name,
            "code": code,
            "kind": kind,
            "metadata": {},
            "created": "2026-01-01T00:00:00Z",
            "updated": "2026-01-01T00:00:00Z",
        }
    })
}

fn license_entitlement_json(
    id: uuid::Uuid,
    name: &str,
    code: &str,
    kind: &str,
    inherited: bool,
    max_value: serde_json::Value,
    current_value: i64,
) -> serde_json::Value {
    serde_json::json!({
        "type": "entitlements",
        "id": id.to_string(),
        "attributes": {
            "name": name,
            "code": code,
            "kind": kind,
            "metadata": {},
            "created": "2026-01-01T00:00:00Z",
            "updated": "2026-01-01T00:00:00Z",
            "inherited": inherited,
            "max_value": max_value,
            "current_value": current_value,
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

#[tokio::test]
async fn list_license_entitlements_keeps_the_inherited_flag() {
    // The licence-scoped list is a union of direct attachments and
    // policy-inherited rows, and only that route carries `inherited`. The
    // flag decides what a caller may do with the row, so it must survive
    // parsing.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let direct_id = uuid::Uuid::nil();
    let inherited_id = uuid::Uuid::max();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements"
        )))
        .and(query_param("limit", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {
                    "type": "entitlements",
                    "id": direct_id.to_string(),
                    "attributes": {
                        "name": "Pro Features", "code": "pro", "kind": "flag", "metadata": {},
                        "created": "2026-01-01T00:00:00Z",
                        "updated": "2026-01-01T00:00:00Z",
                        "inherited": false,
                    }
                },
                {
                    "type": "entitlements",
                    "id": inherited_id.to_string(),
                    "attributes": {
                        "name": "Bundled Support", "code": "support", "kind": "flag", "metadata": {},
                        "created": "2026-01-01T00:00:00Z",
                        "updated": "2026-01-01T00:00:00Z",
                        "inherited": true,
                    }
                },
            ]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let rows = client
        .list_license_entitlements(license_id, Some(100))
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].attributes.code, "pro");
    assert!(!rows[0].attributes.inherited);
    assert_eq!(rows[1].attributes.code, "support");
    assert!(
        rows[1].attributes.inherited,
        "an inherited row cannot be detached and 404s on the item route — \
         dropping the flag hides both"
    );
}

#[tokio::test]
async fn list_license_entitlements_tolerates_a_response_without_the_flag() {
    // Account-, policy- and release-scoped responses carry no `inherited`
    // attribute at all; absence must mean "not inherited", not a parse
    // failure.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [entitlement_json(entitlement_id, "Pro Features", "pro")]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let rows = client
        .list_license_entitlements(license_id, None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].attributes.inherited);
}

#[tokio::test]
async fn has_entitlement_asks_for_the_servers_maximum_page_size() {
    // This route cannot be paginated (`page[after]` is inert), so the single
    // request has to ask for the ceiling or it silently truncates at the
    // server's default of 25.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements"
        )))
        .and(query_param(
            "limit",
            tamga::client::MAX_ENTITLEMENTS_PAGE_SIZE.to_string(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [entitlement_json(entitlement_id, "Pro Features", "pro")]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    assert!(client
        .has_entitlement(license_id, "pro", None)
        .await
        .unwrap());
}

#[tokio::test]
async fn both_entitlement_listings_surface_a_server_error_as_a_typed_error() {
    // `list_entitlements` and `list_license_entitlements` are two methods over
    // the *same* route, differing only in the row type they parse into. Both
    // parse `{ "data": [...] }` on success, so both have to classify a non-2xx
    // body as an error document before attempting that parse — otherwise a 403
    // reaches the caller as an opaque deserialization failure instead of
    // `TamgaError::Forbidden`, and the reason the listing was refused is lost.
    // Testing them together is what keeps the two from diverging.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();

    // Not retryable (only 429 is), so each call asks exactly once.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements"
        )))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "403",
                "code": "FORBIDDEN",
                "title": "Forbidden",
                "detail": "this license key may not read entitlements",
                "source": null,
            }]
        })))
        .expect(2)
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);

    let err = client
        .list_entitlements(license_id, Some(100), None)
        .await
        .expect_err("a 403 body is not a listing");
    assert!(matches!(err, tamga::TamgaError::Forbidden(_)));
    assert_eq!(err.code(), Some("FORBIDDEN"));

    let err = client
        .list_license_entitlements(license_id, Some(100))
        .await
        .expect_err("a 403 body is not a listing");
    assert!(matches!(err, tamga::TamgaError::Forbidden(_)));
    assert_eq!(err.code(), Some("FORBIDDEN"));
}

// ── Entitlement metering: `kind`, `max_value`, `current_value` ────────────

#[tokio::test]
async fn plain_entitlement_listing_carries_kind() {
    // Account-/policy-/release-scoped shape: `kind` only, no
    // `max_value`/`current_value`/`inherited` — those are license-scoped.
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [entitlement_json_with_kind(entitlement_id, "Requests", "requests", "meter")]
        })))
        .mount(&mock_server)
        .await;

    let client = test_client(&mock_server);
    let entitlements = client
        .list_entitlements(license_id, Some(10), None)
        .await
        .unwrap();
    assert_eq!(entitlements.len(), 1);
    assert_eq!(
        entitlements[0].attributes.kind,
        tamga::models::entitlement::EntitlementKind::Meter
    );
}

#[tokio::test]
async fn get_entitlement_carries_kind() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements/{entitlement_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": entitlement_json_with_kind(entitlement_id, "Pro Features", "pro", "flag")
        })))
        .mount(&mock_server)
        .await;

    let entitlement = test_client(&mock_server)
        .get_entitlement(license_id, entitlement_id)
        .await
        .unwrap();
    assert_eq!(
        entitlement.attributes.kind,
        tamga::models::entitlement::EntitlementKind::Flag
    );
}

#[tokio::test]
async fn license_scoped_listing_carries_max_value_and_current_value() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [license_entitlement_json(
                entitlement_id,
                "Requests",
                "requests",
                "meter",
                false,
                serde_json::json!(1000),
                650,
            )]
        })))
        .mount(&mock_server)
        .await;

    let rows = test_client(&mock_server)
        .list_license_entitlements(license_id, None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].attributes.kind,
        tamga::models::entitlement::EntitlementKind::Meter
    );
    assert_eq!(rows[0].attributes.max_value, Some(1000));
    assert_eq!(rows[0].attributes.current_value, 650);
}

#[tokio::test]
async fn license_scoped_listing_null_max_value_means_unlimited() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [license_entitlement_json(
                entitlement_id,
                "Requests",
                "requests",
                "meter",
                false,
                serde_json::Value::Null,
                0,
            )]
        })))
        .mount(&mock_server)
        .await;

    let rows = test_client(&mock_server)
        .list_license_entitlements(license_id, None)
        .await
        .unwrap();
    assert_eq!(rows[0].attributes.max_value, None);
    assert_eq!(rows[0].attributes.current_value, 0);
}

// ── Entitlement metering: increment / decrement / reset ───────────────────

#[tokio::test]
async fn increment_entitlement_usage_returns_the_updated_license_entitlement() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements/{entitlement_id}/actions/increment"
        )))
        .and(body_json(serde_json::json!({ "increment": 3 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": license_entitlement_json(
                entitlement_id, "Requests", "requests", "meter", false,
                serde_json::json!(1000), 8,
            )
        })))
        .mount(&mock_server)
        .await;

    let updated = test_client(&mock_server)
        .increment_entitlement_usage(license_id, entitlement_id, Some(3))
        .await
        .unwrap();
    assert_eq!(updated.attributes.current_value, 8);
    assert_eq!(updated.attributes.max_value, Some(1000));
}

#[tokio::test]
async fn decrement_entitlement_usage_returns_the_updated_license_entitlement() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements/{entitlement_id}/actions/decrement"
        )))
        .and(body_json(serde_json::json!({ "decrement": 2 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": license_entitlement_json(
                entitlement_id, "Requests", "requests", "meter", false,
                serde_json::json!(1000), 3,
            )
        })))
        .mount(&mock_server)
        .await;

    let updated = test_client(&mock_server)
        .decrement_entitlement_usage(license_id, entitlement_id, Some(2))
        .await
        .unwrap();
    assert_eq!(updated.attributes.current_value, 3);
}

#[tokio::test]
async fn reset_entitlement_usage_sends_no_body_and_returns_zero() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements/{entitlement_id}/actions/reset"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": license_entitlement_json(
                entitlement_id, "Requests", "requests", "meter", false,
                serde_json::json!(1000), 0,
            )
        })))
        .mount(&mock_server)
        .await;

    let updated = test_client(&mock_server)
        .reset_entitlement_usage(license_id, entitlement_id)
        .await
        .unwrap();
    assert_eq!(updated.attributes.current_value, 0);
}

#[tokio::test]
async fn increment_entitlement_usage_surfaces_meter_limit_exceeded() {
    let mock_server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let entitlement_id = uuid::Uuid::nil();

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/accounts/acc-123/licenses/{license_id}/entitlements/{entitlement_id}/actions/increment"
        )))
        .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "422",
                "code": "METER_LIMIT_EXCEEDED",
                "title": "Unprocessable Entity",
                "detail": "This entitlement has reached its maximum uses",
                "source": null,
            }]
        })))
        .mount(&mock_server)
        .await;

    let err = test_client(&mock_server)
        .increment_entitlement_usage(license_id, entitlement_id, None)
        .await
        .expect_err("the cap must be enforced");
    assert!(matches!(err, tamga::TamgaError::MeterLimitExceeded(_)));
    assert_eq!(err.code(), Some("METER_LIMIT_EXCEEDED"));
}
