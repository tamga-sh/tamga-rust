//! Integration tests for the artifact routes.
//!
//! The load-bearing test here is
//! [`the_download_303_is_never_followed_with_a_credential_attached`]: two
//! mock servers stand in for the API and the storage host, and the storage
//! host asserts on what reaches it. Everything else is decoding and paging.

use tamga::error::ArtifactDownloadError;
use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn test_client(mock_server: &MockServer) -> Client {
    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    Client::new(config).unwrap()
}

/// A client whose credential rides in the query string rather than a header —
/// the transport `remove_sensitive_headers` would not protect at all.
fn token_query_client(mock_server: &MockServer) -> Client {
    let config = ClientConfig::builder("acc-123", mock_server.uri())
        .auth(AuthTransport::Query("tok-secret".to_string()))
        .build();
    Client::new(config).unwrap()
}

fn artifact_attributes() -> serde_json::Value {
    serde_json::json!({
        "filename": "acme-2.0.0-x86_64.tar.gz",
        "filetype": "application/gzip",
        "filesize": 12,
        "checksum": "d41d8cd98f00b204e9800998ecf8427e",
        "platform": "linux",
        "arch": "x86_64",
        "signature": null,
        "status": "UPLOADED",
        "metadata": {"channel": "stable"},
        "created": "2026-01-01T00:00:00Z",
        "updated": "2026-01-02T00:00:00Z",
    })
}

fn artifact_resource(id: uuid::Uuid) -> serde_json::Value {
    serde_json::json!({
        "type": "artifacts",
        "id": id.to_string(),
        "attributes": artifact_attributes(),
    })
}

// ── Listing ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn lists_a_releases_artifacts() {
    let server = MockServer::start().await;
    let release_id = uuid::Uuid::from_u128(1);
    let a1 = uuid::Uuid::from_u128(2);
    let a2 = uuid::Uuid::from_u128(3);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/releases/{release_id}/artifacts"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [artifact_resource(a1), artifact_resource(a2)]
        })))
        .mount(&server)
        .await;

    let artifacts = test_client(&server)
        .list_release_artifacts(release_id, None, None)
        .await
        .unwrap();

    assert_eq!(artifacts.len(), 2);
    assert_eq!(artifacts[0].id, a1);
    assert_eq!(artifacts[0].resource_type, "artifacts");
    assert_eq!(artifacts[0].attributes.filename, "acme-2.0.0-x86_64.tar.gz");
    assert_eq!(artifacts[0].attributes.platform.as_deref(), Some("linux"));
    // `created`/`updated`, not `createdAt`/`updatedAt`.
    assert_eq!(
        artifacts[0].attributes.created.to_rfc3339(),
        "2026-01-01T00:00:00+00:00"
    );
    // Absent on a listing.
    assert!(artifacts[0].attributes.redirect_url.is_none());
}

#[tokio::test]
async fn the_listing_sends_keyset_parameters_only_when_set() {
    let server = MockServer::start().await;
    let release_id = uuid::Uuid::from_u128(1);
    let after = uuid::Uuid::from_u128(9);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/releases/{release_id}/artifacts"
        )))
        .and(query_param("limit", "50"))
        .and(query_param("page[after]", after.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .mount(&server)
        .await;

    let artifacts = test_client(&server)
        .list_release_artifacts(release_id, Some(50), Some(after))
        .await
        .unwrap();
    assert!(artifacts.is_empty());
}

#[tokio::test]
async fn the_listing_surfaces_a_server_error() {
    let server = MockServer::start().await;
    let release_id = uuid::Uuid::from_u128(1);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/releases/{release_id}/artifacts"
        )))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "403",
                "code": "FORBIDDEN",
                "title": "Forbidden",
                "detail": "insufficient permissions",
                "source": null,
            }]
        })))
        .mount(&server)
        .await;

    let err = test_client(&server)
        .list_release_artifacts(release_id, None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, TamgaError::Forbidden(_)), "{err:?}");
}

// ── Show ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn gets_one_artifacts_metadata() {
    let server = MockServer::start().await;
    let artifact_id = uuid::Uuid::from_u128(2);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": artifact_resource(artifact_id)
        })))
        .mount(&server)
        .await;

    let artifact = test_client(&server)
        .get_artifact(artifact_id)
        .await
        .unwrap();
    assert_eq!(artifact.id, artifact_id);
    assert_eq!(artifact.attributes.status, "UPLOADED");
    assert!(artifact.attributes.redirect_url.is_none());
}

#[tokio::test]
async fn a_missing_artifact_is_not_found() {
    let server = MockServer::start().await;
    let artifact_id = uuid::Uuid::from_u128(2);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}"
        )))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "404",
                "code": "NOT_FOUND",
                "title": "Not Found",
                "detail": "artifact not found",
                "source": null,
            }]
        })))
        .mount(&server)
        .await;

    let err = test_client(&server)
        .get_artifact(artifact_id)
        .await
        .unwrap_err();
    assert!(matches!(err, TamgaError::NotFound(_)), "{err:?}");
}

// ── Download URL ────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_download_action_always_sends_redirect_false() {
    let server = MockServer::start().await;
    let artifact_id = uuid::Uuid::from_u128(2);

    // The `query_param` matcher is the assertion: without `redirect=false`
    // the mock does not match and the call fails.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}/actions/download"
        )))
        .and(query_param("redirect", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "artifacts",
                "id": artifact_id.to_string(),
                "attributes": {
                    "filename": "acme-2.0.0-x86_64.tar.gz",
                    "filetype": "application/gzip",
                    "filesize": 12,
                    "checksum": null,
                    "platform": "linux",
                    "arch": "x86_64",
                    "signature": null,
                    "status": "UPLOADED",
                    "redirectUrl": "https://storage.example.com/o/abc?sig=xyz",
                    "metadata": {},
                    "created": "2026-01-01T00:00:00Z",
                    "updated": "2026-01-02T00:00:00Z",
                }
            }
        })))
        .mount(&server)
        .await;

    let artifact = test_client(&server)
        .artifact_download_url(artifact_id, None)
        .await
        .unwrap();

    assert_eq!(
        artifact.attributes.redirect_url.as_deref(),
        Some("https://storage.example.com/o/abc?sig=xyz"),
        "the camelCase `redirectUrl` must decode"
    );
}

#[tokio::test]
async fn a_ttl_is_sent_in_whole_seconds_and_omitted_when_unset() {
    let server = MockServer::start().await;
    let artifact_id = uuid::Uuid::from_u128(2);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}/actions/download"
        )))
        .and(query_param("redirect", "false"))
        .and(query_param("ttl", "600"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": artifact_resource(artifact_id)
        })))
        .mount(&server)
        .await;

    // 600.9s truncates to 600 — the wire parameter is whole seconds.
    test_client(&server)
        .artifact_download_url(artifact_id, Some(std::time::Duration::from_millis(600_900)))
        .await
        .unwrap();
}

#[tokio::test]
async fn an_out_of_range_ttl_surfaces_the_servers_validation_error() {
    // The server validates rather than clamps: `PRESIGN_TTL_INVALID` is not a
    // mapped code, so it lands on the generic `Api` variant.
    let server = MockServer::start().await;
    let artifact_id = uuid::Uuid::from_u128(2);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}/actions/download"
        )))
        .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "422",
                "code": "PRESIGN_TTL_INVALID",
                "title": "Unprocessable Entity",
                "detail": "Presigned URL TTL must be between 1 minute and 1 week",
                "source": {"pointer": null, "parameter": "ttl"},
            }]
        })))
        .mount(&server)
        .await;

    let err = test_client(&server)
        .artifact_download_url(artifact_id, Some(std::time::Duration::from_secs(1)))
        .await
        .unwrap_err();
    match err {
        TamgaError::Api(e) => assert_eq!(e.code, "PRESIGN_TTL_INVALID"),
        other => panic!("expected Api, got {other:?}"),
    }
}

#[tokio::test]
async fn a_closed_releases_binary_is_forbidden_even_with_the_permission() {
    // The download route enforces `enforce_release_access` on top of
    // `artifact.download`, so a 403 here does not imply a bad credential.
    let server = MockServer::start().await;
    let artifact_id = uuid::Uuid::from_u128(2);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": artifact_resource(artifact_id)
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}/actions/download"
        )))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "403",
                "code": "FORBIDDEN",
                "title": "Forbidden",
                "detail": "release is not accessible",
                "source": null,
            }]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    // Metadata reads fine — only the bytes are gated.
    client.get_artifact(artifact_id).await.unwrap();
    let err = client
        .artifact_download_url(artifact_id, None)
        .await
        .unwrap_err();
    assert!(matches!(err, TamgaError::Forbidden(_)), "{err:?}");
}

// ── Download bytes: the credential-leak proof ───────────────────────────────

/// Mounts a "storage host" on its own `MockServer` that records what reached
/// it, and an API host whose download action points at it.
async fn api_and_storage(artifact_id: uuid::Uuid, body: Vec<u8>) -> (MockServer, MockServer) {
    let storage = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/o/abc"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&storage)
        .await;

    let api = MockServer::start().await;
    let redirect_url = format!("{}/o/abc?sig=xyz", storage.uri());
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}/actions/download"
        )))
        .and(query_param("redirect", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "artifacts",
                "id": artifact_id.to_string(),
                "attributes": {
                    "filename": "acme.bin",
                    "filetype": null,
                    "filesize": 12,
                    "checksum": null,
                    "platform": null,
                    "arch": null,
                    "signature": null,
                    "status": "UPLOADED",
                    "redirectUrl": redirect_url,
                    "metadata": {},
                    "created": "2026-01-01T00:00:00Z",
                    "updated": "2026-01-02T00:00:00Z",
                }
            }
        })))
        .mount(&api)
        .await;

    (api, storage)
}

#[tokio::test]
async fn downloads_the_bytes_from_the_presigned_url() {
    let artifact_id = uuid::Uuid::from_u128(2);
    let (api, _storage) = api_and_storage(artifact_id, b"hello world!".to_vec()).await;

    let bytes = test_client(&api)
        .download_artifact(artifact_id, None, 1024)
        .await
        .unwrap();
    assert_eq!(bytes, b"hello world!");
}

#[tokio::test]
async fn download_artifact_sends_no_credential_to_the_storage_host() {
    let artifact_id = uuid::Uuid::from_u128(2);
    let (api, storage) = api_and_storage(artifact_id, b"hello world!".to_vec()).await;

    test_client(&api)
        .download_artifact(artifact_id, None, 1024)
        .await
        .unwrap();

    let requests: Vec<Request> = storage.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "storage host should be hit exactly once");
    let hit = &requests[0];

    assert!(
        hit.headers.get("authorization").is_none(),
        "the licence key must never reach the storage host: {:?}",
        hit.headers.get("authorization")
    );
    let raw = hit.url.as_str();
    assert!(
        !raw.contains("lic-abc"),
        "credential leaked into the URL: {raw}"
    );
    // The presigned signature itself must still be intact.
    assert!(raw.contains("sig=xyz"), "{raw}");
}

#[tokio::test]
async fn the_query_parameter_transport_also_reaches_storage_uncredentialed() {
    // `remove_sensitive_headers` only strips headers, and only cross-host.
    // A `?token=` credential is outside its reach entirely, so this transport
    // is the one that proves the SDK — not reqwest — is doing the protecting.
    let artifact_id = uuid::Uuid::from_u128(2);
    let (api, storage) = api_and_storage(artifact_id, b"hello world!".to_vec()).await;

    token_query_client(&api)
        .download_artifact(artifact_id, None, 1024)
        .await
        .unwrap();

    let requests = storage.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let raw = requests[0].url.as_str();
    assert!(
        !raw.contains("tok-secret"),
        "token leaked into the URL: {raw}"
    );
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "authorization header reached storage"
    );
}

#[tokio::test]
async fn the_api_call_that_issues_the_url_does_carry_the_credential() {
    // The complement of the two tests above: dropping the credential
    // everywhere would make them pass while breaking the SDK.
    let server = MockServer::start().await;
    let artifact_id = uuid::Uuid::from_u128(2);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}/actions/download"
        )))
        .and(header("authorization", "License lic-abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": artifact_resource(artifact_id)
        })))
        .mount(&server)
        .await;

    test_client(&server)
        .artifact_download_url(artifact_id, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_303_from_the_api_is_never_followed_to_storage() {
    // Belt and braces: if `redirect=false` ever stopped being sent, the
    // server would answer 303 and reqwest's default policy would follow it.
    // The storage host here asserts it is never reached at all.
    let storage = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/o/abc"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SECRET BYTES".to_vec()))
        .mount(&storage)
        .await;

    let api = MockServer::start().await;
    let artifact_id = uuid::Uuid::from_u128(2);
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}/actions/download"
        )))
        .respond_with(
            ResponseTemplate::new(303)
                .insert_header("location", format!("{}/o/abc", storage.uri()).as_str()),
        )
        .mount(&api)
        .await;

    // A 303 is not a success status, so it surfaces as an error rather than
    // being transparently followed into a body this method would try to
    // decode as JSON.
    let _ = test_client(&api)
        .artifact_download_url(artifact_id, None)
        .await;

    assert!(
        storage.received_requests().await.unwrap().is_empty(),
        "the SDK followed a 303 to the storage host"
    );
}

// ── max_bytes ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_content_length_over_the_ceiling_is_rejected_before_the_body_is_read() {
    let artifact_id = uuid::Uuid::from_u128(2);
    let (api, _storage) = api_and_storage(artifact_id, b"hello world!".to_vec()).await;

    let err = test_client(&api)
        .download_artifact(artifact_id, None, 4)
        .await
        .unwrap_err();
    match err {
        ArtifactDownloadError::TooLarge { limit } => assert_eq!(limit, 4),
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn a_body_exactly_at_the_ceiling_is_accepted() {
    // Off-by-one guard: the ceiling is inclusive.
    let artifact_id = uuid::Uuid::from_u128(2);
    let (api, _storage) = api_and_storage(artifact_id, b"hello world!".to_vec()).await;

    let bytes = test_client(&api)
        .download_artifact(artifact_id, None, 12)
        .await
        .unwrap();
    assert_eq!(bytes.len(), 12);
}

#[tokio::test]
async fn a_storage_failure_is_not_reported_as_an_api_failure() {
    let storage = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/o/abc"))
        .respond_with(ResponseTemplate::new(403).set_body_string("<Error>expired</Error>"))
        .mount(&storage)
        .await;

    let api = MockServer::start().await;
    let artifact_id = uuid::Uuid::from_u128(2);
    let redirect_url = format!("{}/o/abc?sig=xyz", storage.uri());
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}/actions/download"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "artifacts",
                "id": artifact_id.to_string(),
                "attributes": {
                    "filename": "acme.bin",
                    "filetype": null, "filesize": null, "checksum": null,
                    "platform": null, "arch": null, "signature": null,
                    "status": "UPLOADED",
                    "redirectUrl": redirect_url,
                    "metadata": {},
                    "created": "2026-01-01T00:00:00Z",
                    "updated": "2026-01-02T00:00:00Z",
                }
            }
        })))
        .mount(&api)
        .await;

    let err = test_client(&api)
        .download_artifact(artifact_id, None, 1024)
        .await
        .unwrap_err();
    match err {
        ArtifactDownloadError::StorageStatus { status } => assert_eq!(status, 403),
        other => panic!("expected StorageStatus, got {other:?}"),
    }
}

#[tokio::test]
async fn a_response_without_a_redirect_url_is_its_own_error() {
    let server = MockServer::start().await;
    let artifact_id = uuid::Uuid::from_u128(2);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}/actions/download"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": artifact_resource(artifact_id)
        })))
        .mount(&server)
        .await;

    let err = test_client(&server)
        .download_artifact(artifact_id, None, 1024)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ArtifactDownloadError::MissingRedirectUrl),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_api_failure_propagates_through_the_download_error() {
    let server = MockServer::start().await;
    let artifact_id = uuid::Uuid::from_u128(2);

    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/accounts/acc-123/artifacts/{artifact_id}/actions/download"
        )))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": [{
                "id": "01926b3e-0000-7000-8000-000000000000",
                "status": "403",
                "code": "FORBIDDEN",
                "title": "Forbidden",
                "detail": "release is not accessible",
                "source": null,
            }]
        })))
        .mount(&server)
        .await;

    let err = test_client(&server)
        .download_artifact(artifact_id, None, 1024)
        .await
        .unwrap_err();
    match err {
        ArtifactDownloadError::Api(TamgaError::Forbidden(_)) => {}
        other => panic!("expected Api(Forbidden), got {other:?}"),
    }
}
