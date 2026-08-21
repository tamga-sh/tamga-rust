//! The server rate-limits; the SDK has to cope.
//!
//! Credential-accepting endpoints run on a tight budget (5 requests/second per
//! IP by default), and the calls a licensing client makes on a timer —
//! validate, heartbeat ping, check-in — are exactly the ones inside it. Without
//! backoff, a retry loop turns one throttled request into a sustained burst
//! that keeps the bucket empty, and the client never recovers on its own.
//!
//! Two properties are asserted here: a throttled *idempotent* call retries and
//! succeeds, and a throttled *create* does not retry — repeating an activation
//! could burn a second seat, and only the caller knows if that is acceptable.
//!
//! The heartbeat routes get their own cases because their suffixes are easy to
//! miss: `/actions/ping-heartbeat` and `/actions/reset-heartbeat` do not end
//! with `/actions/ping` (that is the *process* ping route), so a
//! retryable-suffix list written from the shorter name drops exactly the calls
//! most likely to be throttled — the limiter buckets per route pattern, so a
//! whole fleet on one heartbeat route shares one budget.

use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig, TamgaError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(server: &MockServer) -> Client {
    let config = ClientConfig::builder("acc-123", server.uri())
        .auth(AuthTransport::License("lic-abc".to_string()))
        .build();
    Client::new(config).unwrap()
}

fn client_without_retries(server: &MockServer) -> Client {
    let config = ClientConfig::builder("acc-123", server.uri())
        .auth(AuthTransport::License("lic-abc".to_string()))
        .max_retries(0)
        .build();
    Client::new(config).unwrap()
}

fn validation_body() -> serde_json::Value {
    serde_json::json!({
        "data": {
            "type": "licenses",
            "id": "01926b3e-0000-7000-8000-000000000000",
            "attributes": {
                "name": "Acme Corp", "key": "lic-abc123", "status": "ACTIVE",
                "expiry": null, "suspended": false, "protected": false, "uses": 0,
                "scheme": null, "encrypted": false, "strict": false, "floating": false,
                "max_machines": null, "max_uses": null, "max_users": null,
                "last_validated_at": null, "last_check_in_at": null, "last_check_out_at": null,
                "machines_count": 0, "metadata": {},
                "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z"
            }
        },
        "meta": { "ts": "2026-01-01T00:00:00Z", "valid": true, "detail": "is valid", "code": "VALID" }
    })
}

#[tokio::test]
async fn a_throttled_validation_retries_and_then_succeeds() {
    let server = MockServer::start().await;

    // First call is throttled with a one-second Retry-After...
    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/licenses/actions/validate-key"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    // ...the retry succeeds.
    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/licenses/actions/validate-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_body()))
        .expect(1)
        .mount(&server)
        .await;

    let result = client(&server)
        .validate_by_key("lic-abc123", None)
        .await
        .expect("the retry should succeed");

    assert!(result.meta.valid);
}

#[tokio::test]
async fn a_persistently_throttled_call_surfaces_retry_after() {
    // Once the budget is spent the caller must be told *why* and *for how
    // long*. Folding this into a generic API error would leave a client unable
    // to tell "slow down" from "your credential is wrong" — and it would retry
    // the wrong one of those forever.
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/licenses/actions/validate-key"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "42"))
        .mount(&server)
        .await;

    let err = client_without_retries(&server)
        .validate_by_key("lic-abc123", None)
        .await
        .expect_err("should surface the throttling");

    match err {
        TamgaError::RateLimited { retry_after } => {
            assert_eq!(retry_after, Some(42));
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[tokio::test]
async fn retries_can_be_turned_off() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/licenses/actions/validate-key"))
        .respond_with(ResponseTemplate::new(429))
        // Exactly one request: with retries disabled the SDK must not try again.
        .expect(1)
        .mount(&server)
        .await;

    let err = client_without_retries(&server)
        .validate_by_key("lic-abc123", None)
        .await
        .expect_err("should surface the 429 immediately");

    assert!(matches!(err, TamgaError::RateLimited { retry_after: None }));
}

#[tokio::test]
async fn a_throttled_machine_activation_is_not_retried() {
    // Repeating a create is not safe: the first attempt may well have
    // succeeded server-side, and a second activation burns a second seat.
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/accounts/acc-123/machines"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .expect(1)
        .mount(&server)
        .await;

    let err = client(&server)
        .create_machine(
            uuid::Uuid::parse_str("01926b3e-0000-7000-8000-000000000000").unwrap(),
            "fp-1",
            Default::default(),
        )
        .await
        .expect_err("a create must not be auto-retried");

    assert!(matches!(err, TamgaError::RateLimited { .. }));
}

#[tokio::test]
async fn a_throttled_machine_heartbeat_retries_and_then_succeeds() {
    // `/actions/ping-heartbeat` does not end with `/actions/ping` — that is
    // the *process* ping route — so it needs its own entry on the
    // retryable-suffix list or every throttled heartbeat is dropped
    // silently. Dropped heartbeats strand the machine at DEAD — culled
    // outright if its policy sets `require_heartbeat` — and the limiter
    // buckets per route pattern, so a whole fleet throttles itself here.
    // The write is a bare `last_heartbeat_at = NOW()`; repeating it is
    // unconditionally safe.
    let server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let route = format!("/v1/accounts/acc-123/machines/{machine_id}/actions/ping-heartbeat");

    Mock::given(method("POST"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "machines",
                "id": machine_id.to_string(),
                "attributes": {
                    "fingerprint": "fp-1",
                    "cores": null, "memory": null, "disk": null, "ip": null,
                    "hostname": null, "platform": null, "name": null,
                    "heartbeat_status": "ALIVE",
                    "last_heartbeat_at": "2026-01-01T00:00:00Z",
                    "next_heartbeat_at": null, "last_check_out_at": null,
                    "metadata": {},
                    "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let machine = client(&server)
        .ping_heartbeat(machine_id)
        .await
        .expect("a throttled heartbeat must be retried, not dropped");
    assert_eq!(
        machine.attributes.heartbeat_status,
        tamga::models::machine::HeartbeatStatus::Alive
    );
}

#[tokio::test]
async fn a_throttled_heartbeat_reset_retries_and_then_succeeds() {
    // Same reasoning as ping-heartbeat, and it matters more: reset-heartbeat
    // is the only server-side way to unstick a wedged heartbeat job.
    let server = MockServer::start().await;
    let machine_id = uuid::Uuid::nil();
    let route = format!("/v1/accounts/acc-123/machines/{machine_id}/actions/reset-heartbeat");

    Mock::given(method("POST"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "machines",
                "id": machine_id.to_string(),
                "attributes": {
                    "fingerprint": "fp-1",
                    "cores": null, "memory": null, "disk": null, "ip": null,
                    "hostname": null, "platform": null, "name": null,
                    "heartbeat_status": "NOT_STARTED",
                    "last_heartbeat_at": null,
                    "next_heartbeat_at": null, "last_check_out_at": null,
                    "metadata": {},
                    "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let machine = client(&server)
        .reset_heartbeat(machine_id)
        .await
        .expect("a throttled heartbeat reset must be retried, not dropped");
    assert_eq!(
        machine.attributes.heartbeat_status,
        tamga::models::machine::HeartbeatStatus::NotStarted
    );
}

#[tokio::test]
async fn a_throttled_raw_pem_checkout_retries_and_then_succeeds() {
    // The raw-PEM checkout helpers used to send directly, outside the retry
    // wrapper, while the module doc claimed every GET was retried. Both are
    // GETs and both are safe to repeat.
    let server = MockServer::start().await;
    let license_id = uuid::Uuid::nil();
    let route = format!("/v1/accounts/acc-123/licenses/{license_id}/actions/check-out");

    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_string("-----BEGIN LICENSE FILE-----"))
        .expect(1)
        .mount(&server)
        .await;

    let pem = client(&server)
        .check_out_license(license_id, false, None)
        .await
        .expect("a throttled check-out must be retried");
    assert!(pem.starts_with("-----BEGIN LICENSE FILE-----"));
}

#[test]
fn an_absurd_retry_after_is_capped() {
    // A misconfigured proxy — or a hostile one — must not be able to park the
    // caller for a day on a single header. Asserted directly rather than by
    // waiting, for obvious reasons.
    let honoured = Client::retry_delay_for_test(0, Some(5));
    assert_eq!(honoured.as_secs(), 5, "a sane Retry-After is obeyed");

    let clamped = Client::retry_delay_for_test(0, Some(86_400));
    assert!(
        clamped.as_secs() <= 60,
        "a one-day Retry-After must be clamped, got {}s",
        clamped.as_secs()
    );
}

#[test]
fn backoff_grows_when_the_server_says_nothing() {
    // Without a Retry-After the client has to guess, and guessing the same
    // short delay every time is just the original burst again.
    let first = Client::retry_delay_for_test(0, None);
    let third = Client::retry_delay_for_test(2, None);
    assert!(
        third > first,
        "backoff must grow across attempts: {first:?} then {third:?}"
    );
}
