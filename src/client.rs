//! `Client` and `ClientConfig` — the single home for every endpoint method.
//!
//! An SDK is a thin client, not a multi-slice server, so every endpoint
//! method lives here (grouped by HTTP verb/endpoint) plus the
//! request/response models in [`crate::models`].
//!
//! What lives here:
//!
//! - [`ClientConfig`]: `account_id` (required), `host` (required),
//!   `api_version` (default [`crate::transport::DEFAULT_API_VERSION`]),
//!   request `timeout`, auth transport, and `max_retries`, built via
//!   [`ClientConfigBuilder`].
//! - Base URL construction: `https://<host>/v1/accounts/{account_id}/...` —
//!   `account_id` is always required, including singleplayer mode.
//! - License validation: [`Client::validate_by_key`],
//!   [`Client::validate_by_id`], [`Client::quick_validate`].
//! - License check-in: [`Client::check_in`].
//! - License checkout: [`Client::check_out_license`],
//!   [`Client::check_out_license_json`].
//! - Machine checkout: [`Client::check_out_machine`],
//!   [`Client::check_out_machine_json`].
//! - Machine management: [`Client::create_machine`],
//!   [`Client::ping_heartbeat`], [`Client::reset_heartbeat`],
//!   [`Client::delete_machine`], plus [`Client::activate_machine`], which
//!   composes create + validate + optional auto-delete-on-overage.
//! - Machine offline proof: [`Client::generate_offline_proof`].
//! - Components & processes: [`Client::create_component`],
//!   [`Client::list_components`], [`Client::create_process`],
//!   [`Client::ping_process`].
//! - Entitlements: [`Client::list_entitlements`],
//!   [`Client::list_license_entitlements`], [`Client::get_entitlement`],
//!   [`Client::has_entitlement`].
//!
//! Every method sends the configured [`crate::transport::AuthTransport`]'s
//! credentials. Auth **is** enforced server-side on every endpoint here: a
//! missing or unrecognized credential is `401`, a valid-but-insufficient one
//! `403`. Licence-key auth additionally requires the licence's policy to set
//! `authentication_strategy` to `LICENSE` or `MIXED` — the column defaults to
//! `'TOKEN'`, under which every request with a licence key is refused with
//! `401 LICENSE_NOT_ALLOWED`. See [`crate::error::LicenseAuthCode`].
//!
//! **Rate limiting.** Every request this client sends goes through
//! `send_with_retry`, which retries a `429` up to
//! [`ClientConfig::max_retries`] times using the server's `Retry-After`
//! (capped at 60s) or jittered exponential backoff. Only safe requests
//! qualify: every `GET`, plus `POST` on the seven action suffixes
//! `/actions/validate`, `/actions/validate-key`, `/actions/check-in`,
//! `/actions/check-out`, `/actions/ping`, `/actions/ping-heartbeat` and
//! `/actions/reset-heartbeat`. Creates are excluded on purpose. The rate
//! limiter buckets per `(caller, route pattern)` and, with proxy headers
//! untrusted, a whole fleet can share one bucket per route — so a throttled
//! heartbeat is a routine event, not an edge case.

/// Configuration for a [`Client`].
///
/// Build via [`ClientConfig::builder`]. `account_id` and `host` are always
/// required — including singleplayer mode, per the Tamga API protocol
/// specification.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Tamga account ID, always required (even in singleplayer mode).
    pub account_id: String,
    /// API host, e.g. `"api.tamga.sh"` — scheme and trailing slash, if
    /// present, are stripped by the builder.
    pub host: String,
    /// `Tamga-Version` header value, pinned per SDK major version. Defaults
    /// to [`crate::transport::DEFAULT_API_VERSION`].
    pub api_version: String,
    /// Request timeout for the underlying HTTP client.
    pub timeout: std::time::Duration,
    /// Auth transport used to authenticate every request.
    pub auth: crate::transport::AuthTransport,
    /// How many times to retry a rate-limited (`429`) request before giving
    /// up. Zero disables automatic retries entirely.
    ///
    /// Only requests that are safe to repeat are retried: every `GET`, plus
    /// `POST` on the `validate`, `validate-key`, `check-in`, `check-out`,
    /// `ping`, `ping-heartbeat` and `reset-heartbeat` actions. Creates are
    /// never retried — see the module doc comment.
    pub max_retries: u32,
}

/// Default request timeout used unless overridden via
/// [`ClientConfigBuilder::timeout`].
///
/// Deliberately longer than the server's own 30s request timeout. Matching
/// it exactly makes the two race: a genuinely slow request usually surfaces
/// as a local `reqwest` timeout with nothing to correlate against, instead
/// of the server's `504`, whose body is empty but which carries the
/// `X-Request-Id` a support ticket actually needs. 45s lets the server's
/// deadline win.
const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// Default number of retries for a rate-limited request.
///
/// Three is enough to ride out a short burst without turning a sustained 429
/// into a request that hangs for minutes. The server's auth-endpoint budget is
/// tight (5 req/s by default), and a heartbeat timer plus a retry loop reaches
/// it easily — which is exactly the case this exists for.
const DEFAULT_MAX_RETRIES: u32 = 3;

/// The server's own maximum `limit` on the nested keyset list routes
/// (`GET /licenses/{id}/entitlements`, `GET /machines/{id}/components`).
/// Larger values are clamped to it server-side.
pub const MAX_ENTITLEMENTS_PAGE_SIZE: u32 = 100;

/// The `limit` the server applies when a nested list request omits one.
///
/// Named because it is a **silent** truncation: these routes emit no
/// `meta.page` and no `links`, so a 25-row response with `limit` unset is
/// indistinguishable from a licence or machine that genuinely has 25 rows.
/// Always pass an explicit `limit`.
pub const DEFAULT_SERVER_PAGE_SIZE: u32 = 25;

impl ClientConfig {
    /// Starts building a [`ClientConfig`] with the two always-required
    /// fields. Auth must be set via [`ClientConfigBuilder::auth`] before
    /// calling [`ClientConfigBuilder::build`].
    pub fn builder(account_id: impl Into<String>, host: impl Into<String>) -> ClientConfigBuilder {
        ClientConfigBuilder {
            account_id: account_id.into(),
            host: host.into(),
            api_version: crate::transport::DEFAULT_API_VERSION.to_string(),
            timeout: DEFAULT_TIMEOUT,
            auth: None,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }

    /// `https://<host>/v1/accounts/{account_id}`, with the configured
    /// `host`'s trailing slash (if any) normalized away first, so callers
    /// can pass a bare host, a host with a trailing slash, or a full
    /// `https://` URL interchangeably.
    ///
    /// An explicit `http://` scheme is preserved rather than upgraded — the
    /// production API is always HTTPS, but this keeps `ClientConfig`
    /// usable against a local mock server (`wiremock`, integration tests)
    /// or a self-hosted plain-HTTP deployment without a separate
    /// test-only code path.
    pub fn base_url(&self) -> String {
        let trimmed = self.host.trim_end_matches('/');
        if let Some(host) = trimmed.strip_prefix("http://") {
            format!("http://{host}/v1/accounts/{}", self.account_id)
        } else {
            let host = trimmed.strip_prefix("https://").unwrap_or(trimmed);
            format!("https://{host}/v1/accounts/{}", self.account_id)
        }
    }
}

/// Builder for [`ClientConfig`]. See [`ClientConfig::builder`].
#[derive(Debug, Clone)]
pub struct ClientConfigBuilder {
    account_id: String,
    host: String,
    api_version: String,
    timeout: std::time::Duration,
    auth: Option<crate::transport::AuthTransport>,
    max_retries: u32,
}

impl ClientConfigBuilder {
    /// Overrides the default `Tamga-Version` (`"1.8"`).
    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = version.into();
        self
    }

    /// Overrides the default 45s request timeout. Keep any override above
    /// the server's own 30s deadline: below it the two race, and a slow
    /// request surfaces as a local timeout with nothing to correlate
    /// against instead of the server's `504`, which carries an
    /// `X-Request-Id`.
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the auth transport used to authenticate every request. Required
    /// before [`Self::build`] — there is no auth-less default, because there
    /// is no unauthenticated endpoint: every route this client calls
    /// enforces credentials and answers `401` without them.
    ///
    /// Choosing [`crate::transport::AuthTransport::License`] carries one
    /// server-side precondition worth knowing before shipping: the licence's
    /// policy must set `authentication_strategy` to `LICENSE` or `MIXED`.
    /// The column defaults to `'TOKEN'`, under which a licence key is not an
    /// accepted credential at all and every request is refused with
    /// `401 LICENSE_NOT_ALLOWED` — see [`crate::error::LicenseAuthCode`].
    pub fn auth(mut self, auth: crate::transport::AuthTransport) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Builds the [`ClientConfig`].
    ///
    /// # Panics
    ///
    /// Panics if [`Self::auth`] was never called. This is a programmer
    /// error (a missing required builder call), not a runtime/input
    /// condition — matching the crate's `Result`-for-fallible,
    /// panic-for-misuse convention.
    pub fn build(self) -> ClientConfig {
        ClientConfig {
            account_id: self.account_id,
            host: self.host,
            api_version: self.api_version,
            timeout: self.timeout,
            auth: self
                .auth
                .expect("ClientConfigBuilder::auth must be called before build()"),
            max_retries: self.max_retries,
        }
    }

    /// Override how many times a rate-limited request is retried.
    ///
    /// Set to `0` to handle `429` yourself — the error carries the
    /// server-supplied `Retry-After` so you can schedule your own backoff.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }
}

/// The Tamga API client — every endpoint method (validate, check-in,
/// checkout, machine management, components/processes, entitlements, offline
/// proof) lives here. See the module doc comment for the full index.
#[derive(Debug, Clone)]
pub struct Client {
    pub(crate) http: reqwest::Client,
    pub(crate) config: ClientConfig,
}

impl Client {
    /// Builds a [`Client`] from a [`ClientConfig`], constructing the
    /// underlying `reqwest::Client` with the configured timeout and a
    /// `tamga-rust/<crate-version>` `User-Agent`.
    pub fn new(config: ClientConfig) -> Result<Self, crate::TamgaError> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent(concat!("tamga-rust/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(crate::TamgaError::Http)?;
        Ok(Client { http, config })
    }

    /// Builds a request against `{base_url}{path}`, applying the configured
    /// auth transport, `Tamga-Version` (sanitized), and `Tamga-OTP` (if
    /// `otp` is set) — the common request setup shared by every endpoint
    /// method.
    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        otp: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let url = format!("{}{path}", self.config.base_url());
        let mut builder = self.http.request(method, url);
        if let Some((name, value)) = self.config.auth.header() {
            builder = builder.header(name, value);
        }
        if let Some((name, value)) = self.config.auth.query_param() {
            builder = builder.query(&[(name, value)]);
        }
        builder = builder.header(
            "Tamga-Version",
            crate::transport::sanitize_version(&self.config.api_version),
        );
        if let Some(otp) = otp {
            builder = builder.header("Tamga-OTP", otp);
        }
        builder
    }

    /// Is this request safe to repeat after a `429`?
    ///
    /// `GET` always is. Among the `POST`s only the licensing *actions* are —
    /// they are effectively idempotent (validate, check in/out, ping or reset
    /// a heartbeat), and they are precisely the calls a client makes on a
    /// timer, so they are the ones that hit the rate limit in the first place.
    ///
    /// `/actions/ping-heartbeat` and `/actions/reset-heartbeat` need their own
    /// entries: neither ends with `/actions/ping` (that suffix is the
    /// *process* ping route), so a suffix list without them silently drops
    /// every throttled machine heartbeat. That is the worst failure of the
    /// set — the rate limiter buckets per `(caller, route pattern)`, and with
    /// proxy headers untrusted an entire fleet shares one bucket on this
    /// route, so heartbeats are exactly what gets throttled. Dropped
    /// heartbeats strand the machine at
    /// [`crate::models::machine::HeartbeatStatus::Dead`] — and cull it
    /// outright on a policy that sets `require_heartbeat`. Both are bare
    /// `last_heartbeat_at` writes with no create semantics, so repeating them
    /// is unconditionally safe.
    ///
    /// Creates are deliberately excluded. Retrying `POST /machines` after a
    /// timeout-shaped failure risks a second activation burning a second seat,
    /// and only the caller knows whether that is acceptable.
    fn is_retryable(method: &reqwest::Method, path: &str) -> bool {
        if method == reqwest::Method::GET {
            return true;
        }
        method == reqwest::Method::POST
            && [
                "/actions/validate",
                "/actions/validate-key",
                "/actions/check-in",
                "/actions/check-out",
                "/actions/ping",
                "/actions/ping-heartbeat",
                "/actions/reset-heartbeat",
            ]
            .iter()
            .any(|suffix| path.ends_with(suffix))
    }

    /// How long to wait before retry number `attempt` (0-based).
    ///
    /// Prefers the server's `Retry-After` when present — it knows when the
    /// bucket refills and guessing wastes the budget. Otherwise exponential
    /// backoff with jitter, because a fleet of clients that all retry on the
    /// same schedule reconverges into the same spike it was backing off from.
    fn retry_delay(attempt: u32, retry_after: Option<u64>) -> std::time::Duration {
        if let Some(secs) = retry_after {
            // Cap it: a hostile or misconfigured proxy must not be able to
            // park the caller for an hour.
            return std::time::Duration::from_secs(secs.min(60));
        }
        let base = 1u64 << attempt.min(5); // 1, 2, 4, 8, 16, 32 seconds
        let jitter = crate::transport::jitter_millis(attempt);
        std::time::Duration::from_millis(base * 1000 + jitter)
    }

    /// Parse `Retry-After` as delta-seconds. HTTP-date form is ignored — the
    /// server sends seconds, and misreading a date as a duration would be far
    /// worse than falling back to backoff.
    fn parse_retry_after(response: &reqwest::Response) -> Option<u64> {
        response
            .headers()
            .get(reqwest::header::RETRY_AFTER)?
            .to_str()
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    }

    /// Expose [`Self::retry_delay`] to integration tests.
    ///
    /// The delay policy is worth asserting directly: the alternative is a test
    /// that actually waits, which is either slow or meaningless.
    #[doc(hidden)]
    pub fn retry_delay_for_test(attempt: u32, retry_after: Option<u64>) -> std::time::Duration {
        Self::retry_delay(attempt, retry_after)
    }

    /// Send a request, transparently retrying while the server answers `429`.
    ///
    /// Returns the first non-429 response, or the last 429 once the retry
    /// budget is spent — the caller then turns it into a
    /// [`crate::TamgaError::RateLimited`] carrying `Retry-After`.
    async fn send_with_retry(
        &self,
        builder: reqwest::RequestBuilder,
        method: &reqwest::Method,
        path: &str,
    ) -> Result<reqwest::Response, crate::TamgaError> {
        let retryable = Self::is_retryable(method, path);
        let mut attempt = 0u32;

        loop {
            // `try_clone` fails only for streaming bodies, which this client
            // never sends; if it ever did, not retrying is the safe answer.
            let this_try = match builder.try_clone() {
                Some(b) => b,
                None => return builder.send().await.map_err(crate::TamgaError::Http),
            };

            let response = this_try.send().await?;

            if response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS
                || !retryable
                || attempt >= self.config.max_retries
            {
                return Ok(response);
            }

            let delay = Self::retry_delay(attempt, Self::parse_retry_after(&response));
            tokio::time::sleep(delay).await;
            attempt += 1;
        }
    }

    /// Sends a JSON:API request (`Content-Type: application/vnd.api+json`,
    /// optional JSON body) and deserializes a `{ data: T }` envelope on
    /// success, or a typed [`crate::TamgaError`] (see
    /// [`crate::TamgaError::from_json_api_error`]) on a non-2xx status.
    async fn send_json_api<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
        otp: Option<&str>,
    ) -> Result<T, crate::TamgaError> {
        #[derive(serde::Deserialize)]
        struct Envelope<T> {
            data: T,
        }

        let mut builder = self
            .request(method.clone(), path, otp)
            .header(reqwest::header::CONTENT_TYPE, "application/vnd.api+json");
        if let Some(body) = body {
            builder = builder.json(&body);
        }
        let response = self.send_with_retry(builder, &method, path).await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        let envelope: Envelope<T> = response.json().await?;
        Ok(envelope.data)
    }

    /// Like [`Self::send_json_api`] but also returns the parsed `meta`
    /// field alongside `data` — used by the validate endpoints, whose
    /// `ValidationMeta` lives in `meta`, not `data`.
    async fn send_json_api_with_meta<T, M>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
        otp: Option<&str>,
    ) -> Result<(T, M), crate::TamgaError>
    where
        T: serde::de::DeserializeOwned,
        M: serde::de::DeserializeOwned,
    {
        #[derive(serde::Deserialize)]
        struct EnvelopeWithMeta<T, M> {
            data: T,
            meta: M,
        }

        let mut builder = self
            .request(method.clone(), path, otp)
            .header(reqwest::header::CONTENT_TYPE, "application/vnd.api+json");
        if let Some(body) = body {
            builder = builder.json(&body);
        }
        let response = self.send_with_retry(builder, &method, path).await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        let envelope: EnvelopeWithMeta<T, M> = response.json().await?;
        Ok((envelope.data, envelope.meta))
    }

    /// Sends a request expecting a flat (non-enveloped) JSON body — used
    /// only by quick-validate today, which returns plain
    /// `application/json` with no `data` key.
    async fn send_flat<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        otp: Option<&str>,
    ) -> Result<T, crate::TamgaError> {
        let builder = self.request(method.clone(), path, otp);
        let response = self.send_with_retry(builder, &method, path).await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        Ok(response.json().await?)
    }

    /// Parses a non-2xx response body as a JSON:API error document and
    /// maps its first error to the most specific [`crate::TamgaError`]
    /// variant via [`crate::TamgaError::from_json_api_error`]. Falls back to
    /// a synthetic error (status only, no server-provided detail) if the
    /// body isn't valid JSON:API error JSON — a non-JSON error page (e.g.
    /// from a proxy in front of the API) must not panic or silently
    /// swallow the failure.
    async fn api_error(response: reqwest::Response) -> crate::TamgaError {
        let status = response.status();

        // Surfaced as its own variant rather than folded into the generic API
        // error: a caller that cannot tell "you are going too fast, wait N
        // seconds" from "your credential is wrong" will retry the second one
        // forever and give up on the first.
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = Self::parse_retry_after(&response);
            return crate::TamgaError::RateLimited { retry_after };
        }

        let json_api_error = match response.json::<crate::error::JsonApiErrorDocument>().await {
            Ok(doc) => {
                doc.errors
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| crate::error::JsonApiError {
                        id: String::new(),
                        status: status.as_u16().to_string(),
                        code: "UNKNOWN".to_string(),
                        title: "Unknown Error".to_string(),
                        detail: "server returned an empty errors array".to_string(),
                        source: None,
                    })
            }
            Err(_) => crate::error::JsonApiError {
                id: String::new(),
                status: status.as_u16().to_string(),
                code: "UNKNOWN".to_string(),
                title: "Unknown Error".to_string(),
                detail: format!("server returned {status} with a non-JSON:API body"),
                source: None,
            },
        };
        crate::TamgaError::from_json_api_error(json_api_error)
    }

    /// `POST /licenses/actions/validate-key` — validates a license by its
    /// raw key. No scope support on this endpoint (use
    /// [`Self::validate_by_id`] for scoped validation). `otp` sends
    /// `Tamga-OTP` if the bearer's account has 2FA enabled.
    pub async fn validate_by_key(
        &self,
        key: &str,
        otp: Option<&str>,
    ) -> Result<crate::models::validation::ValidationResult, crate::TamgaError> {
        let body = serde_json::json!({ "key": key });
        let (license, meta) = self
            .send_json_api_with_meta(
                reqwest::Method::POST,
                "/licenses/actions/validate-key",
                Some(body),
                otp,
            )
            .await?;
        Ok(crate::models::validation::ValidationResult { license, meta })
    }

    /// `POST /licenses/{license_id}/actions/validate` — validates a license
    /// by ID, optionally constrained by `scope` (see
    /// [`crate::models::validation::ScopeObject`]: `product`, `policy`,
    /// `user`, `environment`, `entitlements` and `fingerprint` are all
    /// enforced server-side; `version` and `checksum` are refused and are
    /// never sent). `skip_touch: true` suppresses the `last_validated_at`
    /// side-effect. `otp` sends `Tamga-OTP` if the bearer's account has 2FA
    /// enabled.
    ///
    /// Scoping on `fingerprint` is the anti-key-sharing check: passing the
    /// local machine's fingerprint asserts the licence is being validated
    /// from a machine that licence already knows about. Scoping on
    /// `entitlements` is the only way to get an authoritative
    /// entitlement answer for a licence holding more than
    /// [`MAX_ENTITLEMENTS_PAGE_SIZE`] of them — see
    /// [`Self::has_entitlement`].
    pub async fn validate_by_id(
        &self,
        license_id: uuid::Uuid,
        scope: Option<crate::models::validation::ScopeObject>,
        skip_touch: bool,
        otp: Option<&str>,
    ) -> Result<crate::models::validation::ValidationResult, crate::TamgaError> {
        let mut meta = serde_json::json!({ "skip_touch": skip_touch });
        if let Some(scope) = scope {
            meta["scope"] = serde_json::to_value(scope)?;
        }
        let body = serde_json::json!({ "meta": meta });
        let (license, validation_meta) = self
            .send_json_api_with_meta(
                reqwest::Method::POST,
                &format!("/licenses/{license_id}/actions/validate"),
                Some(body),
                otp,
            )
            .await?;
        Ok(crate::models::validation::ValidationResult {
            license,
            meta: validation_meta,
        })
    }

    /// `GET /licenses/{license_id}/actions/validate` — quick-validate.
    /// Returns only the flat `{ ts, valid, detail, code }` body (no license
    /// resource) — cheaper than [`Self::validate_by_id`] when the caller
    /// only needs the outcome, not the license's current attributes. `otp`
    /// sends `Tamga-OTP` if the bearer's account has 2FA enabled.
    ///
    /// This route **does** write `last_validated_at`, and there is no
    /// `skip_touch` on it — but the server skips that write entirely
    /// whenever the request carries an `Origin` header, and the two
    /// responses are byte-identical, so a caller cannot tell which
    /// happened. This SDK never sets `Origin` on any transport, so the
    /// write normally lands; a proxy or middleware that adds one silently
    /// turns it off. That matters more than it looks: a licence with no
    /// machines and a null `last_validated_at` reports `INACTIVE`, and
    /// `last_validated_at` is also the baseline the server's
    /// check-in-overdue sweep measures from, so an always-`Origin` client
    /// can leave a licence permanently un-activated and permanently
    /// overdue. Check-in does not substitute — it writes a different
    /// column.
    ///
    /// The only deliberately side-effect-free path is
    /// [`Self::validate_by_id`] with `skip_touch: true`.
    pub async fn quick_validate(
        &self,
        license_id: uuid::Uuid,
        otp: Option<&str>,
    ) -> Result<crate::models::validation::ValidationMeta, crate::TamgaError> {
        self.send_flat(
            reqwest::Method::GET,
            &format!("/licenses/{license_id}/actions/validate"),
            otp,
        )
        .await
    }

    /// `POST /licenses/{license_id}/actions/check-in` — no body. Returns
    /// the updated license resource with `last_check_in_at` bumped (no
    /// `meta` on this response, unlike validate).
    ///
    /// Fails with [`crate::TamgaError::CheckInNotRequired`] if the
    /// license's policy has `require_check_in: false` — callers should
    /// check that flag on the license's policy before scheduling periodic
    /// check-ins, rather than reacting to this error with retry logic; it
    /// is a caller error, not a transient failure.
    pub async fn check_in(
        &self,
        license_id: uuid::Uuid,
    ) -> Result<crate::models::license::LicenseResource, crate::TamgaError> {
        self.send_json_api(
            reqwest::Method::POST,
            &format!("/licenses/{license_id}/actions/check-in"),
            None,
            None,
        )
        .await
    }

    /// `GET /licenses/{license_id}/actions/check-out` — raw
    /// `application/octet-stream` `.lic` file body. Returns the PEM string
    /// verbatim; pass it to
    /// [`crate::checkout::license_file::verify_license_file`] to verify and
    /// decode it. Non-idempotent — a fresh UUIDv7 backs each call, so
    /// calling this twice yields two different certificates.
    pub async fn check_out_license(
        &self,
        license_id: uuid::Uuid,
        encrypt: bool,
        ttl: Option<u64>,
    ) -> Result<String, crate::TamgaError> {
        let path = format!("/licenses/{license_id}/actions/check-out");
        let mut builder = self.request(reqwest::Method::GET, &path, None);
        builder = builder.query(&[("encrypt", encrypt.to_string())]);
        if let Some(ttl) = ttl {
            builder = builder.query(&[("ttl", ttl.to_string())]);
        }
        let response = self
            .send_with_retry(builder, &reqwest::Method::GET, &path)
            .await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        Ok(response.text().await?)
    }

    /// `POST /licenses/{license_id}/actions/check-out` — JSON:API variant,
    /// returning a full [`crate::checkout::license_file::LicenseFileResource`]
    /// (certificate plus `ttl`/`expiry`/`issued` metadata) instead of the
    /// raw PEM bytes [`Self::check_out_license`] returns.
    ///
    /// Fails with a `LICENSE_NOT_ENCRYPTED` API error if `encrypt: true` is
    /// requested for a license with no `key` set.
    pub async fn check_out_license_json(
        &self,
        license_id: uuid::Uuid,
        encrypt: bool,
        ttl: Option<u64>,
    ) -> Result<crate::checkout::license_file::LicenseFileResource, crate::TamgaError> {
        let body = serde_json::json!({ "meta": { "encrypt": encrypt, "ttl": ttl } });
        self.send_json_api(
            reqwest::Method::POST,
            &format!("/licenses/{license_id}/actions/check-out"),
            Some(body),
            None,
        )
        .await
    }

    /// `GET /machines/{machine_id}/actions/check-out` — raw
    /// `application/octet-stream` `.mach` file body. Returns the PEM string
    /// verbatim; pass it to
    /// [`crate::checkout::machine_file::verify_machine_file`] to verify and
    /// decode it.
    ///
    /// If `ttl` is set, it's pre-checked client-side via
    /// [`crate::checkout::machine_file::check_ttl`] before the round trip
    /// — see that function's doc comment.
    pub async fn check_out_machine(
        &self,
        machine_id: uuid::Uuid,
        encrypt: bool,
        ttl: Option<u64>,
    ) -> Result<String, crate::TamgaError> {
        if let Some(ttl) = ttl {
            crate::checkout::machine_file::check_ttl(ttl)?;
        }
        let path = format!("/machines/{machine_id}/actions/check-out");
        let mut builder = self.request(reqwest::Method::GET, &path, None);
        builder = builder.query(&[("encrypt", encrypt.to_string())]);
        if let Some(ttl) = ttl {
            builder = builder.query(&[("ttl", ttl.to_string())]);
        }
        let response = self
            .send_with_retry(builder, &reqwest::Method::GET, &path)
            .await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        Ok(response.text().await?)
    }

    /// `POST /machines/{machine_id}/actions/check-out` — JSON:API variant,
    /// returning a full
    /// [`crate::checkout::machine_file::MachineFileResource`] instead of
    /// the raw PEM bytes [`Self::check_out_machine`] returns.
    ///
    /// Fails with a `LICENSE_KEY_MISSING` API error if `encrypt: true` is
    /// requested for a machine whose license has no `key` set, or
    /// `SCHEME_NOT_SUPPORTED` if the license's scheme is
    /// `RSA_2048_JWT_RS256`.
    pub async fn check_out_machine_json(
        &self,
        machine_id: uuid::Uuid,
        encrypt: bool,
        ttl: Option<u64>,
    ) -> Result<crate::checkout::machine_file::MachineFileResource, crate::TamgaError> {
        if let Some(ttl) = ttl {
            crate::checkout::machine_file::check_ttl(ttl)?;
        }
        let body = serde_json::json!({ "meta": { "encrypt": encrypt, "ttl": ttl } });
        self.send_json_api(
            reqwest::Method::POST,
            &format!("/machines/{machine_id}/actions/check-out"),
            Some(body),
            None,
        )
        .await
    }

    /// `POST /machines` — registers a machine against `license_id`.
    ///
    /// Unique per `(account_id, license_id, fingerprint)` — a duplicate
    /// fingerprint on the same license fails with
    /// [`crate::TamgaError::FingerprintTaken`].
    ///
    /// **Creation may or may not enforce the policy's limits — the policy
    /// decides.** The server runs the machine/core/memory/disk checks here,
    /// but routes each one through the policy's overage strategy: under a
    /// permissive strategy (`ALLOW_ACCESS`, `ALLOW_1_25X_OVERAGE`, …) the
    /// machine is created and the limit surfaces only on the next
    /// [`Self::validate_by_id`], while under a strict one creation itself
    /// is refused with a `422` carrying a
    /// [`crate::error::LimitExceededCode`] (`MACHINE_LIMIT_EXCEEDED`,
    /// `CORE_LIMIT_EXCEEDED`, `MEMORY_LIMIT_EXCEEDED`,
    /// `DISK_LIMIT_EXCEEDED`).
    ///
    /// A caller doing this by hand therefore has to handle both shapes of
    /// the same outcome. [`Self::activate_machine`] does: it normalizes the
    /// create-time `422` onto the equivalent
    /// [`crate::models::validation::ValidationCode`] and keeps the
    /// create → validate → delete-on-overage path for the permissive case.
    pub async fn create_machine(
        &self,
        license_id: uuid::Uuid,
        fingerprint: &str,
        opts: CreateMachineOptions,
    ) -> Result<crate::models::machine::MachineResource, crate::TamgaError> {
        let body = serde_json::json!({
            "data": {
                "type": "machines",
                "attributes": {
                    "fingerprint": fingerprint,
                    "name": opts.name,
                    "ip": opts.ip,
                    "hostname": opts.hostname,
                    "platform": opts.platform,
                    "cores": opts.cores,
                    "memory": opts.memory,
                    "disk": opts.disk,
                    "metadata": opts.metadata.unwrap_or_else(|| serde_json::json!({})),
                },
                "relationships": {
                    "license": { "data": { "type": "licenses", "id": license_id } }
                }
            }
        });
        self.send_json_api(reqwest::Method::POST, "/machines", Some(body), None)
            .await
    }

    /// `create_machine` + [`Self::validate_by_id`] composed into the
    /// recommended "activate machine" flow (see [`Self::create_machine`]'s
    /// doc comment for why creation enforces limits under some policies and
    /// not others).
    ///
    /// Over-limit activation has **two** shapes and this method flattens
    /// both into one outcome — an `Ok` whose
    /// [`crate::models::validation::ValidationMeta`] has `valid: false` and
    /// the matching over-limit code:
    ///
    /// - *Permissive overage strategy.* Creation succeeds, validation comes
    ///   back over-limit (`TooManyMachines`, `TooManyCores`,
    ///   `TooMuchMemory`, `TooMuchDisk`, `TooManyProcesses`). With
    ///   `auto_delete_on_overage` the just-created machine is deleted
    ///   before returning, implementing "reject over-limit activation"
    ///   instead of leaving an orphaned row behind. Deletion failures are
    ///   not surfaced (the validation result is what the caller asked for);
    ///   a machine left behind after a failed auto-delete is still visible
    ///   to normal machine-management calls for manual cleanup.
    /// - *Strict overage strategy.* Creation itself is refused with a `422`
    ///   [`crate::error::LimitExceededCode`], which short-circuits the flow
    ///   before validation ever runs. That is normalized onto the
    ///   equivalent validation code
    ///   ([`crate::error::LimitExceededCode::as_validation_code`]) and
    ///   returned in the same shape, so one caller-side branch covers both
    ///   policies. **No delete is issued** on this path — no row was
    ///   created, and deleting the machine that already occupies the seat
    ///   would be exactly wrong.
    ///
    /// On that second path the licence resource is still fetched (via a
    /// `skip_touch` validate, so a refused activation records no
    /// `last_validated_at`) to fill out the result; only the returned
    /// `meta` is replaced. If that fetch also fails, the original create
    /// error propagates rather than being masked.
    ///
    /// Any other creation failure — `409 FINGERPRINT_TAKEN`, `401`, `403` —
    /// propagates unchanged.
    pub async fn activate_machine(
        &self,
        license_id: uuid::Uuid,
        fingerprint: &str,
        opts: CreateMachineOptions,
        scope: Option<crate::models::validation::ScopeObject>,
        auto_delete_on_overage: bool,
    ) -> Result<crate::models::validation::ValidationResult, crate::TamgaError> {
        let machine = match self.create_machine(license_id, fingerprint, opts).await {
            Ok(machine) => machine,
            Err(err) => match err.limit_exceeded() {
                Some(limit) => {
                    return self
                        .over_limit_result_without_machine(license_id, scope, limit, err)
                        .await
                }
                None => return Err(err),
            },
        };

        let result = self.validate_by_id(license_id, scope, false, None).await;

        if auto_delete_on_overage {
            let is_overage = matches!(
                &result,
                Ok(r) if is_overage_code(&r.meta.code)
            );
            if is_overage {
                let _ = self.delete_machine(machine.id).await;
            }
        }

        result
    }

    /// Builds the over-limit [`crate::models::validation::ValidationResult`]
    /// for a machine the server refused to create.
    ///
    /// The licence resource comes from a `skip_touch` validate — the flow
    /// needs a `LicenseResource` to return and this is the only read that
    /// yields one without recording a successful validation for an
    /// activation that did not happen. Its `meta` is discarded: it would
    /// describe the licence *without* the refused machine, which is the one
    /// question the caller did not ask. `create_err` is returned untouched
    /// if the licence cannot be read at all, so a second failure never
    /// masks the first.
    async fn over_limit_result_without_machine(
        &self,
        license_id: uuid::Uuid,
        scope: Option<crate::models::validation::ScopeObject>,
        limit: crate::error::LimitExceededCode,
        create_err: crate::TamgaError,
    ) -> Result<crate::models::validation::ValidationResult, crate::TamgaError> {
        let detail = create_err
            .json_api_error()
            .map(|err| err.detail.clone())
            .unwrap_or_default();

        let probe = match self.validate_by_id(license_id, scope, true, None).await {
            Ok(probe) => probe,
            Err(_) => return Err(create_err),
        };

        Ok(crate::models::validation::ValidationResult {
            license: probe.license,
            meta: crate::models::validation::ValidationMeta {
                ts: probe.meta.ts,
                valid: false,
                detail,
                code: limit.as_validation_code(),
            },
        })
    }

    /// `POST /machines/{machine_id}/actions/ping-heartbeat` — no body, sets
    /// `last_heartbeat_at = now`. Returns the updated machine resource.
    ///
    /// The write is unconditional — a bare `last_heartbeat_at = NOW()` with
    /// no resurrection check — so it revives a machine that had gone stale
    /// server-side, however long ago it last pinged.
    ///
    /// ⚠️ The returned `heartbeat_status` is never
    /// [`crate::models::machine::HeartbeatStatus::Dead`]. The server writes
    /// `last_heartbeat_at = NOW()` and then derives the status from that same
    /// timestamp, so the age it measures is ~0 and the answer is always
    /// `Alive` or `Resurrected`. `Dead` is a real state, and it *is* visible
    /// from this crate — inside a verified machine file and on a
    /// [`Self::generate_offline_proof`] response, both built from a read —
    /// just never here. So **do not write a `Dead` branch against this
    /// response**, and do not read a non-`Dead` answer as evidence the
    /// machine was never late.
    ///
    /// **Never stop the ping loop on a status**, whichever comes back. That
    /// rule does not depend on seeing `Dead`, and it is what keeps a stale
    /// machine recoverable.
    ///
    /// The row-is-gone signal is a `404`
    /// ([`crate::TamgaError::NotFound`]) from this call — that, and only
    /// that, is the cue to re-activate with [`Self::activate_machine`].
    ///
    /// ⚠️ Pick the interval deliberately. The server's window is
    /// `policy.heartbeat_duration` and falls back to 600s only when unset,
    /// and the `next_heartbeat_at` on *this* response is computed against
    /// that fallback regardless — so it cannot tell you a tighter policy
    /// needs a tighter interval. A checked-out machine file or a
    /// [`Self::generate_offline_proof`] response can: both resolve through a
    /// policy-joined read, so `next_heartbeat_at - last_heartbeat_at` there
    /// is the real window. See
    /// [`crate::models::machine::HeartbeatStatus`].
    pub async fn ping_heartbeat(
        &self,
        machine_id: uuid::Uuid,
    ) -> Result<crate::models::machine::MachineResource, crate::TamgaError> {
        self.send_json_api(
            reqwest::Method::POST,
            &format!("/machines/{machine_id}/actions/ping-heartbeat"),
            None,
            None,
        )
        .await
    }

    /// `POST /machines/{machine_id}/actions/reset-heartbeat` — no body,
    /// fully rewinds heartbeat state to
    /// [`crate::models::machine::HeartbeatStatus::NotStarted`].
    ///
    /// ⚠️ **Never callable with a licence key.** Unlike
    /// [`Self::ping_heartbeat`], which is permission-gated only, this route
    /// is role-gated: admin, developer, product-token and
    /// environment-token callers pass; a `LicenseToken` — what
    /// [`crate::transport::AuthTransport::License`] produces — is refused
    /// with `403` every single time, regardless of the permissions on the
    /// key. Worth stating plainly because this is the server's only way to
    /// unstick a machine whose heartbeat job is wedged: an embedded client
    /// authenticating by licence key has no recovery here and must escalate
    /// to a back-office credential.
    pub async fn reset_heartbeat(
        &self,
        machine_id: uuid::Uuid,
    ) -> Result<crate::models::machine::MachineResource, crate::TamgaError> {
        self.send_json_api(
            reqwest::Method::POST,
            &format!("/machines/{machine_id}/actions/reset-heartbeat"),
            None,
            None,
        )
        .await
    }

    /// `DELETE /machines/{machine_id}` — `204 No Content` on success.
    pub async fn delete_machine(&self, machine_id: uuid::Uuid) -> Result<(), crate::TamgaError> {
        let response = self
            .request(
                reqwest::Method::DELETE,
                &format!("/machines/{machine_id}"),
                None,
            )
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        Ok(())
    }

    /// `POST /machines/{machine_id}/actions/generate-offline-proof` —
    /// `dataset` defaults to `{}` if `None` (must be a JSON object; a
    /// non-object fails server-side with `422 DATASET_INVALID`). Returns
    /// the updated machine resource plus the `"v1x0.<base64>"` proof
    /// string — pass the proof, plus the exact `account_id`/`machine_id`/
    /// `fingerprint`/`dataset` tuple used here, to
    /// [`crate::proof::verify_offline_proof`] to verify it fully offline.
    ///
    /// ⚠️ **Never callable with a licence key**, same as
    /// [`Self::reset_heartbeat`]: this route is role-gated and a
    /// `LicenseToken` is not among the accepted roles, so it answers `403`
    /// even though the licence-key role does hold the
    /// `machine.proofs.generate` permission. Generating a proof requires a
    /// back-office credential; *verifying* one
    /// ([`crate::proof::verify_offline_proof`]) needs no credential and no
    /// network at all, which is the half an embedded client actually
    /// wants.
    pub async fn generate_offline_proof(
        &self,
        machine_id: uuid::Uuid,
        dataset: Option<serde_json::Value>,
    ) -> Result<(crate::models::machine::MachineResource, String), crate::TamgaError> {
        #[derive(serde::Deserialize)]
        struct ProofMeta {
            proof: String,
        }

        let body = serde_json::json!({
            "meta": { "dataset": dataset.unwrap_or_else(|| serde_json::json!({})) }
        });
        let (machine, meta): (crate::models::machine::MachineResource, ProofMeta) = self
            .send_json_api_with_meta(
                reqwest::Method::POST,
                &format!("/machines/{machine_id}/actions/generate-offline-proof"),
                Some(body),
                None,
            )
            .await?;
        Ok((machine, meta.proof))
    }

    /// `POST /components` — registers a component against `machine_id`.
    /// **Not** JSON:API-enveloped on the request side (unlike
    /// `create_machine`) — the server's `create_component` handler expects
    /// a flat `{ machine_id, fingerprint, name, metadata }` body; this is a
    /// real asymmetry in the Tamga API, not an SDK oversight.
    ///
    /// Unique per `(account_id, machine_id, fingerprint)` — a duplicate
    /// fails with [`crate::TamgaError::FingerprintTaken`].
    pub async fn create_component(
        &self,
        machine_id: uuid::Uuid,
        fingerprint: &str,
        name: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<crate::models::machine::ComponentResource, crate::TamgaError> {
        let body = serde_json::json!({
            "machine_id": machine_id,
            "fingerprint": fingerprint,
            "name": name,
            "metadata": metadata.unwrap_or_else(|| serde_json::json!({})),
        });
        self.send_json_api(reqwest::Method::POST, "/components", Some(body), None)
            .await
    }

    /// `GET /machines/{machine_id}/components` — keyset-paginated
    /// (`limit`, `page[after]`). The response carries no cursor
    /// metadata/links — pass the last returned component's `id` as `after`
    /// to fetch the next page. Unlike the entitlements listing, the cursor
    /// on this route is real and does advance.
    ///
    /// Pass `limit` explicitly. Omitting it does not mean "everything": the
    /// server defaults to [`DEFAULT_SERVER_PAGE_SIZE`] and clamps to
    /// [`MAX_ENTITLEMENTS_PAGE_SIZE`], and with no page metadata in the
    /// response a caller that did not choose the limit cannot tell a full
    /// page from a final one — which is also what makes "is this page
    /// short?" the only usable end-of-listing signal.
    pub async fn list_components(
        &self,
        machine_id: uuid::Uuid,
        limit: Option<u32>,
        after: Option<uuid::Uuid>,
    ) -> Result<Vec<crate::models::machine::ComponentResource>, crate::TamgaError> {
        #[derive(serde::Deserialize)]
        struct Envelope {
            data: Vec<crate::models::machine::ComponentResource>,
        }

        let path = format!("/machines/{machine_id}/components");
        let mut builder = self.request(reqwest::Method::GET, &path, None);
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit.to_string())]);
        }
        if let Some(after) = after {
            builder = builder.query(&[("page[after]", after.to_string())]);
        }
        let response = self
            .send_with_retry(builder, &reqwest::Method::GET, &path)
            .await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        let envelope: Envelope = response.json().await?;
        Ok(envelope.data)
    }

    /// `POST /processes` — registers a process against `machine_id`. Same
    /// flat (non-JSON:API) request body shape as [`Self::create_component`]
    /// — see that method's doc comment.
    ///
    /// Unique PID per machine — a duplicate fails with
    /// [`crate::TamgaError::PidTaken`]. Unlike a machine (which starts
    /// `NOT_STARTED`), a process starts `ALIVE` immediately — its
    /// `last_heartbeat_at` is set at creation, not left unset until a first
    /// ping.
    ///
    /// ⚠️ This call increments the licence's `machines_process_count` against
    /// the policy's `max_processes`, and **nothing ever decrements it on its
    /// own**: the server reaps no process rows (see
    /// [`crate::models::machine::Pid`]), and this crate exposes no delete.
    /// A short-lived process registered here consumes its slot permanently,
    /// so register only what is worth tracking, and reuse a stable PID rather
    /// than minting a fresh one per run.
    pub async fn create_process(
        &self,
        machine_id: uuid::Uuid,
        pid: impl Into<crate::models::machine::Pid>,
        metadata: Option<serde_json::Value>,
    ) -> Result<crate::models::machine::ProcessResource, crate::TamgaError> {
        let body = serde_json::json!({
            "machine_id": machine_id,
            "pid": pid.into(),
            "metadata": metadata.unwrap_or_else(|| serde_json::json!({})),
        });
        self.send_json_api(reqwest::Method::POST, "/processes", Some(body), None)
            .await
    }

    /// `POST /processes/{process_id}/actions/ping` — no body, sets
    /// `last_heartbeat_at = now`.
    ///
    /// ⚠️ Nothing server-side reads that timestamp today: the 30-second
    /// window and the sweep that would delete an expired process both live in
    /// a worker with no call site and no scheduler tick, so **no process row
    /// is ever reaped** — see [`crate::models::machine::Pid`]'s doc comment.
    /// Ping on a ~10s timer anyway; the reaper needs only a scheduler entry
    /// to go live.
    pub async fn ping_process(
        &self,
        process_id: uuid::Uuid,
    ) -> Result<crate::models::machine::ProcessResource, crate::TamgaError> {
        self.send_json_api(
            reqwest::Method::POST,
            &format!("/processes/{process_id}/actions/ping"),
            None,
            None,
        )
        .await
    }

    /// `GET /licenses/{license_id}/entitlements` — the licence's effective
    /// entitlements, direct attachments and policy-inherited rows unioned
    /// together. Despite the URL nesting, returns full
    /// [`crate::models::entitlement::EntitlementResource`]s, not
    /// lightweight junction records.
    ///
    /// ⚠️ **This route cannot be paginated.** `page[after]` is accepted for
    /// wire compatibility and then ignored: the listing is a union across
    /// two tables, so a single keyset cursor no longer describes it and the
    /// server applies no cursor predicate at all. Passing `after` therefore
    /// re-fetches the same first page — never build a "loop until short
    /// page" over this method, and never treat the last row's id as a
    /// cursor here. (`GET /machines/{id}/components`, which
    /// [`Self::list_components`] calls, is unaffected: its cursor is real.)
    ///
    /// `limit` bounds the response instead, and is the only thing that
    /// does. Omitting it does **not** mean "everything" — the server
    /// silently defaults to **25** rows and clamps to a maximum of
    /// [`MAX_ENTITLEMENTS_PAGE_SIZE`], with no `meta`/`links` to signal the
    /// truncation. Pass an explicit limit. A licence with more than 100
    /// effective entitlements cannot be fully enumerated through this
    /// endpoint at all, so a negative answer derived from it is
    /// authoritative only below that ceiling — see
    /// [`Self::has_entitlement`].
    ///
    /// This method drops the licence-scoped `inherited` attribute; use
    /// [`Self::list_license_entitlements`] to keep it.
    pub async fn list_entitlements(
        &self,
        license_id: uuid::Uuid,
        limit: Option<u32>,
        after: Option<uuid::Uuid>,
    ) -> Result<Vec<crate::models::entitlement::EntitlementResource>, crate::TamgaError> {
        #[derive(serde::Deserialize)]
        struct Envelope {
            data: Vec<crate::models::entitlement::EntitlementResource>,
        }

        let path = format!("/licenses/{license_id}/entitlements");
        let mut builder = self.request(reqwest::Method::GET, &path, None);
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit.to_string())]);
        }
        if let Some(after) = after {
            builder = builder.query(&[("page[after]", after.to_string())]);
        }
        let response = self
            .send_with_retry(builder, &reqwest::Method::GET, &path)
            .await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        let envelope: Envelope = response.json().await?;
        Ok(envelope.data)
    }

    /// [`Self::list_entitlements`], keeping the licence-scoped `inherited`
    /// flag each row carries.
    ///
    /// Same endpoint, same request, same pagination caveats — including that
    /// `page[after]` is inert here, which is why this method takes no
    /// cursor at all. It exists because
    /// [`crate::models::entitlement::EntitlementResource`] is shared with
    /// the account-, policy- and release-scoped routes, where the server
    /// emits no `inherited` attribute, so the flag has nowhere to live on
    /// that type.
    ///
    /// Reach for this whenever the caller intends to *act* on a row rather
    /// than just read its `code`: an inherited entitlement cannot be
    /// detached, cannot be re-attached, and 404s on
    /// [`Self::get_entitlement`]. See
    /// [`crate::models::entitlement::LicenseEntitlementAttributes::inherited`].
    pub async fn list_license_entitlements(
        &self,
        license_id: uuid::Uuid,
        limit: Option<u32>,
    ) -> Result<Vec<crate::models::entitlement::LicenseEntitlement>, crate::TamgaError> {
        #[derive(serde::Deserialize)]
        struct Envelope {
            data: Vec<crate::models::entitlement::LicenseEntitlement>,
        }

        let path = format!("/licenses/{license_id}/entitlements");
        let mut builder = self.request(reqwest::Method::GET, &path, None);
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit.to_string())]);
        }
        let response = self
            .send_with_retry(builder, &reqwest::Method::GET, &path)
            .await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        let envelope: Envelope = response.json().await?;
        Ok(envelope.data)
    }

    /// `GET /licenses/{license_id}/entitlements/{entitlement_id}`.
    ///
    /// ⚠️ Resolves **direct attachments only**. An entitlement the licence
    /// holds through its policy appears in
    /// [`Self::list_license_entitlements`] with `inherited: true` but 404s
    /// here — the item route joins only the direct-attachment table. Do not
    /// build a list-then-get-each loop over this resource.
    pub async fn get_entitlement(
        &self,
        license_id: uuid::Uuid,
        entitlement_id: uuid::Uuid,
    ) -> Result<crate::models::entitlement::EntitlementResource, crate::TamgaError> {
        self.send_json_api(
            reqwest::Method::GET,
            &format!("/licenses/{license_id}/entitlements/{entitlement_id}"),
            None,
            None,
        )
        .await
    }

    /// Convenience helper: fetches this license's entitlements (a single
    /// request, up to `limit`) and checks whether any has the given `code`.
    ///
    /// Matches on `code` (the stable, developer-facing identifier) —
    /// **never** on `name` (just a display label). Direct and
    /// policy-inherited entitlements both count, exactly as they do for
    /// [`crate::models::validation::ScopeObject::entitlements`].
    ///
    /// One request is all there is: `limit` defaults to
    /// [`MAX_ENTITLEMENTS_PAGE_SIZE`], the server's ceiling, and this route
    /// cannot be paginated past it (see [`Self::list_entitlements`]). A
    /// `true` answer is always authoritative. A **`false`** answer is
    /// authoritative only for a licence holding at most
    /// [`MAX_ENTITLEMENTS_PAGE_SIZE`] effective entitlements; beyond that
    /// the endpoint cannot enumerate them all and a code past the ceiling
    /// is indistinguishable from an absent one. Scope the validate call
    /// instead ([`crate::models::validation::ScopeObject::entitlements`]),
    /// which the server evaluates against the full set.
    pub async fn has_entitlement(
        &self,
        license_id: uuid::Uuid,
        code: &str,
        limit: Option<u32>,
    ) -> Result<bool, crate::TamgaError> {
        let entitlements = self
            .list_entitlements(
                license_id,
                Some(limit.unwrap_or(MAX_ENTITLEMENTS_PAGE_SIZE)),
                None,
            )
            .await?;
        Ok(entitlements.iter().any(|e| e.attributes.code == code))
    }
}

/// Optional attributes for [`Client::create_machine`]/
/// [`Client::activate_machine`]. All fields default to `None` — construct
/// with [`Default::default()`] and set only what's known.
#[derive(Debug, Clone, Default)]
pub struct CreateMachineOptions {
    /// Optional display name.
    pub name: Option<String>,
    /// IP address to record.
    pub ip: Option<String>,
    /// Hostname to record.
    pub hostname: Option<String>,
    /// OS/platform string to record.
    pub platform: Option<String>,
    /// CPU core count to record.
    pub cores: Option<i32>,
    /// Memory in **megabytes** to record — not bytes. This value feeds the
    /// licence's `machines_memory_count` total and the policy's
    /// `max_memory` check, so reporting bytes here inflates the total by
    /// ~10^6 and trips `MEMORY_LIMIT_EXCEEDED` on the next activation. See
    /// [`crate::models::machine::MachineAttributes::memory`].
    pub memory: Option<i64>,
    /// Disk in **megabytes** to record — same units and same failure mode
    /// as `memory`.
    pub disk: Option<i64>,
    /// Arbitrary caller-set metadata; defaults to `{}` if `None`.
    pub metadata: Option<serde_json::Value>,
}

/// Whether a [`crate::models::validation::ValidationCode`] represents one
/// of the over-limit outcomes [`Client::activate_machine`]'s auto-delete
/// path reacts to.
fn is_overage_code(code: &crate::models::validation::ValidationCode) -> bool {
    use crate::models::validation::ValidationCode;
    matches!(
        code,
        ValidationCode::TooManyMachines
            | ValidationCode::TooManyCores
            | ValidationCode::TooMuchMemory
            | ValidationCode::TooMuchDisk
            | ValidationCode::TooManyProcesses
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::AuthTransport;

    #[test]
    fn builder_sets_required_fields() {
        let config = ClientConfig::builder("acc-123", "api.tamga.sh")
            .auth(AuthTransport::License("lic-abc".to_string()))
            .build();
        assert_eq!(config.account_id, "acc-123");
        assert_eq!(config.host, "api.tamga.sh");
    }

    #[test]
    fn builder_defaults_api_version_to_1_8() {
        let config = ClientConfig::builder("acc-123", "api.tamga.sh")
            .auth(AuthTransport::License("lic-abc".to_string()))
            .build();
        assert_eq!(config.api_version, "1.8");
    }

    #[test]
    fn builder_defaults_timeout_above_the_servers_own_deadline() {
        let config = ClientConfig::builder("acc-123", "api.tamga.sh")
            .auth(AuthTransport::License("lic-abc".to_string()))
            .build();
        assert_eq!(config.timeout, std::time::Duration::from_secs(45));
        assert!(
            config.timeout > std::time::Duration::from_secs(30),
            "must outlast the server's own 30s timeout so its 504 (which \
             carries X-Request-Id) wins the race, not a local timeout"
        );
    }

    #[test]
    fn builder_allows_overriding_api_version_and_timeout() {
        let config = ClientConfig::builder("acc-123", "api.tamga.sh")
            .auth(AuthTransport::License("lic-abc".to_string()))
            .api_version("2.0")
            .timeout(std::time::Duration::from_secs(5))
            .build();
        assert_eq!(config.api_version, "2.0");
        assert_eq!(config.timeout, std::time::Duration::from_secs(5));
    }

    #[test]
    fn base_url_has_no_trailing_slash() {
        let config = ClientConfig::builder("acc-123", "api.tamga.sh")
            .auth(AuthTransport::License("lic-abc".to_string()))
            .build();
        assert_eq!(
            config.base_url(),
            "https://api.tamga.sh/v1/accounts/acc-123"
        );
    }

    #[test]
    fn base_url_strips_trailing_slash_from_host() {
        let config = ClientConfig::builder("acc-123", "api.tamga.sh/")
            .auth(AuthTransport::License("lic-abc".to_string()))
            .build();
        assert_eq!(
            config.base_url(),
            "https://api.tamga.sh/v1/accounts/acc-123"
        );
    }

    #[test]
    fn base_url_strips_scheme_if_caller_included_one() {
        let config = ClientConfig::builder("acc-123", "https://api.tamga.sh")
            .auth(AuthTransport::License("lic-abc".to_string()))
            .build();
        assert_eq!(
            config.base_url(),
            "https://api.tamga.sh/v1/accounts/acc-123"
        );
    }

    #[test]
    fn base_url_preserves_explicit_http_scheme_for_local_testing() {
        let config = ClientConfig::builder("acc-123", "http://127.0.0.1:8080")
            .auth(AuthTransport::License("lic-abc".to_string()))
            .build();
        assert_eq!(
            config.base_url(),
            "http://127.0.0.1:8080/v1/accounts/acc-123"
        );
    }

    #[test]
    fn client_new_succeeds_with_valid_config() {
        let config = ClientConfig::builder("acc-123", "api.tamga.sh")
            .auth(AuthTransport::License("lic-abc".to_string()))
            .build();
        let client = Client::new(config);
        assert!(client.is_ok());
    }
}
