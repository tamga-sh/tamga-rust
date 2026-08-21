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
//!   [`Client::get_machine`], [`Client::list_machines`],
//!   [`Client::update_machine`], [`Client::ping_heartbeat`],
//!   [`Client::reset_heartbeat`], [`Client::delete_machine`], plus
//!   [`Client::activate_machine`] and
//!   [`Client::activate_machine_idempotent`], which compose create +
//!   validate + optional auto-delete-on-overage.
//! - Machine offline proof: [`Client::generate_offline_proof`].
//! - Components & processes: [`Client::create_component`],
//!   [`Client::list_components`], [`Client::create_process`],
//!   [`Client::ping_process`], [`Client::list_machine_processes`],
//!   [`Client::delete_process`], [`Client::delete_machine_processes`].
//! - Entitlements: [`Client::list_entitlements`],
//!   [`Client::list_license_entitlements`], [`Client::get_entitlement`],
//!   [`Client::has_entitlement`].
//! - Licence and policy reads: [`Client::get_license`],
//!   [`Client::get_license_policy`], [`Client::get_policy`], and the
//!   heartbeat sizing they enable —
//!   [`Client::effective_heartbeat_window`],
//!   [`Client::recommended_heartbeat_interval`].
//! - Auto-update: [`Client::check_for_upgrade`].
//! - Liveness: [`Client::health`].
//!
//! **Two routes here break the module's own rules and say so at their own
//! doc comments.** [`Client::list_machines`] is offset paginated where every
//! other listing is keyset (see [`crate::models::page`]), and
//! [`Client::health`] is neither account-scoped, JSON:API-enveloped, nor
//! authenticated.
//!
//! Every method sends the configured [`crate::transport::AuthTransport`]'s
//! credentials, with one deliberate exception ([`Client::health`], for the
//! reason given there). Auth **is** enforced server-side on every other
//! endpoint here: a missing or unrecognized credential is `401`, a
//! valid-but-insufficient one `403`. Licence-key auth additionally requires
//! the licence's policy to set `authentication_strategy` to `LICENSE` or
//! `MIXED` — the column defaults to `'TOKEN'`, under which every request with
//! a licence key is refused with `401 LICENSE_NOT_ALLOWED`. See
//! [`crate::error::LicenseAuthCode`].
//!
//! **Which of these a licence key can call.** The `LicenseToken` role holds a
//! fixed permission set, intersected with the token's own, so it cannot be
//! widened by configuration. Of the routes added here it holds `machine.read`
//! ([`Client::get_machine`], [`Client::list_machines`]), `machine.update`
//! ([`Client::update_machine`]), `process.read`/`process.delete`
//! ([`Client::list_machine_processes`], [`Client::delete_process`]) and
//! `license.read` ([`Client::get_license`], [`Client::get_license_policy`]).
//! It does **not** hold `policy.read`, so [`Client::get_policy`] answers
//! `403` for a licence key — [`Client::get_license_policy`] is the route to
//! the same resource that works.
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

/// The server's maximum `page[size]` on the **offset**-paginated collection
/// routes — `GET /machines` is the only one this crate calls.
///
/// Same ceiling as [`MAX_ENTITLEMENTS_PAGE_SIZE`], reached through a
/// different code path (`list_query::resolve` clamps it, rather than each
/// hand-written keyset query), and named separately because the two
/// pagination styles are not interchangeable — see
/// [`crate::models::page`].
pub const MAX_OFFSET_PAGE_SIZE: i64 = 100;

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
        format!("{}/v1/accounts/{}", self.origin_url(), self.account_id)
    }

    /// `https://<host>` — the configured origin with **no** account segment.
    ///
    /// [`Self::base_url`] appends `/v1/accounts/{account_id}` unconditionally,
    /// which is correct for every route this client called until now and wrong
    /// for exactly one: `GET /v1/health` sits outside the account tree
    /// entirely. Rather than special-casing the account segment away inside
    /// the request builder, the two forms are separate methods, so a route
    /// that must not be account-scoped says so at the call site.
    ///
    /// Same scheme handling as [`Self::base_url`]: a trailing slash is
    /// stripped, an explicit `http://` is preserved rather than upgraded.
    pub fn origin_url(&self) -> String {
        let trimmed = self.host.trim_end_matches('/');
        if let Some(host) = trimmed.strip_prefix("http://") {
            format!("http://{host}")
        } else {
            let host = trimmed.strip_prefix("https://").unwrap_or(trimmed);
            format!("https://{host}")
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
    /// Identical to `http` except that it follows **no** redirects.
    ///
    /// Used only by [`Client::artifact_download_url`]. That route answers
    /// `303 See Other` to a presigned storage URL unless asked not to, and
    /// `reqwest`'s default policy follows up to 10 redirects — carrying this
    /// client's `Authorization` header along whenever the hop stays on the
    /// same host and port, which a deployment fronting object storage on its
    /// own origin does. `?redirect=false` is what actually prevents the 303,
    /// and this is the second line: if a server or an intermediary ever
    /// answers one anyway, it surfaces as a non-success status instead of
    /// being followed.
    ///
    /// Deliberately not applied to `http`: every other route ships in a
    /// patch release, and none of them redirects today, so tightening their
    /// behaviour is not this change's to make.
    pub(crate) no_redirect_http: reqwest::Client,
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
        let no_redirect_http = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent(concat!("tamga-rust/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(crate::TamgaError::Http)?;
        Ok(Client {
            http,
            no_redirect_http,
            config,
        })
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
        self.request_on(&self.http, method, path, otp)
    }

    /// [`Self::request`] against an explicitly chosen underlying client.
    ///
    /// Exists so [`Self::artifact_download_url`] can use the
    /// redirect-disabled client while every other endpoint keeps the default
    /// one; see the `no_redirect_http` field for why the two differ.
    fn request_on(
        &self,
        http: &reqwest::Client,
        method: reqwest::Method,
        path: &str,
        otp: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let url = format!("{}{path}", self.config.base_url());
        let mut builder = http.request(method, url);
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
            // Read the headers off the throttled response itself: the
            // middleware sets `x-ratelimit-*` on the `429` as well as on the
            // requests it lets through, and `x-ratelimit-reset` is the only
            // one of the two wait signals that survives a proxy stripping
            // `Retry-After`.
            let response_info = Box::new(crate::transport::ResponseInfo::from_headers(
                response.headers(),
            ));
            return crate::TamgaError::RateLimited {
                retry_after,
                response_info,
            };
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
    /// [`crate::models::machine::Pid`]). The only decrement is an explicit
    /// [`Self::delete_process`] — pair every create with one, on a shutdown
    /// path that actually runs, or the slot is held permanently. Reusing a
    /// stable PID rather than minting a fresh one per run bounds the damage
    /// if that path is missed.
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

    // ── Machine reads and updates ────────────────────────────────────────

    /// `GET /machines/{machine_id}` — the machine as the server currently
    /// sees it.
    ///
    /// This is a **read**, and that is what makes it different from every
    /// other machine route this client already had. The server resolves it
    /// through `queries::find_by_id`, which joins `policies`, so two fields
    /// mean something here that they cannot mean on a write response:
    ///
    /// - `heartbeat_status` **can be**
    ///   [`crate::models::machine::HeartbeatStatus::Dead`]. Ping, reset and
    ///   create all derive the status from a timestamp they just wrote, so
    ///   its age is ~0 and `Dead` is unreachable there. Nothing wrote this
    ///   row, so the staleness verdict is real. A `Dead` branch against
    ///   *this* response is live code.
    /// - `next_heartbeat_at` is computed against the policy's own
    ///   `heartbeat_duration` rather than the 600s fallback, so
    ///   [`crate::models::machine::MachineAttributes::observed_heartbeat_window`]
    ///   returns the genuine window.
    ///
    /// `Dead` still does **not** mean the row is gone — under the default
    /// policy (`require_heartbeat = false`) nothing is ever culled and a
    /// machine reports `Dead` indefinitely with its seat intact. Keep pinging
    /// it; the only terminal signal is a `404` from the ping itself.
    ///
    /// ⚠️ Not licence-scoped, and the resource cannot tell you whose it is.
    /// The handler checks the `machine.read` permission and the account and
    /// nothing else — no machine route calls the server's
    /// `require_license_scope` — so a licence-key caller can read (and patch,
    /// and delete) any machine in the account. The response is no help
    /// either: [`crate::models::machine::MachineAttributes`] carries no
    /// `license_id` and no `relationships`, because the server's serializer
    /// emits neither. To establish that a machine is on a given licence you
    /// must ask the server, via
    /// [`ListMachinesOptions::license_id`]. Do not present any of this as an
    /// access control this SDK enforces.
    pub async fn get_machine(
        &self,
        machine_id: uuid::Uuid,
    ) -> Result<crate::models::machine::MachineResource, crate::TamgaError> {
        self.send_json_api(
            reqwest::Method::GET,
            &format!("/machines/{machine_id}"),
            None,
            None,
        )
        .await
    }

    /// `GET /machines` — the account's machine collection, **offset**
    /// paginated.
    ///
    /// ⚠️ **This route does not paginate the way anything else here does.**
    /// It is the one collection this crate calls that runs through the
    /// server's shared list-query layer: it takes `page[number]`/`page[size]`
    /// and returns `meta.page` with a real total. `page[after]` is not a
    /// parameter it understands, and passing one is silently ignored rather
    /// than rejected. See [`crate::models::page`] for the table of which
    /// route uses which style, and why they are separate types.
    ///
    /// `page[size]` is clamped server-side to [`MAX_OFFSET_PAGE_SIZE`] and
    /// defaults to 25; read the effective value back from
    /// [`crate::models::page::OffsetPageMeta::size`] rather than assuming the
    /// one you asked for. Use
    /// [`crate::models::page::OffsetPage::next_page_number`] to advance —
    /// a full page is not evidence that another one exists.
    ///
    /// Like [`Self::get_machine`] this is a policy-joined read, so
    /// `heartbeat_status` here can be `Dead` and `next_heartbeat_at` reflects
    /// the real window.
    ///
    /// ⚠️ Not licence-scoped, same as [`Self::get_machine`]: without
    /// [`ListMachinesOptions::license_id`] a licence-key caller sees every
    /// machine in the account.
    pub async fn list_machines(
        &self,
        opts: ListMachinesOptions,
    ) -> Result<
        crate::models::page::OffsetPage<crate::models::machine::MachineResource>,
        crate::TamgaError,
    > {
        #[derive(serde::Deserialize)]
        struct PageEnvelope<T> {
            data: Vec<T>,
            meta: PageMetaEnvelope,
        }

        #[derive(serde::Deserialize)]
        struct PageMetaEnvelope {
            page: crate::models::page::OffsetPageMeta,
        }

        let path = "/machines";
        let mut builder = self.request(reqwest::Method::GET, path, None);
        if let Some(license_id) = opts.license_id {
            builder = builder.query(&[("filter[license]", license_id.to_string())]);
        }
        if let Some(ref platform) = opts.platform {
            builder = builder.query(&[("filter[platform]", platform.as_str())]);
        }
        if let Some(ref search) = opts.search {
            builder = builder.query(&[("filter[q]", search.as_str())]);
        }
        if let Some(number) = opts.page_number {
            builder = builder.query(&[("page[number]", number.to_string())]);
        }
        if let Some(size) = opts.page_size {
            builder = builder.query(&[("page[size]", size.to_string())]);
        }

        let response = self
            .send_with_retry(builder, &reqwest::Method::GET, path)
            .await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        let envelope: PageEnvelope<crate::models::machine::MachineResource> =
            response.json().await?;
        Ok(crate::models::page::OffsetPage {
            items: envelope.data,
            page: envelope.meta.page,
        })
    }

    /// The machine with exactly this `fingerprint`, or `None`.
    ///
    /// There is **no `filter[fingerprint]`** on the machine collection — the
    /// only fingerprint-aware parameter is the free-text `filter[q]`, which
    /// the server turns into a case-insensitive `ILIKE '%term%'` across
    /// `name`, `hostname` *and* `fingerprint`, truncated to 200 characters.
    /// So the search narrows the page and the exact match is made here, on
    /// `attributes.fingerprint`, byte for byte. Both steps err toward a
    /// superset, so a substring or case-folded hit on somebody else's
    /// hostname can never come back as a match.
    ///
    /// **`license_id` is not optional, and widening it would be a seat-sharing
    /// hole rather than a convenience.** It is sent as `filter[license]`, so
    /// every row the server returns is on that licence — and that filter is
    /// the *only* way to establish it, because
    /// [`crate::models::machine::MachineAttributes`] carries no `license_id`
    /// and no `relationships`; the server's machine serializer emits neither.
    /// A machine found without it cannot be attributed to a licence at all.
    ///
    /// A licence-scoped search never misses a genuine re-activation. All three
    /// `machine_uniqueness_strategy` `EXISTS` checks include the caller's own
    /// licence rows: `UNIQUE_PER_LICENSE` matches on `license_id` directly,
    /// `UNIQUE_PER_POLICY` joins licences sharing the policy (the caller's
    /// among them), and `UNIQUE_PER_ACCOUNT` covers every machine in the
    /// account. So re-activating your own machine raises
    /// `FINGERPRINT_TAKEN` under all three and this search finds it under all
    /// three. Widening the search adds exactly one case — a machine on
    /// *another* licence — which is the case the wider strategies exist to
    /// refuse.
    ///
    /// For the genuinely different question "is anything in the account
    /// holding this fingerprint?", call [`Self::list_machines`] with
    /// [`ListMachinesOptions::search`] directly. That result is
    /// unattributable by construction, and asking for it through the raw
    /// listing keeps that obvious.
    pub async fn find_machine_by_fingerprint(
        &self,
        license_id: uuid::Uuid,
        fingerprint: &str,
    ) -> Result<Option<crate::models::machine::MachineResource>, crate::TamgaError> {
        let mut page_number = 1i64;
        loop {
            let page = self
                .list_machines(ListMachinesOptions {
                    license_id: Some(license_id),
                    search: Some(fingerprint.to_string()),
                    page_number: Some(page_number),
                    page_size: Some(MAX_OFFSET_PAGE_SIZE),
                    ..Default::default()
                })
                .await?;

            if let Some(found) = page
                .items
                .iter()
                .find(|machine| machine.attributes.fingerprint == fingerprint)
            {
                return Ok(Some(found.clone()));
            }

            match page.next_page_number() {
                Some(next) => page_number = next,
                None => return Ok(None),
            }
        }
    }

    /// `PATCH /machines/{machine_id}` — updates the mutable attributes of an
    /// already-registered machine.
    ///
    /// ⚠️ **Every field is `COALESCE($n, column)` server-side, so `None`
    /// means "leave alone" and there is no way to clear a field back to
    /// null.** Sending `name: None` does not erase the name; nothing this
    /// endpoint accepts does. A machine whose hostname was recorded once
    /// keeps it forever unless it is overwritten with another value.
    ///
    /// `fingerprint` is deliberately absent from
    /// [`UpdateMachineOptions`]: the server's update statement does not touch
    /// that column, and it is the identity the uniqueness constraint is
    /// built on.
    ///
    /// ⚠️ **Limits are not re-checked here.** Raising `cores`, `memory` or
    /// `disk` adjusts the licence's running totals — and can therefore push
    /// the licence over `max_cores`/`max_memory`/`max_disk` — but the update
    /// itself is never refused for it. The overage surfaces on the next
    /// validate, as `TooManyCores`/`TooMuchMemory`/`TooMuchDisk`.
    ///
    /// `memory` and `disk` are **megabytes**, exactly as on
    /// [`CreateMachineOptions`].
    ///
    /// ⚠️ **This is a write whose response can still report
    /// [`crate::models::machine::HeartbeatStatus::Dead`].** It is the
    /// counterexample to the "a write response can never say `Dead`" rule:
    /// the `UPDATE` touches no heartbeat column, so the status is derived
    /// from a `last_heartbeat_at` that is as old as it was before the call.
    /// The verdict is genuine — branch on it. `next_heartbeat_at`, however,
    /// is *not*: the statement's `RETURNING` list selects no policy column,
    /// so the deadline is computed against the 600s fallback here, exactly
    /// as on ping and create.
    ///
    /// ⚠️ Not licence-scoped. `machine.update` is in the `LicenseToken`
    /// role's permission set and no machine route calls the server's
    /// `require_license_scope`, so a licence key can patch any machine in the
    /// account — as it can [`Self::delete_machine`] any of them. Reported
    /// upstream; do not read this method as enforcing an ownership boundary.
    pub async fn update_machine(
        &self,
        machine_id: uuid::Uuid,
        opts: UpdateMachineOptions,
    ) -> Result<crate::models::machine::MachineResource, crate::TamgaError> {
        let body = serde_json::json!({
            "data": {
                "type": "machines",
                "attributes": {
                    "name": opts.name,
                    "ip": opts.ip,
                    "hostname": opts.hostname,
                    "platform": opts.platform,
                    "cores": opts.cores,
                    "memory": opts.memory,
                    "disk": opts.disk,
                    "metadata": opts.metadata,
                }
            }
        });
        self.send_json_api(
            reqwest::Method::PATCH,
            &format!("/machines/{machine_id}"),
            Some(body),
            None,
        )
        .await
    }

    /// `GET /machines/{machine_id}/processes` — keyset-paginated (`limit`,
    /// `page[after]`), same shape and same caveats as
    /// [`Self::list_components`].
    ///
    /// The cursor on this route is real and does advance — pass the last
    /// returned process's `id` as `after`. Pass `limit` explicitly: the
    /// server defaults to [`DEFAULT_SERVER_PAGE_SIZE`], clamps to
    /// [`MAX_ENTITLEMENTS_PAGE_SIZE`], and sends no page metadata, so a
    /// caller that did not choose the limit cannot tell a full page from a
    /// final one.
    ///
    /// This is the listing [`Self::delete_machine_processes`] walks to find
    /// what to release.
    pub async fn list_machine_processes(
        &self,
        machine_id: uuid::Uuid,
        limit: Option<u32>,
        after: Option<uuid::Uuid>,
    ) -> Result<Vec<crate::models::machine::ProcessResource>, crate::TamgaError> {
        #[derive(serde::Deserialize)]
        struct Envelope {
            data: Vec<crate::models::machine::ProcessResource>,
        }

        let path = format!("/machines/{machine_id}/processes");
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

    // ── Idempotent activation ────────────────────────────────────────────

    /// [`Self::activate_machine`], but a machine that is *already* activated
    /// on this licence is adopted instead of raising
    /// [`crate::TamgaError::FingerprintTaken`].
    ///
    /// Re-running an activation is the normal case, not an error case: an
    /// application restarts, reinstalls, or loses the machine id it stored,
    /// and asks to activate the same fingerprint again. The server answers
    /// `409 FINGERPRINT_TAKEN` — deliberately, its own comment calls this
    /// "already activated, carry on" — and until now the only exit from that
    /// was a raw error the caller had no route to resolve.
    ///
    /// The recovery is a lookup, not an assumption, and the difference
    /// matters. `FINGERPRINT_TAKEN` is raised against the scope the policy's
    /// `machine_uniqueness_strategy` names, which is **not always this
    /// licence**:
    ///
    /// | Strategy | The conflicting machine is on |
    /// |---|---|
    /// | `UNIQUE_PER_LICENSE` (default) | this licence — adopting it is right |
    /// | `UNIQUE_PER_POLICY` | possibly another licence sharing the policy |
    /// | `UNIQUE_PER_ACCOUNT` | possibly any licence in the account |
    ///
    /// Under the two wider strategies the conflict is the anti-seat-sharing
    /// check doing its job, and handing the caller a machine belonging to a
    /// different licence would defeat it. So the conflict is resolved through
    /// [`Self::find_machine_by_fingerprint`], scoped to `license_id`: found
    /// means genuine re-activation and the machine comes back with
    /// [`MachineActivation::reused`] set; not found means the fingerprint is
    /// held elsewhere and the original `409` propagates untouched.
    ///
    /// The scoping is not a preference, it is the only thing that makes the
    /// answer checkable. A [`crate::models::machine::MachineResource`] carries
    /// no `license_id` and no `relationships` — the server's serializer emits
    /// neither — so a machine found by an account-wide search cannot be
    /// attributed to a licence by inspecting it. `filter[license]` is where
    /// that guarantee comes from, and it costs nothing: all three uniqueness
    /// strategies raise the conflict for the caller's own rows too, so a
    /// genuine re-activation is always inside the scoped search.
    ///
    /// What a cross-licence hit would cost, had it been returned: the client
    /// would heartbeat and check out a machine its licence does not own while
    /// its own `machines_count` stayed at zero, and — carrying no
    /// `license_id` — would have no way to notice.
    ///
    /// ⚠️ `auto_delete_on_overage` **never deletes an adopted machine.**
    /// Rolling back is only meaningful for a row this call created; deleting
    /// a pre-existing machine because the licence is over its limit would
    /// destroy a seat the caller did not create and cannot get back. On the
    /// adopted path an over-limit verdict is returned as-is, with the machine
    /// still in place.
    ///
    /// Over-limit **creation** behaves exactly as in
    /// [`Self::activate_machine`], including the strict-policy path where no
    /// row is created and [`MachineActivation::machine`] is `None`.
    pub async fn activate_machine_idempotent(
        &self,
        license_id: uuid::Uuid,
        fingerprint: &str,
        opts: CreateMachineOptions,
        scope: Option<crate::models::validation::ScopeObject>,
        auto_delete_on_overage: bool,
    ) -> Result<MachineActivation, crate::TamgaError> {
        let (machine, reused) = match self.create_machine(license_id, fingerprint, opts).await {
            Ok(machine) => (Some(machine), false),
            Err(err) if matches!(err, crate::TamgaError::FingerprintTaken(_)) => {
                match self
                    .find_machine_by_fingerprint(license_id, fingerprint)
                    .await?
                {
                    Some(existing) => (Some(existing), true),
                    // The fingerprint is taken, but not on this licence —
                    // a wider `machine_uniqueness_strategy` is refusing a
                    // second seat for it. That is not a re-activation.
                    None => return Err(err),
                }
            }
            Err(err) => match err.limit_exceeded() {
                Some(limit) => {
                    let validation = self
                        .over_limit_result_without_machine(license_id, scope, limit, err)
                        .await?;
                    return Ok(MachineActivation {
                        machine: None,
                        validation,
                        reused: false,
                    });
                }
                None => return Err(err),
            },
        };

        let validation = self.validate_by_id(license_id, scope, false, None).await?;

        // Only a row this call created is ours to roll back.
        if auto_delete_on_overage && !reused && is_overage_code(&validation.meta.code) {
            if let Some(ref machine) = machine {
                let _ = self.delete_machine(machine.id).await;
            }
        }

        Ok(MachineActivation {
            machine,
            validation,
            reused,
        })
    }

    // ── Processes: releasing what nothing else releases ──────────────────

    /// `DELETE /processes/{process_id}` — `204 No Content` on success.
    ///
    /// **This is the only thing that ever removes a process row**, and the
    /// only thing that returns its slot against the policy's
    /// `max_processes`. The server's 30-second process window and its
    /// delete-on-expiry sweep are both written and both dead: neither has a
    /// call site and the job scheduler wires no process tick, so no process
    /// is marked dead, no `process.heartbeat.dead` event fires, and nothing
    /// is reaped. [`Self::create_process`] increments the licence's
    /// `machines_process_count` and this call is the only decrement.
    ///
    /// A client that registers a process per run and never calls this
    /// exhausts `max_processes` permanently — the rows outlive the processes
    /// by an unbounded margin. Call it on shutdown, or use
    /// [`Self::delete_machine_processes`] to release a machine's whole set.
    ///
    /// There is no `Drop`-based equivalent: `Drop` cannot be `async`, and a
    /// blocking HTTP call inside one would deadlock the very runtime that has
    /// to drive it. Release is explicit here on purpose.
    ///
    /// A process that is already gone answers `404`
    /// ([`crate::TamgaError::NotFound`]) rather than succeeding silently.
    pub async fn delete_process(&self, process_id: uuid::Uuid) -> Result<(), crate::TamgaError> {
        let response = self
            .request(
                reqwest::Method::DELETE,
                &format!("/processes/{process_id}"),
                None,
            )
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        Ok(())
    }

    /// Deletes every process registered against `machine_id`, returning how
    /// many rows were removed — the shutdown counterpart to
    /// [`Self::create_process`].
    ///
    /// Walks [`Self::list_machine_processes`] and calls
    /// [`Self::delete_process`] on each. The listing is re-read from the
    /// first page after each batch rather than paged forward with a cursor:
    /// the rows are being deleted underneath it, so a keyset cursor pointing
    /// at a row that no longer exists would skip its successors.
    ///
    /// A `404` on an individual delete is counted as success — the goal is
    /// that the row is gone, and a concurrent caller getting there first
    /// satisfies that. Any other error aborts and propagates; the processes
    /// deleted before it stay deleted.
    ///
    /// The machine itself is left alone. It is the seat the licence paid for,
    /// and deleting it would force a fresh activation on the next run — use
    /// [`Self::delete_machine`] explicitly if that is really what you want.
    pub async fn delete_machine_processes(
        &self,
        machine_id: uuid::Uuid,
    ) -> Result<usize, crate::TamgaError> {
        let mut deleted = 0usize;
        loop {
            let batch = self
                .list_machine_processes(machine_id, Some(MAX_ENTITLEMENTS_PAGE_SIZE), None)
                .await?;
            if batch.is_empty() {
                return Ok(deleted);
            }
            for process in &batch {
                match self.delete_process(process.id).await {
                    Ok(()) => deleted += 1,
                    // Already gone is the outcome we wanted.
                    Err(crate::TamgaError::NotFound(_)) => {}
                    Err(err) => return Err(err),
                }
            }
        }
    }

    // ── Licence and policy reads ─────────────────────────────────────────

    /// `GET /licenses/{license_id}` — the licence resource on its own,
    /// without the `last_validated_at` write [`Self::validate_by_id`]
    /// performs.
    ///
    /// ⚠️ **This route is not licence-scoped, and `attributes.key` is
    /// plaintext.** The handler checks the `license.read` permission and the
    /// account; it does not call the server's own `require_license_scope`,
    /// which is what confines a licence-key credential to its own licence on
    /// validate and check-out. A licence key can therefore read *any* licence
    /// in the account, key included. Reported upstream; the SDK cannot fix it
    /// and must not describe this surface as scoped.
    ///
    /// Prefer [`Self::validate_by_id`] with `skip_touch: true` when what you
    /// actually want is a verdict — this route reports the licence's stored
    /// `status` string, not a validation outcome, and knows nothing about
    /// scopes, machine counts or entitlements.
    pub async fn get_license(
        &self,
        license_id: uuid::Uuid,
    ) -> Result<crate::models::license::LicenseResource, crate::TamgaError> {
        self.send_json_api(
            reqwest::Method::GET,
            &format!("/licenses/{license_id}"),
            None,
            None,
        )
        .await
    }

    /// `GET /licenses/{license_id}/policy` — the policy governing this
    /// licence.
    ///
    /// **This is the policy route an embedded client can actually call.** It
    /// is gated on `license.read`, which the `LicenseToken` role holds, while
    /// [`Self::get_policy`] is gated on `policy.read`, which it does not — so
    /// a licence-key caller gets the policy here and a `403` there. The two
    /// return the identical resource.
    ///
    /// It carries the same missing licence-scope check as
    /// [`Self::get_license`]; see that method.
    ///
    /// This is the read that makes a policy-aware heartbeat interval possible
    /// — see [`Self::effective_heartbeat_window`].
    pub async fn get_license_policy(
        &self,
        license_id: uuid::Uuid,
    ) -> Result<crate::models::policy::Policy, crate::TamgaError> {
        self.send_json_api(
            reqwest::Method::GET,
            &format!("/licenses/{license_id}/policy"),
            None,
            None,
        )
        .await
    }

    /// `GET /policies/{policy_id}` — a policy by its own id.
    ///
    /// ⚠️ **Requires the `policy.read` permission, which a licence key does
    /// not have.** The `LicenseToken` role's fixed permission set omits it,
    /// and permissions are intersected rather than granted, so no token
    /// configuration adds it back: authenticating with
    /// [`crate::transport::AuthTransport::License`] gets `403` here every
    /// time. Use [`Self::get_license_policy`] instead, which reaches the same
    /// resource through a permission the licence-key role does hold.
    ///
    /// This method is for back-office credentials — an admin or product
    /// token — that hold a policy id directly.
    pub async fn get_policy(
        &self,
        policy_id: uuid::Uuid,
    ) -> Result<crate::models::policy::Policy, crate::TamgaError> {
        self.send_json_api(
            reqwest::Method::GET,
            &format!("/policies/{policy_id}"),
            None,
            None,
        )
        .await
    }

    // ── Policy-aware heartbeat scheduling ────────────────────────────────

    /// The heartbeat window the server will judge this licence's machines
    /// against, read from its policy.
    ///
    /// This closes the gap that made every documented interval in this crate
    /// a guess. The window is `policy.heartbeat_duration` and falls back to
    /// [`crate::models::policy::DEFAULT_HEARTBEAT_WINDOW_SECS`] only when
    /// that column is null; the cull job's claim query selects on the same
    /// `COALESCE(p.heartbeat_duration, 600)`. Under a policy asking for less
    /// than 600s, a client pinging on the fallback pings too slowly and its
    /// machines fall outside the window on schedule.
    ///
    /// One round trip, via [`Self::get_license_policy`]. Read it once at
    /// startup and size the timer from it — do **not** call it per tick.
    ///
    /// The alternative, `next_heartbeat_at` on a ping response, does not
    /// work: that field is computed against the 600s fallback on exactly the
    /// routes a scheduler calls. See
    /// [`crate::models::machine::MachineAttributes::observed_heartbeat_window`].
    pub async fn effective_heartbeat_window(
        &self,
        license_id: uuid::Uuid,
    ) -> Result<std::time::Duration, crate::TamgaError> {
        let policy = self.get_license_policy(license_id).await?;
        Ok(policy.attributes.effective_heartbeat_window())
    }

    /// [`Self::effective_heartbeat_window`] divided by
    /// [`crate::models::policy::HEARTBEAT_INTERVAL_DIVISOR`] — the ping
    /// interval to schedule for this licence's machines.
    ///
    /// 200s under the 600s fallback. Never zero.
    ///
    /// This crate ships no heartbeat scheduler (see the SDK divergence
    /// register): starting a background task on a caller's behalf is a
    /// decision that belongs to the application embedding it. This is the
    /// number that task needs.
    pub async fn recommended_heartbeat_interval(
        &self,
        license_id: uuid::Uuid,
    ) -> Result<std::time::Duration, crate::TamgaError> {
        let policy = self.get_license_policy(license_id).await?;
        Ok(policy.attributes.recommended_heartbeat_interval())
    }

    // ── Signing keys ─────────────────────────────────────────────────────

    /// `GET /signing-keys` — every Ed25519 signing key the account has held,
    /// retired ones included.
    ///
    /// Retired keys are the point. An offline file names its signer with a
    /// `kid` claim, and a file signed before the last rotation needs the key
    /// that signed it, not the current one; without this route a client's only
    /// options are to fail verification or to accept any key, and the second
    /// defeats signing entirely. Feed the result to
    /// [`crate::checkout::key_set::SigningKeySet::from_resources`], or use
    /// [`Self::signing_key_set`] to do both in one call.
    ///
    /// ⚠️ **A raw licence key cannot call this route.** It is gated on
    /// `account.read`, and `Role::LicenseToken` — what
    /// [`crate::transport::AuthTransport::License`] resolves to — holds a
    /// fixed permission set that does not include it, so an embedded
    /// licence-key client gets [`crate::TamgaError::Forbidden`] here no matter
    /// how the account is configured. Same shape as
    /// `GET /policies/{id}`, and unlike that one there is no equivalent route
    /// reachable through a permission the role does hold. Two ways round it:
    /// fetch the key set with a back-office token and ship the public keys
    /// with the application
    /// ([`crate::checkout::key_set::SigningKeySet::from_public_keys`] takes
    /// them directly), or have the application's own backend proxy this call.
    ///
    /// The resource `id` **is** the `kid` — not a UUID like every other
    /// resource this crate returns. See [`crate::models::signing_key`].
    pub async fn list_signing_keys(
        &self,
    ) -> Result<Vec<crate::models::signing_key::SigningKeyResource>, crate::TamgaError> {
        self.send_json_api(reqwest::Method::GET, "/signing-keys", None, None)
            .await
    }

    /// [`Self::list_signing_keys`], returned as a ready-to-verify
    /// [`crate::checkout::key_set::SigningKeySet`].
    ///
    /// One call, and the result is worth holding for the life of the process:
    /// a rotation adds a key rather than invalidating the ones already there,
    /// so a cached set only ever goes stale for files signed *after* it was
    /// fetched — which is exactly the case
    /// [`crate::error::CheckoutError::UnknownSigningKey`] names, and the
    /// signal to fetch again.
    ///
    /// Carries the same licence-key restriction as
    /// [`Self::list_signing_keys`].
    pub async fn signing_key_set(
        &self,
    ) -> Result<crate::checkout::key_set::SigningKeySet, crate::TamgaError> {
        let keys = self.list_signing_keys().await?;
        Ok(crate::checkout::key_set::SigningKeySet::from_resources(
            &keys,
        ))
    }

    // ── Auto-update ──────────────────────────────────────────────────────

    /// `GET /releases/actions/upgrade` — is there a newer release this caller
    /// may have?
    ///
    /// ⚠️ **A `NoUpdateOffered` answer does not mean you are up to date.**
    /// The server returns `204 No Content` for two different situations and
    /// that is deliberate:
    ///
    /// 1. there is no newer release; or
    /// 2. there **is** one, but this licence has expired under a policy that
    ///    stops it receiving new builds.
    ///
    /// The server's own comment gives the reason: a denial in case 2 would
    /// leak "a newer version exists but you cannot have it", and `204` is the
    /// honest answer to "is there an update *for you*" in both cases. There
    /// is no client-side way to tell them apart and there should not be — so
    /// report this to a user as *no update available*, never as *you are on
    /// the latest version*. See [`UpgradeCheck::NoUpdateOffered`].
    ///
    /// A **suspended** licence is a third outcome and is not folded in: it
    /// gets `403` ([`crate::TamgaError::Forbidden`]), because a suspension is
    /// the licence's own state rather than information about a release.
    ///
    /// The route is `OptionalAuth`: a product whose distribution strategy is
    /// `Open` answers it without any credential, so an auto-updater keeps
    /// working before activation. This client sends its configured credential
    /// regardless, which is what makes case 2 reachable at all — an
    /// unauthenticated call cannot be entitlement-filtered.
    ///
    /// Four of [`UpgradeQuery`]'s fields are required server-side —
    /// `product`, `platform`, `filetype`, `version` — so they are not
    /// `Option` here; omitting one is a `400`, not a broader search.
    ///
    /// The failure outcomes are not all folded into `NoUpdateOffered`: an
    /// unknown `product_id` is `404` ([`crate::TamgaError::NotFound`]), and
    /// the product's distribution-strategy gate runs before any of the
    /// release logic, so a non-`Open` product answers `401`/`403` to a caller
    /// whose credential it does not accept.
    pub async fn check_for_upgrade(
        &self,
        query: UpgradeQuery,
    ) -> Result<UpgradeCheck, crate::TamgaError> {
        #[derive(serde::Deserialize)]
        struct Envelope {
            data: crate::models::release::ReleaseResource,
        }

        let path = "/releases/actions/upgrade";
        let mut builder = self.request(reqwest::Method::GET, path, None).query(&[
            ("product", query.product_id.to_string()),
            ("platform", query.platform),
            ("filetype", query.filetype),
            ("version", query.version),
        ]);
        if let Some(channel) = query.channel {
            builder = builder.query(&[("channel", channel)]);
        }
        if let Some(constraint) = query.constraint {
            builder = builder.query(&[("constraint", constraint)]);
        }

        let response = self
            .send_with_retry(builder, &reqwest::Method::GET, path)
            .await?;
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(UpgradeCheck::NoUpdateOffered);
        }
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        let envelope: Envelope = response.json().await?;
        Ok(UpgradeCheck::Available(Box::new(envelope.data)))
    }

    // ── Artifacts ────────────────────────────────────────────────────────
    //
    // `Role::LicenseToken` already carried `artifact.read`, so the listing and
    // show routes were always reachable with a licence key. Only the bytes
    // were blocked: `artifact.download` was in no role's default list at all,
    // so the download route — which did exist — answered `403` to the
    // credential this SDK is built around. The server granted it to
    // `Role::LicenseToken` and gated the route on the owning release's access
    // check in the same change.
    //
    // Create, update, delete and upload stay out of scope deliberately:
    // `artifact.create`/`update`/`delete` are absent from that role, so a
    // licence key cannot reach them at all.

    /// `GET /releases/{release_id}/artifacts` — the artifacts a release
    /// distributes.
    ///
    /// Keyset paginated, like [`Self::list_components`] and
    /// [`Self::list_machine_processes`] and unlike [`Self::list_machines`]:
    /// pass the last row's `id` as `after` to advance. `limit` is clamped
    /// server-side to `1..=100` and defaults to 25; the response carries no
    /// page metadata, so a short page is the only end-of-listing signal.
    ///
    /// Requires `artifact.read`, which `Role::LicenseToken` now holds.
    ///
    /// Note this route checks the permission and nothing else — unlike
    /// [`Self::artifact_download_url`], it does **not** enforce the owning
    /// release's access gate, so a CLOSED release's artifact metadata lists
    /// here even though its bytes cannot be fetched.
    pub async fn list_release_artifacts(
        &self,
        release_id: uuid::Uuid,
        limit: Option<u32>,
        after: Option<uuid::Uuid>,
    ) -> Result<Vec<crate::models::artifact::ArtifactResource>, crate::TamgaError> {
        #[derive(serde::Deserialize)]
        struct Envelope {
            data: Vec<crate::models::artifact::ArtifactResource>,
        }

        let path = format!("/releases/{release_id}/artifacts");
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

    /// `GET /artifacts/{artifact_id}` — one artifact's metadata.
    ///
    /// `redirect_url` is **absent** here; only
    /// [`Self::artifact_download_url`] populates it.
    ///
    /// Requires `artifact.read`. Like the listing, this route enforces the
    /// permission alone and not the owning release's gate.
    pub async fn get_artifact(
        &self,
        artifact_id: uuid::Uuid,
    ) -> Result<crate::models::artifact::ArtifactResource, crate::TamgaError> {
        #[derive(serde::Deserialize)]
        struct Envelope {
            data: crate::models::artifact::ArtifactResource,
        }

        let path = format!("/artifacts/{artifact_id}");
        let builder = self.request(reqwest::Method::GET, &path, None);
        let response = self
            .send_with_retry(builder, &reqwest::Method::GET, &path)
            .await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        let envelope: Envelope = response.json().await?;
        Ok(envelope.data)
    }

    /// `GET /artifacts/{artifact_id}/actions/download?redirect=false` — the
    /// artifact with its short-lived presigned storage URL in
    /// [`crate::models::artifact::ArtifactAttributes::redirect_url`].
    ///
    /// # `redirect=false` is a security requirement, not a preference
    ///
    /// Left to itself this route answers **`303 See Other`** pointing at the
    /// storage host. `reqwest` follows up to 10 redirects by default and this
    /// crate sets no `reqwest::redirect::Policy`, so the request *would* be followed
    /// automatically — and every request this client makes carries either an
    /// `Authorization: License …` header or a `?token=` query parameter.
    ///
    /// What `reqwest` does with the credential across that hop was measured
    /// against the version this crate builds on, not inferred — see
    /// `measured_reqwest_strips_authorization_across_an_origin_boundary` and
    /// `measured_reqwest_keeps_authorization_within_one_origin` in
    /// `tests/artifacts.rs`:
    ///
    /// - **cross-origin**, the `Authorization` header is dropped. The usual
    ///   S3 case does not leak the key.
    /// - **same-origin**, it arrives intact. This is not hypothetical: the
    ///   server's `s3_endpoint` and `s3_force_path_style` settings allow
    ///   object storage on the API's own origin, and that configuration hands
    ///   the licence key to the storage host.
    ///
    /// The mitigation is also headers-only, so it does nothing for
    /// [`crate::transport::AuthTransport::Query`], whose credential rides in
    /// the query string.
    ///
    /// There is a second reason not to follow the redirect that holds in
    /// **every** configuration, credentials aside: following it buffers the
    /// artifact's bytes before anything can reject them, and an artifact
    /// routinely exceeds any sane response cap — the server admits uploads up
    /// to 1 GiB, and this method would then try to parse that as JSON.
    ///
    /// So this method defends twice. `redirect=false` is sent
    /// unconditionally — there is no code path here that omits it — and the
    /// request goes out on a redirect-disabled client, so a `303` from a
    /// server or intermediary that ignored the parameter surfaces as a
    /// non-success status rather than being followed. The URL is returned for
    /// the caller to fetch **with no credentials attached**.
    /// [`Self::download_artifact`] does exactly that; a caller who wants to
    /// stream to disk should use this method and fetch the URL itself, again
    /// with an unauthenticated client.
    ///
    /// Treat the returned URL as a bearer capability: it grants the bytes to
    /// anyone holding it until it expires. Do not log it.
    ///
    /// # `ttl`
    ///
    /// Seconds of validity for the presigned URL. The server **validates**
    /// rather than clamps: outside `[60s, 1 week]` it answers `422
    /// PRESIGN_TTL_INVALID` (`artifacts/service.rs:33`).
    ///
    /// Note that code is **not** the `TTL_INVALID` the checkout routes emit
    /// (`check_out_license.rs:48`), so it does **not** land on
    /// [`crate::TamgaError::TtlInvalidApi`] — the only typed TTL case this
    /// crate has. It arrives as the generic [`crate::TamgaError::Api`];
    /// match on `code` if you need to tell it apart. Adding a variant for it
    /// is not available: `TamgaError` is public and not `#[non_exhaustive]`,
    /// so that would be a breaking change.
    ///
    /// `None` leaves the server's own 300s default in place. Sub-second
    /// precision is truncated — the parameter is whole seconds on the wire.
    ///
    /// # A `403` here is not necessarily an auth misconfiguration
    ///
    /// This route enforces the owning **release's** read gate
    /// (`releases::service::enforce_release_access` — distribution strategy,
    /// suspension, expiry, entitlement) in addition to the `artifact.download`
    /// permission. A CLOSED release's binary is refused to a caller who holds
    /// the permission and whose licence is in perfect order. Check the
    /// release's distribution strategy and the licence's entitlements before
    /// concluding the token is wrong — [`Self::get_artifact`] and
    /// [`Self::list_release_artifacts`] succeeding while this returns `403`
    /// is the signature of exactly that.
    pub async fn artifact_download_url(
        &self,
        artifact_id: uuid::Uuid,
        ttl: Option<std::time::Duration>,
    ) -> Result<crate::models::artifact::ArtifactResource, crate::TamgaError> {
        #[derive(serde::Deserialize)]
        struct Envelope {
            data: crate::models::artifact::ArtifactResource,
        }

        let path = format!("/artifacts/{artifact_id}/actions/download");
        // Unconditional: see this method's doc comment. There is no code path
        // here that lets the 303 be followed.
        let mut builder = self
            .request_on(&self.no_redirect_http, reqwest::Method::GET, &path, None)
            .query(&[("redirect", "false")]);
        if let Some(ttl) = ttl {
            builder = builder.query(&[("ttl", ttl.as_secs().to_string())]);
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

    /// Fetches an artifact's bytes: [`Self::artifact_download_url`], then an
    /// **unauthenticated** GET of the presigned URL.
    ///
    /// The second request deliberately goes through `self.http` directly
    /// rather than through this client's request builder, so it carries no
    /// `Authorization` header and no `?token=` parameter — the same
    /// deliberate exception [`Self::health`] makes, for a different reason.
    /// Handing a Tamga credential to a storage host is the failure this
    /// design exists to prevent, and
    /// `download_artifact_sends_no_credential_to_the_storage_host` pins it.
    ///
    /// # `max_bytes`
    ///
    /// Required, not defaulted, because the right ceiling is the caller's to
    /// choose and the wrong one is an out-of-memory crash: the server accepts
    /// uploads up to 1 GiB and this method buffers the whole artifact in
    /// memory. Enforced twice — once against `Content-Length` before any body
    /// is read, then again across the streamed chunks, since a
    /// `Content-Length` is a claim by the storage host rather than a fact.
    /// Exceeding it is [`crate::error::ArtifactDownloadError::TooLarge`], and the partial
    /// buffer is dropped.
    ///
    /// To stream to disk instead, or to download something larger than fits
    /// in memory, call [`Self::artifact_download_url`] and fetch the URL
    /// yourself — with an unauthenticated client.
    ///
    /// # Timeout
    ///
    /// The client's configured request timeout (45s by default) covers this
    /// whole call, body included. That is ample for the API round trip and
    /// easily too short for a large artifact on a slow link; raise it via
    /// [`ClientConfigBuilder::timeout`] or stream the URL yourself.
    ///
    /// # Integrity
    ///
    /// The bytes are **not** checked against
    /// [`crate::models::artifact::ArtifactAttributes::checksum`]. No algorithm is declared on the
    /// wire — the server only infers one from the string's shape — so
    /// verifying here would mean guessing, and a guessed pass is worse than
    /// no check. Verify against your own upload-side convention.
    ///
    /// # Errors
    ///
    /// [`crate::error::ArtifactDownloadError::Api`] for the URL request (including the
    /// `403` that a CLOSED release produces — see
    /// [`Self::artifact_download_url`]), and
    /// [`crate::error::ArtifactDownloadError::StorageStatus`] for the storage host, most
    /// often a `403` from a URL that expired between issue and use.
    pub async fn download_artifact(
        &self,
        artifact_id: uuid::Uuid,
        ttl: Option<std::time::Duration>,
        max_bytes: u64,
    ) -> Result<Vec<u8>, crate::error::ArtifactDownloadError> {
        use crate::error::ArtifactDownloadError as E;

        let artifact = self.artifact_download_url(artifact_id, ttl).await?;
        let url = artifact
            .attributes
            .redirect_url
            .ok_or(E::MissingRedirectUrl)?;

        // `self.http` carries the timeout and User-Agent but no credential:
        // auth is applied per-request in `Self::request`, which this
        // deliberately bypasses.
        let response = self.http.get(&url).send().await.map_err(E::Fetch)?;

        if !response.status().is_success() {
            return Err(E::StorageStatus {
                status: response.status().as_u16(),
            });
        }

        // Cheap rejection before a single body byte is read.
        //
        // This cannot change the *outcome*: the streaming guard below would
        // reject the same download on the same input, and deleting this block
        // leaves the whole suite green — measured, not assumed. It is a
        // bandwidth optimisation, not a correctness guard, so it is
        // deliberately not pinned by a test of its own. The streaming guard is
        // the one that must hold, and
        // `the_ceiling_still_holds_when_the_host_sends_no_content_length`
        // exercises it against a server that sends no `Content-Length` at all,
        // which is the case this block cannot cover.
        if let Some(len) = response.content_length() {
            if len > max_bytes {
                return Err(E::TooLarge { limit: max_bytes });
            }
        }

        let mut body = Vec::new();
        let mut response = response;
        while let Some(chunk) = response.chunk().await.map_err(E::Fetch)? {
            // Re-checked per chunk: `Content-Length` is the storage host's
            // claim, and it can be absent (chunked transfer) or wrong.
            if body.len() as u64 + chunk.len() as u64 > max_bytes {
                return Err(E::TooLarge { limit: max_bytes });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    // ── Health ───────────────────────────────────────────────────────────

    /// `GET /v1/health` — the server's liveness probe.
    ///
    /// Two things make this call unlike every other one here.
    ///
    /// **It is not account-scoped.** The path is `/v1/health`, built from
    /// [`ClientConfig::origin_url`] rather than
    /// [`ClientConfig::base_url`]. The response is a flat
    /// `{ status, version, uptime_secs }` — no JSON:API envelope — so it is
    /// decoded directly rather than through the `{data: …}` decoder.
    ///
    /// **It deliberately sends no credential**, which contradicts this
    /// crate's rule everywhere else, and the exception is load-bearing. The
    /// server's auth middleware resolves the request's credential *before*
    /// consulting its public-route list, and in **singleplayer** mode a
    /// route with no `{account_id}` segment still resolves against the
    /// configured account. So a licence key that the policy's
    /// `authentication_strategy` refuses returns `401 LICENSE_NOT_ALLOWED`
    /// from this route too — turning the one call that is supposed to isolate
    /// a problem into another instance of it. Sent anonymously, `/v1/health`
    /// answers `200` on both server modes whatever the caller's credentials
    /// are worth.
    ///
    /// **What it diagnoses.** `/v1/health` also bypasses the `Host`-header
    /// check that every other route runs through. So:
    ///
    /// - every call fails `403 FORBIDDEN` *and* this one succeeds → the
    ///   deployment's `TAMGA_ALLOWED_HOSTS` does not list the host being
    ///   used. Nothing is wrong with the credential.
    /// - this one fails too → the server is unreachable, not misconfigured.
    /// - this one succeeds and an authenticated call returns `401` → the
    ///   credential is the problem.
    pub async fn health(&self) -> Result<crate::models::health::HealthStatus, crate::TamgaError> {
        let url = format!("{}/v1/health", self.config.origin_url());
        let builder = self.http.request(reqwest::Method::GET, url).header(
            "Tamga-Version",
            crate::transport::sanitize_version(&self.config.api_version),
        );
        let response = self
            .send_with_retry(builder, &reqwest::Method::GET, "/v1/health")
            .await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        Ok(response.json().await?)
    }
}

/// Filters and page selection for [`Client::list_machines`].
///
/// All fields default to `None` — construct with [`Default::default()`] and
/// set only what is needed. **Offset** pagination: there is no cursor field
/// here, on purpose, because the route has no cursor (see
/// [`crate::models::page`]).
#[derive(Debug, Clone, Default)]
pub struct ListMachinesOptions {
    /// `filter[license]` — restrict to one licence's machines.
    ///
    /// Without it the listing spans the whole account, which for a
    /// licence-key caller is almost never what is wanted: the route is not
    /// licence-scoped server-side.
    pub license_id: Option<uuid::Uuid>,
    /// `filter[platform]` — exact match on the recorded platform string.
    pub platform: Option<String>,
    /// `filter[q]` — case-insensitive **substring** search across `name`,
    /// `hostname` and `fingerprint`. Not an exact match on any of them; if
    /// you need one, filter the results yourself (as
    /// [`Client::find_machine_by_fingerprint`] does).
    pub search: Option<String>,
    /// `page[number]`, 1-based. Defaults to 1 server-side.
    pub page_number: Option<i64>,
    /// `page[size]`. Defaults to [`DEFAULT_SERVER_PAGE_SIZE`] server-side and
    /// is clamped to [`MAX_OFFSET_PAGE_SIZE`].
    pub page_size: Option<i64>,
}

/// Attributes to change on [`Client::update_machine`].
///
/// All fields default to `None`, and `None` means **leave unchanged** — not
/// "set to null". The server's update is `COALESCE($n, column)` for every
/// column, so no value this struct can hold will clear a field. See
/// [`Client::update_machine`].
#[derive(Debug, Clone, Default)]
pub struct UpdateMachineOptions {
    /// New display name.
    pub name: Option<String>,
    /// New IP address.
    pub ip: Option<String>,
    /// New hostname.
    pub hostname: Option<String>,
    /// New OS/platform string.
    pub platform: Option<String>,
    /// New CPU core count. Adjusts the licence's `machines_core_count`; the
    /// limit is not re-checked here.
    pub cores: Option<i32>,
    /// New memory figure, in **megabytes** — same units and same failure mode
    /// as [`CreateMachineOptions::memory`].
    pub memory: Option<i64>,
    /// New disk figure, in **megabytes**.
    pub disk: Option<i64>,
    /// Replacement metadata object. Replaces wholesale; it is not merged.
    pub metadata: Option<serde_json::Value>,
}

/// The outcome of [`Client::activate_machine_idempotent`].
#[derive(Debug, Clone)]
pub struct MachineActivation {
    /// The activated machine, or `None` when the server refused to create it
    /// under a strict overage strategy — in which case no row exists and
    /// `validation` carries the limit that blocked it.
    pub machine: Option<crate::models::machine::MachineResource>,
    /// The validation performed after activation. Its
    /// [`crate::models::validation::ValidationMeta::code`] is what tells a
    /// caller whether the licence actually permits this machine.
    pub validation: crate::models::validation::ValidationResult,
    /// `true` when the machine already existed on this licence and was
    /// adopted rather than created — a re-activation.
    ///
    /// The distinction is not cosmetic: an adopted machine is never rolled
    /// back by `auto_delete_on_overage`, because this call did not create it.
    pub reused: bool,
}

/// Which release [`Client::check_for_upgrade`] is asking about.
///
/// `product_id`, `platform`, `filetype` and `version` are all required by the
/// server — omitting any of them is a `400`, not a broader search.
#[derive(Debug, Clone)]
pub struct UpgradeQuery {
    /// The product whose releases to search. Not the licence id.
    pub product_id: uuid::Uuid,
    /// Target platform string, as the product's releases are published for.
    pub platform: String,
    /// Target artifact filetype.
    pub filetype: String,
    /// The version currently installed — the baseline "newer than" is
    /// measured against.
    pub version: String,
    /// Optional release channel to stay within.
    pub channel: Option<String>,
    /// Optional version constraint narrowing what counts as an acceptable
    /// upgrade.
    pub constraint: Option<String>,
}

/// The result of [`Client::check_for_upgrade`].
///
/// Two variants, not three, because the server exposes two — and the absence
/// of a third is the point. See [`Self::NoUpdateOffered`].
///
/// Non-exhaustive: if the server ever does gain a way to distinguish the two
/// situations `NoUpdateOffered` covers, a new variant must not be a breaking
/// change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum UpgradeCheck {
    /// A newer release exists and this caller is entitled to it.
    ///
    /// Boxed because the resource is much larger than the other variant, and
    /// an unboxed one would pad every `UpgradeCheck` to its size.
    Available(Box<crate::models::release::ReleaseResource>),
    /// **No update is available to you** — which is not the same claim as
    /// "you are up to date".
    ///
    /// The server answers `204 No Content` both when no newer release exists
    /// and when one exists that this licence has expired out of. It does that
    /// on purpose: distinguishing them would tell an expired licence that a
    /// version it cannot have is out there. Nothing on the wire separates the
    /// two, so nothing here can either.
    ///
    /// Phrase it to users as *no update available*. Reporting "you are on the
    /// latest version" to a customer whose licence quietly stopped receiving
    /// builds is how a renewal conversation never happens.
    NoUpdateOffered,
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
