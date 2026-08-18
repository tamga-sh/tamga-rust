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
//! - Entitlements: [`Client::list_entitlements`], [`Client::get_entitlement`],
//!   [`Client::has_entitlement`].
//!
//! Every method sends the configured [`crate::transport::AuthTransport`]'s
//! credentials, even on endpoints where server-side auth enforcement is not
//! yet wired — this keeps callers forward-compatible with enforcement landing.
//!
//! **Rate limiting.** Requests that go through the JSON:API and
//! quick-validate paths are sent via `send_with_retry`, which retries a `429`
//! up to [`ClientConfig::max_retries`] times using the server's `Retry-After`
//! (capped at 60s) or jittered exponential backoff. Only safe requests
//! qualify: every `GET`, plus `POST` on the five action suffixes
//! `/actions/validate`, `/actions/validate-key`, `/actions/check-in`,
//! `/actions/check-out` and `/actions/ping`. Creates are excluded on purpose.
//! The two raw-PEM helpers ([`Client::check_out_license`],
//! [`Client::check_out_machine`]) send directly and surface a `429` as
//! [`crate::TamgaError::RateLimited`] without retrying.

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
    /// `POST` on the `validate`, `validate-key`, `check-in`, `check-out` and
    /// `ping` actions. Creates are never retried — see the module doc
    /// comment.
    pub max_retries: u32,
}

/// Default request timeout used unless overridden via
/// [`ClientConfigBuilder::timeout`].
const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Default number of retries for a rate-limited request.
///
/// Three is enough to ride out a short burst without turning a sustained 429
/// into a request that hangs for minutes. The server's auth-endpoint budget is
/// tight (5 req/s by default), and a heartbeat timer plus a retry loop reaches
/// it easily — which is exactly the case this exists for.
const DEFAULT_MAX_RETRIES: u32 = 3;

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

    /// Overrides the default 30s request timeout.
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the auth transport used to authenticate every request. Required
    /// before [`Self::build`] — there is no auth-less default, since every
    /// documented server endpoint expects credentials to be sent even where
    /// enforcement isn't wired up yet (see the Tamga API protocol
    /// specification → Known Server-Side Gaps).
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
    /// they are effectively idempotent (validate, check in/out, ping a
    /// heartbeat), and they are precisely the calls a client makes on a timer,
    /// so they are the ones that hit the rate limit in the first place.
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
    /// [`crate::models::validation::ScopeObject`] — only
    /// `product`/`policy`/`user`/`environment` are enforced server-side
    /// today). `skip_touch: true` suppresses the `last_validated_at`
    /// side-effect. `otp` sends `Tamga-OTP` if the bearer's account has 2FA
    /// enabled.
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
        let mut builder = self.request(
            reqwest::Method::GET,
            &format!("/licenses/{license_id}/actions/check-out"),
            None,
        );
        builder = builder.query(&[("encrypt", encrypt.to_string())]);
        if let Some(ttl) = ttl {
            builder = builder.query(&[("ttl", ttl.to_string())]);
        }
        let response = builder.send().await?;
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
        let mut builder = self.request(
            reqwest::Method::GET,
            &format!("/machines/{machine_id}/actions/check-out"),
            None,
        );
        builder = builder.query(&[("encrypt", encrypt.to_string())]);
        if let Some(ttl) = ttl {
            builder = builder.query(&[("ttl", ttl.to_string())]);
        }
        let response = builder.send().await?;
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
    /// **No machine/core/etc. limit is checked at creation time** — those
    /// limits only surface later via [`Self::validate_by_id`]. The
    /// recommended "activate machine" flow is create → validate → interpret
    /// `TooManyMachines`/`TooManyCores`/etc., deleting the machine row on
    /// that path if the desired UX is "reject over-limit activation" — see
    /// [`Self::activate_machine`], which does exactly that.
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
    /// doc comment for why creation alone doesn't enforce limits).
    ///
    /// If validation fails with an over-limit
    /// [`crate::models::validation::ValidationCode`] (`TooManyMachines`,
    /// `TooManyCores`, `TooMuchMemory`, `TooMuchDisk`, `TooManyProcesses`)
    /// and `auto_delete_on_overage` is `true`, the just-created machine is
    /// deleted before returning the validation result — implementing
    /// "reject over-limit activation" instead of leaving an orphaned
    /// machine row behind. Deletion failures are not surfaced (the
    /// validation result is what the caller asked for); a machine left
    /// behind after a failed auto-delete is still visible to normal
    /// machine-management calls for manual cleanup.
    pub async fn activate_machine(
        &self,
        license_id: uuid::Uuid,
        fingerprint: &str,
        opts: CreateMachineOptions,
        scope: Option<crate::models::validation::ScopeObject>,
        auto_delete_on_overage: bool,
    ) -> Result<crate::models::validation::ValidationResult, crate::TamgaError> {
        let machine = self.create_machine(license_id, fingerprint, opts).await?;
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

    /// `POST /machines/{machine_id}/actions/ping-heartbeat` — no body, sets
    /// `last_heartbeat_at = now`. Returns the updated machine resource.
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
    /// to fetch the next page.
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

        let mut builder = self.request(
            reqwest::Method::GET,
            &format!("/machines/{machine_id}/components"),
            None,
        );
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit.to_string())]);
        }
        if let Some(after) = after {
            builder = builder.query(&[("page[after]", after.to_string())]);
        }
        let response = builder.send().await?;
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

    /// `POST /processes/{process_id}/actions/ping` — no body. ⚠️ The
    /// process heartbeat window is a **hardcoded 30 seconds** with no
    /// resurrection grace period — see [`crate::models::machine::Pid`]'s
    /// doc comment.
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

    /// `GET /licenses/{license_id}/entitlements` — keyset-paginated
    /// (`limit`, `page[after]`). Despite the URL nesting, returns full
    /// [`crate::models::entitlement::EntitlementResource`]s, not
    /// lightweight junction records. No auth/permission check is applied
    /// beyond the license existing.
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

        let mut builder = self.request(
            reqwest::Method::GET,
            &format!("/licenses/{license_id}/entitlements"),
            None,
        );
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit.to_string())]);
        }
        if let Some(after) = after {
            builder = builder.query(&[("page[after]", after.to_string())]);
        }
        let response = builder.send().await?;
        if !response.status().is_success() {
            return Err(Self::api_error(response).await);
        }
        let envelope: Envelope = response.json().await?;
        Ok(envelope.data)
    }

    /// `GET /licenses/{license_id}/entitlements/{entitlement_id}`.
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
    /// page, up to `limit`) and checks whether any has the given `code`.
    ///
    /// Matches on `code` (the stable, developer-facing identifier) —
    /// **never** on `name` (just a display label). Fetches at most one
    /// page (`limit`, default 100 — the server's own max page size); for
    /// licenses with more entitlements than fit on one page, paginate via
    /// [`Self::list_entitlements`] directly instead.
    pub async fn has_entitlement(
        &self,
        license_id: uuid::Uuid,
        code: &str,
        limit: Option<u32>,
    ) -> Result<bool, crate::TamgaError> {
        let entitlements = self
            .list_entitlements(license_id, Some(limit.unwrap_or(100)), None)
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
    /// Memory in bytes to record.
    pub memory: Option<i64>,
    /// Disk in bytes to record.
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
    fn builder_defaults_timeout_to_30_seconds() {
        let config = ClientConfig::builder("acc-123", "api.tamga.sh")
            .auth(AuthTransport::License("lic-abc".to_string()))
            .build();
        assert_eq!(config.timeout, std::time::Duration::from_secs(30));
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
