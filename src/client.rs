//! `Client` and `ClientConfig` — the single home for every endpoint method.
//!
//! Per `docs/plans/tamga-rust.plan.md` §2 (Architecture), this repo has no
//! `src/features/<slice>/` VSA layout like `tamga-api`; an SDK is a thin
//! client, not a multi-slice server, so every endpoint method lives here
//! (grouped by HTTP verb/endpoint) plus the request/response models in
//! `src/models/`. Split into `client/` submodules only if this file exceeds
//! ~800 lines in practice.
//!
//! Intended contents (deferred — see plan Sections B through K):
//!
//! - `ClientConfig`: `account_id` (required), `base_url`/`host` (required),
//!   `api_version` (default `"1.8"`), request `timeout`, plus a builder.
//! - Base URL construction: `https://<host>/v1/accounts/{account_id}/...` —
//!   `account_id` is always required, including singleplayer mode.
//! - `reqwest::Client` construction with configurable timeout and a
//!   `User-Agent` string (`tamga-rust/<crate-version>`).
//! - License validation: `validate_by_key`, `validate_by_id`, `quick_validate`.
//! - License check-in: `check_in`.
//! - License checkout: `check_out_license`, `check_out_license_json`.
//! - Machine checkout: `check_out_machine`, `check_out_machine_json`.
//! - Machine management: `create_machine`, `ping_heartbeat`, `reset_heartbeat`,
//!   plus an "activate machine" convenience helper composing
//!   `create_machine` + `validate_by_id` + optional auto-delete-on-overage.
//! - Machine offline proof: `generate_offline_proof`.
//! - Components & processes: `create_component`, `list_components`,
//!   `create_process`, `ping_process`.
//! - Entitlements: `list_entitlements`, `get_entitlement`, `has_entitlement`.
//!
//! Every method should send `Authorization: License <key>` (or another
//! configured [`crate::transport::AuthTransport`]) even where `docs/sdk.md`
//! notes server-side auth enforcement is not yet wired — this keeps the SDK
//! forward-compatible with future server-side enforcement.

/// Configuration for a [`Client`].
///
/// Build via [`ClientConfig::builder`]. `account_id` and `host` are always
/// required — including singleplayer mode, per `docs/sdk.md`.
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
}

/// Default request timeout used unless overridden via
/// [`ClientConfigBuilder::timeout`].
const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
    /// enforcement isn't wired up yet (see `docs/sdk.md` → Known Server-Side
    /// Gaps).
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
        }
    }
}

/// The Tamga API client — every endpoint method (validate, check-in,
/// checkout, machine management, components/processes, entitlements, offline
/// proof) lives here, per plan §2. Endpoint methods land in Sections C–K.
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
            .request(method, path, otp)
            .header(reqwest::header::CONTENT_TYPE, "application/vnd.api+json");
        if let Some(body) = body {
            builder = builder.json(&body);
        }
        let response = builder.send().await?;
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
            .request(method, path, otp)
            .header(reqwest::header::CONTENT_TYPE, "application/vnd.api+json");
        if let Some(body) = body {
            builder = builder.json(&body);
        }
        let response = builder.send().await?;
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
        let response = self.request(method, path, otp).send().await?;
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
