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
    /// `host`'s scheme (if any) and trailing slash (if any) normalized away
    /// first, so callers can pass a bare host, a host with a trailing
    /// slash, or a full `https://` URL interchangeably.
    pub fn base_url(&self) -> String {
        let host = self
            .host
            .trim_end_matches('/')
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        format!("https://{host}/v1/accounts/{}", self.account_id)
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
    // Not read yet — first consumer lands with Section C's endpoint methods
    // (`validate_by_key` etc.), which issue requests through `http` using
    // `config`'s base URL/auth/version.
    #[allow(dead_code)]
    pub(crate) http: reqwest::Client,
    #[allow(dead_code)]
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
    fn client_new_succeeds_with_valid_config() {
        let config = ClientConfig::builder("acc-123", "api.tamga.sh")
            .auth(AuthTransport::License("lic-abc".to_string()))
            .build();
        let client = Client::new(config);
        assert!(client.is_ok());
    }
}
