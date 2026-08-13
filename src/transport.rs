//! Auth transports, request/response headers, and content-type handling.
//!
//! Intended contents (deferred — see `docs/plans/tamga-rust.plan.md` §B):
//!
//! - `AuthTransport` enum, 5 variants matching the server's try-order:
//!   `Bearer(String)`, `Basic(BasicAuth)`, `License(String)`, `Cookie`
//!   (documented as unsupported), `Query(String)`.
//!   - `Bearer` → `Authorization: Bearer <token>` — the default transport
//!     SDKs should prefer per `docs/sdk.md`.
//!   - `Basic` has 3 sub-forms: `email:password`, `token:` (token as
//!     username, empty password), `license:<key>` — all base64-encoded.
//!   - `License` → `Authorization: License <key>` — the **primary transport
//!     for embedded/client SDKs** validating against a raw license key.
//!   - `Cookie: Tamga-Session=<uuid>` is deliberately **not implemented** —
//!     browser/portal-only, requires a matching `Origin` header, not
//!     relevant to a non-browser SDK.
//!   - `Query` → `?token=`/`?auth=` query parameter.
//! - Tokens are opaque strings — no prefix-based type detection. The server
//!   documents `tok-`/`prod-`/`env-`/`activ-`/`lic-` prefixes, but every
//!   issued token currently gets `tok-` regardless of type.
//! - `Tamga-OTP: <code>` header — threaded through the request builder,
//!   read on every authenticated request if 2FA is enabled server-side.
//! - `Tamga-Version: <string>` header — sent explicitly on every request,
//!   pinned per SDK major version, sanitized client-side (alphanumeric +
//!   `.`/`-`, max 32 chars) mirroring server rules. Default `"1.8"`.
//! - Response header readers: `Tamga-Version` (echoed), `Tamga-Edition`
//!   (`"EE"`/`"CE"`), `Tamga-Mode` (`"singleplayer"`/`"multiplayer"`),
//!   `X-Request-Id` (surfaced on error/response types for support logging).
//! - Content-Type: `application/vnd.api+json` default for all JSON:API
//!   bodies, **except** `GET .../actions/validate` (quick-validate), which
//!   returns plain `application/json` with a flat body and no `data`
//!   envelope — this one response shape needs special-cased parsing.
//! - Deliberately **not** implemented: `X-RateLimit-*` response header
//!   parsing (declared in the CORS allowlist only, never set by any handler
//!   today) and the `Tamga-Environment` request header (planned EE feature,
//!   no server-side read path yet).

/// Auth transport variants matching the server's try-order. Stub — see
/// module doc comment above.
#[derive(Debug, Clone)]
pub enum AuthTransport {
    /// `Authorization: Bearer <token>` — default/preferred transport.
    Bearer(String),
    /// `Authorization: Basic <base64>`, 3 sub-forms — see module docs.
    Basic(BasicAuth),
    /// `Authorization: License <key>` — primary transport for embedded SDKs.
    License(String),
    /// `?token=`/`?auth=` query parameter.
    Query(String),
}

/// Sub-forms of HTTP Basic auth accepted by the server. Stub.
#[derive(Debug, Clone)]
pub enum BasicAuth {
    /// `base64(email:password)`.
    EmailPassword {
        /// Account email, used as the Basic auth username.
        email: String,
        /// Account password.
        password: String,
    },
    /// `base64(token:)` — token as username, empty password.
    Token(String),
    /// `base64(license:<key>)`.
    LicenseKey(String),
}

impl BasicAuth {
    /// Renders the `user:pass` string for this sub-form, pre-base64-encoding.
    fn to_user_pass(&self) -> String {
        match self {
            BasicAuth::EmailPassword { email, password } => format!("{email}:{password}"),
            BasicAuth::Token(token) => format!("{token}:"),
            BasicAuth::LicenseKey(key) => format!("license:{key}"),
        }
    }

    /// `base64(user:pass)`, per the server's 3 accepted Basic auth sub-forms.
    fn to_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.to_user_pass())
    }
}

/// The `Authorization` header name, shared by `Bearer`/`Basic`/`License` transports.
const AUTHORIZATION: &str = "Authorization";

/// Query parameter name used by [`AuthTransport::Query`]. The server also
/// accepts `auth` as a synonym; this SDK sends `token` since it mirrors the
/// `Bearer <token>` semantics of the transport it substitutes for.
const QUERY_PARAM_TOKEN: &str = "token";

impl AuthTransport {
    /// Returns the `(header name, header value)` pair to attach to a request
    /// for this transport, or `None` if this transport is query-param-based
    /// instead (see [`AuthTransport::query_param`]).
    pub fn header(&self) -> Option<(&'static str, String)> {
        match self {
            AuthTransport::Bearer(token) => Some((AUTHORIZATION, format!("Bearer {token}"))),
            AuthTransport::Basic(basic) => {
                Some((AUTHORIZATION, format!("Basic {}", basic.to_base64())))
            }
            AuthTransport::License(key) => Some((AUTHORIZATION, format!("License {key}"))),
            AuthTransport::Query(_) => None,
        }
    }

    /// Returns the `(query param name, value)` pair to attach to a request's
    /// URL for this transport, or `None` if this transport is header-based
    /// instead (see [`AuthTransport::header`]).
    pub fn query_param(&self) -> Option<(&'static str, &str)> {
        match self {
            AuthTransport::Query(token) => Some((QUERY_PARAM_TOKEN, token.as_str())),
            _ => None,
        }
    }
}

/// Sanitizes a `Tamga-Version` header value per the server's accepted
/// character set: alphanumeric plus `.`/`-`, truncated to 32 chars.
/// Disallowed characters are dropped (not replaced), matching the server's
/// own filter-then-truncate behavior.
pub fn sanitize_version(version: &str) -> String {
    version
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .take(32)
        .collect()
}

/// Default `Tamga-Version` sent when [`crate::client::ClientConfig`] doesn't
/// override it — matches the server's own default.
pub const DEFAULT_API_VERSION: &str = "1.8";

/// Response headers a caller may want to read off any [`crate::TamgaError`]
/// or successful response for support/debugging purposes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseInfo {
    /// Echoed `Tamga-Version` the server processed the request with.
    pub tamga_version: Option<String>,
    /// `"EE"` or `"CE"`.
    pub tamga_edition: Option<String>,
    /// `"singleplayer"` or `"multiplayer"`.
    pub tamga_mode: Option<String>,
    /// Useful to log for support — correlates a client-side error with
    /// server-side logs.
    pub request_id: Option<String>,
}

impl ResponseInfo {
    /// Extracts known response headers from a header map. Missing headers or
    /// headers containing non-UTF-8 bytes are left as `None` rather than
    /// causing an error — this is diagnostic metadata, not required for
    /// correctness.
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Self {
        let get = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        ResponseInfo {
            tamga_version: get("Tamga-Version"),
            tamga_edition: get("Tamga-Edition"),
            tamga_mode: get("Tamga-Mode"),
            request_id: get("X-Request-Id"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_produces_authorization_header() {
        let transport = AuthTransport::Bearer("tok-abc123".to_string());
        assert_eq!(
            transport.header(),
            Some(("Authorization", "Bearer tok-abc123".to_string()))
        );
        assert_eq!(transport.query_param(), None);
    }

    #[test]
    fn license_produces_authorization_header() {
        let transport = AuthTransport::License("lic-xyz789".to_string());
        assert_eq!(
            transport.header(),
            Some(("Authorization", "License lic-xyz789".to_string()))
        );
    }

    #[test]
    fn query_produces_token_param_not_header() {
        let transport = AuthTransport::Query("tok-abc123".to_string());
        assert_eq!(transport.header(), None);
        assert_eq!(transport.query_param(), Some(("token", "tok-abc123")));
    }

    #[test]
    fn basic_email_password_encodes_correctly() {
        let transport = AuthTransport::Basic(BasicAuth::EmailPassword {
            email: "user@example.com".to_string(),
            password: "hunter2".to_string(),
        });
        // base64("user@example.com:hunter2")
        let expected = "dXNlckBleGFtcGxlLmNvbTpodW50ZXIy";
        assert_eq!(
            transport.header(),
            Some(("Authorization", format!("Basic {expected}")))
        );
    }

    #[test]
    fn basic_token_uses_empty_password() {
        let transport = AuthTransport::Basic(BasicAuth::Token("tok-abc123".to_string()));
        // base64("tok-abc123:")
        let expected = "dG9rLWFiYzEyMzo=";
        assert_eq!(
            transport.header(),
            Some(("Authorization", format!("Basic {expected}")))
        );
    }

    #[test]
    fn basic_license_key_prefixes_with_license_literal() {
        let transport = AuthTransport::Basic(BasicAuth::LicenseKey("lic-xyz789".to_string()));
        // base64("license:lic-xyz789")
        let expected = "bGljZW5zZTpsaWMteHl6Nzg5";
        assert_eq!(
            transport.header(),
            Some(("Authorization", format!("Basic {expected}")))
        );
    }

    #[test]
    fn sanitize_version_keeps_allowed_characters() {
        assert_eq!(sanitize_version("1.8"), "1.8");
        assert_eq!(sanitize_version("v1.0-beta"), "v1.0-beta");
    }

    #[test]
    fn sanitize_version_strips_disallowed_characters() {
        assert_eq!(sanitize_version("1.8; DROP TABLE"), "1.8DROPTABLE");
        assert_eq!(sanitize_version("a/b c"), "abc");
    }

    #[test]
    fn sanitize_version_truncates_to_32_chars() {
        let long = "a".repeat(50);
        let sanitized = sanitize_version(&long);
        assert_eq!(sanitized.len(), 32);
        assert_eq!(sanitized, "a".repeat(32));
    }

    #[test]
    fn response_info_extracts_known_headers() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Tamga-Version", "1.8".parse().unwrap());
        headers.insert("Tamga-Edition", "CE".parse().unwrap());
        headers.insert("Tamga-Mode", "multiplayer".parse().unwrap());
        headers.insert("X-Request-Id", "req-123".parse().unwrap());

        let info = ResponseInfo::from_headers(&headers);
        assert_eq!(info.tamga_version, Some("1.8".to_string()));
        assert_eq!(info.tamga_edition, Some("CE".to_string()));
        assert_eq!(info.tamga_mode, Some("multiplayer".to_string()));
        assert_eq!(info.request_id, Some("req-123".to_string()));
    }

    #[test]
    fn response_info_defaults_missing_headers_to_none() {
        let headers = reqwest::header::HeaderMap::new();
        let info = ResponseInfo::from_headers(&headers);
        assert_eq!(info, ResponseInfo::default());
    }
}

/// Deterministic-per-process jitter, in milliseconds, for retry backoff.
///
/// A fleet of clients that all back off on exactly the same schedule
/// reconverges into the same spike it was backing off from, so the delay needs
/// to be spread out. This derives the spread from the process id and the
/// attempt number rather than pulling in an RNG dependency: different processes
/// get different offsets, which is the property that matters, and the same
/// process stays predictable enough to reason about in a log.
///
/// Range is 0–999 ms, so it perturbs the delay without materially changing it.
pub(crate) fn jitter_millis(attempt: u32) -> u64 {
    let seed = u64::from(std::process::id())
        .wrapping_mul(2_654_435_761)
        .wrapping_add(u64::from(attempt).wrapping_mul(40_503));
    seed % 1000
}

#[cfg(test)]
mod backoff_tests {
    use super::jitter_millis;

    #[test]
    fn jitter_stays_under_a_second() {
        for attempt in 0..10 {
            assert!(jitter_millis(attempt) < 1000);
        }
    }

    #[test]
    fn jitter_varies_between_attempts() {
        // Identical jitter on every attempt would leave a fleet re-synchronised
        // after the first collision.
        let values: std::collections::BTreeSet<u64> = (0..8).map(jitter_millis).collect();
        assert!(
            values.len() > 1,
            "jitter must not be constant across attempts"
        );
    }
}
