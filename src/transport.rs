//! Auth transports, request/response headers, and content-type handling.
//!
//! [`AuthTransport`] carries four of the server's five accepted transports:
//!
//! - [`AuthTransport::Bearer`] → `Authorization: Bearer <token>` — the
//!   default transport, preferred for server-side and CI callers.
//! - [`AuthTransport::Basic`] → `Authorization: Basic <base64>`, in the three
//!   sub-forms of [`BasicAuth`]: `email:password`, `token:` (token as
//!   username, empty password), and `license:<key>`.
//! - [`AuthTransport::License`] → `Authorization: License <key>` — the
//!   **primary transport for embedded/client SDKs** validating against a raw
//!   license key.
//! - [`AuthTransport::Query`] → a `?token=` query parameter, for the rare
//!   caller that cannot set a header. The server also accepts `?auth=`.
//!
//! `Cookie: Tamga-Session=<uuid>` is deliberately **not** implemented —
//! browser/portal-only, requires a matching `Origin` header, not relevant to
//! a non-browser SDK.
//!
//! Tokens are opaque strings; this SDK does no prefix-based type detection.
//!
//! Headers this module owns:
//!
//! - `Tamga-Version` — sent on every request, sanitized by
//!   [`sanitize_version`] (alphanumeric plus `.`/`-`, max 32 chars) mirroring
//!   the server's own filter. Default [`DEFAULT_API_VERSION`].
//! - `Tamga-OTP` — threaded through the request builder for accounts with 2FA
//!   enabled; every [`crate::Client`] validate method takes an `otp` argument.
//! - Response headers, read back via [`ResponseInfo::from_headers`]:
//!   `Tamga-Version` (echoed), `Tamga-Edition` (`"EE"`/`"CE"`), `Tamga-Mode`
//!   (`"singleplayer"`/`"multiplayer"`), `X-Request-Id`.
//!
//! Content-Type is `application/vnd.api+json` for all JSON:API bodies,
//! **except** `GET .../actions/validate` (quick-validate), which returns
//! plain `application/json` with a flat body and no `data` envelope.
//!
//! `x-ratelimit-*` **is** set by the server, and this module claimed otherwise
//! until 0.3.0. The rate-limit middleware attaches all four of
//! `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-reset` and
//! `x-ratelimit-window` to the response it is about to return
//! (`tamga-api/src/shared/rate_limit/middleware.rs:140-143`), and the same four
//! names are in the CORS expose list (`router.rs:123-126`) so a browser client
//! can read them too. The old note confused "in the expose list" with "only in
//! the expose list". They are parsed into [`RateLimitInfo`] and reachable on
//! [`ResponseInfo::rate_limit`], and on the `response_info` field of
//! [`crate::TamgaError::RateLimited`].
//!
//! Still deliberately **not** implemented: the `Tamga-Environment` request
//! header (no server-side read path yet).

/// Auth transport variants matching the server's try-order — see the module
/// doc comment for which header or query parameter each one produces.
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

/// Sub-forms of HTTP Basic auth accepted by the server. All three are
/// base64-encoded into a single `Authorization: Basic <base64>` header.
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

/// The four `x-ratelimit-*` response headers.
///
/// The server's rate-limit middleware sets all four together on the response
/// it is about to return — `x-ratelimit-limit`, `x-ratelimit-remaining`,
/// `x-ratelimit-reset` and `x-ratelimit-window`
/// (`tamga-api/src/shared/rate_limit/middleware.rs:140-143`), on the throttled
/// `429` and on the request it let through alike.
///
/// Every field is nevertheless [`Option`], because "on every response" has two
/// documented exceptions and one undocumented one:
///
/// - the middleware returns early, before the header block, when the
///   deployment has no rate limiter configured at all (`middleware.rs:94`);
/// - and for an `OPTIONS` preflight, which the CORS layer answers
///   (`middleware.rs:99-101`);
/// - and any proxy in front of the API may strip or rewrite them.
///
/// Absent headers are therefore not an error and not a sign of an unlimited
/// budget — they mean *no information*, and a caller must not read `None` as
/// "plenty of room left". Use [`RateLimitInfo::is_present`] to tell the two
/// apart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateLimitInfo {
    /// `x-ratelimit-limit` — the bucket's capacity, i.e. how many requests
    /// the current window admits. The server computes it as
    /// `max(per_second, burst)`, so it is the burst allowance rather than
    /// the refill rate whenever the two differ.
    pub limit: Option<u64>,
    /// `x-ratelimit-remaining` — requests left in the current window.
    /// `0` on the response that was itself throttled.
    pub remaining: Option<u64>,
    /// `x-ratelimit-reset` — **an absolute Unix timestamp in seconds**, not a
    /// delta. Subtract the current time to get a wait; do not sleep for this
    /// value. (`Retry-After`, by contrast, *is* delta-seconds — the server
    /// derives it as `reset - now` at `middleware.rs:147`.) Use
    /// [`RateLimitInfo::seconds_until_reset`] rather than doing the
    /// subtraction by hand.
    pub reset: Option<u64>,
    /// `x-ratelimit-window` — the window length in seconds. A constant `1`
    /// server-side today (`WINDOW_SECS`), which is what makes the configured
    /// `*_burst` behave as a burst allowance rather than a rate.
    pub window: Option<u64>,
}

impl RateLimitInfo {
    /// Extracts the four `x-ratelimit-*` headers from a header map.
    ///
    /// A header that is missing, non-UTF-8, or not a base-10 integer is left
    /// as `None` — this is advisory budget metadata, and a proxy that
    /// rewrites one header must not turn an otherwise good response into an
    /// error.
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Self {
        let num = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .and_then(|v| v.parse::<u64>().ok())
        };
        RateLimitInfo {
            limit: num("x-ratelimit-limit"),
            remaining: num("x-ratelimit-remaining"),
            reset: num("x-ratelimit-reset"),
            window: num("x-ratelimit-window"),
        }
    }

    /// `true` when at least one of the four headers was present and parsable.
    ///
    /// The distinction that matters: an all-`None` value means the response
    /// carried no budget information, **not** that the budget is unlimited.
    pub fn is_present(&self) -> bool {
        self.limit.is_some()
            || self.remaining.is_some()
            || self.reset.is_some()
            || self.window.is_some()
    }

    /// Seconds from `now_unix` until the bucket refills, saturating at `0`.
    ///
    /// `None` when the server sent no `x-ratelimit-reset`. A reset already in
    /// the past yields `0` rather than wrapping — the header is an absolute
    /// timestamp and the local clock is not guaranteed to agree with the
    /// server's.
    pub fn seconds_until_reset(&self, now_unix: u64) -> Option<u64> {
        self.reset.map(|reset| reset.saturating_sub(now_unix))
    }
}

/// Response headers a caller may want to read off any [`crate::TamgaError`]
/// or successful response for support/debugging purposes.
///
/// `#[non_exhaustive]` since 0.3.0: adding [`ResponseInfo::rate_limit`] was
/// itself a breaking change precisely because a struct with all-public fields
/// and no such marker can be built by a consumer with a struct literal, so
/// every later header the server grows would need another minor. Construct one
/// from [`ResponseInfo::default`] and assign fields, or read it back with
/// [`ResponseInfo::from_headers`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The `x-ratelimit-*` budget headers — see [`RateLimitInfo`], and note
    /// that all-`None` means "no information", not "no limit".
    pub rate_limit: RateLimitInfo,
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
            rate_limit: RateLimitInfo::from_headers(headers),
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

    // ── x-ratelimit-* ────────────────────────────────────────────────────

    #[test]
    fn rate_limit_headers_are_read_back_off_a_response() {
        // The middleware sets all four together, on the throttled response
        // and on the ones it lets through alike. This document claimed for a
        // long time that no handler set them at all; it was wrong.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-limit", "20".parse().unwrap());
        headers.insert("x-ratelimit-remaining", "0".parse().unwrap());
        headers.insert("x-ratelimit-reset", "1767225600".parse().unwrap());
        headers.insert("x-ratelimit-window", "1".parse().unwrap());

        let info = ResponseInfo::from_headers(&headers);
        assert_eq!(info.rate_limit.limit, Some(20));
        assert_eq!(info.rate_limit.remaining, Some(0));
        assert_eq!(info.rate_limit.reset, Some(1_767_225_600));
        assert_eq!(info.rate_limit.window, Some(1));
        assert!(info.rate_limit.is_present());
    }

    #[test]
    fn absent_rate_limit_headers_mean_no_information_not_no_limit() {
        // Two live server paths skip the header block entirely (no limiter
        // configured, and OPTIONS preflight), and a proxy can strip them. A
        // caller must be able to tell that apart from a large budget.
        let headers = reqwest::header::HeaderMap::new();
        let info = ResponseInfo::from_headers(&headers);
        assert_eq!(info.rate_limit, RateLimitInfo::default());
        assert!(!info.rate_limit.is_present());
        assert_eq!(info.rate_limit.remaining, None);
    }

    #[test]
    fn a_garbled_rate_limit_header_is_dropped_not_fatal() {
        // Advisory metadata: a proxy that rewrites one header must not turn
        // an otherwise good response into an error, and must not corrupt the
        // three that are still intact.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-limit", "not-a-number".parse().unwrap());
        headers.insert("x-ratelimit-remaining", "-1".parse().unwrap());
        headers.insert("x-ratelimit-reset", " 1767225600 ".parse().unwrap());

        let rl = RateLimitInfo::from_headers(&headers);
        assert_eq!(rl.limit, None);
        assert_eq!(rl.remaining, None, "a negative count is not a u64");
        assert_eq!(
            rl.reset,
            Some(1_767_225_600),
            "surrounding space is trimmed"
        );
        assert!(rl.is_present());
    }

    #[test]
    fn reset_is_an_absolute_timestamp_not_a_delay() {
        // The trap this helper exists to close: sleeping for `reset` rather
        // than for `reset - now` parks the caller until the year 2026.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-reset", "1767225600".parse().unwrap());
        let rl = RateLimitInfo::from_headers(&headers);

        assert_eq!(rl.seconds_until_reset(1_767_225_598), Some(2));
        // A reset already behind us saturates rather than wrapping: the local
        // clock is not guaranteed to agree with the server's.
        assert_eq!(rl.seconds_until_reset(1_767_225_999), Some(0));
        assert_eq!(RateLimitInfo::default().seconds_until_reset(0), None);
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
