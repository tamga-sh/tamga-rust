//! `HealthStatus` — the server's liveness probe, and the one response in this
//! crate that is **not** JSON:API.
//!
//! `GET /v1/health` answers with a flat `{ status, version, uptime_secs }`
//! object: no `data` envelope, no `type`, no `attributes`. Feeding it through
//! the JSON:API decoder every other endpoint uses fails on a missing `data`
//! key, so [`crate::Client::health`] decodes it directly.
//!
//! The route is also the only one this crate calls that is **not** under
//! `/v1/accounts/{account_id}` and takes no credential — see
//! [`crate::Client::health`] for the diagnostic that makes it worth having.

/// The `GET /v1/health` body: `{ status, version, uptime_secs }`.
///
/// Flat, not JSON:API — see the module doc comment.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct HealthStatus {
    /// `"ok"` on the current server. Modelled as a `String` rather than a
    /// closed enum: the handler hardcodes one value today, and a future
    /// `"degraded"` must not fail deserialization on a probe whose whole job
    /// is answering when things are going wrong.
    pub status: String,
    /// The server's own crate version (e.g. `"1.8.3"`) — **not** the
    /// `Tamga-Version` API version this SDK sends. The two are unrelated
    /// strings and neither can be derived from the other.
    pub version: String,
    /// Seconds since the server process started. Resets on every deploy or
    /// restart, so a small value here explains an otherwise mysterious spike
    /// of cold-cache latency or a dropped in-flight request.
    pub uptime_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_the_flat_non_json_api_body() {
        let parsed: HealthStatus =
            serde_json::from_str(r#"{"status":"ok","version":"1.8.3","uptime_secs":42}"#).unwrap();
        assert_eq!(parsed.status, "ok");
        assert_eq!(parsed.version, "1.8.3");
        assert_eq!(parsed.uptime_secs, 42);
    }

    #[test]
    fn an_unknown_status_string_still_decodes() {
        // The probe must answer when the server is unwell; a closed enum here
        // would turn "degraded" into a client-side parse failure.
        let parsed: HealthStatus =
            serde_json::from_str(r#"{"status":"degraded","version":"9.9.9","uptime_secs":0}"#)
                .unwrap();
        assert_eq!(parsed.status, "degraded");
    }
}
