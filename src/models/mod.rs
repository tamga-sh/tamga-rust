//! Wire models for every JSON:API resource and value type this SDK exchanges
//! with the server.
//!
//! Module layout:
//!
//! - [`license`] — `LicenseResource`.
//! - [`validation`] — `ScopeObject` (8 fields), `ValidationMeta`,
//!   `ValidationCode` (24 variants, 16 reachable today).
//! - [`machine`] — `MachineResource`, `HeartbeatStatus`, `ComponentResource`,
//!   `ProcessResource`, the `Pid` newtype (wire-format string, not integer).
//! - [`entitlement`] — `EntitlementResource`.
//! - [`policy`] — `Policy`, `OverageStrategy`, `HeartbeatCullStrategy`,
//!   `HeartbeatResurrectionStrategy`, `LicenseScheme`, and the free-text
//!   (open-string) policy fields (`expiration_strategy`, `renewal_basis`,
//!   `authentication_strategy`).
//! - [`page`] — `OffsetPage`/`OffsetPageMeta`, the **offset** pagination
//!   `GET /machines` uses. Deliberately a separate type from the synthetic
//!   keyset cursor every other listing here uses; see that module for the
//!   table of which route is which.
//! - [`release`] — `ReleaseResource`, returned by the auto-update check. Its
//!   attributes are **camelCase** on the wire, unlike every other resource.
//! - [`health`] — `HealthStatus`, the one non-JSON:API response body.
//! - [`signing_key`] — `SigningKeyResource`, the account's published Ed25519
//!   key set including retired keys. Its `id` is the `kid`, not a UUID, and
//!   `publicKey` is its one camelCase field.
//!
//! These are plain data types only — no HTTP, no verification logic. Request
//! orchestration lives in [`crate::client`]; cryptographic verification
//! lives in [`crate::crypto`] and [`crate::checkout`].

pub mod entitlement;
pub mod health;
pub mod license;
pub mod machine;
pub mod page;
pub mod policy;
pub mod release;
pub mod signing_key;
pub mod validation;
