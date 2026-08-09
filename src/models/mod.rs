//! Wire models for every JSON:API resource and value type this SDK exchanges
//! with the server.
//!
//! Module layout (see `docs/plans/tamga-rust.plan.md` §2, §C, §G, §J, §K):
//!
//! - [`license`] — `LicenseResource`.
//! - [`validation`] — `ScopeObject` (8 fields), `ValidationMeta`,
//!   `ValidationCode` (24 variants, 14 reachable today).
//! - [`machine`] — `MachineResource`, `HeartbeatStatus`, `ComponentResource`,
//!   `ProcessResource`, the `Pid` newtype (wire-format string, not integer).
//! - [`entitlement`] — `EntitlementResource`.
//! - [`policy`] — `Policy`, `OverageStrategy`, `HeartbeatCullStrategy`,
//!   `HeartbeatResurrectionStrategy`, `LicenseScheme`, and the free-text
//!   (open-string) policy fields (`expiration_strategy`, `renewal_basis`,
//!   `authentication_strategy`).
//!
//! These are plain data types only — no HTTP, no verification logic. Request
//! orchestration lives in [`crate::client`]; cryptographic verification
//! lives in [`crate::crypto`] and [`crate::checkout`].

pub mod entitlement;
pub mod license;
pub mod machine;
pub mod policy;
pub mod validation;
