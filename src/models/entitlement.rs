//! `EntitlementResource`.
//!
//! Intended fields (see `docs/plans/tamga-rust.plan.md` §J): `name`, `code`,
//! `metadata`, `created`, `updated`.
//!
//! `code` is the stable, developer-facing identifier — `name` is just a
//! display label. `has_entitlement` (in `src/client.rs`) must match on
//! `code`, never `name`. Despite the URL nesting under
//! `/licenses/{id}/entitlements`, these are full `Entitlement` resources,
//! not lightweight junction/relationship records.

/// The `entitlements` JSON:API resource. Stub — see module doc comment.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EntitlementResource {
    _private: (),
}
