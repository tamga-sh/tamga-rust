//! `LicenseResource` — the JSON:API `licenses` resource.
//!
//! Intended fields (see `docs/plans/tamga-rust.plan.md` §C):
//! - `id`, `type`
//! - attributes: `key`, `name`, `expiry`, `suspended`, `uses`, `metadata`,
//!   `created`, `updated`
//! - relationships: `policy`, `product`, `owner`

/// The `licenses` JSON:API resource. Stub — see module doc comment above.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct LicenseResource {
    _private: (),
}
