//! # tamga
//!
//! Official Rust SDK for [Tamga](https://tamga.sh) — license activation, offline
//! verification, and machine management for Rust applications.
//!
//! ## Shape
//!
//! A single [`client::Client`] built from a [`client::ClientConfig`] exposes every
//! server endpoint (validate, check-in, checkout, machine management,
//! components/processes, entitlements, offline proof) as an async method. In
//! addition, standalone verification functions in [`checkout`] and [`proof`]
//! work with **no network access at all** once the relevant public key
//! material is embedded in the application — this offline-verification path
//! is the core value proposition of this SDK over hand-rolling HTTP calls.
//!
//! ## Offline licence files are format v2 only
//!
//! [`checkout::license_file::verify_license_file`] accepts only an `alg`
//! ending in `+v2` and enforces the signed `exp` claim (60 second clock-skew
//! tolerance). A v1-issued `.lic` file is rejected outright — there is no
//! fallback path. See [`checkout::license_file`] for why.
//!
//! ## Rate limiting
//!
//! The server does return `429 Too Many Requests`. It surfaces as
//! [`error::TamgaError::RateLimited`] carrying the parsed `Retry-After`, and
//! safe requests are retried automatically first — see
//! [`client::ClientConfigBuilder::max_retries`].
//!
//! ## Known server-side gaps
//!
//! Modelled here but not fully live server-side today:
//!
//! - Only 14 of the 24 [`models::validation::ValidationCode`] variants are
//!   reachable; the rest are declared for forward-compatibility.
//! - The `entitlements`/`fingerprint`/`version`/`checksum` fields of
//!   [`models::validation::ScopeObject`] are parsed but not enforced.
//! - Freshly created policies report `"DENY_ACCESS"`/`"NO_RESURRECTION"` —
//!   neither is a real variant. See [`models::policy`] for how this crate
//!   normalizes them.
//! - Release/auto-update checking is not part of this crate's surface.

// Promoted from `warn` to `deny` once doc coverage across the public API
// was complete — a genuinely undocumented public item is now a build
// failure, not a silent gap.
#![cfg_attr(not(test), deny(missing_docs))]

pub mod checkout;
pub mod client;
pub mod crypto;
pub mod error;
pub mod models;
pub mod proof;
pub mod transport;

// Re-exports of the crate's most commonly used public API surface.
pub use client::{Client, ClientConfig};
pub use error::TamgaError;
