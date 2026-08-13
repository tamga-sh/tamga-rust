//! # tamga
//!
//! Official Rust SDK for [Tamga](https://tamga.sh) — license activation, offline
//! verification, and machine management for Rust applications.
//!
//! **Status: Sections A–L implemented and tested** — see
//! `docs/plans/tamga-rust.plan.md` for the full per-section checklist.
//! Sections E, F, and H (all cryptographic code — license checkout, machine
//! checkout, offline proof) have each passed a dedicated `security-reviewer`
//! pass; outcomes are recorded in the plan file. Not yet done: Section M
//! (CI/release automation hasn't been exercised against a real CI run), and
//! `tests/fixtures/` still generates fixtures in-process against the
//! documented wire format rather than from real captured server output (no
//! live `tamga-api` instance was available across the sessions that built
//! this crate).
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
//! Protocol reference: `docs/sdk.md` in the `tamga-api` repository is the
//! authoritative source for every field name, endpoint, and enum value this
//! crate implements against. `docs/plans/tamga-rust.plan.md` (this repo's own
//! `docs/plans/`) is the condensed, scoped-to-this-crate implementation plan.
//!
//! ## Known Server-Side Gaps (do not build against these yet)
//!
//! See `docs/sdk.md` → "Known Server-Side Gaps" for full detail. Items still
//! relevant to this crate: RFC 9421 HTTP response signing (dead code
//! server-side) and the `Tamga-Environment` request header (planned EE
//! feature, not read server-side).
//!
//! Two entries there are now out of date and have been acted on here:
//! `GET /releases/actions/upgrade` no longer crashes (its query referenced a
//! table that never existed), and the server *does* rate-limit — see
//! [`error::TamgaError::RateLimited`] and `ClientConfig::max_retries`.

// Promoted from `warn` to `deny` once doc coverage across the public API
// was complete (see `docs/plans/tamga-rust.plan.md` §L) — a genuinely
// undocumented public item is now a build failure, not a silent gap.
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
