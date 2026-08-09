//! # tamga
//!
//! Official Rust SDK for [Tamga](https://tamga.sh) — license activation, offline
//! verification, and machine management for Rust applications.
//!
//! **Status: scaffold only.** This crate currently contains module wiring and
//! doc-comment placeholders describing intended contents (see
//! `docs/plans/tamga-rust.plan.md` in the SDK-index repo, Section A). No HTTP
//! client, request builder, or cryptographic verification logic is implemented
//! yet — those are deferred to dedicated follow-up sessions covering
//! `docs/plans/tamga-rust.plan.md` Sections B through M.
//!
//! ## Intended shape (once implemented)
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
//! See `docs/sdk.md` → "Known Server-Side Gaps" for full detail. Items
//! relevant to this crate: auto-update/release-checking
//! (`GET /releases/actions/upgrade` crashes at runtime today), RFC 9421 HTTP
//! response signing (dead code server-side), the `Tamga-Environment` request
//! header (planned EE feature, not read server-side), and client-side 429
//! backoff handling (the server never returns 429 today).

#![cfg_attr(not(test), warn(missing_docs))]

pub mod checkout;
pub mod client;
pub mod crypto;
pub mod error;
pub mod models;
pub mod proof;
pub mod transport;

// Re-exports of the public API surface. `Client`/`ClientConfig`/`TamgaError`
// are stub marker types today (Section A) — real fields and methods land in
// Sections B/K of the plan. Re-exported now so the crate root shape is
// stable across that transition.
pub use client::{Client, ClientConfig};
pub use error::TamgaError;
