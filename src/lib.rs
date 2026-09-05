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
//! ## Offline files are format v2 only
//!
//! [`checkout::license_file::verify_license_file`] and
//! [`checkout::machine_file::verify_machine_file`] accept only an `alg`
//! ending in `+v2` and enforce the signed `exp` claim against the same 60
//! second clock-skew tolerance, reporting
//! [`error::CheckoutError::Expired`] for a file that has simply run out. A
//! v1-issued `.lic` or `.mach` file is rejected outright — there is no
//! fallback path. See [`checkout::license_file`] for why, and
//! [`checkout::machine_file`] for the two places the `.mach` wire format
//! differs (a three-field `alg`, and a dot-separated encrypted `enc`).
//!
//! Pass a server-derived timestamp to
//! [`checkout::license_file::verify_license_file_at`] or
//! [`checkout::machine_file::verify_machine_file_at`] rather than trusting a
//! local clock the user can wind back.
//!
//! ## Signing-key rotation
//!
//! Verifying against one embedded public key cannot distinguish a file signed
//! before the account rotated its key from a forged one — both fail
//! identically. Verify through a [`checkout::key_set::SigningKeySet`] instead
//! and the two become distinct outcomes:
//! [`error::CheckoutError::UnknownSigningKey`] (refresh the keys) versus
//! [`error::CryptoError::VerificationFailed`] (refuse the file). Build the set
//! from the account's published key history with [`Client::signing_key_set`],
//! or with no network at all from keys pinned in the binary via
//! [`checkout::key_set::SigningKeySet::from_public_keys`] — the `kid` a file
//! names is computable locally with [`crypto::ed25519::key_id`].
//!
//! Two limits: a raw licence key gets `403` from `GET /signing-keys` (the
//! route needs `account.read`, which `Role::LicenseToken` does not hold), and
//! only Ed25519-signed files are covered.
//!
//! ## Rate limiting
//!
//! The server does return `429 Too Many Requests`. It surfaces as
//! [`error::TamgaError::RateLimited`] carrying the parsed `Retry-After` and
//! the response's `x-ratelimit-*` budget headers
//! ([`transport::RateLimitInfo`]); safe requests are retried automatically
//! first — see [`client::ClientConfigBuilder::max_retries`]. Note
//! `x-ratelimit-reset` is an absolute Unix timestamp, not a delay.
//!
//! ## Auth
//!
//! Auth is enforced on every endpoint: a missing or unrecognized credential
//! is `401`, a valid-but-insufficient one `403`. Authenticating with a raw
//! licence key ([`transport::AuthTransport::License`]) additionally requires
//! the licence's policy to set `authentication_strategy` to `LICENSE` or
//! `MIXED`. That column defaults to `'TOKEN'`, under which every
//! licence-key request is refused with `401 LICENSE_NOT_ALLOWED` — a
//! provisioning precondition, not a transient failure. See
//! [`error::LicenseAuthCode`].
//!
//! ## Known server-side gaps
//!
//! Modelled here but not fully live server-side today:
//!
//! - Only 19 of the 24 [`models::validation::ValidationCode`] variants are
//!   reachable; `NOT_FOUND`, `BANNED`, `COMPONENTS_SCOPE_MISMATCH`,
//!   `CHECKSUM_SCOPE_MISMATCH` and `VERSION_SCOPE_MISMATCH` are declared for
//!   forward-compatibility.
//! - [`models::validation::ScopeObject`]'s `version` and `checksum` fields
//!   are refused by the server (`422 SCOPE_NOT_SUPPORTED` fails the whole
//!   validate call), so this crate never sends them. Its other six fields,
//!   `entitlements` and `fingerprint` included, are enforced.
//! - `GET /licenses/{id}/entitlements` ignores `page[after]`: the listing
//!   is capped by `limit` (max 100) and cannot be paginated past it. See
//!   [`client::Client::list_entitlements`].
//! - Freshly created policies report `"DENY_ACCESS"`/`"NO_RESURRECTION"` —
//!   neither is a real variant. See [`models::policy`] for how this crate
//!   normalizes them.
//! - `GET /licenses/{id}` and `GET /licenses/{id}/policy` are **not**
//!   licence-scoped server-side: unlike validate and check-out they never
//!   call the server's `require_license_scope`, so a licence key reads any
//!   licence in the account, `attributes.key` in plaintext included. This
//!   crate exposes both routes because a client needs its own policy to size
//!   a heartbeat interval; it cannot narrow what the server returns, and does
//!   not claim to.
//! - `GET /releases/actions/upgrade` answers `204 No Content` for two
//!   different situations and deliberately does not distinguish them — see
//!   [`client::UpgradeCheck::NoUpdateOffered`].
//! - `policies.check_in_interval` stores `daily`/`weekly`/`monthly`/`yearly`
//!   (a `CHECK` constraint admits nothing else), while the server's own
//!   overdue calculation matches on `day`/`week`/`month`/`year` and so always
//!   falls through to its 30-day default. Both spellings decode here; see
//!   [`models::policy::CheckInInterval`].
//! - The machine collection is the one **offset**-paginated route this crate
//!   calls; every other listing is keyset. See [`models::page`].
//! - Both checkout handlers compute a file's `kid` claim from the account's
//!   **Ed25519** public key whatever scheme actually signed the bytes, and
//!   rotation only ever mints Ed25519 keys, so `kid` is meaningful for
//!   Ed25519-signed files only. See [`checkout::key_set`].
//!
//! ## Artifacts and the download redirect
//!
//! `Role::LicenseToken` already held `artifact.read`, so
//! [`Client::list_release_artifacts`] and [`Client::get_artifact`] were
//! always reachable with a licence key. The blocked half was fetching the
//! bytes: the server granted `artifact.download` to that role only recently,
//! and until then [`Client::artifact_download_url`] would have been `403`.
//! Create, update, delete and upload are **not** modelled — those
//! permissions are absent from the role, so a licence key cannot reach
//! them.
//!
//! The download action answers `303 See Other` to a short-lived presigned
//! storage URL by default. This crate never lets that redirect be followed
//! with a credential attached: it sends `?redirect=false` and issues the
//! request on a redirect-disabled client, then hands back the URL for an
//! **unauthenticated** fetch. [`Client::download_artifact`] does that fetch
//! and takes a required `max_bytes` ceiling, since the server admits uploads
//! up to 1 GiB. Treat the presigned URL as a bearer capability and keep it
//! out of logs.
//!
//! A `403` from the download action is not necessarily an auth problem: it
//! enforces the owning release's access gate (distribution strategy,
//! suspension, expiry, entitlement) on top of the permission, so a CLOSED
//! release's binary is refused to a caller in perfect standing. The listing
//! and show routes do not apply that gate, so metadata reading while the
//! download is refused is the expected shape of it.
//!
//! ## Fingerprints
//!
//! The server stores `fingerprint TEXT NOT NULL` with no normalisation,
//! unique per `(license_id, fingerprint)` — so `"ABC-123"`, `"abc-123"` and
//! `" ABC-123 "` are three machines on three seats.
//! [`fingerprint::compute`] canonicalizes caller-chosen labelled components
//! into one stable string first. It reads no hardware identifiers — what
//! identifies a machine is a product decision — and it deliberately performs
//! no Unicode normalisation, because a rule the eight Tamga SDKs cannot
//! implement identically would yield two fingerprints for one machine
//! depending on which SDK the application used.
//!
//! ## Heartbeat scheduling
//!
//! This crate ships no heartbeat scheduler — starting a background task on a
//! caller's behalf is a decision that belongs to the embedding application.
//! It does supply the number that task needs:
//! [`client::Client::effective_heartbeat_window`] reads
//! `policy.heartbeat_duration` off the licence's policy, and
//! [`client::Client::recommended_heartbeat_interval`] divides it by
//! [`models::policy::HEARTBEAT_INTERVAL_DIVISOR`]. Do not derive an interval
//! from `next_heartbeat_at` on a ping response: that field is computed
//! against the 600s fallback on precisely the routes a scheduler calls.

// Promoted from `warn` to `deny` once doc coverage across the public API
// was complete — a genuinely undocumented public item is now a build
// failure, not a silent gap.
#![cfg_attr(not(test), deny(missing_docs))]

pub mod checkout;
pub mod client;
pub mod crypto;
pub mod error;
pub mod fingerprint;
pub mod models;
pub mod proof;
pub mod transport;

// Re-exports of the crate's most commonly used public API surface.
pub use client::{Client, ClientConfig};
pub use error::TamgaError;
