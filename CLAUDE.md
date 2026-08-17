# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`tamga-rust` is the official Rust SDK for Tamga (license activation, offline verification, machine
management). Single crate, published to crates.io as the bare name `tamga`. It is priority 1 of the
8-repository SDK index and the **reference implementation** for the whole SDK program: `tamga-c`
exposes this exact crate through a stable C ABI, and `tamga-java`/`tamga-swift` bind to `tamga-c` in
turn rather than re-implementing signature verification per language. Every cryptographic bug or
protocol-parsing mistake made here propagates to three other SDKs — see the GOTCHAS section below
before touching anything in `src/crypto/` or `src/checkout/`.

Protocol spec: the Tamga API protocol specification is the authoritative source for every field
name, endpoint, and enum value this crate implements against. It is generated from the running
server, so where any other description of the wire format disagrees with it, the specification
wins.

**Current state: implemented and tested** — client/transport, license
validation/check-in/checkout, machine checkout/management/offline proof, components/processes,
entitlements, error model. All cryptographic code has passed a dedicated `security-reviewer`
pass — read the GOTCHAS section below before touching anything in `src/crypto/` or
`src/checkout/` regardless. Published on crates.io as `tamga` (v0.1.1), with real CI/release
automation exercised end-to-end.

## Architecture

```
tamga-rust/
├── Cargo.toml                       # edition = "2021", rust-version = "1.75"
├── rust-toolchain.toml              # channel = "stable", components = [rustfmt, clippy]
├── clippy.toml                      # msrv = "1.75"
├── deny.toml                        # advisories/licenses/bans — rsa crate banned (RUSTSEC-2023-0071)
├── rustfmt.toml
├── release-plz.toml
├── .github/workflows/{ci,release}.yml
├── src/
│   ├── lib.rs                       # crate root; re-exports; crate docs
│   ├── client.rs                    # Client, ClientConfig; every endpoint method lives here
│   ├── transport.rs                 # AuthTransport (5 variants), headers
│   ├── error.rs                     # TamgaError, JsonApiError, typed error codes
│   ├── models/                      # license, validation, machine, entitlement, policy
│   ├── crypto/                      # ed25519, rsa, ecdsa, aes_gcm, hkdf, naive_key — primitives only
│   ├── checkout/                    # license_file.rs (.lic), machine_file.rs (.mach) — format + orchestration
│   └── proof.rs                     # machine offline proof (byte-exact serialization + RSA verify)
├── tests/fixtures/                  # known-good .lic/.mach files (not yet captured)
└── examples/                        # validate_license.rs, verify_license_file.rs
```

**No workspace, single crate** — this is a thin HTTP client + verifier, not a multi-slice server; it
has no reason to split into a workspace at this scope (contrast with the Tamga API server, which is
also a single crate but a much larger one).

**`crypto/` holds primitives only** — no HTTP, no PEM parsing, no protocol knowledge. `checkout/`
owns the PEM-envelope format and orchestrates calls into `crypto/`. This separation is what lets
`tamga-c` re-export the crypto primitives independently of the full HTTP client.

**`client.rs` is the single home for every endpoint method** — no `src/features/<slice>/` VSA layout
like the Tamga API server. Split into `client/` submodules only if it exceeds ~800 lines in practice.

## Dev Commands

```bash
cargo build                                                 # build
cargo test                                                  # run tests
cargo fmt / cargo fmt --check                                # format / format check
cargo clippy --all-targets --all-features -- -D warnings     # lint — note --all-targets, plain `cargo clippy` misses test-only lints
cargo llvm-cov nextest --lcov --fail-under-lines 80          # coverage gate (what CI runs)
cargo deny check                                             # license/advisory/ban policy — not run by `cargo test`, run it explicitly
cargo doc --no-deps --open                                   # build + view docs locally
```

No `just`, no Docker Compose, no local Postgres — this is a client SDK. Integration tests mock the
HTTP layer (`wiremock`); they never need a live Tamga API instance except when regenerating
`tests/fixtures/*.lic`/`*.mach` files, which do require one.

## GOTCHAS

Pulled from the Tamga API protocol specification → "Known Server-Side Gaps", filtered to what
actually touches this repo.
Read the full list there before scoping new SDK work — most of it (Analytics, EE Environments/Event
Logs/SSO, Auto-Update) is out of scope for this SDK entirely.

- **The upgrade-check endpoint works now.** `GET /releases/actions/upgrade` used to 500 on every
  call — its query selected seven columns `releases` never had and joined three tables that were
  never created. That is fixed server-side. An expired licence gets `204 No Content` rather than a
  denial when its policy says it has stopped receiving new builds, so treat 204 as "you are current"
  and not as an error.
- **429 is live; handle it.** Credential-accepting endpoints run on a per-IP budget (5 req/s by
  default) that a heartbeat timer reaches easily. `TamgaError::RateLimited` carries the server's
  `Retry-After`. Safe requests (`GET`, plus the licensing `actions/*` `POST`s) retry automatically
  with capped backoff; creates deliberately do not, because repeating an activation can burn a
  second seat.
- **Model all 24 `ValidationCode` variants, but only 14 are live.** `VALID` through `TOO_MANY_USES`
  (14 values) are reachable. `NOT_FOUND` is declared but never emitted — the handler short-circuits
  to HTTP 404 instead. The remaining 9 (`BANNED`, `ENTITLEMENTS_MISSING`, `TOO_MANY_USERS`,
  `HEARTBEAT_DEAD`, `HEARTBEAT_NOT_STARTED`, `FINGERPRINT_SCOPE_MISMATCH`,
  `COMPONENTS_SCOPE_MISMATCH`, `CHECKSUM_SCOPE_MISMATCH`, `VERSION_SCOPE_MISMATCH`) are wired into
  the enum for forward-compatibility but never actually returned. Use `#[serde(other)]` so a future
  server-side addition doesn't hard-fail deserialization.
- **`ScopeObject` has 8 fields; 6 are enforced and 2 are refused.** `product`, `policy`, `user`,
  `environment`, `fingerprint` and `entitlements` are all checked server-side now. `version` and
  `checksum` return `422 SCOPE_NOT_SUPPORTED` — deliberately, because neither has anything
  server-side to compare against, and a scope that silently passes is worse than one that is
  missing: it gets relied on.
- **Auth is enforced everywhere.** A missing credential is `401`, an insufficient one `403`; the two
  are distinct states and must not be conflated in error handling. A licence key is scoped to its
  own licence — validating or checking out someone else's returns `403`. Authenticating with a
  licence key also requires the policy's `authentication_strategy` to be `LICENSE` or `MIXED`; the
  default `TOKEN` yields `401 LICENSE_NOT_ALLOWED`, which is a provisioning matter, not an SDK bug.
- **Policy defaults reference non-existent enum variants.** Freshly-created policies report
  `overage_strategy: "DENY_ACCESS"` and `heartbeat_resurrection_strategy: "NO_RESURRECTION"` — neither
  is a real variant of `OverageStrategy`/`HeartbeatResurrectionStrategy`. Both silently behave as
  the "no restriction" variant (`NO_OVERAGE`/`NO_REVIVE`) server-side. Model these two fields as open
  string newtypes, not closed enums, and treat any unrecognized value as "no restriction" to match
  actual behavior — do not trust the literal default string.
- **RFC 9421 HTTP response signing is dead server-side.** No response is ever signed today
  (`sign_response*` has no call sites). Don't build verification for a `Signature` header that will
  never arrive.
- **`Tamga-Environment` request header is not implemented server-side** (planned EE feature, no
  read path yet). Don't add it to the request builder.

## Critical Dependency Notes

**`rsa` crate is banned**, enforced by `deny.toml`'s `bans.deny`. RUSTSEC-2023-0071 (Marvin timing
attack on PKCS#1 v1.5 decryption) is unpatched. All RSA operations (`src/crypto/rsa.rs`, and the
machine offline proof in `src/proof.rs`, which is always RSA-2048 PKCS#1 v1.5/SHA-256 regardless of
the license's own signing scheme) go through `aws-lc-rs` instead. Run `cargo deny check` before
adding any new dependency — it is not part of `cargo test` or `cargo build`, only CI (and this repo
has no `just check` equivalent yet to bundle it locally).

**Signature covers the base64 string, not decoded bytes** — the single most important gotcha in this
codebase. A `.lic`/`.mach` file's signature is computed over the ASCII/UTF-8 bytes of the `enc`
field's base64-encoded *string itself*, not the bytes you get after decoding it. This is easy to get
backwards when porting verification logic from another language's SDK — always write the negative
test (decoded-bytes verification must fail against a known-good fixture) alongside the positive one.

**License file encryption key is intentionally not a KDF** (`src/crypto/naive_key.rs`) — raw UTF-8
bytes of the license key, zero-padded/truncated to 32 bytes. Machine file encryption
(`src/crypto/hkdf.rs`), by contrast, uses a real HKDF-SHA256 derivation salted with a fixed string
and keyed on both the license key and the machine fingerprint. These are not interchangeable — do
not "unify" them into one derivation function; that would silently break interop with either the
`.lic` or `.mach` format depending on which direction you "fixed" it.

**Byte-exact JSON for offline proof** (`src/proof.rs`) — the signed payload's field order must match
the server's exactly. The server builds it via `serde_json::json!(...)`, and `serde_json::Map` is
`BTreeMap`-backed (alphabetically sorted output) unless the `preserve_order` feature is enabled —
which it is **not**, on either side (confirmed: no `indexmap` next to `serde_json` in either repo's
`Cargo.lock`). So the actual wire bytes are alphabetically sorted at every nesting level, **not** the
literal `account, machine, dataset` order the source code is written in. Build the payload with
`serde_json::Value`/`json!()` (as `proof.rs` does) so it self-normalizes to the same order the server
produces — a fixed-field-order `serde` struct declared in the server's literal source order would
actually be wrong here. Never use a `HashMap` (non-deterministic iteration order). See `proof.rs`'s
module doc comment and its `payload_json_matches_a_known_good_server_produced_fixture` test, which
acts as a drift canary if a future dependency bump ever flips `preserve_order` on asymmetrically.

## Testing

- **Coverage gate: 80% lines**, enforced via `cargo llvm-cov nextest --fail-under-lines 80` in CI.
  Run the same command locally before opening a PR — `cargo test` alone does not check coverage.
- Unit tests live inline (`#[cfg(test)]`) next to the code they cover. Integration tests live in
  `tests/*.rs`, one file per feature area (`tests/license_validation.rs`,
  `tests/checkout_license_file.rs`, etc.) and mock the HTTP layer with `wiremock` — no live server
  required.
- `tests/fixtures/` holds known-good `.lic`/`.mach` files captured from a real Tamga API instance.
  These must come from a real server response, not be hand-constructed — the point of these tests is
  confirming this SDK's verifier reproduces the server's *actual* signing/serialization behavior
  (notably the base64-string-vs-decoded-bytes gotcha above), which a hand-built fixture matching this
  SDK's own assumptions cannot catch.
- **`src/crypto/`, `src/checkout/` and `src/proof.rs` require a `security-reviewer` pass before
  merge.** Do not batch multiple crypto areas into one PR; each covers materially different
  primitives.

## Branch & Commit Convention

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`
Commits: [Conventional Commits](https://www.conventionalcommits.org/) (`feat: …`, `fix: …`, etc.) —
release-plz reads this history directly to compute the next version and generate `CHANGELOG.md`;
an inaccurate commit type can skip a release entirely.
