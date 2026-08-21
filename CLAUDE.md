# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`tamga-rust` is the official Rust SDK for Tamga (license activation, offline verification, machine
management). Single crate, published to crates.io as the bare name `tamga`. It is priority 1 of the
8-repository SDK index and the **reference implementation** for the whole SDK program.

That word no longer means "the code the others run". It used to: `tamga-c` exposed this exact crate
through a C ABI, and `tamga-java`/`tamga-swift` bound to `tamga-c` in turn. All three went native —
Java and Swift on 2026-08-12, `tamga-c` in its v1.3.0 — so **no repository depends on this crate any
more**. What it is instead is the implementation every other SDK is checked *against*: the offline
fixtures the other repos ship are run through this crate's verifier before being committed, so a
divergence here still surfaces everywhere, just as a conformance failure rather than as a shared
bug. Correctness in `src/crypto/` and `src/checkout/` is still the highest-priority concern in this
repository — see the GOTCHAS section below before touching either.

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
  second seat. The limiter buckets per `(caller, route pattern)`, and with proxy headers untrusted
  a whole fleet shares one bucket per route — `ping-heartbeat` and `reset-heartbeat` therefore
  *must* stay on the retryable-suffix list. Neither ends with `/actions/ping` (that is the process
  ping route), so a suffix list without them silently drops throttled heartbeats until the machine
  is stranded at `DEAD` (and culled outright, on a `require_heartbeat` policy).
- **Model all 24 `ValidationCode` variants, but only 16 are live.** Reachable: `VALID`,
  `SUSPENDED`, `EXPIRED`, `OVERDUE`, the four `*_SCOPE_MISMATCH`es for product/policy/user/
  environment, plus `FINGERPRINT_SCOPE_MISMATCH`, `ENTITLEMENTS_MISSING`, `TOO_MANY_MACHINES`,
  `TOO_MANY_CORES`, `TOO_MUCH_MEMORY`, `TOO_MUCH_DISK`, `TOO_MANY_PROCESSES` and `TOO_MANY_USES`.
  `NOT_FOUND` is declared but never emitted — the handler short-circuits to HTTP 404 instead. The
  remaining 7 (`BANNED`, `TOO_MANY_USERS`, `HEARTBEAT_DEAD`, `HEARTBEAT_NOT_STARTED`,
  `COMPONENTS_SCOPE_MISMATCH`, `CHECKSUM_SCOPE_MISMATCH`, `VERSION_SCOPE_MISMATCH`) are wired into
  the enum for forward-compatibility but never actually returned; the last two are structurally
  unreachable, since the scope fields that would produce them are refused first. Use
  `#[serde(other)]` so a future server-side addition doesn't hard-fail deserialization.
- **The five over-limit outcomes have create-time twins.** `POST /machines` runs the
  machine/core/memory/disk checks through the policy's overage strategy: a permissive strategy
  creates the row and defers the limit to validation, a strict one refuses with `422`
  `MACHINE_LIMIT_EXCEEDED` / `CORE_LIMIT_EXCEEDED` / `MEMORY_LIMIT_EXCEEDED` /
  `DISK_LIMIT_EXCEEDED`. Both shapes have to be handled; `error::LimitExceededCode` normalizes the
  `422` onto the matching `ValidationCode`, and `Client::activate_machine` keeps the
  create→validate→rollback path for the permissive case. Do not delete anything on the create-time
  path — no row was created, and the machine holding the seat is somebody else's.
- **Machine `memory` and `disk` are megabytes, not bytes.** They feed the licence's
  `machines_memory_count`/`machines_disk_count` totals. A caller reporting 16 GiB as
  `17179869184` inflates the total by ~10^6 and trips `MEMORY_LIMIT_EXCEEDED` on the next
  activation against that licence.
- **`ScopeObject` has 8 fields; 6 are enforced and 2 are refused.** `product`, `policy`, `user`,
  `environment`, `fingerprint` and `entitlements` are all checked server-side now. `version` and
  `checksum` return `422 SCOPE_NOT_SUPPORTED` — deliberately, because neither has anything
  server-side to compare against, and a scope that silently passes is worse than one that is
  missing: it gets relied on. That `422` fails the *whole* validate call, so the SDK skips
  serializing both fields: a caller that still sets one degrades to an unscoped validate rather
  than to no validate at all. `scope.entitlements` takes entitlement **codes**, not UUIDs, and is
  satisfied by inherited rows as well as direct ones.
- **`page[after]` is inert on `GET /licenses/{id}/entitlements`.** The listing unions direct and
  policy-inherited rows, so no single keyset cursor describes it and the server applies no cursor
  predicate; `limit` (default 25, max 100) is the only bound and there is no `meta`/`links` to
  signal truncation. Never loop on that route — the same first page comes back forever. The
  cursor on `GET /machines/{id}/components` is real and does advance; do not "fix" both together.
  The list rows also carry an `inherited` flag the item route knows nothing about: an inherited
  entitlement 404s on `GET .../entitlements/{id}`, so list-then-get-each is not a valid pattern.
- **`reset-heartbeat` and `generate-offline-proof` are role-gated, not permission-gated.** Both
  answer `403` for every `LicenseToken` caller, i.e. every raw licence-key client, no matter what
  permissions the key holds. `reset-heartbeat` is the server's only way to unstick a wedged
  heartbeat job, so an embedded client has no recovery path there — it needs a back-office
  credential.
- **`DEAD` does not mean the machine was culled — keep pinging it.** `Machine::heartbeat_status*`
  derives the state purely from `last_heartbeat_at` versus the window and never consults
  `require_heartbeat`, while the cull job early-returns on `!policy.require_heartbeat` and its
  claim query filters on `AND p.require_heartbeat`. That column is `NOT NULL DEFAULT FALSE`, so on
  a default policy **nothing is ever culled**: a machine reports `DEAD` forever with its row, and
  the seat it holds against the licence, still in place. Pinging such a machine revives it — the
  update is a bare `SET last_heartbeat_at = NOW()` with no resurrection check.
- **…but no *ping* can report `DEAD`, so do not frame the rule around seeing it there.**
  `ping-heartbeat` writes `last_heartbeat_at = NOW()` and then computes the status from that same
  timestamp (`heartbeat_status_within`, `machines/model.rs:124-146`), so the age is ~0 and it
  answers `ALIVE`/`RESURRECTED` every time; `reset-heartbeat` nulls the column and answers
  `NOT_STARTED`; `POST /machines` never sets it and answers `NOT_STARTED`; and `validate` never
  constructs `HEARTBEAT_DEAD` (zero hits in `validate_license.rs`). **Checkout is the exception and
  `DEAD` is genuinely reachable there:** `check_out_machine.rs:114` and
  `generate_offline_proof.rs:38` both resolve via `queries::find_by_id` — a policy-joined read of a
  row nobody just wrote — then serialize with `MachineResource::from`. In this crate
  `verify_machine_file` returns a `MachineResource`, and `Client::generate_offline_proof` returns
  one directly, so both surface `heartbeat_status` and it can be `DEAD`. Consequences: **never stop
  the ping loop on a status** (the rule stands and never needed `DEAD` to justify it), the only
  terminal signal is a `404 NOT_FOUND`, and no `DEAD` branch belongs against a *ping* response —
  put it on the checkout path instead. `GET /machines/{id}` and the list would carry it too;
  neither is exposed yet (M11 / M36).
- **Processes are never reaped — a registered process leaks its slot.** `process_process_heartbeat`
  and `find_and_claim_dead_processes` implement the 30s window and the delete-on-expiry sweep, but
  a `grep` over the server tree finds two hits for each: their own definitions, and no call sites.
  `scheduler.rs`'s `TICKS` wires only the machine side (`cull_dead_machines` →
  `find_and_claim_dead_machines` → `process_machine_heartbeat`); there is no process tick. So the
  observable behaviour is the opposite of what the code reads like: no process is ever marked dead,
  `process.heartbeat.dead` is never emitted, and no row is ever deleted. `create_process` increments
  the licence's `machines_process_count` and nothing decrements it on its own, so a leaked process
  holds its slot against `max_processes` forever. Only an explicit
  `DELETE /v1/accounts/{account_id}/processes/{process_id}` releases it — that route **does** exist
  server-side and decrements the counter, but this crate exposes no method for it, so a Rust caller
  currently cannot release the slot at all. Same defect class as the `DEAD` bullet above: a claim
  that is true of code that never runs.
- **The heartbeat window is policy-driven, and this crate cannot read it.** `heartbeat_duration`
  is not inert: `Policy::effective_heartbeat_duration_secs`
  (`tamga-api/src/features/policies/model.rs:262-264`) returns the policy value and uses 600s only
  as the null fallback, and the cull job's claim query selects on
  `COALESCE(p.heartbeat_duration, 600)` (`tamga-api/src/workers/machine_jobs.rs:213`). But there is
  no `get_policy` and no `get_machine` here, and the licence resource carries no policy
  relationship, so nothing in this crate can discover the real window — every interval it documents
  is computed against the 600s fallback. `next_heartbeat_at` is **not** a workaround: the server
  derives it from the window on the row, and the policy join exists only on the read queries this
  crate exposes no route for, so on the create / ping-heartbeat / reset-heartbeat responses it is
  always `last_heartbeat_at + 600s`. Under a policy with a shorter window a caller pinging on the
  600s assumption pings too slowly and its machines go `DEAD` on schedule. Say so plainly in docs;
  do not imply the SDK adapts. Adding a policy-aware scheduler is a later turn.
- **Auth is enforced everywhere.** A missing credential is `401`, an insufficient one `403`; the two
  are distinct states and must not be conflated in error handling. A licence key is scoped to its
  own licence — validating or checking out someone else's returns `403`. Authenticating with a
  licence key also requires the policy's `authentication_strategy` to be `LICENSE` or `MIXED`; the
  default `TOKEN` yields `401 LICENSE_NOT_ALLOWED`, which is a provisioning matter, not an SDK bug.
  `NONE` is a fourth legal value and behaves like `TOKEN` at this gate. Two more `401`s come from
  the same gate: `LICENSE_SUSPENDED`, and `LICENSE_EXPIRED` when the policy's
  `expiration_strategy` is `REVOKE_ACCESS` (the fourth legal value there — under the other three an
  expired licence still authenticates and the expiry surfaces at validate). None of the three is
  retryable; `error::LicenseAuthCode` classifies them.
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

**Both file formats derive their key with HKDF-SHA256, with different parameters** — and they are
not interchangeable. License file: salt `"tamga:license-file-key-v1"`, info `"license-file"`.
Machine file: salt `"tamga:machine-file-key-v1"`, info = the machine fingerprint, so decrypting one
needs the fingerprint as well as the license key. Do not "unify" them into a single derivation;
that silently breaks interop with whichever format you did not have in mind.

This paragraph previously described the license-file key as "intentionally not a KDF" — the raw key
bytes zero-padded to 32, via a `src/crypto/naive_key.rs` that no longer exists. That was true before
offline format v2 and is not now; `src/checkout/license_file.rs` calls
`crypto::hkdf::derive_license_file_key`. Corrected 2026-08-20 after `tamga-c`'s native rewrite was
checked against the actual code rather than against this file.

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
