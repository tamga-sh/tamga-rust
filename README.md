# tamga

[![Crates.io](https://img.shields.io/crates/v/tamga.svg)](https://crates.io/crates/tamga)
[![docs.rs](https://img.shields.io/docsrs/tamga)](https://docs.rs/tamga)
[![CI](https://github.com/tamga-sh/tamga-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/tamga-sh/tamga-rust/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Official Rust SDK for Tamga. Integrate license activation, offline
verification, and machine management into your Rust applications.

## Install

```bash
cargo add tamga
```

The crate is published under the bare name `tamga`. It targets Rust 1.75 or
later (`rust-version` in `Cargo.toml`, pinned by a dedicated MSRV job in CI).

TLS backend is selectable: `rustls-tls` is on by default, `native-tls` is
available instead.

```toml
[dependencies]
tamga = { version = "0.2", default-features = false, features = ["native-tls"] }
```

## Quickstart

```rust
use tamga::models::validation::ValidationCode;
use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::builder("YOUR-ACCOUNT-ID", "api.tamga.sh")
        .auth(AuthTransport::License("YOUR-LICENSE-KEY".to_string()))
        .build();

    let client = Client::new(config)?;

    let result = client.validate_by_key("YOUR-LICENSE-KEY", None).await?;

    match result.meta.code {
        ValidationCode::Valid => println!("license is valid"),
        other => println!("license is not valid: {other:?} ({})", result.meta.detail),
    }

    Ok(())
}
```

`ClientConfig::builder` takes the account ID and the API host; `auth` is
required and `build` panics without it. `examples/validate_license.rs` is a
runnable version of the above, and `examples/verify_license_file.rs` covers
the offline path.

Activating a machine is a create-then-validate flow, because no seat limit is
checked at creation time — `Client::activate_machine` composes it and deletes
the machine row again if validation comes back over the limit:

```rust
use tamga::client::CreateMachineOptions;

let result = client
    .activate_machine(
        license_id,
        "machine-fingerprint",
        CreateMachineOptions::default(),
        None, // optional validation scope
        true, // delete the new machine again if the licence is over its limit
    )
    .await?;

println!("activation outcome: {:?}", result.meta.code);
```

## Auth transports

`AuthTransport` covers four of the server's five accepted transports
(`src/transport.rs`). `Cookie: Tamga-Session=<uuid>` is deliberately not
implemented — it is browser/portal-only and needs a matching `Origin` header.

```rust
use tamga::transport::{AuthTransport, BasicAuth};

// Authorization: License <key> — primary transport for embedded/client apps.
let license = AuthTransport::License("XXXX-XXXX-XXXX-XXXX".to_string());

// Authorization: Bearer <token> — default for server-side and CI callers.
let bearer = AuthTransport::Bearer("tok-...".to_string());

// Authorization: Basic <base64>, in three sub-forms.
let basic = AuthTransport::Basic(BasicAuth::Token("tok-...".to_string()));
let basic_email = AuthTransport::Basic(BasicAuth::EmailPassword {
    email: "user@example.com".to_string(),
    password: "...".to_string(),
});
let basic_license = AuthTransport::Basic(BasicAuth::LicenseKey("XXXX-XXXX".to_string()));

// ?token=<token> — for callers that cannot set a header.
let query = AuthTransport::Query("tok-...".to_string());
```

Every request also carries a sanitized `Tamga-Version` header
(`src/transport.rs::sanitize_version`), and the validate methods take an
optional `otp` argument that becomes `Tamga-OTP` for 2FA-enabled accounts.

`AuthTransport::License` has a server-side precondition: the licence's policy
must set `authentication_strategy` to `LICENSE` or `MIXED`. That column
defaults to `'TOKEN'`, under which a licence key is not an accepted credential
at all and every request is refused with `401 LICENSE_NOT_ALLOWED`. It is a
provisioning step, not something to retry — classify it with
`TamgaError::license_auth_failure()`.

## Offline verification

Check out a signed `.lic` (or `.mach`) file once, embed your account's public
key in the application, and every later verification runs with **no network
access at all**.

```rust
use tamga::checkout::license_file::verify_license_file_with_claims;
use tamga::crypto::ed25519::public_key_from_base64;

// Embedded at build time; `pem` came from `client.check_out_license(..)`.
let pubkey = public_key_from_base64(ACCOUNT_ED25519_PUBKEY_B64)?;

let verified = verify_license_file_with_claims(&pem, &pubkey, Some(license_key))?;
println!(
    "license {} verified offline; exp={:?} jti={}",
    verified.license.id, verified.claims.exp, verified.claims.jti
);
```

`verify_license_file` returns just the licence resource if the claims are not
needed, and `verify_license_file_at` takes the current time from the caller —
use it to pass a server-derived timestamp rather than a local clock a user can
wind back.

Machine files verify the same way through
`tamga::checkout::machine_file::verify_machine_file`, with two differences:
the signature scheme comes from the licence's own `scheme` field rather than
being fixed to Ed25519, and decrypting one needs both the licence key **and**
the machine fingerprint. Lighter-weight machine proofs
(`"v1x0.<base64 signature>"`, always RSA-2048 PKCS#1 v1.5 / SHA-256) verify
through `tamga::proof::verify_offline_proof`.

### Compatibility warning: licence files are format v2 only

`alg` must end in `+v2`, and the signed `meta` claims (`iat`, `exp`, `jti`,
`kid`) live inside the signature. **A v1-issued `.lic` file is rejected
outright — there is no fallback path**
(`src/checkout/license_file.rs::verify_license_file_at`), so any caller
holding a v1 file must check out a fresh one. This is a real behavioural
break, and it is the point of v2: in v1 the requested TTL lived only in the
unsigned JSON:API envelope around the certificate, so a 24-hour trial file
stayed cryptographically valid forever.

## Security notes

- **License-file keys are HKDF-SHA256 derived.** `salt =
  "tamga:license-file-key-v1"`, `ikm = <license key>`, `info =
  "license-file"` (`src/crypto/hkdf.rs::derive_license_file_key`). Machine
  files use `salt = "tamga:machine-file-key-v1"`, `ikm = <license key>`,
  `info = <fingerprint>` (`src/crypto/hkdf.rs::derive_machine_file_key`). The
  distinct salts mean one licence key never yields the same AES key for both
  formats. The pre-v2 zero-pad/truncate transform was **deleted, not
  deprecated** — no caller can opt back into it.
- **Derived keys are wiped on drop.** Both derivation functions return
  `Zeroizing<[u8; 32]>` (`src/crypto/hkdf.rs`), so key material does not sit
  in freed-but-unzeroed memory.
- **Signed expiry is enforced, with a 60-second skew tolerance.**
  `CLOCK_SKEW_TOLERANCE_SECS` in
  `src/checkout/license_file.rs::verify_license_file_at` covers ordinary NTP
  drift and nothing more — the clock belongs to the attacker, so a generous
  allowance would just extend every expired file.
- **The signature covers the base64 string, not the decoded bytes.** The
  Ed25519 signature is verified over the ASCII/UTF-8 bytes of the `enc`
  field's base64 *string* (`src/checkout/license_file.rs` passes
  `cert.enc.as_bytes()` to `src/crypto/ed25519.rs::verify`). This replicates
  the server's signing behaviour exactly; verifying against decoded bytes
  rejects every genuine file.
- **Machine-file algorithm selection never trusts the file.** The signature
  scheme comes from the caller-supplied `scheme`, because the self-declared
  `alg` string cannot disambiguate `RSA_2048_PKCS1_SIGN` from
  `RSA_2048_JWT_RS256` — and letting untrusted input pick a crypto primitive
  is an algorithm-confusion risk regardless
  (`src/checkout/machine_file.rs::verify_machine_file`).
- **`429` is handled, with capped and jittered backoff.** `Retry-After` is
  parsed as delta-seconds (`src/client.rs::Client::parse_retry_after`) and
  clamped to 60 seconds so a hostile or misconfigured proxy cannot park the
  caller (`src/client.rs::Client::retry_delay`); without it the client falls
  back to exponential backoff plus jitter
  (`src/transport.rs::jitter_millis`). Auto-retry is scoped to every `GET`
  plus seven safe `POST` actions — `validate`, `validate-key`, `check-in`,
  `check-out`, `ping`, `ping-heartbeat`, `reset-heartbeat` — and creates are
  deliberately excluded, since repeating `POST /machines` risks burning a
  second seat (`src/client.rs::Client::is_retryable`). Every request the
  client sends goes through that wrapper, the raw-PEM checkout helpers
  included. Set
  `ClientConfigBuilder::max_retries(0)` to handle it yourself; the exhausted
  case surfaces as `TamgaError::RateLimited { retry_after }`.
- **Verification errors are deliberately coarse.** "Wrong key" and "tampered
  ciphertext" both surface as `CryptoError::DecryptionFailed`
  (`src/error.rs::CryptoError`) — a finer-grained error would be an oracle.
- **The `rsa` crate is banned.** RUSTSEC-2023-0071 (Marvin timing attack) is
  unpatched, so all RSA verification goes through `aws-lc-rs`
  (`src/crypto/rsa.rs`); the ban is enforced in CI by `deny.toml`.

## Known gaps

- Only 16 of the 24 `ValidationCode` variants are reachable server-side today;
  all 24 are modelled, with an `Unknown(String)` fallback for future additions
  (`src/models/validation.rs`).
- `ScopeObject`'s `version` and `checksum` fields are **refused** by the
  server: setting either fails the whole validate call with
  `422 SCOPE_NOT_SUPPORTED` before any check runs, so the SDK never sends
  them. The other six — including `entitlements` and `fingerprint` — are
  genuinely enforced (`src/models/validation.rs`).
- `GET /licenses/{id}/entitlements` accepts `page[after]` and ignores it. The
  listing is a union of direct and policy-inherited rows, so there is no
  cursor; `limit` (default 25, max 100) is the only bound, and a licence with
  more than 100 effective entitlements cannot be fully enumerated through that
  route. Never loop on it (`src/client.rs::Client::list_entitlements`).
- Auth **is** enforced server-side. A missing or unrecognized credential is
  `401 UNAUTHORIZED`, a valid-but-insufficient one `403 FORBIDDEN`
  (`src/error.rs`). Authenticating with a licence key also requires the
  licence's policy to set `authentication_strategy` to `LICENSE` or `MIXED`;
  the column defaults to `'TOKEN'`, under which every licence-key request is
  refused with `401 LICENSE_NOT_ALLOWED` — a provisioning precondition, not
  something to retry (`TamgaError::license_auth_failure`).
- `Client::reset_heartbeat` and `Client::generate_offline_proof` are role-gated
  and answer `403` for **every** licence-key caller; they need an
  admin/developer/product/environment credential (`src/client.rs`).
- `HeartbeatStatus::Dead` means only "the last ping is older than the heartbeat
  window" — never "the machine was removed". The cull job runs only for
  policies with `require_heartbeat` set, and that column defaults to off, so a
  machine stays `DEAD` indefinitely while its row and its seat survive, and
  `Client::ping_heartbeat` revives it.
- `HeartbeatStatus::Dead` never arrives on a ping, reset or create response. A
  ping writes `last_heartbeat_at = now` and derives the status from that same
  timestamp, so it always answers `Alive` or `Resurrected`; reset and create
  answer `NotStarted`; and validate never returns `HEARTBEAT_DEAD`. It *does*
  arrive on the checkout path: the machine embedded in a `.mach` file, and the
  one returned by `Client::generate_offline_proof`, are both read from the row
  rather than echoed from a write, so their `heartbeat_status` is a real
  staleness verdict and can be `Dead`. Branch on it there, not against a ping.
  Never stop the ping loop on a status; a `404` from the ping is the only
  terminal signal and the cue to re-activate
  (`src/models/machine.rs::HeartbeatStatus`).
- The machine heartbeat window is set by `policy.heartbeat_duration`; 600s is
  only the fallback used when that column is null. There is no `get_policy` or
  `get_machine` to read it directly, and `next_heartbeat_at` on the
  create/ping/reset responses is computed against the fallback, so it will not
  reveal a shorter window. A verified machine file or a
  `Client::generate_offline_proof` response will: both resolve through a
  policy-joined read, so `next_heartbeat_at - last_heartbeat_at` there is the
  real window. Failing that, choose the
  ping interval yourself from out-of-band knowledge of the policy, or machines
  will go `DEAD` while the client believes it is pinging often enough
  (`src/models/machine.rs::HeartbeatStatus`).
- The server does not reap process rows. The 30-second process heartbeat window
  and its delete-on-expiry sweep exist in a worker that has no call site and no
  scheduler tick, so no process is ever marked dead and no row is ever removed.
  `Client::create_process` increments the licence's `machines_process_count`
  against the policy's `max_processes` and nothing decrements it on its own, so
  a process registered and abandoned holds its slot permanently. Releasing it
  needs an explicit `DELETE /processes/{id}` — the route exists server-side but
  this crate does not expose it yet, so keep PIDs stable and register only
  what is worth tracking (`src/models/machine.rs::Pid`).
- Quick-validate's `last_validated_at` write is skipped whenever the request
  carries an `Origin` header, and the two responses are identical. This SDK
  never sets `Origin`, but a proxy that does turns the write off silently
  (`src/client.rs::Client::quick_validate`).
- Freshly created policies report `"DENY_ACCESS"` and `"NO_RESURRECTION"` as
  defaults, neither of which is a real variant. This crate treats any
  unrecognized policy-field value as the "no restriction" variant, matching
  actual server behaviour rather than the literal string
  (`src/models/policy.rs`).
- The `blocking` cargo feature is declared but has no code behind it yet;
  there is no synchronous wrapper around `Client` today.
- Release / auto-update checking is not part of this crate's surface.
- `tests/fixtures/` is still empty: the checkout tests build fixtures
  in-process against the documented wire format rather than replaying
  captured server output.

## Documentation

- [docs.rs/tamga](https://docs.rs/tamga) — generated API reference.
- [tamga.sh](https://tamga.sh) — product and API documentation.
- [`SECURITY.md`](SECURITY.md) — threat model, what counts as a vulnerability
  here, and how to report one privately.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev setup, commands, MSRV policy.

## License

Dual-licensed under either of

- MIT ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
