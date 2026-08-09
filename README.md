# tamga-rust

[![Crates.io](https://img.shields.io/crates/v/tamga.svg)](https://crates.io/crates/tamga)
[![docs.rs](https://img.shields.io/docsrs/tamga)](https://docs.rs/tamga)
[![CI](https://github.com/tamga-sh/tamga-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/tamga-sh/tamga-rust/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Official Rust SDK for [Tamga](https://tamga.sh). Integrate license
activation, offline verification, and machine management into your Rust
applications.

> **Status: scaffold.** This crate currently contains project structure,
> module wiring, and doc-comment placeholders only — no HTTP client or
> cryptographic verification is implemented yet. The snippet below shows the
> *intended* API shape and will not compile against the crate as it stands
> today. Track implementation progress in
> [`docs/plans/tamga-rust.plan.md`](docs/plans/tamga-rust.plan.md).

## Install

```bash
cargo add tamga
```

Published on [crates.io](https://crates.io/crates/tamga) as the bare name
`tamga` — see [`docs/sdk.md`](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md)
in `tamga-api` for the full cross-SDK naming rationale.

## Quickstart (illustrative — stub API, not yet implemented)

```rust,ignore
use tamga::client::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::builder()
        .account_id("your-account-id")
        .base_url("https://api.tamga.sh")
        .build()?;

    let client = Client::new(config)?;

    // Validate a license by its raw key.
    let result = client.validate_by_key("YOUR-LICENSE-KEY").await?;

    match result.meta.code {
        tamga::models::validation::ValidationCode::Valid => {
            println!("license is valid");
        }
        other => {
            println!("license is not valid: {other:?}");
        }
    }

    Ok(())
}
```

## Offline verification

The core value proposition of this SDK over hand-rolling HTTP calls is that,
once you check out a signed `.lic`/`.mach` file and embed the relevant public
key in your application, verification works with **no network access at
all**:

```rust,ignore
let license = tamga::checkout::license_file::verify_license_file(
    &pem_contents,
    &account_ed25519_pubkey,
    Some(license_key),
)?;
```

## Security notes

Two intentional, non-obvious cryptographic choices in this SDK's `.lic`
verifier exist because they replicate exact server behavior — **do not
"fix" either of them**:

1. **Signature covers the base64 string, not decoded bytes.** The `.lic`
   file's Ed25519 signature is computed over the ASCII/UTF-8 bytes of the
   `enc` field's base64-encoded *string*, not the bytes you get after
   base64-decoding it. Verifying against the decoded bytes will silently
   fail against every real server-issued file.
2. **License file encryption key is not a KDF.** The AES-256-GCM key for an
   encrypted `.lic` file is the raw UTF-8 bytes of the license key string,
   zero-padded or truncated to exactly 32 bytes — not a hash, not HKDF, not
   PBKDF2. Machine files (`.mach`), by contrast, *do* use a proper
   HKDF-SHA256 derivation. Don't assume the two formats share a key-derivation
   strategy.

See `src/crypto/naive_key.rs` and `src/crypto/ed25519.rs` for the
authoritative doc comments once implemented.

## Known Server-Side Gaps (scoped to this SDK)

The full list lives in `tamga-api`'s
[`docs/sdk.md`](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md)
→ "Known Server-Side Gaps". Items that affect this SDK's implemented
surface:

- Only 14 of 24 `ValidationCode` values are reachable today; this crate
  models all 24 but only the reachable subset is exercised by tests.
- Auth (`Authorization` header) is not enforced server-side on license or
  machine endpoints yet — send real credentials anyway; don't assume a bad
  credential is rejected today.
- The server never returns `429 Too Many Requests` under the current
  deployment — this SDK has no client-side backoff logic keyed on it.
- Freshly-created policies report non-existent enum strings
  (`"DENY_ACCESS"`, `"NO_RESURRECTION"`) as their defaults; this SDK treats
  any unrecognized policy-field value as the "no restriction" variant to
  match actual server behavior rather than the literal string.
- Auto-update / release-checking (`GET /releases/actions/upgrade`) is not
  built into this SDK — it crashes at runtime server-side today.

## Documentation

- [`docs/plans/tamga-rust.plan.md`](docs/plans/tamga-rust.plan.md) — this
  repo's implementation plan and architecture reference.
- [`docs/sdk.md`](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md)
  in `tamga-api` — the authoritative protocol/feature specification every
  field name, endpoint, and enum value in this SDK is verified against.
- [docs.rs/tamga](https://docs.rs/tamga) — generated API reference (once
  published).

## License

Licensed under the MIT License. See [LICENSE](LICENSE).
