//! TODO(tamga-rust §L): full working example — check out an encrypted
//! `.lic` file and verify it fully offline (no further network access).
//!
//! Intended flow once `Client` and `src/checkout/license_file.rs` land (see
//! `docs/plans/tamga-rust.plan.md` §B, §E):
//!
//! 1. Build a `ClientConfig` and `Client` as in `validate_license.rs`.
//! 2. Call `client.check_out_license(license_id, /* encrypt */ true,
//!    /* ttl */ Some(3600)).await` to obtain raw `.lic` bytes.
//! 3. Drop the network connection conceptually here — everything past this
//!    point works fully offline.
//! 4. Call `tamga::checkout::license_file::verify_license_file(&pem,
//!    &ed25519_pubkey, Some(license_key))` and print the recovered
//!    `LicenseResource`.
//! 5. Demonstrate the client-side expiry check the SDK is responsible for
//!    (`ttl`/`expiry` are checkout metadata only — never re-checked
//!    server-side, per `docs/sdk.md` §4).

fn main() {
    todo!(
        "stub — see docs/plans/tamga-rust.plan.md Section L; \
         implementation deferred until src/checkout/license_file.rs has a \
         real verify_license_file"
    );
}
