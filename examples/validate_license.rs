//! TODO(tamga-rust §L): full working example — validate a license by key
//! against a running `tamga-api` instance and interpret the resulting
//! `ValidationCode`.
//!
//! Intended flow once `Client`/`ClientConfig` land (see
//! `docs/plans/tamga-rust.plan.md` §B, §C):
//!
//! 1. Build a `ClientConfig` from `TAMGA_ACCOUNT_ID` / `TAMGA_BASE_URL` env
//!    vars (or hardcoded values for the example).
//! 2. Construct a `Client`.
//! 3. Call `client.validate_by_key("<license-key>").await`.
//! 4. Match on the returned `ValidationCode` and print a human-readable
//!    outcome, distinguishing the 14 reachable codes from the 10 that are
//!    declared but not yet wired server-side (see `docs/sdk.md` → Known
//!    Server-Side Gaps item 4).

fn main() {
    todo!(
        "stub — see docs/plans/tamga-rust.plan.md Section L; \
         implementation deferred until src/client.rs has a real Client"
    );
}
