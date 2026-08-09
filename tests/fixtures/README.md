# Test Fixtures

Placeholder. This directory will hold known-good `.lic` and `.mach` files
captured from a running `tamga-api` instance, used by the integration tests
under `tests/checkout_license_file.rs`, `tests/checkout_machine_file.rs`, and
`tests/machine_offline_proof.rs` (see `docs/plans/tamga-rust.plan.md` §E, §F,
§H).

Planned contents once captured:

- `license_file_plain.lic` — unencrypted license checkout, Ed25519-signed.
- `license_file_encrypted.lic` — AES-256-GCM encrypted license checkout
  (naive key derivation from the license key string).
- `machine_file_ed25519.mach`, `machine_file_rsa_pkcs1.mach`,
  `machine_file_rsa_pss.mach`, `machine_file_ecdsa_p256.mach` — one per
  supported `LicenseScheme`, both plain and HKDF-encrypted variants.
- `offline_proof_fixture.json` — a `{ proof, dataset, account_id, machine_id,
  fingerprint, rsa_pubkey }` bundle for `verify_offline_proof` tests.

Each fixture must be captured against a real server response, not
hand-constructed — the whole point of these tests is confirming this SDK's
verifier reproduces the server's exact signing/serialization behavior
(notably the base64-string-vs-decoded-bytes Ed25519 gotcha in `.lic` files
and the byte-exact field-ordered JSON in offline proofs). A hand-built fixture
that merely matches this SDK's own (possibly wrong) assumptions would not
catch a real interop bug.
