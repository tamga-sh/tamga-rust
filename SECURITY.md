# Security Policy

## Scope

`tamga-rust` is the reference implementation for the whole Tamga SDK family — `tamga-c` exposes this exact crate through a C ABI, and `tamga-java`/`tamga-swift` bind to `tamga-c` in turn. A cryptographic bug here propagates to three other SDKs. The highest-risk code lives in:

- [`src/crypto/`](src/crypto/) — Ed25519, RSA-PKCS1/PSS (via `aws-lc-rs`, never the banned `rsa` crate), ECDSA-P256, AES-256-GCM, and the HKDF-SHA256 derivations for both offline file types.
- [`src/checkout/`](src/checkout/) — `.lic`/`.mach` file parse/verify/decrypt.
- [`src/proof.rs`](src/proof.rs) — offline proof generate/verify, byte-exact JSON serialization.

## Supported Versions

This SDK is pre-1.0; the latest published minor version receives security
fixes. Once a 1.x series exists, the two most recent minor versions will
receive security patches.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a suspected security vulnerability.**

Report it privately via GitHub's [private vulnerability reporting](https://github.com/tamga-sh/tamga-rust/security/advisories/new)
feature on this repository. Include:

- The affected file(s)/function(s) and, if possible, a minimal reproduction.
- Whether the issue is a verification bypass (a forged `.lic`/`.machine` file
  or offline proof that this SDK would incorrectly accept as valid), an
  information leak, a denial-of-service via malformed/adversarial input, or
  something else.
- The version (git commit or tagged release) you tested against.

You should receive an initial response within 5 business days. Confirmed
vulnerabilities will be fixed in a private branch and disclosed via a GitHub
Security Advisory alongside the patched release; we will credit reporters
who wish to be credited.

## What Counts as a Vulnerability Here

Given this SDK's actual attack surface (an offline file/proof verifier, not
a server), the highest-severity class of bug is **a verifier that accepts
something it should reject** — for example, a signature check computed over
the wrong bytes, a scheme dispatch that picks the wrong algorithm, or an
offline proof that verifies against a differently-serialized (but
semantically equivalent) payload.

## Known, Deliberate Non-Vulnerabilities

The following are intentional design decisions, not bugs, and reports about
them will be closed without action (though corrections/clarifications are
welcome):

- The `.lic`/`.mach` Ed25519 signature is verified over the ASCII/UTF-8 bytes
  of the `enc` field's base64 **string**, not over its decoded bytes
  (`src/checkout/license_file.rs::verify_license_file_at`). This replicates
  the server's signing behaviour exactly; verifying over decoded bytes would
  reject every genuine file.
- Auth is not currently enforced server-side on the license/machine
  validate/check-in endpoints (a server-side gap, not a client-side one) —
  this SDK still always sends its configured credentials for
  forward-compatibility.
- Offline licence files must be format v2. A file whose `alg` does not end in
  `+v2` is rejected outright with no fallback
  (`src/checkout/license_file.rs::verify_license_file_at`). Refusing v1 is
  the fix, not a regression: v1 carried the requested TTL only in the
  unsigned JSON:API envelope, so a trial file stayed cryptographically valid
  forever.
- `CryptoError` deliberately does not distinguish "wrong key" from "tampered
  ciphertext" (`src/error.rs::CryptoError`) — a finer-grained error would be
  an oracle for an attacker probing for valid inputs.
