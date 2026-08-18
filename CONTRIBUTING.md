# Contributing to tamga-rust

## Dev Setup

```bash
git clone https://github.com/tamga-sh/tamga-rust
cd tamga-rust
cargo build
```

No external services are required to build or run the unit test suite — this
is a client SDK, not a server. Integration tests that exercise the HTTP layer
run against a mocked server (`wiremock`), not a live Tamga deployment.

## Commands

```bash
cargo fmt                                            # format
cargo fmt --check                                    # format check (CI)
cargo clippy --all-targets --all-features -- -D warnings   # lint (CI uses --all-targets; plain `cargo clippy` misses test-only lints)
cargo test                                           # run tests
cargo llvm-cov nextest --lcov --fail-under-lines 80  # coverage gate (CI)
cargo deny check                                     # license/advisory/ban policy
cargo doc --no-deps --open                           # build + view docs locally
```

## MSRV Policy

Minimum Supported Rust Version is **1.75**, pinned in three places that must
stay in sync:

- `Cargo.toml` → `rust-version = "1.75"`
- `clippy.toml` → `msrv = "1.75"`
- `.github/workflows/ci.yml` → dedicated MSRV job pinned to `1.75.0`

Bumping the MSRV requires updating all three in the same PR, plus a note in
`CHANGELOG.md` (MSRV bumps are a breaking change per SemVer convention for
libraries).

## Branch & Commit Convention

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`

Commits: [Conventional Commits](https://www.conventionalcommits.org/)
(`feat: …`, `fix: …`, `docs: …`, `refactor: …`, `test: …`, `chore: …`,
`perf: …`, `ci: …`). release-plz reads this history directly to compute the
next version and generate `CHANGELOG.md` — inaccurate commit types produce an
inaccurate changelog and can skip a release entirely.

## Required Status Checks (Branch Protection)

Configure these `.github/workflows/ci.yml` jobs as required checks before
merging to `main` (job names must match the workflow exactly):

- `fmt`
- `clippy`
- `deny`
- `test-and-coverage`
- `msrv`

## Security-Sensitive Changes

Any change under `src/crypto/` or `src/checkout/` (signature verification,
key derivation, decryption) requires a `security-reviewer` pass
(`ecc:security-review`) before merge. Do not merge crypto-path changes on
`rust-reviewer` approval alone.
