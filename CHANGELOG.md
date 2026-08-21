# Changelog

All notable changes to this project will be documented in this file.

## [0.2.6](https://github.com/tamga-sh/tamga-rust/compare/v0.2.5...v0.2.6) - 2026-08-21

### Bug Fixes

- Align the client with the current tamga-api server contract (a8f8037)

- Correct the "DEAD means the machine was culled" guidance (51bb773)

- Correct the "a dead process row is deleted immediately" claim (3333077)

- Reconcile the stale 14-of-24 ValidationCode counts with the live 16 (bf9973a)

- The heartbeat window is policy-driven, not a hardcoded 600s (24c2676)

- DEAD is not observable from any route this crate calls (f783584)

- Narrow the DEAD-observability claim — checkout can report DEAD (f583c65)

- Cover the three genuinely untested lines this PR added (5193ac6)

- Mark ScopeObject::version and ::checksum #[deprecated] (928ca52)

- Verify the machine files the server actually issues (6d4f870)

- Model the wire shapes the missing read routes return (9ec931f)

- Expose the machine, process, policy and upgrade routes the server has (7ebf823)

- Correct the crate notes this turn's routes made stale (2575d38)

- Correct the write-vs-read heartbeat rule and the fingerprint search scope (631a392)

- Drop the stale 'auto-update is out of scope' line from the gotchas preamble (98671fc)

- Make the fingerprint search licence-scoped only (05e93c0)


### CI/CD

- Run CI on stacked pull requests (039d4cc)



## [0.2.5](https://github.com/tamga-sh/tamga-rust/compare/v0.2.4...v0.2.5) - 2026-08-20

### Miscellaneous

- Correct the stale claim that three SDKs run this crate ([#30](https://github.com/tamga-sh/tamga-rust/pull/30)) (e52b22b)



## [0.2.4](https://github.com/tamga-sh/tamga-rust/compare/v0.2.3...v0.2.4) - 2026-08-18

### Miscellaneous

- Bump actions/create-github-app-token from 2 to 3 ([#27](https://github.com/tamga-sh/tamga-rust/pull/27)) (5c3c9fd)

- Bump thiserror from 1.0.69 to 2.0.20 ([#13](https://github.com/tamga-sh/tamga-rust/pull/13)) (99f6d9c)



## [0.2.3](https://github.com/tamga-sh/tamga-rust/compare/v0.2.2...v0.2.3) - 2026-08-18

### Miscellaneous

- Bound every job and install step with a timeout ([#25](https://github.com/tamga-sh/tamga-rust/pull/25)) (1ac0780)



## [0.2.2](https://github.com/tamga-sh/tamga-rust/compare/v0.2.1...v0.2.2) - 2026-08-18

### Bug Fixes

- Open release PRs with a GitHub App token so required checks run ([#23](https://github.com/tamga-sh/tamga-rust/pull/23)) (8ef10c1)



## [0.2.1](https://github.com/tamga-sh/tamga-rust/compare/v0.2.0...v0.2.1) - 2026-08-18

### Bug Fixes

- Correct SDK documentation and align package metadata (0d7cb1a)



## [0.2.0](https://github.com/tamga-sh/tamga-rust/compare/v0.1.5...v0.2.0) - 2026-08-13

### Features

- [**breaking**] SDK v2 security contract — license-file HKDF, offline format v2, HTTP 429 handling (6605fe6)



## [0.1.5](https://github.com/tamga-sh/tamga-rust/compare/v0.1.4...v0.1.5) - 2026-08-12

### Bug Fixes

- Zeroize derived symmetric keys on drop (56bb511)



## [0.1.4](https://github.com/tamga-sh/tamga-rust/compare/v0.1.3...v0.1.4) - 2026-08-12

### Documentation

- Fix stale scaffold-only status and docs/plans path in CLAUDE.md (507727c)



## [0.1.3](https://github.com/tamga-sh/tamga-rust/compare/v0.1.2...v0.1.3) - 2026-08-11


## [0.1.2](https://github.com/tamga-sh/tamga-rust/compare/v0.1.1...v0.1.2) - 2026-08-11

### Documentation

- Add community health files (CoC, PR template, CODEOWNERS, SECURITY, dependabot, editorconfig) (d59c30d)



## [0.1.1](https://github.com/tamga-sh/tamga-rust/compare/v0.1.0...v0.1.1) - 2026-08-11

### Bug Fixes

- Fix release-plz changelog template and license allowlist (72b1d85)

- Grant pull-requests:read to release-plz-publish (e696374)

- Allow CDLA-Permissive-2.0 for webpki-roots (e5140e8)


This file is managed by [release-plz](https://release-plz.ieni.dev/) and
follows [Conventional Commits](https://www.conventionalcommits.org/); entries
below are generated automatically from commit history on each release PR —
do not hand-edit past entries.
