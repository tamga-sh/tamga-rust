## Summary

<!-- What does this PR do, and why? -->

## Checklist

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo llvm-cov nextest --fail-under-lines 80` passes
- [ ] `cargo deny check` passes
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] If this touches `/src/crypto/`, `/src/checkout/`, `/src/proof.rs`: a `security-reviewer` pass was requested and CRITICAL/HIGH findings addressed

## Test plan

<!-- How did you verify this works? -->
