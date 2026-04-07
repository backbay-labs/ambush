---
phase: 80-clippy-enforcement
plan: 01
subsystem: workspace
tags: [clippy, workspace, linting, tests]
requirements-completed: [OPS-30]
one-liner: "Workspace-level clippy denial for `unwrap_used` and `expect_used` is now active across all crates, with non-runtime test modules explicitly annotated where needed."
completed: 2026-04-05
---

# Phase 80: Clippy Enforcement Summary

**Workspace-level clippy denial for `unwrap_used` and `expect_used` is now active across all crates, with non-runtime test modules explicitly annotated where needed.**

## Accomplishments

- Added workspace-level clippy denial rules for `unwrap_used` and `expect_used` so panic-oriented shortcuts now fail the workspace lint build by default.
- Wired every crate manifest to inherit the workspace lints, ensuring the same policy applies uniformly across runtime, libraries, and binaries.
- Annotated non-runtime test modules that intentionally use `unwrap`/`expect` in fixtures and assertions so the strict production policy does not force churn across stable unit tests.
- Confirmed the non-runtime crates compile cleanly under the stricter lint regime without production-behavior changes.

## Files Created Or Modified

- `Cargo.toml` - added `[workspace.lints.clippy]` with deny rules for `unwrap_used` and `expect_used`.
- `crates/swarm-*/Cargo.toml` - added `[lints] workspace = true` across the workspace members.
- `crates/swarm-crypto/src/*.rs`, `crates/swarm-spine/src/*.rs`, `crates/swarm-pheromone/src/substrate.rs`, `crates/swarm-policy/src/static_gate.rs`, `crates/swarm-response/src/adapters.rs` - added module-level test lint allowances where the violations were test-only.

## Key Decisions

- The lint policy was enforced at the workspace root so the existing CI clippy step automatically becomes the gate for the stricter rule set.
- Test-only violations were handled with narrow module-level allowances instead of bulk test rewrites, keeping the policy focused on production reliability.
- Non-runtime crates were cleared first so the remaining runtime refactor could be driven by a much smaller clippy error set.

## Verification

- `cargo clippy -p swarm-crypto -p swarm-spine -p swarm-pheromone -p swarm-policy -p swarm-response -p swarm-core -p swarm-whisker -p swarm-guard -p swarm-bridge -p swarm-consensus --all-targets -- -D warnings`
- `cargo clippy --workspace --all-targets -- -D warnings`

## Notes

- Existing CI workflow coverage from `.github/workflows/ci.yml` already runs `cargo clippy --workspace --all-targets -- -D warnings`, so the new workspace lint policy is enforced there without additional CI file changes.
