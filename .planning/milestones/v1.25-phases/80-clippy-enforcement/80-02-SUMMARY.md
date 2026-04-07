---
phase: 80-clippy-enforcement
plan: 02
subsystem: runtime
tags: [clippy, runtime, error-handling, verification]
requirements-completed: [OPS-30]
one-liner: "swarm-runtime production `expect`/`unwrap` sites now use explicit error handling or safe fallbacks, runtime test modules are annotated, and the full workspace validation suite is green under the stricter lint policy."
completed: 2026-04-05
---

# Phase 80: Clippy Enforcement Summary

**swarm-runtime production `expect`/`unwrap` sites now use explicit error handling or safe fallbacks, runtime test modules are annotated, and the full workspace validation suite is green under the stricter lint policy.**

## Accomplishments

- Replaced remaining production `expect` sites in `swarm-runtime` with explicit invalid-input errors, poison-lock recovery, fallible serialization, safe system-time fallbacks, and non-panicking selector logic.
- Extended the runtime test-module lint allowances across the large in-crate test suites and exempted the benchmark example so the workspace can adopt strict production linting without degrading test ergonomics.
- Cleaned up the CLI binaries under the new lint regime by removing `expect`-based argument assumptions from `swarmctl` and tightening the standalone `swarm-detect` binary for clippy cleanliness.
- Verified that formatting, clippy, build, and the full workspace test suite all remain green after the refactor.

## Files Created Or Modified

- `crates/swarm-runtime/src/evidence.rs` - replaced infallible serialization and UTF-8 assumptions with explicit error variants.
- `crates/swarm-runtime/src/review_workbench.rs`, `crates/swarm-runtime/src/operator_http.rs`, `crates/swarm-runtime/src/service.rs`, `crates/swarm-runtime/src/investigation.rs`, `crates/swarm-runtime/src/mutation.rs` - removed production `expect` usage in runtime logic.
- `crates/swarm-runtime/src/bin/swarmctl.rs` and `crates/swarm-runtime/src/bin/swarm_detect.rs` - removed CLI argument `expect` sites and clippy-cleaned the new service binary.
- `crates/swarm-runtime/src/*.rs` test modules and `crates/swarm-runtime/examples/fast_detection_bench.rs` - added scoped lint allowances for test/example-only `unwrap` and `expect` usage.

## Key Decisions

- Poisoned lock handling now recovers with `into_inner()` in metrics and investigation state because preserving runtime observability is preferable to panic-on-poison failure.
- System-clock regressions now degrade to zero-duration fallbacks instead of panicking, matching the goal of panic-free production code under strict linting.
- CLI selector validation now returns explicit invalid-input errors even for clap-constrained paths, making the binaries robust to future wiring drift.

## Verification

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo build --workspace --all-targets`
- `cargo test --workspace`

## Notes

- The strict lint policy is enforced on production code, while test and example modules use narrow, explicit allowances where assertion-heavy setup still benefits from `unwrap`/`expect`.
