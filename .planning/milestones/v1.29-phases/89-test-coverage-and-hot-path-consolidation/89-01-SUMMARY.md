---
phase: 89-test-coverage-and-hot-path-consolidation
plan: 01
subsystem: runtime
tags: [detection, metrics, hot-path, refactor]
requirements-completed: [TEST-03]
one-liner: "the hot-path detection lane now lives under a dedicated `crate::detection` boundary, and all known runtime consumers were updated to that new path."
completed: 2026-04-05
---

# Phase 89 Plan 01 Summary

**the hot-path detection lane now lives under a dedicated `crate::detection` boundary, and all known runtime consumers were updated to that new path.**

## Accomplishments

- Created `crates/swarm-runtime/src/detection/` with `metrics.rs`, `pipeline.rs`, and a `mod.rs` re-export boundary.
- Removed the old top-level `metrics.rs` and `pipeline.rs` files from `crates/swarm-runtime/src/`.
- Updated runtime consumers in `service.rs`, `ingest.rs`, `http/core.inc`, and `examples/fast_detection_bench.rs` to import through `crate::detection`.
- Preserved the existing pipeline and metrics tests after the move.

## Files Created Or Modified

- `crates/swarm-runtime/src/detection/mod.rs`
- `crates/swarm-runtime/src/detection/metrics.rs`
- `crates/swarm-runtime/src/detection/pipeline.rs`
- `crates/swarm-runtime/src/lib.rs`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/src/http/core.inc`
- `crates/swarm-runtime/examples/fast_detection_bench.rs`

## Verification

- `cargo check -p swarm-runtime`
- `cargo test --workspace`
- `cargo clippy --workspace -- -D warnings`

## Notes

- The move is structural only; the actual detection pipeline and metrics implementations were preserved intact and re-exported through the new boundary.
