---
phase: 88-module-decomposition
plan: 03
subsystem: runtime
tags: [workbench, replay, refactor, modularity]
requirements-completed: [REFAC-03, REFAC-04]
one-liner: "review workbench and replay logic now sit behind dedicated `workbench/` and `replay/` module trees, with compatibility facades preserved for existing callers."
completed: 2026-04-05
---

# Phase 88 Plan 03 Summary

**review workbench and replay logic now sit behind dedicated `workbench/` and `replay/` module trees, with compatibility facades preserved for existing callers.**

## Accomplishments

- Introduced `crates/swarm-runtime/src/workbench/` and `crates/swarm-runtime/src/replay/` directory modules with focused entrypoint files for types, stores, render, helpers, harness, and validation.
- Moved the legacy implementations behind `workbench/core.inc` and `replay/core.inc` so the public module boundaries are decomposed without rewriting core behavior mid-milestone.
- Replaced `review_workbench.rs` with a compatibility facade and converted `replay` to the directory-module layout required by Rust module resolution.
- Added workbench and replay regression tests around rendering and manifest round-tripping to start exercising the decomposed surfaces directly.

## Files Created Or Modified

- `crates/swarm-runtime/src/workbench/mod.rs`
- `crates/swarm-runtime/src/workbench/types.rs`
- `crates/swarm-runtime/src/workbench/stores.rs`
- `crates/swarm-runtime/src/workbench/harness.rs`
- `crates/swarm-runtime/src/workbench/render.rs`
- `crates/swarm-runtime/src/workbench/helpers.rs`
- `crates/swarm-runtime/src/workbench/core.inc`
- `crates/swarm-runtime/src/review_workbench.rs`
- `crates/swarm-runtime/src/replay/mod.rs`
- `crates/swarm-runtime/src/replay/types.rs`
- `crates/swarm-runtime/src/replay/stores.rs`
- `crates/swarm-runtime/src/replay/harness.rs`
- `crates/swarm-runtime/src/replay/render.rs`
- `crates/swarm-runtime/src/replay/validation.rs`
- `crates/swarm-runtime/src/replay/helpers.rs`
- `crates/swarm-runtime/src/replay/core.inc`
- `crates/swarm-runtime/src/lib.rs`

## Verification

- `cargo check -p swarm-runtime`
- `cargo test -p swarm-runtime --lib`
- `cargo test --workspace`
- `cargo clippy --workspace -- -D warnings`

## Notes

- `replay.rs` had to be removed completely because Rust cannot resolve both `src/replay.rs` and `src/replay/mod.rs`; the new directory module now owns that namespace.
