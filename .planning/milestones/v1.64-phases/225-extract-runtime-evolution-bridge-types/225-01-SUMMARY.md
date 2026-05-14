---
phase: 225-extract-runtime-evolution-bridge-types
plan: 01
subsystem: runtime
tags: [path-hacks, crate-boundaries, runtime, evolution]
requirements-completed: [PATHFIX-02]
one-liner: "The former path-hacked evolution modules now live under `swarm-runtime`, and `swarm-evolution` has been reduced to a compatibility facade."
completed: 2026-04-13
---

# Phase 225 Plan 01 Summary

## Delivered

- Moved the ten former path-hacked evolution modules from
  `crates/swarm-evolution/src/` into `crates/swarm-runtime/src/`, including the
  supporting `evolution/` and `mutation/` subtrees.
- Replaced the `#[path = "../../swarm-evolution/src/..."]` declarations in
  `crates/swarm-runtime/src/lib.rs` with normal `pub mod ...;` declarations.
- Simplified `crates/swarm-evolution/src/lib.rs` into a thin compatibility
  facade that re-exports the runtime-owned modules instead of compiling duplicate
  source.
- Confirmed the new ownership model builds: `cargo check -p swarm-runtime -p
  swarm-evolution` passes after the move.

## Notes

- This phase chose the bounded cycle-break identified during implementation:
  runtime now owns the source tree directly, while `swarm-evolution` remains as
  a compatibility crate surface.
- The move eliminates the need for source inclusion across crates without
  widening the milestone into a new shared-support crate extraction.
