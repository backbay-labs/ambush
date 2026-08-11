---
phase: 226-remove-remaining-path-directives-and-fix-imports
plan: 01
subsystem: runtime
tags: [path-hacks, imports, crate-boundaries, cleanup]
requirements-completed: [PATHFIX-03]
one-liner: "The runtime/evolution seam now compiles through normal crate and module paths with no remaining `#[path]` directives in `swarm-runtime`."
completed: 2026-04-13
---

# Phase 226 Plan 01 Summary

## Delivered

- Confirmed that `crates/swarm-runtime/src/lib.rs` no longer contains any
  `#[path = "../../swarm-evolution/..."]` directives.
- Verified that `swarm-runtime` now exposes the moved modules through ordinary
  `pub mod` declarations and `swarm-evolution` exposes them through ordinary
  `pub use swarm_runtime::{...};` re-exports.
- Updated the roadmap and requirements language to reflect the shipped boundary:
  one runtime-owned source tree plus a compatibility facade crate.

## Notes

- Phase 226 did not require another production-code refactor beyond the Phase 225
  source move; the work here was the cleanup/proof pass that shows the bridge is
  now a normal crate boundary.
