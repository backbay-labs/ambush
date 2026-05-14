---
phase: 224-audit-path-hack-dependencies-and-migration-plan
plan: 01
subsystem: planning
tags: [path-hacks, crate-boundaries, audit, roadmap]
requirements-completed: [PATHFIX-01]
one-liner: "The repo now has a concrete inventory of the ten runtime path hacks plus a phased migration plan to replace them with a normal crate boundary."
completed: 2026-04-13
---

# Phase 224 Plan 01 Summary

## Delivered

- Cataloged the ten active path hacks in `crates/swarm-runtime/src/lib.rs`:
  `canary`, `drafting`, `evidence`, `evolution`, `governance_prep`,
  `mutation`, `portfolio`, `promotion`, `selection`, and `strategy`.
- Mapped the runtime-side consumers that currently depend on those modules:
  `kitten_agent.rs`, `ingest/mod.rs`, `evolution_status.rs`,
  `operator_maintenance.rs`, `sphinx_agent.rs`, and the runtime error boundary
  types in `lib.rs`.
- Identified the reverse dependency surface inside `swarm-evolution`: the crate
  currently imports runtime-owned APIs through `config`, `control`,
  `detector_factory`, `evasion_coverage`, `operator_maintenance`, `replay`,
  `service`, and `RuntimeMode`, plus one debug helper in `evidence.rs`.
- Confirmed the architectural problem the path hacks are hiding: the workspace
  currently has `swarm-evolution -> swarm-runtime`, while `swarm-runtime`
  avoids a declared dependency on `swarm-evolution` only by source-including
  evolution modules under the wrong crate root.
- Defined the recommended migration sequence for the remaining milestone:
  extract the runtime-owned support seams into a neutral shared boundary in
  Phase 225, swap `swarm-runtime` to normal `swarm-evolution` re-exports in
  Phase 226, and then prove build/test/clippy/tooling health in Phase 227.

## Notes

- `RuntimeMode` is already core-owned and should stop routing through
  `swarm-runtime` as part of the bridge cleanup.
- The largest bridge seams are `replay`, `config`, `detector_factory`, and
  `service::EventExecutionContext`; those are the highest-risk areas for Phase
  225 because they define most of the current reverse dependency.
- `cargo check -p swarm-runtime` passes before the refactor, which gives the
  milestone a clean pre-change baseline for the final integration proof.
