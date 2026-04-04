---
phase: 42-batch-candidate-materialization-and-validation
plan: 01
subsystem: evolution-mutation
tags:
  - evolution
  - mutation
  - runtime
  - cli
one-liner: Added durable batch materialization and validation flows for mutation-spec variants.
requires:
  - 41-structured-mutation-specs
provides:
  - file-backed mutation materialization batches under `data/evolution-mutation-materialization-batches/`
  - file-backed mutation validation batches under `data/evolution-mutation-validation-batches/`
  - stable per-candidate links from mutation spec to materialization and validation artifacts
affects: []
tech-stack:
  added:
    - serde-backed batch reports and index files
  patterns:
    - guided mutation reuses the existing single-candidate materialization and validation lanes
    - blocked candidates stay persisted and visible inside batch reports
key-files:
  modified:
    - crates/swarm-runtime/src/mutation.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
    - .gitignore
key-decisions:
  - "Keep batch artifacts in the mutation module and persist normal materialization and validation records underneath them."
  - "Reuse the existing drafting validation refresh path per candidate instead of inventing a second batch-only verifier."
  - "Exit nonzero on blocked batch validation while still preserving blocked entries for later review."
patterns-established:
  - "Mutation specs now expand into one durable candidate bench with per-candidate evidence chains."
requirements-completed:
  - EVOL-12
  - EVOL-13
  - EVOL-14
duration: 33min
completed: 2026-04-03
---

# Phase 42: Batch Candidate Materialization And Validation Summary

**The runtime now materializes every variant in one mutation spec and refreshes validation evidence across that batch while preserving per-candidate artifact IDs.**

## Accomplishments

- Added materialization-batch and validation-batch report/store types to `crates/swarm-runtime/src/mutation.rs`.
- Added `swarmctl evolution-mutation-materialize-batch` and `evolution-mutation-validate-batch` plus stable-ID reload commands.
- Preserved queue references, mutation dimensions, and per-candidate materialization and validation IDs inside batch artifacts.
- Added runtime tests covering one ready candidate and one blocked candidate inside the same validation batch.
