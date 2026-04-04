---
phase: 41-structured-mutation-specs
plan: 01
subsystem: evolution-mutation
tags:
  - evolution
  - mutation
  - runtime
  - cli
one-liner: Added durable guided-mutation specs that package explicit candidate variants above the reviewed draft lane.
requires:
  - 40-queue-reconciliation-and-handoff-readiness
provides:
  - file-backed mutation-spec storage rooted under `data/evolution-mutations/`
  - source refs from reviewed drafts or materialized candidates
  - explicit variant append and stable-ID reload through `swarmctl`
affects: []
tech-stack:
  added:
    - serde-backed mutation-spec reports and index files
  patterns:
    - guided mutation stays operator-authored and off the hot path
    - mutation specs preserve queue lineage without auto-enqueueing new candidates
key-files:
  modified:
    - crates/swarm-runtime/src/mutation.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - crates/swarm-runtime/src/lib.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Keep guided mutation in a dedicated runtime module instead of growing `drafting.rs` further."
  - "Represent mutation design as a durable spec plus explicit variant append operations rather than a free-form manifest edit flow."
  - "Allow mutation specs to start from either a reviewed draft or a materialized candidate so later batch work can branch from either seam."
patterns-established:
  - "The evolution lane now has a stable artifact for multi-candidate intent before batch materialization starts."
requirements-completed:
  - EVOL-10
  - EVOL-11
duration: 26min
completed: 2026-04-03
---

# Phase 41: Structured Mutation Specs Summary

**The runtime now preserves operator-authored mutation specs as durable artifacts that can branch explicit variants from reviewed drafts or materialized candidates.**

## Accomplishments

- Added `crates/swarm-runtime/src/mutation.rs` with mutation-spec report, record, store, harness, and render logic.
- Added `swarmctl evolution-mutation-create`, `evolution-mutation-add-variant`, and `evolution-mutation-result`.
- Preserved source kind, draft/materialization lineage, pressure references, and reviewed queue references in one artifact.
- Added runtime tests for both draft-backed and materialization-backed mutation-spec creation.
