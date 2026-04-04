---
phase: 39-validation-bundle-refresh
plan: 01
subsystem: evolution-drafting
tags:
  - evolution
  - validation
  - runtime
  - cli
one-liner: Added fail-closed validation bundles that refresh experiment, verification, proof, shadow, and advisory evidence from materialized drafts.
requires:
  - 38-draft-candidate-materialization
provides:
  - file-backed validation bundle storage rooted under `data/evolution-validation-bundles/`
  - one CLI refresh flow for experiment, verification, proof, shadow, and advisory evidence
  - stable-ID reload through `swarmctl evolution-validation-result`
affects: []
tech-stack:
  added:
    - validation bundle reports and index files
  patterns:
    - validation bundles reuse existing experiment and proof workflows
    - drift checks fail closed and still preserve blocked review artifacts
key-files:
  modified:
    - crates/swarm-runtime/src/drafting.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Refresh validation by calling the existing harnesses rather than duplicating their internal logic."
  - "Preserve advisory scorecards in validation bundles so reconciled queue entries keep operator context."
  - "Treat proof or digest mismatches as persisted blocking reasons, not as silent validation skips."
patterns-established:
  - "Materialized draft candidates now produce one durable evidence chain before queue reconciliation."
requirements-completed:
  - VALD-01
  - VALD-02
duration: 34min
completed: 2026-04-03
---

# Phase 39: Validation Bundle Refresh Summary

**The runtime now refreshes a full evidence chain from one materialized draft candidate and persists the result as one fail-closed validation bundle.**

## Accomplishments

- Added `EvolutionValidationBundleReport`, `EvolutionValidationBundleRecord`, and `FileEvolutionValidationBundleStore`.
- Implemented `DefaultEvolutionDraftingHarness::refresh_validation_bundle`.
- Added `swarmctl evolution-validation-refresh` and `evolution-validation-result`.
- Preserved experiment, verification, proof, shadow, advisory, digest, and blocking-reason context in durable validation artifacts.
