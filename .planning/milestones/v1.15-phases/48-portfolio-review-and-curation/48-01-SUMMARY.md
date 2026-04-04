---
phase: 48-portfolio-review-and-curation
plan: 01
subsystem: evolution-portfolio
tags:
  - evolution
  - portfolio
  - review
  - cli
one-liner: Added durable portfolio curation decisions and filtered portfolio listing.
requires:
  - 47-cross-batch-portfolio-assembly
provides:
  - explicit include, defer, and drop decisions for portfolio entries
  - stable portfolio listing filtered by cohort or review state
  - preserved operator decision history without mutating ranked selection evidence
affects: []
tech-stack:
  added:
    - portfolio review-state and decision-history persistence
  patterns:
    - portfolio curation remains operator-authored and advisory
key-files:
  modified:
    - crates/swarm-runtime/src/portfolio.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Store curation state on the portfolio artifact instead of translating it back onto ranked selections."
  - "Allow blocked entries to be explicitly dropped but never included."
  - "Filter portfolio listings by cohort and review state so operators can review larger cross-batch sets safely."
patterns-established:
  - "Cross-batch candidate review now has a durable operator decision lane before governance or rollout prep."
requirements-completed:
  - EVOL-26
  - EVOL-27
duration: 29min
completed: 2026-04-04
---

# Phase 48: Portfolio Review And Curation Summary

**Operators can now curate durable portfolio entries with explicit include, defer, or drop decisions while preserving immutable ranked selection evidence.**

## Accomplishments

- Added portfolio entry review states plus append-only decision history to `crates/swarm-runtime/src/portfolio.rs`.
- Added `swarmctl evolution-portfolio-decision` and filtered portfolio listing through `evolution-portfolio-list`.
- Preserved cohort, ranking, selection, validation, and rollout-lineage context while changing only the portfolio-local review state.
- Added runtime coverage for valid and invalid curation transitions.
