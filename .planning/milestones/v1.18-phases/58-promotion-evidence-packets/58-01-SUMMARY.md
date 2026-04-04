---
phase: 58-promotion-evidence-packets
plan: 01
subsystem: evidence
tags:
  - evidence
  - promotion
  - advisory
  - rollout
one-liner: Added advisory promotion evidence packets assembled from finalized rollout artifacts and signed supporting evidence.
requires:
  - 57-local-verification-and-evidence-surfaces
provides:
  - durable promotion evidence packets
  - `swarmctl promotion-evidence-create` and `promotion-evidence-result`
  - fail-closed support checks for promotion, canary, verification, and shadow evidence
affects: []
tech-stack:
  added: []
  patterns:
    - Promotion packet assembly reuses existing rollout artifacts and signed evidence summaries instead of regenerating source artifacts
key-files:
  modified:
    - crates/swarm-runtime/src/evidence.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - crates/swarm-runtime/src/operator_http.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Assemble promotion evidence packets from existing promotion outcome plus supporting bundle verification status."
  - "Persist blocked packets when evidence is missing or unverified instead of silently refusing packet creation."
  - "Keep the packet advisory-only even when all supporting evidence is present and verified."
patterns-established:
  - "Production rollout outcome can now be handed off as one durable evidence packet above the single-node promotion lane."
requirements-completed:
  - TRST-01
  - TRST-02
duration: 44min
completed: 2026-04-04
---

# Phase 58: Promotion Evidence Packets Summary

**The runtime can now assemble one advisory promotion evidence packet that preserves finalized rollout outcome, fallback lineage, and signed supporting evidence references.**

## Accomplishments

- Added durable promotion evidence packet storage above the existing production-promotion artifact.
- Reused signed evidence bundle summaries and latest verification status for promotion, canary, verification, and shadow support checks.
- Wired `swarmctl promotion-evidence-create` and `promotion-evidence-result` for packet assembly and reload.
- Exposed persisted promotion evidence packets through the authenticated operator surface for later trust-boundary review.
