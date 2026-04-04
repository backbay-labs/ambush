---
phase: 56-signed-evidence-bundle-export
plan: 01
subsystem: evidence
tags:
  - evidence
  - crypto
  - export
  - cli
one-liner: Added signed evidence bundle export for persisted runtime and rollout artifacts.
requires:
  - 55-maintenance-actions-and-audit-trails
provides:
  - minimal canonical-JSON and Ed25519 signing primitives
  - file-backed signed evidence bundles for stable-ID artifacts
  - `swarmctl evidence-export`, `evidence-result`, and `evidence-list`
affects: []
tech-stack:
  added: []
  patterns:
    - Signed evidence wraps existing stable-ID artifacts instead of introducing a second artifact model
key-files:
  modified:
    - crates/swarm-crypto/src/lib.rs
    - crates/swarm-runtime/Cargo.toml
    - crates/swarm-runtime/src/lib.rs
    - crates/swarm-runtime/src/evidence.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Sign a deterministic statement that includes subject metadata, timestamps, receipt refs, and payload hash instead of signing opaque file blobs."
  - "Keep evidence export repo-owned and single-node by deriving one local Ed25519 key from env-provided secret material."
  - "Reuse persisted replay, investigation, incident, maintenance, canary, promotion, verification, shadow, and promotion-review artifacts by stable ID."
patterns-established:
  - "Signed evidence bundles now provide one portable envelope format above existing runtime and rollout stores."
requirements-completed:
  - EVID-01
  - EVID-02
duration: 82min
completed: 2026-04-04
---

# Phase 56: Signed Evidence Bundle Export Summary

**The runtime can now export persisted runtime and rollout artifacts as signed evidence bundles with canonical payload bytes and durable subject metadata.**

## Accomplishments

- Replaced the `swarm-crypto` stub with repo-owned canonical JSON, SHA-256, and detached Ed25519 signing primitives.
- Added a file-backed evidence module for signed bundle persistence, summary indexing, and supporting rollout references.
- Wired `swarmctl evidence-export`, `evidence-result`, and `evidence-list` around stable-ID artifact lookup.
- Kept the contract conservative: existing artifact stores remain authoritative, and evidence export wraps them instead of replacing them.
