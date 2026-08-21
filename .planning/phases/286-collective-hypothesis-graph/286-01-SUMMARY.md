---
phase: 286-collective-hypothesis-graph
plan: 01
subsystem: core-contracts
tags: [collective-reasoning, hypothesis-graph, evidence, canonical-ids, config]
requires:
  - phase: 286-collective-hypothesis-graph
    provides: sealed oracle fixtures, authority boundary, and exact validation gate
provides:
  - strict typed graph/evidence/hypothesis/task/kill-chain/simulation/memory/metric records
  - canonical SHA-256 identity and signed evidence witness admission
  - bounded disabled-by-default hypothesis graph configuration
affects: [286-02, 286-03, 286-04, collective-reasoning]
tech-stack:
  added: []
  patterns: [deny_unknown_fields, BTreeMap/BTreeSet canonical records, integer basis points, logical time]
key-files:
  created:
    - crates/swarm-core/src/hypothesis_graph.rs
    - crates/swarm-core/src/config/hypothesis.rs
  modified:
    - crates/swarm-core/src/config/mod.rs
    - crates/swarm-core/src/config/root.rs
    - crates/swarm-core/src/config/defaults.rs
    - crates/swarm-core/src/config/validation.rs
    - crates/swarm-core/src/config/tests.rs
    - crates/swarm-core/src/lib.rs
    - crates/swarm-runtime/src/canary.rs
    - crates/swarm-runtime/src/promotion.rs
    - crates/swarm-runtime/src/service/tests_support.rs
key-decisions:
  - "Use integer basis points and GraphLogicalTime for deterministic confidence and scheduling records."
  - "Require key-derived producer identity and detached signatures over canonical evidence material."
  - "Keep containment records simulation-only and separate from live authority types."
  - "Preserve the signed default ruleset byte-for-byte and use serde defaults for the disabled graph shape."
requirements-completed: [COG-01, COG-02, COG-03, COG-04, COG-05, COG-06, COG-07]
metrics:
  duration: "in progress"
  completed: 2026-08-21
---

# Phase 286 Plan 01: Collective Graph Core Contracts Summary

**Strict canonical collective-reasoning records with bounded admission, append-only epistemic state, and disabled-by-default resource configuration.**

## Accomplishments

- Added typed actor, asset, credential, process, and event nodes; evidence envelopes with lineage, clock precision, ordering claims, typed payloads, and signed key-derived witnesses; typed causal edges, conflicts, contradictions, and graph admission.
- Added integer confidence distributions, competing hypothesis status/history, evidence-scoped task claims with leases/fencing and durable terminal proofs, deterministic scheduler keys, evidence-linked kill-chain claims/missing evidence, simulation-only containment options, signed privacy-minimized strategy memory, and deterministic metric reports.
- Hardened direct persisted-record deserialization, canonical ID reconstruction, map-key identity, source-identity admission, hypothesis transition semantics, graph cycles/depth/fan-out, process-parent integrity, task-role authorization, kill-chain topology, and deterministic containment ranking after independent P0/P1/P2 review.
- Added strict configuration/resource limits, default-safe values, unknown-field rejection, and zero/contradictory limit rejection. The signed shipped ruleset remains byte-for-byte unchanged and resolves the omitted field to the disabled defaults.

## Verification

- `cargo test -p swarm-core --lib --locked` — 103 passed.
- `cargo test -p swarm-core hypothesis_graph --lib` — 12 passed.
- `cargo test -p swarm-core config::tests::hypothesis_graph --lib` — 4 passed.
- `cargo clippy -p swarm-core --all-targets -- -D warnings` — passed.
- `cargo check --workspace --all-targets --locked` — passed.
- Exact shipped-default resolution and signed-ruleset attestation tests — passed.
- `cargo fmt --all -- --check` and `git diff --check` — passed.
- Authority-boundary lexical scan found no prohibited live-action imports/types or host-clock types in `hypothesis_graph.rs`.

## Issues Encountered

- Three direct swarm-runtime `SwarmConfig` test literals initially failed compilation after the additive field landed; root updated each to the disabled default.
- The originally planned `rulesets/default.yaml` edit would have invalidated its Ed25519-signed attestation. Root preserved the file at SHA-256 `bc63f0e53780325317f638b6e22f4d6f638048fc7ba177485c18592f6104c324` and made omission resolve through the tested serde default.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Enforced canonical identity checks on deserialization/admission**

- **Found during:** Task 1
- **Issue:** Mutated node/edge IDs could otherwise survive typed deserialization.
- **Fix:** Recompute canonical IDs for all node variants and causal edges during validation.
- **Verification:** Core graph negative tests and clippy pass.

**2. [Rule 3 - Blocking] Repaired tagged task target serialization**

- **Found during:** Task 2
- **Issue:** Serde cannot serialize newtype variants under an internally tagged enum.
- **Fix:** Use strict struct variants for evidence/edge/hypothesis task targets.
- **Verification:** `cargo test -p swarm-core hypothesis_graph --lib` passes.

**3. [Rule 3 - Blocking] Preserved the signed shipped ruleset**

- **Found during:** Task 3
- **Issue:** Editing `rulesets/default.yaml` changes a digest covered by two checked-in Ed25519 attestations whose private keys are unavailable.
- **Fix:** Keep the ruleset byte-identical, make the additive field serde-default to the complete disabled configuration, and update direct test literals.
- **Verification:** Original SHA-256 and size remain unchanged; config/full-package tests cover default resolution.

**4. [Rule 1 - Bug] Closed persisted-state validation and state-machine bypasses**

- **Found during:** Independent Plan 01 P0/P1/P2 review
- **Issue:** Derived serde paths and incomplete nested validation could admit tampered IDs, unbounded conflicts, forged producer identities, invalid task terminals, inconsistent kill chains, unsigned memory, or topology-limit violations.
- **Fix:** Added validated wire conversions, canonical identity checks, signed producer admission, durable terminal proofs, strict transition matrices, topology/resource validation, and adversarial regression tests.
- **Verification:** Focused graph regressions, 103 core tests, core clippy, and the all-target workspace compile pass.

**Total deviations:** 4 auto-fixed.

## Next Phase Readiness

Core contracts and config wiring are ready for downstream normalization and durable-store work. The earlier strict-TDD red-phase commit is `aa958bb`; final implementation remains for root review and commit.

---
*Phase: 286-collective-hypothesis-graph*
*Plan: 01*
*Status: implementation complete; awaiting root review and commit*
