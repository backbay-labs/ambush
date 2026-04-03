# Milestone v1.5: Formal Verification And Shadow Readiness

**Status:** READY
**Date:** 2026-04-03
**Milestone Goal:** Add repo-owned verification inputs, offline verification and shadow evaluation, and promotion-review artifacts without introducing live canary or distributed governance.

## Overview

This milestone turns the offline replay and experiment bench into a promotion-readiness workflow. It adds canonical verification corpora, an invariant gate for candidate detectors, shadow-style comparison against the current baseline, and one durable review packet operators can inspect before any future promotion design is considered.

The milestone stays offline-first. It does not introduce live canarying, quorum promotion, or autonomous mutation. The goal is to make candidate strategy evaluation inspectable and repeatable before the system considers any promotion path beyond the repo-owned bench.

## Phase Plan

### Phase 17: Verification Corpus And Invariants

**Goal:** Define repo-owned verification inputs for candidate detectors, including known-bad indicators, benign controls, and explicit resource-budget or invariant manifests.

**Requirements:** VER-03

**Depends on:** Phase 14, Phase 15, Phase 16

**Plans:** 1

**Success Criteria:**
- Canonical verification corpora and budgets are tracked in repo-owned manifests or config.
- Verification inputs cover known-bad, benign-control, and resource-budget concepts needed for detector evaluation.
- Documentation and tests show verification inputs can be loaded and used without touching the live runtime path.
- This phase seeds later verification and shadow workflows with stable inputs and identifiers.

### Phase 18: Verification Gate And Shadow Runner

**Goal:** Run candidate detectors through repo-owned invariant checks and shadow-style baseline comparison without live side effects.

**Requirements:** VER-01, SHD-01, SHD-02

**Depends on:** Phase 17

**Plans:** 1

**Success Criteria:**
- Candidate detectors can be verified with per-invariant pass or fail output suitable for local and CI use.
- Candidate detectors can run in shadow mode against recorded artifacts without emitting pheromones or response actions.
- Shadow reports compare baseline and candidate on detection deltas, false positives, and latency over the same artifact window.
- Failing verification or shadow runs exit nonzero so they can be used as gates.

### Phase 19: Promotion Review Packets

**Goal:** Persist verification and shadow artifacts into a promotion-ready review packet for operator decision.

**Requirements:** VER-02, PRM-01, PRM-02

**Depends on:** Phase 18

**Plans:** 1

**Success Criteria:**
- Review packets persist strategy lineage, corpus version, verification verdicts, and shadow comparison summaries.
- Verification or shadow failures preserve failing indicator references or counterexamples for operator inspection.
- Operator CLI can reload verification, shadow, and promotion-review artifacts by stable ID.
- Docs explain the end-to-end verification to shadow to review workflow.

## Traceability

| Requirement | Phase |
|-------------|-------|
| VER-03 | Phase 17 |
| VER-01 | Phase 18 |
| SHD-01 | Phase 18 |
| SHD-02 | Phase 18 |
| VER-02 | Phase 19 |
| PRM-01 | Phase 19 |
| PRM-02 | Phase 19 |

## Deferred Work

- Live canary or production promotion remains out of scope for this milestone.
- Quorum-based or BFT promotion approval remains deferred until real independent trust boundaries exist.
- Autonomous mutation and continuous evolution remain offline-only concepts.
- Multi-user control planes and authenticated operator surfaces remain secondary to verification and promotion-readiness artifacts.

## Next Step

`$gsd-plan-phase 17`

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 for milestone v1.5*
