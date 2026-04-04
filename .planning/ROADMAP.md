# Milestone v1.19: Local Evidence Review Surface

**Status:** ACTIVE
**Date:** 2026-04-04
**Milestone Goal:** Add a richer local review surface above the authenticated operator API so signed evidence, verification results, and promotion evidence packets can be inspected without raw JSON-first workflows or direct store access.

## Overview

`v1.18` made runtime and rollout evidence exportable and locally verifiable, but the practical operator experience is still JSON-first. Operators can inspect bundles, verifications, and promotion packets through `swarmctl` and authenticated HTTP endpoints, yet there is still no dedicated local review flow that stitches those artifacts together in one place.

`v1.19` closes that ergonomics gap without widening into a second control plane. It focuses on a richer local review surface layered on the existing authenticated HTTP contracts, evidence and verification inspection flows, and promotion evidence packet review. Quorum approvals, signed votes, multi-user control, and internet-exposed deployments remain deferred.

## Phase Plan

### Phase 59: Review Surface Shell And Auth Reuse

**Status:** PLANNED

**Goal:** Introduce a local read-only evidence review surface that reuses the authenticated operator API and existing stable IDs instead of raw store inspection.

**Requirements:** OPS-08, OPS-11

**Depends on:** Phase 58

**Plans:** 0/0 plans complete

**Success Criteria:**
- Operators can open a richer local review surface above the existing authenticated HTTP operator API.
- The review surface reuses the current bearer-auth and stable-ID artifact contracts instead of creating a second protocol or reading store files directly.
- The review surface remains local, single-node, and read-only for this milestone.

### Phase 60: Evidence And Verification Inspection

**Status:** PLANNED

**Goal:** Surface signed evidence bundles and verification results in a dedicated review flow with filtering and lineage navigation.

**Requirements:** OPS-09, OPS-12

**Depends on:** Phase 59

**Plans:** 0/0 plans complete

**Success Criteria:**
- Operators can browse and inspect signed evidence bundles and verification results without raw JSON-first workflows.
- The review flow supports filtering by subject kind and verification status.
- Evidence views preserve navigation to related stable IDs and underlying runtime or rollout artifacts.

### Phase 61: Promotion Evidence Review

**Status:** PLANNED

**Goal:** Surface promotion evidence packets, fallback lineage, and supporting evidence state in one dedicated local review flow.

**Requirements:** OPS-10

**Depends on:** Phase 60

**Plans:** 0/0 plans complete

**Success Criteria:**
- Operators can inspect one promotion evidence packet together with fallback lineage, supporting evidence references, and latest verification state.
- The review flow preserves the advisory-only boundary and does not approve, deploy, or promote anything automatically.
- Follow-on operator actions remain routed through the existing authenticated maintenance or rollout paths instead of bypassing audit trails.

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| OPS-08 | Phase 59 | Planned |
| OPS-11 | Phase 59 | Planned |
| OPS-09 | Phase 60 | Planned |
| OPS-12 | Phase 60 | Planned |
| OPS-10 | Phase 61 | Planned |

## Deferred Work

- Quorum-based approval, signed vote collection, and durable consensus receipts remain deferred until independent trust boundaries exist.
- Multi-user RBAC, federated operator workflows, and internet-exposed review surfaces remain out of scope for this cycle.
- Direct maintenance or rollout mutation from the new review surface remains deferred; bounded writes stay on the existing authenticated maintenance path.

## Next Step

`$gsd-plan-phase 59`

---
*Roadmap created: 2026-04-04*
*Last updated: 2026-04-04 for milestone v1.19 planning*
