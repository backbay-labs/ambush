# Milestone v1.17: Authenticated Operator Surface

**Status:** ACTIVE
**Date:** 2026-04-04
**Milestone Goal:** Extend the repo-owned operator lane from `swarmctl` into a narrowly scoped authenticated local HTTP surface for review and bounded maintenance, without widening into quorum governance or a multi-user control plane.

## Overview

`v1.16` completed the packet-set and portfolio-history seam above governance-prep artifacts, but all operator interaction still runs through the repo-owned CLI. The runtime already emits serializable status reports, stable-ID artifact views, and durable governance-prep records, so the next practical step is not distributed governance. It is a small authenticated surface that can expose those same views locally and record explicit maintenance actions.

`v1.17` keeps the runtime single-node, repo-owned, and fail-closed. It introduces authenticated control-plane contracts, authenticated review endpoints, and durable audit records for bounded maintenance operations. It does not introduce multi-user RBAC, internet exposure, or quorum-based approval.

## Phase Plan

### Phase 53: Authenticated Control Plane Contracts

**Status:** PLANNED

**Goal:** Define a local authenticated HTTP control-plane boundary that reuses existing runtime and artifact types instead of forking a second operator model.

**Requirements:** OPS-04

**Depends on:** Phase 52

**Plans:** 0/0 plans complete

**Success Criteria:**
- The runtime can host a narrow local HTTP control surface in addition to `swarmctl`.
- Control-plane access fails closed when authentication material is missing or invalid.
- Request and response contracts reuse the existing serializable status and artifact-view types wherever possible.
- Docs define the local-only authentication model and explicitly defer multi-user, RBAC, and internet-exposed deployments.

### Phase 54: Operator Review And Artifact Endpoints

**Status:** PLANNED

**Goal:** Expose authenticated read surfaces for runtime state, stable-ID artifact lookup, and governance-prep review flows.

**Requirements:** OPS-06

**Depends on:** Phase 53

**Plans:** 0/0 plans complete

**Success Criteria:**
- Operators can fetch runtime status and recent review context through authenticated endpoints.
- Operators can reload stable-ID artifact views through the control surface without reading raw store files.
- Packet-set, portfolio-history, and governance-prep summaries are available through authenticated read endpoints with bounded filtering.
- Endpoint payloads stay aligned with the existing CLI-backed report and artifact flow.

### Phase 55: Maintenance Actions And Audit Trails

**Status:** PLANNED

**Goal:** Allow a bounded set of approved maintenance operations through the control surface while preserving durable audit records.

**Requirements:** OPS-05, OPS-07

**Depends on:** Phase 54

**Plans:** 0/0 plans complete

**Success Criteria:**
- Operators can invoke a small approved set of maintenance actions through the authenticated control surface.
- Each maintenance request requires explicit operator identity and rationale.
- Maintenance results persist stable audit records that capture actor, target, request, and final outcome.
- Maintenance endpoints remain bounded and do not mutate rollout, governance, or promotion state beyond the approved maintenance scope.

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| OPS-04 | Phase 53 | Planned |
| OPS-06 | Phase 54 | Planned |
| OPS-05 | Phase 55 | Planned |
| OPS-07 | Phase 55 | Planned |

## Deferred Work

- Quorum-based approval, signed votes, and durable consensus receipts remain deferred until independent trust boundaries exist.
- Multi-user RBAC, federated auth, and internet-exposed operator deployments remain out of scope for this cycle.
- A TUI remains secondary to the authenticated local HTTP surface and can be revisited later if it still adds value.
- Fleet-wide rollout control and distributed governance execution remain out of scope while the runtime stays single-node.

## Next Step

`$gsd-plan-phase 53`

---
*Roadmap created: 2026-04-04*
*Last updated: 2026-04-04 for milestone v1.17 planning*
