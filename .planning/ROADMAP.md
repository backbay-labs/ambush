# Milestone v1.3: Operator Control And Replay Evaluation

**Status:** IN PROGRESS
**Phases:** 11-13
**Total Plans:** 3
**Requirements:** 8 mapped, all covered

## Overview

`v1.3` turns the durable runtime artifacts shipped in `v1.0` through `v1.2` into practical operator workflows and offline regression tooling. The milestone adds a repo-owned operator control surface, deterministic replay over persisted or fixture artifacts, and evaluation gates that catch behavioral or latency drift before future governance or evolution work is reconsidered.

## Phases

### Phase 11: Operator Control Surface

**Goal:** Expose runtime review and artifact lookup through a repo-owned operator CLI without requiring raw file inspection.  
**Depends on:** 07, 10  
**Plans:** 1

Plans:
- [x] 11-01: CLI-backed status, investigation, incident, and replay lookup surface

**Success criteria:**
1. Operator can inspect runtime status, recent decisions, investigations, and incidents through one CLI surface.
2. Operator can load replay bundles, investigation bundles, and incidents by stable IDs such as hunt ID, receipt ID, or incident ID.
3. CLI output clearly distinguishes live runtime data from offline or replay-derived context.
4. Tests cover command handlers, lookup paths, and serialization boundaries.

### Phase 12: Deterministic Replay Harness

**Goal:** Add an offline replay runner that reuses persisted artifacts and fixture corpora without executing live response actions.  
**Depends on:** 11  
**Plans:** 1

Plans:
- [ ] 12-01: Replay runner, scenario manifests, and durable result bundles

**Success criteria:**
1. Team can run deterministic offline replay from stored bundles or fixture corpora without touching live response paths.
2. Replay output captures findings, policy decisions, response receipts, investigation artifacts, and correlated incidents as durable result bundles.
3. Repo-owned scenario manifests define replay inputs plus expected invariants or outcomes.
4. Tests prove identical replay inputs produce repeatable outputs.

### Phase 13: Evaluation And Regression Gates

**Goal:** Turn replay output into practical regression reports and threshold enforcement for detection quality and hot-path performance.  
**Depends on:** 12  
**Plans:** 1

Plans:
- [ ] 13-01: Evaluation reports, expectation checks, and regression failure thresholds

**Success criteria:**
1. Team can generate evaluation reports comparing replay outcomes against expected detections, response decisions, investigations, and incidents.
2. Local or CI verification fails when replay expectations or configured latency thresholds regress past accepted limits.
3. Reports make detector, policy, and incident differences legible enough for operators to debug regressions quickly.
4. Operator docs explain how to run the replay and evaluation workflows end to end.

## Traceability Summary

| Requirement | Phase | Status |
|-------------|-------|--------|
| OPS-01 | Phase 11 | Complete |
| OPS-02 | Phase 11 | Complete |
| OPS-03 | Phase 11 | Complete |
| RPLY-01 | Phase 12 | Pending |
| RPLY-02 | Phase 12 | Pending |
| RPLY-03 | Phase 12 | Pending |
| EVAL-01 | Phase 13 | Pending |
| EVAL-02 | Phase 13 | Pending |

**Coverage:**
- v1.3 requirements: 8 total
- Mapped to phases: 8
- Unmapped: 0

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 after Phase 11*
