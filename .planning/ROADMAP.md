# Milestone v1.4: Adversarial Replay And Strategy Bench

**Status:** READY
**Phases:** 14-16
**Total Plans:** 3
**Requirements:** 7 mapped, all covered

## Overview

`v1.4` turns the replay loop shipped in `v1.3` into an offline adversarial lab. The milestone adds Hellcat-inspired scenario suites with richer metadata, baseline-vs-candidate detector experiments, and persisted comparison reports plus offline safety gates. Promotion, canary deployment, and governance remain explicitly out of scope.

## Phases

### Phase 14: Adversarial Scenario Corpus

**Goal:** Expand the replay corpus into named adversarial suites with campaign and technique metadata.  
**Depends on:** 12, 13  
**Plans:** 1

Plans:
- [ ] 14-01: Suite manifests, scenario metadata, and adversarial corpus execution

**Success criteria:**
1. Team can execute named adversarial suites through the offline replay harness.
2. Scenario manifests carry campaign, technique, and benign-vs-adversarial metadata.
3. Suite execution remains deterministic and reproducible from repo-owned manifests.
4. Tests cover corpus discovery and suite-level replay execution.

### Phase 15: Candidate Strategy Evaluation

**Goal:** Evaluate baseline and candidate detectors against the same replay corpus without touching production config.  
**Depends on:** 14  
**Plans:** 1

Plans:
- [ ] 15-01: Candidate strategy manifests, baseline-vs-candidate runner, and comparison metrics

**Success criteria:**
1. Team can register a candidate detection strategy as a repo-owned experiment input.
2. Baseline and candidate strategies can be evaluated side by side against the same adversarial or benign corpus.
3. Comparison output includes detection quality, false positives, and latency deltas.
4. Candidate evaluation stays fully offline and never hot-loads into the live runtime path.

### Phase 16: Experiment Reports And Offline Safety Gates

**Goal:** Persist experiment lineage and turn candidate evaluation into a practical offline safety gate.  
**Depends on:** 15  
**Plans:** 1

Plans:
- [ ] 16-01: Experiment registry, lineage reports, and known-bad regression gates

**Success criteria:**
1. Candidate experiments persist lineage, corpus version, and comparison summaries for later review.
2. Offline gates fail when a candidate loses known-bad coverage or misses configured thresholds.
3. Reports identify which scenarios, suites, or technique groups caused the regression.
4. Operator docs explain how to run adversarial suites and candidate experiments end to end.

## Traceability Summary

| Requirement | Phase | Status |
|-------------|-------|--------|
| RED-01 | Phase 14 | Pending |
| RED-02 | Phase 14 | Pending |
| RED-03 | Phase 16 | Pending |
| EVO-01 | Phase 15 | Pending |
| EVO-02 | Phase 15 | Pending |
| EVO-03 | Phase 16 | Pending |
| EVO-04 | Phase 16 | Pending |

**Coverage:**
- v1.4 requirements: 7 total
- Mapped to phases: 7
- Unmapped: 0

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.4 definition*
