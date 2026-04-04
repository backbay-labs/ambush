# Milestones

## v1.18 Signed Evidence And External Verification (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- stable-ID runtime, rollout, and maintenance artifacts can now be exported as signed evidence bundles with canonical payloads, digests, signer metadata, and receipt-chain context
- local verification reports now detect payload, digest, signature, or signer drift and can be reloaded through both `swarmctl` and the authenticated operator surface
- advisory promotion evidence packets now tie rollout outcome, fallback lineage, and verified supporting evidence into one governance-ready artifact without implementing quorum approval

---

## v1.17 Authenticated Operator Surface (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now run a local authenticated HTTP control surface in addition to `swarmctl`
- runtime status, stable-ID runtime artifact lookup, and governance-prep review artifacts are now available through authenticated local endpoints
- bounded maintenance actions now persist durable stable-ID audit trails for applied and blocked requests

---

## v1.16 Governance Packet Sets And Portfolio History (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now group multiple governance-ready review packets into durable packet-set artifacts and split child subsets while preserving source evidence lineage
- portfolio history snapshots now derive cross-cohort survival, rollout outcomes, and review debt from existing strategy memories instead of duplicating canary or promotion state
- packet-set and portfolio-history review surfaces are now available through `swarmctl` with stable-ID reload and cohort filtering

---

## v1.15 Cross-Batch Portfolio And Governance Prep (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now assemble durable cross-batch portfolio artifacts from multiple ranked selections and campaign cohorts through `swarmctl`
- portfolio entries now preserve ranking, selection, mutation-batch, validation-batch, cohort, and rollout-lineage context while supporting explicit include, defer, or drop decisions
- curated portfolio entries can now produce governance-ready review packets that reuse existing evidence and fail closed with persisted blocked artifacts instead of implementing distributed governance

---

## v1.14 Ranked Candidate Rollout Bridge (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- ranked shortlist packets can now be turned into durable ranked-candidate selections without re-materializing experiment manifests
- operators can now inspect, list, and explicitly accept, defer, or reject ranked-candidate selections through `swarmctl`
- accepted ranked-candidate selections can now bridge back into the existing queue, handoff, and bounded canary path while blocked or stale selections fail closed with persisted bridge artifacts

---

## v1.13 Guided Mutation And Candidate Ranking (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now derive durable mutation specs from reviewed drafts or materialized candidates without hand-editing multiple manifests
- one mutation spec can now materialize and validate a deterministic batch of candidate variants while preserving per-candidate lineage, proof, advisory, and validation evidence
- deterministic candidate rankings and shortlist review packets now preserve materialization, validation, and reviewed queue references without mutating the later rollout lanes

---

## v1.12 Draft Materialization And Validation Bundles (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- reviewed draft proposals can now be materialized into repo-owned detector experiment manifests with preserved lineage, source experiment references, digests, and applied profile changes
- materialized candidates can now refresh experiment, verification, proof, shadow, and advisory scorecard evidence through one fail-closed validation bundle
- draft-backed queue proposals can now be reconciled in place and marked handoff-ready for the existing accepted-queue canary path without creating duplicate rollout state

---

## v1.11 Proposal Drafting And Selection Pressure (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- replay regressions, verification drift, and strategy-memory gaps can now be materialized as durable selection-pressure reports with stable IDs, explicit rationale, and source-artifact references
- operators can now persist proposal draft artifacts with explicit strategy and lineage hints through `swarmctl` without auto-enqueueing them into rollout
- draft promotion now creates a durable reviewed-queue entry plus a separate promotion record that preserves the pressure source, draft, operator reason, and resulting queue proposal reference

---

## v1.10 Queue Handoff And Canary Launch (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- accepted evolution proposals can now be packaged into durable queue-to-canary handoff packets with stable IDs, proof references, verification references, and shadow evidence
- handoff creation now fails closed on unaccepted proposal state, invalid proof status, missing experiment path, or inconsistent shadow evidence while still preserving blocked packets
- operators can now launch bounded canary directly from a stable handoff packet through `swarmctl`, and the handoff artifact retains the resulting canary run ID

---

## v1.9 Verified Evolution Queue (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- candidate detector updates can now be persisted as proof-backed evolution proposals with stable IDs, lineage, verification references, advisory summaries, and durable review state
- proof artifacts now attest experiment, verification, and lineage evidence with deterministic SHA-256 digests and fail queue admission closed when evidence is missing or inconsistent
- operators can create proofs, inspect queue entries, and record accept, defer, or reject decisions through `swarmctl` without mutating canary or production state

---

## v1.8 Production Memory And Strategy Scoring (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- completed canary and production-promotion artifacts now produce durable strategy-memory records keyed by stable memory IDs
- strategy-memory histories now preserve latest rollout state, rollout lineage, and source-artifact references for operator reload through `swarmctl`
- advisory scorecards now compare the production baseline and verified candidates with deterministic context-aware scores, replay fallback, and explicit contribution breakdowns

---

## v1.7 Controlled Production Promotion (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- canary-approved detectors can now be promoted into the production role with explicit fallback retention and stable production-promotion IDs
- production observation windows now record divergence, latency, and detection-volume metrics and automatically roll back to the retained baseline on threshold failure
- operators can start, inspect, halt, and roll back production promotions through `swarmctl`, and the promotion artifact persists embedded canary evidence plus rollback history

---

## v1.6 Bounded Canary And Rollback (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- verified candidate detectors can now be attached to a repo-owned canary slot with explicit config, stable run IDs, and fail-closed assignment checks against verification and shadow evidence
- bounded live canary observation now records detection deltas, latency, deposit budgets, threshold results, and promotion recommendations without mutating the production baseline
- operators can start, inspect, halt, and roll back canary runs through `swarmctl`, and rollback history persists the slot, reason, and reverted baseline strategy

---

## v1.5 Formal Verification And Shadow Readiness (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- The repo now ships a canonical verification corpus manifest that captures known-bad coverage, benign controls, threat-class templates, and resource budgets for candidate detectors.
- Candidate verification and offline shadow are now first-class persisted workflows with stable IDs, explicit failure output, and `swarmctl` commands for evaluation and reload.
- Promotion review packets now tie candidate lineage, verification evidence, and shadow evidence together as a durable operator handoff artifact.

---

## v1.4 Adversarial Replay And Strategy Bench (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- named replay suites now execute through `swarmctl`, and tracked scenarios carry campaign, technique, and benign-vs-adversarial metadata
- repo-owned detector experiments now compare baseline and candidate profiles offline and persist reports by stable experiment ID
- offline safety gates now fail on known-bad coverage or threshold regressions and attribute failures back to specific scenarios or technique groups

---

## v1.3 Operator Control And Replay Evaluation (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- `swarmctl` now exposes runtime status plus stable-ID lookup for replay bundles, investigation bundles, and incidents
- offline replay now executes tracked scenarios or replay-bundle fixtures in forced `detect_only` mode and persists durable replay-run bundles
- replay evaluation now gates single runs or the full tracked `scenarios/` directory, and the runtime tests execute that corpus as a regression baseline

---

## v1.2 Async Investigation And Correlation (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- replay bundles now seed a config-backed background investigation queue with durable queued, completed, failed, and timed-out investigation artifacts
- durable incidents now assemble from investigation bundles with explicit inclusion and rejection reasons
- one operator review report now combines hot-path decisions, async investigation state, incidents, and freshness markers

---

## v1.1 Durability And Operators (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- self-contained local-journal substrate durability now survives restart and live-response mode fails closed when durability is required
- replay bundles now persist to configurable stores and can be reloaded by hunt or receipt ID without re-executing actions
- runtime stage metrics, component readiness, and recent decision correlation now ship in one operator status report

---

## v1.0 (Shipped: 2026-04-03)

**Phases completed:** 4 phases, 8 plans, 0 tasks

**Key accomplishments:**
- strict repository-owned runtime config loading with explicit `detect_only` and `live_response` modes
- concrete suspicious process-tree detector with an in-memory pheromone substrate and published hot-path benchmarks
- deterministic policy verdicts, scoped capability leases, and normalized sandbox response records
- typed audit trails, replay bundles, and an end-to-end tested detect -> authorize -> execute flow

---
