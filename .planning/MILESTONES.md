# Milestones

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
