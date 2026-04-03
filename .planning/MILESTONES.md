# Milestones

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
