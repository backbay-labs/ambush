# Roadmap: Swarm Team Six

## Milestones

<details>
<summary>Shipped milestones (v1.0 through v1.29) -- see MILESTONES.md and .planning/milestones/</summary>

Phases 1-89 shipped across milestones v1.0 through v1.29. Full history is in `.planning/MILESTONES.md`, and per-milestone roadmap snapshots live in `.planning/milestones/`.

</details>

### v1.30 Structured Observability And Adapter Resilience (In Progress)

**Milestone Goal:** Add structured JSON logging with correlation IDs, expand Prometheus metrics with counter dimensions, implement retry/circuit-breaker for response adapters, add dead-letter persistence, Kubernetes probes, and config validation.

## Phases

- [ ] **Phase 90: Structured Logging And Expanded Metrics** - Operations are traceable through correlation IDs and metrics cover all decision dimensions
- [ ] **Phase 91: Adapter Resilience And Operational Probes** - Response adapters handle transient failures gracefully, health probes separate readiness from liveness, and invalid config is rejected at load time

## Phase Details

### Phase 90: Structured Logging And Expanded Metrics
**Goal**: Operations are traceable through structured logs with correlation IDs and metrics cover all decision dimensions
**Depends on**: Phase 89 (v1.29 complete)
**Requirements**: OBS-01, OBS-02
**Success Criteria** (what must be TRUE):
  1. Every ingest request gets a unique correlation ID that appears in all downstream log entries through detect, policy, and response stages
  2. Log output is JSON-formatted with at minimum timestamp, level, correlation_id, module, and message fields
  3. Prometheus counters track verdict outcomes (allow/deny/require_human), guard rejections by guard name, adapter outcomes (success/timeout/failure), and findings by threat class and detector
**Plans**: TBD

Plans:
- [ ] 90-01: TBD

### Phase 91: Adapter Resilience And Operational Probes
**Goal**: Response adapters handle transient failures gracefully, health probes separate readiness from liveness, and invalid detector config is rejected at load time
**Depends on**: Phase 90
**Requirements**: OBS-03, OBS-04, OBS-05, OBS-06
**Success Criteria** (what must be TRUE):
  1. HTTP EDR and webhook adapters retry transient failures with configurable exponential backoff and max retry count
  2. Circuit breaker disables an adapter after N consecutive failures and re-enables it after a configurable cooldown period
  3. Failed response actions that exhaust retries are written to a dead-letter journal for later inspection instead of being silently lost
  4. /readyz returns 200 only when all runtime components are healthy; /livez returns 200 when the process is alive
  5. Detector profiles with invalid thresholds (negative entropy, out-of-range confidence, non-positive count values) are rejected at load time with clear error messages
**Plans**: TBD

Plans:
- [ ] 91-01: TBD

## Queued Milestones

- `v1.31 Runtime Agent Dispatcher And Pheromone-Driven Escalation`

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 90. Structured Logging And Expanded Metrics | v1.30 | 0/? | Not started | - |
| 91. Adapter Resilience And Operational Probes | v1.30 | 0/? | Not started | - |

---
*Last shipped milestone: v1.29 Runtime Decomposition And Test Coverage on 2026-04-05*
*Last updated: 2026-04-05 after creating v1.30 roadmap*
