# Requirements: Swarm Team Six

**Defined:** 2026-04-05
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.29 Requirements

### Module Decomposition

- [ ] **REFAC-01**: swarmctl CLI logic is extracted into testable library harnesses with the binary reduced to a thin clap wrapper
- [ ] **REFAC-02**: operator_http.rs is split into focused route modules (approval, evolution, evidence, governance, review) each under 1.5K lines
- [ ] **REFAC-03**: review_workbench.rs is split into focused modules (sessions, capsules, exports, readiness) with test coverage for each
- [ ] **REFAC-04**: replay.rs is split into focused modules (scenarios, execution, store, experiments) each under 1.5K lines

### Test Coverage

- [ ] **TEST-01**: swarm-runtime test coverage reaches at least 2% (up from 0.23%) with priority on previously-untested modules
- [ ] **TEST-02**: ingest.rs has tests covering event validation, HTTP error cases, and batch processing edge cases
- [ ] **TEST-03**: Hot-path modules (pipeline, service, detection) are consolidated into a detection/ submodule with clear boundaries

## Future Requirements

### Structured Observability And Adapter Resilience (v1.30)

- **OBS-01**: All ingest and response operations emit structured JSON logs with request correlation IDs
- **OBS-02**: Prometheus metrics include counters for decision verdicts, guard rejections, adapter outcomes, and detector findings per threat class
- **OBS-03**: HTTP EDR and webhook adapters implement retry with exponential backoff and circuit breaker (disable after N consecutive failures)
- **OBS-04**: Failed response actions are persisted to a dead-letter journal instead of being silently lost
- **OBS-05**: /readyz and /livez endpoints exist for Kubernetes-style probe separation
- **OBS-06**: All detector profiles validate configuration thresholds on load (reject invalid entropy, confidence, or count values)

### Runtime Agent Dispatcher And Pheromone-Driven Escalation (v1.31)

- **AGENT-01**: A configurable agent dispatcher runs registered SwarmAgent implementations on a tick interval within swarm-detect
- **AGENT-02**: WhiskerAgent wraps the existing detection pipeline as the first SwarmAgent trait implementation
- **AGENT-03**: Pheromone concentration monitoring triggers mode transitions (Normal to Alert to Incident) when thresholds are crossed
- **AGENT-04**: min_sources_for_escalation is enforced as a live gate on escalation events (not just metadata)
- **AGENT-05**: Integration tests prove multi-source deposit to threshold crossing to escalation event emission

## Out of Scope

| Feature | Reason |
|---------|--------|
| Full crate extraction (splitting swarm-runtime into separate crates) | Module splitting first; crate extraction is a future quarter |
| Rewriting the evolution module mesh | Decompose the 5 giant modules first; evolution refactoring follows |
| Adding new detectors or response adapters | Structural work only in v1.29; capabilities resume in v1.31+ |
| LLM integration or Stalker agent | Agent dispatcher (v1.31) establishes the pattern; LLM agents come after |
| BFT consensus implementation | Still deferred until multi-instance trust boundaries are proven |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| REFAC-01 | Phase 88 | Pending |
| REFAC-02 | Phase 88 | Pending |
| REFAC-03 | Phase 88 | Pending |
| REFAC-04 | Phase 88 | Pending |
| TEST-01 | Phase 89 | Pending |
| TEST-02 | Phase 89 | Pending |
| TEST-03 | Phase 89 | Pending |

**Coverage:**
- v1.29 requirements: 7 total
- Mapped to phases: 7
- Unmapped: 0

---
*Requirements defined: 2026-04-05*
*Last updated: 2026-04-05 after roadmap creation*
