# Requirements: Swarm Team Six

**Defined:** 2026-04-05
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.30 Requirements

### Structured Observability

- [ ] **OBS-01**: All ingest and response operations emit structured JSON logs with request correlation IDs
- [ ] **OBS-02**: Prometheus metrics include counters for decision verdicts, guard rejections, adapter outcomes, and detector findings per threat class

### Adapter Resilience

- [ ] **OBS-03**: HTTP EDR and webhook adapters implement retry with exponential backoff and circuit breaker (disable after N consecutive failures)
- [ ] **OBS-04**: Failed response actions are persisted to a dead-letter journal instead of being silently lost

### Operational Probes And Validation

- [ ] **OBS-05**: /readyz and /livez endpoints exist for Kubernetes-style probe separation
- [ ] **OBS-06**: All detector profiles validate configuration thresholds on load (reject invalid entropy, confidence, or count values)

## Future Requirements

### Runtime Agent Dispatcher And Pheromone-Driven Escalation (v1.31)

- **AGENT-01**: A configurable agent dispatcher runs registered SwarmAgent implementations on a tick interval within swarm-detect
- **AGENT-02**: WhiskerAgent wraps the existing detection pipeline as the first SwarmAgent trait implementation
- **AGENT-03**: Pheromone concentration monitoring triggers mode transitions (Normal to Alert to Incident) when thresholds are crossed
- **AGENT-04**: min_sources_for_escalation is enforced as a live gate on escalation events
- **AGENT-05**: Integration tests prove multi-source deposit to threshold crossing to escalation event emission

## Out of Scope

| Feature | Reason |
|---------|--------|
| OpenTelemetry distributed tracing | Structured logging with trace IDs is sufficient for v1.30; full OTEL is future |
| Grafana dashboard or alerting rules | Metrics export is the deliverable; visualization is downstream |
| APM integration (Sentry, Datadog) | Structured logs feed into any APM; vendor-specific integration is future |
| Adapter-specific retry policies per action type | Uniform retry policy first; per-action tuning is future |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| OBS-01 | — | Pending |
| OBS-02 | — | Pending |
| OBS-03 | — | Pending |
| OBS-04 | — | Pending |
| OBS-05 | — | Pending |
| OBS-06 | — | Pending |

**Coverage:**
- v1.30 requirements: 6 total
- Mapped to phases: 0
- Unmapped: 6

---
*Requirements defined: 2026-04-05*
*Last updated: 2026-04-05 after milestone v1.30 definition*
