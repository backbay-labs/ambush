# Requirements: Swarm Team Six

**Defined:** 2026-04-05
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.25 Requirements

### Service Extraction

- [ ] **OPS-26**: Detection hot path runs as a standalone binary separate from the operator workbench CLI
- [ ] **OPS-27**: Rulesets and scenarios are wired into detection config rather than only the workbench CLI

### Observability And Testing

- [ ] **OPS-28**: Critical path emits structured Prometheus metrics for detection latency, policy evaluation time, and response execution time
- [ ] **OPS-29**: Integration tests cover the full critical path from telemetry to verified receipt

### Code Quality

- [ ] **OPS-30**: Workspace enforces clippy unwrap_used and expect_used denial across all crates

## Out of Scope

| Feature | Reason |
|---------|--------|
| Multi-node or distributed detection service | Service extraction is single-node; fleet deployment is a future concern |
| eBPF or real telemetry source integration | The binary ingests synthetic telemetry; real source adapters are future work |
| Grafana dashboards or alerting rules | Metrics export is the deliverable; visualization is downstream |
| Full error-handling rewrite beyond unwrap/expect | Phase 80 fixes unwrap/expect violations; deeper error-model redesign is out of scope |
| Container images or Kubernetes manifests | Dockerfile and orchestration are future operational work |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| OPS-26 | — | Pending |
| OPS-27 | — | Pending |
| OPS-28 | — | Pending |
| OPS-29 | — | Pending |
| OPS-30 | — | Pending |

**Coverage:**
- v1.25 requirements: 5 total
- Mapped to phases: 0
- Unmapped: 5

---
*Requirements defined: 2026-04-05*
*Last updated: 2026-04-05 after milestone v1.25 definition*
