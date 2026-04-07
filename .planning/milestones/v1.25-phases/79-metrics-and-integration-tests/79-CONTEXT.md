# Phase 79: Metrics And Integration Tests -- Context

## User Decisions

### Locked Decisions

- Use `prometheus-client` crate (official Prometheus Rust client) for metrics
- axum is already a workspace dependency; `/metrics` endpoint is an axum route
- Instrument at: `RuntimeService::process_event` (detection, policy, response stages), `detect_and_deposit` pipeline, `audit_authorize_and_execute_instrumented`
- Integration tests go as integration tests inside `crates/swarm-runtime/tests/` (Rust integration test convention)
- Scenario YAML files in `scenarios/` serve as test fixtures
- Phase 78 creates the `swarm-detect` binary which hosts the `/metrics` endpoint

### Deferred Ideas

- Grafana dashboards or alerting rules (out of scope per REQUIREMENTS.md)
- Container images or Kubernetes manifests
- Custom metric types beyond histograms for the three critical-path stages

### Claude's Discretion

- Histogram bucket boundaries for Prometheus (use the existing `LATENCY_BUCKETS_US` boundaries from `service.rs` for consistency)
- Whether to expose count/sum alongside histograms (yes, standard Prometheus convention)
- How to wire the Prometheus registry into the existing operator HTTP surface vs. a separate route

## Technical Context

### Existing Internal Metrics

The runtime already tracks per-stage latency internally via `RuntimeMetrics` in `service.rs`:
- `StageMetrics` records successes, failures, total_latency_us, max_latency_us, and bucket_counts for 7 latency buckets
- `LATENCY_BUCKETS_US: [u64; 7] = [100, 500, 1_000, 5_000, 10_000, 50_000, u64::MAX]`
- `RuntimeStage` enum: Detect, Policy, Persist, Response
- `RuntimeService::process_event` already times detection, policy, and response stages and calls `self.metrics.record()`

The task is NOT to invent metrics from scratch -- it is to expose the existing internal metrics as Prometheus histograms via the `prometheus-client` crate and add a `/metrics` endpoint.

### Critical Path Flow

```
TelemetryEvent
  -> detect_and_deposit() [whisker detect + pheromone deposit]
  -> audit_authorize_and_execute_instrumented() [policy evaluate + response execute]
  -> persist_replay_bundle() [store replay bundle]
  -> ReplayBundle with AuditTrail
```

### Existing axum Router

`operator_http.rs` has `OperatorHttpSurface::router()` which returns a `Router` with `/v1/operator/*` routes. The `/metrics` route can be added to this router or composed separately.

### Scenario Fixtures

Available scenario YAML files:
- `scenarios/office-dropper-correlation.yaml` -- two suspicious events, expects 2 replay bundles, 1 incident
- `scenarios/benign-baseline.yaml` -- benign events
- `scenarios/pdf-lolbin-execution.yaml` -- adversarial scenario
- `scenarios/python-maintenance-benign.yaml` -- benign scenario

These define `input.events[]` with telemetry payloads and `expectations` with counts and latency bounds.

## Requirements

- **OPS-28**: Critical path emits structured Prometheus metrics for detection latency, policy evaluation time, and response execution time
- **OPS-29**: Integration tests cover the full critical path from telemetry to verified receipt
