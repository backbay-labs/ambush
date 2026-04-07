# Phase 91: Adapter Resilience And Operational Probes

## Context

Phase 91 closes the second half of v1.30 (Structured Observability And Adapter Resilience). Phase 90 provides structured JSON logging with correlation IDs and expanded Prometheus metrics. Phase 91 builds on that logging infrastructure to make response adapters resilient, add Kubernetes-style health separation, and reject bad detector config at load time.

## Decisions

- Retry wraps the existing `execute` path inside `HttpEdrAdapter` and `WebhookAdapter` -- it does not change the `ResponseExecutor` trait signature.
- Circuit breaker state is per-adapter-instance: `consecutive_failures: u32`, `last_failure_time: Option<Instant>`, `cooldown_duration: Duration`. State resets on success.
- Dead-letter journal is an append-only JSONL file, following the same pattern as `LocalJournalPheromoneSubstrate` in swarm-pheromone (ensure parent dir, serialize-and-append, one JSON object per line).
- `/readyz` and `/livez` are new axum routes on the same router as `/healthz` and `/metrics` in `ingest.rs`. `/livez` always returns 200. `/readyz` checks all components (same logic as `/healthz` today but separated).
- Detector profile validation is a `validate()` method on each profile struct in swarm-whisker, called from `supported_detector()` in `control.rs` when building detectors from config.
- Retry and circuit-breaker config fields live on `HttpEdrConfig` and `WebhookConfig` in `swarm-core/src/config.rs` with sensible defaults (max_retries: 3, initial_backoff_ms: 200, circuit_breaker_threshold: 5, circuit_breaker_cooldown_ms: 30000).

## Deferred Ideas

- Per-action-type retry policies (uniform policy first per REQUIREMENTS.md out-of-scope).
- OpenTelemetry distributed tracing.
- Grafana dashboards or alerting rules.
- APM integration.

## Claude's Discretion

- Whether retry helper is a standalone struct wrapping `ResponseExecutor` or inlined into each adapter. A `ResilientExecutor<E: ResponseExecutor>` wrapper is cleaner.
- Dead-letter file path: configurable in `SwarmConfig` with default `./dead-letter.jsonl`.
- Exact exponential backoff jitter strategy.
