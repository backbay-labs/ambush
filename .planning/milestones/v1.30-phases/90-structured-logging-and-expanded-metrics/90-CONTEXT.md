# Phase 90 Context: Structured Logging And Expanded Metrics

## Decisions

- **Correlation IDs use uuid v4**: Generated at ingest entry point, threaded through all downstream stages via tracing spans.
- **JSON logging via tracing-subscriber**: Use `tracing_subscriber::fmt::layer().json()` with the `tracing-subscriber` crate's `json` and `env-filter` features. No external logging framework.
- **Extend CriticalPathMetrics in detection/metrics.rs**: All new Prometheus counters are registered alongside the existing 3 histograms in the same `CriticalPathMetrics` struct, using `prometheus_client::metrics::family::Family<Vec<(String, String)>, Counter>` for label-dimensioned counters.
- **Correlation ID field name**: `correlation_id` in both structured log fields and tracing span fields.
- **uuid crate added to workspace deps**: Add `uuid = { version = "1", features = ["v4"] }` to workspace Cargo.toml and swarm-runtime Cargo.toml.
- **tracing-subscriber features**: Add `json` and `env-filter` features to the workspace `tracing-subscriber` dependency.
- **Subscriber initialization in swarm_detect binary**: The JSON subscriber is configured in `main()` of `swarm_detect.rs`, not in library code. Library code only creates spans and emits events.
- **Counter dimensions match requirement exactly**: verdict (allow/deny/require_human), guard_rejection (by guard_name), adapter_outcome (success/timeout/failure), finding (by threat_class and detector).

## Deferred Ideas

- OpenTelemetry distributed tracing (out of scope per REQUIREMENTS.md)
- Grafana dashboard or alerting rules (out of scope per REQUIREMENTS.md)
- APM integration (out of scope per REQUIREMENTS.md)
- Log rotation or log file output (stdout JSON is sufficient for v1.30)

## Claude's Discretion

- Exact tracing span nesting structure (request-level span wrapping stage spans is reasonable)
- Whether to use `tracing::instrument` macro or manual span creation
- Counter metric naming conventions within the `swarm_` prefix namespace
