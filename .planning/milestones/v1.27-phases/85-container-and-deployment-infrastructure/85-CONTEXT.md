# Phase 85: Container And Deployment Infrastructure -- Context

## User Decisions

### Decisions (Locked)

- Multi-stage Dockerfile for swarm-detect and swarmctl binaries
- docker-compose with optional NATS sidecar
- /healthz endpoint on the existing axum router
- SIGTERM graceful shutdown (drain events, flush metrics)
- Policy file reload without restart (file-watch or SIGHUP)
- Rust edition 2024, workspace builds with `cargo build --workspace`

### Deferred

- Kubernetes manifests / Helm charts (out of scope for v1.27)
- TLS certificate management (reverse proxy handles this)
- Multi-region / HA deployment (v1.28 multi-instance)
- Automatic scaling or load balancing

### Claude's Discretion

- Choice of file-watcher approach (notify crate vs SIGHUP signal handler) -- recommend both: notify for automatic detection, SIGHUP for manual trigger
- Base image for Dockerfile (debian-slim vs alpine vs distroless)
- Health check response format (JSON structure)
- Shutdown drain timeout value

## Existing Seams

- `crates/swarm-runtime/src/ingest.rs` -- `detect_http_router()` builds the axum Router with /metrics and /v1/ingest/events; /healthz goes here
- `crates/swarm-runtime/src/bin/swarm_detect.rs` -- binary entry point, --serve mode starts axum; graceful shutdown and policy reload wire here
- `crates/swarm-runtime/src/service.rs` -- `OperatorStatusReport` and `ComponentStatus` already model readiness; /healthz can reuse
- `crates/swarm-runtime/src/config.rs` -- `load_config()` parses rulesets/default.yaml; reload needs to re-call this
- `IngestState` holds `Arc<IngestRuntimeStack>` with detector and service -- reload must swap the inner config or detector

## Key Types

```rust
// From ingest.rs
pub struct IngestState {
    stack: Arc<IngestRuntimeStack>,
    detector: Arc<SupportedDetector>,
}

// From service.rs
pub struct ComponentStatus {
    pub ready: bool,
    pub durable: Option<bool>,
    pub details: String,
}

pub struct OperatorStatusReport {
    pub mode: RuntimeMode,
    pub detector: ComponentStatus,
    pub substrate: ComponentStatus,
    pub policy: ComponentStatus,
    pub response: ComponentStatus,
    pub replay_store: ComponentStatus,
    // ...
}
```

## Requirements Addressed

- DEPLOY-01: Dockerfile with multi-stage build
- DEPLOY-02: docker-compose for local development
- DEPLOY-03: Health check endpoint and graceful shutdown
- DEPLOY-04: Policy reload at runtime without restart
