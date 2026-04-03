# Stack Research: Rust-First Security Runtime

## Recommendation

Use a narrow Rust stack for the first production slice. Prefer the smallest set of libraries that supports:

- low-latency telemetry ingest
- deterministic authorization
- structured audit output
- measurable benchmarks

## Recommended Stack

### Runtime

- **Rust 2024 edition** — aligns with the current workspace and keeps the production system in one runtime
- **Tokio** — async runtime for telemetry ingestion, substrate tasks, and adapter execution
- **Tracing + tracing-subscriber** — structured logs and instrumentation for latency and audit visibility

### Data and Contracts

- **Serde + serde_json** — internal serialization and event payload handling
- **Strict Rust enums and structs** — prefer STS-owned types over stringly typed contracts
- **YAML parsing for rulesets/config** — add explicit config loading and validation rather than doc-only structs

### Security and Audit

- **Ed25519 signing** — identity and receipt signing
- **Canonical JSON + hash utilities** — deterministic receipt generation and verification
- **Merkle-backed receipt evolution later** — not required to start Phase 1, but keep interfaces compatible

### Transport and Substrate

- **In-memory substrate first** — stabilize APIs and semantics before adding durability
- **NATS JetStream second** — add durability only after the in-memory path and benchmarks are real

### Testing and Verification

- **cargo test** — unit and integration testing
- **cargo clippy** — lint gate
- **Criterion or equivalent benchmark harness** — publish p50, p95, p99, and throughput numbers for the detector path
- **Proptest** — useful for critical core logic like decay, authorization invariants, and receipt formatting

## What Not To Use In The First Slice

- **PyO3 / Python as a runtime seam** — adds avoidable operational and type-boundary complexity
- **BFT or VRF governance as a launch blocker** — not justified until there are real independent fault domains
- **Database-first persistence** — do not add a database before the detector, policy, and receipt contracts are stable
- **Too many adapter types early** — start with one sandboxed response adapter and one real narrow adapter later

## Confidence

| Area | Confidence | Notes |
|------|------------|-------|
| Rust-only runtime | High | Matches the project’s explicit priorities: speed, safety, self-containment |
| In-memory first substrate | High | De-risks API design before JetStream integration |
| Deterministic Rust policy gate | High | Cleaner safety story than cross-runtime orchestration |
| Immediate distributed governance | Low | Adds complexity before the core single-node product is trustworthy |

