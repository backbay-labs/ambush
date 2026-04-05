# Arc as Upstream Source

Arc (`../arc/`) is a 26-crate economic trust infrastructure for governed AI agent actions. It overlaps with STS in crypto and audit primitives but serves a different domain (capability-based authorization and financial settlement vs. threat detection and live response).

ClawdStrike is the primary upstream for guards, crypto, and spine. Arc fills gaps where clawdstrike has no equivalent or where arc's implementation is more portable.

Last reviewed: 2026-04-04

## What to source from Arc (not clawdstrike)

### SIEM export

Arc's `arc-siem` crate has production Splunk HEC and Elasticsearch exporters with batching, exponential backoff, and dead-letter queues (~400 lines). ClawdStrike has OCSF event schemas but no standalone exporter.

Target: new `swarm-siem` crate wrapping arc-siem's `Exporter` trait with swarm event types (PheromoneDeposit, ResponseAction, Receipt).

### Receipt query and analytics

Arc's `arc-kernel` has 8-dimension filtered receipt queries with cursor pagination. ClawdStrike's receipt store is simpler. If swarm-spine needs efficient querying by hunt_id, agent_id, time range, or severity, arc's query module is the better reference.

Target: extend `swarm-spine` receipt store with arc-style query interface.

### CI pipeline and quality infrastructure

Arc has mature CI that STS lacks entirely:
- `.github/workflows/ci.yml` — fmt, clippy, build, test, MSRV validation
- `deny.toml` — license allowlist, unmaintained crate detection, security audit
- Workspace layering guards — blocks transport deps (clap, axum, reqwest) in core domain crates
- Clippy enforcement — `unwrap_used = "deny"`, `expect_used = "deny"` across all crates

Target: model STS CI pipeline on arc's patterns. Add `deny.toml` and clippy lints to workspace.

### Capability/lease model (reference only)

Arc's capability tokens (time-bounded, scope-limited, delegation-tracked) are a more mature version of swarm-policy's `CapabilityLease`. Not a direct copy target, but worth studying if lease semantics need to evolve.

## What NOT to source from Arc

- `arc-kernel` — MCP tool mediation, different execution model
- `arc-settle`, `arc-link` — financial settlement, irrelevant to threat detection
- `arc-reputation`, `arc-credentials`, `arc-did` — agent identity/trust, future concern
- `arc-mercury` — product-specific delivery layer
- `arc-guards` — arc's guards are designed for tool-call mediation; clawdstrike's are security-domain-native and map better to swarm's response pipeline

## Provenance

Arc source: `../arc/` (no specific commit pinned yet — pin when first code is actually copied).
