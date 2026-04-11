# Phase 147 Plan 01 Summary

## Delivered

- Extended the shared telemetry contract in `crates/swarm-core/src/telemetry.rs` with `InfrastructureHealth`, `ThermalAnomaly`, and `ResourceExhaustion`, and exposed the new event types through `crates/swarm-core/src/lib.rs`.
- Added repo-owned Sentinel bridge config in `crates/swarm-core/src/config.rs`, surfaced the bridge kind through `crates/swarm-runtime/src/config.rs`, and documented the operator-facing YAML shape in `rulesets/default.yaml`.
- Created the new `crates/swarm-ingest-sentinel` crate with a deterministic Prometheus-scrape bridge that emits normalized infrastructure events, validates its own schema, and tracks bridge health like the existing bridge crates.
- Wired Sentinel into `crates/swarm-runtime/src/bridge_runtime.rs` so the runtime registry can build, health-track, and metrics-publish Sentinel bridge workers through the same path as Tetragon and JSON sources.
- Added runtime proof in `crates/swarm-runtime/tests/bridge_registry_integration.rs` and bridge-runtime metrics proof in `crates/swarm-runtime/src/bridge_runtime.rs`.
- Updated existing bridge and consumer boundaries in `swarm-ingest-json`, `swarm-ingest-tetragon`, `swarm-spine`, `swarm-evolution`, `swarm-runtime`, and `swarm-whisker` so the new infrastructure payload variants are explicitly accepted or ignored instead of leaving exhaustive matches stale.

## Notes

- Phase 147 stops at ingest and normalized bridge plumbing. Infrastructure threat interpretation was intentionally deferred to Phase 148.
- Legacy bridge validators fail closed on the new infrastructure payload kinds; they do not silently reinterpret them as security events.
