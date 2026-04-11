# Phase 147: Sentinel Infrastructure Telemetry Bridge - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 147 adds a new telemetry dimension: Sentinel-derived infrastructure health signals. The phase stops at normalized ingest and bridge-runtime integration. Detection logic for those payloads belongs to Phase 148.

</domain>

<decisions>
## Implementation Decisions

### Bridge Scope
- Add a dedicated `swarm-ingest-sentinel` crate instead of overloading the existing generic JSON bridge so the infrastructure payload contract remains explicit and versioned.
- Reuse the existing `TelemetryBridge` lifecycle and `BridgeRuntimeRegistry` health model so Sentinel behaves like the other bridge-backed telemetry sources in `/healthz`, `/readyz`, and metrics.
- Keep the first Sentinel source contract deterministic and file-backed if needed for tests; transport-specific live collectors can be layered in later without changing the normalized payload surface.

### Schema Boundary
- Extend `swarm-core` telemetry ownership with infrastructure payload variants before adding the bridge.
- Keep the bridge focused on mapping `InfrastructureHealth`, `ThermalAnomaly`, and `ResourceExhaustion` into normalized `TelemetryPayload` events; threat interpretation remains detector work for Phase 148.

### Verification Boundary
- Prove schema mapping, bridge health updates, runtime registry wiring, and config acceptance for a `"sentinel"` telemetry source.
- Leave escalation and cross-signal confidence boosts to the detector phase.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-core/src/telemetry.rs` owns the normalized event schema and `TelemetryBridge` trait every bridge implements.
- `crates/swarm-runtime/src/bridge_runtime.rs` already builds bridge workers from `TelemetryBridgeConfig` and publishes uniform bridge-health snapshots.
- `crates/swarm-ingest-json` and `crates/swarm-ingest-tetragon` already demonstrate the expected bridge contract, schema validation, and test shape.
- `docs/research/sentinel-convergence/05-TELEMETRY-BRIDGE-ARCHITECTURE.md` defines the proposed Sentinel payload boundary and highlights the infrastructure metrics that matter for Swarm.

### Integration Points
- `swarm-core/src/config.rs` must accept a new bridge kind for Sentinel so `runtime.telemetry_sources` can describe it in repo-owned YAML.
- `BridgeRuntimeRegistry::build_bridge()` is the seam that will instantiate the new crate and expose Sentinel health under the existing metrics/reporting path.
- Runtime bridge integration tests under `crates/swarm-runtime/tests/bridge_registry_integration.rs` are the right place to prove end-to-end bridge registration and telemetry emission.

</code_context>

<deferred>
## Deferred Ideas

- Infrastructure threat scoring, escalation confidence boosts, and detector fusion are explicit Phase 148 work.
- Any direct network transport to a live Sentinel service can remain deferred if the normalized bridge contract is already stable and testable from local fixtures.

</deferred>
