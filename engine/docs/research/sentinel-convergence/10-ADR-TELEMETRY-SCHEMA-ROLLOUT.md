# ADR 0010: TelemetryPayload Schema Rollout for Sentinel Infrastructure Variants

## Status

Proposed on 2026-04-07.

## Context

The `swarm-ingest-sentinel` bridge (Doc 05) introduces three new `TelemetryPayload` variants: `InfrastructureHealth`, `ThermalAnomaly`, and `ResourceExhaustion`. The current `TelemetryPayload` enum in `swarm-core/src/telemetry.rs` has 7 security-event variants. Adding 3 infrastructure variants is the first schema extension since the enum was created, and it sets precedent for all future extensions.

Four questions must be answered before implementation begins:

1. What order must crates upgrade when new variants ship?
2. How should consumers handle unknown variants?
3. Is version negotiation needed between bridges and the runtime?
4. Where does compatibility logic live -- in bridges or in core?

### Key constraints from the existing codebase

- `TelemetryPayload` uses `#[serde(tag = "kind", rename_all = "snake_case")]` (internally tagged enum).
- `TelemetryEvent` and all payload structs use `#[serde(deny_unknown_fields)]`.
- Every bridge's `validate_schema()` exhaustively matches all `TelemetryPayload` variants (see `swarm-ingest-tetragon/src/bridge.rs` lines 240-265, `swarm-ingest-json/src/lib.rs` lines 30-61).
- The runtime dispatches bridges via an exhaustive `match` on `TelemetryBridgeConfig` in `bridge_runtime.rs` line 287.
- `SwarmConfig` already carries `schema_version: u32`.
- Doc 05 Section 7.4 explicitly forbids feature-gating enum variants because `#[cfg]` on enum arms breaks serde deserialization of the gated tag value.

---

## Decision

### Q1: Consumer upgrade order

**Decision: land the core enum change and all existing in-repo consumer updates
in one coordinated workspace PR. The new Sentinel bridge can land in the same
PR or immediately after.**

The `TelemetryPayload` enum lives in `swarm-core`. Rust's exhaustive match checking means that adding a variant to the enum is a compile-time breaking change for every crate that matches on it. The only safe ordering is:

```
Step 1:  coordinated workspace PR
         swarm-core           Add variants + Unknown fallback (see Q2)
         swarm-ingest-json    Add match arms (log-and-skip for infra variants)
         swarm-ingest-tetragon Same
         swarm-runtime        Add Sentinel arm to build_bridge()
         detectors            Add match arms or use _ => fallback
Step 2:  swarm-ingest-sentinel
         New crate, depends on updated workspace types
```

The schema PR and the bridge PR can be developed in parallel, but in this
monorepo the existing consumers cannot be merged after `swarm-core` has already
changed unless they are updated in the same merge.

**What breaks if you get it wrong:**

- If a bridge ships before core: the bridge crate cannot compile -- the variant types do not exist.
- If core lands without existing consumers in the same merge: `rustc` rejects
  every non-exhaustive match with a compile error. The workspace will not
  build.
- If core and consumers update but the bridge is absent: harmless. No events of the new kinds are produced. Detectors never see the new arms. Zero runtime impact.

### Q2: Unknown-variant handling

**Decision: Log-and-skip, enforced in core via a serde `Unknown` fallback variant.**

The current enum uses `#[serde(tag = "kind")]` but has no catch-all. An unrecognized `"kind"` value at the wire level causes a hard deserialization error, which crashes the bridge poll loop (the error propagates through `TelemetryBridgeResult` and the runtime logs it as a poll failure). This is unacceptable in a mixed-version deployment.

Add a single `Unknown` variant to `TelemetryPayload` using serde's `#[serde(other)]` attribute:

```rust
// swarm-core/src/telemetry.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryPayload {
    ProcessStart(ProcessStartEvent),
    NetworkConnect(NetworkConnectEvent),
    DnsQuery(DnsQueryEvent),
    RegistryAccess(RegistryAccessEvent),
    RegistryPersistence(RegistryPersistenceEvent),
    FilePersistence(FilePersistenceEvent),
    AuthenticationEvent(AuthenticationEventData),

    // -- Sentinel infrastructure variants (new) --
    InfrastructureHealth(InfrastructureHealthEvent),
    ThermalAnomaly(ThermalAnomalyEvent),
    ResourceExhaustion(ResourceExhaustionEvent),

    // -- Forward-compatibility fallback --
    /// Deserializes successfully for any unrecognized `kind` tag.
    /// Consumers MUST log and skip this variant, never act on it.
    #[serde(other)]
    Unknown,
}
```

**Why `#[serde(other)]` and not manual deserialization:**

`#[serde(other)]` is a single-line change that serde handles at the derive level. It causes any unrecognized tag value to deserialize into `Unknown` instead of returning `Err`. This is the minimal mechanism -- no custom `Deserialize` impl, no version negotiation protocol, no wrapper types.

**Important caveat:** `#[serde(other)]` only works on a unit variant (no associated data). The unknown payload's fields are silently discarded. This is acceptable because an old consumer cannot meaningfully process a variant it does not understand -- the only correct action is to skip it.

**Enforcement in consumers:**

Every `validate_schema()` and detector `evaluate()` match must handle `Unknown`:

```rust
// In any validate_schema() or detector match:
fn validate_schema(&self, event: &TelemetryEvent) -> bool {
    // ...envelope checks...
    match &event.payload {
        TelemetryPayload::ProcessStart(p) => { /* existing */ }
        TelemetryPayload::NetworkConnect(c) => { /* existing */ }
        // ...other known variants...

        TelemetryPayload::Unknown => {
            tracing::debug!(
                event_id = %event.event_id,
                source = %event.source,
                "skipping event with unrecognized payload kind"
            );
            false  // reject from this bridge's perspective
        }
    }
}
```

The runtime's `run_bridge_worker` already handles `validate_schema() == false` by logging and continuing. No new error path is needed.

**What we explicitly reject:**

| Alternative | Why rejected |
|---|---|
| **Panic on unknown** | Kills the entire runtime for a single unrecognized event. Unacceptable in production. |
| **Buffer unknown for later** | Adds unbounded state. The `Unknown` variant has no data to buffer. No mechanism exists to "replay" buffered events after an upgrade. |
| **Custom `Deserialize` impl** | High maintenance cost, easy to introduce bugs, gains nothing over `#[serde(other)]`. |
| **Per-bridge serde config** | Scatters compatibility logic. Violates the decision in Q4. |

### Q3: Version negotiation

**Decision: No version handshake. Compatibility is structural (serde forward-compat via `Unknown`).**

The `schema_version` field on `SwarmConfig` governs the config file format, not the wire protocol between bridges and the runtime. Bridges and the runtime communicate through in-process Rust types (`Vec<TelemetryEvent>` over `mpsc`), not over a network protocol. There is no wire boundary where a version handshake would execute.

The minimal mechanism is:

1. The `Unknown` variant (Q2) makes deserialization forward-compatible at the serde level.
2. Bridges and runtime link against the same `swarm-core` version via Cargo workspace. If they compile together, they are compatible.
3. For out-of-process scenarios (future: events serialized to NATS JetStream or a dead-letter journal), the `Unknown` variant ensures old consumers skip new events rather than crashing.

**What we explicitly reject:**

| Alternative | Why rejected |
|---|---|
| **Capability advertisement** (bridge tells runtime which variants it produces) | Over-engineering. All bridges already declare `source_id()`. The runtime does not filter by variant kind -- it forwards everything to detectors. |
| **Schema version in `TelemetryEvent`** | Adds a field to every event for information the consumer already has (it compiled against a known `swarm-core`). Violates `deny_unknown_fields` on old consumers unless they also update. |
| **Schema registry / protobuf** | Wrong abstraction level. The system uses serde JSON, not protobuf. Adding a schema registry for 10 enum variants is unjustified. |

### Q4: Compatibility location

**Decision: Centralized in core types. Bridges do not implement their own versioning.**

#### Decision matrix

| Criterion | Bridge-owned (decentralized) | Core-owned (centralized) |
|---|---|---|
| **Single point of change** | No -- every bridge must independently handle version skew | Yes -- `Unknown` variant in `TelemetryPayload` covers all bridges |
| **Consistency guarantee** | Weak -- bridges can diverge in how they handle unknown kinds | Strong -- serde `#[serde(other)]` applies uniformly |
| **New bridge onboarding** | Must reimplement version logic | Gets forward-compat for free by depending on `swarm-core` |
| **Testing surface** | N bridges x M versions | 1 enum + 1 test |
| **Runtime overhead** | Per-bridge version checks | Zero (serde derive handles it) |
| **Existing pattern** | No precedent in codebase | Matches `SwarmConfig.schema_version` centralization |

**Core-owned wins on every criterion.** The `Unknown` variant in the `TelemetryPayload` enum is the single compatibility mechanism. Bridges produce events; core types define what is structurally valid. No bridge needs version-awareness beyond "compile against current `swarm-core`."

---

## Consequences

### Positive

- Any future `TelemetryPayload` extension follows the same pattern: add variant to core, update consumer match arms, ship the producing bridge. No new compatibility mechanism needed.
- Old binaries consuming serialized events (e.g., from a NATS subject or journal file) silently skip new variants instead of crashing.
- Compile-time exhaustiveness checking ensures no consumer silently ignores a known variant -- `Unknown` is the only valid fallback.
- Zero runtime overhead. No version checks, no capability negotiation, no schema registry.

### Negative

- The `Unknown` variant discards all payload data. If a future use case requires forwarding or logging the raw payload of an unrecognized variant, this design must be revisited (e.g., `Unknown { raw: serde_json::Value }`). This is deliberately deferred -- `#[serde(other)]` requires a unit variant, and the complexity of a custom deserializer is not justified today.
- Every consumer must add a `TelemetryPayload::Unknown => { ... }` arm. This is a one-time cost per consumer, enforced by `rustc`.
- `#[serde(other)]` silences what might be a legitimate misconfiguration (e.g., a bridge producing `"kind": "process_strat"` due to a typo). Mitigation: bridge-side `validate_schema()` catches typos before events leave the bridge. The `Unknown` path is for cross-version skew, not bug masking.

### Neutral

- `deny_unknown_fields` on payload structs remains. New fields within an existing variant still require either a new variant or an opt-in migration to `#[serde(default)]` on the new field. This ADR does not change intra-variant evolution rules.

---

## Migration Checklist

### Phase 1: Coordinated schema PR (single workspace PR)

- [ ] Add `InfrastructureHealthEvent`, `ThermalAnomalyEvent`, `ResourceExhaustionEvent` structs to `swarm-core/src/telemetry.rs`
- [ ] Add `ThermalSeverity` and `ExhaustedResource` enums to `swarm-core/src/telemetry.rs`
- [ ] Add `InfrastructureHealth`, `ThermalAnomaly`, `ResourceExhaustion` variants to `TelemetryPayload`
- [ ] Add `#[serde(other)] Unknown` variant to `TelemetryPayload`
- [ ] Add unit test: deserialize JSON with `"kind": "never_heard_of_this"` succeeds as `Unknown`
- [ ] Add unit test: deserialize JSON with `"kind": "infrastructure_health"` succeeds as `InfrastructureHealth`
- [ ] `swarm-ingest-json/src/lib.rs` `validate_event_schema()`: add match arms for 3 new variants + `Unknown => false`
- [ ] `swarm-ingest-tetragon/src/bridge.rs` `validate_schema()`: add match arms for 3 new variants + `Unknown => false`
- [ ] `swarm-runtime/src/bridge_runtime.rs` `build_bridge()`: add `TelemetryBridgeConfig::Sentinel` arm
- [ ] `swarm-core/src/config.rs` `TelemetryBridgeConfig`: add `Sentinel` variant with `SentinelBridgeConfig`
- [ ] All detector `evaluate()` functions: add fallthrough for new variants (most detectors ignore infrastructure events)
- [ ] Verify `cargo build --workspace` succeeds
- [ ] Verify `cargo test --workspace` passes
- [ ] Add round-trip serde test for all three new variants

### Phase 2: Sentinel bridge crate

- [ ] Create `crates/swarm-ingest-sentinel/` with structure from Doc 05 Section 4.6
- [ ] Implement `TelemetryBridge` for `SentinelBridge`
- [ ] Add `swarm-ingest-sentinel` dependency to `swarm-runtime/Cargo.toml`
- [ ] Add integration test: scrape a mock Prometheus endpoint, verify `InfrastructureHealth` event produced
- [ ] Add threshold test: verify `ThermalAnomaly` emitted only above configured threshold
- [ ] Add threshold test: verify `ResourceExhaustion` emitted only above configured threshold

### Phase 4: Validation

- [ ] Deploy runtime with Sentinel bridge disabled, verify zero impact on existing detection
- [ ] Deploy runtime with Sentinel bridge enabled against a real Sentinel endpoint
- [ ] Verify `BridgeHealth` reports for the Sentinel bridge appear in operator surface
- [ ] Bump `schema_version` in `rulesets/default.yaml` to document the schema generation

---

## Implementation Reference

### Core enum after migration (Phase 1 deliverable)

```rust
// swarm-core/src/telemetry.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryPayload {
    // -- Security event variants (existing, unchanged) --
    ProcessStart(ProcessStartEvent),
    NetworkConnect(NetworkConnectEvent),
    DnsQuery(DnsQueryEvent),
    RegistryAccess(RegistryAccessEvent),
    RegistryPersistence(RegistryPersistenceEvent),
    FilePersistence(FilePersistenceEvent),
    AuthenticationEvent(AuthenticationEventData),

    // -- Infrastructure variants (new) --
    InfrastructureHealth(InfrastructureHealthEvent),
    ThermalAnomaly(ThermalAnomalyEvent),
    ResourceExhaustion(ResourceExhaustionEvent),

    // -- Forward-compatibility catch-all --
    #[serde(other)]
    Unknown,
}
```

### Forward-compat serde test (Phase 1 deliverable)

```rust
#[cfg(test)]
mod schema_evolution_tests {
    use super::*;

    #[test]
    fn unknown_kind_deserializes_to_unknown_variant() {
        let json = r#"{
            "source": "future-bridge",
            "event_id": "evt-1",
            "timestamp": 1700000000,
            "host_id": "node-a",
            "payload": { "kind": "quantum_entanglement", "qubits": 42 }
        }"#;

        // This must NOT panic or return Err.
        let event: TelemetryEvent = serde_json::from_str(json)
            .expect("unknown kind should deserialize via #[serde(other)]");

        assert!(matches!(event.payload, TelemetryPayload::Unknown));
    }

    #[test]
    fn known_new_variant_deserializes_correctly() {
        let json = r#"{
            "source": "sentinel",
            "event_id": "sentinel:node-1:health:1700000000",
            "timestamp": 1700000000,
            "host_id": "node-1",
            "payload": {
                "kind": "infrastructure_health",
                "node_name": "node-1",
                "cpu_usage_percent": 45.2,
                "cpu_frequency_mhz": 3200.0,
                "load_average_1m": 1.5,
                "load_average_5m": 1.2,
                "load_average_15m": 0.9,
                "memory_usage_percent": 62.0,
                "memory_available_bytes": 8000000000,
                "disk_usage_percent": 55.0,
                "disk_io_latency_ms": 2.3,
                "network_rx_bytes": 1024,
                "network_tx_bytes": 2048,
                "network_rx_errors": 0,
                "network_tx_errors": 0,
                "failure_probability": 0.12,
                "prediction_confidence": 0.85,
                "time_to_failure_secs": -1.0,
                "collection_duration_ms": 0.8
            }
        }"#;

        let event: TelemetryEvent = serde_json::from_str(json)
            .expect("infrastructure_health should deserialize");

        assert!(matches!(
            event.payload,
            TelemetryPayload::InfrastructureHealth(_)
        ));
    }
}
```

### Consumer match arm update pattern (Phase 2 deliverable)

```rust
// Pattern for ALL validate_schema() implementations.
// Shown for swarm-ingest-json; identical structure in swarm-ingest-tetragon.

fn validate_event_schema(event: &TelemetryEvent, source_id: &str) -> bool {
    if event.source != source_id { return false; }
    if event.event_id.trim().is_empty() || event.timestamp <= 0 { return false; }

    match &event.payload {
        // ...existing 7 arms unchanged...

        TelemetryPayload::InfrastructureHealth(h) => {
            !h.node_name.trim().is_empty()
                && h.cpu_usage_percent >= 0.0
                && h.memory_usage_percent >= 0.0
        }
        TelemetryPayload::ThermalAnomaly(t) => {
            !t.node_name.trim().is_empty()
                && t.temperature_celsius > -273.15
        }
        TelemetryPayload::ResourceExhaustion(r) => {
            !r.node_name.trim().is_empty()
                && r.capacity_value > 0
        }
        TelemetryPayload::Unknown => {
            tracing::debug!(
                event_id = %event.event_id,
                "skipping unrecognized payload kind"
            );
            false
        }
    }
}
```

### Config extension (Phase 2 deliverable)

```rust
// swarm-core/src/config.rs -- TelemetryBridgeConfig gains a Sentinel arm.

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryBridgeConfig {
    Tetragon {
        #[serde(flatten)]
        config: Box<TetragonBridgeConfig>,
    },
    CloudTrail {
        #[serde(flatten)]
        config: Box<CloudTrailBridgeConfig>,
    },
    GenericJson {
        #[serde(flatten)]
        config: Box<GenericJsonBridgeConfig>,
    },
    Sentinel {
        #[serde(flatten)]
        config: Box<SentinelBridgeConfig>,
    },
}
```

---

## Cross-References

| Document | Relevance |
|---|---|
| [ADR 0001](../../decisions/0001-rust-first-runtime.md) | Rust-first runtime decision constrains this to serde/Cargo-based compatibility, not polyglot schema registries. |
| [Doc 05, Section 4.2](./05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Canonical definitions of the three new payload structs. |
| [Doc 05, Section 7](./05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Schema evolution analysis that this ADR resolves into concrete decisions. |
| [Doc 05, Section 7.4](./05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Feature-gating prohibition that constrains the design space. |
| [Doc 07](./07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md) | Audit trail implications of schema version changes. |
