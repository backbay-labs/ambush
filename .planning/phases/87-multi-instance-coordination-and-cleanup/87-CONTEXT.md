# Phase 87 Context: Multi-Instance Coordination And Cleanup

## Phase Goal

Multiple detection instances share pheromone state with correct cross-instance escalation enforcement, and legacy dead code is removed from the workspace.

## Depends On

Phase 86 (NATS JetStream Pheromone Backend) must be complete before this phase begins. Phase 86 delivers:
- A `JetStreamPheromoneSubstrate` implementing `PheromoneSubstrate` trait
- `PheromoneBackendConfig::JetStream { url }` variant in config
- `ConfiguredPheromoneSubstrate::JetStream(...)` variant wired into `from_config`
- `async-nats` as a workspace dependency
- Integration tests proving deposit persistence across simulated restart

## Requirements Addressed

- **SUB-02**: Multiple swarm-detect instances contribute deposits to shared substrate with correct concentration aggregation
- **SUB-03**: min_sources_for_escalation enforcement works correctly across multiple instances
- **CLEAN-01**: swarm-bridge (dead PyO3 shim) and kernel/ Python stubs are removed or archived

## Decisions

1. **Integration test approach**: Use a single shared NATS test server (either the `nats-server` binary in PATH or a docker-based NATS started in the test harness). Two `JetStreamPheromoneSubstrate` instances connect to the same server with distinct `agent_id` values.
2. **swarm-bridge removal**: Delete `crates/swarm-bridge/` directory entirely and remove it from workspace members in `Cargo.toml`. Also remove `pyo3` from workspace dependencies if it was only used by swarm-bridge.
3. **kernel/ removal**: Delete the `kernel/` directory. The `.dockerignore` already excludes it. The `pyproject.toml` references kernel as test paths and maturin module -- those references should be cleaned or the entire `pyproject.toml` can be removed since the project is now Rust-first.
4. **pyproject.toml cleanup**: Remove `pyproject.toml` since it exists solely to build the PyO3 bridge and run Python kernel tests, both of which are dead. This avoids confusion about Python being part of the production stack.
5. **distinct_sources counting**: The existing `concentration_for` function already counts distinct sources via `sources.insert(deposit.agent_id.0.clone())`. For multi-instance, each swarm-detect instance uses a unique `agent_id`, so cross-instance deposits naturally produce `distinct_sources >= 2`. The test must verify this path works through the shared JetStream substrate.

## Key Interfaces

### PheromoneSubstrate trait (from swarm-pheromone/src/substrate.rs)

```rust
#[async_trait]
pub trait PheromoneSubstrate: Send + Sync {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError>;
    async fn query_concentration(&self, threat_class: &ThreatClass, now: i64) -> Result<PheromoneConcentration, SubstrateError>;
    async fn query_deposits(&self, query: DepositQuery) -> Result<Vec<PheromoneDeposit>, SubstrateError>;
    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError>;
    async fn health(&self) -> Result<SubstrateHealth, SubstrateError>;
}
```

### PheromoneDeposit (from swarm-core/src/pheromone.rs)

```rust
pub struct PheromoneDeposit {
    pub indicator: serde_json::Value,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub confidence: f64,
    pub timestamp: i64,
    pub decay_half_life: f64,
    pub agent_id: AgentId,  // <-- distinct source identifier
    pub signature: Vec<u8>,
    pub agent_key: Vec<u8>,
}
```

### PheromoneConcentration (from swarm-core/src/pheromone.rs)

```rust
pub struct PheromoneConcentration {
    pub threat_class: ThreatClass,
    pub total_strength: f64,
    pub distinct_sources: usize,  // <-- what min_sources_for_escalation checks
    pub peak_confidence: f64,
}
```

### PheromoneConfig (from swarm-core/src/config.rs)

```rust
pub struct PheromoneConfig {
    pub min_sources_for_escalation: usize,  // default: 2
    // ...
}
```

### exceeds_threshold (from swarm-core/src/pheromone.rs)

```rust
impl PheromoneConcentration {
    pub fn exceeds_threshold(&self, strength_threshold: f64, min_sources: usize) -> bool {
        self.total_strength >= strength_threshold && self.distinct_sources >= min_sources
    }
}
```

## Removal Inventory

### swarm-bridge (crates/swarm-bridge/)
- `Cargo.toml` -- 24 lines, declares cdylib with pyo3
- `src/lib.rs` -- 14 lines, exports `__version__` only
- No other crate depends on `swarm-bridge`
- Workspace `Cargo.toml` does NOT list `swarm-bridge` in workspace members (already removed)
- Workspace `Cargo.toml` does NOT list `pyo3` in workspace dependencies
- The `swarm-bridge/Cargo.toml` uses `pyo3.workspace = true` but that key is not in root -- this may already be a latent build error

### kernel/ directory
- Contains: `__init__.py`, `archetypes/`, `dispatcher/`, `evolution/`, `harness/`, `memory/`, `red_swarm/`, `scheduler/`
- ~850 lines of Python docstring stubs
- Referenced only in `pyproject.toml` (testpaths) and `.dockerignore` (excluded)
- Not referenced in any `Cargo.toml` or Rust code

### pyproject.toml
- `[tool.maturin] module-name = "swarm_team_six._bridge"` -- points at swarm-bridge
- `testpaths = ["kernel"]` -- points at kernel/
- Build system is maturin for PyO3 -- dead after bridge removal
- Python deps (anthropic, networkx, numpy) are legacy reference

## Docker Compose

The existing `docker-compose.yml` already has a `nats` service with JetStream enabled under the `nats` profile. Integration tests can use this or a standalone `nats-server` binary.
