# Phase 78 Context: Service Extraction And Detection Binary

## User Decisions

### Decisions (Locked)

- New binary lives at `crates/swarm-runtime/src/bin/swarm_detect.rs` (auto-discovered by Cargo, no Cargo.toml changes needed)
- Binary name: `swarm-detect` (Cargo translates underscore to hyphen)
- Reuse existing `config::load_config`, `control::supported_detector`, `ConfiguredRuntimeStack::from_components`, and `pipeline::detect_and_deposit` -- do not duplicate wiring
- Scenarios loaded from `scenarios/*.yaml` using existing `replay.rs` scenario parsing (`load_scenario_manifest` pattern)
- Rulesets loaded from the same `rulesets/default.yaml` path via `--config` flag (same as swarmctl)
- Both `detect_only` and `live_response` modes supported, driven by the config file's `runtime.mode` field
- Binary is minimal: load config, create runtime stack, iterate scenario events through detection pipeline, print results

### Deferred Ideas

- Prometheus metrics endpoint (Phase 79)
- Integration tests for full critical path (Phase 79)
- Clippy lint enforcement (Phase 80)
- Real telemetry source adapters (out of scope for v1.25)
- Container images or deployment manifests

### Claude's Discretion

- Exact CLI flag names and help text for the binary
- Whether to extract `SupportedDetector` and `supported_detector()` from control.rs into a shared module or duplicate minimally
- Output format (structured JSON vs human-readable text)
- How to handle scenario events that have no detection findings (log and continue)

## Technical Context

### Current State

- `swarmctl` is the only binary (~3K lines), located at `crates/swarm-runtime/src/bin/swarmctl.rs`
- The detection hot path is `pipeline::detect_and_deposit()` (~50 lines) -- evaluate event, deposit pheromones
- `SwarmRuntime<P, E>` is the composition root in `lib.rs` -- wires policy + response
- `ConfiguredRuntimeStack` in `service.rs` composes substrate + replay + investigation + correlation from config
- `DefaultControlPlane::from_path()` in `control.rs` loads config and builds the full stack
- `SupportedDetector` enum and `supported_detector()` factory live in `control.rs` (private)
- Scenario files in `scenarios/*.yaml` follow `ReplayScenarioManifest` schema from `replay.rs`
- `rulesets/default.yaml` is the repo-owned config loaded via `config::load_config()`

### Key Interfaces

```rust
// config.rs
pub fn load_config(path: impl AsRef<Path>) -> Result<SwarmConfig, RuntimeConfigError>;

// pipeline.rs
pub async fn detect_and_deposit<D, S>(
    detector: &D, substrate: &S, event: &TelemetryEvent,
    agent_id: &AgentId, pheromone: &PheromoneConfig,
) -> Result<DetectionPipelineOutcome, PipelineError>;

// service.rs
pub struct ConfiguredRuntimeStack<P, E, Strategy> { ... }
impl ConfiguredRuntimeStack { pub fn from_components(...) -> Result<Self, ServiceError>; }
impl ConfiguredRuntimeStack { pub async fn process_event(...) -> Result<...>; }

// control.rs (currently private, needs extraction)
fn supported_detector(strategy: &str) -> Result<SupportedDetector, ControlError>;

// replay.rs (scenario loading, currently crate-private)
fn load_scenario_manifest(path: impl AsRef<Path>) -> Result<LoadedReplayScenario, ReplayHarnessError>;
```

### What Must Change

1. `supported_detector()` and `SupportedDetector` need to be accessible outside `control.rs` -- either made `pub` or extracted to a shared module
2. Scenario loading helpers need `pub` visibility or a thin public wrapper
3. New binary file created at `src/bin/swarm_detect.rs`
