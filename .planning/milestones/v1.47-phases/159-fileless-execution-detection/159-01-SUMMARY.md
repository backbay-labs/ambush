# Phase 159 Plan 01 Summary

## Delivered

- Added a first-class `TelemetryPayload::ProcessMemoryAccess` contract in `crates/swarm-core/src/telemetry.rs` so memory-access evidence is typed, serializable, and available to bridges, replay, and runtime detectors without ad hoc JSON blobs.
- Implemented `FilelessExecutionDetector` in `crates/swarm-whisker/src/fileless_execution.rs` with deterministic heuristics for reflective DLL injection, encoded PowerShell with staged deobfuscation indicators, and raw syscall gadget hints.
- Extended the repo-owned detector profile lane through `crates/swarm-core/src/config.rs`, `crates/swarm-runtime/src/config.rs`, `crates/swarm-runtime/src/detector_factory.rs`, and `crates/swarm-runtime/src/replay/core.inc` so `fileless_execution` is a normal config-selected runtime strategy and replay candidate type.
- Proved the runtime deposit lane in `crates/swarm-runtime/src/detection/pipeline.rs` now maps fileless findings to `ThreatClass::DefenseEvasion` or `ThreatClass::PrivilegeEscalation` and emits strategy-scoped pheromone deposits instead of a detector-specific side channel.
- Updated the checked-in mission guidance in `rulesets/default.yaml` and `docs/CONFIGURATION.md` so the repo documents the new fileless detector surface and its profile overrides.

## Notes

- Phase 159 stayed bounded to deterministic fileless execution coverage and threat-class mapping.
- Per-host baseline learning, decay, and restart persistence were deliberately left for Phase 160.
