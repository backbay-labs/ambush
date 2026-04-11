# Phase 148 Plan 01 Summary

## Delivered

- Added `InfrastructureAnomalyDetector` and `InfrastructureAnomalyProfile` in `crates/swarm-whisker/src/infrastructure_anomaly.rs` with bounded per-node correlation state over `InfrastructureHealth`, `ThermalAnomaly`, and `ResourceExhaustion`.
- The new detector maps sustained CPU plus thermal pressure into `ThreatClass::Execution` for cryptominer-style resource hijack, destructive exhaustion into `ThreatClass::Impact`, and quiet high-memory pressure into `ThreatClass::DefenseEvasion`.
- Wired the detector into the public Whisker surface in `crates/swarm-whisker/src/lib.rs`, the shared detector type exports in `crates/swarm-whisker/src/detector.rs`, the repo-owned profile config in `crates/swarm-core/src/config.rs`, and the runtime config/factory path in `crates/swarm-runtime/src/config.rs` plus `crates/swarm-runtime/src/detector_factory.rs`.
- Updated `rulesets/default.yaml` so the supported-strategy documentation and sample profile overrides include `infrastructure_anomaly`.
- Added an end-to-end integration proof in `crates/swarm-runtime/tests/multi_strategy_integration.rs` showing that infrastructure execution pressure and suspicious process-tree execution findings converge in the same pheromone concentration, produce `distinct_sources == 2`, and trigger alerting through the existing escalation monitor.

## Notes

- The detector intentionally reuses the existing strategy-scoped pheromone deposit and concentration logic rather than introducing a custom cross-signal scoring subsystem.
- This phase uses deterministic threshold-plus-window correlation, not full Sentinel statistical baselines or Kubernetes workload-context suppression.
