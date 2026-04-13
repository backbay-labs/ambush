# Phase 218 Plan 01 Summary

## Delivered

- Extended the shared restart-safe behavioral baseline schema in
  `crates/swarm-core/src/pheromone.rs` with
  `BehavioralTelemetryFamilyBaseline`, so each host, identity, and peer-group
  scope can now persist bounded learned state for non-process telemetry
  families without introducing a second detector-local store.
- Updated `crates/swarm-whisker/src/behavioral_anomaly.rs` so
  `BehavioralAnomalyDetector` now evaluates network, DNS, authentication,
  registry access, registry persistence, file persistence, and process memory
  access telemetry instead of returning `Vec::new()` for every non-process
  payload.
- Kept the explicit Phase 217 deviation model intact across the widened
  detector. Each newly supported telemetry family now emits
  `deviation_scoring`, `telemetry_family`, and per-feature evidence on the same
  bounded finding surface as process-start anomalies.
- Preserved restart-safe baseline learning through the shared substrate seam.
  Non-process telemetry now hydrates and snapshots family-specific learned
  feature maps plus online novelty distributions alongside the existing
  process-start state, and the substrate test helper in
  `crates/swarm-pheromone/src/substrate.rs` now exercises that broadened
  schema.
- Reused the existing behavioral profile seam without adding new breadth-only
  tuning knobs. The repo-owned runtime config merge path still validates and
  loads the behavioral anomaly profile unchanged while the broadened detector
  state compiles and passes through the existing config contract.

## Notes

- Events without an explicit user now learn under bounded process- or
  source-derived subject IDs such as `process:<name>` or `source:<ip>` so the
  widened behavioral detector can keep meaningful identity-scoped baselines
  without inventing a second scope type.
- Phase 218 stays focused on behavioral breadth. The labeled false-positive and
  catch-rate benchmark for the widened detector remains the dedicated Phase 219
  follow-up.
