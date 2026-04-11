# Phase 160 Plan 01 Summary

## Delivered

- Added a typed `BehavioralBaselineSnapshot` contract in `crates/swarm-core/src/pheromone.rs` and extended `crates/swarm-pheromone/src/substrate.rs` plus `crates/swarm-pheromone/src/jetstream.rs` so behavioral baselines can persist across in-memory, local-journal, and JetStream backends.
- Implemented `BehavioralAnomalyDetector` in `crates/swarm-whisker/src/behavioral_anomaly.rs` with per-host ancestry, first-seen binary, and role-tool anomaly scoring, configurable half-life decay, and snapshot hydration or persistence support.
- Extended the detector trait seam in `crates/swarm-whisker/src/detector.rs` and `crates/swarm-whisker/src/composite.rs` so runtime-owned hydration can inspect stateful detectors without baking behavioral logic directly into the runtime.
- Wired the repo-owned config and runtime construction path through `crates/swarm-core/src/config.rs`, `crates/swarm-runtime/src/config.rs`, `crates/swarm-runtime/src/detector_factory.rs`, and the checked-in examples in `rulesets/default.yaml` plus `docs/CONFIGURATION.md`.
- Taught `crates/swarm-runtime/src/detection/pipeline.rs` to hydrate behavioral detectors from the substrate before evaluation and persist dirty snapshots after evaluation, then fixed durable signature validation in `crates/swarm-pheromone/src/substrate.rs` so signer-derived identities remain valid when the runtime scopes `agent_id` with `:<strategy_id>` for distinct-source visibility.

## Notes

- The meaningful blocker during verification was not detector logic but durable-substrate validation: strategy-scoped agent IDs were being rejected even though the runtime intentionally scopes detector deposits. The shipped validator now accepts one scoped suffix when the base Ed25519 identity matches.
- Phase 160 stays focused on process-start behavioral baselines and restart-safe persistence. Evasion corpora and broader robustness scoring remain v1.48 work.
