# Phase 170 Plan 01 Summary

## Delivered

- Extended `crates/swarm-core/src/pheromone.rs` with multi-scope behavioral snapshot types so host, identity, and peer-group baselines can persist independently.
- Updated `crates/swarm-whisker/src/behavioral_anomaly.rs` and `crates/swarm-runtime/src/config.rs` so behavioral detection now learns and evaluates host, identity, and peer-group scope with repo-owned thresholds.
- Wired restart-safe multi-scope persistence through `crates/swarm-pheromone/src/substrate.rs` and `crates/swarm-runtime/src/detection/pipeline.rs`, so scope-specific baselines now hydrate and decay independently after restart.
- Enriched behavioral findings with readable scope attribution, including `identity_id`, `peer_group_id`, `baseline_scope_hits`, and per-scope baseline evidence details.
- Added focused regression coverage proving scope-specific persistence, reload, and anomaly triggering behavior without regressing the shipped host-baseline path.

## Notes

- Phase 170 preserved the existing bounded detector architecture; the milestone deepened behavioral context instead of introducing a new detector family.
- Strategy-scoped deposit validation still honors the signer-derived Ed25519 base identity while carrying the richer baseline snapshot contract.
