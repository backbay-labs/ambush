---
phase: 101-threat-class-pheromone-policy-storage-and-reload
plan: 02
subsystem: operator-surface
tags: [operator, http, control, policy]
requirements-completed: [SUBSTRATE-03]
one-liner: "The authenticated operator surface can now list and upsert `ThreatClassConfig` records, and operator-written policy is visible to the live runtime without restart."
completed: 2026-04-07
---

# Phase 101 Plan 02 Summary

**The authenticated operator surface can now list and upsert `ThreatClassConfig` records, and operator-written policy is visible to the live runtime without restart.**

## Accomplishments

- Added control-plane helpers for listing and storing threat-class pheromone policy records through the configured substrate.
- Extended the authenticated operator HTTP surface with `/v1/operator/pheromone/threat-class-configs` for bearer-token-protected list and upsert operations.
- Added operator-surface tests proving the new route persists and returns `ThreatClassConfig` JSON payloads through the existing auth boundary.
- Added a control-plane runtime proof showing an operator-written alert-threshold override can be stored and immediately observed by `ConcentrationMonitor` without process restart.
- Completed the phase requirement by tying together backend durability, runtime override resolution, and operator-managed state mutation under one verified path.

## Files Created Or Modified

- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-runtime/src/http/core.inc`

## Verification

- `cargo fmt --all`
- `cargo test -p swarm-runtime --lib`
- `cargo test -p swarm-runtime threat_class_config_routes_store_and_list_configs --lib`
- `cargo test -p swarm-runtime --test escalation_integration`
- `cargo clippy -p swarm-core -p swarm-pheromone -p swarm-runtime --tests -- -D warnings`

## Notes

- The operator API writes directly into the substrate-backed source of truth, so the live runtime sees the new policy on the next deposit or concentration evaluation instead of relying on a process-local cache refresh.
- The phase intentionally keeps policy management narrow to `ThreatClassConfig`; threat-intel indicator storage and query APIs remain scoped to phase 102.
