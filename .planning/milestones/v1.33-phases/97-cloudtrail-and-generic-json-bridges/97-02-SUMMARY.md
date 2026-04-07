---
phase: 97-cloudtrail-and-generic-json-bridges
plan: 02
subsystem: config
tags: [bridges, config, json-pointer, validation]
requirements-completed: [BRIDGE-04]
one-liner: "`GenericJsonBridge` now maps arbitrary JSON via config-loaded JSON Pointer mappings, and runtime config validates bridge-backed telemetry sources fail closed at load time."
completed: 2026-04-06
---

# Phase 97 Plan 02 Summary

**`GenericJsonBridge` now maps arbitrary JSON via config-loaded JSON Pointer mappings, and runtime config validates bridge-backed telemetry sources fail closed at load time.**

## Accomplishments

- Implemented `GenericJsonBridge` on top of the shared `TelemetryBridge` contract with config-driven JSON Pointer extraction for all current normalized payload variants: `process_start`, `network_connect`, `dns_query`, `registry_access`, and `authentication_event`.
- Added bridge config types to `swarm-core::config`, including `TelemetryBridgeConfig`, file-backed JSON source config, `FieldMappingConfig`, and payload-specific mapping enums, so bridge behavior can be expressed from repo-owned YAML instead of new Rust code.
- Extended `TelemetrySourceConfig` with an optional `bridge` block while preserving the existing `subject`-based runtime path, which keeps current runtime tests and configs working while making bridge-backed sources available for the next registry phase.
- Added parse-time validation that rejects empty bridge paths and invalid JSON Pointer fields fail closed during `SwarmConfig` load rather than later at runtime.
- Updated `docs/CONFIGURATION.md` with bridge-backed telemetry examples and added runtime config tests proving valid CloudTrail and generic JSON bridge YAML shapes deserialize successfully while malformed JSON Pointer mappings are rejected.

## Files Created Or Modified

- `crates/swarm-core/src/config.rs`
- `crates/swarm-runtime/src/config.rs`
- `crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs`
- `docs/CONFIGURATION.md`
- `crates/swarm-ingest-json/src/generic_json.rs`

## Verification

- `cargo test -p swarm-runtime config --lib`
- `cargo test -p swarm-runtime --test multi_agent_pipeline_integration`
- `cargo test -p swarm-ingest-json --lib`
- `cargo test -p swarm-core --lib`
- `cargo clippy -p swarm-core -p swarm-runtime -p swarm-ingest-json --tests -- -D warnings`

## Notes

- `FieldMappingConfig` uses JSON Pointer syntax because it is deterministic, serde-native, and easy to validate before runtime startup.
- `TelemetrySourceConfig.subject` remains valid for the existing ingest path; bridge-backed sources simply omit `subject` and provide a `bridge` block instead.
