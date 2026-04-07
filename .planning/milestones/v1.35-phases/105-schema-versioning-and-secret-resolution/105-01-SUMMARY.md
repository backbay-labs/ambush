---
phase: 105-schema-versioning-and-secret-resolution
plan: 01
subsystem: config
tags: [config, schema, migration, validation]
requirements-completed: [K8S-04]
one-liner: "Runtime config is now schema-aware, fail-closed for future versions, and able to migrate supported older payloads with structured logging."
completed: 2026-04-07
---

# Phase 105 Plan 01 Summary

**Runtime config is now schema-aware, fail-closed for future versions, and able to migrate supported older payloads with structured logging.**

## Accomplishments

- Added a required `schema_version` field to `SwarmConfig` and updated repo-owned config to declare the current schema explicitly.
- Added `CURRENT_SCHEMA_VERSION` and a schema-aware parse path that inspects raw YAML before deserializing the final config type.
- Implemented backward-compatible migration for legacy configs that omit `schema_version` and log structured migration details when transforms are applied.
- Rejected future or unrecognized schema versions with `RuntimeConfigError::Validation` instead of silently deserializing unknown shapes.
- Added focused config-loader tests proving legacy migration, future-version rejection, and post-migration validation behavior.

## Files Created Or Modified

- `crates/swarm-core/src/config.rs`
- `crates/swarm-runtime/src/config.rs`
- `rulesets/default.yaml`

## Verification

- `cargo test -p swarm-runtime config --lib`
- `cargo test -p swarm-core --lib`
- `cargo build --workspace`

## Notes

- The migration path treats a missing schema version as legacy schema `0`, which keeps old config files readable while still making the compiled contract explicit.
- Schema enforcement now happens before detector-profile validation so malformed future configs fail as configuration errors rather than downstream runtime surprises.
