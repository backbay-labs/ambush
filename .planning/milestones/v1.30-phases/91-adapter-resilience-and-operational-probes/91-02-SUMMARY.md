---
phase: 91-adapter-resilience-and-operational-probes
plan: 02
subsystem: runtime
tags: [probes, config, validation, detectors]
requirements-completed: [OBS-05, OBS-06]
one-liner: "runtime detector builders now resolve validated profile payloads at load time, and the detect server exposes separate `/readyz` and `/livez` probe semantics."
completed: 2026-04-05
---

# Phase 91 Plan 02 Summary

**runtime detector builders now resolve validated profile payloads at load time, and the detect server exposes separate `/readyz` and `/livez` probe semantics.**

## Accomplishments

- Added `ProfileValidationError` plus `validate()` methods across all five detector profile structs in `swarm-whisker`.
- Centralized detector-profile overlay, parse, and validation logic in `swarm-runtime/src/config.rs`, preserving top-level detection thresholds while allowing per-detector JSON overrides.
- Updated control-plane, ingest, CLI, replay, canary, and promotion detector construction paths to consume validated profile config rather than implicit defaults.
- Added `/readyz` and `/livez` routes beside `/healthz`, with readiness still checking detector, substrate, and replay-store health while liveness always returns HTTP 200 for a running process.
- Added probe tests for degraded detector readiness and updated runtime integration tests to use the validated detector-construction path.

## Files Created Or Modified

- `crates/swarm-whisker/src/lib.rs`
- `crates/swarm-whisker/src/detector.rs`
- `crates/swarm-whisker/src/dns_exfiltration.rs`
- `crates/swarm-whisker/src/lateral_movement.rs`
- `crates/swarm-whisker/src/credential_access.rs`
- `crates/swarm-whisker/src/suspicious_scripting.rs`
- `crates/swarm-runtime/src/config.rs`
- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/tests/critical_path_integration.rs`

## Verification

- `cargo test -p swarm-whisker --lib`
- `cargo test -p swarm-runtime --lib`
- `cargo test -p swarm-runtime`
- `cargo test --workspace`
- `cargo clippy -p swarm-core -p swarm-whisker -p swarm-response -p swarm-runtime -- -D warnings`

## Notes

- Profile overrides merge on top of detector-specific defaults seeded with the top-level high and medium confidence thresholds, so existing configs keep their old threshold behavior unless they opt into per-detector overrides.
- `/healthz` remains available as the readiness view for backward compatibility while `/readyz` and `/livez` provide Kubernetes-style split semantics.
