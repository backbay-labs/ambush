---
phase: 104-drain-control-and-startup-probe-surface
plan: 02
subsystem: probes
tags: [kubernetes, probes, startup, readiness]
requirements-completed: [K8S-02]
one-liner: "The serve-mode router now exposes a dedicated `/startupz` contract that validates startup-only invariants independently from readiness and liveness."
completed: 2026-04-07
---

# Phase 104 Plan 02 Summary

**The serve-mode router now exposes a dedicated `/startupz` contract that validates startup-only invariants independently from readiness and liveness.**

## Accomplishments

- Added `/startupz` to the serve-mode router alongside `/livez`, `/readyz`, `/healthz`, `/metrics`, and `/prestop`.
- Implemented startup-only health checks for schema compatibility, substrate readiness, and the presence of at least one configured telemetry source.
- Kept readiness focused on live operational degradation instead of one-time boot invariants so probe semantics stay clean under Kubernetes.
- Extended the health payload shape with lifecycle visibility so operators can distinguish startup, draining, and ready states.
- Added lifecycle tests proving `/startupz` stays separate from steady-state readiness behavior.

## Files Created Or Modified

- `crates/swarm-runtime/src/ingest.rs`

## Verification

- `cargo test -p swarm-runtime ingest --lib`
- `cargo test -p swarm-runtime --lib --no-run`
- `cargo build --workspace`

## Notes

- `/startupz` is intentionally startup-only; heap pressure and drain state remain readiness concerns, not boot blockers.
- Startup checks fail closed before the runtime claims readiness, which makes rollout diagnostics much clearer in Kubernetes.
