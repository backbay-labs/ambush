# Phase 210 Plan 01 Summary

## Delivered

- Added the repo-owned runtime degradation ladder in
  `crates/swarm-core/src/config.rs` with explicit `full`, `detect_only`,
  `read_only`, and `emergency_drain` levels plus bounded capability helpers for
  ingest, detection, live response, artifact writes, and operator read
  surfaces.
- Introduced shared degradation reporting in
  `crates/swarm-runtime/src/service.rs`, including typed triggers,
  capability summaries, transition timestamps, and deterministic signal-to-level
  evaluation so every surface serializes the same contract.
- Updated `crates/swarm-runtime/src/ingest/mod.rs` to evaluate live degradation
  from detector readiness, substrate health, replay-store health, startup
  attestation, anti-tamper state, heap pressure, drain state, and dispatcher
  agent health, while rejecting new ingest when the runtime falls to
  `read_only` or `emergency_drain`.
- Surfaced the shared degradation state through `/readyz`, `/healthz`,
  `swarmctl status`, and `/v2/api/runtime/status` in
  `crates/swarm-runtime/src/ingest/health.rs`,
  `crates/swarm-runtime/src/control.rs`, and
  `crates/swarm-runtime/src/ingest/platform_api.rs`.
- Added focused proof in `crates/swarm-runtime/src/control.rs` and
  `crates/swarm-runtime/src/ingest/tests.rs` that the repo-owned surfaces now
  report `full`, `detect_only`, `read_only`, and `emergency_drain` at the
  expected boundaries.

## Notes

- Phase 210 intentionally stops at deterministic runtime-owned evaluation,
  bounded ingest gating, and shared operator visibility. Scenario-driven proof
  for NATS-unreachable, write-path failure, and heap-pressure transitions
  remains Phase 211 work.
