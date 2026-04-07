---
phase: 78-service-extraction-and-detection-binary
plan: 01
subsystem: runtime
tags: [service-extraction, detection, replay, swarm-detect]
requirements-completed: [OPS-26, OPS-27]
one-liner: "Standalone `swarm-detect` now runs the detection hot path from repo-owned rulesets and scenario inputs without the `swarmctl` workbench."
completed: 2026-04-05
---

# Phase 78: Service Extraction And Detection Binary Summary

**Standalone `swarm-detect` now runs the detection hot path from repo-owned rulesets and scenario inputs without the `swarmctl` workbench.**

## Accomplishments

- Added a focused `swarm-detect` binary that loads `rulesets/default.yaml`, constructs the runtime stack, and processes scenario events through detection, pheromone deposit, policy evaluation, and response execution.
- Promoted the detector factory and replay scenario loader APIs to public runtime interfaces so `swarmctl`, `swarm-detect`, and tests all reuse the same runtime wiring instead of duplicating detector or scenario parsing logic.
- Wired both directory-based and repeated single-file scenario inputs into the binary, with human-readable and JSON output modes for per-event and per-scenario reporting.
- Preserved runtime-mode semantics so the standalone binary respects the same `detect_only` and `live_response` behavior already used by the library runtime.

## Files Created Or Modified

- `crates/swarm-runtime/src/bin/swarm_detect.rs` - added the standalone detection binary, CLI parsing, scenario processing loop, and human/JSON output.
- `crates/swarm-runtime/src/control.rs` - exported `SupportedDetector` and `supported_detector` for binary reuse.
- `crates/swarm-runtime/src/replay.rs` - exported scenario loading helpers and the loaded-scenario wrapper for shared reuse.

## Key Decisions

- The standalone binary reuses `RuntimeService` instead of the lower-level pipeline directly so its behavior stays aligned with the persisted runtime hot path and later observability work.
- Scenario processing accepts both `--scenarios-dir` and repeated `--scenario` flags so operators can run whole corpora or single fixtures without separate tooling.
- Output stays intentionally small: one startup line, one per-event result, one per-scenario summary, and one final summary in either text or JSON.

## Verification

- `cargo build -p swarm-runtime --bin swarm_detect`
- `cargo run -p swarm-runtime --bin swarm_detect -- --config rulesets/default.yaml --scenarios-dir scenarios/`
- `cargo run -p swarm-runtime --bin swarm_detect -- --config rulesets/default.yaml`
- `cargo test -p swarm-runtime --lib -- --quiet`

## Notes

- The binary currently consumes repo-owned scenario fixtures rather than a live telemetry source; live ingress remains future operational work.
- `swarm-detect` is the first service-oriented extraction from the monolithic `swarmctl` CLI and establishes the shared detector/scenario interfaces used in later phases.
