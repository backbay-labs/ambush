---
phase: 12-deterministic-replay-harness
plan: 01
subsystem: replay
tags:
  - replay
  - fixtures
  - offline
  - durability
one-liner: `swarmctl` can now run deterministic offline replay from tracked scenarios or persisted replay bundle fixtures and persist durable replay-run bundles.
requires:
  - 11-operator-control-surface
provides:
  - Repo-owned offline replay harness in `swarm-runtime`
  - Durable replay-run bundle store under `data/replay-runs/`
  - Tracked scenario corpus for suspicious and benign baseline cases
affects: []
tech-stack:
  added: []
  patterns:
    - deterministic timestamps for offline artifact generation
    - separate replay-run store instead of mixing offline artifacts into live runtime stores
    - tracked YAML scenarios driving the same Rust hot-path types
key-files:
  created:
    - crates/swarm-runtime/src/replay.rs
    - scenarios/office-dropper-correlation.yaml
    - scenarios/benign-baseline.yaml
  modified:
    - .gitignore
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - crates/swarm-runtime/src/correlation.rs
    - crates/swarm-runtime/src/lib.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Offline replay forces `detect_only` execution and uses `SandboxExecutor`, so replay cannot execute live actions."
  - "Replay stores performance snapshots, but deterministic comparisons key off a stable summary so repeatability is not polluted by wall-clock variance."
  - "Correlation accepts an explicit timestamp for replay so incident IDs and bundle contents stay stable across reruns."
patterns-established:
  - "Scenario-backed operator workflows should live in `swarm-runtime` beside the CLI and reuse production Rust types."
requirements-completed:
  - RPLY-01
  - RPLY-02
  - RPLY-03
duration: 45min
completed: 2026-04-03
---

# Phase 12: Deterministic Replay Harness Summary

**The repo now ships an offline replay harness that can rerun tracked scenarios or replay bundle fixtures without executing live response actions, then persist one durable replay-run bundle with investigations and incidents.**

## Performance

- **Duration:** 45 min
- **Started:** 2026-04-03T15:08:00Z
- **Completed:** 2026-04-03T15:53:22Z
- **Tasks:** 3
- **Files modified:** 8

## Accomplishments

- Added `crates/swarm-runtime/src/replay.rs` with scenario manifests, a durable replay-run store, deterministic summaries, a replay harness, and focused replay tests.
- Extended `crates/swarm-runtime/src/correlation.rs` so offline replay can mint deterministic incident IDs from a seeded timestamp instead of wall-clock time.
- Added `swarmctl replay-run` and `swarmctl replay-result` so operators can execute and reload offline replay bundles from repo-owned config.
- Added tracked scenarios under `scenarios/` for one suspicious correlated case and one benign baseline case.
- Documented the replay-run/result workflow and default results directory in `docs/CONFIGURATION.md`.

## Decisions Made

- Replay runs use a dedicated result store under `data/replay-runs/` instead of polluting the live replay bundle store.
- Inline investigation during replay keeps IDs, timestamps, and ordering deterministic without reusing the async queue.
- Performance snapshots remain in the replay-run bundle, but deterministic comparisons use a stable summary because latency is machine-dependent.

## Deviations from Plan

Single-run evaluation scaffolding also landed in the replay module because the same result bundle schema needed to carry expectation and latency data for the next phase.

## Issues Encountered

The initial replay tests used a `live_response` config that required a durable substrate. The test config was corrected to disable that validation because replay forces `detect_only` execution and uses an in-memory substrate.

## User Setup Required

Run replay from a tracked scenario:

```bash
cargo run -p swarm-runtime --bin swarmctl -- replay-run --scenario scenarios/office-dropper-correlation.yaml
```

The default output directory is `data/replay-runs/` and is ignored by git.

## Next Phase Readiness

Phase 13 can now treat replay-run bundles as the canonical regression input and turn single-scenario expectation checks into broader operator and CI gates.

---
*Phase: 12-deterministic-replay-harness*
*Completed: 2026-04-03*
