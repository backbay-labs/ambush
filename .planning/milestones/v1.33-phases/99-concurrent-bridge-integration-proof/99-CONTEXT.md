---
phase: 99-concurrent-bridge-integration-proof
type: context
created_at: 2026-04-07
depends_on: [98]
---

# Phase 99 Context

## Goal

Prove that at least two configured telemetry bridge instances can run concurrently against the shared runtime channel and still drive the shipped detection pipeline all the way through pheromone deposit.

## Why This Phase Exists

Phase 98 made bridge construction, worker lifecycle, health snapshots, and Prometheus surfacing real in serve mode. That work is still incomplete as a milestone unless the repo demonstrates bounded end-to-end behavior beyond unit tests: multiple bridge workers, one shared channel, one live detector path, and durable pheromone output.

## What Is Already True

- `BridgeRuntimeRegistry` now builds named bridge instances from `runtime.telemetry_sources[*].bridge` and spawns one worker per configured bridge.
- The bridge workers feed normalized `TelemetryEvent` values into the same `telemetry_tx` channel already consumed by `WhiskerAgent`.
- `WhiskerAgent` still uses the existing `detect_and_deposit` path, so pheromone deposits remain the authoritative proof that bridge-produced events reached the detector lane.
- `CloudTrailBridge` and `GenericJsonBridge` can both emit `AuthenticationEvent` payloads, which means one detector can evaluate both sources in the same bounded test.

## Constraints

- Keep the proof deterministic and fast enough for routine CI execution.
- Avoid external services or live Tetragon dependencies.
- Reuse the shipped runtime seam instead of building a fake bridge runner.

## Phase Direction

- Use two file-backed bridge instances so concurrency is real but bounded.
- Prefer a detector that both bridges can trigger with straightforward fixtures; `credential_access` via `AuthenticationEvent` is the cleanest fit.
- Assert on `PheromoneDeposit` output and source tags, not just raw event receipt, so the proof reaches the substrate.
