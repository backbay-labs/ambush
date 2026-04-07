---
phase: 104-drain-control-and-startup-probe-surface
type: context
created_at: 2026-04-07
depends_on: [103]
---

# Phase 104 Context

## Goal

Add Kubernetes-safe serve-mode lifecycle control so `swarm-detect` can stop accepting new ingest work, finish accepted work within a bounded drain window, and expose a dedicated startup probe contract independent from steady-state readiness.

## Why This Phase Exists

`v1.34` completed the live substrate and threat-intel flow, but the serve-mode runtime still shuts down as a generic process. It does not expose a PreStop-specific drain path, and startup versus readiness probes still share one operational surface. That is acceptable for local development, but it is too weak for Kubernetes rollouts where accepted work must not be dropped and startup needs a separate contract from runtime health drift.

## What Is Already True

- `swarm-detect` already handles `SIGTERM` and `CTRL-C` with graceful Axum shutdown.
- `IngestState` already owns the live runtime stack and is the natural place to hold drain and lifecycle state.
- `/livez`, `/readyz`, and `/healthz` already exist under `detect_http_router`.
- The hot path already awaits `ConfiguredRuntimeStack::process_event`, so in-flight ingest work can be bounded without redesigning detector execution.

## Constraints

- Do not change the JSON request or response contract for `/v1/ingest/events`.
- Drain mode must fail closed for new ingest requests while allowing accepted work to finish.
- Startup checks should stay narrower than readiness checks; readiness still represents healthy operation after boot.
- The implementation should reuse the existing graceful-shutdown path instead of adding a second shutdown subsystem.

## Decisions

- The PreStop handler will be surfaced as a local HTTP route in the same Axum app so Kubernetes can invoke it directly before termination.
- In-flight tracking will be request-scoped around the full ingest handler lifecycle, which conservatively includes detector, policy, replay, and response execution.
- `RuntimeSettings.drain_timeout_ms` will own the drain budget because the bound belongs to operational lifecycle behavior rather than response-adapter retry policy.
- `/startupz` will validate startup-only invariants: supported schema version, substrate readiness, and at least one configured telemetry source.

## Phase Direction

- First add drain-state tracking plus bounded shutdown coordination.
- Then add `/startupz` and tests proving the startup versus readiness split.
- Keep the implementation local to runtime serve-mode seams already present in `ingest.rs` and `swarm_detect.rs`.
