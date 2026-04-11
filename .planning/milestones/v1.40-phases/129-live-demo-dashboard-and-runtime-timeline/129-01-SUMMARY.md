# Phase 129 Summary

## Delivered

- Added repo-owned `operator_surface.runtime_base_url` configuration and validation in `crates/swarm-core/src/config.rs` so the operator review UI can target the runtime demo APIs explicitly.
- Extended live runtime state sharing in `crates/swarm-runtime/src/ingest.rs` and `crates/swarm-runtime/src/bin/swarm_detect.rs` with shared mode-state access plus `GET /v1/demo/dashboard`.
- Added `concentration_snapshot` runtime events in `crates/swarm-runtime/src/runtime_events.rs` and emitted them from the concentration monitor in `crates/swarm-runtime/src/escalation.rs`.
- Upgraded the authenticated review home page in `crates/swarm-runtime/src/http/core.inc` into a live demo dashboard that boots from the runtime snapshot endpoint and stays current over SSE while preserving the existing review tables.

## User-Visible Outcome

- The operator review workbench now shows current swarm mode, visible agent health, per-threat-class pheromone pressure, and a live runtime timeline in one page.
- The dashboard is backed by runtime-owned JSON plus SSE instead of polling files, stores, or logs.
- Cross-origin local demo runs now work directly between the operator surface and the runtime surface through permissive GET CORS headers on the demo snapshot and stream endpoints.

## Notes

- The timeline seeds from recent escalation records and then appends streamed runtime events for ongoing drilldown context.
- `concentration_snapshot` is now part of the typed runtime event vocabulary alongside ingest, replay, action, response, health, escalation, and mode-transition events.
