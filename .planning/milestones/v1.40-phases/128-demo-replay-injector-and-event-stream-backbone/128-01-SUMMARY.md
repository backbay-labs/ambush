# Phase 128 Summary

## Delivered

- Added `runtime.demo_mode` as a repo-owned runtime gate in `crates/swarm-core/src/config.rs` and threaded the new field through runtime fixtures and tests.
- Added a typed runtime event backbone in `crates/swarm-runtime/src/runtime_events.rs` and exported it from `crates/swarm-runtime/src/lib.rs`.
- Wired the shared event broadcaster through serve mode in `crates/swarm-runtime/src/bin/swarm_detect.rs`, dispatcher action/routing in `crates/swarm-runtime/src/dispatcher.rs`, and concentration-monitor escalation/mode transitions in `crates/swarm-runtime/src/escalation.rs`.
- Added `POST /v1/demo/replay` and `GET /v1/events/stream` in `crates/swarm-runtime/src/ingest.rs`.

## User-Visible Outcome

- Operators can now inject repo-owned event scenarios into the live runtime path when `demo_mode` is enabled.
- Downstream demo surfaces can subscribe to typed SSE events and filter by event kind instead of scraping logs.
- Replay injection now emits structured replay lifecycle events and real ingest events while also feeding the running telemetry lane consumed by swarm agents.

## Notes

- The new stream currently carries ingest, replay lifecycle, agent action, response execution, agent health, escalation, and mode-transition events.
- I restored the generated `crates/swarm-runtime/dead-letter.jsonl` journal after verification so the phase did not leave extra test-artifact noise behind.
