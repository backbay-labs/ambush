# Phase 133 Verification

status: passed

## Result

Phase 133 verification passed.

## Commands

- `cargo test -p swarm-pheromone substrate::tests::query_deposits_filters_by_host_id -- --exact`
- `cargo test -p swarm-runtime ingest::tests::process_runtime_event_publishes_finding_runtime_events -- --exact`
- `cargo test -p swarm-runtime ingest::tests::platform_ -- --nocapture`
- `cargo test -p swarm-runtime ingest::tests::events_stream_filters_typed_runtime_events -- --exact`
- `cargo test -p swarm-runtime ingest::tests::healthz_returns_ok_with_component_status -- --exact`

## Verified Behaviors

- Host posture uses substrate-backed host filtering and returns host-scoped threat concentrations, active investigations, escalation level, and recent findings.
- `/v2/api/stream/findings` emits SSE `finding` events containing canonical `SwarmFindingEnvelope` payloads behind platform API key auth.
- The ingest path publishes finding runtime events even when no response action is selected, so detect-only runs still feed the live findings stream.
- Existing Phase 132 platform routes, the legacy runtime SSE filter path, and the health surface remained green after the Phase 133 changes.
