---
phase: 82-telemetry-ingest-server
plan: 01
subsystem: runtime
tags: [ingest, http, axum, swarm-detect, metrics]
requirements-completed: [INGEST-01, INGEST-02]
one-liner: "swarm-detect now serves `/v1/ingest/events` alongside `/metrics`, validating each JSON event independently and returning per-event accepted or rejected status."
completed: 2026-04-05
---

# Phase 82 Summary

**swarm-detect now serves `/v1/ingest/events` alongside `/metrics`, validating each JSON event independently and returning per-event accepted or rejected status.**

## Accomplishments

- Added a dedicated `ingest` runtime module with batch request/response types, structured status enums, and per-event serde validation.
- Implemented `IngestState` and shared HTTP router construction so the ingest route and the Prometheus `/metrics` surface run from the same axum application.
- Added strict malformed-body handling that returns HTTP 400 with structured JSON while still letting mixed valid and invalid events share one 200 response body.
- Updated `swarm_detect` with `--serve` and `--bind` so the binary can run as a long-lived HTTP telemetry receiver instead of only replaying scenario fixtures.
- Added integration tests covering valid batches, empty batches, malformed JSON, schema-invalid events, mixed accept/reject handling, and `/metrics` coexistence.

## Files Created Or Modified

- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/src/lib.rs`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`
- `crates/swarm-runtime/tests/ingest_integration.rs`

## Verification

- `cargo test -p swarm-runtime --test ingest_integration`
- `cargo test -p swarm-runtime --tests`

## Notes

- The ingest handler intentionally routes accepted events through the existing hot-path service with a no-op response builder so validation and detection stay inside the same runtime composition root.
