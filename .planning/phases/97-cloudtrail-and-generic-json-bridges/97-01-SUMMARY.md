---
phase: 97-cloudtrail-and-generic-json-bridges
plan: 01
subsystem: ingest
tags: [bridges, json, cloudtrail, normalization]
requirements-completed: [BRIDGE-03]
one-liner: "`swarm-ingest-json` now ships a reusable JSON record source plus a `CloudTrailBridge` that normalizes CloudTrail auth and data-access records into shared telemetry."
completed: 2026-04-06
---

# Phase 97 Plan 01 Summary

**`swarm-ingest-json` now ships a reusable JSON record source plus a `CloudTrailBridge` that normalizes CloudTrail auth and data-access records into shared telemetry.**

## Accomplishments

- Added a new `swarm-ingest-json` workspace crate to hold JSON-oriented bridge implementations instead of scattering small JSON mapping utilities across unrelated runtime crates.
- Introduced `JsonRecordSource`, a reusable record loader that accepts JSON arrays, single JSON objects, or JSON Lines streams and exposes pulled records to bridge implementations through one shared API.
- Implemented `CloudTrailBridge` as a concrete `TelemetryBridge` that maps authentication-oriented CloudTrail records into `TelemetryPayload::AuthenticationEvent` and non-auth/data-access records into `TelemetryPayload::NetworkConnect`.
- Preserved bridge-health tracking for the JSON bridge path so processed-event counts, lag, and last-error context stay aligned with the shared `BridgeHealth` model introduced in phase 96.
- Covered the bridge with focused unit tests for console login mapping, S3-style data access mapping, and malformed-record fail-closed behavior.

## Files Created Or Modified

- `Cargo.toml`
- `crates/swarm-ingest-json/Cargo.toml`
- `crates/swarm-ingest-json/src/lib.rs`
- `crates/swarm-ingest-json/src/source.rs`
- `crates/swarm-ingest-json/src/cloudtrail.rs`

## Verification

- `cargo test -p swarm-ingest-json --lib`
- `cargo test -p swarm-core --lib`
- `cargo clippy -p swarm-core -p swarm-runtime -p swarm-ingest-json --tests -- -D warnings`

## Notes

- `CloudTrailBridge` currently normalizes local JSON fixtures or JSON Lines streams from disk rather than polling AWS APIs directly; runtime orchestration of bridge instances is deferred to phase 98.
- The shared JSON record source is intentionally bridge-agnostic so future JSON-backed adapters can reuse the same loading path without reimplementing file parsing.
