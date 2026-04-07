---
phase: 109-finding-enrichment-and-delivery-metadata
plan: 01
subsystem: runtime-detection
tags: [runtime, enrichment, findings]
requirements-completed: [SIEM-02]
one-liner: "The runtime now enriches every finding with normalized ancestry, host metadata, and deterministic time-to-detect before persistence or outbound delivery."
completed: 2026-04-07
---

# Phase 109 Plan 01 Summary

**The runtime now enriches every finding with normalized ancestry, host metadata, and deterministic time-to-detect before persistence or outbound delivery.**

## Accomplishments

- Added `FindingEnrichmentService` to the shared runtime path so enrichment happens once for replay, SIEM delivery, and notifications.
- Normalized `parent_process_ancestry` from the typed telemetry payload instead of detector-specific heuristics.
- Added stable `host_metadata` fields for source, host, event identity, and event timestamp.
- Computed `time_to_detect_ms` from the execution context timestamp so replay remains deterministic instead of depending on wall-clock time.
- Kept enrichment bounded and local to event data with no external lookups in the hot path.

## Files Created Or Modified

- `crates/swarm-runtime/src/service.rs`

## Verification

- `cargo test -p swarm-runtime --lib`
- `cargo build --workspace`

## Notes

- Using `ApprovalContext.now_ms` for `time_to_detect_ms` fixed a real replay determinism regression that surfaced during verification.
