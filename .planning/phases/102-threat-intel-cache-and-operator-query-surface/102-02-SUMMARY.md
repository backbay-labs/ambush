---
phase: 102-threat-intel-cache-and-operator-query-surface
plan: 02
subsystem: operator-surface
tags: [operator, http, control, threat-intel]
requirements-completed: [SUBSTRATE-04]
one-liner: "The authenticated operator surface can now seed and query substrate-backed threat-intel entries through one control-plane source of truth."
completed: 2026-04-07
---

# Phase 102 Plan 02 Summary

**The authenticated operator surface can now seed and query substrate-backed threat-intel entries through one control-plane source of truth.**

## Accomplishments

- Added control-plane helpers for storing and querying exact threat-intel entries through the configured substrate.
- Extended the authenticated operator HTTP surface with `/v1/operator/threat-intel/entries` for bearer-token-protected POST and exact-match GET operations.
- Kept operator lookup TTL-aware by accepting an explicit `now` query parameter and defaulting to current wall-clock time when omitted.
- Added operator-surface tests proving a stored threat-intel entry is queryable through the same HTTP surface and that expired entries fail closed as `null`.
- Added control-plane proof showing a stored threat-intel record is visible to live runtime queries without restart.

## Files Created Or Modified

- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-runtime/src/http/core.inc`

## Verification

- `cargo fmt --all`
- `cargo test -p swarm-runtime --lib`
- `cargo test -p swarm-runtime threat_intel_routes_store_and_query_entries --lib`
- `cargo test -p swarm-runtime --test escalation_integration`
- `cargo clippy -p swarm-core -p swarm-pheromone -p swarm-runtime --tests -- -D warnings`

## Notes

- The operator API writes directly into the substrate-backed cache, so later enrichment work uses the same durable source of truth instead of a separate operator-only store.
- The surface intentionally stays narrow to exact seed and lookup behavior in this phase; detector-side confidence shaping lands in phase 103.
