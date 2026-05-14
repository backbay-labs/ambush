# Phase 117: Substrate Durability And Bridge Resilience - Context

**Gathered:** 2026-04-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Close four audit findings: threat-intel GC on all three substrate backends, local-journal rewrite during GC, Tetragon gRPC stream timeout, and empty parent process schema fix. Pure infrastructure hardening.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion — pure infrastructure phase. The audit findings define the exact changes:
- HARDEN-04: gc_expired_threat_intel() on PheromoneSubstrate, all 3 backends, logs purge count
- HARDEN-05: LocalJournal rewrites threat-intel journal during GC (same pattern as deposit journal rewrite)
- HARDEN-06: TetragonBridge::poll() wraps stream.next() in tokio::time::timeout() with configurable event_timeout_secs
- HARDEN-07: TetragonBridge schema validation accepts empty parent_process, stores "<none>" sentinel

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `gc_evaporated()` in substrate.rs already implements deposit GC across all backends
- `rewrite_jsonl()` helper in LocalJournal handles deposit journal compaction
- `TetragonBridge` in swarm-ingest-tetragon/src/bridge.rs with existing reconnect-backoff
- `process_start_schema_valid()` in bridge.rs validates ProcessStartEvent fields

### Established Patterns
- GC runs on configurable interval via `gc_interval_secs` in PheromoneConfig
- LocalJournal uses append-only JSONL files with periodic rewrite
- Bridge health tracked via BridgeHealth struct (events_processed, error_count, lag_seconds)

### Integration Points
- PheromoneSubstrate trait in swarm-pheromone/src/substrate.rs
- InMemoryPheromoneSubstrate, LocalJournalPheromoneSubstrate, JetStream backend
- TetragonBridge in swarm-ingest-tetragon/src/bridge.rs
- TetragonBridgeConfig in swarm-core config

</code_context>

<specifics>
## Specific Ideas

No specific requirements — infrastructure phase driven by audit findings.

</specifics>

<deferred>
## Deferred Ideas

None — all four findings are in scope.

</deferred>
