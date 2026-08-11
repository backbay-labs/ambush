# Phase 119: Pheromone Test Suite - Context

**Gathered:** 2026-04-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Add a focused, self-contained test suite to `swarm-pheromone` covering the substrate trait contract. The crate previously had zero tests. After phases 116-117 added deposit signature validation and threat-intel GC, the substrate now has more surface area that needs independent coverage.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion — pure test infrastructure phase. The requirement specifies:
- HARDEN-10: At least 15 tests in swarm-pheromone
- Cover: deposit, query, evaporation GC, escalation record persistence, threat-intel CRUD with TTL expiry, ThreatClassConfig store/query
- All tests run against InMemoryPheromoneSubstrate without importing swarm-runtime
- Tests for TTL expiry must call gc_expired_threat_intel() and verify results
- `cargo test -p swarm-pheromone` and `cargo clippy -p swarm-pheromone -- -D warnings` must pass

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `InMemoryPheromoneSubstrate` in swarm-pheromone/src/substrate.rs
- `PheromoneSubstrate` trait with deposit, query, gc_evaporated, gc_expired_threat_intel, query_escalations, store/query threat_class_config, store/query threat_intel_entry
- `PheromoneDeposit`, `EscalationRecord`, `ThreatIntelEntry`, `ThreatClassConfig` types
- Existing tests: 5 signature validation tests added in phase 116, ~4 GC tests added in phase 117

### Established Patterns
- Tests use `#[tokio::test]` for async substrate methods
- Deposits require valid Ed25519 signatures (phase 116 added validation)
- Helper: `DepositSigningPayload` for canonical signing

### Integration Points
- swarm-pheromone depends on swarm-core (types) and swarm-crypto (signing)
- Tests must NOT depend on swarm-runtime

</code_context>

<specifics>
## Specific Ideas

No specific requirements — test coverage phase driven by audit finding that swarm-pheromone had zero tests before phases 116-117 added some.

</specifics>

<deferred>
## Deferred Ideas

- JetStream backend integration tests (require NATS, better as separate CI job)
- LocalJournal backend tests (some exist in phase 117 GC tests)

</deferred>
