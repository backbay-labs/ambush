# Phase 5: Durable Substrate - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Add restart-safe substrate persistence and live-response durability gating without changing the detector or policy contracts.

</domain>

<decisions>
## Implementation Decisions

### Backend Strategy
- Use a repo-owned local journal backend before any external JetStream dependency.
- Keep in-memory and durable backends behind the same `PheromoneSubstrate` trait.
- Make backend selection explicit in repository-owned config.

### Live Response Gating
- `live_response` can require a durable substrate backend.
- Readiness must fail closed when durable mode is required but unavailable.
- Detector and policy code must stay unaware of backend type.

### Claude's Discretion
Exact journal file layout and health-report fields are flexible as long as restart recovery and query-by-window are test-covered.

</decisions>

<specifics>
## Specific Ideas

Local JSONL journaling is acceptable for the single-node milestone and better matches the self-contained Rust direction than a hard external service requirement.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Product Direction
- `.planning/ROADMAP.md` - Current milestone phase mapping and success criteria.
- `.planning/REQUIREMENTS.md` - Requirement IDs for durability work.
- `.planning/PROJECT.md` - Rust-only, single-node, operator-focused constraints.

### Existing Code
- `crates/swarm-core/src/config.rs` - Config contract for runtime and pheromone settings.
- `crates/swarm-pheromone/src/substrate.rs` - Current in-memory substrate implementation.
- `crates/swarm-runtime/src/service.rs` - Runtime entrypoint that should enforce readiness.
- `rulesets/default.yaml` - Canonical repository-owned configuration file.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `PheromoneSubstrate` already isolates deposit/query behavior from detector logic.
- `SwarmConfig::validate` is the existing place for cross-field config semantics.

### Established Patterns
- Runtime contracts are serde-backed with explicit semantic validation after deserialize.
- Tests use small synthetic fixtures beside each module and prefer repository-owned sample config.

### Integration Points
- `RuntimeService` is the right place to reject unsafe live-response startup conditions.
- `swarm-whisker` should continue to write deposits through the substrate trait only.

</code_context>

<deferred>
## Deferred Ideas

- External JetStream transport integration
- Multi-node substrate replication

</deferred>

---
*Phase: 05-durable-substrate*
*Context gathered: 2026-04-03*
