# Phase 7: Operator Visibility - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Expose runtime readiness, stage metrics, and recent decision correlation through one operator-facing status surface.

</domain>

<decisions>
## Implementation Decisions

### Status Surface
- Keep operator visibility as a Rust API/report object first, not a CLI or web console.
- Source recent decisions from the replay store index instead of a separate status cache.
- Include component readiness and durability hints directly in the report.

### Metrics
- Track per-stage counters and bounded latency distributions for detect, policy, persist, and response stages.
- Record metrics inside `RuntimeService` where all milestone phases intersect.
- Prefer simple fixed buckets over a dependency-heavy metrics stack in this milestone.

### Claude's Discretion
Exact bucket boundaries and component detail strings are flexible as long as the report is serializable and test-covered.

</decisions>

<specifics>
## Specific Ideas

Operator visibility should be inspectable from tests and future CLIs alike, so a serializable status report is the right boundary.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`

### Existing Code
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/lib.rs`
- `crates/swarm-spine/src/store.rs`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- The runtime now has stage-aware execution details from instrumented audit execution.
- The replay store already exposes recent-decision records and health summaries.

### Established Patterns
- Service-level serializable reports are acceptable and easy to test.
- Stable hunt, trail, and receipt identifiers already exist in the critical path.

### Integration Points
- `RuntimeService` should own stage metrics because it sees detect, policy, persist, and response together.
- Operator status should combine substrate health, replay-store health, runtime mode, and recent persisted records.

</code_context>

<deferred>
## Deferred Ideas

- External metrics exporters
- Dedicated admin server / HTTP surface

</deferred>

---
*Phase: 07-operator-visibility*
*Context gathered: 2026-04-03*
