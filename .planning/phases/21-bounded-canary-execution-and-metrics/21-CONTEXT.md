# Phase 21: Bounded Canary Execution And Metrics - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Execute the candidate detector in a scoped canary lane against live `TelemetryEvent` inputs, record comparison metrics against the production baseline, and keep canary outputs isolated from fleet-wide escalation semantics.

</domain>

<decisions>
## Implementation Decisions

### Live Lane Shape
- Process canary inputs with the runtime-side detector path rather than the replay harness.
- Evaluate baseline and candidate detectors against the same incoming event for direct comparison.
- Keep candidate findings and resource accounting inside a dedicated canary artifact instead of depositing into the production substrate.

### Metrics
- Record baseline detections, candidate detections, shared detections, candidate-only detections, baseline-only detections, and detection latency.
- Treat candidate-only detections as the conservative false-positive proxy for the live canary lane.
- Track resource usage as emitted candidate finding volume over the canary window.

### Operator Surface
- Expose canary event ingestion and canary result lookup through `swarmctl`.
- Make active canary metrics reloadable from the persisted canary run artifact.

</decisions>

<specifics>
## Specific Ideas

The runtime already has one-event processing semantics. This phase should reuse that assumption: a canary run advances as live events are ingested, and the canary window is bounded by repo-owned thresholds and an observation-event budget.

</specifics>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/phases/20-canary-slot-and-strategy-assignment/20-01-PLAN.md`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/pipeline.rs`
- `crates/swarm-whisker/src/detector.rs`
- `docs/EVOLUTION.md`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DetectionStrategy` evaluation is deterministic and side-effect free.
- The fast path already measures latency per event and produces typed findings.
- Replay and experiment code already compares baseline and candidate metrics over the same corpus.

### Established Patterns
- Runtime live behavior belongs in runtime modules, not in the replay harness.
- Persisted operator artifacts use file-backed stores with stable indexes.
- CLI commands render both JSON and human-readable summaries.

### Integration Points
- Extend the canary module with event ingestion and metric accumulation.
- Add canary event commands to `swarmctl`.
- Add focused tests using synthetic `TelemetryEvent` fixtures.

</code_context>

<deferred>
## Deferred Ideas

- Real background telemetry subscription loops
- Canary pheromone deposits that participate in fleet-wide mode transitions
- Multi-slot or percentage-based canary routing

</deferred>

---
*Phase: 21-bounded-canary-execution-and-metrics*
*Context gathered: 2026-04-03*
