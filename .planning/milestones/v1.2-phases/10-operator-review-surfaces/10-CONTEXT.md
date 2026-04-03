# Phase 10: Operator Review Surfaces - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Expose hot-path decisions, async investigation status, and correlated incidents through one serializable operator-facing report with explicit freshness boundaries.

</domain>

<decisions>
## Implementation Decisions

### Surface Shape
- Extend the existing `OperatorStatusReport` rather than inventing a separate review API.
- Keep the surface Rust-serializable and API-first so later CLI or HTTP layers can reuse it unchanged.
- Preserve the existing hot-path status fields while layering async review context beside them.

### Review Content
- Surface investigation queue state, last failure reason, and recent investigation summaries directly from durable investigation artifacts.
- Surface recent incidents from durable incident artifacts, including correlation keys and linked hunts.
- Add explicit freshness timestamps for hot-path decisions, investigations, and incidents so operators can see what was authoritative first and what was attached later.

### Degraded Modes
- Treat investigation-store or incident-store readiness problems as operator warnings, not startup blockers.
- Show queue failure state and recent async status without requiring raw file inspection.
- Keep review surfaces read-only in this milestone; no operator actions or mutation flows.

### Claude's Discretion
Field names and nested report struct boundaries can stay lightweight as long as the result is one serializable surface with clear hot-path versus async distinction.

</decisions>

<specifics>
## Specific Ideas

The existing status report already has runtime mode, component readiness, metrics, and recent decisions. Phase 10 should extend that report with investigation, incident, and freshness sections rather than branching the model.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`

### Existing Code
- `.planning/phases/07-operator-visibility/07-01-SUMMARY.md`
- `.planning/phases/08-async-investigation-pipeline/08-01-SUMMARY.md`
- `.planning/phases/09-correlation-and-incident-assembly/09-01-SUMMARY.md`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/investigation.rs`
- `crates/swarm-runtime/src/correlation.rs`
- `crates/swarm-spine/src/investigation.rs`
- `crates/swarm-spine/src/incident.rs`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `OperatorStatusReport` already captures runtime readiness, metrics, warnings, and recent decisions.
- Investigation bundles already expose status, summary preview, failure reason, and timestamps.
- Incident records already expose included hunts, related receipts, and correlation keys.

### Established Patterns
- Operator-facing data stays serializable and store-backed.
- `RuntimeService` is the convergence point for cross-stage and cross-artifact reporting.

### Integration Points
- `operator_status` should become the base report builder and Phase 10 should extend it with async review sections.
- Investigation coordinator snapshots provide live queue state; durable stores provide recent investigation and incident artifacts.
- Freshness markers can be derived from existing `created_at_ms` and `last_updated_ms` fields.

</code_context>

<deferred>
## Deferred Ideas

- Interactive CLI workflows
- HTTP admin server
- Incident acknowledgement or disposition flows

</deferred>

---
*Phase: 10-operator-review-surfaces*
*Context gathered: 2026-04-03*
