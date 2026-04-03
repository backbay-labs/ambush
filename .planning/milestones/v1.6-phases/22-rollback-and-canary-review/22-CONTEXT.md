# Phase 22: Rollback And Canary Review - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Add automatic and manual rollback to the bounded canary lane, persist rollback history, and turn verification, shadow, and canary evidence into one stable canary review surface.

</domain>

<decisions>
## Implementation Decisions

### Rollback Policy
- Roll back automatically when canary thresholds or resource budgets are exceeded.
- Preserve manual halt and manual rollback as explicit operator actions with recorded reasons.
- Record the reverted baseline strategy on every rollback event.

### Review Surface
- Reuse the same canary run artifact as the operator-facing review packet instead of inventing a separate promotion type.
- Carry forward verification and shadow references from the assignment phase.
- Expose ready-for-promotion vs blocked as a canary recommendation, while keeping actual production promotion out of scope.

### Operator Workflow
- Add CLI commands for manual halt, manual rollback, and canary result lookup by stable ID.
- Document the end-to-end canary lifecycle in `docs/CONFIGURATION.md`.

</decisions>

<specifics>
## Specific Ideas

Rollback is the real safety proof for this milestone. A canary lane without automatic stop conditions is just another live lane. The final artifact should make the decision obvious: ready for the next promotion step, or blocked with preserved reasons and references.

</specifics>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/phases/21-bounded-canary-execution-and-metrics/21-01-PLAN.md`
- `crates/swarm-runtime/src/canary.rs`
- `crates/swarm-runtime/src/bin/swarmctl.rs`
- `docs/EVOLUTION.md`
- `docs/CONFIGURATION.md`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- Verification and shadow artifacts already surface stable IDs and pass/fail evidence.
- Promotion-review packets already model recommendation-plus-blocking-reasons semantics.
- File-backed runtime artifacts already preserve lookup metadata and human-readable renderers.

### Established Patterns
- Automatic gates fail closed and still persist the artifact for later inspection.
- Operator CLI supports both machine-readable JSON and concise human-readable summaries.
- Milestone artifacts should link directly to the previous offline evidence instead of recomputing it.

### Integration Points
- Extend the canary module with threshold evaluation, rollback history, and final recommendation rendering.
- Add manual halt and rollback commands in `swarmctl`.
- Update docs and tests to cover automatic rollback and persisted review behavior.

</code_context>

<deferred>
## Deferred Ideas

- Fleet-wide production promotion
- Consensus-based promotion approval
- Automatic canary-to-production promotion

</deferred>

---
*Phase: 22-rollback-and-canary-review*
*Context gathered: 2026-04-03*
