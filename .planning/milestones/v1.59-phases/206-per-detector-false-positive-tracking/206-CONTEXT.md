# Phase 206: Per-Detector False Positive Tracking - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 206 turns the existing analyst feedback lane into durable measured
false-positive tracking. The goal is not a new feedback UI; it is one bounded
runtime-owned measurement path that records per-detector and per-host
false-positive counts or rates from the feedback already flowing through the
Providence ingress.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing Providence feedback handler as the source of truth for
  analyst-driven false-positive signals instead of inventing a second ingest
  contract.
- Persist bounded per-detector and per-host measurement artifacts that later
  tuning work can reuse directly.
- Surface the measurement through repo-owned operator outputs (`swarmctl` and
  the platform API) so operators do not need to mine raw incident audit
  history.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/ingest/providence_handlers.rs` already verifies
  signed Providence feedback, resolves the target incident member, and routes
  dismiss feedback into the existing Kitten false-positive penalty flow.
- Incident records already retain `feedback_audit_entries`, detector strategy
  IDs, and finding or host context that can anchor rolled-up FP measurements.
- The control and platform status surfaces already expose repo-owned operator
  summaries and are the natural place to publish the new bounded measurement.

</code_context>

<deferred>
## Deferred Ideas

- Concrete tuning recommendations remain Phase 207 work.
- Any broader analyst scoring or quality heuristics beyond false-positive
  measurement remain out of scope for this phase.

</deferred>
