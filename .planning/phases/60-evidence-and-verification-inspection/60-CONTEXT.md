# Phase 60 Context

## Goal

Surface signed evidence bundles and verification results in a dedicated review flow with filtering and lineage navigation.

## Why This Phase Exists

Once the review shell exists, the core operator need is practical evidence inspection. Evidence bundles, verification results, related refs, and stable IDs already exist, but operators should not need to parse raw JSON or manually cross-reference IDs to understand what was signed, verified, or related to a rollout or investigation artifact.

## Inputs

- `.planning/phases/59-review-surface-shell-and-auth-reuse/59-CONTEXT.md`
- `.planning/phases/59-review-surface-shell-and-auth-reuse/59-01-PLAN.md`
- `crates/swarm-runtime/src/operator_http.rs`
- `crates/swarm-runtime/src/evidence.rs`
- `docs/CONFIGURATION.md`

## Prior Decisions

- The review surface remains read-only and local-only.
- Stable IDs and current authenticated API contracts remain the source of truth.
- No new control-plane model or direct store inspection should be introduced.

## Assumptions

- Filtering by `subject_kind` and latest verification status is sufficient for the first dedicated evidence review flow.
- Navigation to related runtime or rollout lineage can initially use links to stable-ID JSON API resources and related HTML review pages.
- Evidence verification detail should surface the individual check outcomes, not only pass or fail.

## Non-Goals

- No bulk export or multi-select review sessions yet.
- No write actions such as re-verification triggers from the review page.
- No new evidence types beyond those already shipped in `v1.18`.

## Phase Exit Signal

Operators can browse and inspect evidence bundles and verification results through the local review surface, filter them meaningfully, and navigate across stable-ID lineage without dropping into raw JSON as the primary workflow.
