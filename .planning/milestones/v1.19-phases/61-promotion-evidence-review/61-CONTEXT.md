# Phase 61 Context

## Goal

Surface promotion evidence packets, fallback lineage, and supporting evidence state in one dedicated local review flow.

## Why This Phase Exists

The evidence review surface is only complete if operators can review the highest-level rollout handoff artifact without reconstructing it manually. Promotion evidence packets already package rollout outcome and supporting evidence for later governance work; this phase makes that packet legible and navigable in the local review client while preserving the advisory-only boundary.

## Inputs

- `.planning/phases/60-evidence-and-verification-inspection/60-CONTEXT.md`
- `.planning/phases/60-evidence-and-verification-inspection/60-01-PLAN.md`
- `crates/swarm-runtime/src/evidence.rs`
- `crates/swarm-runtime/src/operator_http.rs`
- `docs/CONFIGURATION.md`

## Prior Decisions

- Promotion evidence remains advisory and single-node.
- The review client must not approve, deploy, or mutate rollout state.
- Follow-on operator actions must stay routed through the existing authenticated maintenance or rollout APIs.

## Assumptions

- Listing recent promotion evidence packets is part of a credible review flow; operators should not need to know a packet ID in advance.
- A packet detail page should emphasize recommendation state, fallback lineage, and supporting evidence verification status before raw field dumps.
- Links from packet attachments back into evidence bundle and verification review pages are enough for first-pass lineage navigation.

## Non-Goals

- No approval workflow, voting, or governance execution.
- No rollback or promotion buttons on the review page.
- No cross-session collaboration or comment system.

## Phase Exit Signal

Operators can browse promotion evidence packets and inspect a packet’s rollout recommendation, fallback lineage, and supporting evidence relationships through the local review surface without bypassing audit trails or advisory-only constraints.
