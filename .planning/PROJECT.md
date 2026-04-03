# Swarm Team Six

## What This Is

Swarm Team Six is a Rust-first threat detection and controlled live-response runtime for operators who need to act within the response window. The shipped system can now detect suspicious behavior, evaluate narrow response actions through deterministic policy, survive restart with durable local storage, attach async investigation to persisted replay bundles, assemble explainable incidents, and surface the full chain in one operator review report.

## Core Value

Detect real threats quickly enough to take safe action before the window to respond closes.

## Current State: v1.2 Shipped

**Latest shipped milestone:** v1.2 Async Investigation And Correlation

**What shipped:**
- async investigation jobs that run off the hot path and persist durable investigation bundles
- deterministic incident correlation with explicit inclusion and rejection reasoning
- one operator review surface with queue state, recent investigations, recent incidents, warnings, and freshness markers
- one config-backed runtime stack that composes substrate, replay, investigation, and incident components from repo-owned settings

## Requirements

### Validated

- ✓ Operator can run a pure-Rust detect -> authorize -> execute slice with repository-owned config and explicit runtime modes — v1.0
- ✓ Runtime can evaluate a concrete detector, deposit to an in-memory substrate, and publish benchmarked hot-path latency — v1.0
- ✓ Runtime can gate live response through deterministic policy, scoped leases, sandboxed execution, and normalized receipts — v1.0
- ✓ Runtime can emit auditable replay bundles and cover the critical path with integration tests — v1.0
- ✓ Operator can switch between in-memory and local-journal substrate backends and require durable live response at runtime boundaries — v1.1
- ✓ Operator can persist replay bundles to a configured store and reload them by hunt or receipt ID after restart — v1.1
- ✓ Operator can inspect one status surface with stage metrics, component readiness, and recent decision correlation — v1.1
- ✓ Operator can queue async investigation off persisted replay bundles and retrieve durable investigation artifacts by hunt or receipt ID — v1.2
- ✓ Operator can assemble explainable incidents from investigation bundles using shared evidence and time windows — v1.2
- ✓ Operator can review hot-path decisions, async investigation state, incidents, and freshness markers from one serializable report — v1.2
- ✓ Operator can bootstrap the async investigation and correlation stack from repository-owned config instead of test-only manual wiring — v1.2

### Active

(None currently — start the next milestone with `$gsd-new-milestone`)

### Out of Scope

- Async investigation on the hot path — enrichment must not weaken the fast-detection proof point
- Distributed governance / quorum approvals — still premature without independent nodes and trust boundaries
- Gossip membership / CRDT state sharing — not justified for the current single-node operating model
- Python runtime resurrection or PyO3 expansion — conflicts with the Rust-first critical lane
- Live evolution / red-team loops — still better treated as offline evaluation work

## Context

v1.0 shipped the first trusted Rust vertical slice: config loading, detection, in-memory pheromone substrate, deterministic policy, sandboxed response execution, and replayable audit artifacts. v1.1 hardened that slice with local durability, persistent replay storage, and operator status or metrics surfaces. v1.2 layered in async investigation, explainable incident assembly, and one operator review report without compromising the hot path.

The runtime remains intentionally single-node and deterministic. Async enrichment is durable and operator-visible, but it still does not mutate live-response policy automatically. Distributed governance, gossip, and offline evolution labs remain future work.

## Constraints

- **Tech stack**: Production runtime remains pure Rust — enrichment should extend the same operational path and type system
- **Security**: Async enrichment cannot mutate or backdoor the existing live-response verdict path
- **Architecture**: This milestone stays single-node and composition-friendly — avoid BFT, gossip, or multi-authority work
- **Operations**: Investigation jobs need explicit lifecycle and failure visibility so operators know what is enriched versus still pending
- **Performance**: Added enrichment cannot erase the fast-detection proof point — hot-path latency must remain independently measurable

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Move the production runtime to pure Rust | Fast detection and live response are easier to measure, secure, and operate with one runtime | ✓ Good |
| Keep `kernel/` as reference only | The Python tree is useful inspiration but not a viable hot path | ✓ Good |
| Keep `swarm-bridge` as legacy only | PyO3 is unnecessary for the current product direction | ✓ Good |
| Start with a narrow response safety model | Deterministic policy and scoped leases proved the basic live-response boundary without fake distributed consensus | ✓ Good |
| Copy focused upstream code into `vendor/reference/` | Local references reduced upstream dependency risk while preserving freedom to refactor inward | ✓ Good |
| Tackle durability before async investigation | The shipped lane needed restart safety and operator visibility before more reasoning features | ✓ Good |
| Use a repo-owned local journal as the first durable substrate target | Keeps the milestone self-contained and testable without a hard external dependency | ✓ Good |
| Make operator visibility API-first | A serializable Rust status report can back later CLI or HTTP surfaces without rework | ✓ Good |
| Keep investigation asynchronous | Enrichment should improve operator trust and triage without blocking detection or response | ✓ Chosen |
| Build correlation from durable findings and receipts | The runtime now has enough stable artifacts to group and explain related detections | ✓ Chosen |
| Treat correlated incidents as operator context first | Correlation should sharpen review before it influences automated action policy | ✓ Chosen |
| Seed investigation from replay bundles | Durable hot-path artifacts already carry the identifiers and evidence needed for async review | ✓ Good |
| Persist rejected incident candidates | Correlation stays auditable when rejected inputs remain visible instead of being discarded | ✓ Good |
| Extend operator status instead of forking a new API | One serializable report keeps hot-path and async review data aligned for future tooling | ✓ Good |

---
*Last updated: 2026-04-03 after shipping v1.2*
