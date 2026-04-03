# Swarm Team Six

## What This Is

Swarm Team Six is a Rust-first threat detection and controlled live-response runtime for operators who need to act within the response window. The shipped slice can already detect suspicious behavior, evaluate narrow response actions through deterministic policy, survive restart with durable local storage, and emit replayable audit artifacts. The next milestone is about adding slower investigation and correlation capabilities without contaminating the proven hot path.

## Core Value

Detect real threats quickly enough to take safe action before the window to respond closes.

## Current Milestone: v1.2 Async Investigation And Correlation

**Goal:** Add async investigation and incident correlation on top of the durable runtime while keeping fast detection and live response deterministic.

**Target features:**
- async investigation jobs that run off the hot path and attach evidence to prior findings
- correlation logic that groups related findings into higher-confidence incident narratives
- operator review surfaces that show enrichment status, summaries, and incident-level context

## Requirements

### Validated

- ✓ Operator can run a pure-Rust detect -> authorize -> execute slice with repository-owned config and explicit runtime modes — v1.0
- ✓ Runtime can evaluate a concrete detector, deposit to an in-memory substrate, and publish benchmarked hot-path latency — v1.0
- ✓ Runtime can gate live response through deterministic policy, scoped leases, sandboxed execution, and normalized receipts — v1.0
- ✓ Runtime can emit auditable replay bundles and cover the critical path with integration tests — v1.0
- ✓ Operator can switch between in-memory and local-journal substrate backends and require durable live response at runtime boundaries — v1.1
- ✓ Operator can persist replay bundles to a configured store and reload them by hunt or receipt ID after restart — v1.1
- ✓ Operator can inspect one status surface with stage metrics, component readiness, and recent decision correlation — v1.1

### Active

- v1.2 requirements are being defined for async investigation, correlation, and operator review surfaces

### Out of Scope

- Async investigation on the hot path — enrichment must not weaken the fast-detection proof point
- Distributed governance / quorum approvals — still premature without independent nodes and trust boundaries
- Gossip membership / CRDT state sharing — not justified for the current single-node operating model
- Python runtime resurrection or PyO3 expansion — conflicts with the Rust-first critical lane
- Live evolution / red-team loops — still better treated as offline evaluation work

## Context

v1.0 shipped the first trusted Rust vertical slice: config loading, detection, in-memory pheromone substrate, deterministic policy, sandboxed response execution, and replayable audit artifacts. v1.1 hardened that slice with local durability, persistent replay storage, and operator status/metrics surfaces.

The canonical product roadmap in `docs/ROADMAP.md` sequences the next step as "Async Investigation And Correlation". That is the right move now that the runtime can preserve artifacts across restart: use those durable findings and receipts as inputs to slower enrichment, then aggregate related findings into operator-readable incidents. This milestone stays narrow by keeping enrichment asynchronous and deferring multi-node governance or offline evolution labs.

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

---
*Last updated: 2026-04-03 after starting milestone v1.2*
