# Swarm Team Six

## What This Is

Swarm Team Six is a Rust-first threat detection and controlled live-response runtime for operators who need to act within the response window. The shipped system can already detect suspicious behavior, evaluate narrow response actions through deterministic policy, survive restart with durable local storage, attach async investigation to persisted replay bundles, assemble explainable incidents, surface the full chain in one operator review report, and now execute offline replay plus regression evaluation over a tracked scenario corpus.

## Core Value

Detect real threats quickly enough to take safe action before the window to respond closes.

## Current Milestone: v1.3 Operator Control And Replay Evaluation (Completed)

**Goal:** Turn the shipped runtime artifacts into operator-facing control and deterministic replay workflows without widening live-response autonomy.

**Delivered features:**
- operator CLI commands for runtime review and artifact lookup
- deterministic offline replay from persisted bundles or fixture corpora
- regression reports and replay gates that protect detection quality and hot-path latency

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

### Recently Completed

- ✓ Operator can inspect runtime status, recent decisions, investigations, and incidents through a repo-owned control surface — v1.3
- ✓ Operator can retrieve replay bundles, investigation bundles, and incidents by stable IDs without reading raw storage files — v1.3
- ✓ Team can run deterministic offline replay from persisted bundles or fixture corpora without executing live response actions — v1.3
- ✓ Team can define replay scenarios with expected outcomes and reproduce them locally or in CI — v1.3
- ✓ Team can generate regression reports and fail when replay behavior or hot-path latency drifts past configured limits — v1.3

### Out of Scope

- Distributed governance / quorum approvals — still premature without independent nodes and trust boundaries
- HTTP or multi-user operator control plane — CLI-first keeps the auth and deployment story narrow for this cycle
- Live policy mutation from replay or evaluation output — replay remains advisory and offline
- Live red-swarm distribution or autonomous detector evolution — still better treated as offline evaluation work
- Python runtime resurrection or PyO3 expansion — conflicts with the Rust-first critical lane

## Context

v1.0 shipped the first trusted Rust vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response execution, and replayable audit artifacts. v1.1 hardened that slice with local durability, persistent replay storage, and operator status or metrics surfaces. v1.2 layered in async investigation, explainable incident assembly, and one operator review report without compromising the hot path.

The runtime remains intentionally single-node and deterministic. Async enrichment is durable and operator-visible, but it still does not mutate live-response policy automatically. `v1.3` completed the operator CLI plus replay and regression loop. The next milestone should either deepen offline red-team or evolution work, or expand operator surfaces, but it no longer needs to reopen the replay contract itself.

## Constraints

- **Tech stack**: Production runtime remains pure Rust — operator control, replay, and evaluation should extend the same operational path and type system
- **Security**: Replay and evaluation must never execute live response actions by default — offline analysis cannot backdoor production actions
- **Architecture**: This milestone stays single-node and composition-friendly — avoid BFT, gossip, or multi-authority work
- **Operations**: Start with a repo-owned CLI surface — do not widen scope to a multi-user HTTP service before the artifact model is proven
- **Performance**: Replay and regression gates must preserve the fast-detection proof point — hot-path latency remains independently measurable

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
| Keep investigation asynchronous | Enrichment should improve operator trust and triage without blocking detection or response | ✓ Good |
| Build correlation from durable findings and receipts | The runtime now has enough stable artifacts to group and explain related detections | ✓ Good |
| Treat correlated incidents as operator context first | Correlation should sharpen review before it influences automated action policy | ✓ Good |
| Seed investigation from replay bundles | Durable hot-path artifacts already carry the identifiers and evidence needed for async review | ✓ Good |
| Persist rejected incident candidates | Correlation stays auditable when rejected inputs remain visible instead of being discarded | ✓ Good |
| Extend operator status instead of forking a new API | One serializable report keeps hot-path and async review data aligned for future tooling | ✓ Good |
| Prioritize replay/evaluation over advanced governance for the next cycle | Governance is explicitly optional in the roadmap, while replay and operator tooling unlock immediate validation value | ✓ Chosen |
| Start with a CLI-backed operator surface | The existing runtime already exposes serializable reports and stores; CLI is the smallest practical control seam | ✓ Chosen |
| Keep replay offline and deterministic | Evaluation should strengthen trust in production behavior without widening the live-response blast radius | ✓ Chosen |

---
*Last updated: 2026-04-03 after completing v1.3*
