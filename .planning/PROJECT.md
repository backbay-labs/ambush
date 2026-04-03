# Swarm Team Six

## What This Is

Swarm Team Six is a Rust-first threat detection and controlled live-response runtime for operators who need to act within the response window. The shipped slice can already detect suspicious behavior, evaluate narrow response actions through deterministic policy, and emit replayable audit artifacts. The next milestone is about making that slice durable and operator-usable under restart and real infrastructure conditions.

## Core Value

Detect real threats quickly enough to take safe action before the window to respond closes.

## Current Milestone: v1.1 Durability And Operators

**Goal:** Make the shipped single-node Rust lane durable and operator-usable without expanding the architecture prematurely.

**Target features:**
- persistent pheromone substrate with restart recovery
- persisted receipt and replay storage with lookup by stable identifiers
- operator-facing status, metrics, and correlation surfaces for the live-response lane

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

(None currently — milestone complete)

### Out of Scope

- Async investigation and correlation on the hot path — useful next, but not before durability and operator usability are real
- Distributed governance / quorum approvals — still premature without independent nodes and trust boundaries
- Gossip membership / CRDT state sharing — not justified for the current single-node milestone
- Python runtime resurrection or PyO3 expansion — conflicts with the Rust-first critical lane
- Live evolution / red-team loops — offline evaluation work, not current production scope

## Context

v1.0 shipped the first trusted Rust vertical slice: config loading, detection, in-memory pheromone substrate, deterministic policy, sandboxed response execution, and replayable audit artifacts. The next practical gap is not new intelligence logic but operational durability: the current substrate is in-memory, replay persistence is file-local, and operator visibility is still closer to test scaffolding than day-two operations.

The canonical product roadmap in `docs/ROADMAP.md` already sequences this next step as "Durability And Operators". This milestone stays narrow: make the existing slice survive restarts, expose its state clearly, and avoid mixing in slower async investigation or distributed coordination work.

## Constraints

- **Tech stack**: Production runtime remains pure Rust — keep one operational path and one type system
- **Security**: Live response cannot bypass deterministic policy or auditable receipts — durability must strengthen, not weaken, safety boundaries
- **Architecture**: This milestone stays single-node — avoid BFT, gossip, or multi-authority work
- **Operations**: Durable mode must degrade predictably — operators need explicit readiness and failure signals
- **Performance**: Added persistence and observability cannot erase the fast-detection proof point — measure the new costs

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

---
*Last updated: 2026-04-03 after completing milestone v1.1*
