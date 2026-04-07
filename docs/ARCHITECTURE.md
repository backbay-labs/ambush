# Architecture

Canonical architecture for the Rust-first rebuild of Swarm Team Six.

This document supersedes the earlier Python control-plane design as the primary implementation target.

## Executive Summary

STS is no longer being optimized for a broad multi-agent platform as its first milestone. It is being optimized for:

- fast detection
- safe live response
- deterministic policy enforcement
- a self-contained Rust codebase

The system now has two lanes:

- a **critical lane** in Rust for telemetry, detection, policy, response, and receipts
- an **async enrichment lane** for investigation, correlation, and operator context

Only the critical lane is required for the first release.

## Canonical Runtime

```text
telemetry bridges
    |
    v
swarm-whisker
    |
    v
swarm-pheromone
    |
    +--> async investigation/enrichment lane
    |
    v
swarm-policy
    |
    v
swarm-response
    |
    v
swarm-spine + swarm-crypto
```

## Component Roles

### `swarm-whisker`

Owns the hot path.

- consumes telemetry
- applies fast detection strategies
- scores confidence and severity
- emits pheromone deposits and action proposals

No LLMs, no Python, no slow graph work.

### `swarm-pheromone`

Owns stigmergic state.

- stores deposits
- computes concentration
- enforces source diversity
- supports replay and later NATS-backed durability

The first implementation can be in-memory. JetStream is phase-two hardening, not phase-one proof.

### `swarm-policy`

Owns live-response authorization.

- evaluates whether an action may run
- determines whether human approval is required
- mints short-lived capability leases
- fails closed on malformed or weak requests

This replaces the earlier idea of a Python-heavy governance layer on the critical path.

### `swarm-response`

Owns external side effects.

- executes dry-run or live adapters
- scopes execution to an authorization lease
- emits structured response receipts
- remains small and explicit

The first adapter should be sandboxed or mocked.

### `swarm-spine` and `swarm-crypto`

Own the audit trail.

- canonical serialization
- signing and verification
- merkle/checkpoint support
- envelope and receipt plumbing

### `swarm-runtime`

Owns composition.

- wires detector, substrate, policy, and response together
- defines runtime mode (`detect-only` vs `live-response`)
- keeps the first deployable slice small enough to benchmark and test

## Critical Lane vs Async Lane

### Critical lane

Must stay predictable and benchmarkable.

- telemetry ingest
- detection
- pheromone update/query
- policy check
- response execution
- receipt emission

### Async lane

May lag the hot path.

- richer investigation
- evidence summarization
- multi-signal correlation
- operator-facing context
- replay/evaluation

This work may later live in Rust as well, but it is not required for the first safe-response milestone.

## Why Pure Rust

The old Rust/Python split had two structural problems for the new goal:

1. it put the runtime boundary in the middle of the system
2. it made live-response authorization depend on a fragile cross-language contract

Pure Rust fixes the part that matters most now:

- one type system
- one concurrency model
- one packaging story
- simpler testing
- simpler latency measurement

Python is still useful as reference and experimentation space, but it is no longer part of the target runtime architecture.

## Upstream Assimilation Strategy

STS should absorb code from upstreams, not orbit them.

### ClawdStrike

Primary inspiration for:

- guards
- broker/capability ideas
- receipts
- signing
- spine/envelope concepts
- telemetry bridge patterns

### Hellcat

Primary inspiration for:

- operator decomposition
- replay/evaluation loops
- offensive scenario modeling

### Cyntra

Primary inspiration for:

- scheduler ideas
- dispatcher/workcell patterns
- verifier patterns
- memory concepts

Copied reference trees live under `vendor/reference/`. They are temporary and are not active dependencies.

## Deferred Features

These are explicitly out of the first production slice:

- PyO3-first bridging
- Python governance on the hot path
- Tendermint-style BFT
- VRF committee rotation
- SWIM/CRDT gossip
- live red-swarm distribution
- formal-proof driven release gates

They may return later if the Rust-first runtime proves a real need.

## First Vertical Slice

The first milestone is complete only when this works end to end:

1. synthetic telemetry enters the runtime
2. `swarm-whisker` detects a condition
3. `swarm-pheromone` stores the signal
4. `swarm-policy` authorizes or denies action
5. `swarm-response` executes in sandbox or dry-run mode
6. `swarm-spine` and `swarm-crypto` emit a reconstructable receipt chain
7. benchmark results are captured for latency and throughput

## What Is No Longer Canonical

The legacy Python control-plane stubs, `pyproject.toml`, and `swarm-bridge` were removed in `v1.28`.
What remains as non-canonical material is the historical documentation centered on Python agents,
BFT governance, or co-evolution as near-term scope.
