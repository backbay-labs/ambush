# ADR 0001: Rust-First Runtime

## Status

Accepted on 2026-04-02.

## Context

The repo started with a broad Rust/Python split and a near-term roadmap that mixed:

- hot-path detection
- Python orchestration
- BFT governance
- co-evolution
- live response

That architecture was too wide for the first proof point. The product goal is now explicit: **fast detection with safe live response**.

## Decision

STS will adopt a Rust-first production runtime.

### This means

- Rust owns detection, substrate, policy, response, and receipts.
- Python is treated as reference material or experimentation space, not a required runtime dependency.
- Upstream code is copied in for local refactoring instead of relied on through long-lived relative dependency assumptions.
- BFT, gossip, and live red-swarm work are deferred until after a working vertical slice exists.

## Consequences

### Positive

- simpler runtime boundary
- one type system on the critical path
- cleaner latency measurements
- simpler deployment and testing
- clearer ownership of live-response safety

### Negative

- more porting work up front
- some prior Python design work becomes archival rather than directly reusable
- existing docs must be rewritten to avoid describing the wrong system

## Follow-On Work

- keep `vendor/reference/` current enough to support local porting
- keep legacy Python/PyO3 material out of the live runtime surface now that it has been removed
- build one benchmarked end-to-end Rust slice before revisiting distributed governance
