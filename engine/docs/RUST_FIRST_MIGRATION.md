# Rust-First Migration

This document records the current repo transition.

## Decisions

- the production runtime direction is pure Rust
- the Python tree under `kernel/` is reference material, not the target runtime
- `swarm-bridge` is legacy and transitional
- distributed consensus is deferred until the single-node live-response path is real
- upstream sibling repos are being copied into `vendor/reference/` for temporary inspiration

## What Changed

- top-level docs now describe a Rust-first runtime
- new Rust scaffolding crates exist for policy, response, and runtime
- the roadmap is reset around fast detection and narrow live response

## What Did Not Change

- upstream-inspired security and audit concepts still matter
- pheromone coordination is still a useful abstraction
- the repo still contains archived Python material for reference

## Short-Term Engineering Rule

When choosing between:

- more architecture
- more agent modeling
- more Python bridging
- or a smaller Rust vertical slice

choose the smaller Rust vertical slice.
