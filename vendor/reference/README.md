# Vendor Reference Snapshot

This directory contains temporary reference copies from neighboring repos. The purpose is inspiration and local refactoring support, not active dependency management.

## Why This Exists

Swarm Team Six is moving toward a self-contained Rust-first runtime. To make that feasible without depending on adjacent repositories during day-to-day development, selected upstream source trees have been copied in for short-term reference.

These copies are:

- not the source of truth
- not wired into the build
- expected to diverge as STS is refactored

## Provenance

Imported on 2026-04-02 from:

- `../clawdstrike` @ `b69fb2727ff4aa32fbbe6485581336baed011ce9`
- `../hellcat` @ `3ace7f0f65328c4470fa30d958c77f824134dfb7`
- `../../platform/kernel` @ `1728a019258cccf2e7d4c8a5a318890802a08949`

## Included Reference Trees

### ClawdStrike

- `clawdstrike/hush-core/`
- `clawdstrike/spine/`
- `clawdstrike/guards/`
- `clawdstrike/posture.rs`

These are here to inform:

- signing and receipt design
- Merkle and envelope plumbing
- static guard composition
- posture and policy concepts

### Hellcat

- `hellcat/core/`
- `hellcat/operators/`

These are here to inform:

- replay and benchmark harness structure
- planner and operator organization
- audit and reporting concepts

### Cyntra

- `cyntra/core/`

These are here to inform:

- orchestration patterns
- runtime status and escalation concepts
- routing and response-analysis ideas

## Working Rule

If STS adopts logic from these references, the preferred next step is:

1. port or rewrite into active Rust crates
2. add tests in STS
3. stop consulting the copied reference for that area

This directory should shrink over time, not grow without bound.
