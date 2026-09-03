# CLAUDE.md

## Project Overview

Ambush is a Rust-first autonomous detection and live-response engine.

The first proof point is narrow and operational:
- ingest telemetry in Rust
- detect in Rust
- store/query pheromones in Rust
- authorize response through a deterministic Rust policy gate
- execute one safe response adapter
- emit replayable audit artifacts

## Canonical Runtime Direction

The production path is the Rust critical lane under `crates/`:
- `swarm-core` - shared domain types and config contracts
- `swarm-whisker` - fast-path telemetry detection
- `swarm-pheromone` - in-memory substrate, later durability boundary
- `swarm-policy` - deterministic response authorization
- `swarm-response` - dry-run and sandboxed execution adapters
- `swarm-runtime` - composition root for the critical lane
- `swarm-spine` / `swarm-crypto` - receipt and audit primitives as they are adapted

## Reference-Only Material

These paths exist for inspiration or archive context, not as the production runtime:
- `vendor/reference/` - copied upstream code used for adaptation and design reference
- `.planning/milestones/` - archived milestone plans, summaries, and audits

## Upstream Adaptation Strategy

Ambush is being made self-contained. Useful ideas may be copied and refactored locally from:
- ClawdStrike - detection, guards, receipts, signing, envelope ideas
- Hellcat - replay and adversarial evaluation ideas
- Cyntra - scheduler and orchestration patterns

Do not treat upstream repos as active runtime dependencies unless the current task explicitly says otherwise.

## Commands

```bash
# Build Rust crates
cargo build --workspace

# Test Rust crates
cargo test --workspace

# Lint
cargo fmt --all
cargo clippy --workspace -- -D warnings
```

Legacy Python commands are no longer part of the live repo surface or current production milestone.

## Conventions

- Commit messages: Conventional Commits when practical
- Clippy: `-D warnings`
- Rust edition: 2024
- Repository-owned config lives under `rulesets/`
- Runtime mode must be explicit: `detect_only` or `live_response`
- Live response must fail closed on malformed or weak requests
- Handled events should produce auditable detection, policy, and response records

## Repository Layout Since 2026-09-02

This repository holds two products that ship as one:

- **The engine** at the root: the Rust crates under `crates/swarm-*`, `rulesets/`,
  `scenarios/`, `tools/`, `deploy/`. Everything in this file above applies to it.
- **The workspace** under `workspace/`: the Ambush relay, desktop, web and mobile
  clients, merged from a fork of block/buzz with history preserved. It is a
  **separate Cargo workspace** with its own toolchain pin, Hermit toolchain
  (`workspace/bin/activate-hermit`), `justfile`, hooks and CI. Read
  `workspace/CLAUDE.md` before touching anything under it, and run its gates
  from that directory (`cd workspace && just ci`).

The integration of the two — the operator console inside the workspace, fed by
the engine over the relay — is planned in `docs/plans/ambush-ui/`; start at
`docs/plans/ambush-ui/integration/README.md`. Cross-workspace dependencies are
allowed only in the directions `docs/plans/ambush-ui/integration/00-DECISIONS.md`
D2 names.
