# CLAUDE.md

## Project Overview

Swarm Team Six is a Rust-first autonomous detection and live-response engine. Product name: **ClawdStrike Ambush**.

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

These paths exist for inspiration, not as the production runtime:
- `kernel/` - legacy Python ideas and stubs
- `pyproject.toml` - legacy reference only
- `crates/swarm-bridge` - transitional compatibility shim, not the target runtime seam
- `vendor/reference/` - copied upstream code used for adaptation and design reference

## Upstream Adaptation Strategy

Swarm Team Six is being made self-contained. Useful ideas may be copied and refactored locally from:
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

Legacy Python commands may still be useful for reference material, but they are not part of the current production milestone.

## Conventions

- Commit messages: Conventional Commits when practical
- Clippy: `-D warnings`
- Rust edition: 2024
- Repository-owned config lives under `rulesets/`
- Runtime mode must be explicit: `detect_only` or `live_response`
- Live response must fail closed on malformed or weak requests
- Handled events should produce auditable detection, policy, and response records
