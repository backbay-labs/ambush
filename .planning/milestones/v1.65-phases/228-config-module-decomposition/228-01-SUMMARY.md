---
phase: 228-config-module-decomposition
plan: 01
subsystem: config
tags: [config, refactor, serde, validation]
requirements-completed: [CFGEXT-01]
one-liner: "The former 6009-line `swarm-core/src/config.rs` monolith is now a focused `config/` module tree while preserving the stable `swarm_core::config` API."
completed: 2026-04-13
---

# Phase 228 Plan 01 Summary

**The former 6009-line `swarm-core/src/config.rs` monolith is now a focused `config/` module tree while preserving the stable `swarm_core::config` API.**

## Accomplishments

- Replaced `crates/swarm-core/src/config.rs` with `crates/swarm-core/src/config/mod.rs` plus focused domain modules for runtime, bridges, pheromone or policy, response delivery, storage, rollout, evolution, state, operator, defaults, validation helpers, and tests.
- Preserved the existing `swarm_core::config::{...}` contract by keeping the root module path stable and re-exporting the shipped config types from the new module tree.
- Split defaults, validation helpers, semantic validation, and config tests into dedicated files so the boundary is easier to navigate than the original monolith without changing serde-default or validation behavior.
- Brought every extracted config source file under the roadmap size ceiling; the largest implementation file is `validation.rs` at `692` lines and the largest overall file is `tests.rs` at `1341` lines.

## Files Created Or Modified

- `crates/swarm-core/src/config/mod.rs`
- `crates/swarm-core/src/config/root.rs`
- `crates/swarm-core/src/config/runtime.rs`
- `crates/swarm-core/src/config/bridges.rs`
- `crates/swarm-core/src/config/detection.rs`
- `crates/swarm-core/src/config/pheromone.rs`
- `crates/swarm-core/src/config/policy.rs`
- `crates/swarm-core/src/config/response.rs`
- `crates/swarm-core/src/config/storage.rs`
- `crates/swarm-core/src/config/rollout.rs`
- `crates/swarm-core/src/config/evolution.rs`
- `crates/swarm-core/src/config/state.rs`
- `crates/swarm-core/src/config/operator.rs`
- `crates/swarm-core/src/config/defaults.rs`
- `crates/swarm-core/src/config/helpers.rs`
- `crates/swarm-core/src/config/validation.rs`
- `crates/swarm-core/src/config/tests.rs`
- `crates/swarm-core/src/config.rs`

## Verification

- `cargo fmt --all`
- `cargo check -p swarm-core`
- `cargo test -p swarm-core --lib config::`
- `cargo check -p swarm-runtime`
- `wc -l crates/swarm-core/src/config/*.rs | sort -n`

## Notes

- The split intentionally stayed inside `swarm-core` rather than extracting a new crate, which keeps Phase 228 scoped to decomposition and leaves rebuild-boundary proof to Phase 229.
- The downstream `swarm-runtime` compile acts as the compatibility check that the public `swarm_core::config` surface still resolves for existing consumers.
