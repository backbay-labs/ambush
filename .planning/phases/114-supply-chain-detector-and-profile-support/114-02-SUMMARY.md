---
phase: 114-supply-chain-detector-and-profile-support
plan: 02
subsystem: detector-tests
tags: [tests, supply-chain, replay, runtime]
requirements-completed: [PERSIST-02]
one-liner: "Supply-chain heuristics now have focused regression coverage, and runtime strategy selection recognizes `supply_chain` everywhere detector families are constructed."
completed: 2026-04-07
---

# Phase 114 Plan 02 Summary

**Supply-chain heuristics now have focused regression coverage, and runtime strategy selection recognizes `supply_chain` everywhere detector families are constructed.**

## Accomplishments

- Added unit coverage for unsigned trusted-path binaries, DLL side-loading, and signed-binary abuse inside `swarm-whisker`.
- Extended runtime strategy smoke coverage so `supported_detector` accepts `strategy: supply_chain` alongside the existing detector families.
- Kept replay, canary, and promotion detector manifests aligned with the new strategy identifier to avoid live-versus-offline drift.

## Files Created Or Modified

- `crates/swarm-whisker/src/supply_chain.rs`
- `crates/swarm-runtime/tests/critical_path_integration.rs`
- `crates/swarm-runtime/src/replay/core.inc`

## Verification

- `cargo test -p swarm-whisker --lib`
- `cargo test -p swarm-runtime --test persistence_supply_chain_integration --test critical_path_integration`

## Notes

- Runtime strategy coverage stays intentionally small and config-driven so the detector family is proven through the same factory path operators will use.
