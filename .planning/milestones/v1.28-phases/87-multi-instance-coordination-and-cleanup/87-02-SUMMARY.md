---
phase: 87-multi-instance-coordination-and-cleanup
plan: 02
subsystem: repo
tags: [cleanup, docs, legacy, rust-first]
requirements-completed: [CLEAN-01]
one-liner: "the legacy Python/PyO3 bridge surface was removed from the live repo and the canonical docs now match the Rust-only workspace layout."
completed: 2026-04-05
---

# Phase 87 Plan 02 Summary

**the legacy Python/PyO3 bridge surface was removed from the live repo and the canonical docs now match the Rust-only workspace layout.**

## Accomplishments

- Deleted the dead `crates/swarm-bridge/` PyO3 crate, the legacy `kernel/` Python tree, and `pyproject.toml`.
- Updated canonical repo docs to stop presenting those paths as live workspace artifacts.
- Confirmed the workspace manifest still excludes the removed bridge crate and that the Rust workspace remains healthy after deletion.
- Left historical docs that discuss old Python architecture in place as reference material while updating `docs/REFERENCE-STATUS.md` to state that the live artifacts are gone.

## Files Created Or Modified

- `CLAUDE.md`
- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/REFERENCE-STATUS.md`
- `docs/decisions/0001-rust-first-runtime.md`
- `crates/swarm-bridge/`
- `kernel/`
- `pyproject.toml`

## Verification

- `test ! -d crates/swarm-bridge && test ! -d kernel && test ! -f pyproject.toml`
- `cargo fmt --all -- --check`
- `cargo build --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

## Notes

- Historical documentation still references the removed Python design in non-canonical docs such as `docs/AGENTS.md` and `docs/INTEGRATION.md`; that remaining archival prose is intentional and now explicitly covered by `docs/REFERENCE-STATUS.md`.
