---
phase: 115-persistence-and-supply-chain-integration-proof
plan: 02
subsystem: docs-and-planning
tags: [docs, configuration, verification, planning]
requirements-completed: [PERSIST-05]
one-liner: "Operator docs, default config examples, and milestone evidence now describe the new detector families and close `v1.37` cleanly."
completed: 2026-04-07
---

# Phase 115 Plan 02 Summary

**Operator docs, default config examples, and milestone evidence now describe the new detector families and close `v1.37` cleanly.**

## Accomplishments

- Updated the default ruleset comment and configuration docs to advertise the new `persistence` and `supply_chain` strategies.
- Documented the new `registry_persistence` and `file_persistence` generic JSON payload mappings in the operator config reference.
- Updated the README runtime summary so the repo’s top-level description reflects the expanded detector slice.
- Wrote phase summaries, verification reports, and milestone audit artifacts for the full `v1.37` closeout.
- Closed the live planning state and prepared the repo for the next queued milestone.

## Files Created Or Modified

- `docs/CONFIGURATION.md`
- `rulesets/default.yaml`
- `README.md`
- `.planning/ROADMAP.md`
- `.planning/STATE.md`
- `.planning/REQUIREMENTS.md`
- `.planning/MILESTONES.md`
- `.planning/PROJECT.md`

## Verification

- `cargo fmt --all`
- `cargo test --workspace`
- `cargo clippy --workspace --tests -- -D warnings`
- `cargo build --workspace`

## Notes

- The live docs now describe only the shipped strategy surface; future detector families remain queued instead of being implied as already available.
