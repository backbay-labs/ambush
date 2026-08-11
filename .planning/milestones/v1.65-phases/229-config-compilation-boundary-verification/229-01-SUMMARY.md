---
phase: 229-config-compilation-boundary-verification
plan: 01
subsystem: build
tags: [build, config, cargo, verification]
requirements-completed: [CFGEXT-02]
one-liner: "Touching `config/policy.rs` rebuilt 14 of 15 workspace crates, exactly matching the `swarm-core` reverse dependency set and leaving only `swarm-crypto` untouched."
completed: 2026-04-13
---

# Phase 229 Plan 01 Summary

**Touching `config/policy.rs` rebuilt 14 of 15 workspace crates, exactly matching the `swarm-core` reverse dependency set and leaving only `swarm-crypto` untouched.**

## Accomplishments

- Added `tools/measure-config-rebuild-scope.sh` as a repo-owned measurement command that warms the workspace, touches a representative config module, reruns a workspace check, and captures the rebuilt crate set.
- Measured the rebuild fanout after touching `crates/swarm-core/src/config/policy.rs` and confirmed that the rebuilt crate set is exactly the `swarm-core` reverse dependency graph rather than the full workspace.
- Recorded the remaining breadth explicitly: `swarm-core` changes still fan out to `14` workspace crates because the config surface remains inside the shared `swarm-core` crate, not because `config.rs` was still monolithic.
- Established the unaffected boundary too: `swarm-crypto` is the only local crate left untouched by the config-only edit, which gives future config-crate extraction work a clear before-state baseline.

## Files Created Or Modified

- `tools/measure-config-rebuild-scope.sh`
- `.planning/phases/229-config-compilation-boundary-verification/229-CONTEXT.md`
- `.planning/phases/229-config-compilation-boundary-verification/229-01-PLAN.md`

## Verification

- `cargo tree --workspace --invert swarm-core --depth 2`
- `cargo metadata --format-version 1 --no-deps | jq -r '[.packages[] | select(.source == null) | .name] | unique | sort | .[]'`
- `tools/measure-config-rebuild-scope.sh`
- `rg -o '^\s*(Checking|Compiling) ([^ ]+)' target/config-rebuild-scope.log -r '$2' | rg '^swarm-' | sort -u`

## Notes

- Phase 229 proves the current rebuild boundary, but it does not reduce the fanout further; that remaining work would require extracting config into a narrower crate boundary rather than continuing to split files inside `swarm-core`.
- The measured rebuild set is: `swarm-core`, `swarm-policy`, `swarm-whisker`, `swarm-response`, `swarm-guard`, `swarm-ingest-tetragon`, `swarm-spine`, `swarm-pheromone`, `swarm-ingest-json`, `swarm-consensus`, `swarm-ingest-sentinel`, `swarm-runtime`, `swarm-evolution`, and `swarm-cli`.
