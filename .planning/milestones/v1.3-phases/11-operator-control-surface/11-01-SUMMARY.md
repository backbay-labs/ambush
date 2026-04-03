---
phase: 11-operator-control-surface
plan: 01
subsystem: operators
tags:
  - cli
  - control
  - lookup
  - status
one-liner: A new `swarmctl` CLI now exposes runtime status plus stable-ID lookup for replay bundles, investigation bundles, and incidents.
requires:
  - 07-operator-visibility
  - 10-operator-review-surfaces
provides:
  - Repo-owned operator CLI entrypoint
  - Stable-ID artifact lookup through configured runtime stores
  - Origin-labeled control output for runtime status and persisted artifacts
affects: []
tech-stack:
  added:
    - clap
  patterns:
    - thin CLI over config-backed runtime composition
    - origin-labeled control envelopes for operator-facing output
key-files:
  created:
    - crates/swarm-runtime/src/control.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
  modified:
    - crates/swarm-runtime/Cargo.toml
    - crates/swarm-runtime/src/lib.rs
    - crates/swarm-runtime/src/service.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "The control surface stays CLI-first and read-only for this milestone."
  - "Runtime status and persisted artifacts use explicit origin labels so replay results can be added later without ambiguity."
patterns-established:
  - "Operator-facing CLI commands should delegate to reusable runtime control handlers rather than implement store logic directly in the binary."
requirements-completed:
  - OPS-01
  - OPS-02
  - OPS-03
duration: 45min
completed: 2026-04-03
---

# Phase 11: Operator Control Surface Summary

**The repo now ships a `swarmctl` CLI that can show operator status and retrieve replay, investigation, and incident artifacts by stable IDs from repo-owned config.**

## Performance

- **Duration:** 45 min
- **Started:** 2026-04-03T14:47:00Z
- **Completed:** 2026-04-03T15:32:34Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- Added `crates/swarm-runtime/src/control.rs` with reusable control-plane handlers, origin-labeled envelopes, artifact views, and concise human-readable rendering.
- Added `crates/swarm-runtime/src/bin/swarmctl.rs` as a repo-owned CLI for `status`, `replay`, `investigation`, and `incident` lookups.
- Extended `RuntimeService` and `ConfiguredRuntimeStack` with the stable-ID helpers needed for bundle, investigation, and incident retrieval.
- Added focused runtime tests that exercise live status output, stable-ID lookups, JSON serialization, and origin labeling.
- Documented CLI usage and origin semantics in `docs/CONFIGURATION.md`.

## Decisions Made

- The CLI remains read-only in this phase; it is for visibility and lookup, not mutation.
- `ConfiguredRuntimeStack` is the composition seam for operator control so the CLI stays aligned with repo-owned config.
- Origin labels are explicit now to preserve a clean boundary between runtime artifacts and future offline replay output.

## Deviations from Plan

None.

## Issues Encountered

Clippy rejected a large top-level output enum, so the final control output uses boxed variants to keep the binary surface efficient without changing the JSON schema.

## User Setup Required

Run the CLI with a repo-owned config file, for example:

```bash
cargo run -p swarm-runtime --bin swarmctl -- status --config rulesets/default.yaml
```

Durable artifact lookups require the configured stores to point at local file backends with existing data.

## Next Phase Readiness

The operator control seam is now in place. Phase 12 can reuse the same CLI and origin-label pattern for offline replay runs and durable replay result bundles.

---
*Phase: 11-operator-control-surface*
*Completed: 2026-04-03*
