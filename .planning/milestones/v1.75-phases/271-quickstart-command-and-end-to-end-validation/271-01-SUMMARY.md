# Phase 271 Plan 01 Summary

## Delivered

- Added `swarmctl quickstart` in `crates/swarm-cli/src/core.inc` as the
  one-command end-to-end operator proof path. It validates config, runs the
  built-in first-run scenario, and prints the resulting finding, elapsed time,
  receipt-pack ID, and proof Merkle root.
- Reduced default `swarmctl` log noise in `crates/swarm-cli/src/tracing.rs` so
  the quickstart report stays readable without runtime `INFO` spam.
- Updated `Dockerfile` so the release builder copies `rulesets/`, which keeps
  the signed bootstrap assets available at compile time for the packaged CLI.
- Fixed the quickstart follow-up guidance so it only suggests incident lookup
  when the active config already has durable incident storage, and corrected the
  bootstrap include-path handling so the Docker release build can still package
  the signed detect-only bundle.

## Notes

- The signed detect-only bootstrap template is intentionally ephemeral for
  incident review. Quickstart therefore treats the printed finding summary as
  the supported first-run inspection surface unless durable storage is already
  configured.
- The Docker build-path fix is part of the quickstart proof because the milestone
  requires the packaged operator path, not only a source-tree cargo run.
