# Phase 201 Verification

status: passed

## Result

Phase 201 verification passed.

## Commands

- `cargo fmt --all`
- `cargo test -p swarm-runtime sequence_detector_emits_ -- --nocapture`

## Verified Behaviors

- The repo-owned kill-chain rule pack loads successfully and validates the
  required ATT&CK metadata, step matchers, and bounded span settings.
- The sequence detector emits a partial finding when the matched prefix has
  only reached the intermediate stage and upgrades to a full finding when the
  terminal event arrives.
- The detector continues to evaluate against the shared runtime-owned temporal
  window rather than allocating its own parallel event history.
