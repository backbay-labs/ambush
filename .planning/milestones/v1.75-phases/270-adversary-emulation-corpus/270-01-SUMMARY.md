# Phase 270 Plan 01 Summary

## Delivered

- Extended `crates/swarm-runtime/src/evasion_coverage.rs` with a repo-owned
  adversary-emulation coverage summary that tracks per-scenario catch rates,
  per-technique statuses, and the overall mapped coverage percentage.
- Added `crates/swarm-runtime/src/bin/generate_adversary_emulation_report.rs`
  plus `tools/check-adversary-emulation-coverage.sh` so CI and operators can
  regenerate and enforce the adversary-coverage proof surface.
- Added `crates/swarm-runtime/tests/adversary_emulation_integration.rs` and
  documented the scenario-to-detector mapping in
  `docs/benchmarks/adversary-emulation-coverage.md`.

## Notes

- The mapped corpus currently spans 7 adversarial scenarios and 23 ATT&CK
  techniques, with 100% of mapped techniques landing in either `detected` or
  `partial`.
- Intentional telemetry-bound gaps stay explicit in the repo-owned attack
  technique catalog instead of being silently absorbed into the coverage
  percentage.
