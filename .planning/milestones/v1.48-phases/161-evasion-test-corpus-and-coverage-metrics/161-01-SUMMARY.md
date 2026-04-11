# Phase 161 Plan 01 Summary

## Delivered

- Added a repo-owned evasion benchmark under `scenario-suites/evasion-breadth-v1.yaml` with new adversarial scenarios covering execution, defense evasion, command and control, data exfiltration, lateral movement, credential access, and persistence.
- Added `rulesets/evasion/attack-technique-catalog.yaml` so every supported detector can document intentionally uncovered ATT&CK techniques with explicit rationale instead of leaving gaps implicit.
- Extended `crates/swarm-runtime/src/replay/core.inc` so replay scenario metadata can carry an explicit `threat_class`, which keeps the evasion corpus deterministic and avoids fragile payload-only inference.
- Implemented `crates/swarm-runtime/src/evasion_coverage.rs`, which loads the repo-owned suite, evaluates every supported detector through the runtime detector factory, and emits one typed `EvasionCoverageSnapshot`.
- Extended `crates/swarm-runtime/src/detection/metrics.rs` and `crates/swarm-runtime/src/ingest.rs` so the same coverage snapshot now drives `/api/v1/evasion/coverage`, `/v2/api/evasion/coverage`, and Prometheus `swarm_evasion_*` gauges.
- Hardened repo-root discovery for the coverage path so mounted configs outside the repo tree still resolve the checked-in evasion suite and catalog through ancestor plus current-working-directory search.

## Notes

- Phase 161 stayed bounded to the benchmark, API, and metrics surface.
- Feeding the measured gaps back into Kitten mutation remains Phase 162.
