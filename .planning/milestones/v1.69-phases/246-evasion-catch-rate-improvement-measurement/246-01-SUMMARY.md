# Phase 246 Plan 01 Summary

## Delivered

- Added a repo-owned normalization corpus in [scenario-suites/command-line-deobfuscation-v1.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/scenario-suites/command-line-deobfuscation-v1.yaml) with tracked execution and defense-evasion scenarios plus a matching catalog in [rulesets/evasion/command-line-deobfuscation-catalog.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/rulesets/evasion/command-line-deobfuscation-catalog.yaml).
- Extended [crates/swarm-runtime/src/evasion_coverage.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/evasion_coverage.rs) with baseline-vs-normalized benchmark helpers that derive both configs from the same runtime settings by toggling only `command_line_normalization`.
- Added a focused benchmark proof showing the targeted detector lanes improve beyond the 15% requirement on the repo-owned command-line deobfuscation corpus.

## Notes

- The measured comparison is intentionally narrow: `suspicious_scripting` on execution scenarios and `fileless_execution` on defense-evasion scenarios are the milestone’s required proof lanes.
- The benchmark helper still disables normalization across the broader command-line detector family so later work can compare additional lanes without adding more one-off harnesses.
