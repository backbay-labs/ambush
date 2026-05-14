# Phase 247 Plan 01 Summary

## Delivered

- Added benign normalization controls in [scenarios/command-line-deobfuscation-benign.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/scenarios/command-line-deobfuscation-benign.yaml) and kept them in the shared [command-line-deobfuscation-v1.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/scenario-suites/command-line-deobfuscation-v1.yaml) suite.
- Extended [crates/swarm-runtime/src/evasion_coverage.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/evasion_coverage.rs) with a false-positive regression helper that compares normalization-disabled and normalization-enabled configs across the full command-line detector family.
- Added a focused runtime regression proof showing the benign controls remain zero-false-positive with normalization enabled.

## Notes

- The benign proof intentionally measures the full command-line detector family, not just the two benchmark lanes, because the normalization seam was wired into more than one detector.
- The milestone can now close with one bounded statement: command-line normalization improves adversarial catch rate on the targeted lanes without increasing benign false positives.
