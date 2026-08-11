# Phase 245 Plan 01 Summary

## Delivered

- Extended [crates/swarm-whisker/src/command_line.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-whisker/src/command_line.rs) with bounded homoglyph folding, fullwidth ASCII normalization, PowerShell-style encoded-argument decoding, and `FromBase64String(...)` literal decoding.
- Kept the extended normalization on the shared detector seam, so the existing command-line detector families now see folded and decoded `match_text` without taking a second code path.
- Added focused tests proving decoded `IEX` payloads and confusable/fullwidth flags are visible to `fileless_execution`, `suspicious_scripting`, `lateral_movement`, `supply_chain`, and the suspicious process-tree severity heuristics.

## Notes

- The Unicode map is intentionally bounded to common confusables and punctuation forms that matter for the shipped detector heuristics.
- Encoded payloads are surfaced as decoded evidence segments rather than replacing the raw command line, which keeps the seam explainable for later review and measurement.
