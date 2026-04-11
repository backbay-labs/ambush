# Phase 172 Plan 01 Summary

## Delivered

- Added a repo-owned `evolution.assurance` policy in [crates/swarm-core/src/config.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-core/src/config.rs) and [rulesets/default.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/rulesets/default.yaml) covering solver-summary requirements, allowed solver outcomes, a global evasion catch-rate floor, and per-detector overrides.
- Extended the verified evolution queue in [crates/swarm-evolution/src/evolution.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-evolution/src/evolution.rs) so proposal creation now evaluates one shared assurance decision from repo-owned evasion coverage and persisted solver proof status, emits explicit assurance blocking reasons, and persists durable assurance summaries on proposal artifacts.
- Added a detector-family mapping seam so assurance evaluates against the underlying detector type instead of the mutable strategy id, which keeps proposal gating aligned with the repo-owned evasion corpus.
- Surfaced the latest assurance decision through [crates/swarm-runtime/src/evolution_status.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/evolution_status.rs), including the latest proposal id, decision, coverage floor versus actual rate, blocked assurance checks, and solver status.
- Updated supporting proposal construction sites in [crates/swarm-evolution/src/selection.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-evolution/src/selection.rs) and [crates/swarm-evolution/src/drafting.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-evolution/src/drafting.rs) so the new assurance field remains backward-compatible and additive across the current review pipeline.

## Notes

- The default runtime assurance floor remains meaningful in repo config, but the evolution unit-test helper now zeroes that floor so legacy queue tests only opt into assurance gating when they are explicitly testing it.
- Phase 172 stays policy-focused: it does not yet harvest replay cases from assurance failures and it does not yet enforce the same decision across canary or promotion entry.
