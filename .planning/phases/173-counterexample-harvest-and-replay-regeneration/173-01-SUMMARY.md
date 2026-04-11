# Phase 173 Plan 01 Summary

## Delivered

- Added repo-owned harvest controls in [crates/swarm-core/src/config.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-core/src/config.rs) and [rulesets/default.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/rulesets/default.yaml) so assurance-case persistence uses a bounded results directory, per-proposal case cap, and per-case event cap instead of ad hoc paths.
- Extended the verified evolution queue in [crates/swarm-evolution/src/evolution.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-evolution/src/evolution.rs) so blocked proposals now persist durable assurance-case reports plus replay-ready scenario manifests, and the proposal assurance summary records the harvested case ids alongside the original coverage and solver decision.
- Implemented two deterministic harvest modes in [crates/swarm-evolution/src/evolution.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-evolution/src/evolution.rs): coverage-floor failures regenerate trimmed event-based replay scenarios from the repo-owned evasion suite, while solver counterexamples regenerate replay-bundle manifests tied back to the persisted verification bundle and proof artifact.
- Fed harvested evidence back into mutation ranking in [crates/swarm-evolution/src/mutation.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-evolution/src/mutation.rs) by attaching assurance-case counts and ids to ranked candidates and review packets, penalizing unresolved harvested gaps in ranking score, and surfacing that lineage in candidate summaries and rendered ranking output.
- Updated the shared evolution status test harness in [crates/swarm-runtime/src/evolution_status.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/evolution_status.rs) so the durable proposal and ranking fixtures remain compatible with the new assurance-case fields.

## Notes

- Coverage-gap harvesting now runs only when the coverage floor itself failed; solver-only assurance failures no longer emit unrelated coverage cases just because actionable gaps exist elsewhere in the measured corpus.
- Solver counterexample harvesting is driven from the formal safety gate proof path, not the lightweight verification-attestation proof helper, because only the formal gate persists solver artifacts and machine-readable counterexamples.
- Phase 173 stays harvest-focused: it does not yet fail closed on queue, canary, or promotion transitions, and it does not yet add operator waivers or surfaced assurance lineage beyond the harvested case ids already attached to proposals and rankings.
