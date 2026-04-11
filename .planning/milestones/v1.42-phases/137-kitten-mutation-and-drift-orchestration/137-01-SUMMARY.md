# Phase 137 Plan 01 Summary

## Delivered

- Added repo-owned `SwarmConfig.evolution` settings and defaults for drift activation, batch sizing, shortlist sizing, and the evolution artifact paths used by the runtime and extracted evolution harnesses.
- Added a runtime-owned `KittenAgent` with a bounded multi-tick state machine (`AwaitingDrift -> Mutating -> Evaluating -> Verifying -> Proposing`) plus a `ConceptDriftDetector` that derives drift from verification, scorecard, and strategy-memory evidence windows.
- Wired Kitten into `swarm_detect --serve` when evolution is enabled and extended dispatcher coverage so `SwarmAction::ProposeStrategy` becomes peer-visible even before Phase 139 owns the real safety-gated canary handoff.
- Reused the extracted drafting, mutation, replay, proof, and scorecard harnesses for the runtime evolution loop instead of introducing a second mutation or validation pipeline.
- Fixed two real evolution blockers uncovered during runtime verification: mutation materialization now preserves the rollout-baseline lineage parent required by replay validation, and mutation ranking ids are short enough to persist safely on macOS filesystems.
- Added focused runtime tests for drift cooldown behavior, direct validation-batch refresh, and end-to-end Kitten proposal emission.

## Notes

- Phase 137 intentionally stops at bounded proposal emission. The dispatcher still treats `ProposeStrategy` as a warning-only action beyond peer visibility because Phase 139 owns the formal safety gate and canary admission path.
- Drift detection is anchored to durable artifacts the repo already owns; it does not invent a fake live ground-truth oracle just to satisfy the trigger contract.
