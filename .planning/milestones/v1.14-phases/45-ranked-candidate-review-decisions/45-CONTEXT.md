# Phase 45 Context

## Goal

Add explicit operator review decisions for ranked-candidate selections while keeping the underlying ranking evidence immutable.

## Inputs

- Phase 44 now persists stable ranked-candidate selections from shortlist review packets.
- Operators needed a way to inspect and triage those selections without rewriting the original ranking bundle.
- Later rollout bridging should depend on an explicit accepted review state rather than inferred shortlist position.

## Constraints

- Keep review decisions advisory until a later bridge artifact is created.
- Preserve immutable selection evidence while recording operator reason and current review state.
- Support stable-ID listing and reload through `swarmctl`.
