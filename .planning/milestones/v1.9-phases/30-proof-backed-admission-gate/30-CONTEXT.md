# Phase 30 Context

## Goal

Attach proof-backed safety artifacts to queued proposals and fail closed when required evidence is missing or inconsistent.

## Current Repo State

- Verification artifacts already persist invariant verdicts and counterexamples in `crates/swarm-runtime/src/replay.rs`.
- Advisory scorecards already bind rollout memory and replay evidence to candidate strategies.
- There is no proof artifact or queue admission gate yet.

## Constraints

- Admission checks must remain off the hot path.
- Missing or mismatched proof, verification, or lineage metadata must not produce a reviewable pending proposal.
- Blocked queue entries still need durable denial reasons for operator inspection.

## Implementation Notes

- Create a repo-owned proof artifact bound to experiment and verification digests.
- Make queue creation persist blocked proposals when proof admission fails.
- Keep proof and proposal identity stable and reloadable.
