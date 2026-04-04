# Phase 56 Context

## Goal

Export persisted runtime and rollout artifacts as signed evidence bundles with canonical payload bytes and receipt-chain context.

## Inputs

- The runtime already persists stable-ID artifacts for replay, investigation, incident, canary, promotion, maintenance, verification, shadow, and promotion review workflows.
- The operator surface and `swarmctl` can already load most of those artifacts by stable ID.
- `swarm-crypto` is still a stub, so this phase must establish a small real signing and hashing baseline instead of layering on more placeholders.

## Constraints

- Reuse the existing stable-ID artifact stores and avoid inventing a second artifact model.
- Keep the signature scheme local and advisory; do not jump ahead to quorum governance or distributed trust.
- Preserve canonical JSON bytes, timestamps, and receipt references inside the signed statement so verification can fail closed later.
