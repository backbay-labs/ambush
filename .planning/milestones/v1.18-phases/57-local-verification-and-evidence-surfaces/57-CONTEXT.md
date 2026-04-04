# Phase 57 Context

## Goal

Verify signed evidence bundles locally and expose verification summaries through the authenticated operator surface.

## Inputs

- Phase 56 adds a file-backed signed evidence store and stable subject metadata for runtime and rollout artifacts.
- The local operator surface already exposes authenticated read-only endpoints for runtime, portfolio, and maintenance artifacts.
- `swarmctl` is the canonical repo-owned operator entry point and should remain the first-class reload path for verification results.

## Constraints

- Verification must fail closed on canonical-payload drift, digest mismatch, signature mismatch, or unexpected signer key IDs.
- Read endpoints should reuse persisted evidence stores instead of reloading raw source artifacts or re-running signature generation.
- Keep the operator surface local and authenticated; do not widen into multi-user auth or remote evidence exchange.
