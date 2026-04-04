# Phase 53 Context

## Goal

Define a local authenticated HTTP control-plane boundary that reuses existing runtime and artifact types instead of forking a second operator model.

## Inputs

- `DefaultControlPlane` already exposes serializable status and stable-ID artifact lookups.
- `swarmctl` already carries repo-owned config plus results-dir globals for the surrounding runtime and evolution lanes.
- The repo does not yet ship any HTTP stack or operator-surface auth model.

## Constraints

- Keep the surface local-only and fail closed when auth material is missing or invalid.
- Reuse existing status and artifact envelope types wherever possible instead of inventing a second operator schema.
- Do not widen into multi-user RBAC, remote deployment, or quorum governance.
