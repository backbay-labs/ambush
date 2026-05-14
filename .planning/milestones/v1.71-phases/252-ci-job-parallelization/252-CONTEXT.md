# Phase 252 Context

## Goal

Split the repo CI pipeline into bounded parallel jobs with shared cache reuse and a readable green/red signal instead of one serialized workflow.

## Starting Point

- The repo CI surface was effectively monolithic, which hid the failing seam and forced every change through one long serial path.
- Workspace verification still needed fixture and signer cleanup before a dedicated CI test lane could be treated as stable proof.
- Release hardening already existed as a local proof script, but the main CI workflow did not expose it as a first-class job.

## Constraints

- The repo already carries broad workspace test coverage, so the CI split needed to preserve one authoritative success signal instead of fragmenting responsibility.
- Shared artifact reuse mattered because `swarm-runtime` sits on the hot path for most workspace builds.
- The serialized workspace test lane was acceptable if it was the only stable way to avoid suite-order interference.
