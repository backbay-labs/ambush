# Phase 258 Context

## Goal

Accept inbound analyst verdicts from supported SOAR systems and route them into Swarm's existing false-positive tracking and evolution-fitness paths.

## Repo State

- The repo already carries analyst feedback and evolution-fitness seams, but it does not yet ingest verdicts from external SOAR systems on one bounded contract.
- `REQUIREMENTS.md` constrains this phase to Splunk SOAR, Sentinel SOAR, and Chronicle SOAR inputs.
- Audit-lineage depth is reserved for Phase 259, so this phase should focus on accepting, normalizing, and applying the verdicts cleanly.

## Phase Focus

- Define one authenticated inbound verdict surface for the supported SOAR sources.
- Normalize external verdict payloads into the existing false-positive and fitness signals instead of inventing a parallel feedback path.
- Preserve the source-system identity needed for the follow-on audit-lineage phase.

## Verification Target

- Repo-owned tests showing inbound SOAR verdicts are accepted, normalized, and applied to the existing feedback surfaces.
- Negative proof that malformed or unsupported verdict inputs fail closed.
