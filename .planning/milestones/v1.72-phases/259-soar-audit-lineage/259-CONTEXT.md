# Phase 259 Context

## Goal

Persist durable audit lineage from each inbound SOAR verdict through the affected Swarm finding or incident.

## Repo State

- Phase 258 is intended to establish the bounded inbound SOAR verdict surface and connect it to the existing feedback seams.
- The repo already carries durable audit and evidence patterns for operator, runtime, and evolution decisions.
- `SOARSYNC-02` narrows this phase to lineage persistence and visibility rather than widening the sync contract itself.

## Phase Focus

- Attach external analyst identity, source system, verdict metadata, and affected finding or incident references to durable audit records.
- Reuse the existing Swarm audit and evidence patterns instead of creating a parallel SOAR-only lineage store.
- Fail closed on duplicate or incomplete lineage inputs so audit history stays trustworthy.

## Verification Target

- Repo-owned persistence proof for SOAR lineage records tied to the affected Swarm evidence.
- Negative proof for malformed, duplicate, or replayed verdict lineage inputs.
