---
phase: 30-proof-backed-admission-gate
plan: 01
subsystem: evolution-proof
tags:
  - evolution
  - proof
  - verification
  - runtime
one-liner: Added proof-backed safety artifacts and fail-closed admission checks for evolution proposals.
requires:
  - 29-evolution-queue-and-proposal-artifacts
provides:
  - file-backed evolution proof artifacts rooted under `data/evolution-proofs/`
  - deterministic SHA-256 attestation over experiment, verification, and lineage evidence
  - fail-closed proof, verification, and lineage consistency checks during proposal admission
affects: []
tech-stack:
  added:
    - SHA-256 proof attestations using `sha2`
  patterns:
    - proof artifacts are derived only from passed verification evidence
    - blocked admissions persist explicit denial reasons instead of silently rejecting candidates
key-files:
  created:
    - crates/swarm-runtime/src/evolution.rs
  modified:
    - crates/swarm-runtime/Cargo.toml
    - .gitignore
key-decisions:
  - "Use deterministic verification attestation artifacts instead of claiming live external theorem-prover integration."
  - "Treat missing or inconsistent proof evidence as a persisted blocked proposal, not an invisible drop."
  - "Cross-check proof digests against both the experiment manifest and verification artifact before the queue can mark a proposal as proved."
patterns-established:
  - "Proposal admission now has an explicit safety floor: verification -> proof attestation -> queue admission."
requirements-completed:
  - EVOL-01
  - EVOL-03
duration: 30min
completed: 2026-04-03
---

# Phase 30: Proof-Backed Admission Gate Summary

**The runtime now materializes proof artifacts from passed verification evidence and fails queue admission closed when proof, verification, or lineage checks do not line up.**

## Performance

- **Duration:** 30 min
- **Completed:** 2026-04-03T22:31:19Z
- **Tasks:** 4
- **Files modified:** 3

## Accomplishments

- Added `EvolutionProofReport`, `EvolutionProofRecord`, and `FileEvolutionProofStore` to persist proof-backed safety artifacts.
- Implemented `DefaultEvolutionProofHarness::create_proof` to derive deterministic proof attestations from passed verification runs.
- Added proof consistency checks over experiment digest, verification digest, lineage digest, invariant coverage, and corpus identity.
- Persisted blocked queue proposals with explicit denial reasons when proof evidence is missing or inconsistent.

## Decisions Made

- Proof artifacts are generated only from passed verification evidence.
- Attestation uses deterministic digests over repo-owned artifacts rather than a fake runtime dependency on an external verifier.
- Admission failures are recorded as blocked queue artifacts so operators can inspect why the candidate was denied.

## Deviations from Plan

The initial proof system is intentionally named `verification_attestation_v1` and remains repo-owned. That keeps the proof lane truthful to the shipped code while leaving room for stronger external verification later.

## Issues Encountered

The proposal gate needed explicit digest checks for both the experiment manifest and the verification report to avoid letting stale or mismatched evidence appear proved.

## User Setup Required

Inspect the shipped proof workflow docs:

```bash
sed -n '508,548p' docs/CONFIGURATION.md
```

## Next Phase Readiness

Phase 31 can now expose proof-backed queue review and operator decisions through the CLI without inventing its own evidence model.

---
*Phase: 30-proof-backed-admission-gate*
*Completed: 2026-04-03*
