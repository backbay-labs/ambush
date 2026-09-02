# Phase 285 Context: Assurance Foundation Closure

## Decision

Phase 285 is complete under a revised, truthful scope. The useful assurance foundation is local combined-tree evidence plus fresh hosted Linux evidence. Provenance-distinct external GitHub App and repository protected-required-check enforcement is explicitly deferred and is not represented as passed.

## In scope

- Preserve the assumption registry, invariant mapping, negative-registry, fixture-freshness, and supply-chain/SBOM evidence.
- Bind SBOM component and dependency edges to locked `cargo metadata` resolution and keep the negative controls.
- Retain fresh, credential-free hosted evidence with commit-bound machine-readable results.
- Report `wired`, `executed`, `passed`, and `protected-required` as separate states.
- Review the combined integration tree and leave no unresolved P0, P1, or P2 finding in the scoped packet.

## Explicit boundary

The phase does not claim a protected GitHub App check, protected-branch enforcement, distributed failover, or release authorization. Local scripts and workflow wiring are useful assurance evidence, but they are not provenance-distinct repository protection by themselves.

## Evidence handoff

`285-VERIFICATION.md` is the phase status artifact. Later phases may consume its evidence contracts, but must not reopen external App enforcement or reclassify the deferred boundary as an active blocker.

