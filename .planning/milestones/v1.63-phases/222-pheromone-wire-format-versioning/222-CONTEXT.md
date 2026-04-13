# Phase 222: Pheromone Wire Format Versioning - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 222 adds explicit versioning to pheromone deposit wire payloads and
introduces one bounded compatibility path for the current and previous deposit
shape without changing operator-facing API envelopes or broadening the
substrate contract beyond deposit serialization and validation.

</domain>

<decisions>
## Implementation Decisions

- Add the wire version at the shared `PheromoneDeposit` boundary in
  `swarm-core` instead of leaving version knowledge implicit inside one
  substrate implementation.
- Keep signature verification, admission control, and store hydration aligned on
  the same versioned payload contract so migration does not silently bypass the
  existing signed-deposit guarantees.
- Limit compatibility to current-plus-previous deposit versions. Unsupported
  versions must fail closed with explicit errors instead of being coerced.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-core/src/pheromone.rs` currently defines `PheromoneDeposit`
  without an explicit schema version, so the deposit shape is inferred from the
  serialized JSON fields alone.
- `crates/swarm-pheromone/src/substrate.rs` signs and verifies deposits through
  `DepositSigningPayload`, which currently mirrors the unversioned deposit
  fields exactly.
- `crates/swarm-pheromone/src/jetstream.rs` and the substrate test fixtures
  deserialize `PheromoneDeposit` directly from stored JSON, so versioned
  migration has to preserve current storage/read paths and existing signed test
  coverage.

</code_context>

<deferred>
## Deferred Ideas

- Operator/API response schema negotiation remains the separate Phase 223 work.
- Broader historical backfill or long-tail multi-version compatibility is out of
  scope; this phase only requires current-plus-previous migration.
- Any new pheromone semantics beyond wire-version metadata and bounded migration
  remain future work.

</deferred>
