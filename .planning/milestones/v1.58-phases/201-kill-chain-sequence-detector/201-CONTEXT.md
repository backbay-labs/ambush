# Phase 201: Kill Chain Sequence Detector - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 201 consumes the shared temporal event window from Phase 200 and turns
it into a real sequence detector. The output is a repo-owned YAML rule pack
with ATT&CK chain metadata plus runtime wiring that can evaluate those rules
against the shared bounded window.

</domain>

<decisions>
## Implementation Decisions

- Keep the rule contract repo-owned and YAML-authored instead of baking ATT&CK
  chains into Rust constants.
- Reuse the shared runtime window from Phase 200 rather than attaching a
  second detector-local history buffer.
- Keep the detector itself sequence-specific, but let the existing finding and
  deposit pipeline remain responsible for persistence and policy handling.

</decisions>

<code_context>
## Existing Code Insights

- `TemporalEventWindow` already provides bounded ordered-predicate matching, so
  the sequence detector only needs rule parsing plus step predicate mapping.
- `RuntimeService` is the safest integration seam because it already owns the
  accepted-event lifecycle and can evaluate sequence findings after the normal
  single-event detector path.
- `build_detector_from_strategy` still needs to accept
  `kill_chain_sequence` inside multi-strategy configs even though the real
  rule evaluation happens through the service wrapper.

</code_context>

<deferred>
## Deferred Ideas

- Chain-only replay scenarios land in Phase 202, not here.
- Explicit proof that partial and full sequence matches reuse the pheromone and
  replay lanes lands in Phase 203.

</deferred>
