# Phase 241: Fileless And DNS Detector Genomes - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 241 extends the typed-genome mutation seam from Phase 240 to the
remaining supported non-process-tree detectors:
`FilelessExecutionDetector` and `DnsExfiltrationDetector`.

</domain>

<decisions>
## Implementation Decisions

- Reuse the typed genome representation added in Phase 240 instead of creating
  detector-specific ad hoc materialization paths.
- Keep autonomous generation bounded: seed control, small threshold or list
  perturbations, and crossover between compatible parents only.
- Defer benchmark orchestration and milestone-level proof claims to Phases
  242-243.

</decisions>

<code_context>
## Existing Code Insights

- [mutation/types.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/mutation/types.rs) and [drafting.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/drafting.rs) can already round-trip typed detector genomes after Phase 240.
- [swarm-whisker](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-whisker/src) already exposes typed `FilelessExecutionProfile` and `DnsExfiltrationProfile` models with validation-ready fields.
- [mutation/autonomous.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/mutation/autonomous.rs) still needed detector-specific bounded perturbation and crossover recipes for these two families.
- [mutation/test_support.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/mutation/test_support.rs) did not yet expose fileless or DNS fixtures through the typed mutation tests.

</code_context>

<deferred>
## Deferred Ideas

- No multi-generation benchmark proof in this phase.
- No new operator-facing draft or queue UX for the new detector families.

</deferred>
