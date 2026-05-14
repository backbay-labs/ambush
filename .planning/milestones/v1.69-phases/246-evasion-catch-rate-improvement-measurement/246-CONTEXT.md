# Phase 246: Evasion Catch-Rate Improvement Measurement - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase turns the new normalization seam into a repo-owned benchmark proof by
comparing normalization-enabled and normalization-disabled detector profiles on a
tracked adversarial command-line corpus.

</domain>

<decisions>
## Implementation Decisions

### Chosen Approach
- Reuse `crates/swarm-runtime/src/evasion_coverage.rs` instead of inventing a
  new measurement harness.
- Add a dedicated command-line deobfuscation suite and catalog in the existing
  `scenario-suites/` and `rulesets/evasion/` surfaces.
- Compare two configs built from the same runtime settings: one with
  `command_line_normalization` enabled and one with it disabled via detector
  profile overrides.

</decisions>
