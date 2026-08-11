# Phase 244: Caret And Environment Variable Normalization - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase is limited to adding a shared pre-evaluation command-line
normalization seam for caret stripping and environment-variable expansion
before detector heuristics evaluate process command lines.

</domain>

<decisions>
## Implementation Decisions

### Chosen Approach
- Add one `swarm-whisker::command_line` helper instead of mutating telemetry
  payloads or duplicating transforms inside each detector family.
- Keep the raw command line unchanged in evidence and add normalized lineage
  alongside it so operators can still audit the original event content.
- Thread a defaulted `CommandLineNormalizationProfile` through the affected
  detector profiles so baseline-vs-normalized comparisons can disable the seam
  without changing detector logic.

### Deferred To Later Phases
- Unicode homoglyph folding and encoded-argument decoding are Phase 245.
- Catch-rate measurement and benign regression proof are Phases 246-247.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-whisker/src/suspicious_scripting.rs`,
  `fileless_execution.rs`, `lateral_movement.rs`, `supply_chain.rs`, and
  `detector.rs` all lowercased raw `process.command_line` independently before
  doing substring checks.
- `crates/swarm-runtime/src/evasion_coverage.rs` already provides a repo-owned
  benchmark surface that can compare detector catch rates once the profile seam
  exists.

</code_context>

<specifics>
## Specific Ideas

- Normalize `%VAR%` and `$env:VAR` for a bounded set of commonly used shell
  indirections such as `ComSpec`, `WinDir`, and `SystemRoot`.
- Preserve `normalized_command_line`, `decoded_command_segments`, and
  `command_line_transforms` in evidence so the later measurement phases can
  prove lineage and explainability.

</specifics>
