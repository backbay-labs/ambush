# Phase 247: Normalization False-Positive Regression Test - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase closes the milestone with a benign-control proof that the new
command-line normalization seam does not introduce false-positive regressions on
repo-owned benign command lines that exercise the new transform inputs.

</domain>

<decisions>
## Implementation Decisions

### Chosen Approach
- Reuse the command-line deobfuscation suite and add benign controls there so
  both the benchmark and regression proof run from the same tracked surface.
- Count detector false positives as benign payloads that produce any finding for
  the command-line detector family, then compare normalization-disabled vs
  normalization-enabled results.

</decisions>
