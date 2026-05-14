# Phase 227: Path Hack Removal Integration Proof - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 227 proves the refactor is healthy: the affected crates must build, their
library tests must pass, and their production targets must be clippy-clean
after the path-hack removal.

</domain>

<decisions>
## Implementation Decisions

- Use targeted verification on the affected crates rather than repo-wide
  unrelated cleanup.
- Treat unrelated pre-existing test-target clippy debt outside the path-hack
  refactor as separate from this milestone's production-code proof.

</decisions>
