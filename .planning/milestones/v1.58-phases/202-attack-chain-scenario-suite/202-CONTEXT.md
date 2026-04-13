# Phase 202: ATT&CK Chain Scenario Suite - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 202 turns the new sequence detector into replayable proof. The phase
output is a repo-owned scenario suite with at least three chain-only ATT&CK
chains that stay quiet under the shipped single-event detectors and pass when
`kill_chain_sequence` is active.

</domain>

<decisions>
## Implementation Decisions

- Keep the scenarios grounded in the existing replay manifest format so the
  new proof composes with the same harness used by evolution and verification.
- Choose chains whose individual events look benign to the current single-event
  detectors, so the suite proves real multi-event coverage instead of simply
  replaying already-covered heuristics.
- Reuse one focused runtime integration test file to prove both the single-event
  baseline miss and the sequence-detector hit path.

</decisions>

<code_context>
## Existing Code Insights

- `DefaultReplayHarness` already evaluates suites and exposes deterministic
  replay bundle, investigation, and incident counts that can anchor chain-only
  ground truth.
- Phase 201 already ships three detector rules, so the scenario suite can map
  one scenario directly onto each ATT&CK chain without inventing a separate
  synthetic rule vocabulary.
- The existing single-event detectors are deterministic enough to prove
  chain-only misses in one focused integration test without replaying the full
  workspace corpus.

</code_context>

<deferred>
## Deferred Ideas

- Explicit proof that partial and full sequence matches reuse the pheromone and
  replay lanes is still Phase 203 work.

</deferred>
