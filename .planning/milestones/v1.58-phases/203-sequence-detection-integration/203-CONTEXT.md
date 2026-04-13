# Phase 203: Sequence Detection Integration - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 203 finishes the milestone by proving sequence findings behave like
first-class runtime detections. The output is explicit service and replay
integration so partial and full chain matches reuse the existing pheromone,
replay, investigation, and incident lanes.

</domain>

<decisions>
## Implementation Decisions

- Keep sequence evaluation service-owned so it shares the accepted-event window
  and appends findings after the normal single-event detector path.
- Reuse the existing pheromone deposit persistence helper so sequence findings
  inherit signing, agent attribution, and substrate persistence unchanged.
- Make replay harness service construction attach the configured sequence
  detector too, so offline replay and live runtime behavior stay aligned.

</decisions>

<code_context>
## Existing Code Insights

- `detect_and_deposit` already provides the normal single-event deposit lane;
  sequence integration only needs a second finding pass plus reuse of the same
  deposit helper.
- `DefaultReplayHarness` previously built a plain `RuntimeService`, so replay
  would miss sequence findings unless the configured detector is attached at
  service construction time.
- Phase 202 already ships deterministic replay proof, which means Phase 203 can
  verify deposit and incident integration through the same focused suite.

</code_context>

<deferred>
## Deferred Ideas

- Broader operator or platform surfaces for sequence-specific review are future
  milestone work, not part of this initial integration phase.

</deferred>
