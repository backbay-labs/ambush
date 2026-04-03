# Phase 28 Context

## Goal

Surface strategy memory histories and scorecards through `swarmctl` for operator review of the production baseline versus verified candidates.

## Current Reality

- Phase 27 adds the actual scoring logic, but operators still need one durable review surface.
- The repo already favors CLI-first operator flows over HTTP or multi-user control planes.
- Current promotion and replay artifacts are inspectable by stable ID; scorecards should fit that same pattern.

## Constraints

- Keep the review surface CLI-first and file-backed.
- Do not widen the system into governance, automatic promotion, or a multi-user control plane.
- Link the advisory scorecard back to verification, rollout history, and current rollout state.

## Likely Implementation Shape

- Add `swarmctl` commands for memory ingest, lookup, history, scorecard creation, and scorecard reload.
- Persist one durable scorecard artifact per experiment plus verification context.
- Render the review surface with explicit baseline vs candidate score comparison and recommendation.

## Success Checks

- Operators can inspect strategy memory by stable ID or strategy ID without reading raw JSON.
- Operators can create and reload a durable advisory scorecard for a verified candidate.
- Scorecards expose rollout state and recommendation without mutating production configuration.
