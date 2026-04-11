# Phase 177: Analyst Disposition Sync And Memory Feedback - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 177 turns Providence analyst dispositions into durable signed evidence and bounded learning inputs. The inbound feedback endpoint already exists from Phase 151; this phase closes the loop by preserving the Swarm-signed evidence alongside the incident audit trail and by letting Sphinx and Kitten consume bounded outcome signals without expanding into free-form self-training.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing signed Providence feedback deposit from Phase 151 as the signed evidence seam instead of inventing a second artifact format.
- Persist a durable summary of that Swarm-signed deposit directly on the incident feedback audit entry so operator review and later handoff can prove what signal Swarm emitted even after substrate decay.
- Teach Sphinx to recognize Providence feedback deposits and attach the analyst disposition plus note to the matching engagement instead of treating feedback as a separate unrelated observation.
- Keep memory reward bounded with a fixed analyst outcome mapping: `confirm` reinforces, `dismiss` zeroes the engagement reward, and `investigate` marks the engagement as low-confidence pending deeper review.
- Keep Kitten feedback routing intentionally narrow: only dismiss / false-positive feedback mutates evolution fitness, while other dispositions remain durable audit and memory signals.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/ingest/providence_handlers.rs` already signs Providence feedback pheromones and persists incident-linked analyst audit entries.
- `crates/swarm-runtime/src/sphinx_agent.rs` already owns durable engagement memory and Q-value-style retrieval, but today it deduplicates Providence feedback deposits against the original event and therefore never lets analyst dispositions adjust retrieval reward.
- `crates/swarm-runtime/src/kitten_agent.rs` already supports bounded false-positive penalties through `route_feedback_signal`, so Phase 177 should extend evidence lineage and Sphinx memory rather than broadening Kitten into confirm/investigate learning.
- `crates/swarm-spine/src/incident.rs` is the durable incident artifact boundary for feedback audit entries and is the correct place to persist signed-evidence references.

</code_context>

<deferred>
## Deferred Ideas

- Cross-incident analyst trend rollups and operator-facing false-positive dashboards remain later work.
- Free-form memory retraining or unbounded analyst-note embedding remains explicitly out of scope.
- Review-surface rendering of the new evidence lineage remains Phase 179.

</deferred>
