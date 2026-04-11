# Phase 161: Evasion Test Corpus And Coverage Metrics - Context

**Gathered:** 2026-04-10
**Status:** Captured during execution

<domain>
## Phase Boundary

Phase 161 establishes the repo-owned evasion benchmark: curated adversarial scenarios, explicit ATT&CK technique coverage and intentional gaps, and one runtime-owned coverage snapshot that both API consumers and Prometheus can read.

</domain>

<decisions>
## Implementation Decisions

- Keep the evasion suite and technique catalog repo-owned under `scenario-suites/` and `rulesets/evasion/` instead of introducing operator-editable runtime config for the benchmark definition.
- Evaluate coverage against the existing runtime detector factory so catch-rate reporting reflects the same detector construction path used by live runtime and replay evaluation.
- Publish one shared `EvasionCoverageSnapshot` to both `/api/v1/evasion/coverage` and `/metrics` rather than maintaining separate API-only and metrics-only reporting logic.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/replay/core.inc` already owns typed scenario and suite manifests, so the evasion bench should be expressed as one more repo-owned replay suite instead of a parallel corpus format.
- `crates/swarm-runtime/src/detection/metrics.rs` already owns the Prometheus registry and label families, which makes it the right seam for evasion catch-rate gauges.
- `crates/swarm-runtime/src/ingest.rs` already owns the authenticated platform-read surface and `/metrics`, so the API and Prometheus exposure should stay there instead of adding a new serve surface.
- `crates/swarm-whisker` already exposes detector construction through the runtime detector factory, which avoids hand-maintained per-detector coverage code.

</code_context>

<deferred>
## Deferred Ideas

- Turning measured evasion gaps into Kitten mutation pressure is Phase 162.
- Optional solver-backed Z3 verification remains Phase 163.

</deferred>
