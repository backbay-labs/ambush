# Phase 12: Deterministic Replay Harness - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Add an offline replay path that reuses the production Rust detector, policy, and audit types, but never executes live response actions. The output must be durable, deterministic enough to compare across runs, and driven by repo-owned scenario manifests.

</domain>

<decisions>
## Implementation Decisions

### Replay Shape
- Keep replay in `swarm-runtime`; do not create a second orchestration crate for offline tooling.
- Reuse `ReplayBundle`, `InvestigationBundle`, and `CorrelatedIncident` as the durable core artifacts.
- Force offline replay through `detect_only` plus `SandboxExecutor` so replay never widens live-response authority.

### Determinism
- Use manifest-seeded timestamps instead of wall-clock timestamps for replay bundle IDs and deterministic enrichment artifacts.
- Keep performance snapshots separate from deterministic artifact summaries because measured latency is intentionally variable across machines.
- Run investigation inline during replay instead of reusing the async queue so output ordering and IDs stay stable.

### Storage And Operators
- Persist replay-run bundles under a dedicated result store instead of mixing them into the live replay bundle store.
- Extend `swarmctl` rather than adding another binary.
- Start with repo-owned YAML scenarios under `scenarios/`.

</decisions>

<specifics>
## Specific Ideas

The runtime already has enough typed structure for offline replay. The missing seam is a harness that can materialize steps from manifests or stored bundle fixtures, run them with deterministic timestamps, then persist a replay-run bundle that operators can reload later.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`

### Existing Code
- `.planning/phases/11-operator-control-surface/11-01-SUMMARY.md`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/correlation.rs`
- `crates/swarm-runtime/src/investigation.rs`
- `crates/swarm-spine/src/lib.rs`
- `crates/swarm-spine/src/investigation.rs`
- `crates/swarm-spine/src/incident.rs`
- `docs/CONFIGURATION.md`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `RuntimeService::process_event` already builds deterministic replay bundles when given a fixed `ApprovalContext`.
- `SummaryInvestigator` already derives stable enrichment from a `ReplayBundle`.
- `CorrelationEngine` already knows how to assemble incidents from persisted investigation bundles.

### Established Patterns
- CLI-facing behavior lives in `swarm-runtime` and is documented in `docs/CONFIGURATION.md`.
- File-backed stores use a small index plus sanitized stable IDs.
- Operator-facing output should stay serializable and human-readable.

### Integration Points
- A new `replay` module can own scenario manifests, replay-run stores, renderers, and evaluation scaffolding.
- `swarmctl` can expose replay-run and replay-result subcommands beside the live control surface.
- Repo-owned scenarios should be tracked under `scenarios/` and default replay output should avoid dirtying git.

</code_context>

<deferred>
## Deferred Ideas

- Scenario suites or CI-wide replay gates
- HTTP or TUI replay surfaces
- Automatic detector promotion from replay output

</deferred>

---
*Phase: 12-deterministic-replay-harness*
*Context gathered: 2026-04-03*
