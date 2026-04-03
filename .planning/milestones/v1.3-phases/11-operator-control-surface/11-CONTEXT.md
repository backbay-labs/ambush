# Phase 11: Operator Control Surface - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Expose the shipped runtime status and durable artifact stores through a repo-owned CLI without introducing an HTTP service or widening live-response authority.

</domain>

<decisions>
## Implementation Decisions

### Surface Shape
- Start with a small CLI rather than an authenticated networked control plane.
- Reuse the existing serializable runtime report and durable stores instead of inventing new control-only data models.
- Keep the control surface read-only in this phase.

### Runtime Composition
- Build the CLI on top of the config-backed `ConfiguredRuntimeStack` so the same repository-owned config drives status and lookup behavior.
- Use the shipped default components (`StaticApprovalGate`, `SandboxExecutor`, `SummaryInvestigator`) for control-surface composition.
- Add only the missing stable-ID lookup helpers needed to query replay bundles, investigation bundles, and incidents.

### Operator Semantics
- Label output by origin so runtime status and persisted artifacts are distinguishable now, and offline replay artifacts can be distinguished later.
- Human-readable output should stay concise, but JSON output must be lossless and serializable.
- Degraded stores remain visible as warnings rather than blocking the operator surface.

### Claude's Discretion
The exact CLI subcommand tree can stay lightweight as long as operators can inspect status and retrieve artifacts by stable IDs from repo-owned config.

</decisions>

<specifics>
## Specific Ideas

The current runtime already exposes `OperatorStatusReport` plus store-backed bundle and incident types. Phase 11 should put a thin control layer on top of those instead of adding another reporting abstraction.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`

### Existing Code
- `.planning/milestones/v1.2-phases/10-operator-review-surfaces/10-01-SUMMARY.md`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/config.rs`
- `crates/swarm-runtime/src/investigation.rs`
- `crates/swarm-spine/src/store.rs`
- `crates/swarm-spine/src/investigation.rs`
- `crates/swarm-spine/src/incident.rs`
- `docs/CONFIGURATION.md`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ConfiguredRuntimeStack` already composes config-backed substrate, replay, investigation, and incident stores.
- `OperatorStatusReport` already provides one serializable review surface.
- Replay, investigation, and incident stores already support stable-ID lookup internally.

### Established Patterns
- Operator-facing data stays serializable and store-backed.
- `swarm-runtime` is the composition root; control logic should remain a thin layer over it.
- Documentation for live config and operator-facing behavior lives in `docs/CONFIGURATION.md`.

### Integration Points
- `swarm-runtime/src/service.rs` needs stable-ID lookup wrappers for the configured stack.
- A new `control` module can expose reusable CLI handlers and output envelopes.
- A small binary target can sit in `crates/swarm-runtime/src/bin/` without creating a new workspace crate.

</code_context>

<deferred>
## Deferred Ideas

- Authenticated HTTP or TUI operator surfaces
- Mutating operator actions from the CLI
- Offline replay result lookup

</deferred>

---
*Phase: 11-operator-control-surface*
*Context gathered: 2026-04-03*
