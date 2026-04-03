# Phase 20: Canary Slot And Strategy Assignment - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Introduce the repo-owned canary slot contract that turns a verified candidate detector into a bounded live canary input. This phase defines configuration, assignment, and stable canary identifiers. It does not yet execute canary events or implement rollback.

</domain>

<decisions>
## Implementation Decisions

### Assignment Source
- Reuse the existing experiment manifest as the candidate-detector source of truth.
- Require persisted verification and shadow artifacts when starting a canary so the live lane begins from already-reviewed evidence.
- Keep the baseline detector sourced from the main runtime config.

### Canary Scope
- Add a dedicated `canary` section to repo-owned runtime config instead of inventing a separate service manifest.
- Represent canary work as a stable run artifact keyed by slot ID and run ID.
- Keep candidate detections in a separate canary lane so they cannot influence the production substrate.

### Storage And Lookup
- Persist canary artifacts in a file-backed store under `data/canaries/`.
- Expose canary start and canary result flows through `swarmctl`.

</decisions>

<specifics>
## Specific Ideas

`v1.5` already proves offline promotion readiness through verification, shadow, and promotion-review artifacts. This phase should make canary admission explicit: only a verified, shadow-approved candidate may be attached to the bounded canary slot, and the baseline detector must remain the production reference.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`
- `docs/EVOLUTION.md`
- `docs/INTEGRATION.md`

### Existing Code
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-runtime/src/bin/swarmctl.rs`
- `crates/swarm-runtime/src/replay.rs`
- `crates/swarm-core/src/config.rs`
- `rulesets/default.yaml`
- `experiments/`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- Experiment manifests already describe candidate lineage and detector profiles.
- Verification and shadow reports already persist stable IDs and pass/fail state.
- `ConfiguredRuntimeStack` already centralizes repo-owned runtime composition.

### Established Patterns
- New repo-owned behaviors use typed YAML config plus file-backed stores.
- `swarmctl` exposes operator workflows as stable-ID commands.
- Runtime-side status and review surfaces stay in Rust and avoid the replay harness when the behavior is meant to be live.

### Integration Points
- Extend `crates/swarm-core/src/config.rs` with canary settings.
- Add a runtime-side canary module and file-backed store under `crates/swarm-runtime/src/`.
- Extend `swarmctl` with canary start and result commands.

</code_context>

<deferred>
## Deferred Ideas

- Fleet-wide production promotion
- Quorum approval for promotion
- Multi-canary scheduling across several live slots

</deferred>

---
*Phase: 20-canary-slot-and-strategy-assignment*
*Context gathered: 2026-04-03*
