# Phase 1: Baseline Contracts - Context

**Gathered:** 2026-04-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace doc-only assumptions with strict Rust-owned configuration and runtime contracts for the v1 detect-and-respond lane.

</domain>

<decisions>
## Implementation Decisions

### Config Shape
- Use repository-owned YAML as the canonical v1 configuration format.
- Define config around the Rust-first runtime, not the legacy population and consensus scaffold.
- Treat `detect_only` and `live_response` as explicit typed runtime modes.

### Validation
- Reject unknown YAML fields at load time.
- Return actionable validation errors that include the file path and failure reason.
- Keep stringly-typed severity and mode fields out of the runtime contract.

### Claude's Discretion
Exact module ownership between `swarm-core` and `swarm-runtime` is flexible as long as `swarm-runtime` owns the canonical load path.

</decisions>

<specifics>
## Specific Ideas

No specific requirements beyond the Rust-first reset already captured in project docs.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Product Direction
- `.planning/ROADMAP.md` - The v1 milestone phases and success criteria.
- `.planning/REQUIREMENTS.md` - The requirement IDs and phase mapping for config work.
- `docs/ARCHITECTURE.md` - Canonical Rust-first runtime shape.

### Existing Code
- `crates/swarm-core/src/config.rs` - Legacy config scaffold to replace or absorb.
- `crates/swarm-runtime/src/config.rs` - Runtime config entrypoint scaffold.
- `rulesets/default.yaml` - Current repository-owned ruleset that must become loadable.
- `CLAUDE.md` - Stale project instructions that still describe the old Python-first shape.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-core/src/types.rs` - Existing shared enums such as `Severity`.
- `crates/swarm-runtime/src/lib.rs` - Existing `RuntimeMode` enum and runtime wrapper.

### Established Patterns
- The new crates already favor narrow, typed Rust contracts with serde-based data models.
- Unit tests currently live beside the implementation modules and use small synthetic fixtures.

### Integration Points
- `rulesets/default.yaml` must map cleanly into the runtime config loader.
- `swarm-runtime` is the composition root that should consume the config contract.

</code_context>

<deferred>
## Deferred Ideas

None - discussion stayed within phase scope.

</deferred>

---
*Phase: 01-baseline-contracts*
*Context gathered: 2026-04-02*
