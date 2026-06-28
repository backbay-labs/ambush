# Reference Status

This file defines which documents describe the runtime that ships today and
which documents remain historical background or inspiration only.

## Source-Of-Truth Order

When two materials disagree, resolve them in this order:

1. Runtime code and repo-owned config surfaces under `crates/` and
   `rulesets/default.yaml`
2. Canonical contract docs in `docs/`
3. Active planning docs under `.planning/`
4. Historical or reference-only material

The goal for this milestone is simple: the active contract describes the Rust
runtime that exists now, not the earlier mixed Rust/Python design.

## Canonical Active Contract

These files define the active runtime contract:

| Path | Active role |
| --- | --- |
| `docs/ARCHITECTURE.md` | Canonical runtime shape, lane boundaries, and active system map |
| `docs/AGENTS.md` | Current Rust agent roles, config gates, and runtime responsibilities |
| `docs/CONSENSUS.md` | Active governance, approval, identity-admission, and receipt-backed response contract |
| `docs/EVOLUTION.md` | Active replay, proof, queue, canary, promotion, and status contract |
| `docs/CONFIGURATION.md` | Repo-owned YAML and serve-surface configuration contract |
| `docs/REFERENCE-STATUS.md` | Active versus historical policy for the documentation set |

These planning and config artifacts must stay aligned with the canonical docs:

| Path | Role |
| --- | --- |
| `.planning/PROJECT.md` | Milestone-level description of the shipped runtime and current contract work |
| `.planning/ROADMAP.md` | Phase ordering and milestone scope |
| `rulesets/default.yaml` | Concrete repo-owned example of the active config surface |

## Historical Or Reference-Only Material

These materials may still be useful for context, but they do not define the
runtime contract that later milestones build on:

| Path | Status |
| --- | --- |
| `docs/INTEGRATION.md` | Historical mixed-runtime integration context and upstream adaptation notes |
| `docs/research/` | Research and background material only |
| `docs/plans/` | Historical brainstorm and pre-contract planning |
| `vendor/reference/` | Copied upstream code and design reference, not active runtime dependencies |
| `.planning/milestones/` | Archived milestone plans, audits, summaries, and roadmap snapshots |

## Policy Rules

- If an active doc conflicts with historical material, the active doc wins.
- If an active doc conflicts with the current Rust runtime or
  `rulesets/default.yaml`, the runtime and config win and the docs should be
  corrected immediately.
- Removed Python and PyO3 control-plane designs are not part of the shipped
  runtime contract.
- Deferred ideas should be labeled as deferred, not described as current
  behavior.
