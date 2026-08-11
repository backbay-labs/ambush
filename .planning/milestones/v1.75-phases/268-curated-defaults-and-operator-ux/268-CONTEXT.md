# Phase 268 Context

Phase 268 is active under `v1.75 Operator Packaging`.

Goal: operators can reach a working `detect_only` runtime on first run using curated defaults, and the operator status surface plus error messages are clear enough to self-serve.

Known groundwork already in repo:
- `swarmctl init`, `validate`, `readiness`, `first-run`, and `status` command plumbing exists in `crates/swarm-cli/src/core.inc`.
- `rulesets/default.yaml` already exists but still needs curated operator-facing documentation and validation against all shipped detectors.
- Runtime status and bridge-health surfaces already exist and need a clearer one-screen operator summary.

Execution focus:
- tighten the generated detect-only config and default ruleset path
- improve status rendering for runtime mode, detector set, bridge health, recent findings, and escalation state
- make validation and startup failures include concrete remediation guidance
- prove the curated detect-only path boots without hand-editing config
