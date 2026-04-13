# Phase 192: Startup Binary And Ruleset Attestation - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 192 starts `v1.56` by adding startup attestation for the runtime binary
and the repo-owned ruleset set. The boundary is startup verification and
fail-closed live-response admission. Config-file signature verification remains
Phase 193.

</domain>

<decisions>
## Implementation Decisions

- Hook attestation into the existing startup path rather than introducing a
  parallel wrapper binary.
- Treat live-response mode as the fail-closed gate: detect-only can still report
  an attestation failure, but live-response must not start when the binary or
  ruleset set does not verify.
- Reuse existing signing and verification primitives where possible instead of
  inventing a second detached-signature format for runtime-owned artifacts.

</decisions>

<code_context>
## Existing Code Insights

- [swarm_detect.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/bin/swarm_detect.rs)
  already owns startup argument parsing, config loading, and serve-mode
  activation, making it the natural attestation entrypoint.
- [config.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/config.rs)
  and `load_config` already define the runtime startup seam that later phases
  can extend with signature and attestation checks.
- [health.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/health.rs)
  already exposes `/startupz`, `/readyz`, and `/healthz`, giving attestation
  work a clear runtime status surface once verification is added.
- Existing detached-signature and verification primitives already exist in
  runtime code such as
  [approval.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/approval.rs),
  [agent_identity.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/agent_identity.rs),
  and Providence token verification paths, so Phase 192 can likely build on a
  shared signing vocabulary instead of inventing a bespoke verifier.

</code_context>

<deferred>
## Deferred Ideas

- Signed config files and tamper rejection remain Phase 193.
- Runtime anti-tamper monitoring, debugger detection, and SBOM work remain
  later `v1.56` phases.

</deferred>
