# Phase 193: Configuration Signature Verification - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 193 extends the startup trust chain from repo-owned binary and ruleset
attestation to the runtime config file itself. The phase boundary is signed
config admission at startup and on reload; runtime anti-tamper monitoring stays
Phase 194.

</domain>

<decisions>
## Implementation Decisions

- Reuse the detached-signature vocabulary already used by startup attestation,
  approval artifacts, and Providence contracts instead of introducing a second
  signature envelope.
- Verify config bytes before the runtime treats the file as trusted, and keep
  the fail-closed gate on the real `swarm_detect` entrypoint plus config-reload
  path.
- Keep the config-signing trust root out of unsigned config so the loader and
  reload watcher can reject tampered or unsigned files without trusting the file
  they are validating.

</decisions>

<code_context>
## Existing Code Insights

- [config.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/config.rs)
  already owns config file reads, parsing, validation, and secret resolution,
  making it the natural seam for signature verification before deserialization
  becomes trusted state.
- [swarm_detect.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/bin/swarm_detect.rs)
  now evaluates startup attestation before runtime activation, so config
  signature verification can join that same entrypoint contract rather than
  creating an alternate startup path.
- [mod.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/mod.rs)
  and its reload loop already distinguish full config reload from secret-only
  refresh, so Phase 193 can require signatures on the file-backed reload path
  without widening the secret watcher scope.
- [startup_attestation.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/startup_attestation.rs)
  now carries a hardcoded trust root plus signed-statement verification helpers
  that can inform the config-signature contract.

</code_context>

<deferred>
## Deferred Ideas

- Continuous runtime self-monitoring for debugger attachment and unexpected
  library loads remains Phase 194.
- Supply-chain policy, SBOM generation, and advisory gating remain Phase 195.

</deferred>
