# Phase 194: Runtime Anti-Tamper Monitoring - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 194 adds continuous runtime self-monitoring after the startup trust-chain
work in Phases 192 and 193. The boundary is debugger and unexpected-library
tamper detection during live runtime operation; supply-chain policy and SBOM
release artifacts stay Phase 195.

</domain>

<decisions>
## Implementation Decisions

- Keep the probe Linux-first by using `/proc/self/status` and `/proc/self/maps`
  directly, while surfacing `unsupported` on other platforms instead of faking a
  portable signal.
- Evaluate anti-tamper state once before serve-mode startup, then continue in a
  bounded background monitor so live-response mode can fail closed without
  needing a restart.
- Expose the latest anti-tamper result through the same health and platform
  status surfaces operators already use, rather than introducing a parallel
  bypass surface.

</decisions>

<code_context>
## Existing Code Insights

- [swarm_detect.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/bin/swarm_detect.rs)
  already owns startup attestation and the serve-mode lifecycle, so the
  anti-tamper monitor should join that same startup boundary and shutdown flow.
- [mod.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/mod.rs)
  already carries runtime-owned shared state for health and platform reads, so
  it is the natural place to retain the current anti-tamper report.
- [health.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/health.rs)
  and
  [platform_api.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/platform_api.rs)
  already surface startup attestation and runtime status, making them the right
  operator-visible read paths for anti-tamper state too.

</code_context>

<deferred>
## Deferred Ideas

- Dependency-policy enforcement and SBOM release generation remain Phase 195.
- Richer process-memory integrity checks beyond debugger and library-load signals
  remain out of scope for this phase.

</deferred>
