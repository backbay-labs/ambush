# Phase 195: Supply Chain Hardening And SBOM - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 195 closes the attestation milestone with build-time dependency policy and
release inventory. The boundary is CI-enforced dependency hygiene plus
release-ready SBOM artifacts; runtime anti-tamper behavior is already complete
in Phase 194.

</domain>

<decisions>
## Implementation Decisions

- Keep the supply-chain gate repo-owned through checked-in scripts that both CI
  and local operators run, instead of duplicating logic directly in workflow
  YAML.
- Preserve a strict wildcard ban for third-party dependencies while pinning
  first-party workspace crate versions explicitly so internal path wiring does
  not weaken the policy.
- Record temporary RustSec exceptions with reasons instead of silently allowing
  advisories, and generate SBOM artifacts through one reproducible repo script.

</decisions>

<code_context>
## Existing Code Insights

- [Cargo.toml](/Users/connor/Medica/backbay/standalone/swarm-team-six/Cargo.toml)
  already centralizes workspace dependency policy, making it the natural place
  to eliminate internal wildcard requirements.
- [deny.toml](/Users/connor/Medica/backbay/standalone/swarm-team-six/deny.toml)
  already exists, so this phase extends policy instead of introducing a second
  dependency-audit toolchain.
- [.github/workflows/ci.yml](/Users/connor/Medica/backbay/standalone/swarm-team-six/.github/workflows/ci.yml)
  is the shared repo-owned CI lane, so the supply-chain gate should run there
  once as a normal build step.

</code_context>

<deferred>
## Deferred Ideas

- Upstream dependency upgrades that remove the temporary `cargo audit`
  exceptions stay outside this phase.
- Signed publication or external attestation of SBOM artifacts stays out of
  scope; this phase only generates and uploads the inventory.

</deferred>
