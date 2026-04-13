# Phase 195 Plan 01 Summary

## Delivered

- Updated
  [Cargo.toml](/Users/connor/Medica/backbay/standalone/swarm-team-six/Cargo.toml),
  [Cargo.lock](/Users/connor/Medica/backbay/standalone/swarm-team-six/Cargo.lock),
  and
  [deny.toml](/Users/connor/Medica/backbay/standalone/swarm-team-six/deny.toml)
  so first-party workspace dependencies are explicitly version-pinned, the
  wildcard ban now applies cleanly to external dependencies, `fastrand` advances
  to `2.4.1`, and the shipped advisory or license policy matches the current
  dependency graph.
- Added repo-owned supply-chain automation in
  [check-supply-chain.sh](/Users/connor/Medica/backbay/standalone/swarm-team-six/tools/check-supply-chain.sh),
  [generate-sbom.sh](/Users/connor/Medica/backbay/standalone/swarm-team-six/tools/generate-sbom.sh),
  [ci.yml](/Users/connor/Medica/backbay/standalone/swarm-team-six/.github/workflows/ci.yml),
  and
  [release-sbom.yml](/Users/connor/Medica/backbay/standalone/swarm-team-six/.github/workflows/release-sbom.yml).
  CI now runs the shared dependency gate, and tagged releases publish one
  CycloneDX JSON SBOM per workspace crate.
- Updated
  [CONFIGURATION.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/CONFIGURATION.md)
  so the operator docs now describe the shared supply-chain gate, the temporary
  audit exceptions, and the release SBOM workflow.

## Notes

- `cargo audit` still carries one temporary exception for `RUSTSEC-2026-0097`
  because `async-nats 0.47` and `opentelemetry_sdk 0.31` have no newer
  compatible transitive `rand` fix yet.
- The bans check intentionally keeps duplicate-version splits informational by
  allowing only the `duplicate` diagnostic code while still failing on wildcard
  dependencies.
