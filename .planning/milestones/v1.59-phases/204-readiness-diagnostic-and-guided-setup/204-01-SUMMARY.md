# Phase 204 Plan 01 Summary

## Delivered

- Added a repo-owned readiness diagnostic to the control surface so operators
  can run `swarmctl readiness` against a signed config and get one bounded
  report covering telemetry-source readiness, detector activation, and
  substrate health.
- Extended `swarmctl init` so the generated template flow now prints the exact
  readiness follow-up command operators should run before attempting the guided
  first-run flow.
- Updated `/readyz` to expose a telemetry-source summary alongside the existing
  detector, substrate, attestation, and anti-tamper components, and documented
  the new onboarding contract in `docs/CONFIGURATION.md`.

## Notes

- Subject-backed telemetry sources are intentionally reported as
  configuration-validated instead of falsely claiming live transport reachability.
- Bridge-backed telemetry sources use transport-specific validation or probes so
  onboarding failures stay specific without requiring the full Phase 205 wizard.
