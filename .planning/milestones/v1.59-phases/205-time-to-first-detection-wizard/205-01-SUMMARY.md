# Phase 205 Plan 01 Summary

## Delivered

- Added a repo-owned guided first-run walkthrough to the runtime and control
  surface so `swarmctl first-run` now reruns the Phase 204 readiness
  diagnostic, blocks cleanly on readiness failures, and otherwise drives one
  bounded synthetic detection -> approval -> proof flow.
- Reused the existing demo replay, approval, and proof machinery instead of
  creating a second onboarding-only execution lane, and returned the durable
  approval-set, receipt-pack, incident, and proof identifiers in one
  structured walkthrough report.
- Documented the new onboarding command in `docs/CONFIGURATION.md`, including
  the readiness precondition, the required signing env vars, and the optional
  custom-scenario override.

## Notes

- The guided walkthrough forces a sandboxed live-response configuration in
  process so approval and proof export can be exercised safely even when the
  checked-in runtime config is still `detect_only`.
- The walkthrough derives a temporary first-run operator identity from the
  supplied approval-voter signing key so approval artifacts stay signature
  valid instead of relying on placeholder operator IDs such as `local-operator`.
- The shared CLI tracing layer now writes logs to stderr so `swarmctl
  first-run --json` stays machine-readable on stdout while still preserving the
  runtime audit trail during the walkthrough.
