# Phase 268 Plan 01 Summary

## Delivered

- Reworked `swarmctl init --mode detect_only` to emit the repo-owned signed
  bootstrap bundle directly, including sidecar handling that keeps the generated
  `default.yaml` validate-able without hand-editing.
- Added remediation-grade validation and readiness output in
  `crates/swarm-cli/src/core.inc` so signature, detector-profile, endpoint, and
  bridge failures point to a concrete next operator action instead of only
  surfacing raw parser or connection errors.
- Tightened the operator status render path through
  `crates/swarm-runtime/src/control.rs` and the service status types so the text
  output leads with runtime mode, detector set, bridge health, recent findings,
  and escalation state.
- Documented the full shipped detector profile matrix in
  `docs/CONFIGURATION.md`, which is the canonical operator reference while the
  signed `rulesets/default.yaml` bootstrap bundle remains byte-stable.

## Notes

- The signed detect-only bootstrap bundle intentionally stays narrow and
  signature-bound. Operator-facing profile documentation therefore lives in the
  active config reference rather than mutating the checked-in bootstrap bytes.
- Phase 268 closes the curated-defaults and operator-UX contract; deployment
  path walkthroughs and end-to-end packaging proof are handled by Phases 269 and
  271.
