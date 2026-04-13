# Phase 185 Plan 01 Summary

## Delivered

- Added typed service-side sub-errors in [service.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/service.rs) so rehearsal preview failures and durability-readiness failures now propagate as `RehearsalPreviewError` and `ReadinessError` beneath `ServiceError` instead of as anonymous reason strings.
- Converted the request-facing ingest seams in [mod.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/mod.rs) to typed boundaries with `IngestRequestError`, `IngestProcessingError`, and `DemoApprovalError`, covering payload parse failures, Providence scope-token mismatches, widget header construction, runtime event processing, and demo approval bookkeeping.
- Kept the shipped HTTP behavior stable by pushing string rendering to the edge in [demo.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/demo.rs): the demo and ingest surfaces still return the same string-bearing envelopes, but only after the internal typed errors have already classified the failure.
- Replaced the operator surface’s repeated inline `OperatorApiError::internal(error.to_string())` and `OperatorReviewError::internal(error.to_string())` adapters in [core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc) with typed mappers for `ControlError`, `ServiceError`, `EvidenceError`, `EvolutionPortfolioError`, `EvolutionGovernancePrepError`, and `OperatorMaintenanceError`.
- Added focused regression coverage in [ingest/tests.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/tests.rs), [service.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/service.rs), and [core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc) proving typed malformed-input rejection, scope-token mismatch handling, typed readiness failures, and representative operator-surface error mapping.

## Notes

- Phase 185 intentionally stopped at the request-facing and service-facing runtime boundaries. The evolution-specific strategy proposal lane in `ingest/mod.rs` still carries string-only propagation and is the first concrete target for Phase 186, which now owns the wider agent and evolution pass.
- The externally visible error payloads remain string-based by design for this tranche; the phase goal was to improve the internal failure contract without widening the shipped HTTP surface.
