# Phase 259 Plan 01 Summary

## Delivered

- Added optional `soar_lineage` metadata to `AnalystFeedbackAuditEntry` and `FalsePositiveMeasurement` so external analyst identity, source system, verdict id, source case metadata, and verdict timestamp persist with the affected incident evidence.
- The new SOAR verdict handler now writes accepted lineage on success and writes explicit rejection audit entries for duplicate or incomplete inputs.
- Existing Providence feedback keeps the same audit shape with `soar_lineage: null`, so the shared audit store remains backward-compatible for non-SOAR inputs.

## Notes

- Rejection auditing is incident-local by design: if the incident lookup succeeds, Swarm records the rejected SOAR verdict on that incident instead of silently discarding the input.
- The lineage metadata is attached to both the detailed audit record and the normalized false-positive measurement so later replay, reporting, and operator rollups can reuse the same identifiers.
