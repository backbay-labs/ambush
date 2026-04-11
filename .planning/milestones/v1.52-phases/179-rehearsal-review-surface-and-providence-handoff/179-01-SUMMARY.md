# Phase 179 Plan 01 Summary

## Delivered

- Extended the local operator review surface in [core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc) with bounded `hunt_id`, `incident_id`, and `bundle_id` context so one scoped page can show the selected replay bundle, the latest rehearsal proof for that hunt, and the matching Providence reconciliation summary together.
- Added a signed rehearsal proof export route on the same operator surface that reuses the existing replay-bundle evidence contract instead of inventing a new artifact type, and wired the operator surface to share one control plane with the evidence harness so in-memory and file-backed stores resolve the same replay bundle.
- Tightened Providence handoff links in [providence.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/providence.rs) so the review and audit links now land on a scoped review page, while the replay drilldown continues to target the latest replay artifact for the bounded hunt.
- Extended the platform API in [platform_api.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/platform_api.rs) so finding and incident summaries now carry the latest rehearsal proof metadata plus related Providence reconciliation context for the same hunt.
- Threaded the extra artifact directories through [core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc), [core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-cli/src/core.inc), and [evidence.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-evolution/src/evidence.rs) so operator review export can build the shipped evidence harness without a separate config-only bootstrap lane.

## Notes

- Scoped review lookup is strict for explicit `bundle_id` and `incident_id`, but hunt-derived joins are best-effort so Providence and operators can still land on a useful page when one side of the correlation has not been persisted yet.
- Signed rehearsal proof remains an `EvidenceSubjectKind::ReplayBundle` bundle keyed by the rehearsal replay bundle id, which keeps verification, review, and downstream proof handling on the already-shipped evidence format.
- Providence handoff now preserves bounded context through URL parameters only; the operator review surface remains protected by the existing bearer-token contract rather than becoming a Providence-authenticated API.
