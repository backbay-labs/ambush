# Phase 133 Plan 01 Summary

## Delivered

- Added host-filtered deposit queries in `swarm-pheromone` so posture can read substrate signals by asset without introducing a side cache.
- Extended runtime finding publication with a first-class `finding` event and emitted canonical `SwarmFindingEnvelope` payloads from the ingest path.
- Added `GET /v2/api/assets/{host_id}/posture` with per-threat-class concentrations, active investigations, host escalation level, and recent findings.
- Added `GET /v2/api/stream/findings` behind the Phase 132 platform API key middleware, streaming canonical finding payloads as SSE `finding` events.

## Notes

- Detection deposits now carry `host_id` in their indicator payload, and stalker investigation deposits also preserve host identity for host-scoped substrate reads.
- The existing `/v1/events/stream?types=` path now understands the new `finding` runtime event kind without changing its previous filtering behavior.
