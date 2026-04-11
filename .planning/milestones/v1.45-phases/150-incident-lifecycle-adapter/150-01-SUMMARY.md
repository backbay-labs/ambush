# Phase 150 Plan 01 Summary

## Delivered

- Added a dedicated runtime-owned `ProvidenceIncidentAdapter` in `crates/swarm-runtime/src/providence.rs` that creates, updates, and resolves Providence incidents against the configured `providence_webhook` endpoint, signs requests with the Phase 149 HMAC seam, retries writes with exponential backoff, and dead-letters terminal failures after three attempts.
- Extended `swarm-spine` incident persistence with a generic `ExternalReference { system, id, url }` plus trigger metadata (`trigger_strategy_id`, `trigger_finding_id`, `trigger_event_id`, `threat_class`, `severity`) so Providence incident IDs are durable and restart-safe on `IncidentRecord` / `CorrelatedIncident`.
- Updated correlation in `crates/swarm-runtime/src/correlation.rs` to stamp that trigger metadata onto newly assembled incidents, which gives the adapter a stable create-by-key value of `strategy_id:threat_class:finding_id`.
- Wired `IngestState` to build the adapter when `notification_channels.providence_webhook` is configured, run a bounded background sync loop in serve mode, and surface live Providence reachability / auth / accepting-writes health through `/healthz` and `/readyz`.
- Filtered `providence_webhook` out of the generic `NotificationRouter` in `crates/swarm-runtime/src/service.rs` so Providence lifecycle delivery no longer double-sends through the old one-shot channel path, while leaving all other notification channels unchanged.
- Updated `docs/CONFIGURATION.md` and `rulesets/default.yaml` so the reserved `providence_webhook` channel semantics now describe the lifecycle adapter rather than a generic webhook sink.

## Notes

- The lifecycle adapter now treats `notification_channels.providence_webhook.target_url` as the Providence incidents collection endpoint. Create uses `POST <target_url>`; update and resolve use `PUT <target_url>/<remote_id>`.
- Phase 150 intentionally stops at outbound lifecycle sync plus health. Providence analyst feedback, bidirectional reconciliation, and widget embedding remain Phase 151 and Phase 152 work.
