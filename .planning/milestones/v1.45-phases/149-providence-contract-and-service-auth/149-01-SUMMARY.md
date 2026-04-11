# Phase 149 Plan 01 Summary

## Delivered

- Added a shared Providence contract in `crates/swarm-core/src/types.rs` with `SwarmProvidenceWebhookContract`, `ProvidenceCreateIncidentBody`, `schema_version`, and typed runtime / link context so Providence-native payloads are no longer ad hoc JSON.
- Added an RFC 2104 HMAC-SHA256 helper in `crates/swarm-crypto`, then extended `NotificationChannelConfig` in `crates/swarm-core/src/config.rs` and `crates/swarm-runtime/src/config.rs` with optional `request_signature` secret resolution via the existing `@secret:` path.
- Updated `crates/swarm-response/src/notification.rs` to send canonical JSON bodies, preserve bearer auth, and attach `X-Swarm-Signature: sha256=<hex>` when request signing is configured.
- Replaced the live Providence payload builder in `crates/swarm-runtime/src/ingest.rs` with the shared contract, mapping the outbound envelope to `create_incident` while keeping finding, aggregate, runtime, and drilldown context available for Providence-native consumers.
- Documented the new signing config in `docs/CONFIGURATION.md`, added the repo-owned commented example in `rulesets/default.yaml`, and closed the phase with focused tests for contract shape, secret resolution, and live signed delivery.

## Notes

- Phase 149 intentionally keeps Providence delivery on the existing `providence_webhook` notification lane; the dedicated incident lifecycle adapter is deferred to Phase 150.
- The new request-signing seam is generic to notification channels, but Providence is the first concrete consumer and the contract stays Providence-specific.
