# Phase 277 Plan 01 Summary

## Delivered

- Extended the shipped `splunk_hec` config in
  `crates/swarm-core/src/config/response.rs` with explicit batch event and byte
  limits and kept secret resolution on the existing runtime config seam.
- Implemented `SplunkHecAdapter` plus `SwarmFindingBatchEnvelope` in
  `crates/swarm-response/src/splunk_hec.rs` and updated
  `crates/swarm-response/src/siem.rs` so findings forward through one dedicated
  HEC path with CIM-aligned event fields and bounded NDJSON batching.
- Added delivery batch observability in
  `crates/swarm-runtime/src/detection/metrics.rs` and
  `crates/swarm-runtime/src/service/runtime_service.rs`, then updated the runtime
  SIEM test surfaces to validate the new payload shape and delivery counters.

## Notes

- The Splunk path now records transport, event count, and payload byte metadata
  on delivery receipts instead of treating SIEM forwarding as an opaque HTTP
  write.
- The runtime health surface reports `splunk_hec` separately from the response
  adapter so the compose proof can verify both outbound integrations
  independently.
