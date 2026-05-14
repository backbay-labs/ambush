# Phase 272 Plan 01 Summary

## Delivered

- Added the repo-owned `swarm-ingest-taxii` crate with bounded STIX/TAXII 2.1 polling and normalization for IPv4, domain, file-hash, and URL indicators.
- Extended runtime config and health wiring so TAXII feeds run through `runtime.threat_intel_feeds` and surface poll, ingest, and error counts on the existing status path.
- Expanded detection-pipeline enrichment so matching findings carry IOC value, feed source, STIX indicator ID, and the confidence boost applied on the standard signed finding envelope.

## Notes

- The feed lane is intentionally bounded to configured TAXII collection polling rather than a generic external-feed orchestration system.
- Threat-intel deduplication remains type+value scoped on the shared substrate, so re-observation refreshes TTL and confidence instead of creating duplicate records.
