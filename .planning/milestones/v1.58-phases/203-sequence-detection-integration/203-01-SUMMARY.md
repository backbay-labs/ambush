# Phase 203 Plan 01 Summary

## Delivered

- Added `RuntimeService::with_configured_sequence_detector()` so both live
  service construction and offline replay attach the configured sequence
  detector consistently.
- Extended the service hot path to evaluate sequence findings after the normal
  detector pass and persist them through `persist_findings_as_deposits()`, so
  sequence output now reuses the existing signed pheromone lane instead of a
  special-case persistence seam.
- Updated the replay harness to build the same configured sequence detector as
  the live service, and proved partial and full sequence matches persist as
  replay bundles that still fan into investigations and one correlated
  incident.

## Notes

- Partial matches now emit lower-confidence deposits automatically because the
  sequence detector downgrades both severity and confidence before the shared
  deposit helper signs and persists the result.
- The composite detector continues to treat `kill_chain_sequence` as a no-op
  placeholder, which keeps multi-strategy config loading compatible while the
  real sequence evaluation remains service-owned.
