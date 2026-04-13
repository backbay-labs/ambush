# Phase 201 Plan 01 Summary

## Delivered

- Added `KillChainSequenceDetector` in `crates/swarm-runtime/src/sequence_detector.rs`
  with a repo-owned YAML rule schema, ATT&CK chain metadata, rule validation,
  and partial or full ordered-match evaluation against the shared temporal
  window.
- Shipped the first repo-owned rule pack in `sequences/kill-chain-v1.yaml`
  covering three bounded kill-chain sequences: an Outlook installer to mshta
  transfer chain, a remote service stager chain, and an Office-to-msbuild to
  installutil transfer chain.
- Wired the new detector profile through runtime config and service
  construction, while keeping `build_detector_from_strategy("kill_chain_sequence")`
  compatible via a no-op composite entry so real evaluation remains
  service-owned.

## Notes

- The shipped rule pack lives under `sequences/` rather than the attested
  `rulesets/` subtree, so the current startup-attestation manifest remains
  unchanged while the detector still uses repo-owned YAML.
- Partial findings intentionally downgrade severity and confidence from the
  full-chain rule values so later phases can emit intermediate pheromone
  signals without overstating incomplete chains.
