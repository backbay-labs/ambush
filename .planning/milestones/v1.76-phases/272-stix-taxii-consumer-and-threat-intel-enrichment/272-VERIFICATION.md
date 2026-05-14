# Phase 272 Verification

status: passed

## Result

Phase 272 verification passed.

## Commands

- `cargo check -p swarm-core -p swarm-ingest-taxii`
- `cargo test -p swarm-ingest-taxii --lib`
- `cargo test -p swarm-runtime threat_intel --lib`

## Verified Behaviors

- TAXII polling normalizes IPv4, domain, file-hash, and URL indicators into `ThreatIntelEntry` with TTL, source, and indicator ID metadata.
- Re-observed indicators refresh the existing substrate entry rather than creating duplicates.
- Matching findings surface IOC value, feed source, STIX indicator ID, and confidence-boost evidence on the shipped signed finding path.
- Threat-intel feed poll timestamps, ingest counts, and error counts appear on the runtime health surface.

## Notes

- Phase 272 runtime proof is shared across the detection pipeline, control-plane, and HTTP threat-intel route tests because they all consume the same substrate contract.
