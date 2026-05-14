# Phase 269 Verification

status: passed

## Result

Phase 269 verification passed.

## Commands

- `docker compose build swarm-detect`
- `docker compose run --rm --entrypoint swarmctl swarm-detect validate --config /app/rulesets/default.yaml`
- `docker compose run --rm --entrypoint swarmctl -e RUST_LOG=warn -e SWARM_VOTER_SIGNING_KEY=quickstart-voter-key -e SWARM_EVIDENCE_SIGNING_KEY=quickstart-evidence-key swarm-detect --approval-verdict-results-dir /tmp/approval-verdicts --approval-receipt-pack-results-dir /tmp/approval-receipt-packs --approval-set-results-dir /tmp/approval-sets --approval-ledger-results-dir /tmp/approval-ledgers quickstart --config /app/rulesets/default.yaml`
- `helm template swarm-team-six deploy/helm/swarm-team-six -f deploy/helm/swarm-team-six/values-production.yaml`

## Verified Behaviors

- The repo now ships a concrete getting-started guide for the packaged Docker
  flow instead of relying on scattered README or config notes.
- All supported deployment paths are documented with prerequisites, config
  seams, and verification steps.
- The Docker image packaging path still builds after the CLI bootstrap-bundle
  changes.
