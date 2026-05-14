# Phase 271 Verification

status: passed

## Result

Phase 271 verification passed.

## Commands

- `CARGO_TARGET_DIR=target-v175-cli cargo test -p swarm-cli quickstart_command_completes_on_signed_detect_only_template --lib --quiet`
- `tmpdir=$(mktemp -d /tmp/swarm-v175-quickstart-XXXXXX) && cargo run -q -p swarm-runtime --bin swarmctl -- init --mode detect_only --output "$tmpdir/default.yaml" >/dev/null && SWARM_VOTER_SIGNING_KEY=quickstart-voter-key SWARM_EVIDENCE_SIGNING_KEY=quickstart-evidence-key CARGO_TARGET_DIR=target-v175-quickstart cargo run -q -p swarm-runtime --bin swarmctl -- quickstart --config "$tmpdir/default.yaml"`
- `docker compose build swarm-detect`
- `docker compose run --rm --entrypoint swarmctl -e RUST_LOG=warn -e SWARM_VOTER_SIGNING_KEY=quickstart-voter-key -e SWARM_EVIDENCE_SIGNING_KEY=quickstart-evidence-key swarm-detect --approval-verdict-results-dir /tmp/approval-verdicts --approval-receipt-pack-results-dir /tmp/approval-receipt-packs --approval-set-results-dir /tmp/approval-sets --approval-ledger-results-dir /tmp/approval-ledgers quickstart --config /app/rulesets/default.yaml`

## Verified Behaviors

- `swarmctl quickstart` completes against the signed detect-only bootstrap
  bundle and emits the first-run finding proof in one command.
- The operator-facing report stays coherent with the active config and no longer
  suggests unsupported incident follow-ups for in-memory bootstrap state.
- The packaged Docker image still builds with the bootstrap-bundle include path
  changes needed by the quickstart surface.
