# Phase 136 Verification

status: passed

## Result

Phase 136 verification passed.

## Commands

- `cargo check -p swarm-evolution -p swarm-runtime -j 1 --message-format short`
- `for i in $(seq 1 10); do cargo test -p swarm-runtime mutation::tests::mutation_batch_refreshes_ready_and_blocked_validation -- --exact >/tmp/mutation-stability-$i.log 2>&1 || { echo FAIL:$i; cat /tmp/mutation-stability-$i.log; exit 1; }; done; echo STABLE_10`
- `cargo test -p swarm-runtime replay::core::tests::shadow_report_persists_for_control_candidate -- --exact`
- `cargo test -p swarm-runtime replay::core::tests::promotion_review_packet_persists_and_reloads -- --exact`
- `cargo test -p swarm-runtime selection::tests::ranked_candidate_selection_supports_review_decisions_and_listing -- --exact`
- `cargo test -p swarm-runtime drafting::tests::materialized_candidate_refreshes_validation_and_reconciles_queue -- --exact`
- `cargo test -p swarm-runtime -p swarm-cli -j 1 --message-format short`

## Verified Behaviors

- The extracted `swarm-evolution` crate builds cleanly alongside `swarm-runtime`, and the extracted `swarm-cli` surface remains compatible with the shipped binaries.
- `swarmctl` and `swarm_detect` now share the extracted tracing bootstrap, keep stdout JSON as the default sink, and accept optional OTLP export wiring through `--otlp-endpoint`.
- The required hot-path functions now carry stable `trace_id` fields through structured spans without breaking the existing runtime or CLI entrypoints.
- Evolution validation now derives experiment and shadow artifacts from one replay evaluation, which removed the intermittent control-path shadow mismatch during drafting and mutation validation.
- Full `swarm-runtime` and `swarm-cli` package tests passed after the extraction, tracing, and validation-stability fixes landed.
