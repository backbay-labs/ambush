---
phase: 285-assurance-foundation-closure
task: 285-04-03A2b3R1a
status: rejected
candidate_commit: f8c1ec2e131ac95d91ccab9b38c83d3164095fcc
candidate_tree: c8ccc8b4b873948d7286806d3f29a9ffb389d432
candidate_parent: ed77183d3d13d046e446d2837e8c5d21d1d1765d
rejected_ref: refs/rejected/phase285/plan04-task03a2b3r1a-f8c1ec2
accepted_predecessor: false
raw_transcript_retained: false
---

# R1a `f8c1ec2` rejected-evidence record

This is a bounded post-run record, not the deleted raw harness transcript. The exact rejected Git object is preserved under the explicitly non-predecessor local ref above. No `work/`, `checkpoint/`, `candidate`, or `production` ref points to it.

## Immutable identity

- Commit: `f8c1ec2e131ac95d91ccab9b38c83d3164095fcc`
- Tree: `c8ccc8b4b873948d7286806d3f29a9ffb389d432`
- Direct parent: `ed77183d3d13d046e446d2837e8c5d21d1d1765d`
- Exact changed-path count: 7
- Changed-path digest: `272eb9961675aa24a93164825a64c2db7930d1cfa544a520fddd7d085a10e9ab`
- Integrity launcher SHA-256: `e59ba9f62bf126bccdf8c0d3331b54adae9e74f8fe1ee6e31d43e3dec9ca66b1`
- Integrity manifest SHA-256: `4eb5b76c5f5411b447373310cdedf665bacfd6e340dbe8836c4d0d6524bf1b7b`
- Planned initially absent target: `/private/tmp/phase285-r1a-target.jMuOtK`; it remained absent because the first selector failed before the outer Cargo gates.

The evidence-consuming command was the unchanged r72 R1a `<automated>` command after both required A2b3 remote-tracking refs were imported into the ephemeral clone and verified at the exact base. Two earlier shell invocations exited during preflight before target creation or test execution: one lacked exported candidate variables and one lacked the required remote-tracking names. Neither is acceptance evidence.

## Exact captured terminal excerpt

```text
transport_semantics_source mutations=8 unique=8 vacuous=0 passed=1
transport_compiled_progress mutation=other_to_unavailable state=start
    Finished `test` profile [unoptimized + debuginfo] target(s) in 30.94s
     Running unittests src/lib.rs (.../compiled-target/debug/deps/swarm_governance_witness-6ae611e7215fd7ef)

running 1 test
test service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain ...
thread 'phase285-r1a-transport-other' (...) panicked at crates/swarm-governance-witness/src/lib.rs:101:39:
transport response request absent: Elapsed(())
thread 'service_checkpoint_transport_semantics_tests::post_command_other_is_distinct_from_pre_send_drain' (...) panicked at crates/swarm-governance-witness/src/lib.rs:101:39:
transport Other thread panicked: Any { .. }
FAILED

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 22 filtered out; finished in 5.13s
error: test failed, to rerun pass `-p swarm-governance-witness --lib`
```

The raw wrapper transcript was confined beneath its harness scratch and removed by normal harness cleanup. No execution-time raw-transcript hash exists. This record must therefore be cited as a bounded captured excerpt plus independently auditable source diagnosis, not as a retained canonical transcript.

## Independently auditable causal diagnosis

In the preserved commit, `run_transport_other_test_async` connects `SWARM_NATS_WITNESS_CREDENTIAL_PATH` as role `witness` and subscribes ordinary `swarm.governance.witness.v1.fence`. Under `--relay-service-checkpoint`, the harness rewrites the runtime account's ordinary import to the relay account's `swarm.governance.witness.relay.v1.fence` export. That FQN starts no forwarding relay. `subscribe` plus `flush` therefore installs an authenticated but off-path witness subscription; the runtime request cannot reach it. The 100-ms sleep cannot change account or subject routing.

The same source inspection found a masked later failure: `run_response_grant_recovery_leg` starts direct witness/store runners but no `LiveRelayLegsV1`, while relay topology rewrites both public and private service paths through the relay account.

## Immutable hostile production review

The read-only review verified commit, tree, parent, exact seven paths, path digest, and clean diff, then returned P0/P1/P2=`0/2/0`:

1. `NatsPublicWitnessStoreProxyClient` maps `InvalidSubject` and local/response framing failures to `Framing`, but dispatcher `transport` collapses `Framing` with `Unavailable`. This violates the closed contract that shipping `Unavailable` means broker-issued `NoResponders` only. Required repair: map private `Framing` to dispatch `Invalid` and prove InvalidSubject, malformed bytes, operation mismatch, and request-digest mismatch.
2. Grant-expiry evidence compares replay one only with replay two, never with the first response payload enqueued after the CAS and denied by the expired grant. It also prints `no_hold_reply=1` without executing a fresh non-stalled case. Required repair: capture the actual first payload at the real pre-enqueue worker-publisher seam, compare it byte-for-byte with recovery, and run fresh held/no-hold physical cases for both legs.

The reviewer found the public `RequestErrorKind` mapping, responder-observed post-command `Other`, exact targeted broker refusal after an unrelated refusal, one-attempt/one-application CAS evidence, and enqueue-only terminology otherwise sound.

This rejected object is evidence only. It never advances the accepted frontier, never authorizes R1b, and is never a parent of the repaired R1a candidate.
