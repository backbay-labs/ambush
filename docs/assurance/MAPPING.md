# Fail-closed invariant map

Phase 285, MAPPING-01..05 and FALSIFY-01..04.

This map covers the requirement-defined decision universe: both `swarm-policy`
approval gates; `SwarmRuntime::authorize_and_execute` and the refusal helpers it
calls; `swarm-spine` envelope and chain verification; and `swarm-response`
dispatch, containment construction/deserialization, and rollback classification.
It is not a claim about every `if` in every crate.

There are 57 mapped fail-closed invariants below. Five requirement-named
surfaces that do not themselves render a pre-dispatch refusal are recorded in
[`omissions.toml`](omissions.toml), with an owner, reason, and clearing
condition. `tools/check-mapping.sh` resolves both sets, requires every source
marker to be attached to an executable decision inside the exact named
function, and enforces set equality with the many-to-many assumption registry.

Every mapped row has one negative test. The test drives the real function, an
unmutated mirror on the same violating probe, and a mirror with one named guard
removed. The reproduced neutralization output is stored with the row in
[`negative-registry.toml`](negative-registry.toml); no claim is made that old
outputs live in a commit message.

## Map

The Assumptions column is deliberately many-to-many. A digest row can depend on
both canonical encoding and collision resistance; forcing one assumption per
row would make the blast-radius registry false.

| Invariant | Enforcing function | Assumptions | What it refuses |
| --- | --- | --- | --- |
| `POLICY-EMPTY-RULESET-DENIES` | `swarm_policy::configurable_gate::ConfigurableApprovalGate::evaluate` | `ASSUME-CONFIG-INTEGRITY`, `ASSUME-STATEFUL-GATE-DETERMINISM` | An explicitly constructed empty `PolicyConfig` is unconfigured and denies instead of falling through to static allow. The tracked `rulesets/default.yaml` is separate and carries configured rules. |
| `POLICY-RULE-TIME-WINDOW` | `swarm_policy::configurable_gate::ConfigurableApprovalGate::evaluate` | `ASSUME-CONFIG-INTEGRITY`, `ASSUME-OS-CLOCK`, `ASSUME-STATEFUL-GATE-DETERMINISM` | A matching rule outside its configured UTC window. |
| `POLICY-RULE-AGENT-RATE-LIMIT` | `swarm_policy::configurable_gate::ConfigurableApprovalGate::evaluate` | `ASSUME-CONFIG-INTEGRITY`, `ASSUME-OS-CLOCK`, `ASSUME-STATEFUL-GATE-DETERMINISM` | The first matching-rule request beyond that agent's one-minute budget. |
| `POLICY-CONFIGURED-DENY-RULE` | `swarm_policy::configurable_gate::ConfigurableApprovalGate::evaluate` | `ASSUME-CONFIG-INTEGRITY`, `ASSUME-STATEFUL-GATE-DETERMINISM` | A request matched by an explicit configured Deny rule. |
| `POLICY-NULL-EVIDENCE-REFUSED` | `swarm_policy::static_gate::StaticApprovalGate::validate_request` | `ASSUME-STATEFUL-GATE-DETERMINISM` | A JSON-null evidence bundle. |
| `POLICY-ACTION-TARGETS-NONEMPTY` | `swarm_policy::static_gate::StaticApprovalGate::validate_request` | `ASSUME-STATEFUL-GATE-DETERMINISM` | Empty or whitespace-only addressable fields for every response action variant. |
| `POLICY-DESTRUCTIVE-MIN-SEVERITY` | `swarm_policy::static_gate::StaticApprovalGate::evaluate` | `ASSUME-CONFIG-INTEGRITY`, `ASSUME-STATEFUL-GATE-DETERMINISM` | A Low-severity destructive action. |
| `POLICY-DEPLOY-DECOY-MIN-SEVERITY` | `swarm_policy::static_gate::StaticApprovalGate::evaluate` | `ASSUME-CONFIG-INTEGRITY`, `ASSUME-STATEFUL-GATE-DETERMINISM` | A Low-severity decoy deployment. |
| `POLICY-SCOPE-RATE-LIMIT` | `swarm_policy::static_gate::StaticApprovalGate::scope_rate_limit_decision` | `ASSUME-CONFIG-INTEGRITY`, `ASSUME-OS-CLOCK`, `ASSUME-STATEFUL-GATE-DETERMINISM` | The first action beyond one scope's one-minute budget. |
| `POLICY-DESTRUCTIVE-HUMAN-GATE` | `swarm_policy::static_gate::StaticApprovalGate::evaluate` | `ASSUME-CONFIG-INTEGRITY`, `ASSUME-STATEFUL-GATE-DETERMINISM` | Immediate execution of a destructive action at or above the human threshold. |
| `RESPONSE-TTL-STRICTLY-POSITIVE` | `swarm_response::containment::ContainmentTtl::from_config_ms` | `ASSUME-CONFIG-INTEGRITY` | A zero or negative containment lifetime. |
| `RESPONSE-LEASE-BOUNDED` | `swarm_response::containment::ContainmentLease::open` | `ASSUME-OS-CLOCK` | An expiry not strictly after issuance, including saturating-add overflow. |
| `RESPONSE-STORED-LEASE-SCHEMA-KNOWN` | `swarm_response::containment::ContainmentLease::try_from` | `ASSUME-KEYSTORE-ATOMICITY` | A stored lease from an unknown wire schema. |
| `RESPONSE-STORED-LEASE-BOUNDED` | `swarm_response::containment::ContainmentLease::try_from` | `ASSUME-KEYSTORE-ATOMICITY`, `ASSUME-OS-CLOCK` | A stored lease whose expiry is not after issuance. |
| `RESPONSE-MEMORY-DUPLICATE-LEASE-REFUSED` | `swarm_response::containment::ContainmentState::open_lease` | `ASSUME-KEYSTORE-ATOMICITY` | Opening one in-memory lease identifier twice. |
| `RESPONSE-MEMORY-CLOSE-UNKNOWN-LEASE-REFUSED` | `swarm_response::containment::ContainmentState::close` | `ASSUME-KEYSTORE-ATOMICITY` | Closing an in-memory lease that is not open. |
| `RESPONSE-FILE-DUPLICATE-LEASE-REFUSED` | `swarm_response::containment::FileContainmentLeaseStore::open_lease` | `ASSUME-KEYSTORE-ATOMICITY` | Persisting a second open lease under one identifier. |
| `RESPONSE-FILE-CLOSE-UNKNOWN-LEASE-REFUSED` | `swarm_response::containment::FileContainmentLeaseStore::close` | `ASSUME-KEYSTORE-ATOMICITY` | Persisting a close receipt for a lease that is not open. |
| `RESPONSE-IRREVERSIBLE-INVERSE-REFUSED` | `swarm_response::rollback::resolve_inverse` | `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR` | Treating a fresh user session as the inverse of a terminated session. |
| `RESPONSE-UNMAPPED-INVERSE-REFUSED` | `swarm_response::rollback::resolve_inverse` | `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR` | A step/action pair with no addressable inverse, instead of inventing an operation. |
| `RESPONSE-EMPTY-ROLLBACK-NOT-SUCCESS` | `swarm_response::rollback::RollbackReceipt::derive_status` | `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR` | Vacuous success for a rollback with zero step outcomes. |
| `RESPONSE-ENFORCED-SIMULATION-NOT-SUCCESS` | `swarm_response::rollback::RollbackReceipt::derive_status` | `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR` | Success for an Enforced rollback whose steps were only simulated. |
| `RESPONSE-PARTIAL-ROLLBACK-NOT-SUCCESS` | `swarm_response::rollback::RollbackReceipt::derive_status` | `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR` | Success for failed, unsupported, irreversible, or mixed rollback outcomes. |
| `RESPONSE-ROLLBACK-REQUIRES-STEPS` | `swarm_response::rollback::require_steps` | `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR` | Running an executor against an empty inverse plan. |
| `RESPONSE-SANDBOX-NEVER-REVERSES` | `swarm_response::rollback::SandboxRollbackExecutor::rollback` | `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR` | A Reversed step from an executor with no transport. |
| `RUNTIME-POLICY-ERROR-BLOCKS-EXECUTION` | `swarm_runtime::SwarmRuntime::authorize_and_execute` | `ASSUME-STATEFUL-GATE-DETERMINISM` | Treating a policy evaluation error as Allow. |
| `RUNTIME-DENY-BLOCKS-EXECUTION` | `swarm_runtime::SwarmRuntime::authorize_and_execute` | `ASSUME-STATEFUL-GATE-DETERMINISM` | Executor dispatch after a Deny verdict. |
| `RUNTIME-HUMAN-GATE-BLOCKS-LIVE` | `swarm_runtime::SwarmRuntime::authorize_and_execute` | `ASSUME-STATEFUL-GATE-DETERMINISM` | Executor dispatch after RequireHuman in LiveResponse mode. |
| `RUNTIME-GUARD-REJECTION-BLOCKS-EXECUTION` | `swarm_runtime::SwarmRuntime::authorize_and_execute` | `ASSUME-STATEFUL-GATE-DETERMINISM` | Executor dispatch after the guard pipeline rejects. |
| `RUNTIME-CONTAINMENT-NEEDS-STORE` | `swarm_runtime::SwarmRuntime::prepare_containment` | `ASSUME-CONFIG-INTEGRITY`, `ASSUME-KEYSTORE-ATOMICITY` | Enforced containment when no lease store can bound or undo it. |
| `RUNTIME-CONTAINMENT-PREVIEW-REQUIRED` | `swarm_runtime::SwarmRuntime::prepare_containment` | `ASSUME-CONFIG-INTEGRITY` | Enforced containment when its blast radius and inverse plan cannot be derived. |
| `RUNTIME-LEASE-ISSUE-ERROR-BLOCKS-EXECUTION` | `swarm_runtime::SwarmRuntime::authorize_and_execute` | `ASSUME-STATEFUL-GATE-DETERMINISM` | Executor dispatch after capability-lease issuance fails. |
| `RUNTIME-EXPIRED-LEASE-REFUSED` | `swarm_runtime::ensure_active_lease` | `ASSUME-OS-CLOCK`, `ASSUME-STATEFUL-GATE-DETERMINISM` | Execution at or after capability expiry. |
| `RUNTIME-ADAPTER-ERROR-NOT-SUCCESS` | `swarm_runtime::SwarmRuntime::authorize_and_execute` | `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR` | Converting a response-adapter error into a success receipt. |
| `RUNTIME-FAILED-RECEIPT-NOT-SUCCESS` | `swarm_runtime::SwarmRuntime::authorize_and_execute` | `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR` | Returning a non-success response receipt as successful execution. |
| `RUNTIME-RELEASE-ATTESTATION-REQUIRED` | `swarm_runtime::containment::verify_release_attestation` | `ASSUME-ED25519` | A rollback release with no governance attestation. |
| `RUNTIME-RELEASE-ATTESTATION-WELL-FORMED` | `swarm_runtime::containment::verify_release_attestation` | `ASSUME-CANONICAL-JSON`, `ASSUME-ED25519` | A rollback release carrying malformed governance-attestation JSON. |
| `RUNTIME-RELEASE-SIGNATURE-VALID` | `swarm_runtime::containment::verify_release_attestation` | `ASSUME-CANONICAL-JSON`, `ASSUME-ED25519` | A rollback release whose governance signature does not verify. |
| `RUNTIME-RELEASE-SUBJECT-BOUND` | `swarm_runtime::containment::verify_release_attestation` | `ASSUME-CANONICAL-JSON`, `ASSUME-ED25519`, `ASSUME-SHA256` | A genuine attestation lifted onto a rewritten rollback body. This is subject binding, not yet the later trusted-governor anchor. |
| `RUNTIME-FAILED-ROLLBACK-KEEPS-LEASE` | `swarm_runtime::containment::release_lease` | `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR`, `ASSUME-KEYSTORE-ATOMICITY` | Closing the only open lease after a rollback step reports Failed. |
| `SPINE-ENVELOPE-ISSUER-FIELD-REQUIRED` | `swarm_spine::envelope::verify_envelope` | `ASSUME-ED25519` | An envelope with no issuer identity. |
| `SPINE-ENVELOPE-SIGNATURE-FIELD-REQUIRED` | `swarm_spine::envelope::verify_envelope` | `ASSUME-ED25519` | An envelope with no signature field. |
| `SPINE-ENVELOPE-HASH-FIELD-REQUIRED` | `swarm_spine::envelope::verify_envelope` | `ASSUME-CANONICAL-JSON`, `ASSUME-SHA256` | An envelope with no claimed content identity. |
| `SPINE-ENVELOPE-ISSUER-KEY-VALID` | `swarm_spine::envelope::verify_envelope` | `ASSUME-ED25519` | An issuer identifier that cannot decode to an Ed25519 public key. |
| `SPINE-ENVELOPE-SIGNATURE-WELL-FORMED` | `swarm_spine::envelope::verify_envelope` | `ASSUME-ED25519` | Signature material that cannot decode as an Ed25519 signature. |
| `SPINE-ENVELOPE-HASH-BOUND` | `swarm_spine::envelope::verify_envelope` | `ASSUME-CANONICAL-JSON`, `ASSUME-SHA256` | A claimed hash that is not the digest of the unsigned body. |
| `SPINE-ENVELOPE-SIGNATURE-VALID` | `swarm_spine::envelope::verify_envelope` | `ASSUME-CANONICAL-JSON`, `ASSUME-ED25519` | A well-formed signature that does not verify for the claimed issuer. |
| `SPINE-CHAIN-ISSUER-FIELD-REQUIRED` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | A chain link with no issuer identity. |
| `SPINE-CHAIN-SEQ-FIELD-REQUIRED` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | A chain link with no sequence number. |
| `SPINE-CHAIN-PREV-FIELD-REQUIRED` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | A chain link that omits predecessor identity instead of explicitly using null for a first link. |
| `SPINE-CHAIN-PREV-TYPE-VALID` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | A non-null predecessor identity that is not a string. |
| `SPINE-CHAIN-FIRST-SEQ` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | A newly observed issuer starting anywhere except sequence 1. |
| `SPINE-CHAIN-FIRST-PREV-NULL` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | A newly observed issuer's first link pointing to unseen history. |
| `SPINE-CHAIN-ISSUER-BOUND` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY`, `ASSUME-ED25519` | Another issuer extending the held issuer head. |
| `SPINE-CHAIN-HEAD-NOT-OVERFLOWED` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | Wrapping a `u64::MAX` head sequence to zero. |
| `SPINE-CHAIN-SEQ-MONOTONIC` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | A continuation whose sequence is not exactly head plus one. |
| `SPINE-CHAIN-PREV-HASH-BOUND` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY`, `ASSUME-SHA256` | A continuation that names a different predecessor. |

## Reachability and evidence boundary

`verify_chain_link` remains a public tested primitive with no production caller
on this branch. The approval ledger builds links but does not verify them; the
map describes the primitive, not a runtime guarantee. The known trust-anchor
integration is also absent here and will add its own rows after rebase.

All negative tests are single-process. They do not prove concurrency, crash
recovery, distributed JetStream failover, repository branch protection, or
hosted CI. The workflow invokes both gates, but whether the named job is a
protected required check is repository-setting state and remains an external
acceptance item.
