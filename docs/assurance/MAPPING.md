# The invariant map

Phase 285 established this v1.79 assurance map; the Phase 286 repair adds
two dispatch-boundary invariants. Each row identifies an enforcing source point
in `swarm-policy`, `swarm-runtime`, `swarm-response` or `swarm-spine` where a
malformed, weak, unauthorized or unverified operation is **denied**.
`Path` is the exact `crate::module::function` resolved against the current source
tree by `tools/check-mapping.sh`. `Assumption` names the environmental or
primitive contract in `docs/assurance/assumptions.toml` that enforcement rests on.
Mapping synchronization is not proof that the new runtime tests passed or that
Phase 286 is accepted; its pending evidence is tracked in the DST section below.

Phase 285 Task 2 adds a `// INVARIANT: <Name>` comment at each `Source` call
site and a gate that keeps this table, those markers, and the real paths in
sync. `Name` is therefore a stable identifier, not prose. The gate checks
`Path` and `Name`, not the `Source` line numbers: those are approximate
reading hints, and the `// INVARIANT: <Name>` marker at the call site — not
the line number — is the authoritative, drift-proof locator (grep the
`Name`). A `Source` line may sit a line or two off as surrounding code shifts.

| Name | Crate | Path | Source | Assumption | Denies |
|---|---|---|---|---|---|
| `PolicyMalformedRequestRejected` | swarm-policy | `swarm_policy::static_gate::StaticApprovalGate::validate_request` | `crates/swarm-policy/src/static_gate.rs:56` | `ASSUME-NETWORK-TRANSPORT` | An `ActionRequest` whose evidence bundle is JSON `null`, or whose action-specific target/identifier field (`host_id`, `credential_id`, `domain`, `file_path`, ...) is empty or whitespace-only. |
| `PolicyHumanGateOnDestructiveAction` | swarm-policy | `swarm_policy::static_gate::StaticApprovalGate::evaluate` | `crates/swarm-policy/src/static_gate.rs:268,295-300` | `ASSUME-OS-CLOCK` | Unconditional automatic execution of a destructive action (`block_egress`, `isolate_host`, `kill_process`, ...) at or above the configured human-gate severity -- returns `RequireHuman` rather than `Allow`. |
| `PolicyScopeRateLimitDeniesBurst` | swarm-policy | `swarm_policy::static_gate::StaticApprovalGate::evaluate` | `crates/swarm-policy/src/static_gate.rs:209-229,291-293` | `ASSUME-OS-CLOCK` | An action whose target scope has already issued `max_actions_per_scope_per_minute` actions within the trailing 60 seconds of wall-clock time. |
| `RuntimeRequireHumanBlocksLiveExecution` | swarm-runtime | `swarm_runtime::SwarmRuntime::authorize_and_execute` | `crates/swarm-runtime/src/lib.rs:972,993-995` | `ASSUME-OS-CLOCK` | Executing a request whose policy verdict is `RequireHuman` while the runtime is running in `RuntimeMode::LiveResponse` -- no destructive action auto-executes live without a human-approved path. |
| `RuntimeDispatchIntentRequired` | swarm-runtime | `swarm_runtime::dispatch::SwarmRuntime::dispatch_once` | `crates/swarm-runtime/src/dispatch.rs:35` | `ASSUME-DISPATCH-DURABILITY` | An enforced adapter invocation without a configured durable dispatch journal and successfully persisted authorization intent; dry-run does not consume live dispatch permission. |
| `RuntimeDispatchIdentityConsumedOnce` | swarm-runtime | `swarm_runtime::dispatch_journal::DispatchJournal::reserve` | `crates/swarm-runtime/src/dispatch_journal.rs:285` | `ASSUME-DISPATCH-DURABILITY` | Reusing an already reserved requester/action/hunt identity, regardless of completion or changed request content; no reservation is evicted to permit retransmission. |
| `RuntimeLeaseMustBeActive` | swarm-runtime | `swarm_runtime::ensure_active_lease` | `crates/swarm-runtime/src/lib.rs:1416-1426` | `ASSUME-OS-CLOCK` | Executing a response through a `CapabilityLease` whose `expires_at_ms` has already passed. |
| `RuntimeContinuityProofSignatureInvalid` | swarm-runtime | `swarm_runtime::agent_identity::verify_continuity_proof` | `crates/swarm-runtime/src/agent_identity.rs:544-589` | `ASSUME-ED25519` | An agent-identity rotation continuity proof whose signature does not verify against the claimed previous ed25519 public key, or whose key/signature hex is malformed or mis-sized. |
| `RuntimeIdentityDerivedIdMismatch` | swarm-runtime | `swarm_runtime::agent_identity::FileAgentIdentityRegistry::admit_persisted_identity` | `crates/swarm-runtime/src/agent_identity.rs:337-354` | `ASSUME-ED25519` | Admitting a persisted agent identity whose claimed `AgentId` does not equal the ID derived from its own ed25519 signing key's public key. |
| `RuntimeKeystoreKeyIntegrity` | swarm-runtime | `swarm_runtime::agent_identity::FileAgentKeyStore::decode_key` | `crates/swarm-runtime/src/agent_identity.rs:234-244` | `ASSUME-KEYSTORE-ATOMICITY` | Loading a persisted agent signing key file whose contents are not exactly 32 raw seed bytes (rejects truncated, corrupt, or partially written key material). |
| `SpineEnvelopeHashMismatchRejected` | swarm-spine | `swarm_spine::envelope::verify_envelope` | `crates/swarm-spine/src/envelope.rs:114,140-145` | `ASSUME-SHA256` | An envelope whose recomputed SHA-256 hash over its canonical, unsigned body does not equal its claimed `envelope_hash` -- any tampering with envelope content after signing. |
| `SpineChainLinkIntegrityViolation` | swarm-spine | `swarm_spine::chain::verify_chain_link` | `crates/swarm-spine/src/chain.rs:75-150` | `ASSUME-SHA256` | An envelope that does not correctly continue its issuer's hash chain: wrong `prev_envelope_hash`, a sequence gap or regression, or a first envelope that isn't `seq=1` with a null previous hash. |
| `SpineEnvelopeIssuerMustBeEd25519Key` | swarm-spine | `swarm_spine::envelope::parse_issuer_pubkey_hex` | `crates/swarm-spine/src/envelope.rs:24-36` | `ASSUME-ED25519` | An envelope `issuer` string that is not exactly `swarm:ed25519:` followed by 64 hex characters -- a well-formed ed25519 public key encoding. |
| `SpineEnvelopeCanonicalizationRequired` | swarm-spine | `swarm_spine::envelope::envelope_signing_bytes` | `crates/swarm-spine/src/envelope.rs:43-45` | `ASSUME-CANONICAL-JSON` | Computing signing/hash bytes for an envelope body containing a JSON value that cannot be canonicalized (e.g. a non-finite `f64`), rather than silently substituting an arbitrary encoding. |
| `ResponseSandboxRequiresScopedLease` | swarm-response | `swarm_response::adapters::SandboxExecutor::execute` | `crates/swarm-response/src/adapters.rs:12-47` | `ASSUME-SUBPROCESS-ISOLATION` | Executing a destructive/containment-class response action when its `CapabilityLease` carries no `scope` -- an unbounded blast radius. |
| `ResponseHttpEdrEndpointRequired` | swarm-response | `swarm_response::http_edr::HttpEdrAdapter::new` | `crates/swarm-response/src/http_edr.rs:23-28` | `ASSUME-NETWORK-TRANSPORT` | Constructing (and thereby ever dispatching through) an HTTP EDR adapter whose configured endpoint URL is empty or whitespace-only. |
| `ResponseCrowdStrikeRtrBaseUrlRequired` | swarm-response | `swarm_response::crowdstrike_rtr::CrowdStrikeRtrAdapter::new` | `crates/swarm-response/src/crowdstrike_rtr.rs:35-40` | `ASSUME-NETWORK-TRANSPORT` | Constructing a CrowdStrike RTR adapter whose configured `base_url` is empty or whitespace-only. |

17 rows: 3 `swarm-policy`, 7 `swarm-runtime`, 4 `swarm-spine`, 3
`swarm-response`.

## Deterministic-simulation harness (DST, phase 286)

**Status: repaired local evidence recorded; full acceptance pending, 2026-09-07.** Candidate
`1a5c9003b` was rejected; its green seed counts do not prove the phase's safety
properties. See `.planning/phases/286-deterministic-simulation-testing/286-REVIEW.md`
and `286-02-PLAN.md` for the evidence and replacement acceptance contract.

The former harness checked that persisted receipt identities appeared among
observed dispatches. That reverse subset accepts an effect with no durable prior
record. Its dropped-episode disposition check could miss forbidden effects, its
at-most-once check omitted restart/redelivery, its seeds collapsed to four
effective schedules, and its reopen operation swapped in an empty in-memory
substrate. Those are missing proof obligations, not accepted evidence boundaries.

**Required production ordering.** Both `SwarmRuntime::authorize_and_execute` and
`audit_authorize_and_execute_instrumented_internal` must durably reserve the
immutable request identity and authorization intent before a live effect. The
runtime's audit wrappers route through the latter entry. Completion receipts
record observed post-effect outcomes. An authorization intent does not claim
completion, and an unresolved result never permits automatic redispatch.
Production composition must bind a bounded, fsynced, exclusive-writer journal to
the configured audit directory and preserve the store across runtime reload.
Corruption, conflicting identity reuse, unavailable storage and exhausted capacity
must close dispatch. Internal effectful retries must not bypass the reservation.
Current journal and dispatch-specific runtime unit tests and eleven composition
regressions pass.
The whole phase remains unaccepted because required network-enabled regressions
still need terminal evidence. All 17 registered negative tests and full workspace
Clippy pass; scoped final source review passed with the stated evidence limits.

**Three required oracles.** Every observed effect must have a matching durable
prior intent; the deterministic policy's forbidden outcomes must produce no
effects even if the caller's future is dropped; and each immutable request
identity must produce at most one effect over crash/reopen/redelivery histories.
Completion receipts must describe only observed outcomes. A crash can leave an
unresolved durable intent, which is reported as uncertainty rather than falsely
reported completion. The journal is unsigned and OS-protected; existing signed
audit artifacts remain separate and require their own verification.

**Harness and controls required for acceptance.** The replacement must drive real
runtime and gate entry points, a real sandbox effect adapter and a persistent
local-journal pheromone substrate. It must reopen the same storage, redeliver
requests, vary effective fault schedules, report the failing seed and support
`SWARM_DST_SEED=<n>` replay. The ordinary PR lane must run 64 seeds and
`.github/workflows/dst-nightly.yml` must run at least 5,000; distinct seed labels
alone do not establish distinct schedules. Production-source mutation controls
must make the normal harness reject effect-before-intent, duplicate dispatch and
forbidden effects after cancellation. Three independent production mutations at
`92df4f4c8` were rejected by their named safety oracles, and the restored positive
DST suite passed. At `af250a8e8`, the 64-seed suite passed with 53 yielded event
traces and 16 verdict/fault pairs; two explicit seed-57 replays matched exactly.
The 5,000-seed nightly run passed with 897 yielded event traces and all 18 pairs.
These trace counts include polling variation, not just crash/effect ordering;
requests run sequentially with one shared verdict per seed. Retained commands,
patches, source hashes and terminal logs are under the phase review evidence directory. These facts
do not claim full phase acceptance or passing network-enabled regressions.

**Evidence boundary.** The intended scope is single-host/process recovery over
one logical local persistent substrate, including closing and reopening that
same storage. Cancellation by future drop is not itself evidence of child-process
termination. Distributed JetStream failover, cross-node consensus, external
adapter exactly-once semantics, privileged filesystem tampering and durability
beyond the OS/filesystem fsync contract are not established by this harness.

## Loom concurrency models (phase 287)

LOOM-01/02 add two Loom harnesses over the engine's concurrent write paths. Loom
instruments only its own `loom::sync` types, not the production `std::sync`
locks / `arc_swap::ArcSwap` / `std::fs` these paths use, so each harness is an
**abstract** model of the seam reconstructed from reviewed Loom state, not an
instrumented run of the real code. Each is therefore labelled, exactly,
`scope = "bounded_abstract_model"`, and is bounded by a documented preemption
budget (`preemption_bound = 2`, `max_permutations`/`max_duration` left unset) run
by `.github/workflows/loom-nightly.yml`. These are model rows, not enforcement
call sites, so they are deliberately kept OUT of the invariant table above (whose
`Path` column `tools/check-mapping.sh` resolves to real source): a bounded
abstract model proves a concurrency argument, not a fail-closed source invariant.

- `crates/swarm-pheromone/tests/loom_concurrent_write.rs` — `scope = "bounded_abstract_model"`.
  Models concurrent deposit vs. decay-eviction (`gc_evaporated`) over the
  local-journal split-persistence seam (`swarm-pheromone/src/substrate.rs`
  `deposit`/`gc_evaporated` — the in-memory `deposits` vector lock and the JSONL
  journal). Establishes that holding the deposits lock across both the journal
  append and the in-memory push (the LOOM-01 repair) keeps a fresh deposit from
  being dropped by a concurrent journal rewrite. Bound to the production source by
  the non-Loom `concurrent_reopen_regression` in the same file, which fails iff
  the repair is reverted.
- `crates/swarm-policy/tests/loom_concurrent_decision.rs` — `scope = "bounded_abstract_model"`.
  Models concurrent decision-evaluation vs. ruleset reload. The policy crate has
  no reload op (`configurable_gate.rs:13,26` rebuild an immutable rule vector in a
  new gate); the real reload publishes separate `ArcSwap`s non-atomically in
  `swarm-ingest-runtime` (`ingest/mod.rs` `reload`), and the request path reads
  ONE held generation via a single `load_full()` (`ingest/mod.rs:146`). The model
  asserts a decision and its lease share one held runtime generation — NOT that
  all composition fields swap atomically — plus a supplemental last-slot atomic
  prune/check/increment under one mutex (`configurable_gate.rs:85`,
  `agent_limit_exceeded`).
