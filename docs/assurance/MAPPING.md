# The invariant map

Phase 285 (v1.79 assurance floor). Each row below is one fail-closed
invariant found by reading `swarm-policy`, `swarm-runtime`, `swarm-response`,
and `swarm-spine` for the source points where malformed, weak, unauthorized,
or unverified input is **denied** rather than defaulted open. `Path` is the
exact `crate::module::function` that enforces the invariant, verified to
exist at HEAD (see `.superpowers/sdd/285-01-PLAN/task-1-report.md` for the
grep proving each one). `Assumption` is the `docs/assurance/assumptions.toml`
ID the invariant rests on.

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

15 rows: 3 `swarm-policy`, 5 `swarm-runtime`, 4 `swarm-spine`, 3
`swarm-response`.
