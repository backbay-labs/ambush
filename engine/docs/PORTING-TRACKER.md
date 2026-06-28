# Porting Tracker

Status of upstream code assimilation into STS-native crates.

Last reviewed: 2026-04-04

## swarm-crypto (stub — needs hush-core)

Source: `vendor/reference/clawdstrike/libs/hush-core/src/`

| Upstream File | Lines | Target | Status | Notes |
|---|---|---|---|---|
| `signing.rs` | 337 | `swarm-crypto/src/signing.rs` | Not started | Ed25519 keypair, sign/verify. Direct copy. |
| `canonical.rs` | 224 | `swarm-crypto/src/canonical.rs` | Not started | RFC 8785 canonical JSON. Direct copy. |
| `merkle.rs` | 312 | `swarm-crypto/src/merkle.rs` | Not started | RFC 6962 Merkle tree + inclusion proofs. Direct copy. |
| `hashing.rs` | 154 | `swarm-crypto/src/hashing.rs` | Not started | SHA-256, Keccak-256. Direct copy. |
| `error.rs` | 65 | `swarm-crypto/src/error.rs` | Not started | Trim TPM-specific variants. |
| `receipt.rs` | 600+ | `swarm-crypto/src/receipt.rs` | Not started | Verdict, Provenance, SignedReceipt. Copy if audit signing needed. |

New workspace dep needed: `ryu` (canonical JSON number formatting).

## swarm-guard (stub — needs clawdstrike guards)

Source: `clawdstrike/crates/libs/clawdstrike/src/guards/` (live repo, not vendor snapshot — async guards and spider sense are not vendored)

### Core framework

| Upstream File | Target | Status | Notes |
|---|---|---|---|
| `guards/mod.rs` (trait + types) | `swarm-guard/src/lib.rs` | Not started | Guard trait, GuardAction, GuardResult, GuardContext. Simplify: drop org/session context, keep agent_id. |
| `spider_sense.rs` | `swarm-guard/src/spider_sense.rs` | Not started | Cosine similarity detector. Pure, sync, WASM-safe. |
| `rulesets/patterns/s2bench-v1.json` | `swarm-guard/data/s2bench-v1.json` | Not started | 36-entry pattern DB with 3-dim embeddings. |

### Guard implementations (copy selectively)

| Guard | Upstream File | Lines | Priority | Swarm Use |
|---|---|---|---|---|
| ForbiddenPathGuard | `forbidden_path.rs` | 18.4K | High | Prevent response actions from touching credential files |
| ShellCommandGuard | `shell_command.rs` | 14.2K | High | Block destructive commands in response execution |
| SecretLeakGuard | `secret_leak.rs` | 24K | High | Catch secrets in response action arguments |
| EgressAllowlistGuard | `egress_allowlist.rs` | 23.8K | Medium | Control what hosts response adapters can reach |
| PromptInjectionGuard | `prompt_injection.rs` | 8.9K | Low | Future — when LLM integration arrives |
| JailbreakGuard | `jailbreak.rs` | 10.9K | Low | Future — when LLM integration arrives |

Adaptation: `GuardAction` needs swarm's `ResponseAction` variants (IsolateHost, BlockEgress, RevokeCredential) alongside clawdstrike's existing action types.

## swarm-spine (partial — needs envelope/checkpoint from spine)

Source: `vendor/reference/clawdstrike/libs/spine/src/`

Existing swarm-spine code (incident.rs, investigation.rs, store.rs) stays unchanged. New modules add cryptographic commitment on top.

| Upstream File | Target | Status | Notes |
|---|---|---|---|
| `envelope.rs` | `swarm-spine/src/envelope.rs` | Not started | Signed fact messages, canonical JSON hashing, chain linking. |
| `checkpoint.rs` | `swarm-spine/src/checkpoint.rs` | Not started | Checkpoint statements, witness co-signing, quorum validation. |
| `chain.rs` | `swarm-spine/src/chain.rs` | Not started | Hash chain link verification. |
| `trust.rs` | `swarm-spine/src/trust.rs` | Not started | Trust bundles, allowlists, quorum config. Optional. |
| `attestation.rs` | `swarm-spine/src/attestation.rs` | Not started | SPIFFE/K8s bindings. Defer unless needed. |

## swarm-consensus (stub — no upstream source)

ClawdStrike has checkpoint witness quorum validation but no BFT consensus rounds. The checkpoint signing pattern in `spine/checkpoint.rs` is a useful reference for vote encoding, but propose/prevote/precommit state machine must be built from scratch or ported from an external BFT library.

Status: Deferred. Not blocking current milestones.

## Arc as complementary source

See [ARC-UPSTREAM.md](ARC-UPSTREAM.md) for items better sourced from `../arc/` than clawdstrike.
