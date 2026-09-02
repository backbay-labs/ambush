# Phase 286 Plan 03 Summary

## Delivered

- Added `HypothesisGraphStore`, `TaskStore`, and `StrategyMemoryStore` contracts with in-memory and signer-injected local-file backends.
- Persisted bounded, signed graph generations containing graph state, durable task state/history, predecessor revision, logical-time high-water, and fencing high-water.
- Made generic graph CAS task-preserving. Task changes are admitted only through typed create, claim, renew, expire, reclaim, complete, and fail operations. Terminal tombstones and retained attempts prevent a stale snapshot from resurrecting completed work.
- Added idempotent claims, lease-bound terminal operations, monotonic task generations, stream-bound lease IDs, fencing tokens, logical-time checks, and restart-safe expiry/reclaim behavior.
- Added signed strategy-memory generations with producer provenance, canonical deduplication, contiguous record chains, deterministic bounded top-k retrieval, and no raw telemetry or response authority.
- Enforced the same complete signed-envelope byte ceiling before both memory and file backends publish a mutation.
- Added Unix local-file hardening: private roots/files, no-follow and descriptor-relative I/O, bounded reads, nonblocking descriptor/type validation, lifetime root locks, per-store nonblocking parent commit tokens, atomic writes, directory `fsync`, lock-identity revalidation, durable append/rollback recovery, and refusal to reinitialize an existing incomplete namespace.
- Exported the new store types from `swarm-spine` and added the Unix `libc` dependency.

## Persistence protocol

Every file mutation holds the root and external-journal locks, validates the current signed state/head/high-water tuple, and checks the expected CAS revision. Before publishing the candidate, it stages the exact base state/head/high-water tuple and appends a signed external intent. It then writes the candidate state, signed head, and local high-water record; the signed external commit is the commit point. A restart encountering an intent without a commit restores and revalidates the staged base tuple through a durable rollback pointer and appends an abort. It never infers a commit from candidate files and never promotes a mutation whose API call returned an injected persistence error.

The local high-water log and sibling external journal each have a signed/hashed tail manifest and a durable append manifest. Data-record durability can therefore be recovered before tail validation after a crash between the two replacements. Sequence and predecessor links reject gaps, reordering, or valid-prefix truncation while the tail survives. Rotation writes a staged checkpoint data/tail pair, then a durable manifest; restart completes the manifest-selected replacement idempotently and subsequent appends count the active records rather than global sequence numbers. Graph and strategy-memory stores use the same intent/commit/abort, append, tail, and rotation protocol.

The namespace locks are advisory and protect cooperating writers. A noncooperating root rename can still let a descriptor-bound rename mutate the displaced directory before the final identity check returns an error; the pending transaction intent is rollback-only, so that returned-error candidate is not promoted when the namespace is restored and reopened. The sibling journal detects rollback only while its independently stored journal/tail survives. This local design does not claim protection against a same-user adversary that ignores locks and atomically restores or deletes every local state and anchor artifact, nor against filesystems that do not honor durability operations. Those threats require a non-writable parent namespace or an external monotonic service.

## Adversarial controls

| Control | Result |
| --- | --- |
| Generic-CAS task resurrection | Refused; task/tombstone changes require typed task transitions. |
| Claim duplication and stale workers | Idempotent retries return the original result; stale generation, lease, actor, fence, and terminal attempts are refused. |
| Crash boundaries | Injected failure after external intent, state, head, and high-water restores the base tuple for graph and strategy memory. |
| Append/rollback boundaries | Durable append recovery covers local and external logs; rollback recovery is injected after each state/head/high-water replacement for both stores. |
| Returned-error promotion | Pending intent recovery is rollback-only and records an abort; no later reopen commits it. |
| Root rollback and valid-prefix truncation | Signed head/high-water checks and independent journal tail reject surviving-anchor rollback and truncated journal prefixes. |
| Journal exhaustion | Local and external logs rotate through staged checkpoint manifests; graph and strategy-memory manifest-boundary recovery is tested. |
| Signed-envelope size boundary | A test-only per-thread ceiling drives boundary-1/boundary/boundary+1 for graph and strategy-memory signed envelopes; memory/file rejection classes match and rejected calls leave state, files, and journals byte-identical. |
| Memory/file parity | Both backends use the same validation, signing, complete-envelope size admission, and logical mutation paths. |
| Namespace replacement | Descriptor/path/generation checks and per-store nonblocking parent tokens refuse cooperating second writers and fail closed on detected replacement. |
| Lock-file substitution | Symlink, non-regular descriptor, insecure mode, and lock contention paths fail closed without blocking on FIFO/device substitutions. |
| Retrieval allocation | Strategy-memory retrieval retains at most `k` candidates (`k <= 256`) and sorts only that bounded set. |
| Privacy/authority boundary | Strategy memory contains typed graph abstractions only and cannot execute or authorize containment. |

## Verification

- `cargo test -p swarm-spine --all-targets --no-default-features --locked --offline` — 77 unit tests and 17 integration/negative tests passed.
- Fully qualified append-manifest, newline-delimiter, rollback-pointer, graph/strategy rotation-count, displaced-root, parent-token, same-handle serialization, transaction-recovery, task-resurrection, prefix-truncation, and namespace-race tests each executed with a nonzero test count and passed.
- `cargo clippy -p swarm-spine --all-targets --no-default-features --locked --offline -- -D warnings` — passed.
- `cargo fmt --all -- --check` — passed.
- `git diff --check` — passed.

Changes are limited to `Cargo.lock`, the `swarm-spine` manifest/exports, the two new store modules, and this summary; concurrent planning edits were preserved.
