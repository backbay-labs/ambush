# 0011: Persist dispatch intent before the external effect

Date: 2026-09-07
Status: implementation under verification in Phase 286-02

## Problem

The Phase 286 candidate `1a5c9003b` records test-owned pheromone data after a
response and calls the final identity-subset check "receipt-before-action".
Cancellation after the effect passes without a receipt, and a restarted request
is never redelivered. This does not prove DST-03. Both production authorization
entry points previously invoked their response executor before returning audit
material to a caller for persistence.

## Decision

An enforced response must consume a durable dispatch permission before its
adapter future is polled. Both runtime authorization entry points use the same
`dispatch_once` function. Policy, human approval, guards, containment preparation
and capability expiry checks still precede this boundary. A missing, unavailable,
corrupt or full journal refuses execution. Dry runs remain free of side effects.

The durable record before an effect is an **authorization intent**, containing the
request and the capability issued by the gate. It does not assert that the action
happened. An adapter result is a separate **completion record** appended after the
adapter returns. No result may be fabricated when a future is dropped. The local
journal is unsigned and protected by the operating system; it does not replace
signed audit bundles or claim cross-host consensus.

The request identity is a domain-separated canonical hash of the hunt identifier,
requester and complete action. Renewed leases, timestamps, severity and mutable
evidence cannot manufacture a new identity for the same operation. A deliberately
new operation requires a new hunt/request context. A consumed identity is never
automatically removed or executed again, including after completion, cancellation,
process restart or configuration reload. A duplicate receives an explicit refusal,
not a newly minted success receipt.

The file journal has one locked writer shared through `Arc`, bounded record size,
entry count and total size, and no automatic eviction. Appends and their commit
checkpoint are synced before acknowledgement. Reopening validates the durable
history rather than silently skipping malformed or truncated records. Lock
ownership and the journal file identity are checked during writes. Replacing or
rolling back the entire trusted state directory is outside the single-process,
single-store fault model; independent replicated anti-rollback is not claimed.

Production configuration derives the journal location from durable audit storage.
Reload preserves its exact binding and cannot replace consumed history by changing
storage locations. Enforced adapters are invoked once: generic retries after a
timeout, transport error or HTTP failure are disabled because the remote effect
may already have happened. Adapter-specific protocol-level idempotency would need
its own evidence before retries could safely be restored.

## Consequences and acceptance

This chooses safety over automatic retry after uncertainty. A reservation can
survive even when cancellation occurred before the external effect. Such an
operation requires reconciliation; it must not become executable merely because
its outcome is absent. Bounded storage exhaustion also refuses new operations;
automatic truncation would destroy the no-double-dispatch guarantee.

The replacement DST harness must independently read the on-disk intent before a
sandboxed effect, preserve those effects across teardown, reopen the actual local
journal substrate and dispatch journal, and redeliver the same request. Deny and
RequireHuman prohibit effects even when no future returns a result. Negative
controls must expose reordered effects, forbidden effects during cancellation and
duplicate dispatch. The seed must change executed scheduling, yields, verdicts and
retry counts. Production reload tests and external-effect retry tests supplement
the deterministic corpus; none can substitute for the others.

Phase 286 remains in progress until the repair plan's acceptance table is backed
by executed evidence and independent review. The initial candidate's green seed
counts are not inherited as evidence for this change.
