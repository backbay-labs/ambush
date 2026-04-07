---
phase: 76-approval-verdict-and-receipt-packs
created: "2026-04-05"
---

# Phase 76: Approval Verdict And Receipt Packs

## What We Are Building

Two new capabilities in the approval governance lane:

1. **Verdict evaluation**: A pure, deterministic function that takes an approval ledger (from Phase 75) and its threshold rules and produces an approved/not-approved verdict. The same inputs always produce the same result.

2. **Receipt pack export**: A signed, portable artifact that bundles the approval set, all ledger entries, the final verdict, and audit references into one package. Signed with swarm-crypto Ed25519, independently verifiable without local store access.

## Why

Phase 75 creates approval sets (who can vote, what threshold is needed) and signed ledger entries (individual signed votes). But Phase 75 stops at accumulation -- it can tell you the current vote count versus threshold, but it does not produce a final verdict artifact or a portable proof of the approval chain.

Phase 76 closes that gap: evaluate the ledger into a verdict, then export the entire chain as one signed receipt pack that downstream consumers (Phase 77 promotion integration) and external verifiers can use.

## Decisions

- Verdict evaluation is a pure function: no side effects, no store mutations, deterministic from inputs
- Receipt packs are signed using swarm-crypto Ed25519 (DetachedSignature pattern) over canonical JSON
- Receipt packs are self-contained: they carry all approval set, ledger, and verdict data needed for independent verification
- Follow the existing module pattern: types + FileStore + Harness + render functions in a single runtime module
- New swarmctl subcommands: `ApprovalVerdictCreate`, `ApprovalVerdictResult`, `ApprovalReceiptPackExport`, `ApprovalReceiptPackResult`
- Store paths follow convention: `data/approval-verdicts/` and `data/approval-receipt-packs/`

## Deferred Ideas

- HTTP API endpoints for verdict and receipt pack operations (Phase 77 or later)
- Distributed verification or multi-node receipt exchange
- Receipt pack revocation or expiry semantics

## Dependencies

- **Phase 75** (must ship first): Provides `ApprovalSet`, `ApprovalLedger`, `ApprovalLedgerEntry`, threshold types, and their FileStores
- **swarm-crypto**: Ed25519 signing, canonical JSON, SHA-256 hashing
- **swarm-spine**: Envelope patterns (reference, not direct reuse -- receipt packs are a different artifact shape)
