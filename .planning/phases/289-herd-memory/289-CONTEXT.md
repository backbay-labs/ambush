# Phase 289 Context: Herd Memory

## Objective

Transfer learned attack abstractions between swarms without sharing raw telemetry or creating a single publisher whose memory can authorize local action. Memory should improve the next investigation while preserving local corroboration and revocation control.

## Required shape

- Export typed attack abstractions, causal motifs, detector/response outcomes, and strategy utility only. Raw telemetry, secrets, host identifiers, and operator credentials are prohibited by schema and export tests.
- Every record carries version, signer/provenance lineage, source-corpus digest, confidence, expiry, and transformation history. Import rejects tampered, replayed, stale, schema-invalid, or privacy-violating records with a durable refusal reason.
- A receiving swarm requires independent local corroboration before peer memory affects prioritization. Conflicting memories remain visible as contradictions; no single publisher raises confidence or authorizes containment.
- Retrieval changes task ordering only when the memory context matches the current graph and evidence. It cannot bypass hypothesis adjudication, policy, receipts, approval, or response adapters.
- Retention, expiry, revocation, poisoning quarantine, and operator deletion are restart-safe. Garbage collection removes expired payloads and dependent indexes without actionable orphan state.

## Measurement contract

Compare memory-enabled, single-agent, and no-memory controls on hypothesis time, chain recall, false causal edges, duplicate work, and evidence coverage. Pass with checked-integer time improvement `>= 2,000 bp` OR chain-recall improvement `>= 1,000 bp`, false edges `<= 1,000 bp`, duplicate work `<= 500 bp`, at least one previously unseen evasion across the withheld corpus, and withheld-campaign relative gap `<= 500 bp` versus in-sample. No float or wall-clock-only comparison is acceptance evidence.
