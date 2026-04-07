# Phase 75: Approval Set Definition And Signed Ledgers

## Decisions

- Approval sets and ledger entries are persisted as file-backed JSON artifacts following the existing `FileXxxStore` pattern (root dir + reports/ + index.json)
- Ed25519 signing uses the existing `swarm-crypto` `Ed25519Signer` and `verify_detached_signature` APIs -- no new crypto dependencies
- Ledger entries are wrapped in `swarm-spine` signed envelopes for chain integrity, reusing `build_signed_envelope` and `verify_envelope`
- Threshold rules start with a simple `AtLeast { required: usize }` model -- no weighted voting or quorum algebra in this phase
- Voter identity is a public-key-based identifier string (the `swarm:ed25519:<hex>` format already used by spine issuers)
- All governance is single-node and local -- no distributed voting, no network transport
- New `approval` module added to `swarm-runtime` as a single file (`approval.rs`), not a sub-crate
- swarmctl gets new subcommands: `ApprovalSetCreate`, `ApprovalSetResult`, `ApprovalVoteAppend`, `ApprovalLedgerResult`, `ApprovalLedgerList`
- Authenticated HTTP surface gets new routes under `/v1/operator/approval-sets/` and `/v1/operator/approval-ledgers/`
- Approval set references a promotion evidence ID (string ref, not deeply validated in this phase)

## Deferred Ideas

- Weighted voting or complex quorum algebra (future milestone if needed)
- Distributed consensus or multi-node voting
- Automatic verdict assembly from ledger state (Phase 76)
- Receipt packs (Phase 76)
- Human-gate promotion integration (Phase 77)

## Claude's Discretion

- Internal naming of types and helper functions within the approval module
- Exact CLI output formatting (follow existing `render_*` patterns)
- Index ordering (newest-first, matching existing stores)
- Error variant naming within the approval error enum
