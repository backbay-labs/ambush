---
phase: 289-herd-memory
artifact: independent-p0-p2-review
status: planned
open_p0: 0
open_p1: 0
open_p2: 0
---

# Phase 289 Independent P0/P1/P2 Review Contract

This artifact is the required final-review shape, not execution evidence yet.
Its frontmatter has one temporary `status: planned` line so the pre-execution
contract cannot be mistaken for closure. Plan 289-07-01 must replace that
single frontmatter value with `status: complete` and fill distinct implementer
and reviewer identities, the combined-tree/current head, executed commands,
findings, dispositions, provenance, and artifact digests after all
implementation plans are complete. Plan 289-07-01 owns this finalization. The body intentionally contains no second
status key. The closure gate must reject this file unless the final review is
independently authored, all required evidence is nonempty,
`reviewed_head == combined_tree_head == git rev-parse HEAD`, exactly one
anchored status line exists and equals `status: complete`, and all three
counters remain zero.

## Required review scope

The reviewer must inspect the combined diff and evidence for:

- Plan 00 ownership of semantic expected outcomes, metric denominators,
  canonical tactic/technique/primitive/order/timing unseen-evasion fingerprints,
  evaluator-only isolation, and pinned baseline/fixture digests.
- Typed privacy allowlist, tenant/export-namespace HMAC resolver binding,
  resolver rotation/retirement, and absence of raw telemetry or authority.
- Durable registry generation, rotation/revocation history, config-to-importer
  wiring, restart recovery, and `VerifiedHerdMemory` construction boundaries.
- Per-stream head/nonce/replay tombstones, GC sequence-reset refusal, explicit
  epoch transition, atomic lifecycle generations, and backend parity.
- Real `sphinx_agent.rs` export seam scanning, context/corroboration gates,
  advisory-only strategy ordering, and response/policy authority exclusion.
- Three-arm real-runtime benchmark, exact denominators/thresholds, withheld
  evaluator order, fingerprint absence from candidate lineage, mutation controls,
  self-field-excluded digest canonicalization, exact
  `withheld_relative_gap_basis_points` report/parser/CI field, CI invocation,
  and `check-gates-wired.sh` evidence.

## Final evidence fields

The two reviewer-assignment/provenance evidence IDs are required final fields.
They must resolve to root-controlled records authored outside the implementer;
the P0/P1/P2 counters are frontmatter-only and must not be duplicated in body
text or fenced examples.

The completed artifact must record:

```text
implementer:
reviewer:
reviewer_assignment_evidence_id:
reviewer_provenance_evidence_id:
reviewed_head:
combined_tree_head:
current_head:
reviewed_at_logical_or_commit:
commands:
findings:
dispositions:
provenance:
semantic_truth_sha256:
baseline_sha256:
in_sample_corpus_sha256:
memory_set_sha256:
withheld_corpus_sha256:
deterministic_report_sha256_run_1:
deterministic_report_sha256_run_2:
withheld_relative_gap_basis_points:
ci_gate_wired:
```

Every final field above must be nonempty except the counters, which must be
literal zero. The implementer and reviewer must be distinct identities, and
the three head fields must equal the current combined-tree `HEAD`. `commands`
must list nonempty commands that actually ran; findings, dispositions,
provenance, and all digest fields must link to the executed evidence and
immutable Plan 00 public/evaluator-capability artifacts. The review must also
assert that the public baseline contains no withheld expected fingerprint or
per-case digest, and that evaluator fingerprints/resolver access are available
only through the post-freeze evaluator capability. Any empty evidence,
same-identity review, changed head, missing digest, or nonzero P0/P1/P2 counter
is an open gate. The final serialized value must be the literal boolean
`ci_gate_wired: true`; quoted strings or truthy synonyms are invalid. No local
test result may be represented as hosted or release evidence.
