---
phase: 289-herd-memory
artifact: goal-backward-verification
status: planned
open_p0: 0
open_p1: 0
open_p2: 0
---

# Phase 289 Goal-Backward Verification Contract

This artifact defines the final evidence map. It is not a claim that the
implementation or full gate has run. Its frontmatter has one temporary
`status: planned` line; Plan 289-07-01 must replace that single line with
`status: complete` and fill the command, head, digest, identity, provenance,
and result fields from the combined tree. The body intentionally contains no
second status key; the closure checker requires exactly one anchored status
line and rejects planned, pending, TBD, duplicate, or malformed values.

| Requirement | Required executable evidence | Final result |
|---|---|---|
| HERDMEM-01 | Typed allowlist/privacy tests, nested mutation oracle, resolver tenant/export-namespace/key-epoch separation, and real Sphinx export-boundary scan | pending execution |
| HERDMEM-02 | Registry admission, durable rotation/revocation restart test, `VerifiedHerdMemory`, envelope/nonce/strict-chain mutation suite | pending execution |
| HERDMEM-03 | Local corroboration/context/contradiction integration and advisory authority negative suite | pending execution |
| HERDMEM-04 | Three-arm real replay benchmark with Plan 00-pinned outcomes/denominators and deterministic repeatability | pending execution |
| HERDMEM-05 | Atomic lifecycle/backend parity, expiry/revocation/quarantine, tombstone-first GC, stream replay-fence and epoch-transition tests | pending execution |
| HERDMEM-06 | Evaluator-only withheld scoring, canonical unseen-evasion fingerprint, exact threshold/mutation gate, CI and gate-wiring checks | pending execution |

## Required final fields

The two reviewer-assignment/provenance evidence IDs are required final fields.
They must resolve to root-controlled records authored outside the implementer;
the P0/P1/P2 counters are frontmatter-only and must not be duplicated in body
text or fenced examples.

The completed artifact must include distinct implementer/reviewer identities,
the reviewed/combined/current heads, exact nonempty commands, findings,
dispositions, provenance, canonical `semantic_truth_sha256`,
`baseline_sha256`, source/memory/withheld digests, deterministic report digests
from two runs, CI workflow evidence, mutation results, and the independent
review link. It must preserve the candidate-facing rule that only withheld
version/digest crosses the boundary; withheld content, IDs,
tactic/technique/primitive/order/timing inputs, expected fingerprints, and
per-case content digests are evaluator-only. The final gate must revalidate
that the public baseline contains none of that withheld expected material and
that no candidate/importer capability can open the evaluator manifest/resolver
before freeze. It must also revalidate the self-field-excluded canonical digest
rule and carry `withheld_relative_gap_basis_points` through the evaluator report,
parser, benchmark, and CI evidence without accepting a legacy alias.

```text
review_artifact: .planning/phases/289-herd-memory/289-P0-P2-REVIEW.md
implementer:
reviewer:
reviewer_assignment_evidence_id:
reviewer_provenance_evidence_id:
reviewed_head:
reviewed_at_logical_or_commit:
commands:
combined_tree_head:
current_head:
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

The final gate must reject `status: planned`, missing or empty fields, equal
implementer/reviewer identities, `reviewed_head != combined_tree_head !=
current HEAD`, digest drift, absent executed commands/findings/dispositions/
provenance, public withheld-fingerprint/per-case-digest material, pre-freeze
evaluator capability access, or any nonzero open counter. Local evidence must
not be described as hosted or release evidence. The final serialized gate
field must be the literal boolean `ci_gate_wired: true`, never a quoted string
or another truthy spelling.
