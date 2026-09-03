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
  wiring, restart recovery, locked single-use `verify_and_import` generation/
  epoch/nonce/head CAS, and `HerdMemoryImportTicket` construction boundaries.
- Per-stream head/nonce/replay tombstones, GC sequence-reset refusal, explicit
  epoch transition, atomic lifecycle generations, and backend parity.
- Typed poisoning assessment/admission for signed malicious, equivocation,
  contradiction, quota, and local-falsification records, including proof that
  quarantine occurs before actionable indexing or task-order hints.
- Real `sphinx_agent.rs` export seam scanning, context/corroboration gates,
  advisory-only strategy ordering, and response/policy authority exclusion.
- Three-arm real-runtime benchmark through the Phase 288 Arena-owned
  `Phase287ArenaSynthesisAdapter` -> Phase 287 Blue bridge -> Runtime
  `ArenaSynthesisInput`/`ArenaSourceRef` contract, exact denominators/thresholds, withheld
  evaluator order, non-serializable post-freeze capability/provider boundary,
  Phase 287 exact tuple/known-set pin, Arena-owned literal tuple bytes/golden
  vector/sorted aggregate and derived attribution from the pinned
  `ArenaArtifactStore` ref, private evaluator-process tuple/fingerprint types,
  and the six closed `ArenaSourceRole` values with
  schema/canonical-ID/content/payload/partition digests, plus the detached
  source digest/selected source, fingerprint
  absence from candidate lineage, mutation controls, self-field-excluded digest canonicalization, exact
  `withheld_relative_gap_basis_points` report/parser/CI field, CI invocation,
  and `check-gates-wired.sh` evidence.
- Phase 286 ceiling provenance must resolve the accepted
  `.planning/phases/286-collective-hypothesis-graph/286-07B-SUMMARY.md`, its
  independent `286-P0-P2-REVIEW.md` and `286-VERIFICATION.md`, and retained
  `artifacts/phase286/collective-report-one.json`, with matching closure
  HEAD/tree and recomputed lowercase digests. The partial
  `286-VALIDATION-EVIDENCE.md` ledger is explicitly not closure evidence; a
  missing, pending, stale, or substituted artifact leaves the review open.
- Phase 288 upstream provenance must resolve the completed
  `.planning/phases/288-autonomous-detector-response-synthesis/288-VERIFICATION.md`
  closure artifact plus its independent review/validation records, matching
  closure HEAD/tree, zero open counters, and an adapter evidence ID resolving to
  `Phase287ArenaSynthesisAdapter` at `crates/swarm-arena/src/synthesis_adapter.rs`
  emitting `ArenaSynthesisInput` at `crates/swarm-runtime/src/synthesis/arena_input.rs`
  with all six source-role/lineage fields, plus recomputed lowercase
  closure/adapter digests; planned, pending, missing,
  substituted, or drifted closure leaves the review open.

## Final evidence fields

The two reviewer-assignment/provenance evidence IDs are required final fields.
They must resolve to separately root-signed, out-of-band records authored
outside the candidate tree and implementer;
the P0/P1/P2 counters are frontmatter-only and must not be duplicated in body
text or fenced examples.

Before finalization, Plan 07 must resolve two external pins from
`scenarios/herd-memory/upstream-contract-pins.yaml`: the out-of-band
root-signed assignment record at
`/run/ambush/phase289/review-root/assignment.v1.json` and provenance record at
`/run/ambush/phase289/review-root/provenance.v1.json`.
Each has schema/version, `out_of_band: true`, external path and digest, root key
ID/public-key digest/custody evidence, exact artifact kind, distinct
implementer/reviewer identities, assigned/reviewed `head` and `tree` values,
evidence ID, and a lowercase 64-hex self-field-excluded digest/signature. The
root-signed records prove assignment and review independently; a candidate-tree
Markdown file, implementer key, self-carried key, path substitution, missing,
pending, tampered, reviewer-authored, or head-mismatched record is refused.
The closure parser consumes these pins through the typed
`IndependentReviewProvenanceResolver::resolve_and_verify(ReviewRootPin, expected_head, expected_tree, implementer)`
boundary from Plan 07; only the external root/CI provider can return a private
verified record. It permits only the two exact `/run/ambush/phase289/review-root/`
paths, opens regular non-symlink bytes, verifies root custody/signature and the
self-field-excluded subject, and fails closed on path/digest/kind/schema/root/
author/head/tree drift or any candidate-tree/caller resolver substitution.

The completed artifact must record the independently verified Scope A
`CandidateFreezeReceipt` linkage before any evaluator/reviewer Scope B record:
its digest, canonical ArenaLineage digest, frozen tree/allowlist digests,
export-signer anchor digest, generation/predecessor/source-highwater, and the
matching signed evaluator-freeze receipt. These values are recomputed and
cross-checked rather than copied from review prose.

The completed artifact must record:

```text
implementer:
reviewer:
reviewer_assignment_evidence_id:
reviewer_provenance_evidence_id:
review_root_assignment_artifact_digest:
review_root_provenance_artifact_digest:
review_root_key_id:
review_root_public_key_digest:
review_root_out_of_band:
phase_286_closure_evidence_id:
phase_287_known_set_evidence_id:
phase_288_adapter_evidence_id:
evaluator_capability_evidence_id:
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
evaluator_artifact_pin_digest:
candidate_freeze_receipt_digest:
candidate_freeze_lineage_digest:
candidate_freeze_tree_digest:
candidate_freeze_allowlist_digest:
export_signer_anchor_digest:
signed_freeze_receipt_digest:
withheld_relative_gap_basis_points:
metric_schema_version: herd-memory-metrics-v1
evidence_coverage_bp:
evidence_coverage_covered:
evidence_coverage_required:
evidence_coverage_formula_id: floor_div_u128_v1
ci_gate_wired:
head_tree_oid:
tree_scope:
frozen_tree_digest:
frozen_tree_manifest_digest:
tree_manifest_digest:
allowlisted_paths:
unexpected_dirty_paths:
untracked_paths:
```
`reviewed_head`, `combined_tree_head`, `current_head`, `head_tree_oid`, and
their root-provenance counterparts are typed `GitObjectId` values using the
repository's actual object-hash algorithm; frozen/tree-manifest/artifact values
remain `Digest64`.
For this repository `GitObjectId` is `{algorithm: Sha1, hex: [u8; 40]}` and
parses only 40 lowercase hexadecimal characters from `git rev-parse`; uppercase,
`0x`, abbreviations, 64-hex SHA-256, and algorithm substitution are refused.

## Independent review row schema

Plan 07 must materialize exactly one row for every derived subject below in
this artifact and in `289-VERIFICATION.md`; prose coverage does not count:

```text
task:289-00W-01, task:289-00-01, task:289-00-02, task:289-00-03,
task:289-01-01, task:289-01B-01, task:289-01B-02, task:289-01C-01,
task:289-02-01, task:289-02-02, task:289-03-01, task:289-03-02,
task:289-04-01, task:289-04-02, task:289-05-01, task:289-05-02,
task:289-06-01, task:289-06-02, task:289-07-01,
requirement:HERDMEM-01, requirement:HERDMEM-02, requirement:HERDMEM-03,
requirement:HERDMEM-04, requirement:HERDMEM-05, requirement:HERDMEM-06,
upstream:phase-286-07B, upstream:phase-287-06, upstream:phase-288-07,
arm:memory_enabled, arm:single_agent, arm:no_memory,
control:three_arm_shared_inputs, control:empty_frozen_path,
control:withheld_process_isolation, control:poison_admission,
control:export_prepare_commit, control:import_deserialize_boundary,
artifact:<every must_haves.artifacts path>
```

The required mandatory-subject catalog is explicit and is linked into the
artifact rows rather than treated as prose:

```text
trust:issuer-root -> artifact:scenarios/herd-memory/upstream-contract-pins.yaml
trust:export-signer-anchor -> artifact:crates/swarm-spine/src/herd_memory_export_signer.rs
trust:evaluator-root -> artifact:/run/ambush/phase289/evaluator-v1/root.v1
review:review-root-assignment -> artifact:.planning/phases/289-herd-memory/289-P0-P2-REVIEW.md
review:review-root-provenance -> artifact:.planning/phases/289-herd-memory/289-VERIFICATION.md
validation:phase-289-validation -> artifact:.planning/phases/289-herd-memory/289-VERIFICATION.md
bridge:phase-287-arena-adapter -> owner_path:crates/swarm-arena/src/synthesis_adapter.rs -> consumer_artifact:artifact:crates/swarm-runtime/src/herd_memory_benchmark.rs
bridge:phase-288-runtime-dto -> owner_path:crates/swarm-runtime/src/synthesis/arena_input.rs -> consumer_artifact:artifact:crates/swarm-runtime/src/herd_memory_projection.rs
```

Bridge rows carry the canonical owner_path -> consumer_artifact mapping above,
with source paths
`crates/swarm-arena/src/synthesis_adapter.rs` and
`crates/swarm-runtime/src/synthesis/arena_input.rs`; every catalog entry has a
distinct evidence ID, owner, canonical digest binding, and mutation outcome.
The parser rejects an absent, duplicate, wrong-owner, wrong-path, or unlinked
catalog entry while retaining the exact 84-row cardinality.

The canonical artifact-path declarations are deduplicated by normalized path
for subject derivation (the Plan 00-owned baseline is also consumed by Plan
06), yielding exactly 47 unique artifact subjects; therefore the complete
subject set is exactly 84 rows (`19 task + 6 requirement + 3 upstream + 3 arm
+ 6 control + 47 artifact`). The parser rejects any count other than 84, duplicate rows or
duplicate canonical artifact subjects in the materialized evidence, or a row
whose `row_id` is not the deterministic `<category>:<subject>` identity.

Each row has exactly `row_id`, `category`, `subject`, `severity` (`P0|P1|P2|P3|none`),
`status` (`open|closed|not_applicable`), `evidence_id`, `command_id`,
`location`, `reviewer`, `recomputed_digest`, `disposition`,
`observed_exit_code`, `observed_status`, `observed_severity`,
`recomputed_status`, and `recomputed_severity`. The independent parser derives
the expected artifact rows from every plan's `must_haves`, recomputes
status/severity from machine-readable mutation outcomes, and rejects
author-provided severity/status strings or self-digests as authority. It rejects missing/duplicate
rows, unknown subjects, status/severity disagreement, missing command/evidence
links, stale digests, duplicate counters, or a reviewer equal to the
implementer. Root assignment/provenance rows are authored by
the external trusted root and are not authored in this candidate tree; the
implementation author cannot self-author a reviewer result. The final
frozen-tree row additionally binds the sorted allowlist
manifest, `HEAD^{tree}`, dirty/untracked rejection, and the unprefixed
`tools/sha256-root.sh` format-test evidence.
Mutation status/severity is recomputed from the exhaustive typed
`MutationOutcome` mapping: expected pass/reject -> `closed/none`, unexpected
pass -> `open/P1`, unexpected reject -> `open/P2`, missing/malformed evidence
or zero execution -> `open/P0`, and explicitly declared N/A ->
`not_applicable/P3`; unknown tags or author strings fail closed.

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
