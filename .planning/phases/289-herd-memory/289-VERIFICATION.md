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
| HERDMEM-02 | Registry admission, durable rotation/revocation restart test, locked single-use `verify_and_import` CAS with generation/epoch/nonce/head race tests, envelope/nonce/strict-chain mutation suite | pending execution |
| HERDMEM-03 | Local corroboration/context/contradiction integration, typed poisoning admission/quarantine fixtures, and advisory authority negative suite | pending execution |
| HERDMEM-04 | Three-arm real Phase 287 Blue-bridge benchmark through Phase 288's Arena-owned `Phase287ArenaSynthesisAdapter`, consuming Runtime `ArenaSynthesisInput`/`ArenaSourceRef` with Plan 00-pinned outcomes/denominators and deterministic repeatability | pending execution |
| HERDMEM-05 | Atomic lifecycle/backend parity, expiry/revocation/quarantine, signed poisoning/equivocation/quota/local-falsification admission, tombstone-first GC, stream replay-fence and epoch-transition tests | pending execution |
| HERDMEM-06 | Phase 286/287/288 pin validation, Arena-owned `Phase287ArenaSynthesisAdapter` -> Runtime `ArenaSynthesisInput`/`ArenaSourceRef` contract with exact Phase 287 tuple and six closed roles, non-serializable post-freeze evaluator capability, evaluator-only withheld scoring, exact threshold/mutation gate, CI and gate-wiring checks | pending execution |

## Required final fields

The two reviewer-assignment/provenance evidence IDs are required final fields.
They must resolve to separately root-signed, out-of-band records authored
outside the candidate tree and implementer;
the P0/P1/P2 counters are frontmatter-only and must not be duplicated in body
text or fenced examples.

Root-controlled inputs are external artifacts pinned in
`scenarios/herd-memory/upstream-contract-pins.yaml`, not files in the candidate
tree: `/run/ambush/phase289/review-root/assignment.v1.json` and
`/run/ambush/phase289/review-root/provenance.v1.json`. Each has schema/version, `out_of_band: true`, exact artifact kind,
external path/digest, root key ID/public-key digest/custody evidence, distinct
implementer/reviewer identities, assigned/reviewed head/tree, an evidence ID,
and a lowercase 64-hex self-field-excluded assignment/provenance digest plus
root signature. The closure parser verifies the external root signature and
re-hashes both records, rejecting absence, tamper, candidate-tree/path
substitution, author collision, ID mismatch, or head drift. The final artifact also links the
accepted Phase 286 closure/report pin
(`.planning/phases/286-collective-hypothesis-graph/286-07B-SUMMARY.md`, its
independent `286-P0-P2-REVIEW.md` and `286-VERIFICATION.md`, and retained
`artifacts/phase286/collective-report-one.json`, bound to the recorded closure
HEAD/tree and lowercase digests; the partial `286-VALIDATION-EVIDENCE.md`
ledger is not closure evidence), the Phase 287
known-set/tuple pin, the Arena-owned literal tuple bytes/golden vector/sorted
aggregate and derived attribution from its pinned `ArenaArtifactStore` ref, the
private evaluator-process tuple/fingerprint types, and the Phase 288 Arena-owned `Phase287ArenaSynthesisAdapter`
at `crates/swarm-arena/src/synthesis_adapter.rs` emitting Runtime
`ArenaSynthesisInput`/`ArenaSourceRef` from
`crates/swarm-runtime/src/synthesis/arena_input.rs` with exact role/schema/
canonical-ID/content/payload/partition digests, plus the detached source
digest/selected source, and completed
`.planning/phases/288-autonomous-detector-response-synthesis/288-VERIFICATION.md`
closure pin (plus its independent review/validation records), and post-freeze
evaluator-capability issuance evidence from
`scenarios/herd-memory/upstream-contract-pins.yaml`.
Resolution is through Plan 07's typed
`IndependentReviewProvenanceResolver::resolve_and_verify(ReviewRootPin, expected_head, expected_tree, implementer)`
boundary only: it accepts the two exact external paths, regular non-symlink
bytes, independent root custody/signature, and self-field-excluded canonical
subjects, and returns a private verified record or a typed refusal. No
candidate-tree Markdown, caller resolver, path substitution, root replacement,
or implementer-authored pin is accepted.

The completed artifact must first verify the independently root-signed Scope A
`CandidateFreezeReceipt` and carry its receipt, canonical ArenaLineage,
frozen-tree/allowlist, export-signer-anchor, generation/predecessor/
source-highwater, and signed evaluator-freeze linkage digests; the evaluator
and review records must match those values before Scope B is accepted. These
values are recomputed from self-field-excluded bytes, not copied from prose.

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
phase_286_closure_evidence_id:
phase_287_known_set_evidence_id:
phase_288_adapter_evidence_id:
evaluator_capability_evidence_id:
review_root_assignment_artifact_digest:
review_root_provenance_artifact_digest:
review_root_key_id:
review_root_public_key_digest:
review_root_out_of_band:
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

## Structured independent closure coverage

The final parser must emit exactly one structured `review_row` for each task,
requirement, declared artifact, upstream closure pin, arm, and control below in
both this artifact and `289-P0-P2-REVIEW.md`:

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

Every row is exactly `{row_id, category, subject, severity, status,
evidence_id, command_id, location, reviewer, recomputed_digest, disposition,
observed_exit_code, observed_status, observed_severity, recomputed_status,
recomputed_severity}`. The parser recomputes expected subjects from all eleven
plan frontmatters, recomputes status/severity from machine-readable mutation
outcomes, and rejects author-provided severity/status strings or self-digests;
it rejects missing/duplicate rows or subjects, mismatched status/severity,
missing command/evidence links, stale digests, and any reviewer authored by the implementer. The upstream rows must
resolve exact 286-07B/287-06/288-07 closure summaries and independent review/
verification/validation evidence, not the partial Phase 286 validation ledger
or path strings. The final provenance row binds a canonical sorted frozen-tree
allowlist, `git rev-parse --verify HEAD`, `git rev-parse --verify HEAD^{tree}`,
dirty/untracked rejection, and the single unprefixed lowercase-64
`tools/sha256-root.sh` helper.
Mutation status/severity is recomputed from the exhaustive typed
`MutationOutcome` mapping: expected pass/reject -> `closed/none`, unexpected
pass -> `open/P1`, unexpected reject -> `open/P2`, missing/malformed evidence
or zero execution -> `open/P0`, and explicitly declared N/A ->
`not_applicable/P3`; unknown tags or author strings fail closed.

The final gate must reject `status: planned`, missing or empty fields, equal
implementer/reviewer identities, `reviewed_head != combined_tree_head !=
current HEAD`, digest drift, absent executed commands/findings/dispositions/
provenance, public withheld-fingerprint/per-case-digest material, pre-freeze
evaluator capability access, or any nonzero open counter. Local evidence must
not be described as hosted or release evidence. The final serialized gate
field must be the literal boolean `ci_gate_wired: true`, never a quoted string
or another truthy spelling.
