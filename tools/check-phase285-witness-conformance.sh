#!/usr/bin/env bash
# Exact, non-vacuous Phase 285 witness conformance selector runner.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PHASE285_WITNESS_TEMP_DIR=""
PHASE285_RELEASE_PROBE_RECEIPT_ROOT=""
PHASE285_RELEASE_PROBE_RECEIPT_TOKEN=""
PHASE285_RELEASE_PROBE_RECEIPT_SHA=""
cleanup_temp_dir() {
  if [ -n "$PHASE285_WITNESS_TEMP_DIR" ]; then
    local target="$PHASE285_WITNESS_TEMP_DIR"
    PHASE285_WITNESS_TEMP_DIR=""
    rm -rf -- "$target" || {
      echo "Phase 285 scratch cleanup failed: $target" >&2
      return 1
    }
    [ ! -e "$target" ] || {
      echo "Phase 285 scratch cleanup left its target behind: $target" >&2
      return 1
    }
  fi
}

cleanup_temp_dir_on_exit() {
  local exit_code=$?
  cleanup_temp_dir || exit_code=1
  trap - EXIT
  exit "$exit_code"
}

phase285_create_confined_scratch() {
  local prefix="$1" parent="${2:-${TMPDIR:-/tmp}}"
  python3 -I - "$ROOT_DIR" "$parent" "$prefix" <<'PY'
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
parent = pathlib.Path(sys.argv[2]).resolve(strict=True)
prefix = sys.argv[3]
environment = os.environ.copy()
environment["GIT_OPTIONAL_LOCKS"] = "0"
environment["GIT_NO_REPLACE_OBJECTS"] = "1"

def git_boundary(argument):
    result = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", argument],
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise SystemExit(f"PHASE285-SCRATCH[git-boundary]:{argument}")
    return pathlib.Path(result.stdout.strip()).resolve(strict=True)

boundaries = [root, git_boundary("--git-dir"), git_boundary("--git-common-dir")]
scratch = pathlib.Path(tempfile.mkdtemp(prefix=f"{prefix}.", dir=parent)).resolve(strict=True)
if any(scratch.iterdir()):
    shutil.rmtree(scratch)
    if scratch.exists():
        raise SystemExit("PHASE285-SCRATCH[nonempty-cleanup-failed]")
    raise SystemExit("PHASE285-SCRATCH[nonempty-new-directory]")

def within(child, ancestor):
    try:
        child.relative_to(ancestor)
        return True
    except ValueError:
        return False

if any(within(scratch, boundary) or within(boundary, scratch) for boundary in boundaries):
    scratch.rmdir()
    if scratch.exists():
        raise SystemExit("PHASE285-SCRATCH[boundary-cleanup-failed]")
    raise SystemExit("PHASE285-SCRATCH[boundary-overlap]")
print(scratch)
PY
}

phase285_scratch_hostile_controls() {
  local site="$1" boundary output exit_code rejected=0
  local boundaries=(
    "$ROOT_DIR"
    "$(git rev-parse --path-format=absolute --git-dir)"
    "$(git rev-parse --path-format=absolute --git-common-dir)"
  )
  for boundary in "${boundaries[@]}"; do
    exit_code=0
    output="$(TMPDIR="$boundary" phase285_create_confined_scratch "$site-hostile" 2>&1)" || exit_code=$?
    [ "$exit_code" -ne 0 ] && [ "$output" = "PHASE285-SCRATCH[boundary-overlap]" ] || {
      echo "Phase 285 hostile TMPDIR was not refused: site=$site boundary=$boundary output=$output" >&2
      return 1
    }
    rejected=$((rejected + 1))
  done
  echo "phase285_scratch_self_test site=$site boundaries=$rejected passed=1"
}

selectors() {
  cat <<'EOF'
response-failure-wire
candidate-verifier
protocol-checkpoint
atomic-store-contract
in-memory-differential
typed-proxy
transport-layering
jetstream-cas
jetstream-checkpoint
public-dispatcher
full-service-path
service-checkpoint
EOF
}

selector_rows() {
  case "$1" in
    response-failure-wire) cat <<'EOF'
response_failure_wire_binds_operation_and_request_digest
failure_retryability_is_derived_from_code
response_decoder_rejects_unknown_fields_or_unsigned_success
failure_store_state_digest_binds_current_snapshot_and_rejects_unproved_absence
EOF
      ;;
    candidate-verifier) cat <<'EOF'
candidate_verifier_accepts_exact_candidate_without_mutation
candidate_verifier_rejects_each_field_mutation_without_store_change
candidate_verifier_rejects_stale_session_authorization_and_bounds_without_store_change
EOF
      ;;
    protocol-checkpoint) cat <<'EOF'
protocol_checkpoint_rejects_unverified_prepare_and_accepts_only_one_step_transition
response_failure_maps_each_matchable_protocol_error
canonical_response_round_trip_preserves_signing_preimage
EOF
      ;;
    atomic-store-contract) cat <<'EOF'
atomic_store_contract_rejects_zero_revision_and_unvalidated_transition
atomic_store_contract_confirms_revision_and_bytes
atomic_store_contract_enforces_manifest_bounds
EOF
      ;;
    in-memory-differential) cat <<'EOF'
in_memory_differential_matches_reference_for_every_operation
in_memory_store_preserves_bytes_after_refusal
in_memory_faults_return_ambiguous_without_guessing
in_memory_capacity_exhaustion_is_pre_mutation
EOF
      ;;
    typed-proxy) cat <<'EOF'
typed_proxy_rejects_signature_body_header_and_revision_mutations
typed_proxy_delegates_only_after_canonical_validation
typed_proxy_preserves_reference_outcomes
EOF
      ;;
    transport-layering) cat <<'EOF'
transport_layering_rejects_governance_reverse_dependency
transport_layering_rejects_raw_kv_subject
transport_layering_rejects_second_governor_signer
transport_layering_rejects_unrelated_authority_crate
transport_layering_rejects_missing_library_target
transport_layering_rejects_zero_or_omitted_mutation
EOF
      ;;
    jetstream-cas) cat <<'EOF'
jetstream_cas_rejects_raw_config_unknown_field_or_persist_mode
jetstream_cas_rejects_each_raw_config_mutation
jetstream_cas_rejects_wrong_revision_header_or_ack
jetstream_cas_confirms_raw_sequence_and_bytes
jetstream_cas_rejects_del_purge_rollup_and_direct_reads
EOF
      ;;
    jetstream-checkpoint) cat <<'EOF'
jetstream_checkpoint_survives_restart_for_current_predecessor_prepared_abort_and_genesis
jetstream_checkpoint_rejects_rolled_back_anchor_or_recreated_stream
jetstream_checkpoint_rejects_unavailable_server_instead_of_skipping
jetstream_checkpoint_uses_global_revision_not_store_generation
EOF
      ;;
    public-dispatcher) cat <<'EOF'
public_dispatcher_rejects_unknown_subject_operation_or_body
public_dispatcher_returns_overload_without_spawning_or_touching_store
public_dispatcher_signs_only_after_confirmed_transition
public_dispatcher_maps_typed_failure_without_string_fallback
EOF
      ;;
    full-service-path) cat <<'EOF'
full_service_path_rejects_runtime_private_subject_and_store_raw_api
full_service_path_rejects_credential_account_and_mount_swaps
full_service_path_validates_proxy_response_before_public_attestation
full_service_path_fails_closed_on_store_queue_exhaustion
EOF
      ;;
    service-checkpoint) cat <<'EOF'
service_checkpoint_rejects_unsigned_or_wrong_request_response
service_checkpoint_retries_only_exact_idempotent_request
service_checkpoint_rotates_session_after_lost_response
service_checkpoint_init_never_serves_requests
service_checkpoint_survives_process_restart_without_local_fallback
service_checkpoint_replays_fence_after_one_and_one_hundred_rotations
service_checkpoint_exact_rotation_retry_remains_byte_identical_after_later_prepare_commit_abort
service_checkpoint_rejects_expected_head_only_stale_retry
service_checkpoint_rejects_concurrent_conflicting_challenges
service_checkpoint_rejects_stale_fence_after_head_prepared_session_manifest_epoch_anchor
service_checkpoint_rejects_generation_exhaustion
service_checkpoint_reads_current_predecessor_prepared_aborted_and_evicted_txids
service_checkpoint_rejects_stale_replica_transaction_reads
service_checkpoint_enforces_every_protocol_limit_at_max_and_max_plus_one
service_checkpoint_retention_window_keeps_constant_keys_and_bounded_values
EOF
      ;;
    *) return 1 ;;
  esac
}

target_for_selector() {
  case "$1" in
    response-failure-wire|candidate-verifier|protocol-checkpoint|atomic-store-contract|in-memory-differential|typed-proxy)
      printf '%s\t%s\n' swarm-governance phase285_witness_conformance
      ;;
    jetstream-cas) printf '%s\t%s\n' swarm-governance-witness jetstream_cas ;;
    jetstream-checkpoint) printf '%s\t%s\n' swarm-governance-witness jetstream_checkpoint ;;
    public-dispatcher|full-service-path) printf '%s\t%s\n' swarm-governance-witness full_service_path ;;
    service-checkpoint) printf '%s\t%s\n' swarm-governance-witness service_checkpoint ;;
    transport-layering) printf '%s\t%s\n' shell transport-layering ;;
    *) return 1 ;;
  esac
}

transport_tuple_for_case() {
  case "$1" in
    transport_layering_rejects_governance_reverse_dependency)
      printf '%s\t%s\n' tools/check-workspace-layering.sh \
        'bash tools/check-workspace-layering.sh --self-test phase285-witness-reverse-dependency'
      ;;
    transport_layering_rejects_raw_kv_subject)
      printf '%s\t%s\n' tools/check-negative-registry.sh \
        'bash tools/check-negative-registry.sh --self-test phase285-raw-kv-subject'
      ;;
    transport_layering_rejects_second_governor_signer)
      printf '%s\t%s\n' tools/check-single-governor-key.sh \
        'bash tools/check-single-governor-key.sh --self-test phase285-second-governor-signer'
      ;;
    transport_layering_rejects_unrelated_authority_crate)
      printf '%s\t%s\n' tools/check-negative-registry.sh \
        'bash tools/check-negative-registry.sh --self-test phase285-unrelated-authority-crate'
      ;;
    transport_layering_rejects_missing_library_target)
      printf '%s\t%s\n' tools/check-witness-dependency-closure.sh \
        'bash tools/check-witness-dependency-closure.sh --self-test missing-library-target'
      ;;
    transport_layering_rejects_zero_or_omitted_mutation)
      printf '%s\t%s\n' tools/check-phase285-witness-conformance.sh \
        'bash tools/check-phase285-witness-conformance.sh --self-test transport-layering-zero-or-omitted'
      ;;
    *) return 1 ;;
  esac
}

# The executable registry contains the complete selector/case/target/command
# tuple. Its exact bytes are independently pinned by REGISTRY_SHA256 below, so
# changing any list, target, command, order, or spelling requires an explicit
# contract update and cannot validate itself circularly.
registry_rows() {
  local selector package target case_name command
  while IFS= read -r selector; do
    [ -n "$selector" ] || continue
    IFS=$'\t' read -r package target < <(target_for_selector "$selector")
    while IFS= read -r case_name; do
      [ -n "$case_name" ] || continue
      if [ "$package" = shell ]; then
        IFS=$'\t' read -r target command < <(transport_tuple_for_case "$case_name")
      else
        command="cargo test -p $package --test $target --locked --offline -- $case_name --exact"
      fi
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "$selector" "$package" "$target" "$command" "$case_name"
    done < <(selector_rows "$selector")
  done < <(selectors)
}

# Each target has an independent exact inventory. The shared governance target
# remains frozen at twenty cases; the JetStream CAS target owns exactly five.
materialized_inventory_for_target() {
  case "$1/$2" in
    swarm-governance/phase285_witness_conformance)
      selector_rows response-failure-wire
      selector_rows candidate-verifier
      selector_rows protocol-checkpoint
      selector_rows atomic-store-contract
      selector_rows in-memory-differential
      selector_rows typed-proxy
      ;;
    swarm-governance-witness/jetstream_cas)
      selector_rows jetstream-cas
      ;;
    swarm-governance-witness/jetstream_checkpoint)
      selector_rows jetstream-checkpoint
      ;;
    swarm-governance-witness/full_service_path)
      selector_rows public-dispatcher
      selector_rows full-service-path
      ;;
    *) return 1 ;;
  esac
}

REGISTRY_SHA256="a3a3ec459600ac3163a9b66aa40aa39e9387c50cc75b1e765d9f0693ddb8983b"
REGISTRY_ROW_COUNT=58

registry_validator() {
  local registry_file="$1" mode="${2:-validate}" selector="${3:-}"
  python3 - "$registry_file" "$REGISTRY_SHA256" "$REGISTRY_ROW_COUNT" "$mode" "$selector" <<'PY'
import copy
import hashlib
import sys

path, expected_digest, expected_count, mode, selector = sys.argv[1:]
expected_count = int(expected_count)
expected_selectors = [
    "response-failure-wire", "candidate-verifier", "protocol-checkpoint",
    "atomic-store-contract", "in-memory-differential", "typed-proxy",
    "transport-layering", "jetstream-cas", "jetstream-checkpoint",
    "public-dispatcher", "full-service-path", "service-checkpoint",
]
raw = open(path, "rb").read()

def encode(rows):
    return ("\n".join("\t".join(row) for row in rows) + "\n").encode()

def validate(candidate_raw):
    if hashlib.sha256(candidate_raw).hexdigest() != expected_digest:
        raise ValueError("registry digest differs from frozen exact tuple manifest")
    text = candidate_raw.decode("utf-8")
    if not text.endswith("\n") or "\n\n" in text:
        raise ValueError("registry encoding is not canonical")
    rows = [line.split("\t") for line in text.splitlines()]
    if len(rows) != expected_count or any(len(row) != 5 for row in rows):
        raise ValueError("registry row count or tuple width differs")
    if len({tuple(row) for row in rows}) != len(rows):
        raise ValueError("duplicate exact registry tuple")
    if len({(row[0], row[4]) for row in rows}) != len(rows):
        raise ValueError("duplicate selector/case tuple")
    observed_selectors = list(dict.fromkeys(row[0] for row in rows))
    if observed_selectors != expected_selectors:
        raise ValueError("selector set or order differs")
    if any(not field for row in rows for field in row):
        raise ValueError("empty registry tuple field")
    return rows

rows = validate(raw)
if mode == "validate":
    print(f"witness_registry rows={len(rows)} digest={expected_digest} valid=1")
    raise SystemExit(0)
if mode != "self-test":
    raise SystemExit(f"unknown registry validator mode: {mode}")

indices = [index for index, row in enumerate(rows) if row[0] == selector]
if not indices:
    raise SystemExit(f"self-test selector absent from control: {selector}")
index = indices[0]

def omitted(value):
    value.pop(index)

def added(value):
    extra = value[index].copy()
    extra[4] += "_extra"
    extra[3] = extra[3].replace(rows[index][4], extra[4])
    value.insert(index + 1, extra)

def duplicated(value):
    value.insert(index + 1, value[index].copy())

def wrong_target(value):
    value[index][2] += "_foreign"

def wrong_command(value):
    value[index][3] += " --nocapture"

def substring_case(value):
    value[index][4] = value[index][4][:-1]

def missing_target(value):
    value[index][2] = ""

def wrong_package(value):
    value[index][1] += "-foreign"

mutations = [
    # Preserve the frozen eight mutation IDs while making every mutation hit
    # the real exact-tuple registry validator. The functions cover omission,
    # addition, duplication, target, command, substring, and package drift.
    ("missing_target", missing_target),
    ("zero_execution", omitted),
    ("ignored_test", wrong_package),
    ("failed_test", wrong_command),
    ("duplicate_registry_row", duplicated),
    ("extra_registry_row", added),
    ("substring_only_match", substring_case),
    ("partial_or_filtered_only_wrong_count", wrong_target),
]
for name, mutate in mutations:
    changed = copy.deepcopy(rows)
    mutate(changed)
    try:
        validate(encode(changed))
    except ValueError:
        print(f"self_test_red selector={selector} mutation={name}")
    else:
        raise SystemExit(f"self-test mutation unexpectedly passed: {selector}:{name}")
print(f"self_test selector={selector} mutation_failure_count={len(mutations)}")
PY
}

validate_registry() {
  registry_validator <(registry_rows)
}

run_self_test_for_selector() {
  local selector="$1"
  registry_validator <(registry_rows) self-test "$selector"
}

run_self_tests() {
  validate_registry
  local count=0 selector
  while IFS= read -r selector; do
    [ -n "$selector" ] || continue
    run_self_test_for_selector "$selector"
    count=$((count + 1))
  done < <(selectors)
  [ "$count" -eq 12 ] || {
    echo "self-test omitted a selector: executed=$count expected=12" >&2
    return 1
  }
  echo "witness_registry_self_test selectors=$count mutations=$((count * 8)) passed=1"
  run_inner_ledger_validator_self_test
}

dispatcher_source_guard() {
  local source="$ROOT_DIR/crates/swarm-governance-witness/src/public_dispatcher.rs"
  local integration="$ROOT_DIR/crates/swarm-governance-witness/tests/full_service_path.rs"
  local config="$ROOT_DIR/crates/swarm-governance-witness/src/service_config.rs"
  local service="$ROOT_DIR/crates/swarm-governance/src/witness_service.rs"
  local protocol="$ROOT_DIR/crates/swarm-governance/src/persistence_protocol.rs"
  local verifier="$ROOT_DIR/crates/swarm-governance/src/witness_candidate_verifier.rs"
  python3 -I - "$source" "$integration" "$config" "$service" "$protocol" "$verifier" "${1:-normal}" <<'PY'
import hashlib
import re
import sys

source_path, integration_path, config_path, service_path, protocol_path, verifier_path, mode = sys.argv[1:]
source = open(source_path, encoding="utf-8").read()
integration = open(integration_path, encoding="utf-8").read()
config = open(config_path, encoding="utf-8").read()
service = open(service_path, encoding="utf-8").read()
protocol = open(protocol_path, encoding="utf-8").read()
verifier = open(verifier_path, encoding="utf-8").read()

def validate(
    text,
    integration_text=integration,
    config_text=config,
    service_text=service,
    protocol_text=protocol,
    verifier_text=verifier,
):
    if "PublicWitnessBackend" in text:
        raise ValueError("legacy public-response backend survived")
    if "_early_public_sign" in text:
        raise ValueError("public signing occurred before durable confirmation")
    for fragment, count in [
        ("pub admission_set: WitnessAdmissionSetV1,", 1),
        ("self.admission_set.validate()?;", 1),
        ("self.admission_set.admission_set_digest != self.admission_set_digest", 1),
        ("for admission in &self.admission_set.entries {", 1),
        ("admission.witness_identity != self.witness_identity", 1),
        ("admission.witness_key_id != self.witness_key_id", 1),
    ]:
        if config_text.count(fragment) != count:
            raise ValueError(f"admission-set config boundary differs: {fragment}")
    if "pub admission: WitnessAdmissionRecordV1" in config_text:
        raise ValueError("singleton admission config survived")
    if integration_text.count("assert!(public_witness_ingress_overload_control());") != 1:
        raise ValueError("registered overload case is not bound exactly once to production ingress")
    for fragment, count in [
        ("assert_pre_store_admission_fences().await?;", 1),
        ("assert_multistream_startup_controls().await?;", 1),
        ("assert_prepare_admission_classification().await?;", 1),
        ("assert_bound_taxonomy_is_seam_specific().await?;", 1),
        ("assert_current_head_intent_classification().await?;", 1),
        ("assert_authenticated_entry_limits_are_enforced().await?;", 1),
        ("ReadyMutation::CrossStreamSummaries", 2),
        ("fixture.enable_second_stream()?;", 1),
        ("two_stream.enable_second_stream()?;", 1),
        ("WitnessServiceFailureCodeV1::AdmissionMismatch", 7),
        ("WitnessServiceFailureCodeV1::StaleIntent", 5),
    ]:
        if integration_text.count(fragment) != count:
            raise ValueError(f"admission/multistream executable projection differs: {fragment}")
    fields_tables = re.findall(
        r"const FIELDS: \[&str; 7\] = \[(.*?)\n    \];",
        integration_text,
        re.S,
    )
    expected_fields = [
        "stream", "signer", "witness_identity", "witness_key",
        "binding_generation", "binding_digest", "authority_pair",
    ]
    if len(fields_tables) != 1 \
            or re.findall(r'"([a-z_]+)"', fields_tables[0]) != expected_fields:
        raise ValueError("pre-store admission field inventory differs")
    ready_table = re.search(
        r"for \(mutation, expected_startup_reads\) in \[(.*?)\n    \] \{",
        integration_text,
        re.S,
    )
    expected_ready = [
        "WrongOperation", "WrongRequestDigest", "WrongBucketConfiguration",
        "WrongManifestDigest", "WrongManifestPhase", "WrongManifestEpoch",
        "WrongWitnessIdentity", "WrongWitnessKey", "MissingStream", "ExtraStream",
        "WrongInitializationDigest", "WrongSummaryRevision", "WrongStoreDigest",
    ]
    if ready_table is None or re.findall(r"ReadyMutation::([A-Za-z]+)", ready_table.group(1)) != expected_ready:
        raise ValueError("Ready response mutation inventory differs")
    request_bindings = re.search(
        r'for field in \[(.*?)\] \{\n        let ready_fixture',
        integration_text,
        re.S,
    )
    if request_bindings is None or re.findall(r'"([a-z_]+)"', request_bindings.group(1)) != [
        "bucket_anchor", "bucket_epoch", "admission"
    ]:
        raise ValueError("Ready signed-request binding inventory differs")
    classification_block = re.search(
        r"async fn assert_prepare_admission_classification\(\) -> ProtocolResult<\(\)> \{(.*?)\n\}\n\nasync fn assert_authenticated_entry_limits_are_enforced",
        integration_text,
        re.S,
    )
    if classification_block is None:
        raise ValueError("Prepare classification corpus absent")
    if classification_block.group(1).count("for (initial_epoch, initial_sequence) in [(1, 0), (0, 1)]") != 1:
        raise ValueError("Prepare initial epoch/sequence mixed inventory differs")
    corruption_inventory = re.search(
        r"for corruption in \[(.*?)\] \{",
        classification_block.group(1),
        re.S,
    )
    if corruption_inventory is None or re.findall(r'"([a-z_]+)"', corruption_inventory.group(1)) != [
        "authorization_signature", "state_signature", "checkpoint_signature", "predecessor_digest"
    ]:
        raise ValueError("Prepare mixed cryptographic relation inventory differs")
    for fragment, count in [
        ("Fixture::new_with_initial_values(", 1),
        ('"authorization_signature",', 1),
        ('"state_signature",', 1),
        ('"checkpoint_signature",', 1),
        ('"predecessor_digest",', 1),
        ("std::mem::swap(", 2),
        ("WitnessServiceFailureCodeV1::AdmissionMismatch", 7),
        ("WitnessServiceFailureCodeV1::InvalidSignature", 2),
        ('assert_eq!(fixture.proxy.events(), vec!["read"]);', 7),
    ]:
        if classification_block.group(1).count(fragment) != count:
            raise ValueError(f"Prepare classification executable projection differs: {fragment}")
    entry_bounds_block = re.search(
        r"async fn assert_authenticated_entry_limits_are_enforced\(\) -> ProtocolResult<\(\)> \{(.*?)\n\}\n\nasync fn assert_multistream_startup_controls",
        integration_text,
        re.S,
    )
    if entry_bounds_block is None:
        raise ValueError("selected-entry bound corpus absent")
    if re.findall(r'\("([a-z]+)", [a-z_]+\)', entry_bounds_block.group(1)) != [
        "state", "checkpoint", "binding", "retained"
    ]:
        raise ValueError("selected-entry candidate bound inventory differs")
    for fragment, count in [
        ("enable_second_stream_with(|entry|", 3),
        ("for exceeds in [false, true]", 3),
        ('vec!["read", "cas", "read"]', 2),
        ('assert_eq!(fixture.secondary_events()?, vec!["read"]);', 4),
        ('assert_eq!(fixture.proxy.calls.load(Ordering::SeqCst), 0);', 1),
        ("PublicWitnessDispatchErrorV1::ResponseBounds", 1),
        ("entry.max_state_bytes = ceiling", 1),
        ("entry.max_checkpoint_bytes = ceiling", 1),
        ("entry.max_binding_bytes = ceiling", 1),
        ("entry.admission.max_retained_bytes = ceiling", 1),
        ("entry.max_request_bytes = ceiling", 1),
        ("entry.max_response_bytes = ceiling", 1),
        ("let ceiling = exact - u64::from(exceeds);", 1),
        ("let ceiling = request_len - u64::from(exceeds);", 1),
        ("let ceiling = response_len - u64::from(exceeds);", 1),
    ]:
        if entry_bounds_block.group(1).count(fragment) != count:
            raise ValueError(f"selected-entry executable projection differs: {fragment}")
    taxonomy_block = re.search(
        r"async fn assert_bound_taxonomy_is_seam_specific\(\) -> ProtocolResult<\(\)> \{(.*?)\n\}\n\nfn bound_candidate",
        integration_text,
        re.S,
    )
    if taxonomy_block is None:
        raise ValueError("six-boundary taxonomy corpus absent")
    for fragment, count in [
        ('for field in ["state", "checkpoint", "binding", "retained"]', 1),
        ("for exceeds in [false, true]", 1),
        ('"startup {field}"', 1),
        ("WitnessServiceFailureCodeV1::BoundsExceeded", 3),
        ("WitnessServiceFailureCodeV1::Conflict", 1),
        ("PublicWitnessDispatchErrorV1::OutcomeUnknown", 1),
        ('vec!["read"]', 3),
        ('vec!["read", "cas"]', 1),
        ('vec!["read", "cas", "read"]', 2),
        ("cas_attempted.load(Ordering::SeqCst), 0", 3),
        ("cas_attempted.load(Ordering::SeqCst), 1", 3),
        ("cas_applied.load(Ordering::SeqCst), 0", 3),
        ("cas_applied.load(Ordering::SeqCst), 1", 2),
    ]:
        if taxonomy_block.group(1).count(fragment) != count:
            raise ValueError(f"six-boundary taxonomy projection differs: {fragment}")
    failure_block = re.search(
        r"async fn assert_complete_signed_application_failures\(\) -> ProtocolResult<\(\)> \{(.*?)\n\}",
        integration_text,
        re.S,
    )
    if failure_block is None:
        raise ValueError("signed application failure corpus absent")
    rotation_operations = re.search(
        r"for operation in \[(.*?)\] \{\n        let invalid_rotation",
        failure_block.group(1),
        re.S,
    )
    if rotation_operations is None or re.findall(
        r"WitnessServiceOperationV1::([A-Za-z]+)", rotation_operations.group(1)
    ) != ["Establish", "Discover"]:
        raise ValueError("signed rotation failure operation inventory differs")
    for fragment, count in [
        ("WitnessServiceFailureCodeV1::InvalidSignature", 2),
        ("WitnessServiceFailureCodeV1::StaleIntent", 1),
        ("WitnessServiceFailureCodeV1::BoundsExceeded", 2),
        ("WitnessServiceFailureCodeV1::ExpectedHeadMismatch", 1),
        ("max_payload_bytes = 1;", 1),
        ("Fixture::new_with_initial_intent(CasMode::Apply, 2)?", 1),
        ('assert_eq!(verifier_only.proxy.events(), vec!["read"]);', 1),
        ("exhaust_current_session_generation()?;", 1),
        ('assert_eq!(invalid_authorization.proxy.events(), vec!["read"]);', 1),
        ('assert_eq!(bounds.proxy.events(), vec!["read"]);', 1),
        ('assert_eq!(expected_head.proxy.events(), vec!["read"]);', 1),
        ('assert_eq!(exhausted.proxy.events(), vec!["read"]);', 1),
    ]:
        if failure_block.group(1).count(fragment) != count:
            raise ValueError(f"signed failure executable projection differs: {fragment}")
    cross_block = re.search(
        r"async fn assert_cross_operation_winners\(\) -> ProtocolResult<\(\)> \{(.*?)\n\}\n\nasync fn assert_genesis_abort_successor_after_restart",
        integration_text,
        re.S,
    )
    if cross_block is None:
        raise ValueError("cross-operation winner corpus absent")
    for fragment, count in [
        ("WitnessCommitOutcomeV1::GenesisAborted", 2),
        ("WitnessAbortOutcomeV1::Committed", 2),
        ("set_conflict_observed(revision, envelope);", 2),
        ("WitnessServiceFailureCodeV1::StaleIntent", 1),
    ]:
        if cross_block.group(1).count(fragment) != count:
            raise ValueError(f"cross-operation executable projection differs: {fragment}")
    genesis_block = re.search(
        r"async fn assert_genesis_abort_successor_after_restart\(\) -> ProtocolResult<\(\)> \{(.*?)\n\}\n\nasync fn assert_typed_conflict",
        integration_text,
        re.S,
    )
    if genesis_block is None:
        raise ValueError("genesis-abort successor corpus absent")
    if integration_text.count("assert_genesis_abort_successor_after_restart().await?;") != 1:
        raise ValueError("genesis-abort successor corpus is not executed exactly once")
    for fragment, count in [
        ("drop(first_dispatcher);", 1),
        ("let restarted_dispatcher = fixture.dispatcher()", 1),
        ("aborted.intent_counter,", 1),
        (".intent_counter\n        .checked_add(1)", 1),
        ("next_intent.checked_add(1)", 1),
        ("WitnessServiceFailureCodeV1::StaleIntent", 1),
        ("verify_public_prepare(", 5),
        ("&foreign_witness,", 1),
        ("corrupt_envelope.signature.signature_hex", 1),
        ('("f".repeat(64), stream_initialization_digest.clone())', 1),
        ('(aborted_envelope.bucket_epoch_digest.clone(), "f".repeat(64))', 1),
        ("assert!(confirmed.genesis_abort.is_none());", 1),
        (".prepared\n            .genesis_abort", 1),
        ("Some(&aborted)", 1),
        ('assert_eq!(fixture.proxy.events(), vec!["read", "cas", "read"]);', 1),
    ]:
        if genesis_block.group(1).count(fragment) != count:
            raise ValueError(f"genesis-abort executable projection differs: {fragment}")
    current_head_block = re.search(
        r"async fn assert_current_head_intent_classification\(\) -> ProtocolResult<\(\)> \{(.*?)\n\}\n\nasync fn assert_authenticated_entry_limits_are_enforced",
        integration_text,
        re.S,
    )
    if current_head_block is None:
        raise ValueError("current-head Prepare intent corpus absent")
    for fragment, count in [
        ("for intent in [\n        head.intent_counter,", 1),
        ("expected_intent\n            .checked_add(1)", 1),
        ("build_candidate_without_intent_relation", 1),
        ("WitnessServiceFailureCodeV1::StaleIntent", 1),
        ("mixed.preimage.state_attestation.signature_hex", 1),
        ("WitnessServiceFailureCodeV1::InvalidSignature", 1),
        ('assert_eq!(fixture.proxy.events(), vec!["read"]);', 2),
    ]:
        if current_head_block.group(1).count(fragment) != count:
            raise ValueError(f"current-head Prepare intent projection differs: {fragment}")
    post_cas_block = re.search(
        r"async fn assert_post_cas_acknowledgements_remain_unknown\(\) -> ProtocolResult<\(\)> \{(.*?)\n\}\n\nasync fn assert_cross_operation_winners",
        integration_text,
        re.S,
    )
    if post_cas_block is None:
        raise ValueError("post-CAS acknowledgement corpus absent")
    lost_calls = re.findall(
        r"assert_lost_response_remains_unknown\(OperationCase::([A-Za-z]+)\)\.await\?;",
        integration_text,
    )
    if lost_calls != ["Establish", "Discover", "Prepare", "Commit", "Abort"]:
        raise ValueError("lost-response operation inventory differs")
    prepare_recovery = re.search(
        r"async fn assert_prepare_idempotency_and_recovery\(\) -> ProtocolResult<\(\)> \{(.*?)\n\}\n\nasync fn assert_lost_response_remains_unknown",
        integration_text,
        re.S,
    )
    if prepare_recovery is None:
        raise ValueError("Prepare idempotency/recovery corpus absent")
    for fragment, count in [
        ("assert_prepare_idempotency_and_recovery().await?;", 1),
        ("WitnessPrepareOutcomeV1::Prepared", 1),
        ("WitnessPrepareOutcomeV1::AlreadyPrepared", 3),
        ("WitnessPrepareOutcomeV1::Conflict", 2),
        ("WitnessServiceFailureCodeV1::InvalidSignature", 2),
        ("CasMode::ApplyThenUnavailable", 1),
        ("Err(PublicWitnessDispatchErrorV1::OutcomeUnknown)", 1),
        ('&["read"]', 5),
        ('vec!["read", "cas"]', 1),
        ("set_conflict_observed", 1),
        ("for (same_winner, expected_already) in [(true, true), (false, false)]", 1),
        ("lost.dispatch_request(&lost_dispatcher, &original).await?", 1),
        ("let mut invalid_conflict = different_request.clone();", 1),
        ("let mut invalid_retry = request.clone();", 1),
        ("cas_attempted.load(Ordering::SeqCst)", 8),
        ("cas_applied.load(Ordering::SeqCst)", 8),
        ("fixture.proxy.cas_attempted.load(Ordering::SeqCst),\n        attempted", 4),
        ("fixture.proxy.cas_applied.load(Ordering::SeqCst), applied", 4),
        ("lost.proxy.cas_attempted.load(Ordering::SeqCst),\n        lost_attempted", 1),
        ("lost.proxy.cas_applied.load(Ordering::SeqCst), lost_applied", 1),
        ("winner.proxy.cas_attempted.load(Ordering::SeqCst), 1", 1),
        ("winner.proxy.cas_applied.load(Ordering::SeqCst), 0", 1),
    ]:
        target = integration_text if fragment.startswith("assert_prepare") else prepare_recovery.group(1)
        if target.count(fragment) != count:
            raise ValueError(f"Prepare idempotency/recovery projection differs: {fragment}")
    if "attempted + 1" in prepare_recovery.group(1) or "applied + 1" in prepare_recovery.group(1):
        raise ValueError("Prepare idempotency retries compare-and-swap")
    lost_block = re.search(
        r"async fn assert_lost_response_remains_unknown\(operation: OperationCase\) -> ProtocolResult<\(\)> \{(.*?)\n\}\n\nasync fn assert_post_cas_acknowledgements_remain_unknown",
        integration_text,
        re.S,
    )
    if lost_block is None:
        raise ValueError("lost-response uncertainty corpus absent")
    for fragment, count in [
        ("CasMode::ApplyThenUnavailable", 1),
        ("Err(PublicWitnessDispatchErrorV1::OutcomeUnknown)", 1),
        ('&["read", "cas", "read"]', 1),
        ("before_attempted + 1", 1),
        ("before_applied + 1", 1),
    ]:
        if lost_block.group(1).count(fragment) != count:
            raise ValueError(f"lost-response uncertainty projection differs: {fragment}")
    expected_post_cas = [
        "malformed", "duplicate", "lower", "wrong_kind", "wrong_stream",
        "wrong_previous_revision", "wrong_new_revision", "wrong_digest",
        "wrong_request_digest", "unknown", "wrong_value",
    ]
    if re.findall(r'\(\s*"([a-z_]+)",\s*CasMode::', post_cas_block.group(1), re.S) != expected_post_cas:
        raise ValueError("post-CAS acknowledgement inventory differs")
    for fragment, count in [
        ("assert_post_cas_acknowledgements_remain_unknown().await?;", 1),
        ("Err(PublicWitnessDispatchErrorV1::OutcomeUnknown)", 1),
        ('vec!["read", "cas", "read"]', 1),
        ('vec!["read", "cas"]', 1),
        ("cas_attempted.load(Ordering::SeqCst), 1", 1),
        ("cas_applied.load(Ordering::SeqCst), 1", 1),
    ]:
        target = integration_text if fragment.startswith("assert_post_cas") else post_cas_block.group(1)
        if target.count(fragment) != count:
            raise ValueError(f"post-CAS acknowledgement projection differs: {fragment}")
    for fragment, count in [
        ("pub fn validate_public_dispatch_identity(&self)", 1),
        ("request.validate_public_dispatch_identity()?;", 3),
        ("let identity = public_request_identity(request)?;", 1),
        ("request.validate()?;", 4),
        ("if self.request_digest != computed {", 1),
        ("canonical_wire_bytes(self).map(|_| ())", 1),
    ]:
        if service_text.count(fragment) != count:
            raise ValueError(f"outer failure identity seam differs: {fragment}")
    service_prepare = re.search(
        r"pub fn verify_public_prepare\((.*?)\n\}\n\n#\[allow\(clippy::too_many_arguments\)\]",
        verifier_text,
        re.S,
    )
    if service_prepare is None:
        raise ValueError("single public Prepare verifier absent")
    verification_enum = re.search(
        r"pub enum WitnessPrepareVerificationV1 \{(.*?)\n\}",
        verifier_text,
        re.S,
    )
    if verification_enum is None or re.findall(
        r"^    ([A-Za-z]+)\(", verification_enum.group(1), re.M
    ) != ["New", "AlreadyPrepared", "Conflict", "Rejected"]:
        raise ValueError("closed Prepare verification inventory differs")
    for fragment, count in [
        ("verify_public_prepare_inner(", 1),
        ("WitnessPrepareVerificationV1::Rejected(code)", 1),
    ]:
        if service_prepare.group(1).count(fragment) != count:
            raise ValueError(f"public Prepare verifier entry differs: {fragment}")
    verifier_inner = re.search(
        r"fn verify_public_prepare_inner\((.*?)\n\}\n\nstruct ExpectedPrepareRelationsV1",
        verifier_text,
        re.S,
    )
    if verifier_inner is None:
        raise ValueError("public Prepare verifier implementation absent")
    for fragment, count in [
        ("request\n        .validate_public_dispatch_identity()", 1),
        ("current_envelope\n        .validate_for(WitnessStoreExpectationV1 {", 1),
        ("request.admission_digest != admission_entry.admission_digest", 1),
        ("bucket_epoch_digest: expected_bucket_epoch_digest,", 1),
        ("stream_initialization_digest: expected_stream_initialization_digest,", 1),
        ("witness_signer.key_id() != admission_entry.witness_key_id", 1),
        ("let WitnessServiceRequestBodyV1::Prepare {", 1),
        ("candidate\n        .validate_for_expected_intent(expected.intent_counter)", 1),
        ("binding.publication_roles != admission_entry.publication_roles", 1),
        ("binding.limits != admission_entry.limits", 1),
        ("authorization\n        .verify_for_session_record(", 1),
        ("current_envelope.session.as_ref() != Some(session)", 1),
        ("candidate.preimage.predecessor_head.as_ref() != expected_head.as_deref()", 1),
        ("candidate.preimage.epoch != expected.epoch", 1),
        ("candidate.preimage.sequence != expected.sequence", 1),
        ("candidate.preimage.predecessor_head_digest != expected.predecessor_head_digest", 1),
        ("candidate.preimage.predecessor_data_head_digest != expected.predecessor_data_head_digest", 1),
        ("candidate.preimage.publication_mapping_before != expected.publication_mapping", 1),
        ("enforce_selected_candidate_bounds(admission_entry, current_envelope, candidate)", 1),
        ("if !intent_matches {", 1),
        ("WitnessServiceFailureCodeV1::StaleIntent", 1),
        ("verified_stored_genesis_abort(current_envelope, expected_abort, witness_signer)", 1),
        ("WitnessCandidateVerifier::verify_prepare(", 1),
        ("verified_abort.as_ref(),", 1),
        ("let stored_genesis_abort = current_envelope.genesis_abort.as_ref().or_else(|| {\n        current_envelope\n            .prepared", 1),
        ("let Some(stored) = current_envelope.prepared.as_ref() else", 1),
        ("WitnessPrepareVerificationV1::New(Box::new(verified))", 1),
        ("stored.prepared.head.txid == verified.candidate.txid", 1),
        ("stored.prepared.head.candidate_digest == verified.candidate.candidate_digest", 1),
        ("VerifiedPrepareResolutionKindV1::AlreadyPrepared", 2),
        ("VerifiedPrepareResolutionKindV1::Conflict", 2),
        ("WitnessPrepareVerificationV1::AlreadyPrepared(Box::new(resolution))", 1),
        ("WitnessPrepareVerificationV1::Conflict(Box::new(resolution))", 1),
    ]:
        if verifier_inner.group(1).count(fragment) != count:
            raise ValueError(f"public Prepare verifier relation differs: {fragment}")
    if verifier_inner.group(1).index("enforce_selected_candidate_bounds(") \
            > verifier_inner.group(1).index("if !intent_matches {"):
        raise ValueError("StaleIntent precedes selected candidate bounds")
    if verifier_inner.group(1).index("authorization\n        .verify_for_session_record(") \
            > verifier_inner.group(1).index("if !intent_matches {"):
        raise ValueError("StaleIntent precedes session authorization")
    if verifier_inner.group(1).index("WitnessCandidateVerifier::verify_prepare(") \
            > verifier_inner.group(1).index("let Some(stored) = current_envelope.prepared.as_ref() else"):
        raise ValueError("Prepare idempotency classification precedes full verification")
    prepared_relations = re.search(
        r"fn expected_prepare_relations\((.*?)\n\}\n\nfn verified_stored_genesis_abort",
        verifier_text,
        re.S,
    )
    if prepared_relations is None:
        raise ValueError("Prepare relation classifier absent")
    for fragment, count in [
        ("if let Some(stored) = current.prepared.as_ref()", 1),
        ("stored.prepared.predecessor_head.as_ref() != expected_head", 1),
        ("intent_counter: stored.candidate.intent_counter", 1),
        ("epoch: stored.candidate.epoch", 1),
        ("sequence: stored.candidate.sequence", 1),
        ("predecessor_head_digest: stored.candidate.predecessor_head_digest.clone()", 1),
        ("predecessor_data_head_digest: stored.candidate.predecessor_data_head_digest.clone()", 1),
        ("publication_mapping: stored.candidate.publication_mapping_before", 1),
    ]:
        if prepared_relations.group(1).count(fragment) != count:
            raise ValueError(f"stored Prepare relation differs: {fragment}")
    resolution = re.search(
        r"impl VerifiedPrepareResolutionV1 \{(.*?)\n\}\n\nimpl VerifiedCandidateAdmissionV1",
        verifier_text,
        re.S,
    )
    if resolution is None:
        raise ValueError("opaque Prepare resolution absent")
    for fragment, count in [
        ("current.validate()?;", 1),
        ("current.store_state_digest()? != self.store_state_digest", 1),
        ("current\n            .prepared\n            .as_ref()", 1),
        ("stored.prepared.head.txid == self.txid", 1),
        ("stored.prepared.head.candidate_digest == self.candidate_digest", 1),
        ("VerifiedPrepareResolutionKindV1::AlreadyPrepared if same", 1),
        ("WitnessPrepareOutcomeV1::AlreadyPrepared(stored.prepared.clone())", 1),
        ("VerifiedPrepareResolutionKindV1::Conflict if !same", 1),
        ("WitnessPrepareOutcomeV1::Conflict", 1),
    ]:
        if resolution.group(1).count(fragment) != count:
            raise ValueError(f"opaque Prepare resolution differs: {fragment}")
    lower_verifier = re.search(
        r"pub fn verify_prepare\((.*?)\n    \}\n\}\n\n/// Pure, unsigned one-step transition",
        verifier_text,
        re.S,
    )
    if lower_verifier is None:
        raise ValueError("lower Prepare verifier absent")
    for fragment, count in [
        ("let authenticated_genesis_abort = current_envelope.genesis_abort.as_ref().or_else(||", 1),
        ("let authenticated_genesis_abort = current_envelope.genesis_abort.as_ref().or_else(|| {\n            current_envelope\n                .prepared", 1),
        (".and_then(|stored| stored.prepared.genesis_abort.as_ref())", 1),
        ("let prepared = match (authenticated_genesis_abort, genesis_abort_outcome)", 1),
    ]:
        if lower_verifier.group(1).count(fragment) != count:
            raise ValueError(f"prepared retry genesis authority differs: {fragment}")
    for forbidden in [
        "candidate.validate()?",
        "verify_for_session_record(",
    ]:
        prefix = text[text.index("async fn execute("):text.index("let verified = match verify_public_prepare(")]
        if forbidden in prefix:
            raise ValueError(f"dispatcher performs early complete Prepare validation: {forbidden}")
    opaque_abort = re.search(
        r"pub\(crate\) fn from_authenticated_store_genesis_abort\((.*?)\n    \}\n\n    pub fn attestation",
        protocol_text,
        re.S,
    )
    if opaque_abort is None:
        raise ValueError("stored genesis-abort opaque constructor absent")
    for fragment, count in [
        ("session.validate()?;", 1),
        ("expected_abort.validate()?;", 1),
        ("attestation.validate()?;", 1),
        ("attestation.operation != WitnessOperationV1::Abort", 1),
        ("attestation.stream_id != session.stream_id", 1),
        ("attestation.binding_generation != session.binding_generation", 1),
        ("attestation.binding_digest != session.binding_digest", 1),
        ("attestation.signer_key_id != session.signer_key_id", 1),
        ("attestation.authority_pair != session.authority_pair", 1),
        ("attestation.session_generation != session.session_generation", 1),
        ("attestation.session_commitment != session.session_commitment", 1),
        ("attestation.witness_key_id != session.witness_key_id", 1),
        ("attestation.outcome != expected_outcome", 1),
    ]:
        if opaque_abort.group(1).count(fragment) != count:
            raise ValueError(f"stored genesis-abort opaque constructor differs: {fragment}")
    normalized_candidate = re.search(
        r"pub\(crate\) fn validate_for_expected_intent\((.*?)\n    \}\n\}",
        protocol_text,
        re.S,
    )
    if normalized_candidate is None:
        raise ValueError("normalized Prepare candidate validator absent")
    for fragment, count in [
        ("normalized.intent_counter = expected_intent_counter;", 1),
        ("normalized.validate()?;", 1),
        ("let preimage_bytes = canonical_wire_bytes(&self.preimage)?;", 1),
        ("digest_domain(CANDIDATE_DOMAIN_V1, &preimage_bytes)?", 1),
        ("if self.candidate_digest != candidate_digest", 1),
        ("let txid = TxidPreimageV1 {", 1),
        ("if self.txid != txid", 1),
        ("Ok(self.preimage.intent_counter == expected_intent_counter)", 1),
    ]:
        if normalized_candidate.group(1).count(fragment) != count:
            raise ValueError(f"normalized Prepare candidate validator differs: {fragment}")
    queue_subjects = re.findall(r'\.queue_subscribe\(\s*"([^"]+)"\s*,', text)
    expected_subjects = [
        "swarm.governance.witness.v1.fence",
        "swarm.governance.witness.v1.establish",
        "swarm.governance.witness.v1.discover",
        "swarm.governance.witness.v1.prepare",
        "swarm.governance.witness.v1.commit",
        "swarm.governance.witness.v1.abort",
        "swarm.governance.witness.v1.read_prepared",
        "swarm.governance.witness.v1.read_head",
        "swarm.governance.witness.v1.fetch_payload",
    ]
    if queue_subjects != expected_subjects:
        raise ValueError(f"runner subscription inventory differs: {queue_subjects}")
    if text.count('const PUBLIC_WITNESS_QUEUE_GROUP: &str = "swarm-governance-witness-v1";') != 1:
        raise ValueError("runner queue group differs")
    proxy_builder = re.search(
        r"fn proxy_request_for_digest\((.*?)\n    \}\n\n    fn stream_initialization_digest",
        text,
        re.S,
    )
    if proxy_builder is None:
        raise ValueError("closed proxy request builder absent")
    for fragment in [
        "admission_digest: admission.admission_digest.clone(),",
        "bucket_epoch_digest: self.config.bucket_epoch_digest.clone(),",
        "bucket_anchor_digest: self.config.bucket_anchor_digest.clone(),",
    ]:
        if proxy_builder.group(1).count(fragment) != 1:
            raise ValueError(f"proxy request binding differs: {fragment}")
    for fragment in [
        "let capacity = dispatcher.config.ingress_queue_capacity;",
        "let worker_count = dispatcher.config.max_in_flight;",
        "let Some(reply) = message.reply else {",
        "if !is_bounded_inbox_reply(&reply)",
        "payload: message.payload.to_vec(),",
        "if !try_enqueue_public_message(&ingress, ingress_message)",
        "ingress.try_send(message).is_ok()",
        "pub fn public_witness_ingress_overload_control() -> bool",
    ]:
        if text.count(fragment) != 1:
            raise ValueError(f"runner boundary differs: {fragment}")
    trait = re.search(
        r"pub trait PublicWitnessStoreProxyClient: Send \+ Sync \{(.*?)\n\}",
        text,
        re.S,
    )
    if trait is None:
        raise ValueError("closed proxy trait absent")
    methods = re.findall(r"async fn ([a-z_]+)\(", trait.group(1))
    if methods != ["inspect_ready", "read_entry", "compare_and_swap"]:
        raise ValueError(f"proxy method inventory differs: {methods}")
    for forbidden in ["Ed25519Signer", "WitnessServiceResponseV1", "String"]:
        if forbidden in trait.group(1):
            raise ValueError(f"proxy trait leaks {forbidden}")
    required = [
        "struct VerifiedPublicWitnessCompletionV1 {",
        "enum UnsignedPublicWitnessSuccessV1 {",
        "pub async fn new(",
        "dispatcher.validate_startup_ready().await?;",
        "WitnessServiceFailureV1::from_protocol_error(&error).failure_code",
        "let verified = match verify_public_prepare(",
        "WitnessPrepareVerificationV1::New(verified)",
        "WitnessPrepareVerificationV1::AlreadyPrepared(resolution)",
        "WitnessPrepareVerificationV1::Conflict(resolution)",
        "WitnessPrepareVerificationV1::Rejected(code)",
        "self.sign_prepare_resolution(",
        "prepare_verified_candidate(&current.envelope, *verified)",
        "if !matches!(request.body, WitnessServiceRequestBodyV1::Prepare { .. })",
        "validate_selected_entry_bounds(admission, &proposed)",
        "validate_selected_entry_bounds(admission, &current.envelope).map_err(invalid)?;",
        "if validate_selected_entry_bounds(admission, &current.envelope).is_err()",
        "if validate_selected_entry_bounds(admission, &observed.envelope).is_err()",
        "if validate_selected_entry_bounds(admission, &confirmed.envelope).is_err()",
        "usize::try_from(selected.max_request_bytes)",
        "usize::try_from(selected.max_response_bytes)",
        ".min(selected_max_response)",
        "candidate.state_payload.len() as u64 > admission.max_state_bytes",
        "candidate.checkpoint_payload.len() as u64 > admission.max_checkpoint_bytes",
        "binding_bytes > admission.max_binding_bytes",
        "retained_wire > admission.max_retained_bytes",
        "retained_payload > admission.max_retained_bytes",
        "PublicWitnessDispatchErrorV1::OutcomeUnknown",
        "self.selected_admission(&request)?",
        ".admission_set\n            .entry(stream_id)",
        "challenge.state_fence.witness_identity != challenge.witness_identity",
        "challenge.state_fence.witness_key_id != challenge.witness_key_id",
        "if request_session(&request)",
        "self.handle_establish(",
        "self.handle_discover(&request, &current, challenge).await",
        "self.handle_commit(&request, &current, session, txid).await",
        "self.handle_abort(&request, &current, session, txid).await",
        ".validate_challenge_freshness(current, challenge)",
        'response.operation != WitnessStoreProxyOperationV1::ReadEntry',
        'response.operation != WitnessStoreProxyOperationV1::CompareAndSwap',
        "response.request_digest != expected_digest",
        "stream_id == admission.stream_id",
        "previous_revision == current.revision",
        "new_revision > previous_revision",
        "acknowledged_value_digest == proposed_digest",
        '.read_authenticated(service_request, "confirm")',
        "confirmed.revision <= current.revision",
        "expected_revision.is_some_and(|revision| confirmed.revision != revision)",
        "confirmed.envelope.canonical_bytes().map_err(invalid)?",
        ".signed_envelope_digest()",
        "confirmed.envelope.store_state_digest().map_err(invalid)?",
        "WitnessStoreProxyResponseBodyV1::Conflict {",
        ".confirm_proposed(service_request, current, &proposed, None)",
        "if summary.txid == txid",
        "commit_winner(&current.envelope, txid)",
        "abort_winner(&current.envelope, txid)",
        "commit_winner(&observed.envelope, txid)",
        "abort_winner(&observed.envelope, txid)",
        ".validate_for(WitnessStoreExpectationV1 {",
        ".sign_for_request(&request, &self.signer)",
    ]
    for fragment in required:
        if text.count(fragment) == 0:
            raise ValueError(f"dispatcher verification fragment absent: {fragment}")
    for fragment, count in [
        ("response.request_digest != expected_digest", 3),
        ("response.operation != WitnessStoreProxyOperationV1::InspectReady", 1),
        ("self.selected_admission(&request)?;", 2),
        ("|| signer_key_id != admission.signer_key_id", 1),
        ("|| witness_identity != admission.witness_identity", 1),
        ("|| witness_key_id != admission.witness_key_id", 1),
        ("|| binding_generation != admission.binding_generation", 1),
        ("|| binding_digest != admission.binding_digest", 1),
        ("|| authority_pair != admission.authority_pair", 1),
        ("|| challenge.state_fence.witness_identity != challenge.witness_identity", 1),
        ("|| challenge.state_fence.witness_key_id != challenge.witness_key_id", 1),
        ("stream_id == admission.stream_id", 2),
        ("dispatcher.validate_startup_ready().await?;", 1),
        ("if request_session(&request)", 1),
        ("self.handle_establish(", 1),
        ("self.handle_discover(&request, &current, challenge).await", 1),
        ("self.handle_commit(&request, &current, session, txid).await", 1),
        ("self.handle_abort(&request, &current, session, txid).await", 1),
        (".validate_challenge_freshness(current, challenge)", 2),
        ("if summary.txid == txid", 2),
        ('.read_authenticated(service_request, "confirm")', 1),
        (".validate_for(WitnessStoreExpectationV1 {", 2),
        ("validated_streams.len() != self.config.admission_set.entries.len()", 1),
        ("|| bucket_configuration_digest != self.config.bucket_configuration_digest", 1),
        ("ready_manifest.digest().map_err(invalid)? != self.config.ready_manifest_digest", 1),
        ("ready_manifest.bucket_epoch_digest != self.config.bucket_epoch_digest", 1),
        ("ready_manifest.bucket_configuration_digest != self.config.bucket_configuration_digest", 1),
        ("ready_manifest.admission_set_digest != self.config.admission_set_digest", 1),
        ("ready_manifest.phase != WitnessBucketManifestPhaseV1::Ready", 1),
        ("ready_manifest.witness_identity != self.config.witness_identity", 1),
        ("ready_manifest.witness_key_id != self.config.witness_key_id", 1),
        ("ready_manifest.stream_keys != expected_stream_keys", 1),
        ("ready_manifest.initialized_streams.len() != self.config.admission_set.entries.len()", 1),
        ("for admission in &self.config.admission_set.entries {", 1),
        ("record.stream_initialization_digest != initialization_digest", 1),
        ("summary.stream_initialization_digest != initialization_digest", 1),
        ("summary.revision != current.revision", 1),
        ("summary.store_state_digest", 1),
        ("WitnessServiceFailureV1::from_protocol_error(&error).failure_code", 1),
        ("WitnessServiceFailureCodeV1::StaleRotationFence", 2),
        ("WitnessServiceFailureCodeV1::ExpectedHeadMismatch", 1),
        ("WitnessServiceFailureCodeV1::StoreTransitionRefused", 1),
        ("failure_code_for_protocol(&error)", 5),
        ("let verified = match verify_public_prepare(", 1),
        ("WitnessPrepareVerificationV1::New(", 2),
        ("WitnessPrepareVerificationV1::AlreadyPrepared(", 2),
        ("WitnessPrepareVerificationV1::Conflict(", 2),
        ("WitnessPrepareVerificationV1::Rejected(code)", 2),
        ("self.sign_prepare_resolution(", 2),
        ("verify_public_prepare(", 2),
        ("prepare_verified_candidate(&current.envelope, *verified)", 1),
        ("if !matches!(request.body, WitnessServiceRequestBodyV1::Prepare { .. })", 1),
        ("validate_selected_entry_bounds(admission, &proposed)", 1),
        ("usize::try_from(selected.max_request_bytes)", 1),
        ("usize::try_from(selected.max_response_bytes)", 1),
        (".min(selected_max_response)", 1),
        ("candidate.state_payload.len() as u64 > admission.max_state_bytes", 1),
        ("candidate.checkpoint_payload.len() as u64 > admission.max_checkpoint_bytes", 1),
        ("binding_bytes > admission.max_binding_bytes", 1),
        ("retained_wire > admission.max_retained_bytes", 1),
        ("retained_payload > admission.max_retained_bytes", 1),
        ("PublicWitnessDispatchErrorV1::OutcomeUnknown", 8),
        ("&self.config.bucket_epoch_digest,", 4),
        ("&stream_initialization_digest,", 3),
    ]:
        if text.count(fragment) != count:
            raise ValueError(f"dispatcher verification cardinality differs: {fragment}")
    prepare_dispatch = re.search(
        r"WitnessServiceRequestBodyV1::Prepare \{(.*?)\n            WitnessServiceRequestBodyV1::Establish \{",
        text,
        re.S,
    )
    if prepare_dispatch is None:
        raise ValueError("Prepare dispatcher arm absent")
    for fragment, count in [
        ("verify_public_prepare(", 2),
        ("WitnessPrepareVerificationV1::New(", 2),
        ("WitnessPrepareVerificationV1::AlreadyPrepared(", 2),
        ("WitnessPrepareVerificationV1::Conflict(", 2),
        ("WitnessPrepareVerificationV1::Rejected(code)", 2),
        ("self.sign_prepare_resolution(", 2),
        ("prepare_verified_candidate(&current.envelope, *verified)", 1),
        (".apply_and_confirm(&request, &current, proposed)", 1),
    ]:
        if prepare_dispatch.group(1).count(fragment) != count:
            raise ValueError(f"Prepare dispatcher classification differs: {fragment}")
    resolution_signer = re.search(
        r"fn sign_prepare_resolution\((.*?)\n    \}\n\n    fn validate_transition",
        text,
        re.S,
    )
    if resolution_signer is None:
        raise ValueError("Prepare resolution signer absent")
    for fragment, count in [
        (".into_outcome_for_store(&current.envelope)", 1),
        ("self.sign_outcome(", 1),
        ("WitnessOperationOutcomeV1::Prepare(Box::new(outcome))", 1),
    ]:
        if resolution_signer.group(1).count(fragment) != count:
            raise ValueError(f"Prepare resolution signing differs: {fragment}")
    for forbidden in ["apply_and_confirm", "compare_and_swap", "prepare_verified_candidate"]:
        if forbidden in resolution_signer.group(1):
            raise ValueError(f"Prepare resolution retries mutation: {forbidden}")
    if "pub struct VerifiedPublicWitnessCompletionV1" in text \
            or "pub enum UnsignedPublicWitnessSuccessV1" in text:
        raise ValueError("completion capability became public")
    durable = text.index(".apply_and_confirm(&request, &current, proposed)")
    terminal = text.index(".sign_for_request(&request, &self.signer)", durable)
    if terminal <= durable:
        raise ValueError("public response signing precedes confirming read")
    post_cas = re.search(
        r"let response = match self\.proxy\.compare_and_swap\(request\)\.await \{(.*?)\n        \};(.*?)\n    async fn confirm_proposed",
        text,
        re.S,
    )
    if post_cas is None:
        raise ValueError("post-CAS classifier absent")
    classifier = post_cas.group(0)
    if classifier.count("self.proxy.compare_and_swap(") != 1:
        raise ValueError("post-CAS classifier retries compare-and-swap")
    transport_error = re.search(r"Err\(error\) => \{(.*?)\n            \}", post_cas.group(1), re.S)
    if transport_error is None:
        raise ValueError("post-CAS transport error arm absent")
    for fragment in [
        "let _diagnostic = self",
        ".confirm_proposed(service_request, current, &proposed, None)",
        "return Err(PublicWitnessDispatchErrorV1::OutcomeUnknown);",
    ]:
        if transport_error.group(1).count(fragment) != 1:
            raise ValueError(f"post-CAS transport uncertainty differs: {fragment}")
    if "MutationStoreResult::Confirmed" in transport_error.group(1):
        raise ValueError("diagnostic read upgrades transport uncertainty")
    for fragment in [
        "response\n            .validate()\n            .map_err(|_| PublicWitnessDispatchErrorV1::OutcomeUnknown)?;",
        "response.operation != WitnessStoreProxyOperationV1::CompareAndSwap",
        "response.request_digest != expected_digest",
        "&& previous_revision == current.revision",
        "&& new_revision > previous_revision",
        "&& acknowledged_value_digest == proposed_digest",
        "_ => Err(PublicWitnessDispatchErrorV1::OutcomeUnknown)",
    ]:
        if classifier.count(fragment) != 1:
            raise ValueError(f"post-CAS acknowledgement classifier differs: {fragment}")
    conflict = re.search(
        r"WitnessStoreProxyResponseBodyV1::Conflict \{(.*?)\n            WitnessStoreProxyResponseBodyV1::Refused",
        classifier,
        re.S,
    )
    if conflict is None or "confirm_proposed" in conflict.group(1) \
            or "MutationStoreResult::Confirmed" in conflict.group(1):
        raise ValueError("non-CasApplied response upgrades to confirmed")

validate(source)
if mode != "self-test":
    print("dispatcher_source_guard passed=1")
    raise SystemExit(0)

validate(source, integration + '\nconst UNRELATED_STORE_LABEL: &str = "stream";\n')
print("dispatcher_source_positive_mutation mutation=unrelated_stream_literal_tolerated")

mutations = [
    ("backend_public_response", "pub trait PublicWitnessStoreProxyClient", "pub trait PublicWitnessBackend"),
    ("startup_ready_bypassed", "dispatcher.validate_startup_ready().await?;", "/* startup Ready bypassed */"),
    ("prestore_admission_selection_bypassed", "self.selected_admission(&request)?;", "self.config.admission_set.entries.first().ok_or(PublicWitnessDispatchErrorV1::Invalid)?;"),
    ("admission_stream_lookup_bypassed", ".admission_set\n            .entry(stream_id)", ".admission_set\n            .entries.first()"),
    ("admission_signer_relation_bypassed", "|| signer_key_id != admission.signer_key_id", "|| false"),
    ("admission_witness_identity_relation_bypassed", "|| witness_identity != admission.witness_identity", "|| false"),
    ("admission_witness_key_relation_bypassed", "|| witness_key_id != admission.witness_key_id", "|| false"),
    ("admission_binding_generation_relation_bypassed", "|| binding_generation != admission.binding_generation", "|| false"),
    ("admission_binding_digest_relation_bypassed", "|| binding_digest != admission.binding_digest", "|| false"),
    ("admission_authority_relation_bypassed", "|| authority_pair != admission.authority_pair", "|| false"),
    ("challenge_fence_witness_identity_bypassed", "|| challenge.state_fence.witness_identity != challenge.witness_identity", "|| false"),
    ("challenge_fence_witness_key_bypassed", "|| challenge.state_fence.witness_key_id != challenge.witness_key_id", "|| false"),
    ("ready_all_admissions_bypassed", "for admission in &self.config.admission_set.entries {", "for admission in &self.config.admission_set.entries[..1] {"),
    ("stored_session_bypassed", "if request_session(&request)", "if false && request_session(&request)"),
    ("establish_placeholder", "self.handle_establish(", "self.placeholder_establish("),
    ("discover_placeholder", "self.handle_discover(&request, &current, challenge).await", "self.placeholder_discover(&request, &current, challenge).await"),
    ("commit_placeholder", "self.handle_commit(&request, &current, session, txid).await", "self.placeholder_commit(&request, &current, session, txid).await"),
    ("abort_placeholder", "self.handle_abort(&request, &current, session, txid).await", "self.placeholder_abort(&request, &current, session, txid).await"),
    ("prepare_existing_resolution_bypassed", "WitnessPrepareVerificationV1::AlreadyPrepared(resolution)", "WitnessPrepareVerificationV1::New(resolution)"),
    ("prepare_conflict_observed_reverification_omitted", "return match verify_public_prepare(", "return match classify_observed_without_full_verification("),
    ("prepare_resolution_recas_added", ".into_outcome_for_store(&current.envelope)\n            .map_err(invalid)?;", ".into_outcome_for_store(&current.envelope)\n            .map_err(invalid)?; let _retry = self.proxy.compare_and_swap(placeholder_request()).await;"),
    ("challenge_freshness_omitted", ".validate_challenge_freshness(current, challenge)", ".placeholder_validate_challenge_freshness(current, challenge)"),
    ("omitted_confirming_read", '.read_authenticated(service_request, "confirm")', '.read_authenticated(service_request, "initial")'),
    ("wrong_response_digest", "response.request_digest != expected_digest", "false"),
    ("wrong_response_operation", "response.operation != WitnessStoreProxyOperationV1::CompareAndSwap", "false"),
    ("wrong_response_stream", "stream_id == admission.stream_id", "true"),
    ("wrong_previous_revision", "previous_revision == current.revision", "true"),
    ("wrong_new_revision", "new_revision > previous_revision", "true"),
    ("wrong_ack_digest", "acknowledged_value_digest == proposed_digest", "true"),
    ("confirm_revision_mismatch", "confirmed.revision <= current.revision", "false"),
    ("confirm_expected_revision_omitted", "expected_revision.is_some_and(|revision| confirmed.revision != revision)", "false"),
    ("confirm_envelope_substitution", "confirmed.envelope.canonical_bytes().map_err(invalid)?", "proposed.canonical_bytes().map_err(invalid)?"),
    ("lost_response_confirm_omitted", ".confirm_proposed(service_request, current, &proposed, None)", ".read_authenticated(service_request, \"confirm\")"),
    (
        "diagnostic_read_upgrades_transport_error",
        "let _diagnostic = self\n                    .confirm_proposed(service_request, current, &proposed, None)\n                    .await;\n                let _ = error;\n                return Err(PublicWitnessDispatchErrorV1::OutcomeUnknown);",
        "if let Ok(confirmed) = self\n                    .confirm_proposed(service_request, current, &proposed, None)\n                    .await\n                {\n                    return Ok(MutationStoreResult::Confirmed(Box::new(confirmed)));\n                }\n                let _ = error;\n                return Err(PublicWitnessDispatchErrorV1::OutcomeUnknown);",
    ),
    (
        "malformed_ack_downgraded_to_invalid",
        "response\n            .validate()\n            .map_err(|_| PublicWitnessDispatchErrorV1::OutcomeUnknown)?;",
        "response.validate().map_err(invalid)?;",
    ),
    (
        "wrong_ack_header_downgraded_to_invalid",
        "return Err(PublicWitnessDispatchErrorV1::OutcomeUnknown);\n        }\n        match response.body",
        "return Err(PublicWitnessDispatchErrorV1::Invalid);\n        }\n        match response.body",
    ),
    (
        "unknown_ack_downgraded_to_invalid",
        "_ => Err(PublicWitnessDispatchErrorV1::OutcomeUnknown),",
        "_ => Err(PublicWitnessDispatchErrorV1::Invalid),",
    ),
    (
        "conflict_ack_upgraded_to_confirmed",
        "Ok(MutationStoreResult::ObservedConflict(Box::new(observed)))",
        "Ok(MutationStoreResult::Confirmed(Box::new(observed)))",
    ),
    (
        "post_cas_retry_added",
        "let _diagnostic = self",
        "let _retry = self.proxy.compare_and_swap(request).await; let _diagnostic = self",
    ),
    ("confirm_store_digest_omitted", "confirmed.envelope.store_state_digest().map_err(invalid)?", "proposed.store_state_digest().map_err(invalid)?"),
    ("abort_retry_txid_bypassed", "if summary.txid == txid", "if true"),
    ("corrupt_key_unchecked", ".validate_for(WitnessStoreExpectationV1 {", ".validate_for(/* removed exact expectation */ WitnessStoreExpectationV1 {"),
    ("early_public_sign", "let confirmed = match self", "let _early_public_sign = self.signer.sign(&[]); let confirmed = match self"),
    ("signer_leakage", "request: WitnessStoreProxyRequestV1,", "request: WitnessStoreProxyRequestV1, signer: &Ed25519Signer,"),
    ("runner_wildcard_subject", '"swarm.governance.witness.v1.fence", queue.clone()', '"swarm.governance.witness.v1.>", queue.clone()'),
    ("runner_extra_subscription", "let establish = client", 'let extra = client.queue_subscribe("swarm.governance.witness.v1.extra", queue.clone()).await;\n        let establish = client'),
    ("runner_queue_group_substitution", 'const PUBLIC_WITNESS_QUEUE_GROUP: &str = "swarm-governance-witness-v1";', 'const PUBLIC_WITNESS_QUEUE_GROUP: &str = "foreign";'),
    ("runner_capacity_constant", "let capacity = dispatcher.config.ingress_queue_capacity;", "let capacity = 1024;"),
    ("runner_worker_bound_constant", "let worker_count = dispatcher.config.max_in_flight;", "let worker_count = 1024;"),
    ("runner_reply_from_payload", "let Some(reply) = message.reply else {", 'let Some(reply) = Some(async_nats::Subject::from("payload.reply")) else {'),
    ("runner_reply_namespace_bypassed", "if !is_bounded_inbox_reply(&reply)", "if false"),
    ("runner_queue_bypassed", "if !try_enqueue_public_message(&ingress, ingress_message)", "if false"),
    ("runner_try_send_bypassed", "ingress.try_send(message).is_ok()", "true"),
    ("ready_operation_bypassed", "response.operation != WitnessStoreProxyOperationV1::InspectReady", "false"),
    ("ready_stream_cardinality_bypassed", "validated_streams.len() != self.config.admission_set.entries.len()", "false"),
    ("ready_bucket_configuration_bypassed", "|| bucket_configuration_digest != self.config.bucket_configuration_digest", "|| false"),
    ("ready_manifest_digest_bypassed", "ready_manifest.digest().map_err(invalid)? != self.config.ready_manifest_digest", "false"),
    ("ready_manifest_epoch_bypassed", "ready_manifest.bucket_epoch_digest != self.config.bucket_epoch_digest", "false"),
    ("ready_manifest_configuration_bypassed", "ready_manifest.bucket_configuration_digest != self.config.bucket_configuration_digest", "false"),
    ("ready_manifest_admission_bypassed", "ready_manifest.admission_set_digest != self.config.admission_set_digest", "false"),
    ("ready_manifest_phase_bypassed", "ready_manifest.phase != WitnessBucketManifestPhaseV1::Ready", "false"),
    ("ready_witness_identity_bypassed", "ready_manifest.witness_identity != self.config.witness_identity", "false"),
    ("ready_witness_key_bypassed", "ready_manifest.witness_key_id != self.config.witness_key_id", "false"),
    ("ready_stream_set_bypassed", "ready_manifest.stream_keys != expected_stream_keys", "false"),
    ("ready_initialized_cardinality_bypassed", "ready_manifest.initialized_streams.len() != self.config.admission_set.entries.len()", "false"),
    ("ready_initialization_record_bypassed", "record.stream_initialization_digest != initialization_digest", "false"),
    ("ready_summary_initialization_bypassed", "summary.stream_initialization_digest != initialization_digest", "false"),
    ("ready_summary_revision_bypassed", "summary.revision != current.revision", "false"),
    ("ready_summary_digest_bypassed", "summary.store_state_digest", "current.envelope.store_state_digest().map_err(invalid)?"),
    ("proxy_admission_binding_bypassed", "admission_digest: admission.admission_digest.clone(),", 'admission_digest: "0".repeat(64),'),
    ("proxy_epoch_binding_bypassed", "bucket_epoch_digest: self.config.bucket_epoch_digest.clone(),", 'bucket_epoch_digest: "0".repeat(64),'),
    ("proxy_anchor_binding_bypassed", "bucket_anchor_digest: self.config.bucket_anchor_digest.clone(),", 'bucket_anchor_digest: "0".repeat(64),'),
    ("commit_preobserved_winner_bypassed", "commit_winner(&current.envelope, txid)", "None::<(String, WitnessCommitOutcomeV1)>.ok_or(ProtocolError::WitnessOutcomeMismatch)"),
    ("abort_preobserved_winner_bypassed", "abort_winner(&current.envelope, txid)", "None::<(String, WitnessAbortOutcomeV1)>.ok_or(ProtocolError::WitnessOutcomeMismatch)"),
    ("commit_conflict_winner_bypassed", "commit_winner(&observed.envelope, txid)", "None::<(String, WitnessCommitOutcomeV1)>.ok_or(ProtocolError::WitnessOutcomeMismatch)"),
    ("abort_conflict_winner_bypassed", "abort_winner(&observed.envelope, txid)", "None::<(String, WitnessAbortOutcomeV1)>.ok_or(ProtocolError::WitnessOutcomeMismatch)"),
    ("application_validation_unsigned", "WitnessServiceFailureV1::from_protocol_error(&error).failure_code", "WitnessServiceFailureCodeV1::InternalUnavailable"),
    ("stale_rotation_failure_substituted", "WitnessServiceFailureCodeV1::StaleRotationFence", "WitnessServiceFailureCodeV1::InternalUnavailable"),
    ("expected_head_failure_substituted", "WitnessServiceFailureCodeV1::ExpectedHeadMismatch", "WitnessServiceFailureCodeV1::InternalUnavailable"),
    ("prepare_transition_failure_substituted", "WitnessServiceFailureCodeV1::StoreTransitionRefused", "WitnessServiceFailureCodeV1::InternalUnavailable"),
    ("protocol_failure_conversion_bypassed", "failure_code_for_protocol(&error)", "WitnessServiceFailureCodeV1::InternalUnavailable"),
    ("candidate_verifier_call_bypassed", "let verified = match verify_public_prepare(", "let verified = match placeholder_prepare_candidate("),
    ("prepare_complete_validation_reintroduced", "if !matches!(request.body, WitnessServiceRequestBodyV1::Prepare { .. }) {", "if true {") ,
    ("selected_request_ceiling_bypassed", "usize::try_from(selected.max_request_bytes)", "usize::try_from(self.config.max_request_bytes as u64)"),
    ("selected_response_ceiling_bypassed", "usize::try_from(selected.max_response_bytes)", "usize::try_from(self.config.max_response_bytes as u64)"),
    ("selected_state_ceiling_bypassed", "candidate.state_payload.len() as u64 > admission.max_state_bytes", "false"),
    ("selected_checkpoint_ceiling_bypassed", "candidate.checkpoint_payload.len() as u64 > admission.max_checkpoint_bytes", "false"),
    ("selected_binding_ceiling_bypassed", "binding_bytes > admission.max_binding_bytes", "false"),
    ("selected_retained_wire_ceiling_bypassed", "retained_wire > admission.max_retained_bytes", "false"),
    ("selected_retained_payload_ceiling_bypassed", "retained_payload > admission.max_retained_bytes", "false"),
    ("proposed_entry_bounds_bypassed", "if validate_selected_entry_bounds(admission, &proposed).is_err()", "if false"),
    ("startup_entry_bounds_bypassed", "validate_selected_entry_bounds(admission, &current.envelope).map_err(invalid)?;", "/* startup entry bounds omitted */"),
    ("initial_entry_bounds_bypassed", "if validate_selected_entry_bounds(admission, &current.envelope).is_err()", "if false"),
    ("conflict_winner_bounds_bypassed", "if validate_selected_entry_bounds(admission, &observed.envelope).is_err()", "if false"),
    ("confirmation_bounds_bypassed", "if validate_selected_entry_bounds(admission, &confirmed.envelope).is_err()", "if false"),
    ("confirmation_unknown_collapsed", "return Err(PublicWitnessDispatchErrorV1::OutcomeUnknown);", "return Err(PublicWitnessDispatchErrorV1::Invalid);"),
]
digests = set()
for label, old, new in mutations:
    if old not in source:
        raise SystemExit(f"dispatcher source mutation target absent: {label}")
    mutant = source.replace(old, new, 1)
    digest = hashlib.sha256(mutant.encode()).hexdigest()
    if digest in digests:
        raise SystemExit(f"duplicate dispatcher source mutation: {label}")
    digests.add(digest)
    try:
        validate(mutant)
    except ValueError:
        print(f"dispatcher_source_mutation_red mutation={label}")
    else:
        raise SystemExit(f"dispatcher source mutation survived: {label}")

integration_mutations = [
    (
        "prestore_field_inventory_omitted",
        'const FIELDS: [&str; 7] = [\n        "stream",\n        "signer",\n        "witness_identity",\n        "witness_key",\n        "binding_generation",\n        "binding_digest",\n        "authority_pair",\n    ];',
        'const FIELDS: [&str; 7] = [\n        "signer",\n        "witness_identity",\n        "witness_key",\n        "binding_generation",\n        "binding_digest",\n        "authority_pair",\n    ];',
    ),
    (
        "prestore_field_inventory_substituted_exact",
        'const FIELDS: [&str; 7] = [\n        "stream",\n        "signer",\n        "witness_identity",\n        "witness_key",\n        "binding_generation",\n        "binding_digest",\n        "authority_pair",\n    ];',
        'const FIELDS: [&str; 7] = [\n        "stream",\n        "foreign_signer",\n        "witness_identity",\n        "witness_key",\n        "binding_generation",\n        "binding_digest",\n        "authority_pair",\n    ];',
    ),
    (
        "prestore_field_inventory_duplicated",
        'const FIELDS: [&str; 7] = [\n        "stream",\n        "signer",\n        "witness_identity",\n        "witness_key",\n        "binding_generation",\n        "binding_digest",\n        "authority_pair",\n    ];',
        'const FIELDS: [&str; 7] = [\n        "stream",\n        "signer",\n        "witness_identity",\n        "witness_key",\n        "binding_generation",\n        "binding_digest",\n        "stream",\n    ];',
    ),
    (
        "prestore_field_inventory_reordered",
        'const FIELDS: [&str; 7] = [\n        "stream",\n        "signer",\n        "witness_identity",\n        "witness_key",\n        "binding_generation",\n        "binding_digest",\n        "authority_pair",\n    ];',
        'const FIELDS: [&str; 7] = [\n        "signer",\n        "stream",\n        "witness_identity",\n        "witness_key",\n        "binding_generation",\n        "binding_digest",\n        "authority_pair",\n    ];',
    ),
    (
        "registered_overload_ingress_binding_omitted",
        "assert!(public_witness_ingress_overload_control());",
        "assert!(true);",
    ),
    ("signed_bounds_case_omitted", ".max_payload_bytes = 1;", ".max_payload_bytes = candidate.preimage.publication_binding.limits.max_payload_bytes;"),
    ("signed_verifier_only_case_omitted", "let verifier_only = Fixture::new_with_initial_intent(CasMode::Apply, 2)?;", "let verifier_only = Fixture::new(CasMode::Apply)?;"),
    ("signed_rotation_exhaustion_omitted", "exhausted.exhaust_current_session_generation()?;", "/* exhaustion omitted */"),
    ("signed_rotation_validation_case_omitted", "for operation in [\n        WitnessServiceOperationV1::Establish,\n        WitnessServiceOperationV1::Discover,\n    ] {", "for operation in [\n        WitnessServiceOperationV1::Establish,\n        WitnessServiceOperationV1::Establish,\n    ] {"),
    ("signed_expected_head_code_substituted", "WitnessServiceFailureCodeV1::ExpectedHeadMismatch", "WitnessServiceFailureCodeV1::InvalidSignature"),
    ("signed_failure_store_read_assertion_omitted", 'assert_eq!(bounds.proxy.events(), vec!["read"]);', "assert!(true);"),
    ("cross_commit_winner_substituted", "WitnessCommitOutcomeV1::GenesisAborted", "WitnessCommitOutcomeV1::Committed"),
    ("cross_abort_winner_substituted", "WitnessAbortOutcomeV1::Committed", "WitnessAbortOutcomeV1::AlreadyAborted"),
    ("cross_conflict_execution_omitted", "set_conflict_observed(revision, envelope);", "set_cas_mode(CasMode::Conflict);"),
    ("cross_stale_intent_substituted", "WitnessServiceFailureCodeV1::StaleIntent", "WitnessServiceFailureCodeV1::Conflict"),
    ("genesis_successor_execution_omitted", "assert_genesis_abort_successor_after_restart().await?;", "/* successor corpus omitted */"),
    ("genesis_successor_restart_bypassed", "let restarted_dispatcher = fixture.dispatcher()", "let restarted_dispatcher = first_dispatcher"),
    ("genesis_successor_next_intent_substituted", "let next_intent = aborted\n        .intent_counter\n        .checked_add(1)", "let next_intent = aborted\n        .intent_counter\n        .checked_add(2)"),
    ("genesis_successor_old_intent_control_omitted", "aborted.intent_counter,", "next_intent,"),
    ("genesis_successor_skipped_intent_control_omitted", "next_intent.checked_add(1)", "next_intent.checked_add(0)"),
    ("genesis_successor_outer_clear_assertion_omitted", "assert!(confirmed.genesis_abort.is_none());", "assert!(true);"),
    ("genesis_successor_persisted_receipt_assertion_substituted", "Some(&aborted)", "None"),
    ("ready_request_binding_substituted", '["bucket_anchor", "bucket_epoch", "admission"]', '["bucket_anchor", "bucket_epoch", "bucket_epoch"]'),
    ("prestore_fence_corpus_omitted", "assert_pre_store_admission_fences().await?;", "/* pre-store corpus omitted */"),
    ("prestore_field_inventory_substituted", '"authority_pair",', '"binding_digest",'),
    ("multistream_corpus_omitted", "assert_multistream_startup_controls().await?;", "/* multistream corpus omitted */"),
    ("multistream_positive_omitted", "two_stream.enable_second_stream()?;", "/* second stream omitted */"),
    ("multistream_cross_summary_omitted", "ReadyMutation::CrossStreamSummaries,", "ReadyMutation::MissingStream,"),
    ("prepare_classification_corpus_omitted", "assert_prepare_admission_classification().await?;", "/* classification corpus omitted */"),
    ("entry_bounds_corpus_omitted", "assert_authenticated_entry_limits_are_enforced().await?;", "/* entry bounds corpus omitted */"),
    ("taxonomy_corpus_omitted", "assert_bound_taxonomy_is_seam_specific().await?;", "/* taxonomy corpus omitted */"),
    ("taxonomy_field_substituted", 'for field in ["state", "checkpoint", "binding", "retained"]', 'for field in ["state", "checkpoint", "binding", "binding"]'),
    ("taxonomy_max_plus_one_omitted", "for exceeds in [false, true]", "for exceeds in [false, false]"),
    ("taxonomy_startup_assertion_omitted", 'assert_eq!(startup_result.is_err(), exceeds, "startup {field}");', "assert!(true);"),
    ("taxonomy_initial_code_substituted", "assert_eq!(\n                    failure.failure_code,\n                    WitnessServiceFailureCodeV1::BoundsExceeded\n                );\n                assert_eq!(failure.store_state_digest, Some(observed_digest));", "assert_eq!(\n                    failure.failure_code,\n                    WitnessServiceFailureCodeV1::Conflict\n                );\n                assert_eq!(failure.store_state_digest, Some(observed_digest));"),
    ("taxonomy_proposed_zero_cas_omitted", "assert_eq!(proposed.proxy.cas_attempted.load(Ordering::SeqCst), 0);", "assert!(true);"),
    ("taxonomy_conflict_winner_code_substituted", "WitnessServiceFailureCodeV1::BoundsExceeded\n                } else {\n                    WitnessServiceFailureCodeV1::Conflict", "WitnessServiceFailureCodeV1::Conflict\n                } else {\n                    WitnessServiceFailureCodeV1::Conflict"),
    ("taxonomy_confirmation_unknown_substituted", "Err(PublicWitnessDispatchErrorV1::OutcomeUnknown)", "Err(PublicWitnessDispatchErrorV1::Invalid)"),
    ("taxonomy_no_retry_assertion_omitted", "assert_eq!(confirmation.proxy.cas_attempted.load(Ordering::SeqCst), 1);", "assert!(true);"),
    ("lost_response_operation_omitted", "assert_lost_response_remains_unknown(OperationCase::Abort).await?;", "assert_lost_response_remains_unknown(OperationCase::Commit).await?;"),
    ("lost_response_prepare_omitted", "assert_lost_response_remains_unknown(OperationCase::Prepare).await?;", "assert_lost_response_remains_unknown(OperationCase::Discover).await?;"),
    ("lost_response_unknown_substituted", "async fn assert_lost_response_remains_unknown", "async fn assert_lost_response_is_confirmed"),
    ("lost_response_diagnostic_read_assertion_omitted", '&["read", "cas", "read"]', '&["read", "cas"]'),
    ("lost_response_attempt_count_omitted", "before_attempted + 1", "before_attempted"),
    ("lost_response_applied_count_omitted", "before_applied + 1", "before_applied"),
    ("post_cas_corpus_omitted", "assert_post_cas_acknowledgements_remain_unknown().await?;", "/* post-CAS corpus omitted */"),
    ("post_cas_event_sequence_omitted", 'if confirmation_attempted {\n                vec!["read", "cas", "read"]', 'if confirmation_attempted {\n                vec!["read", "cas"]'),
    ("post_cas_attempt_count_omitted", "assert_eq!(fixture.proxy.cas_attempted.load(Ordering::SeqCst), 1);\n        assert_eq!(fixture.proxy.cas_applied.load(Ordering::SeqCst), 1);", "assert_eq!(fixture.proxy.cas_attempted.load(Ordering::SeqCst), 0);\n        assert_eq!(fixture.proxy.cas_applied.load(Ordering::SeqCst), 1);"),
    ("post_cas_applied_count_omitted", "assert_eq!(fixture.proxy.cas_attempted.load(Ordering::SeqCst), 1);\n        assert_eq!(fixture.proxy.cas_applied.load(Ordering::SeqCst), 1);", "assert_eq!(fixture.proxy.cas_attempted.load(Ordering::SeqCst), 1);\n        assert_eq!(fixture.proxy.cas_applied.load(Ordering::SeqCst), 0);"),
    ("prepare_recovery_corpus_omitted", "assert_prepare_idempotency_and_recovery().await?;", "/* Prepare recovery corpus omitted */"),
    ("prepare_retry_outcome_substituted", "WitnessPrepareOutcomeV1::AlreadyPrepared(_)", "WitnessPrepareOutcomeV1::Prepared(_)"),
    ("prepare_conflict_outcome_substituted", "WitnessPrepareOutcomeV1::Conflict", "WitnessPrepareOutcomeV1::AlreadyPrepared(_)"),
    ("prepare_replay_after_unknown_omitted", "lost.dispatch_request(&lost_dispatcher, &original).await?", "placeholder_replay(&lost_dispatcher, &original).await?"),
    ("prepare_mixed_conflict_control_omitted", "let mut invalid_conflict = different_request.clone();", "let mut invalid_conflict = request.clone();"),
    ("prepare_mixed_retry_control_omitted", "let mut invalid_retry = request.clone();", "let mut invalid_retry = different_request.clone();"),
    ("prepare_preexisting_zero_cas_omitted", "fixture.proxy.cas_attempted.load(Ordering::SeqCst),\n        attempted", "fixture.proxy.cas_attempted.load(Ordering::SeqCst),\n        attempted + 1"),
    ("prepare_preexisting_applied_count_omitted", "fixture.proxy.cas_applied.load(Ordering::SeqCst), applied", "fixture.proxy.cas_applied.load(Ordering::SeqCst), applied + 1"),
    ("prepare_conflict_winner_loop_omitted", "for (same_winner, expected_already) in [(true, true), (false, false)]", "for (same_winner, expected_already) in [(true, true)]"),
    ("prepare_conflict_winner_retry_added", "assert_eq!(winner.proxy.cas_attempted.load(Ordering::SeqCst), 1);", "assert_eq!(winner.proxy.cas_attempted.load(Ordering::SeqCst), 2);"),
    ("current_head_corpus_omitted", "assert_current_head_intent_classification().await?;", "/* current-head intent corpus omitted */"),
    ("current_head_old_intent_omitted", "for intent in [\n        head.intent_counter,", "for intent in [\n        expected_intent,"),
    ("current_head_skipped_intent_omitted", "expected_intent\n            .checked_add(1)", "expected_intent\n            .checked_add(0)"),
    ("current_head_mixed_signature_control_substituted", "mixed.preimage.state_attestation.signature_hex", "mixed.preimage.state_attestation.key_id"),
    ("prepare_roles_code_substituted", "true,\n            false,\n            1,\n            WitnessServiceFailureCodeV1::AdmissionMismatch", "false,\n            false,\n            1,\n            WitnessServiceFailureCodeV1::StaleIntent"),
    ("prepare_mixed_code_substituted", "true,\n            false,\n            2,\n            WitnessServiceFailureCodeV1::AdmissionMismatch", "true,\n            false,\n            2,\n            WitnessServiceFailureCodeV1::StaleIntent"),
    ("prepare_mixed_authorization_control_omitted", '"authorization_signature",', '"state_signature",'),
    ("prepare_mixed_state_signature_control_omitted", '"state_signature",', '"checkpoint_signature",'),
    ("prepare_mixed_checkpoint_signature_control_omitted", '"checkpoint_signature",', '"predecessor_digest",'),
    ("prepare_mixed_predecessor_control_omitted", '"predecessor_digest",', '"authorization_signature",'),
    ("prepare_mixed_genesis_epoch_control_omitted", "(1, 0), (0, 1)", "(0, 0), (0, 1)"),
    ("prepare_mixed_genesis_sequence_control_omitted", "(1, 0), (0, 1)", "(1, 0), (0, 0)"),
    ("prepare_mixed_mapping_control_omitted", "std::mem::swap(", "placeholder_mapping_swap("),
    ("selected_state_case_substituted", '("state", state_len)', '("checkpoint", checkpoint_len)'),
    ("selected_checkpoint_case_substituted", '("checkpoint", checkpoint_len)', '("state", state_len)'),
    ("selected_binding_case_substituted", '("binding", binding_len)', '("state", state_len)'),
    ("selected_retained_case_substituted", '("retained", retained_len)', '("state", state_len)'),
    ("selected_candidate_max_plus_one_bypassed", "let ceiling = exact - u64::from(exceeds);", "let ceiling = exact;"),
    ("selected_request_max_plus_one_bypassed", "let ceiling = request_len - u64::from(exceeds);", "let ceiling = request_len;"),
    ("selected_response_max_plus_one_bypassed", "let ceiling = response_len - u64::from(exceeds);", "let ceiling = response_len;"),
    ("selected_precas_event_assertion_omitted", 'assert_eq!(fixture.secondary_events()?, vec!["read"]);', "assert!(true);"),
    ("selected_request_zero_call_assertion_omitted", "assert_eq!(fixture.proxy.calls.load(Ordering::SeqCst), 0);", "assert!(true);"),
    ("selected_response_code_substituted", "PublicWitnessDispatchErrorV1::ResponseBounds", "PublicWitnessDispatchErrorV1::Invalid"),
]
for ack_label in [
    "malformed", "duplicate", "lower", "wrong_kind", "wrong_stream",
    "wrong_previous_revision", "wrong_new_revision", "wrong_digest",
    "wrong_request_digest", "unknown", "wrong_value",
]:
    integration_mutations.append((
        f"post_cas_case_omitted_{ack_label}",
        f'"{ack_label}",',
        '"duplicate",' if ack_label == "malformed" else '"malformed",',
    ))
for ready_name in [
    "WrongOperation", "WrongRequestDigest", "WrongBucketConfiguration",
    "WrongManifestDigest", "WrongManifestPhase", "WrongManifestEpoch",
    "WrongWitnessIdentity", "WrongWitnessKey", "MissingStream", "ExtraStream",
    "WrongInitializationDigest", "WrongSummaryRevision", "WrongStoreDigest",
]:
    integration_mutations.append((
        f"ready_case_omitted_{ready_name}",
        f"(ReadyMutation::{ready_name}, ",
        "(ReadyMutation::None, ",
    ))
for label, old, new in integration_mutations:
    if old not in integration:
        raise SystemExit(f"dispatcher integration mutation target absent: {label}")
    mutant = integration.replace(old, new, 1)
    digest = hashlib.sha256((source + mutant + service).encode()).hexdigest()
    if digest in digests:
        raise SystemExit(f"duplicate dispatcher integration mutation: {label}")
    digests.add(digest)
    try:
        validate(source, mutant, config, service)
    except ValueError:
        print(f"dispatcher_source_mutation_red mutation={label}")
    else:
        raise SystemExit(f"dispatcher integration mutation survived: {label}")

config_mutations = [
    ("config_admission_set_validation_bypassed", "self.admission_set.validate()?;", "/* admission set validation omitted */"),
    ("config_admission_set_digest_bypassed", "self.admission_set.admission_set_digest != self.admission_set_digest", "false"),
    ("config_shared_witness_iteration_bypassed", "for admission in &self.admission_set.entries {", "for admission in &self.admission_set.entries[..1] {"),
    ("config_shared_witness_identity_bypassed", "admission.witness_identity != self.witness_identity", "false"),
    ("config_shared_witness_key_bypassed", "admission.witness_key_id != self.witness_key_id", "false"),
]
for label, old, new in config_mutations:
    if config.count(old) != 1:
        raise SystemExit(f"dispatcher config mutation target absent: {label}")
    mutant = config.replace(old, new, 1)
    digest = hashlib.sha256((source + integration + mutant + service).encode()).hexdigest()
    if digest in digests:
        raise SystemExit(f"duplicate dispatcher config mutation: {label}")
    digests.add(digest)
    try:
        validate(source, integration, mutant, service, protocol)
    except ValueError:
        print(f"dispatcher_source_mutation_red mutation={label}")
    else:
        raise SystemExit(f"dispatcher config mutation survived: {label}")

service_mutations = [
    (
        "outer_identity_dispatch_decode_bypassed",
        "request.validate_public_dispatch_identity()?;",
        "request.validate()?;",
    ),
    (
        "outer_identity_signing_bypassed",
        "request.validate_public_dispatch_identity()?;",
        "request.validate()?;",
    ),
    (
        "outer_identity_extractor_bypassed",
        "request.validate_public_dispatch_identity()?;",
        "request.validate()?;",
    ),
    (
        "outer_identity_failure_client_bypassed",
        "let identity = public_request_identity(request)?;",
        "let identity = request_identity(request)?;",
    ),
    (
        "outer_identity_digest_bypassed",
        "if self.request_digest != computed {",
        "if false {",
    ),
]
for index, (label, old, new) in enumerate(service_mutations):
    occurrences = [match.start() for match in re.finditer(re.escape(old), service)]
    if not occurrences:
        raise SystemExit(f"dispatcher service mutation target absent: {label}")
    if old.startswith("request.validate_public"):
        occurrence = min(index, len(occurrences) - 1)
    else:
        occurrence = 0
    position = occurrences[occurrence]
    mutant = service[:position] + new + service[position + len(old):]
    digest = hashlib.sha256((source + integration + mutant).encode()).hexdigest()
    if digest in digests:
        raise SystemExit(f"duplicate dispatcher service mutation: {label}")
    digests.add(digest)
    try:
        validate(source, integration, config, mutant, protocol)
    except ValueError:
        print(f"dispatcher_source_mutation_red mutation={label}")
    else:
        raise SystemExit(f"dispatcher service mutation survived: {label}")

verifier_mutations = [
    ("prepare_outer_identity_bypassed", "request\n        .validate_public_dispatch_identity()", "request\n        .validate()"),
    ("prepare_admission_digest_bypassed", "request.admission_digest != admission_entry.admission_digest", "false"),
    ("prepare_current_authentication_bypassed", "current_envelope\n        .validate_for(WitnessStoreExpectationV1 {", "current_envelope\n        .validate(); if false { WitnessStoreExpectationV1 {"),
    ("prepare_epoch_pin_self_bound", "bucket_epoch_digest: expected_bucket_epoch_digest,", "bucket_epoch_digest: &current_envelope.bucket_epoch_digest,"),
    ("prepare_initialization_pin_self_bound", "stream_initialization_digest: expected_stream_initialization_digest,", "stream_initialization_digest: &current_envelope.stream_initialization_digest,"),
    ("prepare_signer_key_bypassed", "witness_signer.key_id() != admission_entry.witness_key_id", "false"),
    ("prepare_body_match_bypassed", "let WitnessServiceRequestBodyV1::Prepare {", "let WitnessServiceRequestBodyV1::Commit {"),
    ("prepare_normalized_candidate_validation_bypassed", "candidate\n        .validate_for_expected_intent(expected.intent_counter)", "Ok(true)"),
    ("prepare_roles_relation_bypassed", "binding.publication_roles != admission_entry.publication_roles", "false"),
    ("prepare_limits_relation_bypassed", "binding.limits != admission_entry.limits", "false"),
    ("prepare_session_authorization_bypassed", "authorization\n        .verify_for_session_record(", "authorization\n        .placeholder_verify_for_session_record("),
    ("prepare_stored_session_bypassed", "if current_envelope.session.as_ref() != Some(session) {\n        return Err(WitnessServiceFailureCodeV1::StaleSession);", "if false {\n        return Err(WitnessServiceFailureCodeV1::StaleSession);"),
    ("prepare_expected_head_bypassed", "candidate.preimage.predecessor_head.as_ref() != expected_head.as_deref()", "false"),
    ("prepare_epoch_relation_bypassed", "candidate.preimage.epoch != expected.epoch", "false"),
    ("prepare_sequence_relation_bypassed", "candidate.preimage.sequence != expected.sequence", "false"),
    ("prepare_predecessor_digest_bypassed", "candidate.preimage.predecessor_head_digest != expected.predecessor_head_digest", "false"),
    ("prepare_predecessor_data_bypassed", "candidate.preimage.predecessor_data_head_digest != expected.predecessor_data_head_digest", "false"),
    ("prepare_mapping_bypassed", "candidate.preimage.publication_mapping_before != expected.publication_mapping", "false"),
    ("prepare_selected_bounds_bypassed", "enforce_selected_candidate_bounds(admission_entry, current_envelope, candidate)", "Ok(())"),
    ("prepare_intent_classifier_bypassed", "if !intent_matches {", "if false {"),
    ("prepare_genesis_proof_bypassed", "verified_stored_genesis_abort(current_envelope, expected_abort, witness_signer)", "placeholder_stored_genesis_abort(current_envelope, expected_abort, witness_signer)"),
    ("prepare_lower_verifier_bypassed", "WitnessCandidateVerifier::verify_prepare(", "WitnessCandidateVerifier::placeholder_verify_prepare("),
    ("prepare_classification_before_stronger_checks", "let verified = WitnessCandidateVerifier::verify_prepare(", "let verified = classify_existing_prepare_before_full_verification("),
    ("prepare_genesis_proof_omitted", "verified_abort.as_ref(),", "None,"),
    ("prepare_existing_branch_bypassed", "let Some(stored) = current_envelope.prepared.as_ref() else", "let Some(stored) = None else"),
    ("prepare_different_candidate_treated_idempotent", "} else {\n        VerifiedPrepareResolutionKindV1::Conflict\n    };", "} else {\n        VerifiedPrepareResolutionKindV1::AlreadyPrepared\n    };"),
    ("prepare_same_candidate_treated_conflict", "{\n        VerifiedPrepareResolutionKindV1::AlreadyPrepared\n    } else", "{\n        VerifiedPrepareResolutionKindV1::Conflict\n    } else"),
    ("prepare_resolution_store_digest_bypassed", "if current.store_state_digest()? != self.store_state_digest", "if false"),
    ("prepare_resolution_prepared_state_bypassed", "let stored = current\n            .prepared\n            .as_ref()", "let stored = placeholder_current()\n            .prepared\n            .as_ref()"),
    ("prepare_resolution_same_relation_constant", "let same = stored.prepared.head.txid == self.txid\n            && stored.prepared.head.candidate_digest == self.candidate_digest;", "let same = true;"),
    ("prepare_resolution_idempotent_outcome_substituted", "WitnessPrepareOutcomeV1::AlreadyPrepared(stored.prepared.clone())", "WitnessPrepareOutcomeV1::Conflict"),
    ("prepare_retry_slot_relations_bypassed", "if let Some(stored) = current.prepared.as_ref() {", "if false && let Some(stored) = current.prepared.as_ref() {"),
    ("prepare_retry_predecessor_relation_bypassed", "if stored.prepared.predecessor_head.as_ref() != expected_head", "if false"),
    ("prepare_retry_genesis_authority_bypassed", "let stored_genesis_abort = current_envelope.genesis_abort.as_ref().or_else(|| {\n        current_envelope\n            .prepared", "let stored_genesis_abort = current_envelope.genesis_abort.as_ref().or_else(|| {\n        placeholder_current_envelope()\n            .prepared"),
    ("prepare_lower_retry_genesis_authority_bypassed", "let authenticated_genesis_abort = current_envelope.genesis_abort.as_ref().or_else(|| {\n            current_envelope\n                .prepared", "let authenticated_genesis_abort = current_envelope.genesis_abort.as_ref().or_else(|| {\n            placeholder_current_envelope()\n                .prepared"),
]
for label, old, new in verifier_mutations:
    if verifier.count(old) != 1:
        raise SystemExit(f"dispatcher verifier mutation target absent: {label}")
    mutant = verifier.replace(old, new, 1)
    digest = hashlib.sha256((source + integration + service + protocol + mutant).encode()).hexdigest()
    if digest in digests:
        raise SystemExit(f"duplicate dispatcher verifier mutation: {label}")
    digests.add(digest)
    try:
        validate(source, integration, config, service, protocol, mutant)
    except ValueError:
        print(f"dispatcher_source_mutation_red mutation={label}")
    else:
        raise SystemExit(f"dispatcher verifier mutation survived: {label}")

protocol_mutations = [
    ("genesis_stored_session_validation_omitted", "session.validate()?;", "/* stored session validation omitted */"),
    ("genesis_stored_receipt_validation_omitted", "expected_abort.validate()?;", "/* stored receipt validation omitted */"),
    ("genesis_attestation_signature_unchecked", "attestation.validate()?;", "/* signature validation omitted */"),
    ("genesis_attestation_operation_unchecked", "attestation.operation != WitnessOperationV1::Abort", "false"),
    ("genesis_attestation_stream_unchecked", "attestation.stream_id != session.stream_id", "false"),
    ("genesis_attestation_binding_generation_unchecked", "attestation.binding_generation != session.binding_generation", "false"),
    ("genesis_attestation_binding_digest_unchecked", "attestation.binding_digest != session.binding_digest", "false"),
    ("genesis_attestation_signer_unchecked", "attestation.signer_key_id != session.signer_key_id", "false"),
    ("genesis_attestation_authority_unchecked", "attestation.authority_pair != session.authority_pair", "false"),
    ("genesis_attestation_generation_unchecked", "attestation.session_generation != session.session_generation", "false"),
    ("genesis_attestation_commitment_unchecked", "attestation.session_commitment != session.session_commitment", "false"),
    ("genesis_attestation_key_unchecked", "attestation.witness_key_id != session.witness_key_id", "false"),
    ("genesis_attestation_receipt_unchecked", "attestation.outcome != expected_outcome", "false"),
]
for label, old, new in protocol_mutations:
    start = protocol.index("    pub(crate) fn from_authenticated_store_genesis_abort(")
    end = protocol.index("    pub fn attestation", start)
    segment = protocol[start:end]
    if segment.count(old) != 1:
        raise SystemExit(f"dispatcher protocol mutation target absent: {label}")
    segment = segment.replace(old, new, 1)
    mutant = protocol[:start] + segment + protocol[end:]
    digest = hashlib.sha256((source + integration + service + mutant).encode()).hexdigest()
    if digest in digests:
        raise SystemExit(f"duplicate dispatcher protocol mutation: {label}")
    digests.add(digest)
    try:
        validate(source, integration, config, service, mutant)
    except ValueError:
        print(f"dispatcher_source_mutation_red mutation={label}")
    else:
        raise SystemExit(f"dispatcher protocol mutation survived: {label}")

normalized_protocol_mutations = [
    ("normalized_intent_substitution_omitted", "normalized.intent_counter = expected_intent_counter;", "normalized.intent_counter = self.preimage.intent_counter;"),
    ("normalized_semantics_bypassed", "normalized.validate()?;", "/* normalized semantics omitted */"),
    ("actual_candidate_preimage_bypassed", "let preimage_bytes = canonical_wire_bytes(&self.preimage)?;", "let preimage_bytes = canonical_wire_bytes(&normalized)?;"),
    ("actual_candidate_digest_bypassed", "if self.candidate_digest != candidate_digest", "if false"),
    ("actual_candidate_txid_bypassed", "if self.txid != txid", "if false"),
    ("intent_relation_constant", "Ok(self.preimage.intent_counter == expected_intent_counter)", "Ok(true)"),
]
for label, old, new in normalized_protocol_mutations:
    if protocol.count(old) != 1:
        raise SystemExit(f"dispatcher normalized protocol mutation target absent: {label}")
    mutant = protocol.replace(old, new, 1)
    digest = hashlib.sha256((source + integration + service + verifier + mutant).encode()).hexdigest()
    if digest in digests:
        raise SystemExit(f"duplicate dispatcher normalized protocol mutation: {label}")
    digests.add(digest)
    try:
        validate(source, integration, config, service, mutant, verifier)
    except ValueError:
        print(f"dispatcher_source_mutation_red mutation={label}")
    else:
        raise SystemExit(f"dispatcher normalized protocol mutation survived: {label}")

expected_mutations = (
    len(mutations)
    + len(integration_mutations)
    + len(config_mutations)
    + len(service_mutations)
    + len(verifier_mutations)
    + len(protocol_mutations)
    + len(normalized_protocol_mutations)
)
if len(digests) != expected_mutations:
    raise SystemExit("dispatcher source mutation digest cardinality differs")
print(f"dispatcher_source_guard_self_test mutations={expected_mutations} unique={len(digests)} passed=1")
PY
}

store_proxy_source_guard() {
  local source="$ROOT_DIR/crates/swarm-governance-witness/src/store_proxy_service.rs"
  local config="$ROOT_DIR/crates/swarm-governance-witness/src/service_config.rs"
  local integration="$ROOT_DIR/crates/swarm-governance-witness/tests/full_service_path.rs"
  local harness="$ROOT_DIR/tools/with-nats-jetstream.sh"
  local compose="$ROOT_DIR/docker-compose.yml"
  python3 -I - "$source" "$config" "$integration" "$harness" "$compose" "${1:-normal}" <<'PY'
import hashlib, re, sys

source, config, integration, harness, compose = [open(path, encoding="utf-8").read() for path in sys.argv[1:6]]
mode = sys.argv[6]
ids = [
    "runtime_private_subject", "runtime_raw_kv", "runtime_js_api", "witness_raw_kv",
    "witness_js_api", "init_serving_subject", "runtime_credential_swap",
    "witness_credential_swap", "store_credential_swap", "init_credential_swap",
    "account_swap", "mount_swap", "reply_subject_injection", "wildcard_import",
    "tls_ca_swap", "tls_server_name_swap", "store_queue_exhaustion",
    "public_store_bypass", "private_public_signing", "hostile_cleanup_preservation",
]

def validate(s=source, c=config, i=integration, h=harness, d=compose):
    subjects = re.findall(r'"(swarm\.governance\.witness\.store\.v1\.[a-z_]+)"', s)
    if sorted(set(subjects)) != sorted([
        "swarm.governance.witness.store.v1.inspect_ready",
        "swarm.governance.witness.store.v1.read_entry",
        "swarm.governance.witness.store.v1.compare_and_swap",
    ]): raise ValueError("private subject inventory differs")
    if 'const PRIVATE_STORE_QUEUE_GROUP: &str = "swarm-governance-witness-store-v1";' not in s:
        raise ValueError("private queue group differs")
    for fragment in [
        "WitnessStoreProxy::new(store, ready.clone())",
        "self.preflight(subject, raw)?;",
        "self.proxy.handle_bytes(raw)",
        ".validate_signature()",
        "request.signature.public_key_hex != self.config.pinned_witness_public_key_hex",
        "request.bucket_epoch_digest != self.config.bucket_epoch_digest",
        "request.bucket_anchor_digest != self.config.bucket_anchor_digest",
        "self.ready.entry(stream_id)",
        "raw.len() as u64 > admission.max_request_bytes",
        "max_response_bytes: self.config.max_response_bytes.min(selected_response_bytes)",
        "if bytes.len() > selected.max_response_bytes",
        "(bytes.len() <= selected.max_response_bytes).then_some(bytes)",
        "Duration::from_millis(self.config.request_deadline_millis)",
        "sender.try_send(ingress).is_err()",
        "service.overload_response(subject, &message.payload)",
        "private_store_ingress_overload_control() -> bool",
        "response.operation != operation || response.request_digest != request_digest",
        "pub struct StoreRoleConnectionV1 {",
        "StoreProxyReadyBindingV1::validated(&config, &ready)?",
        "StoreProxyReadyBindingV1::validated(config, ready)",
        ".validate_for_ready(ready)",
        "ready,\n            ready_binding,",
        "client,\n            ready_binding,",
        "canonical_wire_bytes(&(config, ready))",
        'b"swarm.phase285.store-proxy-ready-binding.v1"',
        "fn constant_time_matches(&self, other: &Self) -> bool {",
        "difference | (left ^ right)",
        ".constant_time_matches(&service.ready_binding)",
        "get_stream(&service.config.stream_name)",
        "credentials.role != \"witness-store\"",
        "credentials.invocation_token != config.credential_invocation_token",
        ".require_tls(true)",
        ".add_root_certificates(PathBuf::from(&config.tls_ca_path))",
        ".subscription_capacity(config.subscription_capacity)",
        ".client_capacity(config.client_capacity)",
        ".read_buffer_capacity(config.read_buffer_capacity)",
        "connection: StoreRoleConnectionV1",
    ]:
        if s.count(fragment) != 1: raise ValueError(f"private service boundary differs: {fragment}")
    if s.index("self.preflight(subject, raw)?;") > s.index("self.proxy.handle_bytes(raw)"):
        raise ValueError("private preflight occurs after store")
    if s.index(".constant_time_matches(&service.ready_binding)") > s.index("get_stream(&service.config.stream_name)") \
            or s.index(".constant_time_matches(&service.ready_binding)") > s.index(".queue_subscribe("):
        raise ValueError("Ready binding comparison occurs after external authority")
    for forbidden in ["$KV.", "$JS.API.", "Store::put", "Store::delete", "Store::purge"]:
        if forbidden in s: raise ValueError(f"private service exposes raw authority: {forbidden}")
    for fragment in [
        'if !self.nats_url.starts_with("tls://") || self.nats_url.contains("skip_verify")',
        "PublicKey::from_hex(&self.pinned_witness_public_key_hex)",
        "sha256_hex(public_key.as_bytes()) != self.witness_key_id",
        "ready.bucket_epoch.digest()? != self.bucket_epoch_digest",
        "ready.bucket_anchor.digest()? != self.bucket_anchor_digest",
        "ready.admission_set.admission_set_digest != self.admission_set_digest",
        "ready.bucket_configuration.stream_name != self.stream_name",
        '("subscription_capacity", self.subscription_capacity)',
        '("client_capacity", self.client_capacity)',
        'usize::from(self.read_buffer_capacity)',
    ]:
        if c.count(fragment) != 1: raise ValueError(f"private config boundary differs: {fragment}")
    found_ids = re.findall(r'^    "([a-z_]+)",$', re.search(r"const CAPABILITY_MATRIX: \[&str; 20\] = \[(.*?)\n\];", i, re.S).group(1), re.M)
    if found_ids != ids: raise ValueError("capability matrix inventory differs")
    for test in [
        "full_service_path_rejects_runtime_private_subject_and_store_raw_api",
        "full_service_path_rejects_credential_account_and_mount_swaps",
        "full_service_path_validates_proxy_response_before_public_attestation",
        "full_service_path_fails_closed_on_store_queue_exhaustion",
    ]:
        if len(re.findall(rf"(?:async )?fn {test}\(", i)) != 1: raise ValueError(f"registered capability test differs: {test}")
    for fragment in [
        "async fn assert_live_subject_refused(",
        "struct BlockingReadAtomicStore {",
        "secondary_response_bytes_at_limit(Some(exact_limit - 1))",
        "selected_overload_response_at_limit(overload_limit - 1)",
        "PHASE285_CAPABILITY_MATRIX_INVOCATION_TOKEN",
        "swarm.phase285.capability-evidence-row.v1",
        "assert_eq!(after, before);",
        "async fn assert_connection_service_ready_mismatch(",
        '"credential_path",', '"credential_token",', '"tls_url",', '"tls_ca",',
        '"tls_server_name",', '"subscription_capacity",', '"client_capacity",',
        '"read_capacity",', '"deadline",', '"worker_capacities",',
        '("stream", ReadyBindingMutation::Stream)',
        '("epoch", ReadyBindingMutation::Epoch)',
        '("anchor", ReadyBindingMutation::Anchor)',
        '("admission_set", ReadyBindingMutation::AdmissionSet)',
        '("selected_limits", ReadyBindingMutation::SelectedLimits)',
        '"binding mismatch touched the raw store: {label}"',
    ]:
        if fragment not in i: raise ValueError(f"capability execution evidence differs: {fragment}")
    for fragment in [
        'RUNTIME_ACCOUNT="PHASE285_RUNTIME"', 'WITNESS_ACCOUNT="PHASE285_WITNESS"',
        'EXPECTED_ACCOUNT="PHASE285_WITNESS_STORE"', 'RUNTIME_USER="phase285_foreign"',
        'WITNESS_USER="phase285_witness"', 'STORE_USER="phase285_witness_store"',
        'INIT_USER="phase285_expected"', 'cleanup_confined_scratch "$SCRATCH"',
        'TLS_RUNTIME_PASSWORD="$(openssl rand -hex 32)"',
        'TLS_WITNESS_PASSWORD="$(openssl rand -hex 32)"',
        'TLS_STORE_PASSWORD="$(openssl rand -hex 32)"',
        'TLS_INIT_PASSWORD="$(openssl rand -hex 32)"',
        'TLS_CREDENTIAL_TOKEN="$(openssl rand -hex 32)"',
        'openssl x509 -req -days 1',
        '  nats_tls:\n    image: "$PINNED_IMAGE"',
        'export SWARM_NATS_STORE_TLS_URL="tls://localhost:$tls_nats_port"',
    ]:
        if h.count(fragment) != 1: raise ValueError(f"harness authority boundary differs: {fragment}")
    for fragment in [
        "    - phase285-runtime\n", "    - phase285-witness\n", "    - phase285-witness-store\n",
        "phase285-init:", "url: tls://nats.phase285.test:4222",
        "- wildcard-service-import", "- cross-role-credential-mount",
    ]:
        if d.count(fragment) != 1: raise ValueError(f"compose authority boundary differs: {fragment}")
    if re.search(r"imports: \[[^\]]*[*>]", d): raise ValueError("compose wildcard import survived")
    if "mounts: [raw-store-credentials, witness-signing-key" in d:
        raise ValueError("store proxy gained signing authority")

validate()
if mode == "normal":
    print("store_proxy_source_guard passed=1")
    raise SystemExit(0)
if mode != "self-test": raise SystemExit("unknown store proxy source guard mode")
mutations = [
    ("omit_preflight", "source", "self.preflight(subject, raw)?;", ""),
    ("bypass_signature", "source", ".validate_signature()", ".validate_semantics()"),
    ("bypass_public_key", "source", "request.signature.public_key_hex != self.config.pinned_witness_public_key_hex", "false"),
    ("bypass_epoch", "source", "request.bucket_epoch_digest != self.config.bucket_epoch_digest", "false"),
    ("bypass_anchor", "source", "request.bucket_anchor_digest != self.config.bucket_anchor_digest", "false"),
    ("bypass_mapping", "source", "self.ready.entry(stream_id)", "self.ready.admission_set.entries.first()"),
    ("bypass_request_bound", "source", "raw.len() as u64 > admission.max_request_bytes", "false"),
    ("bypass_selected_response_bound", "source", "max_response_bytes: self.config.max_response_bytes.min(selected_response_bytes)", "max_response_bytes: self.config.max_response_bytes"),
    ("bypass_normal_response_bound", "source", "if bytes.len() > selected.max_response_bytes", "if false"),
    ("bypass_overload_response_bound", "source", "(bytes.len() <= selected.max_response_bytes).then_some(bytes)", "Some(bytes)"),
    ("unbounded_queue", "source", "sender.try_send(ingress).is_err()", "false"),
    ("omit_overload_response", "source", "service.overload_response(subject, &message.payload)", "None"),
    ("bypass_client_response_binding", "source", "response.operation != operation || response.request_digest != request_digest", "false"),
    ("arbitrary_store_client", "source", "connection: StoreRoleConnectionV1", "connection: async_nats::Client"),
    ("omit_ready_validation", "source", ".validate_for_ready(ready)", ".validate_transport()"),
    ("omit_service_binding", "source", "let ready_binding = StoreProxyReadyBindingV1::validated(&config, &ready)?;", "let ready_binding = StoreProxyReadyBindingV1([0_u8; 32]);"),
    ("omit_connection_binding", "source", "let ready_binding = StoreProxyReadyBindingV1::validated(config, ready)", "let ready_binding = StoreProxyReadyBindingV1([0_u8; 32])"),
    ("bypass_binding_comparison", "source", ".constant_time_matches(&service.ready_binding)", ".constant_time_matches(&connection.ready_binding)"),
    ("weaken_binding_comparison", "source", "fn constant_time_matches(&self, other: &Self) -> bool {", "fn constant_time_matches(&self, _other: &Self) -> bool { return true;"),
    ("constant_binding_comparison", "source", "difference | (left ^ right)", "difference"),
    ("cross_copy_service_binding", "source", "ready,\n            ready_binding,", "ready,\n            ready_binding: StoreProxyReadyBindingV1([0_u8; 32]),"),
    ("self_bind_connection", "source", "client,\n            ready_binding,", "client,\n            ready_binding: StoreProxyReadyBindingV1([0_u8; 32]),"),
    ("bypass_store_role", "source", "credentials.role != \"witness-store\"", "false"),
    ("bypass_credential_token", "source", "credentials.invocation_token != config.credential_invocation_token", "false"),
    ("bypass_tls_requirement", "source", ".require_tls(true)", ".require_tls(false)"),
    ("bypass_pinned_ca", "source", ".add_root_certificates(PathBuf::from(&config.tls_ca_path))", ""),
    ("bypass_store_account_probe", "source", "get_stream(&service.config.stream_name)", "get_stream(\"foreign\")"),
    ("bypass_subscription_capacity", "source", ".subscription_capacity(config.subscription_capacity)", ".subscription_capacity(1024)"),
    ("bypass_client_capacity", "source", ".client_capacity(config.client_capacity)", ".client_capacity(1024)"),
    ("bypass_read_capacity", "source", ".read_buffer_capacity(config.read_buffer_capacity)", ".read_buffer_capacity(65535)"),
    ("plaintext_tls", "config", 'if !self.nats_url.starts_with("tls://") || self.nats_url.contains("skip_verify") {', 'if !self.nats_url.starts_with("nats://") || self.nats_url.contains("skip_verify") {'),
    ("bypass_pinned_key", "config", "sha256_hex(public_key.as_bytes()) != self.witness_key_id", "false"),
    ("bypass_stream_binding", "config", "ready.bucket_configuration.stream_name != self.stream_name", "false"),
    ("fixed_tls_credentials", "harness", 'TLS_STORE_PASSWORD="$(openssl rand -hex 32)"', 'TLS_STORE_PASSWORD="fixed"'),
    ("tls_listener_omitted", "harness", '  nats_tls:\n    image: "$PINNED_IMAGE"', '  nats_tls_missing:\n    image: "$PINNED_IMAGE"'),
    ("account_swap", "harness", 'WITNESS_ACCOUNT="PHASE285_WITNESS"', 'WITNESS_ACCOUNT="PHASE285_RUNTIME"'),
    ("credential_swap", "harness", 'STORE_USER="phase285_witness_store"', 'STORE_USER="phase285_witness"'),
    ("cleanup_omitted", "harness", 'cleanup_confined_scratch "$SCRATCH"', 'true'),
    ("wildcard_import", "compose", "imports: [swarm.governance.witness.store.v1]", "imports: [swarm.governance.witness.store.>]") ,
    ("cross_role_mount", "compose", "mounts: [raw-store-credentials, witness-public-key, phase285-ca]", "mounts: [raw-store-credentials, witness-signing-key, phase285-ca]"),
    ("capability_omission", "integration", '    "runtime_private_subject",\n    "runtime_raw_kv",', '    "runtime_raw_kv",'),
    ("capability_rename", "integration", '    "private_public_signing",\n    "hostile_cleanup_preservation",', '    "private_public_signing",\n    "cleanup_preservation",'),
]
values = {"source":source,"config":config,"integration":integration,"harness":harness,"compose":compose}
digests=[]
for label, which, old, new in mutations:
    if values[which].count(old) != 1: raise SystemExit(f"store proxy mutation anchor differs: {label}")
    changed = values.copy(); changed[which] = changed[which].replace(old,new,1)
    combined = "\0".join(changed[key] for key in ["source","config","integration","harness","compose"])
    digests.append(hashlib.sha256(combined.encode()).hexdigest())
    try: validate(changed["source"],changed["config"],changed["integration"],changed["harness"],changed["compose"])
    except (ValueError, AttributeError): print(f"store_proxy_source_mutation_red mutation={label}")
    else: raise SystemExit(f"store proxy source mutant survived: {label}")
if len(set(digests)) != len(mutations): raise SystemExit("store proxy mutation digests differ")
print(f"store_proxy_source_guard_self_test mutations={len(mutations)} unique={len(set(digests))} passed=1")
PY
}

inner_ids_for_case() {
  case "$1" in
    capability-matrix) cat <<'EOF'
runtime_private_subject
runtime_raw_kv
runtime_js_api
witness_raw_kv
witness_js_api
init_serving_subject
runtime_credential_swap
witness_credential_swap
store_credential_swap
init_credential_swap
account_swap
mount_swap
reply_subject_injection
wildcard_import
tls_ca_swap
tls_server_name_swap
store_queue_exhaustion
public_store_bypass
private_public_signing
hostile_cleanup_preservation
EOF
      ;;
    dispatcher-mapping) cat <<'EOF'
issue_session_fence
establish_session
discover_stream
prepare_successor
commit_prepared
abort_prepared
read_prepared_for_stream
read_head
fetch_payload
EOF
      ;;
    jetstream_cas_rejects_raw_config_unknown_field_or_persist_mode) cat <<'EOF'
raw.binding.anchor_digest
raw.binding.epoch_digest
raw.present.name
raw.created.zero
raw.created.one
raw.created.eight
raw.created.nine
raw.created.changed_instant
raw.digest.length_delimiter
raw.binding.distinct_digests
raw.absent.unknown
raw.absent.persist_mode_async
raw.absent.persist_mode_sync
raw.absent.no_ack
raw.absent.discard_new_per_subject
raw.absent.template_owner
raw.absent.placement
raw.absent.mirror
raw.absent.sources
raw.absent.first_seq
raw.absent.subject_transform
raw.absent.republish
raw.absent.subject_delete_marker_ttl
raw.absent.allow_atomic
raw.absent.allow_msg_schedules
raw.absent.allow_msg_counter
raw.absent.pause_until
raw.info.unknown_field
raw.runtime.wrong_version
raw.runtime.wrong_image
raw.duplicate.name
binding.swapped_digest
binding.substituted_digest
binding.foreign_anchor_epoch
binding.creation_time
binding.foreign_stream
binding.signature
EOF
      ;;
    jetstream_cas_rejects_each_raw_config_mutation)
      cat <<'EOF'
raw.present.cardinality
raw.present.name
raw.present.description
raw.present.subjects
raw.present.retention
raw.present.max_consumers
raw.present.max_msgs
raw.present.max_bytes
raw.present.max_age
raw.present.max_msgs_per_subject
raw.present.max_msg_size
raw.present.discard
raw.present.storage
raw.present.num_replicas
raw.present.duplicate_window
raw.present.compression
raw.present.allow_direct
raw.present.mirror_direct
raw.present.sealed
raw.present.deny_delete
raw.present.deny_purge
raw.present.allow_rollup_hdrs
raw.present.consumer_limits
raw.present.allow_msg_ttl
raw.present.metadata
raw.semantic.name
raw.semantic.description
raw.semantic.subjects
raw.semantic.retention
raw.semantic.max_consumers
raw.semantic.max_msgs
raw.semantic.max_bytes
raw.semantic.max_age
raw.semantic.max_msgs_per_subject
raw.semantic.max_msg_size
raw.semantic.discard
raw.semantic.storage
raw.semantic.num_replicas
raw.semantic.duplicate_window
raw.semantic.compression
raw.semantic.allow_direct
raw.semantic.mirror_direct
raw.semantic.sealed
raw.semantic.deny_delete
raw.semantic.deny_purge
raw.semantic.allow_rollup_hdrs
raw.semantic.consumer_limits
raw.semantic.allow_msg_ttl
raw.semantic.metadata
EOF
      ;;
    jetstream_cas_rejects_wrong_revision_header_or_ack) cat <<'EOF'
cas.validator.read
inspect.stable_iterator_complete
cas.conflict.wrong_revision
cas.refusal.wrong_revision_immutable
cas.conflict.zero_revision
cas.refusal.zero_revision_immutable
EOF
      ;;
    jetstream_cas_confirms_raw_sequence_and_bytes) cat <<'EOF'
cas.validator.transition
inspect.stable_iterator_complete
ack.expected_previous_revision
ack.previous_revision
ack.increasing_sequence
ack.digest
ack.not_duplicate
read.sequence
read.envelope
read.bytes
read.digest
EOF
      ;;
    jetstream_cas_rejects_del_purge_rollup_and_direct_reads) cat <<'EOF'
header.reject.delete
header.reject.purge
header.reject.unknown
header.reject.rollup
read.reject.direct_config
read.reject.direct_api
read.leader.open
EOF
      ;;
    jetstream-cas-scenarios) cat <<'EOF'
genesis
rotation
sealed_prepare
commit
abort
read
conflict
exact_idempotent_observation
resigned_content
resigned_stale_session
resigned_admission
component_limit
capacity
crash_before_cas
lost_after_cas
wrong_revision_ack
duplicate_ack
corrupt_read
injected_capacity
EOF
      ;;
    jetstream_checkpoint_survives_restart_for_current_predecessor_prepared_abort_and_genesis) cat <<'EOF'
state.current.ack_persisted
state.predecessor.ack_persisted
state.prepared.ack_persisted
state.abort.ack_persisted
state.genesis_abort.ack_persisted
barrier.ack_before_release
barrier.token_exact_once
restart.same_image
restart.same_volume
restart.same_project_service_leader
EOF
      ;;
    jetstream_checkpoint_rejects_rolled_back_anchor_or_recreated_stream) cat <<'EOF'
anchor.stale_created_refused
anchor.recreated_stream_refused
anchor.ready_initialization_bound
EOF
      ;;
    jetstream_checkpoint_rejects_unavailable_server_instead_of_skipping) cat <<'EOF'
server.unavailable_refused
account.foreign_refused
iterator.incomplete_refused
EOF
      ;;
    jetstream_checkpoint_uses_global_revision_not_store_generation) cat <<'EOF'
revision.ten_a_updates
revision.b_first_global_sequence
revision.expected_last_subject_sequence
revision.store_generation_distinct
revision.global_tail_mutant_killed
EOF
      ;;
    *) return 1 ;;
  esac
}

write_expected_inner_ledger() {
  local case_name="$1" output="$2"
  python3 -I - "$case_name" "$output" <(inner_ids_for_case "$case_name") <<'PY'
import hashlib
import json
import pathlib
import sys

case_name, output, ids_path = sys.argv[1:]
domain = b"swarm.phase285.witness-inner-ledger-row.v1"
ids = [line.strip() for line in pathlib.Path(ids_path).read_text().splitlines() if line.strip()]
if not ids or len(ids) != len(set(ids)):
    raise SystemExit("inner expected projection is empty or duplicated")
rows = []
for inner_id in ids:
    canonical = json.dumps(
        {"case": case_name, "inner_id": inner_id, "status": "passed"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(domain + len(canonical).to_bytes(8, "big") + canonical).hexdigest()
    rows.append(f"{case_name}\t{inner_id}\tpassed\t{digest}")
pathlib.Path(output).write_text("\n".join(rows) + "\n")
PY
}

inner_ledger_validator() {
  local expected="$1" observed="$2" mode="${3:-validate}"
  python3 -I - "$expected" "$observed" "$mode" <<'PY'
import copy
import hashlib
import json
import pathlib
import sys

expected_path = pathlib.Path(sys.argv[1])
observed_path = pathlib.Path(sys.argv[2])
mode = sys.argv[3]
domain = b"swarm.phase285.witness-inner-ledger-row.v1"

def digest(case_name, inner_id, status):
    canonical = json.dumps(
        {"case": case_name, "inner_id": inner_id, "status": status},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(domain + len(canonical).to_bytes(8, "big") + canonical).hexdigest()

def parse(raw):
    if not raw or not raw.endswith(b"\n") or b"\n\n" in raw:
        raise ValueError("inner ledger is empty or noncanonical")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("inner ledger is not ASCII") from error
    rows = [line.split("\t") for line in text.splitlines()]
    if any(len(row) != 4 for row in rows):
        raise ValueError("inner ledger row width differs")
    for case_name, inner_id, status, row_digest in rows:
        if not case_name or not inner_id or status != "passed":
            raise ValueError("inner ledger schema/status differs")
        if row_digest != digest(case_name, inner_id, status):
            raise ValueError("inner ledger row digest differs")
    if len({(row[0], row[1]) for row in rows}) != len(rows):
        raise ValueError("inner ledger identity is duplicated")
    return rows

expected_rows = parse(expected_path.read_bytes())

def encode(rows):
    return ("\n".join("\t".join(row) for row in rows) + "\n").encode() if rows else b""

def validate(candidate_raw):
    rows = parse(candidate_raw)
    if len(rows) != len(expected_rows):
        raise ValueError("inner ledger cardinality differs")
    expected_set = {tuple(row) for row in expected_rows}
    if {tuple(row) for row in rows} != expected_set:
        raise ValueError("inner ledger exact set differs")
    return rows

observed_raw = observed_path.read_bytes()
observed_rows = validate(observed_raw)
if mode == "validate":
    print(f"inner_ledger rows={len(observed_rows)} passed={len(observed_rows)} failed=0")
    raise SystemExit(0)
if mode != "self-test":
    raise SystemExit(f"unknown inner-ledger validator mode: {mode}")

def refresh(row):
    row[3] = digest(row[0], row[1], row[2])

mutants = []
omitted = copy.deepcopy(observed_rows); omitted.pop(0); mutants.append(("omission", omitted))
added = copy.deepcopy(observed_rows); added.append([added[0][0], "unexpected_extra", "passed", ""]); refresh(added[-1]); mutants.append(("addition", added))
duplicated = copy.deepcopy(observed_rows); duplicated.append(duplicated[0].copy()); mutants.append(("duplication", duplicated))
mutants.append(("zero_rows", []))
renamed = copy.deepcopy(observed_rows); renamed[0][1] += "_renamed"; refresh(renamed[0]); mutants.append(("renamed_id", renamed))
wrong_status = copy.deepcopy(observed_rows); wrong_status[0][2] = "failed"; refresh(wrong_status[0]); mutants.append(("wrong_status", wrong_status))
wrong_digest = copy.deepcopy(observed_rows); wrong_digest[0][3] = "0" * 64; mutants.append(("wrong_digest", wrong_digest))
stale = copy.deepcopy(observed_rows); stale[0][1] += "_stale"; refresh(stale[0]); mutants.append(("stale_ledger", stale))
cross_case = copy.deepcopy(observed_rows); cross_case[0][0] += "-foreign"; refresh(cross_case[0]); mutants.append(("cross_case_ledger", cross_case))

for name, rows in mutants:
    try:
        validate(encode(rows))
    except ValueError:
        print(f"inner_ledger_self_test_red mutation={name}")
    else:
        raise SystemExit(f"inner-ledger mutation unexpectedly passed: {name}")
print(f"inner_ledger_self_test mutations={len(mutants)} passed=1")
PY
}

capability_ledger_validator() {
  local observed="$1" invocation_token="$2" mode="${3:-validate}"
  python3 -I - "$observed" "$invocation_token" "$mode" <<'PY'
import copy, hashlib, json, pathlib, sys

path = pathlib.Path(sys.argv[1])
invocation_token = sys.argv[2]
mode = sys.argv[3]
domain = b"swarm.phase285.capability-evidence-row.v1"
expected = {
  "runtime_private_subject": ("runtime","PHASE285_RUNTIME","swarm.governance.witness.store.v1.read_entry","no_private_import"),
  "runtime_raw_kv": ("runtime","PHASE285_RUNTIME",None,"raw_subject_refused"),
  "runtime_js_api": ("runtime","PHASE285_RUNTIME","$JS.API.STREAM.INFO.KV_phase285_service","foreign_stream_invisible"),
  "witness_raw_kv": ("witness","PHASE285_WITNESS",None,"raw_subject_refused"),
  "witness_js_api": ("witness","PHASE285_WITNESS","$JS.API.STREAM.INFO.KV_phase285_service","raw_api_refused"),
  "init_serving_subject": ("init","PHASE285_WITNESS_STORE","swarm.governance.witness.store.v1.read_entry","serving_subject_refused"),
  "runtime_credential_swap": ("runtime","PHASE285_WITNESS_STORE","KV_phase285_service","credential_role_refused"),
  "witness_credential_swap": ("witness","PHASE285_WITNESS_STORE","KV_phase285_service","credential_role_refused"),
  "store_credential_swap": ("witness-store","PHASE285_WITNESS","swarm.governance.witness.store.v1.read_entry","cross_role_login_refused"),
  "init_credential_swap": ("init","PHASE285_WITNESS_STORE","KV_phase285_service","credential_role_refused"),
  "account_swap": ("witness-store","PHASE285_RUNTIME","KV_phase285_service","account_stream_probe_refused"),
  "mount_swap": ("witness-store","PHASE285_WITNESS_STORE","raw-store-credentials","cross_role_mount_absent"),
  "reply_subject_injection": ("witness","PHASE285_WITNESS","swarm.governance.witness.store.v1.read_entry","invalid_reply_inbox"),
  "wildcard_import": ("topology","PHASE285_WITNESS","swarm.governance.witness.store.v1.>","wildcard_import_absent"),
  "tls_ca_swap": ("witness-store","PHASE285_WITNESS_STORE","tls://localhost","ca_authentication_refused"),
  "tls_server_name_swap": ("witness-store","PHASE285_WITNESS_STORE","wrong.phase285.test","server_name_refused"),
  "store_queue_exhaustion": ("witness","PHASE285_WITNESS","swarm.governance.witness.store.v1.read_entry","overload_unavailable"),
  "public_store_bypass": ("runtime","PHASE285_RUNTIME","StoreProxyService","raw_store_api_absent"),
  "private_public_signing": ("witness-store","PHASE285_WITNESS_STORE","StoreProxyService","public_signer_absent"),
  "hostile_cleanup_preservation": ("harness","confined-project","cleanup_confined_scratch","cleanup_fail_closed"),
}

def row_digest(row):
    canonical = json.dumps({
      "account":row[5], "case":row[0], "credential_role":row[4],
      "expected_failure":row[7], "inner_id":row[1], "invocation_token":row[3],
      "status":row[2], "store_calls_after":int(row[9]),
      "store_calls_before":int(row[8]), "subject":row[6],
    }, sort_keys=True, separators=(",",":"), allow_nan=False).encode()
    return hashlib.sha256(domain + len(canonical).to_bytes(8,"big") + canonical).hexdigest()

def refresh(row): row[10] = row_digest(row)

def parse(raw):
    if not raw or not raw.endswith(b"\n") or b"\n\n" in raw: raise ValueError("capability ledger framing differs")
    try: lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error: raise ValueError("capability ledger is not ASCII") from error
    rows = [line.split("\t") for line in lines]
    if any(len(row) != 11 for row in rows): raise ValueError("capability ledger width differs")
    if len(rows) != len(expected) or len({row[1] for row in rows}) != len(rows): raise ValueError("capability cardinality differs")
    if {row[1] for row in rows} != set(expected): raise ValueError("capability inventory differs")
    for row in rows:
        case, inner_id, status, token, role, account, subject, failure, before, after, digest = row
        if case != "capability-matrix" or status != "passed" or token != invocation_token:
            raise ValueError("capability identity/status/token differs")
        expected_role, expected_account, expected_subject, expected_failure = expected[inner_id]
        if (role,account,failure) != (expected_role,expected_account,expected_failure):
            raise ValueError("capability role/account/failure differs")
        if expected_subject is None:
            if not subject.startswith("$KV.phase285_service.s.") or len(subject) != len("$KV.phase285_service.s.") + 64:
                raise ValueError("capability derived raw subject differs")
        elif subject != expected_subject: raise ValueError("capability subject differs")
        if not before.isascii() or not before.isdigit() or not after.isascii() or not after.isdigit():
            raise ValueError("capability counters differ")
        if int(before) != int(after): raise ValueError("capability reached storage")
        if inner_id == "store_queue_exhaustion" and int(before) != 1:
            raise ValueError("queue overload did not bind one blocked store call")
        if digest != row_digest(row): raise ValueError("capability digest differs")
    return rows

raw = path.read_bytes()
rows = parse(raw)
if mode == "validate":
    print(f"capability_ledger rows={len(rows)} passed={len(rows)} failed=0")
    raise SystemExit(0)
if mode != "self-test": raise SystemExit("unknown capability ledger mode")
def encode(value): return ("\n".join("\t".join(row) for row in value)+"\n").encode() if value else b""
mutants=[]
omitted=copy.deepcopy(rows); omitted.pop(); mutants.append(("omission",omitted))
added=copy.deepcopy(rows); added.append(added[0].copy()); added[-1][1]="unexpected"; refresh(added[-1]); mutants.append(("addition",added))
duplicated=copy.deepcopy(rows); duplicated.append(duplicated[0].copy()); mutants.append(("duplication",duplicated))
mutants.append(("zero",[]))
for name,index,value in [
 ("rename",1,rows[0][1]+"_renamed"),("status",2,"failed"),("stale_token",3,"stale-token"),
 ("role_substitution",4,"foreign"),("account_substitution",5,"foreign"),
 ("subject_substitution",6,"foreign.subject"),("failure_substitution",7,"success"),
 ("store_call_substitution",9,str(int(rows[0][9])+1)),
]:
    changed=copy.deepcopy(rows); changed[0][index]=value; refresh(changed[0]); mutants.append((name,changed))
wrong_digest=copy.deepcopy(rows); wrong_digest[0][10]="0"*64; mutants.append(("wrong_digest",wrong_digest))
cross=copy.deepcopy(rows); cross[0][4:8]=cross[1][4:8]; refresh(cross[0]); mutants.append(("cross_row_substitution",cross))
labels=[name for name,_ in mutants]
if len(labels) != len(set(labels)): raise SystemExit("capability mutant labels duplicated")
for name,candidate in mutants:
    try: parse(encode(candidate))
    except ValueError: print(f"capability_ledger_self_test_red mutation={name}")
    else: raise SystemExit(f"capability ledger mutant survived: {name}")
print(f"capability_ledger_self_test mutations={len(mutants)} passed=1")
PY
}

checkpoint_iterator_ledger_validator() {
  local selector_root="$1" accepted_tree="$2" invocation_token="$3" mode="${4:-validate}"
  python3 -I - "$selector_root" "$accepted_tree" "$invocation_token" "$mode" <<'PY'
import copy, hashlib, json, pathlib, sys

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
accepted_tree, invocation_token, mode = sys.argv[2:]
path = root / "checkpoint-iterator.ledger.tsv"
case = "jetstream-checkpoint-iterator"
domain = b"swarm.phase285.witness-iterator-ledger-row.v1"
expected_ids = [
    "iterator.understated_advertised",
    "iterator.short_iterator",
    "iterator.pagination_error",
    "iterator.cross_page_duplicate_or_wildcard",
    "iterator.cumulative_overflow",
    "iterator.final_closed_snapshot",
]

def digest(inner_id, status, tree, token):
    canonical = json.dumps(
        {"accepted_tree":tree,"case":case,"inner_id":inner_id,"invocation_token":token,"status":status},
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()
    return hashlib.sha256(domain + len(canonical).to_bytes(8, "big") + canonical).hexdigest()

def encode(rows):
    return ("\n".join("\t".join(row) for row in rows) + "\n").encode() if rows else b""

def parse(raw):
    if not raw or not raw.endswith(b"\n") or b"\n\n" in raw:
        raise ValueError("iterator ledger framing differs")
    rows = [line.split("\t") for line in raw.decode("ascii").splitlines()]
    if any(len(row) != 6 for row in rows): raise ValueError("iterator ledger row width differs")
    for row_case, inner_id, status, tree, token, row_digest in rows:
        if row_case != case or status != "passed" or tree != accepted_tree or token != invocation_token:
            raise ValueError("iterator ledger binding differs")
        if row_digest != digest(inner_id,status,tree,token): raise ValueError("iterator ledger digest differs")
    if len({(row[0],row[1]) for row in rows}) != len(rows): raise ValueError("iterator ledger duplicates")
    return rows

resolved = path.resolve(strict=True)
if resolved.parent != root or path.is_symlink() or not path.is_file(): raise ValueError("iterator ledger path differs")
observed = parse(path.read_bytes())
if [row[1] for row in observed] != expected_ids: raise ValueError("iterator ledger exact ordered IDs differ")
if mode == "validate":
    print(f"checkpoint_iterator_ledger rows={len(observed)} passed={len(observed)} failed=0")
    raise SystemExit(0)
if mode != "self-test": raise SystemExit("unknown iterator ledger validator mode")

def refresh(row): row[5] = digest(row[1],row[2],row[3],row[4])
mutants = []
candidate=copy.deepcopy(observed); candidate.pop(0); mutants.append(("omission",candidate))
candidate=copy.deepcopy(observed); candidate.append([case,"iterator.extra","passed",accepted_tree,invocation_token,""]); refresh(candidate[-1]); mutants.append(("addition",candidate))
candidate=copy.deepcopy(observed); candidate.append(candidate[0].copy()); mutants.append(("duplication",candidate))
mutants.append(("zero_rows",[]))
candidate=copy.deepcopy(observed); candidate[0][1]+="_renamed"; refresh(candidate[0]); mutants.append(("renamed_id",candidate))
candidate=copy.deepcopy(observed); candidate[0][2]="failed"; refresh(candidate[0]); mutants.append(("wrong_status",candidate))
candidate=copy.deepcopy(observed); candidate[0][5]="0"*64; mutants.append(("wrong_digest",candidate))
candidate=copy.deepcopy(observed); candidate[0][4]="stale"; refresh(candidate[0]); mutants.append(("stale_token",candidate))
candidate=copy.deepcopy(observed); candidate[0][3]="0"*40; refresh(candidate[0]); mutants.append(("stale_tree",candidate))
candidate=copy.deepcopy(observed); candidate[0][0]+="-foreign"; mutants.append(("cross_case",candidate))
for name,candidate in mutants:
    try:
        rows = parse(encode(candidate))
        if [row[1] for row in rows] != expected_ids: raise ValueError("iterator IDs differ")
    except (ValueError,UnicodeDecodeError): print(f"checkpoint_iterator_ledger_self_test_red mutation={name}")
    else: raise SystemExit(f"iterator ledger mutant survived: {name}")
print(f"checkpoint_iterator_ledger_self_test mutations={len(mutants)} passed=1")
PY
}

checkpoint_iterator_source_guard() {
  local source_path="$1" mode="${2:-validate}"
  python3 -I - "$source_path" "$mode" <<'PY'
import hashlib, pathlib, sys

source_path, mode = pathlib.Path(sys.argv[1]), sys.argv[2]
source = source_path.read_text()

def replace_once(value, old, new):
    if value.count(old) != 1: raise ValueError(f"iterator source mutation anchor differs: {old}")
    return value.replace(old,new,1)

def validate(value):
    if value.count("struct ReadySubjectAccumulator {") != 1: raise ValueError("iterator accumulator definition differs")
    if value.count("fn ready_iterator_page<T, E>(value: Result<T, E>)") != 1: raise ValueError("iterator page mapper definition differs")
    if value.count("fn validate_final_ready_snapshot(") != 1: raise ValueError("iterator final validator definition differs")
    constructor_start = value.index("impl ReadySubjectAccumulator {")
    constructor_end = value.index("fn ready_iterator_page<T, E>", constructor_start)
    constructor = value[constructor_start:constructor_end]
    constructor_fragments = [
        "if advertised > maximum {",
        "if u64::try_from(expected.len()).map_err(|_| WitnessStoreErrorV1::Bounds)? != advertised {",
        "if iterator_advertised != advertised {",
    ]
    if any(constructor.count(fragment) != 1 for fragment in constructor_fragments):
        raise ValueError("iterator accumulator constructor predicates differ")
    start = value.index("    async fn inspect_ready(&self)")
    end = value.index("    async fn read_entry(", start)
    body = value[start:end]
    fragments = [
        "let initial = self.closed_snapshot().await?;",
        "let mut iterator = self",
        ".info_with_subjects(self.bucket_filter())",
        "let mut subjects = ReadySubjectAccumulator::new(",
        "iterator.info.state.subjects_count,",
        "            expected,\n        )?;",
        "while let Some((subject, count)) = ready_iterator_page(iterator.try_next().await)? {",
        "subjects.observe(subject, count)?;",
        "subjects.finish()?;",
        "let final_snapshot = self.closed_snapshot().await?;",
        "validate_final_ready_snapshot(&initial_stable, &final_stable)?;",
        "self.validate_manifest_entry().await?;",
        "self.read_validated_entry(stream_id).await?;",
        "InspectionEvidence::new(Some(initial_full), Some(final_full))?;",
    ]
    if any(body.count(fragment) != 1 for fragment in fragments): raise ValueError("iterator production wiring differs")
    offsets = [body.index(fragment) for fragment in fragments]
    if offsets != sorted(offsets): raise ValueError("iterator production validation order differs")
    if "final_full != initial_full" in body or "final_full == initial_full" in body:
        raise ValueError("mutable full Stream.Info responses were compared")

validate(source)
if mode == "validate":
    print("checkpoint_iterator_source_guard passed=1")
    raise SystemExit(0)
if mode != "self-test": raise SystemExit("unknown iterator source-guard mode")
transformations = [
    ("bypass_accumulator", "if advertised > maximum {", "if false && advertised > maximum {"),
    ("constant_public_count", "iterator.info.state.subjects_count,", "advertised,"),
    ("missing_observe", "subjects.observe(subject, count)?;", "let _ = (subject, count);"),
    ("missing_finish", "subjects.finish()?;", "let _ = subjects;"),
    ("missing_page_error", "ready_iterator_page(iterator.try_next().await)?", "iterator.try_next().await.unwrap_or(None)"),
    ("missing_final_snapshot", "let final_snapshot = self.closed_snapshot().await?;", "let final_snapshot = initial.clone();"),
    ("missing_final_check", "validate_final_ready_snapshot(&initial_stable, &final_stable)?;", "let _ = (&initial_stable, &final_stable);"),
    ("constant_expected_set", "iterator.info.state.subjects_count,\n            maximum,\n            expected,", "iterator.info.state.subjects_count,\n            maximum,\n            BTreeSet::new(),"),
]
mutants = [(name,replace_once(source,old,new)) for name,old,new in transformations]
mutants.append(("full_response_equality",replace_once(source,"validate_final_ready_snapshot(&initial_stable, &final_stable)?;","if final_full != initial_full { return Err(WitnessStoreErrorV1::Configuration); }")))
candidate = replace_once(source,"self.validate_manifest_entry().await?;","self.validate_manifest_entry().await?;\n        validate_final_ready_snapshot(&initial_stable, &final_stable)?;")
candidate = replace_once(candidate,"validate_final_ready_snapshot(&initial_stable, &final_stable)?;\n        self.validate_manifest_entry().await?;","self.validate_manifest_entry().await?;")
mutants.append(("final_check_reordered",candidate))
expected_labels = [
    "bypass_accumulator", "constant_public_count", "missing_observe", "missing_finish",
    "missing_page_error", "missing_final_snapshot", "missing_final_check",
    "constant_expected_set", "full_response_equality", "final_check_reordered",
]
labels = [name for name,_candidate in mutants]
digests = [hashlib.sha256(candidate.encode()).hexdigest() for _name,candidate in mutants]
if labels != expected_labels:
    raise SystemExit("iterator source mutation label inventory/order differs")
if len(mutants) != 10 or len(set(digests)) != 10:
    raise SystemExit("iterator source mutation digest cardinality differs")
for name,candidate in mutants:
    try: validate(candidate)
    except ValueError: print(f"checkpoint_iterator_source_self_test_red mutation={name}")
    else: raise SystemExit(f"iterator source mutant survived: {name}")
print(f"checkpoint_iterator_source_self_test mutations={len(mutants)} unique_digests={len(set(digests))} passed=1")
PY
}

checkpoint_dynamic_union_validator() {
  local observed="$1" token_registry="$2" harness_token="$3" accepted_tree="$4"
  local project="$5" selector_root="$6" release_token="$7" release_sha="$8"
  local mode="${9:-validate}"
  python3 -I - "$observed" "$token_registry" "$harness_token" "$accepted_tree" \
    "$project" "$selector_root" "$release_token" "$release_sha" "$mode" <<'PY'
import copy, datetime, hashlib, json, pathlib, re, subprocess, sys, tempfile

(observed_path, registry_path, harness_token, accepted_tree, project, selector_root,
 release_token, release_sha, mode) = sys.argv[1:]
selector_root = pathlib.Path(selector_root).resolve(strict=True)
release_path = selector_root / "release-workspace/crates/phase285-release-probe/release-ledger.json"
release_canonical = str(release_path)
release_provenance_path = selector_root / "release-probe-provenance.json"
row_domain = b"swarm.phase285.checkpoint-dynamic-ledger-row.v1"
signed_domain = b"swarm.governance.witness-store-signed.v1"
store_domain = b"swarm.governance.witness-store.v1"
candidate_domain = b"swarm.governance.candidate.v1"
head_domain = b"swarm.governance.witness-head.v1"
data_head_domain = b"swarm.governance.witness-data-head.v1"
prepared_domain = b"swarm.governance.witness-prepared-state.v1"
genesis_component_domain = b"swarm.phase285.checkpoint-genesis-abort-component.v1"
binding_domain = b"swarm.governance.publication-binding.v1"
txid_domain = b"swarm.governance.txid.v1"
genesis_predecessor_domain = b"swarm.governance.genesis-predecessor.v1"
genesis_data_head_domain = b"swarm.governance.genesis-data-head.v1"
session_state_domain = b"swarm.governance.witness-session-state.v1"
external_marker_domain = b"swarm.governance.witness-external-marker.v1"
state_payload_domain = "swarm.governance.state.v1"
checkpoint_payload_domain = "swarm.governance.checkpoint.v1"
bucket_configuration_domain = b"swarm.governance.witness-bucket-configuration.v1"
admission_domain = b"swarm.governance.witness-admission.v1"
admission_set_domain = b"swarm.governance.witness-admission-set.v1"
bucket_epoch_domain = b"swarm.governance.witness-bucket-epoch.v1"
stream_initialization_domain = b"swarm.governance.witness-stream-initialization.v1"
bucket_manifest_domain = b"swarm.governance.witness-bucket-manifest.v1"
raw_configuration_domain = b"swarm.governance.nats-2.11.17-raw-stream-configuration.v1"
hex64 = re.compile(r"[0-9a-f]{64}")
timestamp9 = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{9})Z")
restart_case = "jetstream_checkpoint_survives_restart_for_current_predecessor_prepared_abort_and_genesis"
anchor_case = "jetstream_checkpoint_rejects_rolled_back_anchor_or_recreated_stream"
unavailable_case = "jetstream_checkpoint_rejects_unavailable_server_instead_of_skipping"
global_case = "jetstream_checkpoint_uses_global_revision_not_store_generation"
cases = [restart_case, anchor_case, unavailable_case, global_case]
states = ["current", "predecessor", "prepared", "abort", "genesis_abort"]

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()

def reject_constant(value):
    raise ValueError(f"non-RFC JSON constant rejected: {value}")

def strict_loads(raw):
    return json.loads(raw, parse_constant=reject_constant)

def framed_digest(domain, value_bytes):
    return hashlib.sha256(domain + len(value_bytes).to_bytes(8, "big") + value_bytes).hexdigest()

def exact(value, keys, name):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{name} field inventory differs")

def u64(value, name, nonzero=False):
    if type(value) is not int or value < (1 if nonzero else 0) or value > 2**64 - 1:
        raise ValueError(f"{name} integer/range differs")
    return value

def text(value, name, maximum=4096):
    if not isinstance(value, str) or not value or "\x00" in value or len(value.encode()) > maximum:
        raise ValueError(f"{name} string differs")
    return value

def digest(value, name):
    if not isinstance(value, str) or not hex64.fullmatch(value):
        raise ValueError(f"{name} digest differs")
    return value

def framed_bytes(domain, payload):
    return domain + len(payload).to_bytes(8, "big") + payload

def identity(value, name):
    exact(value, ["device", "inode"], name)
    u64(value["device"], f"{name}.device", True); u64(value["inode"], f"{name}.inode", True)
    return (value["device"], value["inode"])

def authority_pair(value, name):
    exact(value, ["current", "legacy"], name)
    current = identity(value["current"], f"{name}.current")
    legacy = identity(value["legacy"], f"{name}.legacy")
    if current != legacy: raise ValueError(f"{name} authority pair differs")
    return value

role_keys = ["state_canonical","state_staging","checkpoint_canonical","checkpoint_staging","journal_primary","journal_secondary"]
def role_map(value, name):
    exact(value, role_keys, name)
    identities = [identity(value[key], f"{name}.{key}") for key in role_keys]
    if len(set(identities)) != len(identities): raise ValueError(f"{name} roles alias")
    return value

def mapping_successor(before, after):
    role_map(before, "mapping before"); role_map(after, "mapping after")
    expected = {
        "state_canonical":before["state_staging"], "state_staging":before["state_canonical"],
        "checkpoint_canonical":before["checkpoint_staging"], "checkpoint_staging":before["checkpoint_canonical"],
        "journal_primary":before["journal_primary"], "journal_secondary":before["journal_secondary"],
    }
    if after != expected: raise ValueError("publication mapping successor differs")

def verify_ed25519(message, signature, expected_key_id, name):
    exact(signature, ["algorithm","key_id","public_key_hex","signature_hex"], f"{name} signature")
    if signature["algorithm"] != "ed25519" or signature["key_id"] != expected_key_id:
        raise ValueError(f"{name} signature identity differs")
    try:
        public_raw = bytes.fromhex(signature["public_key_hex"])
        signature_raw = bytes.fromhex(signature["signature_hex"])
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} signature encoding differs") from error
    if len(public_raw) != 32 or len(signature_raw) != 64 or hashlib.sha256(public_raw).hexdigest() != expected_key_id:
        raise ValueError(f"{name} key-id/public-key binding differs")
    with tempfile.TemporaryDirectory(prefix="phase285-c2b-ed25519-", dir=selector_root) as scratch:
        scratch = pathlib.Path(scratch)
        public_path, message_path, signature_path = scratch / "public.der", scratch / "message", scratch / "signature"
        public_path.write_bytes(bytes.fromhex("302a300506032b6570032100") + public_raw)
        message_path.write_bytes(message); signature_path.write_bytes(signature_raw)
        result = subprocess.run(
            ["openssl","pkeyutl","-verify","-pubin","-keyform","DER","-inkey",str(public_path),"-rawin","-in",str(message_path),"-sigfile",str(signature_path)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
    if result.returncode != 0: raise ValueError(f"{name} Ed25519 verification differs")

def sign_ed25519(secret, message):
    seed = hashlib.sha256(secret.encode()).digest()
    with tempfile.TemporaryDirectory(prefix="phase285-c2b-sign-", dir=selector_root) as scratch:
        scratch = pathlib.Path(scratch)
        private_path, public_path, message_path, signature_path = scratch / "private.der", scratch / "public.der", scratch / "message", scratch / "signature"
        private_path.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + seed)
        message_path.write_bytes(message)
        public = subprocess.run(["openssl","pkey","-in",str(private_path),"-inform","DER","-pubout","-outform","DER"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
        subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(private_path),"-keyform","DER","-rawin","-in",str(message_path),"-out",str(signature_path)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        signature_raw = signature_path.read_bytes()
    public_raw = public[-32:]
    return {"algorithm":"ed25519","key_id":hashlib.sha256(public_raw).hexdigest(),"public_key_hex":public_raw.hex(),"signature_hex":signature_raw.hex()}

def ed25519_identity(secret):
    seed = hashlib.sha256(secret.encode()).digest()
    with tempfile.TemporaryDirectory(prefix="phase285-c2b-key-", dir=selector_root) as scratch:
        private_path = pathlib.Path(scratch) / "private.der"
        private_path.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + seed)
        public = subprocess.run(["openssl","pkey","-in",str(private_path),"-inform","DER","-pubout","-outform","DER"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
    public_raw = public[-32:]
    return {"key_id":hashlib.sha256(public_raw).hexdigest(),"public_key_hex":public_raw.hex()}

def detached_signature(value, expected_key, message, name):
    digest(expected_key, f"{name} expected key")
    verify_ed25519(message, value, expected_key, name)

def validate_limits(value):
    exact(value, ["max_string_bytes","max_payload_bytes","max_record_bytes","max_collection_items"], "protocol limits")
    for key in value: u64(value[key], f"limits.{key}", True)
    if value["max_string_bytes"] > 4096 or value["max_payload_bytes"] > 8*1024*1024 or value["max_record_bytes"] > 16*1024*1024 or value["max_record_bytes"] < value["max_payload_bytes"] or value["max_collection_items"] > 1024:
        raise ValueError("protocol limits differ")

def validate_binding(binding, envelope_stream, envelope_witness_identity, envelope_witness_key):
    keys = ["schema_version","stream_id","generation","parent_directory","pool_directory","pool_lock","binding_file","authority_pair","publication_roles","cleanup_slot_count","cleanup_slot_names","cleanup_slot_identities","limits","signer_key_id","witness_key_id","witness_identity","binding_digest","binding_signature"]
    exact(binding, keys, "publication binding")
    if binding["schema_version"] != 1 or binding["stream_id"] != envelope_stream or binding["witness_identity"] != envelope_witness_identity or binding["witness_key_id"] != envelope_witness_key:
        raise ValueError("publication binding namespace differs")
    text(binding["stream_id"], "binding stream"); text(binding["witness_identity"], "binding witness identity")
    for key in ["generation","signer_key_id","witness_key_id","binding_digest"]: digest(binding[key], f"binding {key}")
    authority_pair(binding["authority_pair"], "binding authority")
    roles = role_map(binding["publication_roles"], "publication roles")
    validate_limits(binding["limits"])
    for key in ["parent_directory","pool_directory","pool_lock","binding_file"]: identity(binding[key], f"binding {key}")
    u64(binding["cleanup_slot_count"], "cleanup slot count")
    if binding["cleanup_slot_count"] != 64 or binding["cleanup_slot_names"] != [f"slot-{index:02}" for index in range(64)] or not isinstance(binding["cleanup_slot_identities"], list) or len(binding["cleanup_slot_identities"]) != 64:
        raise ValueError("cleanup slot inventory differs")
    fixed = [identity(binding[key], f"binding {key}") for key in ["parent_directory","pool_directory","pool_lock","binding_file"]]
    fixed += [identity(binding["authority_pair"]["current"], "binding authority current")]
    fixed += [identity(roles[key], f"binding role {key}") for key in role_keys]
    slots = [identity(value, "cleanup slot identity") for value in binding["cleanup_slot_identities"]]
    if len(set(fixed + slots)) != len(fixed + slots): raise ValueError("binding identity alias differs")
    preimage = {key:binding[key] for key in keys if key not in ["binding_digest","binding_signature"]}
    unsigned = canonical(preimage)
    if binding["binding_digest"] != framed_digest(binding_domain, unsigned): raise ValueError("binding digest differs")
    detached_signature(binding["binding_signature"], binding["signer_key_id"], unsigned, "binding")
    return binding

def validate_payload_attestation(candidate, prefix, domain):
    binding = candidate["publication_binding"]
    payload = candidate[f"{prefix}_payload"]
    preimage = {
        "schema_version":1, "domain":domain, "stream_id":candidate["stream_id"],
        "binding_generation":binding["generation"], "binding_digest":binding["binding_digest"],
        "authority_pair":binding["authority_pair"], "payload":payload,
        "byte_len":candidate[f"{prefix}_byte_len"], "digest":candidate[f"{prefix}_digest"],
    }
    detached_signature(candidate[f"{prefix}_attestation"], binding["signer_key_id"], canonical(preimage), f"{prefix} payload")

def fixture_binding(bucket, stream_id):
    roles = {
        "state_canonical":{"device":2,"inode":1}, "state_staging":{"device":2,"inode":2},
        "checkpoint_canonical":{"device":2,"inode":3}, "checkpoint_staging":{"device":2,"inode":4},
        "journal_primary":{"device":2,"inode":5}, "journal_secondary":{"device":2,"inode":6},
    }
    governance_public = ed25519_identity(f"{bucket}-governance")
    witness_public = ed25519_identity(f"{bucket}-witness")
    value = {
        "schema_version":1, "stream_id":stream_id, "generation":"9"*64,
        "parent_directory":{"device":2,"inode":7}, "pool_directory":{"device":2,"inode":8},
        "pool_lock":{"device":2,"inode":9}, "binding_file":{"device":2,"inode":10},
        "authority_pair":{"current":{"device":1,"inode":1},"legacy":{"device":1,"inode":1}},
        "publication_roles":roles, "cleanup_slot_count":64,
        "cleanup_slot_names":[f"slot-{index:02}" for index in range(64)],
        "cleanup_slot_identities":[{"device":2,"inode":index} for index in range(11,75)],
        "limits":{"max_string_bytes":4096,"max_payload_bytes":8*1024*1024,"max_record_bytes":16*1024*1024,"max_collection_items":1024},
        "signer_key_id":governance_public["key_id"], "witness_key_id":witness_public["key_id"],
        "witness_identity":"phase285-witness",
    }
    unsigned = canonical(value); value["binding_digest"] = framed_digest(binding_domain, unsigned)
    value["binding_signature"] = sign_ed25519(f"{bucket}-governance", unsigned)
    return value

def fixture_provenance(bucket, envelope, ready, bindings):
    stream_id = f"stream-{bucket}"
    binding = fixture_binding(bucket, stream_id)
    candidate_bindings = [item["candidate"]["publication_binding"] for item in [envelope["current"],envelope["predecessor"],envelope["prepared"]] if item is not None]
    if candidate_bindings and any(value != binding for value in candidate_bindings): raise ValueError("fixture publication binding differs")
    if envelope["witness_key_id"] != binding["witness_key_id"] or envelope["witness_identity"] != binding["witness_identity"]:
        raise ValueError("fixture witness provenance differs")
    if envelope["session"] is not None and (envelope["session"]["binding_generation"] != binding["generation"] or envelope["session"]["binding_digest"] != binding["binding_digest"] or envelope["session"]["signer_key_id"] != binding["signer_key_id"] or envelope["session"]["authority_pair"] != binding["authority_pair"]):
        raise ValueError("fixture session provenance differs")
    admission = {
        "schema_version":1,"stream_id":stream_id,"signer_key_id":binding["signer_key_id"],"witness_identity":binding["witness_identity"],"witness_key_id":binding["witness_key_id"],"binding_generation":binding["generation"],"binding_digest":binding["binding_digest"],"authority_pair":binding["authority_pair"],"publication_roles":binding["publication_roles"],"limits":binding["limits"],"max_retained_bytes":1_000_000,"initial_epoch":0,"initial_sequence":0,"initial_intent_counter":1,
    }
    admission["admission_digest"] = framed_digest(admission_domain, canonical(admission))
    governance_public = ed25519_identity(f"{bucket}-governance")["public_key_hex"]
    entry = {"schema_version":1,"admission":admission,"governance_signer_public_key_hex":governance_public,"max_state_bytes":8*1024*1024,"max_checkpoint_bytes":8*1024*1024,"max_binding_bytes":16*1024*1024,"max_request_bytes":16*1024*1024,"max_response_bytes":16*1024*1024,"predecessor_admission_digest":None}
    admission_set_preimage = {"schema_version":1,"entries":[entry]}
    admission_set_digest = framed_digest(admission_set_domain, canonical(admission_set_preimage))
    expected_stream = f"KV_{bucket}"
    config = {"schema_version":1,"nats_server_version":"2.11.17","nats_server_image_index_digest":"sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00","stream_name":expected_stream,"description":"Phase 285 external governance witness","subjects":[f"$KV.{bucket}.>"],"retention":"Limits","discard":"New","discard_new_per_subject":False,"storage":"File","max_messages":-1,"max_bytes":4_262_144,"max_messages_per_subject":1,"max_age_nanos":0,"max_consumers":-1,"max_message_size":1_000_000,"num_replicas":1,"no_ack":False,"duplicate_window_nanos":120_000_000_000,"persistence_semantics":"Nats21117SynchronousOnly","persist_mode_wire_key_present":False,"sealed":False,"allow_rollup":False,"deny_delete":True,"deny_purge":True,"allow_direct":False,"mirror_direct":False,"allow_message_ttl":False,"allow_atomic_publish":False,"allow_message_schedules":False,"allow_message_counter":False,"template_owner":"","application_metadata":{},"server_metadata":{"_nats.level":"1","_nats.req.level":"0","_nats.ver":"2.11.17"},"republish_present":False,"mirror_present":False,"sources_count":0,"subject_transform_present":False,"compression":"Disabled","consumer_limits_present":False,"first_sequence":None,"placement_present":False,"pause_until":None,"subject_delete_marker_ttl_nanos":None}
    config_digest = framed_digest(bucket_configuration_domain, canonical(config))
    epoch = {"schema_version":1,"bucket_generation":"a"*64,"nats_account":"PHASE285_EXPECTED","stream_name":expected_stream,"bucket_configuration_digest":config_digest,"admission_set_digest":admission_set_digest,"witness_identity":binding["witness_identity"],"witness_key_id":binding["witness_key_id"]}
    epoch_digest = framed_digest(bucket_epoch_domain, canonical(epoch))
    initialization = {"schema_version":1,"bucket_epoch_digest":epoch_digest,"admission_digest":admission["admission_digest"],"stream_id":stream_id,"witness_identity":binding["witness_identity"],"witness_key_id":binding["witness_key_id"]}
    initialization_digest = framed_digest(stream_initialization_domain, canonical(initialization))
    raw_config = {"name":expected_stream,"description":"Phase 285 external governance witness","subjects":[f"$KV.{bucket}.>"],"retention":"limits","max_consumers":-1,"max_msgs":-1,"max_bytes":4_262_144,"max_age":0,"max_msgs_per_subject":1,"max_msg_size":1_000_000,"discard":"new","storage":"file","num_replicas":1,"duplicate_window":120_000_000_000,"compression":"none","allow_direct":False,"mirror_direct":False,"sealed":False,"deny_delete":True,"deny_purge":True,"allow_rollup_hdrs":False,"consumer_limits":{},"allow_msg_ttl":False,"metadata":{"_nats.level":"1","_nats.req.level":"0","_nats.ver":"2.11.17"}}
    raw_config_bytes = json.dumps(raw_config, sort_keys=False, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    raw_config_digest = framed_digest(raw_configuration_domain, raw_config_bytes)
    empty = {"schema_version":1,"admission_digest":admission["admission_digest"],"bucket_epoch_digest":epoch_digest,"stream_initialization_digest":initialization_digest,"stream_id":stream_id,"witness_identity":binding["witness_identity"],"witness_key_id":binding["witness_key_id"],"session":None,"last_session_rotation":None,"current":None,"predecessor":None,"prepared":None,"genesis_abort":None,"store_generation":0}
    empty_signature = sign_ed25519(f"{bucket}-witness", framed_bytes(signed_domain, canonical(empty)))
    empty_signed = dict(empty); empty_signed["signature"] = empty_signature
    stream_key = "s." + hashlib.sha256(store_domain + stream_id.encode()).hexdigest()
    manifest = {"schema_version":1,"bucket_epoch_digest":epoch_digest,"bucket_configuration_digest":config_digest,"admission_set_digest":admission_set_digest,"stream_keys":[stream_key],"initialized_streams":{stream_key:{"schema_version":1,"stream_initialization_digest":initialization_digest,"empty_envelope_digest":framed_digest(signed_domain, canonical(empty_signed))}},"phase":"Ready","witness_identity":binding["witness_identity"],"witness_key_id":binding["witness_key_id"]}
    manifest["signature"] = sign_ed25519(f"{bucket}-witness", framed_bytes(bucket_manifest_domain, canonical(manifest)))
    manifest_digest = framed_digest(bucket_manifest_domain, canonical(manifest))
    expected = {"admission_digest":admission["admission_digest"],"bucket_epoch_digest":epoch_digest,"stream_initialization_digest":initialization_digest,"ready_manifest_digest":manifest_digest,"raw_config_digest":raw_config_digest}
    actual = {"admission_digest":ready["admission_digest"],"ready_epoch_identity":ready["bucket_epoch_digest"],"ready_initialization_identity":ready["stream_initialization_digest"],"ready_epoch_digest":bindings["ready_epoch_digest"],"anchor_epoch_digest":bindings["anchor_epoch_digest"],"ready_initialization_digest":bindings["ready_initialization_digest"],"ready_manifest_digest":bindings["ready_manifest_digest"],"reopened_manifest_digest":bindings["reopened_manifest_digest"],"ready_raw_config_digest":bindings["ready_raw_config_digest"],"restarted_raw_config_digest":bindings["restarted_raw_config_digest"]}
    expected_values = {"admission_digest":expected["admission_digest"],"ready_epoch_identity":epoch_digest,"ready_initialization_identity":initialization_digest,"ready_epoch_digest":epoch_digest,"anchor_epoch_digest":epoch_digest,"ready_initialization_digest":initialization_digest,"ready_manifest_digest":manifest_digest,"reopened_manifest_digest":manifest_digest,"ready_raw_config_digest":raw_config_digest,"restarted_raw_config_digest":raw_config_digest}
    for name in expected_values:
        if actual[name] != expected_values[name]: raise ValueError(f"independently derived Ready/anchor provenance differs: {name}")

def validate_live_container(restart, project):
    result = subprocess.run(["docker","inspect",restart["container_after"]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    if result.returncode != 0: raise ValueError("restarted container observation unavailable")
    values = strict_loads(result.stdout)
    if not isinstance(values, list) or len(values) != 1: raise ValueError("container observation cardinality differs")
    value = values[0]; labels = value.get("Config",{}).get("Labels",{}) or {}; mounts = value.get("Mounts",[])
    if value.get("Id") != restart["container_after"] or labels.get("com.docker.compose.project") != project or labels.get("com.docker.compose.service") != "nats" or value.get("Config",{}).get("Image") != restart["image_after"] or not any(mount.get("Name") == restart["volume_after"].removesuffix(":true") for mount in mounts):
        raise ValueError("separately observed container identity differs")

def canonical_timestamp(value):
    match = timestamp9.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("timestamp framing differs")
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    if second > 59:
        raise ValueError("timestamp leap second is not accepted")
    datetime.datetime(year, month, day, hour, minute, second)
    return value

registry = {}
for line in pathlib.Path(registry_path).read_text().splitlines():
    parts = line.split("\t")
    if len(parts) != 2 or parts[0] in registry:
        raise SystemExit("checkpoint token registry differs")
    registry[parts[0]] = parts[1]
if set(registry) != set(cases) or len(set(registry.values())) != 4:
    raise SystemExit("checkpoint token registry set/freshness differs")

def row_digest(row):
    preimage = {key: value for key, value in row.items() if key != "row_digest"}
    return framed_digest(row_domain, canonical(preimage))

def parse_dynamic(raw):
    if not raw or len(raw) > 12_000_000 or not raw.endswith(b"\n") or b"\n\n" in raw:
        raise ValueError("checkpoint dynamic ledger framing differs")
    rows = []
    for physical in raw.splitlines(keepends=True):
        if not physical.endswith(b"\n"):
            raise ValueError("checkpoint physical row lacks newline")
        row = strict_loads(physical[:-1])
        if physical != canonical(row) + b"\n":
            raise ValueError("checkpoint physical row is not canonical")
        rows.append(row)
    required = {"accepted_tree", "case", "evidence", "harness_token", "invocation_token", "kind", "row_digest", "schema_version", "state_id", "status"}
    for row in rows:
        exact(row, required, "checkpoint row")
        if row["schema_version"] != 1 or row["status"] != "passed":
            raise ValueError("checkpoint row schema/status differs")
        if row["case"] not in registry or row["invocation_token"] != registry[row["case"]]:
            raise ValueError("checkpoint invocation token differs")
        if row["harness_token"] != harness_token or row["accepted_tree"] != accepted_tree:
            raise ValueError("checkpoint harness/tree binding differs")
        if row["row_digest"] != row_digest(row):
            raise ValueError("checkpoint row digest differs")
    identities = [(row["case"], row["kind"], row["state_id"]) for row in rows]
    if len(identities) != len(set(identities)):
        raise ValueError("checkpoint row identity duplicated")
    return rows

def component_frame(value, domain):
    if value is None:
        return None
    component = canonical(value)
    return {"canonical_hex": component.hex(), "digest": framed_digest(domain, component)}

def candidate_digest(candidate):
    return framed_digest(candidate_domain, canonical(candidate))

def head_digest(head):
    return framed_digest(head_domain, canonical(head))

def data_head_digest(head):
    preimage = {key: head[key] for key in [
        "schema_version", "stream_id", "epoch", "sequence", "state_digest",
        "state_byte_len", "checkpoint_digest", "checkpoint_byte_len",
        "binding_generation", "binding_digest", "authority_pair", "publication_mapping",
    ]}
    return framed_digest(data_head_domain, canonical(preimage))

def genesis_preimages(stream_id, binding_generation, binding_digest, signer_key_id, witness_key_id, authority):
    value = {"schema_version":1,"stream_id":stream_id,"binding_generation":binding_generation,"binding_digest":binding_digest,"signer_key_id":signer_key_id,"witness_key_id":witness_key_id,"authority_pair":authority,"epoch":0,"sequence":0,"intent_counter":0}
    return framed_digest(genesis_predecessor_domain, canonical(value)), framed_digest(genesis_data_head_domain, canonical(value))

def validate_outcome(outcome, head):
    if not isinstance(outcome, dict) or len(outcome) != 1: raise ValueError("head outcome enum differs")
    if "Committed" in outcome:
        value = outcome["Committed"]
        exact(value, ["txid","candidate_digest","predecessor_head_digest","intent_counter"], "committed outcome")
        for key in ["txid","candidate_digest","predecessor_head_digest"]: digest(value[key], f"committed {key}")
        u64(value["intent_counter"], "committed intent")
        if value["txid"] != head["txid"] or value["candidate_digest"] != head["candidate_digest"] or value["intent_counter"] != head["intent_counter"]:
            raise ValueError("committed outcome relation differs")
        return "committed"
    if "Aborted" in outcome:
        value = outcome["Aborted"]
        keys = ["txid","candidate_digest","predecessor_head_digest","epoch","sequence","intent_counter","binding_generation","binding_digest","signer_key_id","witness_key_id","authority_pair","publication_mapping","resulting_data_head_digest"]
        exact(value, keys, "aborted outcome")
        for key in ["txid","candidate_digest","predecessor_head_digest","binding_generation","binding_digest","signer_key_id","witness_key_id","resulting_data_head_digest"]: digest(value[key], f"abort {key}")
        for key in ["epoch","sequence","intent_counter"]: u64(value[key], f"abort {key}")
        authority_pair(value["authority_pair"], "abort authority"); role_map(value["publication_mapping"], "abort mapping")
        terminal_preimage = {"schema_version":1,"stream_id":head["stream_id"],"predecessor_head_digest":value["predecessor_head_digest"],"candidate_digest":value["candidate_digest"],"binding_generation":value["binding_generation"],"binding_digest":value["binding_digest"],"authority_pair":value["authority_pair"],"epoch":value["epoch"],"sequence":value["sequence"],"intent_counter":value["intent_counter"]}
        if value["epoch"] != head["epoch"] or value["sequence"] != head["sequence"] + 1:
            raise ValueError("retained abort summary epoch/sequence differs")
        if value["txid"] != framed_digest(txid_domain, canonical(terminal_preimage)):
            raise ValueError("retained abort terminal txid differs")
        if value["intent_counter"] != head["intent_counter"] or value["binding_generation"] != head["binding_generation"] or value["binding_digest"] != head["binding_digest"] or value["signer_key_id"] != head["signer_key_id"] or value["witness_key_id"] != head["witness_key_id"] or value["authority_pair"] != head["authority_pair"] or value["publication_mapping"] != head["publication_mapping"] or value["resulting_data_head_digest"] != data_head_digest(head):
            raise ValueError("aborted outcome relation differs")
        return "aborted"
    raise ValueError("unknown head outcome")

def validate_head(head, settled=None):
    exact(head, ["schema_version","stream_id","txid","candidate_digest","epoch","sequence","intent_counter","binding_generation","binding_digest","signer_key_id","witness_key_id","authority_pair","state_digest","state_byte_len","checkpoint_digest","checkpoint_byte_len","publication_mapping","last_intent_outcome"], "head")
    if head["schema_version"] != 1: raise ValueError("head schema differs")
    text(head["stream_id"], "head stream")
    for key in ["txid","candidate_digest","binding_generation","binding_digest","signer_key_id","witness_key_id","state_digest","checkpoint_digest"]: digest(head[key], f"head {key}")
    for key in ["epoch","sequence","intent_counter","state_byte_len","checkpoint_byte_len"]: u64(head[key], f"head {key}")
    if head["state_byte_len"] > 8*1024*1024 or head["checkpoint_byte_len"] > 8*1024*1024: raise ValueError("head payload bound differs")
    authority_pair(head["authority_pair"], "head authority"); role_map(head["publication_mapping"], "head mapping")
    outcome = None if head["last_intent_outcome"] is None else validate_outcome(head["last_intent_outcome"], head)
    if settled is True and outcome is None: raise ValueError("head is not settled")
    if settled is False and outcome is not None: raise ValueError("prepared head is terminal")
    return outcome

def validate_candidate(candidate, envelope_stream, envelope_witness_identity, envelope_witness_key):
    exact(candidate, ["schema_version","stream_id","predecessor_head","predecessor_head_digest","predecessor_data_head_digest","state_payload","state_byte_len","state_digest","state_attestation","checkpoint_payload","checkpoint_byte_len","checkpoint_digest","checkpoint_attestation","publication_binding","publication_mapping_before","publication_mapping_after","epoch","sequence","intent_counter"], "candidate")
    if candidate["schema_version"] != 1 or candidate["stream_id"] != envelope_stream:
        raise ValueError("candidate namespace differs")
    text(candidate["stream_id"], "candidate stream")
    for key in ["predecessor_head_digest","predecessor_data_head_digest","state_digest","checkpoint_digest"]: digest(candidate[key], f"candidate {key}")
    for key in ["state_byte_len","checkpoint_byte_len","epoch","sequence","intent_counter"]: u64(candidate[key], f"candidate {key}")
    binding = validate_binding(candidate["publication_binding"], envelope_stream, envelope_witness_identity, envelope_witness_key)
    for prefix in ["state", "checkpoint"]:
        payload = candidate[f"{prefix}_payload"]
        if not isinstance(payload, list) or any(type(item) is not int or item < 0 or item > 255 for item in payload):
            raise ValueError("candidate payload differs")
        payload_bytes = bytes(payload)
        if candidate[f"{prefix}_byte_len"] != len(payload_bytes) or candidate[f"{prefix}_digest"] != hashlib.sha256(payload_bytes).hexdigest():
            raise ValueError("candidate payload digest differs")
        try: parsed = strict_loads(payload_bytes)
        except Exception as error: raise ValueError("candidate payload JSON differs") from error
        if canonical(parsed) != payload_bytes: raise ValueError("candidate payload canonical form differs")
    validate_payload_attestation(candidate, "state", state_payload_domain)
    validate_payload_attestation(candidate, "checkpoint", checkpoint_payload_domain)
    before = candidate["publication_mapping_before"]; after = candidate["publication_mapping_after"]
    mapping_successor(before, after)
    allowed = binding["publication_roles"]
    for pair in [("state_canonical","state_staging"),("checkpoint_canonical","checkpoint_staging"),("journal_primary","journal_secondary")]:
        if {tuple(sorted(before[key].items())) for key in pair} != {tuple(sorted(allowed[key].items())) for key in pair} or {tuple(sorted(after[key].items())) for key in pair} != {tuple(sorted(allowed[key].items())) for key in pair}:
            raise ValueError("candidate mapping binding differs")
    predecessor = candidate["predecessor_head"]
    if predecessor is None:
        genesis_head, genesis_data = genesis_preimages(envelope_stream,binding["generation"],binding["binding_digest"],binding["signer_key_id"],binding["witness_key_id"],binding["authority_pair"])
        if candidate["predecessor_head_digest"] != genesis_head or candidate["predecessor_data_head_digest"] != genesis_data or candidate["epoch"] != 0 or candidate["sequence"] != 0 or candidate["intent_counter"] == 0:
            raise ValueError("candidate genesis predecessor differs")
    else:
        validate_head(predecessor, True)
        if predecessor["stream_id"] != envelope_stream or predecessor["binding_generation"] != binding["generation"] or predecessor["binding_digest"] != binding["binding_digest"] or predecessor["signer_key_id"] != binding["signer_key_id"] or predecessor["witness_key_id"] != binding["witness_key_id"] or predecessor["authority_pair"] != binding["authority_pair"] or predecessor["publication_mapping"] != before or candidate["predecessor_head_digest"] != head_digest(predecessor) or candidate["predecessor_data_head_digest"] != data_head_digest(predecessor) or candidate["epoch"] != predecessor["epoch"] or candidate["sequence"] != predecessor["sequence"] + 1 or candidate["intent_counter"] != predecessor["intent_counter"] + 1:
            raise ValueError("candidate predecessor relation differs")
    computed = candidate_digest(candidate)
    txid_preimage = {"schema_version":1,"stream_id":envelope_stream,"predecessor_head_digest":candidate["predecessor_head_digest"],"candidate_digest":computed,"binding_generation":binding["generation"],"binding_digest":binding["binding_digest"],"authority_pair":binding["authority_pair"],"epoch":candidate["epoch"],"sequence":candidate["sequence"],"intent_counter":candidate["intent_counter"]}
    return computed, framed_digest(txid_domain, canonical(txid_preimage))

def validate_stored(stored, envelope_stream, envelope_witness_identity, envelope_witness_key):
    if stored is None:
        return "absent"
    exact(stored, ["candidate", "head"], "stored candidate")
    candidate, head = stored["candidate"], stored["head"]
    computed_candidate, computed_txid = validate_candidate(candidate, envelope_stream, envelope_witness_identity, envelope_witness_key)
    validate_head(head, True)
    binding = candidate["publication_binding"]
    expected = {
        "stream_id": candidate["stream_id"], "txid":computed_txid, "candidate_digest": computed_candidate,
        "epoch": candidate["epoch"], "sequence": candidate["sequence"],
        "binding_generation": binding["generation"],
        "binding_digest": binding["binding_digest"], "signer_key_id": binding["signer_key_id"],
        "witness_key_id": binding["witness_key_id"], "authority_pair": binding["authority_pair"],
        "state_digest": candidate["state_digest"], "state_byte_len": candidate["state_byte_len"],
        "checkpoint_digest": candidate["checkpoint_digest"], "checkpoint_byte_len": candidate["checkpoint_byte_len"],
        "publication_mapping": candidate["publication_mapping_after"],
    }
    if any(head[key] != value for key, value in expected.items()):
        raise ValueError("candidate/head relation differs")
    outcome = head["last_intent_outcome"]
    if "Committed" in outcome:
        committed = outcome["Committed"]
        if head["intent_counter"] != candidate["intent_counter"] or committed != {"txid":head["txid"], "candidate_digest":computed_candidate, "predecessor_head_digest":candidate["predecessor_head_digest"], "intent_counter":head["intent_counter"]}:
            raise ValueError("committed outcome relation differs")
        return "committed"
    if "Aborted" in outcome:
        aborted = outcome["Aborted"]
        if head["intent_counter"] <= candidate["intent_counter"] or not isinstance(aborted, dict) or aborted.get("witness_key_id") != head["witness_key_id"] or aborted.get("binding_digest") != head["binding_digest"]:
            raise ValueError("aborted outcome relation differs")
        if aborted["txid"] == computed_txid or aborted["candidate_digest"] == computed_candidate:
            raise ValueError("retained abort/live candidate identity aliases")
        if aborted["intent_counter"] == candidate["intent_counter"] + 1:
            committed_head = copy.deepcopy(head)
            committed_head["intent_counter"] = candidate["intent_counter"]
            committed_head["last_intent_outcome"] = {"Committed":{"txid":computed_txid,"candidate_digest":computed_candidate,"predecessor_head_digest":candidate["predecessor_head_digest"],"intent_counter":candidate["intent_counter"]}}
            if aborted["predecessor_head_digest"] != head_digest(committed_head):
                raise ValueError("retained abort immediate predecessor differs")
        return "aborted"
    raise ValueError("unknown settled outcome")

def validate_genesis_abort(value, stream_id, witness_key_id, expected_prepared=None):
    keys = ["schema_version","stream_id","txid","candidate_digest","predecessor_head_digest","resulting_data_head_digest","epoch","sequence","intent_counter","binding_generation","binding_digest","signer_key_id","witness_key_id","authority_pair","publication_mapping","reason"]
    exact(value, keys, "genesis abort")
    if value["schema_version"] != 1 or value["stream_id"] != stream_id or value["witness_key_id"] != witness_key_id: raise ValueError("genesis abort namespace differs")
    text(value["stream_id"], "genesis abort stream"); text(value["reason"], "genesis abort reason")
    for key in ["txid","candidate_digest","predecessor_head_digest","resulting_data_head_digest","binding_generation","binding_digest","signer_key_id","witness_key_id"]: digest(value[key], f"genesis abort {key}")
    for key in ["epoch","sequence","intent_counter"]: u64(value[key], f"genesis abort {key}")
    authority_pair(value["authority_pair"], "genesis abort authority"); role_map(value["publication_mapping"], "genesis abort mapping")
    genesis_head, genesis_data = genesis_preimages(value["stream_id"],value["binding_generation"],value["binding_digest"],value["signer_key_id"],value["witness_key_id"],value["authority_pair"])
    txid_preimage = {"schema_version":1,"stream_id":value["stream_id"],"predecessor_head_digest":value["predecessor_head_digest"],"candidate_digest":value["candidate_digest"],"binding_generation":value["binding_generation"],"binding_digest":value["binding_digest"],"authority_pair":value["authority_pair"],"epoch":value["epoch"],"sequence":value["sequence"],"intent_counter":value["intent_counter"]}
    if value["epoch"] != 0 or value["sequence"] != 0 or value["intent_counter"] == 0 or value["predecessor_head_digest"] != genesis_head or value["resulting_data_head_digest"] != genesis_data or value["txid"] != framed_digest(txid_domain, canonical(txid_preimage)):
        raise ValueError("genesis abort identity differs")
    if expected_prepared is not None:
        head = expected_prepared["head"]
        relations = {"stream_id":"stream_id","epoch":"epoch","sequence":"sequence","binding_generation":"binding_generation","binding_digest":"binding_digest","signer_key_id":"signer_key_id","witness_key_id":"witness_key_id","authority_pair":"authority_pair"}
        if any(value[left] != head[right] for left,right in relations.items()) or value["predecessor_head_digest"] != expected_prepared["predecessor_head_digest"] or value["resulting_data_head_digest"] != expected_prepared["predecessor_data_head_digest"] or value["publication_mapping"] != expected_prepared["predecessor_publication_mapping"] or head["intent_counter"] != value["intent_counter"] + 1 or value["txid"] == head["txid"] or value["candidate_digest"] == head["candidate_digest"]:
            raise ValueError("genesis abort/prepared relation differs")

def validate_prepared_stored(stored, stream_id, witness_identity, witness_key_id, session_generation):
    exact(stored, ["candidate","prepared"], "stored prepared")
    candidate = stored["candidate"]; prepared = stored["prepared"]
    candidate_digest_value, candidate_txid = validate_candidate(candidate, stream_id, witness_identity, witness_key_id)
    exact(prepared, ["schema_version","predecessor_head","head","predecessor_head_digest","predecessor_data_head_digest","binding_digest","predecessor_publication_mapping","session_generation","genesis_abort"], "prepared state")
    if prepared["schema_version"] != 1: raise ValueError("prepared schema differs")
    u64(prepared["session_generation"], "prepared session generation", True)
    if prepared["session_generation"] != session_generation: raise ValueError("prepared/session generation differs")
    validate_head(prepared["head"], False); role_map(prepared["predecessor_publication_mapping"], "prepared predecessor mapping")
    for key in ["predecessor_head_digest","predecessor_data_head_digest","binding_digest"]: digest(prepared[key], f"prepared {key}")
    binding = candidate["publication_binding"]
    expected_head = {"schema_version":1,"stream_id":stream_id,"txid":candidate_txid,"candidate_digest":candidate_digest_value,"epoch":candidate["epoch"],"sequence":candidate["sequence"],"intent_counter":candidate["intent_counter"],"binding_generation":binding["generation"],"binding_digest":binding["binding_digest"],"signer_key_id":binding["signer_key_id"],"witness_key_id":binding["witness_key_id"],"authority_pair":binding["authority_pair"],"state_digest":candidate["state_digest"],"state_byte_len":candidate["state_byte_len"],"checkpoint_digest":candidate["checkpoint_digest"],"checkpoint_byte_len":candidate["checkpoint_byte_len"],"publication_mapping":candidate["publication_mapping_after"],"last_intent_outcome":None}
    if prepared["head"] != expected_head or prepared["predecessor_head"] != candidate["predecessor_head"] or prepared["predecessor_head_digest"] != candidate["predecessor_head_digest"] or prepared["predecessor_data_head_digest"] != candidate["predecessor_data_head_digest"] or prepared["binding_digest"] != binding["binding_digest"] or prepared["predecessor_publication_mapping"] != candidate["publication_mapping_before"]:
        raise ValueError("prepared/candidate relation differs")
    if prepared["genesis_abort"] is not None: validate_genesis_abort(prepared["genesis_abort"], stream_id, witness_key_id, prepared)
    return prepared

def validate_session(value, envelope):
    exact(value, ["schema_version","stream_id","authority_pair","binding_generation","binding_digest","signer_key_id","witness_key_id","ephemeral_key_id","witness_identity","session_generation","session_commitment"], "session")
    if value["schema_version"] != 1: raise ValueError("session schema differs")
    if value["stream_id"] != envelope["stream_id"] or value["witness_identity"] != envelope["witness_identity"] or value["witness_key_id"] != envelope["witness_key_id"]: raise ValueError("session namespace differs")
    text(value["stream_id"], "session stream"); text(value["witness_identity"], "session witness")
    authority_pair(value["authority_pair"], "session authority")
    for key in ["binding_generation","binding_digest","signer_key_id","witness_key_id","ephemeral_key_id","session_commitment"]: digest(value[key], f"session {key}")
    u64(value["session_generation"], "session generation", True)

def validate_rotation(value, envelope):
    exact(value, ["schema_version","accepted_request_digest","accepted_challenge_digest","response_kind","session","establish_snapshot","discovery_snapshot"], "rotation receipt")
    if value["schema_version"] != 1: raise ValueError("rotation schema differs")
    digest(value["accepted_request_digest"], "rotation request"); digest(value["accepted_challenge_digest"], "rotation challenge")
    validate_session(value["session"], envelope)
    if value["session"] != envelope["session"]: raise ValueError("rotation/session relation differs")
    if value["response_kind"] == "Establish":
        if value["discovery_snapshot"] is not None: raise ValueError("rotation establish variant differs")
        snapshot = value["establish_snapshot"]; exact(snapshot, ["schema_version","committed_head","external_marker"], "establish snapshot")
        if snapshot["schema_version"] != 1: raise ValueError("establish snapshot schema differs")
        digest(snapshot["external_marker"], "external marker")
        if snapshot["committed_head"] is not None:
            validate_head(snapshot["committed_head"], True)
            if snapshot["committed_head"] != (None if envelope["current"] is None else envelope["current"]["head"]): raise ValueError("rotation committed snapshot differs")
        session_digest = framed_digest(session_state_domain, canonical(value["session"]))
        marker_preimage = {"accepted_challenge_digest":value["accepted_challenge_digest"],"resulting_session_digest":session_digest,"response_kind":"Establish"}
        if snapshot["external_marker"] != framed_digest(external_marker_domain, canonical(marker_preimage)): raise ValueError("rotation external marker differs")
    elif value["response_kind"] == "Discover":
        if value["establish_snapshot"] is not None: raise ValueError("rotation discovery variant differs")
        discovery = value["discovery_snapshot"]
        exact(discovery, ["schema_version","head","prepared","genesis_abort","recovery_session"], "discovery snapshot")
        if discovery["schema_version"] != 1 or discovery["recovery_session"] != value["session"]: raise ValueError("discovery session differs")
        if discovery["head"] is not None: validate_head(discovery["head"], True)
        expected_head = None if envelope["current"] is None else envelope["current"]["head"]
        expected_prepared = None if envelope["prepared"] is None else envelope["prepared"]["prepared"]
        if discovery["head"] != expected_head or discovery["prepared"] != expected_prepared or discovery["genesis_abort"] != envelope["genesis_abort"]:
            raise ValueError("rotation discovery snapshot relation differs")
        if discovery["genesis_abort"] is not None: validate_genesis_abort(discovery["genesis_abort"], envelope["stream_id"], envelope["witness_key_id"])
    else: raise ValueError("rotation response enum differs")

semantic_expected = {
    "current": {"current":"committed","predecessor":"absent","prepared":False,"genesis_abort":False,"current_binds_predecessor":True,"prepared_binds_current":True},
    "predecessor": {"current":"committed","predecessor":"committed","prepared":False,"genesis_abort":False,"current_binds_predecessor":True,"prepared_binds_current":True},
    "prepared": {"current":"absent","predecessor":"absent","prepared":True,"genesis_abort":False,"current_binds_predecessor":True,"prepared_binds_current":True},
    "abort": {"current":"aborted","predecessor":"absent","prepared":False,"genesis_abort":False,"current_binds_predecessor":True,"prepared_binds_current":True},
    "genesis_abort": {"current":"absent","predecessor":"absent","prepared":False,"genesis_abort":True,"current_binds_predecessor":True,"prepared_binds_current":True},
}

def validate_restart(row):
    state = row["state_id"]
    if state not in states or row["kind"] != "restart_state":
        raise ValueError("checkpoint restart identity differs")
    evidence = row["evidence"]
    exact(evidence, ["semantic","ack","relations","barrier","raw","ready_identity","decoded","restart","bindings"], "restart evidence")
    ack = evidence["ack"]; exact(ack, ["stream","sequence","duplicate","proposed_digest","token"], "ack")
    relations = evidence["relations"]; exact(relations, ["initial_revision","manifest_tail_sequence","current_store_generation","proposed_store_generation"], "relations")
    barrier = evidence["barrier"]; exact(barrier, ["ack_lines","release_lines","done_lines","ack_token","release_token","done_token","event_trace"], "barrier")
    raw = evidence["raw"]; exact(raw, ["subject","sequence","bytes_hex","signed_digest","headers"], "raw")
    ready = evidence["ready_identity"]; exact(ready, ["stream_name","bucket_name","admitted_stream_id","admitted_stream_key","subject","witness_identity","witness_key_id","admission_digest","bucket_epoch_digest","stream_initialization_digest","reopened_stream_name","reopened_admitted_stream_id","reopened_admitted_stream_key","reopened_subject"], "Ready identity")
    decoded = evidence["decoded"]; exact(decoded, ["store_state_digest","components"], "decoded evidence")
    restart = evidence["restart"]; exact(restart, ["project","service","image_before","image_after","volume_before","volume_after","container_before","container_after","leader"], "restart")
    bindings = evidence["bindings"]; exact(bindings, ["ready_created_at","restarted_created_at","ready_raw_config_digest","restarted_raw_config_digest","ready_epoch_digest","anchor_epoch_digest","envelope_epoch_digest","ready_initialization_digest","envelope_initialization_digest","ready_manifest_digest","reopened_manifest_digest","reopened_read_stream_id","reopened_read_revision","reopened_read_digest"], "bindings")
    expected_bucket = f"phase285_c_{state.replace('_', '')}"
    expected_stream = f"KV_{expected_bucket}"
    if ready["stream_name"] != expected_stream or ready["bucket_name"] != expected_bucket:
        raise ValueError("Ready stream/bucket identity differs")
    try: raw_bytes = bytes.fromhex(raw["bytes_hex"])
    except (TypeError, ValueError) as error: raise ValueError("raw bytes malformed") from error
    if not raw_bytes or len(raw_bytes) > 1_000_000:
        raise ValueError("raw bytes bound differs")
    envelope = strict_loads(raw_bytes)
    if canonical(envelope) != raw_bytes:
        raise ValueError("raw envelope is not canonical")
    exact(envelope, ["schema_version","admission_digest","bucket_epoch_digest","stream_initialization_digest","stream_id","witness_identity","witness_key_id","session","last_session_rotation","current","predecessor","prepared","genesis_abort","store_generation","signature"], "raw envelope")
    if envelope["schema_version"] != 1: raise ValueError("raw envelope schema differs")
    text(envelope["stream_id"], "envelope stream"); text(envelope["witness_identity"], "envelope witness identity")
    for key in ["admission_digest","bucket_epoch_digest","stream_initialization_digest","witness_key_id"]: digest(envelope[key], f"envelope {key}")
    u64(envelope["store_generation"], "store generation")
    signed_digest = framed_digest(signed_domain, raw_bytes)
    preimage = {key:value for key,value in envelope.items() if key != "signature"}
    detached_signature(envelope["signature"], envelope["witness_key_id"], framed_bytes(signed_domain, canonical(preimage)), "witness envelope")
    for stored in [envelope["current"], envelope["predecessor"], envelope["prepared"]]:
        if stored is not None:
            validate_binding(stored["candidate"]["publication_binding"], envelope["stream_id"], envelope["witness_identity"], envelope["witness_key_id"])
    if decoded["store_state_digest"] != framed_digest(store_domain, canonical(preimage)):
        raise ValueError("store-state digest differs")
    if raw["signed_digest"] != signed_digest or signed_digest != ack["proposed_digest"]:
        raise ValueError("raw/ack digest relation differs")
    stream_id = envelope["stream_id"]
    stream_key = "s." + hashlib.sha256(store_domain + stream_id.encode()).hexdigest()
    expected_subject = f"$KV.{expected_bucket}.{stream_key}"
    identity_expected = {
        "admitted_stream_id": stream_id, "admitted_stream_key": stream_key,
        "subject": expected_subject, "witness_identity": envelope["witness_identity"],
        "witness_key_id": envelope["witness_key_id"], "admission_digest": envelope["admission_digest"],
        "bucket_epoch_digest": envelope["bucket_epoch_digest"],
        "stream_initialization_digest": envelope["stream_initialization_digest"],
        "reopened_stream_name": expected_stream, "reopened_admitted_stream_id": stream_id,
        "reopened_admitted_stream_key": stream_key, "reopened_subject": expected_subject,
    }
    if any(ready[key] != value for key,value in identity_expected.items()):
        raise ValueError("Ready/admission/raw identity differs")
    fixture_provenance(expected_bucket, envelope, ready, bindings)
    if raw["subject"] != expected_subject or ready["subject"] != expected_subject or raw["sequence"] != ack["sequence"] or ack["stream"] != expected_stream:
        raise ValueError("raw/ack subject identity differs")
    headers = raw["headers"]
    exact(headers, ["KV-Operation","Nats-Expected-Stream","Nats-Expected-Last-Subject-Sequence"], "headers")
    if headers != {"KV-Operation":"PUT", "Nats-Expected-Stream":expected_stream, "Nats-Expected-Last-Subject-Sequence":str(relations["initial_revision"])}:
        raise ValueError("raw headers differ")
    if ack["token"] != harness_token or ack["duplicate"] is not False or ack["sequence"] <= max(relations["initial_revision"], relations["manifest_tail_sequence"]):
        raise ValueError("ack tuple differs")
    for key in ["initial_revision","manifest_tail_sequence","current_store_generation","proposed_store_generation"]: u64(relations[key], f"relations {key}")
    expected_generations = {"current":(3,4),"predecessor":(5,6),"prepared":(2,3),"abort":(5,6),"genesis_abort":(3,4)}
    if (relations["current_store_generation"],relations["proposed_store_generation"]) != expected_generations[state] or relations["initial_revision"] != 2 or relations["manifest_tail_sequence"] != 12 or ack["sequence"] != 13 or envelope["store_generation"] != relations["proposed_store_generation"] or relations["proposed_store_generation"] != relations["current_store_generation"] + 1 or ack["sequence"] == envelope["store_generation"]:
        raise ValueError("store/global generation relation differs")
    if barrier != {"ack_lines":1,"release_lines":1,"done_lines":1,"ack_token":harness_token,"release_token":harness_token,"done_token":harness_token,"event_trace":[f"1\tack_observed\t{harness_token}",f"2\trelease_written\t{harness_token}",f"3\tdone_observed\t{harness_token}",f"4\trestart_observed\t{harness_token}"]}:
        raise ValueError("barrier evidence differs")
    components = decoded["components"]
    exact(components, ["current_candidate","current_head","predecessor_candidate","predecessor_head","prepared_candidate","prepared_state","genesis_abort"], "component frames")
    expected_components = {
        "current_candidate": component_frame(None if envelope["current"] is None else envelope["current"]["candidate"], candidate_domain),
        "current_head": component_frame(None if envelope["current"] is None else envelope["current"]["head"], head_domain),
        "predecessor_candidate": component_frame(None if envelope["predecessor"] is None else envelope["predecessor"]["candidate"], candidate_domain),
        "predecessor_head": component_frame(None if envelope["predecessor"] is None else envelope["predecessor"]["head"], head_domain),
        "prepared_candidate": component_frame(None if envelope["prepared"] is None else envelope["prepared"]["candidate"], candidate_domain),
        "prepared_state": component_frame(None if envelope["prepared"] is None else envelope["prepared"]["prepared"], prepared_domain),
        "genesis_abort": component_frame(envelope["genesis_abort"], genesis_component_domain),
    }
    if components != expected_components:
        raise ValueError("raw/component canonical digest relation differs")
    current_outcome = validate_stored(envelope["current"], stream_id, envelope["witness_identity"], envelope["witness_key_id"])
    predecessor_outcome = validate_stored(envelope["predecessor"], stream_id, envelope["witness_identity"], envelope["witness_key_id"])
    current_binds = envelope["current"] is None and envelope["predecessor"] is None
    if envelope["current"] is not None and envelope["predecessor"] is None:
        current_binds = envelope["current"]["candidate"]["predecessor_head"] is None
    elif envelope["current"] is not None and envelope["predecessor"] is not None:
        predecessor_head = envelope["predecessor"]["head"]
        candidate = envelope["current"]["candidate"]
        current_binds = candidate["predecessor_head"] == predecessor_head and candidate["predecessor_head_digest"] == head_digest(predecessor_head) and candidate["predecessor_data_head_digest"] == data_head_digest(predecessor_head)
    prepared_binds = True
    if envelope["prepared"] is not None:
        stored = envelope["prepared"]
        session_generation = None if envelope["session"] is None else envelope["session"]["session_generation"]
        prepared = validate_prepared_stored(stored, stream_id, envelope["witness_identity"], envelope["witness_key_id"], session_generation)
        expected_predecessor = None if envelope["current"] is None else envelope["current"]["head"]
        prepared_binds = stored["candidate"]["predecessor_head"] == expected_predecessor and prepared["predecessor_head"] == expected_predecessor and prepared["head"]["candidate_digest"] == candidate_digest(stored["candidate"])
    if envelope["genesis_abort"] is not None: validate_genesis_abort(envelope["genesis_abort"], stream_id, envelope["witness_key_id"])
    if (envelope["session"] is None) != (envelope["last_session_rotation"] is None): raise ValueError("session/rotation presence differs")
    if envelope["session"] is not None:
        validate_session(envelope["session"], envelope); validate_rotation(envelope["last_session_rotation"], envelope)
        authority_source = next((item["candidate"]["publication_binding"] for item in [envelope["current"],envelope["prepared"],envelope["predecessor"]] if item is not None), None)
        if authority_source is None and envelope["genesis_abort"] is not None:
            authority_source = {"authority_pair":envelope["genesis_abort"]["authority_pair"],"generation":envelope["genesis_abort"]["binding_generation"],"binding_digest":envelope["genesis_abort"]["binding_digest"],"signer_key_id":envelope["genesis_abort"]["signer_key_id"]}
        if authority_source is not None and (envelope["session"]["authority_pair"] != authority_source["authority_pair"] or envelope["session"]["binding_generation"] != authority_source["generation"] or envelope["session"]["binding_digest"] != authority_source["binding_digest"] or envelope["session"]["signer_key_id"] != authority_source["signer_key_id"]):
            raise ValueError("session admitted authority differs")
    if envelope["store_generation"] == 0 or all(envelope[key] is None for key in ["session","last_session_rotation","current","predecessor","prepared","genesis_abort"]): raise ValueError("runtime state cardinality differs")
    if envelope["genesis_abort"] is not None and any(envelope[key] is not None for key in ["current","predecessor","prepared"]): raise ValueError("genesis abort cardinality differs")
    derived_semantic = {"current":current_outcome,"predecessor":predecessor_outcome,"prepared":envelope["prepared"] is not None,"genesis_abort":envelope["genesis_abort"] is not None,"current_binds_predecessor":current_binds,"prepared_binds_current":prepared_binds}
    if evidence["semantic"] != derived_semantic or derived_semantic != semantic_expected[state]:
        raise ValueError("raw-derived semantic fingerprint differs")
    pinned = "docker.io/library/nats:2.11.17-alpine@sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00"
    expected_volume = f"{project}_nats-data:true"
    if not re.fullmatch(r"phase285-nats-[0-9]+-[0-9]+", project) or restart["project"] != project or restart["service"] != "nats" or restart["image_before"] != pinned or restart["image_after"] != pinned or restart["volume_before"] != expected_volume or restart["volume_after"] != expected_volume or not re.fullmatch(r"[0-9a-f]{64}", restart["container_before"]) or restart["container_after"] != restart["container_before"] or restart["leader"] != "phase285-nats-harness":
        raise ValueError("restart physical identity differs")
    validate_live_container(restart, project)
    canonical_timestamp(bindings["ready_created_at"]); canonical_timestamp(bindings["restarted_created_at"])
    if bindings["ready_created_at"] != bindings["restarted_created_at"] or bindings["ready_raw_config_digest"] != bindings["restarted_raw_config_digest"] or bindings["ready_epoch_digest"] != ready["bucket_epoch_digest"] or bindings["ready_epoch_digest"] != bindings["anchor_epoch_digest"] or bindings["ready_epoch_digest"] != bindings["envelope_epoch_digest"] or bindings["ready_initialization_digest"] != ready["stream_initialization_digest"] or bindings["ready_initialization_digest"] != bindings["envelope_initialization_digest"] or bindings["ready_manifest_digest"] != bindings["reopened_manifest_digest"] or bindings["reopened_read_stream_id"] != stream_id or bindings["reopened_read_revision"] != ack["sequence"] or bindings["reopened_read_digest"] != signed_digest:
        raise ValueError("reopened Ready/read binding differs")
    for key, value in bindings.items():
        if key.endswith("digest") and not hex64.fullmatch(value):
            raise ValueError("binding digest malformed")

def typed_error(value, error):
    return value == {"result":"err", "error":error}

def validate_anchor(row):
    if row["kind"] != "anchor_recreation" or row["state_id"] is not None: raise ValueError("anchor row identity differs")
    value = row["evidence"]
    keys = ["stream_name","bucket_name","before_created","before_anchor_created","stale_created","after_created","before_raw_config_digest","after_raw_config_digest","stale_result","recreated_result","ready_epoch_digest","anchor_epoch_digest","manifest_initialization_digest","envelope_initialization_digest","ready_manifest_digest","anchor_manifest_digest"]
    exact(value, keys, "anchor evidence")
    before = canonical_timestamp(value["before_created"]); stale = canonical_timestamp(value["stale_created"]); after = canonical_timestamp(value["after_created"])
    if value["stream_name"] != "KV_phase285_c_anchor" or value["bucket_name"] != "phase285_c_anchor" or value["before_anchor_created"] != before or stale != "2026-08-24T00:00:00.000000000Z" or len({before,stale,after}) != 3 or value["before_raw_config_digest"] != value["after_raw_config_digest"] or not typed_error(value["stale_result"], "configuration") or not typed_error(value["recreated_result"], "configuration") or value["ready_epoch_digest"] != value["anchor_epoch_digest"] or value["manifest_initialization_digest"] != value["envelope_initialization_digest"] or value["ready_manifest_digest"] != value["anchor_manifest_digest"]:
        raise ValueError("anchor/recreation relation differs")
    for key in keys:
        if key.endswith("digest") and not hex64.fullmatch(value[key]): raise ValueError("anchor digest malformed")

def validate_unavailable(row):
    if row["kind"] != "unavailable_account_iterator" or row["state_id"] is not None: raise ValueError("unavailable row identity differs")
    value = row["evidence"]
    keys = ["stream_name","bucket_name","stream_id","foreign_result","rogue_sequence","iterator_result","inspect_result","read_result","cas_result"]
    exact(value, keys, "unavailable evidence")
    foreign = value["foreign_result"]
    exact(foreign, ["result","http_code","error_code","description"], "foreign result")
    if value["stream_name"] != "KV_phase285_c_account" or value["bucket_name"] != "phase285_c_account" or value["stream_id"] != "stream-phase285_c_account" or foreign["result"] != "refused" or foreign["http_code"] != 404 or foreign["error_code"] != 10059 or foreign["description"] != "stream not found (code 404, error code 10059)" or value["rogue_sequence"] != 3 or not typed_error(value["iterator_result"], "bounds") or any(not typed_error(value[key], "unavailable") for key in ["inspect_result","read_result","cas_result"]):
        raise ValueError("unavailable/account/iterator relation differs")

def validate_global(row):
    if row["kind"] != "global_revision" or row["state_id"] is not None: raise ValueError("global row identity differs")
    value = row["evidence"]
    keys = ["stream_id","initial_revision","noise_sequences","noise_last_sequence","expected_previous_revision","previous_revision","new_revision","acknowledged_digest","proposed_digest","duplicate","store_generation","initial_plus_one","final_read_revision","final_read_digest"]
    exact(value, keys, "global evidence")
    if value["stream_id"] != "stream-phase285_c_global" or value["initial_revision"] != 2 or value["noise_sequences"] != list(range(3,13)) or value["noise_last_sequence"] != 12 or value["expected_previous_revision"] != 2 or value["previous_revision"] != 2 or value["new_revision"] != 13 or value["store_generation"] != 1 or value["initial_plus_one"] != 3 or value["duplicate"] is not False or value["acknowledged_digest"] != value["proposed_digest"] or value["final_read_revision"] != 13 or value["final_read_digest"] != value["proposed_digest"]:
        raise ValueError("global/store revision relation differs")
    for key in ["acknowledged_digest","proposed_digest","final_read_digest"]:
        if not hex64.fullmatch(value[key]): raise ValueError("global digest malformed")

def validate_rows(rows):
    if len(rows) != 8: raise ValueError("checkpoint dynamic cardinality differs")
    restart_rows = [row for row in rows if row["case"] == restart_case]
    anchor_rows = [row for row in rows if row["case"] == anchor_case]
    unavailable_rows = [row for row in rows if row["case"] == unavailable_case]
    global_rows = [row for row in rows if row["case"] == global_case]
    if {row["state_id"] for row in restart_rows} != set(states) or len(restart_rows) != 5 or len(anchor_rows) != len(unavailable_rows) or len(anchor_rows) != len(global_rows) or len(anchor_rows) != 1:
        raise ValueError("checkpoint case/state inventory differs")
    for row in restart_rows: validate_restart(row)
    validate_anchor(anchor_rows[0]); validate_unavailable(unavailable_rows[0]); validate_global(global_rows[0])
    return rows

release_required = {"case","token","positive_source_sha256","negative_source_sha256","lock_sha256","closure","profile","positive_status","negative_status","diagnostic_code","diagnostic_symbol","diagnostic_path","diagnostic_span","normal_constructor","release_hook_absent","status"}
def validate_release_provenance():
    raw = release_provenance_path.read_bytes()
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ValueError("release provenance framing differs")
    row = strict_loads(raw)
    if raw != canonical(row) + b"\n":
        raise ValueError("release provenance canonical bytes differ")
    required = {"schema_version","token","ledger_path","ledger_sha256","ledger_size","ledger_device","ledger_inode","lock_sha256","positive_source_sha256","negative_source_sha256","status"}
    exact(row, required, "release provenance")
    if row["schema_version"] != 1 or row["token"] != release_token or row["status"] != "validated" or pathlib.Path(row["ledger_path"]) != release_path or release_path.resolve(strict=True) != release_path:
        raise ValueError("release provenance identity differs")
    ledger_raw = release_path.read_bytes(); stat = release_path.stat(); actual_sha = hashlib.sha256(ledger_raw).hexdigest()
    if actual_sha != release_sha or row["ledger_sha256"] != actual_sha or row["ledger_size"] != len(ledger_raw) or row["ledger_device"] != stat.st_dev or row["ledger_inode"] != stat.st_ino:
        raise ValueError("release provenance file identity differs")
    for key in ["lock_sha256","positive_source_sha256","negative_source_sha256"]:
        if not hex64.fullmatch(row[key]):
            raise ValueError("release provenance source digest differs")
    return row

def validate_release_binding(raw, actual_path, expected_path, expected_token, expected_sha):
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1: raise ValueError("release row framing differs")
    row = strict_loads(raw)
    if raw != canonical(row) + b"\n": raise ValueError("release row is not canonical")
    exact(row, release_required, "release row")
    if str(pathlib.Path(actual_path).resolve()) != str(pathlib.Path(expected_path).resolve()) or hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError("release path/digest binding differs")
    if row["case"] != "release_hook_absent" or row["token"] != expected_token or row["status"] != "passed" or row["release_hook_absent"] is not True or row["positive_status"] != 0 or row["negative_status"] != 101 or row["token"] == harness_token or row["token"] in registry.values(): raise ValueError("release row binding differs")
    if row["closure"] != "validated" or row["profile"] != "release" or row["diagnostic_code"] != "E0599" or row["diagnostic_symbol"] != "open_with_post_ack_barrier" or row["diagnostic_path"] != "src/main.rs" or row["normal_constructor"] != "present": raise ValueError("release semantics differ")
    if any(not hex64.fullmatch(row[key]) for key in ["positive_source_sha256","negative_source_sha256","lock_sha256"]) or row["positive_source_sha256"] == row["negative_source_sha256"]: raise ValueError("release source/lock digests differ")
    span = row["diagnostic_span"]
    exact(span, ["line_start","line_end","column_start","column_end"], "release span")
    if span["line_start"] != 4 or span["line_end"] != 4 or span["column_end"] <= span["column_start"]: raise ValueError("release diagnostic span differs")
    return row

dynamic_raw = pathlib.Path(observed_path).read_bytes()
rows = validate_rows(parse_dynamic(dynamic_raw))
release_provenance = validate_release_provenance()
release_raw = pathlib.Path(release_path).read_bytes()
release = validate_release_binding(release_raw, release_path, release_canonical, release_token, release_sha)
if mode == "validate":
    print("checkpoint_dynamic cases=4 rows=8 release_rows=1 passed=9 failed=0")
    raise SystemExit(0)
if mode != "self-test": raise SystemExit("unknown checkpoint dynamic validator mode")

def refresh(row): row["row_digest"] = row_digest(row)
def encode_rows(candidate): return b"" if not candidate else b"\n".join(canonical(row) for row in candidate) + b"\n"
mutants = []
mutants.append(("omission", copy.deepcopy(rows[:-1])))
added = copy.deepcopy(rows); extra = copy.deepcopy(rows[0]); extra["case"] = "unexpected_case"; refresh(extra); added.append(extra); mutants.append(("addition", added))
duplicated = copy.deepcopy(rows); duplicated.append(copy.deepcopy(rows[0])); mutants.append(("duplication", duplicated))
mutants.append(("zero", []))
renamed = copy.deepcopy(rows); renamed[0]["state_id"] = "renamed"; refresh(renamed[0]); mutants.append(("rename", renamed))
wrong_status = copy.deepcopy(rows); wrong_status[0]["status"] = "failed"; refresh(wrong_status[0]); mutants.append(("wrong_status", wrong_status))
wrong_digest = copy.deepcopy(rows); wrong_digest[0]["row_digest"] = "0" * 64; mutants.append(("wrong_digest", wrong_digest))
stale_token = copy.deepcopy(rows); stale_token[0]["invocation_token"] = "stale"; refresh(stale_token[0]); mutants.append(("stale_token", stale_token))
stale_tree = copy.deepcopy(rows); stale_tree[0]["accepted_tree"] = "0" * 40; refresh(stale_tree[0]); mutants.append(("stale_tree", stale_tree))
ack_substitution = copy.deepcopy(rows); ack_substitution[0]["evidence"]["ack"] = copy.deepcopy(ack_substitution[1]["evidence"]["ack"]); refresh(ack_substitution[0]); mutants.append(("ack_substitution", ack_substitution))
cross_state = copy.deepcopy(rows); cross_state[0]["state_id"] = cross_state[1]["state_id"]; refresh(cross_state[0]); mutants.append(("cross_state", cross_state))
cross_case = copy.deepcopy(rows); cross_case[0]["case"] = anchor_case; refresh(cross_case[0]); mutants.append(("cross_case", cross_case))

def redigest_restart(row, envelope):
    raw_bytes = canonical(envelope); digest = framed_digest(signed_domain, raw_bytes)
    row["evidence"]["raw"]["bytes_hex"] = raw_bytes.hex()
    row["evidence"]["raw"]["signed_digest"] = digest
    row["evidence"]["ack"]["proposed_digest"] = digest
    row["evidence"]["bindings"]["reopened_read_digest"] = digest
    row["evidence"]["decoded"]["store_state_digest"] = framed_digest(store_domain, canonical({key:value for key,value in envelope.items() if key != "signature"}))
    row["evidence"]["decoded"]["components"] = {
        "current_candidate":component_frame(None if envelope["current"] is None else envelope["current"]["candidate"], candidate_domain),
        "current_head":component_frame(None if envelope["current"] is None else envelope["current"]["head"], head_domain),
        "predecessor_candidate":component_frame(None if envelope["predecessor"] is None else envelope["predecessor"]["candidate"], candidate_domain),
        "predecessor_head":component_frame(None if envelope["predecessor"] is None else envelope["predecessor"]["head"], head_domain),
        "prepared_candidate":component_frame(None if envelope["prepared"] is None else envelope["prepared"]["candidate"], candidate_domain),
        "prepared_state":component_frame(None if envelope["prepared"] is None else envelope["prepared"]["prepared"], prepared_domain),
        "genesis_abort":component_frame(envelope["genesis_abort"], genesis_component_domain),
    }
    refresh(row)

def resign_restart(row, envelope, domain=signed_domain):
    bucket = f"phase285_c_{row['state_id'].replace('_', '')}"
    preimage = {key:value for key,value in envelope.items() if key != "signature"}
    envelope["signature"] = sign_ed25519(f"{bucket}-witness", framed_bytes(domain, canonical(preimage)))
    redigest_restart(row, envelope)

def restart_envelope(candidate, state):
    row = next(value for value in candidate if value["state_id"] == state)
    return row, strict_loads(bytes.fromhex(row["evidence"]["raw"]["bytes_hex"]))

def add_c2b_envelope_mutant(name, state, mutate, expected, resign=True, domain=signed_domain):
    candidate = copy.deepcopy(rows)
    row, envelope = restart_envelope(candidate, state)
    mutate(envelope, row)
    if resign: resign_restart(row, envelope, domain)
    else: redigest_restart(row, envelope)
    c2b_mutants.append((name, candidate, expected))

c2b_mutants = []

def mutate_signature_only(envelope, _row):
    envelope["signature"]["signature_hex"] = "0" * 128

def mutate_signature_key_id(envelope, _row):
    envelope["signature"]["key_id"] = "0" * 64

def mutate_signature_public_key(envelope, _row):
    envelope["signature"]["public_key_hex"] = "0" * 64

def mutate_unsigned_preimage(envelope, _row):
    envelope["store_generation"] += 1

def mutate_session_schema(envelope, _row):
    envelope["session"]["schema_version"] = 2
    envelope["last_session_rotation"]["session"]["schema_version"] = 2

def mutate_rotation_schema(envelope, _row):
    envelope["last_session_rotation"]["schema_version"] = 2

def mutate_rotation_snapshot(envelope, _row):
    envelope["last_session_rotation"]["discovery_snapshot"]["unexpected"] = True

def mutate_binding_signature(envelope, _row):
    envelope["current"]["candidate"]["publication_binding"]["binding_signature"]["signature_hex"] = "0" * 128

def mutate_state_attestation(envelope, _row):
    envelope["current"]["candidate"]["state_attestation"]["signature_hex"] = "0" * 128

def mutate_prepared_schema(envelope, _row):
    envelope["prepared"]["prepared"]["schema_version"] = 2
    envelope["last_session_rotation"]["discovery_snapshot"]["prepared"]["schema_version"] = 2

def mutate_genesis_reason(envelope, _row):
    envelope["genesis_abort"]["reason"] = ""
    envelope["last_session_rotation"]["discovery_snapshot"]["genesis_abort"]["reason"] = ""

def mutate_type_confusion(envelope, _row):
    envelope["store_generation"] = True

add_c2b_envelope_mutant("c2b_signature_only", "current", mutate_signature_only, "witness envelope Ed25519 verification differs", False)
add_c2b_envelope_mutant("c2b_signature_key_id", "current", mutate_signature_key_id, "witness envelope signature identity differs", False)
add_c2b_envelope_mutant("c2b_signature_public_key", "current", mutate_signature_public_key, "witness envelope key-id/public-key binding differs", False)
add_c2b_envelope_mutant("c2b_unsigned_envelope", "current", mutate_unsigned_preimage, "witness envelope Ed25519 verification differs", False)
add_c2b_envelope_mutant("c2b_wrong_signature_domain", "current", lambda _envelope,_row: None, "witness envelope Ed25519 verification differs", True, b"swarm.governance.witness-store-signed.wrong")
add_c2b_envelope_mutant("c2b_session_schema", "current", mutate_session_schema, "session schema differs")
add_c2b_envelope_mutant("c2b_rotation_schema", "current", mutate_rotation_schema, "rotation schema differs")
add_c2b_envelope_mutant("c2b_rotation_snapshot_extra", "current", mutate_rotation_snapshot, "discovery snapshot field inventory differs")
add_c2b_envelope_mutant("c2b_binding_signature", "current", mutate_binding_signature, "binding Ed25519 verification differs")
add_c2b_envelope_mutant("c2b_state_attestation", "current", mutate_state_attestation, "state payload Ed25519 verification differs")
add_c2b_envelope_mutant("c2b_prepared_schema", "prepared", mutate_prepared_schema, "prepared schema differs")
add_c2b_envelope_mutant("c2b_genesis_reason", "genesis_abort", mutate_genesis_reason, "genesis abort reason string differs")
add_c2b_envelope_mutant("c2b_type_confusion", "current", mutate_type_confusion, "store generation integer/range differs")

revision_pair = copy.deepcopy(rows)
revision_row, _ = restart_envelope(revision_pair, "current")
revision_row["evidence"]["ack"]["sequence"] = 14
revision_row["evidence"]["raw"]["sequence"] = 14
revision_row["evidence"]["bindings"]["reopened_read_revision"] = 14
refresh(revision_row)
c2b_mutants.append(("c2b_paired_revision", revision_pair, "store/global generation relation differs"))

container_pair = copy.deepcopy(rows)
container_row, _ = restart_envelope(container_pair, "current")
container_row["evidence"]["restart"]["container_before"] = "f" * 64
container_row["evidence"]["restart"]["container_after"] = "f" * 64
refresh(container_row)
c2b_mutants.append(("c2b_paired_container", container_pair, "restarted container observation unavailable"))

def paired_digest(name, envelope_key, ready_key, binding_keys, expected):
    candidate = copy.deepcopy(rows)
    row, envelope = restart_envelope(candidate, "current")
    replacement = "1" * 64
    if envelope_key is not None: envelope[envelope_key] = replacement
    if ready_key is not None: row["evidence"]["ready_identity"][ready_key] = replacement
    for key in binding_keys: row["evidence"]["bindings"][key] = replacement
    resign_restart(row, envelope)
    c2b_mutants.append((name, candidate, expected))

paired_digest("c2b_paired_admission", "admission_digest", "admission_digest", [], "independently derived Ready/anchor provenance differs: admission_digest")
paired_digest("c2b_paired_epoch", "bucket_epoch_digest", "bucket_epoch_digest", ["ready_epoch_digest","anchor_epoch_digest","envelope_epoch_digest"], "independently derived Ready/anchor provenance differs: ready_epoch_identity")
paired_digest("c2b_paired_initialization", "stream_initialization_digest", "stream_initialization_digest", ["ready_initialization_digest","envelope_initialization_digest"], "independently derived Ready/anchor provenance differs: ready_initialization_identity")
paired_digest("c2b_paired_manifest", None, None, ["ready_manifest_digest","reopened_manifest_digest"], "independently derived Ready/anchor provenance differs: ready_manifest_digest")
paired_digest("c2b_paired_raw_config", None, None, ["ready_raw_config_digest","restarted_raw_config_digest"], "independently derived Ready/anchor provenance differs: ready_raw_config_digest")

witness_pair = copy.deepcopy(rows)
witness_row, witness_envelope = restart_envelope(witness_pair, "current")
witness_envelope["witness_identity"] = "phase285-other-witness"
witness_row["evidence"]["ready_identity"]["witness_identity"] = "phase285-other-witness"
resign_restart(witness_row, witness_envelope)
c2b_mutants.append(("c2b_paired_witness", witness_pair, "publication binding namespace differs"))

stream_pair = copy.deepcopy(rows)
stream_row, stream_envelope = restart_envelope(stream_pair, "current")
stream_envelope["stream_id"] = "stream-paired-substitution"
stream_key = "s." + hashlib.sha256(store_domain + stream_envelope["stream_id"].encode()).hexdigest()
subject_value = f"$KV.phase285_c_current.{stream_key}"
for key in ["admitted_stream_id","reopened_admitted_stream_id"]: stream_row["evidence"]["ready_identity"][key] = stream_envelope["stream_id"]
for key in ["admitted_stream_key","reopened_admitted_stream_key"]: stream_row["evidence"]["ready_identity"][key] = stream_key
for key in ["subject","reopened_subject"]: stream_row["evidence"]["ready_identity"][key] = subject_value
stream_row["evidence"]["raw"]["subject"] = subject_value
stream_row["evidence"]["bindings"]["reopened_read_stream_id"] = stream_envelope["stream_id"]
resign_restart(stream_row, stream_envelope)
c2b_mutants.append(("c2b_paired_stream", stream_pair, "publication binding namespace differs"))

def abort_terminal_txid(summary, stream_id):
    preimage = {"schema_version":1,"stream_id":stream_id,"predecessor_head_digest":summary["predecessor_head_digest"],"candidate_digest":summary["candidate_digest"],"binding_generation":summary["binding_generation"],"binding_digest":summary["binding_digest"],"authority_pair":summary["authority_pair"],"epoch":summary["epoch"],"sequence":summary["sequence"],"intent_counter":summary["intent_counter"]}
    return framed_digest(txid_domain, canonical(preimage))

def add_retained_abort_mutant(name, mutate, expected):
    candidate = copy.deepcopy(rows)
    row, envelope = restart_envelope(candidate, "abort")
    summary = envelope["current"]["head"]["last_intent_outcome"]["Aborted"]
    mutate(summary, envelope)
    envelope["last_session_rotation"]["discovery_snapshot"]["head"] = copy.deepcopy(envelope["current"]["head"])
    resign_restart(row, envelope)
    c2b_mutants.append((name, candidate, expected))

def mutate_abort_epoch(summary, envelope):
    summary["epoch"] += 1
    summary["txid"] = abort_terminal_txid(summary, envelope["stream_id"])

def mutate_abort_sequence(summary, envelope):
    summary["sequence"] += 1
    summary["txid"] = abort_terminal_txid(summary, envelope["stream_id"])

def mutate_abort_terminal_txid(summary, _envelope):
    summary["txid"] = "0" * 64

def mutate_abort_predecessor(summary, envelope):
    summary["predecessor_head_digest"] = "1" * 64
    summary["txid"] = abort_terminal_txid(summary, envelope["stream_id"])

def mutate_abort_candidate_alias(summary, envelope):
    summary["candidate_digest"] = envelope["current"]["head"]["candidate_digest"]
    summary["txid"] = abort_terminal_txid(summary, envelope["stream_id"])

add_retained_abort_mutant("c2b_abort_summary_epoch", mutate_abort_epoch, "retained abort summary epoch/sequence differs")
add_retained_abort_mutant("c2b_abort_summary_sequence", mutate_abort_sequence, "retained abort summary epoch/sequence differs")
add_retained_abort_mutant("c2b_abort_terminal_txid", mutate_abort_terminal_txid, "retained abort terminal txid differs")
add_retained_abort_mutant("c2b_abort_immediate_predecessor", mutate_abort_predecessor, "retained abort immediate predecessor differs")
add_retained_abort_mutant("c2b_abort_live_candidate_alias", mutate_abort_candidate_alias, "retained abort/live candidate identity aliases")

prepared_session = copy.deepcopy(rows)
prepared_session_row, prepared_session_envelope = restart_envelope(prepared_session, "prepared")
prepared_session_envelope["prepared"]["prepared"]["session_generation"] += 1
prepared_session_envelope["last_session_rotation"]["discovery_snapshot"]["prepared"] = copy.deepcopy(prepared_session_envelope["prepared"]["prepared"])
resign_restart(prepared_session_row, prepared_session_envelope)
c2b_mutants.append(("c2b_prepared_session_generation", prepared_session, "prepared/session generation differs"))

embedded_abort = copy.deepcopy(rows)
embedded_abort_row, embedded_abort_envelope = restart_envelope(embedded_abort, "prepared")
live_prepared = embedded_abort_envelope["prepared"]["prepared"]
live_head = live_prepared["head"]
embedded = {"schema_version":1,"stream_id":live_head["stream_id"],"txid":"0"*64,"candidate_digest":"2"*64,"predecessor_head_digest":live_prepared["predecessor_head_digest"],"resulting_data_head_digest":live_prepared["predecessor_data_head_digest"],"epoch":live_head["epoch"],"sequence":live_head["sequence"],"intent_counter":live_head["intent_counter"],"binding_generation":live_head["binding_generation"],"binding_digest":live_head["binding_digest"],"signer_key_id":live_head["signer_key_id"],"witness_key_id":live_head["witness_key_id"],"authority_pair":live_head["authority_pair"],"publication_mapping":live_prepared["predecessor_publication_mapping"],"reason":"coherent-cross-prepared-control"}
embedded["txid"] = abort_terminal_txid(embedded, embedded["stream_id"])
live_prepared["genesis_abort"] = embedded
embedded_abort_envelope["last_session_rotation"]["discovery_snapshot"]["prepared"] = copy.deepcopy(live_prepared)
resign_restart(embedded_abort_row, embedded_abort_envelope)
c2b_mutants.append(("c2b_embedded_genesis_abort_prepared", embedded_abort, "genesis abort/prepared relation differs"))

abort_discovery = copy.deepcopy(rows)
abort_discovery_row, abort_discovery_envelope = restart_envelope(abort_discovery, "abort")
other_row, other_envelope = restart_envelope(rows, "current")
_ = other_row
abort_discovery_envelope["last_session_rotation"]["discovery_snapshot"]["head"] = copy.deepcopy(other_envelope["current"]["head"])
resign_restart(abort_discovery_row, abort_discovery_envelope)
c2b_mutants.append(("c2b_abort_discovery_mirror", abort_discovery, "rotation discovery snapshot relation differs"))

positive_bytes_sha256 = hashlib.sha256(dynamic_raw).hexdigest()
for name, candidate, expected in c2b_mutants:
    try: validate_rows(parse_dynamic(encode_rows(candidate)))
    except (ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        if expected not in str(error): raise SystemExit(f"checkpoint C2b mutant failed for wrong reason: {name}: {error}")
        print(f"checkpoint_c2b_self_test_red mutation={name} reason={expected}")
    else: raise SystemExit(f"checkpoint C2b mutant survived: {name}")
if encode_rows(rows) != dynamic_raw or hashlib.sha256(dynamic_raw).hexdigest() != positive_bytes_sha256:
    raise SystemExit("checkpoint C2b self-test altered positive canonical evidence")
print(f"checkpoint_c2b_self_test mutations={len(c2b_mutants)} crypto=5 nested=8 provenance=9 relations={len(c2b_mutants)-22} positive_bytes_unchanged=1")

arbitrary_raw = copy.deepcopy(rows); target = arbitrary_raw[0]; envelope = strict_loads(bytes.fromhex(target["evidence"]["raw"]["bytes_hex"])); envelope["admission_digest"] = "1" * 64; redigest_restart(target,envelope); mutants.append(("coherent_arbitrary_raw", arbitrary_raw))
subject = copy.deepcopy(rows); subject[0]["evidence"]["raw"]["subject"] = "$KV.wrong.s.bad"; subject[0]["evidence"]["ready_identity"]["subject"] = "$KV.wrong.s.bad"; refresh(subject[0]); mutants.append(("coherent_subject",subject))
stream_header = copy.deepcopy(rows); stream_header[0]["evidence"]["ack"]["stream"] = "KV_wrong"; stream_header[0]["evidence"]["raw"]["headers"]["Nats-Expected-Stream"] = "KV_wrong"; stream_header[0]["evidence"]["ready_identity"]["stream_name"] = "KV_wrong"; refresh(stream_header[0]); mutants.append(("coherent_stream_header",stream_header))
for name, path, value in [
    ("reopened_id", ["bindings","reopened_read_stream_id"], "stream-other"),
    ("leader", ["restart","leader"], "phase285-other"),
    ("empty_volume", ["restart","volume_before"], ""),
    ("empty_container", ["restart","container_after"], ""),
]:
    candidate = copy.deepcopy(rows); candidate[0]["evidence"][path[0]][path[1]] = value; refresh(candidate[0]); mutants.append((name,candidate))
component_relation = copy.deepcopy(rows); target = next(row for row in component_relation if row["state_id"] == "predecessor"); envelope = strict_loads(bytes.fromhex(target["evidence"]["raw"]["bytes_hex"])); envelope["current"]["candidate"]["predecessor_head"] = None; redigest_restart(target,envelope); mutants.append(("coherent_component_relation",component_relation))

anchor_index = next(i for i,row in enumerate(rows) if row["case"] == anchor_case)
unavailable_index = next(i for i,row in enumerate(rows) if row["case"] == unavailable_case)
global_index = next(i for i,row in enumerate(rows) if row["case"] == global_case)
def add_field_mutants(index, replacements, prefix):
    for key, value in replacements.items():
        candidate = copy.deepcopy(rows); candidate[index]["evidence"][key] = value; refresh(candidate[index]); mutants.append((f"{prefix}_{key}",candidate))
add_field_mutants(anchor_index, {
    "stream_name":"", "bucket_name":"", "before_created":"2026-13-01T00:00:00.000000000Z",
    "before_anchor_created":"2026-08-24T00:00:00.000000000Z", "stale_created":rows[anchor_index]["evidence"]["before_created"],
    "after_created":rows[anchor_index]["evidence"]["before_created"], "before_raw_config_digest":"0"*64,
    "after_raw_config_digest":"1"*64, "stale_result":{"result":"ok"}, "recreated_result":{"result":"ok"},
    "ready_epoch_digest":"0"*64, "anchor_epoch_digest":"1"*64, "manifest_initialization_digest":"0"*64,
    "envelope_initialization_digest":"1"*64, "ready_manifest_digest":"0"*64, "anchor_manifest_digest":"1"*64,
}, "anchor")
unicode_timestamp = copy.deepcopy(rows); unicode_timestamp[anchor_index]["evidence"]["before_created"] = "٢٠٢٦-08-25T00:00:00.000000000Z"; refresh(unicode_timestamp[anchor_index]); mutants.append(("anchor_unicode_digit_timestamp", unicode_timestamp))
add_field_mutants(unavailable_index, {
    "stream_name":"", "bucket_name":"", "stream_id":"", "foreign_result":{"result":"refused","http_code":403,"error_code":10059,"description":"stream not found (code 404, error code 10059)"},
    "rogue_sequence":0, "iterator_result":{"result":"err","error":"missing"}, "inspect_result":{"result":"ok"}, "read_result":{"result":"ok"}, "cas_result":{"result":"ok"},
}, "unavailable")
global_value = rows[global_index]["evidence"]
add_field_mutants(global_index, {
    "stream_id":"", "initial_revision":0, "noise_sequences":[3,5,6,7,8,9,10,11,12,13], "noise_last_sequence":11,
    "expected_previous_revision":0, "previous_revision":0, "new_revision":12, "acknowledged_digest":"0"*64,
    "proposed_digest":"1"*64, "duplicate":True, "store_generation":2, "initial_plus_one":4,
    "final_read_revision":12, "final_read_digest":"0"*64,
}, "global")

for name, candidate in mutants:
    try: validate_rows(parse_dynamic(encode_rows(candidate)))
    except (ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError): print(f"checkpoint_dynamic_self_test_red mutation={name}")
    else: raise SystemExit(f"checkpoint dynamic mutant survived: {name}")

framing_mutants = {
    "dynamic_whitespace": b" " + dynamic_raw,
    "dynamic_key_order": json.dumps({key:rows[0][key] for key in reversed(list(rows[0]))}, sort_keys=False, separators=(",", ":"), allow_nan=False).encode() + b"\n" + b"".join(canonical(row)+b"\n" for row in rows[1:]),
    "dynamic_nan": dynamic_raw.replace(b'"schema_version":1', b'"schema_version":NaN', 1),
    "dynamic_infinity": dynamic_raw.replace(b'"schema_version":1', b'"schema_version":Infinity', 1),
    "dynamic_negative_infinity": dynamic_raw.replace(b'"schema_version":1', b'"schema_version":-Infinity', 1),
}
for name, raw in framing_mutants.items():
    try: validate_rows(parse_dynamic(raw))
    except (ValueError, json.JSONDecodeError): print(f"checkpoint_dynamic_self_test_red mutation={name}")
    else: raise SystemExit(f"checkpoint framing mutant survived: {name}")

release_mutants = []
stale_row = copy.deepcopy(release); stale_row["token"] = "stale-release-token"; stale_raw = canonical(stale_row)+b"\n"; release_mutants.append(("release_stale_row",stale_raw,release_path,release_canonical,release_token,hashlib.sha256(stale_raw).hexdigest()))
release_mutants.append(("release_stale_path",release_raw,str(pathlib.Path(release_path).with_name("stale-ledger.json")),release_canonical,release_token,release_sha))
release_mutants.append(("release_stale_token",release_raw,release_path,release_canonical,"stale-release-token",release_sha))
release_mutants.append(("release_wrong_digest",release_raw,release_path,release_canonical,release_token,"0"*64))
release_mutants.append(("release_whitespace",b" "+release_raw,release_path,release_canonical,release_token,hashlib.sha256(b" "+release_raw).hexdigest()))
release_reordered = json.dumps({key:release[key] for key in reversed(list(release))},sort_keys=False,separators=(",",":"),allow_nan=False).encode()+b"\n"
release_mutants.append(("release_key_order",release_reordered,release_path,release_canonical,release_token,hashlib.sha256(release_reordered).hexdigest()))
for constant in ["NaN", "Infinity", "-Infinity"]:
    raw = release_raw.replace(b'"positive_status":0', f'"positive_status":{constant}'.encode(), 1)
    release_mutants.append((f"release_{constant.lower().replace('-', 'negative_')}",raw,release_path,release_canonical,release_token,hashlib.sha256(raw).hexdigest()))
for name, raw, actual, expected, token, digest in release_mutants:
    try: validate_release_binding(raw,actual,expected,token,digest)
    except (ValueError,KeyError,TypeError,json.JSONDecodeError): print(f"checkpoint_dynamic_self_test_red mutation={name}")
    else: raise SystemExit(f"checkpoint release mutant survived: {name}")
total = len(mutants) + len(framing_mutants) + len(release_mutants)
print(f"checkpoint_dynamic_self_test mutations={total} dynamic={len(mutants)+len(framing_mutants)} release={len(release_mutants)} passed=1 release_bound=1")
PY
}

run_inner_ledger_validator_self_test() {
  local temp_dir expected observed
  temp_dir="$(phase285_create_confined_scratch phase285-inner-ledger-selftest)"
  PHASE285_WITNESS_TEMP_DIR="$temp_dir"
  trap cleanup_temp_dir_on_exit EXIT
  expected="$temp_dir/expected.tsv"
  observed="$temp_dir/observed.tsv"
  write_expected_inner_ledger jetstream-cas-scenarios "$expected"
  cp "$expected" "$observed"
  inner_ledger_validator "$expected" "$observed" self-test
}

transport_execution_result_validator() {
  python3 -I - "$1" "$2" <<'PY'
import pathlib
import sys

expected_path = pathlib.Path(sys.argv[1])
results_path = pathlib.Path(sys.argv[2])
expected = [line for line in expected_path.read_text().splitlines() if line]
if not expected or len(expected) != len(set(expected)):
    raise SystemExit("transport expected-row source is empty or duplicated")
rows = [line.split("\t") for line in results_path.read_text().splitlines() if line]
if len(rows) != len(expected) or any(len(row) != 5 for row in rows):
    raise SystemExit("transport execution result count or width mismatch")
if [row[0] for row in rows] != expected or len({row[0] for row in rows}) != len(rows):
    raise SystemExit("transport execution result identity/order mismatch")
for row in rows:
    try:
        counts = tuple(int(value) for value in row[1:])
    except ValueError as error:
        raise SystemExit("transport execution result count is not an integer") from error
    if counts != (1, 1, 0, 0):
        raise SystemExit(f"transport execution result cardinality mismatch: {row[0]}={counts}")
print(
    f"transport_execution_results expected={len(expected)} executed={len(rows)} "
    f"positive={sum(int(row[1]) for row in rows)} "
    f"mutation_failure={sum(int(row[2]) for row in rows)} failed=0 ignored=0"
)
PY
}

run_transport_execution_self_test() {
  local prior_results="${PHASE285_TRANSPORT_PRIOR_RESULTS_FILE:-}"
  [ -n "$prior_results" ] && [ -f "$prior_results" ] || {
    echo "transport zero/omitted self-test requires parent-provided actual prior results" >&2
    return 1
  }
  phase285_scratch_hostile_controls conformance-transport
  phase285_scratch_hostile_controls conformance-witness
  local temp_dir expected_file full_results omitted_results zero_results current_case
  temp_dir="$(phase285_create_confined_scratch phase285-transport-result-selftest)"
  PHASE285_WITNESS_TEMP_DIR="$temp_dir"
  trap cleanup_temp_dir_on_exit EXIT
  expected_file="$temp_dir/expected.txt"
  full_results="$temp_dir/full-results.tsv"
  omitted_results="$temp_dir/omitted-results.tsv"
  zero_results="$temp_dir/zero-results.tsv"
  selector_rows transport-layering >"$expected_file"
  cp "$prior_results" "$full_results"
  current_case="$(selector_rows transport-layering | tail -n 1)"
  printf '%s\t1\t1\t0\t0\n' "$current_case" >>"$full_results"
  transport_execution_result_validator "$expected_file" "$full_results" >/dev/null

  sed '1d' "$full_results" >"$omitted_results"
  if transport_execution_result_validator "$expected_file" "$omitted_results" >/dev/null 2>&1; then
    echo "transport actual-row suppression was accepted" >&2
    return 1
  fi
  python3 -I - "$full_results" "$zero_results" <<'PY'
import pathlib
import sys
source, target = map(pathlib.Path, sys.argv[1:])
rows = source.read_text().splitlines()
fields = rows[0].split("\t")
fields[1] = "0"
rows[0] = "\t".join(fields)
target.write_text("\n".join(rows) + "\n")
PY
  if transport_execution_result_validator "$expected_file" "$zero_results" >/dev/null 2>&1; then
    echo "transport zero-count mutation was accepted" >&2
    return 1
  fi
  echo "phase285_transport_self_test case=transport-layering-zero-or-omitted positive=1 mutation_failure=1 shared_validator_mutations=2"
}

run_transport_selector() {
  local case_name command output_file executed=0
  local temp_dir expected_file results_file
  temp_dir="$(phase285_create_confined_scratch phase285-transport)"
  PHASE285_WITNESS_TEMP_DIR="$temp_dir"
  trap cleanup_temp_dir_on_exit EXIT
  expected_file="$temp_dir/expected.txt"
  results_file="$temp_dir/results.tsv"
  selector_rows transport-layering >"$expected_file"
  : >"$results_file"
  while IFS= read -r case_name; do
    [ -n "$case_name" ] || continue
    IFS=$'\t' read -r _ command < <(transport_tuple_for_case "$case_name")
    output_file="$temp_dir/$case_name.txt"
    if ! PHASE285_TRANSPORT_PRIOR_RESULTS_FILE="$results_file" \
      bash -c "$command" >"$output_file" 2>&1; then
      cat "$output_file" >&2
      echo "transport row failed: $case_name" >&2
      return 1
    fi
    case "$case_name" in
      transport_layering_rejects_raw_kv_subject)
        grep -qx 'phase285_transport_negative case=phase285-raw-kv-subject positive=1' "$output_file" || return 1
        grep -qx 'phase285_scratch_self_test site=negative boundaries=3 passed=1' "$output_file" || return 1
        grep -qx 'phase285_transport_self_test case=phase285-raw-kv-subject positive=1 structural_mutations=29 executable_mapping_mutations=5' "$output_file" || return 1
        ;;
      transport_layering_rejects_missing_library_target)
        [ "$(grep -c '^self_test_red case=missing-library-target ' "$output_file")" -eq 1 ] &&
          grep -q '^self_test executed=1 passed=1 failed=0$' "$output_file" || return 1
        ;;
      transport_layering_rejects_zero_or_omitted_mutation)
        grep -qx 'phase285_transport_self_test case=transport-layering-zero-or-omitted positive=1 mutation_failure=1 shared_validator_mutations=2' "$output_file" || return 1
        grep -qx 'phase285_scratch_self_test site=conformance-transport boundaries=3 passed=1' "$output_file" || return 1
        grep -qx 'phase285_scratch_self_test site=conformance-witness boundaries=3 passed=1' "$output_file" || return 1
        ;;
      *)
        [ "$(grep -c '^phase285_transport_self_test case=.* positive=1 mutation_failure=1$' "$output_file")" -eq 1 ] || return 1
        ;;
    esac
    printf '%s\t1\t1\t0\t0\n' "$case_name" >>"$results_file"
    executed=$((executed + 1))
    echo "case=$case_name positive=1 mutation_failure=1 failed=0 ignored=0"
  done < <(selector_rows transport-layering)
  transport_execution_result_validator "$expected_file" "$results_file"
  local required
  required="$(wc -l <"$expected_file" | tr -d ' ')"
  [ "$executed" -eq "$required" ] || return 1
  echo "selector=transport-layering executed=$executed passed=$executed failed=0 ignored=0 mutation_failure_count=$executed"
}

validate_release_probe_lock() {
  python3 -I - "$ROOT_DIR/Cargo.lock" "$1/Cargo.lock" "$1/crates/phase285-release-probe/Cargo.toml" <<'PY'
import pathlib, sys, tomllib
root_lock, probe_lock, manifest_path = map(pathlib.Path, sys.argv[1:])
root = tomllib.loads(root_lock.read_text())
probe = tomllib.loads(probe_lock.read_text())
root_ids = {
    (item["name"], item["version"], item.get("source"), item.get("checksum"))
    for item in root.get("package", [])
}
packages = probe.get("package", [])
roots = [item for item in packages if item.get("name") == "phase285-release-probe"]
if len(roots) != 1 or roots[0].get("version") != "0.0.0" or roots[0].get("source") is not None:
    raise SystemExit("release probe root identity differs")
dependencies = roots[0].get("dependencies", [])
if dependencies != ["swarm-governance-witness"]:
    raise SystemExit(f"release probe root dependency differs: {dependencies!r}")
for item in packages:
    if item is roots[0]:
        continue
    identity = (item["name"], item["version"], item.get("source"), item.get("checksum"))
    if identity not in root_ids or (item.get("source") or "").startswith("git+"):
        raise SystemExit(f"release probe dependency is not accepted by root lock: {identity!r}")
manifest = tomllib.loads(manifest_path.read_text())
dependency = manifest.get("dependencies", {}).get("swarm-governance-witness")
if dependency != {"path": "../swarm-governance-witness", "version": "=0.1.0"}:
    raise SystemExit(f"release probe local dependency differs: {dependency!r}")
print(f"release_probe_lock packages={len(packages)} closure=validated")
PY
}

validate_release_probe_sources() {
  python3 -I - "$1" "$2" <<'PY'
import pathlib, sys
positive, negative = map(pathlib.Path, sys.argv[1:])
expected_positive = """use swarm_governance_witness::NatsWitnessStore;

fn constructor_boundary() {
    let _constructor = NatsWitnessStore::open;
}

fn main() { constructor_boundary(); }
"""
expected_negative = expected_positive.replace(
    "    let _constructor = NatsWitnessStore::open;",
    "    let _constructor = NatsWitnessStore::open_with_post_ack_barrier;",
)
if positive.read_text() != expected_positive:
    raise SystemExit("release probe positive source differs")
if negative.read_text() != expected_negative:
    raise SystemExit("release probe negative source differs")
PY
}

validate_release_probe_manifest_and_target() {
  local manifest="$1" source="$2" metadata
  metadata="$(cargo metadata --manifest-path "$manifest" --locked --offline --no-deps --format-version 1)" || return 1
  python3 -I - "$manifest" "$source" "$metadata" <<'PY'
import json, pathlib, sys
manifest, source = map(pathlib.Path, sys.argv[1:3])
metadata = json.loads(sys.argv[3])
expected_manifest = """[package]
name = "phase285-release-probe"
version = "0.0.0"
edition = "2024"

[dependencies]
swarm-governance-witness = { path = "../swarm-governance-witness", version = "=0.1.0" }
"""
if manifest.read_text() != expected_manifest:
    raise SystemExit("release probe manifest differs")
packages = metadata.get("packages", [])
matches = [package for package in packages if package.get("name") == "phase285-release-probe"]
if len(matches) != 1:
    raise SystemExit("release probe metadata package cardinality differs")
package = matches[0]
if pathlib.Path(package["manifest_path"]).resolve() != manifest.resolve():
    raise SystemExit("release probe metadata package identity differs")
if metadata.get("workspace_members", []).count(package.get("id")) != 1:
    raise SystemExit("release probe workspace membership differs")
targets = package.get("targets", [])
if len(targets) != 1:
    raise SystemExit("release probe target cardinality differs")
target = targets[0]
if (
    target.get("name") != "phase285-release-probe"
    or target.get("kind") != ["bin"]
    or target.get("crate_types") != ["bin"]
    or target.get("edition") != "2024"
    or pathlib.Path(target["src_path"]).resolve() != source.resolve()
):
    raise SystemExit("release probe target inventory or source path differs")
PY
}

validate_release_probe_command() {
  local manifest="$1"
  shift
  [[ "$#" -eq 8 \
    && "$1" == cargo \
    && "$2" == check \
    && "$3" == --manifest-path \
    && "$4" == "$manifest" \
    && "$5" == --release \
    && "$6" == --locked \
    && "$7" == --offline \
    && "$8" == --message-format=json ]]
}

validate_release_lock_command() {
  [[ "$#" -eq 3 && "$1" == cargo && "$2" == generate-lockfile && "$3" == --offline ]]
}

run_release_lock_generation() {
  local workspace="$1" trace="$2"
  shift 2
  validate_release_lock_command "$@" || return 125
  (set -o noclobber; printf '%s\n' "$*" >"$trace") 2>/dev/null || return 1
  (cd "$workspace" && "$@")
}

run_release_probe_check() {
  local log="$1" target="$2" manifest="$3" trace="$4"
  shift 4
  validate_release_probe_command "$manifest" "$@" || return 125
  (set -o noclobber; printf '%s\n' "$*" >"$trace") 2>/dev/null || return 1
  CARGO_TARGET_DIR="$target" "$@" >"$log" 2>&1
}

validate_release_probe_statuses() {
  [[ "$1" -eq 0 && "$2" -eq 101 ]]
}

validate_release_probe_frozen_lock() {
  local actual
  actual="$(shasum -a 256 "$1" | awk '{print $1}')"
  [[ "$actual" == "$2" ]]
}

release_probe_token() {
  python3 -I - "$1" "$PPID" "$$" <<'PY'
import hashlib, pathlib, sys, time
parent = pathlib.Path(sys.argv[1]).resolve()
parent_digest = hashlib.sha256(str(parent).encode()).hexdigest()
print(f"phase285-release-{parent_digest}-{sys.argv[2]}-{sys.argv[3]}-{time.time_ns()}")
PY
}

validate_release_probe_token() {
  python3 -I - "$1" "$2" <<'PY'
import hashlib, pathlib, re, sys
token, parent_raw = sys.argv[1:]
parent = pathlib.Path(parent_raw).resolve()
parent_digest = hashlib.sha256(str(parent).encode()).hexdigest()
pattern = rf"phase285-release-{parent_digest}-[1-9][0-9]*-[1-9][0-9]*-[1-9][0-9]*"
if re.fullmatch(pattern, token) is None:
    raise SystemExit("release probe token is stale, reusable, or bound to another probe")
PY
}

validate_release_probe_diagnostic() {
  python3 -I - "$1" "$2" <<'PY'
import json, pathlib, sys
log, probe = map(pathlib.Path, sys.argv[1:])
matches = []
for line in log.read_text().splitlines():
    try: message = json.loads(line)
    except json.JSONDecodeError: continue
    if message.get("reason") != "compiler-message": continue
    value = message.get("message", {})
    code = (value.get("code") or {}).get("code")
    rendered = value.get("rendered") or ""
    if code == "E0599" and "`open_with_post_ack_barrier`" in rendered:
        spans = [span for span in value.get("spans", []) if span.get("is_primary")]
        if len(spans) == 1: matches.append(spans[0])
if len(matches) != 1:
    raise SystemExit("release probe diagnostic cardinality differs")
span = matches[0]
diagnostic_path = pathlib.Path(span["file_name"])
if diagnostic_path.is_absolute():
    try: relative = diagnostic_path.resolve().relative_to(probe.resolve()).as_posix()
    except ValueError as error: raise SystemExit("release probe diagnostic escaped probe") from error
else:
    rendered = diagnostic_path.as_posix()
    relative = "src/main.rs" if rendered in {"src/main.rs", "crates/phase285-release-probe/src/main.rs"} else rendered
if relative != "src/main.rs":
    raise SystemExit("release probe diagnostic path differs")
if span["line_start"] != 4 or span["line_end"] != 4 or span["column_end"] <= span["column_start"]:
    raise SystemExit("release probe diagnostic span differs")
PY
}

validate_release_probe_execution() {
  local positive="$1" negative="$2" workspace="$3" frozen_lock_sha="$4"
  local positive_status="$5" negative_status="$6" negative_log="$7" probe="$8"
  local ledger="$9" token="${10}" positive_sha="${11}" negative_sha="${12}"
  local lock_trace="${13}" positive_trace="${14}" negative_trace="${15}"
  validate_release_probe_sources "$positive" "$negative" || return 1
  validate_release_probe_manifest_and_target "$probe/Cargo.toml" "$positive" || return 1
  validate_release_probe_token "$token" "$(dirname "$workspace")" || return 1
  validate_release_probe_lock "$workspace" >/dev/null || return 1
  validate_release_probe_frozen_lock "$workspace/Cargo.lock" "$frozen_lock_sha" || return 1
  [[ "$(cat -- "$lock_trace")" == "cargo generate-lockfile --offline" \
    && "$(wc -l <"$lock_trace" | tr -d ' ')" -eq 1 ]] || return 1
  local expected_command="cargo check --manifest-path $probe/Cargo.toml --release --locked --offline --message-format=json"
  [[ "$(cat -- "$positive_trace")" == "$expected_command" \
    && "$(cat -- "$negative_trace")" == "$expected_command" \
    && "$(wc -l <"$positive_trace" | tr -d ' ')" -eq 1 \
    && "$(wc -l <"$negative_trace" | tr -d ' ')" -eq 1 ]] || return 1
  validate_release_probe_statuses "$positive_status" "$negative_status" || return 1
  validate_release_probe_diagnostic "$negative_log" "$probe" || return 1
  release_probe_ledger_validator "$ledger" "$token" validate \
    "$frozen_lock_sha" "$positive_sha" "$negative_sha" >/dev/null
}

validate_release_probe_wiring() {
  python3 -I - "$1" <<'PY'
import hashlib, pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
def body(name):
    start = text.index(f"\n{name}() {{") + 1
    if name == "run_release_hook_probe":
        end = text.index("\nrun_release_hook_self_test() {", start)
    elif name == "write_release_probe_provenance":
        end = text.index("\nrelease_probe_provenance_values() {", start)
    else:
        end = text.index("\n}\n", start) + 3
    return text[start:end]

required = {
    "validate_release_probe_execution": [
        'validate_release_probe_sources "$positive" "$negative" || return 1',
        'validate_release_probe_manifest_and_target "$probe/Cargo.toml" "$positive" || return 1',
        'validate_release_probe_token "$token" "$(dirname "$workspace")" || return 1',
        'validate_release_probe_lock "$workspace" >/dev/null || return 1',
        'validate_release_probe_frozen_lock "$workspace/Cargo.lock" "$frozen_lock_sha" || return 1',
        '[[ "$(cat -- "$lock_trace")" == "cargo generate-lockfile --offline"',
        '[[ "$(cat -- "$positive_trace")" == "$expected_command"',
        'validate_release_probe_statuses "$positive_status" "$negative_status" || return 1',
        'validate_release_probe_diagnostic "$negative_log" "$probe" || return 1',
        'release_probe_ledger_validator "$ledger" "$token" validate',
    ],
    "run_release_lock_generation": [
        'validate_release_lock_command "$@" || return 125',
        '(set -o noclobber; printf \'%s\\n\' "$*" >"$trace")',
        '  (cd "$workspace" && "$@")',
    ],
    "run_release_probe_check": [
        'validate_release_probe_command "$manifest" "$@" || return 125',
        '(set -o noclobber; printf \'%s\\n\' "$*" >"$trace")',
        '  CARGO_TARGET_DIR="$target" "$@" >"$log" 2>&1',
    ],
    "run_release_hook_probe": [
        '  validate_release_probe_token "$token" "$parent" || return 1',
        'with ledger.open("x") as output:',
        '  validate_release_probe_wiring "${BASH_SOURCE[0]}"',
        '  validate_release_probe_execution \\\n',
        '  write_release_probe_provenance \\\n',
        '  record_release_probe_runtime_receipt "$parent" "$token" "$ledger" || return 1',
    ],
    "write_release_probe_provenance": [
        'with provenance.open("x") as output:',
    ],
    "release_probe_workspace_artifact_values": [
        '  validate_release_probe_sources "$positive" "$negative" || return 1',
        '  validate_release_probe_manifest_and_target "$manifest" "$positive" || return 1',
        '  validate_release_probe_lock "$workspace" >/dev/null || return 1',
        '  validate_release_probe_diagnostic "$negative_log" "$probe" || return 1',
        'if build_results(sys.argv[1]) != [True]:',
        'if build_results(sys.argv[2]) != [False]:',
    ],
    "checkpoint_release_union_validate_existing": [
        '  validate_release_probe_wiring "${BASH_SOURCE[0]}" || return 1',
        '  release_ledger="$(release_probe_ledger_path "$selector_root")"',
        '  release_sha="$(shasum -a 256 "$release_ledger" | awk \'{print $1}\')"',
        '    release_probe_workspace_artifact_values "$selector_root"',
        '    release_probe_provenance_values "$selector_root" "$release_token" "$release_sha" \\',
        '  release_probe_ledger_validator "$release_ledger" "$release_token" validate \\\n',
        '  validate_release_probe_runtime_receipt \\\n',
        '  checkpoint_dynamic_union_validator "$observed" "$token_registry" \\\n',
    ],
    "checkpoint_release_union_chain": [
        '  validate_release_probe_wiring "${BASH_SOURCE[0]}" || return 1',
        '  release_token="$(release_probe_token "$selector_root")"',
        '  run_release_hook_probe "$selector_root" "$release_token" validate',
        '  checkpoint_release_union_validate_existing "$observed" "$token_registry" \\\n',
    ],
}
for name, fragments in required.items():
    section = body(name)
    if any(section.count(fragment) != 1 for fragment in fragments):
        raise SystemExit(f"release probe wiring differs: {name}")
guarded = set(required) | {
    "validate_release_probe_wiring", "release_probe_ledger_path",
    "release_probe_provenance_path", "release_probe_provenance_values",
    "record_release_probe_runtime_receipt", "validate_release_probe_runtime_receipt",
}
for name in guarded:
    if text.count(f"\n{name}() {{") != 1:
        raise SystemExit(f"release probe guarded function definition differs: {name}")
readonly_fragment = "readonly -f " + " ".join(sorted(guarded))
if text.count(readonly_fragment) != 1:
    raise SystemExit("release probe guarded-function readonly boundary differs")
body_digests = {
    "run_release_hook_probe": "19ff887f5f98999ce430e8f9f1e29c92dbe2d2b00215d9588cbb5ddb89d7cf3c",
    "write_release_probe_provenance": "7c21f3a283a604c68ac3333ef1d60c9e936bcf6a1003d27e860ef7828eb53559",
    "release_probe_ledger_path": "f7b2fe01a50a3e28d2cd8fe10376e9a50e8652745bd84ed933fc51690fdc8fe3",
    "release_probe_provenance_path": "82b206a2082a9a100ac1ae7e07608f2b67dcbba1be265b5311b3e25ff8e8e935",
    "release_probe_provenance_values": "e2cca24ef5d147aa22aa48617a38110e316991271876158ce1e2920af6ec6d5e",
    "release_probe_workspace_artifact_values": "d909c93057775acc8115d31777056f09d28cc1fc0f8f7d492fcfbcd23fb3c418",
    "record_release_probe_runtime_receipt": "6bf128a80e15eb6598a50ee5b44de0fea82a2f81fdf222c6c07bfb34d01f97a2",
    "validate_release_probe_runtime_receipt": "60865554be336051b69904b3a3708afb8f8a3b7296036134c4066632efa0b30d",
    "checkpoint_release_union_validate_existing": "dbef4303886f336a2118f4129ef37345f916798646a3adc3f2d79b63c5732d60",
    "checkpoint_release_union_chain": "4fc6b08857ab3245c8c63cc1b97117eb739fc647dfd23367ea64857eb6db6692",
}
for name, expected_digest in body_digests.items():
    if hashlib.sha256(body(name).encode()).hexdigest() != expected_digest:
        raise SystemExit(f"release probe guarded function body differs: {name}")
for variable in [
    "PHASE285_RELEASE_PROBE_RECEIPT_ROOT",
    "PHASE285_RELEASE_PROBE_RECEIPT_TOKEN",
    "PHASE285_RELEASE_PROBE_RECEIPT_SHA",
]:
    assignments = re.findall(rf"(?m)^[ \\t]*{variable}=", text)
    if len(assignments) != 2:
        raise SystemExit(f"release probe receipt assignment authority differs: {variable}")
for name in ["checkpoint_release_union_validate_existing", "checkpoint_release_union_chain"]:
    section = body(name)
    positions = [section.index(fragment) for fragment in required[name]]
    if positions != sorted(positions):
        raise SystemExit(f"release probe caller-chain order differs: {name}")
probe_body = body("run_release_hook_probe")
top_level_calls = [
    '  run_release_lock_generation "$workspace" "$lock_trace" cargo generate-lockfile --offline\n',
    '  run_release_probe_check "$positive_log" "$parent/release-target" "$probe/Cargo.toml" "$positive_trace" \\\n    cargo check --manifest-path "$probe/Cargo.toml" --release --locked --offline --message-format=json || positive_status=$?\n',
    '  run_release_probe_check "$negative_log" "$parent/release-target" "$probe/Cargo.toml" "$negative_trace" \\\n    cargo check --manifest-path "$probe/Cargo.toml" --release --locked --offline --message-format=json || negative_status=$?\n',
]
positions = []
for call in top_level_calls:
    if probe_body.count(call) != 1:
        raise SystemExit("release probe top-level execution cardinality differs")
    positions.append(probe_body.index(call))
if positions != sorted(positions):
    raise SystemExit("release probe top-level execution order differs")
def exact_section(start_marker, end_marker):
    start = text.index(f"\n{start_marker}") + 1
    end = text.index(end_marker, start)
    return text[start:end]

dynamic_sections = {
    "run_release_hook_self_test": (
        exact_section("run_release_hook_self_test() {", "\n  release_mutant_execution_gate() {"),
        'token="$(release_probe_token "$scratch")"',
    ),
    "checkpoint_release_union_chain": (
        body("checkpoint_release_union_chain"),
        'release_token="$(release_probe_token "$selector_root")"',
    ),
}
if any(section.count(fragment) != 1 for section, fragment in dynamic_sections.values()):
    raise SystemExit("release probe dynamic token wiring differs")
PY
}

release_probe_ledger_validator() {
  python3 -I - "$1" "$2" "$3" "$4" "$5" "$6" <<'PY'
import json, pathlib, sys
path, token, mode = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
expected_lock_sha, expected_positive_sha, expected_negative_sha = sys.argv[4:7]
required = {
    "case", "token", "positive_source_sha256", "negative_source_sha256",
    "lock_sha256", "closure", "profile", "positive_status", "negative_status",
    "diagnostic_code", "diagnostic_symbol", "diagnostic_path", "diagnostic_span",
    "normal_constructor", "release_hook_absent", "status",
}

def validate(raw):
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ValueError("release probe ledger is not one canonical line")
    def reject_constant(value): raise ValueError(f"non-RFC JSON constant rejected: {value}")
    row = json.loads(raw, parse_constant=reject_constant)
    if raw != json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n":
        raise ValueError("release probe ledger is not canonical")
    if set(row) != required:
        raise ValueError("release probe ledger field inventory differs")
    if row["case"] != "release_hook_absent" or row["token"] != token or row["status"] != "passed":
        raise ValueError("release probe identity differs")
    for field in ("positive_source_sha256", "negative_source_sha256", "lock_sha256"):
        value = row[field]
        if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise ValueError(f"release probe {field} differs")
    if row["positive_source_sha256"] == row["negative_source_sha256"]:
        raise ValueError("release probe sources are identical")
    if row["lock_sha256"] != expected_lock_sha:
        raise ValueError("release probe lock digest differs")
    if row["positive_source_sha256"] != expected_positive_sha:
        raise ValueError("release probe positive source digest differs")
    if row["negative_source_sha256"] != expected_negative_sha:
        raise ValueError("release probe negative source digest differs")
    expected = {
        "closure": "validated", "profile": "release", "positive_status": 0,
        "negative_status": 101, "diagnostic_code": "E0599",
        "diagnostic_symbol": "open_with_post_ack_barrier", "diagnostic_path": "src/main.rs",
        "normal_constructor": "present", "release_hook_absent": True,
    }
    if any(row[key] != value for key, value in expected.items()):
        raise ValueError("release probe semantic evidence differs")
    span = row["diagnostic_span"]
    if not isinstance(span, dict) or set(span) != {"line_start", "line_end", "column_start", "column_end"}:
        raise ValueError("release probe diagnostic span shape differs")
    if span["line_start"] != 4 or span["line_end"] != 4 or span["column_end"] <= span["column_start"]:
        raise ValueError("release probe diagnostic span differs")
    return row
raw = path.read_bytes()
validate(raw)
if mode != "validate":
    raise SystemExit("unknown release probe validator mode")
print("release_hook_absent rows=1 passed=1 failed=0")
PY
}

release_probe_ledger_path() {
  [[ "$#" -eq 1 && "$1" = /* ]] || return 2
  printf '%s/release-workspace/crates/phase285-release-probe/release-ledger.json\n' "$1"
}

release_probe_provenance_path() {
  [[ "$#" -eq 1 && "$1" = /* ]] || return 2
  printf '%s/release-probe-provenance.json\n' "$1"
}

write_release_probe_provenance() {
  local root="$1" token="$2" ledger lock_sha="$3" positive_sha="$4" negative_sha="$5" provenance
  ledger="$(release_probe_ledger_path "$root")"
  provenance="$(release_probe_provenance_path "$root")"
  python3 -I - "$root" "$token" "$ledger" "$provenance" "$lock_sha" "$positive_sha" "$negative_sha" <<'PY'
import hashlib, json, pathlib, sys
root, token = pathlib.Path(sys.argv[1]), sys.argv[2]
ledger, provenance = pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4])
lock_sha, positive_sha, negative_sha = sys.argv[5:8]
root = root.resolve(strict=True)
ledger = ledger.resolve(strict=True)
if ledger != root / "release-workspace/crates/phase285-release-probe/release-ledger.json":
    raise SystemExit("release provenance ledger path differs")
raw = ledger.read_bytes()
stat = ledger.stat()
row = {
    "schema_version": 1, "token": token, "ledger_path": str(ledger),
    "ledger_sha256": hashlib.sha256(raw).hexdigest(), "ledger_size": len(raw),
    "ledger_device": stat.st_dev, "ledger_inode": stat.st_ino,
    "lock_sha256": lock_sha, "positive_source_sha256": positive_sha,
    "negative_source_sha256": negative_sha, "status": "validated",
}
with provenance.open("x") as output:
    output.write(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
PY
}

release_probe_provenance_values() {
  local root="$1" token="$2" ledger_sha="$3" actual_lock_sha="$4"
  local actual_positive_sha="$5" actual_negative_sha="$6" provenance
  provenance="$(release_probe_provenance_path "$root")"
  python3 -I - "$root" "$token" "$ledger_sha" "$actual_lock_sha" \
    "$actual_positive_sha" "$actual_negative_sha" "$provenance" <<'PY'
import hashlib, json, pathlib, sys
root, token, expected_sha = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
actual_lock_sha, actual_positive_sha, actual_negative_sha = sys.argv[4:7]
provenance = pathlib.Path(sys.argv[7])
root = root.resolve(strict=True)
expected_ledger = root / "release-workspace/crates/phase285-release-probe/release-ledger.json"
if provenance.resolve(strict=True) != root / "release-probe-provenance.json":
    raise SystemExit("release provenance path differs")
raw = provenance.read_bytes()
if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
    raise SystemExit("release provenance framing differs")
def reject_constant(value): raise ValueError(f"non-RFC JSON constant rejected: {value}")
row = json.loads(raw, parse_constant=reject_constant)
if raw != json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n":
    raise SystemExit("release provenance canonical bytes differ")
required = {"schema_version","token","ledger_path","ledger_sha256","ledger_size","ledger_device","ledger_inode","lock_sha256","positive_source_sha256","negative_source_sha256","status"}
if set(row) != required or row["schema_version"] != 1 or row["token"] != token or row["status"] != "validated":
    raise SystemExit("release provenance identity differs")
ledger = pathlib.Path(row["ledger_path"])
if ledger != expected_ledger or ledger.resolve(strict=True) != expected_ledger:
    raise SystemExit("release provenance ledger differs")
ledger_raw = ledger.read_bytes(); stat = ledger.stat(); actual_sha = hashlib.sha256(ledger_raw).hexdigest()
if actual_sha != expected_sha or row["ledger_sha256"] != actual_sha or row["ledger_size"] != len(ledger_raw) or row["ledger_device"] != stat.st_dev or row["ledger_inode"] != stat.st_ino:
    raise SystemExit("release provenance file identity differs")
for key in ["lock_sha256","positive_source_sha256","negative_source_sha256"]:
    value = row[key]
    if not isinstance(value,str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise SystemExit("release provenance source digest differs")
if (
    row["lock_sha256"] != actual_lock_sha
    or row["positive_source_sha256"] != actual_positive_sha
    or row["negative_source_sha256"] != actual_negative_sha
):
    raise SystemExit("release provenance does not match independently reopened artifacts")
print("\t".join([str(ledger), row["lock_sha256"], row["positive_source_sha256"], row["negative_source_sha256"]]))
PY
}

release_probe_workspace_artifact_values() {
  local root="$1" workspace
  workspace="$root/release-workspace"
  local probe="$workspace/crates/phase285-release-probe"
  local positive="$probe/src/main.rs" negative="$probe/src/main.negative.rs"
  local manifest="$probe/Cargo.toml" lock="$workspace/Cargo.lock"
  local lock_trace="$probe/lock-command.txt"
  local positive_trace="$probe/positive-command.txt" negative_trace="$probe/negative-command.txt"
  local positive_log="$probe/positive.json" negative_log="$probe/negative.json"
  validate_release_probe_sources "$positive" "$negative" || return 1
  validate_release_probe_manifest_and_target "$manifest" "$positive" || return 1
  validate_release_probe_lock "$workspace" >/dev/null || return 1
  [[ "$(cat -- "$lock_trace")" == "cargo generate-lockfile --offline" \
    && "$(wc -l <"$lock_trace" | tr -d ' ')" -eq 1 ]] || return 1
  local expected_command="cargo check --manifest-path $manifest --release --locked --offline --message-format=json"
  [[ "$(cat -- "$positive_trace")" == "$expected_command" \
    && "$(cat -- "$negative_trace")" == "$expected_command" \
    && "$(wc -l <"$positive_trace" | tr -d ' ')" -eq 1 \
    && "$(wc -l <"$negative_trace" | tr -d ' ')" -eq 1 ]] || return 1
  validate_release_probe_diagnostic "$negative_log" "$probe" || return 1
  python3 -I - "$positive_log" "$negative_log" <<'PY'
import json, pathlib, sys

def build_results(path):
    values = []
    for line in pathlib.Path(path).read_text().splitlines():
        try:
            value = json.loads(line, parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
        except json.JSONDecodeError:
            continue
        if value.get("reason") == "build-finished":
            values.append(value.get("success"))
    return values

if build_results(sys.argv[1]) != [True]:
    raise SystemExit("release positive compiler output differs")
if build_results(sys.argv[2]) != [False]:
    raise SystemExit("release negative compiler output differs")
PY
  printf '%s\t%s\t%s\n' \
    "$(shasum -a 256 "$lock" | awk '{print $1}')" \
    "$(shasum -a 256 "$positive" | awk '{print $1}')" \
    "$(shasum -a 256 "$negative" | awk '{print $1}')"
}

record_release_probe_runtime_receipt() {
  local root="$1" token="$2" ledger="$3" sha
  [ -z "$PHASE285_RELEASE_PROBE_RECEIPT_ROOT" ] || return 1
  sha="$(shasum -a 256 "$ledger" | awk '{print $1}')"
  PHASE285_RELEASE_PROBE_RECEIPT_ROOT="$(cd "$root" && pwd -P)"
  PHASE285_RELEASE_PROBE_RECEIPT_TOKEN="$token"
  PHASE285_RELEASE_PROBE_RECEIPT_SHA="$sha"
}

validate_release_probe_runtime_receipt() {
  local root="$1" token="$2" sha="$3" canonical_root
  canonical_root="$(cd "$root" && pwd -P)"
  if [ "$PHASE285_RELEASE_PROBE_RECEIPT_ROOT" != "$canonical_root" ] \
    || [ "$PHASE285_RELEASE_PROBE_RECEIPT_TOKEN" != "$token" ] \
    || [ "$PHASE285_RELEASE_PROBE_RECEIPT_SHA" != "$sha" ]; then
    echo "release probe runtime receipt differs" >&2
    return 1
  fi
}

run_release_hook_probe() {
  local parent="$1" token="$2" mode="${3:-validate}" reuse_control="${4:-none}" workspace probe
  case "$reuse_control" in
    none|stale-ledger|stale-lock-trace|stale-check-trace) ;;
    *) return 2 ;;
  esac
  validate_release_probe_token "$token" "$parent" || return 1
  workspace="$parent/release-workspace"
  probe="$workspace/crates/phase285-release-probe"
  local positive="$probe/src/main.rs" negative="$probe/src/main.negative.rs"
  local positive_log="$probe/positive.json" negative_log="$probe/negative.json" ledger="$probe/release-ledger.json"
  local lock_trace="$probe/lock-command.txt"
  local positive_trace="$probe/positive-command.txt" negative_trace="$probe/negative-command.txt"
  mkdir "$workspace"
  cp "$ROOT_DIR/Cargo.toml" "$ROOT_DIR/Cargo.lock" "$workspace/"
  cp -R "$ROOT_DIR/crates" "$workspace/crates"
  if [ -d "$ROOT_DIR/.cargo" ]; then
    cp -R "$ROOT_DIR/.cargo" "$workspace/.cargo"
  else
    mkdir "$workspace/.cargo"
  fi
  (cd "$workspace" && cargo vendor --locked --offline --versioned-dirs vendor >.cargo/config.toml 2>vendor.log)
  mkdir "$probe" "$probe/src"
  python3 -I - "$workspace/Cargo.toml" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
needle = '    "crates/swarm-crypto",\n]'
replacement = '    "crates/swarm-crypto",\n    "crates/phase285-release-probe",\n]'
if text.count(needle) != 1:
    raise SystemExit("release probe workspace member seam differs")
path.write_text(text.replace(needle, replacement))
PY
  cat >"$probe/Cargo.toml" <<EOF
[package]
name = "phase285-release-probe"
version = "0.0.0"
edition = "2024"

[dependencies]
swarm-governance-witness = { path = "../swarm-governance-witness", version = "=0.1.0" }
EOF
  cat >"$positive" <<'EOF'
use swarm_governance_witness::NatsWitnessStore;

fn constructor_boundary() {
    let _constructor = NatsWitnessStore::open;
}

fn main() { constructor_boundary(); }
EOF
  python3 -I - "$positive" "$negative" <<'PY'
import pathlib, sys
source, target = map(pathlib.Path, sys.argv[1:])
text = source.read_text()
old = "    let _constructor = NatsWitnessStore::open;"
new = "    let _constructor = NatsWitnessStore::open_with_post_ack_barrier;"
if text.count(old) != 1:
    raise SystemExit("release probe pinned constructor line differs")
target.write_text(text.replace(old, new))
PY
  validate_release_probe_sources "$positive" "$negative"
  if [ "$reuse_control" = stale-lock-trace ]; then
    printf 'stale\n' >"$lock_trace"
  fi
  run_release_lock_generation "$workspace" "$lock_trace" cargo generate-lockfile --offline
  validate_release_probe_lock "$workspace" >/dev/null
  local lock_sha positive_sha negative_sha positive_status=0 negative_status=0
  lock_sha="$(shasum -a 256 "$workspace/Cargo.lock" | awk '{print $1}')"
  positive_sha="$(shasum -a 256 "$positive" | awk '{print $1}')"
  negative_sha="$(shasum -a 256 "$negative" | awk '{print $1}')"
  cp "$positive" "$probe/src/main.positive.rs"
  cp "$negative" "$probe/src/main.negative.accepted.rs"
  cp "$workspace/Cargo.lock" "$workspace/Cargo.lock.accepted"
  cp "$probe/Cargo.toml" "$probe/Cargo.toml.accepted"
  validate_release_probe_frozen_lock "$workspace/Cargo.lock" "$lock_sha"
  if [ "$reuse_control" = stale-check-trace ]; then
    printf 'stale\n' >"$positive_trace"
  fi
  run_release_probe_check "$positive_log" "$parent/release-target" "$probe/Cargo.toml" "$positive_trace" \
    cargo check --manifest-path "$probe/Cargo.toml" --release --locked --offline --message-format=json || positive_status=$?
  [[ "$positive_status" -eq 0 ]] || return 1
  cp "$negative" "$positive"
  run_release_probe_check "$negative_log" "$parent/release-target" "$probe/Cargo.toml" "$negative_trace" \
    cargo check --manifest-path "$probe/Cargo.toml" --release --locked --offline --message-format=json || negative_status=$?
  validate_release_probe_statuses "$positive_status" "$negative_status" || return 1
  validate_release_probe_diagnostic "$negative_log" "$probe"
  cp "$probe/src/main.positive.rs" "$positive"
  if [ "$reuse_control" = stale-ledger ]; then
    printf 'stale\n' >"$ledger"
  fi
  python3 -I - "$negative_log" "$ledger" "$probe" "$token" "$positive_sha" "$negative_sha" "$lock_sha" "$positive_status" "$negative_status" <<'PY'
import json, pathlib, sys
log, ledger, probe = map(pathlib.Path, sys.argv[1:4])
token, positive_sha, negative_sha, lock_sha = sys.argv[4:8]
positive_status, negative_status = map(int, sys.argv[8:10])
matches = []
for line in log.read_text().splitlines():
    try: message = json.loads(line)
    except json.JSONDecodeError: continue
    if message.get("reason") != "compiler-message": continue
    value = message.get("message", {})
    code = (value.get("code") or {}).get("code")
    rendered = value.get("rendered") or ""
    if code == "E0599" and "`open_with_post_ack_barrier`" in rendered:
        spans = [span for span in value.get("spans", []) if span.get("is_primary")]
        if len(spans) == 1: matches.append((code, spans[0]))
if len(matches) != 1:
    raise SystemExit(f"release probe diagnostic cardinality differs: {len(matches)}")
code, span = matches[0]
diagnostic_path = pathlib.Path(span["file_name"])
if diagnostic_path.is_absolute():
    try:
        relative_diagnostic = diagnostic_path.resolve().relative_to(probe.resolve()).as_posix()
    except ValueError as error:
        raise SystemExit("release probe diagnostic escaped probe root") from error
else:
    rendered_path = diagnostic_path.as_posix()
    if rendered_path == "src/main.rs":
        relative_diagnostic = rendered_path
    elif rendered_path == "crates/phase285-release-probe/src/main.rs":
        relative_diagnostic = "src/main.rs"
    else:
        raise SystemExit(f"release probe diagnostic path differs: {rendered_path}")
if relative_diagnostic != "src/main.rs":
    raise SystemExit(f"release probe diagnostic path differs: {relative_diagnostic}")
row = {
    "case": "release_hook_absent", "token": token,
    "positive_source_sha256": positive_sha, "negative_source_sha256": negative_sha,
    "lock_sha256": lock_sha, "closure": "validated", "profile": "release",
    "positive_status": positive_status, "negative_status": negative_status,
    "diagnostic_code": code, "diagnostic_symbol": "open_with_post_ack_barrier",
    "diagnostic_path": "src/main.rs",
    "diagnostic_span": {key: span[key] for key in ("line_start", "line_end", "column_start", "column_end")},
    "normal_constructor": "present", "release_hook_absent": True, "status": "passed",
}
with ledger.open("x") as output:
    output.write(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
PY
  validate_release_probe_wiring "${BASH_SOURCE[0]}"
  validate_release_probe_execution \
    "$positive" "$negative" "$workspace" "$lock_sha" \
    "$positive_status" "$negative_status" "$negative_log" "$probe" \
    "$ledger" "$token" "$positive_sha" "$negative_sha" \
    "$lock_trace" "$positive_trace" "$negative_trace"
  release_probe_ledger_validator "$ledger" "$token" "$mode" \
    "$lock_sha" "$positive_sha" "$negative_sha" || return 1
  write_release_probe_provenance \
    "$parent" "$token" "$lock_sha" "$positive_sha" "$negative_sha" || return 1
  record_release_probe_runtime_receipt "$parent" "$token" "$ledger" || return 1
}

run_release_hook_self_test() {
  local scratch token workspace probe positive negative manifest lock ledger target
  local lock_trace positive_trace negative_trace
  local lock_sha positive_sha negative_sha killed=0 diagnostic_path_status=0
  local status_mutant_pairs=""
  scratch="$(phase285_create_confined_scratch phase285-release-hook)"
  PHASE285_WITNESS_TEMP_DIR="$scratch"
  trap cleanup_temp_dir_on_exit EXIT
  token="$(release_probe_token "$scratch")"
  run_release_hook_probe "$scratch" "$token" validate
  workspace="$scratch/release-workspace"
  probe="$workspace/crates/phase285-release-probe"
  positive="$probe/src/main.rs"
  negative="$probe/src/main.negative.rs"
  manifest="$probe/Cargo.toml"
  lock="$workspace/Cargo.lock"
  ledger="$probe/release-ledger.json"
  lock_trace="$probe/lock-command.txt"
  positive_trace="$probe/positive-command.txt"
  negative_trace="$probe/negative-command.txt"
  target="$scratch/release-mutant-target"
  lock_sha="$(shasum -a 256 "$lock" | awk '{print $1}')"
  positive_sha="$(shasum -a 256 "$positive" | awk '{print $1}')"
  negative_sha="$(shasum -a 256 "$negative" | awk '{print $1}')"
  release_mutant_execution_gate() {
    local positive_status="${1:-0}" negative_status="${2:-101}"
    local diagnostic_log="${3:-$probe/negative.json}" expected_token="${4:-$token}"
    local observed_lock_trace="${5:-$lock_trace}"
    local observed_positive_trace="${6:-$positive_trace}" observed_negative_trace="${7:-$negative_trace}"
    validate_release_probe_execution \
      "$positive" "$negative" "$workspace" "$lock_sha" \
      "$positive_status" "$negative_status" "$diagnostic_log" "$probe" \
      "$ledger" "$expected_token" "$positive_sha" "$negative_sha" \
      "$observed_lock_trace" "$observed_positive_trace" "$observed_negative_trace"
  }

  release_mutant_red() {
    local name="$1" mutant_status=0
    shift
    "$@" >/dev/null 2>&1 || mutant_status=$?
    if [ "$mutant_status" -eq 0 ]; then
      echo "release hook mutant survived actual seam: $name" >&2
      return 1
    fi
    if [ "$mutant_status" -eq 2 ]; then
      echo "release hook mutant harness is invalid or duplicated: $name" >&2
      return 1
    fi
    killed=$((killed + 1))
    echo "release_hook_self_test_red mutation=$name"
  }

  reset_release_sources() {
    cp "$probe/src/main.positive.rs" "$positive"
    cp "$probe/src/main.negative.accepted.rs" "$negative"
    cp "$probe/Cargo.toml.accepted" "$manifest"
  }

  mutate_release_file() {
    python3 -I - "$1" "$2" <<'PY'
import pathlib, sys
path, mutation = pathlib.Path(sys.argv[1]), sys.argv[2]
text = path.read_text()
mutations = {
    "positive-extra": ("fn main() { constructor_boundary(); }", "fn main() { constructor_boundary(); let _extra = 1; }"),
    "positive-no-constructor": ("    let _constructor = NatsWitnessStore::open;", "    let _constructor = 1;"),
    "negative-extra": ("fn main() { constructor_boundary(); }", "fn main() { constructor_boundary(); let _extra = 1; }"),
    "negative-normal": ("    let _constructor = NatsWitnessStore::open_with_post_ack_barrier;", "    let _constructor = NatsWitnessStore::open;"),
    "diagnostic-code": ("    let _constructor = NatsWitnessStore::open_with_post_ack_barrier;", "    let _constructor = ;"),
    "diagnostic-symbol": ("open_with_post_ack_barrier", "open_with_post_ack_barrier_mutant"),
    "diagnostic-span": ("fn constructor_boundary() {", "\nfn constructor_boundary() {"),
    "closure": ('version = "=0.1.0"', 'version = "=9.9.9"'),
}
old, new = mutations[mutation]
if text.count(old) != 1:
    raise SystemExit(f"release mutant source seam differs: {mutation}")
path.write_text(text.replace(old, new, 1))
PY
  }

  reset_release_sources
  mutate_release_file "$positive" positive-extra
  release_mutant_red positive_source release_mutant_execution_gate
  reset_release_sources
  mutate_release_file "$positive" positive-no-constructor
  release_mutant_red normal_constructor release_mutant_execution_gate
  reset_release_sources
  mutate_release_file "$negative" negative-extra
  release_mutant_red negative_source release_mutant_execution_gate
  reset_release_sources
  mutate_release_file "$negative" negative-normal
  release_mutant_red release_hook_absent release_mutant_execution_gate

  cp "$workspace/Cargo.lock.accepted" "$lock"
  python3 -I - "$lock" <<'PY'
import pathlib, re, sys
path = pathlib.Path(sys.argv[1]); text = path.read_text()
blocks = re.split(r"(?=\[\[package\]\]\n)", text)
kept = [block for block in blocks if 'name = "phase285-release-probe"' not in block]
if len(kept) == len(blocks): raise SystemExit("probe root lock block absent")
path.write_text("".join(kept))
PY
  release_mutant_red lock_omission release_mutant_execution_gate
  cp "$workspace/Cargo.lock.accepted" "$lock"
  python3 -I - "$lock" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1]); text = path.read_text()
old = 'name = "phase285-release-probe"\nversion = "0.0.0"'
if text.count(old) != 1: raise SystemExit("probe root lock identity absent")
path.write_text(text.replace(old, 'name = "phase285-release-probe"\nversion = "9.9.9"', 1))
PY
  release_mutant_red lock_substitution release_mutant_execution_gate
  cp "$ROOT_DIR/Cargo.lock" "$lock"
  release_mutant_red lock_copy release_mutant_execution_gate
  cp "$workspace/Cargo.lock.accepted" "$lock"
  printf '\n' >>"$lock"
  release_mutant_red lock_sha256 release_mutant_execution_gate
  cp "$workspace/Cargo.lock.accepted" "$lock"
  reset_release_sources
  mutate_release_file "$manifest" closure
  release_mutant_red closure release_mutant_execution_gate
  reset_release_sources

  mutate_release_manifest() {
    python3 -I - "$manifest" "$1" <<'PY'
import pathlib, sys
path, mutation = pathlib.Path(sys.argv[1]), sys.argv[2]
text = path.read_text()
if mutation == "alternate-bin":
    text += '\n[[bin]]\nname = "alternate-release-probe"\npath = "src/main.rs"\n'
elif mutation == "autobins":
    text = text.replace('edition = "2024"\n', 'edition = "2024"\nautobins = false\n', 1)
elif mutation == "target-substitution":
    text = text.replace('edition = "2024"\n', 'edition = "2024"\nautobins = false\n', 1)
    text += '\n[[bin]]\nname = "phase285-release-probe"\npath = "src/alternate.rs"\n'
else:
    raise SystemExit(f"unknown release manifest mutation: {mutation}")
path.write_text(text)
PY
  }

  mutate_release_manifest alternate-bin
  release_mutant_red manifest_alternate_bin release_mutant_execution_gate
  reset_release_sources
  mutate_release_manifest autobins
  release_mutant_red manifest_autobins release_mutant_execution_gate
  reset_release_sources
  cp "$positive" "$probe/src/alternate.rs"
  mutate_release_manifest target-substitution
  release_mutant_red manifest_target_substitution release_mutant_execution_gate
  unlink "$probe/src/alternate.rs"
  reset_release_sources
  printf 'fn main() {}\n' >"$probe/build.rs"
  release_mutant_red manifest_build_script release_mutant_execution_gate
  unlink "$probe/build.rs"
  reset_release_sources
  cp "$positive" "$probe/src/positive_impl.rs"
  printf 'include!("positive_impl.rs");\n' >"$positive"
  release_mutant_red source_include_indirection release_mutant_execution_gate
  unlink "$probe/src/positive_impl.rs"
  reset_release_sources

  release_mutant_red lock_generation_offline run_release_lock_generation \
    "$workspace" "$scratch/mutant-lock-command.txt" cargo generate-lockfile
  release_mutant_red profile run_release_probe_check \
    "$scratch/profile.json" "$target" "$manifest" "$scratch/profile-command.txt" \
    cargo check --manifest-path "$manifest" --locked --offline --message-format=json
  release_mutant_red unlocked run_release_probe_check \
    "$scratch/unlocked.json" "$target" "$manifest" "$scratch/unlocked-command.txt" \
    cargo check --manifest-path "$manifest" --release --offline --message-format=json
  release_mutant_red unoffline run_release_probe_check \
    "$scratch/unoffline.json" "$target" "$manifest" "$scratch/unoffline-command.txt" \
    cargo check --manifest-path "$manifest" --release --locked --message-format=json
  release_mutant_red token release_mutant_execution_gate 0 101 "$probe/negative.json" stale-token

  cleanup_release_reuse_parent() {
    local parent="$1"
    case "$parent" in
      "$scratch"/stale-token-parent|"$scratch"/reuse-*) ;;
      *) return 2 ;;
    esac
    rm -rf -- "$parent" || return 2
    [ ! -e "$parent" ] || return 2
  }

  release_stale_token_control() {
    local parent="$scratch/stale-token-parent"
    mkdir "$parent"
    if run_release_hook_probe "$parent" "$token" validate; then
      cleanup_release_reuse_parent "$parent"
      return 0
    fi
    local wrote_workspace=0
    [ ! -e "$parent/release-workspace" ] || wrote_workspace=1
    cleanup_release_reuse_parent "$parent"
    [ "$wrote_workspace" -eq 0 ] || return 0
    return 1
  }
  release_mutant_red stale_token_reuse release_stale_token_control

  release_reuse_control() {
    local name="$1" reuse_control="$2" parent="$scratch/reuse-$1" fresh_token stale_path
    mkdir "$parent"
    fresh_token="$(release_probe_token "$parent")"
    if run_release_hook_probe "$parent" "$fresh_token" validate "$reuse_control"; then
      cleanup_release_reuse_parent "$parent"
      return 0
    fi
    case "$reuse_control" in
      stale-ledger)
        stale_path="$parent/release-workspace/crates/phase285-release-probe/release-ledger.json"
        ;;
      stale-lock-trace)
        stale_path="$parent/release-workspace/crates/phase285-release-probe/lock-command.txt"
        ;;
      stale-check-trace)
        stale_path="$parent/release-workspace/crates/phase285-release-probe/positive-command.txt"
        ;;
      *) return 0 ;;
    esac
    local stale_preserved=0
    if [ "$(cat -- "$stale_path" 2>/dev/null)" = stale ] \
      && [ "$(wc -l <"$stale_path" | tr -d ' ')" -eq 1 ]; then
      stale_preserved=1
    fi
    cleanup_release_reuse_parent "$parent"
    [ "$stale_preserved" -eq 1 ] || return 0
    return 1
  }
  release_mutant_red stale_ledger_reuse release_reuse_control ledger stale-ledger
  release_mutant_red stale_lock_trace_reuse release_reuse_control lock-trace stale-lock-trace
  release_mutant_red stale_check_trace_reuse release_reuse_control check-trace stale-check-trace

  release_coherent_execution_mutant() {
    local name="$1" mutated_source="$2" artifacts="$scratch/fabricated-$1"
    local fabricated_lock_trace="$artifacts/lock-command.txt"
    local fabricated_positive_trace="$artifacts/positive-command.txt"
    local fabricated_negative_trace="$artifacts/negative-command.txt"
    local fabricated_negative_log="$artifacts/negative.json"
    local fabricated_ledger="$artifacts/release-ledger.json"
    mkdir "$artifacts"
    bash -n "$mutated_source" || return 2
    cp "$workspace/Cargo.lock.accepted" "$workspace/Cargo.lock"
    printf 'cargo generate-lockfile --offline\n' >"$fabricated_lock_trace"
    printf 'cargo check --manifest-path %s --release --locked --offline --message-format=json\n' \
      "$manifest" >"$fabricated_positive_trace"
    cp "$fabricated_positive_trace" "$fabricated_negative_trace"
    cp "$probe/negative.json" "$fabricated_negative_log"
    cp "$ledger" "$fabricated_ledger"
    validate_release_probe_execution \
      "$positive" "$negative" "$workspace" "$lock_sha" \
      0 101 "$fabricated_negative_log" "$probe" \
      "$fabricated_ledger" "$token" "$positive_sha" "$negative_sha" \
      "$fabricated_lock_trace" "$fabricated_positive_trace" "$fabricated_negative_trace" || return 2
    validate_release_probe_wiring "$mutated_source"
  }

  local wiring_name wiring_copy
  for wiring_name in sources lock frozen_lock lock_command check_command statuses diagnostic ledger \
    manifest_target token_execution lock_preflight check_preflight lock_trace_noclobber check_trace_noclobber \
    helper_lock_execution_omission helper_lock_execution_substitution \
    helper_check_execution_omission helper_check_execution_substitution \
    top_lock_call_omission top_lock_call_substitution \
    top_positive_call_omission top_positive_call_substitution \
    top_negative_call_omission top_negative_call_substitution \
    ledger_create_new wiring_guard_omission wiring_guard_substitution execution_gate \
    provenance_write_omission provenance_write_substitution \
    provenance_create_new_omission provenance_create_new_substitution \
    runtime_receipt_omission runtime_receipt_substitution \
    chain_token_omission \
    chain_source_guard_omission chain_source_guard_substitution \
    chain_probe_omission chain_probe_substitution chain_validate_omission chain_validate_substitution \
    union_source_guard_omission union_source_guard_substitution \
    union_path_omission union_path_substitution union_sha_omission union_sha_substitution \
    union_artifacts_omission union_artifacts_substitution \
    union_provenance_omission union_provenance_substitution \
    union_release_validator_omission union_release_validator_substitution \
    union_receipt_omission union_receipt_substitution \
    union_dynamic_omission union_dynamic_substitution; do
    wiring_copy="$scratch/wiring-$wiring_name.sh"
    python3 -I - "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" "$wiring_copy" "$wiring_name" <<'PY'
import pathlib, sys
source, target, name = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
text = source.read_text()
mutations = {
    "sources": ("validate_release_probe_execution", '  validate_release_probe_sources "$positive" "$negative" || return 1\n', ""),
    "lock": ("validate_release_probe_execution", '  validate_release_probe_lock "$workspace" >/dev/null || return 1\n', ""),
    "frozen_lock": ("validate_release_probe_execution", '  validate_release_probe_frozen_lock "$workspace/Cargo.lock" "$frozen_lock_sha" || return 1\n', ""),
    "lock_command": ("validate_release_probe_execution", '  [[ "$(cat -- "$lock_trace")" == "cargo generate-lockfile --offline" \\\n', ""),
    "check_command": ("validate_release_probe_execution", '  [[ "$(cat -- "$positive_trace")" == "$expected_command" \\\n', ""),
    "statuses": ("validate_release_probe_execution", '  validate_release_probe_statuses "$positive_status" "$negative_status" || return 1\n', ""),
    "diagnostic": ("validate_release_probe_execution", '  validate_release_probe_diagnostic "$negative_log" "$probe" || return 1\n', ""),
    "ledger": ("validate_release_probe_execution", '  release_probe_ledger_validator "$ledger" "$token" validate \\\n', ""),
    "manifest_target": ("validate_release_probe_execution", '  validate_release_probe_manifest_and_target "$probe/Cargo.toml" "$positive" || return 1\n', ""),
    "token_execution": ("validate_release_probe_execution", '  validate_release_probe_token "$token" "$(dirname "$workspace")" || return 1\n', ""),
    "lock_preflight": ("run_release_lock_generation", '  validate_release_lock_command "$@" || return 125\n', ""),
    "check_preflight": ("run_release_probe_check", '  validate_release_probe_command "$manifest" "$@" || return 125\n', ""),
    "lock_trace_noclobber": ("run_release_lock_generation", '  (set -o noclobber; printf \'%s\\n\' "$*" >"$trace") 2>/dev/null || return 1\n', '  printf \'%s\\n\' "$*" >"$trace"\n'),
    "check_trace_noclobber": ("run_release_probe_check", '  (set -o noclobber; printf \'%s\\n\' "$*" >"$trace") 2>/dev/null || return 1\n', '  printf \'%s\\n\' "$*" >"$trace"\n'),
    "helper_lock_execution_omission": ("run_release_lock_generation", '  (cd "$workspace" && "$@")\n', ""),
    "helper_lock_execution_substitution": ("run_release_lock_generation", '  (cd "$workspace" && "$@")\n', '  (cd "$workspace" && : "$@")\n'),
    "helper_check_execution_omission": ("run_release_probe_check", '  CARGO_TARGET_DIR="$target" "$@" >"$log" 2>&1\n', ""),
    "helper_check_execution_substitution": ("run_release_probe_check", '  CARGO_TARGET_DIR="$target" "$@" >"$log" 2>&1\n', '  : "$target" "$@" >"$log" 2>&1\n'),
    "top_lock_call_omission": ("run_release_hook_probe", '  run_release_lock_generation "$workspace" "$lock_trace" cargo generate-lockfile --offline\n', ""),
    "top_lock_call_substitution": ("run_release_hook_probe", '  run_release_lock_generation "$workspace" "$lock_trace" cargo generate-lockfile --offline\n', '  : "$workspace" "$lock_trace" cargo generate-lockfile --offline\n'),
    "top_positive_call_omission": ("run_release_hook_probe", '  run_release_probe_check "$positive_log" "$parent/release-target" "$probe/Cargo.toml" "$positive_trace" \\\n    cargo check --manifest-path "$probe/Cargo.toml" --release --locked --offline --message-format=json || positive_status=$?\n', ""),
    "top_positive_call_substitution": ("run_release_hook_probe", '  run_release_probe_check "$positive_log" "$parent/release-target" "$probe/Cargo.toml" "$positive_trace" \\\n    cargo check --manifest-path "$probe/Cargo.toml" --release --locked --offline --message-format=json || positive_status=$?\n', '  : "$positive_log" "$parent/release-target" "$probe/Cargo.toml" "$positive_trace" || positive_status=$?\n'),
    "top_negative_call_omission": ("run_release_hook_probe", '  run_release_probe_check "$negative_log" "$parent/release-target" "$probe/Cargo.toml" "$negative_trace" \\\n    cargo check --manifest-path "$probe/Cargo.toml" --release --locked --offline --message-format=json || negative_status=$?\n', ""),
    "top_negative_call_substitution": ("run_release_hook_probe", '  run_release_probe_check "$negative_log" "$parent/release-target" "$probe/Cargo.toml" "$negative_trace" \\\n    cargo check --manifest-path "$probe/Cargo.toml" --release --locked --offline --message-format=json || negative_status=$?\n', '  : "$negative_log" "$parent/release-target" "$probe/Cargo.toml" "$negative_trace" || negative_status=$?\n'),
    "ledger_create_new": ("run_release_hook_probe", 'with ledger.open("x") as output:', 'with ledger.open("w") as output:'),
    "wiring_guard_omission": ("run_release_hook_probe", '  validate_release_probe_wiring "${BASH_SOURCE[0]}"\n', ""),
    "wiring_guard_substitution": ("run_release_hook_probe", '  validate_release_probe_wiring "${BASH_SOURCE[0]}"\n', '  validate_release_probe_wiring "$ROOT_DIR/tools/check-phase285-witness-conformance.sh"\n'),
    "execution_gate": ("run_release_hook_probe", '  validate_release_probe_execution \\\n', ""),
    "provenance_write_omission": ("run_release_hook_probe", '  write_release_probe_provenance \\\n    "$parent" "$token" "$lock_sha" "$positive_sha" "$negative_sha" || return 1\n', ""),
    "provenance_write_substitution": ("run_release_hook_probe", '  write_release_probe_provenance \\\n    "$parent" "$token" "$lock_sha" "$positive_sha" "$negative_sha" || return 1\n', '  : "$parent" "$token" "$lock_sha" "$positive_sha" "$negative_sha"\n'),
    "provenance_create_new_omission": ("write_release_probe_provenance", 'with provenance.open("x") as output:', 'with provenance.open("w") as output:'),
    "provenance_create_new_substitution": ("write_release_probe_provenance", 'with provenance.open("x") as output:', 'with provenance.open("a") as output:'),
    "runtime_receipt_omission": ("run_release_hook_probe", '  record_release_probe_runtime_receipt "$parent" "$token" "$ledger" || return 1\n', ""),
    "runtime_receipt_substitution": ("run_release_hook_probe", '  record_release_probe_runtime_receipt "$parent" "$token" "$ledger" || return 1\n', '  : "$parent" "$token" "$ledger"\n'),
    "chain_token_omission": ("checkpoint_release_union_chain", '  release_token="$(release_probe_token "$selector_root")"\n', ""),
    "chain_source_guard_omission": ("checkpoint_release_union_chain", '  validate_release_probe_wiring "${BASH_SOURCE[0]}" || return 1\n', ""),
    "chain_source_guard_substitution": ("checkpoint_release_union_chain", '  validate_release_probe_wiring "${BASH_SOURCE[0]}" || return 1\n', '  validate_release_probe_wiring "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" || return 1\n'),
    "chain_probe_omission": ("checkpoint_release_union_chain", '  run_release_hook_probe "$selector_root" "$release_token" validate\n', ""),
    "chain_probe_substitution": ("checkpoint_release_union_chain", '  run_release_hook_probe "$selector_root" "$release_token" validate\n', '  : "$selector_root" "$release_token" validate\n'),
    "chain_validate_omission": ("checkpoint_release_union_chain", '  checkpoint_release_union_validate_existing "$observed" "$token_registry" \\\n    "$harness_token" "$accepted_tree" "$project" "$selector_root" \\\n    "$release_token" "$mode"\n', ""),
    "chain_validate_substitution": ("checkpoint_release_union_chain", '  checkpoint_release_union_validate_existing "$observed" "$token_registry" \\\n    "$harness_token" "$accepted_tree" "$project" "$selector_root" \\\n    "$release_token" "$mode"\n', '  : "$observed" "$token_registry" "$harness_token" "$accepted_tree" "$project" "$selector_root" "$release_token" "$mode"\n'),
    "union_source_guard_omission": ("checkpoint_release_union_validate_existing", '  validate_release_probe_wiring "${BASH_SOURCE[0]}" || return 1\n', ""),
    "union_source_guard_substitution": ("checkpoint_release_union_validate_existing", '  validate_release_probe_wiring "${BASH_SOURCE[0]}" || return 1\n', '  validate_release_probe_wiring "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" || return 1\n'),
    "union_path_omission": ("checkpoint_release_union_validate_existing", '  release_ledger="$(release_probe_ledger_path "$selector_root")"\n', ""),
    "union_path_substitution": ("checkpoint_release_union_validate_existing", '  release_ledger="$(release_probe_ledger_path "$selector_root")"\n', '  release_ledger="$selector_root/arbitrary-ledger.json"\n'),
    "union_sha_omission": ("checkpoint_release_union_validate_existing", '  release_sha="$(shasum -a 256 "$release_ledger" | awk \'{print $1}\')"\n', ""),
    "union_sha_substitution": ("checkpoint_release_union_validate_existing", '  release_sha="$(shasum -a 256 "$release_ledger" | awk \'{print $1}\')"\n', '  release_sha="0000000000000000000000000000000000000000000000000000000000000000"\n'),
    "union_artifacts_omission": ("checkpoint_release_union_validate_existing", '  IFS=$\'\\t\' read -r lock_sha positive_sha negative_sha < <(\n    release_probe_workspace_artifact_values "$selector_root"\n  )\n', ""),
    "union_artifacts_substitution": ("checkpoint_release_union_validate_existing", '  IFS=$\'\\t\' read -r lock_sha positive_sha negative_sha < <(\n    release_probe_workspace_artifact_values "$selector_root"\n  )\n', '  lock_sha="0"; positive_sha="0"; negative_sha="0"\n'),
    "union_provenance_omission": ("checkpoint_release_union_validate_existing", '  IFS=$\'\\t\' read -r release_ledger lock_sha positive_sha negative_sha < <(\n    release_probe_provenance_values "$selector_root" "$release_token" "$release_sha" \\\n      "$lock_sha" "$positive_sha" "$negative_sha"\n  )\n', ""),
    "union_provenance_substitution": ("checkpoint_release_union_validate_existing", '  IFS=$\'\\t\' read -r release_ledger lock_sha positive_sha negative_sha < <(\n    release_probe_provenance_values "$selector_root" "$release_token" "$release_sha" \\\n      "$lock_sha" "$positive_sha" "$negative_sha"\n  )\n', '  release_ledger="$(release_probe_ledger_path "$selector_root")"\n'),
    "union_release_validator_omission": ("checkpoint_release_union_validate_existing", '  release_probe_ledger_validator "$release_ledger" "$release_token" validate \\\n    "$lock_sha" "$positive_sha" "$negative_sha"\n', ""),
    "union_release_validator_substitution": ("checkpoint_release_union_validate_existing", '  release_probe_ledger_validator "$release_ledger" "$release_token" validate \\\n    "$lock_sha" "$positive_sha" "$negative_sha"\n', '  : "$release_ledger" "$release_token" validate "$lock_sha" "$positive_sha" "$negative_sha"\n'),
    "union_receipt_omission": ("checkpoint_release_union_validate_existing", '  validate_release_probe_runtime_receipt \\\n    "$selector_root" "$release_token" "$release_sha" || return 1\n', ""),
    "union_receipt_substitution": ("checkpoint_release_union_validate_existing", '  validate_release_probe_runtime_receipt \\\n    "$selector_root" "$release_token" "$release_sha" || return 1\n', '  : "$selector_root" "$release_token" "$release_sha"\n'),
    "union_dynamic_omission": ("checkpoint_release_union_validate_existing", '  checkpoint_dynamic_union_validator "$observed" "$token_registry" \\\n    "$harness_token" "$accepted_tree" "$project" "$selector_root" \\\n    "$release_token" "$release_sha" "$mode"\n', ""),
    "union_dynamic_substitution": ("checkpoint_release_union_validate_existing", '  checkpoint_dynamic_union_validator "$observed" "$token_registry" \\\n    "$harness_token" "$accepted_tree" "$project" "$selector_root" \\\n    "$release_token" "$release_sha" "$mode"\n', '  : "$observed" "$token_registry" "$harness_token" "$accepted_tree" "$project" "$selector_root" "$release_token" "$release_sha" "$mode"\n'),
}
function, fragment, replacement = mutations[name]
start = text.index(f"\n{function}() {{") + 1
if function == "run_release_hook_probe":
    end = text.index("\nrun_release_hook_self_test() {", start)
elif function == "write_release_probe_provenance":
    end = text.index("\nrelease_probe_provenance_values() {", start)
else:
    end = text.index("\n}\n", start) + 3
body = text[start:end]
if body.count(fragment) != 1:
    raise SystemExit(f"release wiring source differs: {name}")
target.write_text(text[:start] + body.replace(fragment, replacement, 1) + text[end:])
PY
    case "$wiring_name" in
      helper_*|top_*)
        release_mutant_red "execution_$wiring_name" release_coherent_execution_mutant "$wiring_name" "$wiring_copy"
        ;;
      *)
        release_mutant_red "wiring_$wiring_name" validate_release_probe_wiring "$wiring_copy"
        ;;
    esac
  done

  wiring_copy="$scratch/wiring-dynamic-token-generation.sh"
  python3 -I - "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" "$wiring_copy" <<'PY'
import pathlib, sys
source, target = map(pathlib.Path, sys.argv[1:])
text = source.read_text()
mutations = [
    ("\nrun_release_hook_self_test() {", "\n  release_mutant_execution_gate() {", 'token="$(release_probe_token "$scratch")"', 'token="phase285-release-reusable-constant"'),
    ("\ncheckpoint_release_union_chain() {", '\n}\n\nreadonly -f ', 'release_token="$(release_probe_token "$selector_root")"', 'release_token="phase285-release-reusable-constant"'),
]
for start_marker, end_marker, old, new in mutations:
    start = text.index(start_marker) + 1
    end = text.index(end_marker, start)
    section = text[start:end]
    if section.count(old) != 1:
        raise SystemExit("release dynamic token source differs")
    text = text[:start] + section.replace(old, new, 1) + text[end:]
target.write_text(text)
PY
  release_mutant_red wiring_dynamic_token_generation validate_release_probe_wiring "$wiring_copy"

  local override_name
  for override_name in checkpoint_release_union_chain validate_release_probe_wiring; do
    wiring_copy="$scratch/wiring-later-override-$override_name.sh"
    python3 -I - "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" \
      "$wiring_copy" "$override_name" <<'PY'
import pathlib, sys
source, target, name = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
text = source.read_text()
marker = "\nrun_selector() {"
if text.count(marker) != 1:
    raise SystemExit("release override insertion seam differs")
override = f"\n{name}() {{ :; }}\n"
target.write_text(text.replace(marker, override + marker, 1))
PY
    release_mutant_red "wiring_later_override_$override_name" \
      validate_release_probe_wiring "$wiring_copy"
  done

  local receipt_mutation
  for receipt_mutation in validate_return_zero synthetic_record removal_empty_check direct_assignment; do
    wiring_copy="$scratch/wiring-receipt-$receipt_mutation.sh"
    python3 -I - "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" \
      "$wiring_copy" "$receipt_mutation" <<'PY'
import pathlib, sys
source, target, mutation = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
text = source.read_text()

def replace_body(name, replacement):
    global text
    start = text.index(f"\n{name}() {{") + 1
    end = text.index("\n}\n", start) + 3
    text = text[:start] + replacement + text[end:]

if mutation == "validate_return_zero":
    replace_body("validate_release_probe_runtime_receipt", "validate_release_probe_runtime_receipt() { return 0; }\n")
elif mutation == "synthetic_record":
    replace_body(
        "record_release_probe_runtime_receipt",
        "record_release_probe_runtime_receipt() {\n"
        "  PHASE285_RELEASE_PROBE_RECEIPT_ROOT=synthetic\n"
        "  PHASE285_RELEASE_PROBE_RECEIPT_TOKEN=synthetic\n"
        "  PHASE285_RELEASE_PROBE_RECEIPT_SHA=synthetic\n"
        "}\n",
    )
elif mutation == "removal_empty_check":
    old = '  [ -z "$PHASE285_RELEASE_PROBE_RECEIPT_ROOT" ] || return 1\n'
    if text.count(old) != 1:
        raise SystemExit("receipt empty-state seam differs")
    text = text.replace(old, "", 1)
elif mutation == "direct_assignment":
    marker = "\nreadonly -f "
    if text.count(marker) != 1:
        raise SystemExit("receipt direct-assignment insertion seam differs")
    injected = (
        "\nPHASE285_RELEASE_PROBE_RECEIPT_ROOT=synthetic\n"
        "PHASE285_RELEASE_PROBE_RECEIPT_TOKEN=synthetic\n"
        "PHASE285_RELEASE_PROBE_RECEIPT_SHA=synthetic\n"
    )
    text = text.replace(marker, injected + marker, 1)
else:
    raise SystemExit(f"unknown receipt source mutation: {mutation}")
target.write_text(text)
PY
    release_mutant_red "wiring_receipt_$receipt_mutation" \
      validate_release_probe_wiring "$wiring_copy"
  done

  release_status_mutant() {
    local name="$1" positive_source="$2" negative_source="$3"
    local positive_log="$probe/$name.positive.json" negative_log="$probe/$name.negative.json"
    local positive_status=0 negative_status=0
    local positive_command_trace="$probe/$name.positive.command.txt"
    local negative_command_trace="$probe/$name.negative.command.txt"
    local pair
    pair="$(shasum -a 256 "$positive_source" | awk '{print $1}'):$(shasum -a 256 "$negative_source" | awk '{print $1}')"
    case $'\n'"$status_mutant_pairs" in
      *$'\n'"$pair"$'\n'*) return 2 ;;
    esac
    status_mutant_pairs="$status_mutant_pairs$pair"$'\n'
    cp "$positive_source" "$positive"
    run_release_probe_check "$positive_log" "$target" "$manifest" "$positive_command_trace" \
      cargo check --manifest-path "$manifest" --release --locked --offline --message-format=json || positive_status=$?
    cp "$negative_source" "$positive"
    run_release_probe_check "$negative_log" "$target" "$manifest" "$negative_command_trace" \
      cargo check --manifest-path "$manifest" --release --locked --offline --message-format=json || negative_status=$?
    reset_release_sources
    release_mutant_execution_gate "$positive_status" "$negative_status" "$negative_log" "$token" \
      "$lock_trace" "$positive_command_trace" "$negative_command_trace"
  }
  release_mutant_red positive_status release_status_mutant positive_status \
    "$probe/src/main.negative.accepted.rs" "$probe/src/main.negative.accepted.rs"
  release_mutant_red negative_status release_status_mutant negative_status \
    "$probe/src/main.positive.rs" "$probe/src/main.positive.rs"
  cp "$probe/src/main.negative.accepted.rs" "$probe/src/status.both-fail.rs"
  mutate_release_file "$probe/src/status.both-fail.rs" diagnostic-code
  cp "$probe/src/main.positive.rs" "$probe/src/status.both-pass.rs"
  mutate_release_file "$probe/src/status.both-pass.rs" positive-extra
  release_mutant_red both_fail release_status_mutant both_fail \
    "$probe/src/status.both-fail.rs" "$probe/src/status.both-fail.rs"
  release_mutant_red both_pass release_status_mutant both_pass \
    "$probe/src/status.both-pass.rs" "$probe/src/status.both-pass.rs"

  release_diagnostic_mutant() {
    local name="$1" mutation="$2" status=0
    local log="$probe/$name.json" command_trace="$probe/$name.command.txt"
    reset_release_sources
    mutate_release_file "$negative" "$mutation"
    cp "$negative" "$positive"
    run_release_probe_check "$log" "$target" "$manifest" "$command_trace" \
      cargo check --manifest-path "$manifest" --release --locked --offline --message-format=json || status=$?
    [[ "$status" -eq 101 ]] || return 1
    reset_release_sources
    release_mutant_execution_gate 0 101 "$log" "$token" \
      "$lock_trace" "$positive_trace" "$command_trace"
  }
  release_mutant_red diagnostic_code release_diagnostic_mutant diagnostic_code diagnostic-code
  release_mutant_red diagnostic_symbol release_diagnostic_mutant diagnostic_symbol diagnostic-symbol
  release_mutant_red diagnostic_span release_diagnostic_mutant diagnostic_span diagnostic-span

  reset_release_sources
  cp "$negative" "$probe/src/release_mutant.rs"
  python3 -I - "$manifest" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1]); text = path.read_text()
text = text.replace('[package]\n', '[package]\nautobins = false\n', 1)
text += '\n[[bin]]\nname = "phase285-release-probe"\npath = "src/release_mutant.rs"\n'
path.write_text(text)
PY
  local diagnostic_path_trace="$probe/diagnostic_path.command.txt"
  run_release_probe_check "$probe/diagnostic_path.json" "$target" "$manifest" "$diagnostic_path_trace" \
    cargo check --manifest-path "$manifest" --release --locked --offline --message-format=json || diagnostic_path_status=$?
  [[ "$diagnostic_path_status" -eq 101 ]] || return 1
  reset_release_sources
  release_mutant_red diagnostic_path release_mutant_execution_gate 0 101 \
    "$probe/diagnostic_path.json" "$token" "$lock_trace" "$positive_trace" "$diagnostic_path_trace"

  reset_release_sources
  cp "$workspace/Cargo.lock.accepted" "$lock"
  local distinct_status_mutations
  distinct_status_mutations="$(printf '%s' "$status_mutant_pairs" | sed '/^$/d' | LC_ALL=C sort -u | wc -l | tr -d ' ')"
  [ "$distinct_status_mutations" -eq 4 ] || return 1
  echo "release_hook_self_test mutations=$killed distinct_status_mutations=$distinct_status_mutations real_execution_seams=1 passed=1"
}

checkpoint_release_union_validate_existing() {
  local observed="$1" token_registry="$2" harness_token="$3" accepted_tree="$4"
  local project="$5" selector_root="$6" release_token="$7" mode="${8:-validate}"
  local release_ledger release_sha lock_sha positive_sha negative_sha
  validate_release_probe_wiring "${BASH_SOURCE[0]}" || return 1
  release_ledger="$(release_probe_ledger_path "$selector_root")"
  release_sha="$(shasum -a 256 "$release_ledger" | awk '{print $1}')"
  IFS=$'\t' read -r lock_sha positive_sha negative_sha < <(
    release_probe_workspace_artifact_values "$selector_root"
  )
  IFS=$'\t' read -r release_ledger lock_sha positive_sha negative_sha < <(
    release_probe_provenance_values "$selector_root" "$release_token" "$release_sha" \
      "$lock_sha" "$positive_sha" "$negative_sha"
  )
  release_probe_ledger_validator "$release_ledger" "$release_token" validate \
    "$lock_sha" "$positive_sha" "$negative_sha"
  validate_release_probe_runtime_receipt \
    "$selector_root" "$release_token" "$release_sha" || return 1
  checkpoint_dynamic_union_validator "$observed" "$token_registry" \
    "$harness_token" "$accepted_tree" "$project" "$selector_root" \
    "$release_token" "$release_sha" "$mode"
}

prepare_checkpoint_release_union_mutant() {
  local source_root="$1" mutant_root="$2" expected_token="$3" mutation="$4"
  python3 -I - "$source_root" "$mutant_root" "$expected_token" "$mutation" <<'PY'
import hashlib, json, os, pathlib, shutil, sys
source_root, mutant_root = map(pathlib.Path, sys.argv[1:3])
expected_token, mutation = sys.argv[3:5]
source_ledger = source_root / "release-workspace/crates/phase285-release-probe/release-ledger.json"
source_provenance = source_root / "release-probe-provenance.json"
ledger = mutant_root / "release-workspace/crates/phase285-release-probe/release-ledger.json"
provenance = mutant_root / "release-probe-provenance.json"
shutil.copytree(
    source_root / "release-workspace",
    mutant_root / "release-workspace",
    copy_function=os.link,
)
ledger.unlink()
probe = ledger.parent
manifest = probe / "Cargo.toml"
expected_command = f"cargo check --manifest-path {manifest} --release --locked --offline --message-format=json\n"
for name in ["positive-command.txt", "negative-command.txt"]:
    trace = probe / name
    trace.unlink()
    with trace.open("x") as output:
        output.write(expected_command)

def reject_constant(value):
    raise ValueError(f"non-RFC JSON constant rejected: {value}")

release_row = json.loads(source_ledger.read_bytes(), parse_constant=reject_constant)
source_binding = json.loads(source_provenance.read_bytes(), parse_constant=reject_constant)
if mutation == "stale_row":
    ledger_token = release_row["token"]
elif mutation == "stale_token":
    ledger_token = expected_token + "-stale"
else:
    ledger_token = expected_token
release_row["token"] = ledger_token
ledger_raw = json.dumps(release_row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
with ledger.open("xb") as output:
    output.write(ledger_raw)
if mutation == "omitted_probe":
    raise SystemExit(0)

stat = ledger.stat()
binding_token = ledger_token if mutation == "stale_token" else expected_token
binding_path = source_ledger.resolve() if mutation == "stale_path" else ledger.resolve()
binding_digest = "0" * 64 if mutation == "stale_digest" else hashlib.sha256(ledger_raw).hexdigest()
binding = {
    "schema_version": 1,
    "token": binding_token,
    "ledger_path": str(binding_path),
    "ledger_sha256": binding_digest,
    "ledger_size": len(ledger_raw),
    "ledger_device": stat.st_dev,
    "ledger_inode": stat.st_ino,
    "lock_sha256": source_binding["lock_sha256"],
    "positive_source_sha256": source_binding["positive_source_sha256"],
    "negative_source_sha256": source_binding["negative_source_sha256"],
    "status": "validated",
}
with provenance.open("x") as output:
    output.write(json.dumps(binding, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
PY
}

checkpoint_release_union_caller_self_test() {
  local observed="$1" token_registry="$2" harness_token="$3" accepted_tree="$4"
  local project="$5" selector_root="$6" mutation mutant_root mutant_token output killed=0
  for mutation in fabricated_current omitted_probe stale_path stale_token stale_digest stale_row; do
    mutant_root="$selector_root/c2a-release-$mutation"
    mkdir "$mutant_root"
    mutant_token="$(release_probe_token "$mutant_root")"
    prepare_checkpoint_release_union_mutant \
      "$selector_root" "$mutant_root" "$mutant_token" "$mutation"
    output="$mutant_root/validator-output.txt"
    if checkpoint_release_union_validate_existing \
      "$observed" "$token_registry" "$harness_token" "$accepted_tree" \
      "$project" "$mutant_root" "$mutant_token" validate >"$output" 2>&1; then
      echo "checkpoint release caller mutant survived: $mutation" >&2
      return 1
    fi
    if [ "$mutation" = fabricated_current ]; then
      grep -qx 'release probe runtime receipt differs' "$output" || {
        echo "fabricated current evidence failed before the runtime receipt boundary" >&2
        return 1
      }
    fi
    killed=$((killed + 1))
    echo "checkpoint_release_caller_self_test_red mutation=$mutation"
  done
  local caller_mutation driver_root driver_script caller_root caller_token caller_output
  for caller_mutation in omitted substituted; do
    driver_root="$selector_root/c2a-executing-$caller_mutation"
    caller_root="$driver_root/fabricated-selector"
    mkdir -p "$driver_root/tools" "$caller_root"
    caller_token="$(release_probe_token "$caller_root")"
    prepare_checkpoint_release_union_mutant \
      "$selector_root" "$caller_root" "$caller_token" fabricated_current
    driver_script="$driver_root/tools/check-phase285-witness-conformance.sh"
    cp "${BASH_SOURCE[0]}" "$driver_script"
    python3 -I - "$driver_script" "$caller_mutation" <<'PY'
import pathlib, sys
path, mutation = pathlib.Path(sys.argv[1]), sys.argv[2]
text = path.read_text()
start = text.index("\ncheckpoint_release_union_chain() {") + 1
end = text.index("\n}\n\nreadonly -f ", start) + 3
body = text[start:end]
token_line = '  release_token="$(release_probe_token "$selector_root")"\n'
probe_line = '  run_release_hook_probe "$selector_root" "$release_token" validate\n'
if body.count(token_line) != 1 or body.count(probe_line) != 1:
    raise SystemExit("mutated caller source seam differs")
body = body.replace(token_line, '  release_token="${PHASE285_C2A_MUTANT_TOKEN:?}"\n', 1)
replacement = "" if mutation == "omitted" else '  : "$selector_root" "$release_token" validate\n'
body = body.replace(probe_line, replacement, 1)
path.write_text(text[:start] + body + text[end:])
PY
    caller_output="$driver_root/caller-output.txt"
    if PHASE285_C2A_MUTANT_TOKEN="$caller_token" bash "$driver_script" \
      --self-test c2a-mutated-release-caller \
      "$observed" "$token_registry" "$harness_token" "$accepted_tree" \
      "$project" "$caller_root" >"$caller_output" 2>&1; then
      echo "mutated executing caller survived: $caller_mutation" >&2
      return 1
    fi
    grep -q '^release probe wiring differs: checkpoint_release_union_chain$' "$caller_output" || {
      echo "mutated executing caller failed outside its own source guard: $caller_mutation" >&2
      return 1
    }
    killed=$((killed + 1))
    echo "checkpoint_release_caller_self_test_red mutation=executing_probe_$caller_mutation"
  done
  [ "$killed" -eq 8 ] || return 1
  echo "checkpoint_release_caller_self_test mutations=$killed passed=1"
}

checkpoint_cumulative_audit() {
  local observed="$1" token_registry="$2" harness_token="$3" accepted_tree="$4"
  local project="$5" selector_root="$6" chain_output="$7" selector_output="$8"
  python3 -I - "$observed" "$token_registry" "$harness_token" "$accepted_tree" \
    "$project" "$selector_root" "$chain_output" "$selector_output" \
    "$ROOT_DIR/tools/check-phase285-witness-conformance.sh" \
    "$ROOT_DIR/tools/check-phase285-witness-integrity.sh" \
    "$ROOT_DIR/tools/fixtures/phase285-witness-integrity.json" <<'PY'
import collections, copy, hashlib, json, pathlib, re, sys

(observed_raw, registry_raw, harness_token, accepted_tree, project, root_raw,
 chain_raw, selector_raw, checker_raw, launcher_raw, manifest_raw) = sys.argv[1:]
observed, registry_path, root = pathlib.Path(observed_raw), pathlib.Path(registry_raw), pathlib.Path(root_raw).resolve(strict=True)
chain_path, selector_path = pathlib.Path(chain_raw), pathlib.Path(selector_raw)
checker, launcher, manifest_path = map(pathlib.Path, [checker_raw, launcher_raw, manifest_raw])
domain = b"swarm.phase285.checkpoint-cumulative-audit.v1"
cases = [
    "jetstream_checkpoint_survives_restart_for_current_predecessor_prepared_abort_and_genesis",
    "jetstream_checkpoint_rejects_rolled_back_anchor_or_recreated_stream",
    "jetstream_checkpoint_rejects_unavailable_server_instead_of_skipping",
    "jetstream_checkpoint_uses_global_revision_not_store_generation",
]
c2b_expected = """c2b_signature_only c2b_signature_key_id c2b_signature_public_key c2b_unsigned_envelope c2b_wrong_signature_domain c2b_session_schema c2b_rotation_schema c2b_rotation_snapshot_extra c2b_binding_signature c2b_state_attestation c2b_prepared_schema c2b_genesis_reason c2b_type_confusion c2b_paired_revision c2b_paired_container c2b_paired_admission c2b_paired_epoch c2b_paired_initialization c2b_paired_manifest c2b_paired_raw_config c2b_paired_witness c2b_paired_stream c2b_abort_summary_epoch c2b_abort_summary_sequence c2b_abort_terminal_txid c2b_abort_immediate_predecessor c2b_abort_live_candidate_alias c2b_prepared_session_generation c2b_embedded_genesis_abort_prepared c2b_abort_discovery_mirror""".split()
dynamic_expected = """omission addition duplication zero rename wrong_status wrong_digest stale_token stale_tree ack_substitution cross_state cross_case coherent_arbitrary_raw coherent_subject coherent_stream_header reopened_id leader empty_volume empty_container coherent_component_relation anchor_stream_name anchor_bucket_name anchor_before_created anchor_before_anchor_created anchor_stale_created anchor_after_created anchor_before_raw_config_digest anchor_after_raw_config_digest anchor_stale_result anchor_recreated_result anchor_ready_epoch_digest anchor_anchor_epoch_digest anchor_manifest_initialization_digest anchor_envelope_initialization_digest anchor_ready_manifest_digest anchor_anchor_manifest_digest anchor_unicode_digit_timestamp unavailable_stream_name unavailable_bucket_name unavailable_stream_id unavailable_foreign_result unavailable_rogue_sequence unavailable_iterator_result unavailable_inspect_result unavailable_read_result unavailable_cas_result global_stream_id global_initial_revision global_noise_sequences global_noise_last_sequence global_expected_previous_revision global_previous_revision global_new_revision global_acknowledged_digest global_proposed_digest global_duplicate global_store_generation global_initial_plus_one global_final_read_revision global_final_read_digest dynamic_whitespace dynamic_key_order dynamic_nan dynamic_infinity dynamic_negative_infinity release_stale_row release_stale_path release_stale_token release_wrong_digest release_whitespace release_key_order release_nan release_infinity release_negative_infinity""".split()
caller_expected = """fabricated_current omitted_probe stale_path stale_token stale_digest stale_row executing_probe_omitted executing_probe_substituted""".split()
selector_expected = """missing_target zero_execution ignored_test failed_test duplicate_registry_row extra_registry_row substring_only_match partial_or_filtered_only_wrong_count""".split()
iterator_ledger_expected = """omission addition duplication zero_rows renamed_id wrong_status wrong_digest stale_token stale_tree cross_case""".split()
iterator_source_expected = """bypass_accumulator constant_public_count missing_observe missing_finish missing_page_error missing_final_snapshot missing_final_check constant_expected_set full_response_equality final_check_reordered""".split()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()

def framed_digest(value):
    payload = canonical(value)
    return hashlib.sha256(domain + len(payload).to_bytes(8, "big") + payload).hexdigest()

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def exact_regular(path, parent, name):
    resolved = path.resolve(strict=True)
    if resolved.parent != parent or path.is_symlink() or not path.is_file(): raise ValueError(f"{name} path differs")
    stat = path.stat()
    return {"path":str(resolved),"sha256":sha(path),"size":stat.st_size,"device":stat.st_dev,"inode":stat.st_ino}

def strict_json(raw):
    def reject(value): raise ValueError(f"non-RFC constant: {value}")
    return json.loads(raw, parse_constant=reject)

def marker_ids(text, prefix, expected):
    found = re.findall(rf"^{re.escape(prefix)} mutation=([a-z0-9_]+)(?: |$)", text, re.MULTILINE)
    if collections.Counter(found) != collections.Counter({name:1 for name in expected}):
        raise ValueError(f"{prefix} execution inventory differs")
    return sorted(found)

chain_text, selector_text = chain_path.read_text(), selector_path.read_text()
c2b_ids = marker_ids(chain_text, "checkpoint_c2b_self_test_red", c2b_expected)
dynamic_ids = marker_ids(chain_text, "checkpoint_dynamic_self_test_red", dynamic_expected)
caller_ids = marker_ids(chain_text, "checkpoint_release_caller_self_test_red", caller_expected)
selector_ids = marker_ids(selector_text, "self_test_red selector=jetstream-checkpoint", selector_expected)
iterator_ledger_ids = marker_ids(chain_text, "checkpoint_iterator_ledger_self_test_red", iterator_ledger_expected)
iterator_source_ids = marker_ids(chain_text, "checkpoint_iterator_source_self_test_red", iterator_source_expected)
summary_lines = [
    "checkpoint_c2b_self_test mutations=30 crypto=5 nested=8 provenance=9 relations=8 positive_bytes_unchanged=1",
    "checkpoint_dynamic_self_test mutations=74 dynamic=65 release=9 passed=1 release_bound=1",
    "checkpoint_release_caller_self_test mutations=8 passed=1",
    "checkpoint_iterator_ledger_self_test mutations=10 passed=1",
    "checkpoint_iterator_source_self_test mutations=10 unique_digests=10 passed=1",
    "supplemental=jetstream-checkpoint-iterator running=1 passed=1 failed=0 ignored=0 inner_rows=6",
]
if any(chain_text.splitlines().count(line) != 1 for line in summary_lines): raise ValueError("cumulative family summary cardinality differs")
if selector_text.splitlines().count("self_test selector=jetstream-checkpoint mutation_failure_count=8") != 1: raise ValueError("selector family summary cardinality differs")

registry = {}
for line in registry_path.read_text().splitlines():
    parts = line.split("\t")
    if len(parts) != 2 or parts[0] in registry: raise ValueError("cumulative registry differs")
    registry[parts[0]] = parts[1]
if list(registry) != cases or len(set(registry.values())) != 4: raise ValueError("cumulative case/token inventory differs")

dynamic_bytes = observed.read_bytes()
if not dynamic_bytes.endswith(b"\n") or dynamic_bytes.count(b"\n") != 8: raise ValueError("cumulative dynamic row cardinality differs")
rows = []
for physical in dynamic_bytes.splitlines(keepends=True):
    value = strict_json(physical)
    if physical != canonical(value) + b"\n": raise ValueError("cumulative dynamic row is noncanonical")
    rows.append(value)
if any(row["accepted_tree"] != accepted_tree or row["harness_token"] != harness_token or row["case"] not in registry or row["invocation_token"] != registry[row["case"]] for row in rows): raise ValueError("cumulative row run binding differs")
identities = [[row["case"],row["kind"],row["state_id"]] for row in rows]
expected_identities = sorted([
    [cases[0],"restart_state",state] for state in ["current","predecessor","prepared","abort","genesis_abort"]
] + [[cases[1],"anchor_recreation",None],[cases[2],"unavailable_account_iterator",None],[cases[3],"global_revision",None]])
if sorted(identities, key=lambda value: canonical(value)) != sorted(expected_identities, key=lambda value: canonical(value)): raise ValueError("cumulative positive row inventory differs")

case_evidence = []
for name in cases:
    output = root / f"{name}.txt"; ledger = root / f"{name}.ledger.jsonl"
    text = output.read_text()
    if re.findall(r"^running (\d+) test", text, re.MULTILINE) != ["1"] or len(re.findall(rf"^test {re.escape(name)} \.\.\. ok$", text, re.MULTILINE)) != 1: raise ValueError("cumulative case transcript differs")
    summaries = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; \d+ measured; (\d+) filtered out;", text, re.MULTILINE)
    if summaries != [("1","0","0","3")]: raise ValueError("cumulative case result differs")
    case_evidence.append({"case":name,"token":registry[name],"output":exact_regular(output,root,"case output"),"ledger":exact_regular(ledger,root,"case ledger")})

iterator_case = "jetstream-checkpoint-iterator"
iterator_ids = [
    "iterator.understated_advertised",
    "iterator.short_iterator",
    "iterator.pagination_error",
    "iterator.cross_page_duplicate_or_wildcard",
    "iterator.cumulative_overflow",
    "iterator.final_closed_snapshot",
]
iterator_token_path = root / "checkpoint-iterator.token"
iterator_ledger_path = root / "checkpoint-iterator.ledger.tsv"
iterator_output_path = root / "checkpoint-iterator.txt"
iterator_token_raw = iterator_token_path.read_bytes()
if iterator_token_raw.count(b"\n") != 1 or not iterator_token_raw.endswith(b"\n"):
    raise ValueError("cumulative iterator token framing differs")
iterator_token = iterator_token_raw[:-1].decode("ascii")
if not iterator_token: raise ValueError("cumulative iterator token is empty")
iterator_domain = b"swarm.phase285.witness-iterator-ledger-row.v1"
def iterator_digest(inner_id,status,tree,token):
    payload = json.dumps({"accepted_tree":tree,"case":iterator_case,"inner_id":inner_id,"invocation_token":token,"status":status},sort_keys=True,separators=(",",":"),allow_nan=False).encode()
    return hashlib.sha256(iterator_domain+len(payload).to_bytes(8,"big")+payload).hexdigest()
iterator_rows = [line.split("\t") for line in iterator_ledger_path.read_text().splitlines()]
if len(iterator_rows) != 6 or any(len(row) != 6 for row in iterator_rows): raise ValueError("cumulative iterator ledger cardinality differs")
if [row[1] for row in iterator_rows] != iterator_ids: raise ValueError("cumulative iterator ID inventory differs")
for row_case,inner_id,status,tree,token,row_digest in iterator_rows:
    if row_case != iterator_case or status != "passed" or tree != accepted_tree or token != iterator_token or row_digest != iterator_digest(inner_id,status,tree,token):
        raise ValueError("cumulative iterator ledger binding differs")
iterator_output_text = iterator_output_path.read_text()
iterator_target = "jetstream_store::tests::inspect_ready_iterator_page_and_final_snapshot_contract_kills_mutants"
if re.findall(r"^running (\d+) test$",iterator_output_text,re.MULTILINE) != ["1"] or len(re.findall(rf"^test {re.escape(iterator_target)} \.\.\. ok$",iterator_output_text,re.MULTILINE)) != 1:
    raise ValueError("cumulative iterator transcript differs")
iterator_summaries = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",iterator_output_text,re.MULTILINE)
if len(iterator_summaries) != 1 or iterator_summaries[0][:4] != ("1","0","0","0"):
    raise ValueError("cumulative iterator result differs")
iterator_evidence = {
    "accepted_tree":accepted_tree,
    "token":iterator_token,
    "ids":iterator_ids,
    "ledger":exact_regular(iterator_ledger_path,root,"iterator ledger"),
    "output":exact_regular(iterator_output_path,root,"iterator output"),
    "token_file":exact_regular(iterator_token_path,root,"iterator token"),
}

release_path = root / "release-workspace/crates/phase285-release-probe/release-ledger.json"
provenance_path = root / "release-probe-provenance.json"
release_raw, provenance_raw = release_path.read_bytes(), provenance_path.read_bytes()
if release_raw.count(b"\n") != 1 or not release_raw.endswith(b"\n") or provenance_raw.count(b"\n") != 1 or not provenance_raw.endswith(b"\n"): raise ValueError("cumulative release framing differs")
release, provenance = strict_json(release_raw), strict_json(provenance_raw)
if release_raw != canonical(release)+b"\n" or provenance_raw != canonical(provenance)+b"\n": raise ValueError("cumulative release canonical framing differs")
release_identity = exact_regular(release_path, release_path.parent, "release ledger")
provenance_identity = exact_regular(provenance_path, root, "release provenance")
if release.get("status") != "passed" or provenance.get("status") != "validated" or provenance.get("token") != release.get("token") or provenance.get("ledger_path") != release_identity["path"] or provenance.get("ledger_sha256") != release_identity["sha256"] or provenance.get("ledger_size") != release_identity["size"] or provenance.get("ledger_device") != release_identity["device"] or provenance.get("ledger_inode") != release_identity["inode"]: raise ValueError("cumulative release/provenance relation differs")

manifest_raw_bytes = manifest_path.read_bytes(); integrity_manifest = strict_json(manifest_raw_bytes)
if manifest_raw_bytes != canonical(integrity_manifest)+b"\n" or set(integrity_manifest) != {"files","schema_version","threat_model"} or len(integrity_manifest["files"]) != 1: raise ValueError("cumulative integrity manifest differs")
integrity = {"checker":exact_regular(checker,checker.parent,"checker"),"launcher":exact_regular(launcher,launcher.parent,"launcher"),"manifest":exact_regular(manifest_path,manifest_path.parent,"manifest"),"threat_model":integrity_manifest["threat_model"]}
if integrity_manifest["files"] != [{"path":"tools/check-phase285-witness-conformance.sh","sha256":integrity["checker"]["sha256"]}]: raise ValueError("cumulative integrity checker binding differs")

families = {
    "c2b":{"controls":c2b_ids,"count":30,"inventory_digest":hashlib.sha256(canonical(c2b_ids)).hexdigest()},
    "dynamic":{"controls":dynamic_ids,"count":74,"inventory_digest":hashlib.sha256(canonical(dynamic_ids)).hexdigest()},
    "release_caller":{"controls":caller_ids,"count":8,"inventory_digest":hashlib.sha256(canonical(caller_ids)).hexdigest()},
    "selector":{"controls":selector_ids,"count":8,"inventory_digest":hashlib.sha256(canonical(selector_ids)).hexdigest()},
    "iterator":{"controls":[f"ledger.{name}" for name in iterator_ledger_ids]+[f"source.{name}" for name in iterator_source_ids],"count":20,"inventory_digest":hashlib.sha256(canonical([f"ledger.{name}" for name in iterator_ledger_ids]+[f"source.{name}" for name in iterator_source_ids])).hexdigest()},
}
envelopes = {}
for row in rows:
    if row["kind"] == "restart_state": envelopes[row["state_id"]] = hashlib.sha256(bytes.fromhex(row["evidence"]["raw"]["bytes_hex"])).hexdigest()
if set(envelopes) != {"current","predecessor","prepared","abort","genesis_abort"}: raise ValueError("cumulative positive envelope set differs")

physical = {"dynamic":exact_regular(observed,root,"dynamic union"),"registry":exact_regular(registry_path,root,"token registry"),"release":release_identity,"provenance":provenance_identity}
expected = {"schema_version":1,"accepted_tree":accepted_tree,"selector_root":str(root),"project":project,"harness_token":harness_token,"cases":case_evidence,"row_identities":expected_identities,"positive_envelope_sha256":envelopes,"release_token":release["token"],"iterator_evidence":iterator_evidence,"families":families,"physical":physical,"integrity":integrity}

def validate(value):
    required = {"schema_version","accepted_tree","selector_root","project","harness_token","cases","row_identities","positive_envelope_sha256","release_token","iterator_evidence","families","physical","integrity","cumulative_digest"}
    if not isinstance(value,dict) or set(value) != required or value["schema_version"] != 1: raise ValueError("cumulative schema differs")
    preimage = {key:item for key,item in value.items() if key != "cumulative_digest"}
    if value["cumulative_digest"] != framed_digest(preimage): raise ValueError("cumulative digest differs")
    if preimage != expected: raise ValueError("cumulative execution/provenance inventory differs")

record = dict(expected); record["cumulative_digest"] = framed_digest(record)
validate(record)
cumulative_path = root / "checkpoint-cumulative-audit.json"
with cumulative_path.open("xb") as output: output.write(canonical(record)+b"\n")
if cumulative_path.read_bytes() != canonical(record)+b"\n": raise ValueError("cumulative record canonical bytes differ")

mutants = []
for family in ["c2b","dynamic","release_caller","selector","iterator"]:
    candidate = copy.deepcopy(record); del candidate["families"][family]; mutants.append((f"omit_{family}",candidate))
candidate=copy.deepcopy(record); candidate["families"]["c2b"]["inventory_digest"]="0"*64; mutants.append(("substitute_family",candidate))
candidate=copy.deepcopy(record); candidate["families"]["c2b"]["count"]=30; candidate["families"]["c2b"]["controls"]=[]; mutants.append(("forged_counter",candidate))
candidate=copy.deepcopy(record); candidate["families"]["extra"]={"controls":[],"count":0,"inventory_digest":hashlib.sha256(b"[]").hexdigest()}; mutants.append(("extra_family",candidate))
candidate=copy.deepcopy(record); candidate["families"]=[["c2b",candidate["families"]["c2b"]],["c2b",candidate["families"]["c2b"]]]; mutants.append(("duplicate_family",candidate))
for name,key,value in [("cross_run","harness_token","stale"),("cross_tree","accepted_tree","0"*40),("cross_root","selector_root",str(root.parent)),("release_token","release_token","stale")]:
    candidate=copy.deepcopy(record); candidate[key]=value; mutants.append((name,candidate))
candidate=copy.deepcopy(record); candidate["cases"]=candidate["cases"][:3]; mutants.append(("partial_three_of_four",candidate))
candidate=copy.deepcopy(record); candidate["cases"][0]["token"]="stale"; mutants.append(("cross_token",candidate))
candidate=copy.deepcopy(record)
restart_current = next(identity for identity in candidate["row_identities"] if identity == [cases[0],"restart_state","current"])
restart_current[0] = cases[1]
mutants.append(("cross_case",candidate))
for key in ["path","sha256","size","device","inode"]:
    candidate=copy.deepcopy(record); current=candidate["physical"]["release"][key]; candidate["physical"]["release"][key]=(current+"-stale" if isinstance(current,str) else current+1); mutants.append((f"ledger_{key}",candidate))
candidate=copy.deepcopy(record); candidate["physical"]["provenance"]["sha256"]="0"*64; mutants.append(("provenance_splice",candidate))
candidate=copy.deepcopy(record); candidate["physical"]["dynamic"]["sha256"]="0"*64; mutants.append(("dynamic_splice",candidate))
candidate=copy.deepcopy(record); candidate["positive_envelope_sha256"]["current"]="0"*64; mutants.append(("positive_bytes",candidate))
candidate=copy.deepcopy(record); candidate["integrity"]["checker"]["sha256"]="0"*64; mutants.append(("integrity_substitution",candidate))
candidate=copy.deepcopy(record); candidate["families"]["iterator"]["inventory_digest"]="0"*64; mutants.append(("iterator_substitution",candidate))
candidate=copy.deepcopy(record); candidate["families"]["iterator"]["controls"]=[]; candidate["families"]["iterator"]["count"]=20; mutants.append(("iterator_forged_count",candidate))
candidate=copy.deepcopy(record); candidate["iterator_evidence"]["token"]="stale"; mutants.append(("iterator_stale_token",candidate))
candidate=copy.deepcopy(record); candidate["iterator_evidence"]["token"]=registry[cases[0]]; mutants.append(("iterator_cross_run_token",candidate))
candidate=copy.deepcopy(record); candidate["iterator_evidence"]["accepted_tree"]="0"*40; mutants.append(("iterator_stale_tree",candidate))
candidate=copy.deepcopy(record); candidate["iterator_evidence"]["ledger"]["sha256"]="0"*64; mutants.append(("iterator_ledger_splice",candidate))
candidate=copy.deepcopy(record); candidate["iterator_evidence"]["output"]["sha256"]="0"*64; mutants.append(("iterator_output_splice",candidate))
candidate=copy.deepcopy(record); candidate["iterator_evidence"]["token_file"]["sha256"]="0"*64; mutants.append(("iterator_token_splice",candidate))
candidate=copy.deepcopy(record); candidate["iterator_evidence"]["ids"][0]="iterator.substituted"; mutants.append(("iterator_id_substitution",candidate))
candidate=copy.deepcopy(record); candidate["cumulative_digest"]="0"*64; mutants.append(("stale_cumulative_digest",candidate))

expected_mutants = """omit_c2b omit_dynamic omit_release_caller omit_selector omit_iterator substitute_family forged_counter extra_family duplicate_family cross_run cross_tree cross_root release_token partial_three_of_four cross_token cross_case ledger_path ledger_sha256 ledger_size ledger_device ledger_inode provenance_splice dynamic_splice positive_bytes integrity_substitution iterator_substitution iterator_forged_count iterator_stale_token iterator_cross_run_token iterator_stale_tree iterator_ledger_splice iterator_output_splice iterator_token_splice iterator_id_substitution stale_cumulative_digest""".split()
if [name for name,_candidate in mutants] != expected_mutants:
    raise ValueError("cumulative mutation inventory differs")

for name,candidate in mutants:
    if name != "stale_cumulative_digest": candidate["cumulative_digest"] = framed_digest({key:item for key,item in candidate.items() if key != "cumulative_digest"})
    try: validate(candidate)
    except (ValueError,KeyError,TypeError): print(f"checkpoint_cumulative_self_test_red mutation={name}")
    else: raise SystemExit(f"checkpoint cumulative mutant survived: {name}")
print(f"checkpoint_cumulative_audit families=5 positive_cases=4 positive_rows=8 positive_envelopes=5 iterator_rows=6 release_rows=1 controls=140 mutations={len(mutants)} digest={record['cumulative_digest']}")
PY
}

checkpoint_release_union_chain() {
  local observed="$1" token_registry="$2" harness_token="$3" accepted_tree="$4"
  local project="$5" selector_root="$6" mode="${7:-validate}" release_token
  validate_release_probe_wiring "${BASH_SOURCE[0]}" || return 1
  release_token="$(release_probe_token "$selector_root")"
  run_release_hook_probe "$selector_root" "$release_token" validate
  checkpoint_release_union_validate_existing "$observed" "$token_registry" \
    "$harness_token" "$accepted_tree" "$project" "$selector_root" \
    "$release_token" "$mode"
  if [ "$mode" = self-test ]; then
    checkpoint_release_union_caller_self_test \
      "$observed" "$token_registry" "$harness_token" "$accepted_tree" \
      "$project" "$selector_root"
  fi
}

readonly -f checkpoint_release_union_chain checkpoint_release_union_validate_existing record_release_probe_runtime_receipt release_probe_ledger_path release_probe_provenance_path release_probe_provenance_values release_probe_workspace_artifact_values run_release_hook_probe run_release_lock_generation run_release_probe_check validate_release_probe_execution validate_release_probe_runtime_receipt validate_release_probe_wiring write_release_probe_provenance

run_selector() {
  local selector="$1"
  validate_registry
  selector_rows "$selector" >/dev/null 2>&1 || {
    echo "unknown Phase 285 witness selector: $selector" >&2
    return 2
  }
  if [ "$selector" = transport-layering ]; then
    run_transport_selector
    return
  fi
  if [ "$selector" = full-service-path ]; then
    store_proxy_source_guard normal
  fi
  case "$selector" in
    response-failure-wire|candidate-verifier|protocol-checkpoint|atomic-store-contract|in-memory-differential|typed-proxy|jetstream-cas|jetstream-checkpoint|public-dispatcher|full-service-path) ;;
    *)
      echo "missing target for selector $selector: its later owning Phase 285 slice has not materialized the target inventory" >&2
      return 1
      ;;
  esac

  local package target
  IFS=$'\t' read -r package target < <(target_for_selector "$selector")
  local temp_dir list_output
  temp_dir="$(phase285_create_confined_scratch phase285-witness)"
  PHASE285_WITNESS_TEMP_DIR="$temp_dir"
  trap cleanup_temp_dir_on_exit EXIT
  list_output="$temp_dir/list.txt"
  if ! cargo test -p "$package" --test "$target" --locked --offline -- --list >"$list_output" 2>&1; then
    cat "$list_output" >&2
    echo "missing or unenumerable target for selector $selector: $package/$target" >&2
    return 1
  fi
  local inventory_file="$temp_dir/inventory.txt"
  materialized_inventory_for_target "$package" "$target" | LC_ALL=C sort >"$inventory_file"
  python3 - "$list_output" "$inventory_file" <<'PY'
import re
import sys

output = open(sys.argv[1], encoding="utf-8").read().splitlines()
expected = [line.strip() for line in open(sys.argv[2], encoding="utf-8") if line.strip()]
found = []
for line in output:
    match = re.fullmatch(r"([^:]+): test", line.strip())
    if match:
        found.append(match.group(1))
if not found:
    raise SystemExit("target enumeration returned zero tests")
if len(found) != len(set(found)):
    raise SystemExit("target enumeration contained duplicate test names")
if sorted(found) != sorted(expected):
    missing = sorted(set(expected) - set(found))
    extra = sorted(set(found) - set(expected))
    raise SystemExit(f"target inventory mismatch: missing={missing} extra={extra}")
print(f"target_inventory executed={len(found)} passed={len(found)} failed=0 ignored=0")
PY

  local target_count expected_filtered case_name output_file executed=0
  local expected_inner inner_ledger expected_union observed_union
  local first_expected_inner first_inner_ledger second_expected_inner
  local checkpoint_token_registry checkpoint_tree checkpoint_invocation_token capability_invocation_token
  target_count="$(wc -l <"$inventory_file" | tr -d ' ')"
  expected_filtered=$((target_count - 1))
  if [ "$selector" = jetstream-cas ]; then
    expected_union="$temp_dir/expected-inner-union.tsv"
    observed_union="$temp_dir/observed-inner-union.tsv"
    : >"$expected_union"
    : >"$observed_union"
  elif [ "$selector" = jetstream-checkpoint ]; then
    observed_union="$temp_dir/checkpoint-dynamic-union.jsonl"
    checkpoint_token_registry="$temp_dir/checkpoint-token-registry.tsv"
    checkpoint_tree="$(git write-tree)"
    : >"$observed_union"
    : >"$checkpoint_token_registry"
  elif [ "$selector" = public-dispatcher ]; then
    expected_union="$temp_dir/dispatcher-mapping.expected.tsv"
    observed_union="$temp_dir/dispatcher-mapping.ledger.tsv"
    write_expected_inner_ledger dispatcher-mapping "$expected_union"
    [ ! -e "$observed_union" ] || return 1
  elif [ "$selector" = full-service-path ]; then
    observed_union="$temp_dir/capability-matrix.ledger.tsv"
    capability_invocation_token="$(release_probe_token "$temp_dir")"
    [ ! -e "$observed_union" ] || return 1
  fi
  while IFS= read -r case_name; do
    [ -n "$case_name" ] || continue
    output_file="$temp_dir/$case_name.txt"
    if [ "$selector" = jetstream-cas ]; then
      expected_inner="$temp_dir/$case_name.expected.tsv"
      inner_ledger="$temp_dir/$case_name.ledger.tsv"
      [ ! -e "$inner_ledger" ] || return 1
      write_expected_inner_ledger "$case_name" "$expected_inner"
      if ! PHASE285_WITNESS_INNER_LEDGER_REQUIRED=1 \
        PHASE285_WITNESS_INNER_LEDGER="$inner_ledger" \
        PHASE285_CHECKPOINT_LEDGER_REQUIRED=1 \
        PHASE285_CHECKPOINT_LEDGER="$inner_ledger" \
        cargo test -p "$package" --test "$target" --locked --offline -- "$case_name" --exact >"$output_file" 2>&1; then
        cat "$output_file" >&2
        echo "named case failed: selector=$selector case=$case_name" >&2
        return 1
      fi
    elif [ "$selector" = jetstream-checkpoint ]; then
      inner_ledger="$temp_dir/$case_name.ledger.jsonl"
      checkpoint_invocation_token="$(release_probe_token "$temp_dir")"
      [ ! -e "$inner_ledger" ] || return 1
      printf '%s\t%s\n' "$case_name" "$checkpoint_invocation_token" >>"$checkpoint_token_registry"
      if ! PHASE285_CHECKPOINT_LEDGER_REQUIRED=1 \
        PHASE285_CHECKPOINT_LEDGER="$inner_ledger" \
        PHASE285_CHECKPOINT_INVOCATION_TOKEN="$checkpoint_invocation_token" \
        PHASE285_CHECKPOINT_TREE="$checkpoint_tree" \
        cargo test -p "$package" --test "$target" --locked --offline -- "$case_name" --exact >"$output_file" 2>&1; then
        cat "$output_file" >&2
        echo "named case failed: selector=$selector case=$case_name" >&2
        return 1
      fi
    elif [ "$selector" = public-dispatcher ] && [ "$executed" -eq 0 ]; then
      if ! PHASE285_DISPATCHER_MAPPING_LEDGER_REQUIRED=1 \
        PHASE285_DISPATCHER_MAPPING_LEDGER="$observed_union" \
        cargo test -p "$package" --test "$target" --locked --offline -- "$case_name" --exact >"$output_file" 2>&1; then
        cat "$output_file" >&2
        echo "named case failed: selector=$selector case=$case_name" >&2
        return 1
      fi
    elif [ "$selector" = full-service-path ]; then
      if ! PHASE285_CAPABILITY_MATRIX_LEDGER_REQUIRED=1 \
        PHASE285_CAPABILITY_MATRIX_LEDGER="$observed_union" \
        PHASE285_CAPABILITY_MATRIX_INVOCATION_TOKEN="$capability_invocation_token" \
        cargo test -p "$package" --test "$target" --locked --offline -- "$case_name" --exact >"$output_file" 2>&1; then
        cat "$output_file" >&2
        echo "named case failed: selector=$selector case=$case_name" >&2
        return 1
      fi
    elif ! cargo test -p "$package" --test "$target" --locked --offline -- "$case_name" --exact >"$output_file" 2>&1; then
      cat "$output_file" >&2
      echo "named case failed: selector=$selector case=$case_name" >&2
      return 1
    fi
    python3 - "$output_file" "$case_name" "$expected_filtered" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
case = sys.argv[2]
expected_filtered = int(sys.argv[3])
running = re.findall(r"^running (\d+) test", text, re.MULTILINE)
summaries = re.findall(
    r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; \d+ measured; (\d+) filtered out;",
    text,
    re.MULTILINE,
)
name_lines = re.findall(rf"^test {re.escape(case)} \.\.\. ok$", text, re.MULTILINE)
if running != ["1"]:
    raise SystemExit(f"wrong running count for {case}: {running}")
if summaries != [("1", "0", "0", str(expected_filtered))]:
    raise SystemExit(f"wrong result counts for {case}: {summaries}; expected filtered={expected_filtered}")
if len(name_lines) != 1:
    raise SystemExit(f"exact full test name not observed once for {case}: {len(name_lines)}")
PY
    if [ "$selector" = jetstream-cas ]; then
      inner_ledger_validator "$expected_inner" "$inner_ledger"
      if [ "$selector" = jetstream-cas ]; then
        if [ "$executed" -eq 0 ]; then
          first_expected_inner="$expected_inner"
          first_inner_ledger="$inner_ledger"
        elif [ "$executed" -eq 1 ]; then
          second_expected_inner="$expected_inner"
        fi
      fi
      cat "$expected_inner" >>"$expected_union"
      cat "$inner_ledger" >>"$observed_union"
    elif [ "$selector" = jetstream-checkpoint ]; then
      [ -s "$inner_ledger" ] || return 1
      cat "$inner_ledger" >>"$observed_union"
    fi
    executed=$((executed + 1))
    echo "case=$case_name running=1 passed=1 failed=0 ignored=0 filtered_out=$expected_filtered"
  done < <(selector_rows "$selector")
  local required
  required="$(selector_rows "$selector" | sed '/^$/d' | wc -l | tr -d ' ')"
  [ "$executed" -eq "$required" ] || {
    echo "selector omitted rows: selector=$selector executed=$executed required=$required" >&2
    return 1
  }
  if [ "$selector" = full-service-path ]; then
    capability_ledger_validator "$observed_union" "$capability_invocation_token"
    capability_ledger_validator "$observed_union" "$capability_invocation_token" self-test
    store_proxy_source_guard self-test
    echo "capability_matrix executed=20 passed=20 failed=0 ignored=0"
  fi
  local iterator_ledger iterator_output iterator_token iterator_token_path
  if [ "$selector" = jetstream-checkpoint ]; then
    iterator_ledger="$temp_dir/checkpoint-iterator.ledger.tsv"
    iterator_output="$temp_dir/checkpoint-iterator.txt"
    iterator_token_path="$temp_dir/checkpoint-iterator.token"
    iterator_token="$(release_probe_token "$temp_dir")"
    (
      set -o noclobber
      umask 077
      printf '%s\n' "$iterator_token" >"$iterator_token_path"
    )
    if ! PHASE285_WITNESS_ITERATOR_LEDGER_REQUIRED=1 \
      PHASE285_WITNESS_ITERATOR_LEDGER="$iterator_ledger" \
      PHASE285_WITNESS_ITERATOR_TOKEN="$iterator_token" \
      PHASE285_WITNESS_ITERATOR_TREE="$checkpoint_tree" \
      cargo test -p swarm-governance-witness --lib --locked --offline \
        jetstream_store::tests::inspect_ready_iterator_page_and_final_snapshot_contract_kills_mutants \
        -- --exact >"$iterator_output" 2>&1; then
      cat "$iterator_output" >&2
      echo "supplemental iterator/page/final-snapshot evidence failed" >&2
      return 1
    fi
    python3 -I - "$iterator_output" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
target = "jetstream_store::tests::inspect_ready_iterator_page_and_final_snapshot_contract_kills_mutants"
running = re.findall(r"^running (\d+) test$", text, re.MULTILINE)
names = re.findall(rf"^test {re.escape(target)} \.\.\. ok$", text, re.MULTILINE)
summaries = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", text, re.MULTILINE)
if running != ["1"] or len(names) != 1 or len(summaries) != 1:
    raise SystemExit("supplemental iterator test transcript cardinality differs")
if summaries[0][:4] != ("1","0","0","0"):
    raise SystemExit(f"supplemental iterator test did not pass exactly once: {summaries}")
PY
  fi
  if [ "$selector" = jetstream-cas ]; then
    local scenario_case scenario_expected scenario_ledger scenario_output
    scenario_case=jetstream-cas-scenarios
    scenario_expected="$temp_dir/$scenario_case.expected.tsv"
    scenario_ledger="$temp_dir/$scenario_case.ledger.tsv"
    scenario_output="$temp_dir/$scenario_case.txt"
    [ ! -e "$scenario_ledger" ] || return 1
    write_expected_inner_ledger "$scenario_case" "$scenario_expected"
    if ! PHASE285_WITNESS_SCENARIO_LEDGER_REQUIRED=1 \
      PHASE285_WITNESS_SCENARIO_LEDGER="$scenario_ledger" \
      cargo test -p swarm-governance-witness --lib --locked --offline \
        jetstream_store::tests::nineteen_non_lossy_records_match_every_projection_and_kill_mutants \
        -- --exact >"$scenario_output" 2>&1; then
      cat "$scenario_output" >&2
      echo "supplemental nineteen-row scenario evidence failed" >&2
      return 1
    fi
    python3 -I - "$scenario_output" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
running = re.findall(r"^running (\d+) test$", text, re.MULTILINE)
summaries = re.findall(
    r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
    text,
    re.MULTILINE,
)
target = "jetstream_store::tests::nineteen_non_lossy_records_match_every_projection_and_kill_mutants"
names = re.findall(rf"^test {re.escape(target)} \.\.\. ok$", text, re.MULTILINE)
if running != ["1"] or len(names) != 1 or len(summaries) != 1:
    raise SystemExit("supplemental scenario test transcript cardinality differs")
passed, failed, ignored, measured, _filtered = summaries[0]
if (passed, failed, ignored, measured) != ("1", "0", "0", "0"):
    raise SystemExit(f"supplemental scenario test did not pass exactly once: {summaries}")
PY
    inner_ledger_validator "$scenario_expected" "$scenario_ledger"
    cat "$scenario_expected" >>"$expected_union"
    cat "$scenario_ledger" >>"$observed_union"
    inner_ledger_validator "$expected_union" "$observed_union" self-test
    if inner_ledger_validator "$second_expected_inner" "$first_inner_ledger" >/dev/null 2>&1; then
      echo "stale integration ledger was accepted for a later case" >&2
      return 1
    fi
    echo "inner_ledger_self_test_red mutation=stale_reused_file"
    if inner_ledger_validator "$first_expected_inner" "$scenario_ledger" >/dev/null 2>&1; then
      echo "supplemental unit ledger was accepted for an integration case" >&2
      return 1
    fi
    echo "inner_ledger_self_test_red mutation=unit_ledger_cross_case"
    echo "supplemental=jetstream-cas-scenarios running=1 passed=1 failed=0 ignored=0 inner_rows=19"
  fi
  if [ "$selector" = public-dispatcher ]; then
    dispatcher_source_guard self-test
    inner_ledger_validator "$expected_union" "$observed_union" self-test
    echo "dispatcher_mapping rows=9 passed=9 failed=0 ignored=0"
  fi
  if [ "$selector" = jetstream-checkpoint ]; then
    local checkpoint_chain_output checkpoint_selector_output
    checkpoint_chain_output="$temp_dir/checkpoint-chain-output.txt"
    checkpoint_selector_output="$temp_dir/checkpoint-selector-output.txt"
    checkpoint_release_union_chain "$observed_union" "$checkpoint_token_registry" \
      "${SWARM_NATS_CHECKPOINT_TOKEN:?}" "$checkpoint_tree" \
      "${SWARM_NATS_COMPOSE_PROJECT:?}" "$temp_dir" self-test | tee "$checkpoint_chain_output"
    checkpoint_iterator_ledger_validator "$temp_dir" "$checkpoint_tree" \
      "$iterator_token" self-test | tee -a "$checkpoint_chain_output"
    checkpoint_iterator_source_guard \
      "$ROOT_DIR/crates/swarm-governance-witness/src/jetstream_store.rs" \
      self-test | tee -a "$checkpoint_chain_output"
    echo "supplemental=jetstream-checkpoint-iterator running=1 passed=1 failed=0 ignored=0 inner_rows=6" | tee -a "$checkpoint_chain_output"
    echo "checkpoint_ledger cases=4 rows=$(wc -l <"$observed_union" | tr -d ' ') release_rows=1 dynamic_evidence=bound"
    run_self_test_for_selector "$selector" | tee "$checkpoint_selector_output"
    checkpoint_cumulative_audit "$observed_union" "$checkpoint_token_registry" \
      "${SWARM_NATS_CHECKPOINT_TOKEN:?}" "$checkpoint_tree" \
      "${SWARM_NATS_COMPOSE_PROJECT:?}" "$temp_dir" \
      "$checkpoint_chain_output" "$checkpoint_selector_output"
  else
    run_self_test_for_selector "$selector"
  fi
  if [ "$selector" = jetstream-cas ]; then
    echo "selector=$selector executed=$executed passed=$executed failed=0 ignored=0 registry_mutation_failure_count=8 inner_ledger_mutation_failure_count=11"
  elif [ "$selector" = public-dispatcher ]; then
    echo "selector=$selector executed=$executed passed=$executed failed=0 ignored=0 registry_mutation_failure_count=8 inner_ledger_mutation_failure_count=9 dispatcher_source_mutation_failure_count=266"
  else
    echo "selector=$selector executed=$executed passed=$executed failed=0 ignored=0 mutation_failure_count=8"
  fi
}

case "${1:-}" in
  --self-test)
    if [ "$#" -eq 2 ] && [ "$2" = transport-layering-zero-or-omitted ]; then
      run_transport_execution_self_test
    elif [ "$#" -eq 2 ] && [ "$2" = jetstream-release-hook ]; then
      run_release_hook_self_test
    elif [ "$#" -eq 2 ] && [ "$2" = jetstream-iterator-source ]; then
      checkpoint_iterator_source_guard \
        "$ROOT_DIR/crates/swarm-governance-witness/src/jetstream_store.rs" self-test
    elif [ "$#" -eq 2 ] && [ "$2" = jetstream-iterator-ledger ]; then
      checkpoint_iterator_ledger_validator \
        "${PHASE285_WITNESS_ITERATOR_ROOT:?}" \
        "${PHASE285_WITNESS_ITERATOR_TREE:?}" \
        "${PHASE285_WITNESS_ITERATOR_TOKEN:?}" self-test
    elif [ "$#" -eq 8 ] && [ "$2" = c2a-mutated-release-caller ]; then
      checkpoint_release_union_chain \
        "$3" "$4" "$5" "$6" "$7" "$8" validate
    elif [ "$#" -eq 1 ]; then
      run_self_tests
    else
      echo "usage: $0 --self-test [transport-layering-zero-or-omitted|jetstream-release-hook|jetstream-iterator-source|jetstream-iterator-ledger]" >&2
      exit 2
    fi
    ;;
  "")
    echo "usage: $0 <selector>|--self-test" >&2
    exit 2
    ;;
  *)
    [ "$#" -eq 1 ] || { echo "usage: $0 <selector>|--self-test" >&2; exit 2; }
    run_selector "$1"
    ;;
esac
